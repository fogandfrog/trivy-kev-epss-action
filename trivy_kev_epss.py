#!/usr/bin/env python3
"""Enrich a Trivy JSON report with CISA KEV and FIRST EPSS data, render it, and gate on it.

This single file is the whole implementation of the ``trivy-kev-epss-action`` composite
action. It also runs as a plain command-line tool::

    python3 trivy_kev_epss.py --report trivy.json --epss-threshold 0.2

Every action input has a matching ``--flag``; when a flag is absent the corresponding
``INPUT_<NAME>`` environment variable is read instead, which is how ``action.yml`` passes
inputs in. The step summary, the workflow-command annotations and the ``$GITHUB_OUTPUT``
file are written only when ``GITHUB_STEP_SUMMARY``, ``GITHUB_ACTIONS`` and ``GITHUB_OUTPUT``
are set, so the stdout rendering is identical inside and outside GitHub Actions.

Standard library only. PyYAML is used when importable to parse ``.trivyignore.yaml`` and
a line-based extraction takes over otherwise.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - the fallback is exercised by monkeypatching
    yaml = None  # type: ignore[assignment]

__version__ = "1.0.0"

SCHEMA_VERSION = 1
DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_OUTPUT = "trivy-enriched.json"
DEFAULT_EPSS_THRESHOLD = 0.10
DEFAULT_FAIL_ON_SEVERITY = "CRITICAL,HIGH"
DEFAULT_MAX_ROWS = 200

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
EPSS_BATCH_SIZE = 100
HTTP_TIMEOUT_SECONDS = 30.0
HTTP_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1.0
MAX_ERROR_ANNOTATIONS = 10
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024
USER_AGENT = (
    f"trivy-kev-epss-action/{__version__} (+https://github.com/fogandfrog/trivy-kev-epss-action)"
)

SEVERITY_RANK: Mapping[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}
IGNORED_RESULT_CLASSES = frozenset({"config", "secret", "license", "license-file"})
TABLE_HEADERS = (
    "Gate",
    "ID",
    "Severity",
    "EPSS",
    "KEV",
    "Package",
    "Installed",
    "Fixed",
    "Target",
)
OUTPUT_NAMES = (
    "gate",
    "failing",
    "total",
    "kev",
    "epss-above-threshold",
    "suppressed-kev",
    "report",
)

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_STEP_FAILED = 2


# --------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------


class StepError(Exception):
    """A condition that fails the step regardless of the gate verdict."""


class ConfigError(StepError):
    """An input could not be interpreted."""


class ReportError(StepError):
    """The Trivy report could not be read or has an unrecognised shape."""


class FeedError(StepError):
    """A feed could not be fetched or is unusable (empty, malformed, wrong status)."""


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    """Resolved inputs, identical whether they came from flags or ``INPUT_*`` variables."""

    report: Path
    trivyignore: Path | None
    epss_threshold: float
    fail_on_kev: bool
    fail_on_epss: bool
    fail_on_severity: tuple[str, ...]
    severity_gate_unfixed: bool
    fail: bool
    title: str | None
    output: Path
    step_summary: bool
    max_rows: int
    kev_url: str
    epss_url: str


def parse_bool(value: str | bool) -> bool:
    """Interpret the boolean spellings GitHub Actions users write in ``with:`` blocks."""
    if isinstance(value, bool):
        return value
    normalised = value.strip().lower()
    if normalised in {"true", "1", "yes", "on"}:
        return True
    if normalised in {"false", "0", "no", "off"}:
        return False
    raise ConfigError(f"expected a boolean, got {value!r}")


def parse_severities(value: str) -> tuple[str, ...]:
    """Split a comma-separated severity list; an empty string disables the severity rule."""
    return tuple(part.strip().upper() for part in value.split(",") if part.strip())


def build_parser() -> argparse.ArgumentParser:
    """Command-line flags, one per action input. Every default is ``None`` so that the
    environment can fill in the gaps afterwards."""
    parser = argparse.ArgumentParser(
        prog="trivy_kev_epss",
        description=(
            "Enrich a Trivy JSON report with CISA KEV and FIRST EPSS data, render a "
            "Markdown summary and gate on exploitation evidence."
        ),
        epilog=(
            "Each flag falls back to the INPUT_<NAME> environment variable, for example "
            "--epss-threshold to INPUT_EPSS_THRESHOLD."
        ),
    )
    parser.add_argument("--report", help="path to the Trivy JSON report (required)")
    parser.add_argument("--trivyignore", help="path to a .trivyignore.yaml or plain .trivyignore")
    parser.add_argument(
        "--epss-threshold",
        help=f"EPSS score at or above which a finding fails (default {DEFAULT_EPSS_THRESHOLD})",
    )
    parser.add_argument("--fail-on-kev", help="fail on KEV membership (default true)")
    parser.add_argument(
        "--fail-on-epss", help="fail on EPSS at or above the threshold (default true)"
    )
    parser.add_argument(
        "--fail-on-severity",
        help=(
            "comma-separated severities that fail when a fix is available "
            f"(default {DEFAULT_FAIL_ON_SEVERITY}; empty disables the rule)"
        ),
    )
    parser.add_argument(
        "--severity-gate-unfixed",
        help="apply --fail-on-severity to unfixed findings too (default false)",
    )
    parser.add_argument("--fail", help="exit non-zero when the gate fails (default true)")
    parser.add_argument(
        "--title", help="heading of the summary (default: the report's artifact name)"
    )
    parser.add_argument(
        "--output", help=f"where the enriched JSON is written (default {DEFAULT_OUTPUT})"
    )
    parser.add_argument(
        "--step-summary", help="write the Markdown to $GITHUB_STEP_SUMMARY (default true)"
    )
    parser.add_argument(
        "--max-rows", help=f"rows in the summary table (default {DEFAULT_MAX_ROWS})"
    )
    parser.add_argument("--kev-url", help="KEV catalogue URL; file:// is accepted")
    parser.add_argument("--epss-url", help="EPSS API URL; file:// is accepted")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def load_config(argv: Sequence[str] | None, environ: Mapping[str, str]) -> Config:
    """Merge command-line flags with ``INPUT_*`` variables and apply the documented defaults."""
    args = build_parser().parse_args(argv)

    def setting(name: str, *, empty_is_value: bool = False) -> str | None:
        flag_value = getattr(args, name.replace("-", "_"))
        if flag_value is not None:
            return str(flag_value)
        env_value = environ.get("INPUT_" + name.upper().replace("-", "_"))
        if env_value is None:
            return None
        if env_value.strip() == "" and not empty_is_value:
            return None
        return env_value.strip()

    report = setting("report")
    if not report:
        raise ConfigError("the report path is required (--report or INPUT_REPORT)")

    threshold_text = setting("epss-threshold") or str(DEFAULT_EPSS_THRESHOLD)
    try:
        epss_threshold = float(threshold_text)
    except ValueError as exc:
        raise ConfigError(f"epss-threshold must be a number, got {threshold_text!r}") from exc
    if not 0.0 <= epss_threshold <= 1.0:
        raise ConfigError(f"epss-threshold must be between 0 and 1, got {epss_threshold}")

    max_rows_text = setting("max-rows") or str(DEFAULT_MAX_ROWS)
    try:
        max_rows = int(max_rows_text)
    except ValueError as exc:
        raise ConfigError(f"max-rows must be an integer, got {max_rows_text!r}") from exc
    if max_rows < 0:
        raise ConfigError(f"max-rows must not be negative, got {max_rows}")

    severity_text = setting("fail-on-severity", empty_is_value=True)
    if severity_text is None:
        severity_text = DEFAULT_FAIL_ON_SEVERITY
    trivyignore = setting("trivyignore")

    return Config(
        report=Path(report),
        trivyignore=Path(trivyignore) if trivyignore else None,
        epss_threshold=epss_threshold,
        fail_on_kev=parse_bool(setting("fail-on-kev") or "true"),
        fail_on_epss=parse_bool(setting("fail-on-epss") or "true"),
        fail_on_severity=parse_severities(severity_text),
        severity_gate_unfixed=parse_bool(setting("severity-gate-unfixed") or "false"),
        fail=parse_bool(setting("fail") or "true"),
        title=setting("title"),
        output=Path(setting("output") or DEFAULT_OUTPUT),
        step_summary=parse_bool(setting("step-summary") or "true"),
        max_rows=max_rows,
        kev_url=setting("kev-url") or DEFAULT_KEV_URL,
        epss_url=setting("epss-url") or DEFAULT_EPSS_URL,
    )


# --------------------------------------------------------------------------------------
# Domain objects
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class KevEntry:
    """What the KEV catalogue says about one CVE."""

    date_added: str
    ransomware: str


@dataclass
class KevCatalog:
    """The parsed KEV feed."""

    date_released: str | None
    count: int | None
    catalog_version: str | None
    entries: dict[str, KevEntry]


@dataclass(frozen=True)
class EpssEntry:
    """One EPSS score."""

    score: float
    percentile: float
    date: str


@dataclass
class EpssScores:
    """EPSS scores for the CVEs that were queried."""

    date: str | None
    entries: dict[str, EpssEntry]


@dataclass
class Finding:
    """One deduplicated vulnerability, enriched and gated."""

    id: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str
    status: str
    title: str
    url: str
    pkg_path: str
    targets: list[str]
    workloads: list[str] = field(default_factory=list)
    kev: KevEntry | None = None
    epss: EpssEntry | None = None
    gate_fail: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)

    @property
    def is_cve(self) -> bool:
        return CVE_PATTERN.match(self.id) is not None


@dataclass
class Report:
    """A Trivy report reduced to what the gate needs."""

    artifact_name: str
    artifact_type: str
    trivy_schema_version: int | None
    kubernetes: bool
    findings: list[Finding]


@dataclass
class Suppression:
    """One entry of the ignore file, cross-checked against KEV."""

    id: str
    statement: str | None = None
    expired_at: str | None = None
    kev: KevEntry | None = None


@dataclass(frozen=True)
class Counts:
    """The numbers that go into the verdict line, the outputs and the JSON."""

    total: int
    failing: int
    kev: int
    epss_above_threshold: int


@dataclass
class RunResult:
    """Everything the renderers need, computed once."""

    cfg: Config
    report: Report
    kev: KevCatalog
    epss: EpssScores
    findings: list[Finding]
    suppressions: list[Suppression]
    counts: Counts
    generated_at: str

    @property
    def title(self) -> str:
        return self.cfg.title or self.report.artifact_name or "Trivy report"

    @property
    def gate_failed(self) -> bool:
        return self.counts.failing > 0

    @property
    def suppressed_kev(self) -> list[Suppression]:
        return [s for s in self.suppressions if s.kev is not None]


# --------------------------------------------------------------------------------------
# Report parsing
# --------------------------------------------------------------------------------------


def load_report(path: Path) -> Report:
    """Read and parse a Trivy JSON report from disk."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot read the Trivy report {path}: {exc}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ReportError(f"the Trivy report {path} is not valid JSON: {exc}") from exc
    return parse_report(document)


def parse_report(document: Any) -> Report:
    """Accept the ``Results[]`` shape of ``fs``/``image``/``rootfs``/``repo`` and the ``k8s``
    wrapper whose ``Resources[]`` (``Vulnerabilities[]`` in older Trivy versions) each carry
    their own ``Results[]``. Misconfiguration, secret and licence results are skipped."""
    if not isinstance(document, dict):
        raise ReportError("the Trivy report is not a JSON object")

    schema_version = document.get("SchemaVersion")
    trivy_schema_version = schema_version if isinstance(schema_version, int) else None
    collector = _FindingCollector()

    is_kubernetes = "ClusterName" in document or isinstance(document.get("Resources"), list)
    if not is_kubernetes and ("Results" in document or "ArtifactName" in document):
        collector.add_results(document.get("Results"), workload=None)
        return Report(
            artifact_name=str(document.get("ArtifactName") or ""),
            artifact_type=str(document.get("ArtifactType") or ""),
            trivy_schema_version=trivy_schema_version,
            kubernetes=False,
            findings=collector.findings(),
        )

    resources = document.get("Resources")
    if not isinstance(resources, list):
        resources = document.get("Vulnerabilities")
    if not isinstance(resources, list) and not is_kubernetes:
        raise ReportError(
            "unrecognised report shape: expected Trivy's Results[] or the k8s Resources[] wrapper"
        )
    for resource in resources or []:
        if isinstance(resource, dict):
            collector.add_results(resource.get("Results"), workload=_workload_label(resource))
    return Report(
        artifact_name=str(document.get("ClusterName") or ""),
        artifact_type="kubernetes",
        trivy_schema_version=trivy_schema_version,
        kubernetes=True,
        findings=collector.findings(),
    )


def _workload_label(resource: Mapping[str, Any]) -> str:
    namespace = str(resource.get("Namespace") or "")
    kind = str(resource.get("Kind") or "")
    name = str(resource.get("Name") or "")
    parts = [part for part in (namespace, kind, name) if part]
    return "/".join(parts) or "unknown"


class _FindingCollector:
    """Deduplicates on (ID, package, installed version, target) and aggregates the k8s
    workloads that share a finding."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str, str, str], Finding] = {}

    def add_results(self, results: Any, workload: str | None) -> None:
        if not isinstance(results, list):
            return
        for result in results:
            if not isinstance(result, dict):
                continue
            if str(result.get("Class") or "") in IGNORED_RESULT_CLASSES:
                continue
            target = str(result.get("Target") or "")
            vulnerabilities = result.get("Vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if isinstance(vulnerability, dict):
                    self._add(vulnerability, target, workload)

    def _add(self, vulnerability: Mapping[str, Any], target: str, workload: str | None) -> None:
        vuln_id = str(vulnerability.get("VulnerabilityID") or "").strip()
        if not vuln_id:
            return
        package = str(vulnerability.get("PkgName") or "")
        installed = str(vulnerability.get("InstalledVersion") or "")
        key = (vuln_id, package, installed, target)
        finding = self._by_key.get(key)
        if finding is None:
            fixed = str(vulnerability.get("FixedVersion") or "")
            finding = Finding(
                id=vuln_id,
                package=package,
                installed_version=installed,
                fixed_version=fixed,
                severity=str(vulnerability.get("Severity") or "UNKNOWN").upper(),
                status=str(vulnerability.get("Status") or ("fixed" if fixed else "affected")),
                title=str(vulnerability.get("Title") or ""),
                url=str(vulnerability.get("PrimaryURL") or ""),
                pkg_path=str(vulnerability.get("PkgPath") or ""),
                targets=[target],
            )
            self._by_key[key] = finding
        if workload and workload not in finding.workloads:
            finding.workloads.append(workload)

    def findings(self) -> list[Finding]:
        for finding in self._by_key.values():
            finding.workloads.sort()
        return list(self._by_key.values())


# --------------------------------------------------------------------------------------
# Feeds
# --------------------------------------------------------------------------------------


def fetch_url(url: str) -> bytes:
    """GET ``url`` following redirects, with a 30 s timeout and three attempts with
    exponential backoff. ``file://`` URLs are read from disk through the same code path."""
    last_error: Exception | None = None
    for attempt in range(1, HTTP_ATTEMPTS + 1):
        request = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return response.read()
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
            if attempt < HTTP_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS * 2 ** (attempt - 1))
        except ValueError as exc:
            raise FeedError(f"cannot fetch {url}: {exc}") from exc
    raise FeedError(f"cannot fetch {url} after {HTTP_ATTEMPTS} attempts: {last_error}")


def _is_file_url(url: str) -> bool:
    return urllib.parse.urlsplit(url).scheme == "file"


def fetch_kev(url: str) -> KevCatalog:
    """Fetch and parse the CISA KEV catalogue. An empty catalogue is a broken feed."""
    raw = fetch_url(url)
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise FeedError(f"the KEV feed at {url} is not valid JSON: {exc}") from exc
    return parse_kev(document, url)


def parse_kev(document: Any, url: str = DEFAULT_KEV_URL) -> KevCatalog:
    """Parse the CISA KEV JSON schema, keeping ``dateAdded`` and
    ``knownRansomwareCampaignUse`` per CVE."""
    vulnerabilities = document.get("vulnerabilities") if isinstance(document, dict) else None
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise FeedError(
            f"the KEV feed at {url} has no vulnerabilities; refusing to gate against an empty "
            "catalogue"
        )
    entries: dict[str, KevEntry] = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve:
            continue
        entries[cve] = KevEntry(
            date_added=str(item.get("dateAdded") or ""),
            ransomware=str(item.get("knownRansomwareCampaignUse") or "Unknown"),
        )
    if not entries:
        raise FeedError(f"the KEV feed at {url} has no usable cveID entries")
    count = document.get("count")
    catalog_version = document.get("catalogVersion")
    date_released = document.get("dateReleased")
    return KevCatalog(
        date_released=str(date_released) if date_released else None,
        count=count if isinstance(count, int) else len(entries),
        catalog_version=str(catalog_version) if catalog_version else None,
        entries=entries,
    )


def fetch_epss(url: str, ids: Iterable[str]) -> EpssScores:
    """Fetch EPSS scores for the CVE identifiers in ``ids``.

    HTTP(S) URLs are queried in batches of 100 through ``?cve=<comma-separated>``. A
    ``file://`` URL cannot carry a query string, so the file is loaded once and filtered
    locally, which is what the offline tests rely on. If at least one CVE was queried and
    nothing came back, the feed is considered broken and the step fails; a single CVE
    missing from the response is simply absent from the result.
    """
    wanted = sorted({cve.upper() for cve in ids if CVE_PATTERN.match(cve)})
    if not wanted:
        return EpssScores(date=None, entries={})
    wanted_set = set(wanted)
    entries: dict[str, EpssEntry] = {}

    if _is_file_url(url):
        rows = _parse_epss_payload(fetch_url(url), url)
        _merge_epss_rows(entries, rows, wanted_set)
    else:
        separator = "&" if "?" in url else "?"
        for start in range(0, len(wanted), EPSS_BATCH_SIZE):
            batch = wanted[start : start + EPSS_BATCH_SIZE]
            query = urllib.parse.urlencode({"cve": ",".join(batch)}, safe=",")
            rows = _parse_epss_payload(fetch_url(f"{url}{separator}{query}"), url)
            _merge_epss_rows(entries, rows, wanted_set)

    if not entries:
        raise FeedError(
            f"the EPSS feed at {url} returned no scores for {len(wanted)} CVEs; the feed "
            "looks broken"
        )
    return EpssScores(date=max(entry.date for entry in entries.values()) or None, entries=entries)


def _parse_epss_payload(raw: bytes, url: str) -> list[Any]:
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise FeedError(f"the EPSS feed at {url} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise FeedError(f"the EPSS feed at {url} did not return a JSON object")
    status = document.get("status")
    if status != "OK":
        raise FeedError(f"the EPSS feed at {url} answered with status {status!r} instead of 'OK'")
    data = document.get("data")
    if not isinstance(data, list):
        raise FeedError(f"the EPSS feed at {url} has no data array")
    return data


def _merge_epss_rows(entries: dict[str, EpssEntry], rows: Iterable[Any], wanted: set[str]) -> None:
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve") or "").strip().upper()
        if cve not in wanted:
            continue
        try:
            score = float(row["epss"])
            percentile = float(row.get("percentile") or 0.0)
        except (KeyError, TypeError, ValueError):
            continue
        entries[cve] = EpssEntry(
            score=score, percentile=percentile, date=str(row.get("date") or "")
        )


# --------------------------------------------------------------------------------------
# Enrichment and gate
# --------------------------------------------------------------------------------------


def enrich(findings: Iterable[Finding], kev: KevCatalog, epss: EpssScores) -> None:
    """Attach KEV and EPSS data to CVE findings. Other identifiers are never looked up."""
    for finding in findings:
        if not finding.is_cve:
            continue
        finding.kev = kev.entries.get(finding.id.upper())
        finding.epss = epss.entries.get(finding.id.upper())


def apply_gate(finding: Finding, cfg: Config) -> None:
    """Decide whether one finding fails and record why."""
    reasons: list[str] = []
    if cfg.fail_on_kev and finding.kev is not None:
        reasons.append("kev")
    if cfg.fail_on_epss and finding.epss is not None and finding.epss.score >= cfg.epss_threshold:
        reasons.append("epss")
    if finding.severity in cfg.fail_on_severity and (finding.fixable or cfg.severity_gate_unfixed):
        reasons.append("severity")
    finding.reasons = reasons
    finding.gate_fail = bool(reasons)


def count_findings(findings: Iterable[Finding], epss_threshold: float) -> Counts:
    """The verdict numbers."""
    total = failing = kev = above = 0
    for finding in findings:
        total += 1
        failing += finding.gate_fail
        kev += finding.kev is not None
        above += finding.epss is not None and finding.epss.score >= epss_threshold
    return Counts(total=total, failing=failing, kev=kev, epss_above_threshold=above)


def sort_key(finding: Finding) -> tuple[Any, ...]:
    """Failing first, then KEV, then EPSS descending with ``n/a`` last, then severity."""
    epss_key = (0, -finding.epss.score) if finding.epss is not None else (1, 0.0)
    return (
        0 if finding.gate_fail else 1,
        0 if finding.kev is not None else 1,
        epss_key,
        SEVERITY_RANK.get(finding.severity, len(SEVERITY_RANK)),
        finding.id,
        finding.package,
        finding.installed_version,
        finding.targets,
    )


# --------------------------------------------------------------------------------------
# Ignore file
# --------------------------------------------------------------------------------------


def load_trivyignore(path: Path) -> list[Suppression]:
    """Collect the suppressed IDs from a ``.trivyignore.yaml`` (``vulnerabilities[].id``)
    or a plain ``.trivyignore`` (one ID per non-comment line, optionally followed by
    ``exp:YYYY-MM-DD``)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read the ignore file {path}: {exc}") from exc

    if yaml is not None:
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError:
            document = None
        if isinstance(document, dict):
            return _suppressions_from_yaml_document(document)
    elif _looks_like_yaml_ignore(text):
        return _suppressions_from_yaml_lines(text)
    return _suppressions_from_plain_lines(text)


def _suppressions_from_yaml_document(document: Mapping[str, Any]) -> list[Suppression]:
    suppressions: list[Suppression] = []
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return suppressions
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        vuln_id = str(item.get("id") or "").strip().upper()
        if not vuln_id:
            continue
        statement = item.get("statement")
        expired_at = item.get("expired_at")
        suppressions.append(
            Suppression(
                id=vuln_id,
                statement=str(statement) if statement is not None else None,
                expired_at=str(expired_at) if expired_at is not None else None,
            )
        )
    return suppressions


_YAML_SECTION = re.compile(r"^([A-Za-z_][\w-]*):\s*$")
_YAML_FIELD = re.compile(r"^(id|statement|expired_at):\s*(.*)$")


def _looks_like_yaml_ignore(text: str) -> bool:
    return any(
        _YAML_SECTION.match(line.strip()) or line.strip().startswith("- ")
        for line in text.splitlines()
    )


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _suppressions_from_yaml_lines(text: str) -> list[Suppression]:
    """Line-based fallback for the YAML form when PyYAML is not importable. It understands
    the layout Trivy documents (a ``vulnerabilities:`` list of ``- id:`` mappings) and
    nothing fancier, which is enough to cross-check IDs against KEV."""
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    in_vulnerabilities = False
    entry_indent: int | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        section = _YAML_SECTION.match(stripped)
        if section and not line[:1].isspace():
            in_vulnerabilities = section.group(1) == "vulnerabilities"
            current = None
            entry_indent = None
            continue
        if not in_vulnerabilities:
            continue
        if stripped.startswith("- "):
            indent = len(line) - len(line.lstrip())
            if entry_indent is None:
                entry_indent = indent
            if indent > entry_indent:
                # An item of a nested list such as paths:, not a new vulnerability entry.
                continue
            current = {}
            entries.append(current)
            stripped = stripped[2:].strip()
        matched = _YAML_FIELD.match(stripped)
        if matched and current is not None:
            current[matched.group(1)] = _unquote(matched.group(2))
    return [
        Suppression(
            id=entry["id"].strip().upper(),
            statement=entry.get("statement"),
            expired_at=entry.get("expired_at"),
        )
        for entry in entries
        if entry.get("id", "").strip()
    ]


def _suppressions_from_plain_lines(text: str) -> list[Suppression]:
    suppressions: list[Suppression] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        expired_at = next((token[4:] for token in tokens[1:] if token.startswith("exp:")), None)
        suppressions.append(Suppression(id=tokens[0].upper(), expired_at=expired_at))
    return suppressions


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------


def escape_cell(text: str) -> str:
    """Make a string safe inside a Markdown table cell."""
    return re.sub(r"\r\n|\r|\n", " ", text).replace("|", "\\|")


def markdown_table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    lines = [
        "| " + " | ".join(escape_cell(h) for h in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(escape_cell(cell) for cell in row) + " |" for row in rows)
    return "\n".join(lines)


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural_form or singular + 's')}"


def _format_epss(finding: Finding) -> str:
    if finding.epss is None:
        return "n/a"
    return f"{finding.epss.score:.4f}"


def _format_kev(finding: Finding) -> str:
    if not finding.is_cve:
        return "n/a"
    if finding.kev is None:
        return "no"
    text = "yes"
    details = [d for d in (finding.kev.date_added,) if d]
    if finding.kev.ransomware.lower() == "known":
        details.append("ransomware")
    return f"{text} ({', '.join(details)})" if details else text


def _format_id(finding: Finding) -> str:
    label = escape_cell(finding.id)
    if finding.url and re.match(r"^https?://", finding.url):
        return f"[{label}]({finding.url})"
    return label


def _finding_row(finding: Finding) -> list[str]:
    gate = "fail (" + ", ".join(finding.reasons) + ")" if finding.gate_fail else "pass"
    return [
        gate,
        _format_id(finding),
        finding.severity,
        _format_epss(finding),
        _format_kev(finding),
        finding.package,
        finding.installed_version,
        finding.fixed_version or "unfixed",
        ", ".join(finding.targets),
    ]


def render_markdown(result: RunResult, max_rows: int | None = None) -> str:
    """The step summary. ``max_rows`` overrides the configured cap, which the 1 MiB guard
    uses to shrink the table."""
    cfg = result.cfg
    counts = result.counts
    cap = cfg.max_rows if max_rows is None else max_rows
    verdict = "fail" if result.gate_failed else "pass"
    sections: list[str] = [f"# {escape_cell(result.title)}"]

    verdict_line = (
        f"**Gate: {verdict}** — {counts.failing} of {plural(counts.total, 'finding')} fail the "
        f"gate (KEV: {counts.kev}, EPSS at or above {cfg.epss_threshold:g}: "
        f"{counts.epss_above_threshold})."
    )
    sections.append(verdict_line)

    feed_bits = []
    kev_bits = []
    if result.kev.catalog_version:
        kev_bits.append(f"catalogue {result.kev.catalog_version}")
    if result.kev.count is not None:
        kev_bits.append(f"{result.kev.count} entries")
    feed_bits.append("KEV " + (", ".join(kev_bits) if kev_bits else "loaded"))
    feed_bits.append(
        f"EPSS scores dated {result.epss.date}" if result.epss.date else "EPSS not queried"
    )
    source = result.report.artifact_name or "unnamed artifact"
    if result.report.artifact_type:
        source += f" ({result.report.artifact_type})"
    sections.append(f"Feeds: {' · '.join(feed_bits)}. Source: {escape_cell(source)}.")

    suppressed = result.suppressed_kev
    if suppressed:
        sections.append("## Suppressed but known exploited")
        sections.append(
            "The ignore file suppresses these IDs and CISA lists them as exploited in the wild. "
            "They do not count against the gate, but an accepted risk should never be silent."
        )
        sections.append(
            markdown_table(
                ("ID", "KEV added", "Ransomware", "Statement", "Expires"),
                (
                    [
                        s.id,
                        s.kev.date_added if s.kev else "",
                        s.kev.ransomware if s.kev else "",
                        s.statement or "",
                        s.expired_at or "",
                    ]
                    for s in suppressed
                ),
            )
        )

    if result.report.kubernetes and result.findings:
        sections.append("## Workloads")
        per_workload: dict[str, list[int]] = {}
        for finding in result.findings:
            for workload in finding.workloads or ["unknown"]:
                tally = per_workload.setdefault(workload, [0, 0])
                tally[0] += 1
                tally[1] += finding.gate_fail
        ordered = sorted(per_workload.items(), key=lambda item: (-item[1][1], -item[1][0], item[0]))
        sections.append(
            markdown_table(
                ("Workload", "Findings", "Failing"),
                ([name, str(tally[0]), str(tally[1])] for name, tally in ordered),
            )
        )

    sections.append("## Findings")
    if not result.findings:
        sections.append("No vulnerabilities in the report.")
    else:
        shown = result.findings[:cap]
        sections.append(markdown_table(TABLE_HEADERS, (_finding_row(f) for f in shown)))
        hidden = len(result.findings) - len(shown)
        if hidden > 0:
            sections.append(
                f"{plural(hidden, 'more finding')} not shown; the full list is in `{cfg.output}`."
            )
    return "\n\n".join(sections) + "\n"


def render_markdown_within_limit(result: RunResult) -> str:
    """Shrink the table until the summary fits GitHub's 1 MiB step-summary limit."""
    rows = result.cfg.max_rows
    text = render_markdown(result, rows)
    while len(text.encode("utf-8")) > STEP_SUMMARY_LIMIT_BYTES and rows > 0:
        rows //= 2
        text = render_markdown(result, rows)
    return text


def escape_workflow_data(text: str) -> str:
    """Encode a workflow-command message as GitHub requires."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def workflow_command(command: str, message: str) -> str:
    return f"::{command}::{escape_workflow_data(message)}"


def render_annotations(result: RunResult) -> list[str]:
    """``::warning::`` per suppressed KEV ID, ``::error::`` per failing finding capped at
    ten plus a count."""
    lines: list[str] = []
    for suppression in result.suppressed_kev:
        added = (
            f" (added {suppression.kev.date_added})"
            if suppression.kev and suppression.kev.date_added
            else ""
        )
        lines.append(
            workflow_command(
                "warning",
                f"{suppression.id} is suppressed by the ignore file but is on the CISA KEV "
                f"catalogue{added}",
            )
        )
    failing = [f for f in result.findings if f.gate_fail]
    for finding in failing[:MAX_ERROR_ANNOTATIONS]:
        fix = f" -> {finding.fixed_version}" if finding.fixed_version else " (unfixed)"
        where = ", ".join(finding.targets)
        lines.append(
            workflow_command(
                "error",
                f"{finding.id} {finding.package} {finding.installed_version}{fix} "
                f"[{finding.severity}] in {where} fails the gate: {', '.join(finding.reasons)}",
            )
        )
    remaining = len(failing) - MAX_ERROR_ANNOTATIONS
    if remaining > 0:
        lines.append(
            workflow_command(
                "error",
                f"{plural(remaining, 'more finding')} fail the gate; see the step summary and "
                f"{result.cfg.output}",
            )
        )
    return lines


def build_document(result: RunResult) -> dict[str, Any]:
    """The enriched JSON: a new document with a stable schema, not a patched Trivy report."""
    cfg = result.cfg
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": result.generated_at,
        "source": {
            "artifactName": result.report.artifact_name,
            "artifactType": result.report.artifact_type,
            "trivySchemaVersion": result.report.trivy_schema_version,
        },
        "feeds": {
            "kev": {
                "dateReleased": result.kev.date_released,
                "catalogVersion": result.kev.catalog_version,
                "count": result.kev.count,
            },
            "epss": {"date": result.epss.date},
        },
        "policy": {
            "epssThreshold": cfg.epss_threshold,
            "failOnKev": cfg.fail_on_kev,
            "failOnEpss": cfg.fail_on_epss,
            "failOnSeverity": list(cfg.fail_on_severity),
            "severityGateUnfixed": cfg.severity_gate_unfixed,
        },
        "gate": {
            "result": "fail" if result.gate_failed else "pass",
            "failing": result.counts.failing,
            "total": result.counts.total,
            "kev": result.counts.kev,
            "epssAboveThreshold": result.counts.epss_above_threshold,
        },
        "findings": [_finding_document(f) for f in result.findings],
        "suppressed": [
            {
                "id": s.id,
                "kev": s.kev is not None,
                "statement": s.statement,
                "expiredAt": s.expired_at,
            }
            for s in result.suppressions
        ],
    }


def _finding_document(finding: Finding) -> dict[str, Any]:
    kev = (
        {"listed": True, "dateAdded": finding.kev.date_added, "ransomware": finding.kev.ransomware}
        if finding.kev is not None
        else {"listed": False, "dateAdded": None, "ransomware": None}
    )
    epss = (
        {
            "score": finding.epss.score,
            "percentile": finding.epss.percentile,
            "date": finding.epss.date,
        }
        if finding.epss is not None
        else {"score": None, "percentile": None, "date": None}
    )
    return {
        "id": finding.id,
        "package": finding.package,
        "pkgPath": finding.pkg_path or None,
        "installedVersion": finding.installed_version,
        "fixedVersion": finding.fixed_version or None,
        "fixable": finding.fixable,
        "severity": finding.severity,
        "status": finding.status,
        "targets": list(finding.targets),
        "workloads": list(finding.workloads),
        "kev": kev,
        "epss": epss,
        "gate": {"fail": finding.gate_fail, "reasons": list(finding.reasons)},
        "title": finding.title,
        "url": finding.url,
    }


def github_outputs(result: RunResult) -> dict[str, str]:
    """The values written to ``$GITHUB_OUTPUT``."""
    return {
        "gate": "fail" if result.gate_failed else "pass",
        "failing": str(result.counts.failing),
        "total": str(result.counts.total),
        "kev": str(result.counts.kev),
        "epss-above-threshold": str(result.counts.epss_above_threshold),
        "suppressed-kev": ",".join(s.id for s in result.suppressed_kev),
        "report": str(result.cfg.output),
    }


def write_github_outputs(path: Path, outputs: Mapping[str, str]) -> None:
    lines: list[str] = []
    for name, value in outputs.items():
        if "\n" in value or "\r" in value:
            delimiter = f"EOF_{name.upper().replace('-', '_')}"
            lines.append(f"{name}<<{delimiter}\n{value}\n{delimiter}")
        else:
            lines.append(f"{name}={value}")
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------------------


def run(cfg: Config, environ: Mapping[str, str] | None = None) -> int:
    """Parse, fetch, enrich, gate, render, and return the exit code. Rendering always
    completes before a failing exit code is returned."""
    env = os.environ if environ is None else environ
    report = load_report(cfg.report)
    suppressions = load_trivyignore(cfg.trivyignore) if cfg.trivyignore else []
    kev = fetch_kev(cfg.kev_url)
    epss = fetch_epss(cfg.epss_url, (finding.id for finding in report.findings))

    enrich(report.findings, kev, epss)
    for finding in report.findings:
        apply_gate(finding, cfg)
    for suppression in suppressions:
        suppression.kev = kev.entries.get(suppression.id)

    result = RunResult(
        cfg=cfg,
        report=report,
        kev=kev,
        epss=epss,
        findings=sorted(report.findings, key=sort_key),
        suppressions=suppressions,
        counts=count_findings(report.findings, cfg.epss_threshold),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    markdown = render_markdown_within_limit(result)
    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if cfg.step_summary and summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(markdown)
    sys.stdout.write(markdown)

    if env.get("GITHUB_ACTIONS"):
        for line in render_annotations(result):
            print(line)

    cfg.output.parent.mkdir(parents=True, exist_ok=True)
    cfg.output.write_text(json.dumps(build_document(result), indent=2) + "\n", encoding="utf-8")

    output_path = env.get("GITHUB_OUTPUT")
    if output_path:
        write_github_outputs(Path(output_path), github_outputs(result))

    sys.stdout.flush()
    if result.gate_failed and cfg.fail:
        print(
            f"gate failed: {plural(result.counts.failing, 'finding')} of {result.counts.total} "
            f"fail; details in {cfg.output}",
            file=sys.stderr,
        )
        return EXIT_GATE_FAILED
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: resolve the configuration, run, and turn step errors into exit code 2."""
    try:
        cfg = load_config(argv, os.environ)
        return run(cfg)
    except StepError as exc:
        message = str(exc)
        if os.environ.get("GITHUB_ACTIONS"):
            print(workflow_command("error", message))
        print(f"error: {message}", file=sys.stderr)
        return EXIT_STEP_FAILED


if __name__ == "__main__":
    sys.exit(main())
