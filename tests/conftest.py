"""Shared fixtures: offline feeds served through ``file://`` URLs, a clean GitHub
environment, and a helper that runs the CLI in-process."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import trivy_kev_epss as tke

FIXTURES = Path(__file__).parent / "fixtures"
FS_REPORT = FIXTURES / "trivy-fs.json"
IMAGE_REPORT = FIXTURES / "trivy-image.json"
K8S_REPORT = FIXTURES / "trivy-k8s.json"
KEV_FEED = FIXTURES / "kev.json"
KEV_EMPTY_FEED = FIXTURES / "kev-empty.json"
EPSS_FEED = FIXTURES / "epss.json"
EPSS_EMPTY_FEED = FIXTURES / "epss-empty.json"
IGNORE_YAML = FIXTURES / "trivyignore.yaml"
IGNORE_PLAIN = FIXTURES / "trivyignore.txt"


def file_url(path: Path) -> str:
    return path.resolve().as_uri()


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests must behave the same on a laptop and inside GitHub Actions, so the GitHub
    variables and any INPUT_* leftovers are removed, and retries do not sleep."""
    for name in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT"):
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("INPUT_"):
            monkeypatch.delenv(name)
    monkeypatch.setattr(tke, "RETRY_BACKOFF_SECONDS", 0.0)


@pytest.fixture
def kev_url() -> str:
    return file_url(KEV_FEED)


@pytest.fixture
def epss_url() -> str:
    return file_url(EPSS_FEED)


@dataclass
class CliRun:
    """What one in-process CLI invocation produced."""

    code: int
    stdout: str
    stderr: str
    output: Path

    @property
    def document(self) -> dict[str, Any]:
        return json.loads(self.output.read_text(encoding="utf-8"))

    def finding(self, vuln_id: str) -> dict[str, Any]:
        return next(f for f in self.document["findings"] if f["id"] == vuln_id)


RunCli = Callable[..., CliRun]


@pytest.fixture
def run_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kev_url: str, epss_url: str
) -> RunCli:
    """Run ``main()`` against the offline feeds. Extra flags are appended verbatim."""

    def _run(
        report: Path | str,
        *args: str,
        kev: str | None = None,
        epss: str | None = None,
        output: Path | None = None,
    ) -> CliRun:
        out = output or tmp_path / "enriched.json"
        argv = [
            "--report",
            str(report),
            "--kev-url",
            kev or kev_url,
            "--epss-url",
            epss or epss_url,
            "--output",
            str(out),
            *args,
        ]
        code = tke.main(argv)
        captured = capsys.readouterr()
        return CliRun(code=code, stdout=captured.out, stderr=captured.err, output=out)

    return _run


def write_report(path: Path, results: list[dict[str, Any]], **top_level: Any) -> Path:
    """Write a minimal ``Results[]``-shaped Trivy report."""
    document: dict[str, Any] = {
        "SchemaVersion": 2,
        "ArtifactName": "synthetic",
        "ArtifactType": "filesystem",
        "Results": results,
    }
    document.update(top_level)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def vulnerability(
    vuln_id: str,
    package: str = "pkg",
    installed: str = "1.0.0",
    fixed: str = "1.0.1",
    severity: str = "HIGH",
    **extra: Any,
) -> dict[str, Any]:
    """A Trivy vulnerability entry with just the fields the script reads."""
    entry: dict[str, Any] = {
        "VulnerabilityID": vuln_id,
        "PkgName": package,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": f"{package} does something wrong",
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{vuln_id.lower()}",
    }
    entry.update(extra)
    return entry
