"""Rendering: table order, truncation, escaping, annotations, the 1 MiB guard, the JSON."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import trivy_kev_epss as tke
from tests.conftest import FS_REPORT, K8S_REPORT, RunCli, vulnerability, write_report


def _table_rows(markdown: str) -> list[list[str]]:
    """The body rows of the findings table, as lists of cells."""
    section = markdown.split("## Findings", 1)[1]
    rows = []
    for line in section.splitlines():
        if line.startswith("| ") and not line.startswith("| Gate") and not line.startswith("|---"):
            rows.append([cell.strip() for cell in line.strip().strip("|").split(" | ")])
    return rows


def test_rows_are_sorted_failing_then_kev_then_epss_then_severity(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    ids = [re.sub(r"\[([^\]]+)\].*", r"\1", row[1]) for row in _table_rows(result.stdout)]
    assert ids == [
        "CVE-2026-48710",  # fail, KEV, EPSS 0.36
        "CVE-2025-10003",  # fail, EPSS 0.55
        "CVE-2025-10001",  # fail, EPSS 0.01, HIGH
        "GHSA-59g5-xgcq-4qw3",  # fail, EPSS n/a, HIGH
        "CVE-2025-10002",  # pass, EPSS 0.0045, HIGH
        "CVE-2026-99999",  # pass, EPSS n/a, LOW
    ]
    first = _table_rows(result.stdout)[0]
    assert first[0] == "fail (kev, epss)"
    assert first[3] == "0.3626"
    assert first[4] == "yes (2026-09-02)"
    assert first[7] == "1.0.1"
    assert first[8] == "uv.lock"


def test_verdict_line_and_feeds_line(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    assert result.stdout.startswith("# .\n\n")
    assert "**Gate: fail** — 4 of 6 findings fail the gate (KEV: 1, EPSS at or above 0.1: 2)." in (
        result.stdout
    )
    assert "KEV catalogue 2026.09.04, 3 entries" in result.stdout
    assert "EPSS scores dated 2026-09-05" in result.stdout


def test_max_rows_truncates_and_says_so(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT, "--max-rows", "2", "--fail", "false")
    assert len(_table_rows(result.stdout)) == 2
    assert "4 more findings not shown; the full list is in `" in result.stdout
    assert len(result.document["findings"]) == 6


def test_pipe_in_package_name_is_escaped(run_cli: RunCli, tmp_path: Path) -> None:
    report = write_report(
        tmp_path / "pipe.json",
        [
            {
                "Target": "weird|target",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    vulnerability(
                        "GHSA-pipe-pipe-pipe",
                        package="weird|pkg",
                        Title="line one\nline two | three",
                    )
                ],
            }
        ],
    )
    result = run_cli(report, "--fail", "false")
    row = _table_rows(result.stdout)[0]
    assert row[5] == r"weird\|pkg"
    assert row[8] == r"weird\|target"
    assert result.finding("GHSA-pipe-pipe-pipe")["package"] == "weird|pkg"


def test_annotations_are_capped_and_escaped(
    run_cli: RunCli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    vulns = [vulnerability(f"GHSA-cap-{n:04d}-x", package=f"pkg{n}") for n in range(13)]
    vulns.append(vulnerability("GHSA-aaaa-esc0-x", package="bad%name\r\nnext"))
    report = write_report(
        tmp_path / "many.json", [{"Target": "t", "Class": "lang-pkgs", "Vulnerabilities": vulns}]
    )
    result = run_cli(report)
    assert result.code == 1
    errors = [line for line in result.stdout.splitlines() if line.startswith("::error::")]
    assert len(errors) == tke.MAX_ERROR_ANNOTATIONS + 1
    assert errors[-1] == "::error::4 more findings fail the gate; see the step summary and " + str(
        result.output
    )
    escaped = next(line for line in errors if "bad%25name" in line)
    assert "%0D%0A" in escaped
    assert "\n" not in escaped
    assert "fails the gate: severity" in escaped


def test_no_annotations_outside_github_actions(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    assert "::error::" not in result.stdout
    assert "::warning::" not in result.stdout


def test_step_summary_stays_under_one_mebibyte(
    run_cli: RunCli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    vulns = [
        vulnerability(f"GHSA-big-{n:04d}-x", package="x" * 40_000 + str(n), severity="LOW")
        for n in range(40)
    ]
    report = write_report(
        tmp_path / "big.json", [{"Target": "t", "Class": "lang-pkgs", "Vulnerabilities": vulns}]
    )
    result = run_cli(report)
    assert result.code == 0
    assert 0 < summary.stat().st_size <= tke.STEP_SUMMARY_LIMIT_BYTES
    assert "more findings not shown" in summary.read_text()
    assert summary.read_text() == result.stdout
    assert len(result.document["findings"]) == 40


def test_step_summary_can_be_disabled(
    run_cli: RunCli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    run_cli(FS_REPORT, "--step-summary", "false")
    assert not summary.exists()


def test_k8s_summary_has_a_workload_table(run_cli: RunCli) -> None:
    result = run_cli(K8S_REPORT)
    assert "## Workloads" in result.stdout
    assert result.stdout.index("## Workloads") < result.stdout.index("## Findings")
    assert "| default/Deployment/api | 2 | 1 |" in result.stdout
    assert "| default/Deployment/web | 1 | 1 |" in result.stdout


def test_title_override_and_default(run_cli: RunCli) -> None:
    assert run_cli(K8S_REPORT).stdout.startswith("# kind-example\n")
    assert run_cli(K8S_REPORT, "--title", "Cluster | prod").stdout.startswith(
        "# Cluster \\| prod\n"
    )


def test_enriched_json_schema(run_cli: RunCli) -> None:
    document = run_cli(FS_REPORT).document
    assert document["schemaVersion"] == 1
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", document["generatedAt"])
    assert document["source"] == {
        "artifactName": ".",
        "artifactType": "filesystem",
        "trivySchemaVersion": 2,
    }
    assert document["feeds"] == {
        "kev": {
            "dateReleased": "2026-09-04T16:47:03.5197Z",
            "catalogVersion": "2026.09.04",
            "count": 3,
        },
        "epss": {"date": "2026-09-05"},
    }
    starlette = next(f for f in document["findings"] if f["id"] == "CVE-2026-48710")
    assert starlette == {
        "id": "CVE-2026-48710",
        "package": "starlette",
        "pkgPath": None,
        "installedVersion": "1.0.0",
        "fixedVersion": "1.0.1",
        "fixable": True,
        "severity": "MEDIUM",
        "status": "fixed",
        "targets": ["uv.lock"],
        "workloads": [],
        "kev": {"listed": True, "dateAdded": "2026-09-02", "ransomware": "Unknown"},
        "epss": {"score": 0.36257, "percentile": 0.98422, "date": "2026-09-05"},
        "gate": {"fail": True, "reasons": ["kev", "epss"]},
        "title": "Starlette has missing Host header validation",
        "url": "https://avd.aquasec.com/nvd/cve-2026-48710",
    }
    assert document["findings"][0]["id"] == "CVE-2026-48710"
    assert document["suppressed"] == []


def test_empty_report_renders_and_passes(run_cli: RunCli, tmp_path: Path) -> None:
    report = write_report(tmp_path / "empty.json", [])
    result = run_cli(report)
    assert result.code == 0
    assert "No vulnerabilities in the report." in result.stdout
    assert "EPSS not queried" in result.stdout
    assert result.document["gate"]["total"] == 0
