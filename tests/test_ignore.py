"""Ignore-file cross-check: YAML form with and without PyYAML, plain form, and the
warn-but-do-not-fail behaviour."""

from __future__ import annotations

from pathlib import Path

import pytest

import trivy_kev_epss as tke
from tests.conftest import FS_REPORT, IGNORE_PLAIN, IGNORE_YAML, RunCli


def _ids(suppressions: list[tke.Suppression]) -> list[str]:
    return [s.id for s in suppressions]


def test_yaml_form_with_pyyaml() -> None:
    pytest.importorskip("yaml")
    suppressions = tke.load_trivyignore(IGNORE_YAML)
    assert _ids(suppressions) == ["CVE-2021-44228", "CVE-2025-30001"]
    log4j = suppressions[0]
    assert log4j.statement == "Log4j is present but the JNDI lookup is disabled at build time"
    assert log4j.expired_at == "2026-12-31"
    assert suppressions[1].expired_at is None


def test_yaml_form_line_based_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tke, "yaml", None)
    suppressions = tke.load_trivyignore(IGNORE_YAML)
    assert _ids(suppressions) == ["CVE-2021-44228", "CVE-2025-30001"]
    assert (
        suppressions[0].statement
        == "Log4j is present but the JNDI lookup is disabled at build time"
    )
    assert suppressions[0].expired_at == "2026-12-31"
    assert suppressions[1].statement == "Not reachable from the service entry points"


@pytest.mark.parametrize("with_yaml", [True, False])
def test_plain_form(monkeypatch: pytest.MonkeyPatch, with_yaml: bool) -> None:
    if with_yaml:
        pytest.importorskip("yaml")
    else:
        monkeypatch.setattr(tke, "yaml", None)
    suppressions = tke.load_trivyignore(IGNORE_PLAIN)
    assert _ids(suppressions) == ["CVE-2021-44228", "CVE-2025-30001"]
    assert suppressions[0].expired_at == "2026-12-31"
    assert suppressions[1].expired_at is None


def test_missing_ignore_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(tke.ConfigError):
        tke.load_trivyignore(tmp_path / "nope")


@pytest.mark.parametrize("ignore_file", [IGNORE_YAML, IGNORE_PLAIN])
def test_suppressed_kev_id_warns_and_does_not_fail(
    run_cli: RunCli, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ignore_file: Path
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    # Disable every gate rule so the verdict is driven by the ignore file alone.
    result = run_cli(
        FS_REPORT,
        "--trivyignore",
        str(ignore_file),
        "--fail-on-kev",
        "false",
        "--fail-on-epss",
        "false",
        "--fail-on-severity",
        "",
    )
    assert result.code == 0
    assert result.document["gate"]["result"] == "pass"
    warnings = [line for line in result.stdout.splitlines() if line.startswith("::warning::")]
    assert len(warnings) == 1
    assert "CVE-2021-44228" in warnings[0]
    assert "added 2021-12-10" in warnings[0]
    assert "## Suppressed but known exploited" in result.stdout
    assert result.stdout.index("## Suppressed but known exploited") < result.stdout.index(
        "## Findings"
    )
    assert "| CVE-2021-44228 | 2021-12-10 | Known |" in result.stdout
    assert "suppressed-kev=CVE-2021-44228" in outputs.read_text()
    suppressed = result.document["suppressed"]
    assert [s["id"] for s in suppressed] == ["CVE-2021-44228", "CVE-2025-30001"]
    assert suppressed[0]["kev"] is True
    assert suppressed[0]["expiredAt"] == "2026-12-31"
    assert suppressed[1]["kev"] is False


def test_no_suppressed_section_without_kev_ids(run_cli: RunCli, tmp_path: Path) -> None:
    ignore = tmp_path / ".trivyignore"
    ignore.write_text("CVE-2025-30001\n")
    result = run_cli(FS_REPORT, "--trivyignore", str(ignore))
    assert "Suppressed but known exploited" not in result.stdout
    assert result.document["suppressed"] == [
        {"id": "CVE-2025-30001", "kev": False, "statement": None, "expiredAt": None}
    ]
