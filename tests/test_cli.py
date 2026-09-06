"""Command-line and GitHub Actions plumbing: inputs from flags and INPUT_* variables,
$GITHUB_OUTPUT, exit codes, and render-before-exit."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import trivy_kev_epss as tke
from tests.conftest import (
    EPSS_EMPTY_FEED,
    FS_REPORT,
    IMAGE_REPORT,
    KEV_EMPTY_FEED,
    RunCli,
    file_url,
)

SCRIPT = Path(tke.__file__).resolve()


def test_github_output_receives_every_output(
    run_cli: RunCli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs.txt"
    outputs.write_text("previous=kept\n")
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    result = run_cli(IMAGE_REPORT)
    lines = outputs.read_text().splitlines()
    assert lines[0] == "previous=kept"
    written = dict(line.split("=", 1) for line in lines[1:])
    assert set(written) == set(tke.OUTPUT_NAMES)
    assert written == {
        "gate": "fail",
        "failing": "1",
        "total": "2",
        "kev": "1",
        "epss-above-threshold": "1",
        "suppressed-kev": "",
        "report": str(result.output),
    }


def test_rendering_completes_before_a_failing_exit(
    run_cli: RunCli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    result = run_cli(IMAGE_REPORT)
    assert result.code == 1
    # Summary first, the same Markdown on stdout, then annotations, then the JSON.
    markdown = summary.read_text()
    assert markdown.startswith("# ghcr.io/example/app:1.2.3\n")
    assert (
        "| Gate | ID | Severity | EPSS | KEV | Package | Installed | Fixed | Target |" in markdown
    )
    assert result.stdout.startswith(markdown)
    assert "::error::CVE-2020-11023 jquery 3.4.1 -> 3.5.0 [MEDIUM]" in result.stdout
    assert result.stdout.index("::error::") > result.stdout.index("| Gate |")
    assert result.output.exists()
    assert "gate=fail" in outputs.read_text()
    assert "gate failed: 1 finding of 2 fail" in result.stderr


def test_fail_false_renders_everything_and_exits_zero(run_cli: RunCli) -> None:
    result = run_cli(IMAGE_REPORT, "--fail", "false")
    assert result.code == 0
    assert result.document["gate"]["result"] == "fail"
    assert "**Gate: fail**" in result.stdout


def test_inputs_come_from_the_environment_when_flags_are_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "env.json"
    monkeypatch.setenv("INPUT_REPORT", str(FS_REPORT))
    monkeypatch.setenv("INPUT_KEV_URL", file_url(Path(FS_REPORT).parent / "kev.json"))
    monkeypatch.setenv("INPUT_EPSS_URL", file_url(Path(FS_REPORT).parent / "epss.json"))
    monkeypatch.setenv("INPUT_OUTPUT", str(out))
    monkeypatch.setenv("INPUT_EPSS_THRESHOLD", "0.9")
    monkeypatch.setenv("INPUT_FAIL_ON_KEV", "false")
    monkeypatch.setenv("INPUT_FAIL_ON_SEVERITY", "")
    monkeypatch.setenv("INPUT_TITLE", "")
    monkeypatch.setenv("INPUT_TRIVYIGNORE", "")
    monkeypatch.setenv("INPUT_MAX_ROWS", "")
    code = tke.main([])
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out.startswith("# .\n")
    cfg = tke.load_config([], os.environ)
    assert cfg.epss_threshold == 0.9
    assert cfg.fail_on_kev is False
    assert cfg.fail_on_severity == ()
    assert cfg.title is None
    assert cfg.trivyignore is None
    assert cfg.max_rows == tke.DEFAULT_MAX_ROWS
    # A flag wins over the variable.
    assert tke.load_config(["--epss-threshold", "0.2"], os.environ).epss_threshold == 0.2


def test_defaults_when_nothing_is_set() -> None:
    cfg = tke.load_config(["--report", "r.json"], {})
    assert cfg.epss_threshold == tke.DEFAULT_EPSS_THRESHOLD
    assert cfg.fail_on_kev is True
    assert cfg.fail_on_epss is True
    assert cfg.fail_on_severity == ("CRITICAL", "HIGH")
    assert cfg.severity_gate_unfixed is False
    assert cfg.fail is True
    assert cfg.step_summary is True
    assert cfg.max_rows == 200
    assert cfg.output == Path("trivy-enriched.json")
    assert cfg.kev_url == tke.DEFAULT_KEV_URL
    assert cfg.epss_url == tke.DEFAULT_EPSS_URL


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--report", "r.json", "--epss-threshold", "high"],
        ["--report", "r.json", "--epss-threshold", "1.5"],
        ["--report", "r.json", "--max-rows", "-1"],
        ["--report", "r.json", "--fail", "maybe"],
    ],
)
def test_invalid_inputs_are_config_errors(argv: list[str]) -> None:
    with pytest.raises(tke.ConfigError):
        tke.load_config(argv, {})


def test_broken_feeds_fail_the_step_with_exit_two(
    run_cli: RunCli, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    empty_kev = run_cli(FS_REPORT, kev=file_url(KEV_EMPTY_FEED))
    assert empty_kev.code == 2
    assert not empty_kev.output.exists()
    assert empty_kev.stdout.startswith("::error::")
    assert "no vulnerabilities" in empty_kev.stderr

    empty_epss = run_cli(FS_REPORT, epss=file_url(EPSS_EMPTY_FEED))
    assert empty_epss.code == 2
    assert "returned no scores" in empty_epss.stderr


def test_missing_report_fails_the_step(run_cli: RunCli, tmp_path: Path) -> None:
    result = run_cli(tmp_path / "absent.json")
    assert result.code == 2
    assert "cannot read the Trivy report" in result.stderr


def test_script_runs_as_a_plain_cli(tmp_path: Path, kev_url: str, epss_url: str) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "INPUT_"))}
    out = tmp_path / "cli.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--report",
            str(IMAGE_REPORT),
            "--kev-url",
            kev_url,
            "--epss-url",
            epss_url,
            "--output",
            str(out),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    assert completed.returncode == 1
    assert completed.stdout.startswith("# ghcr.io/example/app:1.2.3\n")
    assert "::error::" not in completed.stdout
    assert "gate failed" in completed.stderr
    assert out.exists()


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as excinfo:
        tke.main(["--version"])
    assert excinfo.value.code == 0
