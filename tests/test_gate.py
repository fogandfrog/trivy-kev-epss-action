"""Gate rules, end to end through the CLI against the offline feeds."""

from __future__ import annotations

from tests.conftest import FS_REPORT, IMAGE_REPORT, K8S_REPORT, RunCli


def test_both_medium_kev_cves_fail(run_cli: RunCli) -> None:
    fs = run_cli(FS_REPORT)
    assert fs.code == 1
    starlette = fs.finding("CVE-2026-48710")
    assert starlette["severity"] == "MEDIUM"
    assert starlette["kev"] == {"listed": True, "dateAdded": "2026-09-02", "ransomware": "Unknown"}
    assert starlette["epss"]["score"] > 0.36
    assert starlette["gate"] == {"fail": True, "reasons": ["kev", "epss"]}

    image = run_cli(IMAGE_REPORT)
    assert image.code == 1
    jquery = image.finding("CVE-2020-11023")
    assert jquery["severity"] == "MEDIUM"
    assert jquery["kev"]["listed"] is True
    assert jquery["kev"]["dateAdded"] == "2025-01-23"
    assert jquery["epss"]["score"] > 0.8
    assert jquery["gate"] == {"fail": True, "reasons": ["kev", "epss"]}
    assert image.document["gate"] == {
        "result": "fail",
        "failing": 1,
        "total": 2,
        "kev": 1,
        "epssAboveThreshold": 1,
    }


def test_unfixed_high_passes_and_fixable_high_fails(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    unfixed = result.finding("CVE-2025-10002")
    assert unfixed["fixable"] is False
    assert unfixed["fixedVersion"] is None
    assert unfixed["gate"] == {"fail": False, "reasons": []}
    fixable = result.finding("CVE-2025-10001")
    assert fixable["fixable"] is True
    assert fixable["gate"] == {"fail": True, "reasons": ["severity"]}


def test_severity_gate_unfixed_extends_to_unfixed_findings(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT, "--severity-gate-unfixed", "true")
    assert result.finding("CVE-2025-10002")["gate"] == {"fail": True, "reasons": ["severity"]}


def test_non_kev_cve_above_threshold_fails(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    finding = result.finding("CVE-2025-10003")
    assert finding["kev"]["listed"] is False
    assert finding["severity"] == "MEDIUM"
    assert finding["gate"] == {"fail": True, "reasons": ["epss"]}
    raised = run_cli(FS_REPORT, "--epss-threshold", "0.6")
    assert raised.finding("CVE-2025-10003")["gate"]["fail"] is False


def test_ghsa_only_id_follows_the_severity_rule(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    ghsa = result.finding("GHSA-59g5-xgcq-4qw3")
    assert ghsa["kev"] == {"listed": False, "dateAdded": None, "ransomware": None}
    assert ghsa["epss"] == {"score": None, "percentile": None, "date": None}
    assert ghsa["gate"] == {"fail": True, "reasons": ["severity"]}

    relaxed = run_cli(FS_REPORT, "--fail-on-severity", "")
    assert relaxed.finding("GHSA-59g5-xgcq-4qw3")["gate"]["fail"] is False
    assert relaxed.finding("CVE-2025-10001")["gate"]["fail"] is False
    assert relaxed.document["policy"]["failOnSeverity"] == []


def test_cve_absent_from_epss_is_na_and_passes(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    finding = result.finding("CVE-2026-99999")
    assert finding["epss"] == {"score": None, "percentile": None, "date": None}
    assert finding["gate"]["fail"] is False
    assert "| n/a |" in result.stdout


def test_kev_and_epss_rules_can_be_disabled(run_cli: RunCli) -> None:
    result = run_cli(
        IMAGE_REPORT, "--fail-on-kev", "false", "--fail-on-epss", "false", "--fail-on-severity", ""
    )
    assert result.code == 0
    assert result.document["gate"]["result"] == "pass"
    # Enrichment still happens: the counts and the KEV flag are reported, only the verdict changes.
    assert result.document["gate"]["kev"] == 1
    assert result.finding("CVE-2020-11023")["kev"]["listed"] is True


def test_k8s_report_gates_the_shared_finding_once(run_cli: RunCli) -> None:
    result = run_cli(K8S_REPORT)
    assert result.code == 1
    assert result.document["gate"] == {
        "result": "fail",
        "failing": 1,
        "total": 2,
        "kev": 0,
        "epssAboveThreshold": 0,
    }
    shared = result.finding("CVE-2025-20002")
    assert shared["workloads"] == ["default/Deployment/api", "default/Deployment/web"]
    assert shared["gate"]["reasons"] == ["severity"]


def test_counts_in_the_document_match_the_fs_fixture(run_cli: RunCli) -> None:
    result = run_cli(FS_REPORT)
    assert result.document["gate"] == {
        "result": "fail",
        "failing": 4,
        "total": 6,
        "kev": 1,
        "epssAboveThreshold": 2,
    }
    assert result.document["policy"] == {
        "epssThreshold": 0.1,
        "failOnKev": True,
        "failOnEpss": True,
        "failOnSeverity": ["CRITICAL", "HIGH"],
        "severityGateUnfixed": False,
    }
