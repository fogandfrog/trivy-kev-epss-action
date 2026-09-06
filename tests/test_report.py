"""Report parsing: the three shapes, deduplication, workload aggregation, ignored classes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import trivy_kev_epss as tke
from tests.conftest import FS_REPORT, IMAGE_REPORT, K8S_REPORT, vulnerability, write_report


def test_fs_report_is_parsed_and_deduplicated() -> None:
    report = tke.load_report(FS_REPORT)
    assert report.artifact_type == "filesystem"
    assert report.trivy_schema_version == 2
    assert report.kubernetes is False
    ids = sorted(f.id for f in report.findings)
    # CVE-2026-48710 appears twice in the fixture (two severity sources) and once here.
    assert ids == [
        "CVE-2025-10001",
        "CVE-2025-10002",
        "CVE-2025-10003",
        "CVE-2026-48710",
        "CVE-2026-99999",
        "GHSA-59g5-xgcq-4qw3",
    ]
    starlette = next(f for f in report.findings if f.id == "CVE-2026-48710")
    assert starlette.package == "starlette"
    assert starlette.installed_version == "1.0.0"
    assert starlette.fixed_version == "1.0.1"
    assert starlette.fixable is True
    assert starlette.severity == "MEDIUM"
    assert starlette.targets == ["uv.lock"]
    assert starlette.workloads == []


def test_secret_and_config_results_are_ignored() -> None:
    report = tke.load_report(FS_REPORT)
    assert all("Dockerfile" not in f.targets for f in report.findings)
    assert all("config/.env" not in f.targets for f in report.findings)


def test_image_report_keeps_both_layers() -> None:
    report = tke.load_report(IMAGE_REPORT)
    assert report.artifact_name == "ghcr.io/example/app:1.2.3"
    assert report.artifact_type == "container_image"
    by_id = {f.id: f for f in report.findings}
    assert by_id["CVE-2025-20001"].fixable is False
    assert by_id["CVE-2025-20001"].status == "affected"
    assert by_id["CVE-2020-11023"].targets == ["app/package-lock.json"]
    assert by_id["CVE-2020-11023"].package == "jquery"


def test_k8s_report_aggregates_workloads() -> None:
    report = tke.load_report(K8S_REPORT)
    assert report.kubernetes is True
    assert report.artifact_name == "kind-example"
    assert report.artifact_type == "kubernetes"
    by_id = {f.id: f for f in report.findings}
    assert len(by_id) == 2
    assert by_id["CVE-2025-20002"].workloads == ["default/Deployment/api", "default/Deployment/web"]
    assert by_id["CVE-2025-20002"].targets == ["nginx:1.25.0 (debian 12.2)"]
    assert by_id["CVE-2025-20003"].workloads == ["default/Deployment/api"]


def test_older_k8s_wrapper_with_vulnerabilities_key(tmp_path: Path) -> None:
    resources = json.loads(K8S_REPORT.read_text())["Resources"]
    legacy = tmp_path / "k8s-legacy.json"
    legacy.write_text(json.dumps({"ClusterName": "legacy", "Vulnerabilities": resources}))
    report = tke.load_report(legacy)
    assert report.kubernetes is True
    assert sorted(f.id for f in report.findings) == ["CVE-2025-20002", "CVE-2025-20003"]


def test_cluster_scoped_workload_has_no_namespace() -> None:
    resource = {"Kind": "Node", "Name": "worker-1"}
    assert tke._workload_label(resource) == "Node/worker-1"


def test_empty_results_are_an_empty_report(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text(
        json.dumps({"SchemaVersion": 2, "ArtifactName": "x", "ArtifactType": "filesystem"})
    )
    report = tke.load_report(path)
    assert report.findings == []


def test_unrecognised_shape_is_a_report_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(tke.ReportError):
        tke.load_report(path)
    path.write_text("not json")
    with pytest.raises(tke.ReportError):
        tke.load_report(path)
    with pytest.raises(tke.ReportError):
        tke.load_report(tmp_path / "missing.json")


def test_dedup_key_includes_target_and_version(tmp_path: Path) -> None:
    path = write_report(
        tmp_path / "dup.json",
        [
            {
                "Target": "a/requirements.txt",
                "Class": "lang-pkgs",
                "Vulnerabilities": [
                    vulnerability("CVE-2025-10001"),
                    vulnerability("CVE-2025-10001"),
                    vulnerability("CVE-2025-10001", installed="0.9.0"),
                ],
            },
            {
                "Target": "b/requirements.txt",
                "Class": "lang-pkgs",
                "Vulnerabilities": [vulnerability("CVE-2025-10001")],
            },
        ],
    )
    report = tke.load_report(path)
    assert len(report.findings) == 3
