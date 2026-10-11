"""Regression tests for multi-cluster orchestration, context validation, and output isolation."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.manifest import build_manifest
from experiments.metadata import load_run_capture_metadata
from experiments.orchestration import (
    RunMetadata,
    experiment_id,
    kubernetes_context_is_active,
    minikube_context_is_active,
    write_metadata,
)
from experiments.run_experiment import run_scenario, validate_experiment_preflight


def _sample_config(cluster_override: dict | None = None, config_override: dict | None = None) -> dict:
    cluster = {
        "expected_context": "minikube",
        "namespace": "default",
        "target_label": "app=webapp",
        "target_workload": "deployment/webapp",
    }
    if cluster_override:
        cluster.update(cluster_override)
    cfg = {
        "cluster": cluster,
        "output_directory": "experiments/runs",
        "collectors": {
            "network_gadget_version": "v0.55.1",
            "workload_interval_seconds": 5,
        },
        "scenarios": {
            "network_normal": {
                "label": "normal",
                "warmup_seconds": 1,
                "activity_seconds": 1,
                "cooldown_seconds": 1,
                "network_activity": "low",
                "workload_activity": "baseline",
                "network_requests": 1,
                "request_delay_seconds": 1,
            },
        },
    }
    if config_override:
        cfg.update(config_override)
    return cfg


def test_kubernetes_context_validation_exact_and_rejection() -> None:
    def context_mock(desired_context: str):
        return lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=f"{desired_context}\n")

    assert kubernetes_context_is_active("cluster-a", run=context_mock("cluster-a"))
    assert not kubernetes_context_is_active("cluster-a", run=context_mock("cluster-b"))
    assert not kubernetes_context_is_active("cluster-a", run=context_mock("production"))

    # Alias minikube_context_is_active works equivalently
    assert minikube_context_is_active("minikube", run=context_mock("minikube"))
    assert not minikube_context_is_active("minikube", run=context_mock("other"))


def test_incorrect_context_rejection_in_run_scenario(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _sample_config(cluster_override={"expected_context": "cluster-b-constrained", "cluster_id": "cluster-b"})

    # Active context is minikube, but config expects cluster-b-constrained
    monkeypatch.setattr(
        "experiments.orchestration.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="minikube\n"),
    )

    with pytest.raises(RuntimeError, match="active Kubernetes context is not cluster-b-constrained"):
        run_scenario(cfg, "network_normal", tmp_path, execute=True)

    # Verify metadata recorded refusal
    run_dirs = list((tmp_path / "experiments" / "runs" / "cluster-b").glob("*"))
    assert len(run_dirs) == 1
    metadata = json.loads((run_dirs[0] / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "refused_unexpected_context"
    assert "refused: active Kubernetes context did not equal configured context 'cluster-b-constrained'" in metadata["events"][-1]["event"]


def test_incorrect_minikube_context_rejection_backward_compatible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _sample_config(cluster_override={"expected_context": "minikube"})

    # Active context is production, expecting minikube
    monkeypatch.setattr(
        "experiments.orchestration.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="production\n"),
    )

    with pytest.raises(RuntimeError, match="active Kubernetes context is not minikube"):
        run_scenario(cfg, "network_normal", tmp_path, execute=True)

    run_dirs = list((tmp_path / "experiments" / "runs").glob("*"))
    assert len(run_dirs) == 1
    metadata = json.loads((run_dirs[0] / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "refused_non_minikube_context"


def test_missing_cluster_metadata_rejected(tmp_path: Path) -> None:
    # 1. Missing entire cluster section
    cfg_no_cluster = _sample_config()
    del cfg_no_cluster["cluster"]
    with pytest.raises(KeyError, match="Missing required configuration section: 'cluster'"):
        validate_experiment_preflight(cfg_no_cluster, "network_normal", tmp_path)

    # 2. Missing required cluster fields
    for field in ("expected_context", "namespace", "target_workload"):
        cfg_missing_field = _sample_config()
        del cfg_missing_field["cluster"][field]
        with pytest.raises(KeyError, match=f"Missing required cluster field: '{field}'"):
            validate_experiment_preflight(cfg_missing_field, "network_normal", tmp_path)

    # 3. Invalid cluster_id (uppercase, path traversal, shell characters)
    for bad_id in ("ClusterA", "../escape", "cluster;rm", "cluster id"):
        cfg_bad_id = _sample_config(cluster_override={"cluster_id": bad_id})
        with pytest.raises(ValueError):
            validate_experiment_preflight(cfg_bad_id, "network_normal", tmp_path)

    # 4. Invalid cluster_profile (empty or invalid characters)
    cfg_empty_profile = _sample_config(cluster_override={"cluster_profile": "   "})
    with pytest.raises(ValueError, match="cluster_profile must be a non-empty string"):
        validate_experiment_preflight(cfg_empty_profile, "network_normal", tmp_path)


def test_output_directory_isolation_for_multi_cluster(tmp_path: Path) -> None:
    cfg_cluster_b = _sample_config(cluster_override={
        "cluster_id": "cluster-b-constrained",
        "expected_context": "cluster-b-constrained",
        "cluster_profile": "constrained",
    })
    cfg_cluster_c = _sample_config(cluster_override={
        "cluster_id": "cluster-c-hardened",
        "expected_context": "cluster-c-hardened",
        "cluster_profile": "hardened",
    })

    plan_b = validate_experiment_preflight(cfg_cluster_b, "network_normal", tmp_path)
    plan_c = validate_experiment_preflight(cfg_cluster_c, "network_normal", tmp_path)

    # Each plan is isolated in its respective cluster subdirectory
    assert plan_b.canonical_run_dir.parent == (tmp_path / "experiments" / "runs" / "cluster-b-constrained").resolve()
    assert plan_c.canonical_run_dir.parent == (tmp_path / "experiments" / "runs" / "cluster-c-hardened").resolve()

    # The paths are strictly disjoint
    assert plan_b.canonical_run_dir.parent != plan_c.canonical_run_dir.parent
    assert "cluster_b_constrained" in plan_b.canonical_run_dir.name
    assert "cluster_c_hardened" in plan_c.canonical_run_dir.name


def test_legacy_single_cluster_output_directory_compatibility(tmp_path: Path) -> None:
    # 1. Config without cluster_id defaults to flat directory under output_root
    cfg_legacy = _sample_config()
    plan_legacy = validate_experiment_preflight(cfg_legacy, "network_normal", tmp_path)
    assert plan_legacy.canonical_run_dir.parent == (tmp_path / "experiments" / "runs").resolve()
    assert plan_legacy.cluster_id == "minikube"
    assert plan_legacy.cluster_profile == "baseline"

    # 2. Config with isolate_by_cluster=False retains flat directory even with custom cluster_id
    cfg_flat = _sample_config(
        cluster_override={"cluster_id": "cluster-custom"},
        config_override={"isolate_by_cluster": False},
    )
    plan_flat = validate_experiment_preflight(cfg_flat, "network_normal", tmp_path)
    assert plan_flat.canonical_run_dir.parent == (tmp_path / "experiments" / "runs").resolve()

    # 3. Config with isolate_by_cluster=True forces cluster subdirectory even for minikube
    cfg_isolated_minikube = _sample_config(
        config_override={"isolate_by_cluster": True},
    )
    plan_isolated = validate_experiment_preflight(cfg_isolated_minikube, "network_normal", tmp_path)
    assert plan_isolated.canonical_run_dir.parent == (tmp_path / "experiments" / "runs" / "minikube").resolve()


def test_run_metadata_persists_cluster_provenance(tmp_path: Path) -> None:
    cfg = _sample_config(cluster_override={
        "cluster_id": "cluster-b-constrained",
        "expected_context": "cluster-b-constrained",
        "cluster_profile": "constrained",
        "node_count": 2,
    })
    run_dir, metadata = run_scenario(cfg, "network_normal", tmp_path, execute=False)

    assert metadata.cluster_id == "cluster-b-constrained"
    assert metadata.cluster_metadata["cluster_profile"] == "constrained"
    assert metadata.cluster_metadata["node_count"] == 2
    assert metadata.cluster_metadata["expected_context"] == "cluster-b-constrained"

    saved_json = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
    assert saved_json["cluster_id"] == "cluster-b-constrained"
    assert saved_json["cluster_metadata"]["cluster_profile"] == "constrained"
    assert saved_json["cluster_metadata"]["node_count"] == 2


def test_multi_cluster_run_capture_discovery_and_manifest(tmp_path: Path) -> None:
    runs_dir = tmp_path / "experiments" / "runs"

    # Run 1: Flat baseline run
    run1_dir = runs_dir / "run-1"
    run1_dir.mkdir(parents=True)
    (run1_dir / "network.jsonl").write_text('{"timestamp":"2026-09-20T10:00:01Z","type":"accept","src":{"addr":"10.0.0.1","port":80},"dst":{"addr":"10.0.0.2","port":40000}}\n', encoding="utf-8")
    (run1_dir / "workload.csv").write_text("timestamp,pod,cpu_millicores,memory_mib,label\n2026-09-20T10:00:01Z,webapp,1,13,normal\n", encoding="utf-8")
    meta1 = {
        "experiment_id": "run-1",
        "cluster_id": "minikube",
        "scenario": "network_normal",
        "status": "validated",
        "validation": {"valid": True},
        "experiment_start_time_utc": "2026-09-20T10:00:00Z",
        "experiment_end_time_utc": "2026-09-20T10:01:00Z",
        "telemetry": {"network": "network.jsonl", "workload": "workload.csv"},
    }
    (run1_dir / "metadata.json").write_text(json.dumps(meta1), encoding="utf-8")

    # Run 2: Nested cluster_b run
    run2_dir = runs_dir / "cluster_b" / "run-2"
    run2_dir.mkdir(parents=True)
    (run2_dir / "network.jsonl").write_text('{"timestamp":"2026-09-20T10:00:01Z","type":"accept","src":{"addr":"10.0.0.1","port":80},"dst":{"addr":"10.0.0.2","port":40000}}\n', encoding="utf-8")
    (run2_dir / "workload.csv").write_text("timestamp,pod,cpu_millicores,memory_mib,label\n2026-09-20T10:00:01Z,webapp,1,13,normal\n", encoding="utf-8")
    meta2 = {
        "experiment_id": "run-2",
        "cluster_id": "cluster-b-constrained",
        "scenario": "network_normal",
        "status": "validated",
        "validation": {"valid": True},
        "experiment_start_time_utc": "2026-09-20T10:00:00Z",
        "experiment_end_time_utc": "2026-09-20T10:01:00Z",
        "telemetry": {"network": "network.jsonl", "workload": "workload.csv"},
    }
    (run2_dir / "metadata.json").write_text(json.dumps(meta2), encoding="utf-8")

    # 1. Capture metadata discovers both runs and assigns cluster_id
    captures = load_run_capture_metadata(runs_dir)
    cluster_by_session = {c.session_id: c.cluster_id for c in captures}
    assert cluster_by_session["run-1"] == "minikube"
    assert cluster_by_session["run-2"] == "cluster-b-constrained"

    # 2. Build manifest discovers both runs with cluster_id
    manifest_path = tmp_path / "manifest.json"
    manifest = build_manifest(runs_dir, manifest_path)
    assert manifest["count"] == 2
    manifest_clusters = {e["experiment_id"]: e["cluster_id"] for e in manifest["experiments"]}
    assert manifest_clusters["run-1"] == "minikube"
    assert manifest_clusters["run-2"] == "cluster-b-constrained"
