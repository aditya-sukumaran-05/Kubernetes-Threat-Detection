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


def test_cluster_provenance_propagates_to_ml_datasets_and_feature_isolation(tmp_path: Path) -> None:
    from experiments.metadata import CaptureMetadata, LabelInterval, assign_labels
    from ml.datasets import CONTEXT_COLUMNS, build_datasets, read_csv
    from telemetry.schemas import parse_utc_timestamp

    processed_dir = tmp_path / "processed"
    processed_dir.mkdir(parents=True)
    out_dir = tmp_path / "out"

    # 1. CaptureMetadata with explicit non-minikube cluster_id
    interval = LabelInterval(
        parse_utc_timestamp("2026-09-20T10:00:00Z"),
        parse_utc_timestamp("2026-09-20T10:01:00Z"),
        "attack",
        "network_attack",
    )
    capture = CaptureMetadata(
        capture_id="run_b_network",
        source="network",
        path="network.jsonl",
        session_id="run-b",
        description="Cluster B run",
        label_intervals=(interval,),
        scenario="network_attack",
        cluster_id="cluster-b-constrained",
    )

    # 2. Assign labels retains cluster_id
    raw_rows = [{
        "window_start": "2026-09-20T10:00:00Z",
        "window_end": "2026-09-20T10:00:10Z",
        "network_event_count": 5,
    }]
    labeled_rows = assign_labels(raw_rows, capture)
    assert labeled_rows[0]["cluster_id"] == "cluster-b-constrained"

    # Write processed rows for cluster B and a minikube normal run
    import csv
    def write_csv(p: Path, rows: list[dict]):
        with p.open("w", newline="", encoding="utf-8") as h:
            writer = csv.DictWriter(h, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    write_csv(processed_dir / "run_b_network.csv", labeled_rows)
    write_csv(processed_dir / "run_a_network.csv", [{
        "window_start": "2026-09-20T10:00:00Z",
        "window_end": "2026-09-20T10:00:10Z",
        "cluster_id": "minikube",
        "capture_id": "run_a_network",
        "session_id": "run-a",
        "scenario": "network_normal",
        "telemetry_source": "network",
        "label": "normal",
        "attack_type": "normal",
        "network_event_count": 2,
    }])

    # 3. Build datasets
    summaries = build_datasets(processed_dir, out_dir)
    assert summaries["network"].labeled_rows == 2
    assert summaries["network"].cluster_counts == {"cluster-b-constrained": 1, "minikube": 1}

    # 4. Read back CSV and verify cluster_id column is present and correct
    ds_rows = read_csv(out_dir / "network_dataset.csv")
    assert len(ds_rows) == 2
    clusters = {r["session_id"]: r["cluster_id"] for r in ds_rows}
    assert clusters["run-b"] == "cluster-b-constrained"
    assert clusters["run-a"] == "minikube"

    # 5. Verify cluster_id is in CONTEXT_COLUMNS and NOT in features
    assert "cluster_id" in CONTEXT_COLUMNS
    assert "cluster_id" not in summaries["network"].features
    for f in summaries["network"].features:
        assert f.startswith("network_")


def test_preprocessing_non_destructive_directory_protection(tmp_path: Path) -> None:
    from experiments.run_preprocessing import PreprocessingError, run as run_preprocessing

    # Setup dummy legacy captures.json and synthetic capture file
    cap_dir = tmp_path / "telemetry" / "data"
    cap_dir.mkdir(parents=True)
    net_file = cap_dir / "net.jsonl"
    net_file.write_text('{"timestamp":"2026-09-20T10:00:01Z","type":"accept","src":{"addr":"10.0.0.1","port":80},"dst":{"addr":"10.0.0.2","port":40000}}\n', encoding="utf-8")

    meta_file = tmp_path / "captures.json"
    meta_content = {
        "captures": [{
            "id": "cap1",
            "source": "network",
            "path": str(net_file.relative_to(tmp_path)),
            "session_id": "sess1",
            "label_intervals": [{"start": "2026-09-20T10:00:00Z", "end": "2026-09-20T10:01:00Z", "label": "normal", "attack_type": "normal"}],
        }]
    }
    meta_file.write_text(json.dumps(meta_content), encoding="utf-8")

    out_dir = tmp_path / "out"

    # First run without overwrite succeeds
    summary1 = run_preprocessing(meta_file, out_dir, runs_dir=None, overwrite=False)
    assert "cap1" in summary1["captures"]
    out_csv = out_dir / "processed" / "cap1.csv"
    assert out_csv.exists()
    original_sha256 = summary1["captures"]["cap1"]["sha256"]

    # Second run without overwrite must fail safely with PreprocessingError
    with pytest.raises(PreprocessingError, match="already contains data"):
        run_preprocessing(meta_file, out_dir, runs_dir=None, overwrite=False)

    # Verify existing output is byte-for-byte unchanged
    import hashlib
    assert hashlib.sha256(out_csv.read_bytes()).hexdigest() == original_sha256

    # Run with explicit overwrite=True succeeds
    summary2 = run_preprocessing(meta_file, out_dir, runs_dir=None, overwrite=True)
    assert "cap1" in summary2["captures"]


def test_preprocessing_cluster_filtering_and_provenance(tmp_path: Path) -> None:
    from experiments.run_preprocessing import PreprocessingError, run as run_preprocessing

    runs_dir = tmp_path / "runs"
    run_a = runs_dir / "cluster_a" / "run-a"
    run_b = runs_dir / "cluster_b" / "run-b"
    run_a.mkdir(parents=True)
    run_b.mkdir(parents=True)

    event_line = '{"timestamp":"2026-09-20T10:00:01Z","type":"accept","src":{"addr":"10.0.0.1","port":80},"dst":{"addr":"10.0.0.2","port":40000}}\n'
    (run_a / "net.jsonl").write_text(event_line, encoding="utf-8")
    (run_b / "net.jsonl").write_text(event_line, encoding="utf-8")

    def make_meta(exp_id: str, cluster: str):
        return {
            "experiment_id": exp_id,
            "cluster_id": cluster,
            "scenario": "network_normal",
            "status": "validated",
            "validation": {"valid": True},
            "experiment_start_time_utc": "2026-09-20T10:00:00Z",
            "experiment_end_time_utc": "2026-09-20T10:01:00Z",
            "telemetry": {"network": "net.jsonl"},
        }

    (run_a / "metadata.json").write_text(json.dumps(make_meta("run-a", "cluster-a")), encoding="utf-8")
    (run_b / "metadata.json").write_text(json.dumps(make_meta("run-b", "cluster-b")), encoding="utf-8")

    # Preprocessing with cluster_id="cluster-a" only processes cluster-a
    out_a = tmp_path / "out_a"
    summary_a = run_preprocessing(None, out_a, runs_dir=runs_dir, cluster_id="cluster-a")
    assert "run-a_network" in summary_a["captures"]
    assert "run-b_network" not in summary_a["captures"]
    assert summary_a["cluster_counts"] == {"cluster-a": 1}

    # Preprocessing with non-existent cluster raises PreprocessingError
    out_c = tmp_path / "out_c"
    with pytest.raises(PreprocessingError, match="no captures discovered"):
        run_preprocessing(None, out_c, runs_dir=runs_dir, cluster_id="non-existent")


def test_build_datasets_non_destructive_and_cluster_filtering(tmp_path: Path) -> None:
    import csv
    from ml.datasets import DatasetError, build_datasets, read_csv

    proc_dir = tmp_path / "processed"
    proc_dir.mkdir(parents=True)
    out_dir = tmp_path / "datasets"

    def write_csv(p: Path, rows: list[dict]):
        with p.open("w", newline="", encoding="utf-8") as h:
            writer = csv.DictWriter(h, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    row_a = {
        "window_start": "2026-09-20T10:00:00Z",
        "window_end": "2026-09-20T10:00:10Z",
        "cluster_id": "cluster-a",
        "capture_id": "cap_a",
        "session_id": "sess_a",
        "scenario": "network_normal",
        "telemetry_source": "network",
        "label": "normal",
        "attack_type": "normal",
        "network_event_count": 2,
    }
    row_b = {
        "window_start": "2026-09-20T10:00:00Z",
        "window_end": "2026-09-20T10:00:10Z",
        "cluster_id": "cluster-b",
        "capture_id": "cap_b",
        "session_id": "sess_b",
        "scenario": "network_normal",
        "telemetry_source": "network",
        "label": "normal",
        "attack_type": "normal",
        "network_event_count": 3,
    }
    write_csv(proc_dir / "cap_a.csv", [row_a])
    write_csv(proc_dir / "cap_b.csv", [row_b])

    # First build
    build_datasets(proc_dir, out_dir, overwrite=True)
    assert (out_dir / "network_dataset.csv").exists()

    # Attempt build with overwrite=False fails safely
    with pytest.raises(DatasetError, match="already contains dataset files"):
        build_datasets(proc_dir, out_dir, overwrite=False)

    # Filtered build by cluster_id
    out_cluster_b = tmp_path / "datasets_b"
    summaries_b = build_datasets(proc_dir, out_cluster_b, cluster_id="cluster-b")
    assert summaries_b["network"].cluster_counts == {"cluster-b": 1}
    ds_b_rows = read_csv(out_cluster_b / "network_dataset.csv")
    assert len(ds_b_rows) == 1
    assert ds_b_rows[0]["cluster_id"] == "cluster-b"
