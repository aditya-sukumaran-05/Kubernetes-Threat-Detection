"""Mandatory regression tests for pipeline integrity, preflight, staging, and partial-failure safety."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch
import pytest

from ml.datasets import DatasetError, build_datasets
from ml.pipeline_safety import WorkflowError, atomic_replace_file, safe_replace_dir, staging_directory
from ml.run_all import run_all
from ml.train import ExperimentError, load_config, run_experiment


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_synthetic_project(root: Path) -> dict[str, Path]:
    """Create a minimal synthetic project structure for testing."""
    root.mkdir(parents=True, exist_ok=True)
    configs_dir = root / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)

    for name, prefix in (
        ("network", "network_"),
        ("workload", "workload_"),
        ("fusion", "network_"),
    ):
        cfg = {
            "name": name,
            "dataset": f"results/ml_datasets/{name}_dataset.csv",
            "features": [f"{prefix}event_count"],
            "models": ["logistic_regression"],
            "random_seed": 42,
            "output_dir": f"results/{name}",
        }
        (configs_dir / f"{name}.json").write_text(json.dumps(cfg), encoding="utf-8")

    runs_dir = root / "experiments" / "runs" / "cluster-a" / "run-1"
    runs_dir.mkdir(parents=True, exist_ok=True)

    net_event = '{"timestamp":"2026-09-20T10:00:01Z","type":"accept","src":{"addr":"10.0.0.1","port":80},"dst":{"addr":"10.0.0.2","port":40000}}\n'
    workload_sample = "timestamp,pod,cpu_millicores,memory_mib,label\n2026-09-20T10:00:01Z,webapp,1,13,normal\n"

    (runs_dir / "net.jsonl").write_text(net_event, encoding="utf-8")
    (runs_dir / "workload.csv").write_text(workload_sample, encoding="utf-8")

    meta = {
        "experiment_id": "run-1",
        "cluster_id": "cluster-a",
        "scenario": "fusion_normal",
        "status": "validated",
        "validation": {"valid": True},
        "experiment_start_time_utc": "2026-09-20T10:00:00Z",
        "experiment_end_time_utc": "2026-09-20T10:01:00Z",
        "telemetry": {"network": "net.jsonl", "workload": "workload.csv"},
    }
    (runs_dir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")

    return {"root": root, "runs_dir": runs_dir, "configs_dir": configs_dir}


def _seed_valid_target_outputs(target: Path) -> dict[str, str]:
    """Seed existing valid target outputs and return their SHA-256 hashes."""
    target.mkdir(parents=True, exist_ok=True)
    phase1 = target / "phase1_demo"
    phase1.mkdir(parents=True, exist_ok=True)
    (phase1 / "summary.json").write_text(json.dumps({"phase": 1, "status": "existing"}), encoding="utf-8")

    datasets = target / "ml_datasets"
    datasets.mkdir(parents=True, exist_ok=True)
    (datasets / "network_dataset.csv").write_text("window_start,network_event_count,label\n", encoding="utf-8")
    (datasets / "workload_dataset.csv").write_text("window_start,workload_event_count,label\n", encoding="utf-8")
    (datasets / "fusion_dataset.csv").write_text("window_start,network_event_count,label\n", encoding="utf-8")
    (datasets / "dataset_summary.json").write_text(json.dumps({"existing": True}), encoding="utf-8")

    for exp_name in ("network", "workload", "fusion"):
        exp_dir = target / exp_name
        exp_dir.mkdir(parents=True, exist_ok=True)
        (exp_dir / "experiment.json").write_text(json.dumps({"exp": exp_name, "existing": True}), encoding="utf-8")

    (target / "ablation_comparison.csv").write_text("telemetry,model,status\n", encoding="utf-8")
    (target / "ablation_comparison.json").write_text(json.dumps({"ablation": "existing"}), encoding="utf-8")
    (target / "batch_manifest.json").write_text(json.dumps({"run_id": "old-run", "status": "completed"}), encoding="utf-8")

    hashes = {}
    for p in target.rglob("*"):
        if p.is_file():
            hashes[str(p.relative_to(target))] = _sha256(p)
    return hashes


def test_pipeline_preflight_blocks_missing_inputs(tmp_path: Path) -> None:
    empty_root = tmp_path / "empty_proj"
    empty_root.mkdir()
    with pytest.raises(WorkflowError, match="neither capture metadata.*nor runs directory"):
        run_all(empty_root)


def test_pipeline_preflight_blocks_missing_or_corrupt_configs(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    (proj["configs_dir"] / "network.json").unlink()
    with pytest.raises(WorkflowError, match="missing required configuration file"):
        run_all(proj["root"])

    # Corrupt config test
    (proj["configs_dir"] / "network.json").write_text("{invalid json", encoding="utf-8")
    with pytest.raises(WorkflowError, match="invalid configuration"):
        run_all(proj["root"])


def test_historical_outputs_remain_byte_for_byte_unchanged_when_overwrite_disabled(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    results = proj["root"] / "results"
    initial_hashes = _seed_valid_target_outputs(results)

    with pytest.raises(WorkflowError, match="Batch workflow preflight rejected"):
        run_all(proj["root"], overwrite=False)

    # Every single file in results must remain byte-for-byte identical
    current_hashes = {
        str(p.relative_to(results)): _sha256(p)
        for p in results.rglob("*")
        if p.is_file()
    }
    assert current_hashes == initial_hashes


def test_arbitrary_files_in_destination_directories_are_preserved_on_overwrite(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    results = proj["root"] / "results"
    _seed_valid_target_outputs(results)

    unrelated_file = results / "unrelated_notes.txt"
    unrelated_file.write_text("Researcher notes: do not touch", encoding="utf-8")
    unrelated_sub = results / "custom_dir" / "extra.txt"
    unrelated_sub.parent.mkdir(parents=True, exist_ok=True)
    unrelated_sub.write_text("Custom auxiliary data", encoding="utf-8")

    # Run with overwrite=True
    report = run_all(proj["root"], overwrite=True)
    assert report["status"] == "completed"

    # Arbitrary files must be 100% untouched
    assert unrelated_file.exists()
    assert unrelated_file.read_text(encoding="utf-8") == "Researcher notes: do not touch"
    assert unrelated_sub.exists()
    assert unrelated_sub.read_text(encoding="utf-8") == "Custom auxiliary data"


def test_simulated_failure_during_preprocessing_preserves_previous_artifacts(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    results = proj["root"] / "results"
    initial_hashes = _seed_valid_target_outputs(results)

    with patch("ml.run_all.run_preprocessing", side_effect=RuntimeError("Simulated failure in preprocessing")):
        with pytest.raises(RuntimeError, match="Simulated failure in preprocessing"):
            run_all(proj["root"], overwrite=True)

    current_hashes = {
        str(p.relative_to(results)): _sha256(p)
        for p in results.rglob("*")
        if p.is_file() and not p.name.startswith(".staging")
    }
    assert current_hashes == initial_hashes


def test_simulated_failure_during_dataset_generation_preserves_previous_artifacts(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    results = proj["root"] / "results"
    initial_hashes = _seed_valid_target_outputs(results)

    with patch("ml.run_all.build_datasets", side_effect=RuntimeError("Simulated failure in build_datasets")):
        with pytest.raises(RuntimeError, match="Simulated failure in build_datasets"):
            run_all(proj["root"], overwrite=True)

    current_hashes = {
        str(p.relative_to(results)): _sha256(p)
        for p in results.rglob("*")
        if p.is_file() and not p.name.startswith(".staging")
    }
    assert current_hashes == initial_hashes


def test_simulated_failure_during_evaluation_preserves_previous_artifacts(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    results = proj["root"] / "results"
    initial_hashes = _seed_valid_target_outputs(results)

    call_count = 0

    def failing_run_experiment(*args: Any, **kwargs: Any) -> list[dict[str, object]]:
        nonlocal call_count
        call_count += 1
        if call_count >= 2:
            raise RuntimeError("Simulated failure during workload experiment")
        return [{"telemetry": "network", "model": "logistic_regression", "status": "not_evaluable"}]

    with patch("ml.run_all.run_experiment", side_effect=failing_run_experiment):
        with pytest.raises(RuntimeError, match="Simulated failure during workload experiment"):
            run_all(proj["root"], overwrite=True)

    current_hashes = {
        str(p.relative_to(results)): _sha256(p)
        for p in results.rglob("*")
        if p.is_file() and not p.name.startswith(".staging")
    }
    assert current_hashes == initial_hashes


def test_simulated_failure_during_report_writing_preserves_previous_artifacts(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    results = proj["root"] / "results"
    initial_hashes = _seed_valid_target_outputs(results)

    with patch("ml.run_all.write_comparison", side_effect=RuntimeError("Simulated disk error writing comparison")):
        with pytest.raises(RuntimeError, match="Simulated disk error writing comparison"):
            run_all(proj["root"], overwrite=True)

    current_hashes = {
        str(p.relative_to(results)): _sha256(p)
        for p in results.rglob("*")
        if p.is_file() and not p.name.startswith(".staging")
    }
    assert current_hashes == initial_hashes


def test_failed_or_interrupted_run_never_marked_complete(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    custom_target = tmp_path / "fresh_run_target"

    with patch("ml.run_all.build_datasets", side_effect=RuntimeError("Abort early")):
        with pytest.raises(RuntimeError):
            run_all(proj["root"], output_dir=custom_target, overwrite=False)

    manifest_path = custom_target / "batch_manifest.json"
    assert not manifest_path.exists(), "batch_manifest.json must never exist for an aborted run"


def test_repeated_execution_in_isolated_run_dir_does_not_mix(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")

    target1 = tmp_path / "run1"
    target2 = tmp_path / "run2"

    report1 = run_all(proj["root"], output_dir=target1, run_id="run-1", overwrite=False)
    report2 = run_all(proj["root"], output_dir=target2, run_id="run-2", overwrite=False)

    assert report1["run_id"] == "run-1"
    assert report2["run_id"] == "run-2"
    assert (target1 / "batch_manifest.json").exists()
    assert (target2 / "batch_manifest.json").exists()

    manifest1 = json.loads((target1 / "batch_manifest.json").read_text(encoding="utf-8"))
    manifest2 = json.loads((target2 / "batch_manifest.json").read_text(encoding="utf-8"))
    assert manifest1["run_id"] == "run-1"
    assert manifest2["run_id"] == "run-2"


def test_run_experiment_standalone_safety_and_preflight(tmp_path: Path) -> None:
    proj = _make_synthetic_project(tmp_path / "proj")
    cfg = load_config(proj["configs_dir"] / "network.json")
    out_dir = tmp_path / "exp_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "existing_model.joblib").write_text("old model", encoding="utf-8")

    # 1. Non-destructive default blocks execution when non-empty
    ds_path = tmp_path / "dummy_ds.csv"
    ds_path.write_text("window_start,network_event_count,session_id,label\n", encoding="utf-8")
    with pytest.raises(ExperimentError, match="already exists and is non-empty"):
        run_experiment(cfg, proj["root"], overwrite=False, dataset_path=ds_path, output_dir=out_dir)

    # 2. Existing file untouched
    assert (out_dir / "existing_model.joblib").read_text(encoding="utf-8") == "old model"


def test_build_datasets_failure_leaves_existing_datasets_untouched(tmp_path: Path) -> None:
    proc_dir = tmp_path / "processed"
    proc_dir.mkdir(parents=True, exist_ok=True)
    out_dir = tmp_path / "datasets_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "network_dataset.csv").write_text("original network", encoding="utf-8")
    (out_dir / "workload_dataset.csv").write_text("original workload", encoding="utf-8")

    # Calling with empty processed_dir causes DatasetError
    with pytest.raises(DatasetError, match="no processed feature files found"):
        build_datasets(proc_dir, out_dir, overwrite=True)

    # Original files remain completely untouched
    assert (out_dir / "network_dataset.csv").read_text(encoding="utf-8") == "original network"
    assert (out_dir / "workload_dataset.csv").read_text(encoding="utf-8") == "original workload"
