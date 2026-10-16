"""Comprehensive integration and regression tests for Multimodal Runtime ML.

Validates the full target capability matrix across all 7 modalities:
1. network (Network-Only: 13 features)
2. workload (Workload-Only: 11 features)
3. runtime (Runtime-Only: 9 features)
4. fusion (Network + Workload: 24 features)
5. net_rt (Network + Runtime: 22 features)
6. rt_wl (Runtime + Workload: 20 features)
7. full_fusion (Network + Workload + Runtime: 33 features)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

from dashboard.live_engine import LiveWindowRecord
from dashboard.telemetry_provider import CapturedDatasetProvider
from ml.inference import InferenceResult, ThreatDetector
from telemetry.features.runtime import extract_runtime_features
from telemetry.schemas import NetworkEvent, RuntimeEvent, WorkloadSample


ALL_7_MODALITIES = [
    "network",
    "workload",
    "fusion",
    "runtime",
    "net_rt",
    "rt_wl",
    "full_fusion",
]

EXPECTED_FEATURE_COUNTS = {
    "network": 13,
    "workload": 11,
    "fusion": 24,
    "runtime": 9,
    "net_rt": 22,
    "rt_wl": 20,
    "full_fusion": 33,
}


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def detector(repo_root: Path) -> ThreatDetector:
    return ThreatDetector(project_root=repo_root)


def test_multimodal_capability_matrix_configs(repo_root: Path) -> None:
    """Verify that all 7 modality configuration files exist and match the feature matrix."""
    configs_dir = repo_root / "configs"
    for modality in ALL_7_MODALITIES:
        cfg_path = configs_dir / f"{modality}.json"
        assert cfg_path.exists(), f"Configuration file missing: {cfg_path}"
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        assert cfg["name"] == modality
        assert len(cfg["features"]) == EXPECTED_FEATURE_COUNTS[modality], (
            f"Feature count mismatch for {modality}: got {len(cfg['features'])}, "
            f"expected {EXPECTED_FEATURE_COUNTS[modality]}"
        )
        assert set(cfg["models"]) == {"random_forest", "xgboost", "svm"}


def test_multimodal_datasets_presence_and_integrity(repo_root: Path) -> None:
    """Verify that all 7 dataset files exist with valid columns, labels, and summaries."""
    ds_dir = repo_root / "results" / "ml_datasets"
    summary_path = ds_dir / "dataset_summary.json"
    assert summary_path.exists(), "dataset_summary.json missing"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    for modality in ALL_7_MODALITIES:
        ds_path = ds_dir / f"{modality}_dataset.csv"
        assert ds_path.exists(), f"Dataset file missing: {ds_path}"
        df = pd.read_csv(ds_path)
        assert len(df) > 0, f"Dataset {modality} is empty"
        assert "label" in df.columns
        assert "session_id" in df.columns
        assert set(df["label"].unique()).issubset({"normal", "attack"})

        # Summary check
        assert modality in summary, f"{modality} missing from dataset_summary.json"
        s = summary[modality]
        assert s["labeled_rows"] == len(df)
        assert s["labeled_rows"] == len(df[df["label"].isin(["normal", "attack"])])


def test_trained_model_artifacts_for_all_modalities(repo_root: Path) -> None:
    """Verify that trained model checkpoints (.joblib) exist for all 7 modalities."""
    results_dir = repo_root / "results"
    for modality in ALL_7_MODALITIES:
        mod_dir = results_dir / modality / "models"
        assert mod_dir.exists(), f"Models directory missing: {mod_dir}"
        for model_name in ("random_forest", "xgboost", "svm"):
            joblib_path = mod_dir / f"{model_name}.joblib"
            assert joblib_path.exists(), f"Checkpoint missing: {joblib_path}"
            assert joblib_path.stat().st_size > 500, f"Checkpoint suspiciously small: {joblib_path}"


def test_loso_cross_validation_evaluation_artifacts(repo_root: Path) -> None:
    """Verify that LOSO cross-validation artifacts cover all 7 modalities."""
    loso_dir = repo_root / "results" / "loso"
    agg_csv = loso_dir / "loso_aggregate_comparison.csv"
    assert agg_csv.exists(), "loso_aggregate_comparison.csv missing"
    df = pd.read_csv(agg_csv)

    for modality in ALL_7_MODALITIES:
        mod_rows = df[df["telemetry"] == modality]
        assert len(mod_rows) == 3, f"Expected 3 model rows for {modality} in LOSO table, found {len(mod_rows)}"
        for _, row in mod_rows.iterrows():
            assert row["total_samples"] > 0
            assert row["total_folds"] > 0
            assert 0.0 <= float(row["aggregate_f1"]) <= 1.0
            assert 0.0 <= float(row["aggregate_precision"]) <= 1.0
            assert 0.0 <= float(row["aggregate_recall"]) <= 1.0
            assert 0.0 <= float(row["aggregate_false_positive_rate"]) <= 1.0


def test_threat_detector_inference_all_7_modalities(detector: ThreatDetector, repo_root: Path) -> None:
    """Verify that ThreatDetector successfully evaluates samples across all 7 modalities."""
    assert set(detector.SUPPORTED_MODALITIES) == set(ALL_7_MODALITIES)
    ds_dir = repo_root / "results" / "ml_datasets"

    for modality in ALL_7_MODALITIES:
        df = pd.read_csv(ds_dir / f"{modality}_dataset.csv")
        sample_win = df.iloc[0].to_dict()
        sample_win["affected_pods"] = "webapp-test-pod"

        for model_name in ("random_forest", "xgboost", "svm"):
            res = detector.predict(sample_win, modality=modality, model_name=model_name)
            assert isinstance(res, InferenceResult)
            assert res.predicted_label in ("normal", "attack")
            assert res.modality == modality
            assert res.model_name == model_name
            assert res.confidence is not None
            assert 0.0 <= res.confidence <= 1.0
            if res.attack_probability is not None:
                assert 0.0 <= res.attack_probability <= 1.0
            assert "feature_values" in res.evidence


def test_threat_detector_convenience_methods(detector: ThreatDetector) -> None:
    """Test dedicated convenience methods for runtime, net_rt, rt_wl, and full_fusion."""
    # Create sample events
    raw_rt = {
        "timestamp": "2026-10-14T10:00:01.000Z",
        "args": "/bin/bash -i",
        "cwd": "/",
        "exepath": "/bin/bash",
        "proc": {
            "comm": "bash",
            "pid": 1234,
            "tid": 1234,
            "creds": {"uid": 0, "gid": 0, "user": "root"},
            "parent": {"comm": "containerd-shim", "pid": 500},
        },
        "k8s": {"podName": "webapp-pod", "namespace": "default", "containerName": "nginx"},
        "runtime": {"containerId": "c1"},
        "error": "",
    }
    rt_event = RuntimeEvent.from_raw(raw_rt)

    raw_net = {
        "timestamp": "2026-10-14T10:00:02.000Z",
        "type": "accept",
        "src": {"addr": "10.244.0.5", "port": 80},
        "dst": {"addr": "10.244.0.10", "port": 45678},
        "k8s": {"pod": "webapp-pod", "namespace": "default", "container": "nginx"},
    }
    net_event = NetworkEvent.from_raw(raw_net)

    raw_wl = {
        "timestamp": "2026-10-14T10:00:03.000Z",
        "pod": "webapp-pod",
        "cpu_millicores": 250.0,
        "memory_mib": 32.0,
    }
    wl_sample = WorkloadSample.from_raw(raw_wl)

    # 1. Runtime-Only
    res_rt = detector.predict_runtime_events([rt_event])
    assert len(res_rt) == 1
    assert res_rt[0].modality == "runtime"

    # 2. Net + RT
    res_net_rt = detector.predict_net_rt_telemetry([net_event], [rt_event])
    assert len(res_net_rt) == 1
    assert res_net_rt[0].modality == "net_rt"

    # 3. RT + WL
    res_rt_wl = detector.predict_rt_wl_telemetry([wl_sample], [rt_event])
    assert len(res_rt_wl) == 1
    assert res_rt_wl[0].modality == "rt_wl"

    # 4. Full Tri-Modal Fusion
    res_full = detector.predict_full_fusion_telemetry([net_event], [wl_sample], [rt_event])
    assert len(res_full) == 1
    assert res_full[0].modality == "full_fusion"


def test_captured_dataset_provider_all_modalities(repo_root: Path) -> None:
    """Verify that CapturedDatasetProvider supports all 7 modalities for replay and evaluation."""
    provider = CapturedDatasetProvider(ml_datasets_dir=repo_root / "results" / "ml_datasets")
    assert provider.get_modalities() == ["network", "workload", "fusion"]
    all_mods = provider.get_all_modalities()
    assert set(all_mods) == set(ALL_7_MODALITIES)

    for modality in all_mods:
        sessions = provider.get_sessions(modality)
        assert len(sessions) > 0, f"No sessions for {modality}"
        windows = provider.get_windows(modality)
        assert len(windows) > 0, f"No windows for {modality}"
        assert all("affected_pods" in w for w in windows)


def test_live_window_record_multimodal_properties() -> None:
    """Verify that LiveWindowRecord correctly tracks all multimodal fusion properties."""
    record = LiveWindowRecord(
        window_start="2026-10-14T10:00:00.000Z",
        window_end="2026-10-14T10:00:10.000Z",
        affected_pods="webapp-pod",
    )
    assert not record.is_fused
    assert not record.is_net_rt_fused
    assert not record.is_rt_wl_fused
    assert not record.is_full_fused

    record.network_available = True
    record.workload_available = True
    assert record.is_fused
    assert not record.is_full_fused

    record.runtime_available = True
    assert record.is_net_rt_fused
    assert record.is_rt_wl_fused
    assert record.is_full_fused
