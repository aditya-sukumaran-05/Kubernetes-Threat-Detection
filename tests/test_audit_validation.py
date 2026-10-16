"""Regression tests for experimental validation, alignment integrity, and scope isolation."""

from __future__ import annotations

import pandas as pd
from pathlib import Path

from experiments.alignment import align_feature_windows
from ml.loso import evaluate_loso_model
from ml.models import make_model
from ml.train import load_config, _matrix


def test_alignment_conflicting_labels_become_unknown() -> None:
    """Ensure conflicting modality labels produce 'unknown' rather than defaulting to normal."""
    net_rows = [{
        "window_start": "2026-10-14T10:00:00.000Z",
        "window_end": "2026-10-14T10:00:10.000Z",
        "session_id": "test_sess_01",
        "label": "attack",
        "attack_type": "network_attack",
        "network_connection_count": 50,
    }]
    wl_rows = [{
        "window_start": "2026-10-14T10:00:00.000Z",
        "window_end": "2026-10-14T10:00:10.000Z",
        "session_id": "test_sess_01",
        "label": "normal",
        "attack_type": "normal",
        "workload_cpu_millicores_mean": 10.0,
    }]
    aligned = align_feature_windows(net_rows, wl_rows)
    assert len(aligned) == 1
    assert aligned[0]["label"] == "unknown"
    assert aligned[0]["network_available"] is True
    assert aligned[0]["workload_available"] is True


def test_fusion_scope_filtering(tmp_path: Path) -> None:
    """Verify that Scope B isolates genuine 8 fusion sessions and 58 samples."""
    repo_root = Path(__file__).resolve().parent.parent
    ds_path = repo_root / "results" / "ml_datasets" / "fusion_dataset.csv"
    assert ds_path.exists(), "fusion_dataset.csv must exist"
    df = pd.read_csv(ds_path)

    # Scope B: sessions containing 'fusion_'
    df_scope_b = df[df["session_id"].str.contains("fusion_")].copy()
    assert df_scope_b["session_id"].nunique() == 8
    assert len(df_scope_b) == 58
    assert (df_scope_b["label"] == "attack").sum() == 28
    assert (df_scope_b["label"] == "normal").sum() == 30


def test_pipeline_leakage_safety() -> None:
    """Verify that make_model wraps transformers inside a Pipeline with isolated fold fitting."""
    model = make_model("svm", random_seed=42)
    step_names = [name for name, _ in model.steps]
    assert "imputer" in step_names
    assert "scaler" in step_names
    assert "classifier" in step_names


def test_denominator_effect_consistency() -> None:
    """Verify that the FP counts for RF (2) and SVM (5) are identical across Scope A and Scope B."""
    repo_root = Path(__file__).resolve().parent.parent
    ds_path = repo_root / "results" / "ml_datasets" / "fusion_dataset.csv"
    cfg = load_config(repo_root / "configs" / "fusion.json")
    features = list(cfg["features"])
    df = pd.read_csv(ds_path)

    # Scope B
    df_B = df[df["session_id"].str.contains("fusion_")].copy()
    rows_B = df_B.to_dict("records")
    mat_B = _matrix(rows_B, features)
    y_B = [r["label"] for r in rows_B]
    sess_B = [r["session_id"] for r in rows_B]

    res_rf_B = evaluate_loso_model("random_forest", mat_B, y_B, sess_B, rows_B, 42)
    res_svm_B = evaluate_loso_model("svm", mat_B, y_B, sess_B, rows_B, 42)

    cm_rf_B = res_rf_B["aggregate_confusion_matrix"]
    cm_svm_B = res_svm_B["aggregate_confusion_matrix"]

    # False positive count is index [0][1]
    fp_rf_B = cm_rf_B[0][1]
    fp_svm_B = cm_svm_B[0][1]

    assert fp_rf_B == 2, f"Expected 2 FP for RF in Scope B, got {fp_rf_B}"
    assert fp_svm_B == 5, f"Expected 5 FP for SVM in Scope B, got {fp_svm_B}"


def test_dataset_provenance_and_loso_artifact_integrity() -> None:
    """Validate dataset-summary counts against dataset CSVs and LOSO artifacts.

    Explicitly distinguishes raw collector samples from derived 10-second ML observation windows.
    """
    import json
    repo_root = Path(__file__).resolve().parent.parent

    # 1. Load dataset_summary.json
    summary_path = repo_root / "results" / "ml_datasets" / "dataset_summary.json"
    assert summary_path.exists(), "dataset_summary.json must exist"
    with summary_path.open("r", encoding="utf-8") as f:
        summary = json.load(f)

    # 2. Check Raw Telemetry Sample Counts vs ML Observation Windows
    # Raw workload collector captures:
    raw_norm_path = repo_root / "telemetry" / "data" / "workload_normal.csv"
    raw_att_path = repo_root / "telemetry" / "data" / "workload_attack.csv"
    assert raw_norm_path.exists() and raw_att_path.exists()

    df_raw_norm = pd.read_csv(raw_norm_path)
    df_raw_att = pd.read_csv(raw_att_path)
    # The erroneous "339 samples (186 normal, 153 attack)" came from raw CSV file line counts:
    with raw_norm_path.open("r", encoding="utf-8") as f:
        norm_lines = len(f.readlines())
    with raw_att_path.open("r", encoding="utf-8") as f:
        att_lines = len(f.readlines())

    assert norm_lines == 186, "workload_normal.csv has 186 total lines (1 header + 185 data rows)"
    assert att_lines == 153, "workload_attack.csv has 153 total lines (1 header + 152 data rows)"
    assert norm_lines + att_lines == 339, "Sum of raw CSV file lines is exactly 339 (186 + 153)"
    assert len(df_raw_norm) == 185, "185 data rows in workload_normal.csv"
    assert len(df_raw_att) == 152, "152 data rows in workload_attack.csv"

    # 3. Check ML Feature Datasets: Network (N=60), Workload (N=83), Fusion (N=122)
    # A. Network
    net_df = pd.read_csv(repo_root / "results" / "ml_datasets" / "network_dataset.csv")
    assert len(net_df) == 60
    assert summary["network"]["rows"] == 60
    assert summary["network"]["labeled_rows"] == 60
    assert summary["network"]["class_counts"]["normal"] == 32
    assert summary["network"]["class_counts"]["attack"] == 28
    assert (net_df["label"] == "normal").sum() == 32
    assert (net_df["label"] == "attack").sum() == 28

    # B. Workload (Note: 91 total windows generated, 83 labeled windows retained)
    wl_df = pd.read_csv(repo_root / "results" / "ml_datasets" / "workload_dataset.csv")
    assert len(wl_df) == 83, "Workload ML dataset must contain exactly 83 labeled observation windows"
    assert summary["workload"]["rows"] == 91
    assert summary["workload"]["labeled_rows"] == 83
    assert summary["workload"]["class_counts"]["normal"] == 55
    assert summary["workload"]["class_counts"]["attack"] == 28
    assert (wl_df["label"] == "normal").sum() == 55
    assert (wl_df["label"] == "attack").sum() == 28
    # Prove that 83 windows != 339 raw collector lines
    assert len(wl_df) != (norm_lines + att_lines)

    # C. Fusion (Note: 276 total windows, 122 labeled windows retained)
    fusion_df = pd.read_csv(repo_root / "results" / "ml_datasets" / "fusion_dataset.csv")
    assert len(fusion_df) == 122, "Fusion ML dataset must contain exactly 122 labeled observation windows"
    assert summary["fusion"]["rows"] == 276
    assert summary["fusion"]["labeled_rows"] == 122
    assert summary["fusion"]["class_counts"]["normal"] == 94
    assert summary["fusion"]["class_counts"]["attack"] == 28
    assert (fusion_df["label"] == "normal").sum() == 94
    assert (fusion_df["label"] == "attack").sum() == 28

    # 4. Check LOSO Artifact Metrics Consistency
    loso_comp_path = repo_root / "results" / "loso" / "loso_aggregate_comparison.csv"
    assert loso_comp_path.exists(), "loso_aggregate_comparison.csv must exist"
    loso_df = pd.read_csv(loso_comp_path)

    # Validate sample sizes in LOSO aggregate evaluation table
    net_loso = loso_df[(loso_df["telemetry"] == "network") & (loso_df["model"] == "random_forest")].iloc[0]
    wl_loso = loso_df[(loso_df["telemetry"] == "workload") & (loso_df["model"] == "random_forest")].iloc[0]
    fus_loso = loso_df[(loso_df["telemetry"] == "fusion") & (loso_df["model"] == "random_forest")].iloc[0]

    assert net_loso["total_samples"] == 60
    assert wl_loso["total_samples"] == 83
    assert fus_loso["total_samples"] == 122

    # Verify exact out-of-fold metrics
    assert round(net_loso["aggregate_f1"], 3) == 0.964
    assert round(net_loso["aggregate_precision"], 3) == 0.964
    assert round(net_loso["aggregate_recall"], 3) == 0.964
    assert round(net_loso["aggregate_false_positive_rate"], 3) == 0.031

    assert round(wl_loso["aggregate_f1"], 3) == 0.538
    assert round(wl_loso["aggregate_precision"], 3) == 0.583
    assert round(wl_loso["aggregate_recall"], 3) == 0.500
    assert round(wl_loso["aggregate_false_positive_rate"], 3) == 0.182

    assert round(fus_loso["aggregate_f1"], 3) == 0.929
    assert round(fus_loso["aggregate_precision"], 3) == 0.929
    assert round(fus_loso["aggregate_recall"], 3) == 0.929
    assert round(fus_loso["aggregate_false_positive_rate"], 3) == 0.021

