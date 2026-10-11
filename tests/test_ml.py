import csv
from pathlib import Path

import numpy as np
import pytest

from ml.datasets import DatasetError, build_datasets
from ml.evaluation import evaluate_predictions
from ml.models import make_model
from ml.splitting import InsufficientDataError, leave_one_session_out_splits, session_holdout_split


def test_group_split_holds_out_whole_sessions_and_preserves_classes() -> None:
    split = session_holdout_split(
        ["normal", "normal", "attack", "attack", "normal", "attack"],
        ["n1", "n1", "a1", "a1", "n2", "a2"],
    )
    assert set(split.train_session_ids).isdisjoint(split.test_session_ids)
    assert {sessions for index, sessions in enumerate(["n1", "n1", "a1", "a1", "n2", "a2"]) if index in split.train_indices}.isdisjoint(
        {sessions for index, sessions in enumerate(["n1", "n1", "a1", "a1", "n2", "a2"]) if index in split.test_indices}
    )
    assert split.train_class_counts["normal"] > 0 and split.train_class_counts["attack"] > 0
    assert split.test_class_counts["normal"] > 0 and split.test_class_counts["attack"] > 0


def test_group_split_accepts_mixed_label_sessions_without_leakage() -> None:
    labels = ["normal", "attack", "normal", "attack"]
    sessions = ["attack-run-1", "attack-run-1", "attack-run-2", "attack-run-2"]
    split = session_holdout_split(labels, sessions, random_seed=42)
    assert split.train_session_ids == ("attack-run-1",)
    assert split.test_session_ids == ("attack-run-2",)
    assert split.train_class_counts == {"normal": 1, "attack": 1}
    assert split.test_class_counts == {"normal": 1, "attack": 1}


def test_group_split_rejects_when_a_partition_cannot_contain_both_classes() -> None:
    with pytest.raises(InsufficientDataError, match="both classes in train and test"):
        session_holdout_split(["normal", "attack"], ["single-run", "single-run"])


def test_group_split_rejects_single_class() -> None:
    with pytest.raises(InsufficientDataError, match="both classes"):
        session_holdout_split(["normal", "normal"], ["n1", "n2"])


def test_models_train_and_metrics_are_calculated_deterministically() -> None:
    x_train = np.asarray([[0.0], [0.1], [0.2], [9.8], [9.9], [10.0]])
    y_train = ["normal", "normal", "normal", "attack", "attack", "attack"]
    x_test = np.asarray([[0.1], [9.9]])
    y_test = ["normal", "attack"]
    for model_name in ("logistic_regression", "random_forest", "xgboost", "svm"):
        model = make_model(model_name, 42).fit(x_train, y_train)
        metrics, predictions, confidence = evaluate_predictions(model, x_test, y_test)
        assert predictions == y_test, f"{model_name} failed prediction"
        assert metrics["f1"] == 1.0, f"{model_name} failed f1"
        assert metrics["false_positive_rate"] == 0.0, f"{model_name} failed fpr"
        assert len(confidence) == 2


def test_leave_one_session_out_splits_isolates_each_session() -> None:
    labels = ["normal", "normal", "attack", "attack", "normal", "attack"]
    sessions = ["s1", "s1", "s2", "s2", "s3", "s4"]
    folds = leave_one_session_out_splits(labels, sessions)
    assert len(folds) == 4
    for fold in folds:
        assert fold.held_out_session not in fold.train_session_ids
        assert fold.test_session_ids == (fold.held_out_session,)
        assert set(fold.train_indices).isdisjoint(fold.test_indices)
        assert len(fold.train_indices) + len(fold.test_indices) == len(labels)
        assert fold.is_valid is True
        assert fold.train_class_counts["normal"] > 0
        assert fold.train_class_counts["attack"] > 0


def test_leave_one_session_out_splits_flags_invalid_training_fold() -> None:
    labels = ["normal", "normal", "attack", "attack"]
    sessions = ["s1", "s2", "s_only_attack", "s_only_attack"]
    folds = leave_one_session_out_splits(labels, sessions)
    fold_dict = {f.held_out_session: f for f in folds}
    assert fold_dict["s1"].is_valid is True
    assert fold_dict["s2"].is_valid is True
    assert fold_dict["s_only_attack"].is_valid is False
    assert "missing ['attack']" in fold_dict["s_only_attack"].invalid_reason


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_dataset_builder_excludes_unknown_labels_and_writes_empty_fusion(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    processed.mkdir()
    base = {"window_end": "2026-01-01T00:00:10Z", "attack_type": "normal", "network_event_count": "2"}
    _write_csv(processed / "network_normal_20260919.csv", [{**base, "window_start": "2026-01-01T00:00:00Z", "capture_id": "n", "session_id": "n", "label": "normal"}])
    _write_csv(processed / "network_burst_20260919.csv", [{**base, "window_start": "2026-01-01T00:01:00Z", "capture_id": "a", "session_id": "a", "label": "attack"}])
    workload = {"window_end": "2026-01-01T00:00:10Z", "attack_type": "normal", "workload_cpu_millicores_mean": "1"}
    _write_csv(processed / "workload_normal_20260919.csv", [{**workload, "window_start": "2026-01-01T00:00:00Z", "capture_id": "w", "session_id": "w", "label": "normal"}])
    _write_csv(processed / "workload_attack_20260919.csv", [{**workload, "window_start": "2026-01-01T00:01:00Z", "capture_id": "wa", "session_id": "wa", "label": "unknown"}])
    summary = build_datasets(processed, tmp_path / "out")
    assert summary["network"].labeled_rows == 2
    assert summary["workload"].class_counts == {"normal": 1}
    assert summary["fusion"].labeled_rows == 0


def test_dataset_builder_rejects_duplicate_capture_windows(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    processed.mkdir()
    row = {"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:00:10Z", "capture_id": "n", "session_id": "n", "label": "normal", "attack_type": "normal", "network_event_count": "2"}
    _write_csv(processed / "network_normal_20260919.csv", [row, row])
    _write_csv(processed / "network_burst_20260919.csv", [{**row, "capture_id": "a", "session_id": "a", "label": "attack"}])
    _write_csv(processed / "workload_normal_20260919.csv", [{**row, "capture_id": "w", "session_id": "w"}])
    _write_csv(processed / "workload_attack_20260919.csv", [{**row, "capture_id": "wa", "session_id": "wa", "label": "unknown"}])
    with pytest.raises(DatasetError, match="duplicate window"):
        build_datasets(processed, tmp_path / "out")


def test_dataset_builder_keeps_each_ablation_in_its_scenario_family(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    processed.mkdir()
    network = {
        "window_end": "2026-01-01T00:00:10Z", "attack_type": "normal",
        "telemetry_source": "network", "network_event_count": "2",
    }
    _write_csv(processed / "network.csv", [
        {**network, "window_start": "2026-01-01T00:00:00Z", "capture_id": "net-normal", "session_id": "net-normal", "scenario": "network_normal", "label": "normal"},
        {**network, "window_start": "2026-01-01T00:00:10Z", "capture_id": "net-attack", "session_id": "net-attack", "scenario": "network_attack", "label": "attack"},
        {**network, "window_start": "2026-01-01T00:00:20Z", "capture_id": "workload-run", "session_id": "workload-run", "scenario": "workload_attack", "label": "normal"},
    ])
    workload = {
        "window_end": "2026-01-01T00:00:10Z", "attack_type": "normal",
        "telemetry_source": "workload", "workload_cpu_millicores_mean": "1",
    }
    _write_csv(processed / "workload.csv", [
        {**workload, "window_start": "2026-01-01T00:00:00Z", "capture_id": "workload-normal", "session_id": "workload-normal", "scenario": "workload_normal", "label": "normal"},
        {**workload, "window_start": "2026-01-01T00:00:10Z", "capture_id": "workload-attack", "session_id": "workload-attack", "scenario": "workload_attack", "label": "attack"},
        {**workload, "window_start": "2026-01-01T00:00:20Z", "capture_id": "fusion-run", "session_id": "fusion-run", "scenario": "fusion_attack", "label": "attack"},
    ])
    summary = build_datasets(processed, tmp_path / "out")
    assert summary["network"].labeled_rows == 2
    assert summary["network"].class_counts == {"normal": 1, "attack": 1}
    assert summary["workload"].labeled_rows == 2
    assert summary["workload"].class_counts == {"normal": 1, "attack": 1}


def test_dataset_builder_validates_capture_cluster_consistency_and_uniqueness(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    processed.mkdir()
    row = {
        "window_start": "2026-01-01T00:00:00Z",
        "window_end": "2026-01-01T00:00:10Z",
        "capture_id": "cap1",
        "session_id": "sess1",
        "label": "normal",
        "attack_type": "normal",
        "network_event_count": "2",
        "telemetry_source": "network",
    }
    # 1. Conflicting clusters within same capture_id must raise DatasetError
    row_cluster_a = {**row, "cluster_id": "cluster-a"}
    row_cluster_b = {**row, "cluster_id": "cluster-b", "window_start": "2026-01-01T00:00:10Z"}
    _write_csv(processed / "network_conflict.csv", [row_cluster_a, row_cluster_b])
    with pytest.raises(DatasetError, match="conflicting clusters"):
        build_datasets(processed, tmp_path / "out1")

    # 2. Distinct clusters with identical timestamps across different captures should succeed without collision
    processed2 = tmp_path / "processed2"
    processed2.mkdir()
    row_c1 = {**row, "capture_id": "cap_c1", "session_id": "sess_c1", "cluster_id": "cluster-1"}
    row_c2 = {**row, "capture_id": "cap_c2", "session_id": "sess_c2", "cluster_id": "cluster-2"}
    _write_csv(processed2 / "network_c1.csv", [row_c1])
    _write_csv(processed2 / "network_c2.csv", [row_c2])
    summaries = build_datasets(processed2, tmp_path / "out2")
    assert summaries["network"].labeled_rows == 2
    assert summaries["network"].cluster_counts == {"cluster-1": 1, "cluster-2": 1}
