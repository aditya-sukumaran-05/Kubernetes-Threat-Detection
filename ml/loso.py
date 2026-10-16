"""Leave-one-session-out (LOSO) cross-validation pipeline across modalities."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from time import perf_counter
from typing import Any, Sequence

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from ml.datasets import DatasetError, read_csv
from ml.evaluation import evaluate_predictions
from ml.models import make_model
from ml.splitting import InsufficientDataError, leave_one_session_out_splits
from ml.train import _matrix, _write_csv, load_config


def evaluate_loso_model(
    model_name: str,
    matrix: np.ndarray,
    labels: list[str],
    sessions: list[str],
    rows: list[dict[str, str]],
    random_seed: int,
) -> dict[str, Any]:
    """Execute leave-one-session-out cross-validation for a single model."""
    folds = leave_one_session_out_splits(labels, sessions)
    per_session_results: list[dict[str, Any]] = []
    all_test_indices: list[int] = []
    all_actuals: list[str] = []
    all_predictions: list[str] = []
    all_confidences: list[float] = []

    for fold in folds:
        if not fold.is_valid:
            per_session_results.append({
                "held_out_session": fold.held_out_session,
                "status": "invalid_fold",
                "reason": fold.invalid_reason,
                "test_samples": len(fold.test_indices),
                "test_class_counts": fold.test_class_counts,
                "train_class_counts": fold.train_class_counts,
                "accuracy": None,
                "precision": None,
                "recall": None,
                "f1": None,
                "false_positive_rate": None,
                "confusion_matrix": None,
                "training_time_seconds": None,
                "inference_time_seconds": None,
            })
            continue

        train_idx = list(fold.train_indices)
        test_idx = list(fold.test_indices)
        x_train, x_test = matrix[train_idx], matrix[test_idx]
        y_train = [labels[i] for i in train_idx]
        y_test = [labels[i] for i in test_idx]

        model = make_model(model_name, random_seed)
        started = perf_counter()
        model.fit(x_train, y_train)
        training_seconds = perf_counter() - started

        metrics, preds, conf = evaluate_predictions(model, x_test, y_test)

        all_test_indices.extend(test_idx)
        all_actuals.extend(y_test)
        all_predictions.extend(preds)
        all_confidences.extend(conf)

        per_session_results.append({
            "held_out_session": fold.held_out_session,
            "status": "evaluated",
            "reason": "",
            "test_samples": len(test_idx),
            "test_class_counts": fold.test_class_counts,
            "train_class_counts": fold.train_class_counts,
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "false_positive_rate": metrics["false_positive_rate"],
            "confusion_matrix": metrics["confusion_matrix"],
            "training_time_seconds": training_seconds,
            "inference_time_seconds": metrics["inference_time_seconds"],
        })

    # Prediction rows for all held-out evaluations
    prediction_rows = [
        {
            "window_start": rows[idx]["window_start"],
            "session_id": rows[idx]["session_id"],
            "actual_label": actual,
            "predicted_label": pred,
            "attack_probability": conf,
        }
        for idx, actual, pred, conf in zip(all_test_indices, all_actuals, all_predictions, all_confidences)
    ]

    # Aggregate metrics across all pooled held-out predictions
    evaluated_folds = [f for f in per_session_results if f["status"] == "evaluated"]
    invalid_folds = [f for f in per_session_results if f["status"] != "evaluated"]

    if all_actuals:
        matrix_agg = confusion_matrix(all_actuals, all_predictions, labels=["normal", "attack"])
        tn, fp, fn, tp = (int(v) for v in matrix_agg.ravel())
        agg_acc = float(accuracy_score(all_actuals, all_predictions))
        agg_prec = float(precision_score(all_actuals, all_predictions, pos_label="attack", zero_division=0))
        agg_rec = float(recall_score(all_actuals, all_predictions, pos_label="attack", zero_division=0))
        agg_f1 = float(f1_score(all_actuals, all_predictions, pos_label="attack", zero_division=0))
        agg_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        cm_agg = [[tn, fp], [fn, tp]]
    else:
        agg_acc = agg_prec = agg_rec = agg_f1 = agg_fpr = None
        cm_agg = None

    # Mean and standard deviation of F1 across held-out sessions
    f1_all = [f["f1"] for f in evaluated_folds if f["f1"] is not None]
    mean_f1_all = float(np.mean(f1_all)) if f1_all else 0.0
    std_f1_all = float(np.std(f1_all, ddof=1)) if len(f1_all) > 1 else 0.0

    # F1 across attack-containing held-out sessions (where attack is present in test ground-truth)
    f1_attack_sessions = [
        f["f1"] for f in evaluated_folds
        if f["f1"] is not None and f["test_class_counts"].get("attack", 0) > 0
    ]
    mean_f1_attack = float(np.mean(f1_attack_sessions)) if f1_attack_sessions else 0.0
    std_f1_attack = float(np.std(f1_attack_sessions, ddof=1)) if len(f1_attack_sessions) > 1 else 0.0

    return {
        "model": model_name,
        "total_folds": len(folds),
        "valid_folds": len(evaluated_folds),
        "invalid_folds": len(invalid_folds),
        "total_samples": len(all_actuals),
        "aggregate_accuracy": agg_acc,
        "aggregate_precision": agg_prec,
        "aggregate_recall": agg_rec,
        "aggregate_f1": agg_f1,
        "aggregate_false_positive_rate": agg_fpr,
        "aggregate_confusion_matrix": cm_agg,
        "mean_session_f1": mean_f1_all,
        "std_session_f1": std_f1_all,
        "attack_sessions_mean_f1": mean_f1_attack,
        "attack_sessions_std_f1": std_f1_attack,
        "per_session_results": per_session_results,
        "predictions": prediction_rows,
    }


def run_loso_for_config(
    config: dict[str, Any], project_root: Path, output_base: Path | None = None
) -> dict[str, Any]:
    """Run LOSO cross-validation for a given modality configuration."""
    dataset_path = project_root / str(config["dataset"])
    telemetry_name = str(config["name"])
    output_dir = (output_base or (project_root / "results" / "loso")) / telemetry_name
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = read_csv(dataset_path)
    if not rows:
        raise InsufficientDataError(f"{dataset_path} contains zero samples")

    labels = [row["label"] for row in rows]
    sessions = [row["session_id"] for row in rows]
    features = list(config["features"])
    matrix = _matrix(rows, features)
    seed = int(config["random_seed"])

    results: list[dict[str, Any]] = []

    for model_name in config["models"]:
        model_eval = evaluate_loso_model(
            model_name=str(model_name),
            matrix=matrix,
            labels=labels,
            sessions=sessions,
            rows=rows,
            random_seed=seed,
        )

        # Write per-session CSV
        per_session_flat = [
            {
                "held_out_session": item["held_out_session"],
                "status": item["status"],
                "test_samples": item["test_samples"],
                "accuracy": item["accuracy"],
                "precision": item["precision"],
                "recall": item["recall"],
                "f1": item["f1"],
                "false_positive_rate": item["false_positive_rate"],
                "confusion_matrix": str(item["confusion_matrix"]),
                "training_time_seconds": item["training_time_seconds"],
                "inference_time_seconds": item["inference_time_seconds"],
                "reason": item["reason"],
            }
            for item in model_eval["per_session_results"]
        ]
        _write_csv(output_dir / f"{model_name}_per_session.csv", per_session_flat)

        # Write predictions CSV
        _write_csv(output_dir / f"{model_name}_predictions.csv", model_eval["predictions"])

        summary_entry = {
            "telemetry": telemetry_name,
            "model": model_name,
            "total_folds": model_eval["total_folds"],
            "valid_folds": model_eval["valid_folds"],
            "invalid_folds": model_eval["invalid_folds"],
            "total_samples": model_eval["total_samples"],
            "aggregate_accuracy": model_eval["aggregate_accuracy"],
            "aggregate_precision": model_eval["aggregate_precision"],
            "aggregate_recall": model_eval["aggregate_recall"],
            "aggregate_f1": model_eval["aggregate_f1"],
            "aggregate_false_positive_rate": model_eval["aggregate_false_positive_rate"],
            "aggregate_confusion_matrix": model_eval["aggregate_confusion_matrix"],
            "mean_session_f1": model_eval["mean_session_f1"],
            "std_session_f1": model_eval["std_session_f1"],
            "attack_sessions_mean_f1": model_eval["attack_sessions_mean_f1"],
            "attack_sessions_std_f1": model_eval["attack_sessions_std_f1"],
        }
        results.append(summary_entry)

    modality_report = {
        "telemetry": telemetry_name,
        "dataset": str(config["dataset"]),
        "features": features,
        "models": results,
    }
    (output_dir / "summary.json").write_text(json.dumps(modality_report, indent=2), encoding="utf-8")
    return modality_report


ALL_MODALITIES: tuple[str, ...] = (
    "network",
    "workload",
    "fusion",
    "runtime",
    "net_rt",
    "rt_wl",
    "full_fusion",
)


def run_all_loso(
    project_root: Path, modalities: Sequence[str] | None = None
) -> dict[str, Any]:
    """Run LOSO cross-validation across all supported telemetry modalities."""
    results_dir = project_root / "results"
    loso_dir = results_dir / "loso"
    loso_dir.mkdir(parents=True, exist_ok=True)

    all_summaries: list[dict[str, Any]] = []
    modality_reports: dict[str, Any] = {}
    target_modalities = tuple(modalities) if modalities is not None else ALL_MODALITIES

    for name in target_modalities:
        config = load_config(project_root / "configs" / f"{name}.json")
        report = run_loso_for_config(config, project_root, loso_dir)
        modality_reports[name] = report
        all_summaries.extend(report["models"])

    # Write aggregate comparison CSV
    csv_fields = [
        "telemetry",
        "model",
        "total_folds",
        "valid_folds",
        "invalid_folds",
        "total_samples",
        "aggregate_accuracy",
        "aggregate_precision",
        "aggregate_recall",
        "aggregate_f1",
        "aggregate_false_positive_rate",
        "mean_session_f1",
        "std_session_f1",
        "attack_sessions_mean_f1",
        "attack_sessions_std_f1",
        "aggregate_confusion_matrix",
    ]
    with (loso_dir / "loso_aggregate_comparison.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for row in all_summaries:
            row_copy = dict(row)
            row_copy["aggregate_confusion_matrix"] = str(row_copy["aggregate_confusion_matrix"])
            writer.writerow(row_copy)

    # Write aggregate summary JSON
    master_report = {
        "evaluation_strategy": "leave_one_session_out",
        "models": all_summaries,
        "modalities": modality_reports,
    }
    (loso_dir / "loso_summary.json").write_text(json.dumps(master_report, indent=2), encoding="utf-8")
    return master_report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path("."))
    parser.add_argument("--config", type=Path, default=None, help="Run single config if provided.")
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    if args.config:
        config = load_config(args.config)
        report = run_loso_for_config(config, project_root)
        print(json.dumps(report, indent=2))
    else:
        report = run_all_loso(project_root)
        print(json.dumps(report["models"], indent=2))


if __name__ == "__main__":
    main()
