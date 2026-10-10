"""Model-native feature evidence and figures for valid held-out experiments."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import joblib


def generate_feature_importance(results_dir: Path, configurations_dir: Path) -> list[dict[str, object]]:
    """Export model-native importance only for actually persisted evaluated models."""
    output = results_dir / "feature_importance"
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for condition in ("network", "workload", "fusion"):
        experiment_path = results_dir / condition / "experiment.json"
        if not experiment_path.exists():
            continue
        experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
        config = experiment["config"]
        for outcome in experiment["results"]:
            if outcome.get("status") != "evaluated":
                continue
            model_path = results_dir / condition / "models" / f"{outcome['model']}.joblib"
            if not model_path.exists():
                continue
            pipeline = joblib.load(model_path)
            classifier = pipeline.named_steps["classifier"]
            values = getattr(classifier, "feature_importances_", None)
            if values is None and hasattr(classifier, "coef_"):
                values = classifier.coef_[0]
            if values is None:
                continue
            rows.extend({"feature": feature, "importance": float(value), "condition": condition, "model": outcome["model"], "interpretation": "model-derived evidence; not causal"} for feature, value in zip(config["features"], values))
    if rows:
        with (output / "feature_importance.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
    return rows


def generate_figures(results_dir: Path, comparison: list[dict[str, Any]]) -> list[str]:
    """Create figures only from genuine evaluated metrics; return produced paths."""
    valid = [row for row in comparison if row.get("status") == "evaluated"]
    if not valid:
        return []
    import matplotlib.pyplot as plt
    output = results_dir / "figures"
    output.mkdir(parents=True, exist_ok=True)
    paths = []
    for metric in ("f1", "precision", "recall", "false_positive_rate"):
        rows = [row for row in valid if row.get(metric) is not None]
        if not rows:
            continue
        figure, axis = plt.subplots()
        axis.bar([f"{row['telemetry']}\n{row['model']}" for row in rows], [row[metric] for row in rows])
        axis.set_ylabel(metric.replace("_", " "))
        figure.tight_layout()
        path = output / f"{metric}_comparison.png"
        figure.savefig(path, dpi=200)
        plt.close(figure)
        paths.append(str(path))
    matrix_dir = output / "confusion_matrices"
    matrix_dir.mkdir(parents=True, exist_ok=True)
    for row in valid:
        matrix = row.get("confusion_matrix")
        if not matrix:
            continue
        figure, axis = plt.subplots()
        image = axis.imshow(matrix)
        axis.set_xticks([0, 1], ["normal", "attack"])
        axis.set_yticks([0, 1], ["normal", "attack"])
        axis.set_xlabel("Predicted")
        axis.set_ylabel("Actual")
        for y, values in enumerate(matrix):
            for x, value in enumerate(values):
                axis.text(x, y, str(value), ha="center", va="center")
        figure.colorbar(image, ax=axis)
        figure.tight_layout()
        path = matrix_dir / f"{row['telemetry']}_{row['model']}.png"
        figure.savefig(path, dpi=200)
        plt.close(figure)
        paths.append(str(path))
    return paths
