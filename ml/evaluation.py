"""Metrics derived only from actual held-out predictions."""

from __future__ import annotations

from time import perf_counter
from typing import Any, Sequence

from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


def evaluate_predictions(model: Any, x_test: Sequence[Sequence[float]], y_test: Sequence[str]) -> tuple[dict[str, object], list[str], list[float]]:
    started = perf_counter()
    predictions = list(model.predict(x_test))
    inference_seconds = perf_counter() - started
    probabilities = model.predict_proba(x_test)
    classes = list(model.classes_)
    attack_index = classes.index("attack") if "attack" in classes else None
    confidence = [float(row[attack_index]) if attack_index is not None else 0.0 for row in probabilities]
    matrix = confusion_matrix(y_test, predictions, labels=["normal", "attack"])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    metrics: dict[str, object] = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, pos_label="attack", zero_division=0)),
        "recall": float(recall_score(y_test, predictions, pos_label="attack", zero_division=0)),
        "f1": float(f1_score(y_test, predictions, pos_label="attack", zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "inference_time_seconds": inference_seconds,
        "inference_time_per_sample_seconds": inference_seconds / len(y_test) if y_test else None,
        "detection_latency_seconds": None,
        "detection_latency_note": "Unavailable: no ground-truth attack onset event is available in the held-out data.",
    }
    return metrics, predictions, confidence
