"""Train and evaluate a configured baseline using a strict session holdout."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
from dataclasses import asdict
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
import sklearn

from ml.datasets import DatasetError, read_csv
from ml.evaluation import evaluate_predictions
from ml.models import make_model
from ml.splitting import InsufficientDataError, session_holdout_split


def load_config(path: Path) -> dict[str, object]:
    config = json.loads(path.read_text(encoding="utf-8"))
    required = {"name", "dataset", "features", "models", "random_seed", "output_dir"}
    missing = sorted(required - set(config))
    if missing:
        raise ValueError(f"configuration missing fields: {missing}")
    return config


def _matrix(rows: list[dict[str, str]], features: list[str]) -> np.ndarray:
    try:
        return np.asarray([[float(row[feature]) for feature in features] for row in rows], dtype=float)
    except KeyError as exc:
        raise DatasetError(f"configured feature absent from dataset: {exc.args[0]}") from exc
    except ValueError as exc:
        raise DatasetError("all configured ML features must be numeric") from exc


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({field for row in rows for field in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def run_experiment(config: dict[str, object], project_root: Path) -> list[dict[str, object]]:
    dataset_path = project_root / str(config["dataset"])
    output_dir = project_root / str(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = read_csv(dataset_path)
    dataset_sha256 = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    features = list(config["features"])
    results: list[dict[str, object]] = []
    try:
        if not rows:
            raise InsufficientDataError("dataset contains zero labeled samples")
        labels, sessions = [row["label"] for row in rows], [row["session_id"] for row in rows]
        split = session_holdout_split(labels, sessions, int(config["random_seed"]))
        matrix = _matrix(rows, features)
        train_indices, test_indices = list(split.train_indices), list(split.test_indices)
        x_train, x_test = matrix[train_indices], matrix[test_indices]
        y_train, y_test = [labels[index] for index in train_indices], [labels[index] for index in test_indices]
        train_experiments = list(split.train_session_ids)
        test_experiments = list(split.test_session_ids)
        for model_name in config["models"]:
            model = make_model(str(model_name), int(config["random_seed"]))
            started = perf_counter()
            model.fit(x_train, y_train)
            training_seconds = perf_counter() - started
            metrics, predictions, confidence = evaluate_predictions(model, x_test, y_test)
            model_dir = output_dir / "models"
            model_dir.mkdir(parents=True, exist_ok=True)
            joblib.dump(model, model_dir / f"{model_name}.joblib")
            prediction_rows = [
                {"window_start": rows[index]["window_start"], "session_id": rows[index]["session_id"], "actual_label": actual, "predicted_label": predicted, "attack_probability": probability}
                for index, actual, predicted, probability in zip(test_indices, y_test, predictions, confidence)
            ]
            _write_csv(output_dir / f"{model_name}_predictions.csv", prediction_rows)
            results.append({"telemetry": config["name"], "model": model_name, "status": "evaluated", "split_strategy": split.strategy, "training_samples": len(train_indices), "test_samples": len(test_indices), "training_experiment_ids": train_experiments, "test_experiment_ids": test_experiments, "training_class_counts": split.train_class_counts, "test_class_counts": split.test_class_counts, "training_time_seconds": training_seconds, **metrics})
    except (InsufficientDataError, DatasetError) as exc:
        results = [{"telemetry": config["name"], "model": model_name, "status": "not_evaluable", "reason": str(exc), "split_strategy": "session_holdout_per_class", "training_samples": 0, "test_samples": 0} for model_name in config["models"]]
    metadata = {
        "config": config,
        "dataset_sha256": dataset_sha256,
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "results": results,
    }
    (output_dir / "experiment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    project_root = args.config.parents[1]
    print(json.dumps(run_experiment(config, project_root), indent=2))


if __name__ == "__main__":
    main()
