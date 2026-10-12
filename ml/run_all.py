"""One-command Phase 2 workflow: preprocess, build datasets, then evaluate."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from experiments.run_preprocessing import run as run_preprocessing
from ml.datasets import build_datasets
from ml.train import load_config, run_experiment


def write_comparison(path: Path, rows: list[dict[str, object]]) -> None:
    fields = ["telemetry", "model", "status", "accuracy", "precision", "recall", "f1", "false_positive_rate", "inference_time_seconds", "reason"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


class WorkflowError(ValueError):
    """Raised when batch workflow destination checks or preflights fail."""


def run_all(project_root: Path, overwrite: bool = False) -> dict[str, object]:
    phase1_dir = project_root / "results" / "phase1_demo"
    datasets_dir = project_root / "results" / "ml_datasets"
    results_dir = project_root / "results"

    # Preflight all batch outputs before beginning execution
    if not overwrite:
        conflicting = []
        if phase1_dir.exists() and list(phase1_dir.iterdir()):
            conflicting.append(f"Phase 1 demo dir ({phase1_dir}) is non-empty")
        if datasets_dir.exists() and list(datasets_dir.iterdir()):
            conflicting.append(f"ML datasets dir ({datasets_dir}) is non-empty")
        for exp_name in ("network", "workload", "fusion"):
            exp_dir = results_dir / exp_name
            if exp_dir.exists() and list(exp_dir.iterdir()):
                conflicting.append(f"Experiment dir ({exp_dir}) is non-empty")
        comp_csv = results_dir / "ablation_comparison.csv"
        comp_json = results_dir / "ablation_comparison.json"
        if comp_csv.exists():
            conflicting.append(f"Comparison CSV ({comp_csv}) exists")
        if comp_json.exists():
            conflicting.append(f"Comparison JSON ({comp_json}) exists")

        if conflicting:
            details = "; ".join(conflicting)
            raise WorkflowError(
                f"Batch workflow preflight rejected: {details}. Use overwrite=True (--overwrite) or a clean target directory."
            )

    run_preprocessing(
        project_root / "experiments" / "metadata" / "captures.json",
        phase1_dir,
        project_root / "experiments" / "runs",
        overwrite=overwrite,
    )
    summaries = build_datasets(
        phase1_dir / "processed",
        datasets_dir,
        overwrite=overwrite,
    )
    results: list[dict[str, object]] = []
    for name in ("network", "workload", "fusion"):
        config = load_config(project_root / "configs" / f"{name}.json")
        results.extend(run_experiment(config, project_root))
    write_comparison(results_dir / "ablation_comparison.csv", results)
    evaluated = [row for row in results if row.get("status") == "evaluated"]
    report = {
        "datasets": {name: summary.__dict__ for name, summary in summaries.items()},
        "experiments": results,
        "figure_status": (
            "Performance figures can be generated from the evaluated session-held-out results."
            if evaluated else
            "No performance figures were generated because no experiment passed the session-aware evaluation eligibility checks."
        ),
    }
    (results_dir / "ablation_comparison.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path("."))
    parser.add_argument("--overwrite", action="store_true", default=False, help="Explicitly allow overwriting batch outputs.")
    args = parser.parse_args()
    print(json.dumps(run_all(args.project_root.resolve(), overwrite=args.overwrite), indent=2))


if __name__ == "__main__":
    main()
