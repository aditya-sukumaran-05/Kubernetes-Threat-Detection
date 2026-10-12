"""One-command Phase 2 workflow: preprocess, build datasets, then evaluate."""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from experiments.run_preprocessing import run as run_preprocessing
from ml.datasets import build_datasets
from ml.pipeline_safety import (
    WorkflowError,
    atomic_replace_file,
    safe_replace_dir,
    staging_directory,
)
from ml.train import load_config, run_experiment


def write_comparison(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "telemetry",
        "model",
        "status",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "inference_time_seconds",
        "reason",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run_all(
    project_root: Path,
    overwrite: bool = False,
    output_dir: Path | None = None,
    run_id: str | None = None,
    run_scoped: bool = False,
) -> dict[str, object]:
    """Execute complete pipeline with input preflight, staging, and atomic publishing."""
    if run_id is None:
        run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:6]}"

    if run_scoped:
        base_dir = output_dir or (project_root / "results" / "runs")
        target_base = base_dir / run_id
    elif output_dir is not None:
        target_base = output_dir
    else:
        target_base = project_root / "results"

    phase1_dir = target_base / "phase1_demo"
    datasets_dir = target_base / "ml_datasets"
    exp_dirs = [target_base / exp_name for exp_name in ("network", "workload", "fusion")]
    comp_csv = target_base / "ablation_comparison.csv"
    comp_json = target_base / "ablation_comparison.json"
    batch_manifest_file = target_base / "batch_manifest.json"

    # Preflight Check 1: Validate destinations and overwrite permissions
    if not overwrite:
        conflicting = []
        if phase1_dir.exists() and list(phase1_dir.iterdir()):
            conflicting.append(f"Phase 1 demo dir ({phase1_dir}) is non-empty")
        if datasets_dir.exists() and list(datasets_dir.iterdir()):
            conflicting.append(f"ML datasets dir ({datasets_dir}) is non-empty")
        for exp_dir in exp_dirs:
            if exp_dir.exists() and list(exp_dir.iterdir()):
                conflicting.append(f"Experiment dir ({exp_dir}) is non-empty")
        if comp_csv.exists():
            conflicting.append(f"Comparison CSV ({comp_csv}) exists")
        if comp_json.exists():
            conflicting.append(f"Comparison JSON ({comp_json}) exists")
        if batch_manifest_file.exists():
            conflicting.append(f"Batch manifest ({batch_manifest_file}) exists")

        if conflicting:
            details = "; ".join(conflicting)
            raise WorkflowError(
                f"Batch workflow preflight rejected: {details}. Use overwrite=True (--overwrite) or a clean target directory."
            )

    # Preflight Check 2: Validate required inputs before any mutation
    metadata_path = project_root / "experiments" / "metadata" / "captures.json"
    runs_dir = project_root / "experiments" / "runs"
    if not (metadata_path.exists() or runs_dir.exists()):
        raise WorkflowError(
            f"Batch workflow preflight rejected: neither capture metadata ({metadata_path}) nor runs directory ({runs_dir}) exists."
        )

    for exp_name in ("network", "workload", "fusion"):
        cfg_path = project_root / "configs" / f"{exp_name}.json"
        if not cfg_path.exists():
            raise WorkflowError(
                f"Batch workflow preflight rejected: missing required configuration file ({cfg_path})."
            )
        try:
            load_config(cfg_path)
        except Exception as exc:
            raise WorkflowError(
                f"Batch workflow preflight rejected: invalid configuration in {cfg_path}: {exc}"
            ) from exc

    target_base.mkdir(parents=True, exist_ok=True)

    # Staged Execution: Stage all pipeline artifacts separately before publication
    with staging_directory(target_base, prefix=f".staging_{run_id}_") as staged_dir:
        staged_phase1 = staged_dir / "phase1_demo"
        staged_datasets = staged_dir / "ml_datasets"
        staged_results = staged_dir

        # Stage 1: Preprocessing
        run_preprocessing(
            metadata_path if metadata_path.exists() else None,
            staged_phase1,
            runs_dir=runs_dir if runs_dir.exists() else None,
            overwrite=True,
        )

        # Stage 2: ML Datasets
        summaries = build_datasets(
            staged_phase1 / "processed",
            staged_datasets,
            overwrite=True,
        )

        # Stage 3: Experiments and Model Training
        results: list[dict[str, object]] = []
        for name in ("network", "workload", "fusion"):
            config = load_config(project_root / "configs" / f"{name}.json")
            staged_exp_dir = staged_results / name
            staged_ds_path = staged_datasets / f"{name}_dataset.csv"
            exp_results = run_experiment(
                config,
                project_root,
                overwrite=True,
                dataset_path=staged_ds_path,
                output_dir=staged_exp_dir,
            )
            results.extend(exp_results)

        # Stage 4: Comparisons and Ablation Report
        staged_comp_csv = staged_results / "ablation_comparison.csv"
        write_comparison(staged_comp_csv, results)
        evaluated = [row for row in results if row.get("status") == "evaluated"]
        report = {
            "run_id": run_id,
            "status": "completed",
            "datasets": {
                name: asdict(summary) if hasattr(summary, "__dataclass_fields__") else summary.__dict__
                for name, summary in summaries.items()
            },
            "experiments": results,
            "figure_status": (
                "Performance figures can be generated from the evaluated session-held-out results."
                if evaluated
                else "No performance figures were generated because no experiment passed the session-aware evaluation eligibility checks."
            ),
        }
        staged_comp_json = staged_results / "ablation_comparison.json"
        staged_comp_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

        # Stage 5: Batch Manifest with Provenance and Completion Guarantee
        batch_manifest = {
            "run_id": run_id,
            "status": "completed",
            "completed_at_utc": datetime.now(timezone.utc).isoformat(),
            "target_directory": str(target_base),
            "datasets": {name: s.sha256 for name, s in summaries.items()},
            "evaluated_count": len(evaluated),
            "total_count": len(results),
        }
        staged_manifest = staged_results / "batch_manifest.json"
        staged_manifest.write_text(json.dumps(batch_manifest, indent=2), encoding="utf-8")

        # Safe Publication: Atomically publish staged directories and files into target_base
        safe_replace_dir(staged_phase1, phase1_dir)
        safe_replace_dir(staged_datasets, datasets_dir)
        for exp_name in ("network", "workload", "fusion"):
            safe_replace_dir(staged_results / exp_name, target_base / exp_name)
        atomic_replace_file(staged_comp_csv, comp_csv)
        atomic_replace_file(staged_comp_json, comp_json)
        atomic_replace_file(staged_manifest, batch_manifest_file)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=None, help="Optional custom output directory.")
    parser.add_argument("--run-scoped", action="store_true", default=False, help="Write to an isolated run-scoped directory.")
    parser.add_argument("--run-id", type=str, default=None, help="Optional unique run identifier.")
    parser.add_argument("--overwrite", action="store_true", default=False, help="Explicitly allow overwriting batch outputs.")
    args = parser.parse_args()
    print(
        json.dumps(
            run_all(
                args.project_root.resolve(),
                overwrite=args.overwrite,
                output_dir=args.output_dir.resolve() if args.output_dir else None,
                run_id=args.run_id,
                run_scoped=args.run_scoped,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
