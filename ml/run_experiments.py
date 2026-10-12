"""Master Phase 4 command: quality report, session-aware ML, and research report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from experiments.manifest import build_manifest
from ml.analysis import generate_feature_importance, generate_figures
from ml.data_quality import build_data_quality_report
from ml.run_all import run_all


def write_markdown(path: Path, report: dict[str, object]) -> None:
    quality = report["data_quality"]
    experiments = report["experiments"]
    lines = ["# Final Experiment Report", "", "## Dataset summary", "", f"- Valid experiments: {quality['valid_experiment_count']}", f"- Processed windows: {quality['processed_window_count']}", f"- Class distribution: `{quality['class_distribution']}`", "", "## Evaluation", ""]
    for result in experiments:
        lines.append(f"- {result['telemetry']} / {result['model']}: **{result['status']}**" + (f" — {result.get('reason')}" if result.get("reason") else ""))
    lines.extend(["", "## Limitations", "", "- Metrics and figures are emitted only for valid session-held-out evaluations.", "- Feature importance is model-derived evidence, not causal attribution."])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(project_root: Path, overwrite: bool = False) -> dict[str, object]:
    results_dir = project_root / "results"
    manifest = build_manifest(project_root / "experiments" / "runs", results_dir / "experiment_manifest.json", overwrite=overwrite)
    ablation = run_all(project_root, overwrite=overwrite)
    quality = build_data_quality_report(results_dir / "experiment_manifest.json", results_dir / "phase1_demo" / "processed", results_dir)
    importance = generate_feature_importance(results_dir, project_root / "configs")
    figures = generate_figures(results_dir, ablation["experiments"])
    evaluated = [row for row in ablation["experiments"] if row.get("status") == "evaluated"]
    limitations = [
        "Detection latency is unavailable: the batch predictor has no independently recorded online detection timestamp.",
        "Monitoring overhead is unavailable: no paired telemetry-disabled and telemetry-enabled resource measurements were collected.",
        "Kube-IDS0, if analysed, is kept separate because its feature schema, label semantics, workloads, and timing differ from this Minikube corpus.",
    ]
    if not evaluated:
        limitations.append("No telemetry condition passed the session-aware evaluation eligibility checks.")
    if not ablation["datasets"]["fusion"]["labeled_rows"]:
        limitations.append("No valid same-session, fixed-window aligned fusion dataset is available.")
    report = {"dataset_summary": ablation["datasets"], "experiment_inventory": manifest["experiments"], "data_quality": quality, "split_strategy": "session_holdout_per_class", "models": ["logistic_regression", "random_forest"], "experiments": ablation["experiments"], "feature_importance": importance, "figures": figures, "detection_latency": "Unavailable without an independently recorded online detection timestamp.", "monitoring_overhead": "Unavailable: no paired telemetry-disabled/telemetry-enabled resource measurements have been collected.", "limitations": limitations, "reproducibility": {"command": "python -m ml.run_experiments --project-root ."}}
    (results_dir / "final_experiment_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(results_dir / "final_experiment_report.md", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path("."))
    parser.add_argument("--overwrite", action="store_true", default=False, help="Explicitly allow overwriting outputs.")
    args = parser.parse_args()
    print(json.dumps(run(args.project_root.resolve(), overwrite=args.overwrite), indent=2))


if __name__ == "__main__":
    main()
