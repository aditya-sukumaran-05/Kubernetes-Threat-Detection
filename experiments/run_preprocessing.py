"""CLI for reproducible Phase 1 preprocessing without modifying raw captures."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from experiments.alignment import align_feature_windows
from experiments.metadata import assign_labels, load_capture_metadata, load_run_capture_metadata
from telemetry.features.network import extract_network_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import load_network_events, load_workload_samples


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({name for row in rows for name in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run(metadata_path: Path | None, output_dir: Path, runs_dir: Path | None = None) -> dict[str, object]:
    project_root = runs_dir.parents[1] if (runs_dir and runs_dir.exists()) else (metadata_path.parents[2] if metadata_path else Path("."))
    captures: list[CaptureMetadata] = []
    if metadata_path and metadata_path.exists():
        captures.extend(load_capture_metadata(metadata_path))
    if runs_dir and runs_dir.exists():
        captures.extend(load_run_capture_metadata(runs_dir))

    processed_dir = output_dir / "processed"
    aligned_dir = output_dir / "aligned"
    processed_dir.mkdir(parents=True, exist_ok=True)
    aligned_dir.mkdir(parents=True, exist_ok=True)
    for stale in processed_dir.glob("*.csv"):
        stale.unlink()
    for stale in aligned_dir.glob("*.csv"):
        stale.unlink()

    processed: dict[str, list[dict[str, object]]] = {}
    summary: dict[str, object] = {"captures": {}, "aligned_sessions": [], "limitations": []}
    for capture in captures:
        raw_path = project_root / capture.path
        rows = (
            extract_network_features(load_network_events(raw_path))
            if capture.source == "network"
            else extract_workload_features(load_workload_samples(raw_path))
        )
        processed[capture.capture_id] = assign_labels(rows, capture)
        write_csv(processed_dir / f"{capture.capture_id}.csv", processed[capture.capture_id])
        summary["captures"][capture.capture_id] = {
            "source": capture.source,
            "session_id": capture.session_id,
            "windows": len(rows),
            "labels": dict(Counter(str(row["label"]) for row in processed[capture.capture_id])),
        }

    sessions: dict[str, dict[str, list[dict[str, object]]]] = defaultdict(dict)
    for capture in captures:
        sessions[capture.session_id][capture.source] = processed[capture.capture_id]
    for session_id, dimensions in sessions.items():
        if {"network", "workload"}.issubset(dimensions):
            aligned = align_feature_windows(dimensions["network"], dimensions["workload"])
            write_csv(aligned_dir / f"{session_id}.csv", aligned)
            summary["aligned_sessions"].append({"session_id": session_id, "windows": len(aligned)})
    if not summary["aligned_sessions"]:
        summary["limitations"].append(
            "No simultaneous network and workload session is available; no fused dataset was produced."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, default=None, help="Optional legacy captures.json metadata.")
    parser.add_argument("--output-dir", type=Path, default=Path("results/phase1_demo"))
    parser.add_argument("--runs-dir", type=Path, default=Path("experiments/runs"))
    args = parser.parse_args()
    print(json.dumps(run(args.metadata, args.output_dir, args.runs_dir), indent=2))


if __name__ == "__main__":
    main()
