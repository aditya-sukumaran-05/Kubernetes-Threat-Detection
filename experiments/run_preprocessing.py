"""CLI for reproducible Phase 1 preprocessing without modifying raw captures."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from experiments.alignment import align_feature_windows
from experiments.metadata import assign_labels, load_capture_metadata, load_run_capture_metadata
from telemetry.features.network import extract_network_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import load_network_events, load_workload_samples


class PreprocessingError(ValueError):
    """Raised when preprocessing inputs, outputs, or configurations are invalid."""


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path: Path, rows: list[dict[str, object]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({name for row in rows for name in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return _file_sha256(path)


def run(
    metadata_path: Path | None,
    output_dir: Path,
    runs_dir: Path | None = None,
    overwrite: bool = False,
    cluster_id: str | None = None,
) -> dict[str, object]:
    processed_dir = output_dir / "processed"
    aligned_dir = output_dir / "aligned"

    # Destination check: fail safely if output exists and overwrite=False
    if not overwrite:
        existing_files = [
            *processed_dir.glob("*.csv"),
            *aligned_dir.glob("*.csv"),
        ]
        if output_dir.exists() and (existing_files or (output_dir / "summary.json").exists()):
            raise PreprocessingError(
                f"output directory {output_dir} already contains data. Use overwrite=True or a distinct output location."
            )

    project_root = (
        runs_dir.resolve().parents[1]
        if (runs_dir and runs_dir.exists() and len(runs_dir.resolve().parents) >= 2)
        else (metadata_path.resolve().parents[2] if metadata_path and len(metadata_path.resolve().parents) >= 3 else Path(".").resolve())
    )
    captures: list[CaptureMetadata] = []
    if metadata_path and metadata_path.exists():
        loaded_legacy = load_capture_metadata(metadata_path)
        if cluster_id is not None:
            loaded_legacy = [c for c in loaded_legacy if getattr(c, "cluster_id", "minikube") == cluster_id]
        captures.extend(loaded_legacy)
    if runs_dir and runs_dir.exists():
        captures.extend(load_run_capture_metadata(runs_dir, cluster_id=cluster_id))

    if not captures:
        raise PreprocessingError(
            f"no captures discovered (metadata={metadata_path}, runs_dir={runs_dir}, cluster_id={cluster_id})"
        )

    processed_dir.mkdir(parents=True, exist_ok=True)
    aligned_dir.mkdir(parents=True, exist_ok=True)

    if overwrite:
        for stale in processed_dir.glob("*.csv"):
            stale.unlink()
        for stale in aligned_dir.glob("*.csv"):
            stale.unlink()

    processed: dict[str, list[dict[str, object]]] = {}
    summary: dict[str, object] = {
        "inputs": {
            "metadata_path": str(metadata_path) if metadata_path else None,
            "runs_dir": str(runs_dir) if runs_dir else None,
            "cluster_filter": cluster_id,
        },
        "output_dir": str(output_dir),
        "captures": {},
        "aligned_sessions": [],
        "cluster_counts": {},
        "limitations": [],
    }

    cluster_counter: Counter[str] = Counter()

    for capture in captures:
        raw_path = Path(capture.path)
        if not raw_path.is_absolute():
            candidate = project_root / raw_path
            if candidate.exists():
                raw_path = candidate
            elif metadata_path and (metadata_path.parent / raw_path).exists():
                raw_path = metadata_path.parent / raw_path
            elif metadata_path and (metadata_path.parent.parent / raw_path).exists():
                raw_path = metadata_path.parent.parent / raw_path
            else:
                raw_path = candidate

        rows = (
            extract_network_features(load_network_events(raw_path))
            if capture.source == "network"
            else extract_workload_features(load_workload_samples(raw_path))
        )
        labeled = assign_labels(rows, capture)
        processed[capture.capture_id] = labeled
        out_csv = processed_dir / f"{capture.capture_id}.csv"
        csv_hash = write_csv(out_csv, labeled)

        cid = capture.cluster_id or "minikube"
        cluster_counter[cid] += len(labeled)

        summary["captures"][capture.capture_id] = {
            "source": capture.source,
            "session_id": capture.session_id,
            "cluster_id": cid,
            "input_path": str(raw_path),
            "output_path": str(out_csv),
            "sha256": csv_hash,
            "windows": len(rows),
            "labels": dict(Counter(str(row["label"]) for row in labeled)),
        }

    summary["cluster_counts"] = dict(cluster_counter)

    sessions: dict[str, dict[str, list[dict[str, object]]]] = defaultdict(dict)
    for capture in captures:
        sessions[capture.session_id][capture.source] = processed[capture.capture_id]
    for session_id, dimensions in sessions.items():
        if {"network", "workload"}.issubset(dimensions):
            aligned = align_feature_windows(dimensions["network"], dimensions["workload"])
            aligned_csv = aligned_dir / f"{session_id}.csv"
            aligned_hash = write_csv(aligned_csv, aligned)
            aligned_cluster = str(aligned[0].get("cluster_id") or "minikube") if aligned else "minikube"
            summary["aligned_sessions"].append({
                "session_id": session_id,
                "cluster_id": aligned_cluster,
                "windows": len(aligned),
                "output_path": str(aligned_csv),
                "sha256": aligned_hash,
            })
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
    parser.add_argument("--cluster-id", type=str, default=None, help="Filter captures to a specific cluster ID.")
    parser.add_argument("--overwrite", action="store_true", help="Explicitly allow overwriting existing output.")
    args = parser.parse_args()
    print(json.dumps(run(args.metadata, args.output_dir, args.runs_dir, overwrite=args.overwrite, cluster_id=args.cluster_id), indent=2))


if __name__ == "__main__":
    main()
