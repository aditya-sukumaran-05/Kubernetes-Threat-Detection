"""Build a machine-readable inventory of planned, interrupted, and valid runs."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def _row_count(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    if path.suffix == ".csv":
        with path.open(encoding="utf-8", newline="") as handle:
            return sum(1 for _ in csv.DictReader(handle))
    with path.open(encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def build_manifest(
    runs_dir: Path,
    output_path: Path,
    overwrite: bool = True,
    cluster_id: str | None = None,
) -> dict[str, Any]:
    if not overwrite and output_path.exists():
        raise ValueError(
            f"output manifest {output_path} already exists. Use overwrite=True or specify a distinct output path."
        )

    entries = []
    metadata_paths = sorted({p for p in runs_dir.glob("**/metadata.json") if p.is_file()}) if runs_dir.exists() else []
    for metadata_path in metadata_paths:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        entry_cluster = metadata.get("cluster_id", "minikube")
        if cluster_id is not None and entry_cluster != cluster_id:
            continue
        telemetry = metadata.get("telemetry", {})
        entries.append({
            "experiment_id": metadata.get("experiment_id"),
            "cluster_id": entry_cluster,
            "scenario": metadata.get("scenario"),
            "label": metadata.get("label"), "status": metadata.get("status"),
            "start_time_utc": metadata.get("experiment_start_time_utc"), "end_time_utc": metadata.get("experiment_end_time_utc"),
            "network_attack_start_time_utc": metadata.get("network_attack_start_time_utc"), "network_attack_end_time_utc": metadata.get("network_attack_end_time_utc"),
            "workload_attack_start_time_utc": metadata.get("workload_attack_start_time_utc"), "workload_attack_end_time_utc": metadata.get("workload_attack_end_time_utc"),
            "overlap_start_time_utc": metadata.get("overlap_start_time_utc"), "overlap_end_time_utc": metadata.get("overlap_end_time_utc"),
            "telemetry_available": {kind: _row_count(metadata_path.parent / filename) > 0 for kind, filename in telemetry.items()},
            "sample_counts": {kind: _row_count(metadata_path.parent / filename) for kind, filename in telemetry.items()},
            "validation": metadata.get("validation", {}), "notes": metadata.get("notes", ""),
        })
    manifest = {"experiments": entries, "count": len(entries), "cluster_filter": cluster_id}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=Path("experiments/runs"))
    parser.add_argument("--output", type=Path, default=Path("results/experiment_manifest.json"))
    parser.add_argument("--cluster-id", type=str, default=None, help="Filter manifest to a specific cluster ID.")
    parser.add_argument("--overwrite", action="store_true", default=True, help="Allow overwriting existing manifest.")
    parser.add_argument("--no-overwrite", action="store_false", dest="overwrite", help="Reject overwriting existing manifest.")
    args = parser.parse_args()
    print(json.dumps(build_manifest(args.runs_dir, args.output, overwrite=args.overwrite, cluster_id=args.cluster_id), indent=2))


if __name__ == "__main__":
    main()
