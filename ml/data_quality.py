"""Traceable data-quality and independence reporting for experimental runs."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def build_data_quality_report(manifest_path: Path, processed_dir: Path, output_dir: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"experiments": []}
    experiments = manifest.get("experiments", [])
    valid = [item for item in experiments if item.get("status") == "validated" and item.get("validation", {}).get("valid")]
    ids = [item.get("experiment_id") for item in experiments]
    duplicate_ids = sorted({item for item in ids if item and ids.count(item) > 1})
    intervals = [(item.get("experiment_id"), item.get("start_time_utc"), item.get("end_time_utc")) for item in valid]
    overlaps = []
    for index, (left_id, left_start, left_end) in enumerate(intervals):
        for right_id, right_start, right_end in intervals[index + 1:]:
            if all((left_start, left_end, right_start, right_end)) and max(left_start, right_start) < min(left_end, right_end):
                overlaps.append([left_id, right_id])
    processed_files = sorted(processed_dir.glob("*.csv")) if processed_dir.exists() else []
    rows = [row for path in processed_files for row in _read_csv(path)]
    keys = [(row.get("capture_id"), row.get("window_start")) for row in rows]
    duplicate_records = sum(count - 1 for count in Counter(keys).values() if count > 1)
    missingness = {
        field: sum(not row.get(field) for row in rows)
        for field in sorted({field for row in rows for field in row if field.startswith(("network_", "workload_"))})
    }
    per_experiment = Counter(row.get("experiment_id", row.get("session_id", "unknown")) for row in rows)
    labels = Counter(row.get("label", "unknown") for row in rows)
    aligned_dir = processed_dir.parent / "aligned"
    aligned_rows = [row for path in sorted(aligned_dir.glob("*.csv")) for row in _read_csv(path)] if aligned_dir.exists() else []
    report = {
        "experiment_count": len(experiments), "valid_experiment_count": len(valid),
        "processed_window_count": len(rows), "normal_windows": labels["normal"], "attack_windows": labels["attack"], "unknown_windows": labels["unknown"],
        "duplicate_experiment_ids": duplicate_ids, "overlapping_valid_sessions": overlaps, "duplicate_processed_records": duplicate_records,
        "feature_missingness": missingness, "class_distribution": dict(labels), "per_experiment_sample_counts": dict(per_experiment),
        "missing_telemetry_experiments": [item.get("experiment_id") for item in experiments if not all(item.get("telemetry_available", {}).values())],
        "unmatched_fusion_windows": sum(row.get("network_available") != "True" or row.get("workload_available") != "True" for row in aligned_rows),
        "data_hashes": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in processed_files},
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "data_quality_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (output_dir / "data_quality_report.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["experiment_id", "windows"])
        writer.writeheader()
        writer.writerows({"experiment_id": key, "windows": value} for key, value in sorted(per_experiment.items()))
    return report
