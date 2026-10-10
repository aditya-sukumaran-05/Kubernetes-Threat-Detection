import csv
import json
from pathlib import Path

from ml.data_quality import build_data_quality_report


def test_data_quality_reports_duplicates_missingness_and_counts(tmp_path: Path) -> None:
    manifest = {"experiments": [{"experiment_id": "run-1", "status": "validated", "validation": {"valid": True}, "start_time_utc": "2026-01-01T00:00:00Z", "end_time_utc": "2026-01-01T00:01:00Z", "telemetry_available": {"network": True, "workload": True}}]}
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    processed = tmp_path / "processed"; processed.mkdir()
    rows = [{"capture_id": "run-1_network", "experiment_id": "run-1", "session_id": "run-1", "window_start": "2026-01-01T00:00:00Z", "label": "attack", "network_event_count": "2"}, {"capture_id": "run-1_network", "experiment_id": "run-1", "session_id": "run-1", "window_start": "2026-01-01T00:00:00Z", "label": "attack", "network_event_count": "2"}]
    with (processed / "run.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    report = build_data_quality_report(manifest_path, processed, tmp_path / "out")
    assert report["valid_experiment_count"] == 1
    assert report["duplicate_processed_records"] == 1
    assert report["class_distribution"] == {"attack": 2}
    assert (tmp_path / "out" / "data_quality_report.csv").exists()
