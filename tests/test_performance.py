"""Performance and regression tests for incremental offset reading, bounded buffers, and feature equivalence."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dashboard.live_engine import LiveTelemetryEngine
from ml.inference import InferenceResult, ThreatDetector
from telemetry.features.network import extract_network_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import NetworkEvent, WorkloadSample
from telemetry.windowing import window_start


def test_workload_incremental_offset_reading(tmp_path: Path) -> None:
    """Verify that workload CSV reading uses byte offsets, avoiding re-reading existing lines."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Initial write: header + 5 samples
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(5):
            ts = (base_ts + timedelta(seconds=i * 5)).isoformat()
            writer.writerow([ts, "webapp", 100 + i, 15, "normal"])

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    first_read = engine.read_new_workload_samples()
    assert len(first_read) == 5
    assert engine._workload_cumulative_count == 5

    # 2. Subsequent call without new data: returns 0 new samples immediately
    second_read = engine.read_new_workload_samples()
    assert len(second_read) == 0
    assert engine._workload_cumulative_count == 5

    # 3. Append 3 new samples
    with open(wl_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for i in range(5, 8):
            ts = (base_ts + timedelta(seconds=i * 5)).isoformat()
            writer.writerow([ts, "webapp", 100 + i, 15, "normal"])

    third_read = engine.read_new_workload_samples()
    assert len(third_read) == 3
    assert [s.cpu_millicores for s in third_read] == [105.0, 106.0, 107.0]
    assert engine._workload_cumulative_count == 8


def test_workload_incremental_partial_line_write_handling(tmp_path: Path) -> None:
    """Verify that partial/incomplete lines at EOF are buffered until completed with newline."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Header + 1 complete row
    wl_file.write_text(
        "timestamp,pod,cpu_millicores,memory_mib,label\n"
        f"{base_ts.isoformat()},webapp,100,15,normal\n",
        encoding="utf-8",
    )

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    recs = engine.read_new_workload_samples()
    assert len(recs) == 1

    # Append a partial fragment (no newline)
    ts2 = (base_ts + timedelta(seconds=5)).isoformat()
    with open(wl_file, "a", encoding="utf-8") as f:
        f.write(f"{ts2},webapp,120")  # Incomplete!

    recs_partial = engine.read_new_workload_samples()
    assert len(recs_partial) == 0

    # Complete the line
    with open(wl_file, "a", encoding="utf-8") as f:
        f.write(",16,normal\n")

    recs_completed = engine.read_new_workload_samples()
    assert len(recs_completed) == 1
    assert recs_completed[0].cpu_millicores == 120.0
    assert recs_completed[0].memory_mib == 16.0


def test_workload_file_truncation_resets_offset(tmp_path: Path) -> None:
    """Verify that file rotation/truncation resets offset and re-reads cleanly."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Initial file: 10 rows
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(10):
            writer.writerow([(base_ts + timedelta(seconds=i * 5)).isoformat(), "webapp", 100, 15, "normal"])

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    assert len(engine.read_new_workload_samples()) == 10

    # Truncate and write 2 new rows
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        writer.writerow([(base_ts + timedelta(seconds=100)).isoformat(), "webapp", 200, 20, "normal"])
        writer.writerow([(base_ts + timedelta(seconds=105)).isoformat(), "webapp", 210, 20, "normal"])

    assert wl_file.stat().st_size < engine._workload_file_offset
    new_recs = engine.read_new_workload_samples()
    assert len(new_recs) == 2
    assert [s.cpu_millicores for s in new_recs] == [200.0, 210.0]


def test_sliding_horizon_pruning_bounds_in_memory_buffers(tmp_path: Path) -> None:
    """Verify that buffer pruning bounds in-memory telemetry to retention horizon while preserving disk capture."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Write 100 distinct 10-second windows (200 workload samples, 100 net events)
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(200):
            ts = (base_ts + timedelta(seconds=i * 5)).isoformat()
            writer.writerow([ts, "webapp", 100 + (i % 20), 15, "normal"])

    with open(net_file, "w", encoding="utf-8") as f:
        for i in range(100):
            ts = (base_ts + timedelta(seconds=i * 10)).isoformat()
            f.write(json.dumps({
                "timestamp": ts, "type": "accept",
                "src": {"addr": "10.244.0.5", "port": 40000 + i},
                "dst": {"addr": "10.244.0.2", "port": 80},
                "k8s": {"podName": "webapp", "namespace": "default"},
                "error": None,
            }) + "\n")

    disk_wl_size_before = wl_file.stat().st_size
    disk_net_size_before = net_file.stat().st_size

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file, max_retained_windows=30)
    windows = engine.process_live_telemetry()

    assert len(windows) == 30
    # In-memory arrays must be bounded to (30 + 5) = 35 windows
    # Workload: 2 samples per 10s window -> ~70 samples retained (not 200!)
    assert len(engine._workload_valid_samples) <= 35 * 2 + 2
    # Network: 1 event per window -> 35 events retained (not 100!)
    assert len(engine._network_valid_events) <= 35 + 2

    # Verify disk files were NEVER truncated or modified
    assert wl_file.stat().st_size == disk_wl_size_before
    assert net_file.stat().st_size == disk_net_size_before


def test_feature_equivalence_bounded_vs_unbounded(tmp_path: Path) -> None:
    """Verify that bounded sliding buffers produce 100% bitwise-identical feature values to unbounded extraction."""
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"

    # Create 120 distinct windows (240 workload samples, 120 net events)
    all_wl_samples: list[WorkloadSample] = []
    all_net_events: list[NetworkEvent] = []

    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(240):
            ts = base_ts + timedelta(seconds=i * 5)
            sample = WorkloadSample(timestamp=ts, pod="webapp", cpu_millicores=float(100 + (i % 31)), memory_mib=float(15 + (i % 7)))
            all_wl_samples.append(sample)
            writer.writerow([ts.isoformat(), "webapp", sample.cpu_millicores, sample.memory_mib, "normal"])

    with open(net_file, "w", encoding="utf-8") as f:
        for i in range(120):
            ts = base_ts + timedelta(seconds=i * 10)
            raw = {
                "timestamp": ts.isoformat(), "type": "accept" if i % 2 == 0 else "close",
                "src": {"addr": f"10.244.0.{i % 5}", "port": 40000 + i},
                "dst": {"addr": "10.244.0.2", "port": 80},
                "k8s": {"podName": "webapp", "namespace": "default"},
                "error": None,
            }
            all_net_events.append(NetworkEvent.from_raw(raw))
            f.write(json.dumps(raw) + "\n")

    # 1. Unbounded feature extraction directly on full datasets
    full_wl_features = extract_workload_features(all_wl_samples)
    full_net_features = extract_network_features(all_net_events)
    expected_wl_50 = full_wl_features[-50:]
    expected_net_50 = full_net_features[-50:]

    # 2. LiveTelemetryEngine with bounded pruning (max_retained_windows=50)
    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file, max_retained_windows=50)
    live_records = engine.process_live_telemetry()

    assert len(live_records) == 50

    # Compare every feature dictionary key and value
    for i in range(50):
        rec = live_records[i]
        exp_wl = expected_wl_50[i]
        exp_net = expected_net_50[i]

        assert rec.window_start == exp_wl["window_start"] == exp_net["window_start"]
        assert rec.workload_features == exp_wl
        assert rec.network_features == exp_net


def test_collector_health_cumulative_counts_preserved_across_pruning(tmp_path: Path) -> None:
    """Verify that collector health cards display true lifetime record counts even after raw buffer pruning."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # 100 workload samples across 50 windows
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(100):
            writer.writerow([(base_ts + timedelta(seconds=i * 5)).isoformat(), "webapp", 100, 15, "normal"])

    # 50 network events
    with open(net_file, "w", encoding="utf-8") as f:
        for i in range(50):
            f.write(json.dumps({
                "timestamp": (base_ts + timedelta(seconds=i * 10)).isoformat(), "type": "accept",
                "src": {"addr": "10.244.0.5", "port": 40000 + i},
                "dst": {"addr": "10.244.0.2", "port": 80},
                "k8s": {"podName": "webapp", "namespace": "default"},
                "error": None,
            }) + "\n")

    # Engine retaining only 10 windows
    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file, max_retained_windows=10)
    engine.process_live_telemetry()

    # In-memory arrays are pruned:
    assert len(engine._workload_valid_samples) < 100
    assert len(engine._network_valid_events) < 50

    # But CollectorHealth reports the true lifetime cumulative counts!
    wl_health = engine.get_workload_health()
    net_health = engine.get_network_health()

    assert wl_health.total_valid_records == 100
    assert net_health.total_valid_records == 50
