"""Performance and regression tests for incremental offset reading, bounded buffers, and feature equivalence."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dashboard.live_engine import LiveTelemetryEngine
from ml.inference import InferenceResult, ThreatDetector
from telemetry.features.network import extract_network_features
from telemetry.features.runtime import extract_runtime_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import NetworkEvent, RuntimeEvent, WorkloadSample
from telemetry.windowing import isoformat_z, window_start


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


def test_workload_reader_utf8_bom_crlf_quoted_and_incomplete(tmp_path: Path) -> None:
    """Verify workload reader handles UTF-8 BOM, CRLF, quoted fields with commas, and malformed rows."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"

    content = (
        b"\xef\xbb\xbf"
        b"timestamp,pod,cpu_millicores,memory_mib,label\r\n"
        b"2026-10-10T12:00:00Z,\"webapp,staging\",100.5,15.2,normal\r\n"
        b"2026-10-10T12:00:05Z,webapp\r\n"  # Incomplete column count
        b"2026-10-10T12:00:10Z,webapp,110.0,\"16.0\",normal\r\n"
    )
    wl_file.write_bytes(content)

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    samples = engine.read_new_workload_samples()

    assert len(samples) == 2
    assert engine._workload_malformed_count == 1
    assert samples[0].pod == "webapp,staging"
    assert samples[0].cpu_millicores == 100.5
    assert samples[0].memory_mib == 15.2
    assert samples[1].pod == "webapp"
    assert samples[1].cpu_millicores == 110.0
    assert samples[1].memory_mib == 16.0


def test_workload_reader_multibyte_utf8_split_across_writes(tmp_path: Path) -> None:
    """Verify that multibyte UTF-8 characters split across writes are not corrupted into U+FFFD."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Initial write: Header + 1 sample
    with open(wl_file, "wb") as f:
        f.write(b"timestamp,pod,cpu_millicores,memory_mib,label\n")
        f.write(f"{base_ts.isoformat()},webapp,100,15,normal\n".encode("utf-8"))

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    first_read = engine.read_new_workload_samples()
    assert len(first_read) == 1

    # Write 2: Appending a row where the multibyte Greek mu char (0xc2 0xb5) is split
    # Write 2a has 0xc2 at EOF with NO newline
    ts2 = (base_ts + timedelta(seconds=5)).isoformat()
    with open(wl_file, "ab") as f:
        f.write(f"{ts2},webapp-\xc2".encode("latin1"))

    second_read = engine.read_new_workload_samples()
    assert len(second_read) == 0  # Incomplete line, buffered in partial bytes

    # Write 2b completes the multibyte character (0xb5) and row
    with open(wl_file, "ab") as f:
        f.write(b"\xb5,120,16,normal\n")

    third_read = engine.read_new_workload_samples()
    assert len(third_read) == 1
    assert third_read[0].pod == "webapp-\u00b5"
    assert "\ufffd" not in third_read[0].pod


def test_file_rotation_and_replacement_equal_or_larger_size(tmp_path: Path) -> None:
    """Verify that file replacement/rotation is detected even when the replacement file is equal or larger."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Write initial file: 3 rows
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(3):
            writer.writerow([(base_ts + timedelta(seconds=i * 5)).isoformat(), "webapp", 100 + i, 15, "normal"])

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    init_samples = engine.read_new_workload_samples()
    assert len(init_samples) == 3
    assert engine._workload_file_offset > 0

    # 2. Prepare replacement file with 6 rows (larger size than previous file)
    wl_rotated = tmp_path / "workload_metrics_rotated.csv"
    with open(wl_rotated, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(10, 16):
            writer.writerow([(base_ts + timedelta(seconds=i * 5)).isoformat(), "webapp-rot", 200 + i, 20, "normal"])

    # Atomic rotation / replacement (simulates logrotate / collector restart)
    os.replace(wl_rotated, wl_file)

    # Engine must detect file identity change (inode / ctime), reset offset, and read all 6 rows
    new_samples = engine.read_new_workload_samples()
    assert len(new_samples) == 6
    assert all(s.pod == "webapp-rot" for s in new_samples)
    assert engine._workload_cumulative_count == 3 + 6


def test_in_place_overwrite_detected_via_header_check(tmp_path: Path) -> None:
    """Verify that in-place truncation and overwrite is detected when new content exceeds old offset."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Initial file: 2 rows
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        writer.writerow([base_ts.isoformat(), "webapp", 100, 15, "normal"])

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    assert len(engine.read_new_workload_samples()) == 1
    offset_1 = engine._workload_file_offset

    # In-place overwrite with a DIFFERENT header / initial structure and larger size
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label", "extra_col"])
        for i in range(5):
            writer.writerow([(base_ts + timedelta(seconds=100 + i * 5)).isoformat(), "webapp-new", 300, 30, "normal", "extra"])

    assert wl_file.stat().st_size > offset_1

    # Engine detects header mismatch, resets offset to 0, and reads all 5 new rows
    res = engine.read_new_workload_samples()
    assert len(res) == 5
    assert all(s.pod == "webapp-new" for s in res)


def test_bounded_vs_unbounded_runtime_and_multimodal_inference_parity(tmp_path: Path) -> None:
    """Verify bounded sliding buffers produce 100% bitwise parity for runtime features and model predictions."""
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    rt_file = tmp_path / "runtime_events.jsonl"

    all_wl_samples: list[WorkloadSample] = []
    all_net_events: list[NetworkEvent] = []
    all_rt_events: list[RuntimeEvent] = []

    # Generate 120 windows with heterogeneous telemetry
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        for i in range(240):
            ts = base_ts + timedelta(seconds=i * 5)
            sample = WorkloadSample(timestamp=ts, pod="webapp", cpu_millicores=float(100 + (i % 25)), memory_mib=float(15 + (i % 5)))
            all_wl_samples.append(sample)
            writer.writerow([ts.isoformat(), "webapp", sample.cpu_millicores, sample.memory_mib, "normal"])

    with open(net_file, "w", encoding="utf-8") as f:
        for i in range(120):
            ts = base_ts + timedelta(seconds=i * 10)
            raw = {
                "timestamp": ts.isoformat(),
                "type": "accept" if i % 2 == 0 else "close",
                "src": {"addr": f"10.244.0.{i % 5}", "port": 40000 + i},
                "dst": {"addr": "10.244.0.2", "port": 80},
                "k8s": {"podName": "webapp", "namespace": "default"},
                "error": None,
            }
            all_net_events.append(NetworkEvent.from_raw(raw))
            f.write(json.dumps(raw) + "\n")

    with open(rt_file, "w", encoding="utf-8") as f:
        for i in range(120):
            ts = base_ts + timedelta(seconds=i * 10)
            comm = "curl" if i % 5 == 0 else "whoami" if i % 3 == 0 else "nginx"
            raw = {
                "timestamp": ts.isoformat(),
                "comm": comm,
                "pid": 1000 + i,
                "uid": 0 if i % 4 == 0 else 1000,
                "username": "root" if i % 4 == 0 else "app",
                "pod": "webapp",
                "container": "webapp",
                "namespace": "default",
            }
            all_rt_events.append(RuntimeEvent.from_raw(raw))
            f.write(json.dumps(raw) + "\n")

    # 1. Unbounded feature extraction
    full_wl_features = extract_workload_features(all_wl_samples)
    full_net_features = extract_network_features(all_net_events)

    # Unbounded runtime feature extraction grouped by window start
    rt_by_start: dict[str, list[RuntimeEvent]] = {}
    for ev in all_rt_events:
        rt_by_start.setdefault(isoformat_z(window_start(ev.timestamp)), []).append(ev)

    expected_wl_50 = full_wl_features[-50:]
    expected_net_50 = full_net_features[-50:]

    # 2. Bounded LiveTelemetryEngine
    engine = LiveTelemetryEngine(
        network_path=net_file, workload_path=wl_file, runtime_path=rt_file, max_retained_windows=50
    )
    records = engine.process_live_telemetry(model_name="random_forest")

    assert len(records) == 50

    # 3. Assert 100% bitwise parity on features and inference
    for i, rec in enumerate(records):
        start = rec.window_start
        assert rec.network_features == expected_net_50[i]
        assert rec.workload_features == expected_wl_50[i]

        expected_rt_evs = rt_by_start.get(start, [])
        expected_rt_feat = extract_runtime_features(expected_rt_evs)
        assert rec.runtime_features == expected_rt_feat

        # Parity of inferences
        assert "random_forest" in rec.network_inferences
        assert "random_forest" in rec.workload_inferences
        assert "random_forest" in rec.fusion_inferences

        net_inf = rec.network_inferences["random_forest"]
        wl_inf = rec.workload_inferences["random_forest"]
        fus_inf = rec.fusion_inferences["random_forest"]

        unbounded_detector = engine.detector
        exp_net_inf = unbounded_detector.predict(expected_net_50[i], modality="network", model_name="random_forest")
        exp_wl_inf = unbounded_detector.predict(expected_wl_50[i], modality="workload", model_name="random_forest")
        fused_dict = {**expected_net_50[i], **expected_wl_50[i], "network_available": True, "workload_available": True, "affected_pods": "webapp"}
        exp_fus_inf = unbounded_detector.predict(fused_dict, modality="fusion", model_name="random_forest")

        assert net_inf.predicted_label == exp_net_inf.predicted_label
        assert net_inf.confidence == exp_net_inf.confidence
        assert net_inf.attack_probability == exp_net_inf.attack_probability

        assert wl_inf.predicted_label == exp_wl_inf.predicted_label
        assert wl_inf.confidence == exp_wl_inf.confidence
        assert wl_inf.attack_probability == exp_wl_inf.attack_probability

        assert fus_inf.predicted_label == exp_fus_inf.predicted_label
        assert fus_inf.confidence == exp_fus_inf.confidence
        assert fus_inf.attack_probability == exp_fus_inf.attack_probability


def test_late_arriving_telemetry_and_window_boundary_behavior(tmp_path: Path) -> None:
    """Verify that late-arriving telemetry within active horizon updates features, while expired telemetry is safely pruned."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Populate 60 windows
    with open(net_file, "w", encoding="utf-8") as f:
        for i in range(60):
            ts = base_ts + timedelta(seconds=i * 10)
            f.write(json.dumps({
                "timestamp": ts.isoformat(), "type": "accept",
                "src": {"addr": "10.244.0.5", "port": 40000 + i},
                "dst": {"addr": "10.244.0.2", "port": 80},
                "k8s": {"podName": "webapp", "namespace": "default"},
                "error": None,
            }) + "\n")

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file, max_retained_windows=50)
    init_records = engine.process_live_telemetry()
    assert len(init_records) == 50

    # Active deck is windows 10..59 (sorted)
    target_active_start = init_records[30].window_start  # Window ~40
    init_event_count = init_records[30].network_features.get("network_event_count", 0)
    assert init_event_count == 1

    # Late arrival for active window: append 2 more events matching target_active_start
    dt_active = datetime.fromisoformat(target_active_start.replace("Z", "+00:00"))
    with open(net_file, "a", encoding="utf-8") as f:
        for j in range(2):
            ts_late = dt_active + timedelta(seconds=j + 1)
            f.write(json.dumps({
                "timestamp": ts_late.isoformat(), "type": "accept",
                "src": {"addr": "10.244.0.5", "port": 50000 + j},
                "dst": {"addr": "10.244.0.2", "port": 80},
                "k8s": {"podName": "webapp", "namespace": "default"},
                "error": None,
            }) + "\n")

    updated_records = engine.process_live_telemetry()
    active_rec = next(r for r in updated_records if r.window_start == target_active_start)
    assert active_rec.network_features.get("network_event_count") == 3

    # Late arrival for an EXPIRED window (e.g. Window 0, older than the 55-window retention)
    dt_expired = base_ts + timedelta(seconds=1)
    with open(net_file, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "timestamp": dt_expired.isoformat(), "type": "accept",
            "src": {"addr": "10.244.0.5", "port": 60000},
            "dst": {"addr": "10.244.0.2", "port": 80},
            "k8s": {"podName": "webapp", "namespace": "default"},
            "error": None,
        }) + "\n")

    post_expired_records = engine.process_live_telemetry()
    # Active deck remains strictly 50 windows, and expired window 0 is pruned
    assert len(post_expired_records) == 50
    assert all(r.window_start != isoformat_z(window_start(dt_expired)) for r in post_expired_records)


def test_workload_deduplication_state_bounded_and_format_agnostic(tmp_path: Path) -> None:
    """Verify workload deduplication is format-agnostic and remains bounded across prunings."""
    wl_file = tmp_path / "workload_metrics.csv"
    net_file = tmp_path / "network_events.jsonl"
    base_ts = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Write samples with mixed timestamp formatting (Z vs +00:00 and fractional seconds)
    with open(wl_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
        # Distinct sample 1
        writer.writerow(["2026-10-10T12:00:00+00:00", "webapp", 100, 15, "normal"])
        # Duplicate of sample 1 with Z notation
        writer.writerow(["2026-10-10T12:00:00.000000Z", "webapp", 100, 15, "normal"])
        # Distinct sample 2
        writer.writerow(["2026-10-10T12:00:05.123456Z", "webapp", 110, 15, "normal"])
        # Duplicate of sample 2 with +00:00 notation
        writer.writerow(["2026-10-10T12:00:05.123456+00:00", "webapp", 110, 15, "normal"])

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    samples = engine.read_new_workload_samples()

    # Deduplication must identify both as duplicates despite string differences
    assert len(samples) == 2
    assert engine._workload_cumulative_count == 2
    assert len(engine._workload_seen_samples) == 2

    # Now append 80 windows (160 samples) and verify memory bounds under pruning
    with open(wl_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for i in range(160):
            ts = (base_ts + timedelta(seconds=10 + i * 5)).isoformat()
            writer.writerow([ts, "webapp", 100, 15, "normal"])

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file, max_retained_windows=20)
    engine.process_live_telemetry()

    # Bounded retention: max 20 + 5 = 25 windows retained.
    # At 2 samples per window, _workload_seen_samples must not exceed ~55 items (not 162!)
    assert len(engine._workload_seen_samples) <= 25 * 2 + 2
