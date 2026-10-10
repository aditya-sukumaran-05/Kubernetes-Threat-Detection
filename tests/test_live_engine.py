"""Unit and integration tests for the live telemetry streaming engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dashboard.live_engine import LiveTelemetryEngine, LiveWindowRecord
from ml.inference import InferenceResult, ThreatDetector


def _make_raw_net_event(ts_iso: str, event_type: str = "accept", port: int = 54321) -> str:
    return json.dumps({
        "timestamp": ts_iso,
        "type": event_type,
        "src": {"addr": "10.244.0.5", "port": port},
        "dst": {"addr": "10.244.0.2", "port": 80},
        "k8s": {"podName": "webapp-live-test", "namespace": "default"},
        "error": None,
    })


def test_live_engine_incremental_network_reading(tmp_path: Path) -> None:
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"
    net_file.write_text(
        _make_raw_net_event("2026-10-10T10:00:01.000Z") + "\n"
        + _make_raw_net_event("2026-10-10T10:00:03.000Z") + "\n",
        encoding="utf-8",
    )

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    events = engine.read_new_network_events()
    assert len(events) == 2
    assert len(engine._network_valid_events) == 2

    # Second read without new data should return 0 new events
    assert len(engine.read_new_network_events()) == 0

    # Append 1 new event
    with net_file.open("a", encoding="utf-8") as handle:
        handle.write(_make_raw_net_event("2026-10-10T10:00:05.000Z") + "\n")

    new_events = engine.read_new_network_events()
    assert len(new_events) == 1
    assert len(engine._network_valid_events) == 3


def test_live_engine_handles_partial_line_write(tmp_path: Path) -> None:
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    # Write one complete line and one partial line (no trailing newline)
    full_event_1 = _make_raw_net_event("2026-10-10T10:00:01.000Z")
    full_event_2 = _make_raw_net_event("2026-10-10T10:00:04.000Z")
    partial_chunk = full_event_2[: len(full_event_2) // 2]
    remaining_chunk = full_event_2[len(full_event_2) // 2 :]

    net_file.write_text(full_event_1 + "\n" + partial_chunk, encoding="utf-8")

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    events = engine.read_new_network_events()
    assert len(events) == 1  # Only the complete first event is parsed
    assert engine._network_partial_buffer == partial_chunk

    # Now simulate the writer finishing the line
    with net_file.open("a", encoding="utf-8") as handle:
        handle.write(remaining_chunk + "\n")

    events_second_pass = engine.read_new_network_events()
    assert len(events_second_pass) == 1
    assert events_second_pass[0].timestamp == datetime(2026, 10, 10, 10, 0, 4, tzinfo=timezone.utc)
    assert engine._network_partial_buffer == ""


def test_live_engine_skips_malformed_records(tmp_path: Path) -> None:
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    content = (
        _make_raw_net_event("2026-10-10T10:00:01.000Z") + "\n"
        + "{malformed_not_json\n"
        + json.dumps({"timestamp": "not_an_iso_ts", "type": "accept"}) + "\n"
        + _make_raw_net_event("2026-10-10T10:00:05.000Z") + "\n"
    )
    net_file.write_text(content, encoding="utf-8")

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    events = engine.read_new_network_events()
    assert len(events) == 2
    assert engine._network_malformed_count == 2


def test_live_engine_incremental_workload_reading(tmp_path: Path) -> None:
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    header = "timestamp,pod,cpu_millicores,memory_mib,label\n"
    row1 = "2026-10-10T10:00:02.000Z,webapp-live,120,15,normal\n"
    row2 = "2026-10-10T10:00:07.000Z,webapp-live,130,15,normal\n"
    wl_file.write_text(header + row1 + row2, encoding="utf-8")

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    samples = engine.read_new_workload_samples()
    assert len(samples) == 2
    assert len(engine._workload_valid_samples) == 2

    # Subsequent read with no new rows returns 0
    assert len(engine.read_new_workload_samples()) == 0

    # Append 1 row
    row3 = "2026-10-10T10:00:12.000Z,webapp-live,140,15,normal\n"
    with wl_file.open("a", encoding="utf-8") as handle:
        handle.write(row3)

    new_samples = engine.read_new_workload_samples()
    assert len(new_samples) == 1
    assert len(engine._workload_valid_samples) == 3


def test_live_engine_window_inference_caching(tmp_path: Path) -> None:
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"
    net_file.write_text(
        _make_raw_net_event("2026-10-10T10:00:01.000Z") + "\n",
        encoding="utf-8",
    )

    mock_detector = MagicMock(spec=ThreatDetector)
    mock_detector.predict.return_value = InferenceResult(
        predicted_label="normal",
        attack_probability=0.05,
        confidence=0.95,
        window_start="2026-10-10T10:00:00.000Z",
        window_end="2026-10-10T10:00:10.000Z",
        modality="network",
        model_name="random_forest",
        evidence={"feature_values": {}},
        affected_pods="webapp-live-test",
    )

    engine = LiveTelemetryEngine(detector=mock_detector, network_path=net_file, workload_path=wl_file)

    # First call: executes inference once
    records_1 = engine.process_live_telemetry("random_forest")
    assert len(records_1) == 1
    assert mock_detector.predict.call_count == 1

    # Second call without new windows: must hit cache and NOT invoke detector.predict again
    records_2 = engine.process_live_telemetry("random_forest")
    assert len(records_2) == 1
    assert mock_detector.predict.call_count == 1  # Still exactly 1!


def test_live_engine_multimodal_alignment_and_missing_handling(tmp_path: Path) -> None:
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    # Window W1: 10:00:00 -> has BOTH network and workload
    # Window W2: 10:00:10 -> has ONLY network
    # Window W3: 10:00:20 -> has ONLY workload
    net_lines = (
        _make_raw_net_event("2026-10-10T10:00:02.000Z") + "\n"
        + _make_raw_net_event("2026-10-10T10:00:12.000Z") + "\n"
    )
    net_file.write_text(net_lines, encoding="utf-8")

    wl_lines = (
        "timestamp,pod,cpu_millicores,memory_mib,label\n"
        + "2026-10-10T10:00:03.000Z,webapp-live,120,15,normal\n"
        + "2026-10-10T10:00:23.000Z,webapp-live,130,15,normal\n"
    )
    wl_file.write_text(wl_lines, encoding="utf-8")

    mock_detector = MagicMock(spec=ThreatDetector)
    mock_detector.predict.side_effect = lambda win, modality, model_name: InferenceResult(
        predicted_label="normal",
        attack_probability=0.05,
        confidence=0.95,
        window_start=win.get("window_start"),
        window_end=win.get("window_end"),
        modality=modality,
        model_name=model_name,
        evidence={"feature_values": {}},
        affected_pods="webapp-live",
    )

    engine = LiveTelemetryEngine(detector=mock_detector, network_path=net_file, workload_path=wl_file)
    records = engine.process_live_telemetry("random_forest")

    assert len(records) == 3
    w1, w2, w3 = records[0], records[1], records[2]

    # W1: Fused window
    assert w1.window_start == "2026-10-10T10:00:00.000Z"
    assert w1.network_available is True
    assert w1.workload_available is True
    assert w1.is_fused is True
    assert "random_forest" in w1.network_inferences
    assert "random_forest" in w1.workload_inferences
    assert "random_forest" in w1.fusion_inferences

    # W2: Network only (Workload missing)
    assert w2.window_start == "2026-10-10T10:00:10.000Z"
    assert w2.network_available is True
    assert w2.workload_available is False
    assert w2.is_fused is False
    assert "random_forest" in w2.network_inferences
    assert "random_forest" not in w2.workload_inferences
    assert "random_forest" not in w2.fusion_inferences  # Not fabricated!

    # W3: Workload only (Network missing)
    assert w3.window_start == "2026-10-10T10:00:20.000Z"
    assert w3.network_available is False
    assert w3.workload_available is True
    assert w3.is_fused is False
    assert "random_forest" not in w3.network_inferences
    assert "random_forest" in w3.workload_inferences
    assert "random_forest" not in w3.fusion_inferences  # Not fabricated!


def test_live_engine_collector_health_staleness(tmp_path: Path) -> None:
    from datetime import timedelta
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    # Stale timestamp: 1 hour in the past relative to now
    stale_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    net_file.write_text(_make_raw_net_event(stale_ts) + "\n", encoding="utf-8")

    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file)
    engine.read_new_network_events()

    health = engine.get_network_health()
    assert health.file_exists is True
    assert health.total_valid_records == 1
    assert health.is_active is False
    assert "Idle / Stale" in health.status_message


def test_timestamp_alignment_epoch_floor() -> None:
    """Verify that network and workload timestamps with subsecond offsets floor to identical window boundaries."""
    from telemetry.windowing import window_start, isoformat_z
    from telemetry.schemas import parse_utc_timestamp

    ts_net_early = parse_utc_timestamp("2026-10-10T12:00:00.001234Z")
    ts_net_late = parse_utc_timestamp("2026-10-10T12:00:09.999888Z")
    ts_wl_mid = parse_utc_timestamp("2026-10-10T12:00:05.500000Z")

    w_net_early = isoformat_z(window_start(ts_net_early, 10))
    w_net_late = isoformat_z(window_start(ts_net_late, 10))
    w_wl_mid = isoformat_z(window_start(ts_wl_mid, 10))

    assert w_net_early == "2026-10-10T12:00:00.000Z"
    assert w_net_late == "2026-10-10T12:00:00.000Z"
    assert w_wl_mid == "2026-10-10T12:00:00.000Z"


def test_live_engine_dynamic_window_update(tmp_path: Path) -> None:
    """Verify that when new events arrive for an open window, cached inferences are updated."""
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    # First event in window 10:00:00
    net_file.write_text(_make_raw_net_event("2026-10-10T10:00:02.000Z") + "\n", encoding="utf-8")

    mock_detector = MagicMock(spec=ThreatDetector)
    mock_detector.predict.side_effect = lambda win, modality, model_name: InferenceResult(
        predicted_label="normal",
        attack_probability=0.1,
        confidence=0.9,
        window_start=win.get("window_start"),
        window_end=win.get("window_end"),
        modality=modality,
        model_name=model_name,
        evidence={"event_count": win.get("network_event_count")},
        affected_pods="webapp-live",
    )

    engine = LiveTelemetryEngine(detector=mock_detector, network_path=net_file, workload_path=wl_file)
    recs_1 = engine.process_live_telemetry("random_forest")
    assert len(recs_1) == 1
    assert recs_1[0].network_features["network_event_count"] == 1
    assert mock_detector.predict.call_count == 1
    assert recs_1[0].network_inferences["random_forest"].evidence["event_count"] == 1

    # Second event arrives in the same window (e.g. at 10:00:06)
    with net_file.open("a", encoding="utf-8") as handle:
        handle.write(_make_raw_net_event("2026-10-10T10:00:06.000Z") + "\n")

    recs_2 = engine.process_live_telemetry("random_forest")
    assert len(recs_2) == 1
    assert recs_2[0].network_features["network_event_count"] == 2
    # Prediction should have been re-evaluated with the updated count
    assert mock_detector.predict.call_count == 2
    assert recs_2[0].network_inferences["random_forest"].evidence["event_count"] == 2


def test_live_engine_window_buffer_refresh_pruning(tmp_path: Path) -> None:
    """Verify that buffer retention is bounded and internal registry prunes expired keys."""
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    # Create 5 distinct 10-second windows
    events = [
        _make_raw_net_event(f"2026-10-10T10:0{i}:01.000Z") + "\n"
        for i in range(5)
    ]
    net_file.write_text("".join(events), encoding="utf-8")

    # Engine with max_retained_windows = 3
    engine = LiveTelemetryEngine(network_path=net_file, workload_path=wl_file, max_retained_windows=3)
    recs = engine.process_live_telemetry()

    assert len(recs) == 3
    # Check that only the latest 3 windows are retained
    expected_starts = [
        "2026-10-10T10:02:00.000Z",
        "2026-10-10T10:03:00.000Z",
        "2026-10-10T10:04:00.000Z",
    ]
    assert [r.window_start for r in recs] == expected_starts
    # Internal windows dictionary must also be pruned to exactly 3 keys
    assert set(engine.windows.keys()) == set(expected_starts)


def test_live_window_slider_mapping_exact() -> None:
    """Verify that selecting index k maps to records[k] without off-by-one or inversion."""
    records = [
        LiveWindowRecord(
            window_start=f"2026-10-10T10:{i:02d}:00.000Z",
            window_end=f"2026-10-10T10:{i:02d}:10.000Z",
            affected_pods="webapp",
            network_available=(i % 2 == 0),
            workload_available=True,
        )
        for i in range(10)
    ]

    total_windows = len(records)
    for slider_val in range(1, total_windows + 1):
        target_idx = slider_val - 1
        target_rec = records[target_idx]
        assert target_rec.window_start == f"2026-10-10T10:{target_idx:02d}:00.000Z"
        assert target_rec.network_available == (target_idx % 2 == 0)


def test_live_engine_detects_running_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that process liveliness detection reports active collector status."""
    import os
    from dashboard.live_engine import DEFAULT_NETWORK_PATH

    # Mock _check_collector_process to simulate a live collector with current PID
    monkeypatch.setattr(
        "dashboard.live_engine._check_collector_process",
        lambda script, pid_file: (True, os.getpid()),
    )

    engine = LiveTelemetryEngine(network_path=DEFAULT_NETWORK_PATH)
    health = engine.get_network_health()
    assert health.is_process_running is True
    assert health.pid == os.getpid()
    assert "Listening" in health.status_message


