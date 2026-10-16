"""Tests for telemetry stream realignment, offset detection, and derived datasets."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from experiments.alignment import (
    create_derived_telemetry_file,
    detect_network_cluster_offset,
    detect_runtime_cluster_offset,
    reprocess_orchestrator_session,
)
from telemetry.schemas import load_network_events, load_runtime_events
from telemetry.windowing import window_start


@pytest.fixture
def sample_network_events(tmp_path: Path) -> Path:
    p = tmp_path / "network_raw.jsonl"
    events = [
        # Cluster shifted by 100 seconds (raw ts: 10:00:00, host act: 10:01:40)
        {"timestamp": "2026-10-14T10:00:00.000Z", "type": "accept", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50000}},
        {"timestamp": "2026-10-14T10:00:00.010Z", "type": "close", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50000}},
        {"timestamp": "2026-10-14T10:00:01.500Z", "type": "accept", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50002}},
        {"timestamp": "2026-10-14T10:00:01.510Z", "type": "close", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50002}},
    ]
    with p.open("w", encoding="utf-8") as handle:
        for ev in events:
            handle.write(json.dumps(ev) + "\n")
    return p


@pytest.fixture
def sample_runtime_events(tmp_path: Path) -> Path:
    p = tmp_path / "runtime_raw.jsonl"
    events = [
        {"timestamp": "2026-10-14T10:00:00.000Z", "k8s": {"podName": "webapp"}, "proc": {"comm": "id"}, "args": "id"},
        {"timestamp": "2026-10-14T10:00:01.000Z", "k8s": {"podName": "webapp"}, "proc": {"comm": "whoami"}, "args": "whoami"},
        {"timestamp": "2026-10-14T10:00:02.000Z", "k8s": {"podName": "webapp"}, "proc": {"comm": "curl"}, "args": "curl -s http://webapp"},
    ]
    with p.open("w", encoding="utf-8") as handle:
        for ev in events:
            handle.write(json.dumps(ev) + "\n")
    return p


def test_detect_network_cluster_offset(sample_network_events: Path) -> None:
    act_start = "2026-10-14T10:01:40.000Z"
    act_end = "2026-10-14T10:01:42.000Z"
    res = detect_network_cluster_offset(
        sample_network_events,
        activity_start_utc=act_start,
        activity_end_utc=act_end,
        target_port=80,
    )
    assert res.is_aligned is True
    assert res.raw_event_count == 4
    # Expected offset: act_start (10:01:40) - raw first (10:00:00) = 100.0s
    assert res.detected_offset_seconds == 100.0
    assert res.cluster_start_raw == "2026-10-14T10:00:00.000Z"


def test_detect_runtime_cluster_offset(sample_runtime_events: Path) -> None:
    act_start = "2026-10-14T10:01:40.000Z"
    act_end = "2026-10-14T10:01:43.000Z"
    res = detect_runtime_cluster_offset(
        sample_runtime_events,
        activity_start_utc=act_start,
        activity_end_utc=act_end,
        expected_commands=["id", "whoami", "curl"],
    )
    assert res.is_aligned is True
    assert res.raw_event_count == 3
    assert res.detected_offset_seconds == 100.0


def test_create_derived_telemetry_file(sample_network_events: Path, tmp_path: Path) -> None:
    derived_out = tmp_path / "derived_network.jsonl"
    count = create_derived_telemetry_file(sample_network_events, derived_out, offset_seconds=100.0)
    assert count == 4
    assert derived_out.exists()

    loaded = load_network_events(derived_out)
    assert len(loaded) == 4
    # First event shifted to 10:01:40.000Z
    assert loaded[0].timestamp.isoformat() == "2026-10-14T10:01:40+00:00"
    # Window start for 10-second window
    w = window_start(loaded[0].timestamp, window_seconds=10)
    assert w.isoformat() == "2026-10-14T10:01:40+00:00"


def test_derived_preserves_raw_events_bitwise(sample_network_events: Path, tmp_path: Path) -> None:
    derived_out = tmp_path / "derived_network.jsonl"
    create_derived_telemetry_file(sample_network_events, derived_out, offset_seconds=100.0)

    raw_lines = [json.loads(l) for l in sample_network_events.read_text(encoding="utf-8").splitlines() if l.strip()]
    derived_lines = [json.loads(l) for l in derived_out.read_text(encoding="utf-8").splitlines() if l.strip()]

    assert len(raw_lines) == len(derived_lines)
    for r, d in zip(raw_lines, derived_lines):
        assert d["raw_timestamp"] == r["timestamp"]
        assert d["src"] == r["src"]
        assert d["dst"] == r["dst"]
        assert d["type"] == r["type"]


def test_reprocess_session_marks_raw_incomplete_and_derived_complete(tmp_path: Path) -> None:
    # Build a mock session directory
    session_dir = tmp_path / "orchestrator_runs/20261014T100000Z_test_session"
    session_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "session_id": "20261014T100000Z_test_session",
        "scenario": "normal",
        "status": "completed",  # previously mistakenly set to completed
        "dataset_suitable": True,
        "parameters": {"requests": 1},
        "timestamps": {
            "activity_start_time_utc": "2026-10-14T10:01:40.000Z",
            "activity_end_time_utc": "2026-10-14T10:01:42.000Z",
            "observation_end_utc": "2026-10-14T10:01:47.000Z",
        },
    }
    (session_dir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")

    # Raw telemetry dir
    raw_dir = tmp_path / "telemetry/data"
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "network").mkdir(parents=True, exist_ok=True)
    (raw_dir / "runtime").mkdir(parents=True, exist_ok=True)

    # Shifted raw events (offset = 100.0s)
    events = [
        {"timestamp": "2026-10-14T10:00:00.000Z", "type": "accept", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50000}},
        {"timestamp": "2026-10-14T10:00:00.010Z", "type": "close", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50000}},
    ]
    (raw_dir / "network/network_events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    (raw_dir / "runtime/runtime_events.jsonl").write_text("", encoding="utf-8")
    (raw_dir / "workload_metrics.csv").write_text("timestamp,pod,cpu_millicores,memory_mib\n2026-10-14T10:01:41.000Z,webapp,0,16\n", encoding="utf-8")

    summary = reprocess_orchestrator_session(session_dir, telemetry_root=raw_dir)

    # Check that raw was corrected to incomplete
    assert summary["raw_status"] == "incomplete"
    # Check that derived status is completed
    assert summary["derived_status"] == "completed"
    assert summary["derived_dataset_suitable"] is True
    assert summary["derived_window_count"] >= 1
    assert summary["offsets_applied"]["network"] == 100.0

    # Verify updated metadata.json
    updated_meta = json.loads((session_dir / "metadata.json").read_text(encoding="utf-8"))
    assert updated_meta["status"] == "incomplete"
    assert updated_meta["dataset_suitable"] is False
    assert updated_meta["derived_alignment_available"] is True


def test_reprocess_session_fails_suitability_on_event_accounting_mismatch(tmp_path: Path) -> None:
    session_dir = tmp_path / "orchestrator_runs/20261014T100000Z_mismatch_session"
    session_dir.mkdir(parents=True, exist_ok=True)

    # Expects 5 requests (10 events), but raw only has 2 events
    meta = {
        "session_id": "20261014T100000Z_mismatch_session",
        "scenario": "normal",
        "parameters": {"requests": 5},
        "timestamps": {
            "activity_start_time_utc": "2026-10-14T10:01:40.000Z",
            "activity_end_time_utc": "2026-10-14T10:01:42.000Z",
            "observation_end_utc": "2026-10-14T10:01:47.000Z",
        },
    }
    (session_dir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")

    raw_dir = tmp_path / "telemetry/data"
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "network").mkdir(parents=True, exist_ok=True)
    (raw_dir / "runtime").mkdir(parents=True, exist_ok=True)

    events = [
        {"timestamp": "2026-10-14T10:00:00.000Z", "type": "accept", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50000}},
        {"timestamp": "2026-10-14T10:00:00.010Z", "type": "close", "src": {"addr": "10.0.0.1", "port": 80}, "dst": {"addr": "10.0.0.2", "port": 50000}},
    ]
    (raw_dir / "network/network_events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    (raw_dir / "runtime/runtime_events.jsonl").write_text("", encoding="utf-8")
    (raw_dir / "workload_metrics.csv").write_text("timestamp,pod,cpu_millicores,memory_mib\n2026-10-14T10:01:41.000Z,webapp,0,16\n", encoding="utf-8")

    summary = reprocess_orchestrator_session(session_dir, telemetry_root=raw_dir)
    assert summary["derived_status"] == "incomplete"
    assert summary["derived_dataset_suitable"] is False

