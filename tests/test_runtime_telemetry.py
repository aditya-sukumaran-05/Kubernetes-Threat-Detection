"""Unit and integration tests for Kubernetes runtime process telemetry."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dashboard.live_engine import CollectorHealth, LiveTelemetryEngine
from ml.inference import ThreatDetector
from telemetry.features.runtime import extract_runtime_features
from telemetry.schemas import RuntimeEvent, SchemaError, load_runtime_events


def _make_raw_runtime_event(
    ts_iso: str,
    comm: str = "whoami",
    args: str = "whoami",
    uid: int = 0,
    user: str = "root",
    pod: str = "webapp-test-pod",
) -> str:
    return json.dumps({
        "timestamp": ts_iso,
        "args": args,
        "cwd": "/",
        "exepath": f"/usr/bin/{comm}",
        "proc": {
            "comm": comm,
            "pid": 12345,
            "tid": 12345,
            "creds": {"uid": uid, "gid": uid, "user": user},
            "parent": {"comm": "containerd-shim", "pid": 3000},
        },
        "k8s": {
            "podName": pod,
            "namespace": "default",
            "containerName": "nginx",
        },
        "runtime": {
            "containerId": "abc123containerid",
        },
        "error": "",
    })


def test_load_runtime_events_success(tmp_path: Path) -> None:
    p = tmp_path / "runtime.jsonl"
    p.write_text(
        _make_raw_runtime_event("2026-10-10T12:00:01.000Z", "whoami") + "\n"
        + _make_raw_runtime_event("2026-10-10T12:00:05.000Z", "ls", "ls /etc/nginx") + "\n",
        encoding="utf-8",
    )
    events = load_runtime_events(p)
    assert len(events) == 2
    assert events[0].comm == "whoami"
    assert events[0].uid == 0
    assert events[0].pod == "webapp-test-pod"
    assert events[1].comm == "ls"
    assert events[1].args == "ls /etc/nginx"


def test_load_runtime_events_malformed_raises(tmp_path: Path) -> None:
    p = tmp_path / "runtime_bad.jsonl"
    p.write_text("invalid json\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_runtime_events(p)


def test_extract_runtime_features_empty() -> None:
    feats = extract_runtime_features([], window_seconds=10)
    assert feats["runtime_event_count"] == 0
    assert feats["runtime_root_exec_count"] == 0
    assert feats["runtime_exec_rate"] == 0.0


def test_live_engine_runtime_ingestion(tmp_path: Path) -> None:
    rt_file = tmp_path / "runtime_events.jsonl"
    net_file = tmp_path / "network_events.jsonl"
    wl_file = tmp_path / "workload_metrics.csv"

    # Write initial runtime event
    rt_file.write_text(
        _make_raw_runtime_event("2026-10-10T12:00:02.000Z", "whoami") + "\n",
        encoding="utf-8",
    )
    # Write empty files for net and wl
    net_file.write_text("", encoding="utf-8")
    wl_file.write_text("timestamp,pod,cpu_millicores,memory_mib\n", encoding="utf-8")

    mock_detector = MagicMock(spec=ThreatDetector)
    mock_detector.project_root = tmp_path

    engine = LiveTelemetryEngine(
        detector=mock_detector,
        network_path=net_file,
        workload_path=wl_file,
        runtime_path=rt_file,
    )

    records = engine.process_live_telemetry()
    assert len(records) == 1
    rec = records[0]
    assert rec.window_start == "2026-10-10T12:00:00.000Z"
    assert rec.runtime_available is True
    assert len(rec.runtime_events) == 1
    assert rec.runtime_events[0].comm == "whoami"
    assert rec.runtime_features["runtime_root_exec_count"] == 1
    assert rec.runtime_features["runtime_sensitive_command_count"] == 1
    # Multimodal fusion requires network + workload; runtime alone should NOT trigger fabricated fusion
    assert rec.is_fused is False


def test_live_engine_runtime_collector_health(tmp_path: Path) -> None:
    rt_file = tmp_path / "runtime_events.jsonl"
    rt_file.write_text(
        _make_raw_runtime_event("2026-10-10T12:00:02.000Z", "whoami") + "\n",
        encoding="utf-8",
    )
    mock_detector = MagicMock(spec=ThreatDetector)
    mock_detector.project_root = tmp_path

    engine = LiveTelemetryEngine(
        detector=mock_detector,
        runtime_path=rt_file,
    )
    engine.read_new_runtime_events()

    health = engine.get_runtime_health()
    assert isinstance(health, CollectorHealth)
    assert health.total_valid_records == 1
    assert health.file_exists is True
    assert health.source_name == "Runtime (eBPF Process Trace)"


def test_runtime_feature_extractor_imports_and_validates_representative_event() -> None:
    """Regression test: verify runtime feature extractor imports and validates representative event."""
    from telemetry.features.runtime import extract_runtime_features
    from telemetry.schemas import RuntimeEvent

    raw_event = json.loads(_make_raw_runtime_event("2026-10-10T12:00:00.000Z", "whoami"))
    event = RuntimeEvent.from_raw(raw_event)
    assert isinstance(event, RuntimeEvent)
    assert event.comm == "whoami"
    assert event.uid == 0
    assert event.username == "root"
    assert event.parent_comm == "containerd-shim"

    features = extract_runtime_features([event], window_seconds=10)
    assert features["runtime_event_count"] == 1
    assert features["runtime_root_exec_count"] == 1
    assert features["runtime_sensitive_command_count"] == 1
    assert features["runtime_interactive_shell_count"] == 0
    assert features["runtime_exec_rate"] == 0.1


def test_resolve_gadget_executable_custom_and_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from telemetry.runtime_collector import resolve_gadget_executable

    # 1. Custom binary passed directly
    custom_bin = str(tmp_path / "custom-gadget.exe")
    Path(custom_bin).touch()
    assert resolve_gadget_executable(custom_bin) == [custom_bin]

    # 2. Environment variable GADGET_BIN
    env_bin = str(tmp_path / "env-gadget.exe")
    Path(env_bin).touch()
    monkeypatch.setenv("GADGET_BIN", env_bin)
    assert resolve_gadget_executable() == [env_bin]
    monkeypatch.delenv("GADGET_BIN")

    # 3. Default resolution returns non-empty list of string tokens
    resolved = resolve_gadget_executable()
    assert isinstance(resolved, list)
    assert len(resolved) >= 1
    assert any("gadget" in tok.lower() for tok in resolved)


def test_runtime_collector_stale_pid_cleanup(tmp_path: Path) -> None:
    import os
    from telemetry.runtime_collector import check_and_acquire_pid, release_pid

    pid_file = str(tmp_path / ".runtime_collector.pid")
    # Write a definitively non-existent PID
    stale_pid = 99999999
    Path(pid_file).write_text(str(stale_pid), encoding="utf-8")

    check_and_acquire_pid(pid_file)

    # Stale PID should have been replaced with current process PID
    assert Path(pid_file).exists()
    assert Path(pid_file).read_text(encoding="utf-8").strip() == str(os.getpid())

    # Safe release removes current process PID
    release_pid(pid_file)
    assert not Path(pid_file).exists()


def test_runtime_collector_duplicate_live_pid_rejected(tmp_path: Path) -> None:
    import os
    from telemetry.runtime_collector import check_and_acquire_pid

    pid_file = str(tmp_path / ".runtime_collector.pid")
    # Write current process PID which is guaranteed to be alive
    Path(pid_file).write_text(str(os.getpid()), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        check_and_acquire_pid(pid_file)
    assert exc_info.value.code == 1

    # Live PID file must NOT have been deleted
    assert Path(pid_file).exists()
    assert Path(pid_file).read_text(encoding="utf-8").strip() == str(os.getpid())


def test_runtime_collector_release_pid_safe(tmp_path: Path) -> None:
    from telemetry.runtime_collector import release_pid

    pid_file = str(tmp_path / ".runtime_collector.pid")
    # Foreign PID (not os.getpid())
    foreign_pid = 12345
    Path(pid_file).write_text(str(foreign_pid), encoding="utf-8")

    release_pid(pid_file)
    # File must NOT be deleted because PID doesn't match os.getpid()
    assert Path(pid_file).exists()
    assert Path(pid_file).read_text(encoding="utf-8").strip() == str(foreign_pid)


def test_live_engine_runtime_path_resolution_with_resolved_network_path() -> None:
    """Regression test: LiveTelemetryEngine initialized with resolved absolute network path
    must resolve runtime_path to telemetry/data/runtime/runtime_events.jsonl, not network/runtime_events.jsonl."""
    from dashboard.live_engine import DEFAULT_NETWORK_PATH, DEFAULT_RUNTIME_PATH, LiveTelemetryEngine

    resolved_net_path = Path(DEFAULT_NETWORK_PATH).resolve()
    engine = LiveTelemetryEngine(network_path=resolved_net_path)

    expected_runtime_path = Path(DEFAULT_RUNTIME_PATH).resolve()
    actual_runtime_path = engine._resolve_path(engine.runtime_path)

    # Must resolve to telemetry/data/runtime/runtime_events.jsonl, NOT telemetry/data/network/runtime_events.jsonl
    assert actual_runtime_path == expected_runtime_path
    assert "network" not in actual_runtime_path.parent.name
    assert actual_runtime_path.parent.name == "runtime"
    health = engine.get_runtime_health()
    assert health.file_exists is True
    assert "file not found" not in health.status_message



