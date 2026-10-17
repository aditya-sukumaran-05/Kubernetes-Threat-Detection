"""Regression tests for Client Attack Simulation Console, Telemetry, and Correlation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from experiments.correlation import (
    CorrelationReport,
    correlate_client_session,
    floor_to_10s_window,
    parse_iso_utc,
)
from experiments import traffic_simulator
from telemetry.client_telemetry import (
    ClientRequestRecord,
    ClientSessionManifest,
    ClientTelemetryLogger,
    get_client_utc_now,
)


def test_client_request_record_serialization() -> None:
    rec = ClientRequestRecord(
        experiment_id="exp_01",
        session_id="sess_01",
        request_id="req_001",
        client_timestamp_utc="2026-10-17T10:00:00.000Z",
        target_service="http://webapp",
        method="GET",
        status_code=200,
        duration_ms=14.5,
        success=True,
        error_category="none",
        scenario_label="benign_baseline",
    )
    d = rec.to_dict()
    assert d["experiment_id"] == "exp_01"
    assert d["status_code"] == 200
    assert d["duration_ms"] == 14.5

    rec2 = ClientRequestRecord.from_dict(d)
    assert rec2 == rec


def test_client_session_manifest_serialization() -> None:
    manifest = ClientSessionManifest(
        session_id="burst_20261017T100000Z",
        experiment_id="exp_burst",
        scenario="network_burst",
        target_service="http://webapp",
        client_pod="traffic-simulator",
        status="completed",
        start_time_utc="2026-10-17T10:00:00.000Z",
        end_time_utc="2026-10-17T10:00:10.000Z",
        duration_seconds=10.0,
        requests_attempted=50,
        requests_completed=50,
        requests_failed=0,
        response_code_distribution={"200": 50},
        latency_summary={"p50_ms": 12.0},
        errors=[],
        metadata={"note": "test"},
    )
    d = manifest.to_dict()
    assert d["scenario"] == "network_burst"
    assert d["requests_completed"] == 50

    m2 = ClientSessionManifest.from_dict(d)
    assert m2.session_id == manifest.session_id
    assert m2.duration_seconds == 10.0


def test_client_telemetry_logger_request_recording(tmp_path: Path) -> None:
    logger = ClientTelemetryLogger(tmp_path)
    r1 = ClientRequestRecord(
        experiment_id="exp1",
        session_id="sess1",
        request_id="r1",
        client_timestamp_utc="2026-10-17T10:00:00.000Z",
        target_service="http://webapp",
        method="GET",
        status_code=200,
        duration_ms=10.0,
        success=True,
        error_category="none",
        scenario_label="benign_baseline",
    )
    r2 = ClientRequestRecord(
        experiment_id="exp1",
        session_id="sess2",
        request_id="r2",
        client_timestamp_utc="2026-10-17T10:00:01.000Z",
        target_service="http://webapp",
        method="GET",
        status_code=500,
        duration_ms=25.0,
        success=False,
        error_category="server_error",
        scenario_label="benign_baseline",
    )

    logger.record_request(r1)
    logger.record_request(r2)

    reqs_sess1 = logger.get_requests_for_session("sess1")
    assert len(reqs_sess1) == 1
    assert reqs_sess1[0].request_id == "r1"
    assert reqs_sess1[0].success is True

    reqs_sess2 = logger.get_requests_for_session("sess2")
    assert len(reqs_sess2) == 1
    assert reqs_sess2[0].status_code == 500


def test_client_telemetry_logger_manifest_persistence(tmp_path: Path) -> None:
    logger = ClientTelemetryLogger(tmp_path)
    manifest = ClientSessionManifest(
        session_id="sess_alpha",
        experiment_id="exp_alpha",
        scenario="runtime_anomaly",
        target_service="in-container-exec",
        client_pod="deployment/webapp",
        status="completed",
        start_time_utc="2026-10-17T10:05:00.000Z",
        commands_attempted=4,
        commands_completed=4,
    )
    saved_path = logger.save_session_manifest(manifest)
    assert saved_path.exists()

    loaded = logger.get_session_manifest("sess_alpha")
    assert loaded is not None
    assert loaded.session_id == "sess_alpha"
    assert loaded.scenario == "runtime_anomaly"

    all_sessions = logger.list_sessions()
    assert len(all_sessions) == 1
    assert all_sessions[0].session_id == "sess_alpha"


def test_latency_summary_computation() -> None:
    logger = ClientTelemetryLogger()
    empty = logger.compute_latency_summary([])
    assert empty["mean_ms"] == 0.0
    assert empty["p95_ms"] == 0.0

    durations = [10.0, 20.0, 30.0, 40.0, 50.0]
    summary = logger.compute_latency_summary(durations)
    assert summary["min_ms"] == 10.0
    assert summary["max_ms"] == 50.0
    assert summary["mean_ms"] == 30.0
    assert summary["p50_ms"] == 30.0


def test_cpu_stress_safety_rejects_cpu_test() -> None:
    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_cpu_stress_scenario(
            duration_seconds=5.0,
            target_workload="pod/cpu-test",
        )


def test_cpu_stress_execution_and_cleanup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen_cmds: list[list[str]] = []

    class DummyProc:
        pid = 12345
        def poll(self):
            return 0
        def kill(self):
            pass
        def wait(self, timeout=None):
            return 0

    def mock_popen(cmd, **kwargs):
        seen_cmds.append(cmd)
        return DummyProc()

    def mock_run(cmd, **kwargs):
        seen_cmds.append(cmd)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(traffic_simulator.subprocess, "Popen", mock_popen)
    monkeypatch.setattr(traffic_simulator.subprocess, "run", mock_run)
    monkeypatch.setattr(traffic_simulator, "SIMULATION_RUNS_DIR", tmp_path / "sims")
    monkeypatch.setattr(traffic_simulator, "time", SimpleNamespace(
        perf_counter=lambda: 100.0,
        sleep=lambda s: None,
    ))

    session = traffic_simulator.execute_cpu_stress_scenario(
        duration_seconds=10.0,
        target_workload="deployment/webapp",
        namespace="default",
    )

    assert session.scenario == "cpu_stress"
    assert session.status == "completed"
    # Ensure command includes target deployment/webapp and PID file
    cmd_str = " ".join(seen_cmds[0])
    assert "deployment/webapp" in cmd_str
    assert "kubernetes-threat-detection-cpu-attack.pid" in cmd_str


def test_cancel_all_active_traffic(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    logger = ClientTelemetryLogger(tmp_path / "client")
    m1 = ClientSessionManifest(
        session_id="run_1",
        experiment_id="exp_1",
        scenario="network_burst",
        target_service="http://webapp",
        client_pod="traffic-simulator",
        status="running",
        start_time_utc="2026-10-17T10:00:00Z",
    )
    logger.save_session_manifest(m1)

    monkeypatch.setattr(traffic_simulator, "stop_benign_traffic", lambda: {"status": "stopped"})
    monkeypatch.setattr(traffic_simulator, "stop_cpu_attack", lambda c: None)
    monkeypatch.setattr(traffic_simulator, "ClientTelemetryLogger", lambda: logger)

    res = traffic_simulator.cancel_all_active_traffic()
    assert res["status"] == "cancelled"
    assert "run_1" in res["cancelled_sessions"]

    updated = logger.get_session_manifest("run_1")
    assert updated is not None
    assert updated.status == "cancelled"


def test_correlation_engine_floor_window() -> None:
    dt = parse_iso_utc("2026-10-17T10:15:27.450Z")
    floored = floor_to_10s_window(dt)
    assert floored.second == 20
    assert floored.microsecond == 0


def test_correlation_engine_with_mock_telemetry(tmp_path: Path) -> None:
    # Set up client session
    client_dir = tmp_path / "telemetry" / "data" / "client"
    logger = ClientTelemetryLogger(client_dir)

    manifest = ClientSessionManifest(
        session_id="burst_test_01",
        experiment_id="client_burst",
        scenario="network_burst",
        target_service="http://webapp",
        client_pod="traffic-simulator",
        status="completed",
        start_time_utc="2026-10-17T10:00:02.000Z",
        end_time_utc="2026-10-17T10:00:08.000Z",
        duration_seconds=6.0,
        requests_attempted=30,
        requests_completed=30,
    )
    logger.save_session_manifest(manifest)

    # Set up server network events in matching window
    net_dir = tmp_path / "telemetry" / "data" / "network"
    net_dir.mkdir(parents=True)
    net_file = net_dir / "network_events.jsonl"
    events = [
        {"collector_timestamp": "2026-10-17T10:00:03.000Z", "type": "accept", "src": {"addr": "10.0.0.1", "port": 80}},
        {"collector_timestamp": "2026-10-17T10:00:04.000Z", "type": "accept", "src": {"addr": "10.0.0.1", "port": 80}},
    ]
    net_file.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")

    report = correlate_client_session("burst_test_01", project_root=tmp_path, logger=logger)

    assert report.session_id == "burst_test_01"
    assert report.scenario == "network_burst"
    assert report.server_network_events == 2
    assert report.matched_window_count >= 1
    assert report.correlation_grade in ("strongly_correlated", "partially_correlated")
    assert "Live Detection" in report.soc_navigation_guide["recommended_page"]
    assert "Network Only" in report.soc_navigation_guide["recommended_modality"]


def test_correlation_missing_session(tmp_path: Path) -> None:
    report = correlate_client_session("non_existent_session", project_root=tmp_path)
    assert report.client_status == "not_found"
    assert report.correlation_grade == "uncorrelated"


def test_client_console_streamlit_app_renders() -> None:
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("client_console/app.py")
    at.run()
    assert not at.exception
    assert len(at.tabs) == 3
    assert len(at.button) >= 5
