"""Regression and validation tests for expanded scenarios, safety isolation, and performance optimizations."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import pytest

from experiments import correlation, traffic_simulator
from telemetry.client_telemetry import ClientSessionManifest, ClientTelemetryLogger


# ---------------------------------------------------------------------------
# 1. Target Safety & Isolation Tests (Strict Protection of pod/cpu-test)
# ---------------------------------------------------------------------------

def test_benign_baseline_safety_rejects_cpu_test() -> None:
    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_benign_baseline_scenario(client_pod="pod/cpu-test")

    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_benign_baseline_scenario(target_service="http://cpu-test:80")


def test_slow_vs_burst_safety_rejects_cpu_test() -> None:
    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_slow_vs_burst_scenario(client_pod="cpu-test")


def test_recovery_observation_safety_rejects_cpu_test() -> None:
    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_recovery_observation_scenario(client_pod="cpu-test-pod")


def test_runtime_benign_safety_rejects_cpu_test() -> None:
    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_runtime_benign_scenario(target_workload="cpu-test")


def test_sequential_multimodal_safety_rejects_cpu_test() -> None:
    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_sequential_multimodal_scenario(target_workload="pod/cpu-test")

    with pytest.raises(ValueError, match="Safety violation: Targeting cpu-test is strictly prohibited"):
        traffic_simulator.execute_sequential_multimodal_scenario(client_pod="cpu-test")


# ---------------------------------------------------------------------------
# 2. Mocked Execution of New Scenarios
# ---------------------------------------------------------------------------

def test_execute_benign_baseline_scenario_mocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(traffic_simulator, "SIMULATION_RUNS_DIR", tmp_path / "sims")
    client_logger = ClientTelemetryLogger(tmp_path / "client")
    monkeypatch.setattr(traffic_simulator, "ClientTelemetryLogger", lambda: client_logger)

    def mock_run_single(client_pod: str, target_svc: str, ns: str) -> tuple[bool, float, str]:
        return True, 8.5, ""

    monkeypatch.setattr(traffic_simulator, "run_single_http_request", mock_run_single)

    session = traffic_simulator.execute_benign_baseline_scenario(
        duration_seconds=2.0,
        base_interval=0.5,
        jitter=0.1,
    )

    assert session.scenario == "benign_baseline"
    assert session.status == "completed"
    assert session.requests_completed >= 1
    assert (tmp_path / "sims" / session.session_id / "metadata.json").exists()

    manifest = client_logger.get_session_manifest(session.session_id)
    assert manifest is not None
    assert manifest.scenario == "benign_baseline"
    assert manifest.status == "completed"


def test_execute_slow_vs_burst_scenario_mocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(traffic_simulator, "SIMULATION_RUNS_DIR", tmp_path / "sims")
    client_logger = ClientTelemetryLogger(tmp_path / "client")
    monkeypatch.setattr(traffic_simulator, "ClientTelemetryLogger", lambda: client_logger)

    def mock_run_single(client_pod: str, target_svc: str, ns: str) -> tuple[bool, float, str]:
        return True, 6.2, ""

    monkeypatch.setattr(traffic_simulator, "run_single_http_request", mock_run_single)

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="15\n", stderr="")

    monkeypatch.setattr(traffic_simulator.subprocess, "run", mock_subprocess_run)

    session = traffic_simulator.execute_slow_vs_burst_scenario(
        slow_requests=2,
        slow_interval=0.1,
        burst_requests=15,
        burst_duration=3.0,
    )

    assert session.scenario == "slow_vs_burst"
    assert session.status == "completed"
    assert session.requests_completed == 17
    assert "phase1_slow_start" in session.metadata
    assert "phase2_burst_start" in session.metadata


def test_execute_recovery_observation_scenario_mocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(traffic_simulator, "SIMULATION_RUNS_DIR", tmp_path / "sims")
    client_logger = ClientTelemetryLogger(tmp_path / "client")
    monkeypatch.setattr(traffic_simulator, "ClientTelemetryLogger", lambda: client_logger)

    def mock_run_single(client_pod: str, target_svc: str, ns: str) -> tuple[bool, float, str]:
        return True, 5.0, ""

    monkeypatch.setattr(traffic_simulator, "run_single_http_request", mock_run_single)

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="20\n", stderr="")

    monkeypatch.setattr(traffic_simulator.subprocess, "run", mock_subprocess_run)

    session = traffic_simulator.execute_recovery_observation_scenario(
        baseline_seconds=1.0,
        burst_requests=20,
        burst_duration=3.0,
        recovery_seconds=1.0,
    )

    assert session.scenario == "recovery_observation"
    assert session.status == "completed"
    assert session.requests_completed == 26  # 3 baseline + 20 burst + 3 recovery
    assert "phase1_baseline_start" in session.metadata
    assert "phase2_attack_start" in session.metadata
    assert "phase3_recovery_start" in session.metadata


def test_execute_runtime_benign_scenario_mocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(traffic_simulator, "SIMULATION_RUNS_DIR", tmp_path / "sims")
    client_logger = ClientTelemetryLogger(tmp_path / "client")
    monkeypatch.setattr(traffic_simulator, "ClientTelemetryLogger", lambda: client_logger)

    seen_cmds: list[list[str]] = []

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        seen_cmds.append(cmd)
        return SimpleNamespace(returncode=0, stdout="Linux webapp\n", stderr="")

    monkeypatch.setattr(traffic_simulator.subprocess, "run", mock_subprocess_run)

    session = traffic_simulator.execute_runtime_benign_scenario(
        commands=["date -u", "uptime"],
        delay_seconds=0.05,
    )

    assert session.scenario == "runtime_benign"
    assert session.status == "completed"
    assert session.commands_completed == 2
    assert len(seen_cmds) == 2


def test_execute_sequential_multimodal_scenario_mocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(traffic_simulator, "SIMULATION_RUNS_DIR", tmp_path / "sims")
    client_logger = ClientTelemetryLogger(tmp_path / "client")
    monkeypatch.setattr(traffic_simulator, "ClientTelemetryLogger", lambda: client_logger)

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="25\n", stderr="")

    monkeypatch.setattr(traffic_simulator.subprocess, "run", mock_subprocess_run)

    session = traffic_simulator.execute_sequential_multimodal_scenario(
        burst_requests=25,
        burst_duration=3.0,
        commands=["whoami"],
        cpu_duration=2.0,
    )

    assert session.scenario == "sequential_multimodal"
    assert session.status == "completed"
    assert session.requests_completed == 25
    assert session.commands_completed == 2  # 1 exec + 1 cpu stress
    assert "phase1_burst_start" in session.metadata
    assert "phase2_runtime_start" in session.metadata
    assert "phase3_cpu_start" in session.metadata


# ---------------------------------------------------------------------------
# 3. Correlation Engine & SOC Navigation Guidance Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("scenario", "expected_page", "expected_modality"),
    [
        ("slow_vs_burst", "Live Detection", "Network Only (eBPF TCP)"),
        ("recovery_observation", "Telemetry Explorer", "Network + Workload"),
        ("runtime_benign", "Runtime Events", "Runtime Only (trace_exec)"),
        ("sequential_multimodal", "Live Detection", "Full Tri-Modal Fusion"),
    ],
)
def test_correlation_soc_navigation_guide_for_new_scenarios(
    scenario: str,
    expected_page: str,
    expected_modality: str,
    tmp_path: Path,
) -> None:
    client_dir = tmp_path / "telemetry" / "data" / "client"
    logger = ClientTelemetryLogger(client_dir)

    sess_id = f"test_{scenario}_01"
    manifest = ClientSessionManifest(
        session_id=sess_id,
        experiment_id=f"exp_{scenario}",
        scenario=scenario,
        target_service="http://webapp",
        client_pod="traffic-simulator",
        status="completed",
        start_time_utc="2026-10-17T12:00:00.000Z",
        end_time_utc="2026-10-17T12:00:15.000Z",
        duration_seconds=15.0,
    )
    logger.save_session_manifest(manifest)

    report = correlation.correlate_client_session(sess_id, project_root=tmp_path, logger=logger)
    assert report.session_id == sess_id
    assert expected_page in report.soc_navigation_guide["recommended_page"]
    assert expected_modality in report.soc_navigation_guide["recommended_modality"]


def test_correlation_caching_performance(tmp_path: Path) -> None:
    correlation.clear_correlation_cache()
    client_dir = tmp_path / "telemetry" / "data" / "client"
    logger = ClientTelemetryLogger(client_dir)

    sess_id = "cached_sess_01"
    manifest = ClientSessionManifest(
        session_id=sess_id,
        experiment_id="exp_cache",
        scenario="network_burst",
        target_service="http://webapp",
        client_pod="traffic-simulator",
        status="completed",
        start_time_utc="2026-10-17T12:00:00.000Z",
        end_time_utc="2026-10-17T12:00:10.000Z",
        duration_seconds=10.0,
    )
    logger.save_session_manifest(manifest)

    # First call - populates cache
    t0 = time.perf_counter()
    r1 = correlation.correlate_client_session(sess_id, project_root=tmp_path, logger=logger)
    t1 = time.perf_counter()

    # Second call - returns from cache
    t2 = time.perf_counter()
    r2 = correlation.correlate_client_session(sess_id, project_root=tmp_path, logger=logger)
    t3 = time.perf_counter()

    cached_dur = t3 - t2
    assert cached_dur < 0.005  # sub-5ms return from cache
    assert r1.session_id == r2.session_id
    assert r1.correlation_grade == r2.correlation_grade


# ---------------------------------------------------------------------------
# 4. Streamlit App Rendering
# ---------------------------------------------------------------------------

def test_dashboard_app_renders_with_cached_resources() -> None:
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=30)
    assert not at.exception
