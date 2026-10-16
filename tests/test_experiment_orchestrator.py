"""Unit tests for the experiment orchestrator (scripts/run_experiment.py)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scripts.run_experiment import (
    ORCHESTRATOR_BOUNDS,
    CollectorManager,
    CollectorStatus,
    ExperimentOrchestrator,
    parse_args,
)


# ==============================================================================
# 1. Parameter Validation & Safety Bounds Tests
# ==============================================================================

def test_parse_args_defaults() -> None:
    args = parse_args(["--scenario", "normal"])
    assert args.scenario == "normal"
    assert args.requests == 10
    assert args.delay == 1.5
    assert args.duration == 10.0
    assert not args.dry_run


def test_normal_bounds_enforced(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path)
    # Exceeding max requests
    with pytest.raises(ValueError, match="Normal requests"):
        orch.execute_normal(requests=int(ORCHESTRATOR_BOUNDS["normal_max_requests"]) + 1)

    # Delay below minimum
    with pytest.raises(ValueError, match="Normal delay"):
        orch.execute_normal(requests=10, delay_seconds=0.5)


def test_burst_bounds_enforced(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path)
    # Exceeding duration
    with pytest.raises(ValueError, match="Burst duration"):
        orch.execute_network_burst(duration_seconds=float(ORCHESTRATOR_BOUNDS["burst_max_duration_seconds"]) + 5.0)

    # Exceeding requests
    with pytest.raises(ValueError, match="Burst max_requests"):
        orch.execute_network_burst(max_requests=int(ORCHESTRATOR_BOUNDS["burst_max_requests"]) + 10)


def test_runtime_bounds_and_allowlist_enforced(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path)
    # Dangerous unapproved command
    with pytest.raises(Exception):
        orch.execute_runtime(commands=["rm -rf /"])

    # Exceeding max commands
    excessive_cmds = ["id"] * (int(ORCHESTRATOR_BOUNDS["runtime_max_commands"]) + 1)
    with pytest.raises(ValueError, match="Runtime command count"):
        orch.execute_runtime(commands=excessive_cmds)

    # Delay below minimum
    with pytest.raises(ValueError, match="Runtime delay"):
        orch.execute_runtime(commands=["id"], delay_seconds=0.05)


def test_concurrent_bounds_enforced(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path)
    with pytest.raises(ValueError, match="Burst duration"):
        orch.execute_concurrent(burst_duration_seconds=float(ORCHESTRATOR_BOUNDS["concurrent_max_duration_seconds"]) + 1.0)

    with pytest.raises(ValueError, match="Burst requests"):
        orch.execute_concurrent(burst_max_requests=int(ORCHESTRATOR_BOUNDS["concurrent_max_requests"]) + 10)


# ==============================================================================
# 2. Collector Detection & Ownership Management Tests
# ==============================================================================

def test_detect_collector_reusing_existing(tmp_path: Path) -> None:
    mgr = CollectorManager(project_root=tmp_path)
    # Simulate an active PID file
    pid_file = tmp_path / "telemetry/data/.workload_collector.pid"
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text("9999", encoding="utf-8")

    with patch.object(mgr, "_check_process_alive", return_value=True):
        status = mgr.detect_collector("workload")
        assert status.running is True
        assert status.pid == 9999
        assert status.owned is False


def test_collector_manager_cleanup_owned_only(tmp_path: Path) -> None:
    mgr = CollectorManager(project_root=tmp_path)
    mock_owned_proc = MagicMock()
    mock_owned_proc.poll.return_value = None
    mock_owned_proc.pid = 1111

    # Owned collector
    mgr.collectors["network"] = CollectorStatus(
        name="network",
        script="telemetry/network_collector.py",
        running=True,
        pid=1111,
        owned=True,
        process=mock_owned_proc,
    )

    # Unowned pre-existing collector
    mgr.collectors["workload"] = CollectorStatus(
        name="workload",
        script="telemetry/workload_collector.py",
        running=True,
        pid=5392,
        owned=False,
        process=None,
    )

    with patch("subprocess.run") as mock_subproc_run:
        mgr.cleanup_owned()
        # For owned process on win32 or unix:
        if pytest.importorskip("sys").platform == "win32":
            mock_subproc_run.assert_called_once()
            assert "1111" in mock_subproc_run.call_args[0][0]
        else:
            mock_owned_proc.terminate.assert_called_once()


# ==============================================================================
# 3. Preflight Check Tests
# ==============================================================================

def test_preflight_check_fails_on_wrong_context(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(expected_context="minikube", output_dir=tmp_path)
    with patch("scripts.run_experiment.kubernetes_context_is_active", return_value=False):
        ok, errors = orch.preflight_check()
        assert not ok
        assert any("context does not match" in e for e in errors)


def test_preflight_check_passes(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(expected_context="minikube", output_dir=tmp_path)
    with patch("scripts.run_experiment.kubernetes_context_is_active", return_value=True), \
         patch("subprocess.run") as mock_run:
        # Mock responses for target_workload readyReplicas and traffic-generator pod phase
        mock_run.side_effect = [
            SimpleNamespace(returncode=0, stdout="1", stderr=""),
            SimpleNamespace(returncode=0, stdout="Running", stderr=""),
        ]
        ok, errors = orch.preflight_check()
        assert ok
        assert errors == []


# ==============================================================================
# 4. Dry-run Session Tests
# ==============================================================================

def test_run_session_dry_run(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path, project_root=tmp_path)
    with patch.object(orch, "preflight_check", return_value=(True, [])), \
         patch.object(orch.collector_mgr, "ensure_collectors", return_value={
             "workload": CollectorStatus("workload", "s", True, 5392, False),
             "network": CollectorStatus("network", "s", True, 8452, False),
             "runtime": CollectorStatus("runtime", "s", True, 11768, False),
         }):
        run_dir, metadata = orch.run_session(scenario="normal", dry_run=True)
        assert run_dir.exists()
        assert metadata["status"] == "planned"
        assert metadata["scenario"] == "normal"
        assert metadata["collector_status"]["workload"]["pid"] == 5392
        assert metadata["collector_status"]["workload"]["owned"] is False

        # Verify metadata files exist on disk
        meta_file = run_dir / "metadata.json"
        assert meta_file.exists()
        saved = json.loads(meta_file.read_text(encoding="utf-8"))
        assert saved["session_id"] == metadata["session_id"]


# ==============================================================================
# 5. Session Execution & Artifacts Generation Tests
# ==============================================================================

def test_run_session_normal_execution(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path, project_root=tmp_path)
    with patch.object(orch, "preflight_check", return_value=(True, [])), \
         patch.object(orch.collector_mgr, "ensure_collectors", return_value={
             "workload": CollectorStatus("workload", "s", True, 5392, False),
             "network": CollectorStatus("network", "s", True, 8452, False),
             "runtime": CollectorStatus("runtime", "s", True, 11768, False),
         }), \
         patch.object(orch, "execute_normal") as mock_exec, \
         patch.object(orch.harness, "correlate_telemetry") as mock_corr:

        from experiments.harness import ActivityResult, ModalityCorrelation
        mock_exec.return_value = ActivityResult(requests_attempted=10, requests_completed=10, exit_code=0)
        mock_corr.return_value = (
            {
                "network": ModalityCorrelation("network", True, 20),
                "workload": ModalityCorrelation("workload", True, 4),
                "runtime": ModalityCorrelation("runtime", False, 0),
            },
            [{"window_start": "2026-10-14T10:00:00Z", "network_available": True}],
            {},
        )

        run_dir, metadata = orch.run_session(
            scenario="normal", requests=10, delay_seconds=1.5, cooldown_seconds=0.1
        )

        assert metadata["status"] == "completed"
        assert metadata["window_count"] == 1
        assert metadata["modalities_captured"]["network"] is True
        assert metadata["modalities_captured"]["workload"] is True
        assert metadata["modalities_captured"]["runtime"] is False

        assert (run_dir / "metadata.json").exists()
        assert (run_dir / "telemetry_windows.json").exists()
        assert (run_dir / "events.log").exists()


def test_concurrent_tracks_overlap_interval(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path, project_root=tmp_path)
    with patch.object(orch, "preflight_check", return_value=(True, [])), \
         patch.object(orch.collector_mgr, "ensure_collectors", return_value={}), \
         patch.object(orch, "execute_concurrent") as mock_conc, \
         patch.object(orch.harness, "correlate_telemetry") as mock_corr:

        from experiments.harness import ActivityResult, ModalityCorrelation
        mock_conc.return_value = (
            ActivityResult(requests_attempted=50, requests_completed=50, exit_code=0),
            {
                "network_attack_start_time_utc": "2026-10-14T12:00:02.000Z",
                "network_attack_end_time_utc": "2026-10-14T12:00:12.000Z",
                "workload_attack_start_time_utc": "2026-10-14T12:00:00.000Z",
                "workload_attack_end_time_utc": "2026-10-14T12:00:15.000Z",
                "overlap_start_time_utc": "2026-10-14T12:00:02.000Z",
                "overlap_end_time_utc": "2026-10-14T12:00:12.000Z",
            },
        )
        mock_corr.return_value = (
            {
                "network": ModalityCorrelation("network", True, 50),
                "workload": ModalityCorrelation("workload", True, 5),
            },
            [{"window_start": "2026-10-14T12:00:00Z", "network_available": True, "workload_available": True}],
            {},
        )

        run_dir, metadata = orch.run_session(scenario="concurrent", cooldown_seconds=0.1)
        assert metadata["status"] == "completed"
        assert metadata["dataset_suitable"] is True
        assert metadata["timestamps"]["overlap_start_time_utc"] == "2026-10-14T12:00:02.000Z"
        assert metadata["timestamps"]["overlap_end_time_utc"] == "2026-10-14T12:00:12.000Z"


def test_missing_expected_telemetry_marks_incomplete(tmp_path: Path) -> None:
    orch = ExperimentOrchestrator(output_dir=tmp_path, project_root=tmp_path)
    with patch.object(orch, "preflight_check", return_value=(True, [])), \
         patch.object(orch.collector_mgr, "ensure_collectors", return_value={}), \
         patch.object(orch, "execute_normal") as mock_exec, \
         patch.object(orch.harness, "correlate_telemetry") as mock_corr:

        from experiments.harness import ActivityResult, ModalityCorrelation
        mock_exec.return_value = ActivityResult(requests_attempted=10, requests_completed=10, exit_code=0)
        # Network telemetry missing
        mock_corr.return_value = (
            {
                "network": ModalityCorrelation("network", False, 0, reason="No TCP events"),
                "workload": ModalityCorrelation("workload", True, 2),
            },
            [],
            {},
        )

        run_dir, metadata = orch.run_session(scenario="normal", cooldown_seconds=0.1)
        assert metadata["status"] == "incomplete"
        assert metadata["dataset_suitable"] is False
        assert "network" in metadata["missing_modalities"]
        assert any("expected telemetry" in w.lower() for w in metadata["validation_warnings"])
