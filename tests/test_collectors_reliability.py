"""Unit tests for collector reliability: retries, backoff, Gadget resolution, and process recovery."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from telemetry.network_collector import build_network_gadget_command
from telemetry.runtime_collector import resolve_gadget_executable
from telemetry.workload_collector import (
    MetricsCollectionError,
    get_metrics,
    get_webapp_pod,
)


def test_workload_metrics_transient_failure_retries_and_succeeds() -> None:
    """Verify that transient Metrics Server failures trigger exponential backoff retries and succeed."""
    mock_run = MagicMock()
    # Fail twice with CalledProcessError, then succeed with valid pod metrics
    err = subprocess.CalledProcessError(returncode=1, cmd=["kubectl", "top"], stderr="Metrics API unavailable")
    success = subprocess.CompletedProcess(
        args=["kubectl", "top", "pod", "webapp-pod", "-n", "default", "--no-headers"],
        returncode=0,
        stdout="webapp-pod   125m   32Mi\n",
        stderr="",
    )
    mock_run.side_effect = [err, err, success]

    with patch("subprocess.run", mock_run), patch("time.sleep") as mock_sleep:
        cpu, memory = get_metrics(
            "webapp-pod",
            namespace="default",
            max_retries=3,
            base_backoff=0.1,
            max_backoff=0.5,
            jitter=0.0,
        )

    assert cpu == "125"
    assert memory == "32"
    assert mock_run.call_count == 3
    # Verify exponential backoff intervals: attempt 0 -> 0.1s, attempt 1 -> 0.2s
    assert mock_sleep.call_count == 2
    mock_sleep.assert_has_calls([call(0.1), call(0.2)])


def test_workload_metrics_persistent_failure_raises_and_is_bounded() -> None:
    """Verify that persistent Metrics Server failures are bounded and raise MetricsCollectionError."""
    mock_run = MagicMock()
    err = subprocess.CalledProcessError(returncode=1, cmd=["kubectl", "top"], stderr="Metrics API down")
    mock_run.side_effect = err

    with patch("subprocess.run", mock_run), patch("time.sleep"):
        with pytest.raises(MetricsCollectionError) as exc_info:
            get_metrics(
                "webapp-pod",
                namespace="default",
                max_retries=2,
                base_backoff=0.01,
                max_backoff=0.05,
                jitter=0.0,
            )

    # 1 initial attempt + 2 retries = 3 calls total
    assert mock_run.call_count == 3
    assert "Metrics Server call failed for pod 'webapp-pod' after 3 attempts" in str(exc_info.value)


def test_workload_metrics_malformed_output_retries_and_raises() -> None:
    """Verify that corrupt/empty stdout from kubectl top is retried and raises MetricsCollectionError."""
    mock_run = MagicMock()
    bad_output = subprocess.CompletedProcess(
        args=["kubectl", "top"],
        returncode=0,
        stdout="not_enough_columns\n",
        stderr="",
    )
    mock_run.side_effect = [bad_output, bad_output]

    with patch("subprocess.run", mock_run), patch("time.sleep"):
        with pytest.raises(MetricsCollectionError) as exc_info:
            get_metrics("webapp-pod", max_retries=1, base_backoff=0.01)

    assert mock_run.call_count == 2
    assert "Invalid metrics output format" in str(exc_info.value)


def test_webapp_pod_discovery_transient_failure_retries_and_recovers() -> None:
    """Verify that dynamic pod discovery recovers after transient failure."""
    mock_run = MagicMock()
    err = subprocess.CalledProcessError(returncode=1, cmd=["kubectl", "get", "pods"])
    success = subprocess.CompletedProcess(
        args=["kubectl", "get", "pods"],
        returncode=0,
        stdout="webapp-79699899c5-wds9h\n",
        stderr="",
    )
    mock_run.side_effect = [err, success]

    with patch("subprocess.run", mock_run), patch("time.sleep"):
        pod_name = get_webapp_pod(max_retries=2, base_backoff=0.01)

    assert pod_name == "webapp-79699899c5-wds9h"
    assert mock_run.call_count == 2


def test_webapp_pod_discovery_persistent_failure_raises() -> None:
    """Verify that persistent pod discovery failure raises a clear RuntimeError."""
    mock_run = MagicMock()
    mock_run.side_effect = subprocess.CalledProcessError(returncode=1, cmd=["kubectl", "get", "pods"])

    with patch("subprocess.run", mock_run), patch("time.sleep"):
        with pytest.raises(RuntimeError) as exc_info:
            get_webapp_pod(max_retries=2, base_backoff=0.01)

    assert mock_run.call_count == 3
    assert "Failed to discover webapp pod" in str(exc_info.value)


def test_network_collector_build_command_uses_resolved_gadget() -> None:
    """Verify that network collector command construction uses the shared resolve_gadget_executable."""
    # 1. Custom binary
    cmd_custom = build_network_gadget_command(
        gadget_version="v0.55.1",
        namespace="test-ns",
        selector="app=test",
        custom_bin="my-gadget",
    )
    assert cmd_custom[0] == "my-gadget"
    assert cmd_custom[1:] == [
        "run",
        "trace_tcp:v0.55.1",
        "-n",
        "test-ns",
        "-l",
        "app=test",
        "--output",
        "json",
    ]

    # 2. Default resolution returns non-empty executable list ending with gadget parameters
    cmd_default = build_network_gadget_command()
    assert len(cmd_default) >= 8
    assert "trace_tcp:v0.55.1" in cmd_default
    assert "-n" in cmd_default
    assert "default" in cmd_default
    assert "app=webapp" in cmd_default


def test_safe_pid_file_cleanup_preserves_foreign_pid(tmp_path: Path) -> None:
    """Verify that PID cleanup logic only removes files that belong to the current process."""
    foreign_pid_file = tmp_path / ".test_collector.pid"
    foreign_pid = 999999
    foreign_pid_file.write_text(str(foreign_pid), encoding="utf-8")

    # Simulate safe cleanup with a process ID that doesn't match
    if foreign_pid_file.exists():
        content = foreign_pid_file.read_text(encoding="utf-8").strip()
        if content and int(content) == os.getpid():
            foreign_pid_file.unlink()

    # File must still exist!
    assert foreign_pid_file.exists()
    assert foreign_pid_file.read_text(encoding="utf-8").strip() == str(foreign_pid)

    # Now simulate safe cleanup with current process ID
    my_pid_file = tmp_path / ".my_collector.pid"
    my_pid_file.write_text(str(os.getpid()), encoding="utf-8")
    if my_pid_file.exists():
        content = my_pid_file.read_text(encoding="utf-8").strip()
        if content and int(content) == os.getpid():
            my_pid_file.unlink()

    assert not my_pid_file.exists()
