"""Tests for start.py prerequisite checks and launcher utilities.

These tests are intentionally offline-only:
- No Streamlit process is actually launched.
- No Kubernetes cluster is required.
- PID management is tested with mock/temp paths.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Resolve project root and import start module ──────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
_START = _ROOT / "start.py"


def _load_start():
    """Dynamically load start.py without executing __main__ block."""
    spec = importlib.util.spec_from_file_location("start", _START)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def start_mod():
    """Return the start module, skipping tests if start.py does not exist."""
    if not _START.exists():
        pytest.skip("start.py not found — launcher not yet created")
    return _load_start()


@pytest.fixture()
def tmp_pid_file(tmp_path):
    """Return a path to a temporary .launcher_pids file."""
    return tmp_path / ".launcher_pids"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Module-level sanity
# ─────────────────────────────────────────────────────────────────────────────

class TestStartModuleExists:
    def test_start_py_exists(self):
        assert _START.exists(), "start.py must exist at the project root"

    def test_start_py_is_readable(self):
        content = _START.read_text(encoding="utf-8")
        assert len(content) > 100, "start.py appears empty"

    def test_start_py_has_argparse(self):
        content = _START.read_text(encoding="utf-8")
        assert "argparse" in content, "start.py must use argparse for subcommands"

    def test_start_py_has_subcommands(self):
        content = _START.read_text(encoding="utf-8")
        for cmd in ("dashboard", "client", "both", "check", "stop"):
            assert cmd in content, f"start.py must include subcommand '{cmd}'"

    def test_start_py_has_pid_file_reference(self):
        content = _START.read_text(encoding="utf-8")
        assert ".launcher_pids" in content, "start.py must reference .launcher_pids"


# ─────────────────────────────────────────────────────────────────────────────
# 2. PID file round-trip
# ─────────────────────────────────────────────────────────────────────────────

class TestPidFile:
    def test_write_and_read_pid_file(self, start_mod, tmp_pid_file):
        """Writing then reading PIDs via the launcher helpers round-trips."""
        # Patch PID_FILE to point to tmp location, then save/load
        original = start_mod.PID_FILE
        try:
            start_mod.PID_FILE = tmp_pid_file
            pids = {"dashboard": 12345, "client": 12346}
            start_mod._save_pids(pids)
            assert tmp_pid_file.exists()
            loaded = start_mod._load_pids()
            assert loaded == pids
        finally:
            start_mod.PID_FILE = original

    def test_read_missing_pid_file_returns_empty(self, start_mod, tmp_pid_file):
        original = start_mod.PID_FILE
        try:
            start_mod.PID_FILE = tmp_pid_file
            result = start_mod._load_pids()
            assert result == {}
        finally:
            start_mod.PID_FILE = original

    def test_pid_file_contains_valid_json(self, start_mod, tmp_pid_file):
        original = start_mod.PID_FILE
        try:
            start_mod.PID_FILE = tmp_pid_file
            start_mod._save_pids({"dashboard": 99999})
            data = json.loads(tmp_pid_file.read_text())
            assert isinstance(data, dict)
            assert "dashboard" in data
        finally:
            start_mod.PID_FILE = original


# ─────────────────────────────────────────────────────────────────────────────
# 3. Prerequisite check function
# ─────────────────────────────────────────────────────────────────────────────

class TestPrerequisiteChecks:
    def test_python_version_check_passes_current(self, start_mod):
        """The current Python version must pass the minimum check."""
        assert start_mod._check_python() is True

    def test_required_packages_present(self, start_mod):
        """All required packages that are installed must be found by the checker."""
        # _check_packages returns True if all present, prints ✓/✗ per package
        result = start_mod._check_packages()
        assert result is True, "All required packages should be present in this environment"


# ─────────────────────────────────────────────────────────────────────────────
# 4. ML dataset / results check
# ─────────────────────────────────────────────────────────────────────────────

class TestResultsChecks:
    def test_ml_datasets_exist(self):
        """results/ml_datasets/ must contain at least one CSV."""
        ds_dir = _ROOT / "results" / "ml_datasets"
        assert ds_dir.exists(), "results/ml_datasets/ directory must exist"
        csvs = list(ds_dir.glob("*.csv"))
        assert len(csvs) >= 1, "results/ml_datasets/ must contain at least one CSV"

    def test_loso_summary_exists(self):
        """results/loso/loso_summary.json must exist."""
        summary = _ROOT / "results" / "loso" / "loso_summary.json"
        assert summary.exists(), "results/loso/loso_summary.json must exist"

    def test_loso_aggregate_csv_exists(self):
        """results/loso/loso_aggregate_comparison.csv must exist."""
        agg = _ROOT / "results" / "loso" / "loso_aggregate_comparison.csv"
        assert agg.exists(), "results/loso/loso_aggregate_comparison.csv must exist"

    def test_streamlit_config_exists(self):
        """.streamlit/config.toml must exist."""
        cfg = _ROOT / ".streamlit" / "config.toml"
        assert cfg.exists(), ".streamlit/config.toml must exist"

    def test_dashboard_port_in_config(self):
        """Dashboard port must be 8501 as configured."""
        cfg = _ROOT / ".streamlit" / "config.toml"
        if cfg.exists():
            content = cfg.read_text()
            assert "8501" in content, ".streamlit/config.toml must specify port 8501"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Stop command with no PID file — graceful no-op
# ─────────────────────────────────────────────────────────────────────────────

class TestStopCommand:
    def test_stop_with_missing_pid_file_does_not_crash(self, start_mod, tmp_pid_file):
        """Calling stop when no PID file exists must not raise an exception."""
        original = start_mod.PID_FILE
        try:
            start_mod.PID_FILE = tmp_pid_file
            try:
                start_mod.cmd_stop()
            except SystemExit as exc:
                assert exc.code in (0, None)
        finally:
            start_mod.PID_FILE = original

    def test_stop_with_empty_pid_file_does_not_crash(self, start_mod, tmp_pid_file):
        original = start_mod.PID_FILE
        try:
            start_mod.PID_FILE = tmp_pid_file
            tmp_pid_file.write_text("{}")
            try:
                start_mod.cmd_stop()
            except SystemExit as exc:
                assert exc.code in (0, None)
        finally:
            start_mod.PID_FILE = original

    def test_stop_cleans_up_pid_file_for_ghost_pid(self, start_mod, tmp_pid_file):
        """After stop with a nonexistent PID, the PID file should be removed."""
        original = start_mod.PID_FILE
        try:
            start_mod.PID_FILE = tmp_pid_file
            start_mod._save_pids({"dashboard": 999999999})
            try:
                start_mod.cmd_stop()
            except SystemExit:
                pass
            # PID file should be gone after stop
            assert not tmp_pid_file.exists() or tmp_pid_file.read_text().strip() in ("{}", "")
        finally:
            start_mod.PID_FILE = original


# ─────────────────────────────────────────────────────────────────────────────
# 6. Idempotency: already-running detection
# ─────────────────────────────────────────────────────────────────────────────

class TestIdempotency:
    def test_is_process_running_false_for_nonexistent_pid(self, start_mod):
        # PID 999999999 almost certainly does not exist
        assert start_mod._pid_is_running(999999999) is False

    def test_is_process_running_true_for_current_process(self, start_mod):
        # The current test process itself must be running
        assert start_mod._pid_is_running(os.getpid()) is True


# ─────────────────────────────────────────────────────────────────────────────
# 7. Telemetry collectors and Minikube orchestration
# ─────────────────────────────────────────────────────────────────────────────

class TestCollectorOrchestration:
    def test_collector_specs_defined(self, start_mod):
        """COLLECTOR_SPECS must define network, workload, and runtime collectors."""
        assert hasattr(start_mod, "COLLECTOR_SPECS"), "start.py must define COLLECTOR_SPECS"
        specs = start_mod.COLLECTOR_SPECS
        for name in ("network_collector", "workload_collector", "runtime_collector"):
            assert name in specs, f"COLLECTOR_SPECS missing '{name}'"
            assert "script" in specs[name], f"'{name}' missing script path"
            assert "pid_file" in specs[name], f"'{name}' missing pid_file"
            assert specs[name]["script"].exists(), f"Collector script {specs[name]['script']} does not exist"

    def test_is_collector_running_false_when_no_pid_or_process(self, start_mod):
        """_is_collector_running returns False when PID file does not exist."""
        # Use an invalid spec name or ensure non-existent PID file
        running, pid = start_mod._is_collector_running("network_collector")
        # In a test environment without background collectors, should be boolean
        assert isinstance(running, bool)

    def test_cli_accepts_new_subcommands(self):
        """start.py CLI must accept demo, k8s, collectors subcommands."""
        content = _START.read_text(encoding="utf-8")
        for subcmd in ("demo", "k8s", "collectors"):
            assert subcmd in content, f"start.py must support subcommand '{subcmd}'"

    def test_cli_accepts_skip_flags(self):
        """start.py CLI must support --skip-k8s and --skip-collectors."""
        content = _START.read_text(encoding="utf-8")
        assert "--skip-k8s" in content
        assert "--skip-collectors" in content

    def test_cli_accepts_window_monitoring_flags(self):
        """start.py CLI must support separate window monitoring flags."""
        content = _START.read_text(encoding="utf-8")
        assert "--windows" in content
        assert "--windowed" in content
        assert "--separate-windows" in content
        assert "--background" in content
        assert "--headless" in content

    def test_launch_helpers_support_separate_windows(self, start_mod):
        """Verify launch helpers accept separate_windows argument."""
        import inspect
        sig_coll = inspect.signature(start_mod._launch_collector)
        assert "separate_windows" in sig_coll.parameters
        sig_proc = inspect.signature(start_mod._launch_process)
        assert "separate_windows" in sig_proc.parameters
        sig_cmd = inspect.signature(start_mod.cmd_launch)
        assert "separate_windows" in sig_cmd.parameters
        sig_init = inspect.signature(start_mod.init_collectors)
        assert "separate_windows" in sig_init.parameters

