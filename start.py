#!/usr/bin/env python3
"""
start.py — Unified Startup Launcher for Kubernetes Threat Detection Framework.

Chains the complete research stack in three orchestrated steps:
  Step 1: Initializes and verifies the Minikube cluster and lab environment
          (Minikube, webapp workload, Metrics Server, Inspektor Gadget, traffic-generator).
  Step 2: Initializes telemetry collectors in the background with duplicate prevention
          (network_collector, workload_collector, runtime_collector).
  Step 3: Launches the dual Streamlit dashboards (SOC Dashboard on 8501, Client Console on 8502).

Subcommands:
  python start.py            — full stack (Minikube -> Collectors -> Both Dashboards) [default]
  python start.py both       — full stack (Minikube -> Collectors -> Both Dashboards)
  python start.py dashboard  — Minikube -> Collectors -> SOC Dashboard only (port 8501)
  python start.py client     — Minikube -> Collectors -> Client Attack Console only (port 8502)
  python start.py demo       — offline demo mode (skips Minikube & collectors, launches dashboards)
  python start.py k8s        — initialize Minikube lab environment only
  python start.py collectors — initialize Minikube & telemetry collectors only
  python start.py check      — run prerequisite checks only, no processes started
  python start.py stop       — gracefully stop all recorded launcher processes (dashboards + collectors)

Flags:
  --skip-k8s, --no-k8s       — skip Minikube cluster initialization
  --skip-collectors          — skip telemetry collectors initialization
  --demo                     — alias for --skip-k8s --skip-collectors

Process state is persisted to `.launcher_pids` for clean, isolated shutdown.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────────────
# Project root
# ──────────────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent

# Ensure common user tool directories are on PATH (for kubectl-gadget)
def _ensure_gadget_path() -> None:
    home_dirs = [Path.home()]
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        home_dirs.append(Path(user_profile))
    for h in home_dirs:
        cand = h / "bin"
        if cand.is_dir() and str(cand) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{cand}{os.pathsep}{os.environ.get('PATH', '')}"

_ensure_gadget_path()

# ──────────────────────────────────────────────────────────────────────────────
# Configuration constants
# ──────────────────────────────────────────────────────────────────────────────
DASHBOARD_SCRIPT = PROJECT_ROOT / "dashboard" / "app.py"
CLIENT_SCRIPT    = PROJECT_ROOT / "client_console" / "app.py"
PID_FILE         = PROJECT_ROOT / ".launcher_pids"

DASHBOARD_PORT = 8501
CLIENT_PORT    = 8502
DASHBOARD_URL  = f"http://127.0.0.1:{DASHBOARD_PORT}"
CLIENT_URL     = f"http://127.0.0.1:{CLIENT_PORT}"

LAUNCH_SETTLE_SECS = 3
SIGTERM_WAIT_SECS  = 5

# Telemetry collector specifications
COLLECTOR_SPECS: dict[str, dict[str, Any]] = {
    "network_collector": {
        "label": "Network Collector (eBPF TCP)",
        "script": PROJECT_ROOT / "telemetry" / "network_collector.py",
        "args": [],
        "pid_file": PROJECT_ROOT / "telemetry" / "data" / "network" / ".network_collector.pid",
        "alt_pid_files": [PROJECT_ROOT / "telemetry" / "data" / ".network_collector.pid"],
        "log_file": PROJECT_ROOT / "telemetry" / "data" / "network_collector.log",
    },
    "workload_collector": {
        "label": "Workload Collector (cgroup/Metrics Server)",
        "script": PROJECT_ROOT / "telemetry" / "workload_collector.py",
        "args": ["--interval", "5.0"],
        "pid_file": PROJECT_ROOT / "telemetry" / "data" / ".workload_collector.pid",
        "alt_pid_files": [],
        "log_file": PROJECT_ROOT / "telemetry" / "data" / "workload_collector.log",
    },
    "runtime_collector": {
        "label": "Runtime Collector (eBPF trace_exec)",
        "script": PROJECT_ROOT / "telemetry" / "runtime_collector.py",
        "args": [],
        "pid_file": PROJECT_ROOT / "telemetry" / "data" / "runtime" / ".runtime_collector.pid",
        "alt_pid_files": [PROJECT_ROOT / "telemetry" / "data" / ".runtime_collector.pid"],
        "log_file": PROJECT_ROOT / "telemetry" / "data" / "runtime_collector.log",
    },
}

# In-memory subprocess tracking for Ctrl+C
_RUNNING_PROCS: dict[str, subprocess.Popen] = {}

# ──────────────────────────────────────────────────────────────────────────────
# Packages to check
# ──────────────────────────────────────────────────────────────────────────────
CRITICAL_PACKAGES = [
    ("streamlit",    "streamlit"),
    ("sklearn",      "scikit-learn"),
    ("xgboost",      "xgboost"),
    ("pandas",       "pandas"),
    ("numpy",        "numpy"),
    ("joblib",       "joblib"),
    ("yaml",         "PyYAML"),
    ("matplotlib",   "matplotlib"),
    ("plotly",       "plotly"),
]

WARN_DIRS = [
    PROJECT_ROOT / "results" / "network"  / "models",
    PROJECT_ROOT / "results" / "workload" / "models",
    PROJECT_ROOT / "results" / "fusion"   / "models",
]

# ──────────────────────────────────────────────────────────────────────────────
# Banner (ASCII-safe for any Windows code page)
# ──────────────────────────────────────────────────────────────────────────────
BANNER = r"""
+------------------------------------------------------+
|    K8S SENTINEL -- Threat Detection Framework        |
|    VIT SWE3004 Capstone  |  Aditya Sukumaran         |
+------------------------------------------------------+
"""

# ──────────────────────────────────────────────────────────────────────────────
# Logging / Tag helpers
# ──────────────────────────────────────────────────────────────────────────────
def _tag(label: str, msg: str) -> None:
    print(f"[{label:<5}] {msg}")

def _ok(label: str, msg: str) -> None:
    _tag(label, msg + "  [OK]")

def _fail(label: str, msg: str) -> None:
    _tag(label, msg + "  [FAIL]")

def _warn(msg: str) -> None:
    _tag("WARN ", msg)

def _info(msg: str) -> None:
    _tag("INFO ", msg)

def _start(msg: str) -> None:
    _tag("START", msg)

def _k8s(msg: str) -> None:
    _tag("K8S  ", msg)

def _coll(msg: str) -> None:
    _tag("COLL ", msg)

# ──────────────────────────────────────────────────────────────────────────────
# psutil — optional, used for process liveness
# ──────────────────────────────────────────────────────────────────────────────
try:
    import psutil as _psutil  # type: ignore
    _PSUTIL_AVAILABLE = True
except ImportError:
    _psutil = None          # type: ignore
    _PSUTIL_AVAILABLE = False


def _pid_is_running(pid: int) -> bool:
    """Return True if a process with the given PID is currently running."""
    if not _PSUTIL_AVAILABLE:
        return False
    try:
        proc = _psutil.Process(pid)
        return proc.status() != _psutil.STATUS_ZOMBIE
    except _psutil.NoSuchProcess:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# PID file helpers
# ──────────────────────────────────────────────────────────────────────────────
def _load_pids() -> dict:
    """Load PIDs from the JSON PID file. Returns {} if missing or corrupt."""
    if not PID_FILE.exists():
        return {}
    try:
        return json.loads(PID_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_pids(pids: dict) -> None:
    """Persist a PID dict to the JSON PID file."""
    PID_FILE.write_text(json.dumps(pids, indent=2), encoding="utf-8")


def _delete_pid_file() -> None:
    """Remove the PID file if it exists."""
    if PID_FILE.exists():
        try:
            PID_FILE.unlink()
        except OSError:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Prerequisite checks
# ──────────────────────────────────────────────────────────────────────────────
def _check_python() -> bool:
    """Verify Python version >= 3.11."""
    v = sys.version_info
    ver_str = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 11):
        _ok("CHECK", f"Python {ver_str}")
        return True
    _fail("CHECK", f"Python {ver_str} (need >= 3.11)")
    return False


def _check_packages() -> bool:
    """Import each package in CRITICAL_PACKAGES."""
    all_ok = True
    for import_name, pip_name in CRITICAL_PACKAGES:
        try:
            mod = importlib.import_module(import_name)
            version = getattr(mod, "__version__", None) or getattr(mod, "VERSION", None)
            label = f"{import_name} {version}" if version else import_name
            _ok("CHECK", label)
        except ImportError:
            _fail("CHECK", import_name)
            print(f"         → Install with:  pip install {pip_name}")
            all_ok = False
    return all_ok


def _check_datasets() -> bool:
    """Verify results/ml_datasets/ exists with CSVs."""
    ds_dir = PROJECT_ROOT / "results" / "ml_datasets"
    if not ds_dir.exists():
        _fail("CHECK", f"ML datasets dir missing: {ds_dir.relative_to(PROJECT_ROOT)}")
        return False
    csvs = list(ds_dir.glob("*.csv"))
    if not csvs:
        _fail("CHECK", f"No CSV files found in {ds_dir.relative_to(PROJECT_ROOT)}")
        return False
    _ok("CHECK", f"ML datasets found ({len(csvs)} CSV{'s' if len(csvs) != 1 else ''})")
    return True


def _check_loso() -> bool:
    """Verify results/loso/loso_summary.json exists."""
    loso_file = PROJECT_ROOT / "results" / "loso" / "loso_summary.json"
    if loso_file.exists():
        _ok("CHECK", "LOSO results found")
        return True
    _fail("CHECK", f"LOSO summary missing: {loso_file.relative_to(PROJECT_ROOT)}")
    return False


def _check_streamlit_config() -> bool:
    """Verify that .streamlit/config.toml exists."""
    cfg = PROJECT_ROOT / ".streamlit" / "config.toml"
    if cfg.exists():
        _ok("CHECK", ".streamlit/config.toml found")
        return True
    _fail("CHECK", ".streamlit/config.toml missing")
    return False


def _check_model_dirs() -> None:
    """Warn (non-blocking) if expected model directories are absent."""
    for d in WARN_DIRS:
        if not d.exists():
            _warn(f"Model dir not found: {d.relative_to(PROJECT_ROOT)}  (dashboard demo mode will be used)")


def run_checks(fatal_on_error: bool = True) -> bool:
    """Execute all prerequisite checks."""
    print()
    python_ok   = _check_python()
    packages_ok = _check_packages()
    datasets_ok = _check_datasets()
    loso_ok     = _check_loso()
    config_ok   = _check_streamlit_config()

    _check_model_dirs()

    all_critical = python_ok and packages_ok and datasets_ok and loso_ok and config_ok

    if not all_critical and fatal_on_error:
        print()
        print("─" * 56)
        print("  One or more critical checks failed.")
        print("  Resolve the issues above, then re-run this launcher.")
        print("─" * 56)
        sys.exit(1)

    return all_critical


# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Minikube Cluster Initialization & Lab Setup
# ──────────────────────────────────────────────────────────────────────────────
def _init_minikube_native() -> bool:
    """Initialize Minikube cluster and lab components using direct CLI calls."""
    try:
        # Check minikube status
        status_proc = subprocess.run(
            ["minikube", "status", "-p", "minikube", "-o", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        status_data: dict[str, Any] = {}
        if status_proc.returncode == 0 or status_proc.stdout.strip():
            try:
                status_data = json.loads(status_proc.stdout)
            except json.JSONDecodeError:
                pass

        if status_data.get("Host") != "Running":
            _k8s("Starting Minikube cluster profile 'minikube'...")
            start_res = subprocess.run(
                ["minikube", "start", "-p", "minikube"],
                check=False,
            )
            if start_res.returncode != 0:
                _fail("K8S", "Failed to start Minikube cluster.")
                return False
        _ok("K8S", "Minikube host is Running")

        # Ensure active kubectl context is minikube
        subprocess.run(["kubectl", "config", "use-context", "minikube"], capture_output=True, check=False)
        _ok("K8S", "Active context: minikube")

        # Wait for Node readiness
        _k8s("Verifying Minikube node readiness...")
        subprocess.run(["kubectl", "wait", "--for=condition=Ready", "node/minikube", "--timeout=120s"], capture_output=True, check=True)
        _ok("K8S", "Minikube node is Ready")

        # Check / create webapp deployment
        dep_chk = subprocess.run(["kubectl", "get", "deployment", "webapp", "-n", "default"], capture_output=True, check=False)
        if dep_chk.returncode != 0:
            _k8s("Creating webapp deployment (nginx)...")
            subprocess.run(["kubectl", "create", "deployment", "webapp", "-n", "default", "--image=nginx"], capture_output=True, check=True)
            subprocess.run(["kubectl", "expose", "deployment", "webapp", "-n", "default", "--port=80", "--target-port=80", "--type=NodePort", "--name=webapp"], capture_output=True, check=True)
        else:
            svc_chk = subprocess.run(["kubectl", "get", "service", "webapp", "-n", "default"], capture_output=True, check=False)
            if svc_chk.returncode != 0:
                _k8s("Exposing webapp NodePort service (port 80)...")
                subprocess.run(["kubectl", "expose", "deployment", "webapp", "-n", "default", "--port=80", "--target-port=80", "--type=NodePort", "--name=webapp"], capture_output=True, check=True)

        _k8s("Waiting for webapp deployment rollout...")
        subprocess.run(["kubectl", "rollout", "status", "deployment/webapp", "-n", "default", "--timeout=120s"], capture_output=True, check=True)
        _ok("K8S", "Target workload 'webapp' is Ready")

        # Ensure metrics-server addon
        ms_chk = subprocess.run(["kubectl", "get", "deployment", "metrics-server", "-n", "kube-system"], capture_output=True, check=False)
        if ms_chk.returncode != 0:
            _k8s("Enabling Minikube metrics-server addon...")
            subprocess.run(["minikube", "addons", "enable", "metrics-server", "-p", "minikube"], capture_output=True, check=True)
        _k8s("Waiting for metrics-server rollout...")
        subprocess.run(["kubectl", "rollout", "status", "deployment/metrics-server", "-n", "kube-system", "--timeout=120s"], capture_output=True, check=True)
        _ok("K8S", "Metrics Server addon is Ready")

        # Verify Inspektor Gadget
        _ensure_gadget_path()
        gadget_chk = subprocess.run(["kubectl", "gadget", "version"], capture_output=True, text=True, check=False)
        if gadget_chk.returncode == 0:
            _ok("K8S", "Inspektor Gadget v0.55.1 is Ready")
        else:
            _warn("Inspektor Gadget check returned non-zero (daemonset will be accessed at collection)")

        # Ensure traffic-generator pod
        tg_phase = subprocess.run(
            ["kubectl", "get", "pod", "traffic-generator", "-n", "default", "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True, check=False
        ).stdout.strip()
        if not tg_phase or tg_phase in ("Succeeded", "Failed", "Unknown"):
            if tg_phase:
                subprocess.run(["kubectl", "delete", "pod", "traffic-generator", "-n", "default", "--wait=true"], capture_output=True, check=False)
            _k8s("Creating in-cluster traffic-generator pod...")
            subprocess.run(
                ["kubectl", "run", "traffic-generator", "-n", "default", "--image=busybox", "--restart=Never", "--labels=run=traffic-generator", "--command", "--", "sh", "-c", "sleep 3600000"],
                capture_output=True, check=True
            )
        subprocess.run(["kubectl", "wait", "--for=condition=Ready", "pod/traffic-generator", "-n", "default", "--timeout=120s"], capture_output=True, check=True)
        _ok("K8S", "Traffic Generator client pod is Running")

        _ok("K8S", "Kubernetes lab environment verified and ready")
        return True

    except Exception as exc:
        _fail("K8S", f"Error during Minikube initialization: {exc}")
        return False


def init_minikube_cluster() -> bool:
    """
    Step 1: Initialize and verify the Minikube lab environment.
    Uses setup-lab.ps1 on Windows if available, falling back to native Python commands.
    """
    _ensure_gadget_path()
    print()
    _info("Step 1/3: Initializing Minikube cluster and lab environment...")

    # Fast path: setup-lab.ps1 if on Windows and PowerShell is present
    setup_script = PROJECT_ROOT / "setup-lab.ps1"
    if sys.platform == "win32" and setup_script.exists() and shutil.which("powershell"):
        try:
            res = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(setup_script)],
                cwd=str(PROJECT_ROOT),
                check=False,
            )
            if res.returncode == 0:
                _ok("K8S", "Minikube lab environment verified and ready")
                return True
            _warn("setup-lab.ps1 returned non-zero; attempting Python fallback checks...")
        except Exception as exc:
            _warn(f"Could not run setup-lab.ps1: {exc}; attempting Python fallback checks...")

    return _init_minikube_native()


# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Telemetry Collectors Initialization
# ──────────────────────────────────────────────────────────────────────────────
def _is_collector_running(spec_name: str) -> tuple[bool, int | None]:
    """Check whether a collector process is currently running."""
    spec = COLLECTOR_SPECS[spec_name]
    script_stem = spec["script"].stem.lower()

    # 1. Check PID files
    candidate_pid_files = [spec["pid_file"]] + spec.get("alt_pid_files", [])
    for pf in candidate_pid_files:
        if pf.exists():
            try:
                pid = int(pf.read_text(encoding="utf-8").strip())
                if _pid_is_running(pid):
                    return True, pid
            except (ValueError, OSError):
                pass

    # 2. Check process table via psutil
    if _PSUTIL_AVAILABLE:
        try:
            for proc in _psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    cmdline = proc.info.get("cmdline") or []
                    cmd_str = " ".join(cmdline).lower()
                    if script_stem in cmd_str and "python" in (proc.info.get("name") or "").lower():
                        if "-c" not in cmd_str and "streamlit" not in cmd_str:
                            return True, proc.info["pid"]
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    continue
        except Exception:
            pass

    return False, None


def _launch_collector(spec_name: str) -> subprocess.Popen | None:
    """Launch a telemetry collector in the background with output logged to file."""
    spec = COLLECTOR_SPECS[spec_name]
    is_running, pid = _is_collector_running(spec_name)
    if is_running:
        _coll(f"{spec['label']} already running (PID {pid})  [OK]")
        return None

    spec["log_file"].parent.mkdir(parents=True, exist_ok=True)
    log_handle = spec["log_file"].open("a", encoding="utf-8")

    cmd = [sys.executable, str(spec["script"])] + spec["args"]

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    for h in [Path.home(), Path(os.environ.get("USERPROFILE", ""))]:
        cand = h / "bin"
        if cand.is_dir() and str(cand) not in env.get("PATH", ""):
            env["PATH"] = f"{cand}{os.pathsep}{env.get('PATH', '')}"

    creationflags = 0
    if sys.platform == "win32":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200) | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            creationflags=creationflags,
        )
        time.sleep(1.5)
        if proc.poll() is not None:
            _fail("COLL", f"Failed to start {spec['label']} (exit code {proc.poll()})")
            _info(f"Check log: {spec['log_file'].relative_to(PROJECT_ROOT)}")
            return None
        _ok("COLL", f"Started {spec['label']} (PID {proc.pid})")
        return proc
    except Exception as exc:
        _fail("COLL", f"Error launching {spec['label']}: {exc}")
        return None


def init_collectors() -> dict[str, int]:
    """
    Step 2: Ensure all three telemetry collectors are running:
      - network_collector (Inspektor Gadget eBPF TCP)
      - workload_collector (Metrics Server cgroup metrics)
      - runtime_collector (Inspektor Gadget eBPF trace_exec)
    """
    _ensure_gadget_path()
    print()
    _info("Step 2/3: Initializing telemetry collectors...")

    # Ensure output directories exist
    (PROJECT_ROOT / "telemetry" / "data" / "network").mkdir(parents=True, exist_ok=True)
    (PROJECT_ROOT / "telemetry" / "data" / "runtime").mkdir(parents=True, exist_ok=True)

    pids = _load_pids()
    active: dict[str, int] = {}

    for spec_name, spec in COLLECTOR_SPECS.items():
        is_running, existing_pid = _is_collector_running(spec_name)
        if is_running and existing_pid:
            _coll(f"{spec['label']} already running (PID {existing_pid})  ✓")
            active[spec_name] = existing_pid
            pids[spec_name] = existing_pid
        else:
            proc = _launch_collector(spec_name)
            if proc is not None and proc.pid:
                active[spec_name] = proc.pid
                pids[spec_name] = proc.pid
                _RUNNING_PROCS[spec_name] = proc

    _save_pids(pids)
    if active:
        _ok("COLL", f"Active telemetry collectors: {len(active)}/3 running")
    return active


# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Streamlit Dashboards Launch
# ──────────────────────────────────────────────────────────────────────────────
def _streamlit_cmd(script: Path, port: int) -> list[str]:
    """Build the command list to launch a Streamlit app."""
    return [
        sys.executable, "-m", "streamlit", "run",
        str(script),
        "--server.port", str(port),
        "--server.headless", "true",
        "--server.address", "127.0.0.1",
    ]


def _launch_process(name: str, script: Path, port: int, url: str) -> subprocess.Popen | None:
    """Launch a Streamlit subprocess with idempotency check."""
    pids = _load_pids()

    if name in pids:
        stored_pid = pids[name]
        if _PSUTIL_AVAILABLE:
            if _pid_is_running(stored_pid):
                _info(f"{name.capitalize()} already running on {url}  (PID {stored_pid})")
                return None
        else:
            _warn("psutil not available; cannot verify existing PID — launching anyway")

    cmd = _streamlit_cmd(script, port)
    try:
        proc = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT))
        _start(f"{name:<20} →  {url}")
        return proc
    except FileNotFoundError:
        _fail("START", f"Could not launch {name} — is streamlit installed?")
        return None
    except OSError as exc:
        _fail("START", f"OS error launching {name}: {exc}")
        return None


def cmd_launch(targets: list[str]) -> None:
    """Launch one or both Streamlit apps, monitor, and wait for Ctrl+C."""
    # Ensure key directories exist
    for d in [
        PROJECT_ROOT / "results",
        PROJECT_ROOT / "telemetry" / "data",
        PROJECT_ROOT / "results" / "loso",
        PROJECT_ROOT / "results" / "ml_datasets",
    ]:
        d.mkdir(parents=True, exist_ok=True)

    print()
    pids: dict = _load_pids()

    # Dashboard
    if "dashboard" in targets:
        proc = _launch_process("dashboard", DASHBOARD_SCRIPT, DASHBOARD_PORT, DASHBOARD_URL)
        if proc is not None:
            _RUNNING_PROCS["dashboard"] = proc
            pids["dashboard"] = proc.pid

    # Client console
    if "client" in targets:
        proc = _launch_process("client", CLIENT_SCRIPT, CLIENT_PORT, CLIENT_URL)
        if proc is not None:
            _RUNNING_PROCS["client"] = proc
            pids["client"] = proc.pid

    if pids:
        _save_pids(pids)

    dash_count = sum(1 for t in targets if t in _RUNNING_PROCS)
    total_count = len(pids)
    print()
    _info(f"{total_count} total process{'es' if total_count != 1 else ''} recorded in .launcher_pids")
    _info("Press Ctrl+C or run:  python start.py stop")

    time.sleep(LAUNCH_SETTLE_SECS)

    print()
    print("  ┌─ Running ──────────────────────────────────────────┐")
    if "dashboard" in targets:
        print(f"  │  SOC Dashboard   →  {DASHBOARD_URL:<32}│")
    if "client" in targets:
        print(f"  │  Client Console  →  {CLIENT_URL:<32}│")
    for spec_name, spec in COLLECTOR_SPECS.items():
        if spec_name in pids and _pid_is_running(pids[spec_name]):
            lbl = spec["label"].split("(")[0].strip()
            print(f"  │  {lbl:<16}→  Active (PID {pids[spec_name]}){' ' * (17 - len(str(pids[spec_name])))}│")
    print("  └────────────────────────────────────────────────────┘")
    print()

    # Monitor processes until Ctrl+C
    try:
        while True:
            time.sleep(2)
            for name, proc in list(_RUNNING_PROCS.items()):
                if proc.poll() is not None:
                    _warn(f"{name} exited (PID {proc.pid}, code {proc.returncode})")
                    del _RUNNING_PROCS[name]
                    pids.pop(name, None)
                    _save_pids(pids)
            if not _RUNNING_PROCS:
                _info("All foreground launcher processes have exited.")
                break
    except KeyboardInterrupt:
        _shutdown(_RUNNING_PROCS)


# ──────────────────────────────────────────────────────────────────────────────
# Graceful Shutdown
# ──────────────────────────────────────────────────────────────────────────────
def _terminate_pid(name: str, pid: int) -> None:
    """Gracefully terminate a process by PID."""
    if not _PSUTIL_AVAILABLE:
        try:
            if sys.platform == "win32":
                subprocess.call(["taskkill", "/PID", str(pid), "/F", "/T"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.kill(pid, signal.SIGTERM)
            _info(f"Sent termination signal to {name} (PID {pid})")
        except (ProcessLookupError, PermissionError, OSError) as exc:
            _warn(f"Could not signal {name} (PID {pid}): {exc}")
        return

    try:
        proc = _psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=SIGTERM_WAIT_SECS)
            _info(f"Stopped {name} (PID {pid})")
        except _psutil.TimeoutExpired:
            _warn(f"{name} did not exit after {SIGTERM_WAIT_SECS}s — force-killing")
            proc.kill()
            _info(f"Force-killed {name} (PID {pid})")
    except _psutil.NoSuchProcess:
        _info(f"{name} (PID {pid}) was not running — nothing to stop")
    except _psutil.AccessDenied as exc:
        _warn(f"Access denied when stopping {name} (PID {pid}): {exc}")


def _shutdown(procs: dict[str, subprocess.Popen]) -> None:
    """Terminate all managed subprocess handles on KeyboardInterrupt."""
    print()
    _info("Shutting down launcher processes...")
    for name, proc in procs.items():
        if proc is not None and proc.poll() is None:
            _info(f"Terminating {name} (PID {proc.pid})")
            proc.terminate()
            try:
                proc.wait(timeout=SIGTERM_WAIT_SECS)
            except subprocess.TimeoutExpired:
                proc.kill()
    _delete_pid_file()
    _info("Done.")


def cmd_stop() -> None:
    """Read .launcher_pids and stop each recorded process."""
    pids = _load_pids()
    if not pids:
        _info("No recorded PIDs found in .launcher_pids — nothing to stop")
        return

    print()
    _info("Stopping all recorded launcher processes...")
    for name, pid in list(pids.items()):
        _terminate_pid(name, pid)

    # Clean up collector PID files if their process is no longer running
    for spec in COLLECTOR_SPECS.values():
        for pf in [spec["pid_file"]] + spec.get("alt_pid_files", []):
            if pf.exists():
                try:
                    p = int(pf.read_text(encoding="utf-8").strip())
                    if not _pid_is_running(p):
                        pf.unlink()
                except Exception:
                    pass

    _delete_pid_file()
    print()
    _info("All launcher processes stopped.")


# ──────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="start.py",
        description="K8S Sentinel — Unified Startup Launcher for Kubernetes Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python start.py                    # full stack: minikube -> collectors -> dashboards\n"
            "  python start.py both               # full stack\n"
            "  python start.py dashboard          # minikube -> collectors -> SOC dashboard\n"
            "  python start.py client             # minikube -> collectors -> client console\n"
            "  python start.py demo               # offline demo mode (skips minikube & collectors)\n"
            "  python start.py k8s                # initialize minikube lab environment only\n"
            "  python start.py collectors         # initialize minikube & collectors only\n"
            "  python start.py check              # checks only\n"
            "  python start.py stop               # graceful shutdown of all started processes\n"
        ),
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="both",
        choices=["dashboard", "client", "both", "demo", "k8s", "collectors", "check", "stop"],
        help="Subcommand to run (default: both — full stack)",
    )
    parser.add_argument(
        "--skip-k8s", "--no-k8s",
        dest="skip_k8s",
        action="store_true",
        help="Skip Minikube cluster initialization",
    )
    parser.add_argument(
        "--skip-collectors",
        action="store_true",
        help="Skip telemetry collectors initialization",
    )

    args = parser.parse_args()

    # Always print the banner
    print(BANNER)

    # Stop command
    if args.command == "stop":
        cmd_stop()
        return

    # Check command
    if args.command == "check":
        run_checks(fatal_on_error=False)
        return

    # Check prerequisites first
    run_checks(fatal_on_error=True)

    # Determine skip flags based on subcommand
    skip_k8s = args.skip_k8s or (args.command == "demo")
    skip_collectors = args.skip_collectors or (args.command == "demo") or (args.command == "k8s")

    # Step 1: Initialize Minikube cluster
    if not skip_k8s:
        k8s_ok = init_minikube_cluster()
        if not k8s_ok:
            _fail("START", "Minikube cluster initialization failed.")
            print("         → Fix cluster issues above, or run with --skip-k8s for offline demo mode.")
            sys.exit(1)
    else:
        _info("Skipping Minikube cluster initialization (--skip-k8s/demo mode)")

    if args.command == "k8s":
        _ok("K8S", "Minikube cluster initialization complete. Exiting.")
        return

    # Step 2: Initialize Telemetry Collectors
    if not skip_collectors:
        init_collectors()
    else:
        _info("Skipping telemetry collectors initialization")

    if args.command == "collectors":
        _ok("COLL", "Telemetry collectors initialized. Exiting.")
        return

    # Step 3: Launch Dashboards
    if args.command in ("both", "demo"):
        targets = ["dashboard", "client"]
    elif args.command == "dashboard":
        targets = ["dashboard"]
    else:  # client
        targets = ["client"]

    print()
    _info(f"Step 3/3: Launching {', '.join(targets)} dashboard(s)...")
    cmd_launch(targets)


if __name__ == "__main__":
    main()
