"""Repeatable Kubernetes Traffic Simulator for continuous benign traffic and on-demand attack scenarios.

Generates:
1. Continuous background benign HTTP traffic with natural timing jitter.
2. On-demand, bounded attack scenarios:
   - network_burst: High-frequency HTTP connections.
   - runtime_anomaly: In-container introspection commands (id, whoami, curl, uname).
   - concurrent_attack: Simultaneous network burst + in-container execution.

Persists session metadata, request metrics, and telemetry status into experiments/simulation_runs/.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from experiments.orchestration import utc_now
from experiments.run_experiment import cpu_attack_command, stop_cpu_attack
from telemetry.client_telemetry import (
    ClientRequestRecord,
    ClientSessionManifest,
    ClientTelemetryLogger,
    get_client_utc_now,
)
from telemetry.security import validate_k8s_name, validate_safe_output_path

logger = logging.getLogger("experiments.traffic_simulator")

SIMULATION_RUNS_DIR = Path("experiments/simulation_runs")
BENIGN_PID_FILE = Path("telemetry/data/.benign_traffic.pid")
BENIGN_STATUS_FILE = Path("telemetry/data/benign_traffic_status.json")

DEFAULT_TARGET_SERVICE = "http://webapp"
DEFAULT_CLIENT_POD = "traffic-simulator"
DEFAULT_WORKLOAD_POD = "deployment/webapp"
DEFAULT_NAMESPACE = "default"


@dataclass
class SimulationSession:
    session_id: str
    scenario: str
    target_service: str
    client_pod: str
    status: str
    start_time_utc: str
    end_time_utc: str | None = None
    duration_seconds: float = 0.0
    requests_attempted: int = 0
    requests_completed: int = 0
    requests_failed: int = 0
    commands_attempted: int = 0
    commands_completed: int = 0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_current_utc_str() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def check_pod_running(pod_name: str, namespace: str = DEFAULT_NAMESPACE) -> bool:
    """Verify that the target client pod is currently in Running state."""
    cmd = ["kubectl", "get", "pod", pod_name, "-n", namespace, "-o", "jsonpath={.status.phase}"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=8)
        return res.returncode == 0 and res.stdout.strip() == "Running"
    except Exception:
        return False


def run_single_http_request(
    client_pod: str = DEFAULT_CLIENT_POD,
    target_service: str = DEFAULT_TARGET_SERVICE,
    namespace: str = DEFAULT_NAMESPACE,
    timeout: float = 5.0,
) -> tuple[bool, float, str]:
    """Execute a single HTTP GET from client pod to target service."""
    start_t = time.perf_counter()
    cmd = [
        "kubectl", "exec", "-n", namespace, client_pod,
        "--", "wget", "-q", "-O", "/dev/null", target_service,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        duration_ms = (time.perf_counter() - start_t) * 1000.0
        success = (res.returncode == 0)
        err = res.stderr.strip() if not success else ""
        return success, duration_ms, err
    except subprocess.TimeoutExpired:
        duration_ms = (time.perf_counter() - start_t) * 1000.0
        return False, duration_ms, "Request timed out"
    except Exception as exc:
        duration_ms = (time.perf_counter() - start_t) * 1000.0
        return False, duration_ms, str(exc)


def run_benign_daemon_loop(
    client_pod: str = DEFAULT_CLIENT_POD,
    target_service: str = DEFAULT_TARGET_SERVICE,
    namespace: str = DEFAULT_NAMESPACE,
    base_interval: float = 2.0,
    jitter: float = 0.8,
) -> None:
    """Loop indefinitely generating low-volume, jittered benign HTTP traffic until terminated."""
    BENIGN_STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    BENIGN_PID_FILE.write_text(str(os.getpid()), encoding="utf-8")

    total = 0
    success = 0
    failed = 0
    started_at = get_current_utc_str()

    logger.info("Starting benign traffic daemon PID %d targeting %s", os.getpid(), target_service)

    def _update_status(last_lat: float, last_err: str) -> None:
        status_data = {
            "status": "running",
            "pid": os.getpid(),
            "started_at_utc": started_at,
            "last_update_utc": get_current_utc_str(),
            "target_service": target_service,
            "client_pod": client_pod,
            "total_requests": total,
            "successful_requests": success,
            "failed_requests": failed,
            "last_latency_ms": round(last_lat, 2),
            "last_error": last_err,
        }
        try:
            BENIGN_STATUS_FILE.write_text(json.dumps(status_data, indent=2), encoding="utf-8")
        except Exception:
            pass

    daemon_log_file = Path("telemetry/data/benign_traffic.log")
    client_logger = ClientTelemetryLogger()
    try:
        while True:
            try:
                ok, lat, err = run_single_http_request(client_pod, target_service, namespace)
                total += 1
                if ok:
                    success += 1
                else:
                    failed += 1

                _update_status(lat, err)

                # Record structured client-side request telemetry
                rec = ClientRequestRecord(
                    experiment_id="benign_traffic",
                    session_id="benign_daemon",
                    request_id=f"req_{total}_{int(time.time() * 1000)}",
                    client_timestamp_utc=get_client_utc_now(),
                    target_service=target_service,
                    method="GET",
                    status_code=200 if ok else 0,
                    duration_ms=round(lat, 2),
                    success=ok,
                    error_category="none" if ok else ("timeout" if "timeout" in err.lower() else "network_error"),
                    scenario_label="benign_baseline",
                )
                client_logger.record_request(rec)
            except Exception as req_exc:
                failed += 1
                _update_status(0.0, str(req_exc))
                with open(daemon_log_file, "a", encoding="utf-8") as lf:
                    lf.write(f"[{get_current_utc_str()}] Request exception: {req_exc}\n")

            # Jittered sleep (e.g. 2.0s ± 0.8s -> 1.2s to 2.8s)
            delay = max(0.5, base_interval + random.uniform(-jitter, jitter))
            time.sleep(delay)
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as top_exc:
        with open(daemon_log_file, "a", encoding="utf-8") as lf:
            lf.write(f"[{get_current_utc_str()}] Daemon crash: {top_exc}\n")
    finally:
        # Mark stopped
        try:
            status_data = {
                "status": "stopped",
                "pid": None,
                "started_at_utc": started_at,
                "stopped_at_utc": get_current_utc_str(),
                "target_service": target_service,
                "client_pod": client_pod,
                "total_requests": total,
                "successful_requests": success,
                "failed_requests": failed,
            }
            BENIGN_STATUS_FILE.write_text(json.dumps(status_data, indent=2), encoding="utf-8")
        except Exception:
            pass
        if BENIGN_PID_FILE.exists():
            try:
                BENIGN_PID_FILE.unlink()
            except Exception:
                pass


def start_benign_traffic(
    client_pod: str = DEFAULT_CLIENT_POD,
    target_service: str = DEFAULT_TARGET_SERVICE,
    namespace: str = DEFAULT_NAMESPACE,
    base_interval: float = 2.0,
    jitter: float = 0.8,
) -> dict[str, Any]:
    """Start the benign traffic generator as a background daemon process."""
    if is_benign_traffic_running():
        return {"status": "already_running", "message": "Benign traffic simulator is already active."}

    if not check_pod_running(client_pod, namespace):
        return {
            "status": "error",
            "message": f"Client pod '{client_pod}' is not running in namespace '{namespace}'.",
        }

    cmd = [
        sys.executable, "-m", "experiments.traffic_simulator",
        "run-daemon",
        "--client-pod", client_pod,
        "--target-service", target_service,
        "--namespace", namespace,
        "--interval", str(base_interval),
        "--jitter", str(jitter),
    ]

    flags = 0
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    log_path = Path("telemetry/data/benign_traffic_process.log")
    log_file = open(log_path, "a", encoding="utf-8")

    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=log_file,
        stdin=subprocess.DEVNULL,
        close_fds=(sys.platform != "win32"),
        creationflags=flags,
    )
    BENIGN_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    BENIGN_PID_FILE.write_text(str(proc.pid), encoding="utf-8")

    time.sleep(0.5)
    return {
        "status": "started",
        "pid": proc.pid,
        "client_pod": client_pod,
        "target_service": target_service,
        "interval": base_interval,
        "jitter": jitter,
    }


def stop_benign_traffic() -> dict[str, Any]:
    """Stop the running benign traffic generator process."""
    if not BENIGN_PID_FILE.exists():
        return {"status": "not_running", "message": "No active benign traffic simulator found."}

    try:
        pid = int(BENIGN_PID_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        pid = None

    if pid:
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False)
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        except OSError:
            pass

    if BENIGN_PID_FILE.exists():
        try:
            BENIGN_PID_FILE.unlink()
        except Exception:
            pass

    # Update status file
    if BENIGN_STATUS_FILE.exists():
        try:
            st = json.loads(BENIGN_STATUS_FILE.read_text(encoding="utf-8"))
            st["status"] = "stopped"
            st["stopped_at_utc"] = get_current_utc_str()
            BENIGN_STATUS_FILE.write_text(json.dumps(st, indent=2), encoding="utf-8")
        except Exception:
            pass

    return {"status": "stopped", "message": "Benign traffic simulator stopped."}


def is_benign_traffic_running() -> bool:
    """Check if the benign traffic generator is actively running."""
    if not BENIGN_PID_FILE.exists():
        return False
    try:
        pid = int(BENIGN_PID_FILE.read_text(encoding="utf-8").strip())
        import psutil
        if not psutil.pid_exists(pid):
            try:
                BENIGN_PID_FILE.unlink()
            except OSError:
                pass
            return False
        proc = psutil.Process(pid)
        if proc.is_running() and "python" in proc.name().lower():
            return True
        try:
            BENIGN_PID_FILE.unlink()
        except OSError:
            pass
        return False
    except Exception:
        return False


def get_benign_traffic_status() -> dict[str, Any]:
    """Return the current status and metrics of the benign traffic simulator."""
    running = is_benign_traffic_running()
    if not BENIGN_STATUS_FILE.exists():
        return {
            "status": "stopped" if not running else "running",
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
        }
    try:
        data = json.loads(BENIGN_STATUS_FILE.read_text(encoding="utf-8"))
        data["is_process_alive"] = running
        return data
    except Exception:
        return {"status": "unknown", "error": "Could not read status file"}


def execute_network_burst_scenario(
    requests: int = 60,
    duration_seconds: float = 10.0,
    client_pod: str = DEFAULT_CLIENT_POD,
    target_service: str = DEFAULT_TARGET_SERVICE,
    namespace: str = DEFAULT_NAMESPACE,
) -> SimulationSession:
    """Launch an on-demand high-rate HTTP burst."""
    session_id = f"burst_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    session_dir = SIMULATION_RUNS_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    start_utc = get_current_utc_str()
    session = SimulationSession(
        session_id=session_id,
        scenario="network_burst",
        target_service=target_service,
        client_pod=client_pod,
        status="running",
        start_time_utc=start_utc,
        requests_attempted=requests,
    )

    script = (
        f"end=$(( $(date +%s) + {int(duration_seconds)} )); "
        "c=0; "
        f"while [ \"$(date +%s)\" -lt \"$end\" ] && [ $c -lt {requests} ]; do "
        f"wget -q -O /dev/null {target_service}; "
        "c=$((c+1)); "
        "done; "
        "echo $c"
    )

    cmd = ["kubectl", "exec", "-n", namespace, client_pod, "--", "sh", "-c", script]
    t0 = time.perf_counter()
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=duration_seconds + 15)
        dur = time.perf_counter() - t0
        session.duration_seconds = round(dur, 2)
        session.end_time_utc = get_current_utc_str()

        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            try:
                completed = int(lines[-1]) if lines else requests
            except ValueError:
                completed = requests
            session.requests_completed = completed
            session.requests_failed = max(0, requests - completed)
            session.status = "completed"
        else:
            session.status = "failed"
            session.errors.append(res.stderr.strip() or "network burst command failed")
    except Exception as exc:
        session.duration_seconds = round(time.perf_counter() - t0, 2)
        session.end_time_utc = get_current_utc_str()
        session.status = "error"
        session.errors.append(str(exc))

    (session_dir / "metadata.json").write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")

    manifest = ClientSessionManifest(
        session_id=session_id,
        experiment_id="client_network_burst",
        scenario="network_burst",
        target_service=target_service,
        client_pod=client_pod,
        status=session.status,
        start_time_utc=start_utc,
        end_time_utc=session.end_time_utc,
        duration_seconds=session.duration_seconds,
        requests_attempted=requests,
        requests_completed=session.requests_completed,
        requests_failed=session.requests_failed,
        response_code_distribution={"200": session.requests_completed, "0": session.requests_failed},
        errors=session.errors,
        metadata={"target_service": target_service},
    )
    ClientTelemetryLogger().save_session_manifest(manifest)
    return session


def execute_runtime_anomaly_scenario(
    commands: Sequence[str] = ("id", "whoami", "curl -I http://webapp", "uname -a"),
    target_workload: str = DEFAULT_WORKLOAD_POD,
    namespace: str = DEFAULT_NAMESPACE,
    delay_seconds: float = 0.5,
) -> SimulationSession:
    """Launch an on-demand harmless in-container introspection activity scenario."""
    session_id = f"runtime_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    session_dir = SIMULATION_RUNS_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    start_utc = get_current_utc_str()
    session = SimulationSession(
        session_id=session_id,
        scenario="runtime_anomaly",
        target_service="in-container-exec",
        client_pod=target_workload,
        status="running",
        start_time_utc=start_utc,
        commands_attempted=len(commands),
    )

    t0 = time.perf_counter()
    completed = 0
    errors: list[str] = []

    for cmd_str in commands:
        args = ["kubectl", "exec", "-n", namespace, target_workload, "--"] + cmd_str.split()
        try:
            res = subprocess.run(args, capture_output=True, text=True, check=False, timeout=10)
            if res.returncode == 0:
                completed += 1
            else:
                errors.append(f"Command '{cmd_str}' failed: {res.stderr.strip()}")
        except Exception as exc:
            errors.append(f"Command '{cmd_str}' exception: {exc}")
        time.sleep(delay_seconds)

    session.duration_seconds = round(time.perf_counter() - t0, 2)
    session.end_time_utc = get_current_utc_str()
    session.commands_completed = completed
    session.errors = errors
    session.status = "completed" if completed == len(commands) else ("partial" if completed > 0 else "failed")

    (session_dir / "metadata.json").write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")

    manifest = ClientSessionManifest(
        session_id=session_id,
        experiment_id="client_runtime_anomaly",
        scenario="runtime_anomaly",
        target_service="in-container-exec",
        client_pod=target_workload,
        status=session.status,
        start_time_utc=start_utc,
        end_time_utc=session.end_time_utc,
        duration_seconds=session.duration_seconds,
        commands_attempted=len(commands),
        commands_completed=session.commands_completed,
        errors=session.errors,
        metadata={"commands": list(commands), "target_workload": target_workload},
    )
    ClientTelemetryLogger().save_session_manifest(manifest)
    return session


def execute_concurrent_attack_scenario(
    burst_requests: int = 40,
    duration_seconds: float = 8.0,
    commands: Sequence[str] = ("id", "whoami", "date -u"),
    client_pod: str = DEFAULT_CLIENT_POD,
    target_workload: str = DEFAULT_WORKLOAD_POD,
    target_service: str = DEFAULT_TARGET_SERVICE,
    namespace: str = DEFAULT_NAMESPACE,
) -> SimulationSession:
    """Launch concurrent network burst and in-container introspection activity simultaneously."""
    session_id = f"concurrent_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    session_dir = SIMULATION_RUNS_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    start_utc = get_current_utc_str()
    session = SimulationSession(
        session_id=session_id,
        scenario="concurrent_attack",
        target_service=target_service,
        client_pod=f"{client_pod}+{target_workload}",
        status="running",
        start_time_utc=start_utc,
        requests_attempted=burst_requests,
        commands_attempted=len(commands),
    )

    # 1. Start network burst in asynchronous background thread/process
    script = (
        f"end=$(( $(date +%s) + {int(duration_seconds)} )); "
        "c=0; "
        f"while [ \"$(date +%s)\" -lt \"$end\" ] && [ $c -lt {burst_requests} ]; do "
        f"wget -q -O /dev/null {target_service}; "
        "c=$((c+1)); "
        "done; "
        "echo $c"
    )
    burst_cmd = ["kubectl", "exec", "-n", namespace, client_pod, "--", "sh", "-c", script]

    t0 = time.perf_counter()
    burst_proc = subprocess.Popen(burst_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 2. Concurrently execute runtime commands
    completed_cmds = 0
    cmd_errors: list[str] = []
    for cmd_str in commands:
        time.sleep(0.5)
        args = ["kubectl", "exec", "-n", namespace, target_workload, "--"] + cmd_str.split()
        try:
            res = subprocess.run(args, capture_output=True, text=True, check=False, timeout=8)
            if res.returncode == 0:
                completed_cmds += 1
            else:
                cmd_errors.append(f"Command '{cmd_str}' failed: {res.stderr.strip()}")
        except Exception as exc:
            cmd_errors.append(f"Command '{cmd_str}' exception: {exc}")

    # 3. Wait for network burst to complete
    try:
        stdout, stderr = burst_proc.communicate(timeout=duration_seconds + 10)
        lines = stdout.strip().splitlines()
        try:
            completed_reqs = int(lines[-1]) if lines else burst_requests
        except ValueError:
            completed_reqs = burst_requests
    except subprocess.TimeoutExpired:
        burst_proc.kill()
        completed_reqs = 0
        cmd_errors.append("Network burst timed out")

    session.duration_seconds = round(time.perf_counter() - t0, 2)
    session.end_time_utc = get_current_utc_str()
    session.requests_completed = completed_reqs
    session.requests_failed = max(0, burst_requests - completed_reqs)
    session.commands_completed = completed_cmds
    session.errors = cmd_errors
    session.status = "completed" if (completed_reqs > 0 and completed_cmds > 0) else "partial"

    (session_dir / "metadata.json").write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")

    manifest = ClientSessionManifest(
        session_id=session_id,
        experiment_id="client_concurrent_attack",
        scenario="concurrent_attack",
        target_service=target_service,
        client_pod=session.client_pod,
        status=session.status,
        start_time_utc=start_utc,
        end_time_utc=session.end_time_utc,
        duration_seconds=session.duration_seconds,
        requests_attempted=burst_requests,
        requests_completed=session.requests_completed,
        requests_failed=session.requests_failed,
        commands_attempted=len(commands),
        commands_completed=session.commands_completed,
        response_code_distribution={"200": session.requests_completed, "0": session.requests_failed},
        errors=session.errors,
        metadata={"commands": list(commands), "burst_requests": burst_requests},
    )
    ClientTelemetryLogger().save_session_manifest(manifest)
    return session


def execute_cpu_stress_scenario(
    duration_seconds: float = 10.0,
    target_workload: str = DEFAULT_WORKLOAD_POD,
    namespace: str = DEFAULT_NAMESPACE,
) -> SimulationSession:
    """Launch controlled in-pod workload/CPU stress on webapp using marked PID loop.

    Safety constraints:
    - Target is strictly deployment/webapp (never touches cpu-test).
    - Duration is clamped between 1.0s and 30.0s.
    - Uses approved marked PID file (/tmp/kubernetes-threat-detection-cpu-attack.pid).
    - Cleanup verifies the process cmdline before killing and removes the PID marker.
    """
    if "cpu-test" in target_workload.lower():
        raise ValueError("Safety violation: Targeting cpu-test is strictly prohibited.")

    duration_seconds = max(1.0, min(float(duration_seconds), 30.0))
    session_id = f"cpu_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    session_dir = SIMULATION_RUNS_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    start_utc = get_current_utc_str()
    session = SimulationSession(
        session_id=session_id,
        scenario="cpu_stress",
        target_service="in-container-cpu",
        client_pod=target_workload,
        status="running",
        start_time_utc=start_utc,
        metadata={"target_workload": target_workload, "duration_requested": duration_seconds},
    )

    cluster_dict = {"namespace": namespace, "target_workload": target_workload}
    cmd = cpu_attack_command(cluster_dict)
    t0 = time.perf_counter()
    proc = None
    errors: list[str] = []

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(duration_seconds)
    except Exception as exc:
        errors.append(f"Failed to launch CPU stress: {exc}")
    finally:
        stop_err = stop_cpu_attack(cluster_dict)
        if stop_err:
            errors.append(stop_err)
        if proc and proc.poll() is None:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
            else:
                proc.kill()
                proc.wait(timeout=3)

    dur = round(time.perf_counter() - t0, 2)
    session.duration_seconds = dur
    session.end_time_utc = get_current_utc_str()
    session.errors = errors
    session.status = "completed" if not errors else "partial"

    (session_dir / "metadata.json").write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")

    manifest = ClientSessionManifest(
        session_id=session_id,
        experiment_id="client_cpu_stress",
        scenario="cpu_stress",
        target_service="in-container-cpu",
        client_pod=target_workload,
        status=session.status,
        start_time_utc=start_utc,
        end_time_utc=session.end_time_utc,
        duration_seconds=dur,
        commands_attempted=1,
        commands_completed=1 if session.status == "completed" else 0,
        errors=errors,
        metadata={"target_workload": target_workload},
    )
    ClientTelemetryLogger().save_session_manifest(manifest)
    return session


def cancel_all_active_traffic() -> dict[str, Any]:
    """Emergency cancel control: stops benign traffic and cleans up in-container CPU stress."""
    benign_res = stop_benign_traffic()
    cpu_err = stop_cpu_attack({"namespace": DEFAULT_NAMESPACE, "target_workload": DEFAULT_WORKLOAD_POD})

    client_logger = ClientTelemetryLogger()
    cancelled_sessions: list[str] = []
    for manifest in client_logger.list_sessions(limit=10):
        if manifest.status == "running":
            manifest.status = "cancelled"
            manifest.end_time_utc = get_current_utc_str()
            manifest.errors.append("Session aborted by operator emergency cancellation.")
            client_logger.save_session_manifest(manifest)
            cancelled_sessions.append(manifest.session_id)

    return {
        "status": "cancelled",
        "benign_traffic": benign_res,
        "cpu_cleanup": "ok" if not cpu_err else cpu_err,
        "cancelled_sessions": cancelled_sessions,
        "timestamp_utc": get_current_utc_str(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Kubernetes Traffic & Attack Simulation Controller")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # start-benign
    p_start = subparsers.add_parser("start-benign", help="Start continuous benign traffic generator")
    p_start.add_argument("--client-pod", default=DEFAULT_CLIENT_POD)
    p_start.add_argument("--target-service", default=DEFAULT_TARGET_SERVICE)
    p_start.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    p_start.add_argument("--interval", type=float, default=2.0)
    p_start.add_argument("--jitter", type=float, default=0.8)

    # stop-benign
    subparsers.add_parser("stop-benign", help="Stop running benign traffic generator")

    # status
    subparsers.add_parser("status", help="Get status of benign traffic generator")

    # run-daemon (internal)
    p_daemon = subparsers.add_parser("run-daemon", help="Run benign traffic loop in foreground")
    p_daemon.add_argument("--client-pod", default=DEFAULT_CLIENT_POD)
    p_daemon.add_argument("--target-service", default=DEFAULT_TARGET_SERVICE)
    p_daemon.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    p_daemon.add_argument("--interval", type=float, default=2.0)
    p_daemon.add_argument("--jitter", type=float, default=0.8)

    # cpu-stress
    p_cpu = subparsers.add_parser("cpu-stress", help="Execute controlled in-pod CPU stress on webapp")
    p_cpu.add_argument("--duration", type=float, default=10.0)
    p_cpu.add_argument("--target-workload", default=DEFAULT_WORKLOAD_POD)
    p_cpu.add_argument("--namespace", default=DEFAULT_NAMESPACE)

    # cancel
    subparsers.add_parser("cancel", help="Emergency stop all active simulation traffic and clean up CPU stress")

    # run-attack
    p_attack = subparsers.add_parser("run-attack", help="Execute an on-demand attack scenario")
    p_attack.add_argument(
        "--scenario",
        choices=["network_burst", "runtime_anomaly", "concurrent_attack", "cpu_stress"],
        required=True,
    )
    p_attack.add_argument("--requests", type=int, default=50)
    p_attack.add_argument("--duration", type=float, default=10.0)

    args = parser.parse_args()

    if args.command == "start-benign":
        res = start_benign_traffic(
            client_pod=args.client_pod,
            target_service=args.target_service,
            namespace=args.namespace,
            base_interval=args.interval,
            jitter=args.jitter,
        )
        print(json.dumps(res, indent=2))

    elif args.command == "stop-benign":
        res = stop_benign_traffic()
        print(json.dumps(res, indent=2))

    elif args.command == "status":
        res = get_benign_traffic_status()
        print(json.dumps(res, indent=2))

    elif args.command == "run-daemon":
        run_benign_daemon_loop(
            client_pod=args.client_pod,
            target_service=args.target_service,
            namespace=args.namespace,
            base_interval=args.interval,
            jitter=args.jitter,
        )

    elif args.command == "cpu-stress":
        session = execute_cpu_stress_scenario(
            duration_seconds=args.duration,
            target_workload=args.target_workload,
            namespace=args.namespace,
        )
        print(json.dumps(session.to_dict(), indent=2))

    elif args.command == "cancel":
        res = cancel_all_active_traffic()
        print(json.dumps(res, indent=2))

    elif args.command == "run-attack":
        if args.scenario == "network_burst":
            session = execute_network_burst_scenario(requests=args.requests, duration_seconds=args.duration)
        elif args.scenario == "runtime_anomaly":
            session = execute_runtime_anomaly_scenario()
        elif args.scenario == "concurrent_attack":
            session = execute_concurrent_attack_scenario(burst_requests=args.requests, duration_seconds=args.duration)
        elif args.scenario == "cpu_stress":
            session = execute_cpu_stress_scenario(duration_seconds=args.duration)
        print(json.dumps(session.to_dict(), indent=2))


if __name__ == "__main__":
    main()
