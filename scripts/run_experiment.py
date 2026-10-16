"""Safe, repeatable experiment orchestrator for Kubernetes Threat Detection.

Coordinates controlled normal baseline, network burst, runtime introspection,
and concurrent network/workload activity against local Minikube workloads.
Preserves existing collector streams and guarantees process cleanup.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import psutil
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from experiments.harness import (
    ALLOWED_RUNTIME_COMMANDS,
    HARD_LIMITS,
    ActivityResult,
    ModalityCorrelation,
    TelemetryHarness,
    validate_runtime_command,
)
from experiments.orchestration import (
    complete_window_count,
    experiment_id,
    kubernetes_context_is_active,
    overlap_interval,
    utc_now,
)
from experiments.run_experiment import (
    CPU_ATTACK_PID_FILE,
    cpu_attack_command,
    stop_cpu_attack,
)
from telemetry.schemas import parse_utc_timestamp
from telemetry.security import (
    validate_k8s_name,
    validate_positive_float,
    validate_positive_int,
    validate_safe_output_path,
)

logger = logging.getLogger("orchestrator")
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)

DEFAULT_ORCHESTRATOR_OUTPUT_DIR = Path("experiments/orchestrator_runs")

# Orchestrator-specific safety ceilings
ORCHESTRATOR_BOUNDS: dict[str, float | int] = {
    "normal_max_requests": 60,
    "normal_min_delay_seconds": 1.0,
    "burst_max_duration_seconds": 20.0,
    "burst_max_requests": 200,
    "runtime_max_commands": 20,
    "runtime_min_delay_seconds": 0.2,
    "concurrent_max_duration_seconds": 20.0,
    "concurrent_max_requests": 200,
}


@dataclass
class CollectorStatus:
    name: str
    script: str
    running: bool
    pid: int | None = None
    owned: bool = False
    process: subprocess.Popen[str] | None = None


class CollectorManager:
    """Detects and safely manages telemetry collectors without terminating pre-existing instances."""

    COLLECTOR_SPECS: dict[str, dict[str, Any]] = {
        "workload": {
            "script": "telemetry/workload_collector.py",
            "pid_files": [
                Path("telemetry/data/.workload_collector.pid"),
            ],
            "default_output": Path("telemetry/data/workload_metrics.csv"),
            "args": ["--interval", "5.0"],
        },
        "network": {
            "script": "telemetry/network_collector.py",
            "pid_files": [
                Path("telemetry/data/network/.network_collector.pid"),
                Path("telemetry/data/.network_collector.pid"),
            ],
            "default_output": Path("telemetry/data/network/network_events.jsonl"),
            "args": [],
        },
        "runtime": {
            "script": "telemetry/runtime_collector.py",
            "pid_files": [
                Path("telemetry/data/runtime/.runtime_collector.pid"),
                Path("telemetry/data/.runtime_collector.pid"),
            ],
            "default_output": Path("telemetry/data/runtime/runtime_events.jsonl"),
            "args": [],
        },
    }

    def __init__(self, project_root: Path | str = ".") -> None:
        self.project_root = Path(project_root).resolve()
        self.collectors: dict[str, CollectorStatus] = {}

    def _check_process_alive(self, pid: int, script_name: str) -> bool:
        """Verify whether a PID is running and matches the expected collector script or module."""
        try:
            if not psutil.pid_exists(pid):
                return False
            proc = psutil.Process(pid)
            if not proc.is_running():
                return False
            cmdline = proc.cmdline()
            cmd_str = " ".join(cmdline).lower()
            stem = Path(script_name).stem.lower()
            return script_name.lower() in cmd_str or stem in cmd_str
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def detect_collector(self, name: str) -> CollectorStatus:
        """Inspect running processes and PID files to find active collector."""
        spec = self.COLLECTOR_SPECS.get(name)
        if not spec:
            raise ValueError(f"Unknown collector name: {name}")

        script_path = spec["script"]
        script_name = Path(script_path).name
        stem = Path(script_name).stem.lower()

        # 1. Check PID files
        for rel_pid in spec["pid_files"]:
            pid_file = self.project_root / rel_pid
            if pid_file.exists():
                try:
                    pid = int(pid_file.read_text(encoding="utf-8").strip())
                    if self._check_process_alive(pid, script_name):
                        return CollectorStatus(
                            name=name, script=script_path, running=True, pid=pid, owned=False
                        )
                except Exception:
                    pass

        # 2. Process table scan fallback
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    cmdline = proc.info.get("cmdline") or []
                    cmd_str = " ".join(cmdline).lower()
                    if (script_name.lower() in cmd_str or stem in cmd_str) and "python" in (proc.info.get("name") or "").lower():
                        # Exclude one-liners and streamlit
                        if "-c" not in cmd_str and "streamlit" not in cmd_str:
                            pid = proc.info["pid"]
                            return CollectorStatus(
                                name=name, script=script_path, running=True, pid=pid, owned=False
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        return CollectorStatus(name=name, script=script_path, running=False, pid=None, owned=False)

    def ensure_collectors(
        self,
        required: Sequence[str] = ("workload", "network", "runtime"),
        log_file: Path | None = None,
    ) -> dict[str, CollectorStatus]:
        """Ensure required collectors are running. Starts missing ones with ownership=True."""
        out_handle = log_file.open("a", encoding="utf-8") if log_file else None
        try:
            for name in required:
                status = self.detect_collector(name)
                if status.running:
                    logger.info("Collector [%s] running (PID %s) -> REUSING (owned=False)", name, status.pid)
                    self.collectors[name] = status
                else:
                    spec = self.COLLECTOR_SPECS[name]
                    cmd = [sys.executable, spec["script"]] + spec["args"]
                    logger.info("Collector [%s] offline -> STARTING (%s) (owned=True)", name, " ".join(cmd))
                    proc = subprocess.Popen(
                        cmd,
                        cwd=self.project_root,
                        stdout=out_handle or subprocess.DEVNULL,
                        stderr=out_handle or subprocess.DEVNULL,
                        text=True,
                    )
                    time.sleep(1.0)
                    if proc.poll() is not None:
                        logger.error("Collector [%s] failed immediately with exit code %s", name, proc.poll())
                        self.collectors[name] = CollectorStatus(
                            name=name, script=spec["script"], running=False, pid=None, owned=False
                        )
                    else:
                        status = CollectorStatus(
                            name=name,
                            script=spec["script"],
                            running=True,
                            pid=proc.pid,
                            owned=True,
                            process=proc,
                        )
                        self.collectors[name] = status
                        logger.info("Collector [%s] confirmed running (PID %s, owned=True)", name, proc.pid)
        finally:
            if out_handle:
                out_handle.flush()

        return self.collectors

    def cleanup_owned(self) -> None:
        """Safely terminate ONLY collector processes started by this orchestrator instance."""
        for name, status in self.collectors.items():
            if status.owned and status.process and status.process.poll() is None:
                logger.info("Cleaning up orchestrator-owned collector [%s] (PID %s)", name, status.pid)
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(status.pid)],
                        capture_output=True,
                        check=False,
                    )
                else:
                    status.process.terminate()
                    try:
                        status.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        status.process.kill()
            elif not status.owned and status.running:
                logger.debug("Preserving pre-existing collector [%s] (PID %s)", name, status.pid)


class ExperimentOrchestrator:
    """Manages preflight, execution, time-overlap tracking, and window correlation for experiment sessions."""

    def __init__(
        self,
        cluster_id: str = "minikube",
        expected_context: str = "minikube",
        namespace: str = "default",
        target_workload: str = "deployment/webapp",
        traffic_generator: str = "traffic-generator",
        output_dir: Path | str = DEFAULT_ORCHESTRATOR_OUTPUT_DIR,
        project_root: Path | str = ".",
        harness: TelemetryHarness | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.cluster_id = cluster_id
        self.expected_context = expected_context
        self.namespace = validate_k8s_name(namespace, "namespace")
        self.target_workload = validate_k8s_name(target_workload, "target_workload")
        self.traffic_generator = validate_k8s_name(traffic_generator, "traffic_generator")
        from telemetry.security import get_default_allowed_roots

        permitted = list(get_default_allowed_roots())
        if self.project_root not in permitted:
            permitted.append(self.project_root)
        self.output_root = validate_safe_output_path(
            output_dir, base_dir=self.project_root, allowed_roots=permitted
        )
        self.collector_mgr = CollectorManager(project_root=self.project_root)

        cfg_candidate = self.project_root / "configs/harness.yaml"
        harness_root = self.project_root if cfg_candidate.exists() else Path(".").resolve()
        self.harness = harness or TelemetryHarness(project_root=harness_root)

        # Track active children processes for signal teardown
        self._active_children: list[subprocess.Popen[str]] = []
        self._interrupted: bool = False

    def preflight_check(self) -> tuple[bool, list[str]]:
        """Validate Kubernetes context, cluster connectivity, and workload accessibility."""
        errors: list[str] = []

        if not kubernetes_context_is_active(self.expected_context):
            errors.append(f"Active Kubernetes context does not match expected context '{self.expected_context}'")

        # Verify target workload pod is accessible
        res = subprocess.run(
            ["kubectl", "get", self.target_workload, "-n", self.namespace, "-o", "jsonpath={.status.readyReplicas}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            errors.append(f"Target workload '{self.target_workload}' in namespace '{self.namespace}' not reachable: {res.stderr.strip()}")
        elif res.stdout.strip() in {"", "0"}:
            errors.append(f"Target workload '{self.target_workload}' has 0 ready replicas")

        # Verify traffic-generator pod is running
        res_tg = subprocess.run(
            ["kubectl", "get", "pod", self.traffic_generator, "-n", self.namespace, "-o", "jsonpath={.status.phase}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res_tg.returncode != 0:
            errors.append(f"Traffic generator pod '{self.traffic_generator}' not found in namespace '{self.namespace}'")
        elif res_tg.stdout.strip() != "Running":
            errors.append(f"Traffic generator pod '{self.traffic_generator}' is in phase '{res_tg.stdout.strip()}' (expected Running)")

        return (len(errors) == 0, errors)

    def execute_normal(
        self,
        requests: int = 10,
        delay_seconds: float = 1.5,
        timeout_seconds: float = 30.0,
    ) -> ActivityResult:
        """Run bounded, low-rate HTTP baseline requests from traffic-generator to webapp."""
        reqs = validate_positive_int(requests, "requests", allow_zero=False)
        delay = validate_positive_float(delay_seconds, "delay_seconds", allow_zero=False)

        if reqs > int(ORCHESTRATOR_BOUNDS["normal_max_requests"]):
            raise ValueError(f"Normal requests {reqs} exceeds limit {ORCHESTRATOR_BOUNDS['normal_max_requests']}")
        if delay < float(ORCHESTRATOR_BOUNDS["normal_min_delay_seconds"]):
            raise ValueError(f"Normal delay {delay}s is less than minimum {ORCHESTRATOR_BOUNDS['normal_min_delay_seconds']}s")

        script = (
            f"i=0; while [ $i -lt {reqs} ]; do "
            "wget -q -O /dev/null http://webapp; "
            "i=$((i+1)); "
            f"sleep {delay}; "
            "done; "
            "echo $i"
        )
        cmd = ["kubectl", "exec", "-n", self.namespace, self.traffic_generator, "--", "sh", "-c", script]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_seconds)
        if res.returncode != 0:
            return ActivityResult(
                requests_attempted=reqs,
                requests_completed=0,
                exit_code=res.returncode,
                errors=[res.stderr.strip() or "traffic-generator wget loop failed"],
            )
        try:
            completed = int(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            completed = reqs
        return ActivityResult(requests_attempted=reqs, requests_completed=completed, exit_code=0)

    def execute_network_burst(
        self,
        duration_seconds: float = 10.0,
        max_requests: int = 60,
        timeout_seconds: float = 25.0,
    ) -> ActivityResult:
        """Run bounded burst of rapid HTTP requests from traffic-generator."""
        dur = validate_positive_float(duration_seconds, "duration_seconds", allow_zero=False)
        max_req = validate_positive_int(max_requests, "max_requests", allow_zero=False)

        if dur > float(ORCHESTRATOR_BOUNDS["burst_max_duration_seconds"]):
            raise ValueError(f"Burst duration {dur}s exceeds limit {ORCHESTRATOR_BOUNDS['burst_max_duration_seconds']}s")
        if max_req > int(ORCHESTRATOR_BOUNDS["burst_max_requests"]):
            raise ValueError(f"Burst max_requests {max_req} exceeds limit {ORCHESTRATOR_BOUNDS['burst_max_requests']}")

        dur_int = int(dur)
        script = (
            f"end=$(( $(date +%s) + {dur_int} )); "
            "c=0; "
            f"while [ \"$(date +%s)\" -lt \"$end\" ] && [ $c -lt {max_req} ]; do "
            "wget -q -O /dev/null http://webapp; "
            "c=$((c+1)); "
            "done; "
            "echo $c"
        )
        cmd = ["kubectl", "exec", "-n", self.namespace, self.traffic_generator, "--", "sh", "-c", script]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_seconds)
        if res.returncode != 0:
            return ActivityResult(
                requests_attempted=max_req,
                requests_completed=0,
                exit_code=res.returncode,
                errors=[res.stderr.strip() or "traffic-generator burst failed"],
            )
        try:
            completed = int(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            completed = max_req
        return ActivityResult(requests_attempted=max_req, requests_completed=completed, exit_code=0)

    def execute_runtime(
        self,
        commands: Sequence[str] = ("id", "whoami", "curl -s http://webapp"),
        delay_seconds: float = 0.5,
    ) -> ActivityResult:
        """Execute allowlisted introspection commands sequentially inside webapp container."""
        delay = validate_positive_float(delay_seconds, "delay_seconds", allow_zero=True)
        if len(commands) > int(ORCHESTRATOR_BOUNDS["runtime_max_commands"]):
            raise ValueError(f"Runtime command count {len(commands)} exceeds limit {ORCHESTRATOR_BOUNDS['runtime_max_commands']}")
        if delay < float(ORCHESTRATOR_BOUNDS["runtime_min_delay_seconds"]):
            raise ValueError(f"Runtime delay {delay}s is less than minimum {ORCHESTRATOR_BOUNDS['runtime_min_delay_seconds']}s")

        validated_cmds = [validate_runtime_command(cmd) for cmd in commands]
        attempted = len(validated_cmds)
        completed = 0
        errors: list[str] = []

        for cmd_str in validated_cmds:
            args = ["kubectl", "exec", "-n", self.namespace, self.target_workload, "--"] + cmd_str.split()
            res = subprocess.run(args, capture_output=True, text=True, check=False, timeout=10.0)
            if res.returncode == 0:
                completed += 1
            else:
                errors.append(f"Command '{cmd_str}' failed: {res.stderr.strip()}")
            time.sleep(delay)

        return ActivityResult(
            commands_attempted=attempted,
            commands_completed=completed,
            exit_code=0 if not errors else 1,
            errors=errors,
        )

    def execute_concurrent(
        self,
        burst_duration_seconds: float = 10.0,
        burst_max_requests: int = 60,
        cpu_duration_seconds: float = 10.0,
        timeout_seconds: float = 30.0,
    ) -> tuple[ActivityResult, dict[str, str | None]]:
        """Run coordinated network burst and in-pod CPU stress with explicit overlap tracking."""
        b_dur = validate_positive_float(burst_duration_seconds, "burst_duration_seconds", allow_zero=False)
        c_dur = validate_positive_float(cpu_duration_seconds, "cpu_duration_seconds", allow_zero=False)
        max_req = validate_positive_int(burst_max_requests, "burst_max_requests", allow_zero=False)

        if b_dur > float(ORCHESTRATOR_BOUNDS["concurrent_max_duration_seconds"]):
            raise ValueError(f"Burst duration {b_dur}s exceeds limit {ORCHESTRATOR_BOUNDS['concurrent_max_duration_seconds']}s")
        if c_dur > float(ORCHESTRATOR_BOUNDS["concurrent_max_duration_seconds"]):
            raise ValueError(f"CPU stress duration {c_dur}s exceeds limit {ORCHESTRATOR_BOUNDS['concurrent_max_duration_seconds']}s")
        if max_req > int(ORCHESTRATOR_BOUNDS["concurrent_max_requests"]):
            raise ValueError(f"Burst requests {max_req} exceeds limit {ORCHESTRATOR_BOUNDS['concurrent_max_requests']}")

        cluster_dict = {"namespace": self.namespace, "target_workload": self.target_workload}
        # Pre-cleanup any stale CPU loop
        stop_cpu_attack(cluster_dict)

        timestamps: dict[str, str | None] = {
            "workload_attack_start_time_utc": None,
            "workload_attack_end_time_utc": None,
            "network_attack_start_time_utc": None,
            "network_attack_end_time_utc": None,
            "overlap_start_time_utc": None,
            "overlap_end_time_utc": None,
        }

        errors: list[str] = []
        cpu_proc: subprocess.Popen[str] | None = None
        net_res = ActivityResult()

        try:
            # 1. Start CPU stress loop
            timestamps["workload_attack_start_time_utc"] = utc_now()
            cpu_cmd = cpu_attack_command(cluster_dict)
            cpu_proc = subprocess.Popen(cpu_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._active_children.append(cpu_proc)

            # 2. Start concurrent network burst
            timestamps["network_attack_start_time_utc"] = utc_now()
            net_res = self.execute_network_burst(
                duration_seconds=b_dur, max_requests=max_req, timeout_seconds=timeout_seconds
            )
            timestamps["network_attack_end_time_utc"] = utc_now()

            # Ensure CPU stress lasts at least cpu_duration_seconds
            remaining_cpu_time = c_dur - b_dur
            if remaining_cpu_time > 0:
                time.sleep(remaining_cpu_time)

        finally:
            if cpu_proc:
                if cpu_proc in self._active_children:
                    self._active_children.remove(cpu_proc)
                if cpu_proc.poll() is None:
                    if sys.platform == "win32":
                        subprocess.run(["taskkill", "/F", "/T", "/PID", str(cpu_proc.pid)], capture_output=True, check=False)
                    else:
                        cpu_proc.terminate()
            cleanup_err = stop_cpu_attack(cluster_dict)
            timestamps["workload_attack_end_time_utc"] = utc_now()
            if cleanup_err:
                errors.append(cleanup_err)

        # 3. Calculate explicit overlap interval
        ov_start, ov_end = overlap_interval(
            timestamps["network_attack_start_time_utc"],
            timestamps["network_attack_end_time_utc"],
            timestamps["workload_attack_start_time_utc"],
            timestamps["workload_attack_end_time_utc"],
        )
        timestamps["overlap_start_time_utc"] = ov_start
        timestamps["overlap_end_time_utc"] = ov_end

        activity_res = ActivityResult(
            requests_attempted=net_res.requests_attempted,
            requests_completed=net_res.requests_completed,
            commands_attempted=1,
            commands_completed=1 if not errors else 0,
            exit_code=net_res.exit_code if not errors else 1,
            errors=net_res.errors + errors,
        )
        return activity_res, timestamps

    def run_session(
        self,
        scenario: str,
        dry_run: bool = False,
        cooldown_seconds: float = 5.0,
        requests: int = 10,
        delay_seconds: float = 1.5,
        duration_seconds: float = 10.0,
        commands: Sequence[str] = ("id", "whoami", "curl -s http://webapp"),
    ) -> tuple[Path, dict[str, Any]]:
        """Execute a complete, bounded session and save isolated metadata and window telemetry."""
        session_id = experiment_id(scenario, cluster_id=self.cluster_id)
        session_dir = validate_safe_output_path(
            self.output_root / session_id, base_dir=self.output_root, allowed_roots=[self.output_root]
        )
        session_dir.mkdir(parents=True, exist_ok=True)
        events_log = session_dir / "events.log"

        def _log(msg: str) -> None:
            ts = utc_now()
            logger.info("[%s] %s", session_id, msg)
            with events_log.open("a", encoding="utf-8") as handle:
                handle.write(f"[{ts}] {msg}\n")

        _log(f"Session initialized: scenario={scenario}, dry_run={dry_run}")

        # Preflight
        ok, preflight_errors = self.preflight_check()
        if not ok:
            _log(f"Preflight checks failed: {preflight_errors}")
            meta_err = {
                "session_id": session_id,
                "scenario": scenario,
                "status": "preflight_failed",
                "errors": preflight_errors,
            }
            (session_dir / "metadata.json").write_text(json.dumps(meta_err, indent=2), encoding="utf-8")
            raise RuntimeError(f"Preflight check failed: {'; '.join(preflight_errors)}")

        _log("Preflight checks passed: context and pods verified.")

        # Ensure telemetry collectors are active
        collector_log = session_dir / "collectors.log"
        collectors = self.collector_mgr.ensure_collectors(log_file=collector_log)
        collector_summary = {
            name: {"running": status.running, "pid": status.pid, "owned": status.owned}
            for name, status in collectors.items()
        }

        if dry_run:
            _log("Dry-run requested; skipping activity execution.")
            meta_dry = {
                "session_id": session_id,
                "scenario": scenario,
                "status": "planned",
                "start_time_utc": utc_now(),
                "end_time_utc": utc_now(),
                "duration_seconds": 0.0,
                "collector_status": collector_summary,
                "activity_result": asdict(ActivityResult()),
                "modalities_captured": {"network": False, "workload": False, "runtime": False},
                "modality_correlations": {},
                "window_count": 0,
                "notes": "Dry-run execution only; no cluster traffic generated.",
            }
            (session_dir / "metadata.json").write_text(json.dumps(meta_dry, indent=2), encoding="utf-8")
            (session_dir / "session_metadata.json").write_text(json.dumps(meta_dry, indent=2), encoding="utf-8")
            return session_dir, meta_dry

        start_time_utc = utc_now()
        _log(f"Activity started at {start_time_utc}")
        status = "completed"
        activity_res = ActivityResult()
        timing_info: dict[str, str | None] = {}

        try:
            if scenario in {"normal", "baseline"}:
                activity_res = self.execute_normal(requests=requests, delay_seconds=delay_seconds)
            elif scenario == "network_burst":
                activity_res = self.execute_network_burst(
                    duration_seconds=duration_seconds, max_requests=requests
                )
            elif scenario == "runtime":
                activity_res = self.execute_runtime(commands=commands, delay_seconds=delay_seconds)
            elif scenario == "concurrent":
                activity_res, timing_info = self.execute_concurrent(
                    burst_duration_seconds=duration_seconds,
                    burst_max_requests=requests,
                    cpu_duration_seconds=duration_seconds,
                )
            else:
                raise ValueError(f"Unsupported scenario: '{scenario}'")

            if activity_res.exit_code != 0:
                status = "failed"
                _log(f"Activity returned exit code {activity_res.exit_code}: {activity_res.errors}")
            else:
                _log("Activity completed successfully.")

        except KeyboardInterrupt:
            status = "interrupted"
            activity_res.errors.append("Session interrupted by user/operator.")
            _log("Execution interrupted by KeyboardInterrupt.")
            stop_cpu_attack({"namespace": self.namespace, "target_workload": self.target_workload})
        except Exception as exc:
            status = "failed"
            activity_res.errors.append(str(exc))
            _log(f"Activity execution failed: {exc}")
            stop_cpu_attack({"namespace": self.namespace, "target_workload": self.target_workload})
        finally:
            self.collector_mgr.cleanup_owned()

        end_time_utc = utc_now()
        _log(f"Activity ended at {end_time_utc}. Waiting {cooldown_seconds}s cooldown.")
        time.sleep(cooldown_seconds)

        observation_end_utc = utc_now()
        duration_s = round(
            (parse_utc_timestamp(end_time_utc) - parse_utc_timestamp(start_time_utc)).total_seconds(), 2
        )

        # Correlate 10-second observation windows
        _log("Correlating telemetry across observation window...")
        correlations, windows, _ = self.harness.correlate_telemetry(
            start_time_utc=start_time_utc,
            end_time_utc=observation_end_utc,
        )

        modalities_captured = {k: v.captured for k, v in correlations.items()}
        _log(f"Correlation finished: modalities_captured={modalities_captured}, windows={len(windows)}")

        # Validate that expected telemetry streams for the scenario were actually captured
        expected_modalities: list[str] = []
        if scenario in {"normal", "baseline", "network_burst"}:
            expected_modalities = ["network"]
        elif scenario == "runtime":
            expected_modalities = ["runtime"]
        elif scenario == "concurrent":
            expected_modalities = ["network", "workload"]

        missing_modalities = [m for m in expected_modalities if not modalities_captured.get(m)]
        validation_warnings: list[str] = []

        # Diagnose clock skew for missing eBPF streams
        clock_skew_diagnostics: dict[str, Any] = {}
        now_dt = parse_utc_timestamp(utc_now())

        if "network" in missing_modalities and self.harness.network_source.exists():
            try:
                raw_lines = [l for l in self.harness.network_source.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
                if raw_lines:
                    last_obj = json.loads(raw_lines[-1])
                    last_ts_str = last_obj.get("timestamp")
                    if last_ts_str:
                        last_ts = parse_utc_timestamp(last_ts_str)
                        skew_sec = (now_dt - last_ts).total_seconds()
                        if skew_sec > 60:
                            clock_skew_diagnostics["network"] = {
                                "skew_detected": True,
                                "last_event_timestamp": last_ts_str,
                                "offset_seconds": round(skew_sec, 1),
                                "diagnostic": "Inspektor Gadget eBPF trace_tcp timestamp lagged host UTC (kernel monotonic clock drift)",
                            }
            except Exception:
                pass

        if "runtime" in missing_modalities and self.harness.runtime_source.exists():
            try:
                raw_lines = [l for l in self.harness.runtime_source.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
                if raw_lines:
                    last_obj = json.loads(raw_lines[-1])
                    last_ts_str = last_obj.get("timestamp")
                    if last_ts_str:
                        last_ts = parse_utc_timestamp(last_ts_str)
                        skew_sec = (now_dt - last_ts).total_seconds()
                        if skew_sec > 60:
                            clock_skew_diagnostics["runtime"] = {
                                "skew_detected": True,
                                "last_event_timestamp": last_ts_str,
                                "offset_seconds": round(skew_sec, 1),
                                "diagnostic": "Inspektor Gadget eBPF trace_exec timestamp lagged host UTC (kernel monotonic clock drift)",
                            }
            except Exception:
                pass

        if status == "completed" and missing_modalities:
            status = "incomplete"
            warn_msg = (
                f"Scenario '{scenario}' executed commands successfully, but expected telemetry "
                f"{missing_modalities} was not captured in the host UTC observation window."
            )
            if clock_skew_diagnostics:
                warn_msg += f" (Clock skew detected in eBPF streams: {list(clock_skew_diagnostics.keys())})"
            validation_warnings.append(warn_msg)
            _log(f"WARNING: {warn_msg}")

        dataset_suitable = (status == "completed") and (len(windows) > 0)
        suitability_reason = (
            "Fully validated multi-modal capture"
            if dataset_suitable
            else f"Session status is '{status}'; missing required telemetry: {missing_modalities or 'none'}"
        )

        session_meta: dict[str, Any] = {
            "session_id": session_id,
            "scenario": scenario,
            "status": status,
            "dataset_suitable": dataset_suitable,
            "dataset_suitability_reason": suitability_reason,
            "expected_modalities": expected_modalities,
            "missing_modalities": missing_modalities,
            "validation_warnings": validation_warnings,
            "clock_skew_diagnostics": clock_skew_diagnostics,
            "cluster": {
                "cluster_id": self.cluster_id,
                "expected_context": self.expected_context,
                "namespace": self.namespace,
                "target_workload": self.target_workload,
                "traffic_generator": self.traffic_generator,
            },
            "parameters": {
                "requests": requests,
                "delay_seconds": delay_seconds,
                "duration_seconds": duration_seconds,
                "commands": list(commands) if scenario == "runtime" else None,
                "cooldown_seconds": cooldown_seconds,
            },
            "timestamps": {
                "start_time_utc": start_time_utc,
                "activity_start_time_utc": start_time_utc,
                "activity_end_time_utc": end_time_utc,
                "cooldown_start_time_utc": end_time_utc,
                "observation_end_utc": observation_end_utc,
                "duration_seconds": duration_s,
                "overlap_start_time_utc": timing_info.get("overlap_start_time_utc"),
                "overlap_end_time_utc": timing_info.get("overlap_end_time_utc"),
            },
            "collector_status": collector_summary,
            "activity_result": asdict(activity_res),
            "modalities_captured": modalities_captured,
            "modality_correlations": {k: asdict(v) for k, v in correlations.items()},
            "window_count": len(windows),
            "notes": f"Orchestrated session '{scenario}' executed safely.",
        }

        # Write artifacts
        (session_dir / "metadata.json").write_text(json.dumps(session_meta, indent=2), encoding="utf-8")
        (session_dir / "session_metadata.json").write_text(json.dumps(session_meta, indent=2), encoding="utf-8")
        (session_dir / "telemetry_windows.json").write_text(json.dumps(windows, indent=2), encoding="utf-8")
        _log(f"All artifacts saved in {session_dir}")

        return session_dir, session_meta


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safe, reproducible Kubernetes threat detection experiment orchestrator."
    )
    parser.add_argument(
        "--scenario",
        required=True,
        choices=["normal", "baseline", "network_burst", "runtime", "concurrent"],
        help="Experiment scenario to orchestrate.",
    )
    parser.add_argument("--requests", type=int, default=10, help="Request count (for normal or burst).")
    parser.add_argument("--delay", type=float, default=1.5, help="Delay between requests/commands in seconds.")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration for burst or concurrent activity.")
    parser.add_argument(
        "--commands",
        nargs="+",
        default=["id", "whoami", "curl -s http://webapp"],
        help="In-container commands for runtime scenario.",
    )
    parser.add_argument("--cooldown", type=float, default=5.0, help="Cooldown wait time after activity.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_ORCHESTRATOR_OUTPUT_DIR)
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--target-workload", default="deployment/webapp")
    parser.add_argument("--traffic-generator", default="traffic-generator")
    parser.add_argument("--cluster-id", default="minikube")
    parser.add_argument("--expected-context", default="minikube")
    parser.add_argument("--dry-run", action="store_true", help="Perform preflight without executing activity.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    orchestrator = ExperimentOrchestrator(
        cluster_id=args.cluster_id,
        expected_context=args.expected_context,
        namespace=args.namespace,
        target_workload=args.target_workload,
        traffic_generator=args.traffic_generator,
        output_dir=args.output_dir,
    )

    # Register signal handling for clean teardown
    def _handle_signal(signum: int, frame: Any) -> None:
        logger.warning("Caught signal %s; cleaning up controlled activity...", signum)
        orchestrator.collector_mgr.cleanup_owned()
        stop_cpu_attack({"namespace": args.namespace, "target_workload": args.target_workload})
        sys.exit(130)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        run_dir, metadata = orchestrator.run_session(
            scenario=args.scenario,
            dry_run=args.dry_run,
            cooldown_seconds=args.cooldown,
            requests=args.requests,
            delay_seconds=args.delay,
            duration_seconds=args.duration,
            commands=args.commands,
        )
        print(json.dumps({
            "session_id": metadata["session_id"],
            "status": metadata["status"],
            "run_directory": str(run_dir),
            "window_count": metadata.get("window_count", 0),
            "modalities_captured": metadata.get("modalities_captured", {}),
        }, indent=2))
        return 0 if metadata["status"] in {"completed", "planned"} else 1
    except Exception as exc:
        logger.error("Orchestrator failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
