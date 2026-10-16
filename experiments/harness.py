"""Repeatable, resource-bounded Kubernetes telemetry experiment harness.

Generates controlled workload activity (baseline, network burst, runtime activity,
workload variation) and correlates the resulting network, runtime, and workload
telemetry into 10-second observation windows.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import yaml

from experiments.orchestration import (
    experiment_id,
    kubernetes_context_is_active,
    utc_now,
)
from experiments.run_experiment import CPU_ATTACK_PID_FILE, stop_cpu_attack
from telemetry.features.network import extract_network_features
from telemetry.features.runtime import extract_runtime_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import (
    NetworkEvent,
    RuntimeEvent,
    SchemaError,
    WorkloadSample,
    load_network_events,
    load_runtime_events,
    load_workload_samples,
    parse_utc_timestamp,
)
from telemetry.security import (
    validate_k8s_name,
    validate_positive_float,
    validate_positive_int,
    validate_safe_output_path,
)
from telemetry.windowing import WINDOW_SECONDS, isoformat_z, window_start

logger = logging.getLogger("experiments.harness")

DEFAULT_CONFIG_PATH = Path("configs/harness.yaml")
DEFAULT_OUTPUT_DIR = Path("experiments/harness_runs")

# Strict allowlist of benign in-container introspection commands
ALLOWED_RUNTIME_COMMANDS: frozenset[str] = frozenset({
    "id",
    "whoami",
    "uname",
    "uname -a",
    "date",
    "date -u",
    "pwd",
    "ls",
    "ls -la",
    "ls /usr/share/nginx/html",
    "ls /etc/nginx",
    "cat /etc/nginx/nginx.conf",
    "cat /etc/resolv.conf",
    "curl -s http://webapp",
    "curl -s http://localhost",
    "curl -I http://webapp",
    "curl -I http://localhost",
    "curl -s http://127.0.0.1",
    "curl -I http://127.0.0.1",
})

# Hard safety ceilings that cannot be exceeded regardless of config file
HARD_LIMITS: dict[str, float | int] = {
    "max_duration_seconds": 30.0,
    "max_requests": 200,
    "max_workload_duration_seconds": 20.0,
    "max_runtime_commands": 20,
}


class HarnessConfigError(ValueError):
    """Raised when an experiment configuration or parameter violates safety bounds."""


class HarnessExecutionError(RuntimeError):
    """Raised when experiment execution fails."""


@dataclass(frozen=True)
class ScenarioConfig:
    name: str
    description: str
    timeout_seconds: float
    requests: int | None = None
    delay_seconds: float | None = None
    duration_seconds: float | None = None
    max_requests: int | None = None
    commands: tuple[str, ...] | None = None


@dataclass
class ActivityResult:
    requests_attempted: int = 0
    requests_completed: int = 0
    commands_attempted: int = 0
    commands_completed: int = 0
    exit_code: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ModalityCorrelation:
    modality: str
    captured: bool
    record_count: int
    details: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None


@dataclass
class ExperimentMetadata:
    experiment_id: str
    scenario: str
    status: str
    start_time_utc: str
    end_time_utc: str
    duration_seconds: float
    cluster_id: str
    namespace: str
    target_workload: str
    config: dict[str, Any]
    activity_result: dict[str, Any]
    modalities_captured: dict[str, bool]
    modality_correlations: dict[str, dict[str, Any]]
    window_count: int
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_harness_config(path: Path | str = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load and return YAML harness configuration."""
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {cfg_path}")
    with cfg_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise HarnessConfigError("Harness configuration must be a mapping.")
    return data


def validate_runtime_command(command: str) -> str:
    """Validate that a command is strictly within the benign introspection allowlist."""
    if not isinstance(command, str) or not command.strip():
        raise HarnessConfigError("Runtime command must be a non-empty string.")
    cleaned = command.strip()
    # Check for forbidden shell metacharacters
    for bad_char in (";", "&&", "||", "|", ">", "<", "$", "`", "\n", "\r"):
        if bad_char in cleaned:
            raise HarnessConfigError(
                f"Forbidden shell metacharacter '{bad_char}' in command '{cleaned}'"
            )
    if cleaned not in ALLOWED_RUNTIME_COMMANDS:
        raise HarnessConfigError(
            f"Command '{cleaned}' is not in the approved introspection allowlist: "
            f"{sorted(ALLOWED_RUNTIME_COMMANDS)}"
        )
    return cleaned


def validate_scenario_config(
    scenario_name: str, config_dict: dict[str, Any]
) -> ScenarioConfig:
    """Validate scenario parameters and enforce hard upper bounds."""
    scenarios = config_dict.get("scenarios", {})
    if scenario_name not in scenarios:
        raise HarnessConfigError(f"Unknown scenario: {scenario_name}. Known: {list(scenarios)}")

    defn = scenarios[scenario_name]
    desc = str(defn.get("description", scenario_name))
    raw_timeout = defn.get("timeout_seconds", 30.0)
    timeout = min(
        float(HARD_LIMITS["max_duration_seconds"]) + 10.0,
        validate_positive_float(raw_timeout, "timeout_seconds"),
    )

    if scenario_name == "baseline":
        reqs = validate_positive_int(defn.get("requests", 10), "requests")
        if reqs > int(HARD_LIMITS["max_requests"]):
            raise HarnessConfigError(f"requests {reqs} exceeds limit {HARD_LIMITS['max_requests']}")
        delay = validate_positive_float(defn.get("delay_seconds", 1.0), "delay_seconds")
        return ScenarioConfig(
            name=scenario_name,
            description=desc,
            timeout_seconds=timeout,
            requests=reqs,
            delay_seconds=delay,
        )

    elif scenario_name == "network_burst":
        duration = validate_positive_float(defn.get("duration_seconds", 10.0), "duration_seconds")
        if duration > float(HARD_LIMITS["max_duration_seconds"]):
            raise HarnessConfigError(
                f"duration {duration}s exceeds limit {HARD_LIMITS['max_duration_seconds']}s"
            )
        max_reqs = validate_positive_int(defn.get("max_requests", 60), "max_requests")
        if max_reqs > int(HARD_LIMITS["max_requests"]):
            raise HarnessConfigError(f"max_requests {max_reqs} exceeds limit {HARD_LIMITS['max_requests']}")
        return ScenarioConfig(
            name=scenario_name,
            description=desc,
            timeout_seconds=timeout,
            duration_seconds=duration,
            max_requests=max_reqs,
        )

    elif scenario_name == "runtime_activity":
        raw_commands = defn.get("commands", ["id", "uname -a", "date -u"])
        if not isinstance(raw_commands, (list, tuple)) or not raw_commands:
            raise HarnessConfigError("runtime_activity scenario requires a list of commands")
        if len(raw_commands) > int(HARD_LIMITS["max_runtime_commands"]):
            raise HarnessConfigError(
                f"command count {len(raw_commands)} exceeds limit {HARD_LIMITS['max_runtime_commands']}"
            )
        validated_cmds = tuple(validate_runtime_command(cmd) for cmd in raw_commands)
        delay = validate_positive_float(defn.get("delay_seconds", 0.5), "delay_seconds")
        return ScenarioConfig(
            name=scenario_name,
            description=desc,
            timeout_seconds=timeout,
            commands=validated_cmds,
            delay_seconds=delay,
        )

    elif scenario_name == "workload_variation":
        duration = validate_positive_float(defn.get("duration_seconds", 10.0), "duration_seconds")
        if duration > float(HARD_LIMITS["max_workload_duration_seconds"]):
            raise HarnessConfigError(
                f"duration {duration}s exceeds limit {HARD_LIMITS['max_workload_duration_seconds']}s"
            )
        return ScenarioConfig(
            name=scenario_name,
            description=desc,
            timeout_seconds=timeout,
            duration_seconds=duration,
        )

    else:
        raise HarnessConfigError(f"Unsupported scenario type: {scenario_name}")


class TelemetryHarness:
    """Coordinates scenario execution, telemetry capture, window alignment, and export."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        config_path: Path | str = DEFAULT_CONFIG_PATH,
        project_root: Path | str = ".",
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.config = config or load_harness_config(self.project_root / config_path)
        self.cluster = self.config.get("cluster", {})
        self.expected_context = self.cluster.get("expected_context", "minikube")
        self.namespace = validate_k8s_name(self.cluster.get("namespace", "default"), "namespace")
        self.target_workload = validate_k8s_name(
            self.cluster.get("target_workload", "deployment/webapp"), "target_workload"
        )
        self.traffic_generator = validate_k8s_name(
            self.cluster.get("traffic_generator", "traffic-generator"), "traffic_generator"
        )
        self.cluster_id = self.cluster.get("cluster_id", "minikube")

        raw_output_dir = self.config.get("output_directory", str(DEFAULT_OUTPUT_DIR))
        from telemetry.security import get_default_allowed_roots
        permitted = list(get_default_allowed_roots())
        if self.project_root not in permitted:
            permitted.append(self.project_root)
        self.output_root = validate_safe_output_path(
            raw_output_dir, base_dir=self.project_root, allowed_roots=permitted
        )

        sources = self.config.get("telemetry_sources", {})
        self.network_source = self.project_root / sources.get(
            "network", "telemetry/data/network/network_events.jsonl"
        )
        self.workload_source = self.project_root / sources.get(
            "workload", "telemetry/data/workload_metrics.csv"
        )
        self.runtime_source = self.project_root / sources.get(
            "runtime", "telemetry/data/runtime/runtime_events.jsonl"
        )
        self.prefer_collector_timestamp = bool(self.config.get("prefer_collector_timestamp", False))

    def check_preflight(self, run_cmd: Callable[..., Any] | None = None) -> None:
        """Validate cluster context before executing any activity."""
        if not kubernetes_context_is_active(self.expected_context, run=run_cmd):
            raise HarnessExecutionError(
                f"Refusing execution: active Kubernetes context is not '{self.expected_context}'."
            )

    def _execute_baseline(self, cfg: ScenarioConfig) -> ActivityResult:
        """Execute spaced HTTP requests from traffic-generator to webapp."""
        requests = cfg.requests or 10
        delay = cfg.delay_seconds or 1.0
        script = (
            f"i=0; while [ $i -lt {requests} ]; do "
            "wget -q -O /dev/null http://webapp; "
            "i=$((i+1)); "
            f"sleep {delay}; "
            "done; "
            "echo $i"
        )
        cmd = [
            "kubectl", "exec", "-n", self.namespace, self.traffic_generator,
            "--", "sh", "-c", script,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=cfg.timeout_seconds)
        if res.returncode != 0:
            return ActivityResult(
                requests_attempted=requests,
                requests_completed=0,
                exit_code=res.returncode,
                errors=[res.stderr.strip() or "traffic-generator command failed"],
            )
        try:
            completed = int(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            completed = requests
        return ActivityResult(
            requests_attempted=requests,
            requests_completed=completed,
            exit_code=0,
        )

    def _execute_network_burst(self, cfg: ScenarioConfig) -> ActivityResult:
        """Execute bounded high-rate HTTP connection burst from traffic-generator."""
        duration = int(cfg.duration_seconds or 10)
        max_req = cfg.max_requests or 60
        script = (
            f"end=$(( $(date +%s) + {duration} )); "
            "c=0; "
            f"while [ \"$(date +%s)\" -lt \"$end\" ] && [ $c -lt {max_req} ]; do "
            "wget -q -O /dev/null http://webapp; "
            "c=$((c+1)); "
            "done; "
            "echo $c"
        )
        cmd = [
            "kubectl", "exec", "-n", self.namespace, self.traffic_generator,
            "--", "sh", "-c", script,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=cfg.timeout_seconds)
        if res.returncode != 0:
            return ActivityResult(
                requests_attempted=max_req,
                requests_completed=0,
                exit_code=res.returncode,
                errors=[res.stderr.strip() or "network burst command failed"],
            )
        try:
            completed = int(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            completed = max_req
        return ActivityResult(
            requests_attempted=max_req,
            requests_completed=completed,
            exit_code=0,
        )

    def _execute_runtime_activity(self, cfg: ScenarioConfig) -> ActivityResult:
        """Execute harmless introspection commands sequentially in webapp container."""
        commands = cfg.commands or ("id", "uname -a", "date -u")
        delay = cfg.delay_seconds or 0.5
        attempted = len(commands)
        completed = 0
        errors: list[str] = []

        for cmd_str in commands:
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

    def _execute_workload_variation(self, cfg: ScenarioConfig) -> ActivityResult:
        """Execute a bounded in-container CPU variation guarded by PID file."""
        duration = cfg.duration_seconds or 10.0
        script = f"echo $$ > {CPU_ATTACK_PID_FILE}; while :; do :; done"
        cmd = ["kubectl", "exec", "-n", self.namespace, self.target_workload, "--", "sh", "-c", script]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(duration)
        if proc.poll() is None:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        cleanup_error = stop_cpu_attack({"namespace": self.namespace, "target_workload": self.target_workload})
        errors = [cleanup_error] if cleanup_error else []
        return ActivityResult(
            commands_attempted=1,
            commands_completed=1 if not errors else 0,
            exit_code=0 if not errors else 1,
            errors=errors,
        )

    def run_activity(self, scenario_cfg: ScenarioConfig) -> ActivityResult:
        """Dispatch scenario activity generation."""
        if scenario_cfg.name == "baseline":
            return self._execute_baseline(scenario_cfg)
        elif scenario_cfg.name == "network_burst":
            return self._execute_network_burst(scenario_cfg)
        elif scenario_cfg.name == "runtime_activity":
            return self._execute_runtime_activity(scenario_cfg)
        elif scenario_cfg.name == "workload_variation":
            return self._execute_workload_variation(scenario_cfg)
        else:
            raise HarnessConfigError(f"Unknown scenario dispatch: {scenario_cfg.name}")

    def correlate_telemetry(
        self,
        start_time_utc: str,
        end_time_utc: str,
        window_seconds: int = WINDOW_SECONDS,
    ) -> tuple[dict[str, ModalityCorrelation], list[dict[str, Any]], dict[str, list[Any]]]:
        """Filter fresh collector records across start/end interval and group into 10s windows.

        Does NOT invent missing data. Explicitly reports whether each modality was captured.
        """
        start_dt = parse_utc_timestamp(start_time_utc)
        end_dt = parse_utc_timestamp(end_time_utc)

        # 1. Ingest and filter raw events strictly by timestamp
        filtered_net: list[NetworkEvent] = []
        if self.network_source.exists():
            for ev in load_network_events(self.network_source, prefer_collector_timestamp=self.prefer_collector_timestamp):
                if start_dt <= ev.timestamp <= end_dt:
                    filtered_net.append(ev)

        filtered_rt: list[RuntimeEvent] = []
        if self.runtime_source.exists():
            for rev in load_runtime_events(self.runtime_source, prefer_collector_timestamp=self.prefer_collector_timestamp):
                if start_dt <= rev.timestamp <= end_dt:
                    filtered_rt.append(rev)

        filtered_wl: list[WorkloadSample] = []
        if self.workload_source.exists():
            for ws in load_workload_samples(self.workload_source):
                if start_dt <= ws.timestamp <= end_dt:
                    filtered_wl.append(ws)

        # 2. Extract features per modality across the activity window
        net_windows = extract_network_features(filtered_net, window_seconds=window_seconds) if filtered_net else []
        wl_windows = extract_workload_features(filtered_wl, window_seconds=window_seconds) if filtered_wl else []

        # Group runtime events by 10s window
        rt_by_window: dict[str, list[RuntimeEvent]] = {}
        for rev in filtered_rt:
            w_key = isoformat_z(window_start(rev.timestamp, window_seconds=window_seconds))
            rt_by_window.setdefault(w_key, []).append(rev)

        # 3. Construct unified 10s observation windows
        all_window_starts = sorted(
            set(w["window_start"] for w in net_windows)
            | set(w["window_start"] for w in wl_windows)
            | set(rt_by_window.keys())
        )

        net_lookup = {w["window_start"]: w for w in net_windows}
        wl_lookup = {w["window_start"]: w for w in wl_windows}

        unified_windows: list[dict[str, Any]] = []
        for w_start in all_window_starts:
            net_feat = net_lookup.get(w_start)
            wl_feat = wl_lookup.get(w_start)
            rt_list = rt_by_window.get(w_start, [])
            rt_feat = extract_runtime_features(rt_list, window_seconds=window_seconds) if rt_list else None

            w_rec: dict[str, Any] = {
                "window_start": w_start,
                "network_available": net_feat is not None,
                "workload_available": wl_feat is not None,
                "runtime_available": bool(rt_list),
            }
            if net_feat:
                w_rec.update(net_feat)
            if wl_feat:
                w_rec.update(wl_feat)
            if rt_feat:
                w_rec.update(rt_feat)
            unified_windows.append(w_rec)

        # 4. Synthesize modality correlations
        correlations: dict[str, ModalityCorrelation] = {}

        # Network correlation
        if filtered_net:
            conn_count = sum(1 for e in filtered_net if e.event_type == "accept")
            correlations["network"] = ModalityCorrelation(
                modality="network",
                captured=True,
                record_count=len(filtered_net),
                details={
                    "event_count": len(filtered_net),
                    "connection_count": conn_count,
                    "connection_rate": round(conn_count / max(1.0, (end_dt - start_dt).total_seconds()), 3),
                    "distinct_source_ports": len({e.source.port for e in filtered_net if e.source.port}),
                },
            )
        else:
            correlations["network"] = ModalityCorrelation(
                modality="network",
                captured=False,
                record_count=0,
                reason="No TCP events captured by network collector during activity interval",
            )

        # Runtime correlation
        if filtered_rt:
            cmds = sorted({(rev.comm or "").strip() for rev in filtered_rt})
            root_count = sum(1 for rev in filtered_rt if rev.uid == 0 or rev.username == "root")
            correlations["runtime"] = ModalityCorrelation(
                modality="runtime",
                captured=True,
                record_count=len(filtered_rt),
                details={
                    "exec_count": len(filtered_rt),
                    "unique_commands": cmds,
                    "root_exec_count": root_count,
                    "exec_rate": round(len(filtered_rt) / max(1.0, (end_dt - start_dt).total_seconds()), 3),
                },
            )
        else:
            correlations["runtime"] = ModalityCorrelation(
                modality="runtime",
                captured=False,
                record_count=0,
                reason="No process exec events captured by runtime collector during activity interval",
            )

        # Workload correlation
        if filtered_wl:
            cpus = [s.cpu_millicores for s in filtered_wl]
            mems = [s.memory_mib for s in filtered_wl]
            correlations["workload"] = ModalityCorrelation(
                modality="workload",
                captured=True,
                record_count=len(filtered_wl),
                details={
                    "sample_count": len(filtered_wl),
                    "cpu_mean_millicores": round(sum(cpus) / len(cpus), 2),
                    "cpu_max_millicores": max(cpus),
                    "cpu_min_millicores": min(cpus),
                    "cpu_delta_millicores": cpus[-1] - cpus[0],
                    "memory_mean_mib": round(sum(mems) / len(mems), 2),
                    "memory_delta_mib": mems[-1] - mems[0],
                },
            )
        else:
            correlations["workload"] = ModalityCorrelation(
                modality="workload",
                captured=False,
                record_count=0,
                reason="No workload samples captured by workload collector during activity interval",
            )

        raw_slices = {
            "network": filtered_net,
            "runtime": filtered_rt,
            "workload": filtered_wl,
        }
        return correlations, unified_windows, raw_slices

    def execute_experiment(
        self,
        scenario_name: str,
        dry_run: bool = False,
        cooldown_seconds: float = 5.0,
    ) -> tuple[Path, ExperimentMetadata, list[dict[str, Any]]]:
        """Execute a complete, bounded experiment and save all artifacts in an isolated directory."""
        scenario_cfg = validate_scenario_config(scenario_name, self.config)
        run_id = experiment_id(scenario_name, cluster_id=self.cluster_id)
        run_dir = validate_safe_output_path(
            self.output_root / run_id, base_dir=self.output_root, allowed_roots=[self.output_root]
        )

        run_dir.mkdir(parents=True, exist_ok=True)
        events_log = run_dir / "events.log"

        def _log(msg: str) -> None:
            ts = utc_now()
            with events_log.open("a", encoding="utf-8") as handle:
                handle.write(f"[{ts}] {msg}\n")

        _log(f"Experiment {run_id} initialized for scenario '{scenario_name}'.")

        if dry_run:
            _log("Dry-run requested: skipping cluster activity generation.")
            meta = ExperimentMetadata(
                experiment_id=run_id,
                scenario=scenario_name,
                status="planned",
                start_time_utc=utc_now(),
                end_time_utc=utc_now(),
                duration_seconds=0.0,
                cluster_id=self.cluster_id,
                namespace=self.namespace,
                target_workload=self.target_workload,
                config=asdict(scenario_cfg),
                activity_result=asdict(ActivityResult()),
                modalities_captured={"network": False, "runtime": False, "workload": False},
                modality_correlations={},
                window_count=0,
                notes="Dry run only; no cluster activity executed.",
            )
            (run_dir / "experiment_metadata.json").write_text(
                json.dumps(meta.to_dict(), indent=2), encoding="utf-8"
            )
            return run_dir, meta, []

        self.check_preflight()
        _log("Preflight passed: active Kubernetes context verified.")

        start_time_utc = utc_now()
        _log(f"Activity started at {start_time_utc}.")

        activity_res = ActivityResult()
        status = "completed"
        try:
            activity_res = self.run_activity(scenario_cfg)
            if activity_res.exit_code != 0:
                status = "failed"
                _log(f"Activity exited with code {activity_res.exit_code}: {activity_res.errors}")
            else:
                _log("Activity execution completed successfully.")
        except KeyboardInterrupt:
            status = "interrupted"
            activity_res.errors.append("Execution interrupted by user/operator.")
            _log("Execution interrupted by KeyboardInterrupt.")
            stop_cpu_attack({"namespace": self.namespace, "target_workload": self.target_workload})
        except Exception as exc:
            status = "failed"
            activity_res.errors.append(str(exc))
            _log(f"Execution failed with exception: {exc}")
            stop_cpu_attack({"namespace": self.namespace, "target_workload": self.target_workload})

        end_time_utc = utc_now()
        _log(f"Activity ended at {end_time_utc}. Waiting {cooldown_seconds}s cooldown.")
        time.sleep(cooldown_seconds)

        observation_end_utc = utc_now()
        duration_s = round(
            (parse_utc_timestamp(end_time_utc) - parse_utc_timestamp(start_time_utc)).total_seconds(), 2
        )

        # Correlate telemetry
        _log("Correlating telemetry from active collector streams.")
        correlations, windows, raw_slices = self.correlate_telemetry(
            start_time_utc=start_time_utc,
            end_time_utc=observation_end_utc,
        )

        modalities_captured = {k: v.captured for k, v in correlations.items()}
        _log(f"Modalities captured: {modalities_captured}, Observation windows: {len(windows)}.")

        metadata = ExperimentMetadata(
            experiment_id=run_id,
            scenario=scenario_name,
            status=status,
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
            duration_seconds=duration_s,
            cluster_id=self.cluster_id,
            namespace=self.namespace,
            target_workload=self.target_workload,
            config=asdict(scenario_cfg),
            activity_result=asdict(activity_res),
            modalities_captured=modalities_captured,
            modality_correlations={k: asdict(v) for k, v in correlations.items()},
            window_count=len(windows),
            notes=f"Scenario {scenario_name} executed with harness.",
        )

        # Write isolated run artifacts
        (run_dir / "experiment_metadata.json").write_text(
            json.dumps(metadata.to_dict(), indent=2), encoding="utf-8"
        )
        (run_dir / "telemetry_summary.json").write_text(
            json.dumps({"windows": windows, "correlations": {k: asdict(v) for k, v in correlations.items()}}, indent=2),
            encoding="utf-8",
        )

        _log("All experiment artifacts saved.")
        return run_dir, metadata, windows


def compare_experiments(
    baseline_summary_path: Path | str,
    activity_summary_path: Path | str,
    output_csv: Path | str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compare baseline versus activity run metrics across network, runtime, and workload."""
    base_p = Path(baseline_summary_path)
    act_p = Path(activity_summary_path)

    # Allow passing either experiment_metadata.json or the run directory
    base_meta_file = base_p / "experiment_metadata.json" if base_p.is_dir() else base_p
    act_meta_file = act_p / "experiment_metadata.json" if act_p.is_dir() else act_p

    base_meta = json.loads(base_meta_file.read_text(encoding="utf-8"))
    act_meta = json.loads(act_meta_file.read_text(encoding="utf-8"))

    base_corr = base_meta.get("modality_correlations", {})
    act_corr = act_meta.get("modality_correlations", {})

    rows: list[dict[str, Any]] = []

    def _add_metric(modality: str, metric_name: str, base_val: float | int, act_val: float | int, unit: str = "") -> None:
        delta = round(act_val - base_val, 3)
        pct = round((delta / base_val * 100.0), 1) if base_val > 0 else (0.0 if delta == 0 else None)
        rows.append({
            "modality": modality,
            "metric": metric_name,
            "baseline_value": base_val,
            "activity_value": act_val,
            "delta": delta,
            "percent_change": f"{pct}%" if pct is not None else "N/A",
            "unit": unit,
        })

    # Network comparison
    b_net = base_corr.get("network", {}).get("details", {})
    a_net = act_corr.get("network", {}).get("details", {})
    _add_metric("network", "connection_count", b_net.get("connection_count", 0), a_net.get("connection_count", 0), "conn")
    _add_metric("network", "connection_rate", b_net.get("connection_rate", 0.0), a_net.get("connection_rate", 0.0), "conn/s")
    _add_metric("network", "event_count", b_net.get("event_count", 0), a_net.get("event_count", 0), "events")

    # Runtime comparison
    b_rt = base_corr.get("runtime", {}).get("details", {})
    a_rt = act_corr.get("runtime", {}).get("details", {})
    _add_metric("runtime", "exec_count", b_rt.get("exec_count", 0), a_rt.get("exec_count", 0), "execs")
    _add_metric("runtime", "exec_rate", b_rt.get("exec_rate", 0.0), a_rt.get("exec_rate", 0.0), "exec/s")
    _add_metric("runtime", "root_exec_count", b_rt.get("root_exec_count", 0), a_rt.get("root_exec_count", 0), "execs")

    # Workload comparison
    b_wl = base_corr.get("workload", {}).get("details", {})
    a_wl = act_corr.get("workload", {}).get("details", {})
    _add_metric("workload", "cpu_mean", b_wl.get("cpu_mean_millicores", 0.0), a_wl.get("cpu_mean_millicores", 0.0), "m")
    _add_metric("workload", "cpu_max", b_wl.get("cpu_max_millicores", 0.0), a_wl.get("cpu_max_millicores", 0.0), "m")
    _add_metric("workload", "memory_mean", b_wl.get("memory_mean_mib", 0.0), a_wl.get("memory_mean_mib", 0.0), "MiB")

    comparison_dict = {
        "baseline_experiment_id": base_meta.get("experiment_id"),
        "baseline_scenario": base_meta.get("scenario"),
        "activity_experiment_id": act_meta.get("experiment_id"),
        "activity_scenario": act_meta.get("scenario"),
        "metrics": rows,
    }

    if output_csv:
        csv_path = Path(output_csv)
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["modality", "metric", "baseline_value", "activity_value", "delta", "percent_change", "unit"],
            )
            writer.writeheader()
            writer.writerows(rows)

    return comparison_dict, rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=("baseline", "network_burst", "runtime_activity", "workload_variation"),
        help="Target scenario to execute.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to YAML harness configuration.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate parameters and create plan metadata without executing commands.",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("BASELINE_DIR", "ACTIVITY_DIR"),
        help="Compare an activity run against a baseline run.",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="Path to export comparison CSV table.",
    )
    args = parser.parse_args()

    if args.compare:
        base_dir, act_dir = args.compare
        out_csv = args.output_csv or (Path(act_dir) / "comparison.csv")
        cmp_dict, _ = compare_experiments(base_dir, act_dir, output_csv=out_csv)
        print(json.dumps(cmp_dict, indent=2))
        print(f"\nComparison exported to: {out_csv}")
        return

    if not args.scenario:
        parser.error("Either --scenario or --compare is required.")

    harness = TelemetryHarness(config_path=args.config)
    run_dir, metadata, _ = harness.execute_experiment(args.scenario, dry_run=args.dry_run)
    print(json.dumps({
        "experiment_id": metadata.experiment_id,
        "scenario": metadata.scenario,
        "status": metadata.status,
        "duration_seconds": metadata.duration_seconds,
        "modalities_captured": metadata.modalities_captured,
        "run_directory": str(run_dir),
    }, indent=2))


if __name__ == "__main__":
    main()
