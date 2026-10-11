"""Plan or explicitly execute one controlled Minikube telemetry experiment."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from dataclasses import dataclass

from experiments.orchestration import (
    RunMetadata,
    attack_window_report,
    experiment_id,
    mark_interrupted,
    minikube_context_is_active,
    save_metadata,
    utc_now,
    validate_capture_files,
    write_metadata,
)
from telemetry.security import (
    validate_gadget_version,
    validate_k8s_name,
    validate_k8s_selector,
    validate_positive_float,
    validate_positive_int,
    validate_safe_output_path,
)

CPU_ATTACK_PID_FILE = "/tmp/kubernetes-threat-detection-cpu-attack.pid"


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def activity_command(scenario: str, config: dict[str, Any], cluster: dict[str, Any]) -> list[str] | None:
    """Return a local-cluster-only traffic command; no command targets external hosts."""
    definition = config["scenarios"][scenario]
    namespace = validate_k8s_name(cluster["namespace"], "namespace")
    if scenario in {"network_normal", "workload_normal", "workload_attack", "fusion_normal"}:
        requests = validate_positive_int(definition["network_requests"], "network_requests")
        delay = validate_positive_float(definition["request_delay_seconds"], "request_delay_seconds", allow_zero=True)
        script = f"i=0; while [ $i -lt {requests} ]; do wget -q -O /dev/null http://webapp; i=$((i+1)); sleep {delay}; done"
    elif scenario in {"network_attack", "fusion_attack"}:
        duration = validate_positive_int(definition["network_duration_seconds"], "network_duration_seconds")
        script = f"end=$(( $(date +%s) + {duration} )); while [ \"$(date +%s)\" -lt \"$end\" ]; do wget -q -O /dev/null http://webapp; done"
    else:
        return None
    return ["kubectl", "exec", "-n", namespace, "traffic-generator", "--", "sh", "-c", script]


def cpu_attack_command(cluster: dict[str, Any]) -> list[str]:
    """Start a marked local CPU loop that can be safely cleaned up in-pod."""
    namespace = validate_k8s_name(cluster["namespace"], "namespace")
    target_workload = validate_k8s_name(cluster["target_workload"], "target_workload")
    script = f"echo $$ > {CPU_ATTACK_PID_FILE}; while :; do :; done"
    return ["kubectl", "exec", "-n", namespace, target_workload, "--", "sh", "-c", script]


def stop_cpu_attack(cluster: dict[str, Any]) -> str | None:
    """Terminate only the runner's recorded CPU loop, even if kubectl disconnects.

    Terminating a local ``kubectl exec`` process alone can leave its remote shell
    running.  The PID file and command check prevent cleanup from killing an
    unrelated process in the target workload.
    """
    namespace = validate_k8s_name(cluster["namespace"], "namespace")
    target_workload = validate_k8s_name(cluster["target_workload"], "target_workload")
    script = (
        f"pid_file={CPU_ATTACK_PID_FILE}; "
        "[ -f \"$pid_file\" ] || exit 0; "
        "pid=$(cat \"$pid_file\"); "
        "[ -n \"$pid\" ] || { rm -f \"$pid_file\"; exit 0; }; "
        "cmd=$(tr '\\000' ' ' < \"/proc/$pid/cmdline\" 2>/dev/null || true); "
        "case \"$cmd\" in *'while :; do :; done'*) kill \"$pid\"; for _ in 1 2 3 4 5; do [ -d \"/proc/$pid\" ] || break; sleep 0.1; done; [ -d \"/proc/$pid\" ] && kill -9 \"$pid\" 2>/dev/null || true ;; "
        "*) [ -n \"$pid\" ] && [ -d \"/proc/$pid\" ] && { echo \"unexpected CPU attack process: $pid\" >&2; exit 1; } ;; esac; "
        "rm -f \"$pid_file\""
    )
    result = subprocess.run(
        ["kubectl", "exec", "-n", namespace, target_workload, "--", "sh", "-c", script],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip() or f"exit code {result.returncode}"
        return f"failed to clean up controlled CPU workload: {detail}"
    return None


def stop(process: subprocess.Popen[str] | None) -> None:
    if process and process.poll() is None:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
        else:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@dataclass(frozen=True)
class ValidatedExperimentPlan:
    """Preflight-validated experiment configuration and execution parameters."""

    canonical_run_dir: Path
    scenario: str
    label: str
    cluster: dict[str, Any]
    definition: dict[str, Any]
    collectors: dict[str, Any]
    workload_interval_seconds: float
    warmup_seconds: float
    attack_seconds: float
    cooldown_seconds: float


def validate_experiment_preflight(
    config: dict[str, Any],
    scenario: str,
    project_root: Path | str,
    execute: bool = False,
) -> ValidatedExperimentPlan:
    """Perform strict preflight validation of all experiment configuration before file or process creation.

    Validates:
    - Top-level config sections ('cluster', 'output_directory', 'collectors', 'scenarios').
    - Target scenario existence and completeness.
    - Kubernetes namespace, workload, and context identifiers (preventing flag and command injection).
    - Output directory boundaries and containment within project_root.
    - Numerical parameters (warmup, cooldown, attack duration, collector intervals, requests, delays),
      rejecting NaN, Inf, negative numbers, and booleans.
    - Command builders (ensures activity_command and cpu_attack_command can construct without error).
    """
    if not isinstance(config, dict):
        raise TypeError(f"config must be a dictionary, got {type(config).__name__}")

    for section in ("cluster", "output_directory", "collectors", "scenarios"):
        if section not in config:
            raise KeyError(f"Missing required configuration section: {section!r}")

    cluster = config["cluster"]
    if not isinstance(cluster, dict):
        raise TypeError("cluster section must be a dictionary")

    for field in ("namespace", "target_workload", "expected_context"):
        if field not in cluster:
            raise KeyError(f"Missing required cluster field: {field!r}")

    validate_k8s_name(cluster["namespace"], "namespace")
    validate_k8s_name(cluster["target_workload"], "target_workload")
    validate_k8s_name(cluster["expected_context"], "expected_context")
    if "target_label" in cluster:
        validate_k8s_selector(cluster["target_label"], "target_label")

    collectors = config["collectors"]
    if not isinstance(collectors, dict):
        raise TypeError("collectors section must be a dictionary")

    if "workload_interval_seconds" not in collectors:
        raise KeyError("Missing required collectors field: 'workload_interval_seconds'")

    workload_interval = validate_positive_float(
        collectors["workload_interval_seconds"], "workload_interval_seconds", allow_zero=False
    )
    if "network_gadget_version" in collectors:
        validate_gadget_version(collectors["network_gadget_version"])

    scenarios = config["scenarios"]
    if not isinstance(scenarios, dict):
        raise TypeError("scenarios section must be a dictionary")

    if scenario not in scenarios:
        raise ValueError(f"unknown scenario: {scenario}")

    definition = scenarios[scenario]
    if not isinstance(definition, dict):
        raise TypeError(f"Scenario definition for '{scenario}' must be a dictionary")

    for req_field in ("label", "network_activity", "workload_activity", "warmup_seconds", "cooldown_seconds"):
        if req_field not in definition:
            raise KeyError(f"Missing required scenario field in '{scenario}': {req_field!r}")

    label = definition["label"]
    if not isinstance(label, str) or not label.strip():
        raise ValueError(f"label in scenario '{scenario}' must be a non-empty string")

    warmup_seconds = validate_positive_float(
        definition["warmup_seconds"], "warmup_seconds", allow_zero=True
    )
    cooldown_seconds = validate_positive_float(
        definition["cooldown_seconds"], "cooldown_seconds", allow_zero=True
    )

    attack_seconds = 0.0
    if "attack_seconds" in definition:
        attack_seconds = validate_positive_float(
            definition["attack_seconds"], "attack_seconds", allow_zero=False
        )
    elif scenario in {"workload_attack", "fusion_attack"}:
        raise KeyError(f"Missing required field 'attack_seconds' in attack scenario '{scenario}'")

    if "activity_seconds" in definition:
        validate_positive_float(
            definition["activity_seconds"], "activity_seconds", allow_zero=False
        )

    # Validate scenario-specific network parameters and command construction
    if scenario in {"network_normal", "workload_normal", "workload_attack", "fusion_normal"}:
        for net_field in ("network_requests", "request_delay_seconds"):
            if net_field not in definition:
                raise KeyError(f"Missing required field {net_field!r} in scenario '{scenario}'")
        validate_positive_int(definition["network_requests"], "network_requests", allow_zero=False)
        validate_positive_float(definition["request_delay_seconds"], "request_delay_seconds", allow_zero=True)
    elif scenario in {"network_attack", "fusion_attack"}:
        if "network_duration_seconds" not in definition:
            raise KeyError(f"Missing required field 'network_duration_seconds' in scenario '{scenario}'")
        validate_positive_int(definition["network_duration_seconds"], "network_duration_seconds", allow_zero=False)
        if "network_requests" in definition:
            validate_positive_int(definition["network_requests"], "network_requests", allow_zero=False)

    activity_command(scenario, config, cluster)
    if scenario in {"workload_attack", "fusion_attack"}:
        cpu_attack_command(cluster)

    # Enforce strict output directory containment within project_root
    raw_output_dir = config["output_directory"]
    if not raw_output_dir or (isinstance(raw_output_dir, str) and not raw_output_dir.strip()):
        raise ValueError("output_directory cannot be empty")

    resolved_root = Path(project_root).resolve()
    output_root = validate_safe_output_path(
        raw_output_dir, base_dir=resolved_root, allowed_roots=[resolved_root]
    )

    run_id = experiment_id(scenario)
    canonical_run_dir = validate_safe_output_path(
        output_root / run_id, base_dir=output_root, allowed_roots=[output_root]
    )

    return ValidatedExperimentPlan(
        canonical_run_dir=canonical_run_dir,
        scenario=scenario,
        label=label,
        cluster=cluster,
        definition=definition,
        collectors=collectors,
        workload_interval_seconds=workload_interval,
        warmup_seconds=warmup_seconds,
        attack_seconds=attack_seconds,
        cooldown_seconds=cooldown_seconds,
    )


def run_scenario(config: dict[str, Any], scenario: str, project_root: Path, execute: bool) -> tuple[Path, RunMetadata]:
    # 1. Strict preflight validation runs BEFORE any directory creation, file write, or subprocess
    plan = validate_experiment_preflight(config, scenario, project_root, execute=execute)
    run_dir = plan.canonical_run_dir
    cluster = plan.cluster
    definition = plan.definition

    # 2. Construct RunMetadata using preflight-validated values
    metadata = RunMetadata(
        experiment_id=run_dir.name,
        scenario=scenario,
        label=plan.label,
        namespace=cluster["namespace"],
        target_workload=cluster["target_workload"],
        collector_config=plan.collectors,
        network_activity=definition["network_activity"],
        workload_activity=definition["workload_activity"],
        notes="Planned by the reproducible experiment runner.",
    )
    metadata.record("run directory created")
    write_metadata(run_dir, metadata)
    if not execute:
        metadata.status = "planned"
        metadata.record("dry run only; pass --execute to start controlled local activity")
        save_metadata(run_dir, metadata)
        return run_dir, metadata

    # 3. Minikube context check for execution mode
    if not minikube_context_is_active(cluster["expected_context"]):
        metadata.status = "refused_non_minikube_context"
        metadata.record("refused: active Kubernetes context did not equal configured Minikube context")
        save_metadata(run_dir, metadata)
        raise RuntimeError("refusing experiment: active Kubernetes context is not Minikube")

    network_collector = workload_collector = attack_network = attack_workload = None
    cpu_cleanup_error: str | None = None
    events_log = (run_dir / "collector_output.log").open("w", encoding="utf-8")
    try:
        metadata.status = "running"
        metadata.experiment_start_time_utc = metadata.record("experiment started")
        network_collector = subprocess.Popen(
            [sys.executable, "telemetry/network_collector.py", "--output", str(run_dir / "network.jsonl")],
            cwd=project_root, stdout=events_log, stderr=subprocess.STDOUT, text=True,
        )
        workload_collector = subprocess.Popen(
            [
                sys.executable,
                "telemetry/workload_collector.py",
                "--output",
                str(run_dir / "workload.csv"),
                "--interval",
                str(plan.workload_interval_seconds),
            ],
            cwd=project_root, stdout=events_log, stderr=subprocess.STDOUT, text=True,
        )
        time.sleep(2)
        if network_collector.poll() is not None or workload_collector.poll() is not None:
            raise RuntimeError("a collector exited before confirmation")
        metadata.record("network and workload collectors confirmed running")
        save_metadata(run_dir, metadata)
        time.sleep(plan.warmup_seconds)

        command = activity_command(scenario, config, cluster)
        if scenario in {"network_attack", "fusion_attack"}:
            metadata.network_attack_start_time_utc = utc_now()
            metadata.attack_start_time_utc = metadata.network_attack_start_time_utc
            metadata.record("network burst started", metadata.network_attack_start_time_utc)
        if scenario in {"workload_attack", "fusion_attack"}:
            stop_cpu_attack(cluster)
            metadata.workload_attack_start_time_utc = utc_now()
            metadata.attack_start_time_utc = metadata.attack_start_time_utc or metadata.workload_attack_start_time_utc
            metadata.record("controlled CPU workload started", metadata.workload_attack_start_time_utc)
            attack_workload = subprocess.Popen(cpu_attack_command(cluster), cwd=project_root, stdout=events_log, stderr=subprocess.STDOUT, text=True)
        if command:
            attack_network = subprocess.Popen(command, cwd=project_root, stdout=events_log, stderr=subprocess.STDOUT, text=True)
            if scenario not in {"network_attack", "fusion_attack"}:
                metadata.record("normal traffic started")
        if attack_workload:
            time.sleep(plan.attack_seconds)
            stop(attack_workload)
            cpu_cleanup_error = stop_cpu_attack(cluster)
            metadata.workload_attack_end_time_utc = utc_now()
            metadata.record("controlled CPU workload ended", metadata.workload_attack_end_time_utc)
        if attack_network:
            attack_network.wait()
            if scenario in {"network_attack", "fusion_attack"}:
                metadata.network_attack_end_time_utc = utc_now()
                metadata.record("network burst ended", metadata.network_attack_end_time_utc)
        metadata.attack_end_time_utc = max(filter(None, [metadata.network_attack_end_time_utc, metadata.workload_attack_end_time_utc]), default=None)
        time.sleep(plan.cooldown_seconds)
        metadata.experiment_end_time_utc = metadata.record("experiment capture ended")
        metadata.status = "completed"
    except KeyboardInterrupt:
        mark_interrupted(metadata)
    finally:
        stop(attack_network)
        stop(attack_workload)
        if scenario in {"workload_attack", "fusion_attack"}:
            final_cleanup_error = stop_cpu_attack(cluster)
            cpu_cleanup_error = cpu_cleanup_error or final_cleanup_error
        stop(network_collector)
        stop(workload_collector)
        events_log.close()
        metadata.refresh_overlap()
        errors = validate_capture_files(run_dir, metadata.as_dict())
        if cpu_cleanup_error:
            errors.append(cpu_cleanup_error)
        metadata.validation = {"valid": not errors, "errors": errors, "attack_window_report": attack_window_report(metadata.as_dict())}
        if metadata.status == "completed" and not errors:
            metadata.status = "validated"
        save_metadata(run_dir, metadata)
    return run_dir, metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, choices=("network_normal", "network_attack", "workload_normal", "workload_attack", "fusion_normal", "fusion_attack"))
    parser.add_argument("--config", type=Path, default=Path("configs/experiments.yaml"))
    parser.add_argument("--execute", action="store_true", help="Explicitly run controlled activity against local Minikube.")
    args = parser.parse_args()
    root = args.config.resolve().parents[1]
    run_dir, metadata = run_scenario(load_config(args.config), args.scenario, root, args.execute)
    print(json.dumps({"run_directory": str(run_dir), "status": metadata.status, "experiment_id": metadata.experiment_id}, indent=2))


if __name__ == "__main__":
    main()
