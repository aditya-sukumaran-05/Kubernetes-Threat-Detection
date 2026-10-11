"""Safe, metadata-first orchestration primitives for local Minikube experiments."""

from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from telemetry.schemas import parse_utc_timestamp
from telemetry.windowing import WINDOW_SECONDS, window_end, window_start


MIN_FUSION_OVERLAP_WINDOWS = 6


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def experiment_id(scenario: str, now: datetime | None = None, cluster_id: str | None = None) -> str:
    timestamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    safe_scenario = "".join(char if char.isalnum() or char == "_" else "_" for char in scenario)
    if cluster_id and cluster_id != "minikube":
        safe_cluster = "".join(char if char.isalnum() or char == "_" else "_" for char in cluster_id)
        return f"{timestamp}_{safe_cluster}_{safe_scenario}_{uuid.uuid4().hex[:8]}"
    return f"{timestamp}_{safe_scenario}_{uuid.uuid4().hex[:8]}"


def kubernetes_context_is_active(expected_context: str, run: Callable[..., Any] | None = None) -> bool:
    """Check the exact configured Kubernetes context before an attack is run."""
    runner = run or subprocess.run
    result = runner(["kubectl", "config", "current-context"], capture_output=True, text=True, check=False)
    return result.returncode == 0 and result.stdout.strip() == expected_context


def minikube_context_is_active(expected_context: str = "minikube", run: Callable[..., Any] | None = None) -> bool:
    """Check the exact configured Kubernetes context before an attack is run (backward-compatible alias)."""
    return kubernetes_context_is_active(expected_context=expected_context, run=run)


def overlap_interval(
    network_start: str | None, network_end: str | None, workload_start: str | None, workload_end: str | None
) -> tuple[str | None, str | None]:
    if not all((network_start, network_end, workload_start, workload_end)):
        return None, None
    start = max(network_start, workload_start)
    end = min(network_end, workload_end)
    return (start, end) if start < end else (None, None)


def complete_window_count(start: str | None, end: str | None, window_seconds: int = WINDOW_SECONDS) -> int:
    """Count full UTC epoch-aligned windows contained by an observed interval."""
    if not start or not end:
        return 0
    start_time, end_time = parse_utc_timestamp(start), parse_utc_timestamp(end)
    if end_time <= start_time:
        return 0
    candidate = window_start(start_time, window_seconds)
    if candidate < start_time:
        candidate = window_end(candidate, window_seconds)
    count = 0
    while window_end(candidate, window_seconds) <= end_time:
        count += 1
        candidate = window_end(candidate, window_seconds)
    return count


def attack_window_report(metadata: dict[str, Any]) -> dict[str, Any]:
    """Report actual attack and fusion-overlap coverage without inferring labels."""
    network_start, network_end = metadata.get("network_attack_start_time_utc"), metadata.get("network_attack_end_time_utc")
    workload_start, workload_end = metadata.get("workload_attack_start_time_utc"), metadata.get("workload_attack_end_time_utc")
    overlap_start, overlap_end = metadata.get("overlap_start_time_utc"), metadata.get("overlap_end_time_utc")
    def interval(start: str | None, end: str | None) -> dict[str, Any]:
        duration = None
        if start and end:
            duration = (parse_utc_timestamp(end) - parse_utc_timestamp(start)).total_seconds()
        return {"start_time_utc": start, "end_time_utc": end, "duration_seconds": duration, "complete_10_second_windows": complete_window_count(start, end)}
    return {"network_attack": interval(network_start, network_end), "workload_attack": interval(workload_start, workload_end), "fusion_overlap": interval(overlap_start, overlap_end)}


@dataclass
class RunMetadata:
    experiment_id: str
    scenario: str
    label: str
    namespace: str
    target_workload: str
    collector_config: dict[str, Any]
    network_activity: str
    workload_activity: str
    notes: str = ""
    status: str = "created"
    experiment_start_time_utc: str | None = None
    experiment_end_time_utc: str | None = None
    attack_start_time_utc: str | None = None
    attack_end_time_utc: str | None = None
    network_attack_start_time_utc: str | None = None
    network_attack_end_time_utc: str | None = None
    workload_attack_start_time_utc: str | None = None
    workload_attack_end_time_utc: str | None = None
    overlap_start_time_utc: str | None = None
    overlap_end_time_utc: str | None = None
    telemetry: dict[str, str] = field(default_factory=lambda: {"network": "network.jsonl", "workload": "workload.csv"})
    events: list[dict[str, str]] = field(default_factory=list)
    validation: dict[str, Any] = field(default_factory=dict)
    cluster_id: str = "minikube"
    cluster_metadata: dict[str, Any] = field(default_factory=dict)

    def record(self, event: str, timestamp: str | None = None) -> str:
        recorded = timestamp or utc_now()
        self.events.append({"timestamp_utc": recorded, "event": event})
        return recorded

    def refresh_overlap(self) -> None:
        self.overlap_start_time_utc, self.overlap_end_time_utc = overlap_interval(
            self.network_attack_start_time_utc,
            self.network_attack_end_time_utc,
            self.workload_attack_start_time_utc,
            self.workload_attack_end_time_utc,
        )

    def as_dict(self) -> dict[str, Any]:
        self.refresh_overlap()
        return self.__dict__.copy()


def write_metadata(run_dir: Path, metadata: RunMetadata) -> None:
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "metadata.json").write_text(json.dumps(metadata.as_dict(), indent=2), encoding="utf-8")
    (run_dir / "events.log").write_text("", encoding="utf-8")


def save_metadata(run_dir: Path, metadata: RunMetadata) -> None:
    (run_dir / "metadata.json").write_text(json.dumps(metadata.as_dict(), indent=2), encoding="utf-8")
    with (run_dir / "events.log").open("a", encoding="utf-8") as handle:
        for entry in metadata.events:
            handle.write(f"{entry['timestamp_utc']} {entry['event']}\n")
    metadata.events.clear()


def mark_interrupted(metadata: RunMetadata) -> None:
    """Record an interruption while preserving any partial capture files."""
    metadata.status = "interrupted"
    metadata.experiment_end_time_utc = metadata.record("experiment interrupted by operator")


def validate_run_metadata(metadata: dict[str, Any]) -> list[str]:
    """Return explicit validation failures; an empty list means valid intervals."""
    errors: list[str] = []
    required = ("experiment_id", "scenario", "label", "experiment_start_time_utc", "experiment_end_time_utc")
    errors.extend(f"missing {field}" for field in required if not metadata.get(field))
    start, end = metadata.get("experiment_start_time_utc"), metadata.get("experiment_end_time_utc")
    if start and end and start >= end:
        errors.append("experiment start must precede experiment end")
    attack_start, attack_end = metadata.get("attack_start_time_utc"), metadata.get("attack_end_time_utc")
    if (attack_start is None) != (attack_end is None):
        errors.append("attack interval must have both start and end")
    if attack_start and attack_end and attack_start >= attack_end:
        errors.append("attack start must precede attack end")
    for prefix in ("network_attack", "workload_attack"):
        attack_start, attack_end = metadata.get(f"{prefix}_start_time_utc"), metadata.get(f"{prefix}_end_time_utc")
        if (attack_start is None) != (attack_end is None):
            errors.append(f"{prefix} interval must have both start and end")
        if attack_start and attack_end and attack_start >= attack_end:
            errors.append(f"{prefix} start must precede end")
    if metadata.get("scenario") == "fusion_attack":
        overlap_start, overlap_end = metadata.get("overlap_start_time_utc"), metadata.get("overlap_end_time_utc")
        if not overlap_start or not overlap_end or overlap_start >= overlap_end:
            errors.append("fusion attack requires non-zero network/workload overlap")
        for attack_start in (metadata.get("network_attack_start_time_utc"), metadata.get("workload_attack_start_time_utc")):
            if attack_start and overlap_end and attack_start >= overlap_end:
                errors.append("each fusion attack must start before overlap ends")
        if complete_window_count(overlap_start, overlap_end) < MIN_FUSION_OVERLAP_WINDOWS:
            errors.append(f"fusion attack requires at least {MIN_FUSION_OVERLAP_WINDOWS} complete 10-second overlap windows")
    return errors


def validate_capture_files(run_dir: Path, metadata: dict[str, Any]) -> list[str]:
    errors = validate_run_metadata(metadata)
    telemetry = metadata.get("telemetry", {})
    for modality in ("network", "workload"):
        filename = telemetry.get(modality)
        path = run_dir / filename if filename else None
        if not path or not path.exists() or path.stat().st_size == 0:
            errors.append(f"missing or empty {modality} capture")
            continue
        try:
            if modality == "network":
                from telemetry.schemas import load_network_events
                if not load_network_events(path):
                    errors.append("network capture contains no events")
            else:
                from telemetry.schemas import load_workload_samples
                if not load_workload_samples(path):
                    errors.append("workload capture contains no samples")
        except Exception as exc:
            errors.append(f"invalid {modality} capture: {exc}")
    return errors
