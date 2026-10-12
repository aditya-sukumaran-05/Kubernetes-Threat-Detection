"""Explicit scenario metadata and metadata-derived label assignment."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from telemetry.schemas import SchemaError, parse_utc_timestamp


@dataclass(frozen=True)
class LabelInterval:
    start: object
    end: object
    label: str
    attack_type: str

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "LabelInterval":
        start, end = parse_utc_timestamp(raw["start"]), parse_utc_timestamp(raw["end"])
        if end <= start:
            raise SchemaError("label interval end must be after start")
        label, attack_type = raw.get("label"), raw.get("attack_type")
        if label not in {"normal", "attack"} or not isinstance(attack_type, str):
            raise SchemaError("label interval needs label normal/attack and attack_type")
        return cls(start, end, label, attack_type)


@dataclass(frozen=True)
class CaptureMetadata:
    capture_id: str
    source: str
    path: str
    session_id: str
    description: str
    label_intervals: tuple[LabelInterval, ...]
    scenario: str = ""
    cluster_id: str = "minikube"


def load_capture_metadata(path: Path) -> list[CaptureMetadata]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    captures = raw.get("captures") if isinstance(raw, dict) else None
    if not isinstance(captures, list):
        raise SchemaError("metadata must contain a captures array")
    result: list[CaptureMetadata] = []
    ids: set[str] = set()
    for item in captures:
        if not isinstance(item, dict):
            raise SchemaError("capture metadata entry must be an object")
        capture_id = item.get("id")
        if not isinstance(capture_id, str) or not capture_id or capture_id in ids:
            raise SchemaError("capture id must be unique and non-empty")
        ids.add(capture_id)
        source = item.get("source")
        if source not in {"network", "workload"}:
            raise SchemaError(f"{capture_id}: source must be network or workload")
        intervals = tuple(LabelInterval.from_raw(interval) for interval in item.get("label_intervals", []))
        for previous, current in zip(intervals, intervals[1:]):
            if current.start < previous.end:
                raise SchemaError(f"{capture_id}: label intervals overlap")
        result.append(CaptureMetadata(
            capture_id, source, item["path"], item["session_id"],
            item.get("description", ""), intervals, item.get("scenario", capture_id),
            cluster_id=item.get("cluster_id", "minikube"),
        ))
    return result


def assign_labels(rows: list[dict[str, object]], capture: CaptureMetadata) -> list[dict[str, object]]:
    """Label each window only from explicitly recorded metadata intervals.

    Windows lacking a recorded interval are retained as ``unknown`` rather than
    being guessed from raw collector labels or feature values.
    """
    labeled: list[dict[str, object]] = []
    for row in rows:
        timestamp = parse_utc_timestamp(str(row["window_start"]))
        interval = next((item for item in capture.label_intervals if item.start <= timestamp < item.end), None)
        copy = dict(row)
        copy.update({
            "capture_id": capture.capture_id,
            "session_id": capture.session_id,
            "experiment_id": capture.session_id,
            "scenario": capture.scenario,
            "telemetry_source": capture.source,
            "cluster_id": getattr(capture, "cluster_id", "minikube"),
            "label": interval.label if interval else "unknown",
            "attack_type": interval.attack_type if interval else "unknown",
        })
        labeled.append(copy)
    return labeled


def _run_intervals(metadata: dict[str, Any], source: str) -> tuple[LabelInterval, ...]:
    """Build labels solely from the runner's recorded timestamps."""
    start, end = metadata["experiment_start_time_utc"], metadata["experiment_end_time_utc"]
    scenario = metadata["scenario"]
    attack_start = attack_end = None
    if scenario == "network_attack" and source == "network":
        attack_start, attack_end = metadata.get("network_attack_start_time_utc"), metadata.get("network_attack_end_time_utc")
    elif scenario == "workload_attack" and source == "workload":
        attack_start, attack_end = metadata.get("workload_attack_start_time_utc"), metadata.get("workload_attack_end_time_utc")
    elif scenario == "fusion_attack":
        attack_start, attack_end = metadata.get("overlap_start_time_utc"), metadata.get("overlap_end_time_utc")
    if not attack_start or not attack_end:
        return (LabelInterval.from_raw({"start": start, "end": end, "label": "normal", "attack_type": "normal"}),)
    pieces = []
    if start < attack_start:
        pieces.append({"start": start, "end": attack_start, "label": "normal", "attack_type": "normal"})
    pieces.append({"start": attack_start, "end": attack_end, "label": "attack", "attack_type": scenario})
    if attack_end < end:
        pieces.append({"start": attack_end, "end": end, "label": "normal", "attack_type": "normal"})
    return tuple(LabelInterval.from_raw(item) for item in pieces)


CLEAN_CAMPAIGN_CUTOFF = "2026-09-20T09:39:50Z"


def load_run_capture_metadata(
    runs_dir: Path,
    min_start_time_utc: str | None = CLEAN_CAMPAIGN_CUTOFF,
    cluster_id: str | None = None,
) -> list[CaptureMetadata]:
    """Discover only validated clean experiment runs; historical captures stay separate."""
    project_root = runs_dir.resolve().parents[1] if len(runs_dir.resolve().parents) >= 2 else Path(".").resolve()
    captures: list[CaptureMetadata] = []
    cutoff = parse_utc_timestamp(min_start_time_utc) if min_start_time_utc else None
    metadata_paths = sorted({p for p in runs_dir.glob("**/metadata.json") if p.is_file()}) if runs_dir.exists() else []
    for metadata_path in metadata_paths:
        raw = json.loads(metadata_path.read_text(encoding="utf-8"))
        if raw.get("status") != "validated" or not raw.get("validation", {}).get("valid"):
            continue
        run_cluster = str(raw.get("cluster_id") or "minikube")
        if cluster_id is not None and run_cluster != cluster_id:
            continue
        start_time_str = raw.get("experiment_start_time_utc")
        if not start_time_str:
            continue
        if cutoff and parse_utc_timestamp(start_time_str) < cutoff:
            continue
        for source, filename in raw.get("telemetry", {}).items():
            if source not in {"network", "workload"}:
                continue
            capture_path = metadata_path.parent / filename
            if not capture_path.exists():
                raise SchemaError(f"validated run references missing {source} capture: {capture_path}")
            try:
                rel_path = str(capture_path.resolve().relative_to(project_root))
            except ValueError:
                rel_path = str(capture_path)
            captures.append(CaptureMetadata(
                capture_id=f"{raw['experiment_id']}_{source}", source=source,
                path=rel_path, session_id=raw["experiment_id"],
                description=raw.get("notes", ""), label_intervals=_run_intervals(raw, source),
                scenario=raw["scenario"], cluster_id=run_cluster,
            ))
    return captures
