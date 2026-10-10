"""Canonical, validated representations for the project's raw telemetry."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


__all__ = [
    "Endpoint",
    "NetworkEvent",
    "RuntimeEvent",
    "SchemaError",
    "WorkloadSample",
    "ensure_sorted",
    "load_network_events",
    "load_runtime_events",
    "load_workload_samples",
    "parse_utc_timestamp",
]


class SchemaError(ValueError):
    """Raised when a raw telemetry record cannot be represented faithfully."""


def parse_utc_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to an aware UTC datetime.

    Naive timestamps are rejected instead of assuming a local timezone, which
    prevents silent time-alignment errors.
    """
    if not isinstance(value, str) or not value:
        raise SchemaError("timestamp must be a non-empty ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaError(f"invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SchemaError(f"timestamp must include a timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Endpoint:
    address: str | None
    port: int | None

    @classmethod
    def from_raw(cls, value: Any, field_name: str) -> "Endpoint":
        if not isinstance(value, dict):
            raise SchemaError(f"{field_name} must be an object")
        address = value.get("addr")
        port = value.get("port")
        if address is not None and not isinstance(address, str):
            raise SchemaError(f"{field_name}.addr must be a string")
        if port is not None:
            if isinstance(port, bool):
                raise SchemaError(f"{field_name}.port must be an integer")
            try:
                port = int(port)
            except (TypeError, ValueError) as exc:
                raise SchemaError(f"{field_name}.port must be an integer") from exc
        return cls(address=address, port=port)


@dataclass(frozen=True)
class NetworkEvent:
    timestamp: datetime
    event_type: str
    source: Endpoint
    destination: Endpoint
    pod: str | None
    error: str | None

    @classmethod
    def from_raw(cls, value: Any) -> "NetworkEvent":
        if not isinstance(value, dict):
            raise SchemaError("network event must be a JSON object")
        event_type = value.get("type")
        if not isinstance(event_type, str) or not event_type:
            raise SchemaError("network event type must be a non-empty string")
        k8s = value.get("k8s", {})
        if k8s is not None and not isinstance(k8s, dict):
            raise SchemaError("network event k8s field must be an object")
        pod = k8s.get("podName") if isinstance(k8s, dict) else None
        if pod is not None and not isinstance(pod, str):
            raise SchemaError("network event k8s.podName must be a string")
        error = value.get("error")
        if error is not None and not isinstance(error, str):
            raise SchemaError("network event error must be a string")
        return cls(
            timestamp=parse_utc_timestamp(value.get("timestamp")),
            event_type=event_type,
            source=Endpoint.from_raw(value.get("src"), "src"),
            destination=Endpoint.from_raw(value.get("dst"), "dst"),
            pod=pod,
            error=error,
        )


@dataclass(frozen=True)
class WorkloadSample:
    timestamp: datetime
    pod: str
    cpu_millicores: float
    memory_mib: float

    @classmethod
    def from_raw(cls, value: dict[str, str]) -> "WorkloadSample":
        required = ("timestamp", "pod", "cpu_millicores", "memory_mib")
        missing = [field for field in required if not value.get(field)]
        if missing:
            raise SchemaError(f"workload sample missing required fields: {', '.join(missing)}")
        try:
            cpu = float(value["cpu_millicores"])
            memory = float(value["memory_mib"])
        except ValueError as exc:
            raise SchemaError("workload CPU and memory must be numeric") from exc
        if cpu < 0 or memory < 0:
            raise SchemaError("workload CPU and memory cannot be negative")
        return cls(parse_utc_timestamp(value["timestamp"]), value["pod"], cpu, memory)


@dataclass(frozen=True)
class RuntimeEvent:
    timestamp: datetime
    comm: str
    args: str | None
    exepath: str | None
    cwd: str | None
    pid: int | None
    tid: int | None
    uid: int | None
    gid: int | None
    username: str | None
    parent_comm: str | None
    parent_pid: int | None
    parent_exepath: str | None
    pod: str | None
    namespace: str | None
    container_name: str | None
    container_id: str | None
    error: str | None

    @classmethod
    def from_raw(cls, value: Any) -> "RuntimeEvent":
        if not isinstance(value, dict):
            raise SchemaError("runtime event must be a JSON object")

        ts_val = value.get("timestamp")
        if not ts_val:
            raise SchemaError("runtime event missing timestamp")
        timestamp = parse_utc_timestamp(ts_val)

        proc = value.get("proc")
        if proc is not None and not isinstance(proc, dict):
            raise SchemaError("runtime event proc field must be an object")
        if not isinstance(proc, dict):
            proc = {}

        comm = proc.get("comm") or value.get("comm") or value.get("args")
        if not comm or not isinstance(comm, str):
            comm = "unknown"

        args = value.get("args")
        if args is not None and not isinstance(args, str):
            args = str(args)

        exepath = value.get("exepath") or value.get("file")
        if exepath is not None and not isinstance(exepath, str):
            exepath = str(exepath)

        cwd = value.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            cwd = str(cwd)

        pid = proc.get("pid") if isinstance(proc, dict) else None
        if pid is None:
            pid = value.get("pid")
        try:
            pid = int(pid) if pid is not None else None
        except (ValueError, TypeError):
            pid = None

        tid = proc.get("tid") if isinstance(proc, dict) else None
        try:
            tid = int(tid) if tid is not None else None
        except (ValueError, TypeError):
            tid = None

        creds = proc.get("creds") if isinstance(proc, dict) else None
        if not isinstance(creds, dict):
            creds = {}

        uid = creds.get("uid") if creds else value.get("uid")
        try:
            uid = int(uid) if uid is not None else None
        except (ValueError, TypeError):
            uid = None

        gid = creds.get("gid") if creds else value.get("gid")
        try:
            gid = int(gid) if gid is not None else None
        except (ValueError, TypeError):
            gid = None

        username = creds.get("user") if creds else value.get("loginuser")
        if username is not None and not isinstance(username, str):
            username = str(username)

        parent = proc.get("parent") if isinstance(proc, dict) else None
        if not isinstance(parent, dict):
            parent = {}

        parent_comm = parent.get("comm")
        if parent_comm is not None and not isinstance(parent_comm, str):
            parent_comm = str(parent_comm)

        parent_pid = parent.get("pid")
        try:
            parent_pid = int(parent_pid) if parent_pid is not None else None
        except (ValueError, TypeError):
            parent_pid = None

        parent_exepath = value.get("parent_exepath")
        if parent_exepath is not None and not isinstance(parent_exepath, str):
            parent_exepath = str(parent_exepath)

        k8s = value.get("k8s")
        if k8s is not None and not isinstance(k8s, dict):
            raise SchemaError("runtime event k8s field must be an object")
        if not isinstance(k8s, dict):
            k8s = {}

        pod = k8s.get("podName")
        if pod is not None and not isinstance(pod, str):
            pod = str(pod)

        namespace = k8s.get("namespace")
        if namespace is not None and not isinstance(namespace, str):
            namespace = str(namespace)

        container_name = k8s.get("containerName")
        if container_name is not None and not isinstance(container_name, str):
            container_name = str(container_name)

        runtime = value.get("runtime")
        if not isinstance(runtime, dict):
            runtime = {}
        container_id = runtime.get("containerId")
        if container_id is not None and not isinstance(container_id, str):
            container_id = str(container_id)

        error = value.get("error")
        if error is not None and not isinstance(error, str):
            error = str(error)

        return cls(
            timestamp=timestamp,
            comm=comm,
            args=args,
            exepath=exepath,
            cwd=cwd,
            pid=pid,
            tid=tid,
            uid=uid,
            gid=gid,
            username=username,
            parent_comm=parent_comm,
            parent_pid=parent_pid,
            parent_exepath=parent_exepath,
            pod=pod,
            namespace=namespace,
            container_name=container_name,
            container_id=container_id,
            error=error,
        )


def load_network_events(path: Path | str) -> list[NetworkEvent]:
    """Load a JSONL capture, failing with a useful line number on bad evidence."""
    path = Path(path)
    records: list[NetworkEvent] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                records.append(NetworkEvent.from_raw(raw))
            except (json.JSONDecodeError, SchemaError) as exc:
                raise SchemaError(f"{path}:{line_number}: {exc}") from exc
    return records


def load_runtime_events(path: Path | str) -> list[RuntimeEvent]:
    """Load a JSONL runtime process capture, failing with a line number on bad evidence."""
    path = Path(path)
    records: list[RuntimeEvent] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                records.append(RuntimeEvent.from_raw(raw))
            except (json.JSONDecodeError, SchemaError) as exc:
                raise SchemaError(f"{path}:{line_number}: {exc}") from exc
    return records


def load_workload_samples(path: Path | str) -> list[WorkloadSample]:
    """Load a workload CSV using only canonical fields, not collector labels."""
    path = Path(path)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "pod", "cpu_millicores", "memory_mib"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise SchemaError(f"{path}: missing required workload CSV columns")
        records: list[WorkloadSample] = []
        for line_number, row in enumerate(reader, start=2):
            try:
                records.append(WorkloadSample.from_raw(row))
            except SchemaError as exc:
                raise SchemaError(f"{path}:{line_number}: {exc}") from exc
    return records


def ensure_sorted(
    records: Iterable[NetworkEvent | WorkloadSample | RuntimeEvent],
) -> list[NetworkEvent | WorkloadSample | RuntimeEvent]:
    return sorted(records, key=lambda record: record.timestamp)

