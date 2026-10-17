"""Client-side structured telemetry logging and session management.

Provides structured, versioned logging for client-originated requests and experiment
sessions in the K8S Sentinel framework. Writes client logs independently into a
dedicated directory without overwriting or mixing with raw server telemetry.

Strictly avoids recording sensitive credentials, cookies, tokens, or body payloads.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

DEFAULT_CLIENT_TELEMETRY_DIR = Path("telemetry/data/client")
DEFAULT_REQUESTS_LOG = DEFAULT_CLIENT_TELEMETRY_DIR / "requests.jsonl"
DEFAULT_SESSIONS_DIR = DEFAULT_CLIENT_TELEMETRY_DIR / "sessions"
DEFAULT_CONSOLE_STATUS_FILE = DEFAULT_CLIENT_TELEMETRY_DIR / "console_status.json"

_FILE_LOCK = threading.Lock()


def get_client_utc_now() -> str:
    """Return timezone-aware ISO 8601 UTC timestamp string with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class ClientRequestRecord:
    """Individual client HTTP request telemetry record."""

    experiment_id: str
    session_id: str
    request_id: str
    client_timestamp_utc: str
    target_service: str
    method: str
    status_code: int
    duration_ms: float
    duration_unit: str = "ms"
    success: bool = True
    error_category: str = "none"
    scenario_label: str = "benign_baseline"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientRequestRecord:
        return cls(
            experiment_id=str(data.get("experiment_id", "")),
            session_id=str(data.get("session_id", "")),
            request_id=str(data.get("request_id", "")),
            client_timestamp_utc=str(data.get("client_timestamp_utc", "")),
            target_service=str(data.get("target_service", "")),
            method=str(data.get("method", "GET")),
            status_code=int(data.get("status_code", 0)),
            duration_ms=float(data.get("duration_ms", 0.0)),
            duration_unit=str(data.get("duration_unit", "ms")),
            success=bool(data.get("success", True)),
            error_category=str(data.get("error_category", "none")),
            scenario_label=str(data.get("scenario_label", "benign_baseline")),
        )


@dataclass
class ClientSessionManifest:
    """Structured summary manifest of a client-side experiment session."""

    session_id: str
    experiment_id: str
    scenario: str
    target_service: str
    client_pod: str
    status: str  # "running", "completed", "failed", "cancelled", "partial"
    start_time_utc: str
    end_time_utc: str | None = None
    duration_seconds: float = 0.0
    requests_attempted: int = 0
    requests_completed: int = 0
    requests_failed: int = 0
    commands_attempted: int = 0
    commands_completed: int = 0
    response_code_distribution: dict[str, int] = field(default_factory=dict)
    latency_summary: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientSessionManifest:
        return cls(
            session_id=str(data.get("session_id", "")),
            experiment_id=str(data.get("experiment_id", "")),
            scenario=str(data.get("scenario", "")),
            target_service=str(data.get("target_service", "")),
            client_pod=str(data.get("client_pod", "")),
            status=str(data.get("status", "unknown")),
            start_time_utc=str(data.get("start_time_utc", "")),
            end_time_utc=data.get("end_time_utc"),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            requests_attempted=int(data.get("requests_attempted", 0)),
            requests_completed=int(data.get("requests_completed", 0)),
            requests_failed=int(data.get("requests_failed", 0)),
            commands_attempted=int(data.get("commands_attempted", 0)),
            commands_completed=int(data.get("commands_completed", 0)),
            response_code_distribution=dict(data.get("response_code_distribution", {})),
            latency_summary=dict(data.get("latency_summary", {})),
            errors=list(data.get("errors", [])),
            metadata=dict(data.get("metadata", {})),
        )


class ClientTelemetryLogger:
    """Manages thread-safe writing and retrieval of client telemetry."""

    def __init__(self, base_dir: Path | str = DEFAULT_CLIENT_TELEMETRY_DIR) -> None:
        self.base_dir = Path(base_dir)
        self.requests_log = self.base_dir / "requests.jsonl"
        self.sessions_dir = self.base_dir / "sessions"
        self.status_file = self.base_dir / "console_status.json"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def record_request(self, record: ClientRequestRecord) -> None:
        """Append a single client request record to requests.jsonl thread-safely."""
        line = json.dumps(record.to_dict()) + "\n"
        with _FILE_LOCK:
            self._ensure_dirs()
            with open(self.requests_log, "a", encoding="utf-8") as handle:
                handle.write(line)

    def record_requests_batch(self, records: Sequence[ClientRequestRecord]) -> None:
        """Append multiple client request records in a single thread-safe write."""
        if not records:
            return
        lines = "".join(json.dumps(r.to_dict()) + "\n" for r in records)
        with _FILE_LOCK:
            self._ensure_dirs()
            with open(self.requests_log, "a", encoding="utf-8") as handle:
                handle.write(lines)

    def save_session_manifest(self, manifest: ClientSessionManifest) -> Path:
        """Persist session manifest JSON file into sessions/<session_id>.json."""
        with _FILE_LOCK:
            self._ensure_dirs()
            session_file = self.sessions_dir / f"{manifest.session_id}.json"
            session_file.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
            return session_file

    def get_session_manifest(self, session_id: str) -> ClientSessionManifest | None:
        """Load session manifest for a given session_id if it exists."""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return None
        try:
            data = json.loads(session_file.read_text(encoding="utf-8"))
            return ClientSessionManifest.from_dict(data)
        except Exception:
            return None

    def list_sessions(self, limit: int = 50) -> list[ClientSessionManifest]:
        """List all saved session manifests, sorted from most recent to oldest."""
        if not self.sessions_dir.exists():
            return []
        manifests: list[ClientSessionManifest] = []
        for file in sorted(self.sessions_dir.glob("*.json"), key=os.path.getmtime, reverse=True)[:limit]:
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                manifests.append(ClientSessionManifest.from_dict(data))
            except Exception:
                continue
        return manifests

    def get_requests_for_session(self, session_id: str) -> list[ClientRequestRecord]:
        """Read all request records for a specific session_id from requests.jsonl."""
        if not self.requests_log.exists():
            return []
        matching: list[ClientRequestRecord] = []
        with _FILE_LOCK:
            with open(self.requests_log, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record_dict = json.loads(line)
                        if record_dict.get("session_id") == session_id:
                            matching.append(ClientRequestRecord.from_dict(record_dict))
                    except Exception:
                        continue
        return matching

    def compute_latency_summary(self, durations_ms: Sequence[float]) -> dict[str, float]:
        """Calculate statistical summary (min, mean, p50, p95, max) for request latencies."""
        if not durations_ms:
            return {"min_ms": 0.0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
        import numpy as np

        arr = np.asarray(durations_ms, dtype=float)
        return {
            "min_ms": round(float(np.min(arr)), 2),
            "mean_ms": round(float(np.mean(arr)), 2),
            "p50_ms": round(float(np.percentile(arr, 50)), 2),
            "p95_ms": round(float(np.percentile(arr, 95)), 2),
            "max_ms": round(float(np.max(arr)), 2),
        }
