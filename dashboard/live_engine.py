"""Live telemetry streaming and incremental threat detection engine.

Consumes newly arriving network (eBPF TCP) and workload (cgroup/Metrics Server)
telemetry, aligns windows, executes cached inference, and tracks collector health.
"""

from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil

from ml.inference import InferenceResult, InferenceSchemaError, ThreatDetector
from telemetry.features.network import extract_network_features
from telemetry.features.runtime import extract_runtime_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import NetworkEvent, RuntimeEvent, SchemaError, WorkloadSample
from telemetry.windowing import isoformat_z, window_start

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_PATH = Path("telemetry/data/network/network_events.jsonl")
DEFAULT_WORKLOAD_PATH = Path("telemetry/data/workload_metrics.csv")
DEFAULT_RUNTIME_PATH = Path("telemetry/data/runtime/runtime_events.jsonl")
MAX_RETAINED_WINDOWS = 50
STALE_THRESHOLD_SECONDS = 30.0
CLOCK_SKEW_TOLERANCE_SECONDS = 2.0


def _check_collector_process(script_name: str, pid_filename: str) -> tuple[bool, int | None]:
    """Check if the collector process is currently running on the operating system."""
    candidate_dirs = [
        Path("telemetry/data"),
        Path("telemetry/data/runtime"),
        Path("telemetry/data/network"),
    ]
    repo_root = Path(__file__).resolve().parent.parent
    candidate_paths: list[Path] = [d / pid_filename for d in candidate_dirs] + [
        repo_root / d / pid_filename for d in candidate_dirs
    ]

    seen_paths: set[Path] = set()
    for pid_file in candidate_paths:
        try:
            resolved_pid = pid_file.resolve()
        except Exception:
            resolved_pid = pid_file
        if resolved_pid in seen_paths:
            continue
        seen_paths.add(resolved_pid)

        if resolved_pid.exists():
            try:
                pid = int(resolved_pid.read_text(encoding="utf-8").strip())
                if psutil.pid_exists(pid):
                    return True, pid
            except Exception:
                pass

    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmdline = proc.info.get("cmdline") or []
                cmd_str = " ".join(cmdline).lower()
                if script_name.lower() in cmd_str and "python" in (proc.info.get("name") or "").lower():
                    # Filter out dashboard process and one-line python commands
                    if "-c" not in cmd_str and "streamlit" not in cmd_str and "app.py" not in cmd_str:
                        return True, proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    return False, None


def _get_file_identity(st: os.stat_result) -> tuple:
    """Return a stable, unique file identifier for rotation detection across POSIX and Windows.

    On POSIX and Windows NTFS, (st_ino, st_dev) is stable across normal appends and changes
    only on file rotation or replacement. Note: st_ctime is NOT included on POSIX because it represents
    inode metadata change time and updates on every append/write. On Windows, creation time is used
    as fallback only if st_ino is 0 (e.g. non-NTFS volumes).
    """
    if st.st_ino != 0:
        return (st.st_ino, getattr(st, "st_dev", 0))
    if os.name == "nt":
        return (0, getattr(st, "st_dev", 0), getattr(st, "st_ctime_ns", 0))
    return (0, getattr(st, "st_dev", 0))


def _compute_feature_fingerprint(features: dict[str, Any] | None) -> tuple:
    """Compute an immutable content fingerprint of window features for cache invalidation."""
    if not features:
        return ()
    items = []
    for k, v in features.items():
        if isinstance(v, (int, float)):
            items.append((k, round(float(v), 6)))
        elif isinstance(v, (list, tuple)):
            items.append((k, tuple(v)))
        else:
            items.append((k, str(v)))
    return tuple(sorted(items))


@dataclass
class CollectorHealth:
    """Operational status of a live telemetry stream collector."""

    source_name: str
    file_path: Path
    file_exists: bool
    total_valid_records: int
    malformed_records: int
    last_record_timestamp: datetime | None
    is_active: bool  # True if actively streaming or active collector listening
    status_message: str
    is_process_running: bool = False
    pid: int | None = None


@dataclass
class LiveWindowRecord:
    """Synchronized 10-second observation window with cached inference results."""

    window_start: str
    window_end: str
    affected_pods: str
    network_available: bool = False
    workload_available: bool = False
    runtime_available: bool = False
    network_features: dict[str, Any] | None = None
    workload_features: dict[str, Any] | None = None
    runtime_features: dict[str, Any] | None = None
    runtime_events: list[RuntimeEvent] = field(default_factory=list)
    # Cached inferences: model_name -> InferenceResult
    network_inferences: dict[str, InferenceResult] = field(default_factory=dict)
    workload_inferences: dict[str, InferenceResult] = field(default_factory=dict)
    fusion_inferences: dict[str, InferenceResult] = field(default_factory=dict)
    runtime_inferences: dict[str, InferenceResult] = field(default_factory=dict)
    net_rt_inferences: dict[str, InferenceResult] = field(default_factory=dict)
    rt_wl_inferences: dict[str, InferenceResult] = field(default_factory=dict)
    full_fusion_inferences: dict[str, InferenceResult] = field(default_factory=dict)
    last_inferred_net_event_count: int = -1
    last_inferred_wl_sample_count: int = -1
    last_inferred_rt_event_count: int = -1
    last_net_fingerprint: tuple = ()
    last_wl_fingerprint: tuple = ()
    last_rt_fingerprint: tuple = ()

    @property
    def is_fused(self) -> bool:
        """True if both network and workload telemetry are available."""
        return self.network_available and self.workload_available

    @property
    def is_net_rt_fused(self) -> bool:
        """True if both network and runtime telemetry are available."""
        return self.network_available and self.runtime_available

    @property
    def is_rt_wl_fused(self) -> bool:
        """True if both runtime and workload telemetry are available."""
        return self.runtime_available and self.workload_available

    @property
    def is_full_fused(self) -> bool:
        """True if network, workload, and runtime telemetry are available."""
        return self.network_available and self.workload_available and self.runtime_available


class LiveTelemetryEngine:
    """Consumes live telemetry streams incrementally and manages window-level inference."""

    def __init__(
        self,
        detector: ThreatDetector | None = None,
        network_path: Path | str = DEFAULT_NETWORK_PATH,
        workload_path: Path | str = DEFAULT_WORKLOAD_PATH,
        runtime_path: Path | str = DEFAULT_RUNTIME_PATH,
        max_retained_windows: int = MAX_RETAINED_WINDOWS,
        stale_threshold_seconds: float = STALE_THRESHOLD_SECONDS,
        clock_skew_tolerance_seconds: float = CLOCK_SKEW_TOLERANCE_SECONDS,
        prefer_collector_timestamp: bool = True,
    ) -> None:
        self.detector = detector or ThreatDetector()
        self.network_path = Path(network_path)
        self.workload_path = Path(workload_path)
        resolved_net = self._resolve_path(self.network_path)
        resolved_default_net = self._resolve_path(DEFAULT_NETWORK_PATH)
        if Path(runtime_path) == DEFAULT_RUNTIME_PATH and resolved_net != resolved_default_net:
            self.runtime_path = self.network_path.parent / "runtime_events.jsonl"
        else:
            self.runtime_path = Path(runtime_path)
        self.max_retained_windows = max_retained_windows
        self.stale_threshold_seconds = float(stale_threshold_seconds)
        self.clock_skew_tolerance_seconds = float(clock_skew_tolerance_seconds)
        self.prefer_collector_timestamp = prefer_collector_timestamp

        # Incremental file tracking
        self._network_file_offset: int = 0
        self._network_partial_bytes: bytes = b""
        self._network_valid_events: list[NetworkEvent] = []
        self._network_malformed_count: int = 0
        self._network_cumulative_count: int = 0
        self._network_file_id: tuple | None = None
        self._network_header_bytes: bytes = b""

        self._workload_file_offset: int = 0
        self._workload_partial_bytes: bytes = b""
        self._workload_seen_samples: set[tuple[datetime, str]] = set()
        self._workload_valid_samples: list[WorkloadSample] = []
        self._workload_malformed_count: int = 0
        self._workload_cumulative_count: int = 0
        self._workload_file_id: tuple | None = None
        self._workload_header_bytes: bytes = b""

        self._runtime_file_offset: int = 0
        self._runtime_partial_bytes: bytes = b""
        self._runtime_valid_events: list[RuntimeEvent] = []
        self._runtime_malformed_count: int = 0
        self._runtime_cumulative_count: int = 0
        self._runtime_file_id: tuple | None = None
        self._runtime_header_bytes: bytes = b""

        # Synchronized windows registry: window_start -> LiveWindowRecord
        self.windows: dict[str, LiveWindowRecord] = {}

    @property
    def _network_partial_buffer(self) -> str:
        return self._network_partial_bytes.decode("utf-8", errors="replace")

    @_network_partial_buffer.setter
    def _network_partial_buffer(self, val: str | bytes) -> None:
        if isinstance(val, str):
            self._network_partial_bytes = val.encode("utf-8")
        else:
            self._network_partial_bytes = val

    @property
    def _workload_partial_buffer(self) -> str:
        return self._workload_partial_bytes.decode("utf-8", errors="replace")

    @_workload_partial_buffer.setter
    def _workload_partial_buffer(self, val: str | bytes) -> None:
        if isinstance(val, str):
            self._workload_partial_bytes = val.encode("utf-8")
        else:
            self._workload_partial_bytes = val

    @property
    def _runtime_partial_buffer(self) -> str:
        return self._runtime_partial_bytes.decode("utf-8", errors="replace")

    @_runtime_partial_buffer.setter
    def _runtime_partial_buffer(self, val: str | bytes) -> None:
        if isinstance(val, str):
            self._runtime_partial_bytes = val.encode("utf-8")
        else:
            self._runtime_partial_bytes = val

    @property
    def _workload_seen_lines(self) -> set[str]:
        return {f"{isoformat_z(k[0])}|{k[1]}" for k in self._workload_seen_samples}

    @_workload_seen_lines.setter
    def _workload_seen_lines(self, val: set[str]) -> None:
        pass

    def _resolve_path(self, path: Path) -> Path:
        if not path.is_absolute():
            root = getattr(self.detector, "project_root", None)
            if root:
                return (Path(root) / path).resolve()
            return Path(path).resolve()
        return path

    def read_new_network_events(self) -> list[NetworkEvent]:
        """Incrementally read new valid NetworkEvents, handling partial lines, multibyte UTF-8, and rotations."""
        resolved = self._resolve_path(self.network_path)
        if not resolved.exists():
            return []

        try:
            st = resolved.stat()
        except OSError as exc:
            logger.warning("Error stating network capture %s: %s", resolved, exc)
            return []

        if st.st_size == 0:
            return []

        # Detect rotation or replacement (even if replacement file >= previous size)
        current_id = _get_file_identity(st)
        if self._network_file_id is not None and current_id != self._network_file_id:
            logger.info("Network capture file replaced or rotated. Resetting offset.")
            self._network_file_offset = 0
            self._network_partial_bytes = b""
            self._network_header_bytes = b""

        self._network_file_id = current_id

        # Detect in-place truncation
        if st.st_size < self._network_file_offset:
            self._network_file_offset = 0
            self._network_partial_bytes = b""
            self._network_header_bytes = b""

        new_events: list[NetworkEvent] = []
        try:
            with resolved.open("rb") as handle:
                # Detect in-place rewrite of initial records
                if self._network_file_offset > 0 and self._network_header_bytes:
                    handle.seek(0)
                    hdr = handle.read(len(self._network_header_bytes))
                    if hdr != self._network_header_bytes:
                        self._network_file_offset = 0
                        self._network_partial_bytes = b""
                        self._network_header_bytes = b""

                # Optimization: On cold startup with massive historical files (> 2 MB),
                # seek to the last 1 MB so startup is instantaneous (~0.05s instead of 10s)
                # while preserving more than enough window history for max_retained_windows.
                if self._network_file_offset == 0 and st.st_size > 2 * 1024 * 1024:
                    handle.seek(st.st_size - 1024 * 1024)
                    handle.readline()  # Align to newline boundary
                    self._network_file_offset = handle.tell()
                else:
                    handle.seek(self._network_file_offset)

                chunk_bytes = handle.read()
                self._network_file_offset = handle.tell()
        except OSError as exc:
            logger.warning("Error reading network capture %s: %s", resolved, exc)
            return []

        if not chunk_bytes:
            return []

        combined_bytes = self._network_partial_bytes + chunk_bytes
        last_nl = combined_bytes.rfind(b"\n")
        if last_nl == -1:
            self._network_partial_bytes = combined_bytes
            return []

        complete_bytes = combined_bytes[: last_nl + 1]
        self._network_partial_bytes = combined_bytes[last_nl + 1 :]

        if not self._network_header_bytes:
            first_nl = complete_bytes.find(b"\n")
            if first_nl != -1:
                self._network_header_bytes = complete_bytes[: first_nl + 1]

        decoded_text = complete_bytes.decode("utf-8", errors="replace")
        for line in decoded_text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                raw_json = json.loads(line_str)
                event = NetworkEvent.from_raw(raw_json, prefer_collector_timestamp=self.prefer_collector_timestamp)
                new_events.append(event)
                self._network_valid_events.append(event)
            except (json.JSONDecodeError, SchemaError) as exc:
                self._network_malformed_count += 1
                logger.debug("Skipped malformed network event: %s", exc)

        self._network_cumulative_count += len(new_events)
        return new_events

    def read_new_workload_samples(self) -> list[WorkloadSample]:
        """Incrementally read new valid WorkloadSamples from CSV using byte-offset seeking."""
        resolved = self._resolve_path(self.workload_path)
        if not resolved.exists():
            return []

        try:
            st = resolved.stat()
        except OSError as exc:
            logger.warning("Error stating workload capture %s: %s", resolved, exc)
            return []

        if st.st_size == 0:
            return []

        # Detect rotation or replacement (even if replacement file >= previous size)
        current_id = _get_file_identity(st)
        if self._workload_file_id is not None and current_id != self._workload_file_id:
            logger.info("Workload capture file replaced or rotated. Resetting offset.")
            self._workload_file_offset = 0
            self._workload_partial_bytes = b""
            self._workload_seen_samples.clear()
            self._workload_header_bytes = b""

        self._workload_file_id = current_id

        # Detect in-place truncation
        if st.st_size < self._workload_file_offset:
            self._workload_file_offset = 0
            self._workload_partial_bytes = b""
            self._workload_seen_samples.clear()
            self._workload_header_bytes = b""

        try:
            with resolved.open("rb") as handle:
                # Detect in-place rewrite of initial records
                if self._workload_file_offset > 0 and self._workload_header_bytes:
                    handle.seek(0)
                    hdr = handle.read(len(self._workload_header_bytes))
                    if hdr != self._workload_header_bytes:
                        self._workload_file_offset = 0
                        self._workload_partial_bytes = b""
                        self._workload_seen_samples.clear()
                        self._workload_header_bytes = b""

                # Optimization: On cold startup with massive historical files (> 500 KB),
                # seek to the last 200 KB (~3,000 samples = ~4.5 hours of samples, far exceeding
                # max_retained_windows=120 windows).
                if self._workload_file_offset == 0 and st.st_size > 500 * 1024:
                    handle.seek(st.st_size - 200 * 1024)
                    handle.readline()  # Align to newline boundary
                    self._workload_file_offset = handle.tell()
                else:
                    handle.seek(self._workload_file_offset)

                chunk_bytes = handle.read()
                self._workload_file_offset = handle.tell()
        except OSError as exc:
            logger.warning("Error reading workload capture %s: %s", resolved, exc)
            return []

        if not chunk_bytes:
            return []

        combined = self._workload_partial_bytes + chunk_bytes

        # Strip UTF-8 BOM if at the beginning of the stream
        if self._workload_file_offset == len(chunk_bytes) and not self._workload_partial_bytes:
            if combined.startswith(b"\xef\xbb\xbf"):
                combined = combined[3:]

        last_nl = combined.rfind(b"\n")
        if last_nl == -1:
            self._workload_partial_bytes = combined
            return []

        complete_bytes = combined[: last_nl + 1]
        self._workload_partial_bytes = combined[last_nl + 1 :]

        if not self._workload_header_bytes:
            first_nl = complete_bytes.find(b"\n")
            if first_nl != -1:
                self._workload_header_bytes = complete_bytes[: first_nl + 1]

        decoded_text = complete_bytes.decode("utf-8", errors="replace")

        new_samples: list[WorkloadSample] = []
        for parts in csv.reader(decoded_text.splitlines()):
            if not parts:
                continue
            first_field = parts[0].strip()
            if first_field.startswith("timestamp") or (len(parts) > 2 and "cpu" in parts[2]):
                continue

            if len(parts) < 4:
                self._workload_malformed_count += 1
                continue

            row = {
                "timestamp": parts[0].strip(),
                "pod": parts[1].strip(),
                "cpu_millicores": parts[2].strip(),
                "memory_mib": parts[3].strip(),
            }

            try:
                sample = WorkloadSample.from_raw(row)
                dedup_key = (sample.timestamp, sample.pod)
                if dedup_key in self._workload_seen_samples:
                    continue
                self._workload_seen_samples.add(dedup_key)

                new_samples.append(sample)
                self._workload_valid_samples.append(sample)
                self._workload_cumulative_count += 1
            except SchemaError:
                self._workload_malformed_count += 1

        return new_samples

    def read_new_runtime_events(self) -> list[RuntimeEvent]:
        """Incrementally read new valid RuntimeEvents, handling partial lines, multibyte UTF-8, and rotations."""
        resolved = self._resolve_path(self.runtime_path)
        if not resolved.exists():
            return []

        try:
            st = resolved.stat()
        except OSError as exc:
            logger.warning("Error stating runtime capture %s: %s", resolved, exc)
            return []

        if st.st_size == 0:
            return []

        # Detect rotation or replacement (even if replacement file >= previous size)
        current_id = _get_file_identity(st)
        if self._runtime_file_id is not None and current_id != self._runtime_file_id:
            logger.info("Runtime capture file replaced or rotated. Resetting offset.")
            self._runtime_file_offset = 0
            self._runtime_partial_bytes = b""
            self._runtime_header_bytes = b""

        self._runtime_file_id = current_id

        # Detect in-place truncation
        if st.st_size < self._runtime_file_offset:
            self._runtime_file_offset = 0
            self._runtime_partial_bytes = b""
            self._runtime_header_bytes = b""

        new_events: list[RuntimeEvent] = []
        try:
            with resolved.open("rb") as handle:
                # Detect in-place rewrite of initial records
                if self._runtime_file_offset > 0 and self._runtime_header_bytes:
                    handle.seek(0)
                    hdr = handle.read(len(self._runtime_header_bytes))
                    if hdr != self._runtime_header_bytes:
                        self._runtime_file_offset = 0
                        self._runtime_partial_bytes = b""
                        self._runtime_header_bytes = b""

                handle.seek(self._runtime_file_offset)
                chunk_bytes = handle.read()
                self._runtime_file_offset = handle.tell()
        except OSError as exc:
            logger.warning("Error reading runtime event capture %s: %s", resolved, exc)
            return []

        if not chunk_bytes:
            return []

        combined_bytes = self._runtime_partial_bytes + chunk_bytes
        last_nl = combined_bytes.rfind(b"\n")
        if last_nl == -1:
            self._runtime_partial_bytes = combined_bytes
            return []

        complete_bytes = combined_bytes[: last_nl + 1]
        self._runtime_partial_bytes = combined_bytes[last_nl + 1 :]

        if not self._runtime_header_bytes:
            first_nl = complete_bytes.find(b"\n")
            if first_nl != -1:
                self._runtime_header_bytes = complete_bytes[: first_nl + 1]

        decoded_text = complete_bytes.decode("utf-8", errors="replace")
        for line in decoded_text.splitlines():
            clean = line.strip()
            if not clean:
                continue
            try:
                obj = json.loads(clean)
                event = RuntimeEvent.from_raw(obj, prefer_collector_timestamp=self.prefer_collector_timestamp)
                new_events.append(event)
                self._runtime_valid_events.append(event)
            except (json.JSONDecodeError, SchemaError):
                self._runtime_malformed_count += 1

        self._runtime_cumulative_count += len(new_events)
        return new_events

    def get_network_health(self) -> CollectorHealth:
        """Inspect network collector health, process status, and telemetry freshness."""
        self.read_new_network_events()
        resolved = self._resolve_path(self.network_path)
        file_exists = resolved.exists()
        last_ts = self._network_valid_events[-1].timestamp if self._network_valid_events else None
        is_default_target = resolved == self._resolve_path(DEFAULT_NETWORK_PATH)
        is_proc_alive, proc_pid = _check_collector_process("network_collector.py", ".network_collector.pid") if is_default_target else (False, None)

        now_utc = datetime.now(timezone.utc)
        delta_sec = (now_utc - last_ts).total_seconds() if last_ts else None

        if not file_exists and not is_proc_alive:
            status = "Waiting for network collector to start (process offline, file not found)"
            is_active = False
        elif is_proc_alive:
            if last_ts is None:
                status = f"Listening (PID {proc_pid}) - awaiting first TCP socket event"
                is_active = True
            elif delta_sec is not None and -self.clock_skew_tolerance_seconds <= delta_sec <= self.stale_threshold_seconds:
                display_sec = max(0.0, delta_sec)
                status = f"Active (PID {proc_pid}) - latest event {display_sec:.1f}s ago"
                is_active = True
            elif delta_sec is not None and delta_sec < -self.clock_skew_tolerance_seconds:
                status = f"Clock skew / future timestamp: {last_ts.isoformat()}"
                is_active = False
            else:
                assert delta_sec is not None
                status = f"Listening (Idle traffic) (PID {proc_pid}) - no socket events in last {delta_sec:.0f}s"
                is_active = True
        else:
            # Process is not running
            if not self._network_valid_events:
                status = "Capture file present, but collector process offline"
                is_active = False
            elif delta_sec is not None and -self.clock_skew_tolerance_seconds <= delta_sec <= self.stale_threshold_seconds:
                display_sec = max(0.0, delta_sec)
                status = f"Collector Offline (recent writes detected {display_sec:.1f}s ago)"
                is_active = False
            elif delta_sec is not None and delta_sec < -self.clock_skew_tolerance_seconds:
                status = f"Clock skew / future timestamp: {last_ts.isoformat()}"
                is_active = False
            else:
                assert delta_sec is not None
                status = f"Offline / Stopped (Idle / Stale) - latest event was {delta_sec / 60:.1f} min ago"
                is_active = False

        return CollectorHealth(
            source_name="Network (eBPF TCP Trace)",
            file_path=resolved,
            file_exists=file_exists,
            total_valid_records=self._network_cumulative_count,
            malformed_records=self._network_malformed_count,
            last_record_timestamp=last_ts,
            is_active=is_active,
            status_message=status,
            is_process_running=is_proc_alive,
            pid=proc_pid,
        )

    def get_workload_health(self) -> CollectorHealth:
        """Inspect workload collector health, process status, and telemetry freshness."""
        self.read_new_workload_samples()
        resolved = self._resolve_path(self.workload_path)
        file_exists = resolved.exists()
        last_ts = self._workload_valid_samples[-1].timestamp if self._workload_valid_samples else None
        is_default_target = resolved == self._resolve_path(DEFAULT_WORKLOAD_PATH)
        is_proc_alive, proc_pid = _check_collector_process("workload_collector.py", ".workload_collector.pid") if is_default_target else (False, None)

        now_utc = datetime.now(timezone.utc)
        delta_sec = (now_utc - last_ts).total_seconds() if last_ts else None

        if not file_exists and not is_proc_alive:
            status = "Waiting for workload collector to start (process offline, file not found)"
            is_active = False
        elif is_proc_alive:
            if last_ts is None:
                status = f"Sampling (PID {proc_pid}) - awaiting first pod metrics"
                is_active = True
            elif delta_sec is not None and -self.clock_skew_tolerance_seconds <= delta_sec <= self.stale_threshold_seconds:
                display_sec = max(0.0, delta_sec)
                status = f"Active (PID {proc_pid}) - latest sample {display_sec:.1f}s ago"
                is_active = True
            elif delta_sec is not None and delta_sec < -self.clock_skew_tolerance_seconds:
                status = f"Clock skew / future timestamp: {last_ts.isoformat()}"
                is_active = False
            else:
                assert delta_sec is not None
                status = f"Sampling Delayed (PID {proc_pid}) - no sample in last {delta_sec:.0f}s"
                is_active = True
        else:
            # Process is not running
            if not self._workload_valid_samples:
                status = "Metrics CSV present, but collector process offline"
                is_active = False
            elif delta_sec is not None and -self.clock_skew_tolerance_seconds <= delta_sec <= self.stale_threshold_seconds:
                display_sec = max(0.0, delta_sec)
                status = f"Collector Offline (recent writes detected {display_sec:.1f}s ago)"
                is_active = False
            elif delta_sec is not None and delta_sec < -self.clock_skew_tolerance_seconds:
                status = f"Clock skew / future timestamp: {last_ts.isoformat()}"
                is_active = False
            else:
                assert delta_sec is not None
                status = f"Offline / Stopped (Idle / Stale) - latest sample was {delta_sec / 60:.1f} min ago"
                is_active = False

        return CollectorHealth(
            source_name="Workload (cgroup / Metrics Server)",
            file_path=resolved,
            file_exists=file_exists,
            total_valid_records=self._workload_cumulative_count,
            malformed_records=self._workload_malformed_count,
            last_record_timestamp=last_ts,
            is_active=is_active,
            status_message=status,
            is_process_running=is_proc_alive,
            pid=proc_pid,
        )

    def get_runtime_health(self) -> CollectorHealth:
        """Inspect runtime collector health, process status, and telemetry freshness."""
        self.read_new_runtime_events()
        resolved = self._resolve_path(self.runtime_path)
        file_exists = resolved.exists()
        last_ts = self._runtime_valid_events[-1].timestamp if self._runtime_valid_events else None
        is_default_target = resolved == self._resolve_path(DEFAULT_RUNTIME_PATH)
        is_proc_alive, proc_pid = _check_collector_process("runtime_collector.py", ".runtime_collector.pid") if is_default_target else (False, None)

        now_utc = datetime.now(timezone.utc)
        delta_sec = (now_utc - last_ts).total_seconds() if last_ts else None

        if not file_exists and not is_proc_alive:
            status = "Waiting for runtime collector to start (process offline, file not found)"
            is_active = False
        elif is_proc_alive:
            if last_ts is None:
                status = f"Listening (PID {proc_pid}) - awaiting container process execution events"
                is_active = True
            elif delta_sec is not None and -self.clock_skew_tolerance_seconds <= delta_sec <= self.stale_threshold_seconds:
                display_sec = max(0.0, delta_sec)
                status = f"Active (PID {proc_pid}) - latest event {display_sec:.1f}s ago"
                is_active = True
            elif delta_sec is not None and delta_sec < -self.clock_skew_tolerance_seconds:
                status = f"Clock skew / future timestamp: {last_ts.isoformat()}"
                is_active = False
            else:
                assert delta_sec is not None
                status = f"Listening (Idle container) (PID {proc_pid}) - no exec events in last {delta_sec:.0f}s"
                is_active = True
        else:
            if not self._runtime_valid_events:
                status = "Runtime capture file present, but collector process offline"
                is_active = False
            elif delta_sec is not None and -self.clock_skew_tolerance_seconds <= delta_sec <= self.stale_threshold_seconds:
                display_sec = max(0.0, delta_sec)
                status = f"Collector Offline (recent writes detected {display_sec:.1f}s ago)"
                is_active = False
            elif delta_sec is not None and delta_sec < -self.clock_skew_tolerance_seconds:
                status = f"Clock skew / future timestamp: {last_ts.isoformat()}"
                is_active = False
            else:
                assert delta_sec is not None
                status = f"Offline / Stopped (Idle / Stale) - latest event was {delta_sec / 60:.1f} min ago"
                is_active = False

        return CollectorHealth(
            source_name="Runtime (eBPF Process Trace)",
            file_path=resolved,
            file_exists=file_exists,
            total_valid_records=self._runtime_cumulative_count,
            malformed_records=self._runtime_malformed_count,
            last_record_timestamp=last_ts,
            is_active=is_active,
            status_message=status,
            is_process_running=is_proc_alive,
            pid=proc_pid,
        )

    def _prune_telemetry_buffers(self, buffer_extra_windows: int = 5) -> None:
        """Prune in-memory telemetry event buffers beyond the active observation horizon.

        Retains raw events spanning at least (max_retained_windows + buffer_extra_windows)
        distinct window boundaries. Strictly preserves sparse events and idle gaps, guaranteeing
        100% bitwise feature equivalence for all active windows while bounding memory.
        """
        max_allowed_windows = self.max_retained_windows + buffer_extra_windows

        # 1. Prune network events by distinct window starts
        if self._network_valid_events:
            distinct_net = sorted({window_start(ev.timestamp) for ev in self._network_valid_events})
            if len(distinct_net) > max_allowed_windows:
                cutoff_net = distinct_net[-max_allowed_windows]
                self._network_valid_events = [ev for ev in self._network_valid_events if window_start(ev.timestamp) >= cutoff_net]

        # 2. Prune workload samples by distinct window starts
        if self._workload_valid_samples:
            distinct_wl = sorted({window_start(s.timestamp) for s in self._workload_valid_samples})
            if len(distinct_wl) > max_allowed_windows:
                cutoff_wl = distinct_wl[-max_allowed_windows]
                self._workload_valid_samples = [s for s in self._workload_valid_samples if window_start(s.timestamp) >= cutoff_wl]
                self._workload_seen_samples = {k for k in self._workload_seen_samples if k[0] >= cutoff_wl}

        # 3. Prune runtime events by distinct window starts
        if self._runtime_valid_events:
            distinct_rt = sorted({window_start(rev.timestamp) for rev in self._runtime_valid_events})
            if len(distinct_rt) > max_allowed_windows:
                cutoff_rt = distinct_rt[-max_allowed_windows]
                self._runtime_valid_events = [rev for rev in self._runtime_valid_events if window_start(rev.timestamp) >= cutoff_rt]

    def process_live_telemetry(self, model_name: str = "random_forest") -> list[LiveWindowRecord]:
        """Ingest new telemetry, align windows, run bounded inference, and return sorted records."""
        # 1. Ingest any newly appended records across all three streams
        self.read_new_network_events()
        self.read_new_workload_samples()
        self.read_new_runtime_events()

        # 2. Prune in-memory telemetry buffers to active observation horizon
        self._prune_telemetry_buffers()

        # 3. Extract window features across bounded active events
        net_windows = extract_network_features(self._network_valid_events) if self._network_valid_events else []
        workload_windows = extract_workload_features(self._workload_valid_samples) if self._workload_valid_samples else []

        # Group runtime events by 10s epoch window
        runtime_events_by_start: dict[str, list[RuntimeEvent]] = {}
        for rev in self._runtime_valid_events:
            w_start_str = isoformat_z(window_start(rev.timestamp))
            runtime_events_by_start.setdefault(w_start_str, []).append(rev)

        net_by_start = {str(w["window_start"]): w for w in net_windows}
        workload_by_start = {str(w["window_start"]): w for w in workload_windows}

        # Enforce bounded retention: bound network, workload, and runtime independently
        net_starts = sorted(set(net_by_start))
        if len(net_starts) > self.max_retained_windows:
            net_starts = net_starts[-self.max_retained_windows:]

        workload_starts = sorted(set(workload_by_start))
        if len(workload_starts) > self.max_retained_windows:
            workload_starts = workload_starts[-self.max_retained_windows:]

        runtime_starts = sorted(set(runtime_events_by_start))
        if len(runtime_starts) > self.max_retained_windows:
            runtime_starts = runtime_starts[-self.max_retained_windows:]

        all_starts = sorted(set(net_starts) | set(workload_starts) | set(runtime_starts))
        if len(all_starts) > self.max_retained_windows:
            all_starts = all_starts[-self.max_retained_windows:]

        # Prune dropped windows from memory registry
        active_set = set(all_starts)
        self.windows = {k: v for k, v in self.windows.items() if k in active_set}

        for start in all_starts:
            net_win = net_by_start.get(start)
            wl_win = workload_by_start.get(start)

            if start not in self.windows:
                base = net_win or wl_win
                if base:
                    w_end = str(base["window_end"])
                    pod_name = str(base.get("affected_pods") or "webapp")
                else:
                    dt_start = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    dt_end = dt_start + timedelta(seconds=10)
                    w_end = isoformat_z(dt_end)
                    pod_name = "webapp"

                self.windows[start] = LiveWindowRecord(
                    window_start=start,
                    window_end=w_end,
                    affected_pods=pod_name,
                )

            record = self.windows[start]

            # Update feature references and invalidate cache if event counts or feature values changed dynamically
            if net_win:
                net_count = int(net_win.get("network_event_count", 0))
                net_fp = _compute_feature_fingerprint(net_win)
                record.network_available = True
                record.network_features = net_win
                if net_win.get("affected_pods"):
                    record.affected_pods = str(net_win["affected_pods"])
                if record.last_inferred_net_event_count != net_count or record.last_net_fingerprint != net_fp:
                    record.network_inferences.clear()
                    record.fusion_inferences.clear()
                    record.net_rt_inferences.clear()
                    record.full_fusion_inferences.clear()
                    record.last_inferred_net_event_count = net_count
                    record.last_net_fingerprint = net_fp

            if wl_win:
                wl_count = int(wl_win.get("workload_sample_count", 0))
                wl_fp = _compute_feature_fingerprint(wl_win)
                record.workload_available = True
                record.workload_features = wl_win
                if not record.affected_pods and wl_win.get("affected_pods"):
                    record.affected_pods = str(wl_win["affected_pods"])
                if record.last_inferred_wl_sample_count != wl_count or record.last_wl_fingerprint != wl_fp:
                    record.workload_inferences.clear()
                    record.fusion_inferences.clear()
                    record.rt_wl_inferences.clear()
                    record.full_fusion_inferences.clear()
                    record.last_inferred_wl_sample_count = wl_count
                    record.last_wl_fingerprint = wl_fp

            # Attach runtime events and features for this window
            rev_list = runtime_events_by_start.get(start)
            if rev_list:
                rt_count = len(rev_list)
                record.runtime_available = True
                record.runtime_events = rev_list
                record.runtime_features = extract_runtime_features(rev_list)
                if not record.affected_pods:
                    for ev in rev_list:
                        if ev.pod:
                            record.affected_pods = ev.pod
                            break
                rt_fp = _compute_feature_fingerprint(record.runtime_features)
                if record.last_inferred_rt_event_count != rt_count or record.last_rt_fingerprint != rt_fp:
                    record.runtime_inferences.clear()
                    record.net_rt_inferences.clear()
                    record.rt_wl_inferences.clear()
                    record.full_fusion_inferences.clear()
                    record.last_inferred_rt_event_count = rt_count
                    record.last_rt_fingerprint = rt_fp

            # 3. Bounded Inference: Execute each model ONCE per window per modality
            # A. Network-only inference
            if record.network_available and record.network_features:
                if model_name not in record.network_inferences:
                    try:
                        record.network_inferences[model_name] = self.detector.predict(
                            record.network_features, modality="network", model_name=model_name
                        )
                    except (InferenceSchemaError, Exception) as exc:
                        logger.warning("Network inference failed for window %s: %s", start, exc)

            # B. Workload-only inference
            if record.workload_available and record.workload_features:
                if model_name not in record.workload_inferences:
                    try:
                        record.workload_inferences[model_name] = self.detector.predict(
                            record.workload_features, modality="workload", model_name=model_name
                        )
                    except (InferenceSchemaError, Exception) as exc:
                        logger.warning("Workload inference failed for window %s: %s", start, exc)

            # C. Multimodal Fusion inference (Requires BOTH dimensions without fabricating values)
            if record.is_fused and record.network_features and record.workload_features:
                if model_name not in record.fusion_inferences:
                    fused_dict = {**record.network_features, **record.workload_features}
                    fused_dict["network_available"] = True
                    fused_dict["workload_available"] = True
                    fused_dict["affected_pods"] = record.affected_pods
                    try:
                        record.fusion_inferences[model_name] = self.detector.predict(
                            fused_dict, modality="fusion", model_name=model_name
                        )
                    except (InferenceSchemaError, Exception) as exc:
                        logger.warning("Fusion inference failed for window %s: %s", start, exc)

            # D. Runtime-only inference
            if record.runtime_available and record.runtime_features:
                if model_name not in record.runtime_inferences:
                    try:
                        record.runtime_inferences[model_name] = self.detector.predict(
                            record.runtime_features, modality="runtime", model_name=model_name
                        )
                    except (InferenceSchemaError, Exception) as exc:
                        logger.warning("Runtime inference failed for window %s: %s", start, exc)

            # E. Network + Runtime pairwise inference
            if record.network_available and record.runtime_available and record.network_features and record.runtime_features:
                if model_name not in record.net_rt_inferences:
                    net_rt_dict = {**record.network_features, **record.runtime_features}
                    net_rt_dict["affected_pods"] = record.affected_pods
                    try:
                        record.net_rt_inferences[model_name] = self.detector.predict(
                            net_rt_dict, modality="net_rt", model_name=model_name
                        )
                    except (InferenceSchemaError, Exception) as exc:
                        logger.warning("Net+RT inference failed for window %s: %s", start, exc)

            # F. Runtime + Workload pairwise inference
            if record.workload_available and record.runtime_available and record.workload_features and record.runtime_features:
                if model_name not in record.rt_wl_inferences:
                    rt_wl_dict = {**record.workload_features, **record.runtime_features}
                    rt_wl_dict["affected_pods"] = record.affected_pods
                    try:
                        record.rt_wl_inferences[model_name] = self.detector.predict(
                            rt_wl_dict, modality="rt_wl", model_name=model_name
                        )
                    except (InferenceSchemaError, Exception) as exc:
                        logger.warning("RT+WL inference failed for window %s: %s", start, exc)

            # G. Full Tri-Modal Fusion inference
            if record.is_fused and record.runtime_available and record.network_features and record.workload_features and record.runtime_features:
                if model_name not in record.full_fusion_inferences:
                    full_dict = {**record.network_features, **record.workload_features, **record.runtime_features}
                    full_dict["network_available"] = True
                    full_dict["workload_available"] = True
                    full_dict["runtime_available"] = True
                    full_dict["affected_pods"] = record.affected_pods
                    try:
                        record.full_fusion_inferences[model_name] = self.detector.predict(
                            full_dict, modality="full_fusion", model_name=model_name
                        )
                    except (InferenceSchemaError, Exception) as exc:
                        logger.warning("Full fusion inference failed for window %s: %s", start, exc)

        # Return sorted list of active records
        return [self.windows[s] for s in sorted(self.windows) if s in all_starts]
