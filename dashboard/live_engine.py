"""Live telemetry streaming and incremental threat detection engine.

Consumes newly arriving network (eBPF TCP) and workload (cgroup/Metrics Server)
telemetry, aligns windows, executes cached inference, and tracks collector health.
"""

from __future__ import annotations

import csv
import json
import logging
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
MAX_RETAINED_WINDOWS = 100
STALE_THRESHOLD_SECONDS = 30.0


def _check_collector_process(script_name: str, pid_filename: str) -> tuple[bool, int | None]:
    """Check if the collector process is currently running on the operating system."""
    candidate_paths = [
        Path("telemetry/data") / pid_filename,
        Path("telemetry/data/runtime") / pid_filename,
        Path("telemetry/data/network") / pid_filename,
    ]
    for pid_file in candidate_paths:
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text(encoding="utf-8").strip())
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
    last_inferred_net_event_count: int = -1
    last_inferred_wl_sample_count: int = -1

    @property
    def is_fused(self) -> bool:
        """True if both network and workload telemetry are available."""
        return self.network_available and self.workload_available


class LiveTelemetryEngine:
    """Consumes live telemetry streams incrementally and manages window-level inference."""

    def __init__(
        self,
        detector: ThreatDetector | None = None,
        network_path: Path | str = DEFAULT_NETWORK_PATH,
        workload_path: Path | str = DEFAULT_WORKLOAD_PATH,
        runtime_path: Path | str = DEFAULT_RUNTIME_PATH,
        max_retained_windows: int = MAX_RETAINED_WINDOWS,
    ) -> None:
        self.detector = detector or ThreatDetector()
        self.network_path = Path(network_path)
        self.workload_path = Path(workload_path)
        if Path(runtime_path) == DEFAULT_RUNTIME_PATH and self.network_path != DEFAULT_NETWORK_PATH and self.network_path.is_absolute():
            self.runtime_path = self.network_path.parent / "runtime_events.jsonl"
        else:
            self.runtime_path = Path(runtime_path)
        self.max_retained_windows = max_retained_windows

        # Incremental file tracking
        self._network_file_offset: int = 0
        self._network_partial_buffer: str = ""
        self._network_valid_events: list[NetworkEvent] = []
        self._network_malformed_count: int = 0

        self._workload_seen_lines: set[str] = set()
        self._workload_valid_samples: list[WorkloadSample] = []
        self._workload_malformed_count: int = 0

        self._runtime_file_offset: int = 0
        self._runtime_partial_buffer: str = ""
        self._runtime_valid_events: list[RuntimeEvent] = []
        self._runtime_malformed_count: int = 0

        # Synchronized windows registry: window_start -> LiveWindowRecord
        self.windows: dict[str, LiveWindowRecord] = {}

    def _resolve_path(self, path: Path) -> Path:
        if not path.is_absolute():
            root = getattr(self.detector, "project_root", None)
            if root:
                return (Path(root) / path).resolve()
            return Path(path).resolve()
        return path

    def read_new_network_events(self) -> list[NetworkEvent]:
        """Incrementally read new valid NetworkEvents, handling partial lines and bad JSON."""
        resolved = self._resolve_path(self.network_path)
        if not resolved.exists() or resolved.stat().st_size == 0:
            return []

        new_events: list[NetworkEvent] = []
        file_size = resolved.stat().st_size

        # If file was truncated or rotated, reset offset
        if file_size < self._network_file_offset:
            self._network_file_offset = 0
            self._network_partial_buffer = ""

        try:
            with resolved.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._network_file_offset)
                chunk = handle.read()
                self._network_file_offset = handle.tell()
        except OSError as exc:
            logger.warning("Error reading network capture %s: %s", resolved, exc)
            return []

        if not chunk:
            return []

        combined = self._network_partial_buffer + chunk
        lines = combined.split("\n")

        # The last segment after the final newline is either empty or a partial write
        self._network_partial_buffer = lines.pop()

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                raw_json = json.loads(line_str)
                event = NetworkEvent.from_raw(raw_json)
                new_events.append(event)
                self._network_valid_events.append(event)
            except (json.JSONDecodeError, SchemaError) as exc:
                self._network_malformed_count += 1
                logger.debug("Skipped malformed network event: %s", exc)

        return new_events

    def read_new_workload_samples(self) -> list[WorkloadSample]:
        """Incrementally read new valid WorkloadSamples from CSV."""
        resolved = self._resolve_path(self.workload_path)
        if not resolved.exists() or resolved.stat().st_size == 0:
            return []

        new_samples: list[WorkloadSample] = []
        try:
            with resolved.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames:
                    return []
                required = {"timestamp", "pod", "cpu_millicores", "memory_mib"}
                if not required.issubset(reader.fieldnames):
                    return []
                for row in reader:
                    # Deduplicate rows by raw timestamp + pod
                    row_key = f"{row.get('timestamp')}|{row.get('pod')}"
                    if row_key in self._workload_seen_lines:
                        continue
                    self._workload_seen_lines.add(row_key)
                    try:
                        sample = WorkloadSample.from_raw(row)
                        new_samples.append(sample)
                        self._workload_valid_samples.append(sample)
                    except SchemaError:
                        self._workload_malformed_count += 1
        except OSError as exc:
            logger.warning("Error reading workload capture %s: %s", resolved, exc)
            return []

        return new_samples

    def read_new_runtime_events(self) -> list[RuntimeEvent]:
        """Incrementally read new valid RuntimeEvents, handling partial lines and bad JSON."""
        resolved = self._resolve_path(self.runtime_path)
        if not resolved.exists() or resolved.stat().st_size == 0:
            return []

        new_events: list[RuntimeEvent] = []
        file_size = resolved.stat().st_size

        if file_size < self._runtime_file_offset:
            self._runtime_file_offset = 0
            self._runtime_partial_buffer = ""

        try:
            with resolved.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._runtime_file_offset)
                chunk = handle.read()
                self._runtime_file_offset = handle.tell()

            if not chunk:
                return []

            full_data = self._runtime_partial_buffer + chunk
            lines = full_data.split("\n")
            self._runtime_partial_buffer = lines[-1]
            complete_lines = lines[:-1]

            for raw_line in complete_lines:
                clean = raw_line.strip()
                if not clean:
                    continue
                try:
                    obj = json.loads(clean)
                    event = RuntimeEvent.from_raw(obj)
                    new_events.append(event)
                    self._runtime_valid_events.append(event)
                except (json.JSONDecodeError, SchemaError):
                    self._runtime_malformed_count += 1
        except OSError as exc:
            logger.warning("Error reading runtime event capture %s: %s", resolved, exc)
            return []

        return new_events

    def get_network_health(self) -> CollectorHealth:
        """Inspect network collector health, process status, and telemetry freshness."""
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
            elif delta_sec is not None and 0 <= delta_sec <= STALE_THRESHOLD_SECONDS:
                status = f"Active (PID {proc_pid}) - latest event {delta_sec:.1f}s ago"
                is_active = True
            elif delta_sec is not None and delta_sec < 0:
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
            elif delta_sec is not None and 0 <= delta_sec <= STALE_THRESHOLD_SECONDS:
                status = f"Collector Offline (recent writes detected {delta_sec:.1f}s ago)"
                is_active = False
            elif delta_sec is not None and delta_sec < 0:
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
            total_valid_records=len(self._network_valid_events),
            malformed_records=self._network_malformed_count,
            last_record_timestamp=last_ts,
            is_active=is_active,
            status_message=status,
            is_process_running=is_proc_alive,
            pid=proc_pid,
        )

    def get_workload_health(self) -> CollectorHealth:
        """Inspect workload collector health, process status, and telemetry freshness."""
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
            elif delta_sec is not None and 0 <= delta_sec <= STALE_THRESHOLD_SECONDS:
                status = f"Active (PID {proc_pid}) - latest sample {delta_sec:.1f}s ago"
                is_active = True
            elif delta_sec is not None and delta_sec < 0:
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
            elif delta_sec is not None and 0 <= delta_sec <= STALE_THRESHOLD_SECONDS:
                status = f"Collector Offline (recent writes detected {delta_sec:.1f}s ago)"
                is_active = False
            elif delta_sec is not None and delta_sec < 0:
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
            total_valid_records=len(self._workload_valid_samples),
            malformed_records=self._workload_malformed_count,
            last_record_timestamp=last_ts,
            is_active=is_active,
            status_message=status,
            is_process_running=is_proc_alive,
            pid=proc_pid,
        )

    def get_runtime_health(self) -> CollectorHealth:
        """Inspect runtime collector health, process status, and telemetry freshness."""
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
            elif delta_sec is not None and 0 <= delta_sec <= STALE_THRESHOLD_SECONDS:
                status = f"Active (PID {proc_pid}) - latest event {delta_sec:.1f}s ago"
                is_active = True
            elif delta_sec is not None and delta_sec < 0:
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
            elif delta_sec is not None and 0 <= delta_sec <= STALE_THRESHOLD_SECONDS:
                status = f"Collector Offline (recent writes detected {delta_sec:.1f}s ago)"
                is_active = False
            elif delta_sec is not None and delta_sec < 0:
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
            total_valid_records=len(self._runtime_valid_events),
            malformed_records=self._runtime_malformed_count,
            last_record_timestamp=last_ts,
            is_active=is_active,
            status_message=status,
            is_process_running=is_proc_alive,
            pid=proc_pid,
        )

    def process_live_telemetry(self, model_name: str = "random_forest") -> list[LiveWindowRecord]:
        """Ingest new telemetry, align windows, run bounded inference, and return sorted records."""
        # 1. Ingest any newly appended records across all three streams
        self.read_new_network_events()
        self.read_new_workload_samples()
        self.read_new_runtime_events()

        # 2. Extract window features across all accumulated events
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

            # Update feature references and invalidate cache if event counts changed dynamically
            if net_win:
                net_count = int(net_win.get("network_event_count", 0))
                record.network_available = True
                record.network_features = net_win
                if net_win.get("affected_pods"):
                    record.affected_pods = str(net_win["affected_pods"])
                if record.last_inferred_net_event_count != net_count:
                    record.network_inferences.clear()
                    record.fusion_inferences.clear()
                    record.last_inferred_net_event_count = net_count

            if wl_win:
                wl_count = int(wl_win.get("workload_sample_count", 0))
                record.workload_available = True
                record.workload_features = wl_win
                if not record.affected_pods and wl_win.get("affected_pods"):
                    record.affected_pods = str(wl_win["affected_pods"])
                if record.last_inferred_wl_sample_count != wl_count:
                    record.workload_inferences.clear()
                    record.fusion_inferences.clear()
                    record.last_inferred_wl_sample_count = wl_count

            # Attach runtime events and features for this window
            rev_list = runtime_events_by_start.get(start)
            if rev_list:
                record.runtime_available = True
                record.runtime_events = rev_list
                record.runtime_features = extract_runtime_features(rev_list)
                if not record.affected_pods:
                    for ev in rev_list:
                        if ev.pod:
                            record.affected_pods = ev.pod
                            break

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

        # Return sorted list of active records
        return [self.windows[s] for s in sorted(self.windows) if s in all_starts]
