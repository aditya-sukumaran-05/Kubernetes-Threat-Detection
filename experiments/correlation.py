"""Client-to-server telemetry correlation engine.

Correlates client-side experiment records and session manifests with server-side
network (eBPF TCP), runtime (eBPF trace_exec), and workload (Metrics Server)
telemetry.

Identifies matched, unmatched, and ambiguous associations across 10-second observation
windows without fabricating one-to-one matches or assuming 1 HTTP request == 1 TCP event.
Explicitly accounts for host reception-time pipe buffering uncertainty (±100-300ms).
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from telemetry.client_telemetry import ClientSessionManifest, ClientTelemetryLogger


def parse_iso_utc(ts_str: str) -> datetime:
    """Parse ISO 8601 UTC timestamp string to timezone-aware datetime."""
    clean = ts_str.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def isoformat_z(dt: datetime) -> str:
    """Format datetime as ISO 8601 UTC string with millisecond precision and Z suffix."""
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def floor_to_10s_window(dt: datetime) -> datetime:
    """Floor a datetime to its containing fixed 10-second observation window start."""
    return dt.replace(second=(dt.second // 10) * 10, microsecond=0)


@dataclass
class CorrelationReport:
    """Detailed correlation report linking client session to server telemetry."""

    session_id: str
    scenario: str
    client_status: str
    client_start_utc: str
    client_end_utc: str | None
    client_duration_seconds: float
    requests_attempted: int
    requests_completed: int
    requests_failed: int
    target_service: str
    observation_windows: list[str]

    # Server telemetry counts in session interval
    server_network_events: int = 0
    server_runtime_events: int = 0
    server_workload_samples: int = 0
    server_mean_cpu_millicores: float = 0.0
    server_max_connection_rate: float = 0.0

    # Association classification
    matched_window_count: int = 0
    unmatched_window_count: int = 0
    ambiguous_window_count: int = 0
    correlation_grade: str = "uncorrelated"  # "strongly_correlated", "partially_correlated", "uncorrelated"

    # Methodology & navigation
    uncertainty_explanation: str = ""
    soc_navigation_guide: dict[str, Any] = field(default_factory=dict)
    window_details: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def correlate_client_session(
    session_id: str,
    project_root: Path | str = ".",
    logger: ClientTelemetryLogger | None = None,
) -> CorrelationReport:
    """Correlate a client session against active server telemetry records."""
    root = Path(project_root).resolve()
    client_logger = logger or ClientTelemetryLogger(root / "telemetry" / "data" / "client")

    manifest = client_logger.get_session_manifest(session_id)
    if manifest is None:
        # Fallback to simulation_runs directory if not in client sessions
        sim_dir = root / "experiments" / "simulation_runs" / session_id
        meta_file = sim_dir / "metadata.json"
        if meta_file.exists():
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                manifest = ClientSessionManifest.from_dict(data)
            except Exception:
                manifest = None

    if manifest is None:
        return CorrelationReport(
            session_id=session_id,
            scenario="unknown",
            client_status="not_found",
            client_start_utc="",
            client_end_utc=None,
            client_duration_seconds=0.0,
            requests_attempted=0,
            requests_completed=0,
            requests_failed=0,
            target_service="unknown",
            observation_windows=[],
            correlation_grade="uncorrelated",
            uncertainty_explanation="Session manifest could not be located.",
        )

    # Determine start and end time boundaries
    start_dt = parse_iso_utc(manifest.start_time_utc)
    if manifest.end_time_utc:
        end_dt = parse_iso_utc(manifest.end_time_utc)
    else:
        end_dt = start_dt + timedelta(seconds=max(manifest.duration_seconds, 10.0))

    # Calculate covering 10-second observation windows
    first_win = floor_to_10s_window(start_dt)
    last_win = floor_to_10s_window(end_dt)
    covering_windows: list[datetime] = []
    curr = first_win
    while curr <= last_win + timedelta(seconds=10):
        covering_windows.append(curr)
        curr += timedelta(seconds=10)

    win_strings = [isoformat_z(w) for w in covering_windows]

    # Query server telemetry files
    net_path = root / "telemetry" / "data" / "network" / "network_events.jsonl"
    rt_path = root / "telemetry" / "data" / "runtime" / "runtime_events.jsonl"
    wl_path = root / "telemetry" / "data" / "workload_metrics.csv"

    # Window-indexed server telemetry tallies
    win_net_counts: dict[str, int] = {w: 0 for w in win_strings}
    win_rt_counts: dict[str, int] = {w: 0 for w in win_strings}
    win_wl_cpus: dict[str, list[float]] = {w: [] for w in win_strings}

    # 1. Inspect Server Network Events
    if net_path.exists():
        try:
            with open(net_path, "r", encoding="utf-8", errors="replace") as f:
                # Seek backwards if large, or read lines
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        ev = json.loads(line)
                        ts_str = ev.get("collector_timestamp") or ev.get("timestamp")
                        if not ts_str:
                            continue
                        ev_dt = parse_iso_utc(str(ts_str))
                        ev_win_str = isoformat_z(floor_to_10s_window(ev_dt))
                        if ev_win_str in win_net_counts:
                            win_net_counts[ev_win_str] += 1
                    except Exception:
                        continue
        except Exception:
            pass

    # 2. Inspect Server Runtime Events
    if rt_path.exists():
        try:
            with open(rt_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        ev = json.loads(line)
                        ts_str = ev.get("collector_timestamp") or ev.get("timestamp")
                        if not ts_str:
                            continue
                        ev_dt = parse_iso_utc(str(ts_str))
                        ev_win_str = isoformat_z(floor_to_10s_window(ev_dt))
                        if ev_win_str in win_rt_counts:
                            win_rt_counts[ev_win_str] += 1
                    except Exception:
                        continue
        except Exception:
            pass

    # 3. Inspect Server Workload Samples
    if wl_path.exists():
        try:
            with open(wl_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                for parts in reader:
                    if len(parts) >= 4 and not parts[0].startswith("timestamp"):
                        try:
                            s_dt = parse_iso_utc(parts[0].strip())
                            s_win_str = isoformat_z(floor_to_10s_window(s_dt))
                            if s_win_str in win_wl_cpus:
                                win_wl_cpus[s_win_str].append(float(parts[2].strip()))
                        except Exception:
                            continue
        except Exception:
            pass

    total_net = sum(win_net_counts.values())
    total_rt = sum(win_rt_counts.values())
    all_cpus = [c for c_list in win_wl_cpus.values() for c in c_list]
    mean_cpu = round(sum(all_cpus) / len(all_cpus), 2) if all_cpus else 0.0
    max_rate = max((cnt / 10.0 for cnt in win_net_counts.values()), default=0.0)

    # Classify associations across windows
    matched = 0
    unmatched = 0
    ambiguous = 0
    window_details: list[dict[str, Any]] = []

    scenario = manifest.scenario

    for w_str in win_strings:
        w_dt = parse_iso_utc(w_str)
        w_end_dt = w_dt + timedelta(seconds=10)

        # Check if window strictly overlaps the active client session
        strictly_inside = not (w_end_dt <= start_dt or w_dt >= end_dt)
        boundary = (abs((w_dt - start_dt).total_seconds()) <= 2.0 or abs((w_end_dt - end_dt).total_seconds()) <= 2.0)

        net_c = win_net_counts.get(w_str, 0)
        rt_c = win_rt_counts.get(w_str, 0)
        wl_c = len(win_wl_cpus.get(w_str, []))

        # Determine association category based on scenario expectations
        if scenario in ("network_burst", "benign_traffic", "benign_baseline"):
            if net_c > 0 and strictly_inside:
                status = "matched"
                matched += 1
            elif boundary and net_c > 0:
                status = "ambiguous"
                ambiguous += 1
            elif strictly_inside and net_c == 0:
                status = "unmatched"
                unmatched += 1
            else:
                status = "idle_boundary"
        elif scenario in ("runtime_anomaly", "runtime_introspection"):
            if rt_c > 0 and strictly_inside:
                status = "matched"
                matched += 1
            elif boundary and rt_c > 0:
                status = "ambiguous"
                ambiguous += 1
            elif strictly_inside and rt_c == 0:
                status = "unmatched"
                unmatched += 1
            else:
                status = "idle_boundary"
        elif scenario in ("cpu_stress", "workload_stress"):
            if any(c > 100.0 for c in win_wl_cpus.get(w_str, [])):
                status = "matched"
                matched += 1
            elif strictly_inside:
                status = "unmatched"
                unmatched += 1
            else:
                status = "idle_boundary"
        elif scenario == "concurrent_attack":
            if (net_c > 0 or rt_c > 0) and strictly_inside:
                status = "matched"
                matched += 1
            elif boundary:
                status = "ambiguous"
                ambiguous += 1
            else:
                status = "unmatched"
                unmatched += 1
        else:
            status = "matched" if (net_c > 0 or rt_c > 0 or wl_c > 0) else "unmatched"
            if status == "matched":
                matched += 1
            else:
                unmatched += 1

        window_details.append({
            "window_start": w_str,
            "window_end": isoformat_z(w_end_dt),
            "status": status,
            "server_network_events": net_c,
            "server_runtime_events": rt_c,
            "server_workload_samples": wl_c,
            "is_session_active": strictly_inside,
        })

    # Grade overall correlation
    if matched > 0 and unmatched == 0:
        grade = "strongly_correlated"
    elif matched > 0 and unmatched > 0:
        grade = "partially_correlated"
    elif ambiguous > 0:
        grade = "partially_correlated"
    else:
        grade = "uncorrelated"

    # Uncertainty explanation
    uncertainty_explanation = (
        "Server eBPF events use Windows host UTC reception timestamps (±100-300ms buffering uncertainty). "
        "Associations are grouped into fixed 10-second observation windows rather than assuming one-to-one "
        "matching between HTTP requests and TCP socket events."
    )

    # SOC Navigation Guidance
    soc_guide = _generate_soc_guidance(manifest, win_strings, grade)

    return CorrelationReport(
        session_id=manifest.session_id,
        scenario=manifest.scenario,
        client_status=manifest.status,
        client_start_utc=manifest.start_time_utc,
        client_end_utc=manifest.end_time_utc,
        client_duration_seconds=manifest.duration_seconds,
        requests_attempted=manifest.requests_attempted,
        requests_completed=manifest.requests_completed,
        requests_failed=manifest.requests_failed,
        target_service=manifest.target_service,
        observation_windows=win_strings,
        server_network_events=total_net,
        server_runtime_events=total_rt,
        server_workload_samples=len(all_cpus),
        server_mean_cpu_millicores=mean_cpu,
        server_max_connection_rate=max_rate,
        matched_window_count=matched,
        unmatched_window_count=unmatched,
        ambiguous_window_count=ambiguous,
        correlation_grade=grade,
        uncertainty_explanation=uncertainty_explanation,
        soc_navigation_guide=soc_guide,
        window_details=window_details,
    )


def _generate_soc_guidance(
    manifest: ClientSessionManifest,
    observation_windows: list[str],
    grade: str,
) -> dict[str, Any]:
    """Produce precise operator navigation instructions for the SOC dashboard."""
    scenario = manifest.scenario
    primary_win = observation_windows[0] if observation_windows else "N/A"

    if scenario == "network_burst":
        return {
            "recommended_page": "📡 Live Detection",
            "recommended_modality": "2. Network Only (eBPF TCP)",
            "target_windows": observation_windows,
            "primary_window": primary_win,
            "expected_signature": f"Sharp surge in connection rate (~10.0 conn/s) from client {manifest.client_pod}.",
            "ground_truth_note": "Client Ground Truth: Attack (HTTP burst). SOC ML model evaluates decision boundary (e.g. 37.5% score).",
            "instructions": [
                "1. Open SOC Dashboard at http://localhost:8501.",
                "2. Navigate to '📡 Live Detection' in sidebar.",
                "3. Select Modality: '2. Network Only' and Model: 'Random Forest'.",
                f"4. Scroll down to Synchronized Observation Windows and locate window '{primary_win}'.",
                "5. Observe connection count, event count, and model verdict.",
            ],
        }
    if scenario in ("runtime_anomaly", "runtime_introspection"):
        return {
            "recommended_page": "🛡️ Runtime Events",
            "recommended_modality": "4. Runtime Only (trace_exec) or 5. Network + Runtime",
            "target_windows": observation_windows,
            "primary_window": primary_win,
            "expected_signature": "In-container process execution records (id, whoami, curl, uname) under UID 0.",
            "ground_truth_note": "Client Ground Truth: Attack (Introspection commands). Triggers Suspicious Runtime Activity security alert.",
            "instructions": [
                "1. Open SOC Dashboard at http://localhost:8501.",
                "2. Navigate to '🛡️ Runtime Events' in sidebar.",
                f"3. Filter log table by timestamp '{primary_win[:16]}'.",
                "4. Navigate to '📡 Live Detection' (Modality: '5. Network + Runtime') to observe multimodal alert precedence.",
            ],
        }
    if scenario in ("cpu_stress", "workload_stress"):
        return {
            "recommended_page": "🔍 Telemetry Explorer",
            "recommended_modality": "3. Workload Only or 1. Network + Workload",
            "target_windows": observation_windows,
            "primary_window": primary_win,
            "expected_signature": "Marked CPU millicores rise (>500m) in deployment/webapp while network remains quiescent.",
            "ground_truth_note": "Client Ground Truth: Attack (Resource Abuse). cpu-test pod remains untouched.",
            "instructions": [
                "1. Open SOC Dashboard at http://localhost:8501.",
                "2. Navigate to '🔍 Telemetry Explorer' in sidebar.",
                "3. Inspect CPU & Memory time-series graphs.",
                f"4. Observe workload anomaly curve peaking around '{primary_win}'.",
            ],
        }
    if scenario == "concurrent_attack":
        return {
            "recommended_page": "📡 Live Detection",
            "recommended_modality": "7. Full Tri-Modal Fusion",
            "target_windows": observation_windows,
            "primary_window": primary_win,
            "expected_signature": "Simultaneous network TCP connection flood and in-container exec events.",
            "ground_truth_note": "Client Ground Truth: Multimodal Attack. Evaluates Precedence Rule 1 (Correlated Multimodal Incident).",
            "instructions": [
                "1. Open SOC Dashboard at http://localhost:8501.",
                "2. Navigate to '📡 Live Detection' in sidebar.",
                "3. Select Modality: '7. Full Tri-Modal Fusion'.",
                f"4. Inspect window '{primary_win}' for Correlated Multimodal Incident banner.",
            ],
        }

    # Benign baseline default
    return {
        "recommended_page": "📡 Live Detection",
        "recommended_modality": "1. Network + Workload [ML Benchmark]",
        "target_windows": observation_windows,
        "primary_window": primary_win,
        "expected_signature": "Low-rate, jittered HTTP connections with stable CPU/memory conforming to baseline.",
        "ground_truth_note": "Client Ground Truth: Benign Traffic. SOC Model predicts NORMAL (0.0% attack score).",
        "instructions": [
            "1. Open SOC Dashboard at http://localhost:8501.",
            "2. Navigate to '🏠 Overview' to verify Active Detections = 0.",
            "3. Switch to '📡 Live Detection' to confirm green 'TELEMETRY CONFORMS TO BENIGN BASELINE' banner.",
        ],
    }
