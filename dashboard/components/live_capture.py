"""Live network and multimodal threat detection component for Streamlit dashboard.

Consumes newly arriving network (eBPF TCP) and workload (cgroup/Metrics Server)
telemetry, aligns observation windows, executes bounded inference, and displays
live detection history, collector health, and evidence.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from dashboard.components.charts import render_telemetry_charts
from dashboard.components.evidence import render_evidence
from dashboard.components.summary import format_probability, render_detection_summary
from dashboard.live_engine import (
    DEFAULT_NETWORK_PATH,
    DEFAULT_RUNTIME_PATH,
    DEFAULT_WORKLOAD_PATH,
    CollectorHealth,
    LiveTelemetryEngine,
    LiveWindowRecord,
)
from ml.inference import InferenceResult, ThreatDetector
from telemetry.schemas import SchemaError


def _render_collector_card(health: CollectorHealth) -> None:
    """Render a concise operational status card for a telemetry stream collector."""
    status_icon = "🟢" if health.is_active else ("🟡" if health.file_exists else "🔴")
    pid_str = f" (PID `{health.pid}`)" if health.pid else ""
    st.markdown(f"**{status_icon} {health.source_name}**{pid_info if 'pid_info' in locals() else pid_str}")
    st.caption(f"Status: `{health.status_message}`")

    # Freshness / Staleness Indicator
    freshness_str = "No records"
    if health.last_record_timestamp:
        try:
            now_utc = datetime.now(timezone.utc)
            rec_ts = health.last_record_timestamp
            if rec_ts.tzinfo is None:
                rec_ts = rec_ts.replace(tzinfo=timezone.utc)
            age_s = max(0, int((now_utc - rec_ts).total_seconds()))
            if age_s > 60:
                freshness_str = f"⚠️ Stale ({age_s}s ago)"
            else:
                freshness_str = f"Fresh ({age_s}s ago)"
        except Exception:
            freshness_str = "Timestamp recorded"

    c1, c2 = st.columns(2)
    with c1:
        st.caption(f"Valid Records: `{health.total_valid_records}`")
        st.caption(f"Telemetry Freshness: `{freshness_str}`")
    with c2:
        st.caption(f"Skipped / Malformed: `{health.malformed_records}`")


def render_live_capture(
    detector: ThreatDetector,
    selected_model: str,
    capture_path: Path | str = DEFAULT_NETWORK_PATH,
    workload_path: Path | str = DEFAULT_WORKLOAD_PATH,
    runtime_path: Path | str = DEFAULT_RUNTIME_PATH,
    selected_modality: str = "network",
) -> None:
    """Render the Live Detection & Fusion view with incremental telemetry ingestion."""
    raw_net_path = Path(capture_path)
    raw_wl_path = Path(workload_path)
    raw_rt_path = Path(runtime_path)

    resolved_net_path = raw_net_path if raw_net_path.is_absolute() else (detector.project_root / raw_net_path).resolve()
    resolved_wl_path = raw_wl_path if raw_wl_path.is_absolute() else (detector.project_root / raw_wl_path).resolve()
    resolved_rt_path = raw_rt_path if raw_rt_path.is_absolute() else (detector.project_root / raw_rt_path).resolve()

    # 1. Operational Mode Banner
    st.info(
        "📡 **LIVE TELEMETRY THREAT DETECTION & FUSION:** Incrementally ingesting active cluster "
        "telemetry from Inspektor Gadget eBPF TCP socket traces and Kubernetes Metrics Server. "
        "Observation windows are synchronized into fixed 10-second UTC intervals. "
        "*(Note: Inferences are executed once per finalized observation window and cached; "
        "predictions represent automated statistical threat classifications, not confirmed malicious incidents.)*",
        icon="ℹ️",
    )

    # 2. Early file validation for tests and initial setup
    if not resolved_net_path.exists():
        st.warning(
            f"⚠️ Network capture file not found at `{resolved_net_path}`. "
            "Ensure the network collector is running or run: `python telemetry/network_collector.py`"
        )
        return

    try:
        net_size = resolved_net_path.stat().st_size
    except OSError as exc:
        st.error(f"❌ Failed to inspect network capture file `{resolved_net_path}`: {exc}")
        return

    if net_size == 0:
        st.warning(
            f"⚠️ Network capture file `{resolved_net_path}` is empty (0 bytes). "
            "No TCP socket events have been recorded yet."
        )
        return

    # Check for malformed capture file upfront if entire file is unparseable
    try:
        with resolved_net_path.open("r", encoding="utf-8") as handle:
            first_line = handle.readline().strip()
            if first_line and not first_line.startswith("{"):
                raise SchemaError("Invalid JSON structure in network capture")
    except SchemaError as exc:
        st.error(f"❌ Telemetry Schema Error in `{resolved_net_path}`: {exc}")
        return
    except Exception as exc:
        st.error(f"❌ Failed to read network events from `{resolved_net_path}`: {exc}")
        return

    # 3. Retrieve or initialize persistent LiveTelemetryEngine in session state
    engine_key = f"live_engine_{resolved_net_path}_{resolved_wl_path}_{resolved_rt_path}"
    if engine_key not in st.session_state:
        st.session_state[engine_key] = LiveTelemetryEngine(
            detector=detector,
            network_path=resolved_net_path,
            workload_path=resolved_wl_path,
            runtime_path=resolved_rt_path,
        )

    engine: LiveTelemetryEngine = st.session_state[engine_key]

    # Controls Row: Refresh, Cache Reset, and Auto-Refresh Interval
    col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([1, 1, 2])
    with col_ctrl1:
        if st.button("🔄 Refresh Now", help="Re-poll telemetry files and process newly arriving events"):
            st.rerun()
    with col_ctrl2:
        if st.button("🧹 Clear Stream Cache", help="Reset stream state and reprocess capture from beginning"):
            st.session_state.pop(engine_key, None)
            st.rerun()
    with col_ctrl3:
        auto_interval = st.selectbox(
            "⏱️ Stream Refresh Rate",
            options=[0, 5, 10],
            format_func=lambda s: "Manual Only (Auto-Refresh Disabled)" if s == 0 else f"Auto-refresh every {s} seconds",
            index=0,
            help="Select automatic refresh interval for monitoring live stream arrivals.",
        )

    # 4. Stream Health & Collector Status Cards
    st.markdown("#### 🩺 Live Telemetry Ingestion Health")
    health_col1, health_col2, health_col3 = st.columns(3)
    with health_col1:
        _render_collector_card(engine.get_network_health())
    with health_col2:
        _render_collector_card(engine.get_workload_health())
    with health_col3:
        _render_collector_card(engine.get_runtime_health())

    st.markdown("---")

    # 5. Process newly arrived telemetry (inferences are evaluated at most once and cached)
    try:
        records: list[LiveWindowRecord] = engine.process_live_telemetry(model_name=selected_model)
    except Exception as exc:
        st.error(f"❌ Live Stream Processing Error: {exc}")
        return

    if not records:
        st.warning("⚠️ No 10-second observation windows could be formed from the current telemetry.")
        return

    # Extract all window dicts for charting
    chart_windows: list[dict[str, Any]] = []
    for r in records:
        merged_feat: dict[str, Any] = {
            "window_start": r.window_start,
            "window_end": r.window_end,
            "affected_pods": r.affected_pods,
        }
        if r.network_features:
            merged_feat.update(r.network_features)
        if r.workload_features:
            merged_feat.update(r.workload_features)
        chart_windows.append(merged_feat)

    # 6. Primary Stream Overview Metrics
    total_windows = len(records)
    fused_windows = sum(1 for r in records if r.is_fused)
    net_windows = sum(1 for r in records if r.network_available)
    wl_windows = sum(1 for r in records if r.workload_available)

    # Latest record & target inference for primary banner
    latest_record = records[-1]

    # Modality categorization: all 7 modalities have trained ML benchmark models
    is_ml_modality = selected_modality in (
        "network",
        "workload",
        "fusion",
        "net_wl",
        "runtime",
        "net_rt",
        "rt_wl",
        "full_fusion",
    )

    # Determine latest verdict based on selected modality
    latest_inf: InferenceResult | None = None
    if selected_modality == "network":
        latest_inf = latest_record.network_inferences.get(selected_model)
    elif selected_modality == "workload":
        latest_inf = latest_record.workload_inferences.get(selected_model)
    elif selected_modality in ("fusion", "net_wl"):
        latest_inf = latest_record.fusion_inferences.get(selected_model)
    elif selected_modality == "runtime":
        latest_inf = latest_record.runtime_inferences.get(selected_model)
    elif selected_modality == "net_rt":
        latest_inf = latest_record.net_rt_inferences.get(selected_model) or latest_record.network_inferences.get(selected_model)
    elif selected_modality == "rt_wl":
        latest_inf = latest_record.rt_wl_inferences.get(selected_model) or latest_record.workload_inferences.get(selected_model)
    elif selected_modality == "full_fusion":
        latest_inf = latest_record.full_fusion_inferences.get(selected_model) or latest_record.fusion_inferences.get(selected_model)

    # Count evaluations strictly for the selected modality
    evaluated_records = []
    attack_count = 0
    for r in records:
        has_eval = False
        is_attack = False

        if selected_modality == "network" and r.network_available:
            inf = r.network_inferences.get(selected_model)
            if inf is not None:
                has_eval = True
                is_attack = (inf.predicted_label == "attack")
        elif selected_modality == "workload" and r.workload_available:
            inf = r.workload_inferences.get(selected_model)
            if inf is not None:
                has_eval = True
                is_attack = (inf.predicted_label == "attack")
        elif selected_modality in ("fusion", "net_wl") and r.is_fused:
            inf = r.fusion_inferences.get(selected_model)
            if inf is not None:
                has_eval = True
                is_attack = (inf.predicted_label == "attack")
        elif selected_modality == "runtime" and r.runtime_available:
            inf = r.runtime_inferences.get(selected_model)
            if inf is not None:
                has_eval = True
                is_attack = (inf.predicted_label == "attack")
        elif selected_modality == "net_rt" and (r.network_available or r.runtime_available):
            inf = r.net_rt_inferences.get(selected_model) or r.network_inferences.get(selected_model)
            if inf is not None:
                has_eval = True
                is_attack = (inf.predicted_label == "attack")
            elif r.runtime_features and (
                r.runtime_features.get("runtime_sensitive_command_count", 0) > 0
                or r.runtime_features.get("runtime_interactive_shell_count", 0) > 0
            ):
                has_eval = True
                is_attack = True
        elif selected_modality == "rt_wl" and (r.workload_available or r.runtime_available):
            inf = r.rt_wl_inferences.get(selected_model) or r.workload_inferences.get(selected_model)
            if inf is not None:
                has_eval = True
                is_attack = (inf.predicted_label == "attack")
            elif r.runtime_features and (
                r.runtime_features.get("runtime_sensitive_command_count", 0) > 0
                or r.runtime_features.get("runtime_interactive_shell_count", 0) > 0
            ):
                has_eval = True
                is_attack = True
        elif selected_modality == "full_fusion" and (r.is_fused or r.runtime_available):
            inf = r.full_fusion_inferences.get(selected_model) or r.fusion_inferences.get(selected_model)
            if inf is not None:
                has_eval = True
                is_attack = (inf.predicted_label == "attack")
            elif r.runtime_features and (
                r.runtime_features.get("runtime_sensitive_command_count", 0) > 0
                or r.runtime_features.get("runtime_interactive_shell_count", 0) > 0
            ):
                has_eval = True
                is_attack = True

        if has_eval:
            evaluated_records.append(r)
            if is_attack:
                attack_count += 1

    normal_count = len(evaluated_records) - attack_count
    unevaluated_count = total_windows - len(evaluated_records)

    # High-level Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        if selected_modality == "runtime":
            st.metric("Valid Runtime Execs", engine.get_runtime_health().total_valid_records)
        elif selected_modality in ("net_rt", "full_fusion"):
            st.metric("Ingested eBPF Events", f"{engine.get_network_health().total_valid_records + engine.get_runtime_health().total_valid_records:,}")
        else:
            st.metric("Valid Network Events", engine.get_network_health().total_valid_records)
    with m2:
        st.metric("Inference Windows (10s)", total_windows)
    with m3:
        help_msg = f"{len(evaluated_records)} evaluated windows ({unevaluated_count} idle/missing for {selected_modality})"
        status_label = "Threat Breakdown" if is_ml_modality else "Flagged Activity"
        st.metric(status_label, f"{attack_count} Alert / {normal_count} Normal", help=help_msg)
    with m4:
        if is_ml_modality:
            st.metric("Active Model", selected_model.replace("_", " ").title())
        else:
            st.metric("Analysis Engine", "Observational Correlation", help="Rule-based process execution & multi-telemetry correlation")

    # Latest Window Prediction & Telemetry Metrics Row (Modality-Aware)
    # Extract telemetry & inference features for the latest observation window
    rt_sec_count = latest_record.runtime_features.get("runtime_sensitive_command_count", 0) if latest_record.runtime_features else 0
    rt_shell_count = latest_record.runtime_features.get("runtime_interactive_shell_count", 0) if latest_record.runtime_features else 0
    rt_root_count = latest_record.runtime_features.get("runtime_root_exec_count", 0) if latest_record.runtime_features else 0
    rt_total = len(latest_record.runtime_events) if latest_record.runtime_events else 0
    rt_comms = sorted(set(e.comm for e in latest_record.runtime_events)) if latest_record.runtime_events else []

    net_conn_rate = latest_record.network_features.get("network_connection_rate", 0.0) if latest_record.network_features else 0.0
    net_conn_cnt = latest_record.network_features.get("network_connection_count", 0) if latest_record.network_features else 0
    wl_cpu_mean = latest_record.workload_features.get("workload_cpu_millicores_mean", 0.0) if latest_record.workload_features else 0.0
    wl_mem_mean = latest_record.workload_features.get("workload_memory_mib_mean", 0.0) if latest_record.workload_features else 0.0

    # Determine runtime security status string
    if (rt_sec_count > 0 or rt_shell_count > 0):
        rt_status_str = f"ALERT ({rt_sec_count} sens)"
    elif rt_total > 0:
        rt_status_str = f"BENIGN ({rt_total} exec)"
    elif latest_record.runtime_available:
        rt_status_str = "STABLE (0 exec)"
    else:
        rt_status_str = "UNAVAILABLE"

    # Multi-modality aware 4-column metric cards row
    p1, p2, p3, p4 = st.columns(4)
    if selected_modality in ("network", "workload", "fusion", "net_wl"):
        if latest_inf is not None:
            with p1:
                st.metric("Predicted Class", latest_inf.predicted_label.upper())
            with p2:
                st.metric("Attack Probability", format_probability(latest_inf.attack_probability), help="P(y = attack) for latest live window")
            with p3:
                st.metric("Model Confidence", format_probability(latest_inf.confidence), help="P(y = ŷ) for latest live window")
            with p4:
                st.metric("Latest Window UTC", latest_record.window_start[-9:-1] if latest_record.window_start else "N/A")
        else:
            with p1:
                st.metric("Stream Status", "TELEMETRY INCOMPLETE")
            with p2:
                st.metric("Network Available", "YES" if latest_record.network_available else "NO")
            with p3:
                st.metric("Workload Available", "YES" if latest_record.workload_available else "NO")
            with p4:
                st.metric("Latest Window UTC", latest_record.window_start[-9:-1] if latest_record.window_start else "N/A")
    elif selected_modality == "runtime":
        with p1:
            st.metric("Runtime Status", rt_status_str)
        with p2:
            st.metric("Sensitive Binaries", rt_sec_count, help="Interactive shells (sh, bash) or recon utilities (curl, whoami, id)")
        with p3:
            st.metric("Root Execs (UID 0)", rt_root_count)
        with p4:
            st.metric("Latest Window UTC", latest_record.window_start[-9:-1] if latest_record.window_start else "N/A")
    elif selected_modality == "net_rt":
        with p1:
            net_cls = latest_inf.predicted_label.upper() if latest_inf is not None else ("IDLE" if not latest_record.network_available else "PENDING")
            st.metric("Network ML Class", net_cls, help="Supervised ML prediction on TCP network telemetry")
        with p2:
            st.metric("Net Conn Rate", f"{net_conn_rate:.2f}/s", help=f"TCP connections: {net_conn_cnt} in 10s window")
        with p3:
            st.metric("Runtime Security", rt_status_str, help="eBPF container process execution status")
        with p4:
            st.metric("Latest Window UTC", latest_record.window_start[-9:-1] if latest_record.window_start else "N/A")
    elif selected_modality == "rt_wl":
        with p1:
            wl_cls = latest_inf.predicted_label.upper() if latest_inf is not None else ("IDLE" if not latest_record.workload_available else "PENDING")
            st.metric("Workload ML Class", wl_cls, help="Supervised ML prediction on container resource telemetry")
        with p2:
            st.metric("CPU Mean", f"{wl_cpu_mean:.1f}m", help=f"Mean CPU millicores; Mem: {wl_mem_mean:.1f} MiB")
        with p3:
            st.metric("Runtime Security", rt_status_str, help="eBPF container process execution status")
        with p4:
            st.metric("Latest Window UTC", latest_record.window_start[-9:-1] if latest_record.window_start else "N/A")
    elif selected_modality == "full_fusion":
        with p1:
            fus_cls = latest_inf.predicted_label.upper() if latest_inf is not None else ("INCOMPLETE" if not latest_record.is_fused else "PENDING")
            st.metric("Fusion ML Class", fus_cls, help="Supervised ML prediction on synchronized Net+Workload features")
        with p2:
            rate_cpu_str = f"{net_conn_rate:.1f}/s | {wl_cpu_mean:.0f}m" if (latest_record.network_available or latest_record.workload_available) else "N/A"
            st.metric("Net Rate / CPU", rate_cpu_str, help="Net conn rate (/s) and CPU millicores (m)")
        with p3:
            st.metric("Runtime Security", rt_status_str, help="eBPF container process execution status")
        with p4:
            coverage_cnt = sum([latest_record.network_available, latest_record.workload_available, latest_record.runtime_available])
            st.metric("Coverage (x/3)", f"{coverage_cnt}/3 streams", help="Network, Workload, and Runtime streams active in window")

    # 7. Prominent Latest Verdict Banner with Strict Precedence Rules
    # Calculate age of latest observation window relative to wall-clock UTC
    is_latest_stale = False
    window_age_seconds: float = 0.0
    try:
        dt_end = datetime.fromisoformat(latest_record.window_end.replace("Z", "+00:00"))
        now_utc = datetime.now(timezone.utc)
        window_age_seconds = max(0.0, (now_utc - dt_end).total_seconds())
        if window_age_seconds > 60.0:
            is_latest_stale = True
    except Exception:
        pass

    if is_latest_stale:
        st.markdown(f"#### ⚠️ Telemetry Inactive / Stale: Most Recent Evaluated Window (Recorded {int(window_age_seconds)}s ago)")
        st.warning(
            f"⚠️ **TELEMETRY INACTIVE / STALE:** Telemetry ingestion is currently idle or suspended. "
            f"The latest observation window (`{latest_record.window_start}`) concluded {int(window_age_seconds)}s ago. "
            f"This verdict reflects past telemetry and does NOT represent real-time cluster status.",
            icon="⚠️",
        )
    else:
        st.markdown("#### 🚨 Latest Live Observation Window Verdict (Live)")

    stale_tag = " (Historical / Stale Window)" if is_latest_stale else ""

    # Precedence Rules Evaluation
    # Category 1: ML Attack flag
    has_ml_attack = (latest_inf is not None and latest_inf.predicted_label == "attack")

    # Category 2: Runtime Security Rule Finding flag
    has_rt_alert = (rt_sec_count > 0 or rt_shell_count > 0)

    # Category 3: Telemetry Availability for selected modality
    is_telemetry_missing = False
    missing_desc = ""
    if selected_modality == "network" and not latest_record.network_available:
        is_telemetry_missing = True
        missing_desc = "No TCP socket events recorded (Network stream idle)"
    elif selected_modality == "workload" and not latest_record.workload_available:
        is_telemetry_missing = True
        missing_desc = "No Metrics Server resource samples recorded"
    elif selected_modality in ("fusion", "net_wl") and not latest_record.is_fused:
        is_telemetry_missing = True
        missing_desc = "Multimodal fusion requires both Network and Workload streams"
    elif selected_modality == "runtime" and not latest_record.runtime_available:
        is_telemetry_missing = True
        missing_desc = "No runtime eBPF trace_exec events available"
    elif selected_modality == "net_rt" and not (latest_record.network_available or latest_record.runtime_available):
        is_telemetry_missing = True
        missing_desc = "Neither Network nor Runtime telemetry available"
    elif selected_modality == "rt_wl" and not (latest_record.workload_available or latest_record.runtime_available):
        is_telemetry_missing = True
        missing_desc = "Neither Workload nor Runtime telemetry available"
    elif selected_modality == "full_fusion" and not (latest_record.is_fused or latest_record.runtime_available):
        is_telemetry_missing = True
        missing_desc = "Synchronized fusion features and runtime telemetry unavailable"

    # Precedence Rule 1: Correlated Multimodal Incident (ML Attack + Runtime Finding)
    if has_ml_attack and has_rt_alert:
        att_prob_str = format_probability(latest_inf.attack_probability) if latest_inf else "N/A"
        st.error(
            f"🚨 **CORRELATED MULTIMODAL INCIDENT{stale_tag}** in Window `{latest_record.window_start}`\n\n"
            f"• **ML Prediction:** ATTACK ({latest_inf.modality.title()} — {latest_inf.model_name.replace('_', ' ').title()})\n"
            f"• **ML Probability / Confidence:** {att_prob_str} / {format_probability(latest_inf.confidence) if latest_inf else 'N/A'}\n"
            f"• **Runtime Security Alert:** {rt_sec_count} sensitive invocation(s) ({', '.join(rt_comms)})\n"
            f"• **Affected Pod(s):** `{latest_record.affected_pods}`",
            icon="🚨",
        )
        st.caption(
            "🚨 **High-Severity Security Incident:** *Concurrent ML anomaly detection and container runtime rule violation. "
            "Correlated indicators suggest active exploitation or container compromise.*"
        )

    # Precedence Rule 2: ML Anomaly / Threat Detected (Runtime Benign or Idle)
    elif has_ml_attack:
        att_prob_str = format_probability(latest_inf.attack_probability) if latest_inf else "N/A"
        rt_note = f"Runtime process execution is currently benign/idle ({rt_total} execs)." if latest_record.runtime_available else "Runtime telemetry unavailable."
        st.error(
            f"🚨 **PREDICTED THREAT DETECTED{stale_tag}** in Window `{latest_record.window_start}` "
            f"({latest_inf.modality.title()} — {latest_inf.model_name.replace('_', ' ').title()})\n\n"
            f"• **Predicted Label:** ATTACK\n"
            f"• **Attack Probability:** {att_prob_str}\n"
            f"• **Model Confidence:** {format_probability(latest_inf.confidence) if latest_inf else 'N/A'}\n"
            f"• **Runtime State:** {rt_note}\n"
            f"• **Affected Pod(s):** `{latest_record.affected_pods}`",
            icon="🚨",
        )
        st.caption(
            "ℹ️ **Operator Advisory:** *Automated statistical machine-learning prediction "
            "based on telemetry patterns matching trained attack behaviors. Security operators must verify cluster logs.*"
        )

    # Precedence Rule 3: Suspicious Runtime Activity Detected (ML Benign or Not Evaluated)
    elif has_rt_alert:
        mod_title = {
            "runtime": "Runtime Process Execution",
            "net_rt": "Network + Runtime Correlation",
            "rt_wl": "Runtime + Workload Correlation",
            "full_fusion": "Full Tri-Modal Fusion",
        }.get(selected_modality, selected_modality)
        ml_note = f"ML model ({selected_model}) predicts NORMAL." if (latest_inf and latest_inf.predicted_label == "normal") else "ML model not evaluated on this window."
        st.error(
            f"🚨 **SUSPICIOUS RUNTIME ACTIVITY DETECTED{stale_tag}** in Window `{latest_record.window_start}` ({mod_title})\n\n"
            f"• **Sensitive Invocations:** {rt_sec_count} process execution(s) matching recon/shell patterns ({', '.join(rt_comms)})\n"
            f"• **Total Executions:** {rt_total}\n"
            f"• **ML Model Status:** {ml_note}\n"
            f"• **Affected Pod:** `{latest_record.affected_pods}`",
            icon="🚨",
        )
        st.caption(
            "⚠️ **Runtime Security Alert:** *Direct process invocation of sensitive shell or reconnaissance utilities inside container. "
            "Rule-based finding independent of statistical ML predictions.*"
        )

    # Precedence Rule 4: Telemetry Incomplete / Idle (Never report as benign!)
    elif is_telemetry_missing:
        st.warning(
            f"⚠️ **TELEMETRY INCOMPLETE / AWAITING SYNCHRONIZATION** for Window `{latest_record.window_start}`\n\n"
            f"• **Modality:** {selected_modality.replace('_', ' ').title()}\n"
            f"• **Status:** {missing_desc}\n"
            f"• **Telemetry State:** Cannot compute benign baseline while required telemetry streams are incomplete.",
            icon="⚠️",
        )
        st.caption("ℹ️ *Awaiting active telemetry streams. Historical evaluated windows remain available in the log below.*")

    # Precedence Rule 5: Benign / Normal Activity (All evaluated telemetry conforms to baseline)
    else:
        if is_ml_modality and latest_inf is not None:
            att_prob_str = format_probability(latest_inf.attack_probability)
            conf_str = format_probability(latest_inf.confidence)
            if is_latest_stale:
                st.info(
                    f"ℹ️ **PREDICTED NORMAL WORKLOAD{stale_tag}** in Window `{latest_record.window_start}` "
                    f"({latest_inf.modality.title()} — {latest_inf.model_name.replace('_', ' ').title()})\n\n"
                    f"• **Predicted Label:** NORMAL\n"
                    f"• **Attack Probability:** {att_prob_str}\n"
                    f"• **Model Confidence:** {conf_str}\n"
                    f"• **Status:** Conforms to benign application baseline.",
                    icon="ℹ️",
                )
            else:
                st.success(
                    f"✅ **PREDICTED NORMAL WORKLOAD** in Window `{latest_record.window_start}` "
                    f"({latest_inf.modality.title()} — {latest_inf.model_name.replace('_', ' ').title()})\n\n"
                    f"• **Predicted Label:** NORMAL\n"
                    f"• **Attack Probability:** {att_prob_str}\n"
                    f"• **Model Confidence:** {conf_str}\n"
                    f"• **Status:** Conforms to benign application baseline.",
                    icon="✅",
                )
            st.caption("ℹ️ *Observed socket activity and workload dynamics match expected benign application baselines.*")
        elif selected_modality in ("net_rt", "rt_wl", "full_fusion"):
            # Multi-modal correlation where ML (if evaluated) is normal and runtime has no sensitive commands
            ml_text = f"ML ({selected_model}): NORMAL ({format_probability(latest_inf.attack_probability)})" if latest_inf else "ML: Stream Synchronizing"
            rt_text = f"Runtime: {rt_total} process execs (benign)" if rt_total > 0 else "Runtime: Stable (0 execs)"
            if is_latest_stale:
                st.info(
                    f"ℹ️ **TELEMETRY CONFORMS TO BENIGN BASELINE{stale_tag}** in Window `{latest_record.window_start}`\n\n"
                    f"• **{ml_text}**\n"
                    f"• **{rt_text}**\n"
                    f"• **Affected Pod:** `{latest_record.affected_pods}`",
                    icon="ℹ️",
                )
            else:
                st.success(
                    f"✅ **TELEMETRY CONFORMS TO BENIGN BASELINE** in Window `{latest_record.window_start}`\n\n"
                    f"• **{ml_text}**\n"
                    f"• **{rt_text}**\n"
                    f"• **Affected Pod:** `{latest_record.affected_pods}`",
                    icon="✅",
                )
            st.caption("ℹ️ *Heterogeneous telemetry streams active and conforming to verified baseline metrics.*")
        elif selected_modality == "runtime":
            if rt_total > 0:
                st.info(
                    f"ℹ️ **CONTAINER PROCESS ACTIVITY RECORDED** in Window `{latest_record.window_start}`\n\n"
                    f"• **Observed Commands:** {', '.join(rt_comms)}\n"
                    f"• **Total Executions:** {rt_total} (Benign standard process execution)\n"
                    f"• **Affected Pod:** `{latest_record.affected_pods}`",
                    icon="ℹ️",
                )
            else:
                st.success(
                    f"✅ **CONTAINER RUNTIME STABLE (0 Process Executions)** in Window `{latest_record.window_start}`\n\n"
                    f"• **Status:** No process forks or command invocations detected inside container.\n"
                    f"• **Affected Pod:** `{latest_record.affected_pods}`",
                    icon="✅",
                )
            st.caption("ℹ️ *Runtime process execution monitored via eBPF trace_exec.*")


    # 8. Recent Detection History Table (Multi-Modality Breakdown)
    st.markdown("---")
    st.subheader("📋 Synchronized Observation Windows & Modality Comparison")
    st.caption(
        "Each window spans a fixed 10-second UTC interval. Displays distinct detection verdicts "
        "across Network-only, Workload-only, and Multimodal Fusion without fabricating missing measurements."
    )

    col_filter1, col_filter2, col_filter3 = st.columns([2, 1, 1])
    with col_filter1:
        search_query = st.text_input(
            "🔎 Filter Windows by Keyword / Pod / Verdict:",
            value="",
            help="Case-insensitive text filter matching any window column value.",
            key="live_win_search",
        )
    with col_filter2:
        filter_active_net = st.checkbox(
            "🔍 Show only windows with active network traffic",
            value=False,
            help="Filter the view to windows that recorded TCP socket events (useful during low-traffic periods).",
        )
    with col_filter3:
        st.caption(f"Status: {fused_windows} fused / {net_windows} net / {wl_windows} wl")

    history_rows: list[dict[str, Any]] = []
    for idx, r in enumerate(records, start=1):
        net_res = r.network_inferences.get(selected_model)
        wl_res = r.workload_inferences.get(selected_model)
        fus_res = r.fusion_inferences.get(selected_model)

        net_text = f"{net_res.predicted_label.upper()} ({format_probability(net_res.attack_probability)})" if net_res and net_res.attack_probability is not None else ("EVALUATED" if net_res else "No Socket Events (Idle)")
        wl_text = f"{wl_res.predicted_label.upper()} ({format_probability(wl_res.attack_probability)})" if wl_res and wl_res.attack_probability is not None else ("EVALUATED" if wl_res else "No Metrics")
        if r.is_fused and fus_res:
            fus_text = f"{fus_res.predicted_label.upper()} ({format_probability(fus_res.attack_probability)})" if fus_res.attack_probability is not None else "EVALUATED"
        elif not r.network_available:
            fus_text = "Missing Network (Idle)"
        elif not r.workload_available:
            fus_text = "Missing Workload"
        else:
            fus_text = "Pending Eval"

        net_event_count = r.network_features.get("network_event_count", 0) if r.network_features else 0
        runtime_event_count = len(r.runtime_events) if r.runtime_events else 0
        if runtime_event_count > 0:
            distinct_comms = sorted(set(e.comm for e in r.runtime_events))
            rt_summary = f"{runtime_event_count} execs ({', '.join(distinct_comms)[:20]})"
        else:
            rt_summary = "Idle (0 execs)"

        present_sources = []
        if r.network_available:
            present_sources.append("Net")
        if r.workload_available:
            present_sources.append("Workload")
        if r.runtime_available:
            present_sources.append("Runtime")
        present_str = " + ".join(present_sources) if present_sources else "None"

        history_rows.append({
            "Window": idx,
            "Window Start (UTC)": r.window_start,
            "Window End (UTC)": r.window_end,
            "Telemetry Present": present_str,
            "Network Verdict": net_text,
            "Workload Verdict": wl_text,
            "Fusion Verdict": fus_text,
            "Net Events": net_event_count,
            "Net Conn Rate": f"{r.network_features.get('network_connection_rate', 0.0):.2f}/s" if r.network_features else "0.00/s",
            "CPU Mean": f"{r.workload_features.get('workload_cpu_millicores_mean', 0.0):.1f}m" if r.workload_features else "N/A",
            "Runtime Execs": rt_summary,
            "Affected Pod(s)": r.affected_pods,
        })

    display_rows = [r for r in history_rows if r["Net Events"] > 0] if filter_active_net else history_rows
    if search_query.strip():
        q = search_query.strip().lower()
        display_rows = [r for r in display_rows if any(q in str(v).lower() for v in r.values())]

    hist_df = pd.DataFrame(display_rows)
    st.dataframe(hist_df, width="stretch", hide_index=True)

    # Export displayed windows as CSV
    if not hist_df.empty:
        csv_bytes = hist_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Export Filtered Windows (CSV)",
            data=csv_bytes,
            file_name="live_observation_windows.csv",
            mime="text/csv",
            key="btn_dl_live_windows_csv",
        )

    # 9. Detailed Window Inspection & Evidence (reusing existing components)
    st.markdown("---")
    st.subheader("🔎 Window Inspection & Detailed Evidence")

    # Find key reference indices
    last_window_idx = total_windows - 1
    last_net_idx = max((i for i, r in enumerate(records) if r.network_available), default=None)
    last_fused_idx = max((i for i, r in enumerate(records) if r.is_fused), default=None)

    # State tracking: auto-follow latest window by default
    if "live_track_latest" not in st.session_state:
        st.session_state["live_track_latest"] = True

    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 1, 1])
    with ctrl_col1:
        track_latest = st.checkbox(
            "📌 Auto-follow latest observation window on refresh",
            value=st.session_state["live_track_latest"],
            key="cb_track_latest",
            help="When checked, automatically tracks the newest incoming telemetry window.",
        )
        st.session_state["live_track_latest"] = track_latest

    with ctrl_col2:
        if last_net_idx is not None:
            if st.button(f"🌐 Jump to Net Traffic (#{last_net_idx + 1})", help=f"Inspect window {records[last_net_idx].window_start} with active network socket events"):
                st.session_state["live_inspected_window_start"] = records[last_net_idx].window_start
                st.session_state["live_track_latest"] = False
                if "live_window_slider" in st.session_state:
                    st.session_state["live_window_slider"] = last_net_idx + 1
                st.rerun()

    with ctrl_col3:
        if last_fused_idx is not None:
            if st.button(f"🔬 Jump to Fused (#{last_fused_idx + 1})", help=f"Inspect window {records[last_fused_idx].window_start} with complete multimodal telemetry"):
                st.session_state["live_inspected_window_start"] = records[last_fused_idx].window_start
                st.session_state["live_track_latest"] = False
                if "live_window_slider" in st.session_state:
                    st.session_state["live_window_slider"] = last_fused_idx + 1
                st.rerun()

    # Determine currently selected index based on state
    if st.session_state["live_track_latest"]:
        target_idx = last_window_idx
        st.session_state["live_inspected_window_start"] = records[target_idx].window_start
    else:
        pinned_start = st.session_state.get("live_inspected_window_start")
        target_idx = next((i for i, r in enumerate(records) if r.window_start == pinned_start), last_window_idx)
        st.session_state["live_inspected_window_start"] = records[target_idx].window_start

    # Render Slider
    if total_windows > 1:
        insp_col1, insp_col2 = st.columns([3, 1])
        with insp_col1:
            # Sync slider state
            default_slider_val = target_idx + 1
            if "live_window_slider" not in st.session_state:
                st.session_state["live_window_slider"] = default_slider_val
            elif st.session_state["live_track_latest"]:
                st.session_state["live_window_slider"] = default_slider_val

            slider_val = st.slider(
                "Select Window to Inspect:",
                min_value=1,
                max_value=total_windows,
                key="live_window_slider",
                help="Slide to inspect any historical or recent observation window.",
            )
            # If user moved the slider manually, update pinned window and disable auto-follow
            if slider_val - 1 != target_idx:
                target_idx = slider_val - 1
                st.session_state["live_inspected_window_start"] = records[target_idx].window_start
                st.session_state["live_track_latest"] = (target_idx == last_window_idx)

        with insp_col2:
            st.caption(f"**Inspecting Window {target_idx + 1} of {total_windows}**")
            st.caption(f"`{records[target_idx].window_start}`")
    else:
        target_idx = 0

    selected_idx = target_idx
    target_rec = records[selected_idx]

    # Modality inspection tabs to show all 7 telemetry dimensions distinctly
    tab_fus, tab_net, tab_wl, tab_runtime, tab_net_rt, tab_rt_wl, tab_full = st.tabs([
        "🔬 Net + Workload (ML)",
        "🌐 Network (ML)",
        "⚡ Workload (ML)",
        "🛡️ Runtime (eBPF Exec)",
        "🔗 Net + Runtime",
        "🔗 Runtime + Workload",
        "🌐 Full Tri-Modal Fusion",
    ])

    with tab_fus:
        if target_rec.is_fused and target_rec.network_features and target_rec.workload_features:
            fus_res = target_rec.fusion_inferences.get(selected_model)
            if fus_res:
                render_detection_summary(fus_res, is_live=True)
                st.markdown("---")
                render_telemetry_charts(chart_windows, selected_idx, "fusion")
                st.markdown("---")
                render_evidence(fus_res)
            else:
                st.info("Fusion inference is pending for this window.")
        else:
            missing_dims = []
            if not target_rec.network_available:
                missing_dims.append("Network (application idle, no eBPF TCP socket events)")
            if not target_rec.workload_available:
                missing_dims.append("Workload (Metrics Server samples)")
            st.info(
                f"ℹ️ **Multimodal Fusion Unavailable for Window `{target_rec.window_start}`**\n\n"
                f"Missing telemetry dimension(s): **{', '.join(missing_dims)}**.\n\n"
                "The research framework requires concurrent measurements from both telemetry dimensions "
                "to evaluate the 24-feature fusion model without fabricating synthetic values."
            )
            if last_fused_idx is not None and last_fused_idx != selected_idx:
                if st.button(f"🔬 Inspect Recent Completed Fusion Window #{last_fused_idx + 1}", key="fus_empty_jump_btn"):
                    st.session_state["live_inspected_window_start"] = records[last_fused_idx].window_start
                    st.session_state["live_track_latest"] = False
                    if "live_window_slider" in st.session_state:
                        st.session_state["live_window_slider"] = last_fused_idx + 1
                    st.rerun()

    with tab_net:
        if target_rec.network_available and target_rec.network_features:
            net_res = target_rec.network_inferences.get(selected_model)
            if net_res:
                render_detection_summary(net_res, is_live=True)
                st.markdown("---")
                render_telemetry_charts(chart_windows, selected_idx, "network")
                st.markdown("---")
                render_evidence(net_res)
            else:
                st.info("Network inference is pending for this window.")
        else:
            wl_summary = "Not recorded"
            if target_rec.workload_available and target_rec.workload_features:
                wl_cpu = target_rec.workload_features.get("workload_cpu_millicores_mean", 0.0)
                wl_summary = f"Available ({wl_cpu:.1f}m CPU)"
            last_net_ts = records[last_net_idx].window_start if last_net_idx is not None else "None recorded"
            st.info(
                f"ℹ️ **No eBPF network socket events recorded for this observation window** "
                f"(`{target_rec.window_start}` to `{target_rec.window_end}`).\n\n"
                f"The web application was idle with zero TCP socket connection attempts. "
                f"Inspektor Gadget only generates telemetry during active TCP socket operations (`accept` / `close`).\n\n"
                f"• **Workload Telemetry:** {wl_summary}\n"
                f"• **Most Recent Window with Network Events:** `{last_net_ts}`"
            )
            if last_net_idx is not None and last_net_idx != selected_idx:
                if st.button(f"🔎 Inspect Window #{last_net_idx + 1} with Network Traffic", key="net_empty_jump_btn"):
                    st.session_state["live_inspected_window_start"] = records[last_net_idx].window_start
                    st.session_state["live_track_latest"] = False
                    if "live_window_slider" in st.session_state:
                        st.session_state["live_window_slider"] = last_net_idx + 1
                    st.rerun()

    with tab_wl:
        if target_rec.workload_available and target_rec.workload_features:
            wl_res = target_rec.workload_inferences.get(selected_model)
            if wl_res:
                render_detection_summary(wl_res, is_live=True)
                st.markdown("---")
                render_telemetry_charts(chart_windows, selected_idx, "workload")
                st.markdown("---")
                render_evidence(wl_res)
            else:
                st.info("Workload inference is pending for this window.")
        else:
            st.info(
                f"ℹ️ **No workload resource metrics recorded for this observation window** "
                f"(`{target_rec.window_start}` to `{target_rec.window_end}`).\n\n"
                f"Kubernetes Metrics Server did not record CPU/memory usage samples within this 10-second interval."
            )

    with tab_runtime:
        if target_rec.runtime_available and target_rec.runtime_events:
            feats = target_rec.runtime_features or {}
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Executions", feats.get("runtime_event_count", 0))
            c2.metric("Root Executions", feats.get("runtime_root_exec_count", 0))
            c3.metric("Sensitive Commands", feats.get("runtime_sensitive_command_count", 0))
            c4.metric("Unique Binaries", feats.get("runtime_unique_commands", 0))

            if feats.get("runtime_sensitive_command_count", 0) > 0 or feats.get("runtime_interactive_shell_count", 0) > 0:
                st.warning("⚠️ **Security Alert:** Security-sensitive utilities or interactive shells executed inside the container environment during this observation window.")

            st.markdown("##### 📜 Container Process Executions in this Window")
            ev_rows = []
            for ev in target_rec.runtime_events:
                ev_rows.append({
                    "Timestamp (UTC)": ev.timestamp.isoformat(),
                    "Command": ev.comm,
                    "Arguments": ev.args or ev.comm,
                    "User": f"{ev.username or 'uid=' + str(ev.uid)} (uid={ev.uid})",
                    "PID": ev.pid,
                    "Parent": f"{ev.parent_comm} (PID {ev.parent_pid})" if ev.parent_comm else "N/A",
                    "Path": ev.exepath or "N/A",
                    "Pod": ev.pod or "webapp",
                })
            st.dataframe(pd.DataFrame(ev_rows), width="stretch", hide_index=True)
        else:
            last_rt_idx = max((i for i, r in enumerate(records) if r.runtime_available), default=None)
            last_rt_ts = records[last_rt_idx].window_start if last_rt_idx is not None else "None recorded"
            st.info(
                f"ℹ️ **No container process executions recorded for this observation window** "
                f"(`{target_rec.window_start}` to `{target_rec.window_end}`).\n\n"
                f"The container runtime was stable with no new process forks/execs. "
                f"Inspektor Gadget `trace_exec` only triggers when binaries or scripts are executed inside the container.\n\n"
                f"• **Most Recent Window with Process Executions:** `{last_rt_ts}`"
            )
            if last_rt_idx is not None and last_rt_idx != selected_idx:
                if st.button(f"🛡️ Inspect Window #{last_rt_idx + 1} with Runtime Activity", key="rt_empty_jump_btn"):
                    st.session_state["live_inspected_window_start"] = records[last_rt_idx].window_start
                    st.session_state["live_track_latest"] = False
                    if "live_window_slider" in st.session_state:
                        st.session_state["live_window_slider"] = last_rt_idx + 1
                    st.rerun()

    with tab_net_rt:
        st.markdown("#### 🔗 Pairwise Correlation: Network + Runtime")
        st.caption("Correlates eBPF TCP network socket activity with container process executions in this 10-second window.")
        c_nr1, c_nr2 = st.columns(2)
        with c_nr1:
            st.markdown("##### 🌐 Network Stream")
            if target_rec.network_available and target_rec.network_features:
                net_res = target_rec.network_inferences.get(selected_model)
                n_ev = target_rec.network_features.get("network_event_count", 0)
                n_rate = target_rec.network_features.get("network_connection_rate", 0.0)
                st.write(f"• **TCP Socket Events:** {n_ev}")
                st.write(f"• **Connection Rate:** {n_rate:.2f}/sec")
                if net_res:
                    st.write(f"• **Network ML Verdict:** `{net_res.predicted_label.upper()}` ({format_probability(net_res.attack_probability)})")
            else:
                st.info("No network events recorded in this window.")
        with c_nr2:
            st.markdown("##### 🛡️ Runtime Stream")
            if target_rec.runtime_available and target_rec.runtime_events:
                r_ev = len(target_rec.runtime_events)
                r_sec = target_rec.runtime_features.get("runtime_sensitive_command_count", 0) if target_rec.runtime_features else 0
                st.write(f"• **Process Executions:** {r_ev}")
                st.write(f"• **Sensitive Invocations:** {r_sec}")
                if r_sec > 0:
                    st.error("⚠️ Sensitive binary detected alongside network activity!")
            else:
                st.info("No runtime process executions recorded in this window.")
        render_telemetry_charts(chart_windows, selected_idx, "net_rt")

    with tab_rt_wl:
        st.markdown("#### 🔗 Pairwise Correlation: Runtime + Workload")
        st.caption("Correlates container process executions with Metrics Server resource consumption (CPU/Memory) in this 10-second window.")
        c_rw1, c_rw2 = st.columns(2)
        with c_rw1:
            st.markdown("##### 🛡️ Runtime Stream")
            if target_rec.runtime_available and target_rec.runtime_events:
                r_ev = len(target_rec.runtime_events)
                r_root = target_rec.runtime_features.get("runtime_root_exec_count", 0) if target_rec.runtime_features else 0
                st.write(f"• **Process Executions:** {r_ev}")
                st.write(f"• **Root Executions:** {r_root}")
            else:
                st.info("No runtime process executions recorded in this window.")
        with c_rw2:
            st.markdown("##### ⚡ Workload Stream")
            if target_rec.workload_available and target_rec.workload_features:
                wl_res = target_rec.workload_inferences.get(selected_model)
                w_cpu = target_rec.workload_features.get("workload_cpu_millicores_mean", 0.0)
                w_mem = target_rec.workload_features.get("workload_memory_mib_mean", 0.0)
                st.write(f"• **CPU Mean:** {w_cpu:.1f}m")
                st.write(f"• **Memory Mean:** {w_mem:.1f} MiB")
                if wl_res:
                    st.write(f"• **Workload ML Verdict:** `{wl_res.predicted_label.upper()}` ({format_probability(wl_res.attack_probability)})")
            else:
                st.info("No workload metrics recorded in this window.")
        render_telemetry_charts(chart_windows, selected_idx, "rt_wl")

    with tab_full:
        st.markdown("#### 🌐 Full Tri-Modal Telemetry Fusion (Network + Workload + Runtime)")
        st.caption("Simultaneous time-aligned observation window correlating eBPF TCP sockets, Metrics Server CPU/RAM, and container process executions.")
        t_col1, t_col2, t_col3 = st.columns(3)
        with t_col1:
            n_status = "🟢 Active" if target_rec.network_available else "⚪ Idle"
            st.metric("Network Telemetry", n_status, help="eBPF TCP trace")
        with t_col2:
            w_status = "🟢 Active" if target_rec.workload_available else "⚪ Missing"
            st.metric("Workload Telemetry", w_status, help="Metrics Server")
        with t_col3:
            r_status = "🟢 Active" if target_rec.runtime_available else "⚪ Idle"
            st.metric("Runtime Telemetry", r_status, help="eBPF trace_exec")

        if target_rec.is_fused and target_rec.fusion_inferences.get(selected_model):
            fus_res = target_rec.fusion_inferences[selected_model]
            render_detection_summary(fus_res, is_live=True)
        render_telemetry_charts(chart_windows, selected_idx, "full_fusion")

    # Raw Feature & Event Inspector Expander
    with st.expander(f"🔍 Raw Feature Vectors & Telemetry Details for Window #{selected_idx + 1}"):
        col_raw1, col_raw2 = st.columns(2)
        with col_raw1:
            st.markdown("###### Network Features (eBPF)")
            st.json(target_rec.network_features or {"status": "No network events in this window"})
        with col_raw2:
            st.markdown("###### Workload Features (Metrics Server)")
            st.json(target_rec.workload_features or {"status": "No workload samples in this window"})

    # Automatic periodic refresh trigger if configured
    if auto_interval > 0:
        time.sleep(auto_interval)
        st.rerun()

