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

    # Determine latest verdict based on selected modality
    latest_inf: InferenceResult | None = None
    if selected_modality == "network":
        latest_inf = latest_record.network_inferences.get(selected_model)
    elif selected_modality == "workload":
        latest_inf = latest_record.workload_inferences.get(selected_model)
    elif selected_modality == "fusion":
        latest_inf = latest_record.fusion_inferences.get(selected_model)
    else:  # default fallback
        latest_inf = latest_record.fusion_inferences.get(selected_model) or latest_record.network_inferences.get(selected_model)

    # Count evaluations strictly for the selected modality
    evaluated_records = []
    attack_count = 0
    for r in records:
        inf = None
        if selected_modality == "network" and r.network_available:
            inf = r.network_inferences.get(selected_model)
        elif selected_modality == "workload" and r.workload_available:
            inf = r.workload_inferences.get(selected_model)
        elif selected_modality == "fusion" and r.is_fused:
            inf = r.fusion_inferences.get(selected_model)

        if inf is not None:
            evaluated_records.append(r)
            if inf.predicted_label == "attack":
                attack_count += 1

    normal_count = len(evaluated_records) - attack_count
    unevaluated_count = total_windows - len(evaluated_records)

    # High-level Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Valid Network Events", engine.get_network_health().total_valid_records)
    with m2:
        st.metric("Inference Windows (10s)", total_windows)
    with m3:
        help_msg = f"{len(evaluated_records)} evaluated windows ({unevaluated_count} idle/missing for {selected_modality})"
        st.metric("Threat Breakdown", f"{attack_count} Attack / {normal_count} Normal", help=help_msg)
    with m4:
        st.metric("Active Model", selected_model.replace("_", " ").title())

    # Latest Window Prediction Metrics Row (ensures primary prediction metrics are always visible)
    if latest_inf is not None:
        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.metric("Predicted Class", latest_inf.predicted_label.upper())
        with p2:
            st.metric("Attack Probability", format_probability(latest_inf.attack_probability), help="P(y = attack) for latest live window")
        with p3:
            st.metric("Model Confidence", format_probability(latest_inf.confidence), help="P(y = ŷ) for latest live window")
        with p4:
            st.metric("Latest Window UTC", latest_record.window_start[-9:-1] if latest_record.window_start else "N/A")

    # 7. Prominent Latest Verdict Banner with Prediction vs Malicious Activity distinction
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

    if latest_inf is not None:
        att_prob_str = format_probability(latest_inf.attack_probability)
        conf_str = format_probability(latest_inf.confidence)
        stale_tag = " (Historical / Stale Window)" if is_latest_stale else ""
        if latest_inf.predicted_label == "attack":
            st.error(
                f"🚨 **PREDICTED THREAT DETECTED{stale_tag}** in Window `{latest_record.window_start}` "
                f"({latest_inf.modality.title()} — {latest_inf.model_name.replace('_', ' ').title()})\n\n"
                f"• **Predicted Label:** ATTACK\n"
                f"• **Attack Probability:** {att_prob_str}\n"
                f"• **Model Confidence:** {conf_str}\n"
                f"• **Affected Pod(s):** `{latest_record.affected_pods}`",
                icon="🚨",
            )
            st.caption(
                "ℹ️ **Operator Advisory:** *This verdict is an automated statistical machine-learning prediction "
                "based on telemetry patterns matching trained attack behaviors. It is NOT confirmed malicious activity. "
                "Security operators must verify cluster logs before initiating containment procedures.*"
            )
        else:
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
    else:
        if selected_modality == "fusion" and not latest_record.is_fused:
            last_fused_rec = next((r for r in reversed(records) if r.is_fused), None)
            wl_cpu_str = (
                f"{latest_record.workload_features.get('workload_cpu_millicores_mean', 0.0):.1f}m CPU"
                if latest_record.workload_features
                else "N/A"
            )
            st.warning(
                f"⚠️ **FUSION TELEMETRY INCOMPLETE** for latest window `{latest_record.window_start}`.\n\n"
                f"The web application was idle (no TCP socket events recorded by Inspektor Gadget), "
                f"while workload telemetry was actively sampled ({wl_cpu_str}).\n\n"
                f"Multimodal fusion strictly requires concurrent network and workload telemetry before computing detection. "
                f"Single-modality detection results remain accessible in the table below.",
                icon="⚠️",
            )
            if last_fused_rec:
                last_fus_inf = last_fused_rec.fusion_inferences.get(selected_model)
                if last_fus_inf:
                    status_badge = "🚨 ATTACK" if last_fus_inf.predicted_label == "attack" else "✅ NORMAL"
                    prob_str = f"({last_fus_inf.attack_probability * 100:.1f}%)" if last_fus_inf.attack_probability is not None else ""
                    st.info(
                        f"📊 **Most Recent Synchronized Fusion Window:** `{last_fused_rec.window_start}` — "
                        f"Verdict: **{status_badge}** {prob_str}"
                    )
        else:
            if selected_modality == "network" and not latest_record.network_available:
                last_net_rec = next((r for r in reversed(records) if r.network_available), None)
                st.info(
                    f"ℹ️ **Network Telemetry Idle:** No TCP socket events were recorded in latest window `{latest_record.window_start}`. "
                    f"Inspektor Gadget is active and listening for webapp traffic."
                )
                if last_net_rec and last_net_rec.network_inferences.get(selected_model):
                    last_net_inf = last_net_rec.network_inferences[selected_model]
                    status_badge = "🚨 ATTACK" if last_net_inf.predicted_label == "attack" else "✅ NORMAL"
                    st.caption(
                        f"📊 **Most Recent Evaluated Network Window:** `{last_net_rec.window_start}` — "
                        f"Verdict: **{status_badge}** ({format_probability(last_net_inf.attack_probability)})"
                    )
            elif selected_modality == "workload" and not latest_record.workload_available:
                st.info(f"ℹ️ **Workload Telemetry Incomplete:** No Metrics Server samples were captured in window `{latest_record.window_start}`.")
            else:
                st.info(f"ℹ️ Awaiting telemetry evaluation for modality '{selected_modality}' in latest window `{latest_record.window_start}`.")

    # 8. Recent Detection History Table (Multi-Modality Breakdown)
    st.markdown("---")
    st.subheader("📋 Synchronized Observation Windows & Modality Comparison")
    st.caption(
        "Each window spans a fixed 10-second UTC interval. Displays distinct detection verdicts "
        "across Network-only, Workload-only, and Multimodal Fusion without fabricating missing measurements."
    )

    col_filter1, col_filter2 = st.columns([2, 1])
    with col_filter1:
        filter_active_net = st.checkbox(
            "🔍 Show only windows with active network traffic",
            value=False,
            help="Filter the view to windows that recorded TCP socket events (useful during low-traffic periods).",
        )
    with col_filter2:
        st.caption(f"Showing {fused_windows} fused / {net_windows} network / {wl_windows} workload windows")

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
    hist_df = pd.DataFrame(display_rows)
    st.dataframe(hist_df, width="stretch", hide_index=True)

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

    # Modality inspection tabs to show network, workload, fusion, and runtime distinctly
    tab_net, tab_wl, tab_fus, tab_runtime = st.tabs([
        "🌐 Network Modality",
        "⚡ Workload Modality",
        "🔬 Fusion Modality",
        "🛡️ Runtime Process Modality",
    ])

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

    # Automatic periodic refresh trigger if configured
    if auto_interval > 0:
        time.sleep(auto_interval)
        st.rerun()

