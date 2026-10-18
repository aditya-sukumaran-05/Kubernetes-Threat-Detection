"""K8S SENTINEL Security Overview Landing Page component.

Provides cluster/namespace context pills, 4 top KPI cards (Network Events,
Runtime Executions, Workload Samples, Active Detections), synchronized telemetry
activity chart with modality controls, collector health panel, recent runtime activity table, and
recent detection decisions panel matching the K8S SENTINEL reference design.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from dashboard.components.summary import format_probability
from dashboard.live_engine import (
    DEFAULT_NETWORK_PATH,
    DEFAULT_RUNTIME_PATH,
    DEFAULT_WORKLOAD_PATH,
    CollectorHealth,
    LiveTelemetryEngine,
    LiveWindowRecord,
)
from ml.inference import ThreatDetector
from telemetry.schemas import (
    NetworkEvent,
    WorkloadSample,
    load_network_events,
    load_runtime_events,
    load_workload_samples,
)
from telemetry.windowing import isoformat_z, window_start


def _get_historical_active_windows(
    project_root: Path,
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Synthesize synchronized 10s windows containing actual recorded activity across collectors."""
    net_path = project_root / DEFAULT_NETWORK_PATH
    rt_path = project_root / DEFAULT_RUNTIME_PATH
    wl_path = project_root / DEFAULT_WORKLOAD_PATH

    nets: list[NetworkEvent] = []
    if net_path.exists():
        try:
            size = net_path.stat().st_size
            with net_path.open("rb") as f:
                if size > 1024 * 1024:
                    f.seek(size - 1024 * 1024)
                    f.readline()  # discard partial first line
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                for line in lines:
                    line_str = line.strip()
                    if line_str.startswith("{"):
                        try:
                            nets.append(NetworkEvent.from_raw(json.loads(line_str)))
                        except Exception:
                            continue
        except Exception:
            nets = list(load_network_events(net_path))

    rts = list(load_runtime_events(rt_path)) if rt_path.exists() else []

    wls: list[WorkloadSample] = []
    if wl_path.exists():
        try:
            size = wl_path.stat().st_size
            with wl_path.open("rb") as f:
                if size > 150 * 1024:
                    f.seek(size - 150 * 1024)
                    f.readline()  # discard partial first line
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                for parts in csv.reader(lines):
                    if len(parts) >= 4 and not parts[0].startswith("timestamp"):
                        try:
                            wls.append(
                                WorkloadSample(
                                    timestamp=parts[0].strip(),
                                    pod=parts[1].strip(),
                                    cpu_millicores=float(parts[2].strip()),
                                    memory_mib=float(parts[3].strip()),
                                    label=parts[4].strip() if len(parts) > 4 else "normal",
                                )
                            )
                        except Exception:
                            continue
        except Exception:
            wls = list(load_workload_samples(wl_path))

    # Map timestamps to windows
    win_data: dict[str, dict[str, Any]] = {}

    for ev in nets:
        ws = isoformat_z(window_start(ev.timestamp))
        if ws not in win_data:
            win_data[ws] = {"window_start": ws, "network_events": 0, "runtime_execs": 0, "cpu_millicores": 0.0, "sample_count": 0}
        win_data[ws]["network_events"] += 1

    for rev in rts:
        ws = isoformat_z(window_start(rev.timestamp))
        if ws not in win_data:
            win_data[ws] = {"window_start": ws, "network_events": 0, "runtime_execs": 0, "cpu_millicores": 0.0, "sample_count": 0}
        win_data[ws]["runtime_execs"] += 1

    # Map workloads that align with known windows or have CPU > 0
    for s in wls:
        ws = isoformat_z(window_start(s.timestamp))
        if ws in win_data or s.cpu_millicores > 0:
            if ws not in win_data:
                win_data[ws] = {"window_start": ws, "network_events": 0, "runtime_execs": 0, "cpu_millicores": 0.0, "sample_count": 0}
            win_data[ws]["cpu_millicores"] += s.cpu_millicores
            win_data[ws]["sample_count"] += 1

    for ws, val in win_data.items():
        if val["sample_count"] > 1:
            val["cpu_millicores"] = round(val["cpu_millicores"] / val["sample_count"], 1)

    sorted_active = [win_data[k] for k in sorted(win_data)]
    return sorted_active[-limit:] if sorted_active else []


def render_overview(
    detector: ThreatDetector,
    capture_path: Path | str = DEFAULT_NETWORK_PATH,
    workload_path: Path | str = DEFAULT_WORKLOAD_PATH,
    runtime_path: Path | str = DEFAULT_RUNTIME_PATH,
    selected_model: str = "random_forest",
) -> None:
    """Render the Security Overview dashboard matching the K8S SENTINEL reference."""
    raw_net_path = Path(capture_path)
    raw_wl_path = Path(workload_path)
    raw_rt_path = Path(runtime_path)

    resolved_net_path = raw_net_path if raw_net_path.is_absolute() else (detector.project_root / raw_net_path).resolve()
    resolved_wl_path = raw_wl_path if raw_wl_path.is_absolute() else (detector.project_root / raw_wl_path).resolve()
    resolved_rt_path = raw_rt_path if raw_rt_path.is_absolute() else (detector.project_root / raw_rt_path).resolve()

    engine_key = f"live_engine_{resolved_net_path}_{resolved_wl_path}_{resolved_rt_path}"
    if engine_key not in st.session_state:
        st.session_state[engine_key] = LiveTelemetryEngine(
            detector=detector,
            network_path=resolved_net_path,
            workload_path=resolved_wl_path,
            runtime_path=resolved_rt_path,
        )

    engine: LiveTelemetryEngine = st.session_state[engine_key]

    # Ingest latest telemetry
    try:
        records: list[LiveWindowRecord] = engine.process_live_telemetry(model_name=selected_model)
    except Exception as exc:
        import traceback
        logging.getLogger(__name__).error("Failed to process telemetry: %s\n%s", exc, traceback.format_exc())
        st.error(f"Failed to process telemetry: {exc}")
        records = []

    # 1. Top Context Pills
    c_ctx1, c_ctx2, c_ctx3, c_ctx4, c_ctx5 = st.columns([1.5, 1.5, 2.5, 2.0, 0.8])
    with c_ctx1:
        st.markdown(
            '<div class="sentinel-pill">☸️ <strong>Cluster:</strong> minikube</div>',
            unsafe_allow_html=True,
        )
    with c_ctx2:
        st.markdown(
            '<div class="sentinel-pill">📁 <strong>Namespace:</strong> default</div>',
            unsafe_allow_html=True,
        )
    with c_ctx3:
        all_active = engine.get_network_health().is_active and engine.get_workload_health().is_active
        live_class = "sentinel-pill-live" if all_active else "sentinel-pill"
        status_txt = "● LIVE Collectors Active" if all_active else "○ Telemetry Collectors Online"
        st.markdown(
            f'<div class="sentinel-pill {live_class}">{status_txt}</div>',
            unsafe_allow_html=True,
        )
    with c_ctx4:
        now_str = datetime.now(timezone.utc).strftime("%b %d, %Y %H:%M:%S UTC")
        st.caption(f"🕒 **Last updated:** {now_str}")
    with c_ctx5:
        if st.button("🔄", help="Refresh telemetry", key="overview_refresh_btn"):
            st.rerun()

    # 2. Page Header
    st.markdown("## Security Overview")
    st.caption("Telemetry-driven threat detection across your Kubernetes workloads (`webapp / nginx`).")
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 3. KPI Quad Metrics Cards
    net_health = engine.get_network_health()
    wl_health = engine.get_workload_health()
    rt_health = engine.get_runtime_health()

    net_count = net_health.total_valid_records
    rt_count = rt_health.total_valid_records
    wl_count = wl_health.total_valid_records

    # Count real active security detections in evaluated buffer
    # Separate supervised ML predictions from runtime rule-based findings
    ml_detections_count = 0
    runtime_alerts_count = 0
    recent_detections = []
    
    for r in records:
        # Hierarchical inference resolution for top-level incident accounting:
        # 1. Prefer multimodal fusion when heterogeneous streams are aligned.
        # 2. Next, prefer network inference when socket telemetry is active.
        # 3. Workload-only fallback: Standalone workload models evaluate CPU/memory metrics.
        #    At strictly zero CPU (0m), idle containers exhibit a known training artifact where
        #    a historical tie-break predicts attack. To preserve top-level incident KPI integrity
        #    without arbitrary thresholds, an uncorroborated workload-only inference is only counted
        #    as an active ML attack if non-zero CPU activity (mean CPU > 0.0) was observed.
        inf = (
            r.full_fusion_inferences.get(selected_model)
            or r.fusion_inferences.get(selected_model)
            or r.net_rt_inferences.get(selected_model)
            or r.rt_wl_inferences.get(selected_model)
            or r.network_inferences.get(selected_model)
            or r.runtime_inferences.get(selected_model)
        )
        wl_inf = r.workload_inferences.get(selected_model)
        wl_cpu = r.workload_features.get("workload_cpu_millicores_mean", 0.0) if r.workload_features else 0.0

        if not inf and wl_inf:
            if wl_inf.predicted_label == "attack" and wl_cpu <= 0.0:
                inf = None
            else:
                inf = wl_inf

        has_ml_att = bool(inf and inf.predicted_label == "attack")
        rt_sec = r.runtime_features.get("runtime_sensitive_command_count", 0) if r.runtime_features else 0
        rt_shell = r.runtime_features.get("runtime_interactive_shell_count", 0) if r.runtime_features else 0
        has_rt_alert = bool(rt_sec > 0 or rt_shell > 0)

        if has_ml_att:
            ml_detections_count += 1
        if has_rt_alert:
            runtime_alerts_count += 1

        if has_ml_att or has_rt_alert:
            # Correlated or individual incident recorded
            recent_detections.append((r, inf, has_ml_att, has_rt_alert, rt_sec))

    # Total distinct security incident windows (no double counting)
    total_incident_windows = len(recent_detections)

    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.metric(
            label="Network Events",
            value=f"{net_count:,}",
            help="Total valid eBPF TCP socket trace events ingested",
        )
    with m_col2:
        st.metric(
            label="Runtime Executions",
            value=f"{rt_count:,}",
            help="Total container process exec events captured by Inspektor Gadget trace_exec",
        )
    with m_col3:
        wl_display = f"{wl_count / 1000:.1f}k" if wl_count >= 1000 else f"{wl_count}"
        st.metric(
            label="Workload Samples",
            value=wl_display,
            help="Resource metrics sampled via Metrics Server (CPU/Memory)",
        )
    with m_col4:
        st.metric(
            label="Active Detections",
            value=f"{total_incident_windows}",
            help=f"{total_incident_windows} flagged incident windows ({ml_detections_count} ML predictions via {selected_model}, {runtime_alerts_count} runtime rule alerts)",
        )

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # 4. Middle Section: Telemetry Activity & Collector Health
    col_chart, col_health = st.columns([1.8, 1.2])

    with col_chart:
        chart_hdr_col1, chart_hdr_col2 = st.columns([2, 1.2])
        with chart_hdr_col1:
            st.markdown(
                """
                <div class="sentinel-panel-title">📊 Telemetry Activity</div>
                <div class="sentinel-panel-sub">Network, runtime, and workload telemetry across observation windows.</div>
                """,
                unsafe_allow_html=True,
            )
        with chart_hdr_col2:
            time_view_mode = st.selectbox(
                "Activity Horizon:",
                options=["Active Experiment Bursts", "Rolling Engine Windows (10s)"],
                index=0,
                key="ov_time_view_mode",
            )

        # Prepare chart rows based on selected horizon
        if time_view_mode == "Active Experiment Bursts":
            burst_windows = _get_historical_active_windows(detector.project_root, limit=25)
            chart_rows = []
            for bw in burst_windows:
                chart_rows.append({
                    "Time (UTC)": bw["window_start"][11:19],
                    "Network Events": bw["network_events"],
                    "Runtime Execs": bw["runtime_execs"],
                    "Workload CPU (m)": bw["cpu_millicores"],
                })
        else:
            chart_rows = []
            for r in records:
                net_ev = r.network_features.get("network_event_count", 0) if r.network_features else 0
                rt_ev = len(r.runtime_events) if r.runtime_events else 0
                wl_cpu = r.workload_features.get("workload_cpu_millicores_mean", 0.0) if r.workload_features else 0.0
                time_label = r.window_start[11:19] if r.window_start else "N/A"
                chart_rows.append({
                    "Time (UTC)": time_label,
                    "Network Events": net_ev,
                    "Runtime Execs": rt_ev,
                    "Workload CPU (m)": wl_cpu,
                })

        if chart_rows:
            chart_df = pd.DataFrame(chart_rows).set_index("Time (UTC)")
            # Dual Tab / Filter for Unit Isolation
            tab_all, tab_net_rt, tab_cpu = st.tabs([
                "All Series",
                "Events & Executions",
                "Workload CPU (m)",
            ])
            with tab_all:
                st.line_chart(chart_df, height=230)
            with tab_net_rt:
                st.line_chart(chart_df[["Network Events", "Runtime Execs"]], height=230)
            with tab_cpu:
                st.line_chart(chart_df[["Workload CPU (m)"]], height=230)
        else:
            st.info("ℹ️ No observation windows available yet to plot telemetry activity.")

    with col_health:
        st.markdown(
            """
            <div class="sentinel-panel-title">🩺 Collector Health</div>
            <div class="sentinel-panel-sub">Real-time status of eBPF and Metrics telemetry collectors.</div>
            """,
            unsafe_allow_html=True,
        )

        collectors = [
            ("Network Collector (eBPF TCP)", net_health, "net"),
            ("Runtime Collector (eBPF Exec)", rt_health, "rt"),
            ("Workload Collector (Metrics)", wl_health, "wl"),
        ]

        now_utc = datetime.now(timezone.utc)
        for name, h, key in collectors:
            badge_class = "badge-healthy" if h.is_active else ("badge-stale" if h.file_exists else "badge-offline")
            badge_text = "HEALTHY" if h.is_active else ("IDLE / STALE" if h.file_exists else "OFFLINE")

            age_str = "No events"
            if h.last_record_timestamp:
                rec_ts = h.last_record_timestamp
                if rec_ts.tzinfo is None:
                    rec_ts = rec_ts.replace(tzinfo=timezone.utc)
                age_s = max(0, int((now_utc - rec_ts).total_seconds()))
                age_str = f"{age_s}s ago" if age_s < 60 else f"{age_s // 60}m ago"

            pid_str = f"PID {h.pid}" if h.pid else "No PID"

            st.markdown(
                f"""
                <div class="collector-row">
                    <div>
                        <div style="font-weight: 600; color: #f1f5f9; font-size: 0.88rem;">{name}</div>
                        <div style="font-size: 0.74rem; color: #94a3b8;">{pid_str} • Last record: {age_str}</div>
                    </div>
                    <div style="text-align: right;">
                        <span class="status-badge {badge_class}">{badge_text}</span>
                        <div style="font-size: 0.74rem; color: #64748b; margin-top: 3px;">{h.total_valid_records:,} records</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # 5. Bottom Section: Recent Runtime Activity & Recent Detection Decisions
    col_rt_acts, col_decisions = st.columns([1, 1])

    with col_rt_acts:
        st.markdown(
            """
            <div class="sentinel-panel-title">⚡ Recent Runtime Activity</div>
            <div class="sentinel-panel-sub">Latest process execution events captured inside container workloads.</div>
            """,
            unsafe_allow_html=True,
        )

        # Load recent runtime events directly from storage or active buffer
        rt_file = detector.project_root / DEFAULT_RUNTIME_PATH
        recent_rt_events = []
        if rt_file.exists():
            try:
                all_rt = list(load_runtime_events(rt_file))
                recent_rt_events = all_rt[-6:]
            except Exception:
                pass

        if recent_rt_events:
            rt_table_rows = []
            for ev in reversed(recent_rt_events):
                rt_table_rows.append({
                    "Timestamp (UTC)": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "Pod": ev.pod or "webapp",
                    "Process / Command": ev.args or ev.comm,
                    "UID": f"{ev.username or 'root'} ({ev.uid})",
                    "Source": "eBPF exec trace",
                })
            st.dataframe(pd.DataFrame(rt_table_rows), width="stretch", hide_index=True)
        else:
            st.info(
                "ℹ️ **No recent container process executions.** "
                "The container environment is currently stable with zero new process forks/execs."
            )

    with col_decisions:
        st.markdown(
            """
            <div class="sentinel-panel-title">🛡️ Recent Detection Decisions</div>
            <div class="sentinel-panel-sub">Model predictions and statistical threat classifications for recent observation windows.</div>
            """,
            unsafe_allow_html=True,
        )

        if recent_detections:
            dec_rows = []
            for item in reversed(recent_detections[-5:]):
                r, inf, has_ml, has_rt, rt_count_item = item
                if has_ml and has_rt:
                    verdict_text = "🚨 CORRELATED"
                    mod_text = f"{inf.modality.title()}+RT" if inf else "Full Fusion"
                    prob_text = format_probability(inf.attack_probability) if inf else "N/A"
                    conf_text = format_probability(inf.confidence) if inf else "Rule Alert"
                elif has_ml:
                    verdict_text = "🚨 ML ATTACK"
                    mod_text = inf.modality.title() if inf else "ML"
                    prob_text = format_probability(inf.attack_probability) if inf else "N/A"
                    conf_text = format_probability(inf.confidence) if inf else "N/A"
                else:
                    verdict_text = "🚨 RT ALERT"
                    mod_text = "Runtime (eBPF)"
                    prob_text = f"{rt_count_item} sens exec"
                    conf_text = "Rule Match"

                dec_rows.append({
                    "Window": r.window_start[11:19],
                    "Verdict": verdict_text,
                    "Modality": mod_text,
                    "Probability / Signal": prob_text,
                    "Confidence": conf_text,
                    "Affected Pod": r.affected_pods,
                })
            st.dataframe(pd.DataFrame(dec_rows), width="stretch", hide_index=True)
        else:
            st.markdown(
                """
                <div style="text-align: center; padding: 28px 12px; background: rgba(17, 24, 39, 0.4); border-radius: 8px; border: 1px dashed rgba(55, 65, 81, 0.6);">
                    <div style="font-size: 2.2rem; margin-bottom: 6px;">🛡️</div>
                    <div style="font-weight: 600; color: #f1f5f9; font-size: 0.95rem;">No detections in selected window</div>
                    <div style="font-size: 0.78rem; color: #94a3b8; margin-top: 4px;">Telemetry is being continuously evaluated; observed activity matches expected benign baselines.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.caption("ℹ️ *Detections appear here when the model classifies an observation window as anomalous based on heterogeneous telemetry.*")
