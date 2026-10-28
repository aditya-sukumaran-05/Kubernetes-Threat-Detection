"""Unified Telemetry Explorer component for Streamlit dashboard.

Allows unified multi-modality exploration across Network (eBPF TCP), Runtime (eBPF Exec),
and Workload (Metrics Server) observation windows with time-range filtering,
modality breakdown, search/sort, time-series dynamics, and CSV exports.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from dashboard.components.charts import render_telemetry_charts
from dashboard.components.summary import format_probability
from dashboard.live_engine import (
    DEFAULT_NETWORK_PATH,
    DEFAULT_RUNTIME_PATH,
    DEFAULT_WORKLOAD_PATH,
    LiveTelemetryEngine,
    LiveWindowRecord,
)
from ml.inference import ThreatDetector


def render_telemetry_explorer(
    detector: ThreatDetector,
    capture_path: Path | str = DEFAULT_NETWORK_PATH,
    workload_path: Path | str = DEFAULT_WORKLOAD_PATH,
    runtime_path: Path | str = DEFAULT_RUNTIME_PATH,
    selected_model: str = "random_forest",
) -> None:
    """Render the unified Telemetry Explorer page."""
    st.markdown("## 🔍 Telemetry Explorer")
    st.caption(
        "Interactive multi-modality telemetry inspection across synchronized 10-second observation windows. "
        "Correlates Inspektor Gadget eBPF network socket traces, container process execution events, "
        "and cgroup / Metrics Server resource usage."
    )
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

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
    records: list[LiveWindowRecord] = engine.process_live_telemetry(model_name=selected_model)

    if not records:
        st.warning("⚠️ No observation windows available from current telemetry.")
        return

    # Explorer Tabs: Unified, Pairwise, Full Tri-Modal, and Dynamics
    tab_all_win, tab_pairwise, tab_tri_modal = st.tabs([
        "📋 Synchronized Observation Windows",
        "🔗 Dedicated Pairwise Correlations",
        "🌐 Full Tri-Modal Fusion",
    ])

    with tab_all_win:
        # Explorer Controls: Modality filter, Search box, Only Active Traffic toggle
        c_mod, c_search, c_filter = st.columns([1.8, 1.8, 1.4])
        with c_mod:
            mod_filter = st.selectbox(
                "Filter by Modality:",
                options=[
                    "All Modalities",
                    "Network Only (eBPF TCP)",
                    "Workload Only (Metrics Server)",
                    "Runtime Only (trace_exec)",
                    "Network + Workload (ML Benchmark)",
                    "Network + Runtime (Pairwise)",
                    "Runtime + Workload (Pairwise)",
                    "Full Tri-Modal Fusion",
                ],
                index=0,
                help="Filter observation windows by telemetry presence.",
                key="te_mod_filter",
            )
        with c_search:
            search_query = st.text_input(
                "Filter Windows (Pod, Time, Verdict):",
                value="",
                help="Search any text in the window summary table.",
                key="te_search_query",
            )
        with c_filter:
            only_active_net = st.checkbox(
                "Active Network Only",
                value=False,
                help="Hide windows without network socket events.",
                key="te_active_net_cb",
            )

        # Filter records based on controls
        filtered_records = []
        for r in records:
            if only_active_net and not r.network_available:
                continue
            if mod_filter == "Network Only (eBPF TCP)" and not r.network_available:
                continue
            elif mod_filter == "Workload Only (Metrics Server)" and not r.workload_available:
                continue
            elif mod_filter == "Runtime Only (trace_exec)" and not r.runtime_available:
                continue
            elif mod_filter == "Network + Workload (ML Benchmark)" and not r.is_fused:
                continue
            elif mod_filter == "Network + Runtime (Pairwise)" and not (r.network_available and r.runtime_available):
                continue
            elif mod_filter == "Runtime + Workload (Pairwise)" and not (r.runtime_available and r.workload_available):
                continue
            elif mod_filter == "Full Tri-Modal Fusion" and not (r.network_available and r.workload_available and r.runtime_available):
                continue

            filtered_records.append(r)

        # Convert to presentation rows
        history_rows: list[dict[str, Any]] = []
        for idx, r in enumerate(filtered_records, start=1):
            net_res = r.network_inferences.get(selected_model)
            wl_res = r.workload_inferences.get(selected_model)
            rt_res = r.runtime_inferences.get(selected_model)
            fus_res = r.fusion_inferences.get(selected_model)
            tri_res = r.full_fusion_inferences.get(selected_model)

            net_text = f"{net_res.predicted_label.upper()} ({format_probability(net_res.attack_probability)})" if net_res and net_res.attack_probability is not None else ("EVALUATED" if net_res else "Idle")
            wl_text = f"{wl_res.predicted_label.upper()} ({format_probability(wl_res.attack_probability)})" if wl_res and wl_res.attack_probability is not None else ("EVALUATED" if wl_res else "No Metrics")
            if r.runtime_available and rt_res:
                rt_text = f"{rt_res.predicted_label.upper()} ({format_probability(rt_res.attack_probability)})" if rt_res.attack_probability is not None else "EVALUATED"
            elif not r.runtime_available or len(r.runtime_events) == 0:
                rt_text = "No Execs (Idle)"
            else:
                rt_text = "Pending"

            if r.is_fused and fus_res:
                fus_text = f"{fus_res.predicted_label.upper()} ({format_probability(fus_res.attack_probability)})" if fus_res.attack_probability is not None else "EVALUATED"
            elif not r.network_available:
                fus_text = "Missing Network (Idle)"
            elif not r.workload_available:
                fus_text = "Missing Workload"
            else:
                fus_text = "Pending"

            if tri_res:
                tri_text = f"{tri_res.predicted_label.upper()} ({format_probability(tri_res.attack_probability)})" if tri_res.attack_probability is not None else "EVALUATED"
            elif r.is_tri_modal:
                tri_text = "Pending"
            else:
                active_cnt = sum([r.network_available, r.workload_available, r.runtime_available])
                tri_text = f"Partial ({active_cnt}/3)"

            net_events = r.network_features.get("network_event_count", 0) if r.network_features else 0
            rt_events = len(r.runtime_events) if r.runtime_events else 0
            rt_summary = f"{rt_events} execs" if rt_events > 0 else "0 execs"

            history_rows.append({
                "Window": idx,
                "Window Start (UTC)": r.window_start,
                "Window End (UTC)": r.window_end,
                "Network Verdict": net_text,
                "Workload Verdict": wl_text,
                "Runtime Verdict": rt_text,
                "Net+WL Verdict": fus_text,
                "Tri-Modal Verdict": tri_text,
                "Net Events": net_events,
                "Net Conn Rate": f"{r.network_features.get('network_connection_rate', 0.0):.2f}/s" if r.network_features else "0.00/s",
                "CPU Mean": f"{r.workload_features.get('workload_cpu_millicores_mean', 0.0):.1f}m" if r.workload_features else "N/A",
                "Runtime Execs": rt_summary,
                "Affected Pod": r.affected_pods,
            })

        if search_query.strip():
            q = search_query.strip().lower()
            history_rows = [r for r in history_rows if any(q in str(v).lower() for v in r.values())]

        hist_df = pd.DataFrame(history_rows)
        st.dataframe(hist_df, width="stretch", hide_index=True)

        if not hist_df.empty:
            csv_bytes = hist_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="⬇️ Export Filtered Windows (CSV)",
                data=csv_bytes,
                file_name="telemetry_explorer_windows.csv",
                mime="text/csv",
                key="btn_dl_explorer_windows_csv",
            )

    with tab_pairwise:
        st.markdown("### 🔗 Dedicated Pairwise Telemetry Exploration")
        st.caption("Inspect correlated pairs of telemetry sources time-aligned into 10-second observation windows.")

        pairwise_choice = st.radio(
            "Select Pairwise Correlation:",
            options=["Network + Runtime", "Runtime + Workload", "Network + Workload (Benchmark)"],
            horizontal=True,
            key="te_pairwise_radio",
        )

        if pairwise_choice == "Network + Runtime":
            st.markdown("#### 🌐 Network + 🛡️ Runtime Correlation")
            nr_rows = []
            for idx, r in enumerate(records, start=1):
                if r.network_available or r.runtime_available:
                    n_ev = r.network_features.get("network_event_count", 0) if r.network_features else 0
                    n_rate = r.network_features.get("network_connection_rate", 0.0) if r.network_features else 0.0
                    r_ev = len(r.runtime_events)
                    r_sec = r.runtime_features.get("runtime_sensitive_command_count", 0) if r.runtime_features else 0
                    r_root = r.runtime_features.get("runtime_root_exec_count", 0) if r.runtime_features else 0
                    net_res = r.network_inferences.get(selected_model)
                    net_verdict = net_res.predicted_label.upper() if net_res else "Idle"

                    corr_status = "Concurrent Socket + Exec" if (n_ev > 0 and r_ev > 0) else ("Socket Only" if n_ev > 0 else "Exec Only")
                    nr_rows.append({
                        "Window": idx,
                        "Window Start (UTC)": r.window_start,
                        "Correlation Status": corr_status,
                        "Net Events": n_ev,
                        "Net Conn Rate": f"{n_rate:.2f}/s",
                        "Net ML Verdict": net_verdict,
                        "Process Execs": r_ev,
                        "Root Execs (UID 0)": r_root,
                        "Sensitive Binaries": r_sec,
                        "Affected Pod": r.affected_pods,
                    })

            nr_df = pd.DataFrame(nr_rows)
            st.dataframe(nr_df, width="stretch", hide_index=True)
            if not nr_df.empty:
                st.download_button(
                    "⬇️ Export Network + Runtime Windows (CSV)",
                    data=nr_df.to_csv(index=False).encode("utf-8"),
                    file_name="pairwise_network_runtime.csv",
                    key="dl_pairwise_nr",
                )

        elif pairwise_choice == "Runtime + Workload":
            st.markdown("#### 🛡️ Runtime + ⚡ Workload Correlation")
            rw_rows = []
            for idx, r in enumerate(records, start=1):
                if r.runtime_available or r.workload_available:
                    r_ev = len(r.runtime_events)
                    r_sec = r.runtime_features.get("runtime_sensitive_command_count", 0) if r.runtime_features else 0
                    cpu_m = r.workload_features.get("workload_cpu_millicores_mean", 0.0) if r.workload_features else 0.0
                    mem_mib = r.workload_features.get("workload_memory_mib_mean", 0.0) if r.workload_features else 0.0
                    wl_res = r.workload_inferences.get(selected_model)
                    wl_verdict = wl_res.predicted_label.upper() if wl_res else "No Metrics"

                    corr_status = "Concurrent CPU + Exec" if (r_ev > 0 and r.workload_available) else ("Workload Only" if r.workload_available else "Exec Only")
                    rw_rows.append({
                        "Window": idx,
                        "Window Start (UTC)": r.window_start,
                        "Correlation Status": corr_status,
                        "Process Execs": r_ev,
                        "Sensitive Binaries": r_sec,
                        "CPU Mean": f"{cpu_m:.1f}m",
                        "Memory Mean": f"{mem_mib:.1f} MiB",
                        "Workload ML Verdict": wl_verdict,
                        "Affected Pod": r.affected_pods,
                    })

            rw_df = pd.DataFrame(rw_rows)
            st.dataframe(rw_df, width="stretch", hide_index=True)
            if not rw_df.empty:
                st.download_button(
                    "⬇️ Export Runtime + Workload Windows (CSV)",
                    data=rw_df.to_csv(index=False).encode("utf-8"),
                    file_name="pairwise_runtime_workload.csv",
                    key="dl_pairwise_rw",
                )

        else:
            st.markdown("#### 🌐 Network + ⚡ Workload (NetSoft Baseline Fusion)")
            nw_rows = []
            for idx, r in enumerate(records, start=1):
                if r.is_fused:
                    fus_res = r.fusion_inferences.get(selected_model)
                    fus_verdict = f"{fus_res.predicted_label.upper()} ({format_probability(fus_res.attack_probability)})" if fus_res else "Pending"
                    nw_rows.append({
                        "Window": idx,
                        "Window Start (UTC)": r.window_start,
                        "Net Events": r.network_features.get("network_event_count", 0) if r.network_features else 0,
                        "Net Conn Rate": f"{r.network_features.get('network_connection_rate', 0.0):.2f}/s" if r.network_features else "0.00/s",
                        "CPU Mean": f"{r.workload_features.get('workload_cpu_millicores_mean', 0.0):.1f}m" if r.workload_features else "N/A",
                        "Memory Mean": f"{r.workload_features.get('workload_memory_mib_mean', 0.0):.1f} MiB" if r.workload_features else "N/A",
                        "Fusion 24-Feat ML Verdict": fus_verdict,
                        "Affected Pod": r.affected_pods,
                    })

            nw_df = pd.DataFrame(nw_rows)
            st.dataframe(nw_df, width="stretch", hide_index=True)
            if not nw_df.empty:
                st.download_button(
                    "⬇️ Export Network + Workload Windows (CSV)",
                    data=nw_df.to_csv(index=False).encode("utf-8"),
                    file_name="pairwise_network_workload.csv",
                    key="dl_pairwise_nw",
                )

    with tab_tri_modal:
        st.markdown("### 🌐 Full Tri-Modal Multimodal Telemetry Fusion")
        st.caption("Synchronized observation windows correlating all 3 telemetry streams: eBPF TCP Sockets + Metrics Server CPU/RAM + eBPF Process Executions.")

        tri_rows = []
        for idx, r in enumerate(records, start=1):
            n_ev = r.network_features.get("network_event_count", 0) if r.network_features else 0
            n_rate = r.network_features.get("network_connection_rate", 0.0) if r.network_features else 0.0
            cpu_m = r.workload_features.get("workload_cpu_millicores_mean", 0.0) if r.workload_features else 0.0
            r_ev = len(r.runtime_events)
            r_sec = r.runtime_features.get("runtime_sensitive_command_count", 0) if r.runtime_features else 0

            streams_active = sum([r.network_available, r.workload_available, r.runtime_available])
            stream_badge = f"{streams_active}/3 Active"

            fus_res = r.fusion_inferences.get(selected_model) if r.is_fused else None
            fus_verdict = f"{fus_res.predicted_label.upper()} ({format_probability(fus_res.attack_probability)})" if fus_res else ("Incomplete Fusion" if not r.is_fused else "Pending")

            tri_res = r.full_fusion_inferences.get(selected_model)
            if tri_res:
                tri_verdict = f"{tri_res.predicted_label.upper()} ({format_probability(tri_res.attack_probability)})" if tri_res.attack_probability is not None else "EVALUATED"
            elif r.is_tri_modal:
                tri_verdict = "Pending"
            else:
                tri_verdict = f"Incomplete ({streams_active}/3)"

            tri_rows.append({
                "Window": idx,
                "Window Start (UTC)": r.window_start,
                "Telemetry Coverage": stream_badge,
                "Net Events": n_ev,
                "Net Conn Rate": f"{n_rate:.2f}/s",
                "CPU Mean": f"{cpu_m:.1f}m" if r.workload_available else "N/A",
                "Process Execs": r_ev,
                "Sensitive Binaries": r_sec,
                "Net+WL ML Verdict": fus_verdict,
                "Tri-Modal ML Verdict": tri_verdict,
                "Affected Pod": r.affected_pods,
            })

        tri_df = pd.DataFrame(tri_rows)
        st.dataframe(tri_df, width="stretch", hide_index=True)
        if not tri_df.empty:
            st.download_button(
                "⬇️ Export Tri-Modal Observation Windows (CSV)",
                data=tri_df.to_csv(index=False).encode("utf-8"),
                file_name="trimodal_observation_windows.csv",
                key="dl_trimodal_csv",
            )

    # Window Inspection & Time-Series Visualizer
    st.markdown("---")
    st.subheader("📈 Telemetry Time-Series Visualizer")
    if records:
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
            if r.runtime_features:
                merged_feat.update(r.runtime_features)
            chart_windows.append(merged_feat)

        target_idx = st.slider(
            "Inspect Specific Window Time-Series:",
            min_value=1,
            max_value=len(records),
            value=len(records),
            key="explorer_window_slider",
        ) - 1

        render_telemetry_charts(chart_windows, target_idx, "full_fusion")
