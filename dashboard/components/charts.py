"""Telemetry time series visualization component for network, runtime, and workload dynamics."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st


def render_telemetry_charts(
    windows: list[dict[str, Any]], current_index: int, modality: str = "fusion"
) -> None:
    """Render structured, unit-isolated time series charts for network, runtime, and workload dynamics."""
    if not windows:
        st.info("ℹ️ No telemetry observation windows available for charting.")
        return

    df = pd.DataFrame(windows)
    time_col = "window_start" if "window_start" in df.columns else None

    current_window = windows[current_index] if 0 <= current_index < len(windows) else None
    current_time = current_window.get("window_start", f"Index {current_index}") if current_window else ""

    st.subheader("📈 Telemetry Dynamics Across Observation Windows")
    st.info(f"📍 **Inspecting Window {current_index + 1} of {len(windows)}** (`{current_time}`)")

    # Prepare DataFrame with concise time index if window_start is available
    chart_data = df.copy()
    if time_col:
        chart_data["Time (UTC)"] = chart_data[time_col].astype(str).str.slice(11, 19)
    else:
        chart_data["Time (UTC)"] = [f"W{i+1}" for i in range(len(df))]

    # 1. Network Telemetry Charts
    show_network = modality in ("network", "fusion", "net_wl", "net_rt", "full_fusion", "all")
    if show_network:
        st.markdown("#### 🌐 Network Telemetry (eBPF TCP Trace)")
        net_col1, net_col2 = st.columns(2)

        with net_col1:
            st.caption("**Connection Rate (conn/sec) & Connection Count**")
            rate_cols = [c for c in ["network_connection_rate", "network_connection_count"] if c in chart_data.columns]
            if rate_cols:
                plot_df = chart_data.set_index("Time (UTC)")[rate_cols]
                st.line_chart(plot_df)
            else:
                st.info("No network connection rate/count metrics in selected window series.")

        with net_col2:
            st.caption("**Total TCP Socket Events & Unique Destination Ports**")
            event_cols = [c for c in ["network_event_count", "network_unique_destination_ports"] if c in chart_data.columns]
            if event_cols:
                plot_df = chart_data.set_index("Time (UTC)")[event_cols]
                st.line_chart(plot_df)
            else:
                st.info("No network event count metrics in selected window series.")

    # 2. Runtime Telemetry Charts
    show_runtime = modality in ("runtime", "net_rt", "rt_wl", "full_fusion", "all") or any(
        c in chart_data.columns for c in ["runtime_event_count", "runtime_root_exec_count"]
    )
    if show_runtime:
        st.markdown("#### 🛡️ Runtime Telemetry (eBPF Process Exec Trace)")
        rt_col1, rt_col2 = st.columns(2)

        with rt_col1:
            st.caption("**Process Execution Count & Execution Rate (exec/sec)**")
            rt_rate_cols = [c for c in ["runtime_event_count", "runtime_exec_rate"] if c in chart_data.columns]
            if rt_rate_cols:
                plot_df = chart_data.set_index("Time (UTC)")[rt_rate_cols]
                st.line_chart(plot_df)
            else:
                st.caption("No runtime execution counts recorded in selected windows (0 process execs).")

        with rt_col2:
            st.caption("**Privilege & Security Flags (Root Execs & Sensitive Commands)**")
            sec_cols = [c for c in ["runtime_root_exec_count", "runtime_sensitive_command_count"] if c in chart_data.columns]
            if sec_cols:
                plot_df = chart_data.set_index("Time (UTC)")[sec_cols]
                st.line_chart(plot_df)
            else:
                st.caption("No root or sensitive executions recorded in selected windows.")

    # 3. Workload Telemetry Charts
    show_workload = modality in ("workload", "fusion", "net_wl", "rt_wl", "full_fusion", "all")
    if show_workload:
        st.markdown("#### ⚡ Workload Telemetry (cgroup / Metrics Server)")
        work_col1, work_col2 = st.columns(2)

        with work_col1:
            st.caption("**CPU Utilization (Millicores Mean & Max)**")
            cpu_cols = [c for c in ["workload_cpu_millicores_mean", "workload_cpu_millicores_max"] if c in chart_data.columns]
            if cpu_cols:
                plot_df = chart_data.set_index("Time (UTC)")[cpu_cols]
                st.line_chart(plot_df)
            else:
                st.info("No CPU workload samples in selected window series.")

        with work_col2:
            st.caption("**Memory Utilization (MiB Mean & Max)**")
            mem_cols = [c for c in ["workload_memory_mib_mean", "workload_memory_mib_max"] if c in chart_data.columns]
            if mem_cols:
                plot_df = chart_data.set_index("Time (UTC)")[mem_cols]
                st.line_chart(plot_df)
            else:
                st.info("No Memory workload samples in selected window series.")
