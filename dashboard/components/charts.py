"""Telemetry time series visualization component for network and workload dynamics."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st


def render_telemetry_charts(
    windows: list[dict[str, Any]], current_index: int, modality: str
) -> None:
    """Render time series charts for network and workload telemetry dynamics."""
    if not windows:
        st.warning("No telemetry time series data available for charting.")
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
        # Simplify ISO string to MM:SS or HH:MM:SS for cleaner axis
        chart_data["Time (UTC)"] = chart_data[time_col].astype(str).str.slice(11, 19)
    else:
        chart_data["Time (UTC)"] = [f"W{i+1}" for i in range(len(df))]

    # Network Telemetry Charts
    if modality in ("network", "fusion"):
        st.markdown("#### 🌐 Network Telemetry (eBPF TCP Trace)")
        net_col1, net_col2 = st.columns(2)

        with net_col1:
            st.caption("**Connection Rate (conn/sec) & Connection Count**")
            rate_cols = [c for c in ["network_connection_rate", "network_connection_count"] if c in chart_data.columns]
            if rate_cols:
                plot_df = chart_data.set_index("Time (UTC)")[rate_cols]
                st.line_chart(plot_df)

        with net_col2:
            st.caption("**Total TCP Socket Events & Unique Destination Ports**")
            event_cols = [c for c in ["network_event_count", "network_unique_destination_ports"] if c in chart_data.columns]
            if event_cols:
                plot_df = chart_data.set_index("Time (UTC)")[event_cols]
                st.line_chart(plot_df)

    # Workload Telemetry Charts
    if modality in ("workload", "fusion"):
        st.markdown("#### ⚡ Workload Telemetry (cgroup / Metrics Server)")
        work_col1, work_col2 = st.columns(2)

        with work_col1:
            st.caption("**CPU Utilization (Millicores Mean & Max)**")
            cpu_cols = [c for c in ["workload_cpu_millicores_mean", "workload_cpu_millicores_max"] if c in chart_data.columns]
            if cpu_cols:
                plot_df = chart_data.set_index("Time (UTC)")[cpu_cols]
                st.line_chart(plot_df)

        with work_col2:
            st.caption("**Memory Utilization (MiB Mean & Max)**")
            mem_cols = [c for c in ["workload_memory_mib_mean", "workload_memory_mib_max"] if c in chart_data.columns]
            if mem_cols:
                plot_df = chart_data.set_index("Time (UTC)")[mem_cols]
                st.line_chart(plot_df)
