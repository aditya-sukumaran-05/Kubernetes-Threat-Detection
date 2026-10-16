"""Runtime Events dedicated exploration component for Streamlit dashboard.

Presents first-class runtime process telemetry captured via Inspektor Gadget trace_exec:
searchable/sortable process table, process timeline, filters by pod, command, UID,
expandable raw event inspection, and CSV export.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from dashboard.live_engine import (
    DEFAULT_NETWORK_PATH,
    DEFAULT_RUNTIME_PATH,
    DEFAULT_WORKLOAD_PATH,
    LiveTelemetryEngine,
    LiveWindowRecord,
)
from ml.inference import ThreatDetector
from telemetry.schemas import RuntimeEvent, load_runtime_events


def render_runtime_events_page(
    detector: ThreatDetector,
    runtime_path: Path | str = DEFAULT_RUNTIME_PATH,
) -> None:
    """Render the Runtime Events page dedicated to eBPF process execution telemetry."""
    st.markdown("## 🛡️ Container Runtime Events (`trace_exec`)")
    st.caption(
        "First-class container runtime security telemetry captured via Inspektor Gadget eBPF process execution tracing. "
        "Captures process forks, binary executions, arguments, user IDs, and container namespace boundaries."
    )
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    raw_path = Path(runtime_path)
    resolved_path = raw_path if raw_path.is_absolute() else (detector.project_root / raw_path).resolve()

    if not resolved_path.exists():
        st.warning(
            f"⚠️ Runtime events file not found at `{resolved_path}`. "
            "Ensure the runtime collector is active or start it via: `python telemetry/runtime_collector.py`"
        )
        return

    # Load all runtime events from source
    try:
        events: list[RuntimeEvent] = load_runtime_events(resolved_path)
    except Exception as exc:
        st.error(f"Failed to load runtime events: {exc}")
        return

    # High-level Metrics Row
    total_events = len(events)
    unique_commands = len(set(e.comm for e in events)) if events else 0
    root_events = sum(1 for e in events if e.uid == 0) if events else 0
    sensitive_cmds = {"sh", "bash", "whoami", "id", "uname", "cat", "chmod", "chown", "curl", "wget", "nc"}
    sensitive_count = sum(1 for e in events if e.comm in sensitive_cmds) if events else 0

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Executions", f"{total_events:,}")
    with m2:
        st.metric("Unique Binaries", f"{unique_commands}")
    with m3:
        st.metric("Root Executions (UID 0)", f"{root_events}")
    with m4:
        st.metric("Sensitive Commands", f"{sensitive_count}")

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    if not events:
        st.info(
            "ℹ️ **No runtime process executions recorded yet.**\n\n"
            "The container environment has remained stable without new processes being spawned. "
            "Inspektor Gadget `trace_exec` triggers only when binaries or scripts run inside the container "
            "(e.g. during administrative maintenance or command execution attacks)."
        )
        return

    # Filters Row: Search, Pod, Command, User, Time Range
    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([1.8, 1.0, 1.0, 1.0, 1.2])
    with f_col1:
        search_query = st.text_input(
            "🔎 Search Arguments / Path / CWD:",
            value="",
            help="Filter events by matching string in arguments, executable path, or working directory.",
        )
    with f_col2:
        all_pods = sorted(set(e.pod or "webapp" for e in events))
        pod_sel = st.selectbox("Pod Filter:", options=["All Pods"] + all_pods, index=0)
    with f_col3:
        all_comms = sorted(set(e.comm for e in events))
        comm_sel = st.selectbox("Command Filter:", options=["All Commands"] + all_comms, index=0)
    with f_col4:
        all_uids = sorted(set(f"{e.username or 'root'} (UID {e.uid})" for e in events))
        uid_sel = st.selectbox("User Filter:", options=["All Users"] + all_uids, index=0)
    with f_col5:
        time_range_sel = st.selectbox(
            "Time Range:",
            options=["All Time", "Last 15 Minutes", "Last 1 Hour", "Last 24 Hours"],
            index=0,
            help="Filter process events within relative time window from now.",
        )

    # Apply filters
    filtered = events
    if pod_sel != "All Pods":
        filtered = [e for e in filtered if (e.pod or "webapp") == pod_sel]
    if comm_sel != "All Commands":
        filtered = [e for e in filtered if e.comm == comm_sel]
    if uid_sel != "All Users":
        filtered = [e for e in filtered if f"{e.username or 'root'} (UID {e.uid})" == uid_sel]
    if time_range_sel != "All Time":
        now_utc = datetime.now(timezone.utc)
        delta_map = {
            "Last 15 Minutes": timedelta(minutes=15),
            "Last 1 Hour": timedelta(hours=1),
            "Last 24 Hours": timedelta(hours=24),
        }
        cutoff = now_utc - delta_map[time_range_sel]
        filtered = [
            e for e in filtered
            if (e.timestamp.replace(tzinfo=timezone.utc) if e.timestamp.tzinfo is None else e.timestamp) >= cutoff
        ]
    if search_query.strip():
        q = search_query.strip().lower()
        filtered = [
            e for e in filtered
            if q in (e.args or "").lower() or q in (e.exepath or "").lower() or q in (e.cwd or "").lower() or q in e.comm.lower()
        ]

    st.caption(f"Showing **{len(filtered)}** of **{total_events}** process execution events.")

    # Convert to DataFrame
    table_rows = []
    for idx, e in enumerate(filtered, start=1):
        table_rows.append({
            "#": idx,
            "Timestamp (UTC)": e.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "Pod": e.pod or "webapp",
            "Command": e.comm,
            "Arguments": e.args or e.comm,
            "User": f"{e.username or 'root'} ({e.uid})",
            "PID": e.pid or "N/A",
            "PPID": f"{e.parent_comm} ({e.parent_pid})" if e.parent_comm else "N/A",
            "Executable Path": e.exepath or "N/A",
            "CWD": e.cwd or "N/A",
        })

    table_df = pd.DataFrame(table_rows)
    st.dataframe(table_df, width="stretch", hide_index=True)

    # Actions Row: CSV Export & Timeline
    btn_col1, btn_col2 = st.columns([1, 3])
    with btn_col1:
        csv_bytes = table_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Export Filtered Events (CSV)",
            data=csv_bytes,
            file_name="runtime_events_export.csv",
            mime="text/csv",
            key="btn_dl_runtime_events_csv",
        )

    # Expandable Detailed Event Inspector
    with st.expander("🔍 Inspect Individual Event JSON Payloads"):
        if filtered:
            selected_idx = st.number_input(
                "Select Event Index (#):",
                min_value=1,
                max_value=len(filtered),
                value=1,
                step=1,
            )
            target_ev = filtered[selected_idx - 1]
            st.json({
                "timestamp": target_ev.timestamp.isoformat(),
                "comm": target_ev.comm,
                "args": target_ev.args,
                "exepath": target_ev.exepath,
                "cwd": target_ev.cwd,
                "pid": target_ev.pid,
                "tid": target_ev.tid,
                "uid": target_ev.uid,
                "gid": target_ev.gid,
                "username": target_ev.username,
                "parent_comm": target_ev.parent_comm,
                "parent_pid": target_ev.parent_pid,
                "parent_exepath": target_ev.parent_exepath,
                "pod": target_ev.pod,
                "namespace": target_ev.namespace,
                "container_name": target_ev.container_name,
                "container_id": target_ev.container_id,
            })
