"""Traffic Simulation and Attack Generation View for K8S Sentinel SOC Dashboard."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from experiments.traffic_simulator import (
    DEFAULT_CLIENT_POD,
    DEFAULT_NAMESPACE,
    DEFAULT_TARGET_SERVICE,
    DEFAULT_WORKLOAD_POD,
    SIMULATION_RUNS_DIR,
    check_pod_running,
    execute_concurrent_attack_scenario,
    execute_network_burst_scenario,
    execute_runtime_anomaly_scenario,
    get_benign_traffic_status,
    is_benign_traffic_running,
    start_benign_traffic,
    stop_benign_traffic,
)

NETWORK_EVENTS_PATH = Path("telemetry/data/network/network_events.jsonl")
RUNTIME_EVENTS_PATH = Path("telemetry/data/runtime/runtime_events.jsonl")


def _read_jsonl_tail(path: Path, max_lines: int = 20) -> list[dict[str, Any]]:
    """Read the tail of a JSON Lines telemetry file safely."""
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in reversed(lines[-max_lines:]):
            stripped = line.strip()
            if stripped:
                try:
                    records.append(json.loads(stripped))
                except Exception:
                    continue
    except Exception:
        return []
    return records


def _load_simulation_runs() -> list[dict[str, Any]]:
    """Load past simulation sessions from experiments/simulation_runs/."""
    if not SIMULATION_RUNS_DIR.exists():
        return []
    runs: list[dict[str, Any]] = []
    for d in sorted(SIMULATION_RUNS_DIR.iterdir(), reverse=True):
        if d.is_dir():
            meta_path = d / "metadata.json"
            if meta_path.exists():
                try:
                    runs.append(json.loads(meta_path.read_text(encoding="utf-8")))
                except Exception:
                    continue
    return runs


def render_traffic_simulation_view(project_root: Path) -> None:
    """Render the interactive Traffic & Attack Simulation Controller."""
    st.markdown(
        """
        <div style="background: linear-gradient(90deg, #111827 0%, #1e1b4b 100%); 
                    border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 12px; 
                    padding: 16px 20px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h2 style="margin: 0; color: #f8fafc; font-size: 1.4rem; font-weight: 700; letter-spacing: -0.02em;">
                        ⚡ K8S TRAFFIC & ATTACK SIMULATION CONTROLLER
                    </h2>
                    <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 0.85rem;">
                        Controlled in-cluster traffic generation from dedicated client pods to webapp service with synchronized multi-sensor telemetry capture.
                    </p>
                </div>
                <div style="display: flex; gap: 8px;">
                    <span style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); 
                                 color: #34d399; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 600;">
                        CLUSTER: MINIKUBE
                    </span>
                    <span style="background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.4); 
                                 color: #60a5fa; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 600;">
                        eBPF: GADGET v0.55.1
                    </span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. Cluster & Pod Preflight Status Banner
    client_ok = check_pod_running(DEFAULT_CLIENT_POD, DEFAULT_NAMESPACE)
    net_events_tail = _read_jsonl_tail(NETWORK_EVENTS_PATH, max_lines=5)
    rt_events_tail = _read_jsonl_tail(RUNTIME_EVENTS_PATH, max_lines=5)

    col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)
    with col_stat1:
        pod_status_html = "<span style='color: #34d399;'>● RUNNING</span>" if client_ok else "<span style='color: #ef4444;'>● NOT FOUND</span>"
        st.markdown(
            f"""
            <div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 10px 14px;">
                <div style="font-size: 0.70rem; color: #94a3b8; font-weight: 600; text-transform: uppercase;">Traffic Generator Pod</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #f1f5f9; margin-top: 2px;">{DEFAULT_CLIENT_POD}</div>
                <div style="font-size: 0.75rem; margin-top: 4px;">Status: {pod_status_html}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_stat2:
        st.markdown(
            f"""
            <div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 10px 14px;">
                <div style="font-size: 0.70rem; color: #94a3b8; font-weight: 600; text-transform: uppercase;">Target Workload</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #f1f5f9; margin-top: 2px;">webapp:80</div>
                <div style="font-size: 0.75rem; margin-top: 4px; color: #38bdf8;">Service: {DEFAULT_TARGET_SERVICE}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_stat3:
        tcp_count = len(_read_jsonl_tail(NETWORK_EVENTS_PATH, max_lines=500))
        st.markdown(
            f"""
            <div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 10px 14px;">
                <div style="font-size: 0.70rem; color: #94a3b8; font-weight: 600; text-transform: uppercase;">Network Sensor (TCP)</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #f1f5f9; margin-top: 2px;">trace_tcp</div>
                <div style="font-size: 0.75rem; margin-top: 4px; color: #34d399;">Active Events: ~{tcp_count} logged</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_stat4:
        rt_count = len(_read_jsonl_tail(RUNTIME_EVENTS_PATH, max_lines=500))
        st.markdown(
            f"""
            <div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 10px 14px;">
                <div style="font-size: 0.70rem; color: #94a3b8; font-weight: 600; text-transform: uppercase;">Runtime Sensor (Exec)</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #f1f5f9; margin-top: 2px;">trace_exec</div>
                <div style="font-size: 0.75rem; margin-top: 4px; color: #a78bfa;">Active Events: ~{rt_count} logged</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # 2. Main Simulation Tabs
    tab_benign, tab_attacks, tab_telemetry, tab_history = st.tabs([
        "🟢 Continuous Benign Traffic",
        "💥 On-Demand Attack Scenarios",
        "📡 Live Sensor Event Stream",
        "📋 Simulation Run History",
    ])

    # TAB 1: Benign Traffic Generator
    with tab_benign:
        st.markdown("### 🟢 Background Benign Traffic Generator")
        st.caption(
            "Emulates realistic, low-rate user HTTP interactions with normal timing jitter. "
            "Establishes a baseline for network connection rate and container metrics."
        )

        benign_status = get_benign_traffic_status()
        is_running = is_benign_traffic_running()

        b_card_col1, b_card_col2, b_card_col3, b_card_col4 = st.columns(4)
        with b_card_col1:
            st.metric(
                "Generator Status",
                "● ACTIVE" if is_running else "○ STOPPED",
                delta="Online" if is_running else "Idle",
                delta_color="normal" if is_running else "off",
            )
        with b_card_col2:
            st.metric(
                "Total Requests",
                benign_status.get("total_requests", 0),
                delta=f"+{benign_status.get('successful_requests', 0)} ok",
            )
        with b_card_col3:
            tot = benign_status.get("total_requests", 0)
            succ = benign_status.get("successful_requests", 0)
            rate = f"{(succ / tot * 100):.1f}%" if tot > 0 else "100.0%"
            st.metric("Success Rate", rate)
        with b_card_col4:
            lat = benign_status.get("last_latency_ms", 0.0)
            st.metric("Last Latency", f"{lat:.1f} ms" if lat else "N/A")

        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

        ctl_col1, ctl_col2, ctl_col3 = st.columns([1, 1, 2])
        with ctl_col1:
            if st.button("▶️ Start Benign Traffic", type="primary", use_container_width=True, disabled=is_running):
                with st.spinner("Starting benign traffic generator..."):
                    res = start_benign_traffic()
                    st.success(f"Benign traffic started! (PID {res.get('pid')})")
                    st.rerun()

        with ctl_col2:
            if st.button("⏹️ Stop Benign Traffic", use_container_width=True, disabled=not is_running):
                with st.spinner("Stopping benign traffic generator..."):
                    res = stop_benign_traffic()
                    st.info("Benign traffic generator stopped.")
                    st.rerun()

        with ctl_col3:
            st.markdown(
                f"<div style='font-size: 0.80rem; color: #94a3b8; padding-top: 6px;'>"
                f"Client: <code>{benign_status.get('client_pod', DEFAULT_CLIENT_POD)}</code> | "
                f"Target: <code>{benign_status.get('target_service', DEFAULT_TARGET_SERVICE)}</code> | "
                f"Last Update: <code>{benign_status.get('last_update_utc', 'N/A')}</code>"
                f"</div>",
                unsafe_allow_html=True,
            )

    # TAB 2: On-Demand Attack Scenarios
    with tab_attacks:
        st.markdown("### 💥 On-Demand Controlled Attack Scenarios")
        st.caption(
            "Safely trigger reproducible, bounded attack scenarios directly against the local test cluster. "
            "All scenarios are strictly contained within `minikube` namespace `default`."
        )

        atk_col1, atk_col2, atk_col3 = st.columns(3)

        # Card 1: Network Burst
        with atk_col1:
            st.markdown(
                """
                <div style="background: #111827; border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 10px; padding: 14px; min-height: 310px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-weight: 700; color: #f87171; font-size: 1.05rem;">💥 Network Burst Flood</span>
                        <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; font-size: 0.70rem; padding: 2px 6px; border-radius: 4px; font-weight: 600;">HIGH-RATE TCP</span>
                    </div>
                    <p style="font-size: 0.80rem; color: #94a3b8; margin: 8px 0 12px 0;">
                        Generates a rapid sequence of HTTP requests from the client pod to port 80, spiking TCP connection rate and accept events.
                    </p>
                """,
                unsafe_allow_html=True,
            )
            nb_reqs = st.slider("Request Count", min_value=10, max_value=150, value=100, step=10, key="nb_reqs")
            nb_dur = st.slider("Max Duration (s)", min_value=5, max_value=30, value=10, step=5, key="nb_dur")

            if st.button("🚀 Launch Network Burst", type="primary", use_container_width=True, key="btn_nb"):
                with st.spinner(f"Launching {nb_reqs} burst requests..."):
                    session = execute_network_burst_scenario(requests=nb_reqs, duration_seconds=float(nb_dur))
                    if session.status == "completed":
                        st.success(
                            f"✅ Completed {session.requests_completed} requests in {session.duration_seconds:.2f}s! "
                            f"(Session: `{session.session_id}`)"
                        )
                    else:
                        st.error(f"❌ Burst execution status: {session.status}. Errors: {session.errors}")

            st.markdown("</div>", unsafe_allow_html=True)

        # Card 2: Runtime Container Introspection
        with atk_col2:
            st.markdown(
                """
                <div style="background: #111827; border: 1px solid rgba(168, 85, 247, 0.4); border-radius: 10px; padding: 14px; min-height: 310px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-weight: 700; color: #c084fc; font-size: 1.05rem;">🔍 Runtime Introspection</span>
                        <span style="background: rgba(168, 85, 247, 0.2); color: #c084fc; font-size: 0.70rem; padding: 2px 6px; border-radius: 4px; font-weight: 600;">IN-CONTAINER EXEC</span>
                    </div>
                    <p style="font-size: 0.80rem; color: #94a3b8; margin: 8px 0 12px 0;">
                        Executes harmless reconnaissance commands inside <code>webapp</code> (<code>id</code>, <code>whoami</code>, <code>uname -a</code>, <code>curl</code>) to trigger eBPF <code>trace_exec</code> events.
                    </p>
                """,
                unsafe_allow_html=True,
            )
            selected_cmds = st.multiselect(
                "Commands to Execute",
                options=["id", "whoami", "curl -I http://webapp", "uname -a", "date -u"],
                default=["id", "whoami", "curl -I http://webapp", "uname -a"],
                key="rt_cmds",
            )

            if st.button("🛡️ Launch Introspection Activity", use_container_width=True, key="btn_rt"):
                with st.spinner("Executing introspection commands inside webapp container..."):
                    session = execute_runtime_anomaly_scenario(commands=selected_cmds)
                    if session.status == "completed":
                        st.success(
                            f"✅ Executed {session.commands_completed}/{len(selected_cmds)} commands in {session.duration_seconds:.2f}s! "
                            f"(Session: `{session.session_id}`)"
                        )
                    else:
                        st.warning(f"⚠️ Completed {session.commands_completed} commands. Errors: {session.errors}")

            st.markdown("</div>", unsafe_allow_html=True)

        # Card 3: Concurrent Multi-Vector Attack
        with atk_col3:
            st.markdown(
                """
                <div style="background: #111827; border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 10px; padding: 14px; min-height: 310px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span style="font-weight: 700; color: #fbbf24; font-size: 1.05rem;">⚡ Concurrent Multi-Vector</span>
                        <span style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; font-size: 0.70rem; padding: 2px 6px; border-radius: 4px; font-weight: 600;">TRI-MODAL ANOMALY</span>
                    </div>
                    <p style="font-size: 0.80rem; color: #94a3b8; margin: 8px 0 12px 0;">
                        Launches simultaneous high-rate network requests AND container execution activity to evaluate heterogeneous telemetry fusion.
                    </p>
                """,
                unsafe_allow_html=True,
            )
            conc_reqs = st.slider("Burst Requests", min_value=20, max_value=80, value=40, step=10, key="conc_reqs")
            conc_dur = st.slider("Duration (s)", min_value=5, max_value=20, value=8, step=1, key="conc_dur")

            if st.button("💥 Launch Concurrent Attack", use_container_width=True, key="btn_conc"):
                with st.spinner("Executing synchronized network burst + container introspection..."):
                    session = execute_concurrent_attack_scenario(burst_requests=conc_reqs, duration_seconds=float(conc_dur))
                    if session.status == "completed":
                        st.success(
                            f"✅ Concurrent multi-vector attack completed! ({session.requests_completed} reqs, {session.commands_completed} cmds in {session.duration_seconds:.2f}s)\n"
                            f"Session: `{session.session_id}`"
                        )
                    else:
                        st.warning(f"Status: {session.status}. Errors: {session.errors}")

            st.markdown("</div>", unsafe_allow_html=True)

    # TAB 3: Live Sensor Event Stream
    with tab_telemetry:
        st.markdown("### 📡 Live Sensor Event Stream (Dual-Timestamp Provenance)")
        st.caption(
            "Inspect raw eBPF telemetry streaming directly from Minikube nodes. "
            "Every event features both kernel-space event time and user-space collector reception time."
        )

        stream_col1, stream_col2 = st.columns(2)

        with stream_col1:
            st.markdown("##### 🌐 Inspektor Gadget TCP Events (`network_events.jsonl`)")
            raw_tcp = _read_jsonl_tail(NETWORK_EVENTS_PATH, max_lines=15)
            if raw_tcp:
                tcp_rows = []
                for ev in raw_tcp:
                    tcp_rows.append({
                        "Type": ev.get("type"),
                        "Src IP": ev.get("src", {}).get("addr"),
                        "Src Port": ev.get("src", {}).get("port"),
                        "Dst IP": ev.get("dst", {}).get("addr"),
                        "Dst Port": ev.get("dst", {}).get("port"),
                        "Collector UTC": ev.get("collector_timestamp", "N/A"),
                        "eBPF Timestamp": ev.get("timestamp", "N/A"),
                    })
                st.dataframe(pd.DataFrame(tcp_rows), width="stretch", hide_index=True)
            else:
                st.info("No network events recorded yet.")

        with stream_col2:
            st.markdown("##### 🛡️ Inspektor Gadget Process Executions (`runtime_events.jsonl`)")
            raw_rt = _read_jsonl_tail(RUNTIME_EVENTS_PATH, max_lines=15)
            if raw_rt:
                rt_rows = []
                for ev in raw_rt:
                    rt_rows.append({
                        "Command Args": ev.get("args"),
                        "Comm": ev.get("proc", {}).get("comm"),
                        "Exe Path": ev.get("exepath"),
                        "User": ev.get("proc", {}).get("creds", {}).get("user"),
                        "Collector UTC": ev.get("collector_timestamp", "N/A"),
                        "eBPF Timestamp": ev.get("timestamp", "N/A"),
                    })
                st.dataframe(pd.DataFrame(rt_rows), width="stretch", hide_index=True)
            else:
                st.info("No runtime events recorded yet.")

    # TAB 4: Simulation Run History
    with tab_history:
        st.markdown("### 📋 Controlled Simulation Session History")
        runs = _load_simulation_runs()
        if not runs:
            st.info("No simulation sessions recorded in `experiments/simulation_runs/` yet.")
        else:
            summary_rows = []
            for r in runs:
                summary_rows.append({
                    "Session ID": r.get("session_id"),
                    "Scenario": r.get("scenario"),
                    "Status": r.get("status"),
                    "Requests": r.get("requests_completed"),
                    "Commands": r.get("commands_completed"),
                    "Duration (s)": r.get("duration_seconds"),
                    "Start UTC": r.get("start_time_utc"),
                    "End UTC": r.get("end_time_utc"),
                })
            df_runs = pd.DataFrame(summary_rows)
            st.dataframe(df_runs, width="stretch", hide_index=True)

            csv_data = df_runs.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="⬇️ Export Simulation Sessions (CSV)",
                data=csv_data,
                file_name="simulation_sessions.csv",
                mime="text/csv",
                key="btn_dl_sim_runs",
            )
