"""K8S Sentinel — Visual Client Attack Simulation Console.

A dedicated demonstrator console for the SWE3004 final-year capstone project.
Enables controlled generation of benign HTTP traffic and on-demand, bounded attack
scenarios against the test workload deployment/webapp in Minikube.

IMPORTANT ARCHITECTURAL SEPARATION:
- This console operates exclusively on the client/generator side and defines EXPERIMENTAL GROUND TRUTH.
- The SOC Threat Detection Dashboard (port 8501) performs independent telemetry observation and ML inference.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

# Add project root to sys.path if not present
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.correlation import correlate_client_session
from experiments.traffic_simulator import (
    DEFAULT_CLIENT_POD,
    DEFAULT_NAMESPACE,
    DEFAULT_TARGET_SERVICE,
    DEFAULT_WORKLOAD_POD,
    cancel_all_active_traffic,
    check_pod_running,
    execute_concurrent_attack_scenario,
    execute_cpu_stress_scenario,
    execute_network_burst_scenario,
    execute_runtime_anomaly_scenario,
    get_benign_traffic_status,
    is_benign_traffic_running,
    start_benign_traffic,
    stop_benign_traffic,
)
from telemetry.client_telemetry import (
    ClientSessionManifest,
    ClientTelemetryLogger,
    get_client_utc_now,
)

logger = logging.getLogger("client_console.app")

st.set_page_config(
    page_title="K8S Sentinel — Attack Simulation Console",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS styling
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #e2e8f0;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #94a3b8;
        margin-bottom: 1.2rem;
    }
    .ground-truth-banner {
        background-color: #1e293b;
        border-left: 5px solid #38bdf8;
        padding: 12px 18px;
        border-radius: 6px;
        margin-bottom: 20px;
        color: #cbd5e1;
        font-size: 0.95rem;
    }
    .status-card {
        background-color: #0f172a;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 15px;
    }
    .badge-running {
        background-color: #166534;
        color: #bbf7d0;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-stopped {
        background-color: #374151;
        color: #9ca3af;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-attack {
        background-color: #991b1b;
        color: #fecaca;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-safe {
        background-color: #1e3a8a;
        color: #bfdbfe;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .scenario-card {
        background-color: #1e1e2e;
        border: 1px solid #3b4261;
        border-radius: 8px;
        padding: 16px;
        height: 100%;
    }
    .soc-guide-box {
        background-color: #0f2338;
        border: 1px solid #0284c7;
        border-radius: 6px;
        padding: 14px;
        margin-top: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def init_session_state() -> None:
    if "last_action_message" not in st.session_state:
        st.session_state.last_action_message = None
    if "active_scenario_result" not in st.session_state:
        st.session_state.active_scenario_result = None


init_session_state()


def render_header() -> None:
    st.markdown('<div class="main-title">🎯 K8S Sentinel — Client Attack Simulation Console</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-title">Visual Control Plane for Live Traffic Simulation & Controlled Security Demonstrations</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="ground-truth-banner">
            <strong>⚠️ EXPERIMENTAL GROUND TRUTH SEPARATION:</strong><br>
            Actions triggered in this console establish <strong>ground-truth stimuli</strong> for evaluation.
            The independent <strong>SOC Threat Detection Dashboard</strong> (running on Port 8501) performs
            telemetry aggregation, temporal feature extraction, and machine-learning inference.
            Scenario selection defines what is occurring; ML models independently infer whether an intrusion is detected.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_target_status() -> None:
    st.subheader("📡 Cluster Infrastructure & Target Health")

    client_pod_healthy = check_pod_running(DEFAULT_CLIENT_POD, DEFAULT_NAMESPACE)
    benign_status = get_benign_traffic_status()
    benign_running = benign_status.get("is_process_alive", False)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Target Service",
            value="http://webapp:80",
            delta="Service Active",
            delta_color="normal",
        )

    with col2:
        st.metric(
            label="Client Generator Pod",
            value=f"pod/{DEFAULT_CLIENT_POD}",
            delta="Healthy / Running" if client_pod_healthy else "Pod Offline",
            delta_color="normal" if client_pod_healthy else "inverse",
        )

    with col3:
        st.metric(
            label="Target Workload",
            value=DEFAULT_WORKLOAD_POD,
            delta="Namespace: default",
            delta_color="off",
        )

    with col4:
        st.metric(
            label="Workload Isolation",
            value="pod/cpu-test",
            delta="SAFE (Untouched)",
            delta_color="normal",
        )

    st.divider()


def render_emergency_controls() -> None:
    col_em1, col_em2 = st.columns([3, 1])
    with col_em1:
        st.caption("Active safety supervisor: All scenarios are bounded by hard timeouts, explicit PID tracking, and rate limits.")
    with col_em2:
        if st.button("🛑 EMERGENCY CANCEL ALL", type="primary", use_container_width=True, help="Stop all traffic and clean up in-container stress"):
            res = cancel_all_active_traffic()
            st.session_state.last_action_message = f"🚨 Emergency stop initiated: Benign status: {res['benign_traffic'].get('status')}; CPU cleanup: {res['cpu_cleanup']}"
            st.rerun()


def render_benign_traffic_panel() -> None:
    st.subheader("🔄 Automated Benign Traffic Generation")
    benign_status = get_benign_traffic_status()
    running = benign_status.get("is_process_alive", False)

    col_ctrl, col_stats = st.columns([1, 2])

    with col_ctrl:
        st.markdown(
            f"**Current State:** <span class='{'badge-running' if running else 'badge-stopped'}'>{'● RUNNING' if running else '○ STOPPED'}</span>",
            unsafe_allow_html=True,
        )
        if running:
            st.caption(f"Process PID: `{benign_status.get('pid', 'N/A')}` | Started: `{benign_status.get('started_at_utc', 'N/A')[:19]}`")

        interval = st.slider("Base Interval (seconds)", min_value=1.0, max_value=8.0, value=2.0, step=0.5)
        jitter = st.slider("Interval Jitter (± seconds)", min_value=0.0, max_value=2.0, value=0.8, step=0.1)

        b_col1, b_col2 = st.columns(2)
        with b_col1:
            if st.button("▶️ Start Benign", disabled=running, use_container_width=True):
                res = start_benign_traffic(base_interval=interval, jitter=jitter)
                st.session_state.last_action_message = f"Started benign traffic generator (PID {res.get('pid')})"
                st.rerun()
        with b_col2:
            if st.button("⏹️ Stop Benign", disabled=not running, use_container_width=True):
                res = stop_benign_traffic()
                st.session_state.last_action_message = "Stopped benign traffic generator."
                st.rerun()

    with col_stats:
        m1, m2, m3, m4 = st.columns(4)
        total = benign_status.get("total_requests", 0)
        succ = benign_status.get("successful_requests", 0)
        failed = benign_status.get("failed_requests", 0)
        succ_rate = round((succ / total * 100.0), 1) if total > 0 else 100.0

        with m1:
            st.metric("Total Requests", f"{total:,}")
        with m2:
            st.metric("Successful", f"{succ:,}")
        with m3:
            st.metric("Failed", f"{failed:,}")
        with m4:
            st.metric("Success Rate", f"{succ_rate}%")

        st.info(
            f"**Telemetry Signature:** Continuous low-rate HTTP traffic (~0.5 req/s) with Gaussian timing jitter. "
            f"Produces normal server-side TCP handshakes and keeps the baseline feature window healthy. "
            f"Last measured latency: `{benign_status.get('last_latency_ms', 0.0)} ms`."
        )

    st.divider()


def render_attack_scenarios() -> None:
    st.subheader("⚡ Manual Attack Scenario Injection (Red-Team Controls)")
    st.caption("Each scenario simulates a bounded threat condition with safe duration limits and operator confirmation.")

    sc1, sc2, sc3, sc4 = st.columns(4)

    # 1. HTTP Network Burst Flood
    with sc1:
        st.markdown("#### 🌊 Network Request Burst")
        st.markdown("<span class='badge-attack'>eBPF TCP Anomaly</span>", unsafe_allow_html=True)
        st.write("Generates rapid back-to-back HTTP GET requests to saturate server connection rate.")
        burst_reqs = st.slider("Burst Requests", min_value=20, max_value=100, value=50, step=10, key="nb_reqs")
        burst_dur = st.slider("Duration (seconds)", min_value=4.0, max_value=20.0, value=10.0, step=1.0, key="nb_dur")
        burst_confirm = st.checkbox("Confirm Network Burst", key="nb_conf")

        if st.button("🚀 Launch Burst Flood", disabled=not burst_confirm, use_container_width=True):
            with st.spinner(f"Executing {burst_reqs} request burst flood over {burst_dur}s..."):
                session = execute_network_burst_scenario(requests=burst_reqs, duration_seconds=burst_dur)
                st.session_state.active_scenario_result = session.to_dict()
                st.session_state.last_action_message = f"Network burst completed: {session.requests_completed} completed in {session.duration_seconds}s"
                st.rerun()

    # 2. In-Pod Workload / CPU Stress
    with sc2:
        st.markdown("#### ⚡ In-Pod CPU Stress")
        st.markdown("<span class='badge-attack'>Metrics Anomaly</span>", unsafe_allow_html=True)
        st.write("Spawns a controlled tight CPU loop in `deployment/webapp` via marked PID file.")
        cpu_dur = st.slider("Stress Duration (s)", min_value=3.0, max_value=30.0, value=10.0, step=1.0, key="cpu_dur")
        st.caption("Target: `deployment/webapp` strictly. `pod/cpu-test` is NEVER touched.")
        cpu_confirm = st.checkbox("Confirm CPU Stress", key="cpu_conf")

        if st.button("⚡ Launch CPU Stress", disabled=not cpu_confirm, use_container_width=True):
            with st.spinner(f"Running marked CPU stress for {cpu_dur}s in deployment/webapp..."):
                session = execute_cpu_stress_scenario(duration_seconds=cpu_dur)
                st.session_state.active_scenario_result = session.to_dict()
                st.session_state.last_action_message = f"CPU stress scenario completed: status {session.status} in {session.duration_seconds}s"
                st.rerun()

    # 3. In-Container Runtime Introspection
    with sc3:
        st.markdown("#### 🔍 Runtime Introspection")
        st.markdown("<span class='badge-attack'>eBPF Exec Anomaly</span>", unsafe_allow_html=True)
        st.write("Executes harmless audit and reconnaissance commands inside `deployment/webapp`.")
        st.code("id\nwhoami\ncurl -I http://webapp\nuname -a", language="bash")
        rt_confirm = st.checkbox("Confirm Introspection", key="rt_conf")

        if st.button("🔍 Launch Introspection", disabled=not rt_confirm, use_container_width=True):
            with st.spinner("Executing non-destructive runtime introspection commands..."):
                session = execute_runtime_anomaly_scenario()
                st.session_state.active_scenario_result = session.to_dict()
                st.session_state.last_action_message = f"Runtime introspection finished: {session.commands_completed} commands executed."
                st.rerun()

    # 4. Concurrent Multimodal Attack
    with sc4:
        st.markdown("#### 🔥 Concurrent Multimodal Attack")
        st.markdown("<span class='badge-attack'>Full Fusion Scenario</span>", unsafe_allow_html=True)
        st.write("Simultaneously generates network burst flood and in-container process executions.")
        st.caption("Triggers Precedence Rule 1 in SOC Tri-Modal Fusion.")
        con_confirm = st.checkbox("Confirm Concurrent Attack", key="con_conf")

        if st.button("🔥 Launch Multimodal Attack", disabled=not con_confirm, use_container_width=True):
            with st.spinner("Executing concurrent burst and container exec..."):
                session = execute_concurrent_attack_scenario(burst_requests=40, duration_seconds=8.0)
                st.session_state.active_scenario_result = session.to_dict()
                st.session_state.last_action_message = f"Concurrent attack finished: {session.requests_completed} reqs, {session.commands_completed} cmds."
                st.rerun()

    st.divider()


def render_last_action_banner() -> None:
    if st.session_state.last_action_message:
        st.success(f"**Console Action:** {st.session_state.last_action_message}")
        if st.button("Dismiss Message"):
            st.session_state.last_action_message = None
            st.rerun()


def render_recent_activity_and_correlation() -> None:
    st.subheader("📋 Experiment Sessions & SOC Telemetry Correlation")

    client_logger = ClientTelemetryLogger()
    sessions = client_logger.list_sessions(limit=30)

    if not sessions:
        st.info("No experiment sessions recorded yet. Start benign traffic or trigger an attack scenario above.")
        return

    session_options = {
        f"{s.session_id} [{s.scenario}] ({s.status.upper()}) - {s.start_time_utc[:19]}": s.session_id
        for s in sessions
    }

    selected_display = st.selectbox(
        "Select Session to Inspect & Correlate with Server Telemetry:",
        options=list(session_options.keys()),
    )
    selected_id = session_options[selected_display]

    # Perform Correlation Analysis
    report = correlate_client_session(selected_id, project_root=PROJECT_ROOT, logger=client_logger)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Session Scenario", report.scenario)
    with c2:
        st.metric("Client Status", report.client_status.upper())
    with c3:
        st.metric("Client Duration", f"{report.client_duration_seconds:.1f} s")
    with c4:
        grade_color = {
            "strongly_correlated": "🟢 Strongly Correlated",
            "partially_correlated": "🟡 Partially Correlated",
            "uncorrelated": "⚪ Uncorrelated",
        }.get(report.correlation_grade, report.correlation_grade)
        st.metric("Telemetry Correlation", grade_color)

    # Server Observation Summary
    st.markdown("##### 🔬 Server-Side Telemetry Observed in Session Window(s)")
    sm1, sm2, sm3, sm4 = st.columns(4)
    with sm1:
        st.metric("Server Network Events", f"{report.server_network_events:,}")
    with sm2:
        st.metric("Server Runtime Events", f"{report.server_runtime_events:,}")
    with sm3:
        st.metric("Workload Samples", f"{report.server_workload_samples:,}")
    with sm4:
        st.metric("Max Conn Rate", f"{report.server_max_connection_rate:.1f} conn/s")

    # Display SOC Operator Guide
    guide = report.soc_navigation_guide
    if guide:
        st.markdown(
            f"""
            <div class="soc-guide-box">
                <h4 style="margin-top:0; color:#38bdf8;">🧭 Operator SOC Navigation Guide for this Session</h4>
                <p><strong>Recommended SOC Page:</strong> <code>{guide.get('recommended_page', 'N/A')}</code><br>
                <strong>Recommended Modality:</strong> <code>{guide.get('recommended_modality', 'N/A')}</code><br>
                <strong>Primary Observation Window:</strong> <code>{guide.get('primary_window', 'N/A')}</code></p>
                <p><strong>Expected Telemetry Signature:</strong><br><em>{guide.get('expected_signature', 'N/A')}</em></p>
                <p><strong>Ground Truth Context:</strong><br>{guide.get('ground_truth_note', 'N/A')}</p>
                <strong>Operator Demonstration Steps:</strong>
                <ul>
                    {"".join(f"<li>{step}</li>" for step in guide.get('instructions', []))}
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Observation Windows Association Breakdown
    with st.expander("🔍 View Detailed Window-by-Window Correlation Breakdown"):
        st.caption(report.uncertainty_explanation)
        if report.window_details:
            st.table(report.window_details)
        else:
            st.write("No window details available.")


def render_live_request_feed() -> None:
    st.subheader("📊 Live Client-Side Request Stream")

    client_logger = ClientTelemetryLogger()
    requests_path = client_logger.requests_log

    if not requests_path.exists():
        st.info("No client request logs found in telemetry/data/client/requests.jsonl yet.")
        return

    # Read last 25 lines efficiently
    records: list[dict[str, Any]] = []
    try:
        with open(requests_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            for line in lines[-25:]:
                line = line.strip()
                if line and line.startswith("{"):
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        continue
    except Exception as exc:
        st.error(f"Error reading requests log: {exc}")
        return

    if records:
        recent_records = list(reversed(records))
        durations = [r.get("duration_ms", 0.0) for r in records]
        summary = client_logger.compute_latency_summary(durations)

        l1, l2, l3, l4 = st.columns(4)
        with l1:
            st.metric("Sample Latency (Mean)", f"{summary['mean_ms']} ms")
        with l2:
            st.metric("Median (p50)", f"{summary['p50_ms']} ms")
        with l3:
            st.metric("p95 Latency", f"{summary['p95_ms']} ms")
        with l4:
            st.metric("Max Latency", f"{summary['max_ms']} ms")

        # Table formatting
        formatted_table = [
            {
                "Time (UTC)": r.get("client_timestamp_utc", "")[:19],
                "Request ID": r.get("request_id", ""),
                "Method": r.get("method", "GET"),
                "Target": r.get("target_service", ""),
                "Status": r.get("status_code", 0),
                "Latency (ms)": r.get("duration_ms", 0.0),
                "Result": "✅ Success" if r.get("success") else f"❌ {r.get('error_category')}",
            }
            for r in recent_records[:15]
        ]
        st.dataframe(formatted_table, use_container_width=True)


def main() -> None:
    render_header()
    render_last_action_banner()
    render_target_status()
    render_emergency_controls()

    tab_sim, tab_history, tab_stream = st.tabs([
        "🎮 Attack & Traffic Controls",
        "📋 Experiment History & Correlation",
        "📊 Live Client Request Stream",
    ])

    with tab_sim:
        render_benign_traffic_panel()
        render_attack_scenarios()

    with tab_history:
        render_recent_activity_and_correlation()

    with tab_stream:
        render_live_request_feed()

    # Sidebar controls
    with st.sidebar:
        st.image("https://raw.githubusercontent.com/kubernetes/kubernetes/master/logo/logo.png", width=70)
        st.title("K8S Sentinel")
        st.markdown("**Client Attack Console**")
        st.caption("Version 2.0 — Dual-Console Demo Ready")
        st.divider()

        st.markdown(
            """
            **Console Endpoints:**
            - 🎯 **Attack Console:** `http://localhost:8502`
            - 🛡️ **SOC Dashboard:** `http://localhost:8501`
            """
        )
        st.divider()

        if st.button("🔄 Refresh Console Data", use_container_width=True):
            st.rerun()

        st.caption(f"Host UTC: {get_client_utc_now()[:19]}Z")


if __name__ == "__main__":
    main()
