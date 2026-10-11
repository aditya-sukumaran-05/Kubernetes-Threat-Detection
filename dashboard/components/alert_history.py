"""Active buffer alert view and telemetry data health component for Streamlit dashboard.

Displays active in-memory alert logs (retained up to 50 observation windows), export facilities (CSV/JSON),
and collector health diagnostics without inventing records or claiming persistent database storage.
"""

from __future__ import annotations

import io
import json
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
    LiveTelemetryEngine,
)
from ml.inference import ThreatDetector


def render_alert_history(
    detector: ThreatDetector,
    capture_path: Path | str = DEFAULT_NETWORK_PATH,
    workload_path: Path | str = DEFAULT_WORKLOAD_PATH,
    runtime_path: Path | str = DEFAULT_RUNTIME_PATH,
) -> None:
    """Render the Active Buffer Alert View & Telemetry Health view."""
    st.header("📋 Active Buffer Alert View & Telemetry Health")
    st.caption(
        "Inspect active in-memory detection alerts (retaining up to 50 observation windows), "
        "verify collector process health, and export bounded observation records for auditing. "
        "*(Note: This view displays the active in-memory telemetry buffer, not a persistent database.)*"
    )

    # 1. Retrieve or initialize persistent LiveTelemetryEngine in session state
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
    # Incrementally ingest current records
    records = engine.process_live_telemetry(model_name="random_forest")

    # 2. Telemetry Collectors Operational Status Table
    st.subheader("🖥️ Telemetry Collectors Operational Status")
    collectors_health = [
        engine.get_network_health(),
        engine.get_workload_health(),
        engine.get_runtime_health(),
    ]

    health_rows = []
    now_utc = datetime.now(timezone.utc)
    for h in collectors_health:
        pid_val = str(h.pid) if h.pid else "Inactive"
        file_sz = f"{h.file_path.stat().st_size / 1024:.1f} KB" if h.file_path.exists() else "Missing"

        freshness = "No events"
        if h.last_record_timestamp:
            try:
                rec_ts = h.last_record_timestamp
                if rec_ts.tzinfo is None:
                    rec_ts = rec_ts.replace(tzinfo=timezone.utc)
                age_s = max(0, int((now_utc - rec_ts).total_seconds()))
                freshness = f"Fresh ({age_s}s ago)" if age_s <= 60 else f"⚠️ Stale ({age_s}s ago)"
            except Exception:
                freshness = "Recorded"

        health_rows.append({
            "Collector Source": h.source_name,
            "Capture File": h.file_path.name,
            "Status": h.status_message,
            "Process PID": pid_val,
            "File Size": file_sz,
            "Valid Records": h.total_valid_records,
            "Skipped/Malformed": h.malformed_records,
            "Telemetry Freshness": freshness,
        })

    health_df = pd.DataFrame(health_rows)
    st.dataframe(health_df, width="stretch", hide_index=True)

    st.markdown("---")

    # 3. Compile Alert Records from Evaluated Windows
    alert_rows: list[dict[str, Any]] = []
    all_window_rows: list[dict[str, Any]] = []

    for idx, r in enumerate(records, start=1):
        # Inspect all available model inferences for threats
        inferences = {
            "network": r.network_inferences.get("random_forest"),
            "workload": r.workload_inferences.get("random_forest"),
            "fusion": r.fusion_inferences.get("random_forest") if r.is_fused else None,
        }

        # Check if any dimension detected an attack
        for modality, inf in inferences.items():
            if inf is not None:
                record_entry = {
                    "Window #": idx,
                    "Window Start (UTC)": r.window_start,
                    "Window End (UTC)": r.window_end,
                    "Modality": modality.title(),
                    "Model": inf.model_name.replace("_", " ").title(),
                    "Verdict": inf.predicted_label.upper(),
                    "Attack Probability": format_probability(inf.attack_probability),
                    "Confidence": format_probability(inf.confidence),
                    "Affected Pod(s)": r.affected_pods,
                    "Net Events": r.network_features.get("network_event_count", 0) if r.network_features else 0,
                    "CPU Mean": f"{r.workload_features.get('workload_cpu_millicores_mean', 0.0):.1f}m" if r.workload_features else "N/A",
                }
                all_window_rows.append(record_entry)
                if inf.predicted_label == "attack":
                    alert_rows.append(record_entry)

    # 4. Active Threat Alerts Table
    st.subheader("🚨 Active Buffer Threat Incident Alerts Log")
    st.caption("Displays observation windows in the active in-memory buffer flagged as anomalous or attack behavior by active ML models.")

    c_filter1, c_filter2 = st.columns([2, 1])
    with c_filter1:
        view_all = st.checkbox("📋 Show all evaluated windows (including benign)", value=False)
    with c_filter2:
        st.caption(f"Total Alerts: **{len(alert_rows)}** | Total Evaluated Windows: **{len(records)}**")

    display_df = pd.DataFrame(all_window_rows if view_all else alert_rows)
    if display_df.empty:
        if view_all:
            st.info("ℹ️ No observation windows have been evaluated yet.")
        else:
            st.success("✅ No threat alerts detected in the current observation buffer. All evaluated windows are benign.")
    else:
        st.dataframe(display_df, width="stretch", hide_index=True)

    # 5. Data Export Facility (CSV / JSON)
    st.markdown("---")
    st.subheader("📥 Export Evaluated Records (Active Buffer)")

    buf_start_str = records[0].window_start if records else "empty"
    buf_end_str = records[-1].window_end if records else "empty"
    st.caption(
        f"Export bounded observation records from active in-memory buffer "
        f"(Temporal buffer range: `{buf_start_str}` to `{buf_end_str}`) for incident response auditing or academic reports."
    )

    clean_start = buf_start_str.replace(":", "").replace("-", "").replace(".", "")[:15]
    clean_end = buf_end_str.replace(":", "").replace("-", "").replace(".", "")[:15]

    exp_col1, exp_col2 = st.columns(2)
    with exp_col1:
        if alert_rows:
            csv_buf = io.StringIO()
            pd.DataFrame(alert_rows).to_csv(csv_buf, index=False)
            st.download_button(
                label="📥 Download Threat Alerts (CSV)",
                data=csv_buf.getvalue(),
                file_name=f"k8s_threat_alerts_buffer_{clean_start}_to_{clean_end}.csv",
                mime="text/csv",
                help="Download filtered alert incidents from the active buffer as CSV.",
            )
        else:
            st.button("📥 Download Threat Alerts (CSV)", disabled=True, help="No threat alerts available to export.")

    with exp_col2:
        if all_window_rows:
            json_str = json.dumps(all_window_rows, indent=2)
            st.download_button(
                label="📥 Download All Evaluated Windows (JSON)",
                data=json_str,
                file_name=f"k8s_active_buffer_windows_{clean_start}_to_{clean_end}.json",
                mime="application/json",
                help="Download all observation window records from the active buffer as JSON.",
            )
        else:
            st.button("📥 Download All Evaluated Windows (JSON)", disabled=True, help="No records available to export.")
