"""Main Streamlit application for the Kubernetes Threat Detection System."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is available on sys.path when executed via `streamlit run dashboard/app.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from dashboard.components.alert_history import render_alert_history
from dashboard.components.charts import render_telemetry_charts
from dashboard.components.evidence import render_evidence
from dashboard.components.live_capture import render_live_capture
from dashboard.components.manual_input import render_manual_input
from dashboard.components.research_diagnostics import render_research_diagnostics
from dashboard.components.summary import format_probability, render_detection_summary
from dashboard.telemetry_provider import CapturedDatasetProvider
from ml.inference import InferenceSchemaError, ThreatDetector

NAV_LIVE = "Live Threat Monitoring"
NAV_RESEARCH = "Research & Diagnostics"
NAV_ALERTS = "Alert History & Telemetry Health"
NAV_REPLAY = "Historical Replay & Testing"


def build_app() -> None:
    """Build and render the Streamlit threat detection dashboard."""
    st.set_page_config(
        page_title="Kubernetes Threat Detection System",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # 1. Header
    st.title("🛡️ Kubernetes Threat Detection System")
    st.markdown(
        "A heterogeneous machine-learning threat detection framework identifying anomalous "
        "and attack behavior in Kubernetes environments using eBPF network telemetry "
        "and container workload metrics."
    )
    st.markdown("---")

    # Initialize Backend Services
    detector = ThreatDetector(project_root=PROJECT_ROOT)
    provider = CapturedDatasetProvider()

    # 2. Configuration Sidebar
    st.sidebar.header("⚙️ Detection Configuration")

    # Primary Navigation (Live Monitoring prioritized as primary product experience)
    nav_icons = {
        NAV_LIVE: "📡 Live Threat Monitoring",
        NAV_RESEARCH: "🔬 Research & Diagnostics",
        NAV_ALERTS: "📋 Active Buffer Alert View & Health",
        NAV_REPLAY: "📼 Historical Replay & Testing",
    }
    selected_mode = st.sidebar.radio(
        "System Navigation",
        options=[NAV_LIVE, NAV_RESEARCH, NAV_ALERTS, NAV_REPLAY],
        format_func=lambda m: nav_icons.get(m, m),
        index=0,
        help="Select dashboard view: Live streaming detection, research diagnostics, alert history, or historical campaign replay.",
    )

    # Modality Selector
    modality_labels = {
        "fusion": "Fusion (Network + Workload)",
        "network": "Network Only (eBPF TCP Trace)",
        "workload": "Workload Only (CPU / Memory)",
    }
    selected_modality = st.sidebar.selectbox(
        "Telemetry Modality",
        options=["fusion", "network", "workload"],
        format_func=lambda m: modality_labels.get(m, m),
        index=0,
        help="Select the telemetry source dimension to evaluate.",
    )

    # Model Selector
    model_labels = {
        "random_forest": "Random Forest",
        "xgboost": "XGBoost",
        "svm": "Support Vector Machine (SVM)",
    }
    selected_model = st.sidebar.selectbox(
        "Detection Model",
        options=["random_forest", "xgboost", "svm"],
        format_func=lambda m: model_labels.get(m, m),
        index=0,
        help="Select the trained baseline classifier.",
    )

    # Sidebar System Status Card
    st.sidebar.markdown("---")
    st.sidebar.caption("🖥️ **System Status**")
    st.sidebar.markdown(
        "- **Primary Workload:** `webapp (nginx)`\n"
        "- **Cluster Context:** `minikube`\n"
        "- **Telemetry Collectors:** `Inspektor Gadget` & `Metrics Server`\n"
        "- **Window Duration:** `10.0 seconds`\n"
        "- **Validation:** `Session-Isolated LOSO`"
    )

    # 3. Main Dashboard Body based on Mode
    if selected_mode == NAV_LIVE:
        # Priority A: Live Threat Monitoring
        render_live_capture(detector, selected_model, selected_modality=selected_modality)

    elif selected_mode == NAV_RESEARCH:
        # Priority B: Research and Model Diagnostics
        render_research_diagnostics(project_root=PROJECT_ROOT)

    elif selected_mode == NAV_ALERTS:
        # Priority C: Alert History and Telemetry Health
        render_alert_history(detector)

    elif selected_mode == NAV_REPLAY:
        # Priority D: Historical Replay / Testing
        st.info(
            "📼 **HISTORICAL REPLAY & OFFLINE TESTING:** Replay controlled campaign sessions "
            "or submit custom telemetry windows to evaluate the active inference engine. "
            "*(Notice: This view evaluates historical offline captures, not active cluster events.)*",
            icon="ℹ️",
        )

        replay_tab, manual_tab = st.tabs(["📼 Replay Captured Campaigns", "✍️ Submit Custom JSON Window"])

        with replay_tab:
            try:
                available_sessions = provider.get_sessions(selected_modality)
            except Exception as exc:
                st.error(f"Failed to load dataset for '{selected_modality}': {exc}", icon="⚠️")
                return

            if not available_sessions:
                st.warning(f"No experiment sessions found for modality '{selected_modality}'.")
                return

            session_filter = st.selectbox(
                "Select Experiment Session to Inspect:",
                options=["All Sessions"] + available_sessions,
                index=0,
                key=f"session_filter_{selected_modality}",
                help="Filter observation windows by a specific recorded session or inspect all windows.",
            )

            chosen_session = None if session_filter == "All Sessions" else session_filter
            windows = provider.get_windows(selected_modality, session_id=chosen_session)

            if not windows:
                st.warning("No observation windows found for selected session.")
                return

            # Find first ground-truth attack window in currently filtered windows
            first_attack_idx = next(
                (i for i, w in enumerate(windows) if str(w.get("label", "")).strip().lower() == "attack"),
                None,
            )

            # Scoped widget key for stable state reconciliation across modality/session changes
            slider_key = f"replay_slider_{selected_modality}_{session_filter}"
            if slider_key not in st.session_state:
                st.session_state[slider_key] = 1
            elif st.session_state[slider_key] > len(windows):
                st.session_state[slider_key] = 1
            elif st.session_state[slider_key] < 1:
                st.session_state[slider_key] = 1

            # Attack Window Navigation & Jump Controls
            ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 1, 1])
            with ctrl_col1:
                attack_count = sum(1 for w in windows if str(w.get("label", "")).strip().lower() == "attack")
                st.caption(f"📊 **Windows Available:** {len(windows)} ({attack_count} attack / {len(windows) - attack_count} normal)")

            with ctrl_col2:
                if first_attack_idx is not None:
                    if st.button("⚡ Jump to Attack Window", help=f"Jump to window #{first_attack_idx + 1} ({windows[first_attack_idx].get('window_start')})"):
                        st.session_state[slider_key] = first_attack_idx + 1
                        st.rerun()
                else:
                    st.button("⚡ Jump to Attack Window", disabled=True, help="No ground-truth attack windows in this session (benign baseline)")

            with ctrl_col3:
                if st.button("⏮️ Reset to Window 1"):
                    st.session_state[slider_key] = 1
                    st.rerun()

            # Window navigation slider
            current_slider_val = min(max(1, st.session_state[slider_key]), len(windows))
            window_slider_val = st.slider(
                f"Step Through Observation Windows: Window {current_slider_val} of {len(windows)}",
                min_value=1,
                max_value=len(windows),
                value=current_slider_val,
                key=slider_key,
                help="Slide to inspect consecutive 10-second observation windows.",
            )
            window_idx = window_slider_val - 1

            current_window = windows[window_idx]
            ground_truth = str(current_window.get("label", "")) if "label" in current_window else None
            session_id = str(current_window.get("session_id", chosen_session or "All Sessions"))

            # Execute Inference through ThreatDetector
            try:
                inference_result = detector.predict(
                    window=current_window,
                    modality=selected_modality,
                    model_name=selected_model,
                )
            except InferenceSchemaError as exc:
                st.error(f"Telemetry Schema Error: {exc}", icon="⚠️")
                return
            except Exception as exc:
                st.error(f"Inference Engine Error: {exc}", icon="❌")
                return

            # Render Core Dashboard Sections
            render_detection_summary(
                inference_result,
                ground_truth=ground_truth,
                window_idx=window_idx,
                total_windows=len(windows),
                session_id=session_id,
                is_live=False,
            )
            st.markdown("---")
            render_telemetry_charts(windows, window_idx, selected_modality)
            st.markdown("---")
            render_evidence(inference_result)

        with manual_tab:
            st.caption("Submit an arbitrary JSON telemetry window to test real-time schema validation and inference pipeline.")
            inference_result = render_manual_input(detector, selected_modality, selected_model)
            if inference_result:
                st.markdown("---")
                render_detection_summary(inference_result, is_live=False)
                st.markdown("---")
                render_evidence(inference_result)


if __name__ == "__main__":
    build_app()
