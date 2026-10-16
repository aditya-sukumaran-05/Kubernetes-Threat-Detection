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
from dashboard.components.experiment_workspace import render_experiment_workspace
from dashboard.components.live_capture import render_live_capture
from dashboard.components.manual_input import render_manual_input
from dashboard.components.overview import render_overview
from dashboard.components.research_diagnostics import render_research_diagnostics
from dashboard.components.runtime_events_view import render_runtime_events_page
from dashboard.components.settings_view import render_settings_view
from dashboard.components.summary import format_probability, render_detection_summary
from dashboard.components.telemetry_explorer import render_telemetry_explorer
from dashboard.styles import apply_soc_styles, render_brand_sidebar, render_cluster_status_sidebar
from dashboard.telemetry_provider import CapturedDatasetProvider
from ml.inference import InferenceSchemaError, ThreatDetector

# Sentinel Navigation Modes matching Reference Design
NAV_OVERVIEW = "Overview"
NAV_LIVE = "Live Detection"
NAV_SIMULATION = "Traffic Simulation & Attacks"
NAV_EXPLORER = "Telemetry Explorer"
NAV_RUNTIME = "Runtime Events"
NAV_EXPERIMENTS = "Experiments"
NAV_EVALUATION = "Model Evaluation"
NAV_SETTINGS = "Settings"

# Historical compatibility alias for existing tests
NAV_RESEARCH = NAV_EVALUATION
NAV_ALERTS = "Alert History & Telemetry Health"
NAV_REPLAY = "Historical Replay & Testing"


def build_app() -> None:
    """Build and render the Streamlit threat detection dashboard."""
    st.set_page_config(
        page_title="K8S SENTINEL — Kubernetes Threat Detection",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # 1. Apply Sentinel Design Styles
    apply_soc_styles()

    # Initialize Backend Services
    detector = ThreatDetector(project_root=PROJECT_ROOT)
    provider = CapturedDatasetProvider()

    # 2. Sentinel Sidebar
    render_brand_sidebar()

    # Primary Navigation
    nav_icons = {
        NAV_OVERVIEW: "🏠 Overview",
        NAV_LIVE: "📡 Live Detection",
        NAV_SIMULATION: "⚡ Traffic & Attacks",
        NAV_EXPLORER: "🔍 Telemetry Explorer",
        NAV_RUNTIME: "🛡️ Runtime Events",
        NAV_EXPERIMENTS: "🧪 Experiments",
        NAV_EVALUATION: "📈 Model Evaluation",
        NAV_SETTINGS: "⚙️ Settings",
        NAV_ALERTS: "📋 Active Alert View & Health",
        NAV_REPLAY: "📼 Historical Replay",
    }
    nav_options = [
        NAV_OVERVIEW,
        NAV_LIVE,
        NAV_SIMULATION,
        NAV_EXPLORER,
        NAV_RUNTIME,
        NAV_EXPERIMENTS,
        NAV_EVALUATION,
        NAV_SETTINGS,
        NAV_ALERTS,
        NAV_REPLAY,
    ]
    selected_mode = st.sidebar.radio(
        "Navigation",
        options=nav_options,
        format_func=lambda m: nav_icons.get(m, m),
        index=0,
        help="Select dashboard view: Overview, Live Detection, Telemetry Explorer, Runtime Events, Experiments, Model Evaluation, Settings, Alert View, or Replay.",
    )

    # Modality Selector
    st.sidebar.markdown("---")
    st.sidebar.caption("🎛️ **Inference & Telemetry Modality**")
    modality_labels = {
        "fusion": "1. Network + Workload [ML Benchmark]",
        "network": "2. Network Only (eBPF TCP) [ML Model]",
        "workload": "3. Workload Only (Metrics Server) [ML Model]",
        "runtime": "4. Runtime Only (trace_exec) [Observational]",
        "net_rt": "5. Network + Runtime [Observational Fusion]",
        "rt_wl": "6. Runtime + Workload [Observational Fusion]",
        "full_fusion": "7. Full Tri-Modal Fusion (Net + RT + WL)",
    }
    all_modalities = [
        "fusion",
        "network",
        "workload",
        "runtime",
        "net_rt",
        "rt_wl",
        "full_fusion",
    ]
    selected_modality = st.sidebar.selectbox(
        "Telemetry Modality",
        options=all_modalities,
        format_func=lambda m: modality_labels.get(m, m),
        index=0,
        help="Select the telemetry source dimension or fusion combination to evaluate.",
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
        help="Select the trained baseline classifier (applies to ML benchmark modalities).",
    )

    # Sidebar Cluster Status Card (Matching reference design)
    render_cluster_status_sidebar(
        cluster_name="minikube",
        k8s_version="v1.37.0",
        nodes=1,
        pods=4,
        status_text="Ready",
    )

    # 3. Main Dashboard Body based on Mode
    if selected_mode == NAV_OVERVIEW:
        # K8S SENTINEL Landing Page
        render_overview(detector, selected_model=selected_model)

    elif selected_mode == NAV_LIVE:
        # Live Threat Monitoring
        render_live_capture(detector, selected_model, selected_modality=selected_modality)

    elif selected_mode == NAV_SIMULATION:
        # Interactive Traffic & Attack Controller
        from dashboard.components.traffic_simulation_view import render_traffic_simulation_view
        render_traffic_simulation_view(project_root=PROJECT_ROOT)

    elif selected_mode == NAV_EXPLORER:
        # Unified Telemetry Explorer
        render_telemetry_explorer(detector, selected_model=selected_model)

    elif selected_mode == NAV_RUNTIME:
        # Dedicated Container Runtime Events
        render_runtime_events_page(detector)

    elif selected_mode == NAV_EXPERIMENTS:
        # Experiment Research Workspace
        render_experiment_workspace(project_root=PROJECT_ROOT)

    elif selected_mode == NAV_EVALUATION:
        # Research & Model Diagnostics (LOSO ablation tables)
        render_research_diagnostics(project_root=PROJECT_ROOT)

    elif selected_mode == NAV_SETTINGS:
        # Platform Settings & Environment Configuration
        render_settings_view(project_root=PROJECT_ROOT)

    elif selected_mode == NAV_ALERTS:
        # Active Buffer Alert View & Telemetry Health
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
            if selected_modality not in provider.get_modalities():
                st.info(
                    f"ℹ️ **Modality '{modality_labels.get(selected_modality, selected_modality)}' is an Observational / Telemetry Correlation Mode.**\n\n"
                    "Standard offline benchmark datasets with ground-truth experiment labels are currently curated for "
                    "**Network**, **Workload**, and **Network + Workload Fusion**.\n\n"
                    "To inspect streaming or historical runtime process executions and tri-modal correlations, navigate to "
                    "**Live Detection**, **Telemetry Explorer**, or **Runtime Events**.",
                    icon="ℹ️",
                )
                return

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
            st.session_state[slider_key] = current_slider_val
            window_slider_val = st.slider(
                f"Step Through Observation Windows: Window {current_slider_val} of {len(windows)}",
                min_value=1,
                max_value=len(windows),
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
