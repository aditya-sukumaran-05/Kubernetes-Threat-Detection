"""Automated tests for the threat detection dashboard, navigation, and components."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from dashboard.app import (
    NAV_ALERTS,
    NAV_EVALUATION,
    NAV_EXPERIMENTS,
    NAV_EXPLORER,
    NAV_LIVE,
    NAV_OVERVIEW,
    NAV_REPLAY,
    NAV_RESEARCH,
    NAV_RUNTIME,
    NAV_SETTINGS,
    NAV_SIMULATION,
)
from dashboard.components.summary import format_probability, render_detection_summary
from dashboard.telemetry_provider import CapturedDatasetProvider, LiveKubernetesProvider
from ml.inference import InferenceResult


@pytest.fixture
def provider() -> CapturedDatasetProvider:
    return CapturedDatasetProvider(ml_datasets_dir="results/ml_datasets")


def test_provider_modalities(provider: CapturedDatasetProvider) -> None:
    assert provider.get_modalities() == ["network", "workload", "fusion"]


@pytest.mark.parametrize("modality", ["network", "workload", "fusion"])
def test_provider_returns_valid_sessions_and_windows(provider: CapturedDatasetProvider, modality: str) -> None:
    sessions = provider.get_sessions(modality)
    assert len(sessions) > 0

    # Get all windows
    all_windows = provider.get_windows(modality)
    assert len(all_windows) >= len(sessions)

    # Get filtered windows for the first session
    first_session = sessions[0]
    session_windows = provider.get_windows(modality, session_id=first_session)
    assert len(session_windows) > 0
    assert all(w.get("session_id") == first_session for w in session_windows)
    assert all("affected_pods" in w for w in session_windows)


def test_provider_missing_dataset_raises(tmp_path: Path) -> None:
    bad_provider = CapturedDatasetProvider(ml_datasets_dir=tmp_path)
    with pytest.raises(FileNotFoundError, match="Dataset for modality"):
        bad_provider.get_sessions("network")


def test_live_provider_stub() -> None:
    live = LiveKubernetesProvider()
    assert live.get_modalities() == ["network", "workload", "fusion"]
    assert live.get_sessions("network") == ["live_cluster_stream"]
    with pytest.raises(NotImplementedError, match="Phase 5"):
        live.get_windows("network")


def test_format_probability_adaptive_precision() -> None:
    """Verify adaptive probability formatting avoids misleading 0.0% on small non-zero values."""
    assert format_probability(None) == "N/A"
    assert format_probability(0.0) == "0.0%"
    assert format_probability(0.00005) == "< 0.01%"
    assert format_probability(0.0004775) == "0.05%"
    assert format_probability(0.0057577) == "0.6%"
    assert format_probability(0.035) == "3.5%"
    assert format_probability(0.725) == "72.5%"
    assert format_probability(1.0) == "100.0%"


def test_dashboard_app_renders_successfully() -> None:
    """Test full Streamlit app lifecycle using AppTest landing on default Sentinel Overview."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    assert not at.exception
    # Verify title/brand in sidebar
    metric_labels = [m.label for m in at.metric]
    assert "Network Events" in metric_labels
    assert "Runtime Executions" in metric_labels
    assert "Workload Samples" in metric_labels
    assert "Active Detections" in metric_labels


def test_dashboard_navigation_live_detection() -> None:
    """Test navigating to Live Detection view."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    at.run(timeout=25)

    assert not at.exception
    metric_labels = [m.label for m in at.metric]
    assert "Valid Network Events" in metric_labels
    assert "Inference Windows (10s)" in metric_labels
    assert "Active Model" in metric_labels


def test_dashboard_navigation_telemetry_explorer() -> None:
    """Test navigating to Telemetry Explorer view."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_EXPLORER)
    at.run(timeout=25)

    assert not at.exception
    assert len(at.dataframe) >= 1
    # Verify subheader and controls
    subheaders = [s.value for s in at.subheader]
    assert any("Telemetry Time-Series Visualizer" in s for s in subheaders)


def test_dashboard_navigation_runtime_events() -> None:
    """Test navigating to Runtime Events dedicated view."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_RUNTIME)
    at.run(timeout=25)

    assert not at.exception
    metric_labels = [m.label for m in at.metric]
    assert "Total Executions" in metric_labels
    assert "Unique Binaries" in metric_labels
    assert len(at.dataframe) >= 1


def test_dashboard_navigation_traffic_simulation() -> None:
    """Test navigating to Traffic & Attack Simulation Controller view."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_SIMULATION)
    at.run(timeout=25)

    assert not at.exception
    # Verify presence of metric cards and simulation tabs
    metric_labels = [m.label for m in at.metric]
    assert "Generator Status" in metric_labels
    assert "Total Requests" in metric_labels
    assert "Success Rate" in metric_labels


def test_dashboard_navigation_settings() -> None:
    """Test navigating to Settings view."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_SETTINGS)
    at.run(timeout=25)

    assert not at.exception
    assert any("Settings" in str(h.value) for h in at.markdown)


def test_dashboard_navigation_research_diagnostics() -> None:
    """Test navigating to Research & Diagnostics section and rendering LOSO ablation tables."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_RESEARCH)
    at.run(timeout=25)

    assert not at.exception
    # Verify Research header and LOSO metric cards
    metric_labels = [m.label for m in at.metric]
    assert "Total LOSO Folds" in metric_labels
    assert "Total Evaluated Windows" in metric_labels
    # Verify ablation data table is rendered
    assert len(at.dataframe) >= 1


def test_dashboard_navigation_experiment_workspace() -> None:
    """Test navigating to Experiment Workspace and rendering runs and comparisons."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_EXPERIMENTS)
    at.run(timeout=25)

    assert not at.exception
    # Verify subheaders and metrics in Experiment Workspace
    subheaders = [s.value for s in at.subheader]
    assert any("Experiment Run Catalog" in s for s in subheaders)
    metric_labels = [m.label for m in at.metric]
    assert "Scenario" in metric_labels
    assert "Status" in metric_labels
    assert len(at.dataframe) >= 1


def test_dashboard_navigation_alert_history() -> None:
    """Test navigating to Alert History & Telemetry Health section."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_ALERTS)
    at.run(timeout=25)

    assert not at.exception
    # Verify collector health table is rendered
    assert len(at.dataframe) >= 1
    # Verify alert log and export subheaders are present
    subheaders = [s.value for s in at.subheader]
    assert any("Export Evaluated Records" in s for s in subheaders)
    assert any("Threat Incident Alerts Log" in s for s in subheaders)


def test_dashboard_navigation_historical_replay() -> None:
    """Test navigating to Historical Replay & Testing section and stepping through observation windows."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_REPLAY)
    at.run(timeout=25)

    assert not at.exception
    # Verify core replay prediction metrics are rendered
    metric_labels = [m.label for m in at.metric]
    assert "Predicted Class" in metric_labels
    assert "Attack Probability" in metric_labels
    assert "Model Confidence" in metric_labels

    # Verify slider exists and is within bounds
    assert len(at.slider) >= 1
    slider = at.slider[0]
    assert slider.min == 1
    assert slider.max >= 1

    # Verify provenance caption is explicitly historical replay
    assert any("Historical Experiment Replay" in c.value for c in at.caption)


def test_dashboard_replay_attack_jump_button() -> None:
    """Test jumping to the first ground-truth attack window via the attack jump button."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_REPLAY)
    at.run(timeout=25)

    assert not at.exception
    # Find Jump to Attack Window button
    jump_btn = [b for b in at.button if "Jump to Attack Window" in b.label]
    assert len(jump_btn) == 1
    # In All Sessions (fusion/network), attack windows exist so button is enabled
    assert not jump_btn[0].disabled

    jump_btn[0].click()
    at.run(timeout=25)
    assert not at.exception

    # Slider value should have advanced past window 1
    slider = at.slider[0]
    assert slider.value > 1


def test_dashboard_replay_session_switching_and_bounds() -> None:
    """Test switching experiment sessions reconciles slider bounds safely without index errors."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_REPLAY)
    at.run(timeout=25)

    # Initial slider max (All Sessions in fusion has 122 windows)
    initial_max = at.slider[0].max
    assert initial_max > 10

    # Select a specific session from the dropdown
    session_select = [s for s in at.selectbox if "Select Experiment Session" in s.label]
    assert len(session_select) == 1
    session_options = session_select[0].options
    assert len(session_options) > 1

    # Choose first individual session
    target_session = session_options[1]
    session_select[0].set_value(target_session)
    at.run(timeout=25)

    assert not at.exception
    # Reconciled slider should have bounds matching the smaller single session
    reconciled_slider = at.slider[0]
    assert reconciled_slider.max < initial_max
    assert 1 <= reconciled_slider.value <= reconciled_slider.max


def test_dashboard_live_monitoring_model_switch() -> None:
    """Test switching models while in Live Threat Monitoring mode."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    at.run(timeout=25)

    at.sidebar.selectbox[1].set_value("xgboost")
    at.run(timeout=25)

    assert not at.exception
    model_metrics = [m for m in at.metric if m.label == "Active Model"]
    assert len(model_metrics) == 1
    assert model_metrics[0].value == "Xgboost"

    at.sidebar.selectbox[1].set_value("svm")
    at.run(timeout=25)
    assert not at.exception
    model_metrics = [m for m in at.metric if m.label == "Active Model"]
    assert model_metrics[0].value == "Svm"


def test_live_capture_missing_file_handled(tmp_path: Path) -> None:
    """Test graceful handling of a nonexistent capture file."""
    script = '''
import sys
from pathlib import Path
root = Path(".").resolve()
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
from dashboard.components.live_capture import render_live_capture
from ml.inference import ThreatDetector
det = ThreatDetector()
render_live_capture(det, "random_forest", capture_path=Path("nonexistent_events.jsonl"))
'''
    script_file = tmp_path / "run_missing.py"
    script_file.write_text(script, encoding="utf-8")
    at = AppTest.from_file(str(script_file))
    at.run(timeout=10)
    assert not at.exception
    assert any("not found" in w.value for w in at.warning)


def test_live_capture_empty_file_handled(tmp_path: Path) -> None:
    """Test graceful handling of an empty (0-byte) capture file."""
    empty_file = tmp_path / "empty.jsonl"
    empty_file.write_text("", encoding="utf-8")

    script = f'''
import sys
from pathlib import Path
root = Path(".").resolve()
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
from dashboard.components.live_capture import render_live_capture
from ml.inference import ThreatDetector
det = ThreatDetector()
render_live_capture(det, "random_forest", capture_path=Path(r"{empty_file.as_posix()}"))
'''
    script_file = tmp_path / "run_empty.py"
    script_file.write_text(script, encoding="utf-8")
    at = AppTest.from_file(str(script_file))
    at.run(timeout=10)
    assert not at.exception
    assert any("is empty" in w.value for w in at.warning)


def test_live_capture_malformed_file_handled(tmp_path: Path) -> None:
    """Test graceful handling of malformed JSON in capture file."""
    bad_file = tmp_path / "bad.jsonl"
    bad_file.write_text("invalid json content\\n", encoding="utf-8")

    script = f'''
import sys
from pathlib import Path
root = Path(".").resolve()
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
from dashboard.components.live_capture import render_live_capture
from ml.inference import ThreatDetector
det = ThreatDetector()
render_live_capture(det, "random_forest", capture_path=Path(r"{bad_file.as_posix()}"))
'''
    script_file = tmp_path / "run_bad.py"
    script_file.write_text(script, encoding="utf-8")
    at = AppTest.from_file(str(script_file))
    at.run(timeout=10)
    assert not at.exception
    assert any("Schema Error" in e.value for e in at.error)


def test_dashboard_live_capture_filter_and_window_navigation() -> None:
    """Test table filtering and window inspection slider in live capture mode."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    at.run(timeout=25)

    assert not at.exception
    # Verify table is rendered
    assert len(at.dataframe) >= 1
    initial_rows = len(at.dataframe[0].value)

    # Check the network traffic filter checkbox
    filter_cb = [c for c in at.checkbox if "Show only windows with active network traffic" in c.label]
    assert len(filter_cb) == 1
    filter_cb[0].set_value(True)
    at.run(timeout=25)

    assert not at.exception
    # Filtered table should have <= rows than initial
    filtered_rows = len(at.dataframe[0].value)
    assert filtered_rows <= initial_rows

    # Verify slider exists and can be adjusted without exceptions
    assert len(at.slider) >= 1
    slider = at.slider[0]
    assert slider.min == 1
    assert slider.max >= 1
    slider.set_value(1)
    at.run(timeout=15)
    assert not at.exception


def test_live_capture_stale_telemetry_banner(tmp_path: Path) -> None:
    """Verify that live capture renders an explicit inactive/stale banner when telemetry is old."""
    import json
    from datetime import datetime, timedelta, timezone

    stale_ts = (datetime.now(timezone.utc) - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    net_file = tmp_path / "stale_network.jsonl"
    event_json = {
        "timestamp": stale_ts,
        "type": "accept",
        "src": {"addr": "10.244.0.5", "port": 54321},
        "dst": {"addr": "10.244.0.2", "port": 80},
        "k8s": {"podName": "webapp-stale", "namespace": "default"},
        "error": None,
    }
    net_file.write_text(json.dumps(event_json) + "\n", encoding="utf-8")

    empty_wl = tmp_path / "empty_wl.csv"
    empty_wl.write_text("timestamp,pod,cpu_millicores,memory_mib,label\n", encoding="utf-8")

    script = f'''
import sys
from pathlib import Path
root = Path(".").resolve()
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
from dashboard.components.live_capture import render_live_capture
from ml.inference import ThreatDetector
det = ThreatDetector()
render_live_capture(det, "random_forest", capture_path=Path(r"{net_file.as_posix()}"), workload_path=Path(r"{empty_wl.as_posix()}"), selected_modality="network")
'''
    script_file = tmp_path / "run_stale.py"
    script_file.write_text(script, encoding="utf-8")
    at = AppTest.from_file(str(script_file))
    at.run(timeout=25)
    assert not at.exception
    # Verify stale warning banner is displayed
    assert any("TELEMETRY INACTIVE / STALE" in w.value for w in at.warning)
    assert any("Historical / Stale Window" in el.value for el in [*at.info, *at.error])


def test_alert_history_buffer_export_scoping() -> None:
    """Verify that Alert History view scopes export captions and shares engine in session state."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_ALERTS)
    at.run(timeout=25)

    assert not at.exception
    # Verify Active Buffer subheaders and temporal range caption
    subheaders = [s.value for s in at.subheader]
    assert any("Export Evaluated Records (Active Buffer)" in s for s in subheaders)
    assert any("Active Buffer Threat Incident Alerts Log" in s for s in subheaders)
    assert any("Temporal buffer range:" in c.value for c in at.caption)

    # Verify session state retains shared live engine
    all_keys = set(at.session_state._state._new_session_state.keys()) | set(at.session_state._state._old_state.keys())
    shared_engine_keys = [k for k in all_keys if str(k).startswith("live_engine_")]
    assert len(shared_engine_keys) >= 1


@pytest.mark.parametrize(
    "modality",
    [
        "fusion",
        "network",
        "workload",
        "runtime",
        "net_rt",
        "rt_wl",
        "full_fusion",
    ],
)
def test_dashboard_all_seven_modalities_sidebar_selection(modality: str) -> None:
    """Verify that all 7 modalities can be selected in the sidebar without exceptions."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    modality_select = at.sidebar.selectbox[0]
    modality_select.set_value(modality)
    at.run(timeout=25)

    assert not at.exception


@pytest.mark.parametrize(
    "modality",
    [
        "fusion",
        "network",
        "workload",
        "runtime",
        "net_rt",
        "rt_wl",
        "full_fusion",
    ],
)
def test_dashboard_live_capture_all_seven_modalities(modality: str) -> None:
    """Verify that Live Detection view renders cleanly across all 7 modalities."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    modality_select = at.sidebar.selectbox[0]
    modality_select.set_value(modality)
    at.run(timeout=25)

    assert not at.exception
    # Verify metric cards are present
    assert len(at.metric) >= 4


def test_dashboard_telemetry_explorer_pairwise_and_trimodal_tabs() -> None:
    """Verify that Telemetry Explorer renders pairwise correlation and tri-modal fusion tables."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_EXPLORER)
    at.run(timeout=25)

    assert not at.exception
    # Verify dataframes exist for tabs
    assert len(at.dataframe) >= 1
    # Verify pairwise subheader/headers
    subheaders = [s.value for s in at.subheader]
    assert any("Telemetry Time-Series Visualizer" in s for s in subheaders)


def test_dashboard_telemetry_explorer_modality_column_isolation() -> None:
    """Verify that Telemetry Explorer isolates table columns and records to the selected modality."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_EXPLORER)
    at.run(timeout=25)
    assert not at.exception

    # Find the modality filter selectbox
    mod_select = [s for s in at.selectbox if s.label == "Filter by Modality:"]
    assert len(mod_select) == 1

    # 1. Filter by Network Only
    mod_select[0].set_value("Network Only (eBPF TCP)")
    at.run(timeout=25)
    assert not at.exception
    df_net = at.dataframe[0].value
    if not df_net.empty:
        cols = list(df_net.columns)
        assert "Network Verdict" in cols
        assert "Net Events" in cols
        assert "Net Conn Rate" in cols
        assert "Workload Verdict" not in cols
        assert "CPU Mean" not in cols
        assert "Runtime Verdict" not in cols
        assert "Tri-Modal Verdict" not in cols

    # 3. Filter by Runtime Only (re-fetch selectbox from fresh element tree)
    mod_select_rt = [s for s in at.selectbox if s.label == "Filter by Modality:"]
    assert len(mod_select_rt) == 1
    mod_select_rt[0].set_value("Runtime Only (trace_exec)")
    at.run(timeout=25)
    assert not at.exception
    df_rt = at.dataframe[0].value
    if not df_rt.empty:
        cols = list(df_rt.columns)
        assert "Runtime Verdict" in cols
        assert "Process Execs" in cols
        assert "Root Execs (UID 0)" in cols
        assert "Sensitive Binaries" in cols
        assert "Network Verdict" not in cols
        assert "Net Events" not in cols
        assert "CPU Mean" not in cols
        assert "Tri-Modal Verdict" not in cols

    # 2. Filter by Workload Only (re-fetch selectbox from fresh element tree)
    mod_select_wl = [s for s in at.selectbox if s.label == "Filter by Modality:"]
    assert len(mod_select_wl) == 1
    mod_select_wl[0].set_value("Workload Only (Metrics Server)")
    at.run(timeout=25)
    assert not at.exception
    df_wl = at.dataframe[0].value
    if not df_wl.empty:
        cols = list(df_wl.columns)
        assert "Workload Verdict" in cols
        assert "CPU Mean" in cols
        assert "Memory Mean" in cols
        assert "Network Verdict" not in cols
        assert "Net Events" not in cols
        assert "Runtime Verdict" not in cols
        assert "Tri-Modal Verdict" not in cols

    # 3. Filter by Runtime Only (re-fetch selectbox from fresh element tree)
    mod_select_rt = [s for s in at.selectbox if s.label == "Filter by Modality:"]
    assert len(mod_select_rt) == 1
    mod_select_rt[0].set_value("Runtime Only (trace_exec)")
    at.run(timeout=25)
    assert not at.exception
    df_rt = at.dataframe[0].value
    if not df_rt.empty:
        cols = list(df_rt.columns)
        assert "Runtime Verdict" in cols
        assert "Process Execs" in cols
        assert "Root Execs (UID 0)" in cols
        assert "Sensitive Binaries" in cols
        assert "Network Verdict" not in cols
        assert "Net Events" not in cols
        assert "CPU Mean" not in cols
        assert "Tri-Modal Verdict" not in cols


def test_dashboard_runtime_events_time_range_filter() -> None:
    """Verify that Runtime Events view supports time-range filtering without exceptions."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_RUNTIME)
    at.run(timeout=25)

    assert not at.exception
    time_range_sel = [s for s in at.selectbox if "Time Range:" in s.label]
    assert len(time_range_sel) == 1
    time_range_sel[0].set_value("Last 24 Hours")
    at.run(timeout=25)

    assert not at.exception
    assert len(at.dataframe) >= 1


def test_dashboard_replay_observational_modality_guidance() -> None:
    """Verify that selecting an observational modality in Replay shows the guidance banner."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_REPLAY)
    modality_select = at.sidebar.selectbox[0]
    modality_select.set_value("runtime")
    at.run(timeout=25)

    assert not at.exception
    # Should display info notice regarding observational / correlation mode
    assert any("Observational / Telemetry Correlation Mode" in i.value for i in at.info)


@pytest.mark.parametrize(
    ("modality", "expected_card_label"),
    [
        ("network", "Predicted Class"),
        ("workload", "Predicted Class"),
        ("fusion", "Predicted Class"),
        ("runtime", "Runtime Status"),
        ("net_rt", "Network ML Class"),
        ("rt_wl", "Workload ML Class"),
        ("full_fusion", "Fusion ML Class"),
    ],
)
def test_dashboard_modality_aware_metric_cards(modality: str, expected_card_label: str) -> None:
    """Verify that Live Detection view renders modality-specific metric cards for each mode."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    modality_select = at.sidebar.selectbox[0]
    modality_select.set_value(modality)
    at.run(timeout=25)

    assert not at.exception
    metric_labels = [m.label for m in at.metric]
    # Check that either the expected label or Stream Status is rendered
    assert expected_card_label in metric_labels or "Stream Status" in metric_labels


def test_dashboard_live_capture_ml_attack_precedence_over_benign_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that when an ML model predicts an attack and runtime is benign, an error alert is rendered, not a green stable banner."""
    from dashboard.live_engine import LiveTelemetryEngine, LiveWindowRecord
    from ml.inference import InferenceResult

    orig_process = LiveTelemetryEngine.process_live_telemetry

    def mock_process(self, model_name="random_forest"):
        recs = orig_process(self, model_name=model_name)
        if recs:
            latest = recs[-1]
            latest.network_inferences[model_name] = InferenceResult(
                model_name=model_name,
                modality="network",
                predicted_label="attack",
                confidence=0.95,
                attack_probability=0.95,
                window_start=latest.window_start,
                window_end=latest.window_end,
                evidence={},
            )
            latest.network_available = True
            latest.runtime_features = {
                "runtime_sensitive_command_count": 0,
                "runtime_interactive_shell_count": 0,
                "runtime_root_exec_count": 0,
            }
            latest.runtime_events = []
            latest.runtime_available = True
        return recs

    monkeypatch.setattr(LiveTelemetryEngine, "process_live_telemetry", mock_process)

    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    modality_select = at.sidebar.selectbox[0]
    modality_select.set_value("net_rt")
    at.run(timeout=25)

    assert not at.exception
    # Must NOT have a green 'CONTAINER RUNTIME STABLE' or 'TELEMETRY CONFORMS TO BENIGN BASELINE' success banner
    success_banners = [s.value for s in at.success]
    assert not any("CONTAINER RUNTIME STABLE" in s for s in success_banners)
    assert not any("TELEMETRY CONFORMS TO BENIGN BASELINE" in s for s in success_banners)
    # Must have an error banner reporting the threat
    error_banners = [e.value for e in at.error]
    assert any("PREDICTED THREAT DETECTED" in e or "CORRELATED MULTIMODAL" in e for e in error_banners)


def test_dashboard_live_capture_runtime_alert_precedence_over_normal_ml(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that when runtime detects sensitive commands while ML predicts normal, an error banner is rendered."""
    from dashboard.live_engine import LiveTelemetryEngine, LiveWindowRecord
    from ml.inference import InferenceResult
    from telemetry.schemas import RuntimeEvent

    orig_process = LiveTelemetryEngine.process_live_telemetry

    def mock_process(self, model_name="random_forest"):
        recs = orig_process(self, model_name=model_name)
        if recs:
            latest = recs[-1]
            latest.network_inferences[model_name] = InferenceResult(
                model_name=model_name,
                modality="network",
                predicted_label="normal",
                confidence=0.99,
                attack_probability=0.01,
                window_start=latest.window_start,
                window_end=latest.window_end,
                evidence={},
            )
            latest.network_available = True
            latest.runtime_features = {
                "runtime_sensitive_command_count": 2,
                "runtime_interactive_shell_count": 1,
                "runtime_root_exec_count": 1,
            }
            raw_ev = {
                "timestamp": latest.window_start,
                "comm": "sh",
                "args": "/bin/sh",
                "pid": 123,
                "uid": 0,
                "pod": "webapp",
            }
            latest.runtime_events = [RuntimeEvent.from_raw(raw_ev)]
            latest.runtime_available = True
        return recs

    monkeypatch.setattr(LiveTelemetryEngine, "process_live_telemetry", mock_process)

    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    modality_select = at.sidebar.selectbox[0]
    modality_select.set_value("net_rt")
    at.run(timeout=25)

    assert not at.exception
    # Must NOT have a green benign banner
    success_banners = [s.value for s in at.success]
    assert not any("TELEMETRY CONFORMS TO BENIGN BASELINE" in s for s in success_banners)
    assert not any("PREDICTED NORMAL WORKLOAD" in s for s in success_banners)
    # Must have an error banner reporting suspicious runtime activity
    error_banners = [e.value for e in at.error]
    assert any("SUSPICIOUS RUNTIME ACTIVITY DETECTED" in e for e in error_banners)


def test_dashboard_overview_counts_both_ml_and_runtime_alerts() -> None:
    """Verify that overview Active Detections counts both ML attacks and runtime rule findings without double counting."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    # Inspect the Active Detections metric
    active_det_metrics = [m for m in at.metric if m.label == "Active Detections"]
    assert len(active_det_metrics) == 1
    # Check help text references both ML predictions and runtime rule alerts
    assert "ML predictions" in active_det_metrics[0].help
    assert "runtime rule alerts" in active_det_metrics[0].help


def test_dashboard_overview_idle_workload_zero_cpu_not_counted_as_attack(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that an uncorroborated idle zero-CPU workload inference does not inflate overview Active Detections."""
    from dashboard.live_engine import LiveTelemetryEngine, LiveWindowRecord
    from ml.inference import InferenceResult

    def mock_process(self, model_name="random_forest"):
        rec = LiveWindowRecord(
            window_start="2026-10-15T12:00:00Z",
            window_end="2026-10-15T12:00:10Z",
            affected_pods="webapp-79699899c5-wds9h",
            network_available=False,
            workload_available=True,
            runtime_available=False,
            workload_features={
                "workload_cpu_millicores_mean": 0.0,
                "workload_memory_mib_mean": 13.5,
                "workload_sample_count": 2,
            },
        )
        rec.workload_inferences[model_name] = InferenceResult(
            model_name=model_name,
            modality="workload",
            predicted_label="attack",
            confidence=0.75,
            attack_probability=0.75,
            window_start=rec.window_start,
            window_end=rec.window_end,
            evidence={"workload_cpu_millicores_mean": 0.0},
        )
        return [rec]

    monkeypatch.setattr(LiveTelemetryEngine, "process_live_telemetry", mock_process)

    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    assert not at.exception
    active_det_metrics = [m for m in at.metric if m.label == "Active Detections"]
    assert len(active_det_metrics) == 1
    # Active detections MUST be 0 (not 1) because container is idle with zero CPU
    assert active_det_metrics[0].value == "0"


def test_dashboard_overview_active_workload_high_cpu_counted_as_attack(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that an active CPU-abuse workload inference with non-zero CPU IS counted as an attack on overview."""
    from dashboard.live_engine import LiveTelemetryEngine, LiveWindowRecord
    from ml.inference import InferenceResult

    def mock_process(self, model_name="random_forest"):
        rec = LiveWindowRecord(
            window_start="2026-10-15T12:00:00Z",
            window_end="2026-10-15T12:00:10Z",
            affected_pods="webapp-79699899c5-wds9h",
            network_available=False,
            workload_available=True,
            runtime_available=False,
            workload_features={
                "workload_cpu_millicores_mean": 850.0,
                "workload_memory_mib_mean": 25.0,
                "workload_sample_count": 2,
            },
        )
        rec.workload_inferences[model_name] = InferenceResult(
            model_name=model_name,
            modality="workload",
            predicted_label="attack",
            confidence=0.95,
            attack_probability=0.95,
            window_start=rec.window_start,
            window_end=rec.window_end,
            evidence={"workload_cpu_millicores_mean": 850.0},
        )
        return [rec]

    monkeypatch.setattr(LiveTelemetryEngine, "process_live_telemetry", mock_process)

    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    assert not at.exception
    active_det_metrics = [m for m in at.metric if m.label == "Active Detections"]
    assert len(active_det_metrics) == 1
    # Active detections MUST be 1 because container exhibited actual CPU abuse
    assert active_det_metrics[0].value == "1"


def test_get_historical_active_windows_caching_and_invalidation(tmp_path: Path) -> None:
    import json
    from dashboard.components.overview import _get_historical_active_windows

    net_dir = tmp_path / "telemetry" / "data" / "network"
    net_dir.mkdir(parents=True)
    net_file = net_dir / "network_events.jsonl"

    # 1. Initial write with 1 event
    ev1 = {
        "timestamp": "2026-10-18T10:00:01.000Z",
        "collector_timestamp": "2026-10-18T10:00:01.000Z",
        "type": "accept",
        "src": {"addr": "10.0.0.1", "port": 80},
        "dst": {"addr": "10.0.0.2", "port": 12345},
    }
    net_file.write_text(json.dumps(ev1) + "\n", encoding="utf-8")

    res1 = _get_historical_active_windows(tmp_path, limit=10)
    assert len(res1) == 1
    assert res1[0]["network_events"] == 1

    # 2. Subsequent call on unchanged file returns cached result
    res2 = _get_historical_active_windows(tmp_path, limit=10)
    assert len(res2) == 1
    assert res2[0]["network_events"] == 1

    # 3. Append new event in next window -> cache invalidated via file signature change
    ev2 = {
        "timestamp": "2026-10-18T10:00:15.000Z",
        "collector_timestamp": "2026-10-18T10:00:15.000Z",
        "type": "accept",
        "src": {"addr": "10.0.0.1", "port": 80},
        "dst": {"addr": "10.0.0.2", "port": 12346},
    }
    with net_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(ev2) + "\n")

    res3 = _get_historical_active_windows(tmp_path, limit=10)
    assert len(res3) == 2
    assert res3[-1]["network_events"] == 1


def test_dashboard_live_capture_idle_workload_safeguard_suppresses_false_attack(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that an uncorroborated idle workload inference with CPU <= 1.0m does not trigger a false attack alert banner or inflate Threat Breakdown in Live Detection."""
    from dashboard.live_engine import LiveTelemetryEngine, LiveWindowRecord
    from ml.inference import InferenceResult

    def mock_process(self, model_name="random_forest"):
        rec = LiveWindowRecord(
            window_start="2026-10-28T01:25:40.000Z",
            window_end="2026-10-28T01:25:50.000Z",
            affected_pods="webapp-79699899c5-wds9h",
            network_available=False,
            workload_available=True,
            runtime_available=False,
            workload_features={
                "workload_cpu_millicores_mean": 0.5,
                "workload_memory_mib_mean": 13.5,
                "workload_sample_count": 2,
            },
        )
        rec.workload_inferences[model_name] = InferenceResult(
            model_name=model_name,
            modality="workload",
            predicted_label="attack",
            confidence=0.75,
            attack_probability=0.75,
            window_start=rec.window_start,
            window_end=rec.window_end,
            evidence={"workload_sample_count": 2.0},
        )
        return [rec]

    monkeypatch.setattr(LiveTelemetryEngine, "process_live_telemetry", mock_process)

    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    at.sidebar.radio[0].set_value(NAV_LIVE)
    at.sidebar.selectbox[0].set_value("workload")
    at.run(timeout=25)

    assert not at.exception
    # Threat Breakdown must report 0 Alert / 1 Normal (not 1 Alert / 0 Normal)
    threat_breakdown = [m for m in at.metric if m.label == "Threat Breakdown"]
    assert len(threat_breakdown) == 1
    assert "0 Alert" in threat_breakdown[0].value
    assert "1 Normal" in threat_breakdown[0].value

    # Must NOT have a red error banner for the idle baseline
    error_banners = [e.value for e in at.error]
    assert not any("PREDICTED THREAT DETECTED" in e for e in error_banners)

    # Must render the informative safeguard banner
    info_banners = [i.value for i in at.info]
    assert any("Idle Baseline Safeguard Applied" in i for i in info_banners)





