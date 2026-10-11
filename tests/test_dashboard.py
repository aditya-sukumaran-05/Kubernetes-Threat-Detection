"""Automated tests for the threat detection dashboard, navigation, and components."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from dashboard.app import NAV_ALERTS, NAV_LIVE, NAV_REPLAY, NAV_RESEARCH
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
    """Test full Streamlit app lifecycle using AppTest landing on default Live Monitoring."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=25)

    assert not at.exception
    # Verify title
    assert len(at.title) >= 1
    # Verify presence of metrics on default Live Monitoring page
    metric_labels = [m.label for m in at.metric]
    assert "Valid Network Events" in metric_labels
    assert "Inference Windows (10s)" in metric_labels
    assert "Active Model" in metric_labels


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

    # Defaults to Live Threat Monitoring
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

    # Defaults to Live Threat Monitoring
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
