"""Automated tests for the threat detection dashboard and telemetry provider."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from dashboard.telemetry_provider import CapturedDatasetProvider, LiveKubernetesProvider


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


def test_dashboard_app_renders_successfully() -> None:
    """Test full Streamlit app lifecycle using AppTest."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=15)

    assert not at.exception
    # Verify title
    assert len(at.title) >= 1
    # Verify presence of metrics (Predicted Class, Attack Probability, Confidence, Modality)
    metric_labels = [m.label for m in at.metric]
    assert "Predicted Class" in metric_labels
    assert "Attack Probability" in metric_labels
    assert "Model Confidence" in metric_labels


def test_dashboard_manual_mode_toggle() -> None:
    """Test switching detection source mode to Manual Window in AppTest."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=15)

    # Toggle radio to Manual Window
    at.sidebar.radio[0].set_value("Manual Window")
    at.run(timeout=15)

    assert not at.exception
    # Verify text area for JSON input is rendered
    assert len(at.text_area) >= 1
    assert "Telemetry Window JSON Payload" in at.text_area[0].label


def test_dashboard_live_network_capture_mode_toggle() -> None:
    """Test switching detection source mode to Live Network Capture in AppTest."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=15)

    # Toggle radio to Live Network Capture
    at.sidebar.radio[0].set_value("Live Network Capture")
    at.run(timeout=15)

    assert not at.exception
    # Verify live capture metrics are rendered
    metric_labels = [m.label for m in at.metric]
    assert "Valid Network Events" in metric_labels
    assert "Inference Windows (10s)" in metric_labels
    assert "Threat Breakdown" in metric_labels
    assert "Active Model" in metric_labels
    assert "Predicted Class" in metric_labels

    # Verify windows table is rendered
    assert len(at.dataframe) >= 1


def test_dashboard_live_network_capture_model_switch() -> None:
    """Test switching models while in Live Network Capture mode."""
    at = AppTest.from_file("dashboard/app.py")
    at.run(timeout=15)

    at.sidebar.radio[0].set_value("Live Network Capture")
    at.sidebar.selectbox[1].set_value("xgboost")
    at.run(timeout=15)

    assert not at.exception
    model_metrics = [m for m in at.metric if m.label == "Active Model"]
    assert len(model_metrics) == 1
    assert model_metrics[0].value == "Xgboost"

    at.sidebar.selectbox[1].set_value("svm")
    at.run(timeout=15)
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
    at.run(timeout=15)

    at.sidebar.radio[0].set_value("Live Network Capture")
    at.run(timeout=15)

    assert not at.exception
    # Verify table is rendered
    assert len(at.dataframe) >= 1
    initial_rows = len(at.dataframe[0].value)

    # Check the network traffic filter checkbox
    filter_cb = [c for c in at.checkbox if "Show only windows with active network traffic" in c.label]
    assert len(filter_cb) == 1
    filter_cb[0].set_value(True)
    at.run(timeout=15)

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


