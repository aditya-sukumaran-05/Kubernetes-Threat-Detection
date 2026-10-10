"""Unit tests for the end-to-end threat detection inference engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from ml.inference import InferenceResult, InferenceSchemaError, ThreatDetector, predict_window
from telemetry.schemas import Endpoint, NetworkEvent, WorkloadSample


@pytest.fixture
def detector() -> ThreatDetector:
    return ThreatDetector()


@pytest.fixture
def sample_network_window() -> dict[str, object]:
    df = pd.read_csv("results/ml_datasets/network_dataset.csv", nrows=1)
    return df.to_dict("records")[0]


@pytest.fixture
def sample_workload_window() -> dict[str, object]:
    df = pd.read_csv("results/ml_datasets/workload_dataset.csv", nrows=1)
    return df.to_dict("records")[0]


@pytest.fixture
def sample_fusion_window() -> dict[str, object]:
    df = pd.read_csv("results/ml_datasets/fusion_dataset.csv", nrows=1)
    return df.to_dict("records")[0]


def test_inference_rejects_unsupported_modality(detector: ThreatDetector) -> None:
    with pytest.raises(InferenceSchemaError, match="Unsupported modality"):
        detector.predict({}, modality="invalid_modality")


def test_inference_rejects_unsupported_model(detector: ThreatDetector, sample_network_window: dict[str, object]) -> None:
    with pytest.raises(InferenceSchemaError, match="Unsupported model"):
        detector.predict(sample_network_window, modality="network", model_name="neural_net")


def test_inference_rejects_non_dict_window(detector: ThreatDetector) -> None:
    with pytest.raises(InferenceSchemaError, match="must be a dictionary"):
        detector.validate_window(["not", "a", "dict"], modality="network")  # type: ignore[arg-type]


def test_inference_rejects_missing_features(detector: ThreatDetector, sample_network_window: dict[str, object]) -> None:
    incomplete = dict(sample_network_window)
    del incomplete["network_connection_rate"]
    del incomplete["network_event_count"]

    with pytest.raises(InferenceSchemaError, match="Missing required feature.*network_connection_rate"):
        detector.predict(incomplete, modality="network", model_name="random_forest")


def test_inference_rejects_malformed_feature_values(detector: ThreatDetector, sample_workload_window: dict[str, object]) -> None:
    malformed = dict(sample_workload_window)
    malformed["workload_cpu_millicores_mean"] = "not_a_number"

    with pytest.raises(InferenceSchemaError, match="Malformed non-numeric value.*workload_cpu_millicores_mean"):
        detector.predict(malformed, modality="workload", model_name="random_forest")


@pytest.mark.parametrize("modality", ["network", "workload", "fusion"])
@pytest.mark.parametrize("model_name", ["random_forest", "xgboost", "svm"])
def test_successful_inference_across_modalities_and_models(
    detector: ThreatDetector,
    modality: str,
    model_name: str,
    sample_network_window: dict[str, object],
    sample_workload_window: dict[str, object],
    sample_fusion_window: dict[str, object],
) -> None:
    window_map = {
        "network": sample_network_window,
        "workload": sample_workload_window,
        "fusion": sample_fusion_window,
    }
    window = window_map[modality]

    result = detector.predict(window, modality=modality, model_name=model_name)

    assert isinstance(result, InferenceResult)
    assert result.predicted_label in {"normal", "attack"}
    assert result.attack_probability is not None
    assert 0.0 <= result.attack_probability <= 1.0
    assert result.confidence is not None
    assert 0.0 <= result.confidence <= 1.0
    assert result.modality == modality
    assert result.model_name == model_name
    assert "feature_values" in result.evidence

    # Verify dictionary serialization
    result_dict = result.to_dict()
    assert result_dict["predicted_label"] == result.predicted_label
    assert result_dict["modality"] == modality


def test_predict_window_convenience_api(sample_fusion_window: dict[str, object]) -> None:
    result = predict_window(sample_fusion_window, modality="fusion", model_name="random_forest")
    assert isinstance(result, dict)
    assert result["predicted_label"] in {"normal", "attack"}
    assert "evidence" in result
    assert result["modality"] == "fusion"


def test_raw_telemetry_event_inference(detector: ThreatDetector) -> None:
    # Construct mock raw network events in one 10s window
    t0 = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 20, 10, 0, 2, tzinfo=timezone.utc)
    events = [
        NetworkEvent(timestamp=t0, event_type="accept", source=Endpoint("10.244.0.5", 54321), destination=Endpoint("10.244.0.2", 80), pod="webapp-test", error=None),
        NetworkEvent(timestamp=t1, event_type="close", source=Endpoint("10.244.0.5", 54321), destination=Endpoint("10.244.0.2", 80), pod="webapp-test", error=None),
    ]
    net_results = detector.predict_network_events(events, model_name="random_forest")
    assert len(net_results) == 1
    assert net_results[0].modality == "network"
    assert net_results[0].predicted_label in {"normal", "attack"}

    # Construct mock raw workload samples in the same window
    samples = [
        WorkloadSample(timestamp=t0, pod="webapp-test", cpu_millicores=15.0, memory_mib=14.0),
        WorkloadSample(timestamp=t1, pod="webapp-test", cpu_millicores=16.0, memory_mib=14.0),
    ]
    workload_results = detector.predict_workload_samples(samples, model_name="random_forest")
    assert len(workload_results) == 1
    assert workload_results[0].modality == "workload"
    assert workload_results[0].predicted_label in {"normal", "attack"}

    # Test fusion inference from raw streams
    fusion_results = detector.predict_fusion_telemetry(events, samples, session_id="test_sess", model_name="random_forest")
    assert len(fusion_results) == 1
    assert fusion_results[0].modality == "fusion"
    assert fusion_results[0].predicted_label in {"normal", "attack"}
