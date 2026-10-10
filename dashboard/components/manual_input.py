"""Manual telemetry window input component for testing arbitrary JSON payloads."""

from __future__ import annotations

import json
from typing import Any

import streamlit as st

from ml.inference import InferenceResult, InferenceSchemaError, ThreatDetector


def _generate_template_window(detector: ThreatDetector, modality: str) -> dict[str, Any]:
    """Generate a clean JSON template containing all required features for a modality."""
    features = detector.get_required_features(modality)
    template: dict[str, Any] = {
        "window_start": "2026-09-20T12:00:00.000Z",
        "window_end": "2026-09-20T12:00:10.000Z",
        "affected_pods": "webapp-79699899c5-manual",
    }
    for feat in features:
        # Provide reasonable baseline values
        if "rate" in feat:
            template[feat] = 0.5
        elif "count" in feat or "ips" in feat or "ports" in feat:
            template[feat] = 5
        elif "cpu" in feat:
            template[feat] = 120.0
        elif "memory" in feat:
            template[feat] = 15.0
        else:
            template[feat] = 0.0
    return template


def render_manual_input(
    detector: ThreatDetector, modality: str, model_name: str
) -> InferenceResult | None:
    """Render editable JSON input area and run inference upon submission."""
    st.subheader("✍️ Submit Manual Telemetry Window")
    st.markdown(
        f"Submit a custom telemetry observation window for **{modality.title()}** inference using **{model_name}**."
    )

    template = _generate_template_window(detector, modality)
    template_json = json.dumps(template, indent=2)

    user_input = st.text_area(
        label="Telemetry Window JSON Payload",
        value=template_json,
        height=320,
        help="Edit or paste a JSON object matching the required telemetry schema.",
    )

    col1, col2 = st.columns([1, 4])
    with col1:
        submit = st.button("🚀 Run Threat Detection", type="primary")

    if submit:
        try:
            parsed_window = json.loads(user_input)
            if not isinstance(parsed_window, dict):
                st.error("Payload must be a single JSON object (dictionary).", icon="⚠️")
                return None

            result = detector.predict(parsed_window, modality=modality, model_name=model_name)
            return result
        except json.JSONDecodeError as exc:
            st.error(f"Malformed JSON: {exc}", icon="❌")
            return None
        except InferenceSchemaError as exc:
            st.error(f"Feature Schema Validation Error: {exc}", icon="⚠️")
            return None
        except FileNotFoundError as exc:
            st.error(f"Model Checkpoint Error: {exc}", icon="❌")
            return None
        except Exception as exc:  # Catch unexpected errors gracefully
            st.error(f"Inference Failure: {exc}", icon="❌")
            return None

    return None
