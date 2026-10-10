"""Detection summary component displaying inference verdict, probabilities, and context."""

from __future__ import annotations

import streamlit as st

from ml.inference import InferenceResult


def render_detection_summary(result: InferenceResult, ground_truth: str | None = None) -> None:
    """Render the primary detection verdict banner and key metrics."""
    is_attack = result.predicted_label == "attack"

    # Prominent Verdict Banner
    if is_attack:
        st.error(
            "🚨 **SECURITY ALERT: THREAT DETECTED** — Telemetry window exhibits attack patterns.",
            icon="🚨",
        )
    else:
        st.success(
            "✅ **BENIGN STATUS: NORMAL WORKLOAD** — Telemetry window conforms to expected baseline.",
            icon="✅",
        )

    # Core Metrics Row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        delta_str = f"Ground Truth: {ground_truth}" if ground_truth else None
        st.metric(
            label="Predicted Class",
            value=result.predicted_label.upper(),
            delta=delta_str,
            delta_color="normal" if (not ground_truth or ground_truth == result.predicted_label) else "inverse",
        )

    with col2:
        prob_str = f"{result.attack_probability * 100:.1f}%" if result.attack_probability is not None else "N/A"
        st.metric(label="Attack Probability", value=prob_str)

    with col3:
        conf_str = f"{result.confidence * 100:.1f}%" if result.confidence is not None else "N/A"
        st.metric(label="Model Confidence", value=conf_str)

    with col4:
        st.metric(label="Modality & Model", value=f"{result.modality.title()}", delta=result.model_name)

    # Window & Context Sub-Bar
    st.markdown("---")
    ctx_col1, ctx_col2, ctx_col3 = st.columns(3)
    with ctx_col1:
        st.caption("🕒 **Window Start (UTC)**")
        st.write(f"`{result.window_start or 'N/A'}`")
    with ctx_col2:
        st.caption("🕒 **Window End (UTC)**")
        st.write(f"`{result.window_end or 'N/A'}`")
    with ctx_col3:
        st.caption("🎯 **Affected Pod(s)**")
        st.write(f"`{result.affected_pods or 'webapp (app=webapp)'}`")
