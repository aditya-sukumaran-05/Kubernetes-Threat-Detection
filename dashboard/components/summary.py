"""Detection summary component displaying inference verdict, probabilities, and context."""

from __future__ import annotations

import streamlit as st

from ml.inference import InferenceResult


def format_probability(prob: float | None) -> str:
    """Format a probability value with adaptive precision.

    Prevents small non-zero probabilities from being displayed as misleading 0.0%,
    while keeping ordinary numbers clean and readable.
    """
    if prob is None:
        return "N/A"
    if prob == 0.0:
        return "0.0%"
    pct = prob * 100.0
    if pct < 0.01:
        return "< 0.01%"
    if pct < 0.1:
        return f"{pct:.2f}%"
    return f"{pct:.1f}%"


def render_detection_summary(
    result: InferenceResult,
    ground_truth: str | None = None,
    window_idx: int | None = None,
    total_windows: int | None = None,
    session_id: str | None = None,
    is_live: bool = False,
) -> None:
    """Render the primary detection verdict banner and key metrics."""
    is_attack = result.predicted_label == "attack"

    # Data Provenance Banner
    if is_live:
        st.caption("📡 **Data Provenance:** `Live Cluster Telemetry (Active Streaming)`")
    else:
        st.caption("📼 **Data Provenance:** `Historical Experiment Replay (Controlled Campaign — Not Live Activity)`")

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

    # Prominent Window Context Header
    if window_idx is not None and total_windows is not None:
        ctx_parts = [f"📍 **Window {window_idx + 1} of {total_windows}**"]
        if session_id:
            ctx_parts.append(f"Session: `{session_id}`")
        ctx_parts.append(f"Modality: **{result.modality.title()}**")
        ctx_parts.append(f"Model: **{result.model_name.replace('_', ' ').title()}**")
        st.info(" | ".join(ctx_parts), icon="ℹ️")

    # Core Metrics Row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        delta_str = None
        delta_color = "normal"
        if ground_truth:
            gt_norm = str(ground_truth).strip().lower()
            pred_norm = result.predicted_label.strip().lower()
            if gt_norm == pred_norm:
                if gt_norm == "attack":
                    delta_str = "Ground Truth: ATTACK (True Positive)"
                else:
                    delta_str = "Ground Truth: NORMAL (True Negative)"
                delta_color = "normal"
            else:
                if pred_norm == "attack":
                    delta_str = "Ground Truth: NORMAL (False Positive)"
                else:
                    delta_str = "Ground Truth: ATTACK (False Negative)"
                delta_color = "inverse"

        st.metric(
            label="Predicted Class",
            value=result.predicted_label.upper(),
            delta=delta_str,
            delta_color=delta_color,
        )

    with col2:
        prob_str = format_probability(result.attack_probability)
        st.metric(
            label="Attack Probability",
            value=prob_str,
            help="Estimated probability of attack condition: P(y = attack)",
        )

    with col3:
        conf_str = format_probability(result.confidence)
        st.metric(
            label="Model Confidence",
            value=conf_str,
            help="Model confidence in winning predicted class: P(y = ŷ). "
                 "Equals Attack Probability when prediction is ATTACK; "
                 "equals (100% - Attack Probability) when prediction is NORMAL.",
        )

    with col4:
        st.metric(
            label="Modality & Model",
            value=result.modality.title(),
            delta=result.model_name.replace("_", " ").title(),
        )

    # Clarification on Confidence vs Attack Probability
    st.caption(
        "ℹ️ *Note on Confidence:* Predicted-Class Confidence is the probability of the winning class P(y = ŷ). "
        "For attack predictions, it equals Attack Probability. For normal predictions, it equals (100% - Attack Probability)."
    )

    # Window & Context Sub-Bar
    st.markdown("---")
    ctx_col1, ctx_col2, ctx_col3, ctx_col4 = st.columns(4)
    with ctx_col1:
        st.caption("🕒 **Window Start (UTC)**")
        st.write(f"`{result.window_start or 'N/A'}`")
    with ctx_col2:
        st.caption("🕒 **Window End (UTC)**")
        st.write(f"`{result.window_end or 'N/A'}`")
    with ctx_col3:
        st.caption("🎯 **Affected Pod(s)**")
        st.write(f"`{result.affected_pods or 'webapp (app=webapp)'}`")
    with ctx_col4:
        st.caption("🏷️ **Ground-Truth Label**")
        st.write(f"`{ground_truth or 'Unlabeled'}`")
