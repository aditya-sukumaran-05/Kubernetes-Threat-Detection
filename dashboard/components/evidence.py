"""Evidence and explainability component presenting model-derived telemetry feature values."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from ml.inference import InferenceResult


def render_evidence(result: InferenceResult) -> None:
    """Display feature evidence and model-native importances without inventing metrics."""
    st.subheader("🔍 Model-Derived Evidence & Feature Breakdown")

    top_features = result.evidence.get("top_features")

    if top_features:
        st.markdown("**Top Contributing Features** (Model-Native Decision Weight)")
        evidence_df = pd.DataFrame(top_features)
        evidence_df.columns = ["Feature", "Model Importance", "Observed Window Value"]

        col1, col2 = st.columns([3, 2])
        with col1:
            st.dataframe(
                evidence_df.style.format({
                    "Model Importance": "{:.4f}",
                    "Observed Window Value": "{:.4f}",
                }),
                width="stretch",
                hide_index=True,
            )
        with col2:
            chart_df = evidence_df.set_index("Feature")["Model Importance"]
            st.bar_chart(chart_df, horizontal=True)

        st.caption(
            "ℹ️ *Note: Feature importance represents model-derived evidence (tree-impurity weight), "
            "not causal attribution.*"
        )
    elif result.model_name == "svm":
        st.info("ℹ️ *RBF Kernel Support Vector Machines use non-linear dual space; linear feature importances are not defined.*")

    # Complete Raw Feature Values Table
    feature_values = result.evidence.get("feature_values", {})
    if feature_values:
        with st.expander("📋 View All Feature Values for this Window", expanded=False):
            all_df = pd.DataFrame(
                [{"Feature Name": k, "Value": v} for k, v in feature_values.items()]
            )
            st.dataframe(all_df, width="stretch", hide_index=True)
