"""Settings and operational configuration view for K8S Sentinel."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

from dashboard.live_engine import (
    DEFAULT_NETWORK_PATH,
    DEFAULT_RUNTIME_PATH,
    DEFAULT_WORKLOAD_PATH,
    MAX_RETAINED_WINDOWS,
    STALE_THRESHOLD_SECONDS,
)


def render_settings_view(project_root: Path | str | None = None) -> None:
    """Render the Settings and Environment Configuration view."""
    st.markdown("## ⚙️ Platform Settings & Environment Configuration")
    st.caption("Inspect Kubernetes cluster connectivity, telemetry collection paths, and operational thresholds.")
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### ☸️ Cluster & Workload Target")
        st.markdown(
            "- **Cluster Context:** `minikube` (Single-node control plane)\n"
            "- **Target Namespace:** `default`\n"
            "- **Monitored Workload:** `deployment/webapp` (`nginx`)\n"
            "- **Workload Discovery:** Dynamic label selector `app=webapp`\n"
            "- **Service Architecture:** `NodePort` on port `80`\n"
            "- **Container Runtime:** `containerd://2.3.4`"
        )

        st.markdown("#### ⏱️ Engine & Temporal Synchronization")
        st.markdown(
            f"- **Observation Window Duration:** `10.0 seconds` (Fixed UTC alignment)\n"
            f"- **Max Retained Memory Windows:** `{MAX_RETAINED_WINDOWS}`\n"
            f"- **Telemetry Stale Threshold:** `{STALE_THRESHOLD_SECONDS} seconds`\n"
            "- **Clock Skew Tolerance:** `2.0 seconds`"
        )

    with c2:
        st.markdown("#### 📁 Telemetry Ingestion Paths")
        st.markdown(
            f"- **eBPF TCP Trace:** `{DEFAULT_NETWORK_PATH}`\n"
            f"- **eBPF Process Exec:** `{DEFAULT_RUNTIME_PATH}`\n"
            f"- **Metrics Server CSV:** `{DEFAULT_WORKLOAD_PATH}`\n"
            "- **Offline Datasets:** `results/ml_datasets/`\n"
            "- **LOSO Evaluation Artifacts:** `results/loso/`"
        )

        st.markdown("#### 🐍 Runtime & Host Environment")
        st.markdown(
            f"- **Python Version:** `{sys.version.split()[0]}`\n"
            f"- **Operating System:** `{sys.platform.upper()}`\n"
            "- **eBPF Tracer:** `Inspektor Gadget v0.55.1` (`trace_tcp`, `trace_exec`)\n"
            "- **Workload Sampler:** `Kubernetes Metrics Server` (`kubectl top pod`)"
        )
