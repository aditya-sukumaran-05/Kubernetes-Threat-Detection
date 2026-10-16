"""Modern SOC dark-theme styling inspired by the K8S SENTINEL SOC Dashboard design."""

from __future__ import annotations

import streamlit as st


SENTINEL_DARK_THEME_CSS = """
<style>
/* Global Modern SOC Styling */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #cbd5e1;
}

/* Background & Main App Canvas */
.stApp {
    background-color: #0b0f19;
    overflow-x: hidden;
    max-width: 100vw;
}

code, pre, [data-testid="stMarkdownContainer"] code {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Top Sentinel Navbar / Pill Header */
.sentinel-header-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    background: #111827;
    border: 1px solid rgba(55, 65, 81, 0.6);
    border-radius: 12px;
    padding: 10px 18px;
    margin-bottom: 20px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
}

.sentinel-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #1e293b;
    border: 1px solid rgba(75, 85, 99, 0.5);
    border-radius: 8px;
    padding: 4px 10px;
    font-size: 0.80rem;
    font-weight: 500;
    color: #e2e8f0;
    white-space: nowrap;
}

.sentinel-pill-live {
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.4);
    color: #34d399;
}

/* Metric Card Container Styling - K8S Sentinel Quad KPI Cards */
div[data-testid="stMetric"] {
    background: linear-gradient(180deg, #131b2e 0%, #0d1322 100%) !important;
    border: 1px solid rgba(59, 130, 246, 0.2) !important;
    border-radius: 12px !important;
    padding: 12px 14px !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4) !important;
    transition: transform 0.15s ease, border-color 0.15s ease;
    min-width: 0 !important;
    overflow: hidden !important;
}

div[data-testid="stMetric"]:hover {
    border-color: rgba(99, 102, 241, 0.5) !important;
    transform: translateY(-2px);
}

h1 {
    font-size: 2.05rem !important;
    font-weight: 800 !important;
    color: #f8fafc !important;
    letter-spacing: -0.025em !important;
    margin-bottom: 0.35rem !important;
}

h2 {
    font-size: 1.60rem !important;
    font-weight: 750 !important;
    color: #f1f5f9 !important;
    letter-spacing: -0.015em !important;
    margin-bottom: 0.3rem !important;
}

h3 {
    font-size: 1.30rem !important;
    font-weight: 700 !important;
    color: #e2e8f0 !important;
}

h4 {
    font-size: 1.12rem !important;
    font-weight: 650 !important;
    color: #cbd5e1 !important;
}

div[data-testid="stMetricLabel"] {
    font-size: 0.82rem !important;
    font-weight: 700 !important;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #94a3b8 !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}

div[data-testid="stMetricValue"] {
    font-size: 1.70rem !important;
    font-weight: 800 !important;
    color: #ffffff !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #070a13 !important;
    border-right: 1px solid rgba(55, 65, 81, 0.4) !important;
}

/* Sidebar Branding Badge */
.sentinel-brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 6px;
    margin-bottom: 12px;
}

.sentinel-brand-title {
    font-size: 1.15rem;
    font-weight: 800;
    letter-spacing: 0.05em;
    color: #f8fafc;
    line-height: 1.2;
}

.sentinel-brand-sub {
    font-size: 0.72rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}

/* Panel Containers (Collector Health, Telemetry Activity, Recent Decisions) */
.sentinel-panel {
    background: #111827;
    border: 1px solid rgba(55, 65, 81, 0.5);
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.3);
    margin-bottom: 16px;
}

.sentinel-panel-title {
    font-size: 0.95rem;
    font-weight: 600;
    color: #f1f5f9;
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
}

.sentinel-panel-sub {
    font-size: 0.78rem;
    color: #64748b;
    margin-bottom: 14px;
}

/* Collector Row Card in Panel */
.collector-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(17, 24, 39, 0.7);
    border: 1px solid rgba(55, 65, 81, 0.4);
    border-radius: 8px;
    padding: 10px 14px;
    margin-bottom: 8px;
}

.collector-row:hover {
    border-color: rgba(99, 102, 241, 0.4);
}

.status-badge {
    padding: 2px 8px;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.badge-healthy {
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.35);
}

.badge-stale {
    background: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.35);
}

.badge-offline {
    background: rgba(239, 68, 68, 0.15);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.35);
}

.badge-live-stream {
    background: rgba(16, 185, 129, 0.18);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.5);
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 0.75rem;
    letter-spacing: 0.04em;
    display: inline-flex;
    align-items: center;
    gap: 5px;
}

.badge-historical-replay {
    background: rgba(99, 102, 241, 0.18);
    color: #818cf8;
    border: 1px solid rgba(99, 102, 241, 0.5);
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 0.75rem;
    letter-spacing: 0.04em;
    display: inline-flex;
    align-items: center;
    gap: 5px;
}

/* Tabs styling */
div[data-baseweb="tab-list"] {
    background: transparent;
    border-bottom: 1px solid rgba(55, 65, 81, 0.6);
    gap: 6px;
}

div[data-baseweb="tab"] {
    padding: 10px 18px !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    border-radius: 8px 8px 0 0;
    color: #94a3b8 !important;
}

div[data-baseweb="tab"][aria-selected="true"] {
    color: #60a5fa !important;
    border-bottom: 2px solid #3b82f6 !important;
}

/* Tables / DataFrames */
div[data-testid="stDataFrame"] {
    border: 1px solid rgba(55, 65, 81, 0.5) !important;
    border-radius: 8px !important;
    background: #0f172a !important;
}

/* Expander headers */
div[data-testid="stExpander"] {
    border: 1px solid rgba(55, 65, 81, 0.5) !important;
    border-radius: 10px !important;
    background: #0f172a !important;
}

/* Radio buttons in sidebar styled as Nav Items */
div[data-testid="stSidebar"] div[role="radiogroup"] label {
    background: transparent;
    padding: 6px 12px;
    border-radius: 8px;
    margin-bottom: 3px;
    transition: background-color 0.12s ease;
}

div[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
    background: rgba(55, 65, 81, 0.4);
}
</style>
"""


def apply_soc_styles() -> None:
    """Inject custom CSS into Streamlit page."""
    st.markdown(SENTINEL_DARK_THEME_CSS, unsafe_allow_html=True)


def render_brand_sidebar() -> None:
    """Render the Sentinel brand header in the sidebar."""
    st.sidebar.markdown(
        """
        <div class="sentinel-brand">
            <span style="font-size: 1.8rem;">🛡️</span>
            <div>
                <div class="sentinel-brand-title">K8S SENTINEL</div>
                <div class="sentinel-brand-sub">Threat Detection Platform</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_cluster_status_sidebar(
    cluster_name: str = "minikube",
    k8s_version: str = "v1.37.0",
    nodes: int = 1,
    pods: int = 4,
    status_text: str = "Ready",
) -> None:
    """Render the bottom cluster context status in the sidebar matching the reference."""
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        f"""
        <div style="padding: 4px 6px;">
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10b981;"></span>
                <span style="font-size: 0.76rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8;">Cluster Status</span>
            </div>
            <div style="font-size: 0.95rem; font-weight: 700; color: #f8fafc; margin-bottom: 2px;">● {cluster_name}</div>
            <div style="font-size: 0.78rem; color: #64748b;">
                Kubernetes {k8s_version}<br>
                {nodes} node • {pods} active pods
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
