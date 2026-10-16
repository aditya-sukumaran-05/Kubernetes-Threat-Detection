"""Experiment Research Workspace component for Streamlit dashboard.

Enables browsing historical harness runs, viewing multi-modality capture status,
comparing activity versus baseline runs with delta calculations, and inspecting
raw window summaries and correlation details.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from experiments.harness import DEFAULT_OUTPUT_DIR, compare_experiments


def _load_run_dirs(output_root: Path) -> list[Path]:
    """Find all valid experiment run directories containing metadata."""
    if not output_root.exists():
        return []
    run_dirs = []
    for item in sorted(output_root.iterdir(), reverse=True):
        if item.is_dir() and (item / "experiment_metadata.json").exists():
            run_dirs.append(item)
    return run_dirs


def render_experiment_workspace(project_root: Path) -> None:
    """Render the Experiment Research Workspace view."""
    st.info(
        "🔬 **EXPERIMENT RESEARCH WORKSPACE:** Explore reproducible Kubernetes telemetry runs "
        "executed via the experiment harness (`experiments/harness.py`). Review multi-modality "
        "capture status (Network, Runtime, Workload), compare baseline versus activity conditions, "
        "and inspect raw observation windows.",
        icon="ℹ️",
    )

    output_root = (project_root / DEFAULT_OUTPUT_DIR).resolve()
    run_dirs = _load_run_dirs(output_root)

    if not run_dirs:
        st.warning(
            f"No completed experiment runs found in `{output_root}`. "
            "Execute a controlled scenario first via:\n\n"
            "`python experiments/harness.py --scenario baseline`\n"
            "`python experiments/harness.py --scenario network_burst`"
        )
        return

    tab_runs, tab_compare, tab_executor = st.tabs([
        "📂 Browse Experiment Runs",
        "⚖️ Run Comparator (Activity vs Baseline)",
        "🚀 Trigger Controlled Harness Run",
    ])

    # TAB 1: Browse Runs
    with tab_runs:
        st.subheader("📂 Experiment Run Catalog")
        run_options = {d.name: d for d in run_dirs}
        selected_run_name = st.selectbox(
            "Select Experiment Run to Inspect:",
            options=list(run_options.keys()),
            index=0,
            key="exp_workspace_select_run",
        )
        selected_dir = run_options[selected_run_name]

        meta_file = selected_dir / "experiment_metadata.json"
        summary_file = selected_dir / "telemetry_summary.json"

        try:
            metadata: dict[str, Any] = json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception as exc:
            st.error(f"Failed to read experiment metadata: {exc}")
            return

        # High-level run metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Scenario", metadata.get("scenario", "Unknown").replace("_", " ").title())
        m2.metric("Status", str(metadata.get("status", "unknown")).upper())
        m3.metric("Duration (s)", f"{metadata.get('duration_seconds', 0.0):.2f}s")
        m4.metric("Cluster Context", metadata.get("cluster_id", "minikube"))

        # Modality Capture Badges
        st.markdown("##### 📡 Telemetry Modality Ingestion Status")
        caps = metadata.get("modalities_captured", {})
        c_net, c_rt, c_wl = st.columns(3)
        with c_net:
            status_tag = "✅ Captured" if caps.get("network") else "⚪ Inactive / Idle"
            st.markdown(f"**Network (eBPF TCP):** `{status_tag}`")
        with c_rt:
            status_tag = "✅ Captured" if caps.get("runtime") else "⚪ Inactive / Idle"
            st.markdown(f"**Runtime (trace_exec):** `{status_tag}`")
        with c_wl:
            status_tag = "✅ Captured" if caps.get("workload") else "⚪ Inactive / Idle"
            st.markdown(f"**Workload (Metrics):** `{status_tag}`")

        # Correlation Details
        st.markdown("##### 📊 Telemetry Feature Correlation Details")
        corrs = metadata.get("modality_correlations", {})
        corr_rows = []
        for mod, details in corrs.items():
            corr_rows.append({
                "Modality": mod.title(),
                "Captured": "Yes" if details.get("captured") else "No",
                "Record Count": details.get("record_count", 0),
                "Summary Details": str(details.get("details", {})) if details.get("captured") else details.get("reason", "N/A"),
            })
        st.dataframe(pd.DataFrame(corr_rows), width="stretch", hide_index=True)

        # 10s Window Table
        if summary_file.exists():
            st.markdown("##### 🪟 Correlated 10-Second Windows")
            try:
                summary_data = json.loads(summary_file.read_text(encoding="utf-8"))
                windows = summary_data.get("windows", [])
                if windows:
                    win_df = pd.DataFrame(windows)
                    st.dataframe(win_df, width="stretch", hide_index=True)

                    # Export windows as CSV
                    csv_bytes = win_df.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        label="⬇️ Download Correlated Windows (CSV)",
                        data=csv_bytes,
                        file_name=f"{metadata.get('experiment_id', 'run')}_windows.csv",
                        mime="text/csv",
                        key="btn_dl_windows_csv",
                    )
            except Exception as exc:
                st.caption(f"Could not load window details: {exc}")

    # TAB 2: Run Comparator
    with tab_compare:
        st.subheader("⚖️ Comparative Run Evaluation")
        st.caption(
            "Select a baseline run (e.g. benign traffic) and an activity run (e.g. network burst, "
            "process execution, or CPU variation) to compute objective deltas and percent changes."
        )

        col_base, col_act = st.columns(2)
        with col_base:
            base_choice = st.selectbox(
                "Baseline Reference Run:",
                options=list(run_options.keys()),
                index=0,
                key="exp_cmp_baseline",
            )
        with col_act:
            default_act_idx = min(1, len(run_options) - 1)
            act_choice = st.selectbox(
                "Activity / Condition Run:",
                options=list(run_options.keys()),
                index=default_act_idx,
                key="exp_cmp_activity",
            )

        base_dir = run_options[base_choice]
        act_dir = run_options[act_choice]

        try:
            cmp_dict, cmp_rows = compare_experiments(base_dir, act_dir)
            if cmp_rows:
                cmp_df = pd.DataFrame(cmp_rows)

                st.markdown("#### 📊 Metric Divergence Table")
                st.dataframe(cmp_df, width="stretch", hide_index=True)

                # Visualize deltas with a horizontal bar chart
                st.markdown("#### 📈 Delta Overview by Telemetry Modality")
                plot_data = cmp_df[["metric", "delta", "modality"]].copy()
                st.bar_chart(plot_data.set_index("metric")["delta"])

                # CSV Download
                csv_bytes = cmp_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="⬇️ Export Comparison Table (CSV)",
                    data=csv_bytes,
                    file_name=f"comparison_{cmp_dict['baseline_scenario']}_vs_{cmp_dict['activity_scenario']}.csv",
                    mime="text/csv",
                    key="btn_dl_cmp_csv",
                )
        except Exception as exc:
            st.error(f"Error performing run comparison: {exc}")

    # TAB 3: Safe On-Demand Trigger / Preflight Form
    with tab_executor:
        st.subheader("🚀 Controlled Experiment Execution")
        st.caption(
            "Safely trigger a reproducible, resource-bounded experiment scenario. "
            "Execution is bounded by hard safety limits defined in `configs/harness.yaml`."
        )

        scenario_sel = st.selectbox(
            "Select Scenario to Run:",
            options=["baseline", "network_burst", "runtime_activity", "workload_variation"],
            index=0,
            key="harness_exec_scenario",
        )
        dry_run_opt = st.checkbox(
            "Dry-Run Mode (Preflight validation & metadata creation only — no live traffic generated)",
            value=True,
            help="Dry-run tests cluster connectivity and creates experiment plan metadata safely.",
        )

        if st.button("▶️ Execute Controlled Scenario", key="btn_run_harness_scenario"):
            with st.spinner(f"Executing scenario '{scenario_sel}' (dry_run={dry_run_opt})..."):
                try:
                    from experiments.harness import TelemetryHarness
                    harness = TelemetryHarness()
                    r_dir, r_meta, _ = harness.execute_experiment(scenario_sel, dry_run=dry_run_opt)
                    st.success(
                        f"✅ Experiment `{r_meta.experiment_id}` completed successfully!\n\n"
                        f"- **Scenario:** `{r_meta.scenario}`\n"
                        "- **Duration:** " f"`{r_meta.duration_seconds:.2f}s`\n"
                        f"- **Output Directory:** `{r_dir}`"
                    )
                    st.rerun()
                except Exception as exc:
                    st.error(f"❌ Execution failed: {exc}")
