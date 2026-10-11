"""Research diagnostics and telemetry ablation component for Streamlit dashboard.

Presents empirical results from Leave-One-Session-Out (LOSO) cross-validation
and single-session holdout ablation experiments comparing Network-only, Workload-only,
and Multimodal Fusion threat detection performance.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from dashboard.components.summary import format_probability


def _load_loso_data(results_dir: Path) -> list[dict[str, Any]]:
    """Load aggregate LOSO cross-validation results from CSV."""
    loso_csv = results_dir / "loso" / "loso_aggregate_comparison.csv"
    if not loso_csv.exists():
        return []
    with loso_csv.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def _load_ablation_json(results_dir: Path) -> dict[str, Any] | None:
    """Load single-session holdout ablation benchmark JSON."""
    ablation_json = results_dir / "ablation_comparison.json"
    if not ablation_json.exists():
        return None
    try:
        return json.loads(ablation_json.read_text(encoding="utf-8"))
    except Exception:
        return None


def render_research_diagnostics(project_root: Path | str | None = None) -> None:
    """Render the Research & Model Diagnostics view."""
    root = Path(project_root) if project_root else Path(".")
    results_dir = root / "results"

    st.header("🔬 Research & Model Diagnostics")
    st.markdown(
        "Empirical evaluation and telemetry ablation study comparing **Network-only (eBPF TCP)**, "
        "**Workload-only (cgroup / Metrics Server)**, and **Multimodal Fusion** threat detection. "
        "Evaluated via **Leave-One-Session-Out (LOSO)** cross-validation across 24 controlled Kubernetes experiment sessions."
    )

    # 1. Academic Reference & Context Card
    with st.expander("📚 Research Methodology & Academic Positioning", expanded=False):
        st.markdown(
            "• **Academic Context:** M.Tech Software Engineering Capstone Project.\n"
            "• **Primary Baseline:** Morsli, Kara, Ould-Slimane, Lahlou, *'Multidimensional Intrusion Detection System "
            "for Containerized Environments'*, IEEE NetSoft 2025 ([DOI: 10.1109/NetSoft64993.2025.11080585](https://doi.org/10.1109/NetSoft64993.2025.11080585)).\n"
            "• **Data Leakage Prevention:** Temporal autocorrelation across adjacent 10-second observation windows "
            "is eliminated by evaluating entire independent experiment runs (Leave-One-Session-Out). Preprocessing pipelines "
            "(imputation, standard scaling) are fitted strictly per training fold.\n"
            "• **Controlled Environment:** Minikube Kubernetes cluster running `webapp` (nginx) under Inspektor Gadget "
            "v0.55.1 eBPF socket tracing and Metrics Server."
        )

    # 2. Load LOSO aggregate results
    loso_rows = _load_loso_data(results_dir)
    if not loso_rows:
        st.warning(
            f"⚠️ LOSO evaluation results not found at `{results_dir / 'loso' / 'loso_aggregate_comparison.csv'}`. "
            "Run: `python -m ml.loso --project-root .` to generate empirical cross-validation benchmarks."
        )
        return

    # Derive headline metrics dynamically from loaded LOSO artifacts
    fusion_rows = [r for r in loso_rows if str(r.get("telemetry", "")).strip().lower() == "fusion"]
    target_rows = fusion_rows if fusion_rows else loso_rows

    total_folds_val = max((int(r.get("total_folds", 0)) for r in target_rows if str(r.get("total_folds", "")).isdigit()), default=0)
    total_samples_val = max((int(r.get("total_samples", 0)) for r in target_rows if str(r.get("total_samples", "")).isdigit()), default=0)

    best_row = None
    best_f1_val = -1.0
    for r in target_rows:
        try:
            f1_cand = float(r.get("aggregate_f1", -1.0))
            if f1_cand > best_f1_val:
                best_f1_val = f1_cand
                best_row = r
        except (ValueError, TypeError):
            continue

    if best_row is not None and best_f1_val >= 0.0:
        try:
            best_fpr_val = float(best_row.get("aggregate_false_positive_rate", 0.0))
            best_fpr_str = f"{best_fpr_val:.3f} ({best_fpr_val * 100:.1f}%)"
        except (ValueError, TypeError):
            best_fpr_str = "N/A"
        best_model_name = str(best_row.get("model", "N/A")).replace("_", " ").title()
        best_f1_str = f"{best_f1_val:.3f} ({best_f1_val * 100:.1f}%)"
        f1_help = f"{best_model_name} under 24-fold LOSO cross-validation"
    else:
        best_f1_str = "N/A"
        best_fpr_str = "N/A"
        f1_help = "No valid evaluation metrics"

    folds_str = f"{total_folds_val} Folds" if total_folds_val > 0 else "N/A"
    samples_str = f"{total_samples_val} Fused Windows" if total_samples_val > 0 else "N/A"

    # High-level Summary Metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total LOSO Folds", folds_str, help="Each session held out once for unbiased testing")
    with c2:
        st.metric("Total Evaluated Windows", samples_str, help="All synchronized 10-second campaign windows")
    with c3:
        st.metric("Best Multimodal F1", best_f1_str, help=f1_help)
    with c4:
        st.metric("Multimodal FPR", best_fpr_str, help="False positive rate under Multimodal Fusion")

    st.markdown("---")

    # 3. Comprehensive Ablation Table
    st.subheader("📊 Comparative Telemetry Ablation Study (LOSO Cross-Validation)")
    st.caption(
        "Objective comparison of detection performance across telemetry dimensions. "
        "Notice the distinct trade-offs: Network telemetry achieves high burst precision, "
        "Workload telemetry exhibits higher false alarms alone, while Fusion suppresses false alarms across diverse scenarios."
    )

    table_data = []
    for r in loso_rows:
        try:
            acc = float(r["aggregate_accuracy"]) * 100
            prec = float(r["aggregate_precision"]) * 100
            rec = float(r["aggregate_recall"]) * 100
            f1 = float(r["aggregate_f1"]) * 100
            fpr = float(r["aggregate_false_positive_rate"]) * 100
            samples = int(r["total_samples"])
        except (ValueError, KeyError):
            continue

        table_data.append({
            "Telemetry Modality": r["telemetry"].title(),
            "Model": r["model"].replace("_", " ").title(),
            "Samples": samples,
            "Accuracy": f"{acc:.1f}%",
            "Precision": f"{prec:.1f}%",
            "Recall": f"{rec:.1f}%",
            "F1-Score": f"{f1:.1f}%",
            "False Positive Rate": f"{fpr:.1f}%",
            "Confusion Matrix [[TN, FP], [FN, TP]]": r.get("aggregate_confusion_matrix", "N/A"),
        })

    ablation_df = pd.DataFrame(table_data)
    st.dataframe(ablation_df, width="stretch", hide_index=True)

    # 4. Modality Comparison Visualizations
    st.markdown("---")
    st.subheader("📈 Performance Trade-offs Across Telemetry Dimensions")

    chart_rows = []
    for r in loso_rows:
        try:
            chart_rows.append({
                "Modality": r["telemetry"].title(),
                "Model": r["model"].replace("_", " ").title(),
                "F1-Score (%)": round(float(r["aggregate_f1"]) * 100, 1),
                "False Positive Rate (%)": round(float(r["aggregate_false_positive_rate"]) * 100, 1),
                "Recall (%)": round(float(r["aggregate_recall"]) * 100, 1),
            })
        except (ValueError, KeyError):
            continue

    chart_df = pd.DataFrame(chart_rows)

    ch_col1, ch_col2 = st.columns(2)
    with ch_col1:
        st.markdown("##### F1-Score by Modality and Model")
        pivot_f1 = chart_df.pivot(index="Modality", columns="Model", values="F1-Score (%)")
        st.bar_chart(pivot_f1)

    with ch_col2:
        st.markdown("##### False Positive Rate (FPR %) by Modality")
        pivot_fpr = chart_df.pivot(index="Modality", columns="Model", values="False Positive Rate (%)")
        st.bar_chart(pivot_fpr)

    # 5. Single-Session Holdout Latency Benchmarks
    ablation_json = _load_ablation_json(results_dir)
    if ablation_json and "experiments" in ablation_json:
        with st.expander("⏱️ Inference Latency & Computational Overhead Benchmarks (Single-Session Holdout)", expanded=False):
            st.caption(
                "Measured inference and training execution time per model from single-session holdout ablation. "
                "Notice: These benchmarks evaluate a single held-out test session, distinct from the 24-fold LOSO cross-validation above."
            )
            bench_rows = []
            for exp in ablation_json["experiments"]:
                inf_time = exp.get("inference_time_per_sample_seconds")
                train_time = exp.get("training_time_seconds")
                acc = exp.get("accuracy")
                fpr = exp.get("false_positive_rate")

                inf_str = f"{float(inf_time) * 1000.0:.3f} ms" if inf_time is not None else "N/A"
                train_str = f"{float(train_time):.3f} s" if train_time is not None else "N/A"
                acc_str = f"{float(acc) * 100:.1f}%" if acc is not None else "N/A"
                fpr_str = f"{float(fpr) * 100:.1f}%" if fpr is not None else "N/A"

                bench_rows.append({
                    "Modality": exp.get("telemetry", "").title(),
                    "Model": exp.get("model", "").replace("_", " ").title(),
                    "Inference Latency (ms/sample)": inf_str,
                    "Training Duration (s)": train_str,
                    "Test Accuracy": acc_str,
                    "Test FPR": fpr_str,
                })
            st.dataframe(pd.DataFrame(bench_rows), width="stretch", hide_index=True)

    # 6. Honest Research Limitations & Integrity Disclosures
    st.markdown("---")
    st.subheader("⚖️ Scientific Integrity & Known System Limitations")
    st.markdown(
        """
        In adherence to research integrity guidelines defined in project documentation:

        1. **Workload Telemetry Scrape Resolution:** Container-level resource metrics from Kubernetes Metrics Server
           update approximately every 15–30 seconds. In short 10-second observation windows, idle pods produce repeating
           baseline vectors (e.g., 9m CPU, 13 MiB memory). Workload-only classification consequently exhibits higher
           false-alarm rates ($10.9\\% - 20.0\\%$) during transient background cluster activity.
        2. **Ephemeral Ports vs Service Port Scanning:** Inspektor Gadget captures server-side TCP trace events where
           the webapp Pod IP:80 is the source and the client Pod IP:ephemeral port is the destination. Unique destination
           ports in this dataset reflect client-side ephemeral port allocation during rapid HTTP bursts, **not** scanning
           of multiple exposed Kubernetes service ports.
        3. **Dataset Scale and Controlled Environment:** Experiments were conducted in a local Minikube cluster using 24
           controlled sessions (4 network normal, 4 network attack, 4 workload normal, 4 workload attack, 4 fusion normal,
           4 fusion attack). While results demonstrate that combining heterogeneous telemetry suppresses false positives,
           further multi-node cluster validation is recommended for production deployment.
        """
    )
