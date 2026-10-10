"""
Script to generate all publication-quality academic diagrams for Review-2 report.
Figure 1: Implemented System Architecture
Figure 2: Data and ML Pipeline
Figure 3: Use Case Diagram
Figure 4: Implemented Class Diagram
Figure 5: Dashboard Data Flow
Figure 6 & 7: Dashboard UI Mockups / Replay Visualizations
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

os.makedirs('results/figures/report', exist_ok=True)

# Set global styles
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif', 'Times']
plt.rcParams['mathtext.fontset'] = 'stix'

def draw_system_architecture():
    fig, ax = plt.subplots(figsize=(10.5, 7.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Color palette - Academic slate / navy / teal / soft gray
    c_k8s = '#E8EEF5'
    c_net = '#E3F2FD'
    c_work = '#E8F5E9'
    c_align = '#FFF3E0'
    c_data = '#F3E5F5'
    c_ml = '#EDE7F6'
    c_inf = '#E0F2F1'
    c_dash = '#ECEFF1'
    c_border = '#37474F'
    c_future = '#FAFAFA'

    # Title Banner
    ax.text(50, 97.5, 'Figure 11.1: System Architecture of Implemented Kubernetes Threat Detection Framework',
            ha='center', va='center', fontsize=12, fontweight='bold', color='#1A237E')

    # Layer 1: Kubernetes Testbed
    rect1 = patches.FancyBboxPatch((10, 83), 80, 11, boxstyle="round,pad=0.8,rounding_size=1.5",
                                   facecolor=c_k8s, edgecolor=c_border, linewidth=1.5)
    ax.add_patch(rect1)
    ax.text(50, 90.5, 'Controlled Kubernetes Testbed (Minikube on Docker Engine / WSL2)',
            ha='center', va='center', fontsize=11, fontweight='bold', color='#0D47A1')
    ax.text(50, 85.5, 'Web Application Workload: nginx Pod (app=webapp)  |  Controlled Traffic Generator Pod  |  Local NodePort Service',
            ha='center', va='center', fontsize=9.5, color='#263238')

    # Connectors from K8s to Telemetry
    ax.annotate('', xy=(30, 74), xytext=(30, 82),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.8, shrinkA=0, shrinkB=0))
    ax.annotate('', xy=(70, 74), xytext=(70, 82),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.8, shrinkA=0, shrinkB=0))

    # Layer 2: Heterogeneous Telemetry Planes
    rect_net = patches.FancyBboxPatch((8, 62), 40, 12, boxstyle="round,pad=0.8,rounding_size=1.5",
                                      facecolor=c_net, edgecolor='#1565C0', linewidth=1.5)
    ax.add_patch(rect_net)
    ax.text(28, 70.5, 'Network Telemetry Plane', ha='center', va='center', fontsize=10.5, fontweight='bold', color='#0D47A1')
    ax.text(28, 65.5, 'Inspektor Gadget v0.55.1 (eBPF TCP Trace)\nSocket Events (accept, close, drop) & Endpoint IPs/Ports (JSONL)',
            ha='center', va='center', fontsize=8.5, color='#1A237E')

    rect_work = patches.FancyBboxPatch((52, 62), 40, 12, boxstyle="round,pad=0.8,rounding_size=1.5",
                                       facecolor=c_work, edgecolor='#2E7D32', linewidth=1.5)
    ax.add_patch(rect_work)
    ax.text(72, 70.5, 'Workload Telemetry Plane', ha='center', va='center', fontsize=10.5, fontweight='bold', color='#1B5E20')
    ax.text(72, 65.5, 'Kubernetes Metrics Server (metrics-server v0.7.2)\nPod Resource Usage: CPU Millicores & Memory MiB (5s Poll CSV)',
            ha='center', va='center', fontsize=8.5, color='#1B5E20')

    # Connectors to Alignment
    ax.annotate('', xy=(45, 52), xytext=(28, 61),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.8, shrinkA=0, shrinkB=0))
    ax.annotate('', xy=(55, 52), xytext=(72, 61),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.8, shrinkA=0, shrinkB=0))

    # Layer 3: Feature Engineering & Time Alignment
    rect_align = patches.FancyBboxPatch((18, 42), 64, 10, boxstyle="round,pad=0.8,rounding_size=1.5",
                                        facecolor=c_align, edgecolor='#E65100', linewidth=1.5)
    ax.add_patch(rect_align)
    ax.text(50, 48.5, 'Time Alignment & Window Feature Engineering Engine', ha='center', va='center', fontsize=10.5, fontweight='bold', color='#BF360C')
    ax.text(50, 44.5, 'Strict 10s Non-Overlapping UTC Temporal Windowing  |  Label Assignment via Scenario Metadata  |  Zero-Imputation',
            ha='center', va='center', fontsize=8.5, color='#4E342E')

    # Connectors to Datasets
    ax.annotate('', xy=(22, 33), xytext=(35, 41),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.6))
    ax.annotate('', xy=(50, 33), xytext=(50, 41),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.6))
    ax.annotate('', xy=(78, 33), xytext=(65, 41),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.6))

    # Layer 4: Dataset Datastores
    rect_d1 = patches.FancyBboxPatch((8, 25), 26, 8, boxstyle="round,pad=0.6,rounding_size=1.2",
                                     facecolor=c_data, edgecolor='#6A1B9A', linewidth=1.2)
    ax.add_patch(rect_d1)
    ax.text(21, 30.5, 'Network Dataset', ha='center', va='center', fontsize=9.5, fontweight='bold', color='#4A148C')
    ax.text(21, 27.2, '60 Windows (14 feats)\n32 Normal, 28 Attack', ha='center', va='center', fontsize=7.8, color='#311B92')

    rect_d2 = patches.FancyBboxPatch((37, 25), 26, 8, boxstyle="round,pad=0.6,rounding_size=1.2",
                                     facecolor=c_data, edgecolor='#6A1B9A', linewidth=1.2)
    ax.add_patch(rect_d2)
    ax.text(50, 30.5, 'Workload Dataset', ha='center', va='center', fontsize=9.5, fontweight='bold', color='#4A148C')
    ax.text(50, 27.2, '83 Windows (11 feats)\n55 Normal, 28 Attack', ha='center', va='center', fontsize=7.8, color='#311B92')

    rect_d3 = patches.FancyBboxPatch((66, 25), 26, 8, boxstyle="round,pad=0.6,rounding_size=1.2",
                                     facecolor=c_data, edgecolor='#6A1B9A', linewidth=1.2)
    ax.add_patch(rect_d3)
    ax.text(79, 30.5, 'Fusion Dataset', ha='center', va='center', fontsize=9.5, fontweight='bold', color='#4A148C')
    ax.text(79, 27.2, '122 Windows (27 feats)\n94 Normal, 28 Attack', ha='center', va='center', fontsize=7.8, color='#311B92')

    # Connectors to ML & Inference
    ax.annotate('', xy=(50, 18), xytext=(50, 24),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.8))

    # Layer 5: ML Models & ThreatDetector
    rect_ml = patches.FancyBboxPatch((12, 9), 76, 9.5, boxstyle="round,pad=0.8,rounding_size=1.5",
                                     facecolor=c_inf, edgecolor='#004D40', linewidth=1.5)
    ax.add_patch(rect_ml)
    ax.text(50, 15.5, 'ML Detection & Inference Engine: ThreatDetector (ml/inference.py)',
            ha='center', va='center', fontsize=10.5, fontweight='bold', color='#004D40')
    ax.text(50, 11.5, 'Models: Random Forest  |  XGBoost  |  Support Vector Classifier (SVM)\nEvaluated via Strict Leave-One-Session-Out (LOSO) Cross-Validation  |  Model-Derived Evidence Output',
            ha='center', va='center', fontsize=8.5, color='#004D40')

    # Connector to Dashboard
    ax.annotate('', xy=(50, 4.5), xytext=(50, 8.5),
                arrowprops=dict(arrowstyle="->", color=c_border, lw=1.8))

    # Layer 6: Dashboard
    rect_dash = patches.FancyBboxPatch((20, 0.5), 60, 4, boxstyle="round,pad=0.6,rounding_size=1.0",
                                       facecolor=c_dash, edgecolor='#37474F', linewidth=1.2)
    ax.add_patch(rect_dash)
    ax.text(50, 2.5, 'Interactive Operations Dashboard (Streamlit: Summary, Evidence, Telemetry Charts)',
            ha='center', va='center', fontsize=9.5, fontweight='bold', color='#263238')

    # Bottom Extension Scope Callout
    rect_ext = patches.FancyBboxPatch((1, 91.5), 7, 7, boxstyle="square,pad=0.3",
                                      facecolor='#ECEFF1', edgecolor='#90A4AE', linewidth=0.8, linestyle='--')
    ax.add_patch(rect_ext)
    ax.text(4.5, 95, 'Future\nScope', ha='center', va='center', fontsize=7.5, fontweight='bold', color='#546E7A')

    plt.tight_layout()
    fig.savefig('results/figures/report/fig1_system_architecture.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated Fig 1: System Architecture")

def draw_ml_pipeline():
    fig, ax = plt.subplots(figsize=(10.5, 6.5), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    ax.text(50, 97, 'Figure 11.2: End-to-End Data Ingestion, Processing, and ML Evaluation Pipeline',
            ha='center', va='center', fontsize=12, fontweight='bold', color='#1A237E')

    stages = [
        ("1. Clean Campaign Collection\n(24 Sessions, UTC Timestamps)", "#E3F2FD", "#1565C0", 9, 81, 82, 9),
        ("2. Temporal Alignment & Windowing\n(Fixed 10-Second Windows, No Overlap)", "#E8F5E9", "#2E7D32", 9, 68, 82, 9),
        ("3. Modality-Specific Feature Extraction\n(Network: 14 feats | Workload: 11 feats | Fusion: 27 feats)", "#FFF3E0", "#E65100", 9, 55, 82, 9),
        ("4. Session-Isolated Partitioning\n(Strict Leave-One-Session-Out Cross-Validation)", "#F3E5F5", "#6A1B9A", 9, 42, 82, 9),
        ("5. Standardized Model Pipeline Training\n(RobustScaler / StandardScaler + Random Forest / XGBoost / SVM)", "#EDE7F6", "#4527A0", 9, 29, 82, 9),
        ("6. Pooled Evaluation & Evidence Generation\n(Precision, Recall, F1, FPR, Confusion Matrix & Feature Weights)", "#E0F2F1", "#00695C", 9, 16, 82, 9),
        ("7. Verification, Artifact Persistence & Dashboard Replay\n(Serialized Pipelines, Machine-Readable Metrics, Interactive UI)", "#ECEFF1", "#37474F", 9, 3, 82, 9),
    ]

    for text, fc, ec, x, y, w, h in stages:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.8,rounding_size=1.2",
                                      facecolor=fc, edgecolor=ec, linewidth=1.4)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, text, ha='center', va='center', fontsize=9.5, fontweight='bold', color=ec)

    # Downward connectors
    for y_arrow in [80, 67, 54, 41, 28, 15]:
        ax.annotate('', xy=(50, y_arrow - 2.5), xytext=(50, y_arrow),
                    arrowprops=dict(arrowstyle="->", color='#37474F', lw=2.0))

    plt.tight_layout()
    fig.savefig('results/figures/report/fig2_ml_pipeline.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated Fig 2: ML Pipeline")

def draw_use_case():
    fig, ax = plt.subplots(figsize=(9.5, 6.5), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    ax.text(50, 97, 'Figure 12.1: Unified Use Case Diagram for Kubernetes Threat Detection System',
            ha='center', va='center', fontsize=12, fontweight='bold', color='#1A237E')

    # Boundary Box (System Boundary)
    rect_sys = patches.Rectangle((28, 8), 68, 84, facecolor='#FAFAFA', edgecolor='#455A64', linewidth=1.5, linestyle='-')
    ax.add_patch(rect_sys)
    ax.text(62, 88, 'Kubernetes ML Threat Detection Framework', ha='center', va='center', fontsize=11, fontweight='bold', color='#263238')

    # Actor: Security Analyst (Stick figure left)
    # Head
    circle = patches.Circle((14, 62), 3.2, facecolor='#E0E0E0', edgecolor='#212121', linewidth=1.5)
    ax.add_patch(circle)
    # Body
    ax.plot([14, 14], [58.8, 44], color='#212121', lw=2)
    # Arms
    ax.plot([7, 21], [52, 52], color='#212121', lw=2)
    # Legs
    ax.plot([14, 8], [44, 32], color='#212121', lw=2)
    ax.plot([14, 20], [44, 32], color='#212121', lw=2)
    ax.text(14, 26, 'Security Analyst\n(Operator)', ha='center', va='center', fontsize=10, fontweight='bold', color='#212121')

    # Use Cases (Ovals)
    use_cases = [
        ("UC1: Configure Detection & Telemetry Modality\n(Network / Workload / Fusion)", 78),
        ("UC2: Ingest & Inspect Captured Telemetry Session", 64),
        ("UC3: Execute Window-Level Threat Detection", 50),
        ("UC4: Inspect Model Evidence & Feature Contributions", 36),
        ("UC5: Review Comparative Metrics & Ablation Results", 22),
    ]

    for text, y in use_cases:
        ellipse = patches.Ellipse((62, y), 56, 9.5, facecolor='#E8EEF5', edgecolor='#1565C0', linewidth=1.4)
        ax.add_patch(ellipse)
        ax.text(62, y, text, ha='center', va='center', fontsize=9.2, color='#0D47A1', weight='semibold')
        # Connector line from actor to use case
        ax.plot([19, 34], [52, y], color='#37474F', lw=1.2, linestyle='-')

    plt.tight_layout()
    fig.savefig('results/figures/report/fig3_use_case.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated Fig 3: Use Case Diagram")

def draw_class_diagram():
    fig, ax = plt.subplots(figsize=(10.5, 7.8), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    ax.text(50, 97.5, 'Figure 12.2: Implemented Object-Oriented Class Diagram',
            ha='center', va='center', fontsize=12, fontweight='bold', color='#1A237E')

    # Helper function to draw UML Class box
    def draw_class_box(x, y, w, h, title, stereotype="", attrs=[], methods=[], bg='#FFFFFF', ec='#37474F'):
        rect = patches.Rectangle((x, y), w, h, facecolor=bg, edgecolor=ec, linewidth=1.3)
        ax.add_patch(rect)
        # Title area
        header_h = 3.5 if not stereotype else 4.8
        line_y1 = y + h - header_h
        ax.plot([x, x + w], [line_y1, line_y1], color=ec, lw=1.2)
        if stereotype:
            ax.text(x + w/2, y + h - 1.8, stereotype, ha='center', va='center', fontsize=7.5, fontstyle='italic', color='#455A64')
            ax.text(x + w/2, y + h - 3.5, title, ha='center', va='center', fontsize=9.5, fontweight='bold', color='#1A237E')
        else:
            ax.text(x + w/2, y + h - 2.0, title, ha='center', va='center', fontsize=9.5, fontweight='bold', color='#1A237E')

        # Attributes area
        attr_h = len(attrs) * 1.8 + 0.8
        line_y2 = line_y1 - attr_h
        ax.plot([x, x + w], [line_y2, line_y2], color=ec, lw=1.0)
        curr_y = line_y1 - 1.5
        for attr in attrs:
            ax.text(x + 1.2, curr_y, attr, ha='left', va='center', fontsize=7.5, color='#263238', fontfamily='monospace')
            curr_y -= 1.8

        # Methods area
        curr_y = line_y2 - 1.5
        for m in methods:
            ax.text(x + 1.2, curr_y, m, ha='left', va='center', fontsize=7.5, color='#263238', fontfamily='monospace')
            curr_y -= 1.8

    # 1. ThreatDetector (Central engine)
    draw_class_box(30, 52, 40, 39, "ThreatDetector",
                   attrs=["- models_dir: Path", "- loaded_pipelines: Dict[str, Pipeline]", "- feature_schemas: Dict[str, List[str]]"],
                   methods=["+ __init__(models_dir: Path)",
                            "+ predict(window_data: Dict, modality: str, model_type: str): InferenceResult",
                            "+ _load_pipeline(modality: str, model_type: str): Pipeline",
                            "+ _validate_features(window_data: Dict, modality: str): DataFrame",
                            "+ _extract_evidence(pipeline: Pipeline, df: DataFrame, k: int=3): List[Dict]"],
                   bg='#E8EEF5', ec='#1565C0')

    # 2. InferenceResult (Dataclass returned by detector)
    draw_class_box(74, 52, 24, 37, "InferenceResult", stereotype="<<dataclass>>",
                   attrs=["+ verdict: str",
                          "+ attack_probability: float",
                          "+ confidence: float",
                          "+ modality: str",
                          "+ model_type: str",
                          "+ window_start_utc: str",
                          "+ affected_pod: str",
                          "+ evidence_features: List[Dict]",
                          "+ execution_time_ms: float"],
                   methods=["+ to_dict(): Dict", "+ is_threat(): bool"],
                   bg='#E0F2F1', ec='#00695C')

    # Association ThreatDetector -> InferenceResult
    ax.annotate('', xy=(74, 70), xytext=(70, 70),
                arrowprops=dict(arrowstyle="->", color='#00695C', lw=1.5))
    ax.text(71.5, 72, "creates", fontsize=7.5, color='#00695C', ha='center')

    # 3. TelemetryProvider (Interface)
    draw_class_box(2, 64, 24, 25, "TelemetryProvider", stereotype="<<interface>>",
                   attrs=["# source_path: Path"],
                   methods=["+ list_sessions(): List[str]",
                            "+ load_session(session_id: str): DataFrame",
                            "+ get_window(session_id: str, idx: int): Dict"],
                   bg='#FFF8E1', ec='#F57F17')

    # 4. CapturedDatasetProvider (implements TelemetryProvider)
    draw_class_box(2, 28, 24, 26, "CapturedDatasetProvider",
                   attrs=["- datasets_dir: Path", "- active_session: str", "- cached_df: DataFrame"],
                   methods=["+ list_sessions(): List[str]",
                            "+ load_session(session_id: str): DataFrame",
                            "+ get_window(session_id: str, idx: int): Dict",
                            "+ get_modality(): str"],
                   bg='#FFFDE7', ec='#F57F17')

    # Realization arrow from CapturedDatasetProvider to TelemetryProvider
    ax.annotate('', xy=(14, 64), xytext=(14, 54),
                arrowprops=dict(arrowstyle="-|>", color='#F57F17', lw=1.5, facecolor='white'))

    # Association from TelemetryProvider / CapturedDatasetProvider to ThreatDetector
    ax.annotate('', xy=(30, 68), xytext=(26, 68),
                arrowprops=dict(arrowstyle="->", color='#37474F', lw=1.5))
    ax.text(28, 70, "feeds", fontsize=7.5, color='#37474F', ha='center')

    # 5. Feature Extractors & Alignment (Bottom row)
    draw_class_box(30, 10, 32, 34, "FeatureAlignmentEngine",
                   attrs=["- window_size_seconds: int = 10", "- metadata_path: Path"],
                   methods=["+ extract_network_features(events_file: Path): DataFrame",
                            "+ extract_workload_features(csv_file: Path): DataFrame",
                            "+ align_temporal_windows(net_df: DataFrame, wl_df: DataFrame): DataFrame",
                            "+ assign_ground_truth_labels(aligned_df: DataFrame): DataFrame"],
                   bg='#FFF3E0', ec='#E65100')

    # Association FeatureAlignmentEngine -> ThreatDetector
    ax.annotate('', xy=(46, 52), xytext=(46, 44),
                arrowprops=dict(arrowstyle="->", color='#E65100', lw=1.5))
    ax.text(49, 48, "schema input", fontsize=7.5, color='#E65100', ha='left')

    # 6. ModelPipeline / Scaler wrapper
    draw_class_box(68, 10, 30, 34, "ModelTrainingPipeline",
                   attrs=["- model_cls: BaseEstimator", "- scaler: TransformerMixin", "- feature_names: List[str]"],
                   methods=["+ fit(X_train: ndarray, y_train: ndarray): self",
                            "+ predict(X_test: ndarray): ndarray",
                            "+ predict_proba(X_test: ndarray): ndarray",
                            "+ evaluate_loso(sessions: List[str]): Dict"],
                   bg='#EDE7F6', ec='#512DA8')

    # Association ModelTrainingPipeline -> ThreatDetector
    ax.annotate('', xy=(60, 52), xytext=(72, 44),
                arrowprops=dict(arrowstyle="->", color='#512DA8', lw=1.5))
    ax.text(68, 49, "loads pipeline", fontsize=7.5, color='#512DA8', ha='center')

    plt.tight_layout()
    fig.savefig('results/figures/report/fig4_class_diagram.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated Fig 4: Class Diagram")

def draw_dashboard_flow():
    fig, ax = plt.subplots(figsize=(10.0, 5.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    ax.text(50, 96, 'Figure 13.1: Operational Dashboard Data Flow and Inference Replay Pipeline',
            ha='center', va='center', fontsize=12, fontweight='bold', color='#1A237E')

    blocks = [
        ("Captured Telemetry Replay\n(CapturedDatasetProvider)", 6, 48, 22, 28, "#E3F2FD", "#1565C0"),
        ("Standard Schema Validation\n& Feature Array Assembly", 31, 48, 20, 28, "#FFF3E0", "#E65100"),
        ("ThreatDetector Engine\n(Pipeline Inference & Evidence)", 54, 48, 21, 28, "#E8F5E9", "#2E7D32"),
        ("Streamlit UI Presentation\n(Summary, Evidence, Charts)", 78, 48, 20, 28, "#EDE7F6", "#512DA8"),
    ]

    for label, x, y, w, h, bg, border in blocks:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.8,rounding_size=1.2",
                                      facecolor=bg, edgecolor=border, linewidth=1.4)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, label, ha='center', va='center', fontsize=9.2, fontweight='bold', color=border)

    # Arrows
    ax.annotate('', xy=(31, 62), xytext=(28, 62), arrowprops=dict(arrowstyle="->", color='#37474F', lw=2))
    ax.annotate('', xy=(54, 62), xytext=(51, 62), arrowprops=dict(arrowstyle="->", color='#37474F', lw=2))
    ax.annotate('', xy=(78, 62), xytext=(75, 62), arrowprops=dict(arrowstyle="->", color='#37474F', lw=2))

    # Details at bottom
    details_box = patches.FancyBboxPatch((6, 8), 92, 30, boxstyle="round,pad=0.6,rounding_size=1.0",
                                        facecolor='#FAFAFA', edgecolor='#90A4AE', linewidth=1.0)
    ax.add_patch(details_box)
    ax.text(50, 31, 'Runtime Characteristics & Modular Separation', ha='center', va='center', fontsize=10, fontweight='bold', color='#37474F')
    detail_text = (
        "• Replay Fidelity: Windows fed exactly as recorded during controlled experiments (10s UTC intervals)\n"
        "• Engine Reusability: Dashboard directly imports ThreatDetector from ml/inference.py (zero duplicated ML logic)\n"
        "• Modality Switching: Real-time toggling across Network-only, Workload-only, and Fusion inference\n"
        "• Explainability: Tree impurity-based feature weighting highlights leading indicators (e.g. connection_rate, cpu_millicores)"
    )
    ax.text(10, 18, detail_text, ha='left', va='center', fontsize=8.8, color='#455A64', linespacing=1.6)

    plt.tight_layout()
    fig.savefig('results/figures/report/fig5_dashboard_flow.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated Fig 5: Dashboard Flow")

def draw_dashboard_ui_mockups():
    # Figure 6: Dashboard Attack Verdict UI Visualization
    fig, ax = plt.subplots(figsize=(10.0, 6.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Outer browser window frame
    browser_frame = patches.FancyBboxPatch((2, 2), 96, 96, boxstyle="round,pad=0.5,rounding_size=1.0",
                                          facecolor='#FFFFFF', edgecolor='#B0BEC5', linewidth=1.5)
    ax.add_patch(browser_frame)

    # Top app header bar
    top_bar = patches.Rectangle((2, 90), 96, 8, facecolor='#1E293B', edgecolor='#1E293B')
    ax.add_patch(top_bar)
    ax.text(6, 94, 'Kubernetes Threat Detection Operations Console  |  Streamlit Framework',
            ha='left', va='center', fontsize=11, fontweight='bold', color='#FFFFFF')

    # Sidebar (left)
    sidebar = patches.Rectangle((2, 2), 26, 88, facecolor='#F8FAFC', edgecolor='#E2E8F0', linewidth=1.0)
    ax.add_patch(sidebar)
    ax.text(15, 84, 'Configuration', ha='center', va='center', fontsize=10, fontweight='bold', color='#0F172A')
    ax.text(5, 78, '• Mode: Demo / Session Replay', fontsize=8, color='#334155')
    ax.text(5, 73, '• Modality: Fusion (Network+Workload)', fontsize=8, fontweight='bold', color='#1E40AF')
    ax.text(5, 68, '• Model: Random Forest', fontsize=8, color='#334155')
    ax.text(5, 63, '• Session: 20260920T121629Z (Attack)', fontsize=8, color='#334155')
    ax.text(5, 58, '• Window Index: 2 (Active Attack)', fontsize=8, color='#334155')

    # Main Area: Threat Summary Banner (Red for Attack)
    alert_banner = patches.FancyBboxPatch((31, 74), 64, 13, boxstyle="round,pad=0.5,rounding_size=0.8",
                                          facecolor='#FEF2F2', edgecolor='#DC2626', linewidth=1.5)
    ax.add_patch(alert_banner)
    ax.text(34, 82, '[ALERT] DETECTION VERDICT: ATTACK DETECTED', fontsize=11, fontweight='bold', color='#991B1B')
    ax.text(34, 77.5, 'Attack Probability: 89.5%   |   Confidence: High   |   Modality: Fusion   |   Affected Workload: webapp',
            fontsize=8.5, fontweight='bold', color='#B91C1C')

    # Metric Cards
    metrics = [
        ("Ground Truth", "ATTACK", "#DC2626", 31),
        ("Inference Latency", "1.42 ms", "#1E293B", 47.5),
        ("Connection Rate", "2.80 / sec", "#DC2626", 64),
        ("CPU Utilization", "912 mCPU", "#DC2626", 80.5)
    ]
    for m_label, m_val, m_col, m_x in metrics:
        card = patches.FancyBboxPatch((m_x, 56), 14.5, 14, boxstyle="round,pad=0.4,rounding_size=0.6",
                                      facecolor='#F1F5F9', edgecolor='#CBD5E1', linewidth=1.0)
        ax.add_patch(card)
        ax.text(m_x + 7.25, 65, m_label, ha='center', va='center', fontsize=7.8, color='#64748B')
        ax.text(m_x + 7.25, 60, m_val, ha='center', va='center', fontsize=9.5, fontweight='bold', color=m_col)

    # Evidence Panel: Feature Contributions
    evidence_box = patches.FancyBboxPatch((31, 8), 64, 44, boxstyle="round,pad=0.5,rounding_size=0.8",
                                          facecolor='#FFFFFF', edgecolor='#CBD5E1', linewidth=1.0)
    ax.add_patch(evidence_box)
    ax.text(34, 48, 'Model-Derived Evidence & Leading Telemetry Indicators', fontsize=9.5, fontweight='bold', color='#0F172A')

    # Horizontal Bar chart inside evidence box
    feats = [
        ('network_connection_rate', 0.34, '2.80 conn/s'),
        ('cpu_millicores', 0.28, '912.0 mCPU'),
        ('network_accept_count', 0.18, '28 accepts'),
        ('memory_mib', 0.08, '18.4 MiB'),
        ('unique_destination_ports', 0.06, '28 ports (ephemeral client)')
    ]
    bar_y = 41
    for f_name, f_imp, f_val in feats:
        ax.text(34, bar_y, f_name, fontsize=7.5, color='#1E293B', fontfamily='monospace')
        # Background bar
        bar_bg = patches.Rectangle((56, bar_y - 1.2), 30, 2.4, facecolor='#E2E8F0')
        ax.add_patch(bar_bg)
        # Foreground bar
        bar_fg = patches.Rectangle((56, bar_y - 1.2), 30 * (f_imp / 0.4), 2.4, facecolor='#2563EB')
        ax.add_patch(bar_fg)
        ax.text(88, bar_y, f"{f_imp*100:.1f}% ({f_val})", fontsize=7.2, color='#475569')
        bar_y -= 6.8

    plt.tight_layout()
    fig.savefig('results/figures/report/fig6_dashboard_attack_ui.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated Fig 6: Dashboard Attack UI")

    # Figure 7: Dashboard Normal Verdict UI Visualization
    fig, ax = plt.subplots(figsize=(10.0, 6.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Outer browser window frame
    browser_frame = patches.FancyBboxPatch((2, 2), 96, 96, boxstyle="round,pad=0.5,rounding_size=1.0",
                                          facecolor='#FFFFFF', edgecolor='#B0BEC5', linewidth=1.5)
    ax.add_patch(browser_frame)

    # Top app header bar
    top_bar = patches.Rectangle((2, 90), 96, 8, facecolor='#1E293B', edgecolor='#1E293B')
    ax.add_patch(top_bar)
    ax.text(6, 94, 'Kubernetes Threat Detection Operations Console  |  Streamlit Framework',
            ha='left', va='center', fontsize=11, fontweight='bold', color='#FFFFFF')

    # Sidebar (left)
    sidebar = patches.Rectangle((2, 2), 26, 88, facecolor='#F8FAFC', edgecolor='#E2E8F0', linewidth=1.0)
    ax.add_patch(sidebar)
    ax.text(15, 84, 'Configuration', ha='center', va='center', fontsize=10, fontweight='bold', color='#0F172A')
    ax.text(5, 78, '• Mode: Demo / Session Replay', fontsize=8, color='#334155')
    ax.text(5, 73, '• Modality: Fusion (Network+Workload)', fontsize=8, fontweight='bold', color='#1E40AF')
    ax.text(5, 68, '• Model: Random Forest', fontsize=8, color='#334155')
    ax.text(5, 63, '• Session: 20260920T121248Z (Normal)', fontsize=8, color='#334155')
    ax.text(5, 58, '• Window Index: 1 (Baseline Traffic)', fontsize=8, color='#334155')

    # Main Area: Threat Summary Banner (Green for Normal)
    normal_banner = patches.FancyBboxPatch((31, 74), 64, 13, boxstyle="round,pad=0.5,rounding_size=0.8",
                                          facecolor='#F0FDF4', edgecolor='#16A34A', linewidth=1.5)
    ax.add_patch(normal_banner)
    ax.text(34, 82, '[OK] DETECTION VERDICT: NORMAL WORKLOAD BEHAVIOR', fontsize=11, fontweight='bold', color='#166534')
    ax.text(34, 77.5, 'Attack Probability: 3.2%   |   Confidence: High   |   Modality: Fusion   |   Status: Benign Operation',
            fontsize=8.5, fontweight='bold', color='#15803D')

    # Metric Cards
    metrics_normal = [
        ("Ground Truth", "NORMAL", "#16A34A", 31),
        ("Inference Latency", "1.38 ms", "#1E293B", 47.5),
        ("Connection Rate", "0.50 / sec", "#16A34A", 64),
        ("CPU Utilization", "12 mCPU", "#16A34A", 80.5)
    ]
    for m_label, m_val, m_col, m_x in metrics_normal:
        card = patches.FancyBboxPatch((m_x, 56), 14.5, 14, boxstyle="round,pad=0.4,rounding_size=0.6",
                                      facecolor='#F1F5F9', edgecolor='#CBD5E1', linewidth=1.0)
        ax.add_patch(card)
        ax.text(m_x + 7.25, 65, m_label, ha='center', va='center', fontsize=7.8, color='#64748B')
        ax.text(m_x + 7.25, 60, m_val, ha='center', va='center', fontsize=9.5, fontweight='bold', color=m_col)

    # Telemetry Panel: Normal baseline behavior
    telemetry_box = patches.FancyBboxPatch((31, 8), 64, 44, boxstyle="round,pad=0.5,rounding_size=0.8",
                                          facecolor='#FFFFFF', edgecolor='#CBD5E1', linewidth=1.0)
    ax.add_patch(telemetry_box)
    ax.text(34, 48, 'Telemetry Baseline Inspection & Stability Monitoring', fontsize=9.5, fontweight='bold', color='#0F172A')

    # Plot normal telemetry curves
    ax_cpu = fig.add_axes([0.35, 0.15, 0.26, 0.26])
    t = np.arange(0, 60, 10)
    cpu_vals = [10, 12, 14, 11, 13, 12]
    ax_cpu.plot(t, cpu_vals, marker='o', color='#16A34A', lw=1.8, label='CPU (mCPU)')
    ax_cpu.set_title('CPU Load (Stable Baseline)', fontsize=8, fontweight='bold')
    ax_cpu.set_xlabel('Time (s)', fontsize=7)
    ax_cpu.set_ylabel('mCPU', fontsize=7)
    ax_cpu.set_ylim(0, 50)
    ax_cpu.tick_params(labelsize=6)
    ax_cpu.grid(True, linestyle=':', alpha=0.6)

    ax_net = fig.add_axes([0.67, 0.15, 0.26, 0.26])
    conn_vals = [0.5, 0.5, 0.6, 0.5, 0.5, 0.4]
    ax_net.plot(t, conn_vals, marker='s', color='#2563EB', lw=1.8, label='Conn Rate')
    ax_net.set_title('TCP Connection Rate (Benign Spaced)', fontsize=8, fontweight='bold')
    ax_net.set_xlabel('Time (s)', fontsize=7)
    ax_net.set_ylabel('Conn/s', fontsize=7)
    ax_net.set_ylim(0, 3.5)
    ax_net.tick_params(labelsize=6)
    ax_net.grid(True, linestyle=':', alpha=0.6)

    fig.savefig('results/figures/report/fig7_dashboard_normal_ui.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated Fig 7: Dashboard Normal UI")

if __name__ == '__main__':
    draw_system_architecture()
    draw_ml_pipeline()
    draw_use_case()
    draw_class_diagram()
    draw_dashboard_flow()
    draw_dashboard_ui_mockups()
