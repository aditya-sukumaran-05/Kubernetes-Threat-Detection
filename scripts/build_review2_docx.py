"""
Builder script to generate the official SWE3004 Review-2 Word Document:
SWE3004_Review_2_Kubernetes_Threat_Detection.docx
"""

import os
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

OUTPUT_FILENAME = "SWE3004_Review_2_Kubernetes_Threat_Detection.docx"

# Color constants
COLOR_NAVY = RGBColor(26, 35, 126)      # #1A237E
COLOR_DARK = RGBColor(33, 33, 33)       # #212121
COLOR_MUTED = RGBColor(90, 100, 110)    # Muted gray
HEX_HEADER_BG = "1E293B"                 # Dark Slate
HEX_ALT_BG = "F8FAFC"                    # Soft background tint
HEX_CALLOUT_BG = "F1F5F9"                # Callout background
HEX_CALLOUT_BORDER = "3B82F6"            # Blue border

def set_cell_background(cell, hex_color):
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)

def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}>'
                      f'<w:top w:w="{top}" w:type="dxa"/>'
                      f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
                      f'<w:left w:w="{left}" w:type="dxa"/>'
                      f'<w:right w:w="{right}" w:type="dxa"/>'
                      f'</w:tcMar>')
    tcPr.append(tcMar)

def set_table_borders(table, color="D1D5DB", sz="4"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(f'<w:tblBorders {nsdecls("w")}>'
                        f'<w:top w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
                        f'<w:bottom w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
                        f'<w:insideH w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
                        f'<w:insideV w:val="none"/>'
                        f'<w:left w:val="none"/>'
                        f'<w:right w:val="none"/>'
                        f'</w:tblBorders>')
    tblPr.append(borders)

def add_page_number_to_footer(footer_para):
    footer_para.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = footer_para.add_run("Page ")
    run.font.name = "Times New Roman"
    run.font.size = Pt(9.5)
    run.font.color.rgb = COLOR_MUTED

    fld_run = footer_para.add_run()
    fld_run.font.name = "Times New Roman"
    fld_run.font.size = Pt(9.5)
    fld_run.font.color.rgb = COLOR_MUTED

    fldChar1 = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>')
    instrText = parse_xml(f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>')
    fldChar2 = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="separate"/>')
    fldChar3 = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>')
    fld_run._r.append(fldChar1)
    fld_run._r.append(instrText)
    fld_run._r.append(fldChar2)
    fld_run._r.append(fldChar3)

def add_callout(doc, text, title="NOTE"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    tbl.columns[0].width = Inches(6.8)
    cell = tbl.cell(0, 0)
    set_cell_background(cell, HEX_CALLOUT_BG)
    set_cell_margins(cell, top=120, bottom=120, left=180, right=180)

    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(f'<w:tcBorders {nsdecls("w")}>'
                        f'<w:left w:val="single" w:sz="24" w:space="0" w:color="{HEX_CALLOUT_BORDER}"/>'
                        f'<w:top w:val="none"/>'
                        f'<w:bottom w:val="none"/>'
                        f'<w:right w:val="none"/>'
                        f'</w:tcBorders>')
    tcPr.append(borders)

    p = cell.paragraphs[0]
    p.paragraph_format.line_spacing = 1.15
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.space_before = Pt(2)

    r_title = p.add_run(f"[{title}] ")
    r_title.bold = True
    r_title.font.name = "Times New Roman"
    r_title.font.size = Pt(9.5)
    r_title.font.color.rgb = RGBColor(30, 64, 175)

    r_text = p.add_run(text)
    r_text.font.name = "Times New Roman"
    r_text.font.size = Pt(9.5)
    r_text.font.italic = True
    r_text.font.color.rgb = COLOR_DARK

    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def format_paragraph(p, space_before=0, space_after=4, line_spacing=1.15, align=WD_ALIGN_PARAGRAPH.JUSTIFY):
    p.alignment = align
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = line_spacing

def add_heading_1(doc, text):
    p = doc.add_paragraph()
    format_paragraph(p, space_before=12, space_after=4, align=WD_ALIGN_PARAGRAPH.LEFT)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(12)
    run.bold = True
    run.font.color.rgb = COLOR_NAVY
    return p

def add_heading_2(doc, text):
    p = doc.add_paragraph()
    format_paragraph(p, space_before=8, space_after=3, align=WD_ALIGN_PARAGRAPH.LEFT)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(11.5)
    run.bold = True
    run.font.color.rgb = COLOR_DARK
    return p

def add_heading_3(doc, text):
    p = doc.add_paragraph()
    format_paragraph(p, space_before=6, space_after=2, align=WD_ALIGN_PARAGRAPH.LEFT)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(11)
    run.bold = True
    run.font.italic = True
    run.font.color.rgb = COLOR_DARK
    return p

def add_body_p(doc, text, bold_prefix=None, space_after=4):
    p = doc.add_paragraph()
    format_paragraph(p, space_before=0, space_after=space_after, line_spacing=1.15, align=WD_ALIGN_PARAGRAPH.JUSTIFY)
    if bold_prefix:
        r_pre = p.add_run(bold_prefix)
        r_pre.font.name = "Times New Roman"
        r_pre.font.size = Pt(11)
        r_pre.bold = True
    r = p.add_run(text)
    r.font.name = "Times New Roman"
    r.font.size = Pt(11)
    r.font.color.rgb = COLOR_DARK
    return p

def add_bullet_item(doc, bold_prefix, text):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.25)
    format_paragraph(p, space_before=1, space_after=3, line_spacing=1.15, align=WD_ALIGN_PARAGRAPH.JUSTIFY)
    r_bullet = p.add_run("•  ")
    r_bullet.font.name = "Times New Roman"
    r_bullet.font.size = Pt(11)
    r_bullet.bold = True
    if bold_prefix:
        r_pre = p.add_run(bold_prefix + " ")
        r_pre.font.name = "Times New Roman"
        r_pre.font.size = Pt(11)
        r_pre.bold = True
    r_text = p.add_run(text)
    r_text.font.name = "Times New Roman"
    r_text.font.size = Pt(11)
    r_text.font.color.rgb = COLOR_DARK

def add_caption(doc, text, is_table=False):
    p = doc.add_paragraph()
    format_paragraph(p, space_before=4 if is_table else 4, space_after=6 if is_table else 8, align=WD_ALIGN_PARAGRAPH.CENTER)
    p.paragraph_format.keep_with_next = True if is_table else False
    run = p.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(10)
    run.bold = True
    run.font.color.rgb = COLOR_NAVY
    return p

def add_figure_image(doc, img_path, width_in_inches, caption_text):
    if os.path.exists(img_path):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.keep_with_next = True
        run = p.add_run()
        run.add_picture(img_path, width=Inches(width_in_inches))
        add_caption(doc, caption_text, is_table=False)
    else:
        print(f"Warning: Figure not found at {img_path}")

def build_document():
    doc = Document()

    # Section Margins matching Review-1 (0.65" top/bottom, 0.72" left/right)
    section = doc.sections[0]
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    section.left_margin = Inches(0.72)
    section.right_margin = Inches(0.72)
    section.header_distance = Inches(0.5)
    section.footer_distance = Inches(0.5)
    section.different_first_page_header_footer = True

    # Setup footer on standard pages (not cover page)
    add_page_number_to_footer(section.footer.paragraphs[0])

    # -------------------------------------------------------------
    # COVER PAGE
    # -------------------------------------------------------------
    # 1. VIT Logo
    p_logo = doc.add_paragraph()
    p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_logo.paragraph_format.space_before = Pt(0)
    p_logo.paragraph_format.space_after = Pt(8)
    logo_path = "results/review1_media/image1.jpeg"
    if os.path.exists(logo_path):
        run_logo = p_logo.add_run()
        run_logo.add_picture(logo_path, width=Inches(3.2))

    # Academic Department Header
    p_dept = doc.add_paragraph()
    p_dept.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_dept.paragraph_format.space_before = Pt(2)
    p_dept.paragraph_format.space_after = Pt(2)
    p_dept.paragraph_format.line_spacing = 1.15
    r = p_dept.add_run("School of Computer Science Engineering and Information Systems\n")
    r.font.name = "Times New Roman"
    r.font.size = Pt(13)
    r.bold = True
    r = p_dept.add_run("Fall Semester 2026-2027\n")
    r.font.name = "Times New Roman"
    r.font.size = Pt(12)
    r.bold = True
    r = p_dept.add_run("Department of Software and Systems Engineering\n")
    r.font.name = "Times New Roman"
    r.font.size = Pt(12)
    r.bold = True
    r = p_dept.add_run("SWE3004 - Software Design and Development Project\n")
    r.font.name = "Times New Roman"
    r.font.size = Pt(14)
    r.bold = True
    r.font.color.rgb = COLOR_NAVY
    r = p_dept.add_run("Review - 2\n")
    r.font.name = "Times New Roman"
    r.font.size = Pt(14)
    r.bold = True
    r.font.color.rgb = RGBColor(180, 20, 20)
    r = p_dept.add_run("Date: 07.10.2026")
    r.font.name = "Times New Roman"
    r.font.size = Pt(11)
    r.bold = True

    # Project Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(12)
    p_title.paragraph_format.space_after = Pt(8)
    r_title = p_title.add_run("Machine Learning-Based Threat Detection Framework for Kubernetes Environments")
    r_title.font.name = "Times New Roman"
    r_title.font.size = Pt(15)
    r_title.bold = True
    r_title.font.color.rgb = COLOR_NAVY

    # Student Info
    p_stu = doc.add_paragraph()
    p_stu.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_stu.paragraph_format.space_before = Pt(4)
    p_stu.paragraph_format.space_after = Pt(8)
    r_stu = p_stu.add_run("22MIS0050 - Aditya Sukumaran")
    r_stu.font.name = "Times New Roman"
    r_stu.font.size = Pt(13)
    r_stu.bold = True

    # Guide Info
    p_guide = doc.add_paragraph()
    p_guide.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_guide.paragraph_format.space_before = Pt(4)
    p_guide.paragraph_format.space_after = Pt(10)
    p_guide.paragraph_format.line_spacing = 1.15
    r_g1 = p_guide.add_run("Under the Guidance of\n")
    r_g1.font.name = "Times New Roman"
    r_g1.font.size = Pt(12)
    r_g1.bold = True
    r_g2 = p_guide.add_run("Guide Name:  Gunasekaran G\nDesignation: Assistant Professor Sr.")
    r_g2.font.name = "Times New Roman"
    r_g2.font.size = Pt(11.5)

    # Score Section Heading
    p_score_h = doc.add_paragraph()
    p_score_h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_score_h.paragraph_format.space_before = Pt(6)
    p_score_h.paragraph_format.space_after = Pt(4)
    r_sh = p_score_h.add_run("SCORE")
    r_sh.font.name = "Times New Roman"
    r_sh.font.size = Pt(12)
    r_sh.bold = True

    # Review Rubrics Table
    tbl_score = doc.add_table(rows=6, cols=4)
    tbl_score.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl_score.autofit = False
    set_table_borders(tbl_score)

    col_widths_score = [Inches(0.6), Inches(3.8), Inches(1.2), Inches(1.2)]
    headers_score = ["Sl. No.", "Evaluation Component", "Max Marks", "Marks Awarded"]
    for j, h in enumerate(headers_score):
        cell = tbl_score.cell(0, j)
        cell.width = col_widths_score[j]
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        r.font.name = "Times New Roman"
        r.font.size = Pt(10)
        r.bold = True
        r.font.color.rgb = RGBColor(255, 255, 255)

    rows_score_data = [
        ("1", "Architecture & Detailed Design (UML, Modularity)", "15", ""),
        ("2", "Testbed & Telemetry Pipeline Implementation", "20", ""),
        ("3", "ML Baseline & Multi-source LOSO Evaluation", "25", ""),
        ("4", "Operations Console / Dashboard & Evidence Layer", "20", ""),
        ("5", "Quality of Report, Presentation & Viva-Voce", "20", ""),
    ]
    for i, row in enumerate(rows_score_data):
        bg = HEX_ALT_BG if i % 2 == 1 else "FFFFFF"
        for j, val in enumerate(row):
            cell = tbl_score.cell(i+1, j)
            cell.width = col_widths_score[j]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if j in [0, 2, 3] else WD_ALIGN_PARAGRAPH.LEFT
            r = p.add_run(val)
            r.font.name = "Times New Roman"
            r.font.size = Pt(9.5)
            if j == 0:
                r.bold = True

    # Signatures
    p_sig1 = doc.add_paragraph()
    p_sig1.paragraph_format.space_before = Pt(18)
    p_sig1.paragraph_format.space_after = Pt(24)
    r_sig1 = p_sig1.add_run("Guide Signature with date")
    r_sig1.font.name = "Times New Roman"
    r_sig1.font.size = Pt(11)
    r_sig1.bold = True

    p_sig2 = doc.add_paragraph()
    p_sig2.paragraph_format.space_before = Pt(6)
    p_sig2.paragraph_format.space_after = Pt(0)
    p_sig2.paragraph_format.line_spacing = 1.15
    r_sig2 = p_sig2.add_run("Internal Examiner - 1 \t\t\t\t\tInternal Examiner - 2\nSignature\t\t\t\t\t\tSignature")
    r_sig2.font.name = "Times New Roman"
    r_sig2.font.size = Pt(11)
    r_sig2.bold = True

    # Page Break after Cover Page
    doc.add_page_break()

    # -------------------------------------------------------------
    # 1. ABSTRACT
    # -------------------------------------------------------------
    add_heading_1(doc, "1. ABSTRACT")
    add_body_p(doc,
        "Kubernetes has established itself as the de facto container orchestration platform for cloud-native workloads, "
        "providing automated scheduling, horizontal elasticity, service abstraction, and self-healing lifecycle management. "
        "However, its highly dynamic, distributed, and multi-tenant operating model presents intricate security-monitoring challenges. "
        "Threat indicators in containerized infrastructure are inherently heterogeneous: network traffic reveals external communication bursts "
        "and abnormal socket states, while container resource metrics reveal unexpected CPU exhaustion and memory anomalies. "
        "While prior research—such as the benchmark study by Morsli et al. (IEEE NetSoft 2025)—demonstrated that combining network flows "
        "and container metrics enhances intrusion detection, practical implementations frequently struggle with reproducible data capture, "
        "unbiased time-window alignment, session-level data leakage, and operator interpretability.")

    add_body_p(doc,
        "This project presents a reproducible, machine-learning-based threat detection framework engineered specifically for Kubernetes clusters. "
        "The framework establishes a non-invasive, dual-plane telemetry architecture comprising Inspektor Gadget eBPF TCP socket tracing "
        "and Kubernetes Metrics Server resource polling. Telemetry from both streams is synchronized into strict, non-overlapping 10-second "
        "observation windows. A controlled experimental campaign was executed in a Minikube cluster across 24 clean, isolated sessions "
        "(comprising baseline normal traffic, controlled network connection-rate bursts, controlled pod-level CPU abuse, and simultaneous "
        "multimodal attack scenarios). Three supervised learning models—Random Forest, XGBoost, and Support Vector Machines (SVM)—were evaluated "
        "across Network-only, Workload-only, and Multimodal Fusion datasets using a strict Leave-One-Session-Out (LOSO) cross-validation protocol "
        "to eliminate temporal and session data leakage.")

    add_body_p(doc,
        "The empirical findings demonstrate nuanced telemetry trade-offs rather than simplistic superiority: Network Random Forest achieved "
        "the highest overall F1-score (0.9643; Precision 0.9643, Recall 0.9643) due to sharp socket-level connection rate signals, whereas "
        "Multimodal Fusion Random Forest achieved an F1-score of 0.9286 while delivering a substantially lower False Positive Rate "
        "(0.0213 vs. 0.0312 for Network-only), successfully suppressing false alarms across benign windows. Workload-only models demonstrated "
        "lower detection power (F1 0.4400–0.6122), underscoring that resource usage alone is an insufficient standalone security indicator. "
        "The pipeline is production-grounded via a modular Python inference engine (`ThreatDetector`) that yields sub-2ms predictions with "
        "impurity-derived feature importance, visualized through an interactive Streamlit operations console. Full implementation integrity "
        "is confirmed by a comprehensive 60-test automated test suite.")

    add_body_p(doc,
        "Keywords: Kubernetes Security, Machine Learning, Threat Detection, Telemetry Fusion, eBPF Socket Tracing, Container Metrics, "
        "Temporal Windowing, Leave-One-Session-Out Cross-Validation, Anomaly Detection.",
        bold_prefix="Keywords: ")

    # -------------------------------------------------------------
    # 2. INTRODUCTION
    # -------------------------------------------------------------
    add_heading_1(doc, "2. INTRODUCTION")
    add_body_p(doc,
        "Modern cloud-native computing has increasingly shifted enterprise architectures toward containerized microservices managed by "
        "declarative orchestration platforms, primarily Kubernetes. By decoupling application execution from underlying host operating "
        "systems, Kubernetes offers automated workload placement, horizontal pod autoscaling, automated rollouts, and service discovery. "
        "However, this architecture also dissolves traditional perimeter-based security perimeters. Pods within a cluster are ephemeral, "
        "frequently reassigned new IP addresses upon restart, share underlying Linux kernel namespaces, and execute microservices communicating "
        "over complex east-west overlay networks.")

    add_body_p(doc,
        "Intruders exploiting container vulnerabilities or conducting resource-hijacking attacks (such as unauthorized cryptocurrency mining "
        "or connection flooding) generate subtle operational footprints. Detecting these anomalies using single-point monitoring tools produces "
        "critical blind spots. A network-centric monitoring agent captures inbound and outbound TCP socket handshakes but remains entirely "
        "blind to silent computational abuse executed via in-pod binaries. Conversely, resource monitoring systems such as Prometheus or "
        "Kubernetes Metrics Server capture CPU millicores and memory consumption but lack visibility into connection burst frequencies, client "
        "IPs, or TCP flag anomalies. Machine learning (ML) provides a powerful methodology for identifying complex, multi-dimensional anomalies "
        "across these disparate telemetry layers.")

    add_body_p(doc,
        "In academic literature, combining heterogeneous telemetry is not in itself a novel concept; Morsli et al. (IEEE NetSoft 2025) recently "
        "demonstrated multidimensional intrusion detection using flow statistics and container metrics on the KUBE-IDS dataset. However, significant "
        "engineering and research challenges persist regarding how such pipelines are built and evaluated in live, reproducible environments: "
        "(i) how to accurately synchronize asynchronous telemetry streams without artificial latency; (ii) how to partition temporal datasets "
        "to prevent severe cross-window data leakage; (iii) what exact trade-offs emerge between detection rate and false positive rate under "
        "controlled ablation; and (iv) how to provide operational explainability to security analysts without manual rule tuning.")

    add_body_p(doc,
        "This Review-2 report documents the complete design, implementation, and empirical validation of a reproducible Kubernetes threat "
        "detection framework. The framework unifies kernel-level eBPF network tracing with cluster-level pod resource telemetry, formats them "
        "into time-aligned feature spaces, trains and compares multiple ML baselines using session-isolated validation, exposes model-derived "
        "evidence, and delivers an interactive operations console for cluster monitoring.")

    # -------------------------------------------------------------
    # 3. PROBLEM STATEMENT
    # -------------------------------------------------------------
    add_heading_1(doc, "3. PROBLEM STATEMENT")
    add_body_p(doc,
        "Kubernetes cluster telemetry is fundamentally heterogeneous, asynchronous, and temporally decoupled. While network-layer activity "
        "operates at millisecond granularity (e.g., TCP handshakes, resets, and packet transmissions), workload resource metrics are aggregated "
        "over multi-second polling intervals by cluster metric APIs. When security anomalies occur—such as rapid HTTP connection bursts or "
        "malicious CPU exhaustion—single-source intrusion detection systems exhibit either unacceptable false negative rates (blind spots) or "
        "prohibitive false positive rates due to normal application elasticity.")

    add_body_p(doc,
        "Furthermore, existing intrusion detection research frequently relies on synthetic or static benchmark datasets where temporal boundaries "
        "are blurred and evaluation is conducted via randomized train/test splitting. In temporal infrastructure data, random splitting introduces "
        "severe information leakage across adjacent time windows, yielding artificially inflated accuracy figures that collapse in live deployments. "
        "Consequently, there is an urgent need to formulate a reproducible, time-synchronized telemetry processing pipeline that enables rigorous "
        "ablation across network, workload, and multimodal feature spaces, validated under strict session isolation to establish genuine "
        "operational trade-offs.")

    # -------------------------------------------------------------
    # 4. OBJECTIVES
    # -------------------------------------------------------------
    add_heading_1(doc, "4. OBJECTIVES")
    add_body_p(doc, "The primary objectives accomplished in this phase of the project are:")
    add_bullet_item(doc, "O1: Testbed Implementation:", "Deploy a controlled, fully reproducible local Kubernetes testbed (Minikube with Docker driver) hosting containerized web workloads (nginx webapp) and automated traffic injection tooling.")
    add_bullet_item(doc, "O2: Telemetry Ingestion:", "Implement non-invasive telemetry collectors capturing kernel-level TCP socket events via Inspektor Gadget (eBPF) and pod resource consumption (CPU millicores, Memory MiB) via Kubernetes Metrics Server.")
    add_bullet_item(doc, "O3: Temporal Alignment Pipeline:", "Develop a deterministic feature engineering engine that aggregates asynchronous events into synchronized, non-overlapping 10-second UTC windows with rigorous boundary labeling.")
    add_bullet_item(doc, "O4: Clean Experimental Campaign:", "Execute a structured 24-session experimental campaign comprising 4 normal and 4 attack runs across Network, Workload, and Multimodal Fusion conditions.")
    add_bullet_item(doc, "O5: Supervised ML Modelling:", "Train standardized Random Forest, XGBoost, and Support Vector Machine (SVM) classification pipelines across all three telemetry configurations.")
    add_bullet_item(doc, "O6: Leakage-Free LOSO Evaluation:", "Conduct rigorous Leave-One-Session-Out (LOSO) cross-validation, isolating entire experimental sessions to benchmark Precision, Recall, F1-Score, and False Positive Rate without temporal contamination.")
    add_bullet_item(doc, "O7: Explainable Inference Engine:", "Engineer a modular, production-ready inference module (`ThreatDetector`) providing sub-2ms prediction latency and model-derived feature importance rankings.")
    add_bullet_item(doc, "O8: Operational Web Dashboard:", "Deliver a Streamlit-based operations dashboard supporting captured session replay, live telemetry inspection, and manual window diagnostics.")

    # -------------------------------------------------------------
    # 5. RESEARCH QUESTIONS
    # -------------------------------------------------------------
    add_heading_1(doc, "5. RESEARCH QUESTIONS")
    add_body_p(doc, "This research evaluates four central empirical research questions:")
    add_bullet_item(doc, "RQ1 (Telemetry Ablation):", "How does threat detection performance compare when models are trained exclusively on network telemetry, exclusively on workload telemetry, or on time-aligned multimodal fusion?")
    add_bullet_item(doc, "RQ2 (False-Positive Reduction):", "Does the incorporation of multimodal telemetry reduce the false positive rate (FPR) compared to single-plane monitoring under normal baseline fluctuations?")
    add_bullet_item(doc, "RQ3 (Model Robustness under Session Isolation):", "Which machine learning algorithm (Random Forest, XGBoost, or SVM) demonstrates superior generalizability across unseen Kubernetes operational sessions?")
    add_bullet_item(doc, "RQ4 (Operational Evidence & Feasibility):", "Can tree-derived feature importance provide actionable, transparent evidence for cluster security operators without incurring heavy computational overhead?")

    # -------------------------------------------------------------
    # 6. SCOPE OF THE PROJECT
    # -------------------------------------------------------------
    add_heading_1(doc, "6. SCOPE OF THE PROJECT")
    add_body_p(doc,
        "To maintain absolute scientific rigor and avoid overextended claims, the operational scope of this project is strictly defined:")
    add_bullet_item(doc, "In-Scope (Implemented & Validated):",
        "Dual-plane telemetry collection (Inspektor Gadget eBPF TCP socket trace + Metrics Server CPU/memory); "
        "deterministic 10-second UTC temporal windowing; 24 clean experimental sessions (60 network windows, 83 workload windows, "
        "122 fusion windows); standardized pipelines for Random Forest, XGBoost, and SVM; strict leave-one-session-out cross-validation; "
        "modular Python inference engine (`ThreatDetector`); and an interactive Streamlit operations console.")
    add_bullet_item(doc, "Extension / Out-of-Scope (Future Work):",
        "Runtime system-call tracking (e.g., tracing execve or process spawn anomalies via Falco/Tetragon) and Kubernetes control-plane audit "
        "log analysis were outlined in the conceptual Review-1 taxonomy but were NOT completed as part of the validated primary experiment. "
        "They are explicitly positioned as architectural extensions and future research directions to ensure experimental reproducibility.")

    add_callout(doc,
        "Runtime/control-plane telemetry is explicitly marked as future work. The primary evaluated system presented in Review-2 "
        "is strictly based on Network + Workload/Resource telemetry.",
        title="CRITICAL SCOPE BOUNDARY")

    # -------------------------------------------------------------
    # 7. PROPOSED AND IMPLEMENTED SYSTEM
    # -------------------------------------------------------------
    add_heading_1(doc, "7. PROPOSED AND IMPLEMENTED SYSTEM")
    add_body_p(doc,
        "In Review-1, the project proposed a three-plane conceptual monitoring model spanning Network, Workload, and Runtime/Control-Plane "
        "evidence. During Phase-2 engineering and experimental stabilization, the core framework was focused and solidly implemented around "
        "the two most fundamental and production-standard Kubernetes telemetry streams: Network Telemetry and Workload Telemetry.")

    add_body_p(doc,
        "The implemented system architecture decouples telemetry capture, window aggregation, ML inference, and operator presentation:")
    add_bullet_item(doc, "1. Network Observation Plane:",
        "Utilizes Inspektor Gadget v0.55.1 running as a DaemonSet to deploy eBPF bytecode directly into the Linux host kernel. "
        "It monitors TCP socket lifecycle events (`trace_tcp`) filtering on Kubernetes Pod labels (`app=webapp`). Each event records "
        "event type (`connect`, `accept`, `close`), source IP/port, destination IP/port, and pod metadata formatted as structured JSON Lines.")
    add_bullet_item(doc, "2. Workload Observation Plane:",
        "Interrogates the Kubernetes Metrics Server API at 5-second intervals, extracting container-level CPU millicores (`cpu_millicores`) "
        "and working memory footprint in MiB (`memory_mib`) mapped to pod identities.")
    add_bullet_item(doc, "3. Synchronization & Alignment Layer:",
        "A deterministic Python feature engineering pipeline normalizes all event timestamps to ISO 8601 UTC. Telemetry is partitioned "
        "into non-overlapping 10-second fixed observation windows, calculating statistical aggregation features (connection rates, "
        "socket counts, delta resource consumption, rolling averages).")
    add_bullet_item(doc, "4. Multi-Modality Datasets:",
        "Constructs three canonical feature datasets (`network_dataset.csv`, `workload_dataset.csv`, `fusion_dataset.csv`) preserving "
        "session identities (`session_id`) and window start/end timestamps.")
    add_bullet_item(doc, "5. Inference Engine (`ThreatDetector`):",
        "A standalone Python engine in `ml/inference.py` that validates incoming window telemetry against strict canonical schemas, "
        "executes inference across pre-trained model pipelines, and extracts impurity-based feature importance.")
    add_bullet_item(doc, "6. Streamlit Dashboard:",
        "An operational interface enabling security operators to replay historical sessions, visualize real-time window metrics, "
        "inspect feature importance evidence, and test manual diagnostic inputs.")

    # -------------------------------------------------------------
    # 8. LITERATURE SURVEY
    # -------------------------------------------------------------
    add_heading_1(doc, "8. LITERATURE SURVEY")
    add_body_p(doc,
        "A systematic review of foundational and recent literature was conducted to contextualize Kubernetes threat detection. "
        "Table 8.1 summarizes the key contributions and limitations of fifteen representative studies, providing the empirical "
        "grounding for our architectural choices.")

    add_caption(doc, "Table 8.1: Comprehensive Comparative Literature Survey", is_table=True)

    # Literature Table
    tbl_lit = doc.add_table(rows=16, cols=4)
    tbl_lit.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl_lit.autofit = False
    set_table_borders(tbl_lit)

    col_widths_lit = [Inches(0.6), Inches(2.2), Inches(2.2), Inches(2.0)]
    headers_lit = ["S.No.", "Paper / Year", "Main Contribution", "Relevant Limitation"]
    for j, h in enumerate(headers_lit):
        cell = tbl_lit.cell(0, j)
        cell.width = col_widths_lit[j]
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        r.font.name = "Times New Roman"
        r.font.size = Pt(9.5)
        r.bold = True
        r.font.color.rgb = RGBColor(255, 255, 255)

    lit_data = [
        ("1", "Almaraz-Rivera (2023) [1]\nAnomaly Detection in K8s", "Kubernetes infrastructure/network monitoring; cloud-native MLOps workflow; Chaos Engineering evaluation.", "Focuses on infrastructure node anomalies; limited multi-plane security attack classification."),
        ("2", "Ahmed et al. (2024) [2]\nMulti-Class Threat Detection", "Multi-class Kubernetes threat detection; PCA + Autoencoder feature reduction with Naive Bayes (F1: 0.95).", "Evaluated on predefined static datasets; lacks real-time time-window alignment and runtime metrics."),
        ("3", "Aradhya et al. (2025) [3]\nContainer Threat Detection", "Runtime system calls and API events via Falco, VirusTotal intelligence, and automated response in Minikube.", "Relies heavily on signature rules and static indicators rather than machine learning telemetry fusion."),
        ("4", "Matsuo & Ikegami (2021) [4]\nAnomaly Detection Analysis", "Analyzes anomaly detection under Kubernetes horizontal auto-scaling and self-healing behaviors.", "Addresses operational performance anomalies rather than malicious security threat taxonomy."),
        ("5", "Mart et al. (2020) [5]\nObservability in K8s", "Prometheus-based Kubernetes cluster observability and automated anomaly detection.", "Strictly metric-based; lacks socket-level network connection insight and process execution context."),
        ("6", "Mohite & Thangaraju (2024) [6]\neBPF Packet Filtering", "Per-process and per-container network egress visibility and packet enforcement using Linux eBPF.", "Primarily a packet filtering mechanism; does not incorporate machine learning classification."),
        ("7", "Zhuravchak & Dudykevych (2023) [7]\nRansomware Detection", "eBPF-based runtime information combined with ML/NLP for real-time container ransomware detection.", "Narrowly tailored to ransomware patterns; lacks generalization to multi-tenant cluster threat classes."),
        ("8", "German & Ponomareva (2023) [8]\nContainer Security Overview", "Comprehensive IEEE overview of Kubernetes container threat vectors and isolation mechanisms.", "A qualitative survey rather than an empirical experimental detection implementation."),
        ("9", "Zou et al. (2022) [9]\nIsolation Forest Monitoring", "Online anomaly detection using multi-dimensional container resource metrics and optimized Isolation Forest.", "Container resource focused; lacks network connection telemetry and control-plane correlation."),
        ("10", "Zhang et al. (2021) [10]\nOne-Class SVM for Containers", "One-class SVM applied to host and container telemetry for real-time intrusion detection.", "One-class modeling is highly vulnerable to legitimate workload bursts in dynamic Kubernetes pods."),
        ("11", "Tunde-Onadele et al. (2019) [11]\nContainer Exploit Detection", "Evaluated static and dynamic detection against 28 real-world container vulnerability exploits.", "Focuses on static container image exploits rather than continuous operational telemetry analysis."),
        ("12", "Flora et al. (2020) [12]\nAttack Injection Evaluation", "Systematic attack-injection methodology for benchmarking container intrusion detection systems.", "Provides an evaluation methodology rather than a novel multi-modal detection framework."),
        ("13", "Lu et al. (2025) [13]\nBPFGuard Access Control", "eBPF-based runtime monitoring and mandatory access control integrated into Kubernetes.", "Enforcement and access-control oriented; does not perform telemetry ablation or ML classification."),
        ("14", "Morsli et al. (2025) [14]\nMultidimensional IDS (IEEE NetSoft)", "Combines network flows and container metrics; evaluates SVM, XGBoost, and DNN on KUBE-IDS dataset.", "Key baseline: Proves network+workload fusion. Does not evaluate session-isolated LOSO or evidence UI."),
        ("15", "Qi et al. (2023) [15]\nLogGPT Log Anomaly Detection", "Explores Large Language Models (ChatGPT) for parsing and detecting log-based cluster anomalies.", "Computationally heavy inference; impractical for low-latency in-cluster threat detection."),
    ]

    for i, row in enumerate(lit_data):
        bg = HEX_ALT_BG if i % 2 == 1 else "FFFFFF"
        for j, val in enumerate(row):
            cell = tbl_lit.cell(i+1, j)
            cell.width = col_widths_lit[j]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if j == 0 else WD_ALIGN_PARAGRAPH.LEFT
            r = p.add_run(val)
            r.font.name = "Times New Roman"
            r.font.size = Pt(8.5)
            if j == 0:
                r.bold = True

    add_heading_2(doc, "8.1 Findings in Literature Survey")
    add_body_p(doc,
        "The literature survey reveals three distinct trends: (1) eBPF has emerged as the premier mechanism for low-overhead container "
        "telemetry capture due to its in-kernel programmability; (2) container intrusion detection is shifting from purely host-level logs "
        "to multidimensional metrics; and (3) tree-based ensemble models (Random Forest and XGBoost) routinely outperform heavy deep neural "
        "networks in tabular telemetry tasks due to rapid inference times and superior handling of tabular feature distributions.")

    add_heading_2(doc, "8.2 Research Gap and Proposed Contribution")
    add_body_p(doc,
        "A critical finding from our literature survey is that multidimensional fusion combining network flows and container metrics has already "
        "been demonstrated by Morsli et al. (IEEE NetSoft 2025). Therefore, simply fusing network and container telemetry cannot be claimed "
        "as a novel contribution. Instead, the substantial research opportunities addressed by our work are:")
    add_bullet_item(doc, "1. Reproducible Controlled Testbed:", "Providing a fully automated, verifiable Minikube-based collection testbed where attack intervals and baseline workloads are recorded with millisecond UTC precision.")
    add_bullet_item(doc, "2. Strict Temporal Window Synchronization:", "Eliminating fuzzy nearest-neighbor matching by enforcing deterministic 10-second non-overlapping temporal windows that preserve causal ordering.")
    add_bullet_item(doc, "3. Session-Isolated Evaluation Protocol:", "Conducting rigorous Leave-One-Session-Out (LOSO) evaluation across 24 independent sessions, eliminating cross-window data leakage common in published ML benchmarks.")
    add_bullet_item(doc, "4. Objective Telemetry Ablation & Trade-off Analysis:", "Demonstrating that while network-only models achieve peak F1 scores during connection bursts, multimodal fusion significantly suppresses false positive rates (FPR), establishing an objective trade-off curve.")
    add_bullet_item(doc, "5. Evidence-Aware Inference & Operator Console:", "Exposing impurity-derived feature weights alongside predictions to provide transparent, interpretable telemetry indicators in an interactive dashboard.")

    # -------------------------------------------------------------
    # 9. METHODOLOGY
    # -------------------------------------------------------------
    add_heading_1(doc, "9. METHODOLOGY")
    add_body_p(doc,
        "The research and engineering workflow follows a 10-stage methodology designed for experimental reproducibility and scientific integrity:")
    add_bullet_item(doc, "Step 1: Threat Modeling & Scope Formulation:", "Define the target Kubernetes attack surfaces (external connection-rate bursts, pod CPU exhaustion, and concurrent multi-plane attacks).")
    add_bullet_item(doc, "Step 2: Kubernetes Testbed Deployment:", "Automate local cluster provisioning using Minikube (Docker driver), deploying an nginx `webapp` Pod and client traffic injector.")
    add_bullet_item(doc, "Step 3: Non-Invasive Telemetry Instrumentation:", "Deploy Inspektor Gadget v0.55.1 eBPF TCP tracer (`trace_tcp`) and Kubernetes Metrics Server v0.7.2 with automated collection scripts.")
    add_bullet_item(doc, "Step 4: Clean Controlled Experimental Campaign:", "Execute 24 isolated sessions under automated PowerShell orchestration (`collect_missing_sessions.ps1`), enforcing CPU baseline checks before each run.")
    add_bullet_item(doc, "Step 5: UTC Timestamping & Feature Extraction:", "Ingest raw JSONL socket logs and CSV metric logs; extract 14 network features and 11 workload features across 10-second non-overlapping windows.")
    add_bullet_item(doc, "Step 6: Multimodal Temporal Alignment:", "Align network and workload feature rows by `window_start` / `window_end` UTC timestamps, constructing 27 fused features and applying strict boundary labeling.")
    add_bullet_item(doc, "Step 7: Standardized ML Pipeline Construction:", "Build `scikit-learn` and `xgboost` pipelines pairing feature scalers (StandardScaler / RobustScaler) with Random Forest, XGBoost, and SVM.")
    add_bullet_item(doc, "Step 8: Session-Isolated LOSO Evaluation:", "Execute Leave-One-Session-Out cross-validation across all eligible sessions, aggregating pooled out-of-fold confusion matrices and performance metrics.")
    add_bullet_item(doc, "Step 9: Modular Inference Engine (`ThreatDetector`):", "Package the trained pipelines into a low-latency Python engine providing schema validation, attack probability, and top contributing feature extraction.")
    add_bullet_item(doc, "Step 10: Operations Dashboard & Verification:", "Build a Streamlit console for historical session replay and telemetry inspection, backed by a 60-test automated verification suite.")

    add_heading_2(doc, "9.1 Worked Example: 10-Second Time-Alignment and Feature Fusion")
    add_body_p(doc,
        "To illustrate how asynchronous telemetry streams are combined without data leakage, Table 9.1 presents a concrete worked example "
        "of a single 10-second observation window during a concurrent attack scenario.")

    add_caption(doc, "Table 9.1: Worked Example of 10-Second Temporal Window Feature Fusion", is_table=True)

    tbl_ex = doc.add_table(rows=8, cols=3)
    tbl_ex.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl_ex.autofit = False
    set_table_borders(tbl_ex)

    col_widths_ex = [Inches(1.8), Inches(3.2), Inches(1.8)]
    headers_ex = ["Telemetry Plane", "Feature Name", "Extracted Value"]
    for j, h in enumerate(headers_ex):
        cell = tbl_ex.cell(0, j)
        cell.width = col_widths_ex[j]
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        r.font.name = "Times New Roman"
        r.font.size = Pt(9.5)
        r.bold = True
        r.font.color.rgb = RGBColor(255, 255, 255)

    ex_data = [
        ("Network (eBPF TCP)", "network_connection_count", "28 connections"),
        ("Network (eBPF TCP)", "network_connection_rate", "2.80 conn / sec"),
        ("Network (eBPF TCP)", "network_accept_count", "28 accepts"),
        ("Network (eBPF TCP)", "unique_destination_ports", "28 (ephemeral client ports)"),
        ("Workload (Metrics Server)", "cpu_millicores", "912.0 mCPU"),
        ("Workload (Metrics Server)", "memory_mib", "18.4 MiB"),
        ("Fused Ground Truth", "label / attack_type", "ATTACK (concurrent_burst_cpu)"),
    ]
    for i, row in enumerate(ex_data):
        bg = HEX_ALT_BG if i % 2 == 1 else "FFFFFF"
        for j, val in enumerate(row):
            cell = tbl_ex.cell(i+1, j)
            cell.width = col_widths_ex[j]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=50, bottom=50, left=100, right=100)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if j in [0, 2] else WD_ALIGN_PARAGRAPH.LEFT
            r = p.add_run(val)
            r.font.name = "Times New Roman"
            r.font.size = Pt(9)
            if j == 2 and "ATTACK" in val:
                r.bold = True
                r.font.color.rgb = RGBColor(180, 20, 20)

    # -------------------------------------------------------------
    # 10. SOFTWARE REQUIREMENTS
    # -------------------------------------------------------------
    add_heading_1(doc, "10. SOFTWARE REQUIREMENTS")

    add_heading_2(doc, "10.1 Functional Requirements")
    add_bullet_item(doc, "FR1 (Workload Discovery):", "Dynamically identify and monitor target Kubernetes Pods using metadata selectors (`app=webapp`) without hardcoding ephemeral Pod names.")
    add_bullet_item(doc, "FR2 (eBPF TCP Ingestion):", "Capture kernel-level TCP socket connections (SYN/ACCEPT/CLOSE) via Inspektor Gadget with millisecond UTC timestamps.")
    add_bullet_item(doc, "FR3 (Resource Telemetry Ingestion):", "Poll Kubernetes Metrics Server at 5-second intervals to capture container CPU millicores and memory consumption.")
    add_bullet_item(doc, "FR4 (Windowing & Feature Extraction):", "Partition raw event logs into fixed 10-second non-overlapping windows and compute statistical aggregation features.")
    add_bullet_item(doc, "FR5 (Dataset Synchronization):", "Align network and workload feature rows by UTC window identifiers and generate modality-specific datasets (`network`, `workload`, `fusion`).")
    add_bullet_item(doc, "FR6 (Supervised Model Training):", "Train Random Forest, XGBoost, and SVM pipelines using session-isolated leave-one-session-out cross-validation.")
    add_bullet_item(doc, "FR7 (Inference & Evidence Generation):", "Provide sub-2ms programmatic prediction via `ThreatDetector`, outputting classification verdict, attack probability, and top contributing features.")
    add_bullet_item(doc, "FR8 (Operational UI & Replay):", "Provide a web-based dashboard allowing operators to replay captured experimental sessions and inspect telemetry charts.")

    add_heading_2(doc, "10.2 Non-Functional Requirements")
    add_bullet_item(doc, "NFR1 (Performance & Latency):", "Feature extraction and model inference must execute in under 10ms per 10-second window, ensuring near real-time operational capability.")
    add_bullet_item(doc, "NFR2 (Reproducibility):", "All testbed setup, experiment execution, dataset generation, and model training steps must be deterministic and fully scriptable via PowerShell and Python.")
    add_bullet_item(doc, "NFR3 (Non-Invasiveness):", "Telemetry collectors must operate out-of-band without requiring binary instrumentation or sidecar injection into application containers.")
    add_bullet_item(doc, "NFR4 (Reliability & Fault Tolerance):", "The ingestion pipeline must gracefully handle zero-event windows and temporary pod recreation without throwing unhandled exceptions.")
    add_bullet_item(doc, "NFR5 (Data Integrity):", "Raw experimental telemetry files must be strictly immutable; all feature engineering transformations must generate new derived artifacts.")
    add_bullet_item(doc, "NFR6 (Explainability):", "Classification decisions must expose quantitative feature contribution evidence rather than presenting opaque black-box verdicts.")
    add_bullet_item(doc, "NFR7 (Modularity & Maintainability):", "The codebase must enforce strict separation between data extraction (`telemetry/`), model training (`ml/`), inference (`ml/inference.py`), and presentation (`dashboard/`).")

    # -------------------------------------------------------------
    # 11. SYSTEM ARCHITECTURE
    # -------------------------------------------------------------
    add_heading_1(doc, "11. SYSTEM ARCHITECTURE")
    add_body_p(doc,
        "The architecture of the implemented Kubernetes threat detection system is structured into five cohesive layers: "
        "(1) the Kubernetes Testbed Infrastructure; (2) the Telemetry Observation Layer; (3) the Time-Alignment and Feature "
        "Engineering Engine; (4) the Machine Learning Training and Inference Subsystem; and (5) the Operational Streamlit Dashboard. "
        "Figure 11.1 illustrates the structural interaction across these layers.")

    # Embed Figure 1
    add_figure_image(doc, "results/figures/report/fig1_system_architecture.png", 6.8,
                     "Figure 11.1: System Architecture of the Implemented Kubernetes Threat Detection Framework")

    add_body_p(doc,
        "As depicted in Figure 11.1, the target application (`nginx` webapp) runs inside the Minikube cluster and is accessed via a NodePort "
        "service. Inspektor Gadget attaches eBPF kprobes/tracepoints in the kernel to record socket handshakes, while Metrics Server polls cgroup "
        "controllers. Crucially, runtime/control-plane telemetry is explicitly marked as an extension scope and was not evaluated experimentally "
        "in this campaign, ensuring that all reported metrics represent fully reproducible, rock-solid engineering artifacts.")

    add_body_p(doc,
        "Figure 11.2 details the end-to-end data and machine learning evaluation pipeline, tracking the transformation of raw events into "
        "cross-validated model performance metrics.")

    # Embed Figure 2
    add_figure_image(doc, "results/figures/report/fig2_ml_pipeline.png", 6.8,
                     "Figure 11.2: End-to-End Data Ingestion, Processing, and Machine Learning Evaluation Pipeline")

    # -------------------------------------------------------------
    # 12. UML DIAGRAMS
    # -------------------------------------------------------------
    add_heading_1(doc, "12. UML DIAGRAMS")

    add_heading_2(doc, "12.1 Use Case Diagram")
    add_body_p(doc,
        "The functional interactions between the Security Analyst (primary user) and the threat detection system are modeled in "
        "the unified Use Case Diagram shown in Figure 12.1. The system intentionally avoids simulated automated remediation actions, "
        "focusing strictly on reliable detection, evidence extraction, and operator visibility.")

    # Embed Figure 3
    add_figure_image(doc, "results/figures/report/fig3_use_case.png", 6.5,
                     "Figure 12.1: Unified Use Case Diagram for Kubernetes Threat Detection System")

    add_body_p(doc,
        "The primary actor, the Security Analyst, interacts with five core use cases: (UC1) Configuring detection parameters and selecting "
        "the active telemetry modality; (UC2) Ingesting and inspecting captured session telemetry; (UC3) Executing window-level threat inference; "
        "(UC4) Inspecting model-derived evidence and feature importance; and (UC5) Reviewing objective comparative metrics and ablation tables.")

    add_heading_2(doc, "12.2 Class Diagram")
    add_body_p(doc,
        "Figure 12.2 presents the implemented Object-Oriented Class Diagram, directly mirroring the Python class structures, dataclasses, "
        "and architectural abstractions built in the codebase.")

    # Embed Figure 4
    add_figure_image(doc, "results/figures/report/fig4_class_diagram.png", 6.8,
                     "Figure 12.2: Implemented Object-Oriented Class Diagram of the Threat Detection System")

    add_body_p(doc,
        "Key classes include `ThreatDetector` (the core detection engine implementing pipeline caching, schema validation, and evidence extraction), "
        "`InferenceResult` (the standardized output dataclass encapsulating verdict, probability, confidence, and top feature weights), "
        "`TelemetryProvider` (the abstract interface for telemetry playback), and `CapturedDatasetProvider` (which replays experimental datasets). "
        "Feature extraction and model training pipelines are decoupled to guarantee high cohesion and low coupling.")

    # -------------------------------------------------------------
    # 13. IMPLEMENTATION
    # -------------------------------------------------------------
    add_heading_1(doc, "13. IMPLEMENTATION")

    add_heading_2(doc, "13.1 Experimental Testbed")
    add_body_p(doc,
        "The experimental testbed was implemented on Windows 11 with Docker Desktop and WSL2. Minikube v1.39.0 was deployed using the Docker driver, "
        "running Kubernetes v1.37.0. The target workload is an nginx deployment (`webapp`) dynamically discovered via the label `app=webapp`. "
        "A separate containerized traffic generator pod injects controlled HTTP requests. Inspektor Gadget v0.55.1 and Kubernetes Metrics Server "
        "v0.7.2 were verified as active and functional.")

    add_heading_2(doc, "13.2 Telemetry Collection")
    add_body_p(doc,
        "Network telemetry is collected by executing `kubectl gadget run trace_tcp:v0.55.1` targeting namespace `default` and label `app=webapp`. "
        "Events are emitted as JSON Lines capturing timestamp, event type, source IP/port, destination IP/port, and container metadata. "
        "Workload telemetry is gathered by `telemetry/workload_collector.py` polling `kubectl top pod` every 5 seconds, recording "
        "timezone-aware UTC timestamps, CPU millicores, and memory MiB.")

    add_heading_2(doc, "13.3 Feature Engineering")
    add_body_p(doc,
        "Feature extraction groups events into fixed 10-second non-overlapping windows. Connection rate is rigorously computed against the fixed "
        "window duration (`rate = accept_count / 10.0`). The primary datasets generated under `results/ml_datasets/` comprise:")
    add_bullet_item(doc, "Network Dataset (14 Features):", "60 labeled windows (32 normal, 28 attack across 8 sessions). Features include connection_count, connection_rate, event_count, accept_count, close_count, error_count, unique_src_ips, unique_dst_ips, unique_src_ports, unique_dst_ports, and inter-arrival statistics.")
    add_bullet_item(doc, "Workload Dataset (11 Features):", "91 total rows, 83 labeled (55 normal, 28 attack, 8 boundary unknown across 8 sessions). Features include cpu_millicores, memory_mib, cpu_delta, memory_delta, rolling averages, and utilization ratios.")
    add_bullet_item(doc, "Fusion Dataset (27 Features):", "276 total aligned rows, 122 labeled (94 normal, 28 attack across 24 clean sessions). Unifies all 14 network features and 11 workload features joined on UTC window boundaries.")

    add_heading_2(doc, "13.4 Machine Learning Pipelines")
    add_body_p(doc,
        "Supervised ML classification pipelines were constructed for each modality using `scikit-learn` and `xgboost`:")
    add_bullet_item(doc, "Random Forest:", "100 decision trees, Gini impurity splitting, fixed random seed (42). Feature importance is directly derived from mean decrease in impurity.")
    add_bullet_item(doc, "XGBoost:", "Gradient boosted trees with binary logistic objective (`binary:logistic`), learning rate 0.1, max depth 4, evaluating native booster feature gain.")
    add_bullet_item(doc, "Support Vector Machine (SVM):", "Radial Basis Function (RBF) kernel paired with StandardScaler. Probability calibration is performed via Platt scaling (`CalibratedClassifierCV`) to output well-calibrated attack probabilities.")

    add_heading_2(doc, "13.5 Inference Engine (`ThreatDetector`)")
    add_body_p(doc,
        "The inference subsystem is implemented in `ml/inference.py`. The `ThreatDetector` class implements canonical feature schema validation, "
        "in-memory pipeline caching, prediction latency benchmarking, and automated evidence extraction. For any arbitrary 10-second window, "
        "it returns an immutable `InferenceResult` containing classification verdict, attack probability, confidence rating, affected pod, "
        "and top contributing features.")

    add_heading_2(doc, "13.6 Dashboard Implementation")
    add_body_p(doc,
        "The operational console was built using Streamlit (`dashboard/app.py`). It reuses the exact `ThreatDetector` engine without any "
        "duplicated ML logic. It supports two execution modes: (1) Demo / Captured Session Replay (replaying exact 10-second slices from the "
        "24 experimental sessions); and (2) Manual Window Inspection. Figure 13.1 details the dashboard data flow.")

    # Embed Figure 5
    add_figure_image(doc, "results/figures/report/fig5_dashboard_flow.png", 6.8,
                     "Figure 13.1: Operational Dashboard Data Flow and Inference Replay Pipeline")

    add_body_p(doc,
        "Figures 13.2 and 13.3 display the dashboard interface during session replay. Figure 13.2 illustrates an active attack detection "
        "verdict (89.5% attack probability under Fusion Random Forest), prominently featuring the model-derived evidence panel. Figure 13.3 "
        "illustrates a normal workload verdict, confirming baseline stability across CPU and connection rate monitors.")

    # Embed Figures 6 and 7
    add_figure_image(doc, "results/figures/report/fig6_dashboard_attack_ui.png", 6.5,
                     "Figure 13.2: Operations Dashboard Interface Displaying Active Attack Verdict and Feature Evidence")
    add_figure_image(doc, "results/figures/report/fig7_dashboard_normal_ui.png", 6.5,
                     "Figure 13.3: Operations Dashboard Interface Displaying Normal Workload Verdict and Telemetry Stability")

    add_heading_2(doc, "13.7 Testing & Quality Assurance")
    add_body_p(doc,
        "The framework is accompanied by an extensive automated test suite implemented in `pytest`. The test suite comprises 60 test cases "
        "covering schema validation, feature extraction math, alignment logic, model training pipelines, LOSO evaluation integrity, inference "
        "engine error handling, and dashboard components. All 60 automated tests pass with 0 failures and 0 warnings.")

    # -------------------------------------------------------------
    # 14. EVALUATION AND RESULTS
    # -------------------------------------------------------------
    add_heading_1(doc, "14. EVALUATION AND RESULTS")

    add_heading_2(doc, "14.1 Leave-One-Session-Out (LOSO) Cross-Validation Protocol")
    add_body_p(doc,
        "To guarantee complete scientific validity and prevent temporal data leakage, model evaluation was conducted using strict "
        "Leave-One-Session-Out (LOSO) cross-validation rather than randomized k-fold window splitting. In each fold, all windows belonging "
        "to a single experimental session were completely held out as the test set, while the model was trained exclusively on the remaining "
        "independent sessions. Predictions were pooled across all held-out folds to calculate objective aggregate metrics.")

    add_heading_2(doc, "14.2 Comparative Evaluation Results")
    add_body_p(doc,
        "Table 14.1 reports the exact pooled LOSO evaluation results across all three telemetry modalities (Network, Workload, and Fusion) "
        "and all three machine learning classifiers (Random Forest, XGBoost, and SVM).")

    add_caption(doc, "Table 14.1: Pooled Leave-One-Session-Out (LOSO) Cross-Validation Performance across Telemetry Modalities", is_table=True)

    # LOSO Results Table
    tbl_loso = doc.add_table(rows=10, cols=7)
    tbl_loso.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl_loso.autofit = False
    set_table_borders(tbl_loso)

    col_widths_loso = [Inches(1.2), Inches(1.3), Inches(0.8), Inches(0.8), Inches(0.8), Inches(0.8), Inches(1.1)]
    headers_loso = ["Modality", "Model", "Accuracy", "Precision", "Recall", "F1-Score", "False Pos Rate"]
    for j, h in enumerate(headers_loso):
        cell = tbl_loso.cell(0, j)
        cell.width = col_widths_loso[j]
        set_cell_background(cell, HEX_HEADER_BG)
        set_cell_margins(cell, top=70, bottom=70, left=60, right=60)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        r.font.name = "Times New Roman"
        r.font.size = Pt(9)
        r.bold = True
        r.font.color.rgb = RGBColor(255, 255, 255)

    loso_data = [
        ("Network", "Random Forest", "0.9667", "0.9643", "0.9643", "0.9643", "0.0312"),
        ("Network", "XGBoost", "0.9167", "1.0000", "0.8214", "0.9020", "0.0000"),
        ("Network", "SVM", "0.8333", "0.8462", "0.7857", "0.8148", "0.1250"),
        ("Workload", "Random Forest", "0.7108", "0.5833", "0.5000", "0.5385", "0.1818"),
        ("Workload", "XGBoost", "0.6627", "0.5000", "0.3929", "0.4400", "0.2000"),
        ("Workload", "SVM", "0.7711", "0.7143", "0.5357", "0.6122", "0.1091"),
        ("Fusion", "Random Forest", "0.9672", "0.9286", "0.9286", "0.9286", "0.0213"),
        ("Fusion", "XGBoost", "0.9590", "0.9259", "0.8929", "0.9091", "0.0213"),
        ("Fusion", "SVM", "0.9590", "0.8485", "1.0000", "0.9180", "0.0532"),
    ]

    for i, row in enumerate(loso_data):
        bg = HEX_ALT_BG if i % 2 == 1 else "FFFFFF"
        for j, val in enumerate(row):
            cell = tbl_loso.cell(i+1, j)
            cell.width = col_widths_loso[j]
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=50, bottom=50, left=60, right=60)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if j >= 2 else WD_ALIGN_PARAGRAPH.LEFT
            r = p.add_run(val)
            r.font.name = "Times New Roman"
            r.font.size = Pt(8.5)
            if j == 0:
                r.bold = True
            if (row[0] == "Network" and row[1] == "Random Forest") or (row[0] == "Fusion" and row[1] == "Random Forest"):
                if j in [5, 6]:
                    r.bold = True

    add_body_p(doc,
        "Figure 14.1 illustrates the comparative F1-Scores across modalities, while Figure 14.2 compares the False Positive Rates (FPR).")

    # Embed comparative figures
    add_figure_image(doc, "results/figures/f1_comparison.png", 5.5,
                     "Figure 14.1: Comparative F1-Score Performance across Telemetry Modalities and Classifiers")
    add_figure_image(doc, "results/figures/false_positive_rate_comparison.png", 5.5,
                     "Figure 14.2: Comparative False Positive Rate (FPR) across Telemetry Modalities and Classifiers")

    add_heading_2(doc, "14.3 Confusion Matrices Analysis")
    add_body_p(doc,
        "The pooled confusion matrices highlight the exact classification breakdowns under leave-one-session-out conditions:")
    add_bullet_item(doc, "Network Random Forest (60 windows):", "TN=31, FP=1, FN=1, TP=27. High sensitivity and specificity on network bursts; 1 false positive out of 32 normal windows.")
    add_bullet_item(doc, "Workload Random Forest (83 windows):", "TN=45, FP=10, FN=14, TP=14. Substantial false negatives (14) and false positives (10), reflecting the lag and ambiguity of raw CPU metrics.")
    add_bullet_item(doc, "Fusion Random Forest (122 windows):", "TN=92, FP=2, FN=2, TP=26. Out of 94 normal windows, only 2 false positives occurred (FPR=0.0213), with 26 out of 28 attacks successfully captured.")
    add_bullet_item(doc, "Fusion SVM (122 windows):", "TN=89, FP=5, FN=0, TP=28. Achieved perfect 100% recall (28/28 attacks detected with zero missed attacks), with 5 false positives.")

    # Embed confusion matrices
    add_figure_image(doc, "results/figures/confusion_matrices/fusion_random_forest.png", 4.2,
                     "Figure 14.3: Pooled LOSO Confusion Matrix for Fusion Random Forest")

    add_heading_2(doc, "14.4 Discussion: Telemetry Trade-offs")
    add_body_p(doc,
        "A critical, objective analysis of the experimental data refutes the simplistic assumption that 'multimodal fusion is always superior.' "
        "Instead, the results reveal clear telemetry-dependent operational trade-offs:")
    add_bullet_item(doc, "Peak Detection vs. False Alarm Suppression:",
        "Network Random Forest achieved the highest individual F1-score (0.9643 vs. 0.9286 for Fusion RF). In pure connection burst scenarios, "
        "socket-level features (connection_rate, accept_count) provide an immediate, unambiguous threat signal. However, Fusion Random Forest "
        "achieved a lower False Positive Rate (0.0213 vs. 0.0312 for Network RF). Across 94 normal observation windows, the inclusion of "
        "stable workload metrics provided reassuring negative evidence, successfully suppressing false alarms that single-plane network jitter can induce.")
    add_bullet_item(doc, "Zero False-Negative Safety with Fusion SVM:",
        "Fusion SVM achieved perfect Recall (1.0000; 28/28 attacks detected), ensuring zero missed security intrusions. In critical infrastructure "
        "where a missed breach is catastrophic, the fusion feature space provides sufficient multi-plane separability for SVM hyperplanes to capture all anomalies.")
    add_bullet_item(doc, "Weakness of Standalone Workload Monitoring:",
        "Workload-only models performed poorly across all algorithms (F1 0.4400–0.6122; FPR 0.1091–0.2000). CPU millicores and memory consumption "
        "suffer from inherent metric aggregation lag (5-second polling intervals) and legitimate background fluctuations, demonstrating that resource "
        "metrics alone cannot serve as an effective primary security monitor.")

    add_heading_2(doc, "14.5 Limitations & Threats to Validity")
    add_body_p(doc,
        "To maintain academic transparency, several experimental limitations must be acknowledged:")
    add_bullet_item(doc, "1. Cluster Scale:", "Experiments were performed within a single-node Minikube cluster running a representative nginx webapp. While architectural patterns transfer to multi-node clusters, inter-node network overlay dynamics were not evaluated.")
    add_bullet_item(doc, "2. Attack Taxonomy:", "Attacks were controlled, scripted conditions (connection bursts and CPU stress). Advanced persistent threats, kernel privilege escalations, and stealthy low-and-slow exfiltration were not evaluated.")
    add_bullet_item(doc, "3. Server-Side Port Semantics:", "Inspektor Gadget's server-side socket representation maps destination ports to ephemeral client ports; thus, destination port counts reflect unique client connections rather than multi-port service scans.")
    add_bullet_item(doc, "4. Telemetry Scope:", "As established, runtime system-call tracking and Kubernetes audit logs remain future extension scope and were not experimentally tested.")

    # -------------------------------------------------------------
    # 15. SUMMARY
    # -------------------------------------------------------------
    add_heading_1(doc, "15. SUMMARY")
    add_body_p(doc,
        "Review-2 establishes a fully realized, empirically validated threat detection framework for Kubernetes environments. "
        "The project has advanced from the initial conceptual proposal into a rigorous engineering implementation consisting of: "
        "(1) a non-invasive dual-plane telemetry collector combining Inspektor Gadget eBPF socket tracing and Metrics Server resource metrics; "
        "(2) a deterministic 10-second temporal alignment engine; (3) a 24-session clean experimental campaign; (4) a leakage-free "
        "Leave-One-Session-Out evaluation across Random Forest, XGBoost, and SVM; (5) an explainable inference engine (`ThreatDetector`); "
        "(6) an interactive Streamlit operations dashboard; and (7) an automated 60-test verification suite.")

    add_body_p(doc,
        "The empirical findings demonstrate that multimodal telemetry fusion provides a substantial operational benefit by suppressing false "
        "positive rates (reducing FPR to 0.0213) and enabling zero-miss threat recall under SVM modeling, while network-only telemetry provides "
        "the sharpest detection signal for rapid connection bursts. Subsequent work leading into Review-3 will investigate hyperparameter "
        "optimization, explore container runtime telemetry integration, and package the framework for automated deployment.")

    # -------------------------------------------------------------
    # 16. REFERENCES
    # -------------------------------------------------------------
    add_heading_1(doc, "16. REFERENCES")

    references = [
        "[1] J. G. Almaraz-Rivera, \"An Anomaly-based Detection System for Monitoring Kubernetes Infrastructures,\" in IEEE Transactions on Cloud Computing, vol. 11, no. 4, pp. 3412-3424, 2023.",
        "[2] A. A. Ahmed, M. Fayez, M. Al-Qutt, and K. M. Elleithy, \"Multi-Class Threat Detection Using Neural Network and Machine Learning Approaches in Kubernetes Environments,\" in IEEE Access, vol. 12, pp. 45120-45135, 2024.",
        "[3] S. S. Aradhya, A. S. Yogitha, and P. K. Sharma, \"Real-Time Container Threat Detection and Response Using Falco, VirusTotal and Talon,\" in Proc. IEEE Int. Conf. on Cloud Computing (CLOUD), pp. 112-120, 2025.",
        "[4] Y. Matsuo and D. Ikegami, \"Performance Analysis of Anomaly Detection Methods for Application System on Kubernetes,\" in Proc. IEEE/IFIP Network Operations and Management Symposium (NOMS), pp. 1-6, 2021.",
        "[5] O. Mart, C. Negru, F. Pop, and A. Castiglione, \"Observability in Kubernetes Cluster: Automatic Anomalies Detection Using Prometheus,\" in Proc. IEEE Int. Conf. on Dependable, Autonomic and Secure Computing (DASC), pp. 245-252, 2020.",
        "[6] R. Mohite and B. Thangaraju, \"Enhancing Container Security with Per-Process Per-Container Egress Packet Filtering Using eBPF,\" in IEEE Transactions on Network and Service Management, vol. 21, no. 2, pp. 1890-1902, 2024.",
        "[7] D. Zhuravchak and V. Dudykevych, \"Real-Time Ransomware Detection by Using eBPF and NLP/ML,\" in Proc. IEEE Int. Conf. on Information and Telecommunication Technologies and Radio Electronics (UkrMiCo), pp. 88-93, 2023.",
        "[8] K. German and O. Ponomareva, \"An Overview of Container Security in a Kubernetes Cluster,\" in Proc. IEEE Int. Conf. on Cybernetics and Computational Intelligence, pp. 310-316, 2023.",
        "[9] Z. Zou, Y. Xie, K. Huang, G. Xu, D. Zou, and H. Jin, \"A Docker Container Anomaly Monitoring System Based on Optimized Isolation Forest,\" in IEEE Transactions on Industrial Informatics, vol. 18, no. 6, pp. 4154-4164, 2022.",
        "[10] L. Zhang, R. Cushing, C. de Laat, and P. Grosso, \"A Real-Time Intrusion Detection System Based on OC-SVM for Containerized Applications,\" in Proc. IEEE Int. Conf. on Cloud Networking (CloudNet), pp. 1-6, 2021.",
        "[11] O. Tunde-Onadele, J. He, T. Dai, and G. Gu, \"A Study on Container Vulnerability Exploit Detection,\" in Proc. IEEE Int. Conf. on Distributed Computing Systems (ICDCS), pp. 1420-1430, 2019.",
        "[12] J. Flora, P. Gonçalves, and N. Antunes, \"Using Attack Injection to Evaluate Intrusion Detection Effectiveness in Container-Based Systems,\" in Proc. IEEE Int. Symp. on Software Reliability Engineering (ISSRE), pp. 241-252, 2020.",
        "[13] H. Lu, X. Du, D. Hu, S. Su, and Z. Zhang, \"BPFGuard: Multi-Granularity Container Runtime Mandatory Access Control,\" in Proc. IEEE Conf. on Communications and Network Security (CNS), pp. 1-9, 2025.",
        "[14] R. Morsli, N. Kara, H. Ould-Slimane, and L. Lahlou, \"Multidimensional Intrusion Detection System for Containerized Environments,\" in Proc. IEEE 11th Int. Conf. on Network Softwarization (NetSoft), pp. 145-153, 2025. DOI: 10.1109/NetSoft64993.2025.11080585.",
        "[15] J. Qi et al., \"LogGPT: Exploring ChatGPT for Log-Based Anomaly Detection,\" in Proc. IEEE Int. Conf. on Data Engineering Workshops (ICDEW), pp. 210-217, 2023."
    ]

    for ref in references:
        p_ref = doc.add_paragraph()
        format_paragraph(p_ref, space_before=2, space_after=3, line_spacing=1.15, align=WD_ALIGN_PARAGRAPH.JUSTIFY)
        p_ref.paragraph_format.left_indent = Inches(0.35)
        p_ref.paragraph_format.first_line_indent = Inches(-0.35)
        r_ref = p_ref.add_run(ref)
        r_ref.font.name = "Times New Roman"
        r_ref.font.size = Pt(10)
        r_ref.font.color.rgb = COLOR_DARK

    doc.save(OUTPUT_FILENAME)
    print(f"Document successfully created: {OUTPUT_FILENAME}")

if __name__ == "__main__":
    build_document()
