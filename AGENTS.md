# Kubernetes Threat Detection Using Machine Learning
## Project Instructions for Codex

## 1. Project Identity

Project title:

Machine Learning-Based Threat Detection Framework for Kubernetes Environments

Academic context:

Final-year M.Tech Software Engineering capstone project.

Primary objective:

Develop and experimentally evaluate a machine-learning-based threat detection framework for Kubernetes environments using heterogeneous telemetry.

The core research question is:

How does the choice and combination of Kubernetes telemetry affect machine-learning-based threat detection performance, false positives, detection latency, and monitoring overhead?

The core experiment is a telemetry ablation study comparing:

1. Network telemetry only
2. Workload/resource telemetry only
3. Network + workload/resource telemetry

Runtime/control-plane telemetry is an extension and should NOT be treated as a mandatory core component unless it can be integrated reliably without destabilizing the existing system.

---

# 2. Research Positioning

Do NOT claim that combining network and container/workload telemetry is itself novel.

A 2025 IEEE NetSoft paper already demonstrates multidimensional intrusion detection using network-flow data and container-level metrics.

Our project should instead position its contribution around:

- controlled Kubernetes experimentation
- reproducible telemetry collection
- explicit time alignment of heterogeneous telemetry
- telemetry ablation
- comparison of individual versus combined telemetry sources
- detection performance
- false-positive analysis
- detection latency
- monitoring/resource overhead
- evidence-aware security alerts
- optional runtime/control-plane telemetry extension

Do NOT make claims such as:

- "No previous work has combined these telemetry sources"
- "This is the first system to..."
- "No existing system does..."
- "Our fusion approach is novel"

unless such claims are later verified through a literature review.

---

# 3. Primary Reference Paper

Important baseline/reference:

Reda Morsli, Nadjia Kara, Hakima Ould-Slimane, Laaziz Lahlou.

"Multidimensional Intrusion Detection System for Containerized Environments."

IEEE NetSoft 2025.

DOI:

10.1109/NetSoft64993.2025.11080585

The paper uses:

- Kubernetes/containerized environments
- network-flow telemetry
- container-level metrics
- multidimensional/fused intrusion detection
- machine-learning classifiers
- controlled attacks
- comparison of telemetry dimensions

The project should use this paper as a methodological reference rather than copy its implementation.

Associated public dataset:

KUBE-IDS / MIDS Kubernetes intrusion detection dataset.

If the dataset is used for understanding/reference purposes, clearly distinguish it from the project's own experimentally collected Minikube dataset.

---

# 4. Existing Experimental Environment

The current environment is Windows + Docker Desktop + WSL2.

Known versions at the time of development:

- Docker 29.5.2
- Minikube 1.39.0
- Kubernetes cluster 1.37.0
- system kubectl client 1.34.1
- Python 3.13.9

The local Kubernetes cluster is Minikube using the Docker driver.

Existing Kubernetes workload:

Deployment:

webapp

Image:

nginx

Service:

webapp

Service type:

NodePort

The webapp Pod is dynamically discovered using:

label app=webapp

Do NOT hardcode the Pod name because Kubernetes may recreate the Pod.

---

# 5. Existing Kubernetes Components

The environment currently has:

- Minikube
- Metrics Server
- Inspektor Gadget
- webapp Deployment
- webapp Service
- traffic-generator Pod

Metrics Server is functional.

Example:

kubectl top pods

works.

Inspektor Gadget is installed and functional.

Version:

v0.55.1

The kubectl Gadget client is available as:

kubectl gadget

The correct trace interface is:

kubectl gadget run trace_tcp:v0.55.1

Do NOT use:

kubectl gadget trace tcp

because that is not the correct interface for the installed version.

---

# 6. Existing Telemetry Collectors

## 6.1 Workload collector

Existing file:

telemetry/workload_collector.py

It collects Kubernetes workload metrics using:

kubectl top pod

The target webapp Pod is discovered dynamically using:

app=webapp

Current telemetry fields:

timestamp
pod
cpu_millicores
memory_mib
label

Collection interval:

approximately 5 seconds.

Important:

The timestamp has been corrected to UTC.

Expected format:

2026-09-19T11:01:07.244Z

The collector should continue using timezone-aware UTC timestamps.

Do NOT revert to naive local timestamps.

The workload collector should remain robust to Pod recreation.

---

## 6.2 Network collector

Existing file:

telemetry/network_collector.py

It uses Inspektor Gadget:

kubectl gadget run trace_tcp:v0.55.1

Current target:

namespace default

label:

app=webapp

Output:

telemetry/data/network/network_events.jsonl

Events are JSON Lines.

Important fields include:

- timestamp
- type
- src
- dst
- Kubernetes Pod information
- container information
- runtime information
- process information

Inspektor Gadget associates the TCP event with the Kubernetes webapp Pod.

The current observed event representation is server-side:

src:

webapp Pod IP : port 80

dst:

traffic-generator Pod IP : ephemeral client port

Therefore:

DO NOT interpret unique destination ports in the current feature extractor as "number of service ports scanned."

They are primarily client-side ephemeral ports in this server-side event representation.

---

# 7. Existing Feature Extraction

Existing file:

telemetry/network_features.py

It groups network events into fixed:

10-second windows.

Current features include:

- connection_count
- event_count
- unique_source_ips
- unique_source_ports
- unique_destination_ips
- unique_destination_ports
- accept_count
- close_count
- error_count
- connection_rate
- label

Connection rate must be calculated against the fixed window duration:

connection_rate = accept_count / WINDOW_SECONDS

Do NOT revert to calculating rate using the duration between the first and last event.

The current extractor processes:

normal:

telemetry/data/network/network_normal.jsonl

attack:

telemetry/data/network/network_burst_attack.jsonl

The attack output remains named:

network_attack_features.csv

unless there is a strong reason to improve the naming.

---

# 8. Existing Captured Data

IMPORTANT:

Raw experimental data must never be silently overwritten.

Preserved files currently include:

telemetry/data/network/network_normal.jsonl

telemetry/data/network/network_attack_raw.jsonl

telemetry/data/network/network_burst_attack.jsonl

telemetry/data/workload_normal.csv

telemetry/data/workload_attack.csv

Treat these as immutable raw experimental artifacts.

If processing requires a modified dataset:

- create a new derived file
- never overwrite the raw capture

---

# 9. Normal Network Dataset

File:

telemetry/data/network/network_normal.jsonl

The clean normal capture contains:

120 events

representing:

60 TCP connections

The normal traffic was generated by approximately:

60 HTTP requests

with roughly 2-second spacing.

This is the current clean normal network baseline.

---

# 10. Network Burst Attack Dataset

File:

telemetry/data/network/network_burst_attack.jsonl

Contains:

120 events

representing:

60 TCP connections.

The requests were generated rapidly with essentially no intentional 2-second spacing.

Feature extraction produced:

Window 1:
28 connections
2.8 connections/sec

Window 2:
26 connections
2.6 connections/sec

Window 3:
6 connections
0.6 connections/sec

This is a controlled network burst/high-rate connection experiment.

Do NOT describe it as a multi-port scan.

Do NOT infer successful scanning of 28/26/6 service ports.

---

# 11. Workload Attack Dataset

File:

telemetry/data/workload_attack.csv

A controlled CPU-abuse condition was applied directly inside the webapp Pod.

Observed workload behavior:

Baseline:

approximately 0m CPU
13 MiB memory

During the stress condition:

approximately 120m CPU

then approximately:

971m CPU

followed by sustained values in the approximate:

779m–874m

range.

This demonstrates a clear workload anomaly.

IMPORTANT:

The raw workload attack file currently has the collector label field set to "normal" because the collector was not dynamically aware of the experiment phase.

Do NOT trust the raw label column for experiment labeling.

Labels should be assigned during preprocessing using explicit experiment/attack time intervals.

Do not manually alter the raw file.

---

# 12. Current Experimental Conditions

The current captured conditions are:

A. Normal baseline

Network:
normal spaced HTTP traffic

Workload:
low CPU / stable memory

B. Workload-only attack

CPU abuse inside webapp

Workload:
strong CPU increase

Network:
no meaningful corresponding network event capture

C. Network-burst attack

Rapid HTTP connections to webapp

Network:
strong increase in connection rate

Workload:
not captured simultaneously as an attack experiment

These are separate experiments.

DO NOT falsely merge B and C into one simultaneous attack.

---

# 13. Critical Experimental Principle

The project must distinguish:

- attack type
- telemetry source
- feature representation
- label
- experiment window

Do not simply concatenate unrelated captures and call them "multimodal fusion."

For the core fusion experiment, construct properly time-aligned samples where network and workload telemetry refer to the same temporal observation window.

If simultaneous multimodal attack data is required, create a controlled experiment that records both sources during the same attack period.

---

# 14. Required Data Pipeline

Implement a reproducible pipeline:

Raw telemetry
    ↓
Validation
    ↓
Timestamp normalization
    ↓
10-second temporal windowing
    ↓
Network feature extraction
+
Workload feature extraction
    ↓
Window-level alignment
    ↓
Label assignment
    ↓
Merged feature dataset
    ↓
Train/test split
    ↓
ML models
    ↓
Evaluation
    ↓
Ablation comparison
    ↓
Dashboard

Every transformation should be reproducible.

---

# 15. Time Alignment Requirements

Network timestamps are UTC.

Workload timestamps are UTC.

Use timezone-aware datetime handling.

Align both telemetry sources using fixed 10-second windows.

Prefer an explicit window identifier such as:

window_start

or:

window_id

rather than fuzzy nearest-neighbor matching.

The final fused dataset should have one row per observation window.

Example conceptual structure:

window_start
window_end

network_connection_count
network_event_count
network_unique_source_ips
network_unique_destination_ips
network_accept_count
network_close_count
network_error_count
network_connection_rate

cpu_millicores
memory_mib

label

Do not leak information from future windows into earlier windows.

---

# 16. Labeling

Labels should be assigned from controlled experiment intervals.

Possible labels:

normal
attack

Optionally support attack_type:

normal
network_burst
resource_abuse
combined

Do not rely on the collector's current static label.

Create a reproducible experiment metadata/configuration mechanism.

For example:

experiments/
    scenarios/
    metadata/

A scenario metadata file could record:

- scenario name
- start timestamp
- end timestamp
- attack type
- target workload
- description

The preprocessing pipeline should use this metadata to label windows.

---

# 17. Required ML Experiments

Implement at least these three conditions:

## Experiment 1: Network-only

Features:

network telemetry only

Goal:

measure how well network telemetry detects the controlled attack conditions.

---

## Experiment 2: Workload-only

Features:

CPU/memory/workload telemetry only.

Goal:

measure detection using workload behavior.

---

## Experiment 3: Network + Workload

Features:

network + workload telemetry.

Goal:

measure whether heterogeneous telemetry provides additional detection value.

---

# 18. Model Requirements

Start with interpretable, lightweight baseline models.

At minimum consider:

- Logistic Regression
- Random Forest
- XGBoost if dependency/environment permits

Do not start with deep learning unless there is a demonstrated need.

The project is primarily about telemetry fusion and experimental comparison, not maximizing model complexity.

Models must be reproducible.

Use fixed random seeds.

Persist:

- trained models
- preprocessing/scalers
- feature lists
- experiment configuration
- evaluation results

---

# 19. Evaluation Metrics

At minimum calculate:

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- Confusion Matrix

Also calculate:

- Detection latency
- Training time
- Inference time where practical
- CPU overhead
- Memory overhead

Avoid relying only on accuracy.

For imbalanced data, emphasize:

Precision
Recall
F1
FPR

---

# 20. Ablation Study

The final system should produce a table comparing:

Network-only
Workload-only
Network + Workload

For each:

- model
- precision
- recall
- F1
- FPR
- detection latency
- inference time
- monitoring overhead

The purpose is to determine the incremental value of heterogeneous telemetry.

Do not produce a "winner" automatically in code.

Produce objective measurements.

---

# 21. Data Leakage Prevention

This is extremely important.

Do NOT randomly split highly correlated adjacent time windows across train and test if that would cause temporal leakage.

Prefer experiment/session-aware splitting.

For example:

training:

one set of attack/normal runs

testing:

different runs/scenarios

If data volume is initially too small for this, clearly report the limitation.

Do not manufacture samples simply to make the dataset large.

---

# 22. Feature Engineering

Implement a clean feature engineering module.

Network features can include:

- connection count
- event count
- connection rate
- accept count
- close count
- error count
- unique source IP count
- unique destination IP count
- unique source port count
- unique destination port count
- inter-arrival statistics

Potential useful network temporal features:

- mean inter-arrival time
- standard deviation of inter-arrival time
- minimum inter-arrival time
- maximum inter-arrival time

Workload features:

- CPU millicores
- memory MiB
- CPU change/delta
- memory change/delta
- rolling CPU mean
- rolling CPU standard deviation
- CPU utilization relative to baseline if defensible

Do not add features merely for quantity.

Each feature should have a defensible interpretation.

---

# 23. Explainability

Implement basic evidence extraction.

For each detection, retain:

- predicted label
- confidence/probability if supported
- timestamp/window
- affected Pod
- important feature values
- model
- experiment condition

If using Random Forest feature importance or another explainability technique, expose the top contributing features.

Do not claim causal explanations from feature importance.

Call them:

"important contributing features"

or:

"model-derived evidence."

---

# 24. Dashboard

Build a clean web dashboard.

Dashboard is secondary to the research pipeline.

The dashboard should visualize actual experimental/model outputs rather than simulated data.

Preferred sections:

## Overview

Show:

- current detection status
- total alerts
- attack windows
- normal windows
- model currently selected
- telemetry sources enabled

## Alerts

Table containing:

- timestamp
- severity/risk indicator
- predicted class
- affected Pod
- attack type
- confidence
- evidence

## Telemetry

Charts for:

- CPU
- memory
- network connection rate
- connection count

Allow viewing network-only/workload-only/fused features.

## Detection Analysis

Show:

- confusion matrix
- precision
- recall
- F1
- FPR
- latency

## Ablation

Compare:

Network-only
Workload-only
Network + Workload

Display objective metrics without ranking them as "best" unless this is simply a raw numerical comparison.

## Historical Alerts

Persist alerts in a lightweight database or structured storage.

## Export

Allow export of:

- alerts
- experiment results
- feature datasets

CSV is sufficient initially.

---

# 25. Dashboard Technology

Choose a technology that is:

- easy to maintain
- locally runnable
- suitable for a student research prototype
- visually polished

A Python backend with a lightweight frontend is acceptable.

If using Streamlit, structure it cleanly rather than putting the entire application into one script.

If using Flask + HTML/JS or another frontend/backend architecture, keep components modular.

Do not over-engineer the frontend.

The dashboard must remain secondary to the ML pipeline.

---

# 26. API / Backend Requirements

If a separate backend is implemented, provide endpoints conceptually equivalent to:

GET /api/alerts

GET /api/telemetry

GET /api/results

GET /api/ablation

GET /api/models

GET /api/health

Exact endpoint naming may differ if another framework is chosen.

Return real data.

Do not use placeholder/random values in production dashboard paths.

---

# 27. Project Structure

Refactor toward a structure similar to:

telemetry/
    collectors/
    features/
    schemas/
    data/

experiments/
    scenarios/
    metadata/
    runners/

ml/
    preprocessing/
    models/
    training/
    evaluation/
    explainability/

dashboard/
    backend/
    frontend/

results/
    metrics/
    figures/
    models/

tests/

docs/

scripts/

Adjust the exact structure based on the current repository.

Do not unnecessarily break existing working scripts.

---

# 28. Raw Data Protection

Never modify or overwrite:

telemetry/data/network/network_normal.jsonl
telemetry/data/network/network_attack_raw.jsonl
telemetry/data/network/network_burst_attack.jsonl
telemetry/data/workload_normal.csv
telemetry/data/workload_attack.csv

Derived files must be written elsewhere.

If a transformation needs to replace an existing derived file, that is acceptable.

Raw captures are immutable experimental evidence.

---

# 29. Testing Requirements

Add automated tests for:

- JSON event parsing
- timestamp parsing
- UTC normalization
- 10-second window assignment
- network feature extraction
- workload feature extraction
- label assignment
- network/workload alignment
- missing telemetry handling
- empty input handling
- Pod recreation handling where practical
- ML preprocessing
- model inference
- API endpoints if applicable

Tests should not require a live Kubernetes cluster unless explicitly marked as integration tests.

Create separate:

unit tests

and, where practical:

integration tests.

---

# 30. Reproducibility

Create a configuration mechanism.

Do not scatter constants throughout the code.

Configuration should include things such as:

- window size
- target namespace
- target workload label
- random seed
- model configuration
- dataset paths
- experiment name

A YAML/JSON/TOML configuration is acceptable.

---

# 31. Experiment Runner

Implement a reproducible experiment runner capable of executing:

network-only
workload-only
network+workload

and generating:

- processed dataset
- model
- predictions
- metrics
- confusion matrix
- result JSON/CSV

Example conceptual command:

python -m experiments.run --experiment network_only

or equivalent.

The exact CLI is up to implementation.

---

# 32. Result Storage

Store machine-readable results.

For example:

results/
    network_only/
    workload_only/
    fused/

Each experiment should retain:

config
metrics
predictions
confusion matrix
feature list
model metadata

This will later make paper table/figure generation much easier.

---

# 33. Visualization for Research

Generate reproducible figures such as:

- CPU over time
- memory over time
- network connection rate over time
- normal vs attack feature distributions
- confusion matrices
- model comparison
- ablation comparison
- detection latency
- overhead

Save figures to:

results/figures/

Do not hard-code colors unnecessarily.

Figures should be publication-friendly.

---

# 34. Runtime/Control-plane Extension

This is NOT core scope.

Potential future telemetry:

- Kubernetes Events
- Kubernetes audit information
- container runtime events
- eBPF/Falco/Inspektor Gadget runtime events

If implemented, add it as an additional telemetry dimension.

Do not allow this extension to destabilize the network + workload core experiment.

---

# 35. Security/Attack Scope

All attack generation must remain inside the controlled Minikube test environment.

Current/desired controlled scenarios include:

1. Resource/CPU abuse
2. Network burst/high-rate connections
3. Brute-force authentication against an intentionally exposed service
4. RBAC privilege escalation in the test cluster
5. Malicious container exec/reverse shell in the test environment
6. Lateral movement/network scanning inside the test cluster

Only implement scenarios that are safe and reproducible in the local lab.

Do not target external systems.

---

# 36. Current Known Limitation

The current network-burst and workload-abuse datasets were collected as separate experiments.

Do not represent them as simultaneous multimodal attack data.

A future controlled combined experiment should be performed if required for the fusion evaluation.

The combined experiment should collect:

network telemetry
+
workload telemetry

during the same attack interval.

---

# 37. Important Research Integrity Rules

NEVER:

- fabricate metrics
- fabricate attack samples
- fabricate dataset size
- invent missing timestamps
- silently relabel raw data
- report simulated dashboard values as experimental results
- claim an attack succeeded if telemetry does not demonstrate it
- claim service-port scanning from ephemeral client ports
- claim novelty without evidence
- optimize code specifically to produce better-looking experimental results

If data is insufficient:

report the limitation.

If an experiment fails:

record the failure and diagnose it.

---

# 38. Development Style

Prefer:

- small modules
- type hints
- clear function boundaries
- docstrings for research-critical functions
- logging
- deterministic behavior
- reproducible CLI commands
- relative project paths
- cross-platform Python where practical

Avoid:

- giant monolithic scripts
- hidden global state
- hardcoded Pod names
- hardcoded absolute Windows paths
- unnecessary dependencies
- unnecessary deep-learning complexity

---

# 39. Agent Behavior

Before changing existing functionality:

1. inspect the current repository
2. understand existing files
3. run existing tests/scripts where possible
4. preserve working functionality

When uncertain:

DO NOT invent an assumption silently.

Instead:

- inspect the repository
- inspect existing data
- inspect documentation
- make the smallest defensible assumption
- document the assumption

Do not repeatedly ask the user for information that can be determined from the repository.

---

# 40. Implementation Priority

Work in this order:

PHASE 1
Repository inspection and cleanup

PHASE 2
Data schemas and validation

PHASE 3
Network/workload feature extraction

PHASE 4
Timestamp/window alignment

PHASE 5
Experiment metadata and labeling

PHASE 6
Network-only ML pipeline

PHASE 7
Workload-only ML pipeline

PHASE 8
Network + workload fusion

PHASE 9
Evaluation and ablation

PHASE 10
Explainability/evidence extraction

PHASE 11
Dashboard/backend

PHASE 12
Tests and reproducibility

PHASE 13
Documentation

Do not skip directly to the dashboard while the experimental pipeline is unreliable.

---

# 41. Definition of Done

The project should eventually support:

1. Reproducible telemetry collection
2. Reproducible feature extraction
3. Reproducible time alignment
4. Reproducible labeling
5. Network-only ML experiment
6. Workload-only ML experiment
7. Network + workload ML experiment
8. Objective evaluation
9. Ablation results
10. Model persistence
11. Evidence-aware alerts
12. Dashboard visualization
13. CSV export
14. Automated tests
15. Documentation
16. Reproducible experiment commands

The final system must be capable of generating the tables and figures required for the academic report/paper.

---

# 42. Final Rule

The research pipeline is more important than the UI.

If there is a conflict between:

"make the dashboard look impressive"

and

"maintain experimental validity"

choose experimental validity.
