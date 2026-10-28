# Machine Learning-Based Threat Detection Framework for Kubernetes

> **Quick start (demo mode — no Kubernetes required):**
> ```powershell
> pip install -r requirements.txt
> python start.py both
> ```
> Opens the SOC dashboard at **http://127.0.0.1:8501** and the client console at **http://127.0.0.1:8502**.

This repository is a reproducible research prototype for assessing how
Kubernetes network and workload telemetry affect detection performance. It
does not claim telemetry fusion as a novel idea. Its focus is controlled data
collection, explicit time alignment, telemetry ablation, and evidence-aware
evaluation.

## Reproduce Phase 2

Install the recorded Python dependencies, then run the complete workflow from
the repository root:

```powershell
python -m pip install -r requirements.txt
python -m ml.run_all --project-root .
```

The command first rebuilds Phase 1 features from read-only raw telemetry,
builds ML datasets, applies a session-aware holdout eligibility check, and
writes results under `results/`.

Individual experiment commands are:

```powershell
python -m experiments.run_preprocessing --output-dir results\phase1_demo
python -m ml.train --config configs\network.json
python -m ml.train --config configs\workload.json
python -m ml.train --config configs\fusion.json
python -m pytest -q
```

## Scientific safeguards

- Raw captures under `telemetry/data/` are never modified.
- Timestamps are timezone-aware UTC and features use global epoch-aligned
  10-second windows.
- Labels originate only from `experiments/metadata/captures.json`.
- Windows with missing experiment intervals remain `unknown`; they are not
  relabeled from high CPU or high network activity.
- Training/testing is session-aware. It requires two independent sessions per
  class, so adjacent windows cannot leak across a random row split.
- Fusion requires an aligned network and workload capture with the same
  session ID. Separate network-burst and resource-abuse sessions are never
  combined.

## Current evidence limitation

The current network dataset has one normal session and one attack session;
the workload CPU-abuse capture lacks an explicit recorded attack interval; and
there is no simultaneous multimodal attack capture. Therefore, Phase 2 writes
the correctly constructed datasets and transparent `not_evaluable` experiment
records, but no valid held-out metrics, trained production model, or
performance figure. A new controlled capture should record at least two
independent normal and attack sessions for each telemetry condition, and a
combined network+workload attack session for fusion.

## Phase 3: controlled local data collection

The runner is dry-run by default: it creates a unique planned run directory
with metadata but does not start Kubernetes activity. It refuses execution
unless `kubectl config current-context` exactly equals `minikube`.

```powershell
# Plan a normal network session (safe; does not start collectors or traffic)
python -m experiments.run_experiment --scenario network_normal

# Explicitly execute controlled local-Minikube experiments
python -m experiments.run_experiment --scenario network_normal --execute
python -m experiments.run_experiment --scenario network_attack --execute
python -m experiments.run_experiment --scenario workload_normal --execute
python -m experiments.run_experiment --scenario workload_attack --execute
python -m experiments.run_experiment --scenario fusion_normal --execute
python -m experiments.run_experiment --scenario fusion_attack --execute

# Inventory valid and partial captures, then process/evaluate them
python -m experiments.manifest
python -m experiments.run_preprocessing --runs-dir experiments\runs --output-dir results\phase1_demo
python -m ml.run_all --project-root .
```

`network_attack` and `fusion_attack` generate a controlled high-rate HTTP
burst only against `http://webapp` from the local traffic-generator Pod.
`workload_attack` and `fusion_attack` run a controlled CPU loop in the local
test workload. Do not use `--execute` against any context other than Minikube.

## Evaluation Artifacts and Telemetry Ablation Map

The framework produces and maintains distinct evaluation benchmarks across development phases:

- **Canonical 7-Modality LOSO Benchmark (`results/loso/`):**
  - Primary files: `results/loso/loso_aggregate_comparison.csv` and `results/loso/loso_summary.json`
  - Scope: The authoritative reference evaluation comparing all seven modalities (`network`, `workload`, `fusion`, `runtime`, `net_rt`, `rt_wl`, `full_fusion`) across 8 to 35 independent experiment sessions.
  - Leakage Safeguard: Leave-One-Session-Out (LOSO) cross-validation guarantees zero temporal autocorrelation leakage across adjacent 10-second observation windows; data imputation and scaling transformations are strictly fitted on training folds only.
- **Historical 3-Modality Baseline (`results/`):**
  - Primary files: `results/ablation_comparison.csv` and `results/ablation_comparison.json`
  - Scope: Early Phase 2 baseline evaluating only three legacy modalities (`network`, `workload`, `fusion`) under a single train/test session holdout. Preserved as an immutable historical record.
- **Campaign Run Archives (`results/campaign_*/`):**
  - Point-in-time campaign execution snapshots preserved for historical verification.
- **Note on Discontinued Paths:**
  - `results/metrics/ablation_study.csv` does not exist; all cross-modality ablation references should consult `results/loso/loso_aggregate_comparison.csv`.

## Startup, Shutdown & Troubleshooting

### Orchestrated 3-Step Startup Architecture

The primary launcher (`start.py`) orchestrates the complete Kubernetes threat detection research stack in three sequential stages:

```
[Prerequisites Check]
        ↓
1. Minikube Cluster Initialization & Health Verification
   • Minikube cluster running & context set to 'minikube'
   • Node condition Ready
   • Nginx webapp deployment & NodePort service (port 80) Ready
   • Metrics Server addon enabled & rolled out
   • Inspektor Gadget v0.55.1 verified
   • Traffic-generator pod Running
        ↓
2. Telemetry Collectors Initialization (Background)
   • Network Collector (eBPF TCP)               → telemetry/data/network/network_events.jsonl
   • Workload Collector (Metrics Server)        → telemetry/data/workload_metrics.csv
   • Runtime Collector (eBPF trace_exec)        → telemetry/data/runtime/runtime_events.jsonl
   • Duplicate process prevention via PID files & psutil process inspection
        ↓
3. Dual-Console Dashboards Launch
   • SOC Threat Detection Dashboard             → http://127.0.0.1:8501
   • Client Attack Simulation Console           → http://127.0.0.1:8502
```

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | ≥ 3.11 | Tested on 3.13.9 |
| All packages | see `requirements.txt` | Install with `pip install -r requirements.txt` |
| Minikube | ≥ 1.39 | Required for live cluster and collector execution |
| Inspektor Gadget | v0.55.1 | Required for kernel eBPF socket and execution tracing |

### Setup (First Time)

```powershell
# 1. Clone repository and install dependencies
git clone https://github.com/aditya-sukumaran-05/Kubernetes-Threat-Detection.git
Set-Location Kubernetes-Threat-Detection
pip install -r requirements.txt

# 2. Verify all prerequisites
python start.py check
```

### Startup Commands

```powershell
# ── Full Stack (Minikube -> Collectors -> Both Dashboards) [Recommended] ──
python start.py

# ── Launch Only SOC Threat Detection Dashboard (Port 8501) ──
python start.py dashboard

# ── Launch Only Client Attack Simulation Console (Port 8502) ──
python start.py client

# ── Offline Demo Mode (Skips Minikube & Collectors; No Cluster Required) ──
python start.py demo
# or: python start.py --skip-k8s

# ── Live Terminal Telemetry Monitoring (Default on Windows) ──
# Opens separate, titled terminal windows for each collector and dashboard:
python start.py

# ── Headless / Background Mode (Silent CI/Server Mode) ──
# Runs collectors detached in the background without spawning terminal windows:
python start.py --background

# ── Sub-component Operations ──
python start.py k8s            # Initialize Minikube lab environment only
python start.py collectors     # Initialize Minikube & telemetry collectors only
python start.py check          # Run prerequisite validation only
```

The launcher records active process IDs in `.launcher_pids`. Re-running startup is completely idempotent: already-running collectors and dashboards are detected and reused rather than duplicated.

### Real-Time Terminal Telemetry Monitoring

By default on Windows interactive terminals (or via `--windows`), each component opens in its own dedicated, titled terminal window so you can monitor the live telemetry streams side-by-side with the web dashboards:
- **`K8s Sentinel — Network Telemetry Collector`**: Streams real-time eBPF TCP connection events (`connect`, `accept`, `close`).
- **`K8s Sentinel — Workload Telemetry Collector`**: Streams live pod CPU (millicores) and Memory (MiB) utilization ticks every 5 seconds.
- **`K8s Sentinel — Runtime Telemetry Collector`**: Streams real-time pod process execution events (`exec`, user, comm, PID).
- **`K8s Sentinel — SOC Threat Dashboard`**: Streamlit server output for the SOC detection console (`http://127.0.0.1:8501`).
- **`K8s Sentinel — Client Attack Console`**: Streamlit server output for attack generation (`http://127.0.0.1:8502`).
- **Main Launcher Terminal**: Central orchestration dashboard displaying overall stack health, URLs, and PID tracking.

When running in `--background` or `--headless` mode, stdout and stderr are continuously streamed to:
- `telemetry/data/network_collector.log`
- `telemetry/data/workload_collector.log`
- `telemetry/data/runtime_collector.log`

### Clean Shutdown

```powershell
# Gracefully stop all launcher-started processes (dashboards + collectors)
python start.py stop
```

Pressing `Ctrl+C` in the launcher terminal also triggers a clean shutdown of all managed child processes.

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` on start | Missing dependency | `pip install -r requirements.txt` |
| Port 8501 or 8502 already in use | Stale dashboard process | `python start.py stop`, then retry |
| Collector fails to start | Cluster not ready or Gadget missing | Run `python start.py k8s` to diagnose cluster state |
| Minikube not starting | Docker Desktop not running | Start Docker Desktop, then retry `python start.py` |
| Dashboard shows no models | Model joblib files missing | Run `python -m ml.run_all --project-root .` to train |
| `start.py stop` says "nothing to stop" | No PID file | Processes were not launched via `start.py` |

For direct fallback without the launcher:
```powershell
# SOC Dashboard
python -m streamlit run dashboard/app.py --server.port 8501

# Client Console
python -m streamlit run client_console/app.py --server.port 8502
```

For the emergency quick-fix table, see **DEMO_RUNBOOK.md § 4**.

---

## Threat Detection Dashboard

The project includes an interactive Streamlit dashboard for demonstrating the
end-to-end threat detection pipeline:

```powershell
streamlit run dashboard/app.py
```

### Supported Configurations
- **Modalities:**
  - `Fusion (Network + Workload)`: eBPF socket events time-aligned with container metrics.
  - `Network Only`: Inspektor Gadget TCP trace events (13 features).
  - `Workload Only`: cgroup/Metrics Server CPU and memory metrics (11 features).
- **Models:**
  - `Random Forest`: Ensemble baseline with model-native impurity feature importances.
  - `XGBoost`: Gradient-boosted decision tree baseline.
  - `Support Vector Machine (SVM)`: Non-linear RBF kernel classifier with Platt scaling.

### Detection Modes
- **Demo / Captured Data Mode:** Replays offline 10-second observation windows
  from the 24 clean campaign experiment sessions (`results/ml_datasets/`), passing
  each window to the active `ThreatDetector` engine and visualizing time series
  trends, verdicts, confidence scores, and model-derived evidence.
- **Manual Window Mode:** Accepts custom JSON telemetry payloads for on-demand
  schema validation, model scoring, and evidence breakdown.
- **Future Live Telemetry Mode:** The dashboard architecture decouples data
  sources via `TelemetryProvider`. In future development phases, a live Kubernetes
  provider can stream real-time eBPF socket events and Metrics Server samples directly
  into the dashboard without modifying UI or ML inference components.

