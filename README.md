# Machine Learning-Based Threat Detection Framework for Kubernetes

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

