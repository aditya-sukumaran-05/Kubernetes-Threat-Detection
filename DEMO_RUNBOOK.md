# K8S SENTINEL: Final Project Demonstration Runbook

**Project Title:** Machine Learning-Based Threat Detection Framework for Kubernetes Environments  
**Presenter:** Aditya Sukumaran  
**Course:** VIT SWE3004 — Final-Year M.Tech Software Engineering Capstone Project  
**Date:** 2026-10-16  

---

## 1. Quick Reference & Architecture Map

| Component | Port / Path | Purpose |
|:---|:---|:---|
| **Streamlit SOC Dashboard** | `http://localhost:8501` | Primary evaluation interface |
| **Minikube Cluster** | `127.0.0.1:8443` | Local single-node Kubernetes cluster (v1.37.0) |
| **Target Workload** | `deployment/webapp` (Port 80) | Target containerized web application |
| **Traffic Generator Pod** | `pod/traffic-simulator` | Dedicated in-cluster client for benign & attack traffic |
| **eBPF Network Sensor** | `kubectl gadget run trace_tcp` | Kernel TCP event streaming to `network_events.jsonl` |
| **eBPF Runtime Sensor** | `kubectl gadget run trace_exec`| In-container process execution streaming |
| **Workload Collector** | `kubectl top pod` | Container CPU & memory sampling |

---

## 2. Pre-Flight Verification Checklist (Before Presentation)

Open PowerShell and verify everything is ready in under 30 seconds:

```powershell
# 1. Verify Minikube & Pods
kubectl get pods -n default
# Expected:
# webapp-xxx          Running
# traffic-simulator   Running
# cpu-test            Running (Do not touch)

# 2. Verify Dashboard is Live
# Open browser to: http://localhost:8501
```

If the dashboard is not currently running, launch it with:
```powershell
python -m streamlit run dashboard/app.py
```

If the collectors need to be checked:
```powershell
# In PowerShell:
Get-Process python | Select-Object Id, ProcessName
```

---

## 3. Step-by-Step Demonstration Script (10-Minute Presentation)

### Step 1: Welcome & Architectural Overview (1–2 mins)
1. **Navigate to:** `🏠 Overview` on the sidebar.
2. **Point out:**
   - **Cluster Context Card:** Minikube cluster running Kubernetes v1.37.0.
   - **Sensor Health Indicators:** Network (eBPF TCP), Runtime (eBPF trace_exec), and Workload (Metrics Server) are all active.
   - **Research Thesis:** *"Our framework investigates how combining heterogeneous Kubernetes telemetry impacts detection accuracy, false positives, detection latency, and monitoring overhead."*

---

### Step 2: Continuous Benign Traffic Simulation (1–2 mins)
1. **Navigate to:** `⚡ Traffic & Attacks` on the sidebar.
2. **Show the Preflight Banner:**
   - Client Pod: `traffic-simulator` (Running, IP `10.244.0.9`).
   - Target Service: `http://webapp` (Port 80).
3. **Action:** Click `▶️ Start Benign Traffic`.
   - The status badge transitions to `● ACTIVE / RUNNING`.
   - The counter increments every ~2 seconds with realistic latency (~150ms).
4. **Explain to Evaluator:**
   - *"We generate realistic background traffic from a dedicated in-cluster client pod. This creates a realistic baseline of TCP connections without contaminating historical datasets."*

---

### Step 3: Trigger an On-Demand Network Burst Attack (2 mins)
1. **In the same view (`⚡ Traffic & Attacks`), switch to the second tab:** `💥 On-Demand Attack Scenarios`.
2. **Action:** Under **Network Burst Flood**, verify the slider is set to `100 requests` (default) and click `🚀 Launch Network Burst`.
   - Progress spinner runs for ~0.8–1.2 seconds.
   - Success message appears: *"✅ Completed 100 requests in 1.16s! (Session: burst_xxx)"*
3. **Switch to:** `📡 Live Detection` on the sidebar.
4. **Observe Live Stream Metrics:**
   - The sliding 10-second window captures the sudden burst of **100 TCP connections / 200 events** in a single window (`connection_rate: 10.0 conn/s`).
   - The Active Model (**Random Forest**) classifies the window as **`normal`** with an elevated **Attack Probability / Score of 37.5% (0.375)** and **Confidence of 62.5%** (compared to 0.0% attack probability under benign traffic).
   - The **Contributing Evidence Card** highlights `network_connection_count`, `network_event_count`, and `network_connection_rate` as the top driving features.
5. **Key Talking Point for Evaluator (Model Sensitivity):**
   - *"Our models reflect genuine, untampered statistical decision boundaries. In the training baseline (`network_dataset.csv`), historical attack floods averaged 257 connections/window (range 67–613). A 100-connection live burst elevates the attack score significantly to 37.5%, but correctly remains classified as normal because it is below the 50% classification threshold without artificial threshold manipulation."*
6. **🎯 Navigation to Historical Replay (Deterministic In-Sample Ground-Truth Inspection):**
   - If the evaluator wants to inspect pre-trained ground-truth benchmark attack intervals:
     1. Click **`📼 Historical Replay`** on the sidebar.
     2. Select Modality: **`1. Network + Workload [ML Benchmark]`** (or `2. Network Only`).
     3. Click **`🎯 Jump to First Attack Window`**.
     4. This instantly navigates to known benchmark attack intervals, displaying deterministic in-sample point-in-time verdict matching against ground truth using the production reference model (note: out-of-fold generalization metrics are rigorously evaluated under LOSO in `📈 Model Evaluation`).

---

### Step 4: Trigger Container Introspection Activity (2 mins)
1. **Return to:** `⚡ Traffic & Attacks` -> `💥 On-Demand Attack Scenarios`.
2. **Action:** Under **Runtime Container Introspection**, click `🛡️ Launch Introspection Activity`.
   - Executes harmless commands (`id`, `whoami`, `curl -I http://webapp`, `uname -a`) inside `webapp`.
3. **Switch to:** `🛡️ Runtime Events` on the sidebar.
4. **Observe:**
   - Real-time Inspektor Gadget `trace_exec` logs appearing with executable path, user ID (`root`), and parent process (`containerd-shim`).
   - **Explain Reception-Time Window Alignment + Raw Event-Time Inter-Arrival Features:**
     - *Reception-Time Window Alignment (`collector_timestamp`):* Python collectors timestamp each record upon user-space delivery in Windows host UTC to floor events into common 10-second observation windows across heterogeneous streams. This incurs a capture-time uncertainty of approximately $\pm 100\text{--}300\text{ms}$ due to OS pipe buffering, thread scheduling, and JSON serialization; we do NOT claim guaranteed real-world temporal alignment.
     - *Raw Event-Time Inter-Arrival Features (`raw_timestamp`):* Within each observation window, inter-arrival time deltas $(t_{i+1} - t_i)$ are computed strictly using kernel eBPF monotonic timestamps. This isolates packet rate and jitter calculations from pipe buffering latency and cancels out constant hypervisor clock drift.

---

### Step 5: Heterogeneous Telemetry Ablation Study (2 mins)
1. **Navigate to:** `📈 Model Evaluation` on the sidebar.
2. **Point out the Core Research Comparison Table:**
   - **Network Only:** High recall on burst/connection floods, but blind to internal container CPU abuse.
   - **Workload Only:** Detects CPU spikes, but exhibits higher latency due to 5-second Metrics Server sampling intervals.
   - **Network + Workload Fusion:** Provides optimal balance—rapid network anomaly detection backed by workload corroboration, minimizing false positives.
3. **Distinguish Live Controlled Burst from Historical Benchmark Datasets:**
   - *Live Controlled Burst Result:* $N=1$ live window (100 connections in 1.16s, 10.0 conn/s), classified as `normal` (attack score 37.5%, confidence 62.5%) under the frozen production Random Forest model.
   - *Historical Benchmark Datasets & Out-of-Fold LOSO Evaluation:* Evaluated offline using temporal Leave-One-Scenario-Out (LOSO) cross-validation across independent sessions:
     - **Network Modality Dataset:** $N=60$ labeled 10-second observation windows across 8 sessions ($32$ normal, $28$ attack; generated from 120 normal TCP events + 120 burst attack events). Out-of-fold LOSO Random Forest: Precision: $96.4\%$, Recall: $96.4\%$, $F_1 = 0.964$, FPR: $3.1\%$.
     - **Workload Modality Dataset:** $N=83$ labeled 10-second observation windows across 8 sessions ($55$ normal, $28$ attack; derived from $339$ raw Metrics Server CSV lines / samples: $186$ normal in `workload_normal.csv` + $153$ attack in `workload_attack.csv`). Out-of-fold LOSO Random Forest: Precision: $58.3\%$, Recall: $50.0\%$, $F_1 = 0.538$, FPR: $18.2\%$.
     - **Fusion Modality Dataset:** $N=122$ labeled 10-second observation windows across 24 sessions ($94$ normal, $28$ attack; synchronized time-aligned multi-modal windows). Out-of-fold LOSO Random Forest: Precision: $92.9\%$, Recall: $92.9\%$, $F_1 = 0.929$, FPR: $2.1\%$.
4. **Tested Scenario Observation (Not a Universal Law):**
   - In this specific tested scenario, the 100-request burst generated only network traffic to Nginx, consuming negligible CPU ($2\text{m}$ CPU, $18\text{ MiB}$ RAM), so Workload and Fusion inference both classified the window as `normal` (Workload attack score 15.8%, Fusion attack score 8.5%).
   - *This is an observation from the tested scenario, not proof that all attacks require simultaneous CPU and network stress—specialized single-vector threats (e.g. silent cryptomining or pure SYN floods) may manifest primarily in a single telemetry dimension.*

---

### Step 6: Historical Replay & Evaluation Verification (1 min)
1. **Navigate to:** `📼 Historical Replay` on the sidebar.
2. **Select Modality:** `1. Network + Workload [ML Benchmark]`.
3. **Action:** Click `🎯 Jump to First Attack Window`.
   - Compares ground truth with model predictions and displays the confusion matrix.

---

## 4. Emergency Troubleshooting & Quick Fixes

| Issue | Quick Fix Command (PowerShell) |
|:---|:---|
| **Dashboard stops or browser tab freezes** | `python -m streamlit run dashboard/app.py` |
| **Check benign traffic status from CLI** | `python -m experiments.traffic_simulator status` |
| **Stop benign traffic from CLI** | `python -m experiments.traffic_simulator stop-benign` |
| **Trigger network burst from CLI** | `python -m experiments.traffic_simulator run-attack --scenario network_burst --requests 100` |
| **Trigger runtime introspection from CLI** | `python -m experiments.traffic_simulator run-attack --scenario runtime_anomaly` |
| **Trigger concurrent attack from CLI** | `python -m experiments.traffic_simulator run-attack --scenario concurrent_attack` |
| **Run regression test suite** | `pytest tests/test_dashboard.py tests/test_features.py -v` |

---

## 5. Key Talking Points for Evaluator Questions

1. **Why use 10-second observation windows?**
   - 10 seconds matches the Nyquist sampling criterion for Kubernetes Metrics Server (which samples every ~5–10s) while providing sufficient packet/TCP aggregation to compute stable connection rate statistics.
2. **Why server-side TCP event logging?**
   - Inspektor Gadget monitors the `webapp` pod socket interface. High unique destination ports represent client-side ephemeral ports, which must not be confused with port scans.
3. **How does the system prevent data leakage?**
   - Temporal Leave-One-Scenario-Out (LOSO) cross-validation is used instead of random window splitting, ensuring adjacent correlated windows never leak between training and testing sets.
4. **Is the `cpu-test` pod part of the benchmark?**
   - No, `cpu-test` is an existing live pod preserved in the cluster. Benchmark workload abuse data was collected from controlled stress experiments directly on `webapp`.
5. **How are heterogeneous timestamps aligned?**
   - Telemetry alignment uses **reception-time window alignment plus raw event-time inter-arrival features**. Reception timestamps floor events into 10-second bins across heterogeneous streams (with $\pm 100\text{--}300\text{ms}$ capture-time uncertainty due to pipe buffering, without claiming guaranteed real-world temporal alignment). Fine-grained temporal features (inter-arrival deltas) rely strictly on kernel eBPF timestamps, isolating rate statistics from pipe latency and clock drift.
6. **How does the live 100-request burst compare to the benchmark?**
   - The live burst of 100 requests in 1.16s produced a 37.5% attack probability (classified as `normal` under the 50% cutoff) because historical benchmark attack windows ($N=28$ in `network_dataset.csv`) averaged 257 connections (range 67–613). When an evaluator wants to see confirmed benchmark attack detections, navigate to `📼 Historical Replay` or inspect cross-validated generalization metrics in `📈 Model Evaluation`.
