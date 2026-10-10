"""Workload metric feature extraction for UTC fixed windows."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean

from telemetry.schemas import WorkloadSample, ensure_sorted
from telemetry.windowing import WINDOW_SECONDS, isoformat_z, window_end, window_start


def extract_workload_features(samples: list[WorkloadSample], window_seconds: int = WINDOW_SECONDS) -> list[dict[str, object]]:
    """Create causal per-window workload aggregates; no future samples are used."""
    grouped: dict[object, list[WorkloadSample]] = defaultdict(list)
    for sample in ensure_sorted(samples):
        grouped[window_start(sample.timestamp, window_seconds)].append(sample)

    rows: list[dict[str, object]] = []
    for start in sorted(grouped):
        values = grouped[start]
        cpu = [sample.cpu_millicores for sample in values]
        memory = [sample.memory_mib for sample in values]
        pods = {sample.pod for sample in values}
        rows.append({
            "window_start": isoformat_z(start),
            "window_end": isoformat_z(window_end(start, window_seconds)),
            "affected_pods": ";".join(sorted(pods)),
            "workload_sample_count": len(values),
            "workload_cpu_millicores_mean": mean(cpu),
            "workload_cpu_millicores_min": min(cpu),
            "workload_cpu_millicores_max": max(cpu),
            "workload_cpu_millicores_last": cpu[-1],
            "workload_cpu_millicores_delta": cpu[-1] - cpu[0],
            "workload_memory_mib_mean": mean(memory),
            "workload_memory_mib_min": min(memory),
            "workload_memory_mib_max": max(memory),
            "workload_memory_mib_last": memory[-1],
            "workload_memory_mib_delta": memory[-1] - memory[0],
        })
    return rows
