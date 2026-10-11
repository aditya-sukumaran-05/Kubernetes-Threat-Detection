"""Strict temporal alignment for genuinely concurrent telemetry sessions."""

from __future__ import annotations


def align_feature_windows(
    network_rows: list[dict[str, object]], workload_rows: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Outer-join network and workload windows from the *same* session only.

    Missing telemetry is explicit.  Different sessions are rejected so that
    separate captures cannot accidentally be presented as multimodal fusion.
    """
    sessions = {str(row["session_id"]) for row in [*network_rows, *workload_rows]}
    if len(sessions) > 1:
        raise ValueError("cannot align captures from different experiment sessions")
    clusters = {
        str(row.get("cluster_id") or "minikube")
        for row in [*network_rows, *workload_rows]
    }
    if len(clusters) > 1:
        raise ValueError("cannot align captures from different clusters")
    network_by_window = {str(row["window_start"]): row for row in network_rows}
    workload_by_window = {str(row["window_start"]): row for row in workload_rows}
    aligned: list[dict[str, object]] = []
    for key in sorted(set(network_by_window) | set(workload_by_window)):
        network, workload = network_by_window.get(key), workload_by_window.get(key)
        base = network or workload
        assert base is not None
        row: dict[str, object] = {
            "window_start": key,
            "window_end": base["window_end"],
            "cluster_id": base.get("cluster_id") or "minikube",
            "session_id": base["session_id"],
            "network_available": network is not None,
            "workload_available": workload is not None,
        }
        for attr in ("scenario", "experiment_id", "capture_id"):
            if attr in base:
                row[attr] = base[attr]
        for source_row, prefix in ((network, "network_"), (workload, "workload_")):
            if source_row:
                row.update({name: value for name, value in source_row.items() if name.startswith(prefix)})
        labels = {str(item["label"]) for item in (network, workload) if item is not None}
        attack_types = {str(item["attack_type"]) for item in (network, workload) if item is not None}
        row["label"] = labels.pop() if len(labels) == 1 else "unknown"
        row["attack_type"] = attack_types.pop() if len(attack_types) == 1 else "unknown"
        aligned.append(row)
    return aligned
