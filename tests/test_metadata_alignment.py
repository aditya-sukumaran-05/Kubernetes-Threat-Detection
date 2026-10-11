from datetime import datetime, timezone

import pytest

from experiments.alignment import align_feature_windows
from experiments.metadata import CaptureMetadata, LabelInterval, assign_labels


def test_labels_are_assigned_only_from_metadata_intervals() -> None:
    interval = LabelInterval(datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc), "attack", "network_burst")
    capture = CaptureMetadata("capture", "network", "raw.jsonl", "session", "", (interval,))
    rows = assign_labels([
        {"window_start": "2026-01-01T00:00:00Z"},
        {"window_start": "2026-01-01T00:01:00Z"},
    ], capture)
    assert [row["label"] for row in rows] == ["attack", "unknown"]


def test_alignment_is_outer_join_with_explicit_availability() -> None:
    network = [{"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:00:10Z", "session_id": "same", "label": "normal", "attack_type": "normal", "network_event_count": 2}]
    workload = [{"window_start": "2026-01-01T00:00:10Z", "window_end": "2026-01-01T00:00:20Z", "session_id": "same", "label": "normal", "attack_type": "normal", "workload_sample_count": 1}]
    rows = align_feature_windows(network, workload)
    assert [(row["network_available"], row["workload_available"]) for row in rows] == [(True, False), (False, True)]


def test_alignment_rejects_different_sessions() -> None:
    left = [{"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:00:10Z", "session_id": "network"}]
    right = [{"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:00:10Z", "session_id": "workload"}]
    with pytest.raises(ValueError, match="different experiment sessions"):
        align_feature_windows(left, right)


def test_cross_cluster_alignment_is_rejected() -> None:
    left = [
        {"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:00:10Z", "session_id": "s1", "cluster_id": "cluster-a", "network_event_count": 1}
    ]
    right = [
        {"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:00:10Z", "session_id": "s1", "cluster_id": "cluster-b", "workload_sample_count": 1}
    ]
    with pytest.raises(ValueError, match="cannot align captures from different clusters"):
        align_feature_windows(left, right)
