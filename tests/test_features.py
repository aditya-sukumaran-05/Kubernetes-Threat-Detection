from datetime import datetime, timezone

from telemetry.features.network import extract_network_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import Endpoint, NetworkEvent, WorkloadSample
from telemetry.windowing import window_start


def test_windowing_is_epoch_aligned() -> None:
    timestamp = datetime(2026, 9, 19, 12, 0, 9, 999999, tzinfo=timezone.utc)
    assert window_start(timestamp).isoformat() == "2026-09-19T12:00:00+00:00"


def test_network_features_count_events_and_fixed_rate() -> None:
    base = datetime(2026, 9, 19, 12, 0, 1, tzinfo=timezone.utc)
    endpoint = Endpoint("10.0.0.1", 80)
    events = [
        NetworkEvent(base, "accept", endpoint, Endpoint("10.0.0.2", 40000), "webapp-a", ""),
        NetworkEvent(base.replace(second=4), "close", endpoint, Endpoint("10.0.0.2", 40000), "webapp-a", ""),
    ]
    row = extract_network_features(events)[0]
    assert row["network_connection_count"] == 1
    assert row["network_event_count"] == 2
    assert row["network_connection_rate"] == 0.1
    assert row["network_unique_destination_ports"] == 1


def test_workload_features_are_window_aggregates() -> None:
    base = datetime(2026, 9, 19, 12, 0, 1, tzinfo=timezone.utc)
    rows = extract_workload_features([
        WorkloadSample(base, "webapp-old", 10, 13),
        WorkloadSample(base.replace(second=7), "webapp-new", 30, 15),
    ])
    assert rows[0]["workload_sample_count"] == 2
    assert rows[0]["workload_cpu_millicores_mean"] == 20
    assert rows[0]["workload_cpu_millicores_delta"] == 20
    assert rows[0]["affected_pods"] == "webapp-new;webapp-old"


def test_runtime_features_window_aggregates() -> None:
    from telemetry.features.runtime import extract_runtime_features
    from telemetry.schemas import RuntimeEvent

    base = datetime(2026, 9, 19, 12, 0, 1, tzinfo=timezone.utc)
    events = [
        RuntimeEvent(
            timestamp=base,
            comm="whoami",
            args="whoami",
            exepath="/usr/bin/whoami",
            cwd="/",
            pid=1001,
            tid=1001,
            uid=0,
            gid=0,
            username="root",
            parent_comm="containerd-shim",
            parent_pid=500,
            parent_exepath=None,
            pod="webapp-a",
            namespace="default",
            container_name="nginx",
            container_id="c1",
            error=None,
        ),
        RuntimeEvent(
            timestamp=base.replace(second=5),
            comm="bash",
            args="/bin/bash",
            exepath="/bin/bash",
            cwd="/",
            pid=1002,
            tid=1002,
            uid=0,
            gid=0,
            username="root",
            parent_comm="containerd-shim",
            parent_pid=500,
            parent_exepath=None,
            pod="webapp-a",
            namespace="default",
            container_name="nginx",
            container_id="c1",
            error=None,
        ),
    ]
    feats = extract_runtime_features(events, window_seconds=10)
    assert feats["runtime_event_count"] == 2
    assert feats["runtime_unique_commands"] == 2
    assert feats["runtime_root_exec_count"] == 2
    assert feats["runtime_sensitive_command_count"] == 2
    assert feats["runtime_interactive_shell_count"] == 1
    assert feats["runtime_exec_rate"] == 0.2


def test_inter_arrival_with_shared_collector_timestamp_and_distinct_raw_timestamps() -> None:
    from datetime import datetime, timezone
    from telemetry.features.network import extract_network_features
    from telemetry.schemas import Endpoint, NetworkEvent

    # Simulates pipe buffer compression: identical host reception time, distinct kernel times
    collector_t = datetime(2026, 10, 15, 12, 0, 5, 100000, tzinfo=timezone.utc)
    raw_t1 = datetime(2026, 10, 15, 3, 0, 0, 0, tzinfo=timezone.utc)
    raw_t2 = datetime(2026, 10, 15, 3, 0, 0, 5000, tzinfo=timezone.utc)   # +5ms
    raw_t3 = datetime(2026, 10, 15, 3, 0, 0, 20000, tzinfo=timezone.utc)  # +15ms

    endpoint_src = Endpoint("10.0.0.1", 80)
    endpoint_dst = Endpoint("10.0.0.2", 50000)

    events = [
        NetworkEvent(
            timestamp=collector_t,
            event_type="accept",
            source=endpoint_src,
            destination=endpoint_dst,
            pod="webapp-a",
            error=None,
            raw_timestamp=raw_t1,
            collector_timestamp=collector_t,
        ),
        NetworkEvent(
            timestamp=collector_t,
            event_type="accept",
            source=endpoint_src,
            destination=endpoint_dst,
            pod="webapp-a",
            error=None,
            raw_timestamp=raw_t2,
            collector_timestamp=collector_t,
        ),
        NetworkEvent(
            timestamp=collector_t,
            event_type="accept",
            source=endpoint_src,
            destination=endpoint_dst,
            pod="webapp-a",
            error=None,
            raw_timestamp=raw_t3,
            collector_timestamp=collector_t,
        ),
    ]

    rows = extract_network_features(events, window_seconds=10)
    assert len(rows) == 1
    row = rows[0]
    # Window start is derived from event.timestamp (collector_t at 12:00:00Z)
    assert row["window_start"] == "2026-10-15T12:00:00.000Z"
    assert row["network_event_count"] == 3
    # Inter-arrival metrics use raw_timestamp intervals: 0.005s and 0.015s -> mean = 0.010s
    assert abs(row["network_interarrival_mean_seconds"] - 0.010) < 1e-6
    assert abs(row["network_interarrival_min_seconds"] - 0.005) < 1e-6
    assert abs(row["network_interarrival_max_seconds"] - 0.015) < 1e-6


def test_inter_arrival_with_out_of_order_raw_timestamps() -> None:
    from datetime import datetime, timezone
    from telemetry.features.network import extract_network_features
    from telemetry.schemas import Endpoint, NetworkEvent

    collector_t = datetime(2026, 10, 15, 12, 0, 5, 100000, tzinfo=timezone.utc)
    raw_t1 = datetime(2026, 10, 15, 3, 0, 0, 0, tzinfo=timezone.utc)
    raw_t2 = datetime(2026, 10, 15, 3, 0, 0, 5000, tzinfo=timezone.utc)
    raw_t3 = datetime(2026, 10, 15, 3, 0, 0, 20000, tzinfo=timezone.utc)

    endpoint_src = Endpoint("10.0.0.1", 80)
    endpoint_dst = Endpoint("10.0.0.2", 50000)

    # Supply events out of chronological order by raw_timestamp (t3, t1, t2)
    events = [
        NetworkEvent(
            timestamp=collector_t,
            event_type="accept",
            source=endpoint_src,
            destination=endpoint_dst,
            pod="webapp-a",
            error=None,
            raw_timestamp=raw_t3,
            collector_timestamp=collector_t,
        ),
        NetworkEvent(
            timestamp=collector_t,
            event_type="accept",
            source=endpoint_src,
            destination=endpoint_dst,
            pod="webapp-a",
            error=None,
            raw_timestamp=raw_t1,
            collector_timestamp=collector_t,
        ),
        NetworkEvent(
            timestamp=collector_t,
            event_type="accept",
            source=endpoint_src,
            destination=endpoint_dst,
            pod="webapp-a",
            error=None,
            raw_timestamp=raw_t2,
            collector_timestamp=collector_t,
        ),
    ]

    rows = extract_network_features(events, window_seconds=10)
    assert len(rows) == 1
    row = rows[0]
    # Sorting ensures inter-arrival is calculated chronologically without negative deltas
    assert abs(row["network_interarrival_mean_seconds"] - 0.010) < 1e-6
    assert abs(row["network_interarrival_min_seconds"] - 0.005) < 1e-6
    assert abs(row["network_interarrival_max_seconds"] - 0.015) < 1e-6


def test_extract_network_features_empty_input_regression() -> None:
    """Ensure extract_network_features cleanly handles empty event lists without NameError or UnboundLocalError."""
    assert extract_network_features([]) == []


def test_extract_network_features_accept_count_and_rate_logic_regression() -> None:
    """Verify accept_count, close_count, error_count, and connection_rate logic under mixed normal events."""
    base_t = datetime(2026, 10, 15, 12, 0, 1, tzinfo=timezone.utc)
    src = Endpoint("10.244.0.7", 80)
    dst = Endpoint("10.244.0.9", 33508)

    events = [
        # 3 accepts, 2 closes, 1 error
        NetworkEvent(base_t, "accept", src, dst, "webapp", ""),
        NetworkEvent(base_t.replace(second=2), "accept", src, dst, "webapp", ""),
        NetworkEvent(base_t.replace(second=3), "close", src, dst, "webapp", ""),
        NetworkEvent(base_t.replace(second=4), "accept", src, dst, "webapp", ""),
        NetworkEvent(base_t.replace(second=5), "close", src, dst, "webapp", ""),
        NetworkEvent(base_t.replace(second=6), "error", src, dst, "webapp", "connection reset"),
    ]

    rows = extract_network_features(events, window_seconds=10)
    assert len(rows) == 1
    w = rows[0]
    assert w["network_event_count"] == 6
    assert w["network_accept_count"] == 3
    assert w["network_connection_count"] == 3
    assert w["network_close_count"] == 2
    assert w["network_error_count"] == 1
    assert abs(float(w["network_connection_rate"]) - 0.3) < 1e-6


def test_extract_network_features_zero_accepts_regression() -> None:
    """Verify windows with zero accept events calculate rate=0.0 and count=0 without error."""
    base_t = datetime(2026, 10, 15, 12, 0, 1, tzinfo=timezone.utc)
    src = Endpoint("10.244.0.7", 80)
    dst = Endpoint("10.244.0.9", 33508)

    events = [
        NetworkEvent(base_t, "close", src, dst, "webapp", ""),
        NetworkEvent(base_t.replace(second=2), "close", src, dst, "webapp", ""),
    ]

    rows = extract_network_features(events, window_seconds=10)
    assert len(rows) == 1
    w = rows[0]
    assert w["network_event_count"] == 2
    assert w["network_accept_count"] == 0
    assert w["network_connection_count"] == 0
    assert w["network_close_count"] == 2
    assert w["network_connection_rate"] == 0.0



