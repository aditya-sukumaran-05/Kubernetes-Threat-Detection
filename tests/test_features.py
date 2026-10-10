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

