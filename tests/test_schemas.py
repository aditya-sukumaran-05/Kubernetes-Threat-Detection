from datetime import timezone

import pytest

from telemetry.schemas import NetworkEvent, SchemaError, WorkloadSample, parse_utc_timestamp


def test_timestamp_is_normalized_to_utc() -> None:
    assert parse_utc_timestamp("2026-09-19T17:30:00+05:30").tzinfo == timezone.utc
    assert parse_utc_timestamp("2026-09-19T17:30:00+05:30").hour == 12


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(SchemaError, match="timezone"):
        parse_utc_timestamp("2026-09-19T12:00:00")


def test_network_schema_requires_endpoints() -> None:
    with pytest.raises(SchemaError, match="src"):
        NetworkEvent.from_raw({"timestamp": "2026-09-19T12:00:00Z", "type": "accept"})


def test_workload_schema_does_not_consume_raw_label() -> None:
    sample = WorkloadSample.from_raw({"timestamp": "2026-09-19T12:00:00Z", "pod": "webapp-new", "cpu_millicores": "1", "memory_mib": "13", "label": "normal"})
    assert sample.pod == "webapp-new"


def test_runtime_schema_parsing() -> None:
    from telemetry.schemas import RuntimeEvent

    raw = {
        "timestamp": "2026-10-10T06:27:46.138118761Z",
        "args": "whoami",
        "proc": {
            "comm": "whoami",
            "pid": 173413,
            "tid": 173413,
            "creds": {"uid": 0, "gid": 0, "user": "root"},
            "parent": {"comm": "containerd-shim", "pid": 3524},
        },
        "k8s": {"podName": "webapp-test", "namespace": "default", "containerName": "nginx"},
        "cwd": "/",
        "exepath": "/usr/bin/whoami",
    }
    event = RuntimeEvent.from_raw(raw)
    assert event.comm == "whoami"
    assert event.pid == 173413
    assert event.uid == 0
    assert event.username == "root"
    assert event.parent_comm == "containerd-shim"
    assert event.pod == "webapp-test"
    assert event.timestamp.tzinfo == timezone.utc


def test_runtime_schema_requires_timestamp() -> None:
    from telemetry.schemas import RuntimeEvent

    with pytest.raises(SchemaError, match="timestamp"):
        RuntimeEvent.from_raw({"args": "whoami", "proc": {"comm": "whoami"}})

