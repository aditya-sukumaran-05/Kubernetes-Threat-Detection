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


def test_network_event_prefer_collector_timestamp() -> None:
    raw = {
        "timestamp": "2026-10-14T03:00:00.000Z",
        "collector_timestamp": "2026-10-14T12:39:29.000Z",
        "type": "accept",
        "src": {"addr": "10.0.0.1", "port": 80},
        "dst": {"addr": "10.0.0.2", "port": 50000},
    }
    # Default uses eBPF timestamp
    ev_default = NetworkEvent.from_raw(raw)
    assert ev_default.timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_default.raw_timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_default.collector_timestamp is not None
    assert ev_default.collector_timestamp.isoformat() == "2026-10-14T12:39:29+00:00"

    # Preferred uses collector_timestamp
    ev_collector = NetworkEvent.from_raw(raw, prefer_collector_timestamp=True)
    assert ev_collector.timestamp.isoformat() == "2026-10-14T12:39:29+00:00"
    assert ev_collector.raw_timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_collector.collector_timestamp is not None
    assert ev_collector.collector_timestamp.isoformat() == "2026-10-14T12:39:29+00:00"


def test_runtime_event_prefer_collector_timestamp() -> None:
    from telemetry.schemas import RuntimeEvent

    raw = {
        "timestamp": "2026-10-14T03:00:00.000Z",
        "collector_timestamp": "2026-10-14T12:39:29.000Z",
        "args": "id",
        "proc": {"comm": "id"},
    }
    ev_default = RuntimeEvent.from_raw(raw)
    assert ev_default.timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_default.raw_timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_default.collector_timestamp is not None
    assert ev_default.collector_timestamp.isoformat() == "2026-10-14T12:39:29+00:00"

    ev_collector = RuntimeEvent.from_raw(raw, prefer_collector_timestamp=True)
    assert ev_collector.timestamp.isoformat() == "2026-10-14T12:39:29+00:00"
    assert ev_collector.raw_timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_collector.collector_timestamp is not None
    assert ev_collector.collector_timestamp.isoformat() == "2026-10-14T12:39:29+00:00"


def test_missing_collector_timestamp_fallback() -> None:
    raw_net = {
        "timestamp": "2026-10-14T03:00:00.000Z",
        "type": "accept",
        "src": {"addr": "10.0.0.1", "port": 80},
        "dst": {"addr": "10.0.0.2", "port": 50000},
    }
    ev = NetworkEvent.from_raw(raw_net, prefer_collector_timestamp=True)
    assert ev.timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev.raw_timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev.collector_timestamp is None

    from telemetry.schemas import RuntimeEvent
    raw_rt = {
        "timestamp": "2026-10-14T03:00:00.000Z",
        "args": "whoami",
        "proc": {"comm": "whoami"},
    }
    ev_rt = RuntimeEvent.from_raw(raw_rt, prefer_collector_timestamp=True)
    assert ev_rt.timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_rt.raw_timestamp.isoformat() == "2026-10-14T03:00:00+00:00"
    assert ev_rt.collector_timestamp is None


def test_timezone_handling_strict() -> None:
    import pytest
    from datetime import timezone

    # UTC with Z
    ts1 = parse_utc_timestamp("2026-10-14T12:00:00.000Z")
    assert ts1.tzinfo == timezone.utc
    assert ts1.hour == 12

    # Offset converted to UTC
    ts2 = parse_utc_timestamp("2026-10-14T17:30:00.000+05:30")
    assert ts2.tzinfo == timezone.utc
    assert ts2.hour == 12

    # Naive timestamp raises SchemaError
    with pytest.raises(SchemaError):
        parse_utc_timestamp("2026-10-14T12:00:00")

    # Malformed timestamp raises SchemaError
    with pytest.raises(SchemaError):
        parse_utc_timestamp("invalid-date")


def test_positional_constructor_backward_compatibility() -> None:
    from datetime import datetime, timezone
    from telemetry.schemas import Endpoint

    base = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
    ev = NetworkEvent(
        base,
        "accept",
        Endpoint("10.0.0.1", 80),
        Endpoint("10.0.0.2", 50000),
        "webapp-a",
        None,
    )
    assert ev.timestamp == base
    assert ev.raw_timestamp == base
    assert ev.collector_timestamp is None



