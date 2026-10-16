"""Network feature extraction without interpreting ephemeral ports as service scans."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev

from telemetry.schemas import NetworkEvent, ensure_sorted
from telemetry.windowing import WINDOW_SECONDS, isoformat_z, window_end, window_start


def extract_network_features(events: list[NetworkEvent], window_seconds: int = WINDOW_SECONDS) -> list[dict[str, object]]:
    """Aggregate server-side TCP events into UTC epoch-aligned fixed windows."""
    grouped: dict[object, list[NetworkEvent]] = defaultdict(list)
    for event in ensure_sorted(events):
        grouped[window_start(event.timestamp, window_seconds)].append(event)

    rows: list[dict[str, object]] = []
    for start in sorted(grouped):
        window_events = grouped[start]
        source_ips = {event.source.address for event in window_events if event.source.address}
        source_ports = {event.source.port for event in window_events if event.source.port is not None}
        destination_ips = {event.destination.address for event in window_events if event.destination.address}
        destination_ports = {event.destination.port for event in window_events if event.destination.port is not None}
        accept_count: int = sum(event.event_type == "accept" for event in window_events)
        close_count: int = sum(event.event_type == "close" for event in window_events)
        error_count: int = sum(bool(event.error) for event in window_events)
        eff_window_seconds = max(1, window_seconds)
        connection_rate: float = accept_count / eff_window_seconds

        # Inter-arrival calculation uses raw_timestamp for true microsecond kernel intervals
        # (falling back to windowing timestamp if raw_timestamp is absent).
        # Events within the window are explicitly ordered by this timestamp before computing deltas.
        inter_arrival_events = sorted(
            window_events,
            key=lambda e: e.raw_timestamp if e.raw_timestamp is not None else e.timestamp,
        )
        timestamps = [
            e.raw_timestamp if e.raw_timestamp is not None else e.timestamp
            for e in inter_arrival_events
        ]
        inter_arrivals = [
            (later - earlier).total_seconds() for earlier, later in zip(timestamps, timestamps[1:])
        ]
        pods = {event.pod for event in window_events if event.pod}
        rows.append({
            "window_start": isoformat_z(start),
            "window_end": isoformat_z(window_end(start, window_seconds)),
            "affected_pods": ";".join(sorted(pods)),
            "network_connection_count": accept_count,
            "network_event_count": len(window_events),
            "network_unique_source_ips": len(source_ips),
            "network_unique_source_ports": len(source_ports),
            "network_unique_destination_ips": len(destination_ips),
            "network_unique_destination_ports": len(destination_ports),
            "network_accept_count": accept_count,
            "network_close_count": close_count,
            "network_error_count": error_count,
            "network_connection_rate": connection_rate,
            "network_interarrival_mean_seconds": mean(inter_arrivals) if inter_arrivals else 0.0,
            "network_interarrival_std_seconds": pstdev(inter_arrivals) if len(inter_arrivals) > 1 else 0.0,
            "network_interarrival_min_seconds": min(inter_arrivals) if inter_arrivals else 0.0,
            "network_interarrival_max_seconds": max(inter_arrivals) if inter_arrivals else 0.0,
        })
    return rows
