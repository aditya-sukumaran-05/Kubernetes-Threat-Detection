"""Fixed UTC window assignment shared by all telemetry dimensions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from telemetry.schemas import SchemaError


WINDOW_SECONDS = 10


def window_start(timestamp: datetime, window_seconds: int = WINDOW_SECONDS) -> datetime:
    """Return the UTC epoch-aligned start for the timestamp's fixed window."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise SchemaError("cannot assign a naive timestamp to a UTC window")
    utc_time = timestamp.astimezone(timezone.utc)
    seconds = int(utc_time.timestamp())
    return datetime.fromtimestamp(seconds - seconds % window_seconds, tz=timezone.utc)


def window_end(start: datetime, window_seconds: int = WINDOW_SECONDS) -> datetime:
    return start + timedelta(seconds=window_seconds)


def isoformat_z(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
