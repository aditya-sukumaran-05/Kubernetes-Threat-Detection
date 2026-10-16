"""Runtime process execution feature extraction for 10-second observation windows."""

from __future__ import annotations

from typing import Any, Sequence

from telemetry.schemas import RuntimeEvent

SENSITIVE_COMMANDS = frozenset({
    "sh",
    "bash",
    "zsh",
    "dash",
    "curl",
    "wget",
    "nc",
    "netcat",
    "nmap",
    "whoami",
    "id",
    "chmod",
    "chown",
    "iptables",
    "socat",
    "python",
    "python3",
    "perl",
    "su",
    "sudo",
})

INTERACTIVE_SHELLS = frozenset({"sh", "bash", "zsh", "dash"})


def extract_runtime_features(
    events: Sequence[RuntimeEvent],
    window_seconds: int = 10,
) -> dict[str, Any]:
    """Extract runtime process execution telemetry features for an observation window.

    Calculates execution counts, unique commands, root/non-root execution ratios,
    sensitive recon/binary invocations, and execution rate.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    event_count = len(events)
    if event_count == 0:
        return {
            "runtime_event_count": 0,
            "runtime_unique_commands": 0,
            "runtime_root_exec_count": 0,
            "runtime_non_root_exec_count": 0,
            "runtime_unique_users": 0,
            "runtime_sensitive_command_count": 0,
            "runtime_interactive_shell_count": 0,
            "runtime_error_count": 0,
            "runtime_exec_rate": 0.0,
        }

    commands = set()
    users = set()
    root_exec_count = 0
    non_root_exec_count = 0
    sensitive_command_count = 0
    interactive_shell_count = 0
    error_count = 0

    for event in events:
        comm = (event.comm or "unknown").strip().lower()
        commands.add(comm)

        # User / uid tracking
        if event.username:
            users.add(event.username)
        elif event.uid is not None:
            users.add(str(event.uid))

        if event.uid == 0 or (event.username and event.username.lower() == "root"):
            root_exec_count += 1
        elif event.uid is not None:
            non_root_exec_count += 1

        # Check binary name or base comm against sensitive lists
        base_comm = comm.split("/")[-1]
        if base_comm in SENSITIVE_COMMANDS:
            sensitive_command_count += 1
        if base_comm in INTERACTIVE_SHELLS:
            interactive_shell_count += 1

        if event.error and event.error.strip():
            error_count += 1

    exec_rate = round(event_count / float(window_seconds), 4)

    return {
        "runtime_event_count": event_count,
        "runtime_unique_commands": len(commands),
        "runtime_root_exec_count": root_exec_count,
        "runtime_non_root_exec_count": non_root_exec_count,
        "runtime_unique_users": len(users),
        "runtime_sensitive_command_count": sensitive_command_count,
        "runtime_interactive_shell_count": interactive_shell_count,
        "runtime_error_count": error_count,
        "runtime_exec_rate": exec_rate,
    }


def extract_runtime_window_features(
    events: Sequence[RuntimeEvent],
    window_seconds: int = 10,
) -> list[dict[str, Any]]:
    """Aggregate process execution events into UTC epoch-aligned fixed windows."""
    from collections import defaultdict
    from telemetry.schemas import ensure_sorted
    from telemetry.windowing import isoformat_z, window_end, window_start

    grouped: dict[Any, list[RuntimeEvent]] = defaultdict(list)
    for event in ensure_sorted(events):
        grouped[window_start(event.timestamp, window_seconds)].append(event)

    rows: list[dict[str, Any]] = []
    for start in sorted(grouped):
        window_events = grouped[start]
        features = extract_runtime_features(window_events, window_seconds=window_seconds)
        pods = {event.pod for event in window_events if event.pod}
        row = {
            "window_start": isoformat_z(start),
            "window_end": isoformat_z(window_end(start, window_seconds)),
            "affected_pods": ";".join(sorted(pods)) if pods else "unknown",
            **features,
        }
        rows.append(row)
    return rows
