import json
import csv
import os
from collections import defaultdict
from datetime import datetime, timedelta

INPUT_FILES = {
    "normal": "telemetry/data/network/network_normal.jsonl",
    "attack": "telemetry/data/network/network_burst_attack.jsonl"
}

OUTPUT_DIR = "telemetry/data/network/features"
WINDOW_SECONDS = 10

os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_events(filename):
    events = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

                timestamp = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )

                event["_datetime"] = timestamp
                events.append(event)

            except (json.JSONDecodeError, KeyError, ValueError):
                continue

    return events


def extract_features(events, label):
    if not events:
        return []

    events.sort(key=lambda x: x["_datetime"])

    start_time = events[0]["_datetime"]
    windows = defaultdict(list)

    for event in events:
        elapsed = (event["_datetime"] - start_time).total_seconds()
        window_index = int(elapsed // WINDOW_SECONDS)

        windows[window_index].append(event)

    rows = []

    for window_index in sorted(windows):
        window_events = windows[window_index]

        timestamps = [
            event["_datetime"]
            for event in window_events
        ]

        source_ips = set()
        source_ports = set()
        destination_ips = set()
        destination_ports = set()

        accept_count = 0
        close_count = 0
        error_count = 0

        for event in window_events:

            src = event.get("src", {})
            dst = event.get("dst", {})

            if src.get("addr"):
                source_ips.add(src["addr"])

            if src.get("port"):
                source_ports.add(src["port"])

            if dst.get("addr"):
                destination_ips.add(dst["addr"])

            if dst.get("port"):
                destination_ports.add(dst["port"])

            event_type = event.get("type", "")

            if event_type == "accept":
                accept_count += 1

            elif event_type == "close":
                close_count += 1

            if event.get("error"):
                error_count += 1

        window_start = start_time + timedelta(
            seconds=window_index * WINDOW_SECONDS
        )

        window_end = window_start + timedelta(
            seconds=WINDOW_SECONDS
        )

        connection_rate = accept_count / WINDOW_SECONDS

        rows.append({
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "connection_count": accept_count,
            "event_count": len(window_events),
            "unique_source_ips": len(source_ips),
            "unique_source_ports": len(source_ports),
            "unique_destination_ips": len(destination_ips),
            "unique_destination_ports": len(destination_ports),
            "accept_count": accept_count,
            "close_count": close_count,
            "error_count": error_count,
            "connection_rate": round(connection_rate, 4),
            "label": label
        })

    return rows


for label, filename in INPUT_FILES.items():

    print(f"Processing {label}: {filename}")

    events = load_events(filename)

    print(f"  Events loaded: {len(events)}")

    features = extract_features(events, label)

    output_file = os.path.join(
        OUTPUT_DIR,
        f"network_{label}_features.csv"
    )

    if features:
        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=features[0].keys()
            )

            writer.writeheader()
            writer.writerows(features)

    print(f"  Windows created: {len(features)}")
    print(f"  Output: {output_file}\n")

print("Network feature extraction complete.")