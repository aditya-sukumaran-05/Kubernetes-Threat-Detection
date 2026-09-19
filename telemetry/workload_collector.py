import subprocess
import csv
import time
import os
from datetime import datetime, timezone

OUTPUT_FILE = "telemetry/data/workload_metrics.csv"
LABEL = "normal"
INTERVAL = 5


def get_webapp_pod():
    result = subprocess.run(
        [
            "kubectl",
            "get",
            "pods",
            "-l",
            "app=webapp",
            "-o",
            "jsonpath={.items[0].metadata.name}"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    pod_name = result.stdout.strip()

    if not pod_name:
        raise RuntimeError("No webapp pod found.")

    return pod_name


def get_metrics(pod_name):
    result = subprocess.run(
        [
            "kubectl",
            "top",
            "pod",
            pod_name,
            "--no-headers"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    parts = result.stdout.strip().split()

    if len(parts) < 3:
        raise RuntimeError("Invalid metrics output.")

    cpu = parts[1].replace("m", "")
    memory = parts[2].replace("Mi", "")

    return cpu, memory


os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

file_exists = os.path.exists(OUTPUT_FILE)

with open(OUTPUT_FILE, "a", newline="") as file:
    writer = csv.writer(file)

    if not file_exists:
        writer.writerow([
            "timestamp",
            "pod",
            "cpu_millicores",
            "memory_mib",
            "label"
        ])

print("Starting Kubernetes workload telemetry collector...")
print("Automatically discovering the webapp Pod.")
print("Press Ctrl+C to stop.\n")

while True:
    try:
        pod_name = get_webapp_pod()
        cpu, memory = get_metrics(pod_name)

        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        with open(OUTPUT_FILE, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                pod_name,
                cpu,
                memory,
                LABEL
            ])

        print(
            f"[{timestamp}] "
            f"Pod={pod_name}  "
            f"CPU={cpu}m  "
            f"Memory={memory}Mi"
        )

    except subprocess.CalledProcessError:
        print("Unable to retrieve Kubernetes information. Retrying...")

    except Exception as e:
        print(f"Error: {e}")

    except KeyboardInterrupt:
        print("\nCollector stopped.")
        break

    time.sleep(INTERVAL)