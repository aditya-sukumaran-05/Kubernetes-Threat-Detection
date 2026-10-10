import argparse
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect workload telemetry from the dynamically discovered webapp Pod.")
    parser.add_argument("--output", default=OUTPUT_FILE)
    parser.add_argument("--interval", type=float, default=INTERVAL)
    args = parser.parse_args()
    if args.interval <= 0:
        raise ValueError("interval must be positive")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    file_exists = os.path.exists(args.output)
    if not file_exists:
        with open(args.output, "w", newline="") as file:
            csv.writer(file).writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
    print("Starting Kubernetes workload telemetry collector; dynamically discovering app=webapp.")
    pid_file = os.path.join(os.path.dirname(args.output) or ".", ".workload_collector.pid")
    try:
        with open(pid_file, "w", encoding="utf-8") as pf:
            pf.write(str(os.getpid()))
    except Exception:
        pass

    try:
        while True:
            try:
                pod_name = get_webapp_pod()
                cpu, memory = get_metrics(pod_name)
                timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                with open(args.output, "a", newline="") as file:
                    csv.writer(file).writerow([timestamp, pod_name, cpu, memory, LABEL])
                print(f"[{timestamp}] Pod={pod_name} CPU={cpu}m Memory={memory}Mi")
            except subprocess.CalledProcessError:
                print("Unable to retrieve Kubernetes information. Retrying...")
            except Exception as error:
                print(f"Error: {error}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nCollector stopped.")
    finally:
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception:
            pass


if __name__ == "__main__":
    main()
