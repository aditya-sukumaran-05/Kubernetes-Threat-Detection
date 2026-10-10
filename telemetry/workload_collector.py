import argparse
import csv
from datetime import datetime, timezone
import os
import random
import subprocess
import sys
import time

import psutil

OUTPUT_FILE = "telemetry/data/workload_metrics.csv"
LABEL = "normal"
INTERVAL = 5
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_BACKOFF = 0.5
DEFAULT_MAX_BACKOFF = 2.0
DEFAULT_JITTER = 0.2


class MetricsCollectionError(RuntimeError):
    """Raised when Metrics Server fails or returns invalid telemetry after retries are exhausted."""
    pass


def get_webapp_pod(
    namespace: str = "default",
    selector: str = "app=webapp",
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_backoff: float = DEFAULT_BASE_BACKOFF,
    max_backoff: float = DEFAULT_MAX_BACKOFF,
    jitter: float = DEFAULT_JITTER,
) -> str:
    """Discover webapp Pod name using label selector with bounded retries."""
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    namespace,
                    "-l",
                    selector,
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            pod_name = result.stdout.strip()
            if not pod_name:
                raise RuntimeError(f"No pod found matching selector '{selector}' in namespace '{namespace}'.")
            return pod_name
        except (subprocess.CalledProcessError, RuntimeError) as err:
            last_error = err
            if attempt < max_retries:
                backoff = min(max_backoff, base_backoff * (2 ** attempt)) + random.uniform(0, jitter)
                time.sleep(backoff)
            else:
                break

    raise RuntimeError(
        f"Failed to discover webapp pod matching '{selector}' after {max_retries + 1} attempts: {last_error}"
    ) from last_error


def get_metrics(
    pod_name: str,
    namespace: str = "default",
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_backoff: float = DEFAULT_BASE_BACKOFF,
    max_backoff: float = DEFAULT_MAX_BACKOFF,
    jitter: float = DEFAULT_JITTER,
) -> tuple[str, str]:
    """Retrieve pod CPU (millicores) and Memory (MiB) with bounded retries, exponential backoff, and jitter.

    Transient Metrics Server failures (e.g. reconciling or momentarily unavailable)
    are retried up to max_retries times. Persistent failures raise MetricsCollectionError.
    """
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "top",
                    "pod",
                    pod_name,
                    "-n",
                    namespace,
                    "--no-headers",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            parts = result.stdout.strip().split()
            if len(parts) < 3:
                raise RuntimeError(f"Invalid metrics output format: '{result.stdout.strip()}'")

            cpu = parts[1].replace("m", "")
            memory = parts[2].replace("Mi", "")
            return cpu, memory
        except (subprocess.CalledProcessError, RuntimeError) as err:
            last_error = err
            if attempt < max_retries:
                backoff = min(max_backoff, base_backoff * (2 ** attempt)) + random.uniform(0, jitter)
                time.sleep(backoff)
            else:
                break

    raise MetricsCollectionError(
        f"Metrics Server call failed for pod '{pod_name}' after {max_retries + 1} attempts: {last_error}"
    ) from last_error


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect workload telemetry from the dynamically discovered webapp Pod.")
    parser.add_argument("--output", default=OUTPUT_FILE)
    parser.add_argument("--interval", type=float, default=INTERVAL)
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--selector", default="app=webapp")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--base-backoff", type=float, default=DEFAULT_BASE_BACKOFF)
    args = parser.parse_args()
    if args.interval <= 0:
        raise ValueError("interval must be positive")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    file_exists = os.path.exists(args.output)
    if not file_exists:
        with open(args.output, "w", newline="") as file:
            csv.writer(file).writerow(["timestamp", "pod", "cpu_millicores", "memory_mib", "label"])
    print("Starting Kubernetes workload telemetry collector; dynamically discovering app=webapp.")
    candidate_pids = [
        os.path.join(os.path.dirname(args.output) or ".", ".workload_collector.pid"),
        os.path.join("telemetry", "data", ".workload_collector.pid"),
    ]
    for c_pid_file in candidate_pids:
        if os.path.exists(c_pid_file):
            try:
                with open(c_pid_file, "r", encoding="utf-8") as pf:
                    content = pf.read().strip()
                    if content:
                        existing_pid = int(content)
                        if psutil.pid_exists(existing_pid):
                            print(f"Error: Workload collector already running with PID {existing_pid}. Refusing to start duplicate collector.")
                            sys.exit(1)
            except (ValueError, OSError):
                pass
    pid_file = candidate_pids[0]

    try:
        with open(pid_file, "w", encoding="utf-8") as pf:
            pf.write(str(os.getpid()))
    except Exception:
        pass

    try:
        while True:
            try:
                pod_name = get_webapp_pod(
                    namespace=args.namespace,
                    selector=args.selector,
                    max_retries=args.max_retries,
                    base_backoff=args.base_backoff,
                )
                cpu, memory = get_metrics(
                    pod_name,
                    namespace=args.namespace,
                    max_retries=args.max_retries,
                    base_backoff=args.base_backoff,
                )
                timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                with open(args.output, "a", newline="") as file:
                    csv.writer(file).writerow([timestamp, pod_name, cpu, memory, LABEL])
                print(f"[{timestamp}] Pod={pod_name} CPU={cpu}m Memory={memory}Mi", flush=True)
            except MetricsCollectionError as m_err:
                print(f"Metrics collection failed after retries: {m_err}", flush=True)
            except subprocess.CalledProcessError as cpe:
                print(f"Kubernetes subprocess error: {cpe}. Retrying next sample interval...", flush=True)
            except Exception as error:
                print(f"Error during workload collection tick: {error}", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nCollector stopped.")
    finally:
        try:
            if os.path.exists(pid_file):
                with open(pid_file, "r", encoding="utf-8") as pf:
                    content = pf.read().strip()
                if content and int(content) == os.getpid():
                    os.remove(pid_file)
        except Exception:
            pass


if __name__ == "__main__":
    main()
