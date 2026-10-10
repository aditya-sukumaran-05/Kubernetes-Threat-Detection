import argparse
import json
import os
import subprocess
import sys

import psutil

OUTPUT_FILE = "telemetry/data/network/network_events.jsonl"


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect Inspektor Gadget TCP telemetry for app=webapp.")
    parser.add_argument("--output", default=OUTPUT_FILE)
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--selector", default="app=webapp")
    parser.add_argument("--gadget-version", default="v0.55.1")
    args = parser.parse_args()
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    candidate_pids = [
        os.path.join(os.path.dirname(args.output) or ".", ".network_collector.pid"),
        os.path.join("telemetry", "data", ".network_collector.pid"),
    ]
    for c_pid_file in candidate_pids:
        if os.path.exists(c_pid_file):
            try:
                with open(c_pid_file, "r", encoding="utf-8") as pf:
                    content = pf.read().strip()
                    if content:
                        existing_pid = int(content)
                        if psutil.pid_exists(existing_pid):
                            print(f"Error: Network collector already running with PID {existing_pid}. Refusing to start duplicate collector.")
                            sys.exit(1)
            except (ValueError, OSError):
                pass
    pid_file = candidate_pids[0]

    gadget_dir = os.path.join(os.path.expanduser("~"), "bin")
    env = os.environ.copy()
    env["PATH"] = gadget_dir + os.pathsep + env.get("PATH", "")

    command = [
        "kubectl",
        "gadget",
        "run",
        f"trace_tcp:{args.gadget_version}",
        "-n",
        args.namespace,
        "-l",
        args.selector,
        "--output",
        "json",
    ]
    print("Starting Kubernetes network telemetry collector. Press Ctrl+C to stop.")
    try:
        with open(pid_file, "w", encoding="utf-8") as pf:
            pf.write(str(os.getpid()))
    except Exception:
        pass

    try:
        with open(args.output, "a", encoding="utf-8") as file:

            process = subprocess.Popen(
                command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            try:
                assert process.stdout is not None
                for line in process.stdout:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        event = json.loads(line)

                        file.write(json.dumps(event) + "\n")
                        file.flush()

                        print(f"[{event.get('timestamp', '?')}] {event.get('type', '?')} | {event.get('src', {}).get('addr', '?')}:{event.get('src', {}).get('port', '?')} -> {event.get('dst', {}).get('addr', '?')}:{event.get('dst', {}).get('port', '?')}")

                    except json.JSONDecodeError:
                        print(f"[Gadget] {line}")

            except KeyboardInterrupt:
                print("\nStopping network collector...")
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
                else:
                    process.terminate()
                    process.wait()
    finally:
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception:
            pass

    print("Network collector stopped.")

if __name__ == "__main__":
    main()
