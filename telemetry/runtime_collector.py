import argparse
import json
import os
import subprocess
import sys

OUTPUT_FILE = "telemetry/data/runtime/runtime_events.jsonl"


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect Inspektor Gadget runtime process exec telemetry for app=webapp.")
    parser.add_argument("--output", default=OUTPUT_FILE)
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--selector", default="app=webapp")
    parser.add_argument("--gadget-version", default="v0.55.1")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    gadget_dir = os.path.join(os.path.expanduser("~"), "bin")
    env = os.environ.copy()
    env["PATH"] = gadget_dir + os.pathsep + env.get("PATH", "")

    command = [
        "kubectl",
        "gadget",
        "run",
        f"trace_exec:{args.gadget_version}",
        "-n",
        args.namespace,
        "-l",
        args.selector,
        "--paths",
        "--output",
        "json",
    ]
    print(f"Starting Kubernetes runtime process telemetry collector for {args.selector} in {args.namespace}...")
    print("Press Ctrl+C to stop.")

    pid_file = os.path.join(os.path.dirname(args.output) or ".", ".runtime_collector.pid")
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

                        ts = event.get("timestamp", "?")
                        pod = event.get("k8s", {}).get("podName", "?")
                        proc = event.get("proc", {})
                        comm = proc.get("comm") or event.get("args") or event.get("exepath") or "?"
                        pid = proc.get("pid", "?")
                        creds = proc.get("creds", {})
                        user = creds.get("user") or str(creds.get("uid", "?"))
                        parent = proc.get("parent", {}).get("comm", "?")

                        print(f"[{ts}] POD: {pod} | EXEC: {user} ran '{comm}' (PID: {pid}, Parent: {parent})")
                    except json.JSONDecodeError:
                        print(f"[Gadget] {line}")

            except KeyboardInterrupt:
                print("\nStopping runtime process collector...")
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

    print("Runtime process collector stopped.")


if __name__ == "__main__":
    main()
