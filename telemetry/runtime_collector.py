"""Runtime process execution telemetry collector using Inspektor Gadget trace_exec."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Sequence

import psutil

OUTPUT_FILE = "telemetry/data/runtime/runtime_events.jsonl"


def resolve_gadget_executable(custom_bin: str | None = None) -> list[str]:
    """Resolve the Inspektor Gadget executable path with portability fallbacks.

    Priority:
    1. Explicit custom_bin parameter (or CLI --gadget-bin).
    2. Environment variable GADGET_BIN.
    3. Standalone executable kubectl-gadget / kubectl-gadget.exe in user ~/bin.
    4. Standalone executable kubectl-gadget on system PATH.
    5. kubectl plugin invocation ('kubectl', 'gadget') if kubectl is on PATH.
    6. Default fallback to 'kubectl-gadget'.
    """
    if custom_bin:
        resolved = shutil.which(custom_bin) or (custom_bin if os.path.exists(custom_bin) else None)
        if resolved:
            return [resolved]
        return custom_bin.split()

    env_bin = os.environ.get("GADGET_BIN")
    if env_bin:
        resolved = shutil.which(env_bin) or (env_bin if os.path.exists(env_bin) else None)
        if resolved:
            return [resolved]
        return env_bin.split()

    home_dirs = [os.path.expanduser("~")]
    user_profile = os.environ.get("USERPROFILE")
    if user_profile and user_profile not in home_dirs:
        home_dirs.append(user_profile)
    home_env = os.environ.get("HOME")
    if home_env and home_env not in home_dirs:
        home_dirs.append(home_env)

    # Check standalone binaries in ~/bin
    for h in home_dirs:
        for name in ("kubectl-gadget.exe", "kubectl-gadget"):
            cand = os.path.join(h, "bin", name)
            if os.path.isfile(cand):
                return [cand]

    # Check standalone binaries on system PATH
    for name in ("kubectl-gadget.exe", "kubectl-gadget"):
        found = shutil.which(name)
        if found:
            return [found]

    # Check kubectl plugin fallback
    if shutil.which("kubectl"):
        return ["kubectl", "gadget"]

    return ["kubectl-gadget.exe" if os.name == "nt" else "kubectl-gadget"]


def check_and_acquire_pid(pid_file: str) -> None:
    """Safely check candidate PID files, purge stale PIDs, and register current PID.

    Refuses execution if a live collector is already running. Never deletes a live collector's PID.
    """
    candidate_pids = [
        pid_file,
        os.path.join(os.path.dirname(pid_file) or ".", ".runtime_collector.pid"),
    ]
    default_runtime_dir = os.path.abspath(os.path.join("telemetry", "data", "runtime"))
    default_data_dir = os.path.abspath(os.path.join("telemetry", "data"))
    pid_dir = os.path.abspath(os.path.dirname(pid_file) or ".")
    if pid_dir in (default_runtime_dir, default_data_dir):
        candidate_pids.extend([
            os.path.join("telemetry", "data", "runtime", ".runtime_collector.pid"),
            os.path.join("telemetry", "data", ".runtime_collector.pid"),
        ])
    seen: set[str] = set()

    for c_path in candidate_pids:
        norm = os.path.abspath(c_path)
        if norm in seen:
            continue
        seen.add(norm)

        if not os.path.exists(norm):
            continue

        try:
            with open(norm, "r", encoding="utf-8") as pf:
                content = pf.read().strip()
            if content:
                existing_pid = int(content)
                if psutil.pid_exists(existing_pid):
                    print(
                        f"Error: Runtime collector already running with PID {existing_pid}. "
                        "Refusing to start duplicate collector."
                    )
                    sys.exit(1)
                else:
                    print(
                        f"Stale PID file detected at {c_path} (PID {existing_pid} is not running). "
                        "Safely cleaning up stale file."
                    )
                    try:
                        os.remove(norm)
                    except OSError:
                        pass
        except (ValueError, OSError) as exc:
            print(f"Warning: Corrupt or unreadable PID file at {c_path}: {exc}. Overwriting.")

    try:
        with open(pid_file, "w", encoding="utf-8") as pf:
            pf.write(str(os.getpid()))
    except OSError as exc:
        print(f"Warning: Could not write PID file {pid_file}: {exc}")


def release_pid(pid_file: str) -> None:
    """Safely remove the PID file only if it still belongs to this process."""
    try:
        if os.path.exists(pid_file):
            with open(pid_file, "r", encoding="utf-8") as pf:
                content = pf.read().strip()
            if content and int(content) == os.getpid():
                os.remove(pid_file)
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Inspektor Gadget runtime process exec telemetry for app=webapp."
    )
    parser.add_argument("--output", default=OUTPUT_FILE, help="Output JSONL file path.")
    parser.add_argument("--namespace", default="default", help="Kubernetes namespace.")
    parser.add_argument("--selector", default="app=webapp", help="Kubernetes pod label selector.")
    parser.add_argument("--gadget-version", default="v0.55.1", help="Inspektor Gadget image/trace version.")
    parser.add_argument(
        "--gadget-bin",
        default=None,
        help="Custom path or command for the Inspektor Gadget executable.",
    )
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    gadget_dir = os.path.join(os.path.expanduser("~"), "bin")
    env = os.environ.copy()
    env["PATH"] = gadget_dir + os.pathsep + env.get("PATH", "")

    pid_file = os.path.join(os.path.dirname(args.output) or ".", ".runtime_collector.pid")
    check_and_acquire_pid(pid_file)

    gadget_cmd = resolve_gadget_executable(args.gadget_bin)
    full_command = gadget_cmd + [
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

    print(f"Starting Kubernetes runtime process telemetry collector for {args.selector} in {args.namespace}...", flush=True)
    print(f"Using Gadget binary: {' '.join(gadget_cmd)}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)

    process: subprocess.Popen[str] | None = None
    try:
        with open(args.output, "a", encoding="utf-8") as file:
            try:
                process = subprocess.Popen(
                    full_command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError as exc:
                print(f"Error: Gadget executable not found: {exc}")
                print(f"Command attempted: {' '.join(full_command)}")
                print("Please install Inspektor Gadget in ~/bin or provide --gadget-bin.")
                sys.exit(1)
            except OSError as exc:
                print(f"Error launching Gadget subprocess: {exc}")
                sys.exit(1)

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

                        print(f"[{ts}] POD: {pod} | EXEC: {user} ran '{comm}' (PID: {pid}, Parent: {parent})", flush=True)
                    except json.JSONDecodeError:
                        print(f"[Gadget] {line}", flush=True)

                retcode = process.poll()
                if retcode is not None and retcode != 0:
                    print(f"Error: Gadget process exited with code {retcode}.")

            except KeyboardInterrupt:
                print("\nStopping runtime process collector...")
                if process:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                            capture_output=True,
                            check=False,
                        )
                    else:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
    finally:
        if process and process.poll() is None:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                    check=False,
                )
            else:
                process.terminate()
        release_pid(pid_file)

    print("Runtime process collector stopped.")


if __name__ == "__main__":
    main()
