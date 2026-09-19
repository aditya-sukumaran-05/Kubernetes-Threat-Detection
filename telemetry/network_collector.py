import subprocess
import json
import os

OUTPUT_FILE = "telemetry/data/network/network_events.jsonl"

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

command = [
    "kubectl",
    "gadget",
    "run",
    "trace_tcp:v0.55.1",
    "-n",
    "default",
    "-l",
    "app=webapp",
    "--output",
    "json"
]

print("Starting Kubernetes network telemetry collector...")
print("Target: webapp")
print("Press Ctrl+C to stop.\n")

with open(OUTPUT_FILE, "a", encoding="utf-8") as file:

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    try:
        for line in process.stdout:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

                file.write(json.dumps(event) + "\n")
                file.flush()

                print(
                    f"[{event.get('timestamp', '?')}] "
                    f"{event.get('type', '?')} | "
                    f"{event.get('src', {}).get('addr', '?')}:"
                    f"{event.get('src', {}).get('port', '?')} -> "
                    f"{event.get('dst', {}).get('addr', '?')}:"
                    f"{event.get('dst', {}).get('port', '?')}"
                )

            except json.JSONDecodeError:
                print(f"[Gadget] {line}")

    except KeyboardInterrupt:
        print("\nStopping network collector...")
        process.terminate()
        process.wait()

print("Network collector stopped.")