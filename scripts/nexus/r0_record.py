#!/usr/bin/env python3
"""Bounded, serial R0 command recorder; no credentials in the environment log."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--cwd", type=Path, default=REPO)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or not args.label.replace("-", "").replace("_", "").replace(".", "").isalnum():
        parser.error("command and safe label required")
    args.report.mkdir(parents=True, exist_ok=True)
    output = args.report / f"{args.label}.log"
    argv = ["timeout", f"{args.seconds}s", *command]
    uptime = lambda: subprocess.check_output(["uptime"], text=True).strip()
    record = {"argv": argv, "cwd": str(args.cwd), "environment_names": sorted(os.environ),
              "uptime_before": uptime(), "started": time.time(), "log": str(output),
              "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "source_sha256": {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in [*(p for folder in ("scripts/nexus", "tests/support", "nexus_bridge")
                                            for p in (REPO / folder).glob("*.py")),
                                          REPO / "Cargo.toml", REPO / "tests/nexus_r0_prototypes.rs",
                                          REPO / "scripts/nexus/r0_maintenance_launch.sh"]}}
    with output.open("w") as stream:
        result = subprocess.run(argv, cwd=args.cwd, stdout=stream, stderr=subprocess.STDOUT)
    record.update(exit=result.returncode, uptime_after=uptime(), ended=time.time(),
                  log_sha256=hashlib.sha256(output.read_bytes()).hexdigest())
    with (args.report / "validation.jsonl").open("a") as stream:
        stream.write(json.dumps(record) + "\n")
    print(json.dumps({key: record[key] for key in ("argv", "exit", "uptime_before", "uptime_after", "log")}))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
