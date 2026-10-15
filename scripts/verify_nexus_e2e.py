#!/usr/bin/env python3
"""N3 real lifecycle suite, exact counts, isolated environment and owned cleanup."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tests/support"))
from nexus_env import Environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--ipc-root", type=Path, help="short private directory for per-router Unix sockets")
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    try:
        env = Environment(args.root)
    except (OSError, ValueError) as error:
        parser.exit(1, f"BLOCKED: {error}\n")
    with env.exclusive():
        if args.cleanup:
            print(json.dumps({"cleanup_signalled": env.cleanup()}))
            env.assert_clean()
            return 0
        if not (env.root / "fixtures/mini").is_file() or not Path(env.manifest["ida_dir"]).is_dir():
            parser.exit(1, "BLOCKED: IDA installation or test sample missing\n")
        if env.ledger.exists():
            parser.error("use a fresh prepared environment")
        patch_status = env.client_patch_status()
        if not patch_status["applied"]:
            parser.error("client cancellation patch required; BLOCKED")
        variables = env.variables()
        cargo_path = shutil.which("cargo")
        if cargo_path is None or not args.sdk.is_dir() or not args.target.is_dir():
            parser.exit(1, "BLOCKED: cargo, SDK or target directory missing\n")
        ipc_root = (args.ipc_root or env.root / "ipc").absolute()
        if len(str(ipc_root).encode()) > 65:
            parser.exit(1, "BLOCKED: provide a shorter --ipc-root for Unix sockets\n")
        cargo = Path(cargo_path).absolute()
        variables.update({"PATH": str(cargo.parent) + os.pathsep + variables["PATH"],
                          "IDASDKDIR": str(args.sdk.resolve(strict=True)),
                          "CARGO_TARGET_DIR": str(args.target.resolve(strict=True)),
                          "IDA_TEST": "1", "RUSTC_WRAPPER": "", "N3_ENV_ROOT": str(env.root),
                          "N3_IPC_ROOT": str(ipc_root)})
        Path(variables["N3_IPC_ROOT"]).mkdir(mode=0o700, exist_ok=True)
        (env.root / "rust-env.json").write_text(json.dumps(variables, indent=2) + "\n")
        command = ["timeout", "180s", str(cargo), "test", "--locked", "--test", "nexus_lifecycle_e2e", "--", "--test-threads=1"]
        result = {"status":"FAIL", "command":command, "client_cancel_patch":patch_status}
        def interrupted(sig, _frame):
            raise InterruptedError(f"suite interrupted by signal {sig}")
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, interrupted)
        try:
            with (env.root / "lifecycle.log").open("w") as output:
                child = env.spawn(lambda: subprocess.Popen(command, cwd=REPO, env=variables, stdout=output, stderr=subprocess.STDOUT), command)
                result["exit"] = child.wait()
            text = (env.root / "lifecycle.log").read_text()
            summary = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
            if child.returncode and re.search(r"license.*(?:invalid|failed|not found|unavailable|expired)|no valid license", text, re.IGNORECASE):
                result["status"] = "BLOCKED"
            assert child.returncode == 0, f"{result['status']}: lifecycle command failed: {child.returncode}"
            assert summary == [("7", "0", "0")], f"wrong actual test count: {summary}"
            events = [json.loads(line) for line in (env.root / "rust-evidence.jsonl").read_text().splitlines()]
            cases = [event["case"] for event in events if event.get("status") == "PASS"]
            expected = ["E02", "E03", "E05", "E06-client", "E06-bridge", "E07-packed", "E07-unpacked"]
            assert sorted(cases) == sorted(expected), f"wrong scenario evidence: {cases}"
            env.assert_clean()
            assert not list((env.root / "state/instances").glob("*.json")), "Nexus registrations remain"
            result.update({"status":"PASS", "actual_tests":7, "cases":cases})
        finally:
            result["cleanup_signalled_pids"] = env.cleanup()
            env.assert_clean()
            result["owned_processes"] = len(env.entries())
            (env.root / "lifecycle-result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
