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
import stat
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
    parser.add_argument("--tmp-root", type=Path, help="short alias of the prepared environment's tmp directory")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--suite", choices=("lifecycle", "contract", "concurrency", "n6"), default="lifecycle")
    parser.add_argument("--baseline", type=Path, help="fixed independently hashed N0 binary for N4")
    parser.add_argument("--case", choices=("E22",), help="run only E22 in a fresh contract environment")
    args = parser.parse_args()
    if args.case and args.suite != "contract":
        parser.error("--case requires --suite contract")
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
        if args.tmp_root:
            if args.tmp_root.resolve(strict=True) != env.root / "tmp":
                parser.error("--tmp-root must resolve to this environment's tmp directory")
            variables["TMPDIR"] = str(args.tmp_root.absolute())
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
        if args.suite in {"concurrency", "n6"}:
            variables.update({"IDA_CLI_NEXUS_DEV": "1",
                "IDA_NEXUS_PYTHON": str(env.root / "venv/bin/python"),
                "IDA_NEXUS_IPC_ROOT": str(ipc_root),
                "IDA_NEXUS_BRIDGE_SCRIPT": str(REPO / "tests/support/nexus_client_fixture.py")})
        if args.suite in {"contract", "concurrency", "n6"}:
            if args.baseline is None or not args.baseline.is_file():
                parser.error("contract suite requires --baseline")
            variables["N4_BASELINE"] = str(args.baseline.resolve(strict=True))
        Path(variables["N3_IPC_ROOT"]).mkdir(mode=0o700, exist_ok=True)
        (env.root / "ipc-root.json").write_text(json.dumps(str(ipc_root)))
        (env.root / "rust-env.json").write_text(json.dumps(variables, indent=2) + "\n")
        command = ["timeout", "180s", str(cargo), "test", "--locked", "--test", f"nexus_{args.suite}_e2e", "--", "--test-threads=1"]
        if args.case:
            command.insert(command.index("--"), "e22_old_cache_proof_preserves_edits_and_warm_lease")
        result = {"status":"FAIL", "command":command, "client_cancel_patch":patch_status}
        def interrupted(sig, _frame):
            raise InterruptedError(f"suite interrupted by signal {sig}")
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, interrupted)
        try:
            if args.suite == "concurrency":
                native_command = ["timeout", "30s", "/usr/bin/cc", "-dynamiclib",
                    str(REPO / "tests/support/n5_hold.c"), "-o",
                    str(env.root / "fixtures/n5_hold.dylib")]
                with (env.root / "native-fixture.log").open("w") as output:
                    native = env.spawn(lambda: subprocess.Popen(native_command, cwd=REPO,
                        env=variables, stdout=output, stderr=subprocess.STDOUT), native_command)
                    result["native_fixture_exit"] = native.wait()
                assert result["native_fixture_exit"] == 0, "native fixture compilation failed"
                result["native_fixture_command"] = native_command
            with (env.root / f"{args.suite}.log").open("w") as output:
                child = env.spawn(lambda: subprocess.Popen(command, cwd=REPO, env=variables, stdout=output, stderr=subprocess.STDOUT), command)
                result["exit"] = child.wait()
            text = (env.root / f"{args.suite}.log").read_text()
            summary = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
            if child.returncode and re.search(r"license.*(?:invalid|failed|not found|unavailable|expired)|no valid license", text, re.IGNORECASE):
                result["status"] = "BLOCKED"
            assert child.returncode == 0, f"{result['status']}: lifecycle command failed: {child.returncode}"
            count = 1 if args.case else {"lifecycle": 9, "contract": 4, "concurrency": 14, "n6": 4}[args.suite]
            assert summary == [(str(count), "0", "0")], f"wrong actual test count: {summary}"
            if args.suite == "lifecycle":
                events = [json.loads(line) for line in (env.root / "rust-evidence.jsonl").read_text().splitlines()]
                cases = [event["case"] for event in events if event.get("status") == "PASS"]
                expected = ["E02", "E03", "E05", "E06-client", "E06-bridge", "E07-packed", "E07-unpacked", "E05-concurrent-open", "E06-lease-fault"]
            elif args.suite == "contract":
                expected = [args.case] if args.case else ["E04", "E16", "E17", "E22"]
                events = [json.loads((env.root/f"{case}-result.json").read_text()) for case in expected]
                cases = [event["case"] for event in events if event["status"] == "PASS"]
            elif args.suite == "n6":
                expected = ["E04-N6", "E20", "N6-tools", "E20-cancel"]
                events = [json.loads((env.root/f"{case}-result.json").read_text()) for case in expected[:-1]]
                events += [event for event in map(json.loads, (env.root/"rust-evidence.jsonl").read_text().splitlines())
                           if event.get("case") == "E20-cancel"]
                cases = [event["case"] for event in events if event["status"] == "PASS"]
            else:
                events = [json.loads(line) for line in (env.root / "rust-evidence.jsonl").read_text().splitlines()]
                expected = ["E08", "E09", "E10", "E11", "E12", "E13", "E14", "E15", "E18", "E26", "N5-hooks", "N5-lifecycle", "N5-reconnect", "N5-compare"]
                cases = [event["case"] for event in events if event.get("status") == "PASS"]
            assert sorted(cases) == sorted(expected), f"wrong scenario evidence: {cases}"
            env.assert_clean()
            assert not list((env.root / "state/instances").glob("*.json")), "Nexus registrations remain"
            result.update({"status":"PASS", "actual_tests":count, "cases":cases})
        finally:
            result["cleanup_signalled_pids"] = env.cleanup()
            env.assert_clean()
            result["owned_processes"] = len(env.entries())
            sockets = [str(path) for path in ipc_root.rglob("*") if stat.S_ISSOCK(path.lstat().st_mode)]
            result["residual_sockets"] = sockets
            (env.root / f"{args.suite}-result.json").write_text(json.dumps(result, indent=2) + "\n")
            assert not sockets, f"owned IPC socket files remain: {sockets}"
        print(json.dumps(result))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
