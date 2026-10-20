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
import time

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tests/support"))
from nexus_env import Environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--ipc-root", type=Path, help="short private directory for per-router Unix sockets")
    parser.add_argument("--tmp-root", type=Path, help="short alias of the prepared environment's tmp directory")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--suite", choices=("lifecycle", "contract", "concurrency", "n6", "special_inputs", "release"), default="lifecycle")
    parser.add_argument("--baseline", type=Path, help="fixed independently hashed N0 binary for N4")
    parser.add_argument("--case", choices=("E16", "E17", "E22", "E27", "E28", "E29"), help="run one case in a fresh contract environment")
    args = parser.parse_args()
    if args.case and ((args.suite == "contract" and args.case not in {"E16","E17","E22"}) or (args.suite == "release" and args.case not in {"E27","E28","E29"}) or args.suite not in {"contract","release"}):
        parser.error("--case must belong to the selected contract/release suite")
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
        if not patch_status["applied"] or not patch_status["close_applied"]:
            parser.error("client cancellation and close proof patches required; BLOCKED")
        variables = env.variables()
        ida_version = env.manifest.get("installed_ida_version", "9.5")
        needs_baseline = args.suite in {"concurrency", "n6"} or (args.suite == "contract" and (not args.case or (args.case == "E22" and ida_version == "9.5"))) or (args.suite == "release" and args.case not in {"E27","E29"})
        if needs_baseline and ida_version != "9.5":
            blocked = {"status": "BLOCKED", "reason": "N0 baseline links IDA 9.5; cross-version output comparison is invalid", "actual_tests": 0}
            (env.root / f"{args.suite}-result.json").write_text(json.dumps(blocked, indent=2)+"\n")
            parser.exit(1, "BLOCKED: " + blocked["reason"] + "\n")
        if args.suite == 'release':
            from compare_nexus_baseline import BASELINE_SHA, digest
            if args.baseline is None or not args.baseline.is_file() or digest(args.baseline) != BASELINE_SHA:
                blocked = {'status':'BLOCKED','actual_tests':0,'reason':'release requires the fixed N0 --baseline and its SHA256'}
                (env.root/'release-result.json').write_text(json.dumps(blocked,indent=2)+'\n')
                parser.exit(1, 'BLOCKED: '+blocked['reason']+'\n')
            copied = env.root/'n0-baseline'
            shutil.copyfile(args.baseline, copied)
            copied.chmod(0o700)
            assert digest(copied) == BASELINE_SHA
            args.baseline = copied
            release_binary = args.target.resolve(strict=True)/'release/ida-cli'
            if not release_binary.is_file():
                parser.exit(1, 'BLOCKED: build target/release/ida-cli first\n')
            variables['N9_RELEASE_BINARY'] = str(release_binary)
        for name in ("CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"):
            if os.environ.get(name):
                variables[name] = os.environ[name]
        if args.tmp_root:
            if args.tmp_root.resolve(strict=True) != env.root / "tmp":
                parser.error("--tmp-root must resolve to this environment's tmp directory")
            variables["TMPDIR"] = str(args.tmp_root.absolute())
        cargo_path = shutil.which("cargo")
        if cargo_path is None or not args.target.is_dir():
            parser.exit(1, "BLOCKED: cargo or target directory missing\n")
        ipc_root = (args.ipc_root or env.root / "ipc").absolute()
        if len(str(ipc_root).encode()) > 65:
            parser.exit(1, "BLOCKED: provide a shorter --ipc-root for Unix sockets\n")
        cargo = Path(cargo_path).absolute()
        variables.update({"PATH": str(cargo.parent) + os.pathsep + variables["PATH"],
                          "CARGO_TARGET_DIR": str(args.target.resolve(strict=True)),
                          "IDA_TEST": "1", "RUSTC_WRAPPER": "", "N3_ENV_ROOT": str(env.root),
                          "N3_IPC_ROOT": str(ipc_root)})
        if args.suite in {"concurrency", "n6", "special_inputs"}:
            variables.update({
                "IDA_NEXUS_PYTHON": str(env.root / "venv/bin/python"),
                "IDA_NEXUS_IPC_ROOT": str(ipc_root),
                "IDA_NEXUS_BRIDGE_SCRIPT": str(REPO / "tests/support/nexus_client_fixture.py")})
        if args.suite == "special_inputs":
            variables["IDA_NEXUS_GC_GRACE_MS"] = "0"
        if needs_baseline:
            if args.baseline is None or not args.baseline.is_file():
                blocked = {'status':'BLOCKED','actual_tests':0,'reason':'selected suite/case requires fixed N0 --baseline (IDA 9.5)'}
                (env.root/f'{args.suite}-result.json').write_text(json.dumps(blocked,indent=2)+'\n')
                parser.exit(1, 'BLOCKED: '+blocked['reason']+'\n')
            variables["N4_BASELINE"] = str(args.baseline.resolve(strict=True))
        if args.baseline is not None:
            variables["N4_BASELINE"] = str(args.baseline.resolve(strict=True))
        Path(variables["N3_IPC_ROOT"]).mkdir(mode=0o700, exist_ok=True)
        (env.root / "ipc-root.json").write_text(json.dumps(str(ipc_root)))
        native_ledger = env.root / 'native-processes.jsonl'
        native_ledger.touch(mode=0o600, exist_ok=True)
        variables['R2_LEDGER'] = str(native_ledger)
        (env.root / "rust-env.json").write_text(json.dumps(variables, indent=2) + "\n")
        suite_timeout = "300s" if args.suite == "special_inputs" else "180s"
        command = ["timeout", suite_timeout, str(cargo), "test", "--locked", "--features", "nexus-test-support", "--test", f"nexus_{args.suite}_e2e", "--", "--test-threads=1"]
        if args.case and args.suite == "contract":
            command.insert(command.index("--"), {"E16":"e16_cli_stdio_http_and_independent_close_token", "E17":"e17_unicode_streams_errors_and_response_cache", "E22":"e22_old_cache_proof_preserves_edits_and_warm_lease"}[args.case])
            command.append("--exact")
        commands = [command]
        if args.suite == 'release':
            names = {'E27':'e27_shutdown_and_same_product_restart', 'E28':'e28_version_rollback_from_private_backup', 'E29':'e29_unique_backend_installed_release'}
            commands=[]
            for case in ([args.case] if args.case else names):
                exact=command.copy()
                exact.insert(exact.index('--'),names[case]);exact.append('--exact')
                commands.append(exact)
        if args.suite == "n6":
            # Each real case keeps its own 180s shell bound. Four complete
            # exact terminals replace a single aggregate timeout around them.
            functions = ("n6_e04_all_write_and_advanced_methods",
                "n6_e20_cancelled_write_retains_first_slice_without_replay",
                "n6_e20_seven_categories_survive_save_close_reopen",
                "n6_tools_and_aliases_preserve_mcp_contract")
            commands = []
            for function in functions:
                exact = command.copy()
                exact.insert(exact.index("--"), function)
                exact.append("--exact")
                commands.append(exact)
        result = {"status":"FAIL", "commands":commands, "client_cancel_patch":patch_status}
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
            terminals = []
            with (env.root / f"{args.suite}.log").open("w") as output:
                for selected in commands:
                    started = time.time()
                    before = subprocess.check_output(["timeout", "5s", "uptime"], text=True).strip()
                    child = env.spawn(lambda: subprocess.Popen(selected, cwd=REPO, env=variables,
                        stdout=output, stderr=subprocess.STDOUT), selected)
                    code = child.wait()
                    terminal = {"argv":selected, "started":started, "ended":time.time(), "exit":code,
                        "uptime_before":before,
                        "uptime_after":subprocess.check_output(["timeout", "5s", "uptime"], text=True).strip()}
                    terminals.append(terminal)
                    with (env.root/f"{args.suite}-commands.jsonl").open("a") as ledger:
                        ledger.write(json.dumps(terminal)+"\n")
            result["child_results"] = terminals
            result["exit"] = next((row["exit"] for row in terminals if row["exit"]), 0)
            text = (env.root / f"{args.suite}.log").read_text()
            summary = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
            if result["exit"] and re.search(r"license.*(?:invalid|failed|not found|unavailable|expired)|no valid license", text, re.IGNORECASE):
                result["status"] = "BLOCKED"
            if args.suite == 'release':
                expected = [args.case] if args.case else ['E27','E28','E29']
                events = [json.loads((env.root/f'{case}-result.json').read_text()) for case in expected if (env.root/f'{case}-result.json').is_file()]
                result.update(actual_tests=len(terminals), case_results=events,
                    cases=[row['case'] for row in events if row['status']=='PASS'])
                if any(row['status']=='BLOCKED' for row in events):result['status']='BLOCKED'
            assert result["exit"] == 0, f"{result['status']}: suite command failed: {result['exit']}"
            count = 1 if args.case else {"lifecycle": 9, "contract": 4, "concurrency": 14, "n6": 4, "special_inputs": 8, "release":3}[args.suite]
            expected_summary = [("1", "0", "0")]*4 if args.suite == "n6" else ([("1","0","0")]*count if args.suite == "release" else [(str(count), "0", "0")])
            assert summary == expected_summary, f"wrong actual test count: {summary}"
            if args.suite == "release":
                cases = result["cases"]
            elif args.suite == "lifecycle":
                events = [json.loads(line) for line in (env.root / "rust-evidence.jsonl").read_text().splitlines()]
                cases = [event["case"] for event in events if event.get("status") == "PASS"]
                expected = ["E02", "E03", "E05", "E06-client", "E06-bridge", "E07-packed", "E07-unpacked", "E05-concurrent-open", "E06-lease-fault"]
            elif args.suite == "contract":
                expected = [args.case] if args.case else ["E04", "E16", "E17", "E22"]
                events = [json.loads((env.root/f"{case}-result.json").read_text()) for case in expected]
                cases = [event["case"] for event in events if event["status"] == "PASS"]
            elif args.suite == "special_inputs":
                expected = ["E19", "E21-held", "E21-before-rename", "E21-after-rename", "E21-before-delete", "E21-release", "E21-lock", "F3-cold"]
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
            from verify_nexus_gui import capture_ready
            capture_ready(env)
            env.assert_clean()
            assert not list((env.root / "state/instances").glob("*.json")), "Nexus registrations remain"
            result.update({"status":"PASS", "actual_tests":count, "cases":cases})
        finally:
            from verify_nexus_gui import capture_native_processes, capture_ready
            cleanup_error = None
            try:
                if args.suite == 'release':
                    for case in ('E27','E28','E29'):
                        directory=env.root/case
                        if not directory.exists():continue
                        owned=Environment(env.root)
                        owned.ledger=directory/'processes.jsonl'
                        owned.intents=directory/'process-intents'
                        capture_native_processes(owned,directory/'native-processes.jsonl')
                        owned.cleanup()
                        owned.assert_clean()
                capture_ready(env)
            except Exception as error:
                cleanup_error = error
                result.update(status='FAIL', native_capture_error=str(error))
            try:
                result["cleanup_signalled_pids"] = env.cleanup()
                env.assert_clean()
            except Exception as error:
                cleanup_error = error
                result.update(status='FAIL', cleanup_error=str(error))
            result["owned_processes"] = len(env.entries())
            sockets = [str(path) for path in ipc_root.rglob("*") if stat.S_ISSOCK(path.lstat().st_mode)]
            result["residual_sockets"] = sockets
            (env.root / f"{args.suite}-result.json").write_text(json.dumps(result, indent=2) + "\n")
            if cleanup_error is not None:
                raise cleanup_error
            assert not sockets, f"owned IPC socket files remain: {sockets}"
        print(json.dumps(result))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
