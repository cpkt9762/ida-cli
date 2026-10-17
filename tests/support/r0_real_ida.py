"""One private tiny IDA database, public SDK, loaded v1 code and discard flags."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

from nexus_env import Environment
from r0_common import durable

REPO = Path(__file__).resolve().parents[2]

# The same externally supplied inspector is used locally and in the real owner.
from r0_v1 import expected_snapshot, validate
VALIDATOR = Path(__file__).with_name('r0_v1.py').read_text()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=Path, required=True)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    env = Environment(args.env)
    case = args.case.resolve()
    case.mkdir(mode=0o700, parents=True)
    variables = env.variables()
    variables.update(HOME=os.environ["HOME"], IDA_CLI_HOME=str(case / "cli"),
                     IDA_NEXUS_STATE_DIR=str(case / "state"))
    os.environ.update(variables)
    sys.path.insert(0, str(args.candidate))
    sys.path.insert(0, str(REPO / "nexus_bridge"))
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions, wait_database_released
    import bridge
    calls, spawned, result = [], [], {"scope": "real-IDA-9.5-tiny-public-chain"}
    handle = None
    listener, accepted = None, []
    intent = None
    def observer(stage, value):
        nonlocal intent
        calls.append(stage)
        if stage == "LaunchIntent":
            intent = env._begin_creation(["SDK-direct-worker", value["suffix"]])
        if stage == "Spawned":
            process = value["process"]
            env.record(process, process.args, intent=intent)
            intent = None
            spawned.append(process)
    try:
        outcome = DatabaseHandle.open_outcome(str(env.root / "fixtures/mini"),
            options=DatabaseOpenOptions(output_database=str(case / "tiny.i64"),
                auto_analysis=False, startup_timeout=40, worker_env=variables,
                worker_cwd=str(case)), observer=observer)
        if outcome["cause"]:
            raise RuntimeError("public open outcome failed: " + str(outcome["cause"]))
        handle = outcome["handle"]
        result["direct_child_is_owner"] = bool(spawned and spawned[0].pid == handle.instance.pid)
        result["events"] = calls
        result["runtime"] = handle.execute_python(bridge.guarded_source(
            "import ida_kernwin\nresult=ida_kernwin.get_kernel_version()", {"method":"r0-real"}))["result"]
        # Independent same-uid process uses only discover/attach/execute/close.
        child_code = '''import json,os
from ida_nexus import DatabaseHandle,discover_databases
entry=next(x.instance for x in discover_databases() if x.instance.idb_path==os.environ['R0_TARGET'])
h=DatabaseHandle.attach(entry)
try:
 print(json.dumps({'owner_pid':h.execute_python('import os\\nresult=os.getpid()')['result'], 'close':h.close_outcome(wait_for_database=False,timeout=3)}))
finally:
 h.close_outcome(wait_for_database=False,timeout=1)
'''
        command = ["timeout", "30s", sys.executable, "-B", "-c", child_code]
        child = env.spawn(lambda: subprocess.Popen(command, env=dict(variables, R0_TARGET=handle.instance.idb_path),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), command)
        stdout, stderr = child.communicate(timeout=35)
        if child.returncode:
            raise RuntimeError("independent public client failed: " + stderr)
        independent = json.loads(stdout)
        assert independent["owner_pid"] == handle.instance.pid
        assert independent["close"]["lease_released"] and not independent["close"]["shutdown_pending"]
        result["independent_same_uid_public_entry"] = independent
        result["same_boot_eligibility"] = "Unsupported: independent same-uid public execution cannot be revoked"
        # Exercise the actual production slice installer with an empty rename.
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(case / "life"))
        listener.listen(1)
        listener.settimeout(10)
        def handshake():
            connection, _ = listener.accept()
            accepted.append(connection)
            connection.recv(256)
            connection.sendall(b"ok")
        handshake_thread = threading.Thread(target=handshake)
        handshake_thread.start()
        context = ["r0", "r0-lease", handle.instance.record_id, 1, str(case / "life")]
        code = bridge.TOOL_SOURCE + f"\nresult=invoke_slice('batch_rename', {{'renames':[], '_n5_job':'r0-job'}}, {context!r}, {bridge.SLICE_SOURCE!r})"
        result["slice"] = handle.execute_python(bridge.guarded_source(code, {"method":"r0-slice"}))["result"]
        handshake_thread.join(10)
        assert result["slice"]["ok"] and not handshake_thread.is_alive()
        loaded_code = VALIDATOR + f"\nresult=snapshot({{name:sys.modules[name] for name in NAMES}}, ida_version={result['runtime']!r})"
        loaded = handle.execute_python(loaded_code)["result"]
        expected = expected_snapshot(REPO, Path(json.loads((env.root / "environment.json").read_text())["ida_dir"]))
        durable(case / "v1-observed.json", loaded)
        durable(case / "v1-expected.json", expected)
        compatibility_key = validate(loaded, expected)
        result["loaded_v1"] = loaded
        result["v1_compatibility_key"] = compatibility_key
        result["v1_validation"] = {"comparison":"complete-equality", "passed":True,
            "validator_sha256":hashlib.sha256(VALIDATOR.encode()).hexdigest(),
            "expected_key":compatibility_key, "actual_key":compatibility_key}
        result["fingerprint_python_abi"] = list(sys.version_info[:3])
        handle.save_database()
        packed = Path(handle.instance.idb_path)
        before = hashlib.sha256(packed.read_bytes()).hexdigest()
        # Deliberate damage is restricted to this fresh disposable tiny IDB.
        handle.execute_python("import ida_netnode\nida_netnode.netnode('Root Node',0,False).kill()")
        proof = handle.execute_python("import sys,ida_loader\ng=sys.modules['_ida_cli_save_guard_v1']\n"
            "result={'status':g.close_status(),'flags':{k:ida_loader.is_database_flag(getattr(ida_loader,k)) for k in ('DBFL_TEMP','DBFL_KILL')}}")["result"]
        assert proof["status"]["close_safe"] and proof["status"]["save_guard_error"]
        assert all(proof["flags"].values())
        result["close_guard"] = proof
        result["close"] = handle.close_outcome(wait_for_database=True, timeout=20)
        assert result["close"]["lease_released"] and result["close"]["owner_released"]
        assert wait_database_released(handle.instance, timeout=0)
        result["packed_before"] = before
        result["packed_after"] = hashlib.sha256(packed.read_bytes()).hexdigest()
        assert result["packed_after"] == before
        result["unpacked_after"] = [str(p) for p in case.glob("tiny.*") if p.suffix in (".id0", ".id1", ".id2", ".nam", ".til")]
        assert not result["unpacked_after"]
        result["public_close_calls"] = 1
        for process in spawned:
            process.wait(timeout=5)
        handle = None
    finally:
        if handle is not None:
            # Failure cleanup uses only this exact fresh worker's SDK handle.
            handle.close_outcome(wait_for_database=True, timeout=5)
        for connection in accepted:
            connection.close()
        if listener is not None:
            listener.close()
            (case / "life").unlink(missing_ok=True)
        result["forced_cleanup_pids"] = env.cleanup()
        env.assert_clean()
        result["remaining_registry"] = [str(p) for p in (case / "state/instances").glob("*.json")]
        assert not result["remaining_registry"]
        durable(case / "result.json", result)
    print(json.dumps({"result":str(case / "result.json"), "runtime":result["runtime"], "audit":"clean"}))


if __name__ == "__main__":
    main()
