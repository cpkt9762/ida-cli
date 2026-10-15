"""Verify precise public cancellation after transport failure; unpatched red exits 2.

This diagnostic is not a bridge or an E02/E03/E05/E06/E07 acceptance suite.
Only the standard-library response connection is faulted. The N0 spawn hook
records test-owned process identities; it does not alter cancellation behavior.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]


def wait_for(path, timeout=5):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"barrier did not arrive: {path.name}")
        threading.Event().wait(0.01)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expect-unpatched", action="store_true", help="fresh red control only")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(REPO / "scripts"))
    from verify_nexus_n0 import Environment, owned_nexus_spawn
    env = Environment(args.root)
    if env.root.is_relative_to(REPO) or REPO.is_relative_to(env.root):
        parser.error("use a fresh prepared environment outside the repository")
    if not (env.root / "profile/.n0-isolated-profile").is_file():
        parser.error("an isolated N0 profile is required")
    if env.ledger.exists() or (env.root / "cancel-gap.json").exists():
        parser.error("refusing a used environment; prepare another fresh root")
    if Path(sys.executable).parent.resolve() != env.root / "venv/bin":
        parser.error("run with the prepared environment's venv/bin/python")
    os.environ.clear()
    os.environ.update(env.variables())
    from ida_nexus import (DatabaseHandle, DatabaseOpenOptions, NexusConnectionError,
                           RemoteError, discover_databases, wait_database_released)
    from ida_nexus import _resolver
    import ida_nexus.handle as handle_module
    assert Path(handle_module.__file__).resolve().is_relative_to(env.root / "venv")
    assert not {"idapro", "ida_kernwin", "ida_domain"}.intersection(sys.modules)
    original_spawn = _resolver.spawn_worker
    def spawn(*args, **kwargs):
        return owned_nexus_spawn(env, original_spawn, *args, **kwargs)
    def resolve(*args, **kwargs):
        return _resolver.resolve_instance(*args, **kwargs, spawner=spawn)
    def interrupted(sig, _frame):
        raise InterruptedError(f"probe interrupted by signal {sig}")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    handles = []
    futures = []
    gates = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="probe-execute")
    evidence = {"status": "FAIL", "actual_probes": 0}
    evidence["client_cancel_patch"] = env.client_patch_status()
    assert evidence["client_cancel_patch"]["applied"] != args.expect_unpatched
    def program(label):
        started = env.root / f"{label}.started"
        continued = env.root / f"{label}.continued"
        observe = env.root / f"{label}.observe"
        release = env.root / f"{label}.release"
        gates.append(release)
        code = ("from pathlib import Path\nimport time\n"
                f"Path({str(started)!r}).touch()\n"
                f"while not Path({str(observe)!r}).exists():\n    time.sleep(0.01)\n"
                f"Path({str(continued)!r}).touch()\n"
                f"while not Path({str(release)!r}).exists():\n    time.sleep(0.01)\n"
                "result = 'finished_once'\n")
        return code, started, continued, observe, release
    try:
        with env.exclusive():
            assert not discover_databases(), "fresh state must have no owner"
            with patch("ida_nexus.handle.resolve_instance", side_effect=resolve):
                handle = DatabaseHandle.open(str(env.root / "fixtures/mini"), options=DatabaseOpenOptions(
                    startup_timeout=10, worker_env=env.variables(), worker_cwd=env.root))
            handles.append(handle)
            peer = DatabaseHandle.attach(handle.instance)
            handles.append(peer)
            runtime = handle.execute_python("import ida_kernwin\nresult = ida_kernwin.get_kernel_version()", timeout=3)
            evidence.update({"ida": runtime["result"], "python": sys.version.split()[0],
                             "nexus": importlib.metadata.version("ida-nexus"),
                             "domain": importlib.metadata.version("ida-domain"),
                             "instance_id": handle.instance.record_id, "worker_pid": handle.instance.pid,
                             "lease_origin_ids": [h.event_origin_id for h in handles],
                             "client_did_not_load_ida": not {"idapro", "ida_kernwin", "ida_domain"}.intersection(sys.modules),
                             "loaded_handle_sha256": hashlib.sha256(Path(handle_module.__file__).read_bytes()).hexdigest()})
            (env.root / "public-api-source.txt").write_text(
                inspect.getsource(DatabaseHandle._request) + "\n" + inspect.getsource(DatabaseHandle.cancel_operation)
                + "\n" + inspect.getsource(DatabaseHandle.cancel_active))
            original_request = http.client.HTTPConnection.request
            original_response = http.client.HTTPConnection.getresponse
            control_requests = []
            executions = {}
            def request(connection, method, url, *args, **kwargs):
                if url == "/cancel_operation":
                    control_requests.append(url)  # Never retain headers, tokens or lease secrets.
                if url == "/execute_python":
                    operation = json.loads(kwargs["body"])["operation_id"]
                    executions[operation] = executions.get(operation, 0) + 1
                return original_request(connection, method, url, *args, **kwargs)
            with patch.object(http.client.HTTPConnection, "request", request):
                code, started, continued, observe, release = program("healthy")
                future = pool.submit(handle.execute_python, code, operation_id="n3-healthy-cancel", timeout=None)
                futures.append(future)
                wait_for(started)
                before = len(control_requests)
                ack = handle.cancel_operation("n3-healthy-cancel")
                assert ack, "healthy precise operation cancellation must ACK"
                assert len(control_requests) == before + 1, "healthy cancel must send a control request"
                try:
                    future.result(timeout=5)
                    raise AssertionError("healthy operation must return cancelled")
                except RemoteError as error:
                    assert error.code == "operation_cancelled", error.code
                assert not continued.exists(), "healthy cancel stops before the later barrier"
                evidence["healthy"] = {"ack": ack, "control_requests": len(control_requests) - before,
                                       "execution_returned": "operation_cancelled"}
                evidence["actual_probes"] += 1
                code, started, continued, observe, release = program("disconnected")
                injected = threading.Event()
                def response(connection):
                    if threading.current_thread().name.startswith("probe-execute") and not injected.is_set():
                        wait_for(started)
                        injected.set()
                        connection.close()
                        raise http.client.RemoteDisconnected("probe: response connection dropped after started barrier")
                    return original_response(connection)
                with patch.object(http.client.HTTPConnection, "getresponse", response):
                    future = pool.submit(handle.execute_python, code,
                                         operation_id="n3-unknown-operation", timeout=None)
                    futures.append(future)
                    try:
                        future.result(timeout=5)
                        raise AssertionError("injected response disconnect must propagate")
                    except NexusConnectionError as error:
                        evidence["transport_error"] = type(error).__name__
                    assert injected.is_set()
                    assert handle.connected, "SSE lease must remain alive after one request connection fails"
                    before = len(control_requests)
                    ack = handle.cancel_operation("n3-unknown-operation")
                    sent = len(control_requests) - before
                    if args.expect_unpatched:
                        active_ack = handle.cancel_active(timeout=0.1)
                        assert ack is False and active_ack is False and sent == 0
                        observe.touch()
                        wait_for(continued)
                        release.touch()
                    else:
                        assert ack is True and sent == 1, "patched unknown cancellation must send exactly once"
                        proof = handle.execute_python("result = 'same_lease_successor_completed'", timeout=3)
                        assert proof["result"] == "same_lease_successor_completed"
                        assert not continued.exists(), "cancelled original must never cross the continued barrier"
                        stopped = handle.cancel_operation_outcome("n3-unknown-operation")
                        assert stopped["status"] == "not_pending" and stopped["execution_stopped"], stopped
                        observe.touch()
                        assert not continued.exists(), "causal control absence proves original stopped before barrier release"
                        active_ack = None
                    evidence["after_disconnect"] = {
                        "connected": handle.connected, "cancel_ack": ack,
                        "cancel_active_ack": active_ack, "control_requests": sent,
                        "continued_after_cancel": continued.exists(),
                        "operation_id": "n3-unknown-operation",
                        "operation_replayed": False}
                    assert executions["n3-unknown-operation"] == 1, "unknown execution must never replay"
                result = peer.execute_python("result = 'peer_usable_after_unknown_stopped'", timeout=3)
                assert result["result"] == "peer_usable_after_unknown_stopped"
                evidence["peer_usable"] = True
                evidence["actual_probes"] += 1
                done = handle.execute_python("result = 'done'", operation_id="n3-already-ended", timeout=3)
                assert done["result"] == "done"
                code, started, continued, observe, release = program("successor")
                future = pool.submit(handle.execute_python, code, operation_id="n3-new-operation", timeout=None)
                futures.append(future)
                wait_for(started)
                assert handle.cancel_operation("n3-already-ended") is False
                observe.touch()
                wait_for(continued)
                release.touch()
                assert future.result(timeout=5)["result"] == "finished_once"
                evidence["completed_then_cancel"] = {"old_cancel": False, "successor_unaffected": True}
                evidence["actual_probes"] += 1
            if not args.expect_unpatched:
                # Deterministic causal ordering checks use a separate in-memory
                # client. The real-IDA scenarios above remain unchanged.
                sys.path.insert(0, str(REPO / "tests/nexus_bridge"))
                import pytest
                import test_client_patch
                import test_causal_patch
                for check in (test_causal_patch.test_p11_delayed_success_cannot_retire_later_running_unknown,
                              test_causal_patch.test_p11_false_issued_before_true_ack_cannot_retire_unknown):
                    with pytest.MonkeyPatch.context() as injected:
                        fixture = test_client_patch.client.__wrapped__(injected)
                        client = next(fixture)
                        try:
                            check(client, injected)
                        finally:
                            try:
                                next(fixture)
                            except StopIteration:
                                pass
                    evidence["actual_probes"] += 1
                evidence["causal_orderings"] = ["late_success", "late_pre_ack_false"]
            assert evidence["actual_probes"] == (3 if args.expect_unpatched else 5)
            instance = handle.instance
            for item in handles:
                item.close(wait_for_database=True, timeout=5)
            assert wait_database_released(instance, timeout=5), "final release must finish database close"
            assert not discover_databases(), "no test owners after release"
            evidence["saved_packed_database"] = Path(instance.idb_path).is_file()
            assert evidence["saved_packed_database"]
            env.assert_clean()
            evidence["status"] = "BLOCKED_PUBLIC_CANCEL_AFTER_TRANSPORT_LOSS" if args.expect_unpatched else "PASS"
    finally:
        cleanup_errors = []
        for gate in gates:
            try:
                gate.touch(exist_ok=True)
            except OSError as error:
                cleanup_errors.append(f"release barrier: {error}")
        for item in handles:
            try:
                item.close(wait_for_database=True, timeout=5)
            except Exception as error:
                cleanup_errors.append(f"handle close: {type(error).__name__}")
        for future in futures:
            if not future.done():
                try:
                    future.result(timeout=5)
                except Exception as error:
                    cleanup_errors.append(f"executor drain: {type(error).__name__}")
        try:
            evidence["cleanup_signalled_pids"] = env.cleanup()
            env.assert_clean()
        except Exception as error:
            cleanup_errors.append(f"owned process cleanup: {error}")
        pool.shutdown(wait=False, cancel_futures=True)
        evidence["cleanup"] = "FAIL" if cleanup_errors else "CLEAN"
        evidence["cleanup_errors"] = cleanup_errors
        evidence["recorded_processes"] = len(env.entries())
        (env.root / "cancel-gap.json").write_text(json.dumps(evidence, indent=2) + "\n")
        if cleanup_errors:
            raise RuntimeError("probe cleanup failed; inspect cancel-gap.json")
    print(json.dumps(evidence))
    return 2 if args.expect_unpatched else 0


if __name__ == "__main__":
    raise SystemExit(main())
