"""Real pinned client + production bridge, fake public transport and IDA APIs."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
import inspect
import sys
import threading
import tempfile
import time
import types
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ['R3A_CASE_ROOT'])
sys.path.insert(0, str(REPO / "nexus_bridge"))
import ida_nexus
from ida_nexus import DatabaseHandle
import ida_nexus.handle as client


def load_bridge(version):
    import bridge
    return bridge


def case(version='current', lost_ack=False, root_loss=False, slice_cleanup=False,
         sibling=False, prove=False, retry=False, barrier=False):
    bridge = load_bridge(version)
    live, calls, proofs, checks = set(), [], [], []
    state = {"root": True, "flags": set(), "proved": prove}
    arrived, proceed = threading.Event(), threading.Event()
    spec = importlib.util.spec_from_file_location("_ida_cli_save_guard_v1", REPO / "nexus_bridge/save_guard.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    directory = Path(tempfile.mkdtemp(prefix='release-', dir=ROOT))
    path = str(directory / "mock.i64")
    Path(path).write_bytes(b"private release input")
    instance = types.SimpleNamespace(record_id="review-owner", backend="idalib",
        managed=True, pid=os.getpid(), started_at=time.time(), port=1, idb_path=path, exe_path="",
        _token=os.urandom(16).hex())

    class Hook:
        def hook(self):
            return True

    modules = {
        "_ida_cli_save_guard_v1": guard,
        "ida_netnode": types.SimpleNamespace(netnode=types.SimpleNamespace(exist=lambda _: state["root"])),
        "ida_loader": types.SimpleNamespace(PATH_TYPE_IDB=0, DBFL_TEMP=8, DBFL_KILL=1,
            get_path=lambda _: path, set_database_flag=state["flags"].add,
            is_database_flag=lambda flag: flag in state["flags"]),
        "ida_idp": types.SimpleNamespace(IDB_Hooks=Hook),
        "ida_nalt": types.SimpleNamespace(get_input_file_path=lambda: "mock",
            retrieve_input_file_size=lambda: 1, retrieve_input_file_md5=lambda: b"1" * 16,
            retrieve_input_file_sha256=lambda: b"2" * 32),
    }
    names = {}

    class Connection:
        status = 200

        def request(self, method, endpoint, **kwargs):
            assert endpoint == "/release_lease", endpoint
            self.lease = json.loads(kwargs["body"])["lease_id"]
            live.discard(self.lease)
            self.pending = not live
            calls.append({"lease": names[self.lease], "shutdown_pending": self.pending})
            if names[self.lease] == "primary" and root_loss:
                state["root"] = False

        def getresponse(self):
            return self

        def read(self):
            if names[self.lease] == "auxiliary" and lost_ack:
                raise OSError("injected lost auxiliary release ACK")
            return json.dumps({"ok": True, "result": {
                "released": True, "shutdown_pending": self.pending}}).encode()

        def close(self):
            pass

    def lifetime(*args, **kwargs):
        proofs.append("lifetime-query")
        if barrier:
            arrived.set()
            assert proceed.wait(2), "lifetime barrier not released"
        return state["proved"]

    with patch.dict(sys.modules, modules), \
            patch.object(DatabaseHandle, "_open_lease", return_value=(None, None, None)), \
            patch.object(DatabaseHandle, "_monitor_lease", return_value=None), \
            patch.object(client.http.client, "HTTPConnection", side_effect=lambda *a, **kw: Connection()), \
            patch.object(client, "wait_database_released", side_effect=lifetime), \
            patch.object(ida_nexus, "wait_database_released", side_effect=lifetime), \
            patch.object(ida_nexus, "discover_databases", return_value=[types.SimpleNamespace(instance=instance)]):
        primary = DatabaseHandle(path, instance)
        auxiliary = DatabaseHandle(path, instance)
        names.update({primary._lease_id: "primary", auxiliary._lease_id: "auxiliary"})
        live.update(names)
        if sibling:
            live.add("real-sibling-lease")
        primary._disconnected.set()
        guard.begin({"method": "open"})

        def execute(source, **kwargs):
            namespace = {}
            exec(source, namespace)
            result = namespace.get("result")
            checks.append(result)
            return {"result": result}

        auxiliary.execute_python = execute
        owner = bridge.Bridge.__new__(bridge.Bridge)
        lease = {"lease_id": "logical", "instance_id": "review-owner", "generation": 1}
        owner.lock = threading.Lock()
        owner.identity, owner.lifetime_path = "review-bridge", str(ROOT / "lifetime")
        owner.handles = {"logical": (lease, primary)}
        owner.custodians = {}
        owner.cleanup_handles = {}
        # Bound optional poison diagnostics with the supplied context deadline;
        # the inspected guard's executable functions remain unmodified.
        owner.metadata_contexts = {"logical":{"deadline":time.monotonic()}}
        owner.Handle = types.SimpleNamespace(attach=lambda entry: auxiliary)
        owner.drop_lifetime = lambda key: None
        messages = []
        raised = []
        slices_module = None
        if slice_cleanup:
            import slices as slices_module
            slices_module.cleanup_handles.clear()
            live.discard(primary._lease_id)
        def invoke():
            try:
                if slice_cleanup:
                    args = [auxiliary, ["bridge", "logical", "review-owner", 1, str(ROOT / "lifetime")], slices_module.incarnation]
                    # F9 makes the shared release function an explicit payload dependency.
                    if len(inspect.signature(slices_module.cleanup_disconnected).parameters) == 4:
                        from lifecycle import release_handle
                        args.append(release_handle)
                    slices_module.cleanup_disconnected(*args)
                else:
                    owner.invoke(types.SimpleNamespace(send=messages.append), {"sequence": 1},
                                 {"command": "release", "lease": lease}, time.monotonic() + 1, [False])
            except (RuntimeError, ValueError) as exc:
                raised.append(str(exc))
        blocked = None
        if barrier:
            worker = threading.Thread(target=invoke)
            worker.start()
            reached = arrived.wait(2)
            blocked = reached and worker.is_alive() and not any(m['event']=='released' for m in messages)
            state['proved'] = True
            proceed.set()
            worker.join(2)
            assert not worker.is_alive(), 'release worker remained blocked'
        else:
            invoke()
        retained_before_retry = bool(slices_module.cleanup_handles if slice_cleanup else owner.cleanup_handles)
        if retry:
            before = len(calls)
            state['proved'] = True
            invoke()
            assert len(calls) == before, 'proof coordination must never replay release'
        retained_auxiliary = bool(slices_module.cleanup_handles if slice_cleanup else owner.cleanup_handles)
        outcome = {"retained_before_retry": retained_before_retry, "barrier_blocked": blocked, "raised": raised, "version": version, "lost_auxiliary_ack": lost_ack, "root_loss": root_loss,
                   "release_calls": calls, "lifetime_queries": proofs,
                   "sample_results": checks, "flags": sorted(state["flags"]),
                   "messages": messages, "retained_primary": bool(owner.handles),
                   "retained_auxiliary": retained_auxiliary,
                   "auxiliary_client_outcome": auxiliary._close_outcome}
    return outcome



class ReleaseTests(unittest.TestCase):
    def test_shared_protocol_accumulates_errors_across_healthy_retry(self):
        from lifecycle import release_handle
        handle = types.SimpleNamespace(instance=object(), close_outcome=Mock(return_value={
            'status': 'uncertain', 'lease_released': True, 'shutdown_pending': True,
            'failure': 'lifetime_unconfirmed'}))
        check = Mock(return_value={'close_safe': True, 'save_guard_error': 'saving refused: first'})
        with patch.object(ida_nexus, 'wait_database_released', side_effect=[False, True]):
            self.assertIsNone(release_handle(handle, time.monotonic()+1, check=check))
            result = release_handle(handle, time.monotonic()+1,
                check=Mock(side_effect=AssertionError('closed handle must not be queried')),
                errors=('saving refused: second',))
        self.assertIn('saving refused: first', result['save_guard_error'])
        self.assertIn('saving refused: second', result['save_guard_error'])
        self.assertTrue(result['owner_released'])
        self.assertIsNone(result['failure'])
        handle.close_outcome.assert_called_once()
        check.assert_called_once()

    def test_shared_protocol_refuses_unsafe_check_without_release(self):
        from lifecycle import release_handle
        handle = types.SimpleNamespace(instance=object(), close_outcome=Mock())
        with self.assertRaisesRegex(RuntimeError, 'saving refused'):
            release_handle(handle, time.monotonic()+1,
                check=lambda: {'close_safe': False, 'save_guard_error': 'saving refused'})
        handle.close_outcome.assert_not_called()

    def test_last_auxiliary_waits_for_public_lifetime_barrier(self):
        row = case(barrier=True)
        self.assertTrue(row['barrier_blocked'], row)
        self.assertEqual(row['messages'][-1]['event'], 'released')
        self.assertTrue(row['messages'][-1]['outcome']['owner_released'])

    def test_lost_auxiliary_ack_retains_exact_responsibility(self):
        row = case(lost_ack=True)
        self.assertFalse(any(m['event']=='released' for m in row['messages']), row)
        self.assertTrue(row['retained_primary'])
        self.assertTrue(row['retained_auxiliary'])
        self.assertTrue(row['lifetime_queries'])

    def test_lost_ack_retry_only_coordinates_proof(self):
        row = case(lost_ack=True, retry=True)
        self.assertTrue(row['retained_before_retry'])
        self.assertEqual(row['messages'][-1]['event'], 'released')
        self.assertEqual(len(row['release_calls']), 2)
        self.assertFalse(row['retained_auxiliary'])

    def test_real_sibling_allows_nonfinal_ack_without_owner_exit(self):
        row = case(sibling=True)
        self.assertEqual(row['messages'][-1]['event'], 'released')
        self.assertFalse(row['lifetime_queries'])
        self.assertTrue(all(not c['shutdown_pending'] for c in row['release_calls']))

    def test_auxiliary_save_refusal_survives_into_result_and_sideband(self):
        row = case(root_loss=True, prove=True)
        final = row['messages'][-1]
        self.assertEqual(final['event'], 'released')
        self.assertIsInstance(final.get('save_guard_error'), str)
        self.assertIn('saving refused', final['save_guard_error'])
        self.assertIn('saving refused', final['outcome']['save_guard_error'])
        self.assertEqual(row['flags'], [1, 8])

    def test_slice_last_auxiliary_lost_ack_keeps_handle(self):
        row = case(lost_ack=True, slice_cleanup=True)
        self.assertTrue(row['retained_auxiliary'], row)
        self.assertTrue(row['lifetime_queries'])
        self.assertTrue(row['raised'])

    def test_slice_lost_ack_retry_does_not_repeat_release(self):
        row = case(lost_ack=True, slice_cleanup=True, retry=True)
        self.assertTrue(row['retained_before_retry'])
        self.assertFalse(row['retained_auxiliary'])
        self.assertEqual(len(row['release_calls']), 1)

if __name__ == '__main__':
    unittest.main()
