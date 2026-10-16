"""Production open/guard flow with public API stubs; no IDA is launched."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
import threading
import time
import types
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "nexus_bridge"))
import bridge


def case(branch):
    temporary = tempfile.TemporaryDirectory(prefix='r9-analysis-')
    target_dir = Path(temporary.name)
    target = target_dir / "input.i64"
    target.write_bytes(b"last successful packed save")
    context = {"present": True, "flags": set(), "events": []}
    spec = importlib.util.spec_from_file_location("_ida_cli_save_guard_v1", REPO / "nexus_bridge/save_guard.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    guard._log = lambda value: None
    guard._delayed_probes = lambda value: []

    class Hook:
        def hook(self):
            return True

    def set_flag(flag):
        if branch == "set" and not context["present"]:
            raise OSError("cannot set flag")
        context["flags"].add(flag)

    def read_flag(flag):
        if not context["present"]:
            if branch == "read-error":
                raise OSError("cannot read flag")
            if branch == "readback":
                return False
        return flag in context["flags"]

    instance = types.SimpleNamespace(record_id="review-owner", idb_path=str(target),
                                     pid=1000, backend="idalib")

    class Handle:
        connected = True
        recovery = "none"

        def __init__(self):
            self.instance = instance

        def execute_python(self, source, **kwargs):
            namespace = {}
            exec(source, namespace)
            result = namespace.get("result")
            if isinstance(result, dict) and "close_safe" in result:
                context["close_proof"] = result
            return {"result": result}

        def set_disconnect_callback(self, callback):
            self.callback = callback

        def wait_autoanalysis(self, **kwargs):
            context["present"] = branch == "healthy"
            context["events"].append("analysis-failed-after-root-loss")
            raise RuntimeError("injected analysis failure")

        def close_outcome(self, **kwargs):
            context["events"].append("discard-close" if context["flags"] == {1, 8} else "default-save-close")
            # A hook notification cannot veto a default saving close. Only
            # count the request here; do not claim to emulate IDA file writes.
            try:
                guard._state["hook"].savebase()
            except Exception as error:
                context["hook_error"] = str(error)
            return {"status": "lease_released", "lease_released": True}

    handle = Handle()
    modules = {
        "_ida_cli_save_guard_v1": guard,
        "ida_netnode": types.SimpleNamespace(netnode=types.SimpleNamespace(exist=lambda _: context["present"])),
        "ida_loader": types.SimpleNamespace(PATH_TYPE_IDB=0, DBFL_TEMP=8, DBFL_KILL=1,
            get_path=lambda _: str(target), set_database_flag=set_flag, is_database_flag=read_flag),
        "ida_idp": types.SimpleNamespace(IDB_Hooks=Hook),
        "ida_nalt": types.SimpleNamespace(get_input_file_path=lambda: "input",
            retrieve_input_file_size=lambda: 1, retrieve_input_file_md5=lambda: b"1" * 16,
            retrieve_input_file_sha256=lambda: b"2" * 32),
        "ida_kernwin": types.SimpleNamespace(get_kernel_version=lambda: "9.5"),
        "ida_nexus": types.SimpleNamespace(discover_databases=lambda **kw: [],
            probe_database_state=lambda *args, **kw: {"idb_path": str(target), "state": "packed"},
            wait_database_released=lambda *args, **kw: True),
    }
    owner = bridge.Bridge.__new__(bridge.Bridge)
    owner.Handle = types.SimpleNamespace(open=lambda *args, **kw: handle)
    owner.Options = lambda **kw: kw
    owner.lock = threading.Lock()
    owner.handles, owner.metadata_contexts, owner.generations = {}, {}, {}
    events = []
    channel = types.SimpleNamespace(send=events.append)
    command = {"command": "open", "identity": {"client_id": "review", "operation_id": "open-review"},
               "path": str(target), "options": {"wait_analysis": True}}
    if branch == "probe-error":
        modules["ida_netnode"].netnode.exist = lambda _: True if context["present"] else (_ for _ in ()).throw(OSError("probe unavailable"))
    with patch.dict(sys.modules, modules), patch.dict(os.environ, {"IDA_CLI_HOME": str(target_dir / "home")}), \
            patch.object(bridge, "idb_context", return_value={}), \
            patch.object(bridge, "database_diagnostics", return_value={}):
        error = None
        started = [False]
        try:
            owner.invoke(channel, {"sequence": 1}, command, time.monotonic() + 5, started)
        except RuntimeError as exc:
            error = str(exc)
        context["post_close_safe"] = guard.close_status()["close_safe"]
    retained = list(owner.handles.values())
    unchanged = target.read_bytes() == b"last successful packed save"
    temporary.cleanup()
    return {"error": error, "public_started": started[0], "exact_handle_retained": bool(retained and retained[0][1] is handle),
            "first_failure": (guard._state or {}).get("first_failure"), "branch": branch, "events": context["events"],
            "proof_before_close": context.get("close_proof"),
            "hook_error": context.get("hook_error"),
            "post_close_safe": context["post_close_safe"],
            "retained_handles": len(owner.handles), "bridge_events": events,
            "packed_file_unchanged": unchanged}

class AnalysisFailureTests(unittest.TestCase):
    def test_analysis_root_loss_with_unconfirmed_flags_retains_exact_lease(self):
        for branch in ('set', 'readback', 'read-error', 'probe-error'):
            with self.subTest(branch=branch):
                result = case(branch)
                self.assertEqual(result['events'], ['analysis-failed-after-root-loss'])
                self.assertTrue(result['exact_handle_retained'])
                self.assertTrue(result['public_started'], 'run() must report uncertain')
                self.assertIn('exact lease retained', result['error'])
                self.assertEqual(result['bridge_events'], [])
                self.assertFalse(result['post_close_safe'])
                self.assertFalse(result['first_failure']['previous_sample'] is None,
                                 'analysis failure cannot become an initial-open retry')

    def test_analysis_failure_with_current_healthy_root_cleans_normally(self):
        result = case('healthy')
        self.assertEqual(result['events'], ['analysis-failed-after-root-loss', 'default-save-close'])
        self.assertEqual(result['retained_handles'], 0)
        self.assertEqual(result['bridge_events'][0]['event'], 'failed')
        self.assertIsNone(result['error'])

    def test_analysis_root_loss_with_confirmed_flags_discards(self):
        result = case('confirmed')
        self.assertEqual(result['events'], ['analysis-failed-after-root-loss', 'discard-close'])
        self.assertEqual(result['retained_handles'], 0)
        self.assertEqual(result['bridge_events'][0]['event'], 'failed')
        self.assertIsNone(result['error'])

if __name__ == '__main__':
    unittest.main()
