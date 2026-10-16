"""Owner guard state, fail-closed probes and first-transition attribution."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


class GuardTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'nexus_bridge/save_guard.py'
        spec = importlib.util.spec_from_file_location('test_save_guard', path)
        self.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guard)
        self.present = True
        self.flags = set()
        self.logs = []
        self.guard._log = self.logs.append

        class Hook:
            def hook(self):
                return True

        modules = {'ida_netnode': types.SimpleNamespace(netnode=types.SimpleNamespace(exist=lambda _: self.present)),
            'ida_loader': types.SimpleNamespace(PATH_TYPE_IDB=0, DBFL_TEMP=8, DBFL_KILL=1,
                get_path=lambda _: '/test/input.i64', set_database_flag=self.flags.add,
                is_database_flag=lambda flag: flag in self.flags, save_database=lambda *args: True),
            'ida_idp': types.SimpleNamespace(IDB_Hooks=Hook),
            'ida_nalt': types.SimpleNamespace(get_input_file_path=lambda: 'input',
                retrieve_input_file_size=lambda: 10, retrieve_input_file_md5=lambda: b'1'*16,
                retrieve_input_file_sha256=lambda: b'2'*32)}
        self.modules = patch.dict(sys.modules, modules)
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_first_loss_has_operation_and_previous_sample_and_stays_poisoned(self):
        self.guard.begin({'method': 'open', 'operation_id': 'open-1'})
        operation = {'method': 'run_script', 'operation_id': 'op-2', 'lease': {'lease_id': 'lease-3'}}
        self.guard.begin(operation)
        self.present = False
        with self.assertRaisesRegex(RuntimeError, 'original file retained'):
            self.guard.finish(operation)
        self.assertEqual(self.flags, {1, 8})
        self.assertEqual(len(self.logs), 1)
        evidence = self.logs[0]
        self.assertTrue(evidence['first_transition'])
        self.assertEqual(evidence['operation'], operation)
        self.assertEqual(evidence['previous_sample']['stage'], 'before')
        self.present = True
        with self.assertRaisesRegex(RuntimeError, 'Root Node'):
            self.guard.save_database()
        self.assertEqual(len(self.logs), 1)

    def test_unverifiable_probe_also_disarms_close(self):
        self.guard.begin({'method': 'open'})
        def unavailable(_):
            raise RuntimeError('probe unavailable')
        sys.modules['ida_netnode'].netnode.exist = unavailable
        self.assertIn('saving refused', self.guard.finish({'method': 'close'}, refuse=False))
        self.assertEqual(self.flags, {1, 8})
        self.assertEqual(self.logs[0]['probe_error'], 'RuntimeError')

    def test_diagnostic_getter_failure_does_not_break_healthy_operations(self):
        def unavailable():
            raise RuntimeError('diagnostic unavailable')
        sys.modules['ida_nalt'].get_input_file_path = unavailable
        self.guard.begin({'method': 'open'})
        self.guard.finish({'method': 'read'})
        self.assertEqual(self.flags, set())
        self.assertTrue(self.guard.save_database())

    def test_automatic_close_hook_checks_again_after_last_operation(self):
        self.guard.begin({'method': 'open'})
        self.present = False
        self.guard._state['hook'].closebase()
        self.assertEqual(self.flags, {1, 8})
        self.assertEqual(self.logs[0]['stage'], 'automatic-close')

    def test_raw_python_preserves_future_imports_and_result_globals(self):
        directory = Path(__file__).resolve().parents[1] / 'nexus_bridge'
        spec = importlib.util.spec_from_file_location('guard_bridge', directory/'bridge.py')
        bridge = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'path', [str(directory), *sys.path]):
            spec.loader.exec_module(bridge)
        calls = []
        guard = types.SimpleNamespace(begin=lambda *a, **k: calls.append('before'),
                                      finish=lambda *a, **k: calls.append('after'))
        code = bridge.guarded_source('from __future__ import annotations\nresult = 42', {'method': 'execute_python'})
        namespace = {}
        with patch.dict(sys.modules, {'_ida_cli_save_guard_v1': guard}):
            exec(code, namespace)
        self.assertEqual(namespace['result'], 42)
        self.assertEqual(calls, ['before', 'after'])


if __name__ == '__main__':
    unittest.main()
