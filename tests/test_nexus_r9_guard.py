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
        self.delayed_probes = self.guard._delayed_probes
        self.guard._delayed_probes = lambda context: []

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

    def test_failed_hook_is_persistent_across_shared_owner_opens(self):
        for throws in (False, True):
            with self.subTest(throws=throws):
                self.guard._state = None
                self.guard._failed_state = None
                hooks = []
                def fail_hook(_hook):
                    hooks.append('hook')
                    if throws:
                        raise OSError('hook unavailable')
                    return False
                with patch.object(sys.modules['ida_idp'].IDB_Hooks, 'hook', fail_hook):
                    # A separate public lease keeps this exact owner alive.
                    sibling = object()
                    for method in ('open-first', 'open-again'):
                        with self.assertRaisesRegex(RuntimeError, 'protection unavailable'):
                            self.guard.begin({'method': method, 'sibling': id(sibling)})
                    self.assertIsNone(self.guard._state, 'no usable guard may be published')
                    self.assertEqual(hooks, ['hook'])
                    with self.assertRaisesRegex(RuntimeError, 'protection unavailable'):
                        self.guard.save_database()
                    self.assertIn('protection unavailable', self.guard.begin({'method': 'close'}, refuse=False))
                    self.assertEqual(self.flags, {1, 8})

    def test_hook_failure_shared_owner_protocol_reopen_and_final_close(self):
        import tempfile
        import time
        directory = Path(__file__).resolve().parents[1] / 'nexus_bridge'
        with patch.object(sys, 'path', [str(directory), *sys.path]):
            import open_recovery
            from bridge import guarded_source
        guard = self.guard
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)/'input.i64'
            target.write_bytes(b'original packed')
            live = {'sibling'}
            acquired, released, hook_calls = [], [], []
            class Handle:
                instance = types.SimpleNamespace(record_id='same-owner', idb_path=str(target))
                def __init__(self, lease):
                    self.lease = lease
                    live.add(lease)
                def execute_python(self, source, **kwargs):
                    namespace = {}
                    exec(source, namespace)
                    return {'result': namespace.get('result')}
                def close_outcome(self, **kwargs):
                    if not guard.close_status()['close_safe']:
                        raise AssertionError('unsafe saving close')
                    live.remove(self.lease)
                    return {'lease_released': True}
            sibling = Handle('sibling')
            def open_handle(*args, **kwargs):
                return Handle('open-'+str(len(acquired)))
            def fail_hook(_hook):
                hook_calls.append('hook')
                return False
            api = types.SimpleNamespace(probe_database_state=lambda *a, **kw: {
                'idb_path': str(target), 'state': 'packed'},
                wait_database_released=lambda *a, **kw: False)
            with patch.dict(sys.modules, {'ida_nexus': api, '_ida_cli_save_guard_v1': guard}), \
                    patch.dict(__import__('os').environ, {'IDA_CLI_HOME': str(Path(temp)/'home')}), \
                    patch.object(sys.modules['ida_idp'].IDB_Hooks, 'hook', fail_hook):
                for _ in range(2):
                    with self.assertRaisesRegex(RuntimeError, 'protection unavailable'):
                        open_recovery.open_checked(types.SimpleNamespace(open=open_handle),
                            lambda **kw: kw, str(target), {}, time.monotonic()+2,
                            guarded_source, {'method': 'open'},
                            acquired=lambda h, _: acquired.append(h), released=released.append)
                    self.assertEqual(live, {'sibling'})
                result = sibling.execute_python(guarded_source('pass', {'method': 'close'}, refuse=False))
                self.assertIn('protection unavailable', result['result']['save_guard_error'])
                sibling.close_outcome()
                self.assertEqual(live, set())
                self.assertEqual(hook_calls, ['hook'])
                self.assertEqual(acquired, released)
                self.assertEqual(target.read_bytes(), b'original packed')

    def test_flag_failure_records_poison_before_any_cleanup(self):
        self.present = False
        loader = sys.modules['ida_loader']
        for branch in ('set', 'readback', 'read-error'):
            with self.subTest(branch=branch):
                self.guard._state = None
                self.flags.clear()
                def set_flag(flag):
                    if branch == 'set':
                        raise OSError('cannot set flag')
                    self.flags.add(flag)
                def read_flag(flag):
                    if branch == 'read-error':
                        raise OSError('cannot query flag')
                    return False
                with patch.object(loader, 'set_database_flag', set_flag), patch.object(loader, 'is_database_flag', read_flag):
                    with self.assertRaisesRegex(RuntimeError, 'protection unavailable'):
                        self.guard.begin({'method': 'open', 'lease': 'exact-lease'})
                    self.assertTrue(self.guard._state['poisoned'])
                    self.assertIsNotNone(self.guard._state['first_failure'])
                    self.assertFalse(self.guard.close_status()['close_safe'])
                    with self.assertRaisesRegex(RuntimeError, 'protection unavailable'):
                        self.guard.finish({'method': 'close'}, refuse=False)

    def test_unconfirmed_flags_never_request_default_close(self):
        import tempfile
        import time
        directory = Path(__file__).resolve().parents[1] / 'nexus_bridge'
        with patch.object(sys, 'path', [str(directory), *sys.path]):
            import open_recovery
            from bridge import guarded_source
        for branch in ('set', 'readback', 'read-error'):
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as temp:
                self.guard._state = None
                self.guard._failed_state = None
                self.present = False
                target = Path(temp)/'input.i64'
                target.write_bytes(b'original packed')
                calls, retained = [], []
                guard = self.guard
                class Handle:
                    instance = types.SimpleNamespace(record_id='shared-owner', idb_path=str(target))
                    def execute_python(self, source, **kwargs):
                        namespace = {}
                        exec(source, namespace)
                        return {'result': namespace.get('result')}
                    def close_outcome(self, **kwargs):
                        calls.append('default-save-close')
                        return {'lease_released': True}
                handle = Handle()
                loader = sys.modules['ida_loader']
                def set_flag(flag):
                    if branch == 'set':
                        raise OSError('cannot set flag')
                def read_flag(flag):
                    if branch == 'read-error':
                        raise OSError('cannot query flag')
                    return False
                api = types.SimpleNamespace(probe_database_state=lambda *a, **kw: {
                    'idb_path': str(target), 'state': 'packed'}, wait_database_released=lambda *a, **kw: False)
                with patch.dict(sys.modules, {'ida_nexus': api, '_ida_cli_save_guard_v1': guard}), \
                        patch.dict(__import__('os').environ, {'IDA_CLI_HOME': str(Path(temp)/'home')}), \
                        patch.object(loader, 'set_database_flag', set_flag), \
                        patch.object(loader, 'is_database_flag', read_flag):
                    with self.assertRaises(RuntimeError):
                        open_recovery.open_checked(types.SimpleNamespace(open=lambda *a, **kw: handle),
                            lambda **kw: kw, str(target), {}, time.monotonic()+2,
                            guarded_source, {'method': 'open'}, acquired=lambda h, _: retained.append(h))
                self.assertEqual(calls, [], 'unconfirmed flags must never reach save=True close')
                self.assertEqual(retained, [handle], 'keep the exact lease cleanup responsibility')
                self.assertEqual(target.read_bytes(), b'original packed')

    def test_bridge_teardown_never_defaults_to_save_after_guard_failure(self):
        import threading
        directory = Path(__file__).resolve().parents[1] / 'nexus_bridge'
        with patch.object(sys, 'path', [str(directory), *sys.path]):
            import bridge
        from unittest.mock import Mock
        for connected in (True, False):
            with self.subTest(connected=connected):
                handle = Mock(connected=connected)
                handle.execute_python.side_effect = RuntimeError('protection unavailable')
                owner = bridge.Bridge.__new__(bridge.Bridge)
                owner.stopped, owner.proof_wakeup = threading.Event(), threading.Event()
                owner.lock = threading.Lock()
                owner.handles = {'lease': ({'lease_id': 'lease'}, handle)}
                owner.verification_probes, owner.cleanup_handles = {}, {}
                owner.executing, owner.metadata_contexts = {}, {}
                owner.lifetime_socket = Mock()
                owner.lifetime_path = '/nonexistent/f7-lifetime'
                owner.drop_lifetime = Mock()
                owner.business, owner.control = Mock(), Mock()
                owner.business_pool, owner.cancel_pool = Mock(), Mock()
                owner.release_pool, owner.proof_pool = Mock(), Mock()
                owner.close()
                handle.close.assert_not_called()
                handle.close_outcome.assert_not_called()
                self.assertIs(owner.handles['lease'][1], handle)

    def test_unverifiable_root_refuses_open_and_explicit_save(self):
        def unavailable(_):
            raise RuntimeError('Root Node probe unavailable')
        sys.modules['ida_netnode'].netnode.exist = unavailable
        with self.assertRaisesRegex(RuntimeError, 'Root Node'):
            self.guard.begin({'method': 'open'})
        with self.assertRaisesRegex(RuntimeError, 'saving refused'):
            self.guard.save_database()
        self.assertEqual(self.flags, {1, 8})

    def test_failure_captures_actual_components_before_protection(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'active.id0').write_bytes(b'component')
            (root/'other.i64.lock').write_bytes(b'lock')
            loader = sys.modules['ida_loader']
            loader.PATH_TYPE_CMD, loader.PATH_TYPE_ID0 = 1, 2
            loader.DBFL_COMP, loader.DBFL_BAK = 2, 4
            loader.get_path = lambda kind: str(root/('active.id0' if kind==2 else 'input.i64'))
            with patch.dict(sys.modules, {'ida_ida': types.SimpleNamespace(
                    inf_pack_idb=lambda: True, inf_compress_idb=lambda: False, inf_get_lflags=lambda: 512)}):
                self.present = False
                with self.assertRaisesRegex(RuntimeError, 'Root Node'):
                    self.guard.begin({'method': 'open'})
            context = self.logs[0]['database_at_failure']
            self.assertEqual(context['paths']['PATH_TYPE_ID0'], str(root/'active.id0'))
            files = {row['name']:row['stat'] for row in context['directories'][str(root)]}
            self.assertEqual(set(files), {'active.id0','other.i64.lock'})
            self.assertEqual(files['active.id0']['size'], 9)
            self.assertEqual(files['active.id0']['inode'], (root/'active.id0').stat().st_ino)
            self.assertFalse(self.logs[0]['flags_before_protection']['DBFL_TEMP'])
            self.assertTrue(context['database_flags']['DBFL_TEMP'])
            self.assertEqual(self.flags, {1, 8})

    def test_delayed_root_recovery_never_unpoisons_owner(self):
        self.guard._delayed_probes = self.delayed_probes
        self.present = False
        with patch.object(self.guard.time, 'sleep', side_effect=lambda _: setattr(self, 'present', True)):
            with self.assertRaisesRegex(RuntimeError, 'Root Node'):
                self.guard.begin({'method': 'open'})
        probes = self.guard._state['first_failure']['delayed_probes']
        self.assertEqual(len(probes), 3)
        self.assertTrue(all(row['root_present'] for row in probes))
        with self.assertRaisesRegex(RuntimeError, 'saving refused'):
            self.guard.save_database()

    def test_diagnostic_failure_does_not_mask_protection(self):
        self.present = False
        with patch.object(self.guard, 'database_context', side_effect=OSError('directory denied')):
            with self.assertRaisesRegex(RuntimeError, 'Root Node'):
                self.guard.begin({'method': 'open'})
        self.assertEqual(self.logs[0]['database_at_failure'], {'error':'OSError'})
        self.assertEqual(self.flags, {1, 8})

    def test_poisoned_close_keeps_a_fresh_component_snapshot(self):
        self.present = False
        def capture_open():
            self.assertEqual(self.flags, {1, 8})
            return {'files': 'open'}
        with patch.object(self.guard, 'database_context', side_effect=capture_open):
            self.guard.begin({'method': 'open'}, refuse=False)
        with patch.object(self.guard, 'database_context', return_value={'files': 'close'}):
            self.guard._state['hook'].closebase()
        boundary = self.guard._state['last_failure_boundary']
        self.assertEqual(boundary['stage'], 'automatic-close')
        self.assertEqual(boundary['database'], {'files': 'close'})
        self.assertEqual(self.logs[0]['database_at_failure'], {'files': 'open'})
        self.assertEqual(self.flags, {1, 8})

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
