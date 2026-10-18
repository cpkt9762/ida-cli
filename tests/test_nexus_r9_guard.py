"""Owner guard state, fail-closed probes and first-transition attribution."""
import importlib.util
import os
import tempfile
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


class GuardTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'nexus_bridge/save_guard.py'
        spec = importlib.util.spec_from_file_location('_ida_cli_save_guard_v1', path)
        self.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guard)
        self.present = True
        self.flags = set()
        self.logs = []
        self.original_log = self.guard._log
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

    def checked_guard(self):
        # Compatibility inspection must see the actual source functions. Direct
        # sampler tests above/below may still capture logs at their own boundary.
        self.guard._log = self.original_log
        self.guard._delayed_probes = self.delayed_probes

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
        with self.assertRaisesRegex(RuntimeError, 'current Root query failed'):
            self.guard.finish({'method': 'close'}, refuse=False)
        self.assertFalse(self.guard.close_status()['close_safe'])
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
        self.checked_guard()
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
                    return {'status': 'lease_released', 'lease_released': True, 'shutdown_pending': False}
            sibling = Handle('sibling')
            def open_handle(*args, **kwargs):
                return Handle('open-'+str(len(acquired)))
            def fail_hook(_hook):
                hook_calls.append('hook')
                return False
            api = types.SimpleNamespace(get_state_dir=lambda: Path(os.environ['IDA_NEXUS_STATE_DIR']), probe_database_state=lambda *a, **kw: {
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
        self.checked_guard()
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
                        return {'status': 'lease_released', 'lease_released': True, 'shutdown_pending': False}
                handle = Handle()
                loader = sys.modules['ida_loader']
                def set_flag(flag):
                    if branch == 'set':
                        raise OSError('cannot set flag')
                def read_flag(flag):
                    if branch == 'read-error':
                        raise OSError('cannot query flag')
                    return False
                api = types.SimpleNamespace(get_state_dir=lambda: Path(os.environ['IDA_NEXUS_STATE_DIR']), probe_database_state=lambda *a, **kw: {
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
                owner.lifetime_endpoint = None
                owner.lifetime_socket = Mock()
                owner.custodians = {}
                owner.lifetime_path = '/nonexistent/f7-lifetime'
                owner.drop_lifetime = Mock()
                owner.business, owner.control = Mock(), Mock()
                owner.business_pool, owner.cancel_pool = Mock(), Mock()
                owner.release_pool, owner.proof_pool = Mock(), Mock()
                owner.preflight_pool, owner.detach_pool = Mock(), Mock()
                owner.close()
                handle.close.assert_not_called()
                handle.close_outcome.assert_not_called()
                self.assertIs(owner.handles['lease'][1], handle)

    def test_close_confirmation_samples_current_root_and_preserves_first_failure(self):
        self.guard.begin({'method': 'open'})
        self.present = False
        proof = self.guard.close_status()
        self.assertTrue(proof['close_safe'])
        self.assertFalse(proof['initial'], 'a later loss must not authorize initial-open retry')
        self.assertEqual(proof['evidence']['stage'], 'before-close')
        first = proof['evidence']
        self.flags.clear()
        self.assertTrue(self.guard.close_status()['close_safe'])
        self.assertEqual(self.flags, {1, 8}, 're-arm flags, never reuse a prior confirmation')
        self.assertIs(self.guard.close_status()['evidence'], first)

    def test_slice_disconnect_cleanup_retains_auxiliary_handle_on_unsafe_close(self):
        from unittest.mock import Mock
        path = Path(__file__).resolve().parents[1] / 'nexus_bridge/slices.py'
        spec = importlib.util.spec_from_file_location('test_slices_cleanup', path)
        slices = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(slices)
        spec = importlib.util.spec_from_file_location('test_cleanup_lifecycle',
                                                     path.with_name('lifecycle.py'))
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        context = ['bridge', 'lease', 'owner', 1, '/lifetime']
        self.guard.begin({'method': 'open'})
        with patch.dict(sys.modules, {'_ida_cli_save_guard_v1': self.guard}):
            for branch in ('set', 'readback', 'read-error', 'query', 'healthy', 'confirmed'):
                with self.subTest(branch=branch):
                    self.guard._state = None
                    self.flags.clear()
                    self.present = True
                    self.guard.begin({'method': 'open'})
                    def execute(source, **kwargs):
                        if 'release_lease' in source:
                            self.present = branch == 'healthy'
                            raise RuntimeError('injected slice cleanup failure')
                        namespace = {}
                        exec(source, namespace)
                        return {'result': namespace['result']}
                    handle = Mock()
                    handle.close_outcome.return_value = {'status': 'lease_released', 'lease_released': True, 'shutdown_pending': False}
                    handle.execute_python.side_effect = execute
                    loader = sys.modules['ida_loader']
                    def set_flag(flag):
                        if branch == 'set':
                            raise OSError('cannot set flag')
                        self.flags.add(flag)
                    def read_flag(flag):
                        if branch == 'read-error':
                            raise OSError('cannot query flag')
                        return branch != 'readback' and flag in self.flags
                    def root(_):
                        if branch == 'query' and not self.present:
                            raise OSError('cannot query Root')
                        return self.present
                    with patch.object(loader, 'set_database_flag', set_flag), \
                            patch.object(loader, 'is_database_flag', read_flag), \
                            patch.object(sys.modules['ida_netnode'].netnode, 'exist', root):
                        with self.assertRaises(RuntimeError):
                            slices.cleanup_disconnected(handle, context, slices.incarnation,
                                                        lifecycle.release_handle)
                    if branch in ('healthy', 'confirmed'):
                        handle.close_outcome.assert_called_once()
                        handle.close.assert_not_called()
                        self.assertNotIn(tuple(context), slices.cleanup_handles)
                    else:
                        handle.close.assert_not_called()
                        self.assertIs(slices.cleanup_handles[tuple(context)], handle)

    def test_unverifiable_root_refuses_open_and_explicit_save(self):
        def unavailable(_):
            raise RuntimeError('Root Node probe unavailable')
        sys.modules['ida_netnode'].netnode.exist = unavailable
        with self.assertRaisesRegex(RuntimeError, 'Root Node'):
            self.guard.begin({'method': 'open'})
        with self.assertRaisesRegex(RuntimeError, 'saving refused'):
            self.guard.save_database()
        self.assertEqual(self.flags, {1, 8})

    def test_disconnected_release_rechecks_before_last_auxiliary_close(self):
        self.checked_guard()
        import threading
        import time
        from unittest.mock import Mock
        from ida_nexus import RemoteError
        sys.path.insert(0,str(Path(__file__).resolve().parent/'support'))
        from release_wrapper import install
        directory = Path(__file__).resolve().parents[1] / 'nexus_bridge'
        with patch.object(sys, 'path', [str(directory), *sys.path]):
            import bridge
        lease = {'lease_id': 'exact', 'instance_id': 'owner', 'generation': 1}
        private = Path(tempfile.mkdtemp(dir=os.environ['R3A_CASE_ROOT'], prefix='r9-release-'))
        target = private/'input.i64'
        target.write_bytes(b'private owner input')
        instance = types.SimpleNamespace(record_id='owner',backend='idalib',pid=os.getpid(),started_at=time.time(),idb_path=str(target))
        for loss in (False, True):
            with self.subTest(root_loss_after_primary_release=loss):
                self.guard._state = None
                self.present = True
                self.flags.clear()
                self.guard.begin({'method': 'open'})
                primary = Mock(connected=False, instance=instance)
                auxiliary = Mock(connected=True, instance=instance)
                auxiliary.close_outcome.return_value = {'status': 'lease_released', 'lease_released': True, 'shutdown_pending': False}
                def execute(source, **kwargs):
                    namespace = {}
                    exec(source, namespace)
                    return {'result': namespace.get('result')}
                auxiliary.execute_python.side_effect = execute
                def release(**kwargs):
                    self.assertTrue(self.present, 'original release must be checked while healthy')
                    self.present = not loss
                    return {'status': 'lease_released', 'lease_released': True, 'shutdown_pending': False}
                primary.close_outcome.side_effect = release
                owner = bridge.Bridge.__new__(bridge.Bridge)
                owner.identity, owner.lifetime_path = 'bridge', '/lifetime'
                owner.lock = threading.Lock()
                owner.handles = {'exact': (lease, primary)}
                owner.cleanup_handles, owner.metadata_contexts, owner.custodians = {}, {}, {}
                owner.Handle = types.SimpleNamespace(attach=lambda _: auxiliary)
                owner.drop_lifetime = Mock()
                _, child = install(owner,lease,primary,auxiliary)
                messages=[]
                api = types.SimpleNamespace(
                    RemoteError=RemoteError,
                    get_state_dir=lambda: Path(os.environ['IDA_NEXUS_STATE_DIR']),
                    discover_databases=lambda: [types.SimpleNamespace(instance=instance)],
                    wait_database_released=Mock(side_effect=AssertionError('unexpected lifetime wait')))
                loader = sys.modules['ida_loader']
                with patch.dict(sys.modules, {'ida_nexus': api, '_ida_cli_save_guard_v1': self.guard}), \
                        patch.object(loader, 'set_database_flag', side_effect=OSError('cannot protect close')):
                    try:
                        owner.invoke(types.SimpleNamespace(send=messages.append),{'sequence':1},
                            {'command':'release','lease':lease},time.monotonic()+15,[False])
                        owner.invoke(types.SimpleNamespace(send=messages.append),{'sequence':2},
                            {'command':'release','lease':child.lease},time.monotonic()+15,[False])
                    finally:
                        owner.detach_pool.shutdown(wait=True)
                    self.assertEqual(messages[0]['event'],'released','primary parsed ACK must remain valid')
                    if loss:
                        self.assertEqual(messages[-1]['event'],'not_sent')
                        self.assertIn('protection',messages[-1]['error']['message'])
                        auxiliary.close_outcome.assert_not_called()
                        self.assertIs(owner.handles[child.lease['lease_id']][1],auxiliary)
                        self.assertNotIn('exact',owner.handles,'primary is already detached')
                    else:
                        self.assertEqual(messages[-1]['event'],'released')
                        auxiliary.close_outcome.assert_called_once()
                        self.assertEqual(owner.handles,{})
                    auxiliary.close.assert_not_called()
                    api.wait_database_released.assert_not_called()
                primary.close_outcome.assert_called_once()

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
        self.checked_guard()
        directory = Path(__file__).resolve().parents[1] / 'nexus_bridge'
        spec = importlib.util.spec_from_file_location('guard_bridge', directory/'bridge.py')
        bridge = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'path', [str(directory), *sys.path]):
            spec.loader.exec_module(bridge)
        code = bridge.guarded_source('from __future__ import annotations\nresult = 42', {'method': 'execute_python'})
        namespace = {}
        with patch.dict(sys.modules, {'_ida_cli_save_guard_v1': self.guard}):
            exec(code, namespace)
        self.assertEqual(namespace['result'], 42)
        self.assertEqual(self.guard._state['operation']['method'], 'execute_python')
        self.assertEqual(self.guard._state['last_sample']['stage'], 'after',
            'actual guard begin/finish must surround the future-import source')



if __name__ == '__main__':
    unittest.main()
