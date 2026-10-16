"""Diagnostic failures preserve business results; full hashes require opt-in."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('Q1Q2_SOURCE', REPO/'nexus_bridge'))


def load(name):
    spec = importlib.util.spec_from_file_location('q_' + name, SOURCE/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def modules():
    attrs = {
        'ida_idaapi': dict(BADADDR=2**64-1),
        'ida_funcs': dict(get_func_qty=lambda: 0),
        'ida_ida': dict(inf_get_filetype=lambda: 0, inf_get_baseaddr=lambda: 0,
            inf_get_main=lambda: 2**64-1, inf_is_64bit=lambda: True,
            inf_get_min_ea=lambda: 0, inf_get_max_ea=lambda: 1),
        'ida_nalt': dict(retrieve_input_file_md5=lambda: None,
            retrieve_input_file_sha256=lambda: None, get_input_file_path=lambda: '',
            retrieve_input_file_size=lambda: 0, get_root_filename=lambda: ''),
        'ida_loader': dict(PATH_TYPE_IDB=0, get_path=lambda _: ''),
        'ida_auto': dict(auto_is_ok=lambda: True, get_auto_state=lambda: 0),
        'ida_nexus': dict(discover_databases=lambda **_: []),
    }
    return {name: types.SimpleNamespace(**attrs.get(name, {})) for name in
        (*attrs, 'ida_idp', 'idautils', 'idc')}


class Diagnostics(unittest.TestCase):
    def setUp(self):
        self.metadata = load('metadata')
        self.tools = load('tools')
        self.tools.processor_name = lambda: 'stub processor'
        self.stubs = modules()
        self.patch = patch.dict(sys.modules, self.stubs)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        # The completed business result without diagnostic work is the contract.
        self.tools.install_tools({'warn_missing_input_metadata': lambda *_: None})
        self.expected = self.tools.invoke('get_database_info', {})
        self.assertTrue(self.expected['ok'])
        self.assertEqual(self.expected['value']['md5'], '0' * 32)
        self.tools.install_tools({'warn_missing_input_metadata': self.metadata.warn_missing_input_metadata})

    def check_warning(self):
        with self.assertLogs('ida_cli.metadata', level='WARNING') as logs:
            result = self.tools.invoke('get_database_info', {})
        self.assertEqual(result, self.expected)
        return '\n'.join(logs.output)

    def test_diagnostic_getters_preserve_result_and_record_error(self):
        for module, getter in [('ida_loader', 'get_path'), ('ida_auto', 'auto_is_ok'),
                               ('ida_auto', 'get_auto_state')]:
            with self.subTest(getter=getter), patch.object(
                    self.stubs[module], getter, side_effect=RuntimeError('diagnostic getter')):
                self.assertIn('RuntimeError', self.check_warning())

    def test_serialization_failure_preserves_result_and_warns(self):
        with patch('json.dumps', side_effect=TypeError('diagnostic serialization')):
            self.assertIn('TypeError', self.check_warning())

    def test_unexpected_sampler_failure_preserves_result_and_warns(self):
        with patch.object(self.metadata, 'input_metadata_evidence', side_effect=ValueError('sample')):
            self.assertIn('ValueError', self.check_warning())

    def test_business_getter_failure_is_not_downgraded(self):
        with patch.object(self.stubs['ida_nalt'], 'retrieve_input_file_size',
                          side_effect=RuntimeError('business getter')):
            with self.assertRaisesRegex(RuntimeError, 'business getter'):
                self.tools.invoke('get_database_info', {})

    def test_installation_still_fails_when_capability_missing(self):
        with self.assertRaisesRegex(RuntimeError, 'requires callable'):
            self.tools.install_tools({})
        with self.assertRaisesRegex(RuntimeError, 'not installed'):
            self.tools.invoke('get_database_info', {})

    def test_default_diagnostic_disk_context_does_not_read_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'missing-metadata.i64'
            path.write_bytes(b'private fixture')
            with patch.object(self.stubs['ida_loader'], 'get_path', return_value=str(path)), \
                    patch.object(Path, 'open', side_effect=AssertionError('unexpected full read')):
                evidence = self.metadata.input_metadata_evidence()
            self.assertEqual(evidence['disk_now']['size'], 15)
            self.assertNotIn('sha256', evidence['disk_now'])


class OpenFingerprints(unittest.TestCase):
    def check_open(self, enabled):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                sys, 'path', [str(SOURCE), *sys.path]), patch.dict(
                    sys.modules, {'ida_nexus': types.SimpleNamespace(discover_databases=lambda: [])}):
            bridge = load('bridge')
            path = Path(directory)/'normal.i64'
            payload = b'private packed fixture'
            path.write_bytes(payload)
            instance = types.SimpleNamespace(record_id='owner', backend='idalib', pid=123,
                idb_path=str(path))
            handle = types.SimpleNamespace(instance=instance, recovery=None,
                set_disconnect_callback=lambda _: None,
                execute_python=lambda *_, **__: {'result': '9.5'})
            owner = object.__new__(bridge.Bridge)
            owner.Handle = types.SimpleNamespace(open=lambda *_, **__: handle)
            owner.Options = lambda **kwargs: kwargs
            owner.lock = threading.Lock()
            owner.generations, owner.handles, owner.metadata_contexts = {}, {}, {}
            events, reads = [], []
            original = Path.open

            def track(target, *args, **kwargs):
                if target == path and (args[0] if args else kwargs.get('mode', 'r')) == 'rb':
                    reads.append(str(target))
                    self.assertTrue(enabled, 'normal open must not read packed bytes')
                return original(target, *args, **kwargs)

            env = {'IDA_CLI_HOME': directory}
            if enabled:
                env['IDA_CLI_NEXUS_FORENSIC_HASH'] = '1'
            with patch.dict(os.environ, env, clear=True), patch.object(Path, 'open', track), \
                    patch.object(bridge, 'readiness', return_value={'capabilities': {'runtime': {}}}):
                for _ in range(2):
                    owner.invoke(types.SimpleNamespace(send=events.append), {},
                        {'command': 'open', 'path': str(path),
                         'identity': {'client_id': 'client'}, 'options': {}},
                        time.monotonic()+5, [False])
            self.assertEqual([e['event'] for e in events], ['opened', 'opened'])
            self.assertEqual(len(reads), 2 if enabled else 0)
            for context in owner.metadata_contexts.values():
                before = context['before_open']
                self.assertEqual(before['size'], len(payload))
                self.assertEqual(before['inode'], path.stat().st_ino)
                self.assertEqual(before['mtime_ns'], path.stat().st_mtime_ns)
                if enabled:
                    self.assertEqual(before['sha256'], hashlib.sha256(payload).hexdigest())
                else:
                    self.assertNotIn('sha256', before)

    def test_normal_open_uses_stat_without_reading_file(self):
        self.check_open(False)

    def test_explicit_forensic_mode_reads_and_hashes_file(self):
        self.check_open(True)


if __name__ == '__main__':
    unittest.main()
