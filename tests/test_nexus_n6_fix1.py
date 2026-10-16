"""N6-F1 edge contracts; real IDA counterparts live in the N6 comparison."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / 'nexus_bridge' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Compatibility(unittest.TestCase):
    def test_e22_failure_always_persists_public_diagnostics(self):
        spec = importlib.util.spec_from_file_location('compare_failure', REPO / 'scripts/compare_nexus_baseline.py')
        comparison = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(comparison)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'home-e22-match-1/idb/copy.i64'
            target.parent.mkdir(parents=True)
            target.write_bytes(b'isolated')
            diagnostics = types.SimpleNamespace(database_diagnostics=lambda path: {'target': str(path), 'lifetime': 'held'})
            args = ['compare', '--root', str(root), '--baseline', 'baseline', '--binary', 'binary', '--case', 'E22']
            with patch.object(sys, 'argv', args), patch.dict(os.environ, {'IDA_TEST': '1'}), \
                    patch.object(comparison, 'digest', return_value=comparison.BASELINE_SHA), \
                    patch.object(comparison, 'Environment', return_value=types.SimpleNamespace(root=root)), \
                    patch.object(comparison, 'legacy_cache', side_effect=RuntimeError('injected WorkerStartError')), \
                    patch.dict(sys.modules, {'lifecycle': diagnostics}):
                with self.assertRaisesRegex(RuntimeError, 'WorkerStartError'):
                    comparison.main()
            self.assertEqual(json.loads((root / 'E22-result.json').read_text())['status'], 'FAIL')
            saved = json.loads((root / 'E22-failure-diagnostics.json').read_text())
            self.assertEqual(saved['targets'], [{'target': str(target), 'lifetime': 'held'}])

    def test_handler_address_uses_rust_whitespace_and_u64_grammar(self):
        query = load('query_tools')
        parse = load('tools').parse_address
        for char in '\x1c\x1d\x1e\x1f':
            self.assertIsNone(query.handler_address(char + '16', parse))
        for prefix, digits in [('', '16'), ('0x', '10'), ('0b', '10000'), ('0o', '20')]:
            self.assertEqual(query.handler_address('\u2003' + prefix + '+' + '0' * 5000 + digits + '\u3000', parse), 16)
        for raw in ('1_6', '-1', '18446744073709551616', '0x10000000000000000', '0o2000000000000000000000', '0b' + '1' * 65):
            self.assertIsNone(query.handler_address(raw, parse))

    def test_missing_metadata_has_native_zero_buffers(self):
        attributes = {
            'ida_idaapi': dict(BADADDR=2**64-1),
            'ida_funcs': dict(get_func_qty=lambda: 2),
            'ida_ida': dict(inf_get_filetype=lambda: 25, inf_get_baseaddr=lambda: 0,
                inf_get_main=lambda: 0x100, inf_is_64bit=lambda: True,
                inf_get_min_ea=lambda: 0x100, inf_get_max_ea=lambda: 0x200),
            'ida_nalt': dict(retrieve_input_file_md5=lambda: None,
                retrieve_input_file_sha256=lambda: None, get_input_file_path=lambda: None,
                retrieve_input_file_size=lambda: 0)}
        modules = {name: types.SimpleNamespace(**attributes.get(name, {})) for name in
            ('ida_auto', 'ida_funcs', 'ida_ida', 'ida_idaapi', 'ida_idp', 'ida_loader', 'ida_nalt', 'idautils', 'idc')}
        with patch.dict(sys.modules, modules):
            tools = load('tools')
            tools.processor_name = lambda: 'test processor'
            info = tools.invoke('get_database_info', {})['value']
        self.assertEqual({k: info[k] for k in ('input_file_path', 'input_file_size', 'md5', 'sha256')},
            dict(input_file_path='', input_file_size=0, md5='0'*32, sha256='0'*64))

    def test_existing_function_without_frame_preserves_error_result(self):
        modules = dict(ida_funcs=types.SimpleNamespace(get_func=lambda ea: object()),
            ida_typeinf=types.SimpleNamespace(tinfo_t=lambda: object(), udt_type_data_t=lambda: [],
                GTD_CALC_LAYOUT=0, TERR_BAD_TYPE=-5, TERR_BAD_ARG=-4, TERR_NOT_FOUND=-38),
            ida_frame=types.SimpleNamespace(get_func_frame=lambda tif, pfn: False))
        with patch.dict(sys.modules, modules):
            tools = load('type_tools')
            for method, params, code in [('delete_stack_variable', {'var_name':'slot'}, -4),
                    ('apply_type', {'stack_name':'slot', 'decl':'int'}, -5)]:
                with self.subTest(method=method):
                    self.assertEqual(tools.stack_edit(method, 0x100, params),
                        dict(function='0x100', name='slot', offset=0, code=code, status='error'))


if __name__ == '__main__':
    unittest.main()
