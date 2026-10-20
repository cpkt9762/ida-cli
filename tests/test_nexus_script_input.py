"""The owner-side script adapter requires resolved code, including explicit empty code."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


class ScriptAdapterTests(unittest.TestCase):
    def test_missing_or_null_code_is_an_error_and_empty_code_is_explicit(self):
        spec = importlib.util.spec_from_file_location('script_tools', REPO/'nexus_bridge/tools.py')
        tools = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tools)
        names = ('ida_auto','ida_funcs','ida_ida','ida_idaapi','ida_nalt','idautils','idc')
        with patch.dict(sys.modules,{name:types.ModuleType(name) for name in names}):
            for params in ({}, {'file':'not-resolved.py'}, {'code':None}):
                with self.subTest(params=params):
                    value = tools.invoke('run_script',params)
                    self.assertFalse(value['ok'])
                    self.assertIn("requires resolved 'code'",value['error'])
            value = tools.invoke('run_script',{'code':''})
            self.assertTrue(value['ok'])
            self.assertTrue(value['value']['success'])
            self.assertEqual(value['value']['stdout'],'')


if __name__ == '__main__':
    unittest.main()
