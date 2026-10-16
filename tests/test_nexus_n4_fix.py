"""N4-F1 deterministic business and comparison regressions (no IDA runtime)."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tools = load("n4_tools", "nexus_bridge/tools.py")
# The owner evaluates metadata.py and tools.py in one namespace, as bridge.py
# does. Keep this isolated business fixture faithful to that composition.
metadata = load("n4_metadata", "nexus_bridge/metadata.py")
tools.warn_missing_input_metadata = metadata.warn_missing_input_metadata
compare = load("n4_compare", "scripts/compare_nexus_baseline.py")


class Business(unittest.TestCase):
    def setUp(self):
        names = ("ida_auto ida_funcs ida_ida ida_idaapi ida_idp ida_loader "
                 "ida_nalt idautils idc ida_hexrays ida_kernwin").split()
        names.append("ida_lines")
        self.modules = {name: types.ModuleType(name) for name in names}
        self.context = patch.dict(sys.modules, self.modules)
        self.context.start()
        self.addCleanup(self.context.stop)

    def test_p25_decompile_array_retains_per_item_failure(self):
        self.modules["ida_hexrays"].init_hexrays_plugin = lambda: True
        self.modules["ida_funcs"].get_func = lambda ea: ea
        self.modules["ida_hexrays"].hexrays_failure_t = lambda: None
        self.modules["ida_hexrays"].DECOMP_NO_WAIT = 1
        self.modules["ida_hexrays"].DECOMP_NO_CACHE = 2
        def decompile(ea, *_):
            if ea == 16:
                raise RuntimeError("injected native decompiler failure")
            return "int good() { return 1; }"
        self.modules["ida_lines"].tag_remove = lambda text: text
        original = decompile
        def cfunc(ea, *args):
            text = original(ea, *args)
            return types.SimpleNamespace(get_pseudocode=lambda: [types.SimpleNamespace(line=text)])
        self.modules["ida_hexrays"].decompile = cfunc
        result = tools.invoke("decompile_function", {"address": [16, 32]})
        self.assertEqual(result, {"ok": True, "value": {"results": [
            {"address": "0x10", "error": "IDA error: injected native decompiler failure"},
            {"address": "0x20", "code": "int good() { return 1; }\n"}]}})

    def test_p26_error_is_truncated_before_summary(self):
        result = tools.invoke("run_script", {"code": "raise ValueError('x' * (1024*1024+1))"})["value"]
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "x" * (1024*1024) + "\n... [truncated at 1MB]")
        self.assertEqual(result["error_summary"], result["error"])

    def test_p26_nul_error_matches_native_c_string(self):
        result = tools.invoke("run_script", {"code": "raise ValueError(chr(0)+'hidden')"})["value"]
        self.assertEqual(result, {"success": True, "stdout": "", "stderr": ""})

    def test_processor_unverified_version_keeps_database_info_available(self):
        ida = self.modules["ida_ida"]
        for name, value in {"filetype": 25, "baseaddr": 0, "main": 16, "min_ea": 0,
                            "max_ea": 32, "procname": "metapc"}.items():
            setattr(ida, "inf_get_"+name, lambda value=value: value)
        ida.inf_is_64bit = lambda: True
        self.modules["ida_idaapi"].BADADDR = 2**64-1
        self.modules["ida_funcs"].get_func_qty = lambda: 2
        nalt = self.modules["ida_nalt"]
        nalt.retrieve_input_file_md5 = lambda: b""
        nalt.retrieve_input_file_sha256 = lambda: b""
        nalt.retrieve_input_file_size = lambda: 100
        nalt.get_input_file_path = lambda: "test-copy"
        self.modules["ida_kernwin"].get_kernel_version = lambda: "9.6"
        with self.assertLogs(level="WARNING") as logs:
            result = tools.invoke("get_database_info", {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["value"]["processor"], "metapc")
        self.assertIn("9.6", " ".join(logs.output))


class Comparator(unittest.TestCase):
    def test_p27_json_types_are_strict_recursively(self):
        # Baseline uses Python equality here; the fallback exercises that same
        # public comparison operation until the strict comparator is introduced.
        equal = getattr(compare, "json_equal", lambda a, b: a == b)
        for left, right in [(True, 1), (1, 1.0), (False, 0), ([True], [1]),
                            ({"x": 1}, {"x": 1.0}), (None, "null"), ([], {})]:
            with self.subTest(left=left, right=right):
                self.assertFalse(equal(left, right))
        for value in [None, True, 1, 1.0, "a", [1, True], {"x": [1.0]}]:
            self.assertTrue(equal(value, value))


if __name__ == "__main__":
    unittest.main()
