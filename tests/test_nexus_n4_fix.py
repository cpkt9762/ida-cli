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
edit_tools = load("n4_edit_tools", "nexus_bridge/edit_tools.py")
metadata = load("n4_metadata", "nexus_bridge/metadata.py")
# tools.py shares locate_by_name with edit_tools.py via the bridge's concatenated source.
tools.locate_by_name = edit_tools.locate_by_name
tools.install_tools({'warn_missing_input_metadata': metadata.warn_missing_input_metadata})
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

    def test_line_addresses_resolve_only_valid_ctree_items(self):
        cfunc = types.SimpleNamespace(treeitems=[types.SimpleNamespace(ea=0x1010),
            types.SimpleNamespace(ea=0x1000), types.SimpleNamespace(ea=2**64-1)])
        tag = lambda value: "\x01\x28" + f"{value:016x}"
        tagged = "".join(tag(n) for n in (0, 1, 0, 2, 99, 0x80000000, 0x20000000, 2**64-1))
        self.assertEqual(tools.pseudocode_line_addresses(cfunc, tagged), ["0x1000", "0x1010"])
        self.assertEqual(tools.pseudocode_line_addresses(cfunc, "\x03"+tag(0)), [])
        self.assertEqual(tools.pseudocode_line_addresses(cfunc, "\x01\x36"+tag(0)), [])
        self.assertEqual(tools.pseudocode_line_addresses(cfunc, "\x01\x28xyz"), [])

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

    def install_named_functions(self, entries):
        """entries: [(start, name)] in IDA iteration order, 0x10 bytes each."""
        funcs = self.modules["ida_funcs"]
        objs = [types.SimpleNamespace(start_ea=ea, end_ea=ea + 0x10) for ea, _ in entries]
        names = dict(entries)
        funcs.get_func_qty = lambda: len(objs)
        funcs.getn_func = lambda index: objs[index]
        funcs.get_func_name = lambda ea: names.get(ea)
        funcs.get_func = lambda ea: next((f for f in objs if f.start_ea <= ea < f.end_ea), None)
        self.modules["idautils"].Names = lambda: iter(entries)

    def test_function_by_name_prefers_exact_match_over_earlier_substring(self):
        self.install_named_functions([(0x10, "_entrypoint_impl"), (0x20, "_entrypoint")])
        exact = tools.invoke("get_function_by_name", {"name": "_entrypoint"})
        self.assertEqual(exact["value"]["address"], "0x20")
        self.assertEqual(exact["value"]["name"], "_entrypoint")
        fallback = tools.invoke("get_function_by_name", {"name": "entrypoint"})
        self.assertEqual(fallback["value"]["address"], "0x10")
        missing = tools.invoke("get_function_by_name", {"name": "no_such_function"})
        self.assertEqual(missing, {"ok": False, "error": "Function not found: no_such_function"})

    def test_target_name_prefers_exact_function_and_exact_symbol(self):
        self.install_named_functions([(0x10, "_entrypoint_impl"), (0x20, "_entrypoint")])
        result = tools.invoke("get_function_at_address", {"target_name": "_entrypoint"})
        self.assertEqual(result["value"]["start"], "0x20")
        # No function carries the name: the symbol table decides, exact first.
        self.modules["idautils"].Names = lambda: iter([(0x10, "data_sym_old"), (0x20, "data_sym")])
        result = tools.invoke("get_function_at_address", {"target_name": "data_sym"})
        self.assertEqual(result["value"]["start"], "0x20")
        result = tools.invoke("get_function_at_address", {"target_name": "sym_old"})
        self.assertEqual(result["value"]["start"], "0x10")

    def test_batch_rename_current_name_prefers_exact_match(self):
        self.install_named_functions([(0x10, "_entrypoint_impl"), (0x20, "_entrypoint")])
        renamed = []
        sys.modules["ida_name"] = types.ModuleType("ida_name")
        sys.modules["ida_name"].set_name = lambda ea, name, flags: renamed.append((ea, name)) or True
        parse = lambda raw: None
        edit_tools.rename_entry({"current_name": "_entrypoint", "new_name": "a"}, parse)
        edit_tools.rename_entry({"current_name": "entrypoint", "new_name": "b"}, parse)
        self.assertEqual(renamed, [(0x20, "a"), (0x10, "b")])

    def test_exact_symbol_beats_function_substring_for_lookup_and_rename(self):
        # `foo` is a non-function symbol inside function `other`; function
        # `foo_bar` merely contains the query. The exact symbol must win.
        self.install_named_functions([(0x10, "foo_bar"), (0x30, "other")])
        self.modules["idautils"].Names = lambda: iter([(0x10, "foo_bar"), (0x38, "foo")])
        located = tools.invoke("get_function_at_address", {"target_name": "foo"})
        self.assertEqual(located["value"]["start"], "0x30")
        renamed = []
        sys.modules["ida_name"] = types.ModuleType("ida_name")
        sys.modules["ida_name"].set_name = lambda ea, name, flags: renamed.append((ea, name)) or True
        edit_tools.rename_entry({"current_name": "foo", "new_name": "a"}, lambda raw: None)
        self.assertEqual(renamed, [(0x38, "a")])
        # Without an exact symbol the first function substring still wins,
        # and a symbol substring is the last resort.
        edit_tools.rename_entry({"current_name": "oo_b", "new_name": "b"}, lambda raw: None)
        self.assertEqual(renamed[-1], (0x10, "b"))
        self.modules["idautils"].Names = lambda: iter([(0x40, "zzz_sym")])
        edit_tools.rename_entry({"current_name": "zz_s", "new_name": "c"}, lambda raw: None)
        self.assertEqual(renamed[-1], (0x40, "c"))

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
