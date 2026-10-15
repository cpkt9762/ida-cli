"""N6 approved comparison exceptions must never weaken unrelated contracts."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("n6_compare", Path(__file__).resolve().parents[1] /
                                             "scripts/compare_nexus_baseline.py")
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


class FieldOrder(unittest.TestCase):
    def setUp(self):
        self.original = {"result": {"nodes": [{"address": "0x10", "name": "a", "size": 1},
                                               {"address": "0x20", "name": "b", "size": 2}],
                                    "edges": [{"from": "0x10", "to": "0x20"},
                                              {"from": "0x20", "to": "0x10"}]}}
        self.changed = copy.deepcopy(self.original)
        self.changed["result"]["nodes"].reverse()

    def equal(self):
        return compare.json_equal(self.original, self.changed, "build_callgraph")

    def test_only_registered_nodes_reordering_is_equal(self):
        self.assertTrue(self.equal())

    def test_all_node_values_and_types_remain_strict(self):
        for field, value in (("name", "changed"), ("size", True), ("size", 2.0), ("extra", 0)):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.changed)
                changed["result"]["nodes"][0][field] = value
                self.assertFalse(compare.json_equal(self.original, changed, "build_callgraph"))

    def test_duplicates_on_either_side_fail_even_if_identical(self):
        duplicate = {"result": {"nodes": [{"address": "x"}, {"address": "x"}]}}
        self.assertFalse(compare.json_equal(duplicate, duplicate, "build_callgraph"))
        self.changed["result"]["nodes"][0]["address"] = "0x10"
        self.assertFalse(self.equal())
        self.assertFalse(compare.json_equal(self.changed, self.original, "build_callgraph"))

    def test_count_and_identity_must_match(self):
        self.changed["result"]["nodes"].pop()
        self.assertFalse(self.equal())
        self.changed = copy.deepcopy(self.original)
        self.changed["result"]["nodes"][0]["address"] = "0x30"
        self.assertFalse(self.equal())

    def test_missing_or_composite_identity_fails(self):
        for node in ({}, {"address": []}, {"address": {}}):
            value = {"result": {"nodes": [node]}}
            self.assertFalse(compare.json_equal(value, value, "build_callgraph"))

    def test_unregistered_method_path_and_edges_stay_ordered(self):
        self.assertFalse(compare.json_equal(self.original, self.changed))
        self.assertFalse(compare.json_equal(self.original, self.changed, "other"))
        self.assertFalse(compare.json_equal(self.original["result"], self.changed["result"], "build_callgraph"))
        self.changed["result"]["edges"].reverse()
        self.assertFalse(self.equal())


if __name__ == "__main__":
    unittest.main()
