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


class AllocatedMember(unittest.TestCase):
    def setUp(self):
        self.entity = dict(struct_name="Pair", struct_ordinal=41, member_index=0,
                           member_name="left", member_type="int", member_offset_bits=0,
                           member_size_bits=32)
        self.left = {"result": dict(self.entity, tid="0xff00000000000116", xrefs=[], truncated=False)}
        self.right = copy.deepcopy(self.left)
        self.right["result"]["tid"] = "0xff00000000000117"
        self.witnesses = [dict(repeat_tid=r["result"]["tid"], lookup_tid=r["result"]["tid"],
                               member_ids=[r["result"]["tid"]], entity=copy.deepcopy(self.entity))
                          for r in (self.left, self.right)]

    def equal(self):
        return compare.allocated_member_equal(self.left, self.right, "get_xrefs_to_struct_field", self.witnesses)

    def test_allocated_ids_require_complete_runtime_witnesses(self):
        self.assertFalse(compare.json_equal(self.left, self.right, "get_xrefs_to_struct_field"))
        self.assertTrue(self.equal())
        self.assertFalse(compare.allocated_member_equal(self.left, self.right, "other", self.witnesses))
        self.assertFalse(compare.allocated_member_equal(self.left, self.right, "get_xrefs_to_struct_field", []))

    def test_invalid_duplicate_unstable_or_unusable_ids_fail(self):
        for field, value in (("repeat_tid", "0x9"), ("lookup_tid", "0x9"),
                             ("member_ids", []), ("member_ids", ["0x0"]),
                             ("member_ids", ["0xff00000000000117"] * 2),
                             ("member_ids", ["0xffffffffffffffff"]),
                             ("member_ids", [True]), ("member_ids", ["bogus"])):
            with self.subTest(field=field, value=value):
                witnesses = copy.deepcopy(self.witnesses)
                witnesses[1][field] = value
                self.assertFalse(compare.allocated_member_equal(self.left, self.right, "get_xrefs_to_struct_field", witnesses))
        for tid in ("0x0", "0xffffffffffffffff", "0x10000000000000000", "bad-id", 10):
            right = copy.deepcopy(self.right)
            right["result"]["tid"] = tid
            self.assertFalse(compare.allocated_member_equal(self.left, right, "get_xrefs_to_struct_field", self.witnesses))

    def test_entity_types_semantic_values_and_unregistered_fields_stay_strict(self):
        for field, value in (("member_size_bits", 64), ("member_offset_bits", 1),
                             ("member_index", False), ("member_name", "other"),
                             ("member_type", "long"), ("struct_name", "Other"),
                             ("xrefs", [{"address": "0x123"}]), ("extra_tid", "0x9")):
            with self.subTest(field=field):
                right = copy.deepcopy(self.right)
                right["result"][field] = value
                witnesses = copy.deepcopy(self.witnesses)
                if field in self.entity:
                    witnesses[1]["entity"][field] = value
                self.assertFalse(compare.allocated_member_equal(self.left, right, "get_xrefs_to_struct_field", witnesses))
        self.witnesses[1]["entity"]["member_name"] = "wrong-lookup"
        self.assertFalse(self.equal())


if __name__ == "__main__":
    unittest.main()
