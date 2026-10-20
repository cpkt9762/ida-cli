"""GC only accepts the exact retained DSC bundle declared by its manifest."""
import hashlib
import importlib.util
import os
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'nexus_bridge'))
if os.environ.get('N7B_BASELINE_STORE'):
    spec = importlib.util.spec_from_file_location('baseline_store', os.environ['N7B_BASELINE_STORE'])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    Store = module.Store
else:
    from cache_store import Store


class DscBundle(unittest.TestCase):
    def test_exact_bundle_is_managed_but_unknown_or_replaced_members_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            group = root/'generations/example'
            group.mkdir(parents=True)
            (group/'input').write_bytes(b'identity')
            (group/'input.i64').write_bytes(b'packed fixture')
            bundle = group/'dsc-inputs'
            bundle.mkdir()
            member = bundle/'dyld_shared_cache_arm64e'
            member.write_bytes(b'snapshot')
            manifest = {'version': 1, 'key': 'test', 'dsc_inputs': {
                member.name: hashlib.sha256(member.read_bytes()).hexdigest()}}
            (group/'generation.json').write_text(json.dumps(manifest))
            store = Store(root, probe=lambda _: None)
            self.assertIsNone(store.check(group))
            (bundle/'foreign').touch()
            self.assertIsNotNone(store.check(group))
            (bundle/'foreign').unlink()
            member.unlink()
            member.symlink_to(group/'input')
            self.assertIsNotNone(store.check(group))


if __name__ == '__main__':
    unittest.main()
