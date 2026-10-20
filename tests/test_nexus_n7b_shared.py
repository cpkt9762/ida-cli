"""Shared DSC GC reference accounting with real files/locks and no public owners."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]/'nexus_bridge/cache_store.py'
spec = importlib.util.spec_from_file_location('shared_cache', SOURCE)
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


def identity(meta):
    return dict(dev=meta.st_dev, ino=meta.st_ino, size=meta.st_size,
                mtime_ns=meta.st_mtime_ns, ctime_ns=meta.st_ctime_ns,
                uid=meta.st_uid, mode=meta.st_mode & 0o7777, nlink=meta.st_nlink)


class SharedMembers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.digest = hashlib.sha256(b'shared private member').hexdigest()
        store = self.root/'dsc-members'
        store.mkdir(mode=0o700)
        self.object = store/self.digest
        self.object.mkdir(mode=0o700)
        self.data = self.object/'data'
        self.data.write_bytes(b'shared private member')
        self.data.chmod(0o400)
        receipt = self.object/'verified.json'
        receipt.write_text(json.dumps({'version': 1, 'sha256': self.digest,
                                      'identity': identity(self.data.stat())}))
        receipt.chmod(0o600)
        self.clock = 100.0
        self.store = cache.Store(self.root, grace=1, epoch='b1', probe=lambda _: None,
                                 clock=lambda: self.clock)

    def group(self, name):
        group = self.root/'generations'/name
        group.mkdir(parents=True)
        (group/'dsc-inputs').mkdir()
        os.link(self.data, group/'dsc-inputs/cache')
        (group/'input').write_bytes(b'identity')
        (group/'input.i64').write_bytes(b'packed private database')
        (group/'generation.json').write_text(json.dumps({
            'version': 1, 'key': name, 'dsc_store': 1,
            'dsc_inputs': {'cache': self.digest}}))
        return group

    def delete(self, name):
        self.store.collect(0, key=name)
        self.clock += 2
        result = self.store.collect(0, key=name)
        self.assertEqual(result['evicted_groups'], 1, result)
        return result

    def test_second_generation_reference_survives_first_gc_then_last_reference_reclaims(self):
        self.group('a')
        second = self.group('b')
        self.delete('a')
        self.assertTrue(self.data.exists())
        self.assertEqual(self.data.stat().st_nlink, 2)
        self.assertEqual((second/'dsc-inputs/cache').read_bytes(), b'shared private member')
        self.delete('b')
        self.assertFalse(self.object.exists(), 'no generation references remain')

    def test_incomplete_or_external_hardlink_is_an_additional_reference(self):
        held = self.root/'incomplete-input'
        os.link(self.data, held)
        self.store.collect(0)
        self.assertTrue(self.data.exists())
        held.unlink()
        self.store.collect(0)
        self.assertFalse(self.object.exists())

    def test_unknown_manifest_or_unregistered_object_never_authorizes_deletion(self):
        bad = self.root/'generations/bad'
        bad.mkdir(parents=True)
        (bad/'generation.json').write_text('{')
        self.store.collect(0)
        self.assertTrue(self.data.exists())
        (bad/'generation.json').unlink()
        bad.rmdir()
        (self.object/'verified.json').unlink()
        self.store.collect(0)
        self.assertTrue(self.data.exists())

    def test_replaced_object_is_refused_and_not_deleted(self):
        group = self.group('a')
        self.data.unlink()
        self.data.write_bytes(b'foreign object')
        self.data.chmod(0o400)
        self.assertIsNotNone(self.store.check(group))
        self.store.collect(0)
        self.assertEqual(self.data.read_bytes(), b'foreign object')
        self.assertTrue(group.exists())

    def test_symlink_object_or_member_is_refused(self):
        group = self.group('a')
        self.data.unlink()
        self.data.symlink_to(group/'input')
        self.assertIsNotNone(self.store.check(group))
        self.store.collect(0)
        self.assertTrue(self.data.is_symlink())

    def test_shared_store_tag_requires_an_explicit_member_inventory(self):
        group = self.root/'generations/broken'
        group.mkdir(parents=True)
        (group/'input.i64').write_bytes(b'unknown retained database')
        (group/'generation.json').write_text(json.dumps({'version': 1, 'key': 'broken', 'dsc_store': 1}))
        self.store.collect(0)
        self.assertTrue(group.exists(), 'an incomplete new-format manifest cannot authorize isolation')
        self.assertTrue(self.data.exists())


if __name__ == '__main__':
    unittest.main()
