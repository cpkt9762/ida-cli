"""Count production binding/admission work; no elapsed-time assertions."""
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'nexus_bridge')]
import origin
import target_coordination as coordination


class MountCache(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ['R3A_CASE_ROOT'])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for cache in (origin._scopes, coordination._capabilities):
            isolated = patch.dict(cache, {}, clear=True)
            isolated.start()
            self.addCleanup(isolated.stop)

    def target(self, name):
        path = self.root/name
        path.write_bytes(b'private database input')
        return path

    def counts(self, action):
        mkdir = os.mkdir
        probes = []
        def create(name, *args, **kwargs):
            if str(name).startswith('.ida-cli-cap-probe-'):
                probes.append(str(name))
            return mkdir(name, *args, **kwargs)
        with patch.object(subprocess, 'Popen', wraps=subprocess.Popen) as children, \
                patch.object(os, 'mkdir', side_effect=create):
            action()
        return {'subprocesses': children.call_count, 'probe_directories': len(probes)}

    def bind(self, path):
        with coordination.Target(path, for_open=True) as target, target.locked():
            return target.directory.read('volume.json')[0]

    def test_second_binding_has_no_subprocess_or_probe_directory(self):
        first, second = self.target('first.i64'), self.target('second.i64')
        warm = self.counts(lambda: self.bind(first))
        self.assertGreater(warm['probe_directories'], 0)
        observed = self.counts(lambda: self.bind(second))
        print({'second_binding': observed}, flush=True)
        self.assertEqual(observed, {'subprocesses': 0, 'probe_directories': 0})

    def test_second_admission_has_no_subprocess_or_probe_directory(self):
        path = self.target('input.i64')
        warm = self.counts(lambda: coordination.preflight_capabilities(path))
        self.assertGreater(warm['probe_directories'], 0)
        observed = self.counts(lambda: coordination.preflight_capabilities(path))
        print({'second_admission': observed}, flush=True)
        self.assertEqual(observed, {'subprocesses': 0, 'probe_directories': 0})

    def test_different_mount_with_reused_device_recollects_scope_and_capabilities(self):
        path = self.target('input.i64')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        mounted = coordination.native_mount(fd)
        changed = dict(mounted, fsid=[mounted['fsid'][0], mounted['fsid'][1] + 1])
        with patch.object(coordination, 'native_mount', return_value=mounted):
            coordination.preflight_capabilities(path)
            first = origin.creation_scope(self.root, 'first')
        with patch.object(coordination, 'native_mount', return_value=changed):
            observed = self.counts(lambda: coordination.preflight_capabilities(path))
            with patch.object(origin, 'native_scope', wraps=origin.native_scope) as collect:
                second = origin.creation_scope(self.root, 'second')
            self.assertEqual(collect.call_count, 1)
        self.assertEqual(first['device'], second['device'])
        self.assertEqual(observed['probe_directories'], 1)
        self.assertEqual(observed['subprocesses'], 0)

    def test_stable_unsupported_capability_is_cached_but_transient_failure_is_not(self):
        import recovery_files
        path = self.target('input.i64')
        with patch.object(recovery_files, 'rename_noreplace',
                side_effect=OSError(errno.ENOTSUP, 'unsupported filesystem input')):
            with self.assertRaises(coordination.FilesystemCapabilityError) as first:
                coordination.preflight_capabilities(path)
        def refuse_again():
            with self.assertRaises(coordination.FilesystemCapabilityError) as second:
                coordination.preflight_capabilities(path)
            self.assertEqual(first.exception.details, second.exception.details)
        self.assertEqual(self.counts(refuse_again), {'subprocesses': 0, 'probe_directories': 0})
        coordination._capabilities.clear()
        with patch.object(os, 'write', side_effect=OSError(errno.ENOSPC, 'transient input')):
            with self.assertRaises(coordination.FilesystemCapabilityError):
                coordination.preflight_capabilities(path)
        self.assertEqual(coordination._capabilities, {})
        self.assertTrue(coordination.preflight_capabilities(path)['supported'])


if __name__ == '__main__':
    unittest.main()
