"""Production target writer exits and fresh-process recovery; no IDA/OS proof model."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'nexus_bridge')]
from target_coordination import Target
from target_journal import Journal


def crash(target_path, boundary):
    with Target(target_path) as target, target.locked():
        journal = Journal(target)
        journal.value['revision'] = 41
        actual_replace, actual_fsync = os.replace, os.fsync

        def replace(source, destination, **options):
            if destination == 'custody.json' and boundary == 'before_rename':
                os._exit(96)
            result = actual_replace(source, destination, **options)
            if destination == 'custody.json' and boundary == 'after_rename':
                os._exit(96)
            return result

        def fsync(fd):
            result = actual_fsync(fd)
            if boundary == 'file_fsynced':
                try:
                    pending = os.stat('custody.json.new', dir_fd=target.directory.fd, follow_symlinks=False)
                except FileNotFoundError:
                    return result
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) == (pending.st_dev, pending.st_ino):
                    os._exit(96)
            return result

        os.replace, os.fsync = replace, fsync
        journal.save()
    raise AssertionError('actual production durable boundary not reached')


def recover(target_path):
    with Target(target_path) as target, target.locked():
        journal = Journal(target)
        journal.gate()
        assert journal.value['revision'] == 42, journal.value
        assert not list(target.directory.path.glob('*.new*'))


class DurableRecovery(unittest.TestCase):
    def test_pending_journal_authorization_is_checked_before_publication(self):
        import copy
        from unittest.mock import patch
        from target_journal import require_verification_scope, verification_scope
        from durable_records import boundary
        self.assertTrue(callable(boundary))
        parent = dict(client_id='pending-scope',request_id='pending-scope',operation_id='pending-scope',task_id=None)
        for variant in ('missing','foreign-parent','conflict','wrong-coordinate'):
            with self.subTest(variant=variant):
                root = Path(tempfile.mkdtemp(prefix='pending-scope-',dir=os.environ['R3A_CASE_ROOT']))
                target_path = root/'probe.i64'
                target_path.write_bytes(b'preserve pending authorization')
                with Target(target_path) as target, target.locked():
                    verification_scope(target,parent)
                    candidate = copy.deepcopy(Journal(target).value)
                    if variant == 'missing':candidate.pop('verification_scope')
                    elif variant == 'foreign-parent':candidate['verification_scope']['parent']['operation_id']='foreign'
                    elif variant == 'conflict':candidate['verification_cleanup_conflict']=True
                    else:candidate['coord_key']={'kind':'foreign'}
                    def interrupted(_directory,name,stage):
                        if name=='custody.json' and stage=='before_rename':
                            raise RuntimeError('controlled completed pending write')
                    with patch('durable_records.boundary',interrupted):
                        with self.assertRaisesRegex(RuntimeError,'controlled completed pending write'):
                            target.directory.durable('custody.json',candidate)
                    names=('custody.json','custody.json.new','custody.json.new.owner')
                    before={name:(target.directory.path/name).read_bytes() for name in names}
                    with self.assertRaises(RuntimeError):
                        require_verification_scope(target,parent)
                    self.assertEqual({name:(target.directory.path/name).read_bytes() for name in names},before)

    def test_known_pending_write_resumes_through_fresh_target_gate(self):
        root = Path(tempfile.mkdtemp(prefix='durable-', dir=os.environ['R3A_CASE_ROOT']))
        for boundary in ('file_fsynced', 'before_rename', 'after_rename'):
            with self.subTest(boundary=boundary):
                folder = root/boundary
                folder.mkdir(mode=0o700)
                target_path = folder/'input.i64'
                target_path.write_bytes(b'private target stays unchanged')
                with Target(target_path) as target, target.locked():
                    Journal(target).save()
                results = []
                for mode, expected in (('--crash', 96), ('--recover', 0)):
                    argv = ['timeout', '10s', sys.executable, '-B', __file__, mode, str(target_path), boundary]
                    before = subprocess.check_output(['uptime'], text=True).strip()
                    result = subprocess.run(argv, capture_output=True, text=True, check=False)
                    after = subprocess.check_output(['uptime'], text=True).strip()
                    results.append(dict(argv=argv, exit=result.returncode, stdout=result.stdout,
                                        stderr=result.stderr, uptime_before=before, uptime_after=after))
                    (folder/'results.json').write_text(json.dumps(results, indent=2))
                    self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(target_path.read_bytes(), b'private target stays unchanged')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--crash':
        crash(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) > 1 and sys.argv[1] == '--recover':
        recover(Path(sys.argv[2]))
    else:
        unittest.main(verbosity=2)
