"""Real process exits inside durable writes, followed by fresh-process recovery."""
import os
from pathlib import Path
import sys
import unittest

import r0_common
from r0_common import durable, fork, read
from r0_records import Store

ROOT = Path(os.environ['R0_CASE_ROOT'])
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)


def recover(path):
    store = Store(path)
    snapshot = read(path / 'snapshot.json')
    store.compact()
    store.compact()
    assert (path / 'routine/1.json').read_text() == snapshot['live']
    assert (path / 'retained/1.json').read_text() == snapshot['retained']
    assert store.event(1) == 'Active'
    assert store.event(2) == 'AlreadyClosed'
    assert read(path / 'state.json')['active'] == {'1': 'routine'}
    assert not list(path.glob('*.new*'))
    for _ in range(4):
        for _ in range(5):
            store.allocate()
        store.compact()
    assert len(list((path / 'routine').glob('*.json'))) == 1
    assert len(read(path / 'summary.json')['closed_after_holes']) == 1
    assert not list(path.rglob('*.new*'))


class DurablePrototypes(unittest.TestCase):
    def child(self, *args):
        pid = fork()
        if pid == 0:
            os.execv(sys.executable, [sys.executable, '-B', __file__, *map(str, args)])
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])

    def test_internal_write_crashes_resume_from_new_process(self):
        rows = []
        for target in ('summary.json', 'intent.json', 'state.json'):
            for stage in ('temp_written', 'file_fsynced', 'before_rename', 'after_rename', 'directory_fsynced'):
                with self.subTest(target=target, stage=stage):
                    path = ROOT / (target + '-' + stage)
                    store = Store(path)
                    store.allocate(['live-reference'], closed=False)
                    store.allocate()
                    store.allocate()
                    store.retain_failure({'result': 'UnknownOutcome', 'NeverReplay': True})
                    durable(path / 'snapshot.json', {'live': (path / 'routine/1.json').read_text(),
                        'retained': (path / 'retained/1.json').read_text()})
                    self.assertEqual(self.child('--crash', path, target, stage), 96)
                    self.assertEqual(self.child('--recover', path), 0)
                    rows.append({'target': target, 'internal_boundary': stage,
                                 'crash_exit': 96, 'fresh_recovery_exit': 0, 'waited': True})
        durable(ROOT / 'durable-results.json', rows)

    def test_unknown_conflicting_symlink_and_permissions_preserved(self):
        rows = []
        for kind in ('conflict', 'partial', 'symlink', 'mode', 'hardlink', 'unknown-exact'):
            with self.subTest(kind=kind):
                folder = ROOT / ('unknown-' + kind)
                folder.mkdir()
                target, temp = folder / 'state.json', folder / 'state.json.new'
                target.write_text('old')
                if kind == 'symlink':
                    temp.symlink_to(target)
                else:
                    temp.write_bytes(b'{"new": true}' if kind in ('mode', 'hardlink', 'unknown-exact') else b'{' if kind == 'partial' else b'foreign')
                    temp.chmod(0o644 if kind == 'mode' else 0o600)
                    if kind == 'hardlink':
                        os.link(temp, folder / 'alias')
                before = temp.lstat()
                with self.assertRaises((RuntimeError, OSError)):
                    durable(target, {'new': True})
                self.assertEqual(temp.lstat().st_ino, before.st_ino)
                self.assertEqual(target.read_text(), 'old')
                rows.append({'input': kind, 'rejected': True, 'preserved': True})
        durable(ROOT / 'durable-rejections.json', rows)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--crash':
        path, target, stage = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
        def barrier(actual, boundary):
            if actual == path / target and boundary == stage:
                os._exit(96)
        r0_common.durable_boundary = barrier
        Store(path).compact()
        raise AssertionError('internal fault barrier not reached')
    elif len(sys.argv) > 1 and sys.argv[1] == '--recover':
        recover(Path(sys.argv[2]))
    else:
        unittest.main(verbosity=2)
