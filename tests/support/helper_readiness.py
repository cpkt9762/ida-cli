"""Deterministic real helper publication/identity cases shared by the fixture."""
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from proof_helper import request

REPO = Path(__file__).resolve().parents[2]


def bind_window_case(self, fault=None):
    from unittest.mock import patch
    from types import SimpleNamespace
    import select
    import socket
    real_popen, real_lstat = subprocess.Popen, Path.lstat
    bound_r, bound_w = os.pipe()
    release_r, release_w = os.pipe()
    endpoint = self.root/'h'
    helper = REPO/'nexus_bridge/custody/proof_helper.py'
    child = None
    armed = False
    released = False
    evidence = {}
    replacement = None
    replacement_inode = None

    def release():
        nonlocal released
        if not released:
            os.write(release_w, b'x')
            os.close(release_w)
            released = True

    def spawn(argv, **options):
        nonlocal child, armed
        self.assertEqual(argv[2], str(helper))
        command = [*argv[:2], str(REPO/'tests/support/r4_helper_bind_window.py'),
                   *argv[2:], str(bound_w), str(release_r)]
        child = real_popen(command, pass_fds=(bound_w, release_r), **options)
        os.close(bound_w)
        os.close(release_r)
        self.assertTrue(select.select([bound_r], [], [], 2)[0], 'real helper bind reached')
        with os.fdopen(bound_r, 'r') as source:
            evidence['bound'] = json.loads(source.readline())
        self.assertEqual(evidence['bound']['mode'], 0o755)
        self.assertEqual(evidence['bound']['uid'], os.getuid())
        with self.assertRaisesRegex(RuntimeError, '^ProtocolMismatch: untrusted helper endpoint$') as error:
            request(endpoint, self.identity, {'kind':'heartbeat'})
        evidence['early_request_error'] = str(error.exception)
        armed = True
        return child

    def sampled(path, *args, **options):
        nonlocal armed, replacement, replacement_inode
        info = real_lstat(path, *args, **options)
        if armed and path == endpoint:
            armed = False
            evidence['fixture_observed_mode'] = stat.S_IMODE(info.st_mode)
            if fault in ('replace', 'file'):
                endpoint.rename(self.root/'o')
                if fault == 'replace':
                    replacement = socket.socket(socket.AF_UNIX)
                    replacement.bind(str(endpoint))
                else:
                    endpoint.write_bytes(b'foreign endpoint input')
                endpoint.chmod(0o600)
                changed = real_lstat(endpoint)
                replacement_inode = (changed.st_dev, changed.st_ino)
                evidence['replacement_inode'] = list(replacement_inode)
                if fault == 'file':return changed
            elif fault == 'uid':
                evidence['controlled_uid_input'] = os.getuid()+1
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid()+1,
                                       st_dev=info.st_dev, st_ino=info.st_ino)
            else:
                release()  # Return the actual pre-publication stat snapshot.
        return info

    try:
        with patch.object(subprocess, 'Popen', spawn), patch.object(Path, 'lstat', sampled):
            if fault is None:
                self.assertEqual(self.start_helper(), endpoint)
            else:
                expected = 'endpoint replaced' if fault == 'replace' else 'endpoint type or uid'
                with self.assertRaisesRegex(RuntimeError, expected) as error:
                    self.start_helper()
                evidence['fixture_rejected'] = str(error.exception)
        if fault is None:evidence['ready'] = request(endpoint, self.identity, {'kind':'heartbeat'})
    finally:
        if replacement_inode is not None:
            current = real_lstat(endpoint)
            self.assertEqual((current.st_dev, current.st_ino), replacement_inode)
            if replacement is not None:replacement.close()
            endpoint.unlink()  # Only the exact substitute created above.
            (self.root/'o').rename(endpoint)
        release()
        if child is not None:
            deadline = time.monotonic()+2
            while True:
                info = real_lstat(endpoint)
                if stat.S_IMODE(info.st_mode) == 0o600:
                    try:
                        request(endpoint, self.identity, {'kind':'finish'}, timeout=max(.001, deadline-time.monotonic()))
                        break
                    except ConnectionRefusedError:
                        pass
                if time.monotonic() >= deadline:
                    self.fail('real helper did not publish for natural cleanup')
                time.sleep(.002)
            evidence['published'] = dict(uid=info.st_uid, mode=stat.S_IMODE(info.st_mode),
                                         inode=[info.st_dev, info.st_ino])
            evidence['exit'] = child.wait(timeout=3)
            evidence['forced'] = False
            (self.root/'readiness-publication.json').write_text(json.dumps(evidence, indent=2))
            self.assertEqual(evidence['exit'], 0, 'same helper finishes naturally')
    self.assertEqual(evidence['bound']['inode'], evidence['published']['inode'])
    self.assertEqual(evidence['fixture_observed_mode'], 0o755)
    self.assertEqual(evidence['published']['mode'], 0o600)
