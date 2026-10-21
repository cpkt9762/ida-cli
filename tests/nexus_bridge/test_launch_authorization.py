"""Atomic permission race, fail-closed records, and SDK worker pre-IDB gate."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from ida_nexus._launch_authorization import create, decide, revoked
from ida_nexus.cli import worker


class LaunchAuthorization(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ['R3A_CASE_ROOT'])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root/'grant'
        self.target = str(self.root/'target.i64')
        self.suffix = 'abcdef'
        create(self.path, self.suffix, self.target)

    def test_claim_and_revoke_have_exactly_one_winner(self):
        for i in range(48):
            path = self.root/str(i)
            create(path, self.suffix, self.target)
            barrier = threading.Barrier(2)
            def run(decision):
                barrier.wait(timeout=5)
                return decide(path, self.suffix, self.target, decision)
            with ThreadPoolExecutor(2) as pool:
                claim, revoke = [pool.submit(run, d) for d in ('claimed', 'revoked')]
                # An O_EXCL loser may see an unfinished decision: fail closed
                # is an explicit error, never a second successful claimant.
                results = []
                for f in (claim, revoke):
                    try:
                        results.append(f.result(timeout=5))
                    except (RuntimeError, ValueError):
                        results.append(False)
            self.assertEqual(results.count(True), 1)
            self.assertEqual(revoked(path, self.suffix, self.target), results[1])
            self.assertFalse(decide(path, self.suffix, self.target, 'claimed'), 'claim never replays')

    def test_revocation_replays_but_grant_cannot_be_reissued(self):
        self.assertTrue(decide(self.path, self.suffix, self.target, 'revoked'))
        self.assertTrue(decide(self.path, self.suffix, self.target, 'revoked'))
        with self.assertRaises(FileExistsError):
            create(self.path, self.suffix, self.target)
        self.assertFalse(decide(self.path, self.suffix, self.target, 'claimed'))

    def test_final_directory_and_grant_symlinks_remain_forbidden(self):
        alias = self.root/'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            decide(alias/'grant', self.suffix, self.target, 'claimed')
        link = self.root/'grant-link'
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            decide(link, self.suffix, self.target, 'claimed')
        self.assertFalse((self.root/'grant.decision').exists())

    def test_nonprivate_grant_directory_remains_forbidden(self):
        self.root.chmod(0o755)
        self.addCleanup(self.root.chmod, 0o700)
        with self.assertRaisesRegex(RuntimeError, 'not private'):
            decide(self.path, self.suffix, self.target, 'claimed')
        self.assertFalse((self.root/'grant.decision').exists())

    def test_missing_incomplete_and_mismatched_grants_never_authorize(self):
        with self.assertRaises(FileNotFoundError):
            decide(self.root/'absent', self.suffix, self.target, 'claimed')
        with self.assertRaisesRegex(RuntimeError, 'identity mismatch'):
            decide(self.path, '123456', self.target, 'claimed')
        (self.root/'grant.decision').touch(mode=0o600)
        with self.assertRaisesRegex(RuntimeError, 'invalid or incomplete'):
            decide(self.path, self.suffix, self.target, 'claimed')

    def test_revoked_worker_exits_before_loading_idalib_or_opening_idb(self):
        sample = self.root/'sample'
        sample.write_bytes(b'private sample')
        self.assertTrue(decide(self.path, self.suffix, self.target, 'revoked'))
        with patch.object(worker, '_redirect_output'), patch.object(worker, 'probe') as probe:
            code = worker.main([str(sample), '--record-suffix', self.suffix,
                '--launch-authorization', str(self.path), '--launch-target', self.target])
        self.assertEqual(code, 78)
        probe.assert_not_called()
        self.assertFalse(Path(self.target).exists())

    def test_ordinary_sdk_worker_without_argument_keeps_its_upstream_path(self):
        sample = self.root/'sample'
        sample.write_bytes(b'private sample')
        with patch.object(worker, '_redirect_output'), patch.object(worker, 'probe', side_effect=RuntimeError('pre-IDB sentinel')) as probe:
            with self.assertRaisesRegex(RuntimeError, 'pre-IDB sentinel'):
                worker.main([str(sample)])
        probe.assert_called_once()
        self.assertFalse((self.root/'grant.decision').exists())
