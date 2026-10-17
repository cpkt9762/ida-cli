"""Exercise the Rust-produced closed installation in isolated subprocesses."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class VerifiedCustodyInstallation(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=os.environ['R3A_CASE_ROOT'], prefix='boot-'))
        self.installation = self.root/'installation'
        shutil.copytree(os.environ['R3A_INSTALLATION'], self.installation)
        self.cwd = self.root/'cwd'
        self.cwd.mkdir()
        self.marker = self.root/'unverified-executed'
        self.environment = dict(os.environ, PYTHONPATH=str(self.cwd))

    def run_entry(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(self.installation/'bootstrap.py'),
                                 'cache_store', '--help'], cwd=self.cwd, env=self.environment,
                                capture_output=True, timeout=3)
        self.assertFalse(self.marker.exists(), 'unverified executable input ran')
        return result

    def test_hostile_cwd_and_pythonpath_are_never_executable_sources(self):
        for name in ('json', 'socket', 'hashlib', 'target_journal', 'proof_helper'):
            (self.cwd/(name+'.py')).write_text(f"open({str(self.marker)!r},'w').write('unsafe')\n")
        result = self.run_entry()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'usage:', result.stdout)

    def test_missing_extra_changed_and_symlink_members_fail_before_entry(self):
        member = self.installation/'proof_helper.py'
        original = member.read_bytes()
        for fault in ('missing', 'extra', 'changed', 'symlink', 'mode', 'pyc'):
            with self.subTest(fault=fault):
                if fault == 'missing':
                    member.unlink()
                elif fault == 'extra':
                    (self.installation/'unknown.py').write_bytes(b'raise RuntimeError("unsafe")')
                elif fault == 'changed':
                    member.write_bytes(original+b'\n# changed bytes\n')
                elif fault == 'symlink':
                    other = self.root/'outside.py'
                    other.write_bytes(original)
                    member.unlink()
                    member.symlink_to(other)
                elif fault == 'mode':
                    member.chmod(0o666)
                else:
                    cache = self.installation/'__pycache__'
                    cache.mkdir()
                    (cache/'proof_helper.cpython.pyc').write_bytes(b'unverified bytecode')
                result = self.run_entry()
                self.assertNotEqual(result.returncode, 0, fault)
                if member.is_symlink():
                    member.unlink()
                member.write_bytes(original)
                member.chmod(0o600)
                (self.installation/'unknown.py').unlink(missing_ok=True)
                shutil.rmtree(self.installation/'__pycache__', ignore_errors=True)

    def test_manifest_closure_and_loaded_source_match_rust_installation(self):
        import hashlib
        manifest = json.loads((self.installation/'manifest.json').read_text())
        self.assertIn('custody_process_identity.py', manifest['files'])
        self.assertNotIn('process_identity.py', manifest['files'])
        for name, expected in manifest['files'].items():
            self.assertEqual(hashlib.sha256((self.installation/name).read_bytes()).hexdigest(),
                             expected['sha256'])
        self.assertEqual(self.run_entry().returncode, 0)


if __name__ == '__main__':
    unittest.main()
