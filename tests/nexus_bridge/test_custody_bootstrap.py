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

    def test_short_entry_compiles_only_imported_fd_verified_members(self):
        code = '''
import builtins, json, os, runpy, sys
bootstrap = sys.argv[1]
runtime = runpy.run_path(bootstrap, run_name='verified_test')
compiled = []
original = builtins.compile
def tracked(source, filename, *args, **kwargs):
    compiled.append(os.path.basename(filename))
    return original(source, filename, *args, **kwargs)
builtins.compile = tracked
sys.argv = [bootstrap, 'cache_store', '--help']
entry = runtime['load_entry']()
assert 'cache_store.py' in compiled, compiled
assert 'bridge.py' not in compiled and 'tools.py' not in compiled, compiled
manifest = json.load(open(os.path.join(os.path.dirname(bootstrap), 'manifest.json')))
expected = {name for name in manifest['files'] if name.endswith('.py') and name != 'bootstrap.py'}
assert set(sys._ida_cli_verified_sources) == expected
assert entry.__verified_source__ == sys._ida_cli_verified_sources['cache_store.py']
print('complete closure verified; only imported original bytes compiled')
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
                                 str(self.installation/'bootstrap.py')], cwd=self.cwd,
                                env=self.environment, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
