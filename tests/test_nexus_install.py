"""IDA discovery uses only injected private application roots."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.applications = self.root / 'Applications'
        self.applications.mkdir()

    def app(self, name):
        app = self.applications / name
        (app / 'Contents/MacOS').mkdir(parents=True)
        return app

    def detect(self, explicit=None, check_runtime=False):
        env = os.environ | {'HOME': str(self.root),
            'IDA_CLI_IDA_SEARCH_ROOTS': json.dumps([str(self.applications)])}
        env.pop('IDADIR', None)
        if explicit is not None:
            env['IDADIR'] = str(explicit)
        argv = [sys.executable, '-B', str(REPO / 'scripts/prepare_nexus_env.py'), '--detect-ida']
        if check_runtime:
            argv.append('--check-runtime')
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=10)

    def test_unique_install_is_detected(self):
        app = self.app("IDA Professional 9.5 ' private.app")
        result = self.detect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(app / 'Contents/MacOS'))

    def test_explicit_paths_win_and_normalize(self):
        app = self.app('IDA Professional 9.5.app')
        self.app('IDA Professional 9.4.app')
        for path in (app, app / 'Contents', app / 'Contents/MacOS'):
            with self.subTest(path=path):
                result = self.detect(path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(app / 'Contents/MacOS'))

    def test_multiple_candidates_choose_newest_and_list_candidates(self):
        apps = [self.app(f'IDA Professional {version}.app') for version in ('9.4', '9.5')]
        result = self.detect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(apps[1] / 'Contents/MacOS'))
        self.assertIn('Selected IDA', result.stderr)
        self.assertIn('Other IDA candidates', result.stderr)
        for app in apps:
            self.assertIn(str(app / 'Contents/MacOS'), result.stderr)

    def test_version_components_compare_as_integers(self):
        self.app('IDA Professional 9.9.app')
        newest = self.app('IDA Professional 9.10.app')
        self.assertEqual(self.detect().stdout.strip(), str(newest / 'Contents/MacOS'))
        self.app('IDA Professional 9.50.app')
        newest = self.app('IDA Professional 10.0.app')
        self.assertEqual(self.detect().stdout.strip(), str(newest / 'Contents/MacOS'))
        self.app('IDA Professional 10.0.0.99.app')
        newest = self.app('IDA Professional 10.0.1.app')
        self.assertEqual(self.detect().stdout.strip(), str(newest / 'Contents/MacOS'))

    def test_zero_padded_versions_tie_by_canonical_path(self):
        apps = [self.app('IDA Professional ' + version + '.app') for version in ('9.5', '9.5.0')]
        result = self.detect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(min(apps) / 'Contents/MacOS'))

    def test_unversioned_name_ranks_below_numeric_version(self):
        self.app('IDA Professional.app')
        newest = self.app('IDA Professional 9.5.app')
        self.assertEqual(self.detect().stdout.strip(), str(newest / 'Contents/MacOS'))

    def test_newest_incompatible_wheel_fails_without_selecting_older(self):
        self.app('IDA Professional 9.4.app')
        newest = self.app('IDA Professional 9.5.app')
        runtime = newest / 'Contents/MacOS'
        (runtime.parent / 'Info.plist').write_text(
            '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleShortVersionString</key>'
            '<string>9.5</string></dict></plist>')
        wheel = runtime / 'idalib/python/idapro-0.0.10-py3-none-any.whl'
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b'incompatible wheel')
        result = self.detect(check_runtime=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('selected idapro wheel hash mismatch', result.stderr)
        self.assertIn(str(wheel), result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertIn('set IDADIR', result.stderr)
        self.assertIn('9.4.app', result.stderr)

    def test_no_candidate_fails_with_search_roots_and_guidance(self):
        result = self.detect()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no IDA installation', result.stderr)
        self.assertIn(str(self.applications), result.stderr)
        self.assertIn('set IDADIR', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_canonical_aliases_are_one_installation(self):
        app = self.app('IDA Professional 9.5.app')
        (self.applications / 'IDA Professional alias.app').symlink_to(app)
        result = self.detect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(app / 'Contents/MacOS'))

    def test_invalid_explicit_path_never_selects_another_installation(self):
        self.app('IDA Professional 9.5.app')
        missing = self.root / 'missing.app'
        result = self.detect(missing)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(missing), result.stderr)
        self.assertIn('set IDADIR', result.stderr)
        self.assertEqual(result.stdout, '')


class RuntimeLockTests(unittest.TestCase):
    setUp = DiscoveryTests.setUp
    app = DiscoveryTests.app
    def runtime(self, version='9.4'):
        import hashlib
        import plistlib
        spec = importlib.util.spec_from_file_location('runtime_preparer', REPO / 'scripts/prepare_nexus_env.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        runtime = self.app('IDA Professional '+version+'.app') / 'Contents/MacOS'
        (runtime.parent / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString': version}))
        wheel = runtime / 'idalib/python/idapro-test.whl'
        wheel.parent.mkdir(parents=True)
        wheel.write_bytes(b'private test wheel')
        lock = {'assets': {}, 'runtimes': {'9.4': {'idapro_wheel': wheel.name,
            'idapro_wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()}}}
        return module, runtime, wheel, lock

    def test_94_selects_only_its_locked_wheel(self):
        module, runtime, wheel, lock = self.runtime()
        self.assertEqual(module.validate_runtime(runtime, lock), wheel)

    def test_hash_mismatch_is_not_accepted(self):
        module, runtime, wheel, lock = self.runtime()
        wheel.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'wheel hash mismatch'):
            module.validate_runtime(runtime, lock)

    def test_unsupported_old_and_unknown_new_versions(self):
        for version in ('9.3', '9.6', '10.0'):
            module, runtime, _, lock = self.runtime(version)
            with self.assertRaisesRegex(RuntimeError, 'unsupported IDA'):
                module.validate_runtime(runtime, lock)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "version ' quoted"
        self.root.mkdir()
        binary = self.root / 'ida-cli.real'
        binary.write_text('#!/bin/sh\nprintf \'%s\\n\' "$IDADIR"\n')
        binary.chmod(0o700)
        spec = importlib.util.spec_from_file_location('n9_install_preparer', REPO / 'scripts/prepare_nexus_env.py')
        preparer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparer)
        self.default = self.root / "IDA Professional 9.5 ' literal.app/Contents/MacOS"
        self.launcher = self.root / 'launcher'
        self.launcher.write_text(preparer.launcher_source(self.root, self.default))
        self.launcher.chmod(0o700)

    def launch(self, explicit=None):
        env = os.environ | {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'IDA_CLI_IDA_SEARCH_ROOTS': 'not JSON'}
        env.pop('IDADIR', None)
        if explicit is not None:
            env['IDADIR'] = str(explicit)
        return subprocess.run([str(self.launcher)], env=env, capture_output=True, text=True, timeout=10)

    def test_install_default_is_used_without_python_or_rediscovery(self):
        self.assertFalse((self.root / 'nexus/venv/bin/python').exists())
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.default))

    def test_explicit_override_wins_and_normalizes_without_rediscovery(self):
        app = self.root / 'IDA Professional 9.4.app'
        paths = [str(path) + suffix for path in (app, app / 'Contents', app / 'Contents/MacOS')
                 for suffix in ('', '/', '//')]
        paths.append('~/IDA Professional 9.4.app/')
        for path in paths:
            with self.subTest(path=path):
                result = self.launch(path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(app / 'Contents/MacOS'))


if __name__ == '__main__':
    unittest.main()
