"""IDA discovery uses only injected private application roots."""
import json
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

    def detect(self, explicit=None):
        env = os.environ | {'HOME': str(self.root),
            'IDA_CLI_IDA_SEARCH_ROOTS': json.dumps([str(self.applications)])}
        env.pop('IDADIR', None)
        if explicit is not None:
            env['IDADIR'] = str(explicit)
        return subprocess.run([sys.executable, '-B', str(REPO / 'scripts/prepare_nexus_env.py'),
                               '--detect-ida'], env=env, capture_output=True, text=True, timeout=10)

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

    def test_multiple_candidates_fail_with_candidates_and_guidance(self):
        apps = [self.app(f'IDA Professional {version}.app') for version in ('9.4', '9.5')]
        result = self.detect()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('multiple IDA installations', result.stderr)
        self.assertIn('set IDADIR', result.stderr)
        for app in apps:
            self.assertIn(str(app / 'Contents/MacOS'), result.stderr)
        self.assertEqual(result.stdout, '')

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


if __name__ == '__main__':
    unittest.main()
