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

    def test_94_exception_accepts_no_other_conflict_or_changed_code(self):
        from unittest.mock import patch
        module, _, _, _ = self.runtime()
        conflict = 'ida-domain 0.5.1 has requirement idapro>=0.0.10, but you have idapro 0.0.9.'
        hashes = {'__init__.py':'registered-init', 'config.py':'registered-config'}
        entry = {'code_sha256':hashes, 'compatibility':{'pip_check_exception':conflict}}
        def invoke(output, actual=hashes):
            def runner(root, label, args):
                if label == 'idapro-code':return json.dumps(actual)
                result = subprocess.run(args,capture_output=True,text=True,timeout=5)
                if result.returncode:raise RuntimeError('pip check rejected conflict')
                return result.stdout
            pip = [sys.executable,'-c', 'import sys; print('+repr(output)+'); sys.exit(1)']
            with patch.object(module,'run',side_effect=runner):
                module.check_dependencies(self.root, Path(sys.executable), pip, entry)
        invoke(conflict)
        with self.assertRaisesRegex(RuntimeError,'rejected conflict'):invoke(conflict+'\nextra dependency conflict')
        with self.assertRaisesRegex(RuntimeError,'code hash mismatch'):invoke(conflict,hashes|{'config.py':'changed'})


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


class SourceTreeTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        spec = importlib.util.spec_from_file_location('source_preparer', REPO / 'scripts/prepare_nexus_env.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.input = self.root / 'input'
        shutil.copytree(REPO / '3rd-github/ida-nexus', self.input)

    def prepare(self, name='output'):
        root = self.root / name
        (root / 'logs').mkdir(parents=True)
        return self.module.prepare_source(root, self.input)

    def snapshot(self):
        import hashlib
        return {str(path.relative_to(self.input)): (path.stat().st_mode,
                hashlib.sha256(path.read_bytes()).hexdigest())
                for path in self.input.rglob('*') if path.is_file()}

    def test_pristine_tree_head_and_source_unchanged(self):
        before = self.snapshot()
        source = self.prepare()
        tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=source, text=True).strip()
        self.assertEqual(tree, self.module.NEXUS_TREE)
        original = subprocess.check_output(['git', 'show', 'HEAD:ida_nexus/_http.py'], cwd=source)
        self.assertEqual(original, (self.input / 'ida_nexus/_http.py').read_bytes())
        patch = REPO / 'scripts/nexus/loopback-bind.patch'
        subprocess.run(['git', 'apply', str(patch)], cwd=source, check=True)
        self.assertNotEqual(original, (source / 'ida_nexus/_http.py').read_bytes())
        self.assertEqual(original, subprocess.check_output(['git', 'show', 'HEAD:ida_nexus/_http.py'], cwd=source))
        self.assertEqual(before, self.snapshot())

    def test_modified_extra_missing_and_mode_changes_rejected_with_paths(self):
        target = self.input / 'README.md'
        original = target.read_bytes()
        for kind in ('modified', 'extra', 'missing', 'mode'):
            with self.subTest(kind=kind):
                path = self.input / 'extra.txt' if kind == 'extra' else target
                if kind == 'modified':path.write_bytes(original + b'changed')
                if kind == 'extra':path.write_text('unexpected')
                if kind == 'missing':path.unlink()
                if kind == 'mode':path.chmod(0o755)
                before = self.snapshot()
                with self.assertRaisesRegex(RuntimeError, path.name) as error:
                    self.prepare(kind)
                self.assertIn('scripts/nexus/', str(error.exception))
                self.assertEqual(before, self.snapshot())
                if kind == 'extra':path.unlink()
                else:target.write_bytes(original); target.chmod(0o644)

    def test_ignored_products_not_copied_and_commits_deterministic(self):
        cache = self.input / 'ida_nexus/__pycache__'
        cache.mkdir()
        (cache / 'generated.pyc').write_bytes(b'ignored')
        before = self.snapshot()
        one, two = self.prepare('one'), self.prepare('two')
        for source in (one, two):
            self.assertFalse((source / 'ida_nexus/__pycache__').exists())
            self.assertEqual(subprocess.check_output(['git', 'status', '--porcelain', '--ignored'], cwd=source), b'')
        self.assertEqual(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=one),
                         subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=two))
        self.assertEqual(before, self.snapshot())

    def test_package_contains_exact_upstream_tree_and_diagnostics(self):
        import tarfile
        binary = self.root / 'binary'
        binary.write_bytes(b'test executable')
        archive = self.root / 'bundle.tar.gz'
        result = subprocess.run([sys.executable, str(REPO / 'scripts/package_release.py'),
                                 '--binary', str(binary), '--output', str(archive)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = json.loads((REPO / 'scripts/nexus/source-tree.json').read_text())
        with tarfile.open(archive) as bundle:
            prefix = '3rd-github/ida-nexus/'
            entries = {member.name[len(prefix):]: member for member in bundle.getmembers()
                       if member.name.startswith(prefix)}
            self.assertEqual(set(entries), set(expected))
            self.assertIn('scripts/nexus/source-tree.json', bundle.getnames())
            for name, member in entries.items():
                self.assertEqual(bundle.extractfile(member).read(), (self.input / name).read_bytes())
                self.assertEqual(bool(member.mode & 0o111), expected[name]['mode'] == '100755')

    def test_dirty_clone_is_not_silently_reset(self):
        import shutil
        source = self.prepare()
        shutil.rmtree(self.input)
        subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(source), str(self.input)], check=True)
        (self.input / 'README.md').write_text('uncommitted edit')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'README.md'):
            self.prepare('dirty')
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main()
