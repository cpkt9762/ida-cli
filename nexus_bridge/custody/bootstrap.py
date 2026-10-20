#!/usr/bin/env python3
"""Verified source entry for the production bridge and independent helper. Launch with -I -B."""
import sys

# os/posixpath must already be frozen, before any path-based import is possible.
os = sys.modules.get('os')
if os is None or os.__spec__.origin != 'frozen' or os.path.__spec__.origin != 'frozen':
    raise RuntimeError('trusted frozen os and path required')

# A closed installation, including the complete current bridge module closure.
REQUIRED = frozenset(('acquisition.py', 'analysis_tools.py', 'bootstrap.py', 'bridge.py', 'bridge_observer.py', 'cache_store.py', 'config.py', 'durable_records.py', 'edit_tools.py', 'lifecycle.py', 'lifetime.py', 'metadata.py', 'open_recovery.py', 'owner_modules.py', 'owner_release.py', 'origin.py', 'owner_identity.py', 'custody_process_identity.py', 'proof_helper.py', 'protocol.py', 'query_tools.py', 'recovery_files.py', 'recovery_transaction.py', 'save_guard.py', 'search_tools.py', 'slices.py', 'struct_tools.py', 'target_coordination.py', 'target_journal.py', 'tools.py', 'type_tools.py'))


REQUIRED |= frozenset(('legacy_cache.py','legacy_cache_files.py','legacy_cache_offline.py','recovery_job.py','recovery_transfer.py','recovery_maintenance.py','recovery_probe.py','recovery_resources.py','recovery_legacy.py'))
REQUIRED |= frozenset(('volume_identity.py',))
REQUIRED |= frozenset(('process_timeout.py',))
ASSETS = frozenset(('maintenance-launch',))


def load_entry():
    root = os.path.dirname(os.path.realpath(__file__))
    excluded = {root, os.path.realpath(os.path.dirname(sys.argv[0])), os.path.realpath(os.getcwd())}
    version = f'python{sys.version_info.major}.{sys.version_info.minor}'
    base = os.path.realpath(sys.base_prefix)
    prefix = os.path.realpath(sys.prefix)
    stdlib = os.path.realpath(os.path.join(base, sys.platlibdir, version))
    if not sys._stdlib_dir or os.path.realpath(sys._stdlib_dir) != stdlib:
        raise RuntimeError('unrecognized interpreter stdlib layout')
    # Derive exact directories from builtin interpreter facts, never sysconfig
    # or another module that the installation could shadow. Prefix descendants
    # are not implicitly trusted. Canonical aliases of excluded paths also go.
    allowed = {stdlib, os.path.join(stdlib, 'lib-dynload'),
               os.path.join(prefix, 'lib', version, 'site-packages')}
    verified_paths = []
    for path in sys.path:
        if not path or not os.path.isabs(path):
            continue
        canonical = os.path.realpath(path)
        if canonical not in allowed or canonical in excluded:
            continue
        # The prepared interpreter is the trust anchor. Check every directory
        # from the exact search directory back to that anchor, without imports.
        anchor = prefix if canonical.startswith(prefix + os.sep) else base
        current = canonical
        while True:
            info = os.lstat(current)
            if (info.st_mode & 0o170000 != 0o040000 or info.st_uid not in (0, os.getuid())
                    or info.st_mode & 0o022):
                raise RuntimeError('untrusted interpreter search directory')
            if current == anchor:
                break
            current = os.path.dirname(current)
        verified_paths.append(canonical)
    if stdlib not in verified_paths:
        raise RuntimeError('verified interpreter stdlib required')
    sys.path[:] = verified_paths
    import hashlib
    import importlib.abc
    import importlib.util
    import json
    import stat

    def verified_read(name):
        path = os.path.join(root, name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_nlink != 1):
                raise RuntimeError('untrusted module permissions or identity')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read()
            after = os.fstat(fd)
            if (info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise RuntimeError('module changed during verification')
            return data, stat.S_IMODE(info.st_mode)
        finally:
            os.close(fd)

    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise RuntimeError('untrusted installation permissions')
    raw, _mode = verified_read('manifest.json')
    manifest = json.loads(raw)
    if (set(manifest) != {'schema', 'files'} or type(manifest['schema']) is not int
            or manifest['schema'] != 1 or set(manifest['files']) != REQUIRED | ASSETS):
        raise RuntimeError('incomplete installation manifest schema/closure')
    if {name for name in os.listdir(root) if name.endswith('.py')} != REQUIRED:
        raise RuntimeError('unexpected executable source member')
    if any(name.endswith('.pyc') for _folder, _dirs, files in os.walk(root) for name in files):
        raise RuntimeError('unverified bytecode is not permitted')
    verified = {}
    for name, expected in manifest['files'].items():
        if not isinstance(expected, dict) or set(expected) != {'sha256', 'mode'}:
            raise RuntimeError('invalid executable manifest entry')
        data, mode = verified_read(name)
        if type(expected['mode']) is not int or mode != expected['mode']:
            raise RuntimeError('manifest permissions mismatch')
        if hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise RuntimeError('manifest mismatch')
        if name != 'bootstrap.py' and name.endswith('.py'):
            verified[name[:-3]] = (os.path.join(root, name), data, data.decode('utf-8'))

    class VerifiedSource(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in verified:
                return importlib.util.spec_from_loader(fullname, self, origin=verified[fullname][0])
            return None

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            path, data, source = verified[module.__name__]
            module.__verified_source__ = source
            module.__file__ = path
            # Verify the entire closure above before importing any member, but
            # compile only a member that is actually loaded. Short-lived target
            # writers must not compile the unrelated IDA tool implementation on
            # every proof/settlement. Execute the same FD-verified bytes; never
            # reopen a source path or use a bytecode cache.
            exec(compile(data, path, 'exec'), vars(module))

    if set(verified) & set(sys.modules):
        raise RuntimeError('installation module was already imported before verification')
    sys._ida_cli_verified_sources = {name + '.py': value[2] for name, value in verified.items()}
    # No root path insertion, ordinary source loader or bytecode lookup. Every
    # member executes the in-memory bytes read and hashed through the same FD.
    sys.meta_path.insert(0, VerifiedSource())
    entry = sys.argv.pop(1)
    if entry not in ('legacy_cache', 'bridge', 'proof_helper', 'cache_store', 'target_journal', 'recovery_job', 'open_recovery', 'recovery_probe'):
        raise RuntimeError('unrecognized verified entry')
    return __import__(entry)


def main():
    result = load_entry().main()
    if result is not None:
        raise SystemExit(result)


if __name__ == '__main__':
    main()
