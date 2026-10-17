#!/usr/bin/env python3
"""Installation bootstrap prototype. Invoke only via r0_maintenance_launch.sh."""
import sys
import os

# A closed installation, including the complete current bridge module closure.
REQUIRED = frozenset(('r0_bootstrap.py', 'r0_maintenance_payload.py', 'analysis_tools.py',
    'bridge.py', 'cache_store.py', 'edit_tools.py', 'lifecycle.py', 'metadata.py',
    'open_recovery.py', 'query_tools.py', 'save_guard.py', 'search_tools.py',
    'slices.py', 'struct_tools.py', 'tools.py', 'type_tools.py'))


def main():
    if os.__spec__.origin != 'frozen':
        raise RuntimeError('trusted frozen os required')
    trusted = os.path.realpath(sys.base_prefix)
    venv = os.path.realpath(sys.prefix)
    sys.path[:] = [p for p in sys.path if p and os.path.isabs(p) and
                   any(os.path.realpath(p).startswith(base + os.sep) for base in (trusted, venv))]
    import hashlib
    import importlib.abc
    import importlib.util
    import json
    import stat
    root = os.path.dirname(os.path.realpath(__file__))

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
            or manifest['schema'] != 1 or set(manifest['files']) != REQUIRED):
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
        if name != 'r0_bootstrap.py':
            verified[name[:-3]] = (os.path.join(root, name), compile(data, os.path.join(root, name), 'exec'))

    class VerifiedSource(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, fullname, path=None, target=None):
            if fullname in verified:
                return importlib.util.spec_from_loader(fullname, self, origin=verified[fullname][0])
            return None

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            path, code = verified[module.__name__]
            module.__file__ = path
            exec(code, vars(module))

    if set(verified) & set(sys.modules):
        raise RuntimeError('installation module was already imported before verification')
    # No root path insertion, ordinary source loader or bytecode lookup. Every
    # member executes the in-memory bytes read and hashed through the same FD.
    sys.meta_path.insert(0, VerifiedSource())
    import r0_maintenance_payload
    print(json.dumps({'source': r0_maintenance_payload.__file__, 'mode': sys.argv[1:],
        'prototype_only': True, 'execution': 'verified-source-bytes',
        'manifest_members': sorted(manifest['files'])}))


if __name__ == '__main__':
    main()
