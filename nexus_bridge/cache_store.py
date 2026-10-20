"""Nexus cache quarantine. Uses public observations, never Nexus private locks."""
import argparse
import ctypes
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import shutil
import sys
import time
import uuid

if '__verified_source__' not in globals():
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'custody'))


@contextmanager
def lock(root, exclusive=True):
    root.mkdir(parents=True, exist_ok=True)
    fd = os.open(root/'.cache.lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        yield
    finally:
        # Explicit unlock: an inherited open file description must not extend it.
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_json(path, value):
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    try:
        with temporary.open('x') as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def rename_group(source, destination):
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'darwin':
        rename = library.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        result = rename(os.fsencode(source), os.fsencode(destination), 4)
    elif sys.platform.startswith('linux'):
        rename = library.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    else:
        raise OSError('atomic non-replacing group rename unavailable')
    if result != 0:
        raise OSError(ctypes.get_errno(), 'atomic non-replacing group rename failed')


def public_owner_probe(path):
    from ida_nexus import discover_databases, find_database_owner, get_state_dir
    try:
        if find_database_owner(path, timeout=0.2) is not None:
            return 'public owner holds database'
        discovered = discover_databases(timeout=0.2)
        # Veto only: public discovery may omit malformed lock-held records.
        # Let the public API reap valid dead records first. Never open/lock any
        # Nexus lock or read, rewrite, or remove registration contents here.
        configured = os.environ.get('IDA_NEXUS_STATE_DIR')
        if not configured:
            return 'registration completeness unknown: IDA_NEXUS_STATE_DIR missing'
        directory = get_state_dir()/'instances'
        if directory.is_symlink():
            return 'registration completeness unknown: symlink registry'
        records = [p for p in directory.iterdir() if p.name.endswith('.json')] if directory.exists() else []
        if any(item.is_symlink() or not item.is_file() for item in records):
            return 'registration completeness unknown: non-regular registration'
        explained = [item.instance.record_id for item in discovered]
        if len(explained) != len(records) or set(explained) != {p.stem for p in records}:
            return 'registration completeness unknown: public discovery does not explain all registrations'
        if any(Path(item.instance.idb_path).resolve() == path.resolve()
               for item in discovered):
            return 'discovered owner holds database'
    except Exception as error:
        return 'public occupancy proof failed: ' + type(error).__name__
    return None


def public_probe(path):
    from ida_nexus import probe_database_state
    reason = public_owner_probe(path)
    if reason:
        return reason
    try:
        state = probe_database_state(path)
        if state['unpacked_files']:
            return 'unpacked component files remain'
        if state['state'] not in ('packed', 'missing'):
            return 'database state is ' + state['state']
        if state.get('error'):
            return 'database state proof failed: ' + state['error']
    except Exception as error:
        return 'public occupancy proof failed: ' + type(error).__name__
    return None


class Store:
    def __init__(self, root, *, grace=60, epoch=None, probe=public_probe,
                 clock=time.time, hook=lambda *_: None):
        self.root = Path(root).resolve()
        if not math.isfinite(grace) or grace < 0:
            raise ValueError('GC grace must be finite and non-negative')
        self.grace, self.epoch = grace, epoch or uuid.uuid4().hex
        self.probe, self.clock, self.hook = probe, clock, hook
        self.generations = self.root/'generations'
        self.quarantine = self.root/'quarantine'

    @contextmanager
    def target_gate(self, group):
        # collect already holds this actual cache root EX. Opening another SH
        # description here would deadlock against our own GC lock.
        from target_coordination import Target
        from target_journal import Journal
        with Target(group/'input.i64', root_locked=True) as target:
            with target.locked(nb=True):
                journal = Journal(target)
                journal.gate()
                journal.settle()
                if journal.value['entries']:
                    raise RuntimeError('ObservationPending: target still has durable references')
                yield

    def check(self, group, *, missing=False):
        reason = self.probe(group/'input.i64')
        if reason:
            return reason
        if group.is_symlink():
            return 'symlink generation refused'
        if not group.exists():
            return None if missing else 'generation is missing'
        if group.is_symlink() or not group.is_dir():
            return 'generation is not a regular directory'
        allowed = {'input', 'input.i64', 'generation.json', 'quarantine.json'}
        try:
            manifest = self.manifest(group)
        except (OSError, ValueError, TypeError) as error:
            return f'invalid generation manifest: {error}'
        bundle = manifest.get('dsc_inputs')
        if bundle is not None:
            if (not isinstance(bundle, dict) or not bundle or len(bundle) > 1024
                    or any(not isinstance(name, str) or name in ('', '.', '..')
                           or '/' in name or '\\' in name or '\x00' in name
                           or not isinstance(digest, str) or len(digest) != 64
                           or any(c not in '0123456789abcdef' for c in digest)
                           for name, digest in bundle.items())):
                return 'invalid retained DSC bundle manifest'
            directory = group/'dsc-inputs'
            if directory.is_symlink() or not directory.is_dir():
                return 'retained DSC bundle is missing or replaced'
            entries = list(directory.iterdir())
            if ({p.name for p in entries} != set(bundle)
                    or any(p.is_symlink() or not p.is_file() for p in entries)):
                return 'unexpected retained DSC bundle member'
            allowed.add('dsc-inputs')
        for item in group.iterdir():
            if item.name == 'dsc-inputs' and bundle is not None:
                continue
            if item.is_symlink() or not item.is_file() or item.name not in allowed:
                return 'unexpected or unpacked generation component: ' + item.name
        if not missing and not (group/'input.i64').is_file():
            return 'generation has no packed database'
        return None

    def pair_check(self, original, isolated):
        reason = self.check(original, missing=True) or self.check(isolated)
        if not reason and original.exists():
            reason = 'original generation path was recreated'
        return reason

    def restore(self, original, isolated, rejected, reason):
        if isolated.is_symlink() or not isolated.is_dir():
            rejected.append({'path':str(isolated), 'reason':'unsafe isolation container retained'})
            return
        if original.exists():
            rejected.append({'path':str(isolated), 'reason':reason + '; restoration collision, both paths retained'})
            return
        # Never overwrite a recreated generation, including an empty directory.
        # All cooperating routers hold the same exclusive root lock here.
        rename_group(isolated, original)
        sync_directory(original.parent)
        sync_directory(isolated.parent)
        (original/'quarantine.json').unlink(missing_ok=True)
        rejected.append({'path':str(original), 'reason':reason + '; restored'})

    def manifest(self, group):
        path = group/'generation.json'
        if path.is_symlink():
            raise ValueError('symlink generation manifest')
        data = json.loads(path.read_text())
        if (not isinstance(data, dict) or type(data.get('version')) is not int
                or data['version'] != 1 or not isinstance(data.get('key'), str) or not data['key']):
            raise ValueError('invalid generation manifest')
        return data

    def journal(self, isolated):
        path = isolated/'quarantine.json'
        if path.is_symlink():
            raise ValueError('symlink quarantine journal')
        data = json.loads(path.read_text())
        if (not isinstance(data, dict) or type(data.get('version')) is not int
                or data['version'] != 1 or data.get('name') != isolated.name
                or not isinstance(data.get('epoch'), str) or not data['epoch']
                or type(data.get('since')) not in (float, int)
                or not 0 <= data['since'] <= sys.float_info.max
                or type(data.get('checks')) is not int or not 0 <= data['checks'] < 2**63):
            raise ValueError('invalid quarantine journal')
        return data

    def retire(self, isolated, rejected, *, allow_delete=True):
        original = self.generations/isolated.name
        self.manifest(isolated)
        data = self.journal(isolated)
        reason = self.pair_check(original, isolated)
        if reason:
            self.restore(original, isolated, rejected, reason)
            return False
        now = self.clock()
        if data['epoch'] != self.epoch or now < data['since']:
            # A new router cannot reuse the previous incarnation's grace proof.
            data.update(epoch=self.epoch, since=now, checks=0)
        data['checks'] += 1
        atomic_json(isolated/'quarantine.json', data)
        if not allow_delete or data['checks'] < 2 or now - data['since'] < self.grace:
            return False
        self.hook('before_delete', original, isolated)
        reason = self.pair_check(original, isolated)
        if reason:
            self.restore(original, isolated, rejected, reason)
            return False
        # Make future normal opens choose a fresh path before destructive work.
        index_path = self.root/'nexus-index.json'
        if index_path.exists():
            index = json.loads(index_path.read_text())
            if not isinstance(index, dict) or any(not isinstance(v, str) for v in index.values()):
                raise ValueError('invalid generation index')
            relative = str(original.relative_to(self.root)/'input.i64')
            index = {key:value for key,value in index.items() if value != relative}
            atomic_json(index_path, index)
        shutil.rmtree(isolated)
        sync_directory(self.quarantine)
        return True

    def isolate(self, group, rejected):
        isolated = self.quarantine/group.name
        self.manifest(group)
        reason = self.check(group)
        if reason:
            rejected.append({'path':str(group), 'reason':reason})
            return
        if isolated.exists():
            raise ValueError('quarantine name collision')
        self.hook('before_rename', group, isolated)
        # Recheck after the barrier; an external opener ignores our flock.
        reason = self.check(group)
        if reason:
            rejected.append({'path':str(group), 'reason':reason})
            return
        atomic_json(group/'quarantine.json', {'version':1, 'name':group.name,
            'epoch':self.epoch, 'since':self.clock(), 'checks':0})
        rename_group(group, isolated)
        sync_directory(group.parent)
        sync_directory(isolated.parent)
        self.hook('after_rename', group, isolated)
        reason = self.pair_check(group, isolated)
        if reason:
            self.restore(group, isolated, rejected, reason)
        else:
            atomic_json(isolated/'quarantine.json', {'version':1, 'name':group.name,
                'epoch':self.epoch, 'since':self.clock(), 'checks':1})

    def collect(self, limit, key=None):
        result = {'evicted_groups':0, 'evicted_files':0, 'evicted_bytes':0,
                  'remaining_bytes':0, 'rejected':[]}
        try:
            with lock(self.root):
                self._collect(limit, key, result)
        except BlockingIOError:
            result['rejected'].append({'path':str(self.root), 'reason':'router lease/open/publication or another GC holds cache lock'})
        result['remaining_bytes'] = sum(p.stat().st_size for p in self.root.rglob('*') if p.is_file() and not p.is_symlink())
        return result

    def _collect(self, limit, key, result):
        for directory in (self.generations, self.quarantine):
            if directory.is_symlink():
                raise ValueError('symlink cache container')
            directory.mkdir(exist_ok=True)
        rejected = result['rejected']
        recovery = self.root/'recovery'
        if recovery.exists() or recovery.is_symlink():
            rejected.append({'path':str(recovery), 'reason':
                'recovery snapshots and failed products retained; no automatic deletion proof'})
        total = sum(p.stat().st_size for p in self.root.rglob('*') if p.is_file() and not p.is_symlink())
        budget = max(0, total - limit)
        planned = 0
        # Recovery always precedes new isolation, including explicit clean.
        for isolated in sorted(self.quarantine.iterdir()):
            try:
                if isolated.is_symlink() or not isolated.is_dir():
                    raise ValueError('unsafe quarantine container')
                if key is not None and self.manifest(isolated)['key'] != key:
                    continue
                files = list(isolated.iterdir())
                size = sum(p.stat().st_size for p in files if p.is_file())
                with self.target_gate(isolated):
                    if self.retire(isolated, rejected, allow_delete=key is not None or budget > 0):
                        result['evicted_groups'] += 1
                        result['evicted_files'] += len(files)
                        result['evicted_bytes'] += size
                        budget = max(0, budget - size)
                    elif isolated.exists() and self.pair_check(self.generations/isolated.name, isolated) is None:
                        planned += size
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                rejected.append({'path':str(isolated), 'reason':'quarantine retained: ' + str(error)})
        groups = sorted(self.generations.iterdir(), key=lambda p: p.stat().st_mtime)
        for group in groups:
            if key is None and planned >= budget:
                break
            try:
                if key is not None and self.manifest(group)['key'] != key:
                    continue
                with self.target_gate(group):
                    self.isolate(group, rejected)
                    isolated = self.quarantine/group.name
                    if isolated.exists() and not group.exists():
                        planned += sum(p.stat().st_size for p in isolated.iterdir() if p.is_file())
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                rejected.append({'path':str(group), 'reason':'generation retained: ' + str(error)})
        for legacy in self.root.glob('*.i64'):
            rejected.append({'path':str(legacy), 'reason':'legacy flat group has no atomic directory container; retained'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--limit', type=int, default=0)
    parser.add_argument('--key')
    parser.add_argument('--epoch', required=True)
    args = parser.parse_args()
    grace = float(os.environ.get('IDA_NEXUS_GC_GRACE_MS', '60000')) / 1000
    print(json.dumps(Store(args.root, grace=grace, epoch=args.epoch).collect(args.limit, args.key)))


if __name__ == '__main__':
    main()
