"""Bounded initial-open retries and conservative, post-recovery rollback."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import stat
import time
import uuid

from cache_store import atomic_json, public_owner_probe, rename_group, sync_directory


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('open total deadline expired; no further attempt or rollback')
    return value


@contextmanager
def open_locks(root, target, deadline):
    """Use N7a's root flock plus a same-database lock for every adapter open."""
    root.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(os.fsencode(target)).hexdigest()
    descriptors = []
    try:
        for name, mode in (('.cache.lock', fcntl.LOCK_SH),
                           ('.recovery-open-' + key + '.lock', fcntl.LOCK_EX)):
            fd = os.open(root/name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            descriptors.append(fd)
            while True:
                remaining(deadline)
                try:
                    fcntl.flock(fd, mode | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(min(.005, remaining(deadline)))
        yield
    finally:
        for fd in reversed(descriptors):
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def stable_stat(value):
    return (value.st_ino, value.st_dev, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def identity(path, deadline):
    remaining(deadline)
    before = path.lstat()
    value = dict(inode=before.st_ino, device=before.st_dev, mode=before.st_mode,
                 size=before.st_size, mtime_ns=before.st_mtime_ns)
    if not stat.S_ISREG(before.st_mode):
        if stat.S_ISLNK(before.st_mode):
            raise RuntimeError('recovery refuses symlink: ' + str(path))
        return value
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if stable_stat(os.fstat(stream.fileno())) != stable_stat(before):
            raise RuntimeError('recovery file identity changed before read: ' + str(path))
        while chunk := stream.read(1024*1024):
            remaining(deadline)
            digest.update(chunk)
        if stable_stat(os.fstat(stream.fileno())) != stable_stat(before) or stable_stat(path.lstat()) != stable_stat(before):
            raise RuntimeError('recovery file identity changed during read: ' + str(path))
    value['sha256'] = digest.hexdigest()
    return value


def inventory(directory, deadline):
    return {p.name: identity(p, deadline) for p in sorted(directory.iterdir())}


class Snapshot:
    def __init__(self, root, target, deadline, *, owner_probe=None):
        self.target, self.deadline = target, deadline
        self.owner_probe = owner_probe or public_owner_probe
        self.names = {target.name, *(target.with_suffix(ext).name
            for ext in ('.id0', '.id1', '.id2', '.nam', '.til'))}
        self.check_owner()
        root.mkdir(parents=True, exist_ok=True)
        container = root/'recovery'
        if container.is_symlink():
            raise RuntimeError('symlink recovery container refused')
        container.mkdir(mode=0o700, exist_ok=True)
        self.path = container/uuid.uuid4().hex
        self.path.mkdir(mode=0o700)
        (self.path/'snapshot').mkdir(mode=0o700)
        self.parent_identity = stable_stat(target.parent.lstat())[:3]
        self.before = inventory(target.parent, deadline)
        self.data = {'version': 1, 'target': str(target), 'status': 'snapshotting',
                     'before': self.before, 'parent_identity': self.parent_identity,
                     'files': {}, 'snapshot_files': {}, 'attempts': []}
        self.journal()
        for name, value in self.before.items():
            if name not in self.names:
                continue
            if not stat.S_ISREG(value['mode']):
                raise RuntimeError('non-regular recovery component refused')
            self.copy(target.parent/name, self.path/'snapshot'/name, value, 0o400)
            self.data['snapshot_files'][name] = identity(self.path/'snapshot'/name, deadline)
            self.data['files'][name] = value
        self.check_owner()
        self.expect(self.before)
        self.data['status'] = 'ready'
        self.journal()

    def journal(self):
        atomic_json(self.path/'recovery.json', self.data)

    def check_owner(self):
        remaining(self.deadline)
        reason = self.owner_probe(self.target)
        if not reason:
            from ida_nexus import probe_database_state
            state = probe_database_state(self.target)
            if state['state'] in ('in_use', 'unknown') or state.get('error'):
                reason = 'external IDA lock or indeterminate database state: ' + state['state']
        remaining(self.deadline)
        if reason:
            raise RuntimeError('recovery rollback refused: ' + reason + '; snapshot/scene retained')

    def expect(self, expected):
        if stable_stat(self.target.parent.lstat())[:3] != self.parent_identity:
            raise RuntimeError('recovery parent directory identity changed; scene retained')
        if inventory(self.target.parent, self.deadline) != expected:
            raise RuntimeError('recovery file identity/directory changed; snapshot/scene retained')

    def copy(self, source, destination, expected, mode):
        actual = identity(source, self.deadline)
        # Snapshot files have a different inode/mode; content must still match.
        if (actual['size'], actual.get('sha256')) != (expected['size'], expected['sha256']):
            raise RuntimeError('recovery snapshot content changed; scene retained')
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream, destination.open('xb') as output:
            opened = os.fstat(stream.fileno())
            if opened.st_ino != actual['inode'] or opened.st_dev != actual['device']:
                raise RuntimeError('recovery source identity changed before copy')
            while chunk := stream.read(1024*1024):
                remaining(self.deadline)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        destination.chmod(mode)
        copied = identity(destination, self.deadline)
        if copied['sha256'] != expected['sha256'] or copied['size'] != expected['size']:
            raise RuntimeError('recovery snapshot copy verification failed')
        if identity(source, self.deadline) != actual:
            raise RuntimeError('recovery source changed during copy; scene retained')

    def failed(self, attempt):
        """Record owner-produced identities before allowing the owner to close."""
        observed = inventory(self.target.parent, self.deadline)
        for name, value in observed.items():
            if name not in self.names and self.before.get(name) != value:
                raise RuntimeError('unexpected new/changed recovery directory entry: ' + name)
        if any(name not in observed for name in self.before if name not in self.names):
            raise RuntimeError('unrelated recovery directory entry disappeared')
        self.data['attempts'].append({'attempt': attempt, 'failed': observed})
        # KILL can remove owner components on close. Preserve their failed bytes
        # as well as the original snapshot before obtaining the release proof.
        failed_files = self.path/('failed-files-' + str(attempt))
        failed_files.mkdir(mode=0o700)
        for name in observed.keys() & self.names:
            self.copy(self.target.parent/name, failed_files/name, observed[name], 0o400)
        self.expect(observed)
        self.data['status'] = 'failed-owner-held'
        self.journal()
        return observed

    def rollback(self, observed):
        """Only after lease AND public owner lifetime release were proved."""
        self.check_owner()
        current = inventory(self.target.parent, self.deadline)
        for name, value in current.items():
            if observed.get(name) != value:
                raise RuntimeError('recovery file identity changed after close: ' + name)
        # TEMP|KILL may remove components. Missing unrelated files/packed are unsafe.
        for name in observed.keys() - current.keys():
            if name not in self.names or name == self.target.name:
                raise RuntimeError('recovery file unexpectedly removed: ' + name)
        self.data['status'] = 'rolling-back'
        self.journal()
        isolated = self.path/('quarantine-' + str(len(self.data['attempts'])))
        isolated.mkdir(mode=0o700)
        for name in sorted(current.keys() & self.names):
            self.check_owner()
            self.expect(current)
            rename_group(self.target.parent/name, isolated/name)
            current.pop(name)
            sync_directory(self.target.parent)
            sync_directory(isolated)
        for name, value in self.data['files'].items():
            if identity(self.path/'snapshot'/name, self.deadline) != self.data['snapshot_files'][name]:
                raise RuntimeError('recovery snapshot content changed or identity replaced; scene retained')
            self.check_owner()
            self.expect(current)
            self.copy(self.path/'snapshot'/name, self.target.parent/name,
                      value, stat.S_IMODE(value['mode']))
            current[name] = identity(self.target.parent/name, self.deadline)
            sync_directory(self.target.parent)
        self.check_owner()
        self.expect(current)
        self.data['attempts'][-1]['restored'] = current
        self.data['status'] = 'restored'
        self.journal()

    def complete(self):
        self.data['status'] = 'opened'
        self.journal()


def failure_state(handle, deadline):
    return handle.execute_python(
        "import sys\n_g=sys.modules.get('_ida_cli_save_guard_v1')\n"
        "result = {'initial': bool(_g and _g._state and _g._state['first_failure'] "
        "and _g._state['first_failure']['previous_sample'] is None), "
        "'evidence': _g._state['first_failure'] if _g and _g._state else None}",
        timeout=remaining(deadline))['result']


def open_checked(Handle, Options, path, options, deadline, guarded_source, context,
                 acquired=lambda *_: None, released=lambda *_: None, starting=lambda: None):
    """Retry only a guard-confirmed *first* sample failure, never a business call."""
    from ida_nexus import probe_database_state, wait_database_released
    root = Path(os.environ['IDA_CLI_HOME']).resolve()/'idb'
    state = probe_database_state(path, output_database=options.get('output_database'))
    target = Path(state['idb_path']).resolve()
    with open_locks(root, target, deadline):
        state = probe_database_state(path, output_database=options.get('output_database'))
        snapshot = Snapshot(root, target, deadline) if state['state'] in ('crashed', 'unpacked') else None
        for number in range(1, 4):
            logging.getLogger('ida_cli.open').debug('open attempt %d/3: %s', number, target)
            attempt_context = dict(context, open_attempt=number, deadline=deadline)
            starting()
            handle = Handle.open(path, options=Options(**dict(options,
                startup_timeout=remaining(deadline))))
            acquired(handle, attempt_context)
            attempt_context['record_id'] = handle.instance.record_id
            try:
                actual = handle.execute_python(guarded_source(
                    'import ida_kernwin\nresult = ida_kernwin.get_kernel_version()',
                    attempt_context), timeout=remaining(deadline))
            except Exception as exc:
                proof = failure_state(handle, deadline)
                if proof['initial']:
                    logging.getLogger('ida_cli.open').warning('Root Node initial-open failure: %s',
                        json.dumps(dict(attempt=number, maximum=3, record_id=handle.instance.record_id,
                                        evidence=proof['evidence'], recovery_snapshot=str(snapshot.path) if snapshot else None)))
                observed, observation_error = None, None
                if snapshot and proof['initial']:
                    try:
                        observed = snapshot.failed(number)
                    except Exception as error:
                        observation_error = error
                outcome = handle.close_outcome(wait_for_database=True, timeout=remaining(deadline))
                lifetime = wait_database_released(handle.instance, timeout=remaining(deadline))
                if not outcome.get('lease_released') or not lifetime:
                    raise RuntimeError('open cleanup release unconfirmed; snapshot/scene retained') from exc
                released(handle)
                if observation_error:
                    raise observation_error from exc
                if not proof['initial']:
                    raise RuntimeError('open runtime check failed; no initial Root retry: ' + str(exc)) from exc
                if snapshot:
                    snapshot.rollback(observed)
                if number == 3:
                    raise RuntimeError('Root Node initial open failed after 3 attempts; '
                                       'original file retained; recovery snapshot/scene retained') from exc
                continue
            if snapshot:
                snapshot.complete()
            if number > 1:
                logging.getLogger('ida_cli.open').warning(
                    'Root Node automatic reopen succeeded after %d attempts: %s', number, handle.instance.record_id)
            return handle, actual, number
