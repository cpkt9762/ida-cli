"""Bounded initial-open retries and conservative, post-recovery rollback."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
from config import ida_cli_home
import stat
import time
import uuid

from cache_store import atomic_json, public_owner_probe, rename_group, sync_directory
from lifecycle import release_handle


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


class OpenGate:
    """Target admission for compatible opens before full custody migration."""
    def __init__(self, root, target, deadline):
        self.root, self.path, self.deadline = root, target, deadline
        self.target = self.guard = self.legacy = None

    def __enter__(self):
        from target_coordination import Target
        from target_journal import Journal
        from owner_identity import state_identity
        try:
            self.target = Target(self.path)  # Actual managed root SH precedes home locks.
            self.legacy = open_locks(self.root, self.path, self.deadline)
            self.legacy.__enter__()
            self.lock()
            self.target.business_admission()
            Journal(self.target).gate(state_identity())
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def lock(self):
        self.guard = self.target.locked(deadline=self.deadline)
        self.guard.__enter__()

    def unlock(self):
        if self.guard is not None:
            self.guard.__exit__(None, None, None)
            self.guard = None

    @contextmanager
    def file_gate(self):
        if self.guard is not None:
            yield
        else:
            with self.target.locked(deadline=self.deadline):
                yield

    def __exit__(self, *_):
        self.unlock()
        if self.legacy is not None:
            self.legacy.__exit__(None, None, None)
            self.legacy = None
        if self.target is not None:
            self.target.close()


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


def inventory(directory, deadline, coordination=None):
    result = {}
    for path in sorted(directory.iterdir()):
        value = identity(path, deadline)
        if coordination is not None and path == coordination.path:
            coordination.verify()
            # Only this exact no-follow coordination directory may change its
            # routine entries. Its inode/dev/mode remain part of the snapshot.
            value = {k:value[k] for k in ('inode', 'device', 'mode')}
        result[path.name] = value
    return result


class Snapshot:
    def __init__(self, root, target, deadline, *, owner_probe=None, coordination=None):
        self.target, self.deadline = target, deadline
        self.coordination = coordination
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
        self.before = self.inventory()
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
        if self.coordination is not None:
            from target_journal import Journal
            Journal(self.coordination).file_intent(self.path/'recovery.json', self.data['status'], self.data['attempts'])

    def inventory(self):
        return inventory(self.target.parent, self.deadline,
                         self.coordination.directory if self.coordination is not None else None)

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
        if self.inventory() != expected:
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
        observed = self.inventory()
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
        current = self.inventory()
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
        "result = _g.close_status() if _g else {'close_safe': False, 'initial': False}",
        timeout=remaining(deadline))['result']


def open_checked(Handle, Options, path, options, deadline, guarded_source, context,
                 acquired=lambda *_: None, released=lambda *_: None, starting=lambda: None,
                 *, custodian=None):
    """Retry only a guard-confirmed *first* sample failure, never a business call."""
    from ida_nexus import probe_database_state
    root = ida_cli_home()/'idb'
    # Target identity is derived without calling Nexus probe: the new gate must
    # reject damaged coordination before any resolver/owner side effect.
    output = options.get('output_database') or path
    target = Path(output).resolve()
    if target.suffix not in ('.i64', '.idb'):
        target = Path(str(target) + '.i64')
    locking = custodian.gate(target) if custodian else OpenGate(root, target, deadline)
    with locking:
        coordination = custodian.target if custodian else locking.target
        state = probe_database_state(path, output_database=options.get('output_database'))
        snapshot = Snapshot(root, target, deadline, coordination=coordination) if state['state'] in ('crashed', 'unpacked') else None
        for number in range(1, 4):
            logging.getLogger('ida_cli.open').debug('open attempt %d/3: %s', number, target)
            attempt_context = dict(context, open_attempt=number, deadline=deadline)
            if not custodian and number > 1:
                locking.lock()
                locking.target.business_admission()
                from target_journal import Journal
                from owner_identity import state_identity
                Journal(locking.target).gate(state_identity())
            starting()
            current_options = dict(options, startup_timeout=remaining(deadline))
            if custodian:
                handle = custodian.obtain(Handle, Options, path, current_options, attempt_context)
            else:
                handle = Handle.open(path, options=Options(**current_options))
                acquired(handle, attempt_context)
                locking.unlock()
            attempt_context['record_id'] = handle.instance.record_id
            try:
                code = guarded_source('import ida_kernwin\nresult = ida_kernwin.get_kernel_version()', attempt_context)
                if custodian:
                    custodian.execute('guard', guarded_source('pass', attempt_context))
                    custodian.execute('root', guarded_source('pass', attempt_context))
                    actual = custodian.execute('runtime', code)
                else:
                    actual = handle.execute_python(code, timeout=remaining(deadline))
            except Exception as exc:
                try:
                    if custodian:
                        proof = custodian.execute('root',
                            "import sys\n_g=sys.modules.get('_ida_cli_save_guard_v1')\n"
                            "result = _g.close_status() if _g else {'close_safe': False, 'initial': False}")['result']
                    else:
                        proof = failure_state(handle, deadline)
                except Exception as diagnostic:
                    # An already disconnected client cannot run the fresh
                    # guard query. It is never permission to reopen the owner.
                    proof = {'initial': False, 'evidence_error': type(diagnostic).__name__}
                if proof.get('close_safe') is not True:
                    raise RuntimeError('save protection unavailable; owner and exact lease retained; '
                                       'no default close') from exc
                retryable = proof['initial'] and handle.instance.backend == 'idalib'
                if retryable:
                    logging.getLogger('ida_cli.open').warning('Root Node initial-open failure: %s',
                        json.dumps(dict(attempt=number, maximum=3, record_id=handle.instance.record_id,
                                        evidence=proof['evidence'], recovery_snapshot=str(snapshot.path) if snapshot else None)))
                observed, observation_error = None, None
                if snapshot and retryable:
                    # This is an accepted restore obligation, independent of
                    # permission to start the next acquisition.
                    snapshot.deadline = float('inf')
                    try:
                        with custodian.file_gate(recovery=True) if custodian else locking.file_gate():
                            observed = snapshot.failed(number)
                    except Exception as error:
                        observation_error = error
                # Snapshot collection can take time or fail. Its earlier proof
                # classifies the failure; only a new owner sample permits close.
                try:
                    outcome = (custodian.release_for_retry(owner_required=retryable, require_ack=retryable) if custodian else
                               release_handle(handle, deadline, owner_required=retryable))
                except Exception as pending:
                    if custodian and snapshot and observed is not None and observation_error is None:
                        custodian.retain_restore(snapshot, observed)
                    raise RuntimeError('initial open cleanup pending after attempt ' + str(number)
                                       + '; original failure: ' + str(exc) + '; ' + str(pending)) from exc
                if outcome is None or (retryable and not outcome.get('resource_retirement')
                                       and not outcome['release_acknowledged']):
                    raise RuntimeError('open cleanup release unconfirmed; snapshot/scene retained') from exc
                released(handle)
                if observation_error:
                    if custodian:
                        custodian.retain_restore(snapshot, None)
                        custodian.recovery_blocked = True
                        custodian.recovery_error = type(observation_error).__name__ + ': ' + str(observation_error)
                    raise observation_error from exc
                if not retryable:
                    raise RuntimeError('open runtime check failed; no initial Root retry: ' + str(exc)
                                       + '; ' + (outcome['save_guard_error'] or '')) from exc
                if snapshot:
                    with custodian.file_gate(recovery=True) if custodian else locking.file_gate():
                        snapshot.rollback(observed)
                if number == 3:
                    raise RuntimeError('Root Node initial open failed after 3 attempts; '
                                       'original file retained; recovery snapshot/scene retained') from exc
                if custodian:
                    custodian.next_retry()
                continue
            if snapshot:
                with custodian.file_gate() if custodian else locking.file_gate():
                    snapshot.complete()
            if number > 1:
                logging.getLogger('ida_cli.open').warning(
                    'Root Node automatic reopen succeeded after %d attempts: %s', number, handle.instance.record_id)
            return handle, actual, number
