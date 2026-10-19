"""Bounded initial-open retries and conservative, post-recovery rollback."""
import sys


def _verified_maintenance_entry():
    # This is the absolute script entry, before ANY path-based business import.
    native = sys.modules.get('os')
    if native is None or native.__spec__.origin != 'frozen' or native.path.__spec__.origin != 'frozen':
        raise RuntimeError('MaintenanceBlocked: frozen os/path required')
    version = f'python{sys.version_info.major}.{sys.version_info.minor}'
    base, prefix = native.path.realpath(sys.base_prefix), native.path.realpath(sys.prefix)
    stdlib = native.path.join(base,sys.platlibdir,version)
    if not sys._stdlib_dir or native.path.realpath(sys._stdlib_dir) != stdlib:
        raise RuntimeError('MaintenanceBlocked: unrecognized prepared interpreter')
    allowed = (stdlib,native.path.join(stdlib,'lib-dynload'),native.path.join(prefix,'lib',version,'site-packages'))
    for directory in allowed:
        anchor = prefix if directory.startswith(prefix+native.sep) else base
        current = directory
        while True:
            info = native.lstat(current)
            if info.st_mode & 0o170000 != 0o040000 or info.st_uid not in (0,native.getuid()) or info.st_mode & 0o022:
                raise RuntimeError('MaintenanceBlocked: untrusted interpreter search directory')
            if current == anchor:break
            parent = native.path.dirname(current)
            if parent == current:raise RuntimeError('MaintenanceBlocked: invalid interpreter anchor')
            current = parent
    sys.path[:] = list(allowed)
    import hashlib
    import json
    root = native.path.dirname(native.path.abspath(__file__))
    current = root
    while current != '/':
        info = native.lstat(current)
        # A root-owned sticky temporary ancestor is a namespace boundary;
        # descendants still must be exact no-follow private installation paths.
        sticky = info.st_uid == 0 and info.st_mode & 0o1000
        if info.st_mode & 0o170000 != 0o040000 or info.st_uid not in (0,native.getuid()) or (info.st_mode & 0o022 and not sticky):
            raise RuntimeError('MaintenanceBlocked: untrusted installation path chain')
        current = native.path.dirname(current)
    def read(name):
        path = native.path.join(root,name)
        fd = native.open(path,native.O_RDONLY | native.O_NOFOLLOW | native.O_CLOEXEC)
        try:
            before = native.fstat(fd)
            if (before.st_mode & 0o170000 != 0o100000 or before.st_uid != native.getuid()
                    or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > 4*1024*1024):
                raise RuntimeError('MaintenanceBlocked: untrusted entry/manifest identity')
            chunks=[]
            while data := native.read(fd,1024*1024):chunks.append(data)
            after, at_path = native.fstat(fd), native.lstat(path)
            signature=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
            if signature(before) != signature(after) or signature(before) != signature(at_path):
                raise RuntimeError('MaintenanceBlocked: entry changed during same-FD verification')
            return b''.join(chunks), before.st_mode & 0o777
        finally:native.close(fd)
    manifest=json.loads(read('manifest.json')[0])
    if set(manifest) != {'schema','files'} or type(manifest['schema']) is not int or manifest['schema'] != 1:
        raise RuntimeError('MaintenanceBlocked: invalid installation manifest')
    entries={name:read(name) for name in ('open_recovery.py','bootstrap.py')}
    for name,(data,mode) in entries.items():
        if manifest['files'].get(name) != {'sha256':hashlib.sha256(data).hexdigest(),'mode':mode}:
            raise RuntimeError('MaintenanceBlocked: bootstrap/entry manifest mismatch')
    bootstrap={'__name__':'_verified_maintenance_bootstrap','__file__':native.path.join(root,'bootstrap.py')}
    exec(compile(entries['bootstrap.py'][0],bootstrap['__file__'],'exec'),bootstrap)
    sys.argv.insert(1,'open_recovery')
    module=bootstrap['load_entry']()
    return module.maintenance_main()


if __name__ == '__main__':
    raise SystemExit(_verified_maintenance_entry())

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

from cache_store import public_owner_probe
from lifecycle import release_handle


def maintenance_main():
    from protocol import verify_client
    verify_client()
    from recovery_maintenance import main
    return main()


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
            from recovery_legacy import import_known_home
            import_known_home(self.target,self.root)
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
    def __init__(self, root, target, deadline, *, owner_probe=None, coordination=None, custodian=None):
        from recovery_transaction import Transaction
        self.target, self.deadline = target, deadline
        self.coordination = coordination
        self.custodian = custodian
        self.owner_probe = owner_probe or public_owner_probe
        self.names = {target.name, *(target.with_suffix(ext).name
            for ext in ('.id0', '.id1', '.id2', '.nam', '.til'))}
        self.token = None
        self.path = None
        self.active = None
        self.check_owner()
        with self.file_gate() as actual:
            def started(transaction):
                self.active = transaction
                self.path = transaction.directory.path
                self.recovery_id,self.token=transaction.recovery_id,transaction.token
                self.data,self.before=transaction.data,transaction.data['before']
                if custodian is not None:
                    custodian.file_recovery_id=self.recovery_id
                    custodian.file_snapshot=self
                transaction.owner_probe = self.owner_probe
                transaction.copy_hook = self.copy_hook
            try:
                self.recovery_id, self.token = Transaction.create(actual,on_begin=started)
            except BaseException as original:
                self.active=None
                if self.path is not None:
                    try:
                        from acquisition import failure_details
                        with self.transaction() as transaction:
                            transaction.data['cause']=failure_details(original)
                            transaction.save()
                            # No resolver was entered. Retain our partial
                            # snapshot without rolling back later valid saves;
                            # unknown namespace/backup changes still refuse.
                            transaction.register_backups()
                            transaction.expect_unrelated(transaction.data['before'])
                            transaction.archive('snapshot construction failed before resolver; partial evidence retained')
                    except Exception as cleanup_error:
                        if custodian is not None:
                            custodian.recovery_error=type(cleanup_error).__name__+': '+str(cleanup_error)
                            custodian.recovery_blocked=True
                        raise RuntimeError('RecoveryBlocked: snapshot setup '+str(original)
                            +'; independent file_archive_error: '+str(cleanup_error)) from original
                raise
            finally:self.active=None
            with Transaction(actual,self.recovery_id,token=self.token) as transaction:
                self.data = transaction.data
                self.before = self.data['before']

    @contextmanager
    def file_gate(self):
        from target_coordination import Target
        if self.coordination is not None and self.coordination.target_fd is not None:
            yield self.coordination
        else:
            with Target(self.target) as target, target.locked():
                yield target

    @contextmanager
    def transaction(self):
        from recovery_transaction import Transaction
        with self.file_gate() as target:
            with Transaction(target,self.recovery_id,token=self.token) as transaction:
                executor=transaction.data['executor']
                if (not self.token.valid or executor['actor'] != self.token.actor
                        or executor['epoch'] != self.token.epoch):
                    self.token=transaction.resume_executor()
                transaction.owner_probe = self.owner_probe
                transaction.copy_hook = self.copy_hook
                self.active = transaction
                try:
                    yield transaction
                finally:
                    self.data = transaction.data
                    self.active = None

    def journal(self):
        with self.transaction() as transaction:
            transaction.data = self.data
            transaction.save()

    def inventory(self):
        from recovery_files import inventory as inspect
        from target_coordination import Directory
        directory = Directory(self.target.parent,private=False)
        try:
            return inspect(directory,self.coordination.directory if self.coordination is not None else None)
        finally:
            directory.close()

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
        if self.inventory() != expected:
            raise RuntimeError('recovery file identity/directory changed; snapshot/scene retained')

    def copy_hook(self, source, name, destination, expected, mode):
        return self.copy(source.path/name,destination.path/name,expected,mode)

    def copy(self, source, destination, expected, mode):
        from target_coordination import Directory
        if self.active is None or source.name != destination.name or self.path not in destination.parents:
            raise RuntimeError('RecoveryBlocked: copy is restricted to the active private transaction')
        input_directory = Directory(source.parent,private=False)
        output_directory = Directory(destination.parent)
        input_directory.inherit_volume(self.active.directory)
        output_directory.inherit_volume(self.active.directory)
        try:
            return self.active.copy_file(input_directory,source.name,output_directory,expected,mode)
        finally:
            output_directory.close()
            input_directory.close()

    def failed(self, attempt, *, cause=None):
        with self.transaction() as transaction:
            custodian = getattr(self,'custodian',None)
            if custodian is not None:
                from target_journal import Journal
                journal = Journal(transaction.target)
                fields = ('watch','epoch','acquisition','owner','lease','origin_binding')
                self.requirements = [{key:item.get(key) for key in fields}
                    for item in journal.value['entries'].values()
                    if item['acquisition'] == custodian.acquisition]
                if not self.requirements:
                    raise RuntimeError('RecoveryBlocked: failed acquisition has no exact durable resource source')
            observed = transaction.capture_failure(attempt,getattr(self,'requirements',()),cause=cause)
            from target_journal import Journal
            Journal(transaction.target).file_intent(self.path/'recovery.json',transaction.data['status'],transaction.data['attempts'])
            return observed

    def rollback(self, observed):
        """Only after lease AND public owner lifetime release were proved."""
        with self.transaction() as transaction:
            from recovery_files import compatible, file_info
            snapshot = transaction.child('snapshot')
            try:
                for name, expected in transaction.data['snapshot_files'].items():
                    if not compatible(file_info(snapshot,name),expected):
                        raise RuntimeError('RecoveryBlocked: snapshot content changed or identity replaced')
            finally:
                snapshot.close()
            if not transaction.data['attempts']:
                raise RuntimeError('RecoveryBlocked: no failed attempt authorizes rollback')
            if observed != transaction.data['attempts'][-1]['failed']:
                raise RuntimeError('RecoveryBlocked: rollback does not match exact failed attempt')
            if transaction.data['status'] in ('restored','opened','archived'):
                return
            if getattr(self,'custodian',None) is not None:
                # File work is accepted independently of the open future. Its
                # receiver opens its own root SH and receives this exact target
                # OFD; neither caller timeout nor bridge EOF cancels it.
                transaction.require_resources()
                from recovery_job import start
                try:
                    start(transaction)
                except Exception:
                    self.custodian.retain_restore(self,observed)
                    raise
                transaction.data, transaction.info, transaction.raw = transaction.directory.read('recovery.json')
                return
            transaction.restore()
            from target_journal import Journal
            Journal(transaction.target).file_intent(self.path/'recovery.json',transaction.data['status'],transaction.data['attempts'])

    def complete(self):
        with self.transaction() as transaction:
            transaction.register_backups()
            transaction.complete()

    def status(self):
        from target_coordination import Directory,Target
        with Target(self.target,create=False) as target:
            directory=Directory(self.path)
            directory.inherit_volume(target.directory)
            try:
                record,_,_=directory.read('recovery.json')
                if (record.get('recovery_id') != self.recovery_id or record.get('directory') != directory.identity
                        or record.get('target') != self.data['target']):
                    raise RuntimeError('RecoveryBlocked: status transaction identity changed')
                return {'job_id':self.recovery_id,'transaction':str(directory.path),'phase':record['status'],
                        'job':record.get('job'),'executor':record['executor'],'progress':record['progress'],
                        'cause':record.get('cause'),'last_error':record.get('last_error')}
            finally:directory.close()

    def resolver_failed(self, *, no_acquisition):
        with self.transaction() as transaction:
            transaction.register_backups()
            expected = transaction.data['before']
            if transaction.data['status'] == 'restored':
                # A previous attempt published new staged inodes. Compare the
                # exact durable scene of this same transaction, not its original
                # pre-restore inodes and not merely the restored content hashes.
                expected = transaction.data['attempts'][-1]['restored']
                if not expected:
                    raise RuntimeError('RecoveryBlocked: restored transaction lacks exact published scene')
            current=transaction.expect_unrelated(expected,exact_components=True)
            if no_acquisition and current:
                transaction.archive('resolver failed without acquisition; verified original bytes and retained backups')


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
        snapshot = Snapshot(root, target, deadline, coordination=coordination,custodian=custodian) if state['state'] in ('crashed', 'unpacked') else None
        if snapshot is not None:
            snapshot.custodian = custodian
            if custodian is not None:
                custodian.file_recovery_id = snapshot.recovery_id
                custodian.file_snapshot = snapshot
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
            try:
                if custodian:
                    handle = custodian.obtain(Handle, Options, path, current_options, attempt_context)
                else:
                    handle = Handle.open(path, options=Options(**current_options))
                    acquired(handle, attempt_context)
                    locking.unlock()
            except BaseException as original:
                if snapshot:
                    try:
                        with custodian.file_gate(recovery=True) if custodian else locking.file_gate():
                            snapshot.resolver_failed(no_acquisition=custodian.known_no_acquisition() if custodian else False)
                    except Exception as evidence_error:
                        raise RuntimeError('RecoveryBlocked: resolver failure '+str(original)
                                           +'; file/backup responsibility: '+str(evidence_error)) from original
                raise
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
                            from acquisition import failure_details
                            observed = snapshot.failed(number,cause=failure_details(exc))
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
