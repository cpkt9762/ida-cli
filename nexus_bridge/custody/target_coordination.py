"""Target-side coordination, immutable observations and bounded healthy epochs.

All target authority changes require root SH followed by the stable target EX.
An unrecognized or torn record is retained and blocks this target.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

SCHEMA = 1
LIMIT = 96
RESERVE = 8
SUMMARY_LIMIT = 64
SUMMARY_BYTES = 16384
MAX_RECORD = 1024 * 1024


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid]


def checked(fd, directory=False):
    value = os.fstat(fd)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(value.st_mode) or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != (0o700 if directory else 0o600)
            or (not directory and value.st_nlink != 1)):
        raise RuntimeError('CoordinationBlocked: untrusted type/uid/mode/link identity')
    return value


class Directory:
    def __init__(self, path, *, private=True, _fd=None):
        self.path = Path(path)
        self.fd = _fd if _fd is not None else self.open_path(self.path)
        value = os.fstat(self.fd)
        try:
            if private:
                checked(self.fd, True)
            elif not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, os.getuid()):
                raise RuntimeError('CoordinationBlocked: target parent ownership')
            self.identity = identity(value)
        except BaseException:
            os.close(self.fd)
            raise

    @staticmethod
    def open_path(path):
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('absolute coordination path required')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=fd)
                os.close(fd)
                fd = next_fd
            result, fd = fd, None
            return result
        finally:
            if fd is not None:
                os.close(fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def verify(self):
        if identity(os.stat(self.path, follow_symlinks=False)) != self.identity:
            raise RuntimeError('CoordinationBlocked: directory identity changed')

    def child(self, name, *, create=True):
        if not name or Path(name).name != name or name in ('.', '..'):
            raise ValueError('unsafe coordination component')
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=self.fd)
                os.fsync(self.fd)
            except FileExistsError:
                pass
        self.verify()
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        result = Directory(self.path / name, _fd=fd)
        try:
            result.verify()
            self.verify()
            return result
        except BaseException:
            result.close()
            raise

    def read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = checked(fd)
            if before.st_size > MAX_RECORD:
                raise RuntimeError('CoordinationBlocked: oversized record')
            data = os.read(fd, MAX_RECORD + 1)
            after = os.fstat(fd)
            at_path = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or identity(before) != identity(at_path) or len(data) != before.st_size):
                raise RuntimeError('CoordinationBlocked: record changed during read')
            return json.loads(data), before, data
        finally:
            os.close(fd)

    def durable(self, name, value, *, immutable=False):
        from durable_records import write
        write(self, name, value, immutable=immutable)

    def recover_record(self, name, *, validate=None):
        from durable_records import resume
        return resume(self, name, validate=validate)

    def retry_immutable(self, name, value, *, immutable=True):
        """Resume only this producer's durably reserved exact immutable slot."""
        data = encoded(value)
        if len(data) > MAX_RECORD or Path(name).name != name:
            raise ValueError('invalid immutable fact slot')
        temporary = name + '.new'
        # Publication can fail between link and unlink. Only the two exact
        # names of this reserved slot may share the completed immutable inode.
        if immutable:
            try:
                final = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                pending = os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if (identity(final) == identity(pending) and final.st_nlink == 2
                        and stat.S_ISREG(final.st_mode) and final.st_uid == os.getuid()
                        and stat.S_IMODE(final.st_mode) == 0o600):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
                    try:
                        if identity(os.fstat(fd)) != identity(final) or os.read(fd, MAX_RECORD+1) != data:
                            raise RuntimeError('ObservationRecoveryBlocked: linked fact conflict')
                        self.verify()
                        if identity(os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)) != identity(final):
                            raise RuntimeError('ObservationRecoveryBlocked: pending link changed')
                        os.unlink(temporary, dir_fd=self.fd)
                        os.fsync(self.fd)
                    finally:
                        os.close(fd)
        try:
            current, _, raw = self.read(name)
        except FileNotFoundError:
            pass
        else:
            if immutable:
                if raw != data or current != value:
                    raise RuntimeError('ObservationRecoveryBlocked: immutable fact conflict')
                os.fsync(self.fd)
                return
        try:
            fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self.fd)
        except FileExistsError:
            fd = os.open(temporary, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = checked(fd)
            prefix = os.read(fd, MAX_RECORD + 1)
            if not data.startswith(prefix) or len(prefix) != before.st_size:
                raise RuntimeError('ObservationRecoveryBlocked: reserved fact partial content conflict')
            self.verify()
            if identity(before) != identity(os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)):
                raise RuntimeError('ObservationRecoveryBlocked: reserved fact inode changed')
            view = memoryview(data)[len(prefix):]
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError('short immutable fact write')
                view = view[count:]
            os.fsync(fd)
            if immutable:
                os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
                os.unlink(temporary, dir_fd=self.fd)
            else:
                os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)

    def lock(self, name='lock', *, shared=False, deadline=None, nb=False):
        created = False
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=self.fd)
            created = True
        except FileExistsError:
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            value = checked(fd)
            if created:
                os.fsync(fd)
                os.fsync(self.fd)
            while True:
                try:
                    fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if nb or deadline is None or time.monotonic() >= deadline:
                        raise
                    time.sleep(min(.005, max(0, deadline - time.monotonic())))
            if identity(value) != identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)):
                raise RuntimeError('CoordinationBlocked: stable lock replaced')
            self.verify()
            return fd
        except BaseException:
            os.close(fd)
            raise


def canonical(path):
    return os.path.realpath(os.path.abspath(os.path.expanduser(os.fspath(path))))


def folded(path):
    value = canonical(path)
    return value.casefold() if sys.platform == 'darwin' else os.path.normcase(value) if os.name == 'nt' else value


class Target:
    def __init__(self, target, *, root_locked=False):
        self.target = Path(canonical(target))
        self.root = None
        self.directories = []
        self.root_fd = self.target_fd = None
        try:
            # Evidence paths cannot silently become ordinary business targets.
            if any(part.startswith('.ida-cli-txn-') or part == '.nexus-coordination'
                   for part in self.target.parts):
                raise RuntimeError('CoordinationBlocked: evidence is not a business target')
            container = self.target.parent.parent
            self.binding = None
            if container.name in ('generations', 'quarantine'):
                self.root = Directory(container.parent, private=False)
                self.directories.append(self.root)
                if not root_locked:
                    self.root_fd = self.root.lock('.cache.lock', shared=True)
                gid = self.target.parent.name
                if not gid or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in gid):
                    raise RuntimeError('CoordinationBlocked: invalid generation identity')
                # A rename into quarantine retains exactly the same generation
                # inode/manifest and stable lock. Missing payloads require the
                # already established coordination identity; never make a new one.
                paths = [container.parent / name / gid for name in ('generations', 'quarantine')]
                existing = [p for p in paths if p.exists() or p.is_symlink()]
                if len(existing) > 1:
                    raise RuntimeError('CoordinationBlocked: generation identity collision')
                if existing:
                    parent = Directory(existing[0], private=False)
                    self.directories.append(parent)
                    fd = os.open('generation.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent.fd)
                    try:
                        info = os.fstat(fd)
                        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                                or info.st_nlink != 1 or info.st_size > MAX_RECORD
                                or stat.S_IMODE(info.st_mode) & 0o022):
                            raise RuntimeError('CoordinationBlocked: invalid generation manifest identity')
                        raw = os.read(fd, MAX_RECORD + 1)
                        manifest = json.loads(raw)
                        if (not isinstance(manifest, dict) or type(manifest.get('version')) is not int
                                or manifest['version'] != 1 or not isinstance(manifest.get('key'), str)
                                or not manifest['key'] or len(raw) != info.st_size):
                            raise RuntimeError('CoordinationBlocked: invalid generation manifest')
                        self.binding = {'group':parent.identity, 'manifest':[info.st_dev, info.st_ino],
                                        'sha256':digest(raw)}
                    finally:
                        os.close(fd)
                parent = self.root
                coordination = self.root.child('.nexus-coordination')
                self.directories.append(coordination)
                generations = coordination.child('generations')
                self.directories.append(generations)
                self.directory = generations.child(gid, create=bool(existing))
                self.key = {'kind':'generation', 'root':self.root.identity, 'gid':gid}
                self.original = str(container.parent / 'generations' / gid / 'input.i64')
            else:
                parent = Directory(self.target.parent, private=False)
                self.directories.append(parent)
                key = digest(folded(self.target).encode())
                self.directory = parent.child('.ida-cli-txn-' + key)
                self.key = {'kind':'direct', 'parent':parent.identity, 'identity_key':key}
                self.original = str(self.target)
            self.directories.append(self.directory)
            if self.directory.identity[0] != parent.identity[0]:
                raise RuntimeError('CoordinationBlocked: coordination crosses target volume')
        except BaseException:
            self.close()
            raise

    def business_admission(self):
        """Evidence/GC access keeps its identity; business may only use live payload."""
        if self.target_fd is None:
            raise RuntimeError('business admission requires target EX')
        if self.root is not None:
            live = self.root.path / 'generations' / self.key['gid']
            isolated = self.root.path / 'quarantine' / self.key['gid']
            if isolated.exists():
                raise RuntimeError('TargetQuarantined: payload is reserved for GC/evidence')
            if not live.exists():
                raise RuntimeError('TargetRetired: payload is reserved for GC/evidence')
            if self.target.parent.parent.name == 'quarantine':
                raise RuntimeError('TargetQuarantined: quarantine is not a business path')
            if identity(os.stat(live, follow_symlinks=False)) != self.binding['group']:
                raise RuntimeError('CoordinationBlocked: live payload identity changed')

    @contextmanager
    def locked(self, *, deadline=None, nb=False, recover=True):
        fd = self.directory.lock(deadline=deadline, nb=nb)
        self.target_fd = fd
        try:
            if recover:
                self.directory.recover_record('target.json')
            expected = {'schema':SCHEMA, 'coord_key':self.key, 'target':self.original,
                        'generation':self.binding, 'lock_identity':identity(os.fstat(fd))}
            try:
                value, _, _ = self.directory.read('target.json')
                if self.root is not None and self.binding is None:
                    expected['generation'] = value.get('generation')
                if (recover and encoded(value) == encoded(dict(expected, creation_intent=True))
                        and set(os.listdir(self.directory.fd)) == {'lock','target.json'}):
                    self.directory.durable('target.json', expected)
                    value = expected
                if encoded(value) != encoded(expected) or (self.root is not None and not expected['generation']):
                    raise RuntimeError('CoordinationBlocked: target identity mismatch')
            except FileNotFoundError:
                if self.root is not None and self.binding is None:
                    raise RuntimeError('CoordinationBlocked: missing payload has no stable identity') from None
                if set(os.listdir(self.directory.fd)) != {'lock'}:
                    raise RuntimeError('CoordinationBlocked: missing target identity with existing responsibilities') from None
                # A crash at either durable boundary preserves an explicit
                # uncommitted identity instead of blessing a partial namespace.
                self.directory.durable('target.json', dict(expected, creation_intent=True), immutable=True)
                self.directory.durable('target.json', expected)
            yield self
        finally:
            self.target_fd = None
            os.close(fd)

    def close(self):
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None
        for directory in reversed(self.directories):
            directory.close()
        self.directories.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
