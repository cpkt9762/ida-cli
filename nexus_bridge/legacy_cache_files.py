"""No-follow, identity-bound files for explicit legacy cache maintenance."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time
import uuid

from target_coordination import Directory


TIMEOUT_ENV = 'IDA_CLI_LEGACY_TIMEOUT_SECS'
DEFAULT_TIMEOUT = 1800
_interrupted = None
_deadline = None
_rollback = False


class MaintenanceInterrupted(RuntimeError):
    """A cooperative interrupt observed before another mutation/chunk."""


def timeout_policy():
    raw = os.environ.get(TIMEOUT_ENV, str(DEFAULT_TIMEOUT))
    if not raw.isascii() or not raw.isdigit() or not 1 <= int(raw) <= 3600:
        raise ValueError(TIMEOUT_ENV + ' must be an integer between 1 and 3600')
    return {'seconds': int(raw), 'rollback_grace_seconds': 35,
            'configuration': TIMEOUT_ENV, 'default_seconds': DEFAULT_TIMEOUT}


def begin_runtime():
    global _interrupted, _deadline
    _interrupted = None
    _deadline = time.monotonic() + timeout_policy()['seconds']
    def requested(number, _frame):
        global _interrupted
        _interrupted = signal.Signals(number).name
    previous = {number: signal.signal(number, requested) for number in (signal.SIGTERM, signal.SIGINT)}
    return previous


def end_runtime(previous):
    global _interrupted, _deadline
    for number, handler in previous.items():
        signal.signal(number, handler)
    _interrupted = _deadline = None


def checkpoint():
    if not _rollback:
        if _interrupted:
            raise MaintenanceInterrupted('maintenance interrupted by ' + _interrupted)
        if _deadline is not None and time.monotonic() >= _deadline:
            raise MaintenanceInterrupted('maintenance time budget expired')


def remaining_seconds():
    checkpoint()
    return max(1, int(_deadline - time.monotonic()) + 1) if _deadline is not None else timeout_policy()['seconds']


@contextmanager
def rollback_window():
    global _rollback
    previous, _rollback = _rollback, True
    try:
        yield
    finally:
        _rollback = previous


def directory(path, *, private=False):
    checkpoint()
    path = Path(path)
    handle = Directory(path, private=private)
    handle.close()
    return path


def object_id(path):
    value = path.lstat()
    return [value.st_dev, value.st_ino, value.st_uid]


@contextmanager
def opened(path):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & 0o022):
            raise ValueError('untrusted file type/owner/mode/link: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            yield stream, before
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (any(getattr(before, k) != getattr(after, k) for k in fields)
                or object_id(path) != [before.st_dev, before.st_ino, before.st_uid]):
            raise ValueError('file changed during read: ' + str(path))
    finally:
        os.close(fd)


def read(path):
    # Only small metadata uses in-memory reads. IDBs and snapshots stream.
    with opened(path) as (stream, info):
        if info.st_size > 16 * 1024 * 1024:
            raise ValueError('oversized metadata file: ' + str(path))
        return stream.read()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(path):
    if path.is_symlink():
        return {'name': path.name, 'unsafe': 'symlink'}
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode):
        return {'name': path.name, 'unsafe': 'non-regular file'}
    with opened(path) as (stream, info):
        hasher = hashlib.sha256()
        for block in iter(lambda: stream.read(64 * 1024), b''):
            checkpoint()
            hasher.update(block)
        result = {'name': path.name, 'bytes': info.st_size, 'sha256': hasher.hexdigest(),
                  'identity': [info.st_dev, info.st_ino, info.st_uid]}
    return result


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, data):
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync(path.parent)


def replace(path, data, expected):
    """Only replace metadata whose exact currently approved bytes still match."""
    current = optional(path)
    if current != expected:
        raise ValueError('metadata changed; refusing replacement: ' + str(path))
    temporary = path.with_name('.n8tool-' + uuid.uuid4().hex)
    create(temporary, data)
    try:
        if optional(path) != expected:
            raise ValueError('metadata changed during publication')
        checkpoint()
        os.replace(temporary, path)
        sync(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def optional(path):
    try:
        return read(path)
    except FileNotFoundError:
        return None


def index(path):
    raw = optional(path)
    value = json.loads(raw) if raw is not None else {}
    if type(value) is not dict:
        raise ValueError('invalid index: ' + str(path))
    return raw, value


def metadata(root):
    result = {}
    for name in ('index.json', 'nexus-index.json'):
        raw, value = index(root/name)
        if name == 'nexus-index.json' and any(type(k) is not str or type(v) is not str for k, v in value.items()):
            raise ValueError('invalid generation index')
        result[name] = {'sha256': digest(raw) if raw is not None else None, 'value': value}
    return result


def matches(path, expected):
    actual = fingerprint(path)
    return actual.get('bytes') == expected['bytes'] and actual.get('sha256') == expected['sha256']


def copy_verified(source, destination, expected):
    directory(destination.parent)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with opened(source) as (input_stream, info), os.fdopen(fd, 'wb', closefd=False) as output:
            hasher = hashlib.sha256()
            for block in iter(lambda: input_stream.read(64 * 1024), b''):
                checkpoint()
                hasher.update(block)
                output.write(block)
            if info.st_size != expected['bytes'] or hasher.hexdigest() != expected['sha256']:
                raise ValueError('source changed before backup/copy: ' + str(source))
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync(destination.parent)
    if not matches(destination, expected):
        raise ValueError('copied bytes failed hash verification: ' + str(destination))


def safe_name(name):
    if type(name) is not str or not name or Path(name).name != name or name in ('.', '..'):
        raise ValueError('unsafe filename')
    return name


def restore_files(root, backup, manifest):
    """Idempotent rollback, never overwrite an unexplained destination."""
    for item in manifest['files']:
        name = safe_name(item['name'])
        if not matches(backup/'files'/name, item):
            raise ValueError('backup failed hash verification: ' + name)
        if (root/name).exists() or (root/name).is_symlink():
            if not matches(root/name, item):
                raise ValueError('restore collision; both copies retained: ' + name)
    metadata_updates = []
    for name in ('index.json', 'nexus-index.json'):
        item = manifest['indices'][name]
        before = read(backup/'indices'/name) if item['before'] is not None else None
        if before is not None and digest(before) != item['before']:
            raise ValueError('backup index failed hash verification')
        current = optional(root/name)
        current_hash = digest(current) if current is not None else None
        if current_hash not in (item['before'], item['after']):
            raise ValueError('restore index collision; metadata retained: ' + name)
        metadata_updates.append((name, before, current))
    for item in manifest['files']:
        name = item['name']
        if not (root/name).exists():
            # Publish restored bytes only after a full verified copy. A signal
            # while copying must never leave an ambiguous partial original.
            from cache_store import rename_group
            temporary = root/('.n8tool-restore-' + uuid.uuid4().hex)
            copy_verified(backup/'files'/name, temporary, item)
            checkpoint()
            rename_group(temporary, root/name)
            sync(root)
    for name, before, current in metadata_updates:
        if current == before:
            continue
        if before is None:
            if optional(root/name) != current:
                raise ValueError('restore index changed before removal')
            (root/name).unlink()
            sync(root)
        else:
            replace(root/name, before, current)
