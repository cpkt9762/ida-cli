"""Private R0 prototype primitives. These are not production proof interfaces."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import array
import stat


def fork():
    """Register every own native child in this case before returning to its parent."""
    from process_identity import identity
    pid = os.fork()
    if pid:
        folder = Path(os.environ["R0_CASE_ROOT"]) / "owned-processes"
        folder.mkdir(mode=0o700, exist_ok=True)
        durable(folder / f"{pid}.json", {"pid":pid, "parent":os.getpid(),
                "identity":identity(pid), "source":"r0-native-fork"})
    return pid


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else
                          json.dumps(value, sort_keys=True).encode()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def durable_boundary(path, stage):
    """Fault barrier inside the atomic write; the normal path has no action."""


def private_info(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise RuntimeError("UntrustedPendingWrite:identity_or_permissions")
    return info


def pending_owner(owner):
    fd = os.open(owner, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = private_info(fd)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            record = json.loads(stream.read(4096))
        return record, info
    finally:
        os.close(fd)


def unlink_owned(path, info):
    current = path.lstat()
    if (current.st_dev, current.st_ino, current.st_mode, current.st_nlink) != (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink):
        raise RuntimeError("UntrustedPendingWrite:identity_changed")
    path.unlink()


def pending_record(path, info, data):
    return {"schema":1, "writer":"r0-durable", "target":path.name,
            "inode":info.st_ino, "device":info.st_dev, "sha256":digest(data)}


def finish_renamed(path, owner):
    """A crash after rename can leave just the bound ownership record."""
    record, owner_info = pending_owner(owner)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = private_info(fd)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read()
        if record != pending_record(path, info, data):
            raise RuntimeError("UntrustedPendingWrite:published_identity_or_content")
        sync_dir(path.parent)
        unlink_owned(owner, owner_info)
        sync_dir(path.parent)
    finally:
        os.close(fd)


def durable(path, value):
    """Single writer; exact pending inode/content and private ownership record.

    Callers serialize each path (target EX for Store). Unknown/partial/conflicting
    slots are preserved as explicit errors, even if their bytes happen to match.
    At most one temporary plus one ownership record per destination is retained.
    """
    path = Path(path)
    temp = path.with_name(path.name + ".new")
    owner = temp.with_name(temp.name + ".owner")
    data = json.dumps(value, sort_keys=True).encode()
    if not temp.exists() and owner.exists():
        finish_renamed(path, owner)
    try:
        fd = os.open(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
    except FileExistsError:
        fd = os.open(temp, os.O_RDWR | os.O_NOFOLLOW)
        created = False
    try:
        info = private_info(fd)
        record = pending_record(path, info, data)
        if created:
            marker_fd = os.open(owner, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(marker_fd, 'wb') as stream:
                stream.write(json.dumps(record, sort_keys=True).encode())
                stream.flush()
                os.fsync(stream.fileno())
            sync_dir(path.parent)
        stored, owner_info = pending_owner(owner)
        if stored != record:
            raise RuntimeError("UntrustedPendingWrite:ownership_or_content")
        with os.fdopen(fd, "r+b", closefd=False) as stream:
            if not created and stream.read() != data:
                raise RuntimeError("UntrustedPendingWrite:content_conflict")
            stream.seek(0)
            stream.write(data)
            stream.flush()
            durable_boundary(path, "temp_written")
            os.fsync(stream.fileno())
            durable_boundary(path, "file_fsynced")
        current = temp.lstat()
        if (current.st_dev, current.st_ino, current.st_mode, current.st_nlink) != (
                info.st_dev, info.st_ino, info.st_mode, info.st_nlink):
            raise RuntimeError("UntrustedPendingWrite:identity_changed")
        durable_boundary(path, "before_rename")
        os.replace(temp, path)
        durable_boundary(path, "after_rename")
        sync_dir(path.parent)
        durable_boundary(path, "directory_fsynced")
        unlink_owned(owner, owner_info)
        sync_dir(path.parent)
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def lock(path, mode=fcntl.LOCK_EX, nb=False):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, mode | (fcntl.LOCK_NB if nb else 0))
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextmanager
def ordered(root, target):
    root_fd = lock(root, fcntl.LOCK_SH)
    try:
        target_fd = lock(target)
        try:
            yield target_fd
        finally:
            os.close(target_fd)
    finally:
        os.close(root_fd)


def blocked(path):
    try:
        fd = lock(path, nb=True)
    except BlockingIOError:
        return True
    os.close(fd)
    return False


def send_fd(channel, fd, payload):
    return channel.sendmsg([json.dumps(payload).encode()],
                           [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])


def recv_fd(channel):
    data, ancillary, flags, _address = channel.recvmsg(4096, socket.CMSG_SPACE(4))
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise RuntimeError("truncated transfer")
    descriptors = array.array("i")
    for level, kind, content in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            descriptors.frombytes(content[:len(content) - len(content) % descriptors.itemsize])
    if len(descriptors) != 1:
        for fd in descriptors:
            os.close(fd)
        raise RuntimeError("exactly one FD required")
    return descriptors[0], json.loads(data)
