"""Private R0 prototype primitives. These are not production proof interfaces."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import array


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


def durable(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".new")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        data = json.dumps(value, sort_keys=True).encode()
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        if temp.exists():
            temp.unlink()


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
