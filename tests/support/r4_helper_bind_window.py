"""Real helper, paused at bind publication; no handler or protocol substitution."""
import json
import os
from pathlib import Path
import runpy
import select
import socket
import stat
import sys

script, endpoint, incarnation, capacity, bound_fd, release_fd = sys.argv[1:]
bound_fd, release_fd = int(bound_fd), int(release_fd)
actual_bind = socket.socket.bind


def paused_bind(stream, address):
    result = actual_bind(stream, address)
    if str(address) == endpoint:
        # Controlled unpublished-mode input, regardless of the caller's umask.
        # The production main still performs its original chmod(0600)/listen.
        os.chmod(endpoint, 0o755)
        info = Path(endpoint).lstat()
        data = json.dumps(dict(uid=info.st_uid, mode=stat.S_IMODE(info.st_mode),
                               inode=[info.st_dev, info.st_ino])).encode() + b'\n'
        assert os.write(bound_fd, data) == len(data)
        os.close(bound_fd)
        if not select.select([release_fd], [], [], 3)[0] or os.read(release_fd, 1) != b'x':
            raise TimeoutError('test bind publication barrier was not released')
        os.close(release_fd)
    return result


socket.socket.bind = paused_bind
sys.path.insert(0, str(Path(script).parent))
sys.argv = [script, endpoint, incarnation, capacity]
runpy.run_path(script, run_name='__main__')
