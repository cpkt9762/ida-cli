"""Fresh SDK process for one exact maintenance state-root occupancy check."""
import json
import os
from pathlib import Path
import sys

from target_coordination import Directory


def bind_state(value):
    if (type(value) is not dict or set(value) != {'path','device','inode','uid'}
            or any(type(value[k]) is not int for k in ('device','inode','uid'))):
        raise RuntimeError('MaintenanceBlocked: exact state-root identity required')
    path=Path(value['path'])
    if not path.is_absolute() or str(path) != os.path.realpath(path):
        raise RuntimeError('MaintenanceBlocked: state root must be canonical absolute')
    directory=Directory(path,private=False)
    try:
        if directory.identity != [value['device'],value['inode'],value['uid']]:
            raise RuntimeError('MaintenanceBlocked: state-root identity changed')
    finally:directory.close()
    os.environ['IDA_NEXUS_STATE_DIR']=str(path)


def main():
    if len(sys.argv) != 3:
        raise RuntimeError('MaintenanceBlocked: exact state-root and target required')
    bind_state(json.loads(sys.argv[1]))
    from cache_store import public_owner_probe
    print(json.dumps({'reason':public_owner_probe(Path(sys.argv[2]))}))
