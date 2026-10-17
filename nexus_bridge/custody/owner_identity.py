"""Non-sensitive physical identity; authentication-bearing instances stay local."""
import math
import os
from pathlib import Path
from target_coordination import canonical


def state_identity():
    from ida_nexus import get_state_dir
    path = Path(canonical(get_state_dir()))
    configured = os.environ.get('IDA_NEXUS_STATE_DIR')
    if not configured or not Path(configured).is_absolute() or canonical(configured) != str(path):
        raise RuntimeError('ProtocolMismatch: fixed absolute state root required before import')
    info = path.stat()
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid}


def owner_key(instance, state=None):
    return {'state_root': state or state_identity(), 'record_id': instance.record_id,
            'pid': instance.pid, 'started_at': instance.started_at,
            'canonical_idb_path': canonical(instance.idb_path), 'backend': instance.backend}


def validate_owner(value):
    if (not isinstance(value, dict) or set(value) != {'state_root', 'record_id', 'pid',
            'started_at', 'canonical_idb_path', 'backend'} or value['state_root'] != state_identity()
            or type(value['pid']) is not int or value['pid'] <= 0
            or not isinstance(value['record_id'], str) or not value['record_id']
            or type(value['started_at']) not in (int, float) or not math.isfinite(value['started_at']) or value['started_at'] <= 0
            or value['canonical_idb_path'] != canonical(value['canonical_idb_path'])
            or value['backend'] not in ('idalib', 'gui')):
        raise ValueError('ProtocolMismatch: incomplete physical OwnerKey or wrong state root')
    return value
