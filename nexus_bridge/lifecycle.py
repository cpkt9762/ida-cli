"""Public owner release proof and metadata-only open failure diagnostics."""
from pathlib import Path
import time


def database_diagnostics(path):
    from ida_nexus import discover_databases, wait_database_released
    target = Path(path).resolve()
    if target.suffix not in ('.i64', '.idb'):
        target = Path(str(target) + '.i64')
    result = {'target': str(target), 'components': [], 'owners': [],
              'lifetime': 'no_registered_owner_proof'}
    try:
        for entry in sorted(target.parent.iterdir()):
            if (entry.name == target.name or entry.stem == target.stem
                    or entry.name.startswith(target.name + '.')) and entry.suffix in (
                    '.i64', '.idb', '.id0', '.id1', '.id2', '.nam', '.til'):
                info = entry.lstat()
                result['components'].append({'path': str(entry), 'size': info.st_size,
                                             'mtime_ns': info.st_mtime_ns})
    except OSError as exc:
        result['components_error'] = type(exc).__name__
    try:
        for item in discover_databases(timeout=0.2):
            if Path(item.instance.idb_path).resolve() == target:
                result['owners'].append({'instance_id': item.instance.record_id,
                    'pid': item.instance.pid, 'state': item.state.value,
                    'lifetime_released': wait_database_released(item.instance, timeout=0)})
        if result['owners']:
            result['lifetime'] = 'released' if all(
                item['lifetime_released'] for item in result['owners']) else 'held'
    except Exception as exc:
        result['discovery_error'] = type(exc).__name__
    return result


def release_handle(handle, deadline, publish):
    """Publish uncertainty before one bounded, read-only public lifetime wait."""
    from ida_nexus import wait_database_released
    outcome = handle.close_outcome(wait_for_database=True,
                                   timeout=max(0, deadline - time.monotonic()))
    if outcome['status'] in ('lease_released', 'owner_released'):
        return outcome
    publish('uncertain', outcome)
    if wait_database_released(handle.instance, timeout=max(0, deadline - time.monotonic())):
        return {'status': 'owner_released', 'owner_released': True,
                'lease_released': True, 'proof': 'public_owner_lifetime'}
    publish('release_unconfirmed', outcome)
    return None
