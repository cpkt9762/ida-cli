"""Public owner release proof and metadata-only open failure diagnostics."""
from pathlib import Path
import time
import threading


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


def release_state(handle):
    """The exact handle retains its one-shot request and all observed errors."""
    return vars(handle).setdefault('_ida_cli_release', {
        'lock': threading.RLock(), 'requested': False, 'outcome': None, 'errors': []})


def save_guard_error(handle):
    return '; '.join(release_state(handle)['errors']) or None


def release_errors(handle):
    return tuple(release_state(handle)['errors'])


def close_check(handle, deadline):
    return handle.execute_python(
        "import sys\n_g=sys.modules.get('_ida_cli_save_guard_v1')\n"
        "result=_g.close_status() if _g else {'close_safe': False}",
        timeout=max(.001, deadline-time.monotonic()))['result']


def release_handle(handle, deadline, publish=lambda *_: None, *, check=None,
                   errors=(), owner_required=False, request_only=False):
    """One guarded release; groups request all own leases before waiting for proof.

    request_only returns the raw request outcome, never a logical release proof.
    Subsequent calls coordinate public proof without repeating guard or release.
    """
    from ida_nexus import wait_database_released
    state = release_state(handle)
    if not state['lock'].acquire(timeout=max(0, deadline-time.monotonic())):
        raise TimeoutError('lease release already in progress; exact handle retained')
    try:
        for message in errors:
            if message and message not in state['errors']:
                state['errors'].append(message)
        if not state['requested']:
            if time.monotonic() >= deadline:
                raise TimeoutError('release deadline expired; exact handle retained')
            proof = check() if check else close_check(handle, deadline)
            message = proof.get('save_guard_error')
            if message and message not in state['errors']:
                state['errors'].append(message)
            if proof.get('close_safe') is not True:
                raise RuntimeError('save protection unavailable; owner and exact lease retained; no default close'
                                   + ('; ' + save_guard_error(handle) if state['errors'] else ''))
            # Latch before calling: even an exception is never permission to replay.
            state['requested'] = True
            try:
                state['outcome'] = handle.close_outcome(wait_for_database=False,
                    timeout=max(0, deadline-time.monotonic()))
            except Exception as exc:
                state['outcome'] = {'status': 'uncertain', 'lease_released': False,
                                    'failure': type(exc).__name__}
        outcome = dict(state['outcome'], save_guard_error=save_guard_error(handle),
                       release_acknowledged=state['outcome'].get('lease_released') is True)
        if request_only:
            return outcome
        if state.get('owner_proved'):
            return dict(outcome, status='owner_released', owner_released=True,
                        lease_released=True, failure=None, proof='public_owner_lifetime')
        if (not owner_required and outcome.get('status') == 'lease_released'
                and outcome.get('lease_released') is True
                and outcome.get('shutdown_pending') is False):
            return outcome
        publish('uncertain', outcome)
        if wait_database_released(handle.instance, timeout=max(0, deadline-time.monotonic())):
            state['owner_proved'] = True
            return dict(outcome, status='owner_released', owner_released=True,
                        lease_released=True, failure=None, proof='public_owner_lifetime')
        publish('release_unconfirmed', outcome)
        return None
    finally:
        state['lock'].release()
