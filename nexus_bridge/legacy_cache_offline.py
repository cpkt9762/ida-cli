"""Operator-maintained exclusion plus continuous cooperating-opener guards.

Public probes are vetoes, never an offline proof. Independent IDA and remote
writers must be stopped and prevented throughout the declared offline window.
"""
from contextlib import ExitStack, contextmanager
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

from custody_process_identity import identity
from legacy_cache_files import directory, object_id, read
from target_coordination import Directory

CONFIRMATION = 'I established and maintain this exclusive offline window'
SCOPE = {'all_target_openers_stopped': True, 'new_openers_prevented': True,
         'cross_uid_openers_excluded': True, 'remote_writers_excluded': True,
         'automatic_restarts_prevented': True}


def binding(path):
    directory(path)
    return {'path': str(path), 'identity': object_id(path)}


def boot():
    current = identity(os.getpid())
    if current is None:
        raise RuntimeError('current boot identity unavailable')
    return current['boot_id']


def validate(evidence, plan_hash, root, homes, states):
    if (type(evidence) is not dict or evidence.get('schema') != 1
            or evidence.get('plan_sha256') != plan_hash
            or evidence.get('root') != binding(root)
            or evidence.get('router_homes') != [binding(p) for p in homes]
            or evidence.get('state_roots') != [binding(p) for p in states]
            or evidence.get('boot_id') != boot()
            or evidence.get('uid') != os.getuid()
            or type(evidence.get('operator')) is not str or not evidence['operator'].strip()
            or type(evidence.get('exclusion_method')) is not str or not evidence['exclusion_method'].strip()
            or evidence.get('confirmation') != CONFIRMATION
            or evidence.get('offline_scope') != SCOPE):
        raise RuntimeError('offline evidence does not bind this plan/boot/directories/operator/scope')
    start, end = evidence.get('started_at'), evidence.get('expires_at')
    if (type(start) not in (int, float) or type(end) not in (int, float)
            or not math.isfinite(start) or not math.isfinite(end)
            or not start <= time.time() < end or not 0 < end-start <= 3600):
        raise RuntimeError('offline window expired or invalid (maximum 3600 seconds)')
    if not homes or not states:
        raise RuntimeError('complete router-home and Nexus state-root inventories required')


def assert_daemon_offline(home):
    directory(home)
    for name in ('server.sock', 'mcp.sock'):
        path = home/name
        if path.exists() or path.is_symlink():
            raise RuntimeError('router socket still present; stop router and resolve stale socket explicitly: ' + str(path))
    pidfile = home/'server.pid'
    try:
        pid = int(read(pidfile).decode().strip())
    except FileNotFoundError:
        return
    if pid <= 0:
        raise ValueError('invalid router PID')
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    raise RuntimeError('router PID is still alive or reused: ' + str(pidfile))


@contextmanager
def locked(root, homes, targets):
    """Hold all guards for the complete backup/publication/removal/rollback."""
    from target_coordination import Target
    from target_journal import Journal
    with ExitStack() as stack:
        for home in homes:
            handle = Directory(home, private=False)
            stack.callback(handle.close)
            fd = handle.lock('.startup.lock', nb=True)
            stack.callback(os.close, fd)
            assert_daemon_offline(home)
        handle = Directory(root, private=False)
        stack.callback(handle.close)
        fd = handle.lock('.cache.lock', nb=True)
        stack.callback(os.close, fd)
        for path in sorted(set(targets)):
            target = stack.enter_context(Target(path, root_locked=True))
            stack.enter_context(target.locked(nb=True))
            journal = Journal(target)
            journal.gate()
            journal.settle()
            if journal.value['entries'] or journal.value.get('file_intents'):
                raise RuntimeError('unsettled target custody; offline permission does not retire obligations')
        yield


def child_argv(*arguments):
    if '__verified_source__' in globals():
        return [sys.executable, '-I', '-B', str(Path(__file__).parent/'bootstrap.py'), 'legacy_cache', *arguments]
    return [sys.executable, '-B', str(Path(__file__).with_name('legacy_cache.py')), *arguments]


def observe(path, states, *, read_only=True):
    """Fresh SDK import per exact state root; no registry tokens are read here."""
    if not states:
        return {'packed': None, 'openers': 'unknown: no Nexus state-root inventory'}
    for state in states:
        result = subprocess.run(['timeout', '5s', *child_argv('--observe-readonly' if read_only else '--observe', str(path))],
                                env=os.environ | {'IDA_NEXUS_STATE_DIR': str(state)},
                                capture_output=True, text=True, check=False)
        if result.returncode:
            return {'packed': None, 'openers': 'unknown: public observation failed', 'exit': result.returncode}
        value = json.loads(result.stdout)
        if value.get('openers') is not None or value.get('packed') is not True:
            return value
    return {'packed': True, 'openers': None}


def public_observation(path, *, read_only=False):
    from ida_nexus import probe_database_state
    if read_only:
        # Public discovery may reap dead registrations. Preview must not call
        # it, create state directories, or open registration contents/tokens.
        state = Path(os.environ['IDA_NEXUS_STATE_DIR'])
        directory(state)
        registry = state/'instances'
        if registry.exists() or registry.is_symlink():
            directory(registry)
            reason = 'registrations present; preview does not reap or read tokens' if any(registry.iterdir()) else None
        else:
            reason = None
    else:
        from cache_store import public_owner_probe
        reason = public_owner_probe(path)
    state = probe_database_state(path)
    return {'packed': state.get('state') == 'packed' and not state.get('unpacked_files') and not state.get('error'),
            'openers': reason, 'state': state.get('state'), 'error': state.get('error')}


def active_observe(path, states):
    return observe(path, states, read_only=False)


def assert_unoccupied(paths, states, *, probe=active_observe):
    for path in paths:
        observation = probe(path, states)
        if observation.get('openers') is not None or observation.get('packed') is not True:
            raise RuntimeError('packed/offline veto for ' + str(path) + ': ' + json.dumps(observation))
