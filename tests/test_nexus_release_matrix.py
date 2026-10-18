"""Reachable release-group states, checked against six independent invariants."""
import collections
import fcntl
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.environ.get('F11_SOURCE', str(REPO / 'nexus_bridge')))
import bridge
import ida_nexus
import ida_nexus.instances as instances
import lifecycle
from lifecycle import release_state

GUARDS = ('healthy', 'root_missing', 'set_failed', 'read_false', 'read_raised')
ACKS = ('nonlast', 'last', 'lost', 'transport')
TIMES = ('before', 'during', 'between', 'held')


def cases():
    """Filter impossible ACKs/timing and canonicalize unvisited branches."""
    excluded = collections.Counter()
    rows = []
    for group in ('primary', 'auxiliary', 'sibling'):
        count = 1 if group == 'primary' else 2
        for guards, acks, timing in itertools.product(
                itertools.product(GUARDS, repeat=count),
                itertools.product(ACKS, repeat=count), TIMES):
            live = count + (group == 'sibling')
            reason = None
            stopped = False
            for guard, ack in zip(guards, acks):
                if stopped or guard not in GUARDS[:2]:
                    if ack != 'lost':
                        reason = 'unissued_ACK_is_NA'
                    if stopped and guard != 'healthy':
                        reason = 'unvisited_guard_is_NA'
                    stopped = True
                    continue
                live -= 1
                if ack in ACKS[:2] and ack != ('last' if live == 0 else 'nonlast'):
                    reason = 'ACK_disagrees_with_live_leases'
            if not reason and ((live > 0) != (timing == 'held')):
                reason = 'lifetime_cannot_release_while_lease_held'
            if not reason and timing == 'between' and (
                    count == 1 or acks[0] == 'nonlast'):
                reason = 'no_first_lifetime_wait'
            if reason:
                excluded[reason] += 1
            else:
                rows.append((group, guards, acks, timing))
    return rows, excluded


def exercise(row, directory, *, alien=False):
    group, guards, acks, timing = row
    count = len(guards)
    messages, calls, checks, queries, drops = [], [], [], [], []
    live = set(range(count + (group == 'sibling')))
    target = directory / 'matrix.i64'
    if not target.exists():
        target.write_bytes(b'private release compatibility input')
    instance = types.SimpleNamespace(record_id='matrix-owner', pid=os.getpid(),
        started_at=1, idb_path=str(target), backend='idalib')
    lock_fd = os.open(directory / 'matrix-owner.lock', os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    real_wait = instances.wait_database_released
    observed_errors = []
    clock = [time.monotonic()]

    def unlock():
        fcntl.flock(lock_fd, fcntl.LOCK_UN)

    def lifetime(owner, **kwargs):
        assert len(calls) == count, 'all own requests precede lifetime'
        if timing == 'during' or (timing == 'between' and queries):
            unlock()
        # Real public API observes a private flock. Polling with zero timeout
        # makes timing deterministic without lengthening production deadlines.
        result = real_wait(owner, timeout=0)
        if timing == 'between' and not queries:
            clock[0] += 2
        if timing == 'between' and queries:
            assert kwargs['timeout'] == 0, 'proof after the original deadline'
        queries.append((owner.record_id, result))
        return result

    class Handle:
        def __init__(self, index):
            self.index = index
            self.instance = instance
            self.connected = count == 1

        def execute_python(self, source, **kwargs):
            index = 0 if 'module.release_lease' in source else self.index
            checks.append(index)
            guard = guards[index]
            message = None if guard == 'healthy' else f'{index}: {guard} save refused'
            if message:
                observed_errors.append(message)
            if guard not in GUARDS[:2] and index == 0:
                # guarded_source(refuse=False) raises on unknown protection;
                # Bridge.run must preserve the same error in caller/sideband.
                release_state(handles[0])['errors'].append(message)
                raise RuntimeError(message)
            return {'result': {'close_safe': guard in GUARDS[:2],
                               'save_guard_error': message}}

        def close_outcome(self, **kwargs):
            assert kwargs['wait_for_database'] is False
            calls.append(self.index)
            live.remove(self.index)
            if timing == 'before' and not live:
                unlock()
            if acks[self.index] == 'transport':
                raise OSError('injected post-commit transport error')
            if acks[self.index] == 'lost':
                return {'status': 'uncertain', 'lease_released': False,
                        'failure': 'injected ACK loss'}
            return {'status': 'lease_released', 'lease_released': True,
                    'shutdown_pending': acks[self.index] == 'last'}

    handles = [Handle(i) for i in range(count)]
    if alien:
        handles[1].instance = types.SimpleNamespace(**vars(instance))
        field, value = alien
        setattr(handles[1].instance, field, value)
    owner = bridge.Bridge.__new__(bridge.Bridge)
    lease = {'lease_id': 'logical', 'instance_id': instance.record_id, 'generation': 1}
    owner.lock, owner.stopped = threading.Lock(), threading.Event()
    owner.identity, owner.lifetime_path = 'matrix-bridge', '/private/matrix-lifetime'
    owner.handles, owner.metadata_contexts = {'logical': (lease, handles[0])}, {'logical': {}}
    owner.cleanup_handles, owner.grants = {}, {}
    owner.custodians = {}  # This matrix exercises the retained auxiliary path.
    owner.Handle = types.SimpleNamespace(attach=lambda _: handles[1])
    owner.drop_lifetime = drops.append

    def send(message):
        messages.append(message)
        if message['event'] == 'dispatch_ready':
            ready, grants = owner.grants[1]
            grants.append(({'grant': True, 'remaining_ms': 1000}, time.monotonic()))
            ready.set()

    try:
        with patch.object(instances, 'REGISTRY_DIR', directory), \
                patch.object(lifecycle, 'time', types.SimpleNamespace(monotonic=lambda: clock[0])), \
                patch.object(ida_nexus, 'wait_database_released', side_effect=lifetime), \
                patch.object(ida_nexus, 'discover_databases', return_value=[
                    types.SimpleNamespace(instance=instance)]):
            owner.run(types.SimpleNamespace(send=send), {'attempt': {'sequence': 1},
                'payload': {'command': 'release', 'lease': lease}}, threading.Semaphore(0))
            if timing == 'held' and owner.handles:
                # Re-enter uncertain coordination: never repeat a sent request.
                owner.run(types.SimpleNamespace(send=send), {'attempt': {'sequence': 1},
                    'payload': {'command': 'release', 'lease': lease}}, threading.Semaphore(0))
        released = any(m['event'] == 'released' for m in messages)
        unsafe = any(g not in GUARDS[:2] for g in guards)
        same_proof = any(key == instance.record_id and proved for key, proved in queries)
        ack_proofs = all(a == 'nonlast' and i in calls for i, a in enumerate(acks))
        failures = []

        def invariant(name, condition):
            if not condition:
                failures.append(name)

        invariant('I1', all(guards[i] in GUARDS[:2] for i in calls))
        invariant('I2', all(calls.count(i) <= 1 for i in range(count)))
        invariant('I3', not released or (not unsafe and (ack_proofs or same_proof)))
        final = messages[-1]
        invariant('I4', all(e in (final.get('save_guard_error') or '')
                  and e in str(final.get('outcome', final.get('error'))) for e in observed_errors))
        invariant('I5', alien or group == 'sibling' or unsafe or (
            released and not owner.handles and not owner.cleanup_handles
            and not owner.metadata_contexts and drops == ['logical']))
        must_retain = unsafe or (group == 'sibling' and not ack_proofs) or alien
        expected_not_sent = guards[0] not in GUARDS[:2]
        invariant('NotSent_boundary', not expected_not_sent or (
            calls == [] and live == set(range(count + (group == 'sibling')))
            and all(not release_state(h)['requested'] for h in handles)
            and final['event'] == 'not_sent' and final.get('save_guard_error') == observed_errors[0]))
        invariant('I6', not must_retain or (not released and owner.handles.get('logical') ==
            (lease, handles[0]) and owner.metadata_contexts == {'logical': {}}
            and (count == 1 or owner.cleanup_handles.get('logical') is handles[1])
            and not drops and final['event'] in (('not_sent',) if expected_not_sent
                else ('uncertain', 'release_unconfirmed'))))
        # Raw ACK provenance is never rewritten by a shared owner proof.
        invariant('raw_ACK', all(not release_state(h).get('requested') or
            release_state(h)['outcome'].get('lease_released') is (acks[i] in ACKS[:2])
            for i, h in enumerate(handles)))
        return failures, {'case': row, 'failures': failures, 'calls': calls,
                          'queries': queries, 'events': [m['event'] for m in messages],
                          'messages':messages}
    finally:
        os.close(lock_fd)


class MatrixTests(unittest.TestCase):
    def test_reachable_matrix(self):
        rows, excluded = cases()
        failures = []
        with tempfile.TemporaryDirectory(prefix='n7matrix-') as root:
            for row in rows:
                bad, detail = exercise(row, Path(root))
                if bad:
                    failures.append(detail)
        result = {'raw_combinations': 3280, 'reachable': len(rows),
                  'excluded': dict(excluded), 'assertions_per_case': list(('I1', 'I2', 'I3', 'I4', 'I5', 'I6', 'raw_ACK', 'NotSent_boundary')),
                  'failed': failures}
        if os.environ.get('F11_MATRIX_RESULT'):
            Path(os.environ['F11_MATRIX_RESULT']).write_text(json.dumps(result, indent=2) + '\n')
        self.assertEqual(failures, [], json.dumps(result))

    def test_different_owner_proof_is_not_shared(self):
        for field, value in (('record_id', 'alien-owner'), ('pid', os.getpid() + 1),
                ('started_at', 2), ('idb_path', '/private/alien.i64'), ('backend', 'gui')):
            with self.subTest(field=field), tempfile.TemporaryDirectory(prefix='n7alien-') as root:
                bad, detail = exercise(('auxiliary', ('healthy', 'healthy'),
                    ('lost', 'last'), 'between'), Path(root), alien=(field, value))
                self.assertEqual(bad, [], detail)


if __name__ == '__main__':
    unittest.main()
