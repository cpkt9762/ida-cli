"""Reachable per-member release primitive graph; no N1/proof messages are forged.

Rust nexus_r3b covers actual custody/operation grants, membership, callers and
fairness. This unit graph exercises raw guard/SDK outcome inputs and real public
lifetime observation of a private flock, with no donor or private error prefill.
"""
import collections
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'nexus_bridge'))
import ida_nexus
import ida_nexus.instances as instances
import lifecycle
from lifecycle import release_handle, release_state, release_errors

GUARDS = ('healthy', 'root_missing', 'set_failed', 'read_false', 'read_raised')
ACKS = ('ack', 'lost', 'transport')
TIMES = ('before', 'during', 'after_deadline', 'held')


def cases():
    """Walk executable guard/request edges; derive ACK kind from actual members."""
    rows = []
    for group in ('primary', 'auxiliary', 'sibling'):
        count = 1 if group == 'primary' else 2
        def visit(index, live, guards=(), outcomes=()):
            if index == count:
                for timing in TIMES if not live else ('held',):
                    rows.append((group, guards, outcomes, timing))
                return
            for guard in GUARDS:
                if guard not in GUARDS[:2]:
                    visit(index+1, live, (*guards,guard), (*outcomes,None))
                else:
                    for outcome in ACKS:
                        visit(index+1, live-{index}, (*guards,guard), (*outcomes,outcome))
        visit(0,set(range(count+(group=='sibling'))))
    return rows


def exercise(row, directory, *, alien=None):
    group, guards, modes, timing = row
    count = len(guards)
    live = set(range(count+(group=='sibling')))
    calls, checks, queries, errors, observation_errors = [], [], [], [], []
    target = directory/'matrix.i64'
    target.write_bytes(b'private primitive input')
    instance = types.SimpleNamespace(record_id='matrix-owner',pid=os.getpid(),
        started_at=1,idb_path=str(target),backend='idalib')
    fd = os.open(directory/'matrix-owner.lock',os.O_CREAT|os.O_RDWR,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    real_wait = instances.wait_database_released
    clock = [time.monotonic()]
    deadline = clock[0]+1

    class Handle:
        def __init__(self,index):
            self.index, self.instance = index, instance
        def execute_python(self,_source,**_options):
            checks.append(self.index)
            guard = guards[self.index]
            message = None if guard=='healthy' else f'{self.index}: {guard} saving refused'
            return {'result':{'close_safe':guard in GUARDS[:2],'save_guard_error':message}}
        def close_outcome(self,**options):
            assert options['wait_for_database'] is False
            calls.append(self.index)
            live.remove(self.index)
            if modes[self.index]=='transport':
                raise OSError('actual modeled transport failure after service commit')
            if modes[self.index]=='lost':
                return {'status':'uncertain','lease_released':False,'failure':'lost_ack'}
            return {'status':'lease_released','lease_released':True,
                    'shutdown_pending':not live,'owner_released':False}
    handles = [Handle(i) for i in range(count)]
    if alien:
        handles[1].instance = types.SimpleNamespace(**vars(instance))
        setattr(handles[1].instance,*alien)

    def lifetime(owner,**_options):
        if not lifecycle.same_owner(handles[0],types.SimpleNamespace(instance=owner)):
            raise OSError('no matching original public object for this OwnerKey')
        if timing=='during':
            fcntl.flock(fd,fcntl.LOCK_UN)
        if timing=='after_deadline' and not queries:
            clock[0] += 2
        result = real_wait(owner,timeout=0)
        queries.append((owner.record_id,result))
        return result

    def observe(handle):
        try:
            return release_handle(handle,deadline,owner_required=True)
        except OSError as error:
            observation_errors.append(str(error))
            return None

    try:
        with patch.object(instances,'REGISTRY_DIR',directory), \
                patch.object(lifecycle,'time',types.SimpleNamespace(monotonic=lambda:clock[0])), \
                patch.object(ida_nexus,'wait_database_released',side_effect=lifetime):
            outcomes = []
            # Every available member advances, even when an earlier guard failed.
            for handle in handles:
                try:
                    outcomes.append(release_handle(handle,deadline,request_only=True))
                except RuntimeError as error:
                    errors.append(str(error))
                    outcomes.append(None)
            if timing=='before':
                fcntl.flock(fd,fcntl.LOCK_UN)
            for handle in handles:
                if release_state(handle)['requested']:
                    observe(handle)
            if timing=='after_deadline':
                fcntl.flock(fd,fcntl.LOCK_UN)
                for handle in handles:
                    if release_state(handle)['requested']:
                        observe(handle)
            before = list(calls)
            for handle in handles:
                if release_state(handle)['requested']:
                    release_handle(handle,deadline,request_only=True)
            assert calls==before,'later observations must not replay a native request'

        failures = []
        def invariant(name, value):
            if not value:
                failures.append(name)
        invariant('I1',all(guards[i] in GUARDS[:2] for i in calls))
        invariant('I2',all(calls.count(i)<=1 for i in range(count)))
        invariant('fresh_guard',checks==list(range(count)))
        for i,handle in enumerate(handles):
            state = release_state(handle)
            raw = state['outcome'] or {}
            expected_ack = i in calls and modes[i]=='ack'
            invariant('I3',not state.get('owner_proved') or
                any(proved for _,proved in queries) and lifecycle.same_owner(handles[0],handle))
            invariant('raw_ACK',raw.get('lease_released',False) is expected_ack)
            if guards[i]!='healthy':
                message=f'{i}: {guards[i]} saving refused'
                invariant('I4',message in release_errors(handle) and (
                    message in str(outcomes[i]) or any(message in e for e in errors)))
            if guards[i] not in GUARDS[:2]:
                invariant('NotSent_boundary',not state['requested'] and i in live and i not in calls)
            if i in calls and not expected_ack and not state.get('owner_proved'):
                invariant('I6',state['requested'] and raw.get('lease_released') is False
                    and raw.get('status')=='uncertain')
        if timing!='held' and not alien:
            invariant('I5',all(release_state(h).get('owner_proved') for h in handles))
        if timing=='held':
            invariant('owner_held',not any(release_state(h).get('owner_proved') for h in handles))
        if alien:
            invariant('exact_owner',not release_state(handles[1]).get('owner_proved') and bool(observation_errors))
        return failures, {'case':row,'calls':calls,'checks':checks,'queries':queries,
                          'errors':errors,'observation_errors':observation_errors,'failures':failures}
    finally:
        os.close(fd)


class MatrixTests(unittest.TestCase):
    def test_reachable_matrix(self):
        rows = cases()
        failures = []
        counts = collections.Counter(row[0] for row in rows)
        with tempfile.TemporaryDirectory(prefix='n7matrix-') as root:
            for row in rows:
                failed, detail = exercise(row,Path(root))
                if failed:
                    failures.append(detail)
        result={'scope':'per-member primitive, not Rust/N1 custody','reachable':len(rows),
                'groups':dict(counts),'failed':failures,'static_exclusions':0}
        if os.environ.get('F11_MATRIX_RESULT'):
            Path(os.environ['F11_MATRIX_RESULT']).write_text(json.dumps(result,indent=2)+'\n')
        self.assertGreater(len(rows),200,'must enumerate actual guard/request/owner edges')
        self.assertEqual(failures,[],json.dumps(result))

    def test_different_owner_proof_is_not_shared(self):
        for field,value in (('record_id','alien-owner'),('pid',os.getpid()+1),
                ('started_at',2),('idb_path','/private/alien.i64'),('backend','gui')):
            with self.subTest(field=field), tempfile.TemporaryDirectory(prefix='n7alien-') as root:
                failed,detail=exercise(('auxiliary',('healthy','healthy'),('lost','lost'),'before'),Path(root),alien=(field,value))
                self.assertEqual(failed,[],detail)


if __name__=='__main__':
    unittest.main()
