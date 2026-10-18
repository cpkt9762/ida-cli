"""Independent pinned-SDK release wrapper units; real custody is in nexus_r3b."""
import json
import os
from pathlib import Path
import sys
import threading
import time
import tempfile
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [os.environ.get('F10_SOURCE', str(REPO / 'nexus_bridge')), str(REPO/'tests/support')]
from release_wrapper import install
from lifecycle import release_handle, release_state
import bridge
import ida_nexus
from ida_nexus import DatabaseHandle
import ida_nexus.handle as client


def scenario(*, sibling=False, both_lost=False, unsafe=False):
    live, names, calls, queries, messages, checks = set(), {}, [], [], [], []
    path = Path(tempfile.mkdtemp(dir=os.environ['R3A_CASE_ROOT'], prefix='group-'))/'mock.i64'
    path.write_bytes(b'private group input')
    instance = types.SimpleNamespace(record_id='group-owner', backend='idalib',
        managed=True, pid=os.getpid(), started_at=time.time(), port=1, idb_path=str(path),
        exe_path='', _token=os.urandom(16).hex())
    deadline = time.monotonic() + 1

    class Connection:
        status = 200

        def request(self, method, endpoint, **kwargs):
            assert endpoint == '/release_lease'
            self.lease = json.loads(kwargs['body'])['lease_id']
            live.remove(self.lease)
            self.pending = not live
            calls.append(names[self.lease])
            assert time.monotonic() < deadline, 'own releases must share original deadline'

        def getresponse(self):
            return self

        def read(self):
            if names[self.lease] == 'primary' or both_lost:
                raise OSError('injected ACK loss')
            return json.dumps({'ok': True, 'result': {
                'released': True, 'shutdown_pending': self.pending}}).encode()

        def close(self):
            pass

    def lifetime(*args, **kwargs):
        queries.append({'calls': list(calls), 'live': [names[x] for x in live]})
        return not live

    with patch.object(DatabaseHandle, '_open_lease', return_value=(None, None, None)), \
            patch.object(DatabaseHandle, '_monitor_lease', return_value=None), \
            patch.object(client.http.client, 'HTTPConnection', side_effect=lambda *a, **kw: Connection()), \
            patch.object(ida_nexus, 'wait_database_released', side_effect=lifetime), \
            patch.object(client, 'wait_database_released', side_effect=lifetime), \
            patch.object(ida_nexus, 'discover_databases', return_value=[types.SimpleNamespace(instance=instance)]):
        primary = DatabaseHandle(instance.idb_path, instance)
        auxiliary = DatabaseHandle(instance.idb_path, instance)
        external = DatabaseHandle(instance.idb_path, instance) if sibling else None
        names.update({primary._lease_id: 'primary', auxiliary._lease_id: 'auxiliary'})
        if external:
            names[external._lease_id] = 'sibling'
        live.update(names)
        primary._disconnected.set()

        def execute(source, **kwargs):
            stage = 'primary' if not checks else 'auxiliary'
            checks.append(stage)
            return {'result': {'close_safe': not (unsafe and stage == 'auxiliary'),
                               'save_guard_error': stage + ' save refused'}}

        auxiliary.execute_python = execute
        owner = bridge.Bridge.__new__(bridge.Bridge)
        lease = {'lease_id': 'logical', 'instance_id': 'group-owner', 'generation': 1}
        owner.lock = threading.Lock()
        owner.identity, owner.lifetime_path = 'group-bridge', '/private/lifetime'
        owner.handles = {'logical': (lease, primary)}
        owner.custodians = {}  # Explicit wrapper boundary double, never N1 proof.
        owner.cleanup_handles, owner.metadata_contexts = {}, {}
        owner.Handle = types.SimpleNamespace(attach=lambda entry: auxiliary)
        owner.drop_lifetime = lambda key: None

        _, child = install(owner,lease,primary,auxiliary)
        try:
            owner.invoke(types.SimpleNamespace(send=messages.append), {'sequence':1},
                {'command':'release','lease':lease},time.monotonic()+15,[False])
            owner.invoke(types.SimpleNamespace(send=messages.append), {'sequence':2},
                {'command':'release','lease':child.lease},time.monotonic()+15,[False])
        finally:
            owner.detach_pool.shutdown(wait=True)
        terminals=[event for event in messages if event['event'] in ('released','uncertain','not_sent')]
        assert len(terminals)==2 and terminals[0]['event']=='uncertain',terminals
        assert calls.count('primary')==1
        assert checks==['primary','auxiliary'] and not queries,(checks,queries)
        assert owner.handles['logical'][1] is primary,'unknown primary must retain its own handle'
        assert 'primary save refused' in terminals[0]['save_guard_error']
        assert 'auxiliary save refused' in terminals[1]['save_guard_error']
        before=list(calls)
        release_handle(primary,deadline,request_only=True)
        assert calls==before,'unknown primary cannot replay because another member succeeded'
        if unsafe:
            assert terminals[1]['event']=='not_sent' and calls==['primary'],terminals
            assert child.lease['lease_id'] in owner.handles
            assert release_state(auxiliary)['requested'] is False
            assert 'save protection unavailable' in terminals[1]['error']['message']
        else:
            assert calls==['primary','auxiliary'],calls
            assert terminals[1]['event']==('uncertain' if both_lost else 'released'),terminals
            assert (child.lease['lease_id'] in owner.handles) is both_lost
            # A separate owner observation primitive can learn public True. It
            # does not manufacture a Rust retirement or rewrite either SDK ACK.
            if sibling:
                assert release_handle(primary,deadline,owner_required=True) is None
                assert live_names(live,names)==['sibling']
                external.close_outcome(wait_for_database=False,timeout=.1)
            proof=release_handle(primary,deadline,owner_required=True)
            assert proof['owner_released'] and proof['release_acknowledged'] is False,proof
            assert release_state(primary)['outcome']['lease_released'] is False
            assert owner.handles['logical'][1] is primary,'only matching Rust custody retirement removes this entry'
        assert calls.count('primary') == 1 and calls.count('auxiliary') <= 1
        return {'calls': calls, 'queries': queries, 'checks': checks, 'events': messages}


def live_names(live, names):
    return sorted(names[x] for x in live)


class GroupTests(unittest.TestCase):
    def test_primary_ack_lost_releases_own_helper_before_proof(self):
        scenario()

    def test_primary_ack_lost_waits_for_real_sibling(self):
        scenario(sibling=True)

    def test_both_acks_lost_require_owner_proof(self):
        scenario(both_lost=True)

    def test_unsafe_auxiliary_is_retained_without_close(self):
        scenario(unsafe=True)


if __name__ == '__main__':
    unittest.main()
