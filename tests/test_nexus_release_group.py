"""Lost ACK coordination with the pinned client and production bridge."""
import json
import os
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.environ.get('F10_SOURCE', str(REPO / 'nexus_bridge')))
import bridge
import ida_nexus
from ida_nexus import DatabaseHandle
import ida_nexus.handle as client


def scenario(*, sibling=False, both_lost=False, unsafe=False):
    live, names, calls, queries, messages, checks = set(), {}, [], [], [], []
    instance = types.SimpleNamespace(record_id='group-owner', backend='idalib',
        managed=True, pid=os.getpid(), port=1, idb_path='/private/mock.i64',
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
            stage = 'primary' if 'module.release_lease' in source else 'auxiliary'
            checks.append(stage)
            return {'result': {'close_safe': not (unsafe and stage == 'auxiliary'),
                               'save_guard_error': stage + ' save refused'}}

        auxiliary.execute_python = execute
        owner = bridge.Bridge.__new__(bridge.Bridge)
        lease = {'lease_id': 'logical', 'instance_id': 'group-owner', 'generation': 1}
        owner.lock = threading.Lock()
        owner.identity, owner.lifetime_path = 'group-bridge', '/private/lifetime'
        owner.handles = {'logical': (lease, primary)}
        owner.cleanup_handles, owner.metadata_contexts = {}, {}
        owner.Handle = types.SimpleNamespace(attach=lambda entry: auxiliary)
        owner.drop_lifetime = lambda key: None

        def invoke():
            owner.invoke(types.SimpleNamespace(send=messages.append), {'sequence': 1},
                         {'command': 'release', 'lease': lease}, deadline, [False])

        if unsafe:
            owner.grants, owner.stopped = {}, threading.Event()
            def send(event):
                messages.append(event)
                if event['event'] == 'dispatch_ready':
                    ready, grants = owner.grants[1]
                    grants.append(({'grant': True, 'remaining_ms': 1000}, deadline - 1))
                    ready.set()
            owner.run(types.SimpleNamespace(send=send), {'attempt': {'sequence': 1},
                'payload': {'command': 'release', 'lease': lease}}, threading.Semaphore(0))
            assert calls == ['primary'], calls
            assert checks == ['primary', 'auxiliary'], checks
            assert not queries, 'cannot spend proof deadline before checking own auxiliary'
            assert owner.handles and owner.cleanup_handles
            assert not any(m['event'] == 'released' for m in messages)
            assert 'auxiliary' in live_names(live, names)
            from lifecycle import save_guard_error
            assert 'primary save refused' in save_guard_error(auxiliary)
            assert 'auxiliary save refused' in save_guard_error(auxiliary)
            assert messages[-1]['event'] == 'uncertain', messages
            assert 'save protection unavailable' in messages[-1]['error']['message'], messages
            assert 'primary save refused' in messages[-1]['save_guard_error'], messages
            assert 'auxiliary save refused' in messages[-1]['save_guard_error'], messages
        else:
            invoke()
            assert calls == ['primary', 'auxiliary'], calls
            assert checks == ['primary', 'auxiliary'], checks
            assert queries and all(q['calls'] == ['primary', 'auxiliary'] for q in queries), queries
            if sibling:
                assert owner.handles and owner.cleanup_handles
                assert not any(m['event'] == 'released' for m in messages)
                assert live_names(live, names) == ['sibling']
                invoke()
                assert calls == ['primary', 'auxiliary'], 'never replay either own release'
                # The real pinned sibling handle releases only on its caller's request.
                external.close_outcome(wait_for_database=False, timeout=.1)
                invoke()
                assert calls == ['primary', 'auxiliary', 'sibling']
            assert not owner.handles and not owner.cleanup_handles
            final = messages[-1]
            assert final['event'] == 'released', final
            assert final['outcome']['failure'] is None
            assert final['outcome']['proof'] == 'public_owner_lifetime', final
            assert 'primary save refused' in final['save_guard_error'], final
            assert 'auxiliary save refused' in final['save_guard_error'], final
            if both_lost:
                assert final['outcome']['release_acknowledged'] is False
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
