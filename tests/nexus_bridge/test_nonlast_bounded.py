"""Deterministic lease/ACK boundary with real durable producers and public lifetime.

Lease acquisition and parsed nonlast ACK are stipulated inputs to the journal;
no N1 stop/public-owner proof is fabricated. Production transfer APIs, locks,
registry persistence, discovery and public lifetime run unchanged.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'tests/support'), str(REPO/'nexus_bridge')]
from bridge_observer import BackupSources
from owner_identity import owner_key
from proof_helper import Observer
from r0_transport import Boundary
from target_coordination import Directory, Target, encoded
from target_journal import Journal


class NonlastBounded(unittest.TestCase):
    def test_long_lived_owner_more_than_512_nonlast_leases(self):
        root = Path(tempfile.mkdtemp(prefix='nl-', dir=os.environ['R3A_CASE_ROOT']))
        storage = Directory(root)
        observer = Observer('nonlast-helper', 512, storage=storage)
        bridge = SimpleNamespace(lock=threading.RLock(), acquisitions={}, custodians={},
                                 control=SimpleNamespace(send=lambda _: None))
        backup = BackupSources(bridge, 512)
        samples = []
        retired_query = None
        try:
            with Boundary(root/'owner', stub_ida=False) as boundary:
                owner = owner_key(boundary.instance)
                def request(kind, **fields):
                    result = observer.receive(dict(kind=kind, protocol=2, helper=observer.incarnation, **fields))
                    observer.persist()
                    return result
                for n in range(521):
                    parent = dict(client_id='bounded', request_id=str(n), operation_id=str(n), task_id=None)
                    acquisition = dict(parent=parent, purpose='final', ordinal=1)
                    watch = 'watch-'+str(n)
                    lease = dict(lease_id='lease-'+str(n))
                    request('reserve_parent', parent=parent)
                    with Target(boundary.path) as target, target.locked():
                        journal = Journal(target)
                        epoch = journal.begin(acquisition, watch, owner=owner)
                        value = dict(watch=watch, target=str(boundary.path), coord_key=target.key,
                                     acquisition=acquisition, owner=owner, subscription_epoch=epoch)
                        if n == 1:
                            retired_query = dict(value)
                        backup.subscribe(boundary.instance, owner, watch)
                        journal.bridge_signed(backup.bind(value))
                        signed = request('subscribe', **value)['receipt']
                        journal.owner_signed(signed)
                        journal.adopt(dict(value, receipt=signed, lease=lease))
                        attempt = dict(target=dict(kind='release', lease=lease), sequence=1)
                        journal.release_observation(dict(value, epoch=epoch, lease=lease,
                            attempt=attempt, observation_id='release-'+str(n), outcome=dict(detach_called=False)))
                        result = journal.detach_outcome(dict(value, epoch=epoch, lease=lease,
                            attempt=attempt, outcome=dict(lease_released=True, ack_kind='last' if n == 520 else 'nonlast')))
                    if result.get('successor'):
                        if n == 1:
                            with self.assertRaisesRegex(ValueError, 'successor'):
                                request('nonlast_transfer', watch=watch, successor=watch)
                        closed = request('nonlast_transfer', watch=watch, successor=result['successor'])['consumer']
                        self.assertEqual(request('nonlast_transfer', watch=watch, successor=result['successor'])['consumer'],closed,
                                         'lost helper ACK must replay the exact producer closure')
                        if n == 1:
                            with self.assertRaisesRegex(ValueError, 'durably adopted'):
                                backup.nonlast_transfer(closed)
                        with Target(boundary.path) as target, target.locked():
                            Journal(target).nonlast_transfer(dict(watch=watch, consumer=closed))
                        bridge_closed = backup.nonlast_transfer(closed)
                        with Target(boundary.path) as target, target.locked():
                            Journal(target).nonlast_closed(dict(watch=watch, consumer=closed, bridge_consumer=bridge_closed))
                        request('retire', watch=watch, sha256=closed['sha256'])
                        with Target(boundary.path) as target, target.locked():
                            Journal(target).settle()
                        request('retire_parent', parent=parent)
                        backup.retire(watch)
                    status = request('heartbeat', summary_only=True)
                    samples.append(dict(cycle=n, used=status['used'], parents=status['parent_count'],
                                        live_ref_bytes=status['live_ref_bytes'], registry_bytes=len(encoded(storage.read('helper-state.json')[0]))))
                self.assertLessEqual(max(s['used'] for s in samples[:-1]), 1)
                self.assertLessEqual(samples[-1]['used'], 2)
                self.assertLessEqual(max(s['parents'] for s in samples[:-1]), 1)
                self.assertLessEqual(samples[-1]['parents'], 2)
                self.assertLess(max(s['registry_bytes'] for s in samples), 65536)
                self.assertLess(max(s['live_ref_bytes'] for s in samples), 65536)
                # The final last-close input releases the held owner barrier;
                # actual SDK wait produces the only public lifetime proof.
                boundary.release_owner()
                end = time.monotonic()+4
                while not (all(item.get('proof') for item in observer.items.values())
                           and all(entry['released'] for entry in backup.items.values())):
                    self.assertLess(time.monotonic(), end, 'public lifetime deadline')
                    threading.Event().wait(.005)
                self.assertIsNone(backup.query(retired_query),'late retired query cannot revive its producer')
                for watch, item in list(observer.items.items()):
                    proof = item['proof']
                    with Target(boundary.path) as target, target.locked():
                        Journal(target).proof(dict(watch=watch, proof=proof))
                    bridge_consumer = backup.close(dict(owner=owner, watch=watch, target=str(boundary.path), proof=proof))
                    with Target(boundary.path) as target, target.locked():
                        Journal(target).bridge_closed(dict(watch=watch, consumer=bridge_consumer))
                    consumer = request('proof_custody_ack', watch=watch, path=proof['path'], sha256=proof['sha256'])['consumer']
                    with Target(boundary.path) as target, target.locked():
                        Journal(target).producer_closed(dict(watch=watch, consumer=consumer))
                    request('retire', watch=watch, sha256=consumer['sha256'])
                    request('retire_parent', parent=item['acquisition']['parent'])
                    backup.retire(watch)
                with Target(boundary.path) as target, target.locked():
                    journal = Journal(target); journal.settle()
                    self.assertEqual(journal.value['entries'], {})
                status = request('heartbeat', summary_only=True)
                self.assertEqual([status[k] for k in ('used','live_ref_bytes','parent_count','reserved')], [0,0,0,0])
                self.assertEqual(backup.items, {})
        finally:
            (root/'counts.json').write_text(json.dumps(samples, indent=2))
            for entry in [*observer.owners.values(), *backup.items.values()]:
                entry['stop'].set()
                entry.get('thread') and entry['thread'].join(2)
            storage.close()


if __name__ == '__main__':
    unittest.main()
