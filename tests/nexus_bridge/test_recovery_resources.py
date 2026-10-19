"""Resource-certificate handoff and routine pins; no synthetic owner proof."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge'),str(Path(__file__).parent)]
from test_recovery_transaction import isolate_owner_input, no_owner_input
from open_recovery import Snapshot
from recovery_transaction import Transaction
from target_coordination import Target, digest
from target_journal import Journal


class ResourceCertificates(unittest.TestCase):
    def setUp(self):
        isolate_owner_input(self)

    def test_internal_snapshot_resolves_original_authority_and_rejects_business(self):
        no_owner_input()
        root=Path(tempfile.mkdtemp(prefix='internal-gate-',dir=os.environ['R3A_CASE_ROOT']))
        target=root/'input.i64'
        target.write_bytes(b'original')
        snapshot=Snapshot(root/'home',target,float('inf'),owner_probe=lambda _:None)
        with Target(target) as original,original.locked():
            key=original.key
            inode=os.fstat(original.target_fd).st_ino
        evidence=snapshot.path/'snapshot/input.i64'
        with Target(evidence) as alias,alias.locked():
            self.assertEqual(alias.key,key)
            self.assertEqual(os.fstat(alias.target_fd).st_ino,inode)
            with self.assertRaisesRegex(RuntimeError,'not a business target'):
                alias.business_admission()
        self.assertFalse(list(evidence.parent.glob('.ida-cli-txn-*')),'evidence must never create a parallel lock')

    def test_ready_pins_sources_and_retained_certificate_survives_routine_settlement(self):
        no_owner_input()
        root=Path(tempfile.mkdtemp(prefix='recovery-refs-',dir=os.environ['R3A_CASE_ROOT']))
        payload=root/'payload'
        payload.mkdir(mode=0o700)
        path=payload/'input.i64'
        path.write_bytes(b'original')
        snapshot=Snapshot(root/'unrelated-home',path,float('inf'),owner_probe=lambda _:None)
        with Target(path) as target,target.locked():
            journal=Journal(target)
            acquisition={'parent':dict(client_id='pin',request_id='pin',operation_id='pin',task_id=None),
                         'purpose':'final','ordinal':1}
            epoch=journal.begin(acquisition,'no-side-effect')
            journal.abort_unstarted('no-side-effect')
            self.assertIn(str(epoch),journal.value['entries'],'ready snapshot must pin potential source')
            item=journal.value['entries'][str(epoch)]
            snapshot.requirements=[{k:copy.deepcopy(item.get(k)) for k in
                ('watch','epoch','acquisition','owner','lease','origin_binding')}]
        path.write_bytes(b'failed scene')
        snapshot.failed(1)
        snapshot.rollback(snapshot.data['attempts'][0]['failed'])
        self.assertEqual(path.read_bytes(),b'original')
        with Target(path) as target,target.locked():
            journal=Journal(target)
            journal.settle()
            self.assertNotIn(str(epoch),journal.value['entries'])
            with Transaction(target,snapshot.recovery_id) as transaction:
                requirement=transaction.data['requirements'][0]
                key=digest(requirement)
                certificate=transaction.data['certified_resources'][key]
                transaction.validate_certificate(requirement,certificate)
                value,_,_=transaction.directory.read(certificate['name'])
                value['evidence']['record']['unacked_events']=True
                transaction.directory.durable(certificate['name'],value)
                with self.assertRaisesRegex(RuntimeError,'binding mismatch'):
                    transaction.validate_certificate(requirement,certificate)

    def test_unclosed_source_never_authorizes_restore_or_routine_release(self):
        no_owner_input()
        root=Path(tempfile.mkdtemp(prefix='recovery-open-ref-',dir=os.environ['R3A_CASE_ROOT']))
        path=root/'input.i64'
        path.write_bytes(b'original')
        snapshot=Snapshot(root/'home',path,float('inf'),owner_probe=lambda _:None)
        with Target(path) as target,target.locked():
            journal=Journal(target)
            epoch=journal.begin({'parent':dict(client_id='x',request_id='x',operation_id='x',task_id=None),
                                 'purpose':'final','ordinal':1},'pending')
            item=journal.value['entries'][str(epoch)]
            snapshot.requirements=[{k:item.get(k) for k in ('watch','epoch','acquisition','owner','lease','origin_binding')}]
        path.write_bytes(b'failed')
        observed=snapshot.failed(1)
        with self.assertRaisesRegex(RuntimeError,'double proof pending'):
            snapshot.rollback(observed)
        self.assertEqual(path.read_bytes(),b'failed')
        self.assertEqual(snapshot.data['status'],'failed-owner-held')


if __name__=='__main__':unittest.main(verbosity=2)
