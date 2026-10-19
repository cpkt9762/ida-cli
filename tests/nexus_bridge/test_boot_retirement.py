"""U6 validates native creation scope and journal identity before retirement."""
import copy
import os
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'nexus_bridge/custody'))
from origin import boot_change, creation_scope
from target_coordination import Target
from target_journal import Journal


class BootRetirement(unittest.TestCase):
    def test_empty_epoch_table_needs_no_resource_retirement_probe(self):
        with Target(self.path) as target,target.locked():
            journal=Journal(target)
            with patch('target_journal.creation_scope',side_effect=AssertionError('no resource exists')):
                self.assertEqual(journal.retire_old_boot(),{'retirements':[]})
            journal.begin({'parent':'nonempty-scope','purpose':'final','ordinal':1},'live-watch')
            before=(target.directory.path/'custody.json').read_bytes()
            with patch('target_journal.creation_scope',side_effect=RuntimeError('controlled source unavailable')):
                with self.assertRaisesRegex(RuntimeError,'controlled source unavailable'):journal.retire_old_boot()
            self.assertEqual((target.directory.path/'custody.json').read_bytes(),before)

    def setUp(self):
        self.root=Path(tempfile.mkdtemp(dir=os.environ['R3A_CASE_ROOT'],prefix='boot-scope-'))
        self.path=self.root/'tiny.i64'
        self.path.write_bytes(b'private target')

    def test_unsupported_platform_cannot_gain_u6_from_boot_difference(self):
        with patch('origin.sys.platform','unverified-platform'),patch('origin.capture',return_value={'kind':'unknown','boot_id':'old'}):
            binding=creation_scope(self.root,'old')
        self.assertEqual(binding['boot_retirement_capability'],'UnsupportedBootScope')
        current=copy.deepcopy(binding)
        current['creator']['boot_id']='new'
        with self.assertRaisesRegex(RuntimeError,'UnsupportedBootScope'):
            boot_change(binding,current)

    def test_missing_binding_bad_journal_old_epoch_and_file_intent_fail_closed(self):
        acquisition={'parent':{'operation_id':'r2-private'},'purpose':'final','ordinal':1}
        with Target(self.path) as target:
            with target.locked():
                journal=Journal(target)
                epoch=journal.begin(acquisition,'watch',launch={'suffix':'old-startup'})
                origin=copy.deepcopy(journal.value['entries'][str(epoch)]['origin_binding'])
                current=copy.deepcopy(origin)
                current['creator']['boot_id']='00000000-0000-4000-8000-000000000001'
                if current['creator']['boot_id'] == origin['creator']['boot_id']:
                    self.fail('test boot must differ from actual boot')
                before=(target.directory.path/'custody.json').read_bytes()
                with self.assertRaisesRegex(RuntimeError,'old/unknown epoch'):
                    journal.item('watch',epoch+1)
                self.assertEqual((target.directory.path/'custody.json').read_bytes(),before)
                journal.value['entries'][str(epoch)]['origin_binding']={}
                journal.save()
                missing=(target.directory.path/'custody.json').read_bytes()
                with patch('target_journal.creation_scope',return_value=current):
                    with self.assertRaisesRegex(RuntimeError,'UnsupportedBootScope'):
                        journal.retire_old_boot()
                self.assertEqual((target.directory.path/'custody.json').read_bytes(),missing)
                journal.value['entries'][str(epoch)]['origin_binding']=origin
                journal.value['file_intents']={'a'*64:{'path':str(self.path),'status':'failed-owner-held'}}
                journal.save()
                with patch('target_journal.creation_scope',return_value=current):
                    journal.retire_old_boot()
                    with self.assertRaisesRegex(RuntimeError,'retained file intent'):
                        Journal(target).gate()
                with patch('target_journal.creation_scope',return_value=current):
                    retired=Journal(target).value
                self.assertEqual(retired['file_intents'],journal.value['file_intents'])
                self.assertTrue(retired['entries'][str(epoch)]['resource_retirement'])
                self.assertFalse(retired['entries'][str(epoch)]['detached'])
                retired['entries'][str(epoch)]['epoch']=epoch+1
                target.directory.durable('custody.json',retired)
                corrupt=(target.directory.path/'custody.json').read_bytes()
                with patch('target_journal.creation_scope',return_value=current):
                    with self.assertRaisesRegex(RuntimeError,'malformed active observation'):
                        Journal(target).retire_old_boot()
                self.assertEqual((target.directory.path/'custody.json').read_bytes(),corrupt)

    def retired_fixture(self, target):
        journal = Journal(target)
        epoch = journal.begin({'parent':{'operation_id':'rf-private'},'purpose':'final','ordinal':1},
                              'retired-watch', owner={'record_id':'old-owner'})
        item = journal.value['entries'][str(epoch)]
        item['lease'] = {'lease_id':'old-lease'}
        journal.save()
        current = copy.deepcopy(item['origin_binding'])
        current['creator']['boot_id'] = '00000000-0000-4000-8000-000000000002'
        with patch('target_journal.creation_scope', return_value=current):
            journal.retire_old_boot()
        return copy.deepcopy(journal.value), current

    def test_persisted_retirement_reread_rejects_every_corrupt_binding_without_write(self):
        with Target(self.path) as target, target.locked():
            original, current = self.retired_fixture(target)
            evidence = original['entries']['1']['resource_retirement']
            mutations = [True, 'retired', {}, dict(evidence, scope='wrong'),
                         dict(evidence, new_boot=evidence['old_boot']),
                         dict(evidence, sha256='0'*64)]
            # Recompute the digest for binding corruptions: digest alone is not authority.
            from target_coordination import digest
            for key, value in [('owner',{'record_id':'other'}), ('lease',{'lease_id':'other'}),
                               ('target_binding',{}), ('coord_key','other'), ('epoch',True),
                               ('watch','other'), ('acquisition',{'parent':'other'}),
                               ('launch',{'suffix':'other'}), ('schema',True)]:
                bad = dict(evidence, **{key:value})
                bad.pop('sha256', None)
                bad['sha256'] = digest(bad)
                mutations.append(bad)
            for bad in mutations:
                with self.subTest(retirement=bad):
                    value = copy.deepcopy(original)
                    value['entries']['1']['resource_retirement'] = bad
                    target.directory.durable('custody.json', value)
                    before = (target.directory.path/'custody.json').read_bytes()
                    with patch('target_journal.creation_scope',return_value=current):
                        with self.assertRaisesRegex(RuntimeError,'retirement|BootScope'):
                            reread = Journal(target)
                            reread.gate()
                            reread.check_owner({'record_id':'new-owner'})
                    self.assertEqual((target.directory.path/'custody.json').read_bytes(), before)
            target.directory.durable('custody.json', original)
            with patch('target_journal.creation_scope',return_value=current):
                reread = Journal(target)
                reread.check_owner({'record_id':'new-owner'})
                self.assertEqual(reread.accounting()['live_refs'], 0)
            # A genuine certificate cannot retire resources in the original boot.
            with patch('target_journal.creation_scope',return_value=evidence['binding']):
                with self.assertRaisesRegex(RuntimeError,'BootScope'):
                    Journal(target)

    def test_late_target_events_and_recovery_cannot_write_retired_history(self):
        with Target(self.path) as target, target.locked():
            original, current = self.retired_fixture(target)
            item = original['entries']['1']
            attempt = {'sequence':1,'target':{'kind':'release','lease':item['lease']}}
            item['release_observation'] = {'attempt':attempt}
            target.directory.durable('custody.json',original)
            before = (target.directory.path/'custody.json').read_bytes()
            with patch('target_journal.creation_scope',return_value=current):
                for action, value in [
                    ('detach_outcome', dict(watch=item['watch'],epoch=1,owner=item['owner'],lease=item['lease'],
                        attempt=attempt,outcome={'lease_released':True,'ack_kind':'last'})),
                    ('proof',dict(watch=item['watch'],proof={'record':{'subscription_epoch':1}}))]:
                    with self.subTest(action=action):
                        with self.assertRaisesRegex(RuntimeError,'retired'):
                            getattr(Journal(target), action)(value)
                        self.assertEqual((target.directory.path/'custody.json').read_bytes(), before)
                reread = Journal(target)
                # Recovery must skip the closed epoch before consulting old producers.
                with patch.object(reread,'authorized_producers',side_effect=AssertionError('old producer read')):
                    reread.recover_public_proofs()
                self.assertEqual((target.directory.path/'custody.json').read_bytes(), before)
                # New owner uses a new epoch and cannot inherit old retirement.
                epoch = reread.begin({'parent':{'operation_id':'new'},'purpose':'final','ordinal':1},
                                     'new-watch',owner={'record_id':'new-owner'})
                self.assertEqual(epoch,2)
                self.assertNotIn('resource_retirement',reread.value['entries']['2'])

    def test_waiting_writer_rechecks_retirement_inside_target_lock(self):
        with Target(self.path) as target:
            with target.locked():
                original, current = self.retired_fixture(target)
                item = original['entries']['1']
                attempt = {'sequence':1,'target':{'kind':'release','lease':item['lease']}}
                item['release_observation'] = {'attempt':attempt}
                live = copy.deepcopy(original)
                live['entries']['1'].pop('resource_retirement')
                target.directory.durable('custody.json',live)
                request = dict(watch=item['watch'],epoch=1,owner=item['owner'],lease=item['lease'],
                               attempt=attempt,outcome={'lease_released':True,'ack_kind':'last'})
                script = """
import json,sys,time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from target_coordination import Target
from target_journal import Journal
path,current,request=sys.argv[2],json.loads(sys.argv[3]),json.loads(sys.argv[4])
Path(path+'.waiting').touch()
with Target(path) as target, target.locked(deadline=time.monotonic()+2):
    with patch('target_journal.creation_scope',return_value=current):
        try: Journal(target).detach_outcome(request)
        except RuntimeError as error:
            assert 'retired' in str(error),str(error)
            print('retired writer rejected')
        else: raise AssertionError('late writer changed historical ACK')
"""
                child = subprocess.Popen([sys.executable,'-B','-c',script,str(REPO/'nexus_bridge/custody'),
                    str(self.path),json.dumps(current),json.dumps(request)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                import time
                deadline = time.monotonic()+2
                while not Path(str(self.path)+'.waiting').exists():
                    if time.monotonic() >= deadline:
                        self.fail('writer did not reach target lock barrier')
                    time.sleep(.005)
                # The earlier writer retires while the late writer is queued.
                with patch('target_journal.creation_scope',return_value=current):
                    Journal(target).retire_old_boot()
                before = (target.directory.path/'custody.json').read_bytes()
            out, err = child.communicate(timeout=3)
            self.assertEqual(child.returncode,0,err.decode())
            self.assertIn(b'retired writer rejected',out)
            with target.locked():
                self.assertEqual((target.directory.path/'custody.json').read_bytes(),before)


if __name__=='__main__':
    unittest.main(verbosity=2)
