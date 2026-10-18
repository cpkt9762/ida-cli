"""U6 validates native creation scope and journal identity before retirement."""
import copy
import os
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


if __name__=='__main__':
    unittest.main(verbosity=2)
