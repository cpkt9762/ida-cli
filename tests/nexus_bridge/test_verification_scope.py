"""Exact production scope/cleanup authority over private IDB copies and real EX.

Foreign epoch terminal flags below are explicitly file-journal boundary inputs,
not N1/helper/public owner proof. Runtime closure is covered by Rust regressions.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'nexus_bridge'))
sys.path.insert(0,str(REPO/'nexus_bridge/custody'))
from target_coordination import Target
from target_journal import Journal, verification_scope, verification_probe_cleanup
from owner_identity import state_identity


PARENT={'client_id':'scope-test','operation_id':'verification','request_id':'verification','task_id':None}


class VerificationScope(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='scope-',dir=os.environ['R3A_CASE_ROOT']))
        self.root.chmod(0o700)
        self.probe=self.root/'probe.i64'
        shutil.copyfile(os.environ['R3F1_SAMPLE'],self.probe)
        self.probe.chmod(0o600)
        (self.root/'input').write_bytes(b'private immutable input')
        # Keep private input/journal scenes for independent verification, including failures.

    def initialize(self,target):
        return verification_scope(target,copy.deepcopy(PARENT))

    def test_cleanup_cannot_initialize_missing_or_malformed_scope(self):
        variants=['missing','null','bool-schema','float-schema','float-directory','bool-directory',
                  'parent-null','parent-empty','parent-string','parent-extra','parent-missing',
                  'parent-bool','task-bool','unknown-field','foreign-parent']
        for variant in variants:
            with self.subTest(variant=variant):
                child=self.root/variant;child.mkdir(mode=0o700)
                probe=child/'probe.i64';shutil.copyfile(self.probe,probe)
                (child/'input').write_bytes(b'private immutable input')
                with Target(probe) as target,target.locked():
                    self.initialize(target)
                    journal=Journal(target);value=journal.value
                    if variant=='missing':value.pop('verification_scope')
                    elif variant=='null':value['verification_scope']=None
                    elif variant=='bool-schema':value['verification_scope']['schema']=True
                    elif variant=='float-schema':value['verification_scope']['schema']=1.0
                    elif variant=='float-directory':value['verification_scope']['directory']=[float(n) for n in target.key['parent']]
                    elif variant=='bool-directory':value['verification_scope']['directory'][0]=True
                    elif variant=='parent-null':value['verification_scope']['parent']=None
                    elif variant=='parent-empty':value['verification_scope']['parent']={}
                    elif variant=='parent-string':value['verification_scope']['parent']='bad'
                    elif variant=='parent-extra':value['verification_scope']['parent']['extra']=1
                    elif variant=='parent-missing':value['verification_scope']['parent'].pop('request_id')
                    elif variant=='parent-bool':value['verification_scope']['parent']['client_id']=True
                    elif variant=='task-bool':value['verification_scope']['parent']['task_id']=False
                    elif variant=='unknown-field':value['verification_scope']['extra']=1
                    elif variant=='foreign-parent':value['verification_scope']['parent']['operation_id']='foreign'
                    target.directory.durable('custody.json',value)
                    before=(probe.read_bytes(),(target.directory.path/'custody.json').read_bytes())
                    error=None
                    try:verification_probe_cleanup(target,state_identity(),PARENT)
                    except (ValueError,RuntimeError,TypeError) as exc:error=exc
                    after=(probe.read_bytes() if probe.exists() else None,(target.directory.path/'custody.json').read_bytes())
                    evidence={'variant':variant,'rejected':error is not None,'error':None if error is None else str(error),
                              'probe_retained':probe.exists(),'journal_unchanged':after[1]==before[1]}
                    (self.root.parent/(self.root.name+'-'+variant+'.json')).write_text(json.dumps(evidence))
                    self.assertIsNotNone(error,'cleanup must never recreate or accept invalid existing authority')
                    self.assertEqual(after,before,'rejection must preserve payload and journal')
                    self.assertFalse((child/'closed').exists())

    def test_missing_scope_foreign_epoch_compaction_cannot_restore_old_authority(self):
        for lost in (False,True):
            with self.subTest(scope_lost=lost):
                child=self.root/str(lost);child.mkdir(mode=0o700)
                probe=child/'probe.i64';shutil.copyfile(self.probe,probe);(child/'input').write_bytes(b'input')
                with Target(probe) as target,target.locked():
                    self.initialize(target)
                    journal=Journal(target)
                    if lost:
                        journal.value.pop('verification_scope');journal.save()
                    journal=Journal(target)
                    foreign=dict(PARENT,operation_id='later-foreign-parent')
                    epoch=journal.begin({'parent':foreign,'purpose':'final','ordinal':1},'foreign-epoch')
                    # Only the terminal flags are a stipulated journal boundary.
                    journal.value['entries'][str(epoch)].update(producer_closed=True,consumer_closed=True,
                        detached=True,bridge_closed=True,unacked_events=False)
                    journal.settle()
                    self.assertEqual(journal.value['entries'],{})
                    before=(probe.read_bytes(),(target.directory.path/'custody.json').read_bytes())
                    error=None
                    try:verification_probe_cleanup(target,state_identity(),PARENT)
                    except RuntimeError as exc:error=exc
                    evidence={'scope_lost':lost,'foreign_epoch':epoch,'compacted':True,'error':None if error is None else str(error),
                              'payload_survived':probe.exists(),'scope_after':Journal(target).value.get('verification_scope')}
                    (self.root.parent/(self.root.name+'-foreign-'+str(lost)+'.json')).write_text(json.dumps(evidence))
                    self.assertIsNotNone(error,'compaction must not erase foreign authorization history')
                    self.assertTrue(probe.exists(),'later payload cannot be deleted under old authority')
                    self.assertEqual((probe.read_bytes(),(target.directory.path/'custody.json').read_bytes()),before)
                    with self.assertRaises(RuntimeError,msg='late initialization cannot erase any earlier epoch'):
                        self.initialize(target)

    def test_initialization_is_once_before_any_epoch_and_normal_cleanup_works(self):
        with Target(self.probe) as target,target.locked():
            first=self.initialize(target)
            before=(target.directory.path/'custody.json').read_bytes()
            # Exact existing scope validation is harmless and never rewrites it.
            self.initialize(target)
            self.assertEqual((target.directory.path/'custody.json').read_bytes(),before)
            self.assertEqual(first.value['verification_scope']['parent'],PARENT)
            receipt=verification_probe_cleanup(target,state_identity(),PARENT)
            self.assertEqual(receipt['kind'],'verification_probe_cleanup')
            self.assertFalse(self.probe.exists())
            self.assertEqual((self.root/'input').read_bytes(),b'private immutable input')
            self.assertTrue((target.directory.path/'lock').exists())


if __name__=='__main__':unittest.main()
