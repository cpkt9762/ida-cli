"""Actual journal deletion and process exits with explicit closed-epoch inputs.

The closure flags are fixture inputs, not manufactured public owner proofs.
The separate helper/N1 suites exercise the production proof producers.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]
from target_coordination import Target, digest
from target_journal import Journal


def setup(path):
    path.write_bytes(b'unchanged private payload')
    with Target(path) as target,target.locked():
        journal=Journal(target)
        epoch=journal.begin({'parent':'compaction-fixture','purpose':'final','ordinal':1},'closed-watch')
        container=target.directory.child('observations')
        producer=container.child('fixture-producer')
        try:
            producer.durable('record.json',{'kind':'NoAttach','fixture':'closed input, no public proof'})
            _,info,raw=producer.read('record.json')
            reference={'path':str(producer.path/'record.json'),'sha256':digest(raw),
                       'inode':[info.st_dev,info.st_ino],'kind':'NoAttach'}
        finally:
            producer.close()
            container.close()
        journal.value['entries'][str(epoch)].update(producer_closed=True,consumer_closed=True,
            detached=True,bridge_closed=True,unacked_events=False,facts=[reference])
        journal.save()
        return target.directory.path,reference


def child(path,stage):
    import target_journal
    def boundary(actual,_detail):
        if stage==actual:os._exit(98)
    target_journal.compaction_boundary=boundary
    with Target(path) as target,target.locked():
        journal=Journal(target)
        journal.settle()
        journal.gate()
        assert journal.value['entries']=={},journal.value
        assert journal.value['closed_through']==1,journal.value
        assert journal.value['compaction'] is None,journal.value
        try:journal.item('closed-watch',1)
        except RuntimeError as error:assert 'old/unknown epoch' in str(error)
        else:raise AssertionError('closed observation revived')


class Compaction(unittest.TestCase):
    def test_each_deletion_boundary_resumes_in_fresh_process(self):
        base=Path(tempfile.mkdtemp(prefix='compact-exits-',dir=os.environ['R3A_CASE_ROOT']))
        for stage in ('intent_durable','before_unlink','after_unlink','file_directory_fsynced',
                      'producer_removed','container_fsynced','committed'):
            with self.subTest(stage=stage):
                folder=base/stage
                folder.mkdir(mode=0o700)
                path=folder/'input.i64'
                coordination,reference=setup(path)
                lock=(coordination/'lock').stat()
                results=[]
                for fault,expected in ((stage,98),('none',0)):
                    argv=['timeout','10s',sys.executable,'-B',__file__,str(path),fault]
                    uptime=subprocess.check_output(['uptime'],text=True).strip()
                    result=subprocess.run(argv,capture_output=True,text=True,check=False)
                    results.append(dict(argv=argv,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                        uptime_before=uptime,uptime_after=subprocess.check_output(['uptime'],text=True).strip()))
                    (folder/'results.json').write_text(json.dumps(results,indent=2))
                    self.assertEqual(result.returncode,expected,result.stderr)
                self.assertFalse(Path(reference['path']).exists())
                self.assertEqual((coordination/'lock').stat().st_ino,lock.st_ino)
                self.assertEqual(path.read_bytes(),b'unchanged private payload')

    def test_resume_refuses_new_references_and_changed_exact_fact(self):
        from unittest.mock import patch
        base=Path(tempfile.mkdtemp(prefix='compact-recheck-',dir=os.environ['R3A_CASE_ROOT']))
        for variant in ('event','producer','bridge','launch','file_intent','foreign_epoch','changed_fact'):
            with self.subTest(variant=variant):
                folder=base/variant
                folder.mkdir(mode=0o700)
                path=folder/'input.i64'
                coordination,reference=setup(path)
                with Target(path) as target,target.locked():
                    journal=Journal(target)
                    with patch('target_journal.compaction_boundary',side_effect=RuntimeError('paused intent')):
                        with self.assertRaisesRegex(RuntimeError,'paused intent'):journal.settle()
                    value=copy.deepcopy(journal.value)
                    item=value['entries']['1']
                    if variant=='event':item['unacked_events']=True
                    elif variant=='producer':item['producer_closed']=False
                    elif variant=='bridge':item['bridge_closed']=False
                    elif variant=='launch':item['launch']={'suffix':'pending'}
                    elif variant=='file_intent':
                        pointer=str(coordination/'retained/recovery.json')
                        value['file_intents']={digest(pointer.encode()):{'path':pointer,'status':'snapshotting','attempts':[]}}
                    elif variant=='foreign_epoch':
                        other=copy.deepcopy(item)
                        other.update(epoch=2,watch='other-live',unacked_events=True,consumer_closed=False)
                        value['entries']['2']=other
                        value['next_epoch']=3
                    else:
                        with Path(reference['path']).open('ab') as output:output.write(b'foreign bytes')
                    target.directory.durable('custody.json',value)
                    before=(coordination/'custody.json').read_bytes()
                    fact_before=Path(reference['path']).read_bytes()
                    with self.assertRaisesRegex(RuntimeError,'RoutineCompactionFailed'):
                        Journal(target)
                    self.assertEqual((coordination/'custody.json').read_bytes(),before)
                    self.assertEqual(Path(reference['path']).read_bytes(),fact_before)


if __name__=='__main__':
    if len(sys.argv)==3:child(Path(sys.argv[1]),sys.argv[2])
    else:unittest.main(verbosity=2)
