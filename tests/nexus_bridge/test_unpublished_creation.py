"""Actual create-before-binding exits retain unpublished bytes and resume."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]


def action(root,kind,crash):
    from target_coordination import Directory
    from recovery_files import copy_exact,file_info
    actual=os.open
    fault=crash if isinstance(crash,str) else None
    def intercepted(name,flags,*args,**kwargs):
        fd=actual(name,flags,*args,**kwargs)
        # The first owned file creation is the precise unbound-create window.
        if flags & os.O_EXCL and crash is True:
            (root/'created.json').write_text(json.dumps({'name':str(name),'inode':os.fstat(fd).st_ino}))
            os._exit(97)
        return fd
    directory=Directory(root/'destination')
    source=Directory(root/'source')
    try:
        os.open=intercepted
        if kind.startswith('record'):
            import durable_records
            def boundary(_directory,_name,stage):
                if stage==fault:os._exit(97)
            durable_records.boundary=boundary
            name=kind.split(':',1)[1] if ':' in kind else 'custody.json'
            directory.durable(name,{'known':'complete requested bytes'})
        else:
            import recovery_files
            def boundary(_action,stage,_detail):
                if stage==fault:os._exit(97)
            recovery_files.boundary=boundary
            path=root/'binding.json'
            binding=json.loads(path.read_text()) if path.exists() else None
            def checkpoint(value):
                path.write_text(json.dumps(value))
                with path.open() as stream:os.fsync(stream.fileno())
            copy_exact(source,'input.i64',directory,file_info(source,'input.i64'),0o400,
                       binding,checkpoint,directory.verify)
    finally:
        os.open=actual
        directory.close();source.close()


class UnpublishedCreation(unittest.TestCase):
    def scene(self):
        root=Path(tempfile.mkdtemp(prefix='creation-boundary-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        for folder in ('destination','source'):(root/folder).mkdir(mode=0o700)
        (root/'source/input.i64').write_bytes(b'exact source bytes'*1024)
        (root/'source/input.i64').chmod(0o600)
        return root

    def child(self,root,kind,fault):
        argv=['timeout','10s',sys.executable,'-B',__file__,'--child',str(root),kind,fault]
        uptime=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()
        result=subprocess.run(argv,capture_output=True,text=True)
        with (root/'boundaries.jsonl').open('a') as output:
            output.write(json.dumps(dict(argv=argv,uptime=uptime,exit=result.returncode,stderr=result.stderr))+'\n')
        return result

    def test_each_new_internal_boundary_fresh_process_continues(self):
        coverage=[]
        for name in ('custody.json','recovery.json','target.json','volume.json'):
            for stage in ('unbound_created','owner_unbound_created','owner_published'):
                with self.subTest(record=name,stage=stage):
                    root=self.scene()
                    result=self.child(root,'record:'+name,stage)
                    self.assertEqual(result.returncode,97,result.stderr)
                    result=self.child(root,'record:'+name,'none')
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(json.loads((root/'destination'/name).read_text()),{'known':'complete requested bytes'})
                    coverage.append(dict(record=name,stage=stage,case=str(root)))
        for stage in ('unbound_created','created','chunk','file_fsynced','directory_fsynced','checkpointed'):
            with self.subTest(copy=stage):
                root=self.scene()
                result=self.child(root,'copy',stage)
                self.assertEqual(result.returncode,97,result.stderr)
                result=self.child(root,'copy','none')
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual((root/'destination/input.i64').read_bytes(),(root/'source/input.i64').read_bytes())
                coverage.append(dict(copy=stage,case=str(root)))
        (Path(os.environ['R3A_CASE_ROOT'])/'creation-coverage.json').write_text(json.dumps(coverage,indent=2))

    def test_bound_preparations_and_foreign_live_names_fail_closed_without_writes(self):
        from test_recovery_preview import fingerprints
        for kind in ('record','copy'):
            for variant in ('inode','bytes','mode','foreign-live'):
                with self.subTest(kind=kind,variant=variant):
                    root=self.scene()
                    stage='owner_published' if kind=='record' else 'checkpointed'
                    self.assertEqual(self.child(root,kind,stage).returncode,97)
                    if kind=='record':
                        owner=json.loads((root/'destination/custody.json.new.owner').read_text())
                        prepared=root/'destination'/owner['prepared']
                    else:prepared=root/'destination'/json.loads((root/'binding.json').read_text())['prepared']
                    if variant=='inode':
                        replacement=root/'replacement'
                        replacement.write_bytes(prepared.read_bytes());replacement.chmod(prepared.stat().st_mode & 0o777)
                        os.replace(replacement,prepared)
                    elif variant=='bytes':
                        prepared.chmod(0o600);prepared.write_bytes(b'foreign changed bytes')
                    elif variant=='mode':prepared.chmod(0o666)
                    else:
                        name='custody.json.new' if kind=='record' else 'input.i64'
                        (root/'destination'/name).write_bytes(b'foreign live slot');(root/'destination'/name).chmod(0o600)
                    before=fingerprints(root/'destination')
                    result=self.child(root,kind,'none')
                    self.assertNotEqual(result.returncode,0,'foreign or altered reservation must block')
                    self.assertEqual(fingerprints(root/'destination'),before)

    def test_fresh_process_resumes_after_real_unbound_creation(self):
        root=Path(tempfile.mkdtemp(prefix='unbound-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        for kind in ('record','copy'):
            with self.subTest(kind=kind):
                case=root/kind;case.mkdir(mode=0o700)
                for name in ('destination','source'):(case/name).mkdir(mode=0o700)
                (case/'source/input.i64').write_bytes(b'complete original'*100)
                (case/'source/input.i64').chmod(0o600)
                results=[]
                for crash,expected in ((True,97),(False,0)):
                    argv=['timeout','10s',sys.executable,'-B',__file__,'--child',str(case),kind,str(int(crash))]
                    uptime=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()
                    result=subprocess.run(argv,capture_output=True,text=True)
                    results.append(dict(argv=argv,exit=result.returncode,stderr=result.stderr,uptime=uptime))
                    (case/'runs.json').write_text(json.dumps(results,indent=2))
                    self.assertEqual(result.returncode,expected,result.stderr)
                created=json.loads((case/'created.json').read_text())
                # The unbound inode survives as retained evidence, never read
                # as authority and never removed to make the test pass.
                self.assertEqual((case/'destination'/created['name']).stat().st_ino,created['inode'])
                if kind=='record':self.assertEqual(json.loads((case/'destination/custody.json').read_text()),{'known':'complete requested bytes'})
                else:self.assertEqual((case/'destination/input.i64').read_bytes(),(case/'source/input.i64').read_bytes())


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':
        value=sys.argv[4]
        action(Path(sys.argv[2]),sys.argv[3],bool(int(value)) if value in ('0','1') else value)
    else:unittest.main(verbosity=2)
