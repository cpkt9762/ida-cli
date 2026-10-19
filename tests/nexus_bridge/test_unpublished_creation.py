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
    def test_installed_maintenance_deletes_only_the_approved_unpublished_identity(self):
        from test_recovery_preview import Preview,evidence_for,fingerprints
        from target_coordination import Target
        root=Path(tempfile.mkdtemp(prefix='scratch-installed-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        path=root/'tiny.i64';path.write_bytes(b'private installed maintenance target');path.chmod(0o600)
        with Target(path) as target,target.locked():
            scratch=target.directory.path/('.ida-cli-unpublished-'+'d'*32)
            scratch.write_bytes(b'exact orphan scratch');scratch.chmod(0o600)
        recovery_id='e'*32
        evidence=evidence_for(root,path,recovery_id)
        evidence['cleanup_unpublished']=True
        before=fingerprints(scratch.parent)
        caller=Preview()
        failure,result=caller.invoke(root,path,recovery_id,evidence,installed=True)
        self.assertIsNone(failure,repr(failure))
        self.assertEqual(fingerprints(scratch.parent),before,'installed preview mutated coordination')
        self.assertEqual([v['path'] for v in result['plan']['unpublished_scratch']],[str(scratch)])
        evidence['approved_plan_sha256']=result['plan_sha256']
        failure,result=caller.invoke(root,path,recovery_id,evidence,dry=False,installed=True)
        self.assertIsNone(failure,repr(failure))
        self.assertFalse(scratch.exists())
        self.assertEqual(path.read_bytes(),b'private installed maintenance target')

    def test_maintenance_previews_and_explicitly_deletes_only_unreferenced_exact_scratch(self):
        from unittest.mock import patch
        from test_recovery_preview import evidence_for
        from target_coordination import Target
        import recovery_maintenance as maintenance
        root=Path(tempfile.mkdtemp(prefix='scratch-maint-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        (root/'payload').mkdir(mode=0o700)
        path=root/'payload/input.i64';path.write_bytes(b'private maintenance target');path.chmod(0o600)
        with Target(path) as target,target.locked():
            scratch=target.directory.path/('.ida-cli-unpublished-'+'a'*32)
            scratch.write_bytes(b'unbound creation bytes');scratch.chmod(0o600)
        recovery_id='b'*32
        evidence=evidence_for(root,path,recovery_id)
        with Target(path,create=False) as target,target.locked(recover=False), \
                patch.object(maintenance,'occupancy',return_value=None):
            plan,_=maintenance.snapshotless_preview(target,recovery_id,evidence)
            self.assertEqual([item['path'] for item in plan['unpublished_scratch']],[str(scratch)])
            self.assertEqual(plan['unpublished_scratch'][0]['size'],len(b'unbound creation bytes'))
            self.assertTrue(scratch.exists(),'preview must not delete scratch')
        evidence['cleanup_unpublished']=True
        from contextlib import redirect_stdout
        import io
        permission=root/'operator.json'
        def invoke(dry_run):
            permission.write_text(json.dumps(evidence));permission.chmod(0o600)
            argv=['maintenance','--maintenance','--offline-evidence',str(permission),
                '--target',str(path),'--transaction',recovery_id]
            if dry_run:argv.append('--dry-run')
            output=io.StringIO()
            with patch.object(sys,'argv',argv),redirect_stdout(output), \
                    patch.object(maintenance,'occupancy',return_value=None):
                self.assertEqual(maintenance.main(),0)
            return json.loads(output.getvalue())
        result=invoke(True)
        evidence['approved_plan_sha256']=result['plan_sha256']
        self.assertTrue(scratch.exists())
        invoke(False)
        self.assertFalse(scratch.exists(),'approved apply must remove exact unbound scratch')
        self.assertEqual(path.read_bytes(),b'private maintenance target')

    def test_maintenance_retains_referenced_and_rejects_changed_scratch(self):
        from target_coordination import Target
        import recovery_maintenance as maintenance
        for variant in ('inode','bytes','permissions','reference','inode-reference','symlink'):
            with self.subTest(variant=variant):
                root=Path(tempfile.mkdtemp(prefix='scratch-ref-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
                path=root/'tiny.i64';path.write_bytes(b'private target');path.chmod(0o600)
                with Target(path) as target,target.locked():
                    scratch=target.directory.path/('.ida-cli-unpublished-'+'c'*32)
                    scratch.write_bytes(b'original scratch');scratch.chmod(0o600)
                    approved=maintenance.scratch_inventory(target)
                    if variant=='inode':
                        other=root/'other';other.write_bytes(scratch.read_bytes());other.chmod(0o600)
                        os.replace(other,scratch)
                    elif variant=='bytes':scratch.write_bytes(b'replaced scratch')
                    elif variant=='permissions':scratch.chmod(0o666)
                    elif variant=='symlink':
                        scratch.unlink();scratch.symlink_to(path)
                    elif variant=='reference':
                        # Actual owner/checkpoint publication binds a previously
                        # unreferenced name; deletion must recheck references.
                        target.directory.durable('checkpoint.json',{'prepared':scratch.name})
                        self.assertNotIn(str(scratch),[v['path'] for v in maintenance.scratch_inventory(target)])
                    else:
                        info=scratch.stat()
                        target.directory.durable('checkpoint.json',{'identity':[info.st_dev,info.st_ino,info.st_uid]})
                        self.assertNotIn(str(scratch),[v['path'] for v in maintenance.scratch_inventory(target)])
                    with self.assertRaises((RuntimeError,OSError)):
                        maintenance.remove_scratch(target,approved)
                    self.assertTrue(scratch.exists())
                    self.assertEqual(path.read_bytes(),b'private target')
                # No public owner proof or N1 phase is fabricated by this file-boundary test.

    def test_maintenance_retains_real_pending_owner_preparation(self):
        from unittest.mock import patch
        from target_coordination import Target
        import recovery_maintenance as maintenance
        root=Path(tempfile.mkdtemp(prefix='scratch-owner-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        path=root/'tiny.i64';path.write_bytes(b'private target');path.chmod(0o600)
        with Target(path) as target,target.locked():
            def stop(_directory,name,stage):
                if name=='checkpoint.json' and stage=='owner_published':
                    raise RuntimeError('real durable owner published boundary')
            with patch('durable_records.boundary',stop),self.assertRaisesRegex(RuntimeError,'real durable owner'):
                target.directory.durable('checkpoint.json',{'complete':'pending data'})
            owner=target.directory.read('checkpoint.json.new.owner')[0]
            bound=target.directory.path/owner['prepared']
            self.assertTrue(bound.is_file())
            self.assertNotIn(str(bound),[v['path'] for v in maintenance.scratch_inventory(target)])
            self.assertTrue(bound.is_file())

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
