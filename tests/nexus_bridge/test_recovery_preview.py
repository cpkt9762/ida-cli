"""Production maintenance preview/apply, exact full-tree no-write assertions."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]
from target_coordination import Target,Directory,encoded
from recovery_transaction import Transaction
from recovery_maintenance import main,tree
from recovery_files import inventory,component_names
from origin import creation_scope
from owner_identity import state_identity


def fingerprints(root):
    result={}
    for path in (root,*root.rglob('*')):
        value=path.lstat()
        item={key:getattr(value,'st_'+key) for key in
              ('dev','ino','mode','uid','gid','nlink','mtime_ns','ctime_ns')}
        if path.is_file():item.update(size=value.st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        result[str(path.relative_to(root))]=item
    return result


def scene(root,phase='archived'):
    payload=root/'payload';payload.mkdir(mode=0o700)
    path=payload/'input.i64';shutil.copyfile(os.environ['R3F1_SAMPLE'],path);path.chmod(0o600)
    with Target(path) as target,target.locked():
        recovery_id,token=Transaction.allocate(target,source_files={})
        with Transaction(target,recovery_id,token=token) as transaction:
            if phase=='archived':transaction.archive('no failure private test')
            pending=copy.deepcopy(transaction.data);pending['revision']+=1;pending['cause']='exact authorized pending'
            def stop(_directory,name,stage):
                if name=='recovery.json' and stage=='before_rename':raise RuntimeError('pending test boundary')
            with patch('durable_records.boundary',stop):
                try:transaction.directory.durable('recovery.json',pending)
                except RuntimeError as error:
                    if str(error)!='pending test boundary':raise
                else:raise AssertionError('pending record boundary not reached')
    return path,recovery_id


def evidence_for(root,path,recovery_id,existing=False):
    backup=root/'backup';backup.mkdir(mode=0o700)
    with Target(path,create=False) as target,target.locked(recover=False):
        parent=Directory(path.parent,private=False)
        try:components={k:v for k,v in inventory(parent,target.directory).items() if k in component_names(path)}
        finally:parent.close()
        retained={}
        if existing:
            directory=target.directory.child(recovery_id,create=False)
            try:retained=tree(directory);shutil.copytree(directory.path,backup/'transaction')
            finally:directory.close()
        else:(backup/'transaction').mkdir(mode=0o700)
        (backup/'components').mkdir(mode=0o700)
        for name in components:shutil.copy2(path.parent/name,backup/'components'/name)
        return dict(schema=1,operator=dict(uid=os.getuid(),name='private fix1 test operator',
            confirmation='I established and maintain this exclusive offline window'),
            host=creation_scope(target.directory.path,'preview-test'),
            window=dict(id='private-preview',started_at=time.time()-1,expires_at=time.time()+120),
            target=target.original,coord_key=target.key,directory=target.directory.identity,
            root_binding=target.recovery_root_binding(),transaction=recovery_id,components=components,
            retained=retained,stopped_openers=[],state_roots=[state_identity()],
            offline_scope=dict(all_target_openers_stopped=True,new_openers_prevented=True,
                cross_uid_openers_excluded=True,remote_writers_excluded=True,automatic_restarts_prevented=True),
            backup=dict(path=str(backup),directory=[backup.stat().st_dev,backup.stat().st_ino,os.getuid()]),
            approved_plan_sha256=None)


class Preview(unittest.TestCase):
    def root(self):return Path(tempfile.mkdtemp(prefix='preview-fix1-',dir=os.environ['R3A_CASE_ROOT'])).resolve()

    def invoke(self,root,path,recovery_id,value,dry=True,installed=False):
        evidence=root/'evidence.json'
        evidence.write_bytes(value if isinstance(value,bytes) else encoded(value));evidence.chmod(0o600)
        argv=['open_recovery.py','--maintenance','--offline-evidence',str(evidence),
              '--target',str(path),'--transaction',recovery_id]+(['--dry-run'] if dry else [])
        if installed:
            installation=Path(os.environ['R3A_INSTALLATION']).resolve()
            command=['timeout','15s',str(installation/'maintenance-launch'),sys.executable,str(installation),
                     'isolated',*argv[1:]]
            before=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()
            result=subprocess.run(command,capture_output=True,text=True,check=False)
            with (root/'calls.jsonl').open('a') as output:
                output.write(json.dumps(dict(argv=command,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                    uptime_before=before,uptime_after=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()))+'\n')
            return (RuntimeError(result.stderr) if result.returncode else None,
                    json.loads(result.stdout) if result.returncode==0 else None)
        stdout=io.StringIO();error=None
        with patch.object(sys,'argv',argv),redirect_stdout(stdout):
            try:main()
            except Exception as caught:error=caught
        with (root/'calls.jsonl').open('a') as output:
            output.write(json.dumps(dict(argv=argv,error=repr(error),stdout=stdout.getvalue()))+'\n')
        return error,json.loads(stdout.getvalue()) if stdout.getvalue() else None

    def test_rejected_or_unapproved_preview_preserves_other_terminal_and_active_pending(self):
        for phase in ('archived','snapshotting'):
            for variant in ('invalid','malformed','expired','unapproved','wrong-plan'):
                with self.subTest(phase=phase,evidence=variant):
                    root=self.root();path,_=scene(root,phase);recovery_id=uuid.uuid4().hex
                    value=evidence_for(root,path,recovery_id)
                    if variant=='invalid':value={}
                    elif variant=='malformed':value=b'{'
                    elif variant=='expired':value['window']['expires_at']=time.time()-1
                    elif variant=='wrong-plan':value['approved_plan_sha256']='0'*64
                    before=fingerprints(path.parent)
                    error,_=self.invoke(root,path,recovery_id,value)
                    self.assertIsNotNone(error)
                    self.assertEqual(fingerprints(path.parent),before)

    def test_exact_pending_preview_is_read_only_and_approved_apply_resumes(self):
        root=self.root();path,recovery_id=scene(root)
        value=evidence_for(root,path,recovery_id,True);before=fingerprints(path.parent)
        error,preview=self.invoke(root,path,recovery_id,value,installed=True)
        self.assertIsNone(error,repr(error));self.assertEqual(fingerprints(path.parent),before)
        self.assertFalse(preview['public_owner_proof'])
        value['approved_plan_sha256']=preview['plan_sha256']
        for variant in ('expired','plan','identity'):
            with self.subTest(refused_apply=variant):
                bad=copy.deepcopy(value)
                if variant=='expired':bad['window']['expires_at']=time.time()-1
                elif variant=='plan':bad['approved_plan_sha256']='0'*64
                else:bad['directory'][1]+=1
                error,_=self.invoke(root,path,recovery_id,bad,False,installed=True)
                self.assertIsNotNone(error);self.assertEqual(fingerprints(path.parent),before)
        error,result=self.invoke(root,path,recovery_id,value,False,installed=True)
        self.assertIsNone(error,repr(error));self.assertEqual(result['status']['job_id'],recovery_id)
        self.assertEqual(result['status']['phase'],'archived')
        directory=next(path.parent.glob('.ida-cli-txn-*'))/recovery_id
        self.assertFalse((directory/'recovery.json.new').exists())
        self.assertFalse((directory/'recovery.json.new.owner').exists())
        self.assertEqual(path.read_bytes(),Path(os.environ['R3F1_SAMPLE']).read_bytes())

    def test_installed_official_entry_rejects_without_publishing_other_pending(self):
        root=self.root();path,_=scene(root);recovery_id=uuid.uuid4().hex
        evidence=root/'evidence.json';evidence.write_text('{}');evidence.chmod(0o600)
        installation=Path(os.environ['R3A_INSTALLATION']).resolve()
        self.assertTrue((installation/'manifest.json').is_file(),'current installed closure must exist')
        before=fingerprints(path.parent)
        for mode in ('ordinary','isolated','safe','envsafe'):
            with self.subTest(mode=mode):
                argv=['timeout','15s',str(installation/'maintenance-launch'),sys.executable,str(installation),mode,
                    '--maintenance','--offline-evidence',str(evidence),'--target',str(path),
                    '--transaction',recovery_id,'--dry-run']
                start=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()
                result=subprocess.run(argv,capture_output=True,text=True,check=False)
                with (root/'installed.jsonl').open('a') as output:
                    output.write(json.dumps(dict(argv=argv,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                        uptime_before=start,uptime_after=subprocess.check_output(['timeout','5s','uptime'],text=True).strip()))+'\n')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(fingerprints(path.parent),before)
                self.assertIn('read-only inspection retains a pending file writer',result.stderr)

    def test_apply_rechecks_actual_bytes_identity_and_new_opener_after_preview(self):
        for variant in ('inode','bytes','new-opener'):
            with self.subTest(change=variant):
                root=self.root();path,recovery_id=scene(root)
                value=evidence_for(root,path,recovery_id,True)
                error,plan=self.invoke(root,path,recovery_id,value,installed=True)
                self.assertIsNone(error,repr(error));value['approved_plan_sha256']=plan['plan_sha256']
                if variant=='inode':
                    replacement=root/'replacement';shutil.copyfile(path,replacement);replacement.chmod(0o600)
                    self.assertNotEqual(replacement.stat().st_ino,path.stat().st_ino);os.replace(replacement,path)
                elif variant=='bytes':
                    with path.open('ab') as output:output.write(b'changed after preview')
                else:
                    from target_journal import Journal
                    with Target(path) as target,target.locked():
                        Journal(target).begin({'parent':'new-private-opener','purpose':'final','ordinal':1},
                            'new-unproved-watch',launch={'suffix':'explicit fixture, no native birth'})
                before=fingerprints(path.parent)
                error,_=self.invoke(root,path,recovery_id,value,False,installed=True)
                self.assertIsNotNone(error,'stale preview cannot authorize recovery of changed input')
                self.assertEqual(fingerprints(path.parent),before)


if __name__=='__main__':unittest.main(verbosity=2)
