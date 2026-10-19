"""Production metadata/file recovery under explicit OS device/boot inputs.

The kernel locks and bytes are real; device-number changes and boot sources are
controlled inputs, not a claim of an actual remount, reboot, VM or IDA run.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO=Path(os.environ.get('R4_PRODUCT_SOURCE',Path(__file__).resolve().parents[2]))
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge'),str(Path(__file__).parent)]


def inputs(old=False,overrides=None):
    from test_recovery_transaction import no_owner_input
    no_owner_input()
    if old:
        actual_stat,actual_fstat,actual_lstat=os.stat,os.fstat,os.lstat
        class DeviceStat:
            def __init__(self,real):self.real=real
            @property
            def st_dev(self):return self.real.st_dev+1000
            def __getattr__(self,name):return getattr(self.real,name)
            def __getitem__(self,index):return self.st_dev if index==2 else self.real[index]
            def __len__(self):return len(self.real)
        os.stat=lambda *a,**kw:DeviceStat(actual_stat(*a,**kw))
        os.fstat=lambda *a,**kw:DeviceStat(actual_fstat(*a,**kw))
        os.lstat=lambda *a,**kw:DeviceStat(actual_lstat(*a,**kw))
    else:
        import origin
        actual_scope=origin.creation_scope
        def scope(path,incarnation,**options):
            value=actual_scope(path,incarnation,**options)
            if not (overrides or {}).get('sameboot'):
                value['creator']=dict(value['creator'],boot_id='00000000-0000-4000-8000-000000000001')
            for key,item in (overrides or {}).items():
                if key!='sameboot':value[key]=copy.deepcopy(item)
            return value
        origin.creation_scope=scope


def produce(case,managed=False):
    inputs(old=True)
    from open_recovery import Snapshot
    from target_coordination import Target
    payload=case/('cache/generations/g-volume' if managed else 'payload')
    payload.mkdir(mode=0o700,parents=True)
    if managed:
        manifest=payload/'generation.json'
        manifest.write_text(json.dumps({'version':1,'key':'volume-epoch'}))
        manifest.chmod(0o600)
    path=payload/'input.i64'
    original=b'exact original before device epoch'
    path.write_bytes(original)
    snapshot=Snapshot(case/'home',path,float('inf'),owner_probe=lambda _:None)
    path.write_bytes(b'failed complete file')
    snapshot.failed(1)
    with Target(path) as target,target.locked():
        reference={'target':str(path),'recovery_id':snapshot.path.name,'snapshot':str(snapshot.path),'coord_key':target.key,
            'lock_inode':os.fstat(target.target_fd).st_ino,'directory':str(target.directory.path),
            'original_sha256':hashlib.sha256(original).hexdigest()}
    (case/'reference.json').write_text(json.dumps(reference))


def consume(case,overrides):
    inputs(overrides=overrides)
    from target_coordination import Target
    from target_journal import Journal
    from recovery_transaction import Transaction
    reference=json.loads((case/'reference.json').read_text())
    with Target(reference['target']) as target,target.locked():
        assert target.key==reference['coord_key'],'must keep the same logical authority'
        assert os.fstat(target.target_fd).st_ino==reference['lock_inode'],'never replace stable lock'
        with Transaction(target,reference['recovery_id']) as transaction:
            transaction.resume_executor()
            transaction.restore()
            assert transaction.data['status']=='restored'
        Journal(target).gate()
    assert hashlib.sha256(Path(reference['target']).read_bytes()).hexdigest()==reference['original_sha256']


def quiescent_scene(case,variant):
    inputs(old=True)
    from target_coordination import Target
    from target_journal import Journal
    path=case/'tiny.i64';path.write_bytes(b'quiescent target bytes');path.chmod(0o600)
    with Target(path) as target,target.locked():
        if variant in ('acquisition','helper','startup'):
            Journal(target).begin({'parent':{'operation_id':'r6-private'},'purpose':'final','ordinal':1},
                'r6-unclosed',owner={'record_id':'r6-owner'} if variant=='helper' else None,
                launch={'suffix':'r6-private-launch'} if variant=='startup' else None)
        elif variant=='pending':
            from unittest.mock import patch
            def stop(_directory,name,stage):
                if name=='custody.json' and stage=='before_rename':raise RuntimeError('retain real pending write')
            with patch('durable_records.boundary',stop):
                try:target.directory.durable('custody.json',Journal(target).value)
                except RuntimeError as error:assert 'retain real pending' in str(error)
                else:raise AssertionError('pending boundary missed')
        (case/'quiescent.json').write_text(json.dumps({'target':str(path),'key':target.key,
            'lock_inode':os.fstat(target.target_fd).st_ino,'directory':str(target.directory.path),
            'target_record':(target.directory.path/'target.json').read_text()}))


def reopen_quiescent(case,options):
    inputs(overrides={'sameboot':True,**options.get('scope',{})})
    from target_coordination import Target
    if options.get('crash'):
        import durable_records
        def stop(_directory,name,stage):
            if name=='volume.json' and stage==options['crash']:os._exit(97)
        durable_records.boundary=stop
    ref=json.loads((case/'quiescent.json').read_text())
    with Target(ref['target']) as target,target.locked():
        assert target.key==ref['key']
        assert os.fstat(target.target_fd).st_ino==ref['lock_inode']
        assert (target.directory.path/'target.json').read_text()==ref['target_record']
        binding=target.directory.read('volume.json')[0]
        assert binding['schema']==2 and binding['mapped_device']==os.fstat(target.target_fd).st_dev
        assert binding['device']!=binding['mapped_device']
    assert Path(ref['target']).read_bytes()==b'quiescent target bytes'


class VolumeEpoch(unittest.TestCase):
    def test_permission_equivalence_requires_local_mount_owner_file_owner_and_allowlisted_type(self):
        from unittest.mock import patch
        import stat
        import types
        import target_coordination as coordination
        root=Path(tempfile.mkdtemp(prefix='mount-policy-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
        path=root/'private-file';path.write_bytes(b'permission decision input');path.chmod(0o666)
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        real=os.fstat(descriptor)
        variants=[('exfat',0x1000,os.getuid(),os.getuid(),True),
            ('exfat',0,os.getuid(),os.getuid(),False),
            ('exfat',0x1000,os.getuid()+1,os.getuid(),False),
            ('exfat',0x1000,os.getuid(),os.getuid()+1,False),
            *[(fs,0x1000,os.getuid(),os.getuid(),False) for fs in ('apfs','hfs','smbfs','nfs','afpfs')]]
        try:
            for fs,flags,mounter,owner,accepted in variants:
                with self.subTest(filesystem=fs,flags=flags,mounter=mounter,owner=owner):
                    observed=types.SimpleNamespace(st_mode=stat.S_IFREG|0o666,st_uid=owner,
                        st_nlink=1,st_dev=real.st_dev)
                    mount=dict(filesystem=fs,flags=flags,owner=mounter,fsid=[123,456])
                    with patch.object(coordination,'native_mount',return_value=mount), \
                            patch.object(coordination,'capability_status',return_value={'supported':True}), \
                            patch.object(os,'fstat',return_value=observed):
                        if accepted:self.assertIs(coordination.checked(descriptor),observed)
                        else:
                            with self.assertRaisesRegex(RuntimeError,'CoordinationBlocked'):
                                coordination.checked(descriptor)
            self.assertEqual(path.stat().st_ino,real.st_ino)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o666,'classification must be read-only')
        finally:os.close(descriptor)

    def test_sameboot_quiescent_rebinding_is_durable_before_effect_and_resumes_after_exit(self):
        for fault in (None,'owner_published','before_rename','after_rename','directory_fsynced'):
            with self.subTest(fault=fault):
                case=Path(tempfile.mkdtemp(prefix='quiescent-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
                self.assertEqual(self.child(case,'--quiescent-produce',{'variant':'clean'}).returncode,0)
                if fault:
                    result=self.child(case,'--quiescent-consume',{'crash':fault})
                    self.assertEqual(result.returncode,97,result.stderr)
                result=self.child(case,'--quiescent-consume')
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(self.child(case,'--quiescent-consume').returncode,0,'persisted mapping must reopen')

    def test_sameboot_rebinding_keeps_each_unsettled_obligation_and_missing_uuid_blocked(self):
        for variant,options in [('acquisition',{}),('helper',{}),('startup',{}),('pending',{}),
                ('clean',{'scope':{'volume_sha256':None}}),('clean',{'scope':{'volume_sha256':'0'*64}})]:
            with self.subTest(variant=variant,options=options):
                case=Path(tempfile.mkdtemp(prefix='rebind-block-',dir=os.environ['R3A_CASE_ROOT'])).resolve()
                result=self.child(case,'--quiescent-produce',{'variant':variant})
                self.assertEqual(result.returncode,0,result.stderr)
                directory=Path(json.loads((case/'quiescent.json').read_text())['directory'])
                before={str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()}
                result=self.child(case,'--quiescent-consume',options)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('UnsupportedBootScope',result.stderr)
                self.assertEqual({str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()},before)

    def test_unavailable_or_non_apfs_native_scope_is_explicitly_unsupported(self):
        from unittest.mock import patch
        import plistlib
        import origin
        for variant in ('exfat','hfs','smbfs','nfs','diskutil','machine','volume','mount'):
            with self.subTest(variant=variant):
                def output(argv,**_options):
                    if '/usr/sbin/ioreg' in argv:
                        return plistlib.dumps([{} if variant=='machine' else {'IOPlatformUUID':'private-native-machine'}])
                    if '/bin/df' in argv:
                        return b'' if variant=='mount' else b'Filesystem Used Available Capacity Mounted\n/private-device 1 2 3 /private\n'
                    if '/usr/sbin/diskutil' in argv:
                        if variant=='diskutil':raise subprocess.CalledProcessError(1,argv)
                        return plistlib.dumps(dict(FilesystemType=variant if variant in ('exfat','hfs','smbfs','nfs') else 'apfs',
                            **({} if variant=='volume' else {'VolumeUUID':'private-native-volume'}),Internal=True))
                    if '/usr/sbin/sysctl' in argv:return b'0\n'
                    raise AssertionError(argv)
                with patch.object(origin.subprocess,'check_output',side_effect=output), \
                        self.assertLogs('origin',level='WARNING') as diagnostics:
                    scope=origin.native_scope(Path(os.environ['R3A_CASE_ROOT']),123)
                self.assertEqual(scope['boot_retirement_capability'],'UnsupportedBootScope')
                self.assertTrue(scope['unsupported_reason'])
                self.assertIn(scope['unsupported_reason'],diagnostics.output[0])
                with self.assertRaisesRegex(RuntimeError,'UnsupportedBootScope'):
                    origin.boot_change(scope,scope)

    def child(self,case,mode,overrides=None):
        environment=dict(os.environ)
        if mode=='--legacy-produce':
            environment['R4_PRODUCT_SOURCE']=os.environ['R4_BASELINE_SOURCE']
            mode='--produce'
        argv=['timeout','12s',sys.executable,'-B',__file__,mode,str(case.resolve()),json.dumps(overrides or {})]
        before=subprocess.check_output(['uptime'],text=True).strip()
        result=subprocess.run(argv,capture_output=True,text=True,check=False,env=environment)
        with (case/'runs.jsonl').open('a') as output:
            output.write(json.dumps({'argv':argv,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
                'uptime_before':before,'uptime_after':subprocess.check_output(['uptime'],text=True).strip()})+'\n')
        return result

    def test_interrupted_v1_import_resumes_same_id_after_device_epoch(self):
        case=Path(tempfile.mkdtemp(prefix='legacy-volume-',dir=os.environ['R3A_CASE_ROOT']))
        for mode,expected in (('--legacy-produce',0),('--partial-import',97),('--resume-import',0)):
            result=self.child(case,mode)
            self.assertEqual(result.returncode,expected,result.stderr)

    def scene(self):
        case=Path(tempfile.mkdtemp(prefix='volume-epoch-',dir=os.environ['R3A_CASE_ROOT']))
        result=self.child(case,'--produce')
        self.assertEqual(result.returncode,0,result.stderr)
        return case,json.loads((case/'reference.json').read_text())

    def test_qualified_device_epoch_keeps_identity_lock_and_resumes_exact_bytes(self):
        case,_=self.scene()
        result=self.child(case,'--consume')
        self.assertEqual(result.returncode,0,result.stderr)

    def test_unqualified_device_mapping_never_writes_or_thaws_old_obligation(self):
        for overrides in ({'sameboot':True},{'machine_sha256':'0'*64},{'volume_sha256':'0'*64},
                {'virtualized':True},{'local_internal':False},{'host_domain':'namespace-only'},
                {'file_id':0},{'device':0},{'boot_retirement_capability':'UnsupportedBootScope'}):
            with self.subTest(overrides=overrides):
                case,reference=self.scene()
                directory=Path(reference['directory'])
                before={str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()}
                result=self.child(case,'--consume',overrides)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('UnsupportedBootScope',result.stderr)
                self.assertEqual({str(p):p.read_bytes() for p in directory.rglob('*') if p.is_file()},before)
                self.assertEqual(Path(reference['target']).read_bytes(),b'failed complete file')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--quiescent-produce':quiescent_scene(Path(sys.argv[2]),json.loads(sys.argv[3])['variant'])
    elif len(sys.argv)>1 and sys.argv[1]=='--quiescent-consume':reopen_quiescent(Path(sys.argv[2]),json.loads(sys.argv[3]))
    elif len(sys.argv)>1 and sys.argv[1]=='--produce':produce(Path(sys.argv[2]))
    elif len(sys.argv)>1 and sys.argv[1]=='--produce-managed':produce(Path(sys.argv[2]),True)
    elif len(sys.argv)>1 and sys.argv[1]=='--consume':consume(Path(sys.argv[2]),json.loads(sys.argv[3]))
    elif len(sys.argv)>1 and sys.argv[1] in ('--partial-import','--resume-import'):
        case=Path(sys.argv[2])
        inputs(old=sys.argv[1]=='--partial-import')
        from target_coordination import Target
        from recovery_legacy import import_v1
        import recovery_files
        reference=json.loads((case/'reference.json').read_text())
        def fault(action,stage,_detail):
            if sys.argv[1]=='--partial-import' and action=='copy' and stage=='chunk':os._exit(97)
        recovery_files.boundary=fault
        with Target(reference['target']) as target,target.locked():
            result=import_v1(target,reference['snapshot'])
            assert result['job_id']==reference['recovery_id'] and result['phase']=='failed-owner-held',result
            from recovery_transaction import Transaction
            with Transaction(target,reference['recovery_id']) as transaction:
                assert transaction.data['imported_v1']['state']=='Complete'
                transaction.resume_executor()
                try:transaction.restore()
                except RuntimeError as error:assert 'original resource identity' in str(error),str(error)
                else:raise AssertionError('legacy import cannot manufacture resource proof')
    else:unittest.main(verbosity=2)
