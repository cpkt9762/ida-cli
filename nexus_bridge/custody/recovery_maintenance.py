"""Explicit offline operator permission; never a public owner release proof."""
import argparse
import copy
import json
import os
from pathlib import Path
import sys
import time
import subprocess
from types import SimpleNamespace

from origin import creation_scope
from process_timeout import run
from recovery_files import file_info, inventory, visible_names
from recovery_transaction import Transaction, recovery_name
from target_coordination import Directory, Target, MAX_RECORD, digest, encoded


def boundary(_stage,_detail):
    """Deterministic exit input; accepted offline permission stays durable."""


def tree(directory, depth=0):
    if depth > 8:
        raise RuntimeError('MaintenanceBlocked: evidence depth exceeds bound')
    result={}
    for name in sorted(os.listdir(directory.fd)):
        info=os.stat(name,dir_fd=directory.fd,follow_symlinks=False)
        if __import__('stat').S_ISDIR(info.st_mode):
            child=directory.child(name,create=False)
            try:result[name]={'directory':child.identity,'children':tree(child,depth+1)}
            finally:child.close()
        else:
            result[name]=file_info(directory,name)
    return result


def content(value):
    if 'children' in value:
        return {'children':{k:content(v) for k,v in value['children'].items()}}
    return {k:value[k] for k in ('size','sha256','mode')}


def scratch_inventory(target):
    """Read all owner/checkpoint references before proposing scratch removal."""
    from recovery_files import preparation_name
    candidates, references, objects = [], set(), set()
    scanned=[0]
    def reference_record(directory,name):
        # Archived v1 checkpoints are immutable evidence (often 0400), not
        # live 0600 authority. Read their exact bytes without changing modes;
        # malformed or changing evidence still blocks reference discovery.
        expected=file_info(directory,name)
        if expected['size']>MAX_RECORD:
            raise RuntimeError('MaintenanceBlocked: oversized scratch reference record')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory.fd)
        try:
            data=os.read(fd,MAX_RECORD+1)
            actual=os.fstat(fd)
            if (directory.object_identity(actual)[:2]!=[expected['device'],expected['inode']]
                    or len(data)!=expected['size'] or digest(data)!=expected['sha256']
                    or file_info(directory,name)!=expected):
                raise RuntimeError('MaintenanceBlocked: scratch reference record changed')
            return json.loads(data)
        finally:os.close(fd)
    def referenced(value):
        if type(value) is dict:
            # A valid accepted permission contains a deletion inventory, not
            # an owner binding. Other records and malformed grants stay visible.
            if (set(value)=={'schema','plan_sha256','plan','applied_at'}
                    and type(value['schema']) is int and value['schema']==1
                    and type(value['plan']) is dict and value['plan'].get('kind')=='manual_offline_recovery'
                    and digest(value['plan'])==value['plan_sha256']):
                return
            if type(value.get('device')) is int and type(value.get('inode')) is int:
                objects.add((value['device'],value['inode']))
            for key,item in value.items():
                if key in ('identity','inode') and type(item) is list and len(item) in (2,3) and all(type(n) is int for n in item):
                    objects.add(tuple(item[:2]))
                referenced(item)
        elif type(value) is list:
            for item in value:referenced(item)
        elif type(value) is str and preparation_name(Path(value).name):
            references.add(Path(value).name)
    def scan(directory, depth=0):
        with directory.fact_view(shared=True):
            scan_locked(directory,depth)
    def scan_locked(directory,depth):
        if depth>8 or len(candidates)>4096:
            raise RuntimeError('MaintenanceBlocked: scratch inventory exceeds bound')
        for name in sorted(os.listdir(directory.fd)):
            scanned[0]+=1
            if scanned[0]>4096:
                raise RuntimeError('MaintenanceBlocked: scratch namespace exceeds bound')
            info=os.stat(name,dir_fd=directory.fd,follow_symlinks=False)
            if __import__('stat').S_ISDIR(info.st_mode):
                child=directory.child(name,create=False)
                try:scan(child,depth+1)
                finally:child.close()
            elif preparation_name(name):
                candidates.append(dict(path=str(directory.path/name),directory=directory.identity,
                    **file_info(directory,name)))
            elif name.endswith(('.json','.new','.new.owner')):
                try:value=reference_record(directory,name)
                except (ValueError,UnicodeError) as error:
                    raise RuntimeError('MaintenanceBlocked: cannot establish scratch references: '+str(directory.path/name)) from error
                referenced(value)
    scan(target.directory)
    return [item for item in candidates if Path(item['path']).name not in references
            and (item['device'],item['inode']) not in objects]


def remove_scratch(target, approved):
    """Called only under target EX, after the exact reviewed plan is accepted."""
    if target.target_fd is None:
        raise RuntimeError('MaintenanceBlocked: scratch deletion requires target EX')
    current={item['path']:item for item in scratch_inventory(target)}
    if any(current.get(item['path']) != item for item in approved):
        raise RuntimeError('MaintenanceBlocked: scratch identity or references changed')
    for item in approved:
        path=Path(item['path'])
        directory=Directory(path.parent)
        try:
            directory.inherit_volume(target.directory)
            actual=dict(path=str(path),directory=directory.identity,**file_info(directory,path.name))
            if actual != item:
                raise RuntimeError('MaintenanceBlocked: scratch changed before unlink')
            directory.verify()
            os.unlink(path.name,dir_fd=directory.fd)
            os.fsync(directory.fd)
        finally:directory.close()


def validate_evidence(evidence, target, transaction, components, retained):
    required={'schema','operator','host','window','target','coord_key','directory','root_binding',
              'transaction','components','retained','stopped_openers','state_roots','offline_scope','backup','approved_plan_sha256'}
    if (type(evidence) is not dict or set(evidence) not in (required,required|{'cleanup_unpublished'})
            or type(evidence.get('cleanup_unpublished',False)) is not bool
            or type(evidence['schema']) is not int or evidence['schema'] != 1
            or type(evidence['operator']) is not dict
            or set(evidence['operator']) != {'uid','name','confirmation'}
            or type(evidence['operator']['uid']) is not int or evidence['operator']['uid'] != os.getuid()
            or type(evidence['operator']['name']) is not str or not evidence['operator']['name']
            or evidence['operator']['confirmation'] != 'I established and maintain this exclusive offline window'
            or evidence['target'] != target.original or encoded(evidence['coord_key']) != encoded(target.key)
            or encoded(evidence['directory']) != encoded(target.directory.identity)
            or encoded(evidence['root_binding']) != encoded(target.recovery_root_binding())
            or evidence['transaction'] != transaction.recovery_id
            or encoded(evidence['components']) != encoded(components)
            or encoded(evidence['retained']) != encoded(retained)):
        raise RuntimeError('MaintenanceBlocked: offline evidence schema/target/bytes/operator mismatch')
    window=evidence['window']
    now=time.time()
    if (type(window) is not dict or set(window) != {'id','started_at','expires_at'}
            or type(window['id']) is not str or not window['id']
            or any(type(window[k]) not in (int,float) for k in ('started_at','expires_at'))
            or not window['started_at'] <= now < window['expires_at']
            or window['expires_at']-window['started_at'] > 3600):
        raise RuntimeError('MaintenanceBlocked: offline window expired/invalid')
    current=creation_scope(target.directory.path,'offline-window-verification')
    if any(encoded(evidence['host'].get(k)) != encoded(current.get(k)) for k in
           ('machine_sha256','volume_sha256','host_domain','file_id','uid','boot_retirement_capability')):
        raise RuntimeError('MaintenanceBlocked: offline host/volume/object scope changed')
    if evidence['host'].get('creator',{}).get('boot_id') != current['creator']['boot_id']:
        raise RuntimeError('MaintenanceBlocked: offline window belongs to another host boot')
    scope=evidence['offline_scope']
    if encoded(scope) != encoded({'all_target_openers_stopped':True,'new_openers_prevented':True,
                 'cross_uid_openers_excluded':True,'remote_writers_excluded':True,
                 'automatic_restarts_prevented':True}):
        raise RuntimeError('MaintenanceBlocked: incomplete exclusive offline operator scope')
    from target_journal import Journal
    journal=Journal(target,recover=False)
    expected=[{k:copy.deepcopy(item.get(k)) for k in ('watch','epoch','acquisition','owner','lease','launch')}
              for item in journal.value['entries'].values()]
    if encoded(evidence['stopped_openers']) != encoded(expected):
        raise RuntimeError('MaintenanceBlocked: exact startup/owner opener inventory changed')
    roots=evidence['state_roots']
    if type(roots) is not list or not 1 <= len(roots) <= 96 or len({encoded(r) for r in roots}) != len(roots):
        raise RuntimeError('MaintenanceBlocked: bounded complete state-root inventory required')
    known=[item['owner']['state_root'] for item in expected if item.get('owner')]
    if any(root not in roots for root in known):
        raise RuntimeError('MaintenanceBlocked: owner state root omitted from offline inventory')
    from recovery_probe import bind_state
    for root in roots:bind_state(root,target)
    bind_state(roots[0],target)
    backup=evidence['backup']
    if type(backup) is not dict or set(backup) != {'path','directory'}:
        raise RuntimeError('MaintenanceBlocked: exact private evidence copy required')
    directory=Directory(backup['path'])
    try:
        if directory.identity != backup['directory']:
            raise RuntimeError('MaintenanceBlocked: evidence copy directory changed')
        if set(os.listdir(directory.fd)) != {'transaction','components'}:
            raise RuntimeError('MaintenanceBlocked: incomplete evidence copy namespace')
        for name,original in (('transaction',retained),('components',components)):
            child=directory.child(name,create=False)
            try:
                saved=tree(child)
                if {k:content(v) for k,v in saved.items()} != {k:content(v) for k,v in original.items()}:
                    raise RuntimeError('MaintenanceBlocked: evidence copy differs from current '+name)
            finally:child.close()
    finally:directory.close()


def preview(target, transaction, evidence):
    parent=transaction.parent_directory()
    names=set(transaction.data['files'])
    current=inventory(parent,target.directory)
    components={name:value for name,value in current.items() if name in __import__('recovery_files').component_names(target.target)}
    retained=tree(transaction.directory)
    validate_evidence(evidence,target,transaction,components,retained)
    transaction.owner_probe=lambda path:occupancy(evidence['state_roots'],path)
    transaction.check_occupancy()
    if transaction.data['failure_intent']:
        if not transaction.data['attempts']:
            raise RuntimeError('MaintenanceBlocked: failure has no durable attempted scene')
        snapshot=transaction.directory.child('snapshot',create=False)
        try:
            if visible_names(snapshot) != names:
                raise RuntimeError('MaintenanceBlocked: snapshot component set incomplete')
            from recovery_files import compatible
            for name,expected in transaction.data['snapshot_files'].items():
                if not compatible(file_info(snapshot,name),expected):
                    raise RuntimeError('MaintenanceBlocked: immutable snapshot changed')
        finally:snapshot.close()
    return make_plan(target,transaction.recovery_id,evidence,components,retained,digest(transaction.raw),
        'restore_complete_snapshot' if transaction.data['failure_intent'] else 'archive_without_rollback')


def make_plan(target,recovery_id,evidence,components,retained,record_hash,action):
    plan={'schema':1,'kind':'manual_offline_recovery','target':target.original,'coord_key':target.key,
        'directory':target.directory.identity,'transaction':recovery_id,
        'root_binding':target.recovery_root_binding(),
        'record_sha256':record_hash,'components':components,'retained':retained,
        'operator':evidence['operator'],'window':evidence['window'],'host':evidence['host'],
        'stopped_openers':evidence['stopped_openers'],'offline_scope':evidence['offline_scope'],
        'state_roots':evidence['state_roots'],
        'backup':evidence['backup'],
        'unpublished_scratch':scratch_inventory(target),
        'cleanup_unpublished':evidence.get('cleanup_unpublished',False),
        'action':action}
    return plan,digest(plan)


def snapshotless_preview(target,recovery_id,evidence):
    from target_journal import Journal
    from recovery_transaction import inspect_transactions
    if Journal(target,recover=False).value.get('file_intents') or any(
            item['phase'] not in ('restored','opened','archived') for item in inspect_transactions(target,recover=False)):
        raise RuntimeError('MaintenanceBlocked: unresolved file transaction requires its exact RecoveryId')
    parent=Directory(target.target.parent,private=False)
    parent.inherit_volume(target.directory)
    try:
        current=inventory(parent,target.directory)
        components={k:v for k,v in current.items() if k in __import__('recovery_files').component_names(target.target)}
    finally:parent.close()
    validate_evidence(evidence,target,SimpleNamespace(recovery_id=recovery_id),components,{})
    if occupancy(evidence['state_roots'],target.target):
        raise RuntimeError('MaintenanceBlocked: current target remains occupied')
    return make_plan(target,recovery_id,evidence,components,{},None,'archive_without_snapshot')


def apply(target,transaction,plan,plan_hash):
    # The fresh locked preview and approved hash bind the entire pending tree.
    # Only now may that exact prospective record become the committed record.
    expected=transaction.raw
    def validate(raw):
        if raw != expected:
            raise RuntimeError('MaintenanceBlocked: approved pending record changed')
    transaction.directory.recover_record('recovery.json',validate=validate)
    transaction.data,transaction.info,transaction.raw=transaction.directory.read('recovery.json')
    if transaction.raw != expected:
        raise RuntimeError('MaintenanceBlocked: approved transaction changed')
    transaction.validate()
    transaction.resume_executor()
    permission=transaction.data.get('manual_offline_recovery')
    if permission is None or permission['plan_sha256'] != plan_hash:
        permission={'schema':1,'plan_sha256':plan_hash,'plan':plan,'applied_at':time.time()}
    transaction.data['manual_offline_recovery']=permission
    transaction.save()
    boundary('accepted',permission)
    if transaction.data['failure_intent']:
        transaction.restore(manual=True)
    else:transaction.archive('authorized offline no-failure archive')
    from target_journal import Journal
    Journal(target).complete_manual(permission)
    if plan.get('cleanup_unpublished',False):
        remove_scratch(target,plan['unpublished_scratch'])
    return transaction.status()


def accepted_preview(target,transaction,evidence):
    """An accepted plan resumes only inside its original operator window.

    The backup and approved original inputs stay immutable. Current bytes may
    differ only as allowed by the transaction's exact staged rename intents.
    """
    permission=transaction.data.get('manual_offline_recovery')
    if permission is None or evidence.get('approved_plan_sha256') != permission['plan_sha256']:
        return preview(target,transaction,evidence)
    transaction.validate_manual_permission(permission)
    plan=permission['plan']
    if any(encoded(evidence.get(key)) != encoded(plan.get(key))
           for key in ('operator','window','host','components','retained','backup','stopped_openers','state_roots','offline_scope')):
        raise RuntimeError('MaintenanceBlocked: original accepted offline evidence changed')
    validate_evidence(evidence,target,transaction,plan['components'],plan['retained'])
    transaction.owner_probe=lambda path:occupancy(evidence['state_roots'],path)
    transaction.check_occupancy()
    if not transaction.data['failure_intent']:
        current=inventory(transaction.parent_directory(),target.directory)
        components={k:v for k,v in current.items() if k in __import__('recovery_files').component_names(target.target)}
        if encoded(components) != encoded(plan['components']):
            raise RuntimeError('MaintenanceBlocked: no-failure scene changed after offline acceptance')
    return plan,permission['plan_sha256']


def occupancy(roots, path):
    installation=Path(__file__).parent
    for state in roots:
        try:
            result=run([sys.executable,'-I','-B',str(installation/'bootstrap.py'),
                'recovery_probe',json.dumps(state),str(path)],text=True,check=False,
                timeout=3)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError('MaintenanceBlocked: independent exact-state occupancy timed out') from error
        if result.returncode != 0:
            raise RuntimeError('MaintenanceBlocked: independent exact-state occupancy failed: '+result.stderr)
        reason=json.loads(result.stdout)['reason']
        if reason:return reason
    return None


def main():
    parser=argparse.ArgumentParser(description='Verified installed Nexus offline file maintenance')
    parser.add_argument('--maintenance',action='store_true',required=True)
    parser.add_argument('--offline-evidence',required=True)
    parser.add_argument('--target',required=True)
    parser.add_argument('--transaction',required=True)
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    if not recovery_name(args.transaction):
        raise RuntimeError('MaintenanceBlocked: exact RecoveryId required')
    evidence_path=Path(args.offline_evidence)
    directory=Directory(evidence_path.parent)
    try:evidence,_,_=directory.read(evidence_path.name)
    finally:directory.close()
    # Never initialize a missing marker, lock, journal, or pending write during
    # preview. Apply also begins with the SAME immutable preview under new locks.
    with Target(args.target,create=False) as target,target.locked(nb=True,recover=False):
        try:os.stat(args.transaction,dir_fd=target.directory.fd,follow_symlinks=False)
        except FileNotFoundError:
            plan,plan_hash=snapshotless_preview(target,args.transaction,evidence)
            result={'dry_run':args.dry_run,'plan':plan,'plan_sha256':plan_hash,
                    'bridge_dir':str(Path(__file__).parent),'prepared_python':sys.executable,
                    'evidence_type':'manual_offline_recovery','public_owner_proof':False}
            if not args.dry_run:
                if evidence['approved_plan_sha256'] != plan_hash:
                    raise RuntimeError('MaintenanceBlocked: reviewed plan hash changed or not approved')
                recovery_id,token=Transaction.allocate(target,recovery_id=args.transaction,source_files={})
                with Transaction(target,recovery_id,token=token) as transaction:
                    result['status']=apply(target,transaction,plan,plan_hash)
            print(json.dumps(result,sort_keys=True))
            return 0
        with Transaction(target,args.transaction,recover=False,pending_view=True) as transaction:
            plan,plan_hash=accepted_preview(target,transaction,evidence)
            result={'dry_run':args.dry_run,'plan':plan,'plan_sha256':plan_hash,
                    'bridge_dir':str(Path(__file__).parent),'prepared_python':sys.executable,
                    'evidence_type':'manual_offline_recovery','public_owner_proof':False}
            if not args.dry_run:
                if evidence['approved_plan_sha256'] != plan_hash:
                    raise RuntimeError('MaintenanceBlocked: reviewed plan hash changed or not approved')
                result['status']=apply(target,transaction,plan,plan_hash)
            print(json.dumps(result,sort_keys=True))
    return 0
