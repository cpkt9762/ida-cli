"""Independent executor for an already accepted target-side file obligation."""
from pathlib import Path
import os
import logging
import socket
import stat
import subprocess
import sys
import threading
import uuid

from recovery_transaction import ExecutorToken, Transaction
from recovery_transfer import FrozenOffer, accept, receive, receive_guard
from target_coordination import Target, encoded


def validate_ready(hello, transaction, pid=None):
    expected={'actor','recovery_id','target','coord_key','directory','root_binding'}
    if (set(hello) != expected or (pid is not None and hello['actor']['native']['pid'] != pid)
            or hello['recovery_id'] != transaction.recovery_id or hello['target'] != transaction.data['target']
            or encoded(hello['coord_key']) != encoded(transaction.target.key)
            or encoded(hello['directory']) != encoded(transaction.target.directory.identity)
            or encoded(hello['root_binding']) != encoded(transaction.target.recovery_root_binding())):
        raise RuntimeError('HandoffBlocked: receiver readiness physical identity mismatch')


def rust_start(transaction, prepare, timeout):
    installation=Path(__file__).parent
    nonce=uuid.uuid4().hex
    path=installation.parent/('j'+nonce[:12]+'s')
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
    owned=None
    primary=None
    try:
        channel.settimeout(timeout)
        channel.bind(str(path))
        info=path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeError('HandoffBlocked: source reply socket identity unavailable')
        owned=(info.st_dev,info.st_ino)
        os.chmod(path,0o600,follow_symlinks=False)
        transaction.data['job']={'state':'SpawnIntent','job_nonce':nonce,'reply_endpoint':str(path),
            'reply_identity':list(owned),'python':sys.executable,'installation':str(installation),'actor':None}
        transaction.save()
        prepared=prepare(transaction,path,owned,nonce)
        hello=prepared['hello']
        validate_ready(hello,transaction)
        transaction.data['job'].update(state='Prepared',actor=hello['actor'],stderr=prepared['stderr'])
        transaction.save()
        endpoint=Path(prepared['endpoint'])
        entry=endpoint.lstat()
        if (not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != os.getuid()
                or [entry.st_dev,entry.st_ino] != prepared['endpoint_identity']
                or endpoint.parent != path.parent):
            raise RuntimeError('HandoffBlocked: Rust relay endpoint changed')
        channel.connect(str(endpoint))
        if [endpoint.lstat().st_dev,endpoint.lstat().st_ino] != prepared['endpoint_identity']:
            raise RuntimeError('HandoffBlocked: Rust relay replaced during connect')
        offer=FrozenOffer(transaction,hello['actor'])
        offer.send(channel)
        result,_=receive(channel,0)
        if result.get('job_nonce')==nonce and result.get('error'):
            raise RuntimeError(result['error'])
        if result.get('transfer_id') != offer.binding['transfer_id']:
            raise RuntimeError('HandoffBlocked: relay completion transfer identity mismatch')
        if result.get('error'):raise RuntimeError(result['error'])
        return result
    except BaseException as error:
        primary=error
        raise
    finally:
        channel.close()
        if owned is not None:
            try:
                current=path.lstat()
                if not stat.S_ISSOCK(current.st_mode) or (current.st_dev,current.st_ino) != owned:
                    raise RuntimeError('HandoffBlocked: source reply endpoint replaced; unlink refused')
                path.unlink()
            except Exception as cleanup:
                if primary is not None:
                    raise RuntimeError(str(primary)+'; independent endpoint_cleanup_error: '+str(cleanup)) from primary
                raise


def start(transaction, *, timeout=8):
    """Transfer a unique guard; timeout never cancels the accepted file job."""
    installation = Path(__file__).parent
    if not getattr(sys,'_ida_cli_verified_sources',None):
        raise RuntimeError('RecoveryBlocked: independent job requires verified installed sources')
    transaction.authorize()
    prepare=getattr(transaction.target,'file_job_prepare',None)
    if prepare is not None:
        return rust_start(transaction,prepare,timeout)
    transaction.data['job'] = {'state':'SpawnIntent','python':sys.executable,
                               'installation':str(installation),'actor':None}
    transaction.save()
    sender, receiver = socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    sender.settimeout(timeout)
    process = None
    try:
        argv = [sys.executable,'-I','-B',str(installation/'bootstrap.py'),'recovery_job',
                str(receiver.fileno()),transaction.data['target'],transaction.recovery_id]
        process = subprocess.Popen(argv,pass_fds=(receiver.fileno(),),start_new_session=True,
                                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        receiver.close()
        # A reaper owns waitpid even after caller timeout. It holds no file/lease
        # authority and cannot cancel, signal or replay this job.
        threading.Thread(target=process.wait,daemon=True).start()
        hello, _ = receive(sender,0)
        validate_ready(hello,transaction,process.pid)
        offer = FrozenOffer(transaction,hello['actor'])
        offer.send(sender)
        result, _ = receive(sender,0)
        if result.get('accepted') is True and result.get('transfer_id')==offer.binding['transfer_id']:
            result,_=receive(sender,0)
        if result.get('transfer_id') != offer.binding['transfer_id']:
            raise RuntimeError('HandoffBlocked: completion transfer identity mismatch')
        if result.get('error'):
            raise RuntimeError(result['error'])
        return result
    finally:
        receiver.close()
        sender.close()


def execute(channel, path, recovery_id):
    actor = ExecutorToken().actor
    with Target(path,create=False) as target:
        # Target opened its own root SH before any received target rights.
        channel.send(encoded({'actor':actor,'recovery_id':recovery_id,'target':target.original,
            'coord_key':target.key,'directory':target.directory.identity,'root_binding':target.recovery_root_binding()}))
        binding, guard = receive_guard(channel,target)
        with target.locked(_received=guard), Transaction(target,recovery_id) as transaction:
            accept(transaction,binding,actor)
            job=dict(transaction.data.get('job') or {})
            job.update(state='Accepted',python=sys.executable,installation=str(Path(__file__).parent),actor=actor)
            transaction.data['job']=job
            transaction.save()
            try:
                channel.send(encoded({'accepted':True,'transfer_id':binding['transfer_id']}))
            except OSError as error:
                transaction.data['job']['acknowledgement_error']=type(error).__name__+': '+str(error)
                transaction.save()  # A lost ACK never cancels this already Accepted job.
            try:
                transaction.restore()
                transaction.data['job']['state'] = 'Completed'
                transaction.save()
                result = {'transfer_id':binding['transfer_id'],'status':transaction.status(),'error':None}
            except Exception as error:
                cause = type(error).__name__+': '+str(error)
                transaction.data['last_error'] = cause
                transaction.data['job']['state'] = 'Blocked'
                transaction.save()
                result = {'transfer_id':binding['transfer_id'],'status':transaction.status(),'error':cause}
        # Target EX is closed BEFORE reporting file completion. A resumed gate
        # must still establish its own NB OFD fence; completion is not a guard.
        try:
            channel.send(encoded(result))
        except (BrokenPipeError,ConnectionRefusedError) as error:
            logging.getLogger(__name__).error('file-job completion delivery failed; recovery_id=%s transfer_id=%s: %s',
                recovery_id,binding['transfer_id'],error)
        return 1 if result['error'] else 0


def main():
    from protocol import verify_client
    verify_client()
    if len(sys.argv) != 4:
        raise RuntimeError('RecoveryBlocked: expected inherited channel, target and RecoveryId')
    with socket.socket(fileno=int(sys.argv[1])) as channel:
        channel.settimeout(8)
        return execute(channel,sys.argv[2],sys.argv[3])
