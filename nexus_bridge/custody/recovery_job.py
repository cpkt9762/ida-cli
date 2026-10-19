"""Independent executor for an already accepted target-side file obligation."""
from pathlib import Path
import socket
import subprocess
import sys
import threading

from recovery_transaction import ExecutorToken, Transaction
from recovery_transfer import FrozenOffer, accept, receive, receive_guard
from target_coordination import Target, encoded


def start(transaction, *, timeout=8):
    """Transfer a unique guard; timeout never cancels the accepted file job."""
    installation = Path(__file__).parent
    if not getattr(sys,'_ida_cli_verified_sources',None):
        raise RuntimeError('RecoveryBlocked: independent job requires verified installed sources')
    transaction.authorize()
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
        if set(hello) != {'actor'} or hello['actor']['native']['pid'] != process.pid:
            raise RuntimeError('HandoffBlocked: receiver readiness identity mismatch')
        offer = FrozenOffer(transaction,hello['actor'])
        offer.send(sender)
        result, _ = receive(sender,0)
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
    with Target(path) as target:
        # Target opened its own root SH before any received target rights.
        channel.send(encoded({'actor':actor}))
        binding, guard = receive_guard(channel,target)
        with target.locked(_received=guard), Transaction(target,recovery_id) as transaction:
            accept(transaction,binding,actor)
            transaction.data['job'] = {'state':'Accepted','python':sys.executable,
                'installation':str(Path(__file__).parent),'actor':actor}
            transaction.save()
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
            # Accepted is already durable; a disconnected sender affects only
            # delivery of this read-only completion, not execution permission.
            try:
                channel.send(encoded(result))
            except (BrokenPipeError,ConnectionRefusedError):
                pass
            return 1 if result['error'] else 0


def main():
    if len(sys.argv) != 4:
        raise RuntimeError('RecoveryBlocked: expected inherited channel, target and RecoveryId')
    with socket.socket(fileno=int(sys.argv[1])) as channel:
        channel.settimeout(8)
        return execute(channel,sys.argv[2],sys.argv[3])
