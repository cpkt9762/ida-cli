"""Production SCM_RIGHTS and file executor, controlled absent-owner input."""
import array
import copy
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge'),str(Path(__file__).parent)]
from test_recovery_transaction import isolate_owner_input, no_owner_input, setup
from recovery_transaction import ExecutorToken, Transaction
from recovery_transfer import FrozenOffer, accept, receive, receive_guard
from target_coordination import Target, encoded


def receiver(channel, reference, fault):
    no_owner_input()
    actor = ExecutorToken().actor
    with Target(reference['target']) as target:
        channel.send(encoded({'actor':actor}))
        binding, guard = receive_guard(channel,target)
        if fault=='received':os._exit(91)
        with target.locked(_received=guard), Transaction(target,reference['recovery_id']) as transaction:
            if fault=='wrong_epoch':binding['epoch'] += 1
            try:
                accept(transaction,binding,actor)
            except RuntimeError:
                if fault=='wrong_epoch':return
                raise
            if fault=='accepted':os._exit(92)
            if fault != 'ack_lost':channel.send(b'Accepted')
            if channel.recv(32) != b'continue':raise AssertionError('test continuation')
            if fault=='intent':
                transaction.data['intent'] = {'kind':'test-only-before-first-file-step'}
                transaction.save()
                os._exit(93)
            if fault=='duplicate':
                duplicate, fds = receive(channel,2)
                if duplicate != binding:raise AssertionError('duplicate differs')
                for fd in fds:os.close(fd)
            transaction.restore()
            channel.send(b'Done')
            if channel.recv(32) != b'close':raise AssertionError('test close')


def blocked(path, *, root=False):
    with Target(path) as target:
        fd = os.open(target.resource_root.path/target.resource_lock if root else target.directory.path/'lock',os.O_RDWR)
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:return True
            return False
        finally:os.close(fd)


class Transfer(unittest.TestCase):
    def setUp(self):
        isolate_owner_input(self)

    def test_same_process_move_survives_old_context_close_without_unlock(self):
        root=Path(tempfile.mkdtemp(prefix='local-move-',dir=os.environ['R3A_CASE_ROOT']))
        setup(root)
        reference=json.loads((root/'reference.json').read_text())
        with Target(reference['target']) as source,source.locked():
            with Transaction(source,reference['recovery_id']) as previous:
                previous.resume_executor()
                target,transaction=previous.move_executor()
                with self.assertRaisesRegex(RuntimeError,'Stale'):previous.authorize()
        try:
            self.assertTrue(blocked(reference['target']),'old future drop cannot unlock moved OFD')
            with self.assertRaisesRegex(RuntimeError,'shared OFD'):transaction.resume_executor()
            transaction.restore()
            self.assertEqual(transaction.data['status'],'restored')
        finally:
            transaction.close()
            target.close()
        self.assertFalse(blocked(reference['target']))

    def test_sender_exit_retains_inflight_rights_until_accept_or_discard(self):
        root=Path(tempfile.mkdtemp(prefix='inflight-',dir=os.environ['R3A_CASE_ROOT']))
        for disposition in ('accept','discard'):
            with self.subTest(disposition=disposition):
                case=root/disposition
                case.mkdir(mode=0o700)
                setup(case)
                reference=json.loads((case/'reference.json').read_text())
                actor=ExecutorToken().actor
                a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
                b.settimeout(5)
                with Target(reference['target']) as target:
                    process=subprocess.Popen(['timeout','10s',sys.executable,'-B',__file__,'--sender',
                        str(a.fileno()),str(case/'reference.json'),json.dumps(actor)],pass_fds=(a.fileno(),),
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
                    a.close()
                    stdout,stderr=process.communicate(timeout=12)
                    (case/'sender.json').write_text(json.dumps(dict(exit=process.returncode,stdout=stdout,stderr=stderr)))
                    self.assertEqual(process.returncode,94,stderr)
                    self.assertTrue(blocked(reference['target']),'kernel queued rights survive sender death')
                    if disposition=='accept':
                        binding,guard=receive_guard(b,target)
                        with target.locked(_received=guard),Transaction(target,reference['recovery_id']) as transaction:
                            accept(transaction,binding,actor)
                            transaction.restore()
                            self.assertEqual(transaction.data['status'],'restored')
                    b.close()
                self.assertFalse(blocked(reference['target']))
                with Target(reference['target']) as target,target.locked(nb=True):
                    with Transaction(target,reference['recovery_id']) as transaction:
                        transaction.resume_executor()
                        transaction.restore()
                        self.assertEqual(transaction.data['status'],'restored')

    def test_move_transfer_duplicates_crash_and_independent_fence(self):
        root=Path(tempfile.mkdtemp(prefix='transfer-',dir=os.environ['R3A_CASE_ROOT']))
        for fault in ('normal','ack_lost','received','accepted','intent','duplicate','wrong_epoch'):
            with self.subTest(fault=fault):
                case=root/fault
                case.mkdir(mode=0o700)
                setup(case)
                reference=json.loads((case/'reference.json').read_text())
                a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
                a.settimeout(5)
                process=subprocess.Popen(['timeout','12s',sys.executable,'-B',__file__,'--receiver',
                    str(b.fileno()),str(case/'reference.json'),fault],pass_fds=(b.fileno(),),start_new_session=True,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                b.close()
                try:
                    hello,_=receive(a,0)
                    self.assertNotEqual(hello['actor']['native']['pid'],os.getpid())
                    with Target(reference['target']) as target,target.locked():
                        with Transaction(target,reference['recovery_id']) as transaction:
                            transaction.resume_executor()
                            with self.assertRaises(TypeError):copy.copy(target.target_guard)
                            offer=FrozenOffer(transaction,hello['actor'])
                            old_token=transaction.token
                            old_epoch=old_token.epoch
                            with self.assertRaisesRegex(RuntimeError,'Stale'):transaction.save()
                            offer.abort_unsent()
                            self.assertEqual(transaction.token.epoch,old_epoch+1)
                            with self.assertRaisesRegex(RuntimeError,'Stale'):old_token.check()
                            transaction.authorize()
                            offer=FrozenOffer(transaction,hello['actor'])
                            duplicate_fd=os.dup(target.target_fd) if fault=='duplicate' else None
                            offer.send(a)
                            self.assertIsNone(target.target_fd)
                            with self.assertRaisesRegex(RuntimeError,'Uncertain'):offer.abort_unsent()
                            if fault not in ('received','wrong_epoch','accepted'):
                                if fault!='ack_lost':self.assertEqual(a.recv(32),b'Accepted')
                                # A lost ACK never authorizes a sender write.
                                with self.assertRaisesRegex(RuntimeError,'Stale'):transaction.save()
                                a.send(b'continue')
                                if fault=='duplicate':
                                    try:
                                        a.sendmsg([encoded(offer.binding)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                            array.array('i',[duplicate_fd,target.directory.fd]))])
                                    finally:os.close(duplicate_fd)
                                if fault!='intent':
                                    self.assertEqual(a.recv(32),b'Done')
                                    self.assertTrue(blocked(reference['target']))
                                    a.send(b'close')
                    stdout,stderr=process.communicate(timeout=15)
                    (case/'receiver.json').write_text(json.dumps(dict(exit=process.returncode,stdout=stdout,stderr=stderr)))
                    self.assertEqual(process.returncode,{'received':91,'accepted':92,'intent':93}.get(fault,0),stderr)
                    self.assertFalse(blocked(reference['target']),'all old OFD copies must close before fence')
                    with Target(reference['target']) as target,target.locked(nb=True):
                        with Transaction(target,reference['recovery_id']) as transaction:
                            old=transaction.data['executor']['epoch']
                            transaction.resume_executor()
                            self.assertEqual(transaction.token.epoch,old+1)
                            transaction.restore()
                            self.assertEqual(transaction.data['status'],'restored')
                    for name,value in reference['original'].items():
                        import hashlib
                        self.assertEqual(hashlib.sha256((case/'payload'/name).read_bytes()).hexdigest(),value)
                finally:
                    a.close()
                    if process.poll() is None:
                        # No signals: closing the private channel ends a waiting
                        # child through EOF/timeout; record its natural terminal.
                        process.communicate(timeout=15)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--receiver':
        with socket.socket(fileno=int(sys.argv[2])) as channel:
            channel.settimeout(5)
            receiver(channel,json.loads(Path(sys.argv[3]).read_text()),sys.argv[4])
    elif len(sys.argv)>1 and sys.argv[1]=='--sender':
        reference=json.loads(Path(sys.argv[3]).read_text())
        with socket.socket(fileno=int(sys.argv[2])) as channel:
            with Target(reference['target']) as target,target.locked():
                with Transaction(target,reference['recovery_id']) as transaction:
                    transaction.resume_executor()
                    FrozenOffer(transaction,json.loads(sys.argv[4])).send(channel)
                    os._exit(94)
    else:unittest.main(verbosity=2)
