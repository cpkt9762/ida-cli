"""Directional target OFD transfer; durable acceptance, never ACK, grants I/O."""
import array
import json
import os
import socket
import uuid

from custody_process_identity import capture
from target_coordination import TransferredTargetGuard, encoded, identity

MAX_MESSAGE = 64*1024


def boundary(_stage, _binding):
    """Deterministic process-exit injection; production does nothing."""


def receive(channel, count):
    values = []
    try:
        data, ancillary, flags, _ = channel.recvmsg(MAX_MESSAGE, socket.CMSG_SPACE(8*array.array('i').itemsize))
        for level, kind, raw in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise RuntimeError('HandoffBlocked: unexpected ancillary message')
            fds = array.array('i')
            fds.frombytes(raw[:len(raw)-(len(raw)%fds.itemsize)])
            values.extend(fds)
        for fd in values:
            os.set_inheritable(fd, False)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(values) != count:
            raise RuntimeError('HandoffBlocked: truncated/unexpected descriptor table')
        result = json.loads(data)
        return result, values
    except BaseException:
        for fd in values:
            os.close(fd)
        raise


class FrozenOffer:
    """A prepared but unsent offer may abort; send entry permanently freezes it."""
    def __init__(self, transaction, receiver):
        transaction.authorize()
        native = receiver.get('native', {})
        if (type(native.get('pid')) is not int or native['pid'] <= 0
                or native != capture(native['pid']) or not receiver.get('incarnation')):
            raise RuntimeError('HandoffBlocked: receiver native birth mismatch')
        self.transaction = transaction
        self.started = False
        self.guard = None
        self.binding = {'schema':1,'transfer_id':uuid.uuid4().hex,
            'recovery_id':transaction.recovery_id,'epoch':transaction.token.epoch,
            'sender':transaction.token.actor,'receiver':receiver,
            'coord_key':transaction.target.key,'directory':transaction.target.directory.identity,
            'root_binding':transaction.data['root_binding'],
            'lock_identity':identity(os.fstat(transaction.target.target_fd))}
        transaction.data['executor']['state'] = 'FrozenOffer'
        transaction.data['executor']['transfer_id'] = self.binding
        transaction.save()
        transaction.token.valid = False
        boundary('prepared', self.binding)

    def abort_unsent(self):
        if self.started:
            raise RuntimeError('HandoffUncertain: sendmsg may have delivered; sender stays frozen')
        transaction = self.transaction
        current, info, raw = transaction.directory.read('recovery.json')
        if (current['executor']['state'] != 'FrozenOffer'
                or current['executor']['transfer_id'] != self.binding
                or raw != transaction.raw):
            raise RuntimeError('HandoffBlocked: offer changed before definitely-not-sent abort')
        current['executor']['state'] = 'LocalExecuting'
        current['executor']['transfer_id'] = None
        current['revision'] += 1
        transaction.directory.durable('recovery.json', current)
        transaction.data, transaction.info, transaction.raw = transaction.directory.read('recovery.json')
        transaction.token.valid = True

    def send(self, channel):
        if self.started:
            raise RuntimeError('HandoffUncertain: offer was already submitted')
        self.guard = self.transaction.target.move_guard()
        self.started = True  # BEFORE sendmsg: even syscall errors cannot thaw authority.
        try:
            boundary('before_send', self.binding)
            rights = array.array('i', [self.guard.fd, self.transaction.target.directory.fd])
            payload = encoded(self.binding)
            sent = channel.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            if sent != len(payload):
                raise RuntimeError('HandoffUncertain: partial transfer message')
            boundary('sent', self.binding)
        finally:
            self.guard.close()


def accept(transaction, binding, receiver):
    """Called with the received target OFD and an independently opened root SH."""
    expected = transaction.data['executor']
    if (not transaction.target.transferred or expected['state'] != 'FrozenOffer'
            or encoded(expected['transfer_id']) != encoded(binding)
            or set(binding) != {'schema','transfer_id','recovery_id','epoch','sender','receiver',
                                'coord_key','directory','root_binding','lock_identity'}
            or type(binding['schema']) is not int or binding['schema'] != 1
            or binding['receiver'] != receiver or receiver['native'] != capture(os.getpid())
            or binding['recovery_id'] != transaction.recovery_id
            or binding['epoch'] != expected['epoch'] or binding['sender'] != expected['actor']
            or encoded(binding['coord_key']) != encoded(transaction.target.key)
            or binding['directory'] != transaction.target.directory.identity
            or binding['root_binding'] != transaction.target.recovery_root_binding()
            or binding['lock_identity'] != identity(os.fstat(transaction.target.target_fd))):
        raise RuntimeError('HandoffBlocked: stale/foreign directional transfer binding')
    from recovery_transaction import ExecutorToken
    token = ExecutorToken(receiver, expected['epoch'])
    transaction.data['executor'] = dict(expected,state='Accepted',actor=receiver)
    transaction.data['revision'] += 1
    transaction.validate()
    transaction.directory.durable('recovery.json',transaction.data)
    transaction.data, transaction.info, transaction.raw = transaction.directory.read('recovery.json')
    transaction.token = token
    boundary('accepted',binding)
    return token


def receive_guard(channel, target):
    binding, fds = receive(channel,2)
    lock_fd, directory_fd = fds
    try:
        if identity(os.fstat(directory_fd)) != target.directory.identity:
            raise RuntimeError('HandoffBlocked: received directory differs from independent path')
        if identity(os.fstat(lock_fd)) != identity(os.stat('lock',dir_fd=directory_fd,follow_symlinks=False)):
            raise RuntimeError('HandoffBlocked: received target lock replaced')
        guard = TransferredTargetGuard(lock_fd)
        lock_fd = None
        return binding, guard
    finally:
        os.close(directory_fd)
        if lock_fd is not None:
            os.close(lock_fd)
