"""Ordinary lease detach; public owner observation remains independent."""
from collections import deque
import threading
import time

from lifecycle import release_handle, release_state


class FairReleases:
    """One preflight per owner, bounded by the caller's admission permit."""
    def __init__(self, pool):
        self.pool = pool
        self.lock = threading.Lock()
        self.pending = deque()
        self.active = set()

    def submit(self, owner, call):
        with self.lock:
            self.pending.append((owner, call))
            self._dispatch()

    def _dispatch(self):
        for _ in range(len(self.pending)):
            owner, call = self.pending.popleft()
            if owner in self.active or len(self.active) >= 2:
                self.pending.append((owner, call))
                continue
            self.active.add(owner)
            self.pool.submit(self._run, owner, call)

    def _run(self, owner, call):
        try:
            call()
        finally:
            with self.lock:
                self.active.remove(owner)
                self._dispatch()


def ordinary_release(bridge, channel, attempt, lease, handle, custody, deadline, cleanup_code):
    """The preflight and detach lanes never wait for owner saving or exit."""
    state = release_state(handle)
    if not state['requested']:
        preflight_deadline = deadline - 6  # detach, observation ACK, target ACK persistence <=2s each
        proof = None
        failure = None
        try:
            if not handle.connected:
                raise RuntimeError('CleanupBlocked: disconnected handle cannot provide fresh protection; exact owner observation retained')
            if preflight_deadline - time.monotonic() <= 5:
                raise TimeoutError('preflight NotSent: insufficient public HTTP allowance')
            custody.cleanup()
            checked = custody.execute('cleanup', cleanup_code, cleanup=True,
                                      deadline=preflight_deadline)
            proof = checked['result']
            if not isinstance(proof, dict) or type(proof.get('close_safe')) is not bool:
                raise RuntimeError('CleanupBlocked: invalid fresh protection result')
            if proof.get('save_guard_error') and proof['save_guard_error'] not in state['errors']:
                state['errors'].append(proof['save_guard_error'])
            if proof['close_safe'] is not True:
                raise RuntimeError('CleanupBlocked: fresh save protection unavailable; no detach')
        except Exception as exc:
            failure = exc
        observation = {'stage':'preflight', 'protection':proof,
            'save_guard_error':'; '.join(state['errors']) or None,
            'cause':None if failure is None else {'type':type(failure).__name__, 'message':str(failure)},
            'detach_called':False, 'owner_pending':True}
        # This must precede detach even for a healthy guard. ACK loss reuses the
        # exact transaction nonce; target authority and Rust retain the facts.
        custody.transact('release_observation', _deadline=deadline-2,
            acquisition=custody.acquisition, lease=lease, watch=custody.watch,
            owner=custody.owner, attempt=attempt, outcome=observation)
        if failure is not None:
            channel.send({'event':'not_sent', 'attempt':attempt, 'outcome':observation,
                'save_guard_error':observation['save_guard_error'],
                'error':{'code':'operation_failed', 'message':str(failure)}})
            return
        detach_deadline = min(deadline, time.monotonic()+2)
        if detach_deadline <= time.monotonic():
            raise TimeoutError('detach NotSent: original close budget exhausted')
        outcome = bridge.detach_pool.submit(release_handle, handle, detach_deadline,
            check=lambda:proof, request_only=True).result()
    else:
        # A possibly sent request is never reissued, even by a later caller.
        outcome = dict(state['outcome'], save_guard_error='; '.join(state['errors']) or None)
    if outcome.get('lease_released') is True:
        bridge.drop_lifetime(lease['lease_id'])
        with bridge.lock:
            bridge.handles.pop(lease['lease_id'], None)
            bridge.metadata_contexts.pop(lease['lease_id'], None)
        channel.send({'event':'released', 'attempt':attempt, 'outcome':outcome,
                      'save_guard_error':outcome.get('save_guard_error')})
    else:
        channel.send({'event':'uncertain', 'attempt':attempt, 'outcome':outcome,
            'save_guard_error':outcome.get('save_guard_error'),
            'error':{'code':'unknown_outcome', 'message':'detach may have been sent; exact owner retained; never replay'}})
    # A retrying open may query N1 only after the ordered command terminal.
    # Public proof remains independently consumable while this send is pending.
    custody.release_outcome = outcome
    custody.release_event.set()
