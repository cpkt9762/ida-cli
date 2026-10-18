"""R5 path/admission tables and deterministic lifetime handoff barriers."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'nexus_bridge'))
from bridge import Bridge, readiness
from config import ida_cli_home, startup_paths
from protocol import contract, validate


class LifetimeRig:
    def __init__(self, root):
        self.owner = Bridge.__new__(Bridge)
        b = self.owner
        b.lock, b.stopped = threading.Lock(), threading.Event()
        b.handles = {key: ({'lease_id': key, 'instance_id': 'owner', 'generation': 1},
                          types.SimpleNamespace(connected=True)) for key in ('a', 'b')}
        b.executing, b.identity = {}, 'incarnation'
        b.proof_wakeup = threading.Event()
        b.lifetime_path = str(root / 'l')
        b.init_lifetimes(8)
        self.peers = []

    def pair(self, key, wrapper=lambda x: x):
        server, peer = socket.socketpair()
        self.peers.append(peer)
        peer.sendall(key.encode('ascii'))
        return wrapper(server), peer

    def handshake(self, key):
        server, peer = self.pair(key)
        self.owner.accept_lifetime(server)
        self.assert_ack(peer)
        return server, peer

    @staticmethod
    def assert_ack(peer):
        peer.settimeout(1)
        assert peer.recv(2) == b'ok'

    def close(self):
        self.owner.stopped.set()
        self.owner.lifetime_socket.close()
        for key in list(self.owner.lifetimes):
            self.owner.drop_lifetime(key)
        for peer in self.peers:
            peer.close()
        Path(self.owner.lifetime_path).unlink(missing_ok=True)


class SocketBarrier:
    def __init__(self, connection, *, after_send=lambda: None, failure=None):
        self.connection, self.after_send, self.failure = connection, after_send, failure

    def __getattr__(self, key):
        return getattr(self.connection, key)

    def sendall(self, value):
        if self.failure:
            raise self.failure
        self.connection.sendall(value)
        self.after_send()


class FoundationTests(unittest.TestCase):
    def test_listener_identity_is_not_reacquired_after_bind(self):
        cases = []
        for boundary in ('listen', 'settimeout'):
            for replacement in ('socket', 'file', 'symlink', 'missing'):
                with self.subTest(boundary=boundary, replacement=replacement), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    rig = LifetimeRig(root)
                    b = rig.owner
                    old_a, peer_a = rig.handshake('a')
                    old_b, peer_b = rig.handshake('b')
                    failed = b.lifetime_socket
                    failed.close()
                    original_socket = socket.socket
                    created = []
                    path = Path(b.lifetime_path)
                    displaced = root / 'displaced'
                    observations = {}

                    def replace():
                        observations['bound_inode'] = path.lstat().st_ino
                        path.rename(displaced)
                        if replacement == 'socket':
                            foreign = original_socket(socket.AF_UNIX)
                            created.append(foreign)
                            foreign.bind(str(path))
                            foreign.listen(8)
                        elif replacement == 'file':
                            path.write_text('foreign endpoint')
                        elif replacement == 'symlink':
                            path.symlink_to(displaced)
                        if replacement != 'missing':
                            observations['foreign_inode'] = path.lstat().st_ino

                    class BindBarrier:
                        def __init__(self):
                            self.socket = original_socket(socket.AF_UNIX)
                            created.append(self.socket)

                        def __getattr__(self, key):
                            return getattr(self.socket, key)

                        def listen(self, capacity):
                            self.socket.listen(capacity)
                            if boundary == 'listen':
                                replace()

                        def settimeout(self, value):
                            self.socket.settimeout(value)
                            if boundary == 'settimeout':
                                replace()

                    try:
                        with patch('lifetime.socket.socket', side_effect=lambda *_a, **_k: BindBarrier()):
                            recovered = b.recover_lifetime_listener(failed)
                        self.assertFalse(recovered, 'changed endpoint must never be published healthy')
                        self.assertFalse(b.lifetime_healthy)
                        if replacement != 'missing':
                            self.assertEqual(path.lstat().st_ino, observations['foreign_inode'])
                            self.assertNotEqual(b.lifetime_inode, observations['foreign_inode'])
                        self.assertFalse(b.recover_lifetime_listener(failed), 'unverified absence is not retry authority')
                        if replacement == 'socket':
                            with original_socket(socket.AF_UNIX) as peer:
                                peer.connect(str(path))
                                accepted, _ = created[-1].accept()
                                accepted.close()
                        self.assertIs(b.lifetimes['a'], old_a)
                        self.assertIs(b.lifetimes['b'], old_b)
                        old_a.sendall(b'A')
                        old_b.sendall(b'B')
                        self.assertEqual(peer_a.recv(1), b'A')
                        self.assertEqual(peer_b.recv(1), b'B')
                        self.assertFalse(b.stopped.is_set())
                        cases.append(dict(observations, boundary=boundary, replacement=replacement,
                                          recovered=recovered, old_a_and_b_usable=True))
                    finally:
                        for item in created:
                            item.close()
                        rig.close()
        if os.environ.get('R5_ROOT'):
            (Path(os.environ['R5_ROOT']) / 'listener-identity-cases.json').write_text(json.dumps(cases))

    def test_real_cancel_invocation_revokes_inflight_handshakes(self):
        cases = []
        for timing in ('before_handshake', 'after_ack'):
            results = ('pending', 'failed', 'exception', 'replace_record', 'replace_handle')
            if timing == 'after_ack':
                results += ('replace_before_install',)
            for result in results:
                with self.subTest(timing=timing, result=result), tempfile.TemporaryDirectory() as directory:
                    rig = LifetimeRig(Path(directory))
                    b = rig.owner
                    old_a, peer_a = rig.handshake('a')
                    old_b, peer_b = rig.handshake('b')
                    lease, handle = b.handles['a']
                    entered, finish = threading.Event(), threading.Event()
                    errors, messages, calls = [], [], []
                    original = {'handle': handle, 'native_id': 'native-original', 'attempt': {'sequence': 1},
                                'cancel_requested': False, 'unknown': True, 'proving': False,
                                'next': 0, 'expired': False, 'deadline': time.monotonic() + 10}
                    b.executing['operation'] = original
                    b.unknown = {'operation': original['attempt']}

                    def cancellation(native_id):
                        calls.append(native_id)
                        entered.set()
                        assert finish.wait(2), 'release public cancellation barrier'
                        if result == 'exception':
                            raise OSError('public cancellation failed')
                        return {'status': 'failed' if result == 'failed' else 'cancelled',
                                'execution_stopped': result.startswith('replace_'), 'failure': 'still running'}

                    handle.cancel_operation_outcome = cancellation
                    def cancel():
                        try:
                            with patch.dict(sys.modules, {'ida_nexus': types.SimpleNamespace(discover_databases=lambda: [])}):
                                b.invoke(types.SimpleNamespace(send=messages.append), {'sequence': 2},
                                         {'command': 'cancel', 'identity': {'operation_id': 'operation', 'lease': lease}},
                                         time.monotonic() + 10, [False])
                        except Exception as exc:
                            errors.append(exc)

                    thread = threading.Thread(target=cancel)
                    successor = None
                    def start_cancel():
                        nonlocal successor
                        thread.start()
                        self.assertTrue(entered.wait(1), errors)
                        if result == 'replace_before_install':
                            with b.lock:
                                successor = {key: value for key, value in original.items()
                                             if key not in ('cancel_intent', 'cancel_inflight', 'cancel_gate')}
                                successor.update(native_id='native-next', attempt={'sequence': 3})
                                b.executing['operation'] = successor
                                b.unknown['operation'] = successor['attempt']

                    server, peer = rig.pair('a', lambda sock: SocketBarrier(sock, after_send=start_cancel)
                                            if timing == 'after_ack' else sock)
                    try:
                        if timing == 'before_handshake':
                            start_cancel()
                        with self.assertRaises(ValueError):
                            b.accept_lifetime(server)
                        self.assertEqual(server.fileno(), -1)
                        if timing == 'after_ack':
                            self.assertEqual(peer.recv(2), b'ok')
                        self.assertEqual(peer.recv(1), b'')
                        self.assertIs(b.lifetimes['a'], old_a)
                        self.assertIs(b.lifetimes['b'], old_b)
                        old_a.sendall(b'A')
                        old_b.sendall(b'B')
                        self.assertEqual(peer_a.recv(1), b'A')
                        self.assertEqual(peer_b.recv(1), b'B')
                        self.assertFalse(original['cancel_requested'], 'proof retries must wait for the public call')
                        self.assertNotIn('stop_proof', original)
                        if result in ('replace_record', 'replace_handle'):
                            with b.lock:
                                if result == 'replace_handle':
                                    b.handles['a'] = (dict(lease), types.SimpleNamespace(connected=True))
                                successor = dict(original, handle=b.handles['a'][1], native_id='native-next',
                                                 attempt={'sequence': 3})
                                for field in ('cancel_intent', 'cancel_inflight', 'cancel_gate'):
                                    successor.pop(field, None)
                                b.executing['operation'] = successor
                                b.unknown['operation'] = successor['attempt']
                        finish.set()
                        thread.join(2)
                        self.assertFalse(thread.is_alive())
                        self.assertEqual(calls, ['native-original'])
                        self.assertEqual(len(errors), int(result == 'exception'))
                        self.assertTrue(original.get('cancel_intent'), 'intent survives failed calls and detached records')
                        self.assertNotIn('stop_proof', original)
                        if successor is not None:
                            self.assertFalse(successor['cancel_requested'])
                            self.assertNotIn('cancel_intent', successor)
                            self.assertNotIn('stop_proof', successor)
                            self.assertEqual(b.unknown['operation'], {'sequence': 3})
                        else:
                            self.assertTrue(original['cancel_requested'])
                            rejected, _ = rig.pair('a')
                            with self.assertRaises(ValueError):
                                b.accept_lifetime(rejected)
                            self.assertIs(b.lifetimes['a'], old_a)
                        self.assertFalse(any(m['event'] == 'stopped' for m in messages))
                        b.executing.clear()  # Execution ended; a later legal handshake can replace A.
                        new, _ = rig.handshake('a')
                        self.assertIs(b.lifetimes['a'], new)
                        self.assertEqual(old_a.fileno(), -1)
                        self.assertIs(b.lifetimes['b'], old_b)
                        cases.append({'timing': timing, 'public_result': result, 'calls': calls,
                                      'old_a_and_b_usable': True, 'successor_untouched': successor is not None,
                                      'stopped_published': False, 'next_handshake': True})
                    finally:
                        finish.set()
                        if thread.ident is not None:
                            thread.join(2)
                        server.close()
                        rig.close()
        if os.environ.get('R5_ROOT'):
            (Path(os.environ['R5_ROOT']) / 'cancel-invoke-cases.json').write_text(json.dumps(cases))

    def test_public_cancel_and_proof_retries_are_serial(self):
        for failure in (False, True):
            with self.subTest(public_exception=failure), tempfile.TemporaryDirectory() as directory:
                rig = LifetimeRig(Path(directory))
                b = rig.owner
                lease, handle = b.handles['a']
                entered, finish, scanned = threading.Event(), threading.Event(), threading.Event()
                calls, messages, errors, submitted = [], [], [], []
                record = {'handle': handle, 'native_id': 'native', 'attempt': {'sequence': 1},
                          'cancel_requested': False, 'unknown': True, 'proving': False,
                          'next': 0, 'expired': False, 'deadline': time.monotonic() + 10}

                class ScannedRecords(dict):
                    def items(self):
                        yield from super().items()
                        scanned.set()

                b.executing = ScannedRecords(operation=record)
                b.unknown = {'operation': record['attempt']}
                b.control = types.SimpleNamespace(send=messages.append)
                b.proof_gate = threading.BoundedSemaphore(2)
                b.proof_pool = types.SimpleNamespace(submit=lambda *args: submitted.append(args))

                def cancellation(native):
                    calls.append(native)
                    if len(calls) == 2:
                        entered.set()
                        assert finish.wait(2), 'release second public cancellation'
                        if failure:
                            raise OSError('public cancellation error')
                    return {'status': 'cancelled', 'execution_stopped': len(calls) == 3}

                handle.cancel_operation_outcome = cancellation
                def cancel():
                    try:
                        b.invoke(b.control, {'sequence': len(calls) + 2},
                                 {'command': 'cancel', 'identity': {'operation_id': 'operation', 'lease': lease}},
                                 time.monotonic() + 10, [False])
                    except Exception as exc:
                        errors.append(exc)

                public_thread = threading.Thread(target=cancel)
                proof_thread = threading.Thread(target=b.proofs)
                try:
                    with patch.dict(sys.modules, {'ida_nexus': types.SimpleNamespace(discover_databases=lambda: [])}):
                        cancel()  # Real producer made cancel_requested true on return.
                        self.assertTrue(record['cancel_requested'])
                        public_thread.start()
                        self.assertTrue(entered.wait(1))
                        proof_thread.start()
                        self.assertTrue(scanned.wait(1), 'actual proof scheduler scanned in-flight public cancel')
                        with b.lock:
                            self.assertFalse(submitted, 'no retry may be queued while public cancellation is in flight')
                            self.assertNotIn('stop_proof', record)
                            self.assertIs(b.executing['operation'], record)
                        b.stopped.set()
                        b.proof_wakeup.set()
                        proof_thread.join(1)
                        self.assertFalse(proof_thread.is_alive())
                        finish.set()
                        public_thread.join(1)
                        self.assertFalse(public_thread.is_alive())
                        self.assertEqual(len(errors), int(failure))
                        self.assertEqual(calls, ['native', 'native'])
                        self.assertNotIn('stop_proof', record)
                        self.assertFalse(any(m['event'] == 'stopped' for m in messages))
                        # Once the public call ended, the existing public proof path works.
                        b.proof_gate.acquire()
                        record['proving'] = True
                        b.confirm_stop('operation', record)
                        self.assertEqual(calls, ['native'] * 3)
                        self.assertEqual([m['event'] for m in messages].count('stopped'), 1)
                        self.assertFalse(b.unknown)
                        self.assertFalse(b.executing)
                finally:
                    finish.set()
                    b.stopped.set()
                    b.proof_wakeup.set()
                    for thread in (public_thread, proof_thread):
                        if thread.ident is not None:
                            thread.join(2)
                    rig.close()

    def test_listener_failed_setup_and_close_preserve_foreign_types(self):
        for fault in ('listen_error', 'timeout_error', 'identity_error', 'close_socket', 'close_file', 'close_symlink'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                rig = LifetimeRig(root)
                b = rig.owner
                path = Path(b.lifetime_path)
                original_socket = socket.socket
                created = []
                try:
                    if fault.startswith('close_'):
                        path.rename(root / 'original')
                        if fault == 'close_socket':
                            foreign = original_socket(socket.AF_UNIX)
                            created.append(foreign)
                            foreign.bind(str(path))
                            foreign.listen(1)
                        elif fault == 'close_file':
                            path.write_text('foreign')
                        else:
                            path.symlink_to(root / 'original')
                        foreign_inode = path.lstat().st_ino
                        b.close_lifetime_listener()
                        self.assertEqual(path.lstat().st_ino, foreign_inode)
                        self.assertFalse(b.lifetime_healthy)
                        continue

                    class SetupFailure:
                        def __init__(self):
                            self.socket = original_socket(socket.AF_UNIX)
                            created.append(self.socket)

                        def __getattr__(self, key):
                            return getattr(self.socket, key)

                        def bind(self, address):
                            self.socket.bind(address)
                            if fault == 'identity_error':
                                path.rename(root / 'original')
                                path.write_text('foreign')

                        def listen(self, capacity):
                            if fault == 'listen_error':
                                raise OSError('listen failure')
                            self.socket.listen(capacity)

                        def settimeout(self, value):
                            raise OSError('timeout setup failure')

                    b.lifetime_socket.close()
                    failed = b.lifetime_socket
                    with patch('lifetime.socket.socket', side_effect=lambda *_a, **_k: SetupFailure()):
                        self.assertFalse(b.recover_lifetime_listener(failed))
                    self.assertFalse(b.lifetime_healthy)
                    if fault == 'identity_error':
                        self.assertEqual(path.read_text(), 'foreign')
                        self.assertFalse(b.recover_lifetime_listener(failed))
                        b.close_lifetime_listener()
                        self.assertEqual(path.read_text(), 'foreign')
                    else:
                        self.assertFalse(path.exists(), 'owned failed setup is safely unlinked')
                        self.assertTrue(b.recover_lifetime_listener(failed))
                        rig.handshake('a')
                finally:
                    for item in created:
                        item.close()
                    rig.close()

    def test_freeze_separates_historical_red_from_r5_f2(self):
        scripts = REPO / 'scripts/nexus'
        sys.path.insert(0, str(scripts))
        spec = importlib.util.spec_from_file_location('r5_freeze', scripts / 'r0_freeze.py')
        freeze = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(freeze)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('slow-owner', 'early-analysis', 'lost-ack'):
                (root / name).mkdir()
                (root / name / 'rust-result.json').write_text(json.dumps({
                    'scope': 'current-product-expected-red', 'fact': {'id': name}}))
            reds, fixed, paths = freeze.product_results(root)
            self.assertEqual((len(reds), len(fixed), len(paths)), (3, 0, 3))
            path = root / 'lost-ack/rust-result.json'
            row = {'scope': 'R5-production-isolation', 'fact': {
                'id': 'F2', 'unrelated_b': 'Active', 'query': {'result': {'result': 42}}}}
            path.write_text(json.dumps(row))
            reds, fixed, _ = freeze.product_results(root)
            self.assertEqual(len(reds), 2)
            self.assertEqual(fixed, [row['fact']])
            for field, bad in (('unrelated_b', 'Disconnected'), ('query', {'result': {'result': 0}})):
                changed = dict(row, fact=dict(row['fact'], **{field: bad}))
                path.write_text(json.dumps(changed))
                with self.assertRaises(AssertionError):
                    freeze.product_results(root)

    def test_home_matches_rust_table(self):
        cases = json.loads((REPO / 'tests/fixtures/nexus_r5_home.json').read_text())
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(str(ida_cli_home(case['environment'], case['cwd'])), case['expected'])
        self.assertEqual(len(cases), 12)

    def test_state_uses_public_rules_and_freezes_worker_input(self):
        from ida_nexus import get_state_dir
        with tempfile.TemporaryDirectory() as root:
            values = [('IDA_NEXUS_STATE_DIR', '~/explicit-state'),
                      ('IDA_NEXUS_STATE_DIR', 'relative-state'), ('IDAUSR', root + '/profile')]
            records = []
            for key, value in values:
                environment = {'HOME': root, key: value}
                with patch.dict(os.environ, environment, clear=True):
                    expected = str(Path(get_state_dir()).absolute())
                    paths = startup_paths()
                    self.assertEqual(paths['state_dir'], expected)
                    self.assertEqual(os.environ['IDA_NEXUS_STATE_DIR'], expected)
                    self.assertEqual(paths['ida_cli_home'], root + '/.ida')
                    records.append(paths)
            self.assertEqual(len(records), 3)

    def test_protocol_full_positive_and_negative_table(self):
        validate(contract())
        reordered = contract()
        reordered['capabilities'].reverse()
        validate(reordered)
        cases = []
        for field in contract():
            missing = contract()
            missing.pop(field)
            cases.append(missing)
        for field in ('wire', 'schema', 'release', 'open', 'owner_observation'):
            bad = contract()
            bad[field] += 1
            cases.append(bad)
        for version in (1, True):
            bad = contract()
            bad['wire'] = version
            cases.append(bad)
        for capabilities in ([], ['receiver_isolation_v1'], contract()['capabilities'] + ['custody_v1'],
                             contract()['capabilities'] + ['helper_v1'],
                             contract()['capabilities'] + [contract()['capabilities'][0]]):
            bad = contract()
            bad['capabilities'] = capabilities
            cases.append(bad)
        bad = contract()
        bad['client_hash'] = '0' * 64
        cases.append(bad)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                validate(case)
        with patch.dict(os.environ, {'IDA_CLI_NEXUS_PROTOCOL': json.dumps(cases[-1])}):
            ready = readiness()
            self.assertFalse(ready['ready'])
            self.assertIn('ProtocolMismatch', ready['error']['message'])
        self.assertNotIn('custody_v1', contract()['capabilities'])
        self.assertEqual(contract()['owner_observation'], 1)
        self.assertEqual(contract()['same_boot_exit'], 0)
        self.assertEqual(contract()['boot_retirement'], 1)
        # This is the message schema, never unconditional OS eligibility.
        bad = contract()
        bad['boot_retirement'] = 0
        with self.assertRaises(ValueError):
            validate(bad)

    def test_f9_barriers_preserve_old_connection_and_b(self):
        records = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for fault in ('send_failure', 'cancel', 'drop', 'disconnect', 'replace_lease', 'incarnation', 'peer_eof'):
                with self.subTest(fault=fault):
                    rig = LifetimeRig(root)
                    b = rig.owner
                    try:
                        old, _ = rig.handshake('a')
                        other, _ = rig.handshake('b')
                        def barrier():
                            if fault == 'cancel':
                                b.executing['operation'] = {'handle': b.handles['a'][1], 'cancel_requested': True}
                            elif fault == 'drop':
                                b.drop_lifetime('a')
                            elif fault == 'disconnect':
                                b.handles['a'][1].connected = False
                                b.drop_lifetime('a')
                            elif fault == 'replace_lease':
                                b.handles['a'] = (dict(b.handles['a'][0], generation=2), types.SimpleNamespace(connected=True))
                            elif fault == 'incarnation':
                                b.identity = 'replacement'
                            elif fault == 'peer_eof':
                                peer.close()
                        server, peer = rig.pair('a', lambda sock: SocketBarrier(sock, after_send=barrier,
                            failure=BrokenPipeError('injected send failure') if fault == 'send_failure' else None))
                        with self.assertRaises((OSError, ValueError)):
                            b.accept_lifetime(server)
                        self.assertEqual(server.fileno(), -1)
                        self.assertEqual(other.fileno() >= 0, True)
                        self.assertIs(b.lifetimes['b'], other)
                        if fault in ('drop', 'disconnect'):
                            self.assertEqual(old.fileno(), -1, 'real old disconnect must stay disconnected')
                            self.assertNotIn('a', b.lifetimes)
                        else:
                            self.assertIs(b.lifetimes['a'], old)
                            self.assertGreaterEqual(old.fileno(), 0, 'healthy old watcher must survive rejection')
                        self.assertFalse(b.lifetime_pending)
                        b.executing.clear()
                        b.handles['a'][1].connected = True
                        new, _ = rig.handshake('a')
                        self.assertIs(b.lifetimes['a'], new)
                        self.assertEqual(old.fileno(), -1)
                        self.assertIs(b.lifetimes['b'], other)
                        self.assertFalse(b.stopped.is_set())
                        records.append({'fault': fault, 'b_healthy': True, 'next_handshake': True})
                    finally:
                        rig.close()
        if os.environ.get('R5_ROOT'):
            (Path(os.environ['R5_ROOT']) / 'lifetime-barriers.json').write_text(json.dumps(records))

    def test_listener_retries_failed_rebind_without_replacing_foreign_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            rig = LifetimeRig(Path(directory))
            b = rig.owner
            failed = b.lifetime_socket
            try:
                failed.close()
                with patch.object(b, 'new_lifetime_listener', side_effect=OSError('bind injected')):
                    self.assertFalse(b.recover_lifetime_listener(failed))
                self.assertFalse(b.lifetime_healthy)
                self.assertFalse(Path(b.lifetime_path).exists())
                self.assertTrue(b.recover_lifetime_listener(failed))
                self.assertTrue(b.lifetime_healthy)
                rig.handshake('a')
                rig.handshake('b')
                b.lifetime_socket.close()
                Path(b.lifetime_path).unlink()
                with socket.socket(socket.AF_UNIX) as foreign:
                    foreign.bind(b.lifetime_path)
                    inode = Path(b.lifetime_path).lstat().st_ino
                    self.assertFalse(b.recover_lifetime_listener(b.lifetime_socket))
                    self.assertEqual(Path(b.lifetime_path).lstat().st_ino, inode)
                self.assertFalse(b.stopped.is_set())
            finally:
                rig.close()

    def test_f9_bad_connections_and_listener_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            rig = LifetimeRig(Path(directory))
            b = rig.owner
            old_a, _ = rig.handshake('a')
            old_b, _ = rig.handshake('b')
            listener_thread = threading.Thread(target=b.accept_lifetimes)
            listener_thread.start()
            try:
                # First handshake times out without stopping accept. Actual AF_UNIX input.
                for payload in (None, b'\xff', b'a' * 257, b'unknown', b''):
                    with socket.socket(socket.AF_UNIX) as peer:
                        peer.settimeout(3)
                        peer.connect(b.lifetime_path)
                        if payload is not None:
                            peer.sendall(payload)
                        if payload == b'':
                            peer.shutdown(socket.SHUT_WR)
                        self.assertEqual(peer.recv(2), b'')
                    self.assertFalse(b.stopped.is_set())
                    self.assertIs(b.lifetimes['a'], old_a)
                    self.assertIs(b.lifetimes['b'], old_b)
                    self.assertGreaterEqual(old_a.fileno(), 0)
                    self.assertGreaterEqual(old_b.fileno(), 0)
                old_inode = b.lifetime_inode
                b.lifetime_socket.close()  # Actual listener failure; exact endpoint can recover.
                deadline = threading.Event()
                for _ in range(300):
                    if b.lifetime_healthy and b.lifetime_inode != old_inode:
                        break
                    deadline.wait(.005)
                self.assertTrue(b.lifetime_healthy)
                self.assertNotEqual(b.lifetime_inode, old_inode)
                self.assertIs(b.lifetimes['a'], old_a)
                self.assertIs(b.lifetimes['b'], old_b)
                self.assertGreaterEqual(old_a.fileno(), 0)
                self.assertGreaterEqual(old_b.fileno(), 0)
                for key in ('a', 'b'):
                    with socket.socket(socket.AF_UNIX) as peer:
                        peer.settimeout(2)
                        peer.connect(b.lifetime_path)
                        peer.sendall(key.encode())
                        self.assertEqual(peer.recv(2), b'ok')
                self.assertFalse(b.stopped.is_set())
            finally:
                rig.close()
                listener_thread.join(2)
                self.assertFalse(listener_thread.is_alive())


if __name__ == '__main__':
    unittest.main()
