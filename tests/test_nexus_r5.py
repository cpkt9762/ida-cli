"""R5 path/admission tables and deterministic lifetime handoff barriers."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
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
        self.assertEqual(contract()['owner_observation'], 0)

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
