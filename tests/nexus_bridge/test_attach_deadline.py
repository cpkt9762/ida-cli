"""Exact clock/helper/HTTP model for the fixed SDK's final callback boundary."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge/custody'), str(REPO/'nexus_bridge')]
import acquisition
import ida_nexus.handle as sdk


class AttachDeadline(unittest.TestCase):
    def run_boundary(self, entry, signed):
        clock = [entry]
        requests, receipts = [], []
        owner = {'record_id':'controlled-owner'}
        custody = acquisition.Custodian.__new__(acquisition.Custodian)
        custody.deadline = 2.0
        custody.owner, custody.subscription = owner, {'signed':True}
        custody.attach_ordinal = 3
        custody.observations = {'watch':{'owner':owner,'attempts':{}}}
        def helper(value):
            self.assertEqual(value['kind'],'attach_attempt')
            self.assertEqual(value['attempt']['state'],'may_send')
            clock[0] = signed
            receipts.append(value)
            return {'signed':True}
        custody.helper_request = helper
        class Connection:
            def __init__(self,*args,**kwargs):
                self.sock = SimpleNamespace(settimeout=lambda _:None)
            def request(self,*args,**kwargs):
                requests.append(clock[0])
            def getresponse(self):
                return SimpleNamespace(status=200)
            def close(self):
                pass
        handle = sdk.DatabaseHandle.__new__(sdk.DatabaseHandle)
        handle._lease_id, handle.keepalive, handle.idle_timeout = 'model-lease', 0, None
        handle._on_stage = custody.stage
        instance = SimpleNamespace(port=0,_token='test-only-not-output')
        originals, launches = {'original':instance}, {'startup':object()}
        custody.originals, custody.launches = originals, launches
        custody.post_exit_resolve_used = True
        http = SimpleNamespace(client=SimpleNamespace(HTTPConnection=Connection,
            HTTPException=sdk.http.client.HTTPException))
        error = None
        with patch.object(acquisition,'time',SimpleNamespace(monotonic=lambda:clock[0])), \
             patch.object(acquisition,'owner_key',lambda _:owner), patch.object(sdk,'http',http):
            try:
                handle._open_lease(instance)
            except sdk.StageObserverFailure as failure:
                error = failure.cause
        self.assertEqual(custody.deadline,2.0)
        self.assertIs(custody.owner,owner)
        self.assertIs(custody.originals,originals)
        self.assertIs(custody.originals['original'],instance)
        self.assertIs(custody.launches,launches)
        self.assertTrue(custody.post_exit_resolve_used)
        return custody, requests, receipts, error

    def test_healthy_signing_allows_one_request(self):
        custody, requests, receipts, error = self.run_boundary(1.0,1.1)
        self.assertEqual(requests,[1.1])
        self.assertIsNone(error)
        self.assertEqual(len(receipts),1)
        self.assertEqual(custody.observations['watch']['attempts'][3]['state'],'may_send')

    def test_expired_entry_never_calls_helper_or_http(self):
        custody, requests, receipts, error = self.run_boundary(2.1,2.1)
        self.assertEqual(requests,[])
        self.assertEqual(receipts,[])
        self.assertIsInstance(error,TimeoutError)
        self.assertEqual(custody.observations['watch']['attempts'],{})

    def test_signature_at_deadline_preserves_signed_fact_without_request(self):
        self.assert_rejected_signature(2.0)

    def test_signature_after_deadline_preserves_signed_fact_without_request(self):
        self.assert_rejected_signature(2.1)

    def assert_rejected_signature(self,signed):
        custody, requests, receipts, error = self.run_boundary(1.9,signed)
        self.assertEqual(requests,[])
        self.assertIsInstance(error,TimeoutError)
        self.assertEqual(len(receipts),1)
        self.assertEqual(custody.observations['watch']['attempts'][3]['state'],'may_send')


class RetirementAck(unittest.TestCase):
    def test_duplicate_retirement_ack_keeps_full_duplex_control_progress(self):
        self.exercise_control_progress('custody_retired_ack')

    def test_duplicate_public_proof_ack_keeps_full_duplex_control_progress(self):
        self.exercise_control_progress('owner_proof_ack')

    def exercise_control_progress(self, event):
        import json
        import os
        import queue
        import socket
        import tempfile
        import threading
        from bridge import Channel
        path = Path(tempfile.mkdtemp(dir=os.environ['R3A_CASE_ROOT'],prefix='ack-'))/'s'
        stopped, progress = threading.Event(), threading.Event()
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(path))
        bound = path.lstat()
        listener.listen(1)
        ack = {'event':event,'receipt':{'watch':'same-watch','evidence':'x'*200000}}
        def receive(channel, message):
            if message['kind']=='retire':
                channel.send(ack)
            else:
                progress.set()
        channel = Channel(str(path),2,receive,stopped)
        peer,_ = listener.accept()
        channel.socket.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,1024)
        try:
            # The peer withholds reads of the first large ACK while delivering
            # duplicate retirement requests followed by an unrelated reply.
            frames = [dict(kind='retire') for _ in range(5)] + [dict(kind='reply')]
            peer.sendall(b''.join(json.dumps(v).encode()+b'\n' for v in frames))
            self.assertTrue(progress.wait(1),'duplicate ACK backpressure blocked the control reader')
            peer.settimeout(1)
            data = b''
            while b'\n' not in data:
                data += peer.recv(65536)
            self.assertEqual(json.loads(data.split(b'\n')[0]),ack)
            peer.settimeout(.1)
            with self.assertRaises(socket.timeout):
                peer.recv(1)
        finally:
            stopped.set()
            for stream in (peer,channel.socket):
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            while True:
                try:
                    channel.output.get_nowait()
                except queue.Empty:
                    break
            channel.output.put({'event':'test_teardown'})
            channel.reader.join(1)
            channel.writer.join(1)
            peer.close()
            channel.socket.close()
            listener.close()
            current = path.lstat()
            self.assertEqual((current.st_dev, current.st_ino), (bound.st_dev, bound.st_ino))
            path.unlink()  # The exact local listener created and closed above.
            self.assertFalse(channel.reader.is_alive(),'control reader did not naturally stop')
            self.assertFalse(channel.writer.is_alive(),'control writer did not naturally stop')
