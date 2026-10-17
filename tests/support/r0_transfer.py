"""SCM_RIGHTS transfer prototype: journal execution authority is separate from OFD."""
import fcntl
import json
import os
from pathlib import Path
import socket
import time
import unittest

from r0_common import fork, blocked, durable, lock, read, recv_fd, send_fd

ROOT = Path(os.environ["R0_CASE_ROOT"])
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)


def append_action(case, actor, epoch, action):
    state = read(case / "executor.json")
    if state["actor"] != actor or state["epoch"] != epoch or state["state"] not in ("LocalExecuting", "Accepted", "Resumed"):
        raise PermissionError("frozen or stale executor")
    with (case / "actions.jsonl").open("a") as stream:
        stream.write(json.dumps(dict(pid=os.getpid(), actor=actor, epoch=epoch, action=action)) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    # A real non-overwriting file side effect, not just an external lock probe.
    path = case / action
    if path.exists():
        raise RuntimeError("side effect replay")
    path.write_bytes(actor.encode())


def receiver(case, channel, boundary):
    root = lock(case / "root.lock", fcntl.LOCK_SH)
    channel.send(b"Prepared")
    fd = None
    try:
        fd, transfer = recv_fd(channel)
        if boundary == "received":
            os._exit(81)
        offer = read(case / "executor.json")
        if offer["transfer_id"] != transfer or offer["state"] != "FrozenOffer":
            raise RuntimeError("invalid directional offer")
        if os.fstat(fd).st_ino != (case / "target.lock").stat().st_ino:
            raise RuntimeError("wrong target inode")
        durable(case / "executor.json", dict(offer, state="Accepted", actor="receiver"))
        if boundary != "ack_lost":
            channel.send(b"Accepted")
        if boundary == "accepted":
            os._exit(82)
        channel.recv(16)  # Sender observes durable acceptance; ACK may be ignored.
        if boundary == "intent":
            durable(case / "intent.json", {"action":"receiver-file", "epoch":1})
            os._exit(83)
        append_action(case, "receiver", 1, "receiver-file")
        if boundary == "action":
            os._exit(84)
        # Duplicate FD must be close-only, never explicit LOCK_UN.
        extra, duplicate = recv_fd(channel)
        if duplicate != transfer:
            os.close(extra)
            raise RuntimeError("mismatched duplicate")
        os.close(extra)
        channel.send(b"Done")
        channel.recv(16)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root)


class TransferPrototypes(unittest.TestCase):
    def test_directional_transfer_crashes_duplicates_and_fence(self):
        summaries = []
        for boundary in ("normal", "ack_lost", "received", "accepted", "intent", "action"):
            case = ROOT / boundary
            case.mkdir()
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            a.settimeout(5)
            b.settimeout(5)
            # Fork before either parent lock opens: receiver does not inherit root or target OFDs.
            pid = fork()
            if pid == 0:
                a.close()
                try:
                    receiver(case, b, boundary)
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    os._exit(99)
                os._exit(0)
            b.close()
            self.assertEqual(a.recv(16), b"Prepared")
            root = lock(case / "root.lock", fcntl.LOCK_SH)
            fd = lock(case / "target.lock")
            transfer = {"recovery":"r0", "epoch":1, "sender":os.getpid(), "receiver":pid,
                        "nonce":boundary, "inode":os.fstat(fd).st_ino}
            durable(case / "executor.json", dict(state="LocalExecuting", actor="sender", epoch=1,
                                                   transfer_id=transfer))
            append_action(case, "sender", 1, "sender-file")
            durable(case / "executor.json", dict(state="FrozenOffer", actor=None, epoch=1,
                                                   transfer_id=transfer))
            with self.assertRaises(PermissionError):
                append_action(case, "sender", 1, "forbidden-file")
            send_fd(a, fd, transfer)
            # SendMayHaveDelivered: retained FD is protection, never writer permission.
            self.assertTrue(blocked(case / "target.lock"))
            if boundary != "received":
                if boundary == "ack_lost":
                    deadline = time.monotonic() + 5
                    while read(case / "executor.json")["state"] != "Accepted":
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(.005)
                    # No ACK was put on the socket. Only durable status is consumed.
                else:
                    self.assertEqual(a.recv(16), b"Accepted")
                with self.assertRaises(PermissionError):
                    append_action(case, "sender", 1, "forbidden-after-accept")
                a.send(b"continue")
            if boundary in ("normal", "ack_lost"):
                send_fd(a, fd, transfer)
                self.assertEqual(a.recv(16), b"Done")
                os.close(fd)
                fd = None
                os.close(root)
                root = None
                self.assertTrue(blocked(case / "target.lock"), "receiver still owns target after sender closes")
                self.assertTrue(blocked(case / "root.lock"), "receiver acquired independent root SH")
                a.send(b"close")
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]),
                             {"received":81,"accepted":82,"intent":83,"action":84}.get(boundary, 0))
            if fd is not None:
                self.assertTrue(blocked(case / "target.lock"), "sender must drop its OWN old reference before fence")
                os.close(fd)
            if root is not None:
                os.close(root)
            self.assertFalse(blocked(case / "target.lock"))
            root = lock(case / "root.lock", fcntl.LOCK_SH)
            fence = lock(case / "target.lock", nb=True)
            self.assertEqual(os.fstat(fence).st_ino, transfer["inode"])
            old = read(case / "executor.json")
            durable(case / "executor.json", dict(old, state="Resumed", actor="recovery", epoch=2))
            # Continue exactly the uncompleted step, never repeat the previous action.
            if not (case / "receiver-file").exists():
                append_action(case, "recovery", 2, "receiver-file")
            with self.assertRaises(PermissionError):
                append_action(case, "receiver", 1, "late-old-actor")
            actions = [json.loads(line) for line in (case / "actions.jsonl").read_text().splitlines()]
            self.assertEqual([a["action"] for a in actions], ["sender-file", "receiver-file"])
            self.assertEqual(len({(a["actor"], a["epoch"]) for a in actions}), 2)
            self.assertFalse((case / "forbidden-file").exists())
            os.close(fence)
            os.close(root)
            a.close()
            summaries.append({"boundary":boundary, "actions":actions, "unique_writer":True})
        durable(ROOT / "transfer-results.json", {"scope":"real-process-prototype", "cases":summaries})

    def test_both_endpoints_exit_and_wrong_identity_rejection(self):
        results = []
        for boundary in ("sender_before_send", "sender_after_send", "sender_after_accepted", "both_after_intent", "wrong_identity"):
            case = ROOT / boundary
            case.mkdir()
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            a.settimeout(5)
            b.settimeout(.05)
            receiver_pid = fork()
            if receiver_pid == 0:
                a.close()
                root = lock(case / "root.lock", fcntl.LOCK_SH)
                try:
                    while True:
                        try:
                            fd, transfer = recv_fd(b)
                            break
                        except TimeoutError:
                            if (case / "finish").exists():
                                os._exit(90)
                    offer = read(case / "executor.json")
                    if transfer != offer["transfer_id"]:
                        os.close(fd)
                        durable(case / "rejected.json", {"reason":"wrong_transfer_identity"})
                        os._exit(91)
                    durable(case / "executor.json", dict(offer, state="Accepted", actor="receiver"))
                    if boundary in ("sender_after_accepted", "both_after_intent"):
                        b.send(b"Accepted")
                    if boundary == "both_after_intent":
                        durable(case / "intent.json", {"action":"receiver-file", "epoch":1})
                        os._exit(92)
                    while not (case / "finish").exists():
                        time.sleep(.005)
                    os.close(fd)
                    os._exit(0)
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    os._exit(99)
                finally:
                    os.close(root)
            sender_pid = fork()
            if sender_pid == 0:
                b.close()
                root = lock(case / "root.lock", fcntl.LOCK_SH)
                fd = lock(case / "target.lock")
                transfer = {"sender":os.getpid(), "receiver":receiver_pid, "epoch":1, "nonce":boundary}
                durable(case / "executor.json", dict(state="FrozenOffer", actor=None, epoch=1, transfer_id=transfer))
                if boundary == "sender_before_send":
                    os._exit(93)
                send_fd(a, fd, dict(transfer, nonce="wrong") if boundary == "wrong_identity" else transfer)
                if boundary in ("sender_after_accepted", "both_after_intent"):
                    assert a.recv(16) == b"Accepted"
                os._exit(94)
            a.close()
            b.close()
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(sender_pid, 0)[1]),
                             93 if boundary == "sender_before_send" else 94)
            (case / "finish").touch()
            code = os.waitstatus_to_exitcode(os.waitpid(receiver_pid, 0)[1])
            self.assertEqual(code, {"sender_before_send":90, "both_after_intent":92, "wrong_identity":91}.get(boundary, 0))
            # Neither original endpoint is alive, and recovery opens an independent OFD.
            root = lock(case / "root.lock", fcntl.LOCK_SH)
            fence = lock(case / "target.lock", nb=True)
            try:
                offer = read(case / "executor.json")
                durable(case / "executor.json", dict(offer, state="Resumed", actor="recovery", epoch=2))
                append_action(case, "recovery", 2, "receiver-file")
                with self.assertRaises(PermissionError):
                    append_action(case, "receiver", 1, "stale-write")
            finally:
                os.close(fence)
                os.close(root)
            results.append({"boundary":boundary, "sender_reaped":True, "receiver_reaped":True,
                            "receiver_exit":code, "recovery_action_count":1})
        durable(ROOT / "both-exit.json", results)

    def test_definitely_not_sent_and_queued_fd_sender_exit(self):
        case = ROOT / "not-sent"
        case.mkdir()
        target = case / "target.lock"
        fd = lock(target)
        durable(case / "executor.json", dict(state="FrozenOffer", actor=None, epoch=1))
        # No sendmsg has been called on this branch; only this branch may AbortOffer.
        durable(case / "executor.json", dict(state="LocalExecuting", actor="sender", epoch=2))
        append_action(case, "sender", 2, "abort-offer-file")
        os.close(fd)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        pid = fork()
        if pid == 0:
            b.close()
            fd = lock(target)
            send_fd(a, fd, {"epoch":3})
            os.close(fd)
            os._exit(0)
        a.close()
        self.assertEqual(os.waitpid(pid, 0)[1], 0)
        self.assertTrue(blocked(target), "sender gone but queued SCM_RIGHTS holds OFD")
        received, _payload = recv_fd(b)
        self.assertTrue(blocked(target))
        os.close(received)
        b.close()
        self.assertFalse(blocked(target))

    def test_old_explicit_unlock_counterexample_and_move(self):
        target = ROOT / "drop.lock"
        fd = lock(target)
        copy = os.dup(fd)
        os.close(fd)
        self.assertTrue(blocked(target), "close-only move preserves lock")
        # This is the old CacheGuard Drop operation, preserved as a counterexample.
        fcntl.flock(copy, fcntl.LOCK_UN)
        self.assertFalse(blocked(target), "LOCK_UN breaks protection of every shared OFD reference")
        os.close(copy)
        fd = lock(target)
        moved = fd
        fd = None
        self.assertTrue(blocked(target))
        os.close(moved)
        self.assertFalse(blocked(target))

    def test_gc_double_nonblocking_and_root_first_writers(self):
        case = ROOT / "order"
        case.mkdir()
        root_path, target_path = case / "root.lock", case / "target.lock"
        held = lock(target_path)
        root = lock(root_path, nb=True)
        with self.assertRaises(BlockingIOError):
            lock(target_path, nb=True)
        os.close(root)
        # A busy target never keeps root EX held while waiting.
        root = lock(root_path, fcntl.LOCK_SH, nb=True)
        os.close(root)
        os.close(held)
        for writer in ("maintenance", "proof_merge", "revoke", "compaction"):
            root = lock(root_path, fcntl.LOCK_SH)
            target = lock(target_path)
            with self.assertRaises(BlockingIOError):
                lock(root_path, nb=True)
            durable(case / (writer + ".json"), {"order":["root_SH", "target_EX"]})
            os.close(target)
            os.close(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
