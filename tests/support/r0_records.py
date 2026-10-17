"""Bounded routine record/epoch prototype; retained evidence and lock inode survive."""
import errno
import json
import os
from pathlib import Path
import unittest

from r0_common import fork, digest, durable, finish_renamed, ordered, read, sync_dir

ROOT = Path(os.environ["R0_CASE_ROOT"])
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
SUMMARY_LIMIT = 64
SUMMARY_BYTES = 16384
ROUTINE_LIMIT = 96
FINISH_RESERVE = 8
RETAINED_LIMIT = 4
RETAINED_BYTES = 4096


def closed_summary(watermark, ranges, selected):
    """Keep intervals, not one tombstone per healthy epoch behind a live hole."""
    merged = []
    for first, last in sorted([*ranges, *([epoch, epoch] for epoch in selected)]):
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], last)
        else:
            merged.append([first, last])
    while merged and merged[0][0] <= watermark + 1:
        watermark = max(watermark, merged.pop(0)[1])
    return {"closed_through":watermark, "closed_after_holes":merged}


class Store:
    def __init__(self, path):
        self.path = path
        path.mkdir(exist_ok=True)
        (path / "routine").mkdir(exist_ok=True)
        (path / "retained").mkdir(exist_ok=True)
        if not (path / "state.json").exists():
            durable(path / "state.json", {"next_epoch":1, "closed_through":0,
                    "closed_after_holes":[], "active":{}, "revision":0})

    def allocate(self, refs=(), closed=True):
        # Compaction has its own root->target acquisition, before admission locks.
        if len(read(self.path / "state.json")["active"]) >= ROUTINE_LIMIT - FINISH_RESERVE:
            self.compact()
        with ordered(self.path / "root.lock", self.path / "target.lock"):
            state = read(self.path / "state.json")
            if len(state["active"]) >= ROUTINE_LIMIT - FINISH_RESERVE:
                raise RuntimeError("Busy+live_refs")
            epoch = state["next_epoch"]
            state["next_epoch"] += 1
            state["revision"] += 1
            durable(self.path / "routine" / f"{epoch}.json", {
                "schema":1, "epoch":epoch, "refs":list(refs),
                "producer_closed":closed, "consumer_closed":closed,
                "unacked_events":0, "failure":False, "last_safety_evidence":False})
            state["active"][str(epoch)] = "routine"
            durable(self.path / "state.json", state)
            return epoch

    def retain_failure(self, value):
        with ordered(self.path / "root.lock", self.path / "target.lock"):
            files = list((self.path / "retained").glob("*.json"))
            encoded = json.dumps(value, sort_keys=True).encode()
            if len(files) >= RETAINED_LIMIT or sum(path.stat().st_size for path in files) + len(encoded) > RETAINED_BYTES:
                raise RuntimeError("RetainedQuotaFull")
            durable(self.path / "retained" / f"{len(files)+1}.json", value)

    def event(self, epoch):
        with ordered(self.path / "root.lock", self.path / "target.lock"):
            state = read(self.path / "state.json")
            if epoch <= state["closed_through"] or any(first <= epoch <= last for first,last in state["closed_after_holes"]):
                return "AlreadyClosed"
            if str(epoch) not in state["active"]:
                return "UnknownEpoch"
            return "Active"

    def compact(self, crash=None, io_error=None):
        with ordered(self.path / "root.lock", self.path / "target.lock"):
            # Reconcile completed renames before consuming/unlinking an intent;
            # otherwise its ownership record could outlive the published file.
            for name in ("summary.json", "intent.json", "state.json"):
                path = self.path / name
                owner = path.with_name(path.name + ".new.owner")
                if not path.with_name(path.name + ".new").exists() and owner.exists():
                    finish_renamed(path, owner)
            state = read(self.path / "state.json")
            intent_path = self.path / "intent.json"
            if intent_path.exists():
                intent = read(intent_path)
                if intent["revision"] != state["revision"]:
                    raise RuntimeError("RoutineCompactionFailed:new_reference_or_epoch")
            else:
                selected = []
                for path in sorted((self.path / "routine").glob("*.json")):
                    value = read(path)
                    if (not value["refs"] and value["producer_closed"] and value["consumer_closed"]
                            and not value["unacked_events"] and not value["failure"]
                            and not value["last_safety_evidence"]):
                        selected.append({"epoch":value["epoch"], "inode":path.stat().st_ino,
                                         "hash":digest(path.read_bytes())})
                summary = closed_summary(state["closed_through"], state["closed_after_holes"],
                                         [value["epoch"] for value in selected])
                if len(summary["closed_after_holes"]) > SUMMARY_LIMIT or len(json.dumps(summary)) > SUMMARY_BYTES:
                    raise RuntimeError("Busy+summary_holes")
                if crash == "before_summary":
                    os._exit(91)
                if io_error:
                    raise OSError(io_error, "RoutineCompactionFailed")
                durable(self.path / "summary.json", summary)
                if crash == "summary":
                    os._exit(92)
                intent = {"schema":1, "revision":state["revision"], "selected":selected,
                          "summary":summary}
                durable(intent_path, intent)
                if crash == "intent":
                    os._exit(93)
            for index, value in enumerate(intent["selected"]):
                path = self.path / "routine" / f"{value['epoch']}.json"
                if path.exists():
                    if (path.stat().st_ino != value["inode"] or digest(path.read_bytes()) != value["hash"]):
                        raise RuntimeError("RoutineCompactionFailed:identity_changed")
                    path.unlink()
                    sync_dir(path.parent)
                if index == 0 and crash == "unlink":
                    os._exit(94)
                state["active"].pop(str(value["epoch"]), None)
            state.update(intent["summary"])
            durable(self.path / "state.json", state)
            if crash == "state_fsync":
                os._exit(95)
            intent_path.unlink()
            sync_dir(self.path)


class RecordPrototypes(unittest.TestCase):
    def test_fixed_targets_many_rounds_bounded_with_retained_unchanged(self):
        metrics = []
        for target in range(2):
            case = ROOT / f"bounded-{target}"
            store = Store(case)
            durable(case / "retained.json", {"failed":"UnknownOutcome", "NeverReplay":True})
            retained = (case / "retained.json").read_bytes()
            store.allocate(["cross-router:A", "cross-target:B"], closed=False)
            for _round in range(128):
                for _ in range(5):
                    store.allocate()
                store.compact()
                summary = read(case / "summary.json")
                self.assertLessEqual(len(summary["closed_after_holes"]), SUMMARY_LIMIT)
                self.assertLessEqual((case / "summary.json").stat().st_size, SUMMARY_BYTES)
                self.assertEqual(len(summary["closed_after_holes"]), 1,
                                 "one active hole must not grow a tombstone for every healthy round")
                self.assertLessEqual((case / "summary.json").stat().st_size, 128)
                self.assertEqual(len(list((case / "routine").glob("*.json"))), 1)
                self.assertEqual((case / "retained.json").read_bytes(), retained)
            self.assertEqual(store.event(1), "Active", "valid live hole not rejected by watermark")
            self.assertEqual(store.event(2), "AlreadyClosed", "late message cannot resurrect references")
            first = case / "routine/1.json"
            value = read(first)
            value.update(refs=[], producer_closed=True, consumer_closed=True)
            durable(first, value)
            lock_inode = (case / "target.lock").stat().st_ino
            store.compact()
            self.assertEqual(read(case / "summary.json")["closed_through"], 641)
            self.assertEqual((case / "target.lock").stat().st_ino, lock_inode)
            metrics.append({"target":target, "rounds":128, "routine_files":0,
                            "summary_bytes":(case / "summary.json").stat().st_size,
                            "namespace_bytes":sum((case / n).stat().st_size for n in ("root.lock","target.lock"))})
        durable(ROOT / "bounded-results.json", {"targets":metrics, "not_a_benchmark":True})

    def test_crash_boundaries_resume_idempotently(self):
        for boundary in ("before_summary", "summary", "intent", "unlink", "state_fsync"):
            store = Store(ROOT / boundary)
            for _ in range(3):
                store.allocate()
            pid = fork()
            if pid == 0:
                store.compact(crash=boundary)
                os._exit(99)
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]),
                             {"before_summary":91,"summary":92,"intent":93,"unlink":94,"state_fsync":95}[boundary])
            store.compact()
            store.compact()
            self.assertFalse(list((store.path / "routine").glob("*.json")))
            self.assertEqual(store.event(1), "AlreadyClosed")

    def test_reference_change_io_failure_and_quota_are_distinct(self):
        store = Store(ROOT / "ref-change")
        store.allocate()
        pid = fork()
        if pid == 0:
            store.compact(crash="intent")
            os._exit(99)
        os.waitpid(pid, 0)
        store.allocate(["new-consumer"], closed=False)
        with self.assertRaisesRegex(RuntimeError, "new_reference_or_epoch"):
            store.compact()
        self.assertTrue((store.path / "routine/1.json").exists())
        for code in (errno.ENOSPC, errno.EACCES):
            candidate = Store(ROOT / f"io-{code}")
            candidate.allocate()
            with self.assertRaises(OSError) as failure:
                candidate.compact(io_error=code)
            self.assertEqual(failure.exception.errno, code)
            self.assertTrue((candidate.path / "routine/1.json").exists())
        candidate = Store(ROOT / "quota")
        for _ in range(ROUTINE_LIMIT - FINISH_RESERVE):
            candidate.allocate(["live"], closed=False)
        with self.assertRaisesRegex(RuntimeError, "Busy\\+live_refs"):
            candidate.allocate()
        # Reserved finish space remains writable even when ordinary admission is full.
        durable(candidate.path / "cleanup-ack.json", {"ack":"existing obligation"})
        candidate.compact()
        self.assertEqual(len(read(candidate.path / "state.json")["active"]), 88)
        healthy = Store(ROOT / "automatic")
        for _ in range(ROUTINE_LIMIT - FINISH_RESERVE + 1):
            healthy.allocate()
        self.assertEqual(len(read(healthy.path / "state.json")["active"]), 1,
                         "routine-full admission compacts healthy history automatically")
        retained = Store(ROOT / "retained-quota")
        for index in range(RETAINED_LIMIT):
            retained.retain_failure({"observation":"EACCES", "transaction":index})
        original = {path.name:path.read_bytes() for path in (retained.path / "retained").glob("*.json")}
        with self.assertRaisesRegex(RuntimeError, "RetainedQuotaFull"):
            retained.retain_failure({"observation":"ENOSPC"})
        self.assertEqual(original, {path.name:path.read_bytes() for path in (retained.path / "retained").glob("*.json")})
        # Existing cleanup uses its reserved durable space at retained quota too.
        durable(retained.path / "finish-existing.json", {"finished_transaction":0})
        durable(ROOT / "quota-results.json", {"active_full":"Busy+live_refs", "automatic_compaction":True,
            "retained_full":"RetainedQuotaFull", "retained_files_preserved":True,
            "io_errors_injected":[errno.ENOSPC,errno.EACCES], "existing_finish_space_writable":True,
            "limits":{"retained_files":RETAINED_LIMIT,"retained_bytes":RETAINED_BYTES}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
