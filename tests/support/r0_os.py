"""Real private OS counterexamples plus explicitly injected authority/U6 models."""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import plistlib
import socket
import subprocess
import sys
import time
import unittest

from process_identity import identity, ProcBsdInfo
from r0_common import fork, blocked, digest, durable, lock, ordered, read, recv_fd, send_fd


ROOT = Path(os.environ["R0_CASE_ROOT"])
ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)


def platform_capability():
    """Only availability and hashes leave this function, never raw machine IDs."""
    if sys.platform != "darwin":
        return {"platform": sys.platform, "status": "NotTested", "reason": "macOS probe only"}
    def output(argv):
        return subprocess.check_output(["timeout", "30s", *argv])
    hardware = plistlib.loads(output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice", "-a"]))
    device = output(["df", "-P", str(ROOT.resolve())]).decode().splitlines()[-1].split()[0]
    volume = plistlib.loads(output(["diskutil", "info", "-plist", device]))
    boot = output(["sysctl", "-n", "kern.bootsessionuuid"]).strip()
    vm = output(["sysctl", "-n", "kern.hv_vmm_present"]).strip()
    machine = hardware[0].get("IOPlatformUUID", "")
    volume_id = volume.get("VolumeUUID", "")
    sources = {"machine": machine, "volume": volume_id, "boot": boot.decode()}
    local = volume.get("Internal") is True and volume.get("FilesystemType") == "apfs"
    # Darwin has one host PID/time domain. It is not a claim about Linux namespaces.
    return {"platform": "darwin", "method": "IOPlatformUUID/APFS-VolumeUUID/bootsessionuuid-v1",
            "available": {k: bool(v) for k, v in sources.items()},
            "hashes": {k: digest(v.encode()) for k, v in sources.items()},
            "virtualized": vm != b"0", "local_apfs_internal": local,
            "host_observation_domain": "Darwin-host-kernel-no-PID-or-time-namespaces",
            "status": "CandidateSourcesAvailable" if all(sources.values()) and local and vm == b"0"
                      else "UnsupportedBootScope",
            "real_reboot_product_chain": "NotTested"}


def retirement(binding, current, state, guards, *, journal_ok=True, occupied=False, retirement_path=None):
    """Prototype authority consumes capability; no public ACK or Released invented."""
    required = ("machine", "volume", "domain", "fileid", "incarnation")
    if (not current["capable"] or current["virtualized"] or current["remote"] or
            any(not binding.get(k) or binding[k] != current.get(k) for k in required) or
            not binding.get("boot") or binding["boot"] == current["boot"]):
        return "UnsupportedBootScope"
    for resource in state["resources"]:
        if resource["incarnation"] == binding["incarnation"] and resource["boot"] == binding["boot"]:
            resource.update(disposition="RetiredByBootChange", liveness="ImpossibleInCurrentBoot", active=False)
    if retirement_path is None:
        raise RuntimeError("durable resource disposition required before dropping guards")
    durable(retirement_path, {"schema":1,"binding":binding,"state":state})
    if read(retirement_path)["state"] != state:
        raise RuntimeError("resource disposition readback mismatch")
    for fd in guards:
        os.close(fd)
    guards.clear()
    return "FileGateBlocked" if not journal_ok or occupied else "ResourceGateSatisfied"


class OSPrototypes(unittest.TestCase):
    def test_public_occupancy_probe_is_not_a_general_fd_inventory(self):
        from ida_nexus import probe_database_state
        results = []
        for holds_lock in (False, True):
            path = ROOT / f"occupancy-{holds_lock}.i64"
            component = path.with_suffix(".id0")
            component.write_bytes(b"\0" * 19 + b"B-tree v2")
            fd = os.open(component, os.O_RDONLY)
            if holds_lock:
                fcntl.flock(fd, fcntl.LOCK_EX)
            a, b = socket.socketpair()
            pid = fork()
            if pid == 0:
                a.close()
                b.send(b"held")
                b.recv(1)
                os.close(fd)
                os._exit(0)
            b.close()
            self.assertEqual(a.recv(16), b"held")
            os.close(fd)
            try:
                state = probe_database_state(path)
                self.assertEqual(state["state"], "in_use" if holds_lock else "unpacked")
                results.append({"inherited_flock":holds_lock,"public_state":state["state"]})
            finally:
                a.send(b"x")
                a.close()
                self.assertEqual(os.waitpid(pid, 0)[1], 0)
        durable(ROOT / "occupancy.json", {"scope":"real-OS-private-id0-header", "cases":results,
            "conclusion":"detects inherited flock; cannot inventory an arbitrary open unlocked FD; grants no eligibility"})

    def test_owner_exits_but_detached_descendant_holds_lock(self):
        path = ROOT / "owner-gone.lock"
        parent, child = socket.socketpair()
        parent.settimeout(5)
        owner = fork()
        if owner == 0:
            parent.close()
            fd = lock(path)
            escaped = fork()
            if escaped == 0:
                os.setsid()
                child.send(json.dumps({"pid":os.getpid(), "sid":os.getsid(0),
                                       "pgid":os.getpgrp(), "birth":identity(os.getpid())}).encode())
                child.recv(1)
                os.close(fd)
                os._exit(0)
            os.close(fd)
            os._exit(0)
        child.close()
        record = json.loads(parent.recv(2048))
        try:
            self.assertEqual(os.waitpid(owner, 0)[1], 0)
            self.assertIsNone(identity(owner))
            self.assertEqual(identity(record["pid"]), record["birth"])
            self.assertEqual(record["sid"], record["pid"])
            self.assertTrue(blocked(path), "owner absence and its old session are insufficient")
        finally:
            parent.send(b"x")
            parent.close()
        deadline = time.monotonic() + 5
        while identity(record["pid"]) is not None and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertIsNone(identity(record["pid"]), "owned orphan must exit; host reaper owns waitpid")
        self.assertFalse(blocked(path))
        durable(ROOT / "owner-gone.json", {"owner_reaped":True, "escaped":record,
            "escaped_exited":True, "counterexample":True,
            "session_enumeration":"native sid/pgid observed; excludes escaped session by construction",
            "arbitrary_fd_transfer_enumeration":"Unsupported; no complete same-uid recipient inventory"})

    def test_birth_exec_and_platform_sources(self):
        case = ROOT / "birth"
        case.mkdir()
        # Direct child identity captured before exec, then same birth after exec.
        a, b = socket.socketpair()
        pid = fork()
        if pid == 0:
            a.close()
            os.set_inheritable(b.fileno(), True)
            b.send(b"before")
            b.recv(16)
            os.environ["R0_EXEC_FD"] = str(b.fileno())
            os.execv(sys.executable, [sys.executable, "-c",
                     "import os,socket; s=socket.socket(fileno=int(os.environ['R0_EXEC_FD'])); "
                     "s.send(b'after'); s.recv(16)"])
        b.close()
        try:
            self.assertEqual(a.recv(16), b"before")
            before = identity(pid)
            self.assertIsNotNone(before)
            a.send(b"exec")
            self.assertEqual(a.recv(16), b"after")
            self.assertEqual(identity(pid), before, "native birth survives exec")
            a.send(b"done")
            self.assertEqual(os.waitpid(pid, 0)[1], 0)
        finally:
            a.close()
        native = identity(os.getpid())
        capability = platform_capability()
        capability["birth_precision"] = "microsecond" if native["kind"] == "macos-libproc-v1" else "native-tick"
        capability["native_birth_layout"] = [ctypes.sizeof(ProcBsdInfo), 120, 128]
        durable(ROOT / "platform.json", capability)

    def test_fork_setsid_and_fd_in_flight_counterexamples(self):
        results = []
        for mode in ("fork", "setsid", "scm_rights", "exec_inherit"):
            path = ROOT / ("escape-" + mode)
            fd = lock(path)
            parent, child = socket.socketpair()
            if mode == "scm_rights":
                send_fd(parent, fd, {"scope": "private-lock"})
                os.close(fd)
                self.assertTrue(blocked(path), "FD in socket queue still owns OFD")
                received, _payload = recv_fd(child)
                os.close(received)
                self.assertFalse(blocked(path))
            else:
                pid = fork()
                if pid == 0:
                    parent.close()
                    if mode == "setsid":
                        os.setsid()
                    if mode == "exec_inherit":
                        os.set_inheritable(fd, True)
                        os.set_inheritable(child.fileno(), True)
                        os.execv(sys.executable, [sys.executable, "-c",
                            f"import socket,os; s=socket.socket(fileno={child.fileno()}); "
                            f"os.fstat({fd}); s.send(b'held'); s.recv(1)"])
                    child.send(b"held")
                    child.recv(1)
                    os.close(fd)
                    os._exit(0)
                child.close()
                try:
                    self.assertEqual(parent.recv(16), b"held")
                    os.close(fd)
                    self.assertTrue(blocked(path), "CLOEXEC does not prevent fork/setsid escape")
                    parent.send(b"x")
                    self.assertEqual(os.waitpid(pid, 0)[1], 0)
                    self.assertFalse(blocked(path))
                finally:
                    parent.close()
                results.append({"mode": mode, "held_after_sender_close": True})
                continue
            parent.close()
            child.close()
            results.append({"mode": mode, "held_in_transit": True})
        durable(ROOT / "escape.json", {"real_os": results,
                "same_boot_supported": False, "reason": "independent same-uid public SDK entry cannot be revoked"})

    def test_revocation_cross_helper_and_crash_boundaries(self):
        case = ROOT / "eligibility"
        case.mkdir()
        authority = case / "authority.json"
        durable(authority, {"owner": "prototype-owner", "epoch": 1, "allow": True})
        old = read(authority)
        # An actual other process owns the write, not a second cached bool.
        for boundary in ("before", "durable", "ack", "grant"):
            pid = fork()
            if pid == 0:
                with ordered(case / "root.lock", case / "target.lock"):
                    if boundary == "before":
                        os._exit(71)
                    value = read(authority)
                    value.update(allow=False, epoch=value["epoch"] + 1)
                    durable(authority, value)
                    if boundary == "durable":
                        os._exit(72)
                    durable(case / "revoke_ack.json", {"epoch": value["epoch"], "hash": digest(value)})
                    if boundary == "ack":
                        os._exit(73)
                    durable(case / "grant.json", {"epoch": value["epoch"], "purpose": "may_escape"})
                os._exit(0)
            status = os.waitpid(pid, 0)[1]
            self.assertEqual(os.waitstatus_to_exitcode(status), {"before":71,"durable":72,"ack":73,"grant":0}[boundary])
            if boundary != "grant":
                self.assertFalse((case / "grant.json").exists())
            if boundary != "before":
                with ordered(case / "root.lock", case / "target.lock"):
                    current = read(authority)
                    self.assertFalse(current["allow"] and current["epoch"] == old["epoch"],
                                     "helper A cached candidate must be rejected after helper B revoked")
        self.assertGreater(read(authority)["epoch"], old["epoch"])

    def test_u6_injected_retirement_keeps_history_and_releases_real_guards(self):
        binding = dict(machine="m", volume="v", domain="darwin-host", fileid=12,
                       incarnation="router-1", boot="old")
        current = dict(binding, boot="new", capable=True, virtualized=False, remote=False)
        # The prototype produces an unknown from an actual sent request and EOF,
        # not by injecting a Released or private N1 error/proof into a matrix.
        left, right = socket.socketpair()
        durable(ROOT / "u6-request.json", {"phase":"ReleaseRequested", "request":"one-shot"})
        left.send(b"one-shot release")
        self.assertEqual(right.recv(64), b"one-shot release")
        right.close()  # Public ACK was not delivered at this input boundary.
        self.assertEqual(left.recv(64), b"")
        left.close()
        history = dict(read(ROOT / "u6-request.json"), result="UnknownOutcome", ack=False,
                       execution_stopped=False, retry="NeverReplay")
        durable(ROOT / "u6-history.json", history)
        results = []
        for name, changes in (("same_boot", {"boot":"old"}), ("machine_copy", {"machine":"other"}),
                              ("volume_changed", {"volume":"other"}), ("namespace", {"domain":"other"}),
                              ("new_owner", {"incarnation":"router-new"}), ("replaced_file", {"fileid":13}),
                              ("vm_clone", {"virtualized":True}), ("remote", {"remote":True}),
                              ("missing", {"machine":""}), ("snapshot", {"capable":False})):
            state = {"history": history.copy(), "resources":[]}
            self.assertEqual(retirement(binding, dict(current, **changes), state, []), "UnsupportedBootScope")
            self.assertEqual(state["history"], history)
            results.append(name)
        for occupied, valid in ((False, True), (True, True), (False, False)):
            path = ROOT / f"u6-{occupied}-{valid}.lock"
            target = ROOT / f"u6-target-{occupied}-{valid}.lock"
            current_owner_fd = lock(target) if occupied else None
            guards = [lock(path, fcntl.LOCK_SH)]
            state = {"history":history.copy(), "resources":[
                dict(incarnation="router-1", boot="old", active=True),
                dict(incarnation="router-new", boot="new", active=True)]}
            disposition = ROOT / f"retirement-{occupied}-{valid}.json"
            outcome = retirement(binding, current, state, guards, journal_ok=valid, occupied=occupied,
                                 retirement_path=disposition)
            self.assertEqual(outcome, "ResourceGateSatisfied" if valid and not occupied else "FileGateBlocked")
            self.assertFalse(blocked(path), "old root SH actually closed")
            self.assertFalse(state["resources"][0]["active"])
            self.assertTrue(state["resources"][1]["active"])
            self.assertEqual(state["history"], history)
            self.assertEqual(read(disposition)["state"]["history"], history)
            self.assertEqual(blocked(target), occupied, "new owner target lock survives old resource retirement")
            if current_owner_fd is not None:
                os.close(current_owner_fd)
        durable(ROOT / "u6.json", {"scope":"injected-OS-input-prototype", "rejections":results,
                                   "history_preserved": True, "real_guards_released":True,
                                   "product_reboot":"NotTested"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
