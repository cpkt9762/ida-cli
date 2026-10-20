"""Run the unmodified production bridge over controlled external HTTP/IDA inputs."""
import os
from pathlib import Path
import socket
import sys
import threading

from process_identity import identity
from r0_common import durable
from r0_transport import Boundary
from ida_nexus import wait_database_released

ROOT = Path(os.environ["R0_CASE_ROOT"])
SCENARIO = os.environ["R0_SCENARIO"]
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "nexus_bridge"))
import bridge


def main():
    durable(ROOT / "process.json", {"pid":os.getpid(), "identity":identity(os.getpid())})
    with Boundary(ROOT, SCENARIO) as boundary:
        stopped = threading.Event()
        reopened = False
        def inputs():
            nonlocal reopened
            disconnected = False
            while not stopped.wait(.005):
                if (ROOT / "owner-release").exists() and not (ROOT / "owner-released").exists():
                    boundary.release_owner()
                    durable(ROOT / "owner-proof.json", {"public_lifetime_released":
                        wait_database_released(boundary.instance, timeout=0)})
                    (ROOT / "owner-released").touch()
                if (ROOT / "owner-reopen").exists() and not reopened:
                    from ida_nexus._registry import InstanceIdentity, InstanceRegistration, REGISTRY_DIR
                    import secrets
                    boundary.registration = InstanceRegistration(REGISTRY_DIR,
                        InstanceIdentity(str(boundary.path), str(boundary.path), "idalib", True), token=secrets.token_hex(24))
                    boundary.instance = boundary.registration.publish(boundary.server.server_port)
                    boundary.released = False
                    reopened = True
                    (ROOT / "owner-reopened").touch()
                if not disconnected and (ROOT / "disconnect-primary").exists():
                    with boundary.lock:
                        stream = next(iter(boundary.streams.values()))
                        stream.shutdown(socket.SHUT_RDWR)
                    disconnected = True
                    (ROOT / "primary-input-disconnected").touch()
                if (ROOT / "snapshot-request").exists():
                    with boundary.lock:
                        durable(ROOT / "snapshot.json", {"physical_leases":len(boundary.leases),
                            "release_requests":sum(x["endpoint"] == "/release_lease" for x in boundary.requests),
                            "analysis_failed":boundary.analysis_failed})
        observer = threading.Thread(target=inputs, daemon=True)
        observer.start()
        try:
            return bridge.main()
        finally:
            stopped.set()
            observer.join(2)
            durable(ROOT / "fixture-audit.json", {"input_observer_stopped":not observer.is_alive(),
                "no_public_api_or_guard_replacement":True, "registry_owned":boundary.instance.record_id})


if __name__ == "__main__":
    os._exit(main())
