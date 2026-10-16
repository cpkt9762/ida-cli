"""Test-only identity instrumentation and an independent public Nexus client."""
import http.client
import importlib.metadata
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import threading
import types
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests/support"))
from nexus_env import Environment

env = Environment(Path(os.environ["N3_ENV_ROOT"]))
# No signal handler changes in the bridge's business threads. Persist creation
# intent before Popen and the exact birth before returning it to Nexus.
real_popen = subprocess.Popen
proxy = types.SimpleNamespace(**vars(subprocess))
def owned_popen(command, **options):
    intent = env._begin_creation(command)
    child = real_popen(command, **options)
    try:
        env._record(child, command)
        env._finish_creation(intent)
    except BaseException:
        child.kill()
        child.wait(timeout=3)
        raise
    env.children.append(child)
    return child
proxy.Popen = owned_popen
# Record even a dependency-failure bridge before importing Nexus.
env._record(types.SimpleNamespace(pid=os.getpid()), [sys.executable, __file__, *sys.argv[1:]])
try:
    import ida_nexus._resolver as resolver
except ImportError:
    if len(sys.argv) > 1 and sys.argv[1] == "external":
        raise
    runpy.run_path(str(REPO / "nexus_bridge/bridge.py"), run_name="__main__")
    raise AssertionError("bridge main must exit")
resolver.subprocess = proxy
# Popen remains owned until waitpid observes exit; the production Nexus client
# deliberately detaches its owner. This test-only observer sends no signals.
def reap_workers():
    while True:
        for child in list(env.children):
            child.poll()
        threading.Event().wait(0.02)
threading.Thread(target=reap_workers, daemon=True).start()

if len(sys.argv) > 1 and sys.argv[1] == "external":
    from ida_nexus import DatabaseHandle, DatabaseOpenOptions
    handle = DatabaseHandle.open(sys.argv[2], options=DatabaseOpenOptions(
        startup_timeout=10, worker_env=env.variables(), worker_cwd=env.root))
    print(json.dumps({"event":"external_opened", "instance_id":handle.instance.record_id,
                      "pid":handle.instance.pid}), flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            if request["command"] == "close":
                handle.close(wait_for_database=True, timeout=10)
                print(json.dumps({"event":"external_closed"}), flush=True)
                break
            result = handle.execute_python(request["code"], timeout=None)
            print(json.dumps(result), flush=True)
    finally:
        handle.close(wait_for_database=True, timeout=10)
else:
    if os.environ.get('N7_R9_LOSS_ON_OPEN') == '1' or os.environ.get('N7_R9_OPEN_LOSSES'):
        from ida_nexus import DatabaseHandle
        original_open = DatabaseHandle.open
        loss_count = [0]
        loss_limit = int(os.environ.get('N7_R9_OPEN_LOSSES', '3'))

        def lose_root_on_open(_class, *args, **kwargs):
            handle = original_open(*args, **kwargs)
            loss_count[0] += 1
            if loss_count[0] <= loss_limit:
                handle.execute_python("import ida_netnode\nida_netnode.netnode('Root Node', 0, False).kill()", timeout=5)
            return handle

        DatabaseHandle.open = classmethod(lose_root_on_open)
    if os.environ.get("N3_LEASE_FAULT"):
        from ida_nexus import DatabaseHandle
        original_open_lease = DatabaseHandle._open_lease
        first = [True]
        def open_lease(handle, instance):
            connection, response, stream = original_open_lease(handle, instance)
            if first[0]:
                first[0] = False
                readline = response.readline
                def faulted_readline(*args, **kwargs):
                    line = readline(*args, **kwargs)
                    if (env.root / "lease-fault.inject").exists():
                        (env.root / "lease-fault.observed").touch()
                        raise http.client.RemoteDisconnected("injected isolated first-lease SSE failure")
                    return line
                response.readline = faulted_readline
            return connection, response, stream
        # Fault only one actual HTTP response at its read boundary. Never change
        # the server or restore client fields; sibling SSE/execute sockets remain real.
        DatabaseHandle._open_lease = open_lease
    if os.environ.get("N3_WRONG_VERSION"):
        original_version = importlib.metadata.version
        importlib.metadata.version = lambda name: "0.13.3" if name == "ida-nexus" else original_version(name)
    runtime = runpy.run_path(os.environ.get("N6_TEST_BRIDGE_SOURCE", str(REPO / "nexus_bridge/bridge.py")), run_name="n4_fixture")
    bridge_init = runtime["Bridge"].__init__
    def registered_init(self, business, control, capacity):
        # F2/P2-b: parent endpoints predate initialization. Record before any
        # child import/connect can block; l is journalled at its actual bind.
        for path in (business, control):
            env.record_socket(path, os.getppid())
        import socket
        original_bind = socket.socket.bind
        lifetime = str(Path(business).with_name("l"))
        def registered_bind(endpoint, address):
            original_bind(endpoint, address)
            if address == lifetime:
                env.record_socket(address, os.getpid())
        with patch.object(socket.socket, "bind", registered_bind):
            bridge_init(self, business, control, capacity)
    runtime["Bridge"].__init__ = registered_init
    send = runtime["Channel"].send
    def boundary_send(self, message):
        publish = os.environ.get('N7_PUBLISH_BARRIER')
        if publish and message.get('event') == 'opened':
            barrier = Path(publish)
            barrier.with_suffix('.arrived').write_text(json.dumps({'idb_path':message['idb_path']}))
            import time
            deadline = time.monotonic() + 15
            while not barrier.with_suffix('.release').exists():
                if time.monotonic() > deadline:
                    raise TimeoutError('N7 before index publication barrier')
                threading.Event().wait(.005)
        arm = env.root / "n5-boundary.arm"
        if message.get("event") == "yielded" and arm.exists():
            arm.unlink()
            (env.root / "n5-boundary.identity").write_text(json.dumps(message["attempt"]["target"]["identity"]))
            (env.root / "n5-boundary.observed").touch()
            import time
            end = time.monotonic() + 15
            while not (env.root / "n5-boundary.release").exists():
                if time.monotonic() >= end:
                    raise TimeoutError("test slice boundary release missing")
                threading.Event().wait(0.005)
        return send(self, message)
    runtime["Channel"].send = boundary_send
    # P2-3: a real socketpair relay stops consuming bytes, while the reverse
    # grant/read lane and the separate control socket remain fully operational.
    import socket
    import time
    channel_write = runtime["Channel"].write
    def stalled_write(self):
        original_socket = self.socket
        if not original_socket.getpeername().endswith('/b'):
            return channel_write(self)
        sender, consumer = socket.socketpair()
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        def armed():
            arm = env.root / "n5-backpressure.arm"
            return arm.exists() and arm.read_text() == str(os.getpid())
        inflight = [0]
        delivered = [0]
        def relay():
            try:
                while not self.stopped.is_set():
                    if armed():
                        (env.root / "n5-backpressure.consumer-paused").touch()
                        end = time.monotonic() + 15
                        while not (env.root / "n5-backpressure.release").exists():
                            if time.monotonic() >= end:
                                raise TimeoutError("real consumer release missing")
                            threading.Event().wait(.005)
                    raw = consumer.recv(65536)
                    if not raw:
                        return
                    original_socket.sendall(raw)
                    delivered[0] += len(raw)
            finally:
                consumer.close()
        threading.Thread(target=relay, daemon=True).start()
        class RelaySocket:
            def __getattr__(self, name):
                return getattr(original_socket, name)
            def sendall(self, raw):
                inflight[0] = len(raw)
                sender.sendall(raw)  # Actual kernel write, blocked by full OS buffer.
                inflight[0] = 0
            def close(self):
                sender.close()
                original_socket.close()
        def fill():
            while not (armed() and inflight[0] > 1000000
                       and (env.root / "n5-backpressure.consumer-paused").exists()):
                if self.stopped.wait(.005):
                    return
            # Fill the actual unchanged production output queue behind the
            # blocked large public Nexus result, plus one producer blocked in put.
            for index in range(self.output.maxsize):
                send(self, {"event":"local_status", "id":"n5-pressure", "index":index})
            pending = threading.Event()
            returned = threading.Event()
            def extra():
                pending.set()
                send(self, {"event":"local_status", "id":"n5-pressure", "index":self.output.maxsize})
                returned.set()
            threading.Thread(target=extra, daemon=True).start()
            assert pending.wait(1)
            assert self.output.full() and not returned.is_set()
            (env.root / "n5-backpressure.observed").write_text(json.dumps({
                "capacity":self.output.maxsize, "queued":self.output.qsize(),
                "blocked_send_bytes":inflight[0], "producer_returned":returned.is_set(),
                "consumer_paused":True, "delivered_before_pause":delivered[0]}))
        threading.Thread(target=fill, daemon=True).start()
        self.socket = RelaySocket()
        return channel_write(self)
    runtime["Channel"].write = stalled_write
    invoke = runtime["Bridge"].invoke
    subscriptions = {}
    def record_task(self, channel, attempt, command, deadline, public_started):
        if command.get("method") == "_n5_cleanup":
            (env.root / "n5-cleanup-executed").write_text(json.dumps(command["params"]))
        action = command.get("params", {}).get("n5_subscription")
        if action:
            lease = command["identity"]["lease"]
            handle = self.handles[lease["lease_id"]][1]
            if action == "start":
                subscriptions[lease["lease_id"]] = handle.subscribe_idb_events()
            else:
                subscription = subscriptions.pop(lease["lease_id"])
                event = next(subscription)
                subscription.close()
                (env.root / "n5-subscription-drained").write_text(str(event))
        identity = command.get("identity", {})
        if command.get("command") == "execute" and identity.get("task_id"):
            with (env.root / "task-identities.jsonl").open("a") as output:
                output.write(json.dumps(identity) + "\n")
        return invoke(self, channel, attempt, command, deadline, public_started)
    if (env.root / "e22-reverify-save.inject").exists():
        close_verification = runtime["Bridge"].close_verification
        def save_active_original(self, verification, probe, deadline):
            close_verification(self, verification, probe, deadline)
            # Force the real owner to save between the probe and final hash.
            # Only the second verification has an already-owned original.
            original = Path(verification).parents[1]
            with self.lock:
                handles = [handle for _, handle in self.handles.values()
                           if Path(handle.instance.idb_path).parent == original]
            if handles:
                handle = handles[0]
                before = Path(handle.instance.idb_path).read_bytes()
                result = handle.execute_python(
                    "import ida_bytes, ida_funcs, ida_loader\n"
                    "assert ida_bytes.set_cmt(ida_funcs.getn_func(0).start_ea, 'F3 concurrent save', True)\n"
                    "assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)\n"
                    "result = True", timeout=10)
                assert result["result"] is True
                assert Path(handle.instance.idb_path).read_bytes() != before, "real save must change packed bytes"
                (env.root / "e22-reverify-save.observed").write_text(str(handle.instance.idb_path))
        runtime["Bridge"].close_verification = save_active_original
    runtime["Bridge"].invoke = record_task
    runtime["main"]()
