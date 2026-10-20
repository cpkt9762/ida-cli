"""Private router process that leaves its exact helper after a named barrier."""
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'nexus_bridge/custody'), str(REPO / 'tests/support')]
from process_identity import identity
from proof_helper import request
from target_coordination import Target

root = Path(sys.argv[1])
clock = root / 'clock'
clock.write_bytes(bytes(8));clock.chmod(0o600)
(root / 'helper').mkdir(mode=0o700)
(root / 'target').mkdir(mode=0o700)
target = root / 'target/tiny.i64';target.write_bytes(b'private startup obligation')
with Target(target) as gate, gate.locked():
    coord = gate.key
endpoint = root / 'helper/h'
incarnation = 'orphan-fixture'
# Reproduce daemon's ignored SIGTERM disposition inherited across exec.
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with (root / 'helper.log').open('w') as output:
    child = subprocess.Popen([sys.executable, '-B', os.environ.get('FA_HELPER_SOURCE',str(REPO / 'nexus_bridge/custody/proof_helper.py')),
        str(endpoint), incarnation, '8'], env=dict(os.environ, IDA_CLI_HELPER_TEST_CLOCK=str(clock)),
        stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True)
    deadline = time.monotonic()+3
    while True:
        assert child.poll() is None, 'helper failed to start'
        try:
            request(endpoint, incarnation, {'kind':'heartbeat'})
            break
        except (FileNotFoundError, ConnectionRefusedError):
            assert time.monotonic()<deadline
            time.sleep(.002)
    request(endpoint,incarnation,{'kind':'reserve_parent','parent':'held'})
    request(endpoint,incarnation,{'kind':'launch_intent','watch':'pending','target':str(target),
        'coord_key':coord,'subscription_epoch':1,'acquisition':{'parent':'held','purpose':'final','ordinal':1},
        'launch':{'suffix':'no-owner-proof','target':str(target),'backend':'idalib'}})
    (root / 'ready.json').write_text(json.dumps({'pid':child.pid,'identity':identity(child.pid)}))
    while not (root / 'parent-exit').exists():
        assert time.monotonic()<deadline+3
        time.sleep(.002)
    os._exit(0)
