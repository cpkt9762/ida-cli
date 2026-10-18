"""Actual production cleanup issuer on private files; no simulated N1/proof."""
import hashlib
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'nexus_bridge'))
from bridge import Bridge

root=Path(sys.argv[1]);probe=root/'probe.i64'
def metadata(path):
    value=path.lstat()
    return {'identity':[value.st_dev,value.st_ino],'size':value.st_size,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
bridge=Bridge.__new__(Bridge)
bridge.lock=threading.RLock()
bridge.verification_probes={str(probe):SimpleNamespace(verification_seed=metadata(probe), acquisition={"parent":{"client_id":"file-fixture","operation_id":"file-issuer","request_id":"file-issuer","task_id":None}})}
bridge.finish_verification_copy(str(probe))
print(json.dumps({'issuer':'actual Bridge.finish_verification_copy','directory':str(root),
                  'probe_present':probe.exists(),'marker_size':(root/'closed').stat().st_size,
                  'scope':'private copied file, real Target/Journal/public SDK idle probe; no IDA launch or N1 exit proof supplied'}))
