"""Frozen v1 producer over a private real-format IDB; no native launch."""
import json
import os
from pathlib import Path
import shutil
import sys

root=Path(sys.argv[1])
baseline=Path(os.environ['R4_BASELINE_SOURCE'])
sys.path[:0]=[str(baseline/'nexus_bridge/custody'),str(baseline/'nexus_bridge')]
from open_recovery import Snapshot
from target_coordination import Target

payload=root/'payload'
payload.mkdir(mode=0o700)
path=payload/'input.i64'
shutil.copyfile(os.environ['R3F1_SAMPLE'],path)
path.chmod(0o600)
with Target(path) as target,target.locked():
    snapshot=Snapshot(root/'oldhome/idb',path,float('inf'),coordination=target)
    replacement=payload/'replacement'
    shutil.copyfile(path,replacement)
    replacement.chmod(0o600)
    os.replace(replacement,path)
    snapshot.failed(1)
(root/'reference.json').write_text(json.dumps({'target':str(path),'legacy':str(snapshot.path),
    'recovery_id':snapshot.path.name}))
