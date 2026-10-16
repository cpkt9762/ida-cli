"""Trusted test processor; copies normally and blocks one input with a descendant."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nexus_env import Environment

source, output = map(Path, sys.argv[1:])
if source.name != 'blocked-native':
    shutil.copyfile(source, output)
else:
    env = Environment(Path(os.environ['N3_ENV_ROOT']))
    env._record(type('Identity', (), {'pid':os.getpid()})(), [sys.executable, __file__, *sys.argv[1:]])
    code = "import sys,threading; from pathlib import Path; Path(sys.argv[1]).write_text('ready'); threading.Event().wait(120); Path(sys.argv[2]).write_bytes(b'late overwrite')"
    marker = env.root/'descendant.ready'
    command = [sys.executable, '-c', code, str(marker), str(output)]
    child = env.spawn(lambda: subprocess.Popen(command), command)
    (env.root/'processor.started').write_text(json.dumps({'pid':os.getpid(), 'descendant':child.pid, 'output':str(output)}))
    child.wait()
    threading.Event().wait(120)
