"""Instrument only the task-owned sbx/idat chain, pausing actual IDAPython."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nexus_env import Environment

env = Environment(Path(os.environ['N3_ENV_ROOT']))
mode, *args = sys.argv[1:]
if mode == 'sbx':
    env._record(type('Owned', (), {'pid': os.getpid()})(), [os.environ['N7B_REAL_SBX'], *args])
    variables = os.environ.copy()
    variables.pop('IDADIR', None)
    variables['IDAT'] = str(env.root/'fixtures/idat-barrier')
    output = args[args.index('--output')+1]
    (env.root/'cancel-sbx.started').write_text(json.dumps({'pid': os.getpid(), 'output': output}))
    os.execve(os.environ['N7B_REAL_SBX'], [os.environ['N7B_REAL_SBX'], *args], variables)
elif mode == 'idat':
    scripts = [i for i, arg in enumerate(args) if arg.startswith('-S')]
    assert len(scripts) == 1, args
    index = scripts[0]
    source = Path(args[index][2:])
    paused = source.with_name('n7b-paused.py')
    marker = env.root/'cancel-idat.started'
    fifo = env.root/'cancel-idat.release'
    prefix = (
        'import sys, os, json\nfrom pathlib import Path\n'
        f'sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n'
        'from nexus_env import Environment\n'
        f'env = Environment(Path({str(env.root)!r}))\n'
        "env._record(type('Owned', (), {'pid':os.getpid()})(), ['actual-idat-IDAPython-barrier'])\n"
        f'Path({str(marker)!r}).write_text(json.dumps({{"pid":os.getpid()}}))\n'
        f'with open({str(fifo)!r}) as gate: gate.read()\n'
    )
    paused.write_text(prefix + source.read_text())
    args[index] = '-S'+str(paused)
    os.execv(os.environ['N7B_REAL_IDAT'], [os.environ['N7B_REAL_IDAT'], *args])
else:
    raise AssertionError(mode)
