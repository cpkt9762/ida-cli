"""Readiness-only negative inputs: no business connection or physical acquisition."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'nexus_bridge'))
from config import startup_paths
from protocol import contract
from process_identity import identity

root = Path(os.environ['R5_ROOT'])
(root / 'process.json').write_text(json.dumps({'pid': os.getpid(), 'identity': identity(os.getpid())}))
protocol = contract()
fault = os.environ['R5_FAULT']
if fault.startswith('missing-') and fault.removeprefix('missing-') in protocol:
    protocol.pop(fault.removeprefix('missing-'))
elif fault == 'wrong-hash':
    protocol['client_hash'] = '0' * 64
elif fault == 'unknown-capability':
    protocol['capabilities'].append('custody_v1')
elif fault == 'duplicate-capability':
    protocol['capabilities'].append(protocol['capabilities'][0])
elif fault == 'missing-capability':
    protocol['capabilities'].pop()
elif fault == 'old-wire':
    protocol['wire'] = 1
elif fault == 'bool-wire':
    protocol['wire'] = True
elif fault == 'unknown-field':
    protocol['future'] = 1
elif fault in ('wrong-home', 'relative-state', 'sdk-version', 'domain-version'):
    pass
else:
    protocol[fault] += 1
paths = startup_paths()
if fault == 'wrong-home':
    paths['ida_cli_home'] += '/wrong'
if fault == 'relative-state':
    paths['state_dir'] = 'relative'
runtime = {'ida': [9, 5, 0], 'python': [3, 14, 7], 'nexus': [0, 13, 4], 'domain': [0, 5, 1]}
if fault == 'sdk-version':
    runtime['nexus'] = [0, 13, 3]
if fault == 'domain-version':
    runtime['domain'] = [0, 5, 0]
print(json.dumps({'ready': True, 'protocol': protocol, 'paths': paths, 'capabilities': {
    'runtime': runtime, 'methods': {'execute_python': 'may_write'}}}), flush=True)
# Remain a registered child until the parent's rejection guard reaps us.
sys.stdin.buffer.read()
