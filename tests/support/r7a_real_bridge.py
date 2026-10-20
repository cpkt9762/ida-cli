"""Real IDA Root losses at initial guard entry; custody and SDK remain production."""
import json
import hashlib
import os
from pathlib import Path
import runpy
import sys

from r2_process_ledger import install
install()
installation = Path(os.environ['IDA_CLI_BRIDGE_INSTALLATION'])
sys.argv = [str(installation / 'bootstrap.py'), 'bridge', *sys.argv[1:]]
runtime = runpy.run_path(sys.argv[0], run_name='r7a_verified_bridge')['load_entry']()
from acquisition import Custodian
original_execute = Custodian.execute
original_retry = Custodian.next_retry
original_obtain = Custodian.obtain
limit = int(os.environ.get('R7A_ROOT_FAILURES', '0'))
trace = Path(os.environ['R7A_ROOT_TRACE'])


def execute(self, purpose, code, **kwargs):
    if purpose == 'guard':
        row = {'ordinal': self.acquisition['ordinal'], 'target': self.target_path,
               'owner': self.handle.instance.record_id, 'injected': self.acquisition['ordinal'] <= limit}
        with trace.open('a') as output:
            output.write(json.dumps(row) + '\n')
        if row['injected']:
            code = "import ida_netnode\nida_netnode.netnode('Root Node',0,False).kill()\n" + code
    try:
        return original_execute(self, purpose, code, **kwargs)
    except Exception as error:
        with trace.open('a') as output:
            output.write(json.dumps({'purpose': purpose, 'error': str(error), 'type': type(error).__name__}) + '\n')
        raise


Custodian.execute = execute


def next_retry(self):
    with trace.open('a') as output:
        output.write(json.dumps({'before_retry_ordinal': self.acquisition['ordinal'],
            'packed_sha256': hashlib.sha256(Path(self.target_path).read_bytes()).hexdigest()}) + '\n')
    return original_retry(self)


Custodian.next_retry = next_retry
def obtain(self, Handle, Options, path, options, context):
    if os.environ.get('R7A_STARTUP_SCRIPT'):
        options = dict(options, script_file=os.environ['R7A_STARTUP_SCRIPT'], startup_timeout=2)
    return original_obtain(self, Handle, Options, path, options, context)


Custodian.obtain = obtain
runtime.main()

