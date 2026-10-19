"""Actual final bridge/N1/writer; only native IDA inputs and fault timing vary."""
import copy
import json
import os
from pathlib import Path
import runpy
import sys

REPO = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ['R3A_CASE_ROOT'])
sys.path.insert(0, str(REPO / 'tests/support'))
actual_run = runpy.run_path


def instrument(runtime):
    from acquisition import Custodian
    from r0_transport import barrier
    actual = Custodian.transact

    def transact(self, action, **fields):
        if action != 'release_observation' or self.acquisition['purpose'] != 'final':
            return actual(self, action, **fields)
        (ROOT / 'production-preflight.json').write_text(json.dumps(fields, indent=2))
        barrier(ROOT, 'rr3-sideband', seconds=8)
        fields = copy.deepcopy(fields)
        fields['outcome']['controlled_summary_pressure'] = 'x' * 17000
        try:
            return actual(self, action, **fields)
        except Exception as exc:
            (ROOT / 'actual-writer-error.json').write_text(json.dumps({
                'type': type(exc).__name__, 'message': str(exc)}))
            raise

    Custodian.transact = transact
    send = runtime.Channel.send

    def terminal(self, event):
        if event.get('event') in ('not_sent', 'uncertain', 'released'):
            (ROOT / 'actual-terminal.json').write_text(json.dumps(event, indent=2))
        return send(self, event)

    runtime.Channel.send = terminal
    return runtime


def installed(path, **options):
    result = actual_run(path, **options)
    if Path(path).name == 'bootstrap.py' and 'load_entry' in result:
        load = result['load_entry']
        result['load_entry'] = lambda: instrument(load())
    return result


runpy.run_path = installed
actual_run(str(REPO / 'tests/support/r3a_bridge_fixture.py'), run_name='__main__')
