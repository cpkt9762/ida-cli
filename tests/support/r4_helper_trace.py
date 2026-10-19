"""Feature-only helper scheduling evidence; all production handlers run unchanged."""
import json
import os
from pathlib import Path
import runpy
import sys
import time

bootstrap = sys.argv.pop(1)
sys.argv[0] = bootstrap
entry = runpy.run_path(bootstrap, run_name='verified_helper_trace')['load_entry']()
receive = entry.Observer.receive


def traced(self, value):
    started = time.monotonic_ns()
    before = json.loads(json.dumps(self.parents))
    error = None
    result = None
    try:
        result = receive(self, value)
        return result
    except BaseException as exc:
        error = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        row = dict(started=started, ended=time.monotonic_ns(), kind=value['kind'],
                   parent=value.get('parent'), acquisition=value.get('acquisition'), watch=value.get('watch'),
                   before=before, after=self.parents, error=error,
                   result={k: result[k] for k in ('retired', 'reserved') if result and k in result},
                   items={k: v['acquisition'] for k, v in self.items.items()})
        with Path(os.environ['R4_HELPER_TRACE']).open('a') as output:
            output.write(json.dumps(row) + '\n')
        root = Path(os.environ['R3F2_BARRIER_ROOT'])
        if value['kind'] == 'retire_parent' and (root/'helper_parent_retire.release').exists():
            (root/'helper-parent-retired.json').write_text(json.dumps(row))


entry.Observer.receive = traced
entry.main()
