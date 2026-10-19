"""Pause only the successor caller; helper and N1 predicates remain production."""
import json
import os
from pathlib import Path
import time


def install(custodian):
    if not os.environ.get('R4_PARENT_SCHEDULE'):
        return
    root = Path(os.environ['R3F2_BARRIER_ROOT'])
    original = custodian.helper_request

    def request(self, value):
        result = original(self, value)
        arrived = root/'helper_parent_retire.arrived'
        predecessor = json.loads(arrived.read_text()) if arrived.exists() else None
        if (value['kind'] == 'reserve_parent' and self.acquisition['ordinal'] == 2
                and predecessor is not None and predecessor['parent'] == self.acquisition['parent']):
            (root/'successor-reserved.json').write_text(json.dumps({
                'acquisition': self.acquisition,
                'retirement_still_paused': not (root/'helper_parent_retire.release').exists()}))
            deadline = time.monotonic() + 2
            while not (root/'helper-parent-retired.json').exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError('test schedule: predecessor retirement not observed')
                time.sleep(.001)
        return result

    custodian.helper_request = request
