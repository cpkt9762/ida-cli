"""Fresh-process installed target gate; no file/proof/owner substitution."""
import json
import runpy
import sys
import time
from pathlib import Path

installation,target_path=sys.argv[1:]
sys.argv=[str(Path(installation)/'bootstrap.py'),'target_journal']
entry=runpy.run_path(sys.argv[0],run_name='verified_fresh_gate')['load_entry']()
with entry.Target(target_path,create=False) as target,target.locked(deadline=time.monotonic()+1.5):
    journal=entry.Journal(target)
    journal.gate()
    from recovery_transaction import inspect_transactions
    print(json.dumps({'transactions':inspect_transactions(target),'accounting':journal.accounting()}))
