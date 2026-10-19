"""Actual IDA/SDK bridge with one explicit Root observation fault in native IDA.

No Nexus outcome/proof is substituted. This is not natural Root corruption.
The save guard, close, public lifetime and file recovery executor stay production.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys

from r2_process_ledger import install
from r4_helper_schedule import install as schedule_parent
install()

root=Path(os.environ['R3A_CASE_ROOT'])
wanted=Path(os.environ['R4_REAL_R9_TARGET']).resolve()
installation=Path(os.environ['IDA_CLI_BRIDGE_INSTALLATION'])
sys.argv=[str(installation/'bootstrap.py'),'bridge',*sys.argv[1:]]
runtime=runpy.run_path(sys.argv[0],run_name='verified_real_r4')['load_entry']()
from acquisition import Custodian
schedule_parent(Custodian)
from recovery_transaction import Transaction
from recovery_files import inventory
original_execute=Custodian.execute
original_retry=Custodian.next_retry
original_expect=Transaction.expect_unrelated


def expect_unrelated(self, expected, **kwargs):
    try:
        return original_expect(self, expected, **kwargs)
    except Exception:
        (root/'r4-directory-mismatch.json').write_text(json.dumps({
            'recovery_id': self.recovery_id, 'expected': expected,
            'actual': inventory(self.parent_directory(), self.target.directory),
            'backups': self.data['backups']}))
        raise


def execute(self,purpose,code,**kwargs):
    if (purpose=='guard' and Path(self.target_path)==wanted and self.acquisition['ordinal']==1
            and not (root/'r4-native-root-fault.json').exists()):
        (root/'r4-native-root-fault.json').write_text(json.dumps({'acquisition':self.acquisition,
            'lease':self.lease,'snapshot':str(self.file_snapshot.path),
            'scope':'one injected IDAPython Root observation in actual native IDA; no natural corruption claim'}))
        code='import ida_netnode\nida_netnode.netnode.exist=staticmethod(lambda _name:False)\n'+code
    return original_execute(self,purpose,code,**kwargs)


def retry(self):
    injected = root/'r4-native-root-fault.json'
    binding = json.loads(injected.read_text()) if injected.exists() else None
    if (binding is not None and self.acquisition == binding['acquisition']
            and self.file_snapshot is not None):
        snapshot=self.file_snapshot
        record=json.loads((snapshot.path/'recovery.json').read_text())
        actual={name:hashlib.sha256((wanted.parent/name).read_bytes()).hexdigest() for name in record['snapshot_files']}
        (root/'r4-restored-before-next.json').write_text(json.dumps({'record':record,'actual_sha256':actual}))
    return original_retry(self)


Custodian.execute=execute
Custodian.next_retry=retry
Transaction.expect_unrelated=expect_unrelated
runtime.main()
