"""Actual installed offline executor, with a process-exit boundary only."""
import os
from pathlib import Path
import runpy
import sys

installation,stage,*arguments=sys.argv[1:]
sys.argv=[str(Path(installation)/'bootstrap.py'),'open_recovery',*arguments]
entry=runpy.run_path(sys.argv[0],run_name='verified_offline_exit')['load_entry']()
import recovery_maintenance
import recovery_files


def boundary(actual,_detail):
    if actual==stage:os._exit(99)


def files(action,actual,detail):
    if action=='rename' and actual=='after':boundary('after_rename',detail)


recovery_maintenance.boundary=boundary
recovery_files.boundary=files
raise SystemExit(entry.maintenance_main())
