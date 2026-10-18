"""Real private IDA 9.5 owner-module compatibility through public SDK RPC."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'nexus_bridge'),str(REPO/'nexus_bridge/custody'),str(REPO/'tests/support')]
from bridge import guarded_source
from process_identity import identity
from ida_nexus import DatabaseHandle, DatabaseOpenOptions

ROOT = Path(os.environ['R2_CASE_ROOT'])
FILES = {'save_guard.py':'9246769e369f3c869ff9eaecb83ae7688a3b33ef547287391834a2e69442160e',
         'lifecycle.py':'ad717157bb88693a6b66ba3ec6547a0b418b48c05905e0421db2a1f3471c125a',
         'slices.py':'e09245f83953689f55cdb5db03998ee0f5fda34388f4f591000f13a2c06c7088'}
old = {}
for file,digest in FILES.items():
    data = subprocess.check_output(['git','show','f47dd2301b096f1c4b6643906f6e8976e8663469:nexus_bridge/'+file],cwd=REPO)
    assert hashlib.sha256(data).hexdigest() == digest
    (ROOT/file).write_bytes(data)
    old[file] = data.decode()

def record(value):
    with Path(os.environ['R2_LEDGER']).open('a') as output:
        output.write(json.dumps(value)+'\n'); output.flush(); os.fsync(output.fileno())

children=[]
def observe(stage,value):
    if stage == 'LaunchIntent':
        record({'kind':'intent','source':'r2-owner-sdk','suffix':value['suffix'],'target':str(ROOT/'tiny.i64')})
    if stage == 'Spawned':
        children.append(value['process'])
        record({'kind':'started','source':'r2-owner-sdk','pid':value['pid'],'identity':identity(value['pid'])})

handle = None
result = {}
try:
    handle = DatabaseHandle.open(os.environ['R2_REAL_INPUT'],options=DatabaseOpenOptions(
        output_database=ROOT/'tiny.i64',auto_analysis=False,startup_timeout=30,
        worker_env=dict(os.environ),worker_cwd=ROOT,acquisition_observer=observe))
    setup = "import sys,types\n"
    for name,file in zip(('_ida_cli_save_guard_v1','_ida_cli_release_protocol_v1','_ida_cli_nexus_slices_v1'),FILES):
        setup += f"module=types.ModuleType({name!r})\n"
        if file == 'slices.py':
            setup += "module.__dict__.update(sys=sys,types=types,_release_module=sys.modules['_ida_cli_release_protocol_v1'])\n"
        setup += f"exec({old[file]!r},module.__dict__)\nsys.modules[{name!r}]=module\n"
    setup += "sys.modules['_ida_cli_save_guard_v1'].begin({'record_id':'r2-real-legacy'})\nresult=True\n"
    assert handle.execute_python(setup,timeout=5)['result'] is True
    check = guarded_source("raise AssertionError('old coordinator or business executed')",{'method':'close'},refuse=False)
    protection = handle.execute_python(check,timeout=5)['result']
    assert protection['close_safe'] is True and not protection['save_guard_error'],protection
    result['known_v1_cleanup_only'] = protection
    for code in (guarded_source('result=True',{'method':'business'}),):
        try:
            handle.execute_python(code,timeout=5)
        except Exception as error:
            assert 'known v1 permits cleanup only' in str(error),str(error)
        else:
            raise AssertionError('old modules authorized new business')
    mutate = "import sys\nm=sys.modules['_ida_cli_nexus_slices_v1']\nexec(\"def unsafe_report():\\n    raise AssertionError('unknown report executed')\",m.__dict__)\nresult=True"
    assert handle.execute_python(mutate,timeout=5)['result'] is True
    try:
        handle.execute_python(check,timeout=5)
    except Exception as error:
        assert 'ProtocolMismatch/CleanupBlocked' in str(error),str(error)
        assert 'unknown report executed' not in str(error),str(error)
    else:
        raise AssertionError('unknown full combination allowed cleanup')
    result['unknown_rejected'] = True
    handle.execute_python("import sys\ndel sys.modules['_ida_cli_nexus_slices_v1'].unsafe_report",timeout=5)
    result['closed'] = handle.close_outcome(wait_for_database=True,timeout=20)
    assert result['closed']['lease_released'] and result['closed']['owner_released']
finally:
    if handle is not None:
        closed = handle.close_outcome(wait_for_database=True,timeout=5)
        assert closed['lease_released'] and closed['owner_released'],closed
    for child in children:
        status=child.wait(timeout=5)
        record({'kind':'reaped','source':'r2-owner-sdk','pid':child.pid,'exit':status})
        assert status == 0,status
    (ROOT/'owner-module-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
