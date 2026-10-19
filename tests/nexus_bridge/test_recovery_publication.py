"""Golden partial-final boundary against either frozen or current production."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

REPO=Path(os.environ.get('R4_PRODUCT_SOURCE',Path(__file__).resolve().parents[2]))
sys.path[:0]=[str(REPO/'nexus_bridge/custody'),str(REPO/'nexus_bridge')]


def child(case):
    import cache_store
    cache_store.public_owner_probe=lambda _:None
    sys.modules['ida_nexus']=types.SimpleNamespace(probe_database_state=lambda *_a,**_k:{'state':'crashed'})
    from open_recovery import Snapshot
    payload=case/'payload'
    payload.mkdir(mode=0o700)
    target=payload/'input.i64'
    original=b'original-complete-component'*150000
    target.write_bytes(original)
    target.chmod(0o600)
    snapshot=Snapshot(case/'home',target,float('inf'),owner_probe=lambda _:None)
    target.write_bytes(b'failed complete component')
    observed=snapshot.failed(1)
    (case/'input.json').write_text(json.dumps({'sha256':hashlib.sha256(original).hexdigest(),
        'snapshot':str(snapshot.path),'production':str(REPO)}))
    actual=Path.open
    class InterruptedFinal:
        def __init__(self,stream):self.stream=stream
        def __enter__(self):return self
        def __exit__(self,*args):return self.stream.__exit__(*args)
        def write(self,data):
            self.stream.write(data)
            self.stream.flush()
            os.fsync(self.stream.fileno())
            # The real production writer has exposed its first complete write
            # chunk at the final path. Exit before subsequent chunks, no
            # production predicate/result/proof is changed by this wrapper.
            os._exit(96)
        def __getattr__(self,name):return getattr(self.stream,name)
    def open_file(path,*args,**kwargs):
        stream=actual(path,*args,**kwargs)
        return InterruptedFinal(stream) if path==target and args and args[0]=='xb' else stream
    Path.open=open_file
    snapshot.rollback(observed)


class Publication(unittest.TestCase):
    def test_process_exit_cannot_expose_partial_component_at_final_path(self):
        root=Path(tempfile.mkdtemp(prefix='partial-final-',dir=os.environ['R3A_CASE_ROOT']))
        argv=['timeout','15s',sys.executable,'-B',__file__,'--child',str(root)]
        before=subprocess.check_output(['uptime'],text=True).strip()
        result=subprocess.run(argv,capture_output=True,text=True,check=False)
        (root/'process.json').write_text(json.dumps(dict(argv=argv,exit=result.returncode,stdout=result.stdout,
            stderr=result.stderr,uptime_before=before,uptime_after=subprocess.check_output(['uptime'],text=True).strip())))
        self.assertIn(result.returncode,(0,96),result.stderr)
        data=json.loads((root/'input.json').read_text())
        target=root/'payload/input.i64'
        actual=hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
        self.assertIn(actual,(None,data['sha256'],hashlib.sha256(b'failed complete component').hexdigest()),
                      'partial component exposed at final path after actual writer exit')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(Path(sys.argv[2]))
    else:unittest.main(verbosity=2)
