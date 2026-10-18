"""Review fault barriers around installed production; SDK/helper/N1 stay real."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys

ROOT=Path(os.environ['R3A_CASE_ROOT'])
MODE=os.environ.get('R3F1_CASE','')
REPO=Path(__file__).resolve().parents[2]
from r0_transport import barrier


def fingerprint(path):
    p=Path(path);info=p.lstat()
    return {'identity':[info.st_dev,info.st_ino],'size':info.st_size,
            'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}


def instrument(runtime):
    from acquisition import Custodian
    if MODE.startswith('f1-'):
        actual=Custodian.transact
        failed=[False]
        def delivery_failure(self, action, **fields):
            if action=='observe' and self.acquisition['purpose']=='auxiliary' and not failed[0]:
                failed[0]=True
                (ROOT/'failed-child.json').write_text(json.dumps({'acquisition':self.acquisition,
                    'watch':self.watch,'receipt':self.subscription}))
                raise RuntimeError('controlled auxiliary observe NotSent after helper subscribe')
            return actual(self,action,**fields)
        Custodian.transact=delivery_failure
        reconcile=Custodian.reconcile_outcome
        held=[False]
        def outside_gate(self, outcome):
            if self.acquisition['purpose']=='auxiliary' and self.target is None and not held[0]:
                held[0]=True
                barrier(ROOT,'compensation',seconds=8)
            return reconcile(self,outcome)
        Custodian.reconcile_outcome=outside_gate
    if MODE.startswith('f2-'):
        path=ROOT/'rejected.i64'
        path.write_bytes(b'R0 external database-state input')
        actual_stage=Custodian.stage
        def failed_stage(self,stage,value):
            if self.acquisition['parent']['operation_id']=='bad':
                with (ROOT/'bad-sdk-stages.jsonl').open('a') as log:log.write(json.dumps({'stage':stage})+'\n')
                if MODE=='f2-resolve' and stage=='BeforeResolve':
                    raise RuntimeError('controlled pre-resolver failure')
            return actual_stage(self,stage,value)
        Custodian.stage=failed_stage
        if MODE=='f2-probe':
            import ida_nexus
            probe=ida_nexus.probe_database_state
            def failed_probe(path,**options):
                if Path(path).name=='rejected.i64':raise RuntimeError('controlled pre-SDK probe failure')
                return probe(path,**options)
            ida_nexus.probe_database_state=failed_probe
        if MODE=='f2-options':
            initialize=runtime.Bridge.__init__
            def failed_options_init(self,*args,**kwargs):
                initialize(self,*args,**kwargs)
                actual_options=self.Options
                def options(**fields):
                    callback=fields.get('acquisition_observer')
                    if callback is not None and callback.__self__.acquisition['parent']['operation_id']=='bad':
                        raise ValueError('controlled pre-SDK Options failure')
                    return actual_options(**fields)
                self.Options=options
            runtime.Bridge.__init__=failed_options_init
    if MODE=='f2-gate':
        from target_coordination import Target
        path=ROOT/'rejected.i64'
        path.write_bytes(b'R0 external database-state input')
        with Target(path) as target,target.locked():
            target.directory.durable('custody.json',{'schema':'intentional malformed negative gate input'})
    if MODE=='real-probe-trace':
        init=Custodian.__init__
        def trace_initial(self,*args,**kwargs):
            init(self,*args,**kwargs)
            if self.verification_path:
                (ROOT/'probe-before.json').write_text(json.dumps(fingerprint(self.verification_path)))
        Custodian.__init__=trace_initial
        finish=runtime.Bridge.finish_verification_copy
        def trace_finish(self,path):
            (ROOT/'probe-after.json').write_text(json.dumps(fingerprint(path)))
            return finish(self,path)
        runtime.Bridge.finish_verification_copy=trace_finish
    return runtime


actual_run=runpy.run_path

def installed_entry(path, **options):
    result=actual_run(path,**options)
    if Path(path).name=='bootstrap.py' and 'load_entry' in result:
        load=result['load_entry']
        result['load_entry']=lambda:instrument(load())
    return result


runpy.run_path=installed_entry
if MODE=='real-probe-trace':
    installation=Path(os.environ['IDA_CLI_BRIDGE_INSTALLATION'])
    sys.argv=[str(installation/'bootstrap.py'),'bridge',*sys.argv[1:]]
    installed_entry(sys.argv[0],run_name='verified_fix1')['load_entry']().main()
else:
    actual_run(str(REPO/'tests/support/r2_multi_bridge.py'),run_name='__main__')
