"""Scheduling inputs around the installed production bridge; SDK/helper stay real."""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import runpy

REPO=Path(__file__).resolve().parents[2]
ROOT=Path(os.environ['R3A_CASE_ROOT'])
MODE=os.environ.get('R3F2_CASE','completion')


def instrument(runtime):
    if MODE=='completion':
        from acquisition import Custodian
        from r0_transport import barrier
        (ROOT/'fix2-instrumented.json').write_text(json.dumps({'mode':MODE,'module':Custodian.__module__,'source':__file__}))
        original_drop=runtime.Bridge.drop_lifetime
        def drop(self,lease_id):
            with self.lock:
                custody=self.custodians.get(lease_id)
                if custody is not None and custody.acquisition['purpose']=='final':
                    temporary=ROOT/'late-cleanup-context.new'
                    temporary.write_text(json.dumps([self.identity,lease_id,self.lifetime_path]))
                    temporary.replace(ROOT/'late-cleanup-context.json')
            return original_drop(self,lease_id)
        runtime.Bridge.drop_lifetime=drop
        actual=Custodian.finish_without_handle
        def finish(self):
            if self.acquisition['purpose']=='auxiliary':
                barrier(ROOT,'before_sdk_finished',seconds=8)
            result=actual(self)
            if self.acquisition['purpose']=='auxiliary':
                value={'acquisition':self.acquisition,'sdk_entered':self.sdk_entered,
                       'has_handle':self.handle is not None,'has_lease':self.lease is not None,
                       'retained_child':any(child is self for child in self.bridge.cleanup_handles.values())}
                temporary=ROOT/'after_sdk_finished.new'
                temporary.write_text(json.dumps(value));temporary.replace(ROOT/'after_sdk_finished.json')
            return result
        Custodian.finish_without_handle=finish
    elif MODE.startswith('retry-'):
        from acquisition import Custodian
        from r0_transport import barrier,install_ida_inputs
        from ida_nexus._registry import InstanceIdentity,InstanceRegistration,REGISTRY_DIR
        import secrets
        original_gate=Custodian.gate
        moved=[False]
        @contextmanager
        def gate(self,target):
            if self.acquisition['purpose']=='verification' and not moved[0]:
                boundary=OWNERS[0]
                boundary.release_owner()
                boundary.path=Path(target)
                boundary.registration=InstanceRegistration(REGISTRY_DIR,
                    InstanceIdentity(str(boundary.path),str(boundary.path),'idalib',True),token=secrets.token_hex(24))
                boundary.instance=boundary.registration.publish(boundary.server.server_port)
                boundary.released=False
                install_ida_inputs(boundary.path)
                import ida_netnode
                ida_netnode.netnode.exist=staticmethod(lambda _:False)
                moved[0]=True
            with original_gate(self,target) as value:yield value
        Custodian.gate=gate
        original_retry=Custodian.next_retry
        def retry(self):
            value={'acquisition':self.acquisition,'watch':self.watch,'target':self.target_path}
            temporary=ROOT/'before_retry.new';temporary.write_text(json.dumps(value));temporary.replace(ROOT/'before_retry.json')
            barrier(ROOT,'before_retry',seconds=8)
            return original_retry(self)
        Custodian.next_retry=retry
        original_stage=Custodian.stage
        def stage(self,name,value):
            result=original_stage(self,name,value)
            if MODE=='retry-resolved' and self.acquisition['ordinal']==2 and name=='Resolved':
                temporary=ROOT/'retry_current.new';temporary.write_text(json.dumps({'acquisition':self.acquisition,'watch':self.watch,
                    'target':self.target_path,'verification_path':self.verification_path}));temporary.replace(ROOT/'retry_current.json')
                barrier(ROOT,'retry_current',seconds=8)
            return result
        Custodian.stage=stage
        original_obtained=Custodian.obtained
        def obtained(self,*args,**kwargs):
            result=original_obtained(self,*args,**kwargs)
            if MODE=='retry-acquired' and self.acquisition['ordinal']==2:
                temporary=ROOT/'retry_current.new';temporary.write_text(json.dumps({'acquisition':self.acquisition,'watch':self.watch,
                    'target':self.target_path,'verification_path':self.verification_path,'lease':self.lease}));temporary.replace(ROOT/'retry_current.json')
                barrier(ROOT,'retry_current',seconds=8)
            return result
        Custodian.obtained=obtained
    elif MODE=='publication':
        from acquisition import Custodian
        from r0_transport import barrier
        original_gate=Custodian.gate
        @contextmanager
        def gate(self,target):
            second=self.acquisition['parent']['operation_id']=='publication-racer'
            if second:barrier(ROOT,'publication_second_before_gate',seconds=8)
            with original_gate(self,target) as value:
                if second:(ROOT/'publication_second_admitted').touch()
                yield value
        Custodian.gate=gate
    return runtime


actual_run=runpy.run_path

def installed(path,**options):
    result=actual_run(path,**options)
    if Path(path).name=='bootstrap.py' and 'load_entry' in result:
        load=result['load_entry']
        result['load_entry']=lambda:instrument(load())
    return result


runpy.run_path=installed
if MODE=='completion':
    os.environ['R3F1_CASE']='f1-proof'
    actual_run(str(REPO/'tests/support/r3b_fix1_bridge.py'),run_name='__main__')
elif MODE=='publication':
    os.environ['N3_ENV_ROOT']=os.environ['R3F2_ENV']
    actual_run(str(REPO/'tests/support/nexus_client_fixture.py'),run_name='__main__')
else:
    from r0_transport import Boundary
    OWNERS=[]
    original_boundary=Boundary.__init__
    def boundary_init(self,*args,**kwargs):
        original_boundary(self,*args,**kwargs);OWNERS.append(self)
    Boundary.__init__=boundary_init
    os.environ['R3A_SCENARIO']='r9-multiple'
    os.environ['R3B_R9_FAILURES']='1'
    actual_run(str(REPO/'tests/support/r3a_bridge_fixture.py'),run_name='__main__')
