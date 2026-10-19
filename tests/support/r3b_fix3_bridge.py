"""Scheduling inputs around the installed production bridge; SDK/helper stay real."""
import json
import os
from pathlib import Path
import runpy
import sys

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'tests/support'))
ROOT=Path(os.environ['R3A_CASE_ROOT'])
MODE=os.environ.get('R3F2_CASE','completion')


def instrument(runtime):
    if MODE=='completion':
        from acquisition import Custodian
        from r0_transport import barrier
        (ROOT/'fix2-instrumented.json').write_text(json.dumps({'mode':MODE,'module':Custodian.__module__,'source':__file__}))
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
        transact=Custodian.transact
        def observations(self,action,**fields):
            if action!='release_observation' or self.acquisition['purpose']!='final':
                return transact(self,action,**fields)
            import copy
            mode=os.environ.get('R3F3_CASE','')
            if mode=='identities':
                rows=[]
                for variant in ('lease','generation','ordinal','owner','watch','attempt'):
                    bad=copy.deepcopy(fields)
                    if variant=='lease':
                        bad['lease']['lease_id']+='-foreign'
                        bad['attempt']['target']['lease']=bad['lease']
                    elif variant=='generation':
                        bad['lease']['generation']+=1
                        bad['attempt']['target']['lease']=bad['lease']
                    elif variant=='ordinal':bad['acquisition']['ordinal']+=1
                    elif variant=='owner':bad['owner']['record_id']+='-foreign'
                    elif variant=='watch':bad['watch']+='-foreign'
                    else:bad['attempt']['sequence']+=1
                    try:transact(self,action,**bad)
                    except RuntimeError as exc:rows.append(dict(variant=variant,rejected=True,error=str(exc)))
                    else:raise AssertionError('foreign observation accepted: '+variant)
                (ROOT/'identity-rejections.json').write_text(json.dumps(rows,indent=2))
            if mode=='persistence':
                # A real writer rejects its bounded summary before persistence.
                # No forged receipt or sideband reply is injected.
                fields=copy.deepcopy(fields)
                fields['outcome']['controlled_summary_pressure']='x'*17000
            return transact(self,action,**fields)
        Custodian.transact=observations
    return runtime


actual_run=runpy.run_path

def installed(path,**options):
    result=actual_run(path,**options)
    if Path(path).name=='bootstrap.py' and 'load_entry' in result:
        load=result['load_entry']
        result['load_entry']=lambda:instrument(load())
    return result


runpy.run_path=installed
os.environ['R3F1_CASE']='f1-proof'
actual_run(str(REPO/'tests/support/r3b_fix1_bridge.py'),run_name='__main__')
