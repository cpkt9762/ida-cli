"""N5 strict batch/search comparison using the fixed N0 binary."""
import json
import os
from pathlib import Path
import shutil
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from compare_nexus_baseline import (Environment, Process, Candidate, digest,
                                  BASELINE_SHA, json_equal, normalized)

def main():
    env=Environment(Path(sys.argv[1])); baseline=Path(sys.argv[2]); binary=Path(sys.argv[3])
    assert digest(baseline)==BASELINE_SHA
    assert os.environ["IDA_TEST"]=="1"
    sample=env.root/"fixtures/n5-compare-old";shutil.copyfile(env.root/"fixtures/mini",sample)
    variables=env.variables() | {"IDA_CLI_HOME":str(env.root/"n5-baseline-home"),"TMPDIR":os.environ["TMPDIR"]}
    Path(variables["IDA_CLI_HOME"]).mkdir()
    old=Process(env,[str(baseline),"serve-worker"],variables,"n5-baseline")
    assert "result" in old.rpc("open",{"path":str(sample)})
    funcs=old.rpc("list_functions",{})["result"]["functions"]
    ea=funcs[0]["address"]
    other=funcs[1]["address"]
    new_sample=env.root/"fixtures/n5-compare-new";shutil.copyfile(sample,new_sample)
    new=Candidate(env,binary,new_sample,"n5-compare",transport="stdio",inline="8000000")
    matrix=[("run_auto_analysis",{}),
        ("batch_decompile",{"addresses":[ea,other,ea]}),
        ("batch_decompile",{"addresses":[]}),
        ("batch_decompile",{"addresses":[ea,"bad","0x0",other,True,None,-1]}),
        ("batch_decompile",{"addresses":json.dumps([ea,other])}),
        ("batch_decompile",{"addresses":["  "+ea+"  ",int(ea,16)]}),
        ("search_pseudocode",{"pattern":"return"}),
        ("search_pseudocode",{"pattern":"return","limit":1}),
        ("search_pseudocode",{"pattern":"return","limit":0}),
        ("search_pseudocode",{"pattern":"N5_NO_MATCH_雪","limit":100}),
        ("search_pseudocode",{"pattern":"","limit":100})]
    fault=("import ida_hexrays\nassert ida_hexrays.init_hexrays_plugin()\n"
        "class N5Fault(ida_hexrays.Hexrays_Hooks):\n"
        "    def microcode(self,mba):\n"
        f"        return ida_hexrays.MERR_BADSP if mba.entry_ea=={int(ea,16)} else 0\n"
        "N5_FAULT=N5Fault()\nassert N5_FAULT.hook()")
    matrix += [("run_script",{"code":fault}),
        ("batch_decompile",{"addresses":[ea,other,ea]}),
        ("search_pseudocode",{"pattern":"return","limit":100}),
        ("run_script",{"code":"assert N5_FAULT.unhook(); del N5_FAULT"})]
    observations=[]
    try:
        for method,params in matrix:
            expected=old.rpc(method,params);expected.pop("jsonrpc",None);expected.pop("id",None)
            actual=new.direct(method,params)
            assert json_equal(normalized(expected,sample),normalized(actual,new_sample)),(method,params,expected,actual)
            if method=="batch_decompile" and params.get("addresses")==[ea,other,ea] and len(observations)>11:
                assert expected["result"][0]["success"] is False
                assert expected["result"][1]["success"] is True
            observations.append({"method":method,"params":params,"baseline":expected,"nexus":actual,"status":"PASS"})
    finally:
        (env.root/"n5-comparison.json").write_text(json.dumps({"baseline_sha256":digest(baseline),"observations":observations},ensure_ascii=False,indent=2)+"\n")
        old.rpc("close");old.rpc("shutdown");old.wait();new.stop()
    assert len(observations)==15
    (env.root/"N5-compare-result.json").write_text(json.dumps({"status":"PASS","case":"N5-compare","comparisons":len(observations)}))
if __name__=="__main__":main()
