#!/usr/bin/env python3
"""N6 real IDA contracts against a fixed, independently hashed N0 binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from compare_nexus_baseline import (Environment, Process, Candidate, BASELINE_SHA,
                                    digest, json_equal, normalized, allocated_member_equal)
import runpy
METADATA_SOURCE = Path(__file__).resolve().parents[1] / 'nexus_bridge/metadata.py'
idb_fingerprint = runpy.run_path(str(METADATA_SOURCE))['idb_fingerprint']


def edit_cases(ea, funcs):
    return [
        ('list_segments', {}),
        ('list_imports', {}),
        ('list_exports', {}),
        ('list_entry_points', {}),
        ('list_globals', {}),
        ('list_strings', {}),
        ('get_xrefs_to_string', {'query':'N6-no-match'}),
        ('get_address_info', {'address':ea}),
        ('batch_lookup_functions', {'queries':['main',ea,'missing','0b100']}),
        ('export_functions', {}),
        ('get_basic_blocks', {'address':ea}),
        ('get_callees', {'address':ea}),
        ('get_callers', {'address':funcs[0]['address']}),
        ('build_callgraph', {'address':ea,'max_depth':10}),
        ('find_control_flow_paths', {'start':ea,'end':ea}),
        ('build_xref_matrix', {'addrs':[ea,funcs[0]['address']]}),
        ('scan_memory_table', {'base_address':ea,'count':2,'stride':4}),
        ('diff_pseudocode', {'addr1':ea,'addr2':funcs[0]['address']}),
        ('get_pseudocode_at', {'address':ea}),
        ('get_pseudocode_at', {'address':ea,'end_address':hex(int(ea,16)+16)}),
        ('search_bytes', {'patterns':'00 00','limit':2}),
        ('search_bytes', {'patterns':['00 00','bad-pattern'],'limit':2}),
        ('search_text', {'text':'main','max_results':2}),
        ('search_imm', {'imm':2,'max_results':2}),
        ('search_instructions', {'patterns':['RET'],'limit':2}),
        ('search_instruction_operands', {'patterns':['SP'],'limit':2}),
        ('get_function_prototype', {'address':ea}),
        ('infer_type', {'address':ea}),
        ('get_stack_frame', {'address':ea}),
        ('declare_c_type', {'decl':'struct N6Pair { int left; int right; };'}),
        ('declare_c_type', {'decl':'typedef unsigned int N6Word;'}),
        ('list_local_types', {'filter':'N6'}),
        ('list_structs', {'filter':'N6'}),
        ('get_struct_info', {'name':'N6Pair'}),
        ('read_struct_at_address', {'address':ea,'name':'N6Pair'}),
        ('get_xrefs_to_struct_field', {'name':'N6Pair','member_name':'left'}),
        ('create_enum', {'decl':'enum N6Choice { N6_ZERO=0, N6_SEVEN=7 };'}),
        ('list_enums', {'filter':'N6'}),
        ('set_function_prototype', {'address':ea,'prototype':'int main(int count, char **args);'}),
        ('get_function_prototype', {'address':ea}),
        ('apply_type', {'address':ea,'decl':'int main(int count, char **args);'}),
        ('set_comment', {'address':ea,'comment':'N6 comment 雪'}),
        ('set_function_comment', {'address':ea,'comment':'N6 function'}),
        ('rename_symbol', {'address':ea,'name':'n6_main'}),
        ('batch_rename', {'renames':[{'address':ea,'new_name':'n6_main_2'},{'current_name':'missing','new_name':'n6_no'},{'address':ea,'new_name':'n6_main'}]}),
        ('get_function_by_name', {'name':'n6_main'}),
        ('read_bytes', {'address':ea,'size':8}),
        ('read_int', {'address':ea,'size':4}),
        ('read_string', {'address':ea,'max_len':8}),
        ('read_global_variable', {'query':ea}),
        ('read_global_variable', {'query':'N6_missing'}),
        ('load_debug_info', {'path':'/N6-missing-symbols'}),
        ('load_debug_info', {}),
        ('rename_local_variable', {'func_address':ea,'lvar_name':'count','new_name':'n6_count'}),
        ('set_local_variable_type', {'func_address':ea,'lvar_name':'n6_count','type_str':'unsigned int'}),
        ('set_decompiler_comment', {'func_address':ea,'address':ea,'comment':'N6 pseudocode'}),
        ('decompile_function', {'address':ea}),
        ('rename_local_variable', {'func_address':ea,'lvar_name':'N6_missing','new_name':'n6_no'}),
        ('set_local_variable_type', {'func_address':ea,'lvar_name':'N6_missing','type_str':'not a C type'}),
        ('set_decompiler_comment', {'func_address':'0x0','address':'0x0','comment':'bad'}),
        ('patch_assembly', {'address':ea,'line':'NOP'}),
        ('read_bytes', {'address':ea,'size':8}),
        ('patch_bytes', {'address':ea,'bytes':'00 00 00 00'}),
        ('read_bytes', {'address':ea,'size':8}),
        ('create_stack_variable', {'address':ea,'offset':-4,'var_name':'n6_slot','decl':'int'}),
        ('get_stack_frame', {'address':ea}),
        ('rename_stack_variable', {'func_address':ea,'name':'n6_slot','new_name':'n6_renamed'}),
        ('set_stack_variable_type', {'func_address':ea,'name':'n6_renamed','type_decl':'unsigned int'}),
        ('get_stack_frame', {'address':ea}),
        ('delete_stack_variable', {'address':ea,'var_name':'n6_renamed'}),
        ('get_stack_frame', {'address':ea}),
        ('declare_c_type', {'decl':'not a C declaration ;'}),
        ('apply_type', {'address':ea,'decl':'not a C declaration ;'})]


def script_result(response):
    value = response["result"]
    assert value["success"], value
    assert value["stderr"] == "", value
    return json.loads(value["stdout"])


def metadata_checkpoint(env, old, new, label):
    row = {'checkpoint': label}
    try:
        expected = old.call('get_database_info', {}) if isinstance(old, Candidate) else old.rpc('get_database_info')
        row['baseline'] = expected
        actual = new.call('get_database_info', {})
        row['nexus'] = actual
        assert json_equal(normalized({'result': expected['result']}, env.root/'fixtures/mini'),
                          normalized({'result': actual['result']}, env.root/'fixtures/mini')), (expected, actual)
        for answer in (expected, actual):
            assert answer['result']['input_file_size'] == (env.root/'fixtures/mini').stat().st_size
            assert answer['result']['sha256'] == digest(env.root/'fixtures/mini')
    except Exception as exc:
        row['failure_type'] = type(exc).__name__
        row['disk_at_failure'] = [idb_fingerprint(x) for x in (old.sample, new.sample)] if isinstance(old, Candidate) else [idb_fingerprint(new.sample)]
        try:
            context = {'requested_path': str(new.sample), 'forensic_hash': True}
            for record in env.root.glob('*-prebuilt-idb.json'):
                for item in json.loads(record.read_text()).get('before_open_fingerprints', []):
                    if item['path'] == str(new.sample):
                        context['before_open'] = item
            code = METADATA_SOURCE.read_text() + f'\nimport json\nprint(json.dumps(input_metadata_evidence({context!r}, stage="failed N6 checkpoint")))'
            row['owner_evidence'] = script_result(new.call('run_script', {'code': code}))
        except Exception as exc:
            row['evidence_error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        with (env.root/'n6-metadata-checkpoints.jsonl').open('a') as output:
            output.write(json.dumps(row) + '\n')


def member_witness(client, result, direct):
    tid = result["tid"]
    code = f"""import json, ida_typeinf as ti
parent, member = ti.tinfo_t(), ti.udm_t()
index = parent.get_udm_by_tid(member, {int(tid,16)})
assert index >= 0
udt = ti.udt_type_data_t()
assert parent.get_udt_details(udt, ti.GTD_CALC_LAYOUT)
print(json.dumps({{"lookup_tid":hex(parent.get_udm_tid(index)),
 "member_ids":[hex(parent.get_udm_tid(i)) for i in range(len(udt))],
 "entity":{{"struct_name":parent.get_type_name(), "struct_ordinal":parent.get_ordinal(),
 "member_index":index, "member_name":member.name, "member_type":member.type.dstr(),
 "member_offset_bits":member.offset, "member_size_bits":member.size}}}}))
"""
    rpc = client.direct if direct else client.rpc
    witness = script_result(rpc("run_script", {"code":code}))
    repeat = rpc("get_xrefs_to_struct_field", {"name":result["struct_name"], "member_name":result["member_name"]})
    witness["repeat_tid"] = repeat["result"]["tid"]
    return witness


def prebuilt_pair(env, binary, label="n6", source=None):
    seed = Candidate(env, binary, source or env.root/"fixtures/mini", label+"-seed", transport="stdio", inline="8000000")
    try:
        original = str(source or env.root/"fixtures/mini")
        saved = seed.call("run_script", {"code":f"""import hashlib, json, ida_auto, ida_ida, ida_loader, ida_nalt
ida_ida.inf_set_auto_enabled(True)
ida_auto.enable_auto(True)
assert ida_auto.auto_wait()
ida_nalt.set_root_filename({original!r})
assert ida_nalt.get_input_file_path() == {original!r}
assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)
print(json.dumps({{"input_file_path":ida_nalt.get_input_file_path(),
 "input_file_size":ida_nalt.retrieve_input_file_size(),
 "md5":ida_nalt.retrieve_input_file_md5().hex(),
 "sha256":ida_nalt.retrieve_input_file_sha256().hex()}}))
"""})
        metadata = script_result(saved)
        assert metadata["input_file_size"] == Path(original).stat().st_size, metadata
        assert metadata["sha256"] == digest(original), metadata
    finally:
        seed.stop()
    seeds = [*(seed.home/"idb").glob("*.i64"),
             *(seed.home/"idb").glob("generations/*/input.i64")]
    assert len(seeds) == 1, seeds
    samples = [env.root/f"fixtures/{label}-old.i64", env.root/f"fixtures/{label}-new.i64"]
    for sample in samples:
        shutil.copyfile(seeds[0], sample)
    hashes = [digest(p) for p in [seeds[0], *samples]]
    assert len(set(hashes)) == 1
    (env.root/(label+"-prebuilt-idb.json")).write_text(json.dumps({"seed":str(seeds[0]),
        "copies":list(map(str,samples)), "sha256":hashes,
        "analyzed_seed_metadata":metadata,
        "before_open_fingerprints":[idb_fingerprint(p) for p in [seeds[0], *samples]]}, indent=2)+"\n")
    return samples


def baseline_prebuilt_open(env, baseline, sample, label, *, native=False):
    """Only the frozen N0 side may reopen twice for the exact upstream r9 signature.

    The analyzed seed and unchanged packed bytes are prerequisites, not fields
    fabricated for the comparator. A corrupt/changed file is never restored here.
    This runs before any comparison edits and never retries a Nexus operation.
    """
    assert digest(baseline) == BASELINE_SHA, 'not the fixed N0 baseline'
    records = [json.loads(path.read_text()) for path in env.root.glob('*-prebuilt-idb.json')]
    record, = [item for item in records if str(sample) in item['copies']]
    metadata = record['analyzed_seed_metadata']
    original = Path(metadata['input_file_path'])
    assert metadata['input_file_size'] == original.stat().st_size > 0
    assert metadata['sha256'] == digest(original) != '0' * 64
    assert metadata['md5'] == hashlib.md5(original.read_bytes()).hexdigest() != '0' * 32
    packed_hash = record['sha256'][0]
    assert digest(record['seed']) == digest(sample) == packed_hash

    def stop(client):
        if native:
            assert 'result' in client.rpc('close')
            assert 'result' in client.rpc('shutdown')
            client.wait()
        else:
            client.stop()

    for attempt in range(3):
        client = None
        row = {'label': label, 'attempt': attempt, 'time_ns': time.time_ns(),
               'uptime': subprocess.check_output(['timeout', '5s', 'uptime'], text=True).strip(),
               'sample': str(sample), 'verified_packed_sha256': packed_hash}
        try:
            assert digest(record['seed']) == digest(sample) == packed_hash
            if native:
                home = env.root / f'{label}-home-{attempt}'
                home.mkdir(mode=0o700)
                variables = env.variables() | {'TMPDIR': os.environ['TMPDIR'], 'IDA_CLI_HOME': str(home)}
                client = Process(env, [str(baseline), 'serve-worker'], variables, f'{label}-{attempt}')
                row['open_response'] = client.rpc('open', {'path': str(sample)})
                assert 'result' in row['open_response'], row
                response = client.rpc('get_database_info')
            else:
                client = Candidate(env, baseline, sample, f'{label}-{attempt}', transport='stdio', inline='8000000')
                row['open_response'] = client.open_result
                response = client.call('get_database_info', {})
            row['metadata_response'] = response
            value = response.get('result', {})
            missing = (value.get('input_file_path') == '' and value.get('input_file_size') == 0
                       and value.get('md5') == '0' * 32 and value.get('sha256') == '0' * 64)
            row['r9_signature'] = missing
            if not missing:
                return client
            row['disk_sha256_before_close'] = digest(sample)
            assert row['disk_sha256_before_close'] == packed_hash, 'baseline disk changed; no reopen'
            closing, client = client, None
            stop(closing)
            row['disk_sha256_after_close'] = digest(sample)
            assert row['disk_sha256_after_close'] == packed_hash, 'baseline close changed disk; no reopen'
            assert attempt < 2, 'baseline r9 persists after two extra opens; comparison fails'
            row['reopen_scheduled'] = True
        except BaseException as exc:
            row['error'] = type(exc).__name__ + ': ' + str(exc)
            if client is not None:
                try:
                    stop(client)
                except Exception as cleanup_error:
                    row['cleanup_error'] = type(cleanup_error).__name__ + ': ' + str(cleanup_error)
            raise
        finally:
            with (env.root / 'baseline-reopens.jsonl').open('a') as output:
                output.write(json.dumps(row) + '\n')


def comparison(env, baseline, binary):
    assert digest(baseline) == BASELINE_SHA
    old = new = None
    records = []
    samples = prebuilt_pair(env, binary)
    try:
        old = baseline_prebuilt_open(env, baseline, samples[0], 'n6-baseline', native=True)
        funcs = old.rpc("list_functions", {})["result"]["functions"]
        ea = next(x["address"] for x in funcs if x["name"] in ("main", "_main"))
        new = Candidate(env, binary, samples[1], "n6-candidate", transport="stdio", inline="8000000")
        metadata_checkpoint(env, old, new, 'E04-N6 reopened prebuilt copies')
        for method, params in edit_cases(ea, funcs):
            expected = old.rpc(method, params)
            expected.pop("jsonrpc", None)
            expected.pop("id", None)
            # load_debug_info.path names symbols; raw CLI's legacy path slot
            # selects an IDB instead. Exercise the public MCP schema here.
            via_mcp = method == "load_debug_info"
            actual = new.call(method, params) if via_mcp else new.direct(method, params)
            witnesses = None
            id_exception = False
            if "error" in expected:
                equal = actual.get("error") == ("IDA error: " if via_mcp else "Error: ") + expected["error"]["message"]
                if not via_mcp:
                    equal = equal and actual.get("exit") == 1
            else:
                equal = json_equal(normalized(expected, samples[0]), normalized(actual, samples[1]), method)
                if method == "get_xrefs_to_struct_field" and "result" in actual:
                    witnesses = [member_witness(old, expected["result"], False), member_witness(new, actual["result"], True)]
                    identity_equal = allocated_member_equal(expected, {"result":actual["result"]}, method, witnesses)
                    assert identity_equal, ("member identity evidence invalid", witnesses)
                    id_exception = not equal
                    equal = equal or identity_equal
            records.append({"method":method, "params":params, "baseline":expected, "nexus":actual,
                            "allocated_id_witnesses":witnesses, "allocated_id_exception":id_exception,
                            "status":"PASS" if equal else "FAIL"})
    finally:
        (env.root/"n6-comparison.json").write_text(json.dumps(records, ensure_ascii=False, indent=2)+"\n")
        try:
            if old:
                old.rpc("close")
                old.rpc("shutdown")
                old.wait()
        finally:
            if new:
                new.stop()
    failures = [r for r in records if r["status"] != "PASS"]
    assert not failures, json.dumps(failures)
    return {"comparisons":len(records), "methods":sorted({r["method"] for r in records}),
            "allocated_id_exceptions":[r["method"] for r in records if r["allocated_id_exception"]],
            "assembly":assembly(env, baseline, binary),
            **compatibility_edges(env, baseline, binary)}


def assembly(env, baseline, binary):
    """ARM64 N0 cannot assemble NOP; also require real x86 patch success."""
    source = env.root/"fixtures/mini-x86"
    command = ["timeout", "30s", "clang", "-arch", "x86_64", "-O0", "-fno-inline",
               str(env.root/"fixtures/mini.c"), "-o", str(source)]
    before = subprocess.check_output(["uptime"], text=True).strip()
    compiled = subprocess.run(command, capture_output=True, text=True)
    (env.root/"n6-x86-build.json").write_text(json.dumps({"command":command, "exit":compiled.returncode,
        "stdout":compiled.stdout,"stderr":compiled.stderr,"uptime_before":before,
        "uptime_after":subprocess.check_output(["uptime"], text=True).strip()}, indent=2)+"\n")
    assert compiled.returncode == 0, compiled.stderr
    samples = prebuilt_pair(env, binary, "n6-x86", source)
    old = new = None
    records = []
    try:
        old = baseline_prebuilt_open(env, baseline, samples[0], 'n6-x86-baseline')
        new = Candidate(env, binary, samples[1], "n6-x86-nexus", transport="stdio", inline="8000000")
        ea = next(f["address"] for f in old.call("list_functions",{})["result"]["functions"]
                  if f["name"] in ("main","_main"))
        for method, params in [("patch_assembly",{"address":ea,"line":"NOP"}),
                               ("read_bytes",{"address":ea,"size":1})]:
            expected, actual = old.call(method,params), new.call(method,params)
            assert "result" in expected and "result" in actual, (expected,actual)
            assert json_equal(expected, actual, method), (expected,actual)
            records.append({"method":method,"params":params,"baseline":expected,"nexus":actual,"status":"PASS"})
        assert records[-1]["nexus"]["result"] == {"address":ea,"bytes":"90","length":1}, records
    finally:
        (env.root/"n6-x86-comparison.json").write_text(json.dumps(records, indent=2)+"\n")
        try:
            if old: old.stop()
        finally:
            if new: new.stop()
    return {"architecture":"x86_64","comparisons":len(records),"successful_assembly":True}


def persistence(env, binary):
    sample = env.root/"fixtures/n6-e20"
    shutil.copyfile(env.root/"fixtures/mini", sample)
    client = Candidate(env, binary, sample, "n6-e20-write", transport="stdio", inline="8000000")
    evidence = {"writes":[]}
    try:
        funcs = client.call("list_functions", {})["result"]["functions"]
        ea = next(f["address"] for f in funcs if f["name"] in ("main", "_main"))
        patch = next(f["address"] for f in funcs if f["address"] != ea)
        writes = [
            ("rename_symbol", {"address":ea, "name":"n6_persist_main"}),
            ("set_comment", {"address":ea, "comment":"N6 persistent 雪"}),
            ("set_function_comment", {"address":ea, "comment":"N6 function persistent", "repeatable":True}),
            ("declare_c_type", {"decl":"struct N6Persistent { int left; unsigned int right; };"}),
            ("declare_c_type", {"decl":"typedef unsigned int N6PersistWord;"}),
            ("apply_type", {"address":ea, "decl":"int main(int persist_arg, char **persist_argv);"}),
            ("create_enum", {"decl":"enum N6PersistentEnum { N6_FIRST=1, N6_LAST=7 };"}),
            ("create_stack_variable", {"address":ea, "offset":-4, "var_name":"n6_persist_slot", "decl":"int"}),
            ("rename_stack_variable", {"func_address":ea, "name":"n6_persist_slot", "new_name":"n6_persist_renamed"}),
            ("set_stack_variable_type", {"func_address":ea, "name":"n6_persist_renamed", "type_decl":"unsigned int"}),
            ("patch_bytes", {"address":patch, "bytes":"11 22 33 44"})]
        for method, params in writes:
            answer = client.call(method, params)
            assert "result" in answer, (method, answer)
            if method == "apply_type":
                assert answer["result"]["applied"] is True
            if method in ("declare_c_type", "create_enum", "create_stack_variable"):
                assert answer["result"]["code"] == 0
            evidence["writes"].append({"method":method, "params":params, "response":answer})
        partial = client.call("batch_rename", {"renames":[{"address":ea,"new_name":"n6_persist_after_error"},
            {"current_name":"N6_MISSING","new_name":"n6_impossible"}]})
        assert [r["success"] for r in partial["result"]["results"]] == [True, False], partial
        evidence["partial_batch"] = partial
        error = client.call("run_script", {"code":f"import ida_bytes\nassert ida_bytes.set_cmt({int(ea,16)}, 'N6 modified before error', True)\nraise RuntimeError('N6 deliberate failure after write')"})
        assert "N6 deliberate failure after write" in json.dumps(error), error
        evidence["partial_error"] = error
        readback = f"""import json, ida_bytes, ida_funcs, ida_name, ida_nalt, ida_typeinf as ti
type_info = ti.tinfo_t()
assert ida_nalt.get_tinfo(type_info, {int(ea,16)})
enum_info, word_info = ti.tinfo_t(), ti.tinfo_t()
assert enum_info.get_named_type(None, 'N6PersistentEnum')
assert word_info.get_named_type(None, 'N6PersistWord')
enum_members = ti.enum_type_data_t()
assert enum_info.get_enum_details(enum_members)
print(json.dumps({{"name":ida_name.get_name({int(ea,16)}),
 "comment":ida_bytes.get_cmt({int(ea,16)}, False),
 "partial_comment":ida_bytes.get_cmt({int(ea,16)}, True),
 "function_comment":ida_funcs.get_func_cmt_ea({int(ea,16)}, True),
 "type":type_info.dstr(), "patch":ida_bytes.get_bytes({int(patch,16)}, 4).hex(),
 "enum_members":[[m.name,m.value] for m in enum_members],
 "typedef_unsigned_int":word_info.is_uint() and word_info.is_unsigned(),
 "typedef_size":word_info.get_size()}}))
"""
        def snapshot(c):
            answer = {"facts":script_result(c.call("run_script", {"code":readback})),
                      "struct":c.call("get_struct_info", {"name":"N6Persistent"})["result"],
                      "enum":c.call("list_enums", {"filter":"N6PersistentEnum"})["result"],
                      "types":c.call("list_local_types", {"filter":"N6PersistWord"})["result"],
                      "frame":c.call("get_stack_frame", {"address":ea})["result"]}
            facts = answer["facts"]
            assert facts["name"] == "n6_persist_after_error" and facts["comment"] == "N6 persistent 雪"
            assert facts["partial_comment"] == "N6 modified before error"
            assert facts["function_comment"] == "N6 function persistent"
            assert "persist_arg" in facts["type"] and facts["patch"] == "11223344", facts
            assert facts["enum_members"] == [["N6_FIRST",1],["N6_LAST",7]], facts
            assert facts["typedef_unsigned_int"] is True and facts["typedef_size"] == 4, facts
            assert answer["struct"]["size"] == 8 and [m["name"] for m in answer["struct"]["members"]] == ["left", "right"]
            assert answer["enum"]["total"] == 1 and answer["types"]["total"] == 1
            member = next(m for m in answer["frame"]["members"] if m["name"] == "n6_persist_renamed")
            assert member["type_name"] == "unsigned int" and member["size"] == 4
            return answer
        evidence["before_close"] = snapshot(client)
        saved = client.call("run_script", {"code":"import ida_loader; assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)"})
        assert saved["result"]["success"], saved
        evidence["explicit_save"] = saved
        client.stop()
        idbs = [*(client.home/"idb").glob("*.i64"),
                *(client.home/"idb").glob("generations/*/input.i64")]
        assert len(idbs) == 1
        evidence["saved_idb_sha256"] = digest(idbs[0])
        client = Candidate(env, binary, idbs[0], "n6-e20-reopen", transport="stdio", inline="8000000")
        evidence["after_reopen"] = snapshot(client)
        assert json_equal(evidence["before_close"], evidence["after_reopen"]), evidence
    finally:
        client.stop()
        (env.root/"e20-persistence.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+"\n")
    return {"categories":["rename", "comments", "patch", "types", "struct", "enum", "stack"],
            "partial_batch_preserved":True, "partial_error_preserved":True, "save_close_reopen":True}


def tool_contracts(env, baseline, binary):
    import re
    repo = Path(__file__).resolve().parents[1]
    source = (repo/"src/tool_registry.rs").read_text().split('pub static TOOL_REGISTRY: &[ToolInfo] = &[',1)[1].split('];',1)[0]
    tools = []
    for block in re.findall(r'ToolInfo \{(.*?)\n    \},', source, re.S):
        name = re.search(r'name: "([^"]+)"',block)[1]
        example = json.loads(re.search(r'example: r#"(.*?)"#',block,re.S)[1])
        aliases = re.findall(r'"([^"]+)"', re.search(r'aliases: &\[(.*?)\]',block,re.S)[1])
        tools.append((name,example,aliases))
    assert len(tools) == 107
    samples = prebuilt_pair(env, binary, "n6-tools")
    old = new = None
    records = []
    try:
        old = baseline_prebuilt_open(env, baseline, samples[0], 'n6-tool-baseline')
        new = Candidate(env, binary, samples[1], "n6-tool-nexus", transport="stdio", inline="8000000")
        metadata_checkpoint(env, old, new, "reopened prebuilt copies")
        funcs = old.call("list_functions", {})["result"]["functions"]
        ea = next(f["address"] for f in funcs if f["name"] in ("main", "_main"))
        other = next(f["address"] for f in funcs if f["address"] != ea)
        # Compare explicit equivalent analysis state, rather than racing the
        # asynchronous Nexus startup against the native synchronous open.
        setup = "import ida_typeinf as ti, ida_ida, ida_auto\nida_ida.inf_set_auto_enabled(True)\nida_auto.enable_auto(True)\nassert ida_auto.auto_wait()\nassert ti.idc_parse_types('struct N6ToolPair { int left; int right; };', ti.PT_SIL) == 0"
        for c in (old,new):
            assert c.call("run_script", {"code":setup})["result"]["success"]
        metadata_checkpoint(env, old, new, "after equivalent analysis and type setup")
        overrides = {
          # The frozen N0 binary predates line_addresses. Compare its original
          # plain request; the new option has separate live CLI/MCP coverage.
          "decompile_function":{"address":ea},
          "get_function_by_name":{"name":"main"}, "batch_lookup_functions":{"queries":[ea,"main","missing"]},
          "build_xref_matrix":{"addrs":[ea,other]}, "build_callgraph":{"address":ea,"max_depth":2},
          "find_control_flow_paths":{"start":ea,"end":ea}, "read_global_variable":{"query":ea},
          "read_bytes":{"address":ea,"size":8}, "load_debug_info":{"path":"/N6-missing-symbols"},
          "set_comment":{"address":ea,"comment":"N6 tool"}, "set_function_comment":{"address":ea,"comment":"N6 function"},
          "rename_symbol":{"address":other,"name":"n6_tool_add"}, "batch_rename":{"renames":[{"address":other,"new_name":"n6_tool_add"}]},
          "apply_type":{"address":ea,"decl":"int main(int count, char **args);"}, "infer_type":{"address":ea},
          "create_stack_variable":{"address":ea,"offset":-4,"var_name":"n6_tool_slot","decl":"int"},
          "delete_stack_variable":{"address":ea,"var_name":"n6_tool_slot"},
          "get_struct_info":{"name":"N6ToolPair"}, "read_struct_at_address":{"address":ea,"name":"N6ToolPair"},
          "get_xrefs_to_struct_field":{"name":"N6ToolPair","member_name":"left"},
          "search_structs":{"filter":"N6ToolPair"}, "patch_assembly":{"address":ea,"line":"NOP"},
          "patch_bytes":{"address":other,"bytes":"1f 20 03 d5"},
          "get_task_status":{"task_id":"N6-missing-task"}, "run_script":{"code":"print('N6 tool script')"},
          "set_function_prototype":{"address":ea,"prototype":"int main(int count, char **args);"},
          "rename_local_variable":{"func_address":ea,"lvar_name":"count","new_name":"n6_count"},
          "set_local_variable_type":{"func_address":ea,"lvar_name":"n6_count","type_str":"unsigned int"},
          "rename_stack_variable":{"func_address":ea,"name":"var_8","new_name":"n6_stack"},
          "set_stack_variable_type":{"func_address":ea,"name":"n6_stack","type_decl":"unsigned int"},
          "decompile_structured":{"address":ea,"max_depth":5,"include_types":True,"include_addresses":True},
          "search_text":{"targets":"main","kind":"text","limit":2}, "export_functions":{"limit":2},
          "search_bytes":{"patterns":"00 00","limit":2}}
        def replace(value):
            if isinstance(value,dict): return {k:replace(v) for k,v in value.items()}
            if isinstance(value,list): return [replace(v) for v in value]
            if isinstance(value,str):
                if value.startswith('0x'): return ea
                if value in ('interesting_function','process_swap'): return 'main'
            return value
        # list_idbs was added on master after the frozen N0 baseline; its live
        # ownership contract is covered by list_idbs_e2e, not baseline equality.
        excluded = {"open_idb","close_idb","open_dsc","dsc_add_dylib","dsc_add_region","list_idbs"}
        for name,example,aliases in tools:
            if name in excluded or name.startswith('dbg_'):
                continue
            params = overrides.get(name,replace(example))
            for called in [name,*aliases]:
                print(json.dumps({"case":"N6-tools","calling":called}), flush=True)
                expected = old.call(called,params)
                actual = new.call(called,params)
                with (env.root/"n6-tool-responses.jsonl").open("a") as output:
                    output.write(json.dumps({"called":called,"baseline":expected,"nexus":actual})+"\n")
                # Cache is presentation metadata; inline threshold is identical.
                a,b = dict(expected),dict(actual)
                a.pop('cache',None);b.pop('cache',None)
                if name == 'get_database_info':
                    # A reopened IDB retains the original binary input path.
                    a = normalized(a,env.root/"fixtures/mini")
                    b = normalized(b,env.root/"fixtures/mini")
                witnesses = None
                equal = json_equal(a,b,name)
                if not equal and name=='get_xrefs_to_struct_field' and 'result' in a and 'result' in b:
                    witnesses=[member_witness(old,a['result'],True),member_witness(new,b['result'],True)]
                    equal=allocated_member_equal(a,b,name,witnesses)
                records.append({'tool':name,'called':called,'params':params,'baseline':expected,'nexus':actual,
                    'allocated_id_witnesses':witnesses,'status':'PASS' if equal else 'FAIL'})
        refusals = {}
        for name in ("open_dsc", "dsc_add_dylib", "dsc_add_region"):
            refusal = new.call(name, {})
            assert "not implemented by Nexus; no legacy fallback" in refusal["error"], refusal
            refusals[name] = refusal
        unknown = new.direct("unknown_n6", {})
        assert unknown["exit"] == 1 and "no legacy fallback" in unknown["error"], unknown
        status = new.direct("status", {})["result"]
        assert status["backend_counts"] == {"nexus":1}, status
        assert len(status["workers"]) == 1 and status["workers"][0]["backend"] == "nexus", status
        assert status["workers"][0]["pending_requests"] == 0, status
        (env.root/"n6-no-fallback.json").write_text(json.dumps({"status":status,"unknown":unknown}, indent=2)+"\n")
        (env.root/"n6-capability-refusals.json").write_text(json.dumps(refusals, indent=2)+"\n")
        # Instrument only this test owner's Python subprocess creation. The
        # debugger helper starts a real local dbgsrv; never leave it untracked.
        # The error contract includes the listening port verbatim. Reserve an
        # OS-selected test port and run the two debug-server calls serially on
        # that same port; do not normalize network addresses in the comparator.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            debug_port = reservation.getsockname()[1]
        setup = f"""import sys, subprocess, types, socket
sys.path.insert(0, {str(repo/'tests/support')!r})
from pathlib import Path
from nexus_env import Environment
N6_DEBUG_ENV = Environment(Path({str(env.root)!r}))
N6_DEBUG_POPEN = subprocess.Popen
def n6_owned_debug_popen(command, **options):
    intent = N6_DEBUG_ENV._begin_creation(command)
    child = N6_DEBUG_POPEN(command, **options)
    try:
        N6_DEBUG_ENV._record(child, command)
        N6_DEBUG_ENV._finish_creation(intent)
    except BaseException:
        child.kill()
        child.wait(timeout=3)
        raise
    return child
subprocess.Popen = n6_owned_debug_popen
N6_DEBUG_BIND = socket.socket.bind
def n6_owned_debug_bind(endpoint, address):
    if address == ('127.0.0.1', 0):
        address = ('127.0.0.1', {debug_port})
    return N6_DEBUG_BIND(endpoint, address)
socket.socket.bind = n6_owned_debug_bind
import ida_dbg
assert ida_dbg.load_debugger('arm_mac', True)
"""
        for c in (old,new):
            assert c.call('run_script',{'code':setup})['result']['success']
        debug = [
          ('dbg_load_debugger', {'debugger_name':'arm_mac'}),
          ('dbg_get_state', {}), ('dbg_list_threads', {}),
          ('dbg_add_breakpoint', {'address':ea,'bpt_type':'soft'}),
          ('dbg_enable_breakpoint', {'address':ea,'enable':False}),
          ('dbg_list_breakpoints', {}), ('dbg_del_breakpoint', {'address':ea}),
          ('dbg_get_registers', {'register_names':['X0']}),
          ('dbg_set_register', {'register_name':'X0','value':'0x1'}),
          ('dbg_read_memory', {'address':ea,'size':4}),
          ('dbg_write_memory', {'address':ea,'data':'00'}),
          ('dbg_get_memory_info', {}), ('dbg_select_thread', {'thread_id':2147483647}),
          ('dbg_continue', {'timeout_secs':1}), ('dbg_step_into', {'timeout_secs':1}),
          ('dbg_step_over', {'timeout_secs':1}), ('dbg_step_until_ret', {'timeout_secs':1}),
          ('dbg_run_to', {'address':ea,'timeout_secs':1}), ('dbg_wait_event', {'timeout_secs':1}),
          ('dbg_start_process', {'path':'/N6-nonexistent-debug-target','timeout_secs':1}),
          ('dbg_attach_process', {'pid':2147483647,'timeout_secs':1}),
          ('dbg_detach_process', {}), ('dbg_exit_process', {})]
        # The invalid PID is established absent before passing it to IDA.
        from process_identity import identity
        assert identity(2147483647) is None
        assert {name for name,_,_ in tools if name.startswith('dbg_')} == {name for name,_ in debug}
        for name,params in debug:
            print(json.dumps({"case":"N6-tools","calling":name}), flush=True)
            expected = old.call(name,params)
            if name == 'dbg_attach_process':
                stopped = old.call('run_script', {'code':'assert _kill_dbgsrv()'})
                assert stopped['result']['success'], stopped
            actual = new.call(name,params)
            a,b = dict(expected),dict(actual)
            a.pop('cache',None);b.pop('cache',None)
            equal = json_equal(a,b,name)
            records.append({'tool':name,'called':name,'params':params,'baseline':expected,'nexus':actual,
                            'status':'PASS' if equal else 'FAIL','coverage':'real IDA idle debugger / breakpoint and failure contract'})
        for c in (old,new):
            result=c.call('run_script', {'code':"subprocess.Popen = N6_DEBUG_POPEN\nsocket.socket.bind = N6_DEBUG_BIND\nif '_kill_dbgsrv' in globals():\n    _kill_dbgsrv()"})
            assert result['result']['success'],result
    finally:
        (env.root/'n6-tool-comparison.json').write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n')
        try:
            if old:old.stop()
        finally:
            if new:new.stop()
    failures=[r for r in records if r['status']!='PASS']
    assert not failures, json.dumps(failures)
    return {'tool_comparisons':len(records),'tools':sorted({r['tool'] for r in records}),
            'debug_comparison_port':debug_port}



def compatibility_edges(env, baseline, binary):
    """Strict F1/F2/F3 real IDA comparisons, including an incomplete stored IDB."""
    assert digest(baseline) == BASELINE_SHA
    samples = prebuilt_pair(env, binary, "n6-edges")
    variables = env.variables() | {"TMPDIR":os.environ["TMPDIR"], "IDA_CLI_HOME":str(env.root/"edges-native")}
    Path(variables["IDA_CLI_HOME"]).mkdir(mode=0o700)
    seed = Process(env, [str(baseline), "serve-worker"], variables, "edges-seed")
    try:
        assert "result" in seed.rpc("open", {"path":str(samples[0])})
        setup = seed.rpc("run_script", {"code":"""import ctypes, ida_ida, ida_nalt, ida_funcs, ida_frame, ida_typeinf as ti, ida_auto, json
ida_auto.enable_auto(False)
ea = ida_funcs.get_func_ea_by_num(0)
if ida_frame.get_func_frame_ea(ti.tinfo_t(), ea):
    assert ida_frame.del_frame_ea(ea)
assert ida_funcs.get_func_start(ea) == ea
assert not ida_frame.get_func_frame_ea(ti.tinfo_t(), ea)
delinf = ctypes.CDLL(None).delinf
delinf.argtypes = [ctypes.c_int]
delinf.restype = ctypes.c_bool
for key in (ida_ida.INF_MD5, ida_ida.INF_SHA256, ida_ida.INF_INPUT_FILE_PATH):
    assert delinf(key)
setinf = ctypes.CDLL(None).setinf
setinf.argtypes = [ctypes.c_int, ctypes.c_uint64]
setinf.restype = ctypes.c_bool
assert setinf(ida_ida.INF_FSIZE, 0)
assert ida_nalt.get_input_file_path() in (None, '')
assert ida_nalt.retrieve_input_file_md5() is None
assert ida_nalt.retrieve_input_file_sha256() is None
assert ida_nalt.retrieve_input_file_size() == 0
print(json.dumps({'function':hex(ea), 'frame':False, 'metadata_missing':True}))
"""})
        fixture = script_result(setup)
        assert "result" in seed.rpc("close")
        assert "result" in seed.rpc("shutdown")
        seed.wait()
    finally:
        if seed.child.poll() is None:
            seed.child.stdin.close()
            seed.wait()
    shutil.copyfile(samples[0], samples[1])
    hashes = [digest(p) for p in samples]
    assert hashes[0] == hashes[1]
    old = new = None
    rows = []
    try:
        old = Process(env, [str(baseline), "serve-worker"], variables, "edges-baseline")
        assert "result" in old.rpc("open", {"path":str(samples[0])})
        new = Candidate(env, binary, samples[1], "n6-edges", transport="stdio", inline="8000000")
        ea = fixture['function']
        cases = [("get_database_info", {}),
            ("delete_stack_variable", {"address":ea,"var_name":"slot"}),
            ("apply_type", {"address":ea,"stack_name":"slot","decl":"int"}),
            ("set_stack_variable_type", {"func_address":ea,"name":"slot","type_decl":"int"})]
        for text in [*(char+ea for char in '\x1c\x1d\x1e\x1f'), '0'*5000+str(int(ea,16)), '0b'+bin(int(ea,16))[2:], '0o'+oct(int(ea,16))[2:]]:
            cases += [("batch_lookup_functions", {"queries":[text]}), ("read_global_variable", {"query":text})]
        for method, params in cases:
            expected = old.rpc(method, params)
            expected.pop('jsonrpc', None); expected.pop('id', None)
            actual = new.direct(method, params)
            actual.pop('cache', None)
            equal = (actual.get('exit') == 1 and actual.get('error') == 'Error: ' + expected['error']['message']) if 'error' in expected else json_equal(expected, actual, method)
            rows.append({'method':method,'params':params,'baseline':expected,'nexus':actual,'status':'PASS' if equal else 'FAIL'})
            (env.root/'n6-edge-comparison.json').write_text(json.dumps({'fixture':fixture,'input_hashes':hashes,'rows':rows},indent=2)+'\n')
        assert rows[0]['baseline']['result']['input_file_path'] == ''
        assert rows[0]['baseline']['result']['md5'] == '0'*32
        assert rows[0]['baseline']['result']['sha256'] == '0'*64
        assert rows[0]['baseline']['result']['input_file_size'] == 0
        assert rows[1]['baseline']['result']['code'] == -4
        assert rows[2]['baseline']['result']['code'] == -5
        assert "code -5" in rows[3]['baseline']['error']['message']
    finally:
        try:
            if old:
                assert "result" in old.rpc("close")
                old.rpc("shutdown"); old.wait()
        finally:
            if new: new.stop()
    failures = sum(row['status']!='PASS' for row in rows)
    assert not failures, f'{failures} N6 edge comparisons failed; see n6-edge-comparison.json'
    return {'edge_comparisons':len(rows),'edge_failures':failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--case", choices=("E04-N6", "E20", "N6-tools"), required=True)
    args = parser.parse_args()
    env = Environment(args.root)
    result = {"case":args.case, "status":"FAIL"}
    def interrupted(*_):
        raise InterruptedError("N6 suite interrupted")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        result.update({"E04-N6":lambda:comparison(env, args.baseline, args.binary), "E20":lambda:persistence(env, args.binary), "N6-tools":lambda:tool_contracts(env,args.baseline,args.binary)}[args.case]())
        result["status"] = "PASS"
    finally:
        # The supervising verifier owns the full ledger, including this
        # driver's ancestors, and performs cleanup after this process exits.
        (env.root/(args.case+"-result.json")).write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
