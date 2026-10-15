#!/usr/bin/env python3
"""Strict N4 comparison against an independently supplied, hashed N0 binary.

No old source or installed CLI is used. The real suite owns only processes
recorded by the N0 Environment and uses copies of its tiny compiled fixture.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tests/support"))
from nexus_env import Environment

BASELINE_SHA = "6b890f6702175a3e3fdbbf70596def1f68596325b330228cdc480df059be463b"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Lines:
    def __init__(self, stream):
        self.stream, self.pending = stream, b""

    def json(self):
        deadline = time.monotonic() + 25
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([self.stream], [], [], remaining)[0], "protocol response deadline"
            chunk = os.read(self.stream.fileno(), 65536)
            assert chunk, f"protocol EOF: {self.pending[:200]!r}"
            self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        return json.loads(line)  # Log pollution is a failure, never filtered.


class Process:
    def __init__(self, env, args, variables, label):
        self.env, self.args = env, args
        self.log = (env.root / f"{label}.stderr.log").open("wb")
        self.child = env.spawn(lambda: subprocess.Popen(args, env=variables, cwd=REPO,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log), args)
        self.lines = Lines(self.child.stdout)
        self.sequence = 0

    def rpc(self, method, params=None, notification=False):
        self.sequence += 1
        request = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notification:
            request["id"] = str(self.sequence)
        self.child.stdin.write((json.dumps(request, ensure_ascii=False) + "\n").encode())
        self.child.stdin.flush()
        if notification:
            return None
        response = self.lines.json()
        assert response.get("id") == request["id"], response
        return response

    def wait(self):
        self.child.wait(timeout=15)
        assert self.child.returncode == 0, (self.args, self.child.returncode)
        self.log.close()


def unwrap_cache(value, home):
    if isinstance(value, dict) and value.get("cached") is True:
        assert set(value) == {"cached", "file", "size_bytes", "item_count", "summary"}, value
        path = Path(value["file"]).resolve(strict=True)
        assert path.is_relative_to(home.resolve()), path
        raw = path.read_bytes()
        assert len(raw) == value["size_bytes"]
        assert str(path) in value["summary"]
        return json.loads(raw), value
    return value, None


class Http:
    def __init__(self, port):
        self.port, self.session, self.sequence = port, None, 0
        self.rpc("initialize", {"protocolVersion":"2025-03-26", "capabilities":{},
            "clientInfo":{"name":"n4-contract", "version":"1"}})
        self.rpc("notifications/initialized", notification=True)

    def rpc(self, method, params=None, notification=False):
        self.sequence += 1
        data = {"jsonrpc":"2.0", "method":method, "params":params or {}}
        if not notification:
            data["id"] = str(self.sequence)
        headers = {"Content-Type":"application/json", "Accept":"application/json, text/event-stream",
                   "MCP-Protocol-Version":"2025-03-26"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=25)
        try:
            connection.request("POST", "/mcp", json.dumps(data), headers)
            response = connection.getresponse()
            assert response.status in (200, 202), (response.status, response.read())
            self.session = response.getheader("Mcp-Session-Id") or self.session
            if notification:
                response.read()
                return None
            if "event-stream" in response.getheader("Content-Type", ""):
                while True:
                    line = response.readline()
                    assert line, "HTTP SSE EOF before response"
                    if line.startswith(b"data: "):
                        value = json.loads(line[6:])
                        if value.get("id") == data["id"]:
                            return value
            value = json.loads(response.read())
            assert value.get("id") == data["id"], value
            return value
        finally:
            connection.close()

    def call(self, name, arguments):
        return self.rpc("tools/call", {"name": name, "arguments": arguments})


class Candidate:
    def __init__(self, env, binary, sample, label, transport="http", inline="512", seed=None, allow_open_error=False):
        label = f"{label}-{os.getpid()}"
        self.env, self.binary, self.sample, self.transport = env, binary, sample, transport
        self.home = env.root / f"home-{label}"
        self.home.mkdir(mode=0o700)
        if seed:
            (self.home/"idb").mkdir()
            shutil.copyfile(seed,self.home/"idb"/seed.name)
            self.seed = self.home/"idb"/seed.name
            assert not self.seed.with_suffix("").exists()
        ipc = Path(os.environ["N3_IPC_ROOT"]) / label
        ipc.mkdir(mode=0o700, parents=True)
        temporary = Path(os.environ["TMPDIR"])
        self.variables = env.variables() | {"IDA_CLI_HOME":str(self.home), "TMPDIR":str(temporary),
            "N3_ENV_ROOT":str(env.root), "IDA_CLI_NEXUS_DEV":"1", "IDA_NEXUS_PYTHON":str(env.root/"venv/bin/python"),
            "IDA_NEXUS_IPC_ROOT":str(ipc), "IDA_NEXUS_BRIDGE_SCRIPT":str(REPO/"tests/support/nexus_client_fixture.py"),
            "IDA_MCP_MAX_INLINE_BYTES":inline}
        self.process = Process(env, [str(binary), "serve"] if transport == "stdio" else
            [str(binary), "serve-http", "--bind", "127.0.0.1:0"], self.variables, label)
        if transport == "stdio":
            self.process.rpc("initialize", {"protocolVersion":"2025-03-26", "capabilities":{},
                "clientInfo":{"name":"n4-contract", "version":"1"}})
            self.process.rpc("notifications/initialized", notification=True)
            self.client = self.process
        else:
            deadline = time.monotonic() + 15
            port = None
            while not port:
                assert time.monotonic() < deadline and self.process.child.poll() is None, "HTTP readiness"
                if not (self.home/"server.sock").exists():
                    time.sleep(.02)
                    continue
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as control:
                    control.settimeout(5)
                    control.connect(str(self.home/"server.sock"))
                    control.sendall(b'{"jsonrpc":"2.0","id":"ready","method":"status","params":{}}\n')
                    data=control.makefile("rb").readline()
                metadata=json.loads(data)["result"]["metadata"]
                port=int(metadata["http_address"].rsplit(":",1)[1])
            self.client = Http(port)
        self.open_result = self.mcp("open_idb", {"path":str(sample)})
        if not allow_open_error:
            assert "result" in self.open_result, self.open_result
        self.opened = self.open_result.get("result")
        if self.opened:
            assert self.opened["close_token"] and self.opened["db_handle"]

    def mcp(self, method, params):
        response = self.client.rpc("tools/call", {"name":method, "arguments":params})
        assert "result" in response, response
        result = response["result"]
        assert result.get("content") and len(result["content"]) == 1, result
        text = result["content"][0]["text"]
        if result.get("isError"):
            return {"error":text}
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = text
        value, cache = unwrap_cache(value, self.home)
        return {"result":value, "cache":cache}

    def direct(self, method, params):
        args = ["timeout", "30s", str(self.binary), "--socket", str(self.home/"server.sock"),
            "--compact", "--path", str(self.sample), "raw", json.dumps({"method":method,"params":params})]
        child = self.env.spawn(lambda: subprocess.Popen(args, env=self.variables,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE), args)
        stdout, stderr = child.communicate(timeout=32)
        stderr = stderr.decode()
        log_notice = f"[ida-cli] log -> {self.home / 'logs/server.log'}\n"
        assert stderr.startswith(log_notice), stderr
        stderr = stderr[len(log_notice):]
        if child.returncode:
            return {"error":stderr.strip(), "exit":child.returncode}
        assert stderr == "", stderr
        value, cache = unwrap_cache(json.loads(stdout), self.home)
        return {"result":value, "cache":cache}

    def call(self, method, params):
        return self.mcp(method, params)

    def stop(self):
        if self.opened:
            result = self.mcp("close_idb", {"close_token":self.opened["close_token"]})
            assert "result" in result, result
        if self.transport == "stdio":
            self.process.child.stdin.close()
        else:
            args = ["timeout", "30s", str(self.binary), "--socket", str(self.home/"server.sock"), "shutdown"]
            child = self.env.spawn(lambda: subprocess.Popen(args, env=self.variables,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE), args)
            stdout, stderr = child.communicate(timeout=32)
            assert child.returncode == 0, (stdout, stderr, child.returncode)
        self.process.wait()


def cases(address, name):
    return [("get_database_info", {}), ("get_analysis_status", {}),
        ("list_functions", {}), ("list_functions", {"limit":1,"offset":0}),
        ("list_functions", {"limit":1,"offset":1}), ("list_functions", {"limit":0}),
        ("list_functions", {"offset":999}), ("list_functions", {"filter":name.upper()}),
        ("list_functions", {"limit":-1}), ("list_functions", {"offset":"bad"}),
        ("get_function_by_name", {"name":name}),
        ("get_function_by_name", {"name":"N4_MISSING"}),
        ("get_function_at_address", {"address":address}),
        ("get_function_at_address", {"name":name,"offset":1}),
        ("get_xrefs_to", {"address":address}), ("get_xrefs_from", {"address":address}),
        ("disassemble", {"address":address,"count":3}),
        ("disassemble", {"address":[address,"0x0"],"count":1}),
        ("disassemble", {"address":[]}),
        ("disassemble", {"address":[address,"bad"]}),
        ("disassemble", {"address":"  "+address+"  ","count":1}),
        ("disassemble_function", {"name":name,"count":3}),
        ("disassemble_function_at", {"address":address,"count":3}),
        ("decompile_function", {"address":address}),
        ("decompile_function", {"address":[address,"0x0"]}),
        ("disassemble", {"address":"bad"}), ("disassemble", {"address":"0x0"}),
        ("run_script", {"code":"import sys; print('中文 Ω'); print('错误 stderr',file=sys.stderr)"}),
        ("run_script", {"code":"print('before'); raise ValueError('N4 exception')"}),
        ("run_script", {"code":"raise ValueError(chr(0)+'hidden')"}),
        ("run_script", {"code":"raise ValueError('x'*(1024*1024+1))"}),
        ("run_script", {"code":"print('before exit'); raise SystemExit('N4 exit')"}),
        ("run_script", {"code":"global N4_GLOBAL; N4_GLOBAL=42; print('set')"}),
        ("run_script", {"code":"print(N4_GLOBAL)"}),
        ("run_script", {"code":"print('雪'*400000)"})]


# Each entry requires repeated fixed-N0 observations on the same IDB/input.
# Evidence and approval: docs/plan/nexus-backend.md, N6 differences list.
UNORDERED_FIELDS = {("build_callgraph", ("result", "nodes")): "address"}


def json_equal(left, right, method=None, path=()):
    """Strict JSON equality, with only registered method/field order exceptions."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            json_equal(left[k], right[k], method, path + (k,)) for k in left)
    if isinstance(left, list):
        if len(left) != len(right):
            return False
        key = UNORDERED_FIELDS.get((method, path))
        if key:
            # Type-tagged scalar identities prevent bool/int and string/number
            # collisions. Missing, composite or duplicate identities fail closed.
            def indexed(items):
                result = {}
                for item in items:
                    if not isinstance(item, dict) or key not in item:
                        return None
                    identity = item[key]
                    if type(identity) not in (str, int, float, bool, type(None)):
                        return None
                    identity = (type(identity), identity)
                    if identity in result:
                        return None
                    result[identity] = item
                return result
            a, b = indexed(left), indexed(right)
            return a is not None and b is not None and a.keys() == b.keys() and all(
                json_equal(a[k], b[k], method, path + ("[]",)) for k in a)
        return all(json_equal(a, b, method, path + ("[]",)) for a, b in zip(left, right))
    return left == right


def normalized(response, sample):
    # Only input_file_path varies because equivalent inputs live in independent
    # homes. Validate that path actually resolves to this runtime's exact bytes.
    value = json.loads(json.dumps(response))
    value.pop("cache", None)
    result = value.get("result")
    if isinstance(result, dict) and "input_file_path" in result:
        assert digest(result["input_file_path"]) == digest(sample)
        result["input_file_path"] = "<verified-identical-input>"
    return value


def comparison(env, baseline, binary):
    sample = env.root/"fixtures/e04-old"
    shutil.copyfile(env.root/"fixtures/mini", sample)
    variables = env.variables() | {"IDA_CLI_HOME":str(env.root/f"baseline-home-{os.getpid()}"),"TMPDIR":os.environ["TMPDIR"]}
    Path(variables["IDA_CLI_HOME"]).mkdir()
    old = Process(env, [str(baseline),"serve-worker"], variables, "e04-baseline")
    assert "result" in old.rpc("open", {"path":str(sample)})
    funcs = old.rpc("list_functions", {})["result"]["functions"]
    address, name = funcs[0]["address"], funcs[0]["name"]
    new_sample = env.root/"fixtures/e04-new"
    shutil.copyfile(sample,new_sample)
    new = Candidate(env,binary,new_sample,"e04")
    fault_setup = ("import ida_hexrays\n"
        "assert ida_hexrays.init_hexrays_plugin()\n"
        "class N4Fault(ida_hexrays.Hexrays_Hooks):\n"
        "    def microcode(self, mba):\n"
        f"        return ida_hexrays.MERR_BADSP if mba.entry_ea == {int(address,16)} else 0\n"
        "N4_FAULT = N4Fault()\nassert N4_FAULT.hook()")
    matrix = cases(address, name) + [
        ("run_script", {"code":fault_setup}),
        ("decompile_function", {"address":[address, funcs[1]["address"]]}),
        ("run_script", {"code":"assert N4_FAULT.unhook(); del N4_FAULT"})]
    observations = []
    try:
        for method, params in matrix:
            expected = old.rpc(method,params)
            expected.pop("jsonrpc",None); expected.pop("id",None)
            actual = new.direct(method,params)
            # CLI prints transport errors on stderr with a presentation prefix.
            if "error" in expected:
                assert actual.get("exit") == 1, actual
                assert actual["error"] == "Error: " + expected["error"]["message"], (method,expected,actual)
            else:
                assert json_equal(normalized(expected,sample), normalized(actual,new_sample), method), (method,params,expected,actual)
            if method == "decompile_function" and params.get("address") == [address, funcs[1]["address"]]:
                results = expected["result"]["results"]
                assert "error" in results[0] and "code" in results[1], results
            observations.append({"method":method,"params":params,"status":"PASS","baseline":expected,"nexus":actual})
    finally:
        (env.root/"comparison.json").write_text(json.dumps({"baseline_sha256":digest(baseline),"observations":observations,
            "differences":[{"field":"input_file_path","rule":"must resolve to exact identical input SHA256; path alone normalized"}]},ensure_ascii=False,indent=2)+"\n")
        old.rpc("close"); old.rpc("shutdown"); old.wait()
        new.stop()
    assert len(observations) == len(matrix)
    return {"comparisons":len(observations),"methods":sorted({m for m,_ in cases(address,name)})}


def entrypoints(env, binary):
    sample = env.root/"fixtures/e16"
    shutil.copyfile(env.root/"fixtures/mini",sample)
    http = Candidate(env,binary,sample,"e16-http")
    functions = http.call("list_functions",{})["result"]["functions"]
    # MCP deserializes tool schemas at its JSON-RPC layer; raw CLI does so at
    # dispatch. E04 checks the raw validation messages. E16 compares the shared
    # valid-schema/runtime-error contract, including malformed address values.
    matrix = [(m,p) for m,p in cases(functions[0]["address"],functions[0]["name"])
              if (m,p) not in (("list_functions",{"limit":-1}),("list_functions",{"offset":"bad"}))]
    expected = [http.call(m,p) for m,p in matrix]
    queued = http.direct("enqueue", {"method":"run_script", "task_params":{"code":"print('queued identity')"}})["result"]
    task_id = queued["task_id"]
    deadline = time.monotonic() + 10
    while True:
        task = http.direct("task_status", {"task_id":task_id})["result"]
        if task["status"] == "completed":
            break
        assert task["status"] != "failed" and time.monotonic() < deadline, task
        time.sleep(.02)
    assert task["result"]["stdout"] == "queued identity\n", task
    identities = [json.loads(line) for line in (env.root/"task-identities.jsonl").read_text().splitlines()]
    assert any(identity["task_id"] == task_id for identity in identities), identities
    # A second HTTP MCP session independently opens the same canonical IDB.
    other = Http(http.client.port)
    response = other.call("open_idb",{"path":str(sample)})["result"]
    opened = json.loads(response["content"][0]["text"])
    first = http.mcp("close_idb",{"close_token":http.opened["close_token"]})
    assert "still active" in first["result"],first
    assert http.call("list_functions",{})["result"]["functions"] == functions
    http.opened = opened
    try:
        for (method,params), baseline in zip(matrix,expected):
            direct = http.direct(method,params)
            if "error" in baseline:
                assert direct.get("exit") == 1 and direct["error"] == "Error: "+baseline["error"], (baseline,direct)
            else:
                assert json_equal(normalized(direct,sample), normalized(baseline,sample), method),(method,baseline,direct)
        std_sample=env.root/"fixtures/e16-stdio"
        shutil.copyfile(sample,std_sample)
        stdio=Candidate(env,binary,std_sample,"e16-stdio","stdio")
        try:
            for (method,params), baseline in zip(matrix,expected):
                actual=stdio.call(method,params)
                assert json_equal(normalized(actual,std_sample), normalized(baseline,sample), method),(method,baseline,actual)
            for candidate in (http,stdio):
                refusal=candidate.call("rename_symbol",{"address":functions[0]["address"],"new_name":"FORBIDDEN"})
                assert "not implemented by Nexus N4" in refusal["error"],refusal
        finally:
            stdio.stop()
    finally:
        http.stop()
    return {"calls_per_entry":len(matrix),"http_lease_isolation":True,"capability_refusal":True}


def streams(env,binary):
    sample=env.root/"fixtures/e17"
    shutil.copyfile(env.root/"fixtures/mini",sample)
    client=Candidate(env,binary,sample,"e17")
    try:
        code="import sys; print('雪'*20000); print('stderr Ω',file=sys.stderr)"
        for index,call in enumerate((client.call,client.direct)):
            response=call("run_script",{"code":code})
            assert (response["cache"] is not None) == (index==1),response
            value=response["result"]
            assert value["stdout"]=="雪"*20000+"\n" and value["stderr"]=="stderr Ω\n" and value["success"] is True
            failure=call("run_script",{"code":"import sys; print('先'); print('错',file=sys.stderr); raise RuntimeError('异常')"})
            value=failure["result"]
            assert value["stdout"]=="先\n" and value["stderr"]=="错\n" and value["error"]=="异常" and value["success"] is False,value
            subsequent=call("run_script",{"code":"print('later')"})["result"]
            assert subsequent=={"success":True,"stdout":"later\n","stderr":""},subsequent
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs=[pool.submit(client.call,"run_script",{"code":f"import sys,time; print('{tag}'); time.sleep(.05); print('{tag} err',file=sys.stderr)"}) for tag in ("甲","乙")]
            for tag,job in zip(("甲","乙"),jobs):
                result=job.result(timeout=10)["result"]
                assert result["stdout"]==tag+"\n" and result["stderr"]==tag+" err\n",result
        marker=env.root/"e17-native-started"
        cancelled=client.direct("run_script",{"code":f"from pathlib import Path; Path({str(marker)!r}).touch()\nwhile True:\n    pass", "timeout_secs":1})
        assert marker.is_file() and cancelled.get("exit")==1,cancelled
        assert "deadline" in cancelled["error"].lower(),cancelled
        deadline=time.monotonic()+10
        while True:
            status=client.direct("status",{})["result"]
            if len(status["workers"])==1 and status["workers"][0]["ref_count"]==1 and status["workers"][0]["pending_requests"]==0:
                break
            assert time.monotonic()<deadline,status
            time.sleep(.02)
        assert client.call("list_functions",{})["result"]["total"]==2
        std_sample=env.root/"fixtures/e17-stdio"
        shutil.copyfile(sample,std_sample)
        stdio=Candidate(env,binary,std_sample,"e17-stdio","stdio")
        try:
            result=stdio.call("run_script",{"code":code})
            assert result["cache"] is None and result["result"]["stdout"]=="雪"*20000+"\n"
            assert result["result"]["stderr"]=="stderr Ω\n"
        finally:
            stdio.stop()
    finally:
        client.stop()
    return {"unicode_bytes":60000,"stdout_stderr_separate":True,"script_exception":True,"large_cache":True}


def legacy_cache(env,baseline,binary):
    sample=env.root/f"fixtures/e22-{os.getpid()}"
    shutil.copyfile(env.root/"fixtures/mini",sample)
    results=[]
    for kind in ("match","missing","mismatch"):
        home=env.root/f"legacy-{kind}-{os.getpid()}"
        home.mkdir()
        variables=env.variables() | {"IDA_CLI_HOME":str(home),"TMPDIR":os.environ["TMPDIR"]}
        old=Process(env,[str(baseline),"serve-worker"],variables,f"e22-old-{kind}")
        opened=old.rpc("open",{"path":str(sample)})
        assert "result" in opened,opened
        idb=Path(opened["result"]["path"])
        code="import ida_name, ida_funcs, ida_bytes\nea=ida_funcs.getn_func(0).start_ea\nassert ida_name.set_name(ea,'N4_USER_EDIT',ida_name.SN_CHECK)\nassert ida_bytes.set_cmt(ea,'N4 preserved comment',False)\nprint('USER_EDIT_SAVED')"
        if kind!="match":
            code+="\nimport ctypes, ida_ida, ida_nalt\nf=ctypes.CDLL(None).setinf_buf\nf.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t]\nf.restype=ctypes.c_bool\n"
            if kind=="missing":
                code+="b=ctypes.create_string_buffer(b'X')\nassert f(ida_ida.INF_SHA256,b,1)\nassert ida_nalt.retrieve_input_file_sha256() is None\n"
            else:
                code+="b=ctypes.create_string_buffer(b'X'*32)\nassert f(ida_ida.INF_SHA256,b,32)\nassert ida_nalt.retrieve_input_file_sha256()==b'X'*32\n"
        script=old.rpc("run_script",{"code":code})
        assert script["result"]["success"] is True and script["result"]["stdout"]=="USER_EDIT_SAVED\n",script
        assert "result" in old.rpc("close")
        old.rpc("shutdown"); old.wait()
        original_hash=digest(idb)
        client=Candidate(env,binary,sample,f"e22-{kind}",seed=idb,allow_open_error=True)
        try:
            if kind=="match":
                assert client.opened,client.open_result
                names=client.call("list_functions",{})["result"]["functions"]
                assert names[0]["name"]=="N4_USER_EDIT",names
                comment=client.call("run_script",{"code":"import ida_bytes, ida_funcs; print(ida_bytes.get_cmt(ida_funcs.getn_func(0).start_ea,False))"})["result"]
                assert comment["stdout"]=="N4 preserved comment\n",comment
                snapshot=client.seed.with_suffix("")
                assert snapshot.is_file() and digest(snapshot)==digest(sample), "verified input snapshot not retained"
                # The active owner may legitimately save different packed bytes.
                # A warm open must use the retained proof, without copying that
                # live packed file into a second verification database.
                saved=client.call("run_script",{"code":"import ida_loader; assert ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)"})["result"]
                assert saved["success"],saved
                warm_reply=client.direct("prewarm",{"keep_warm":True})
                assert "result" in warm_reply,warm_reply
                warm=warm_reply["result"]
                assert warm["kept_warm"] and warm["database_info"]["function_count"]==2,warm
                if (env.root/"e22-reverify-save.inject").exists():
                    assert not (env.root/"e22-reverify-save.observed").exists(), "warm open re-entered packed verification"
                closed=client.mcp("close_idb",{"close_token":client.opened["close_token"]})
                assert "still active" in closed["result"],closed
                client.opened=None
                assert client.direct("close",{})["result"]=={"ok":True}
                # Last warm reference has saved/unlocked this exact old cache.
                assert client.direct("get_function_by_name",{"name":"N4_USER_EDIT"})["result"]["name"]=="N4_USER_EDIT"
            else:
                expected="unavailable" if kind=="missing" else "mismatch"
                assert not client.opened and expected in client.open_result["error"],client.open_result
                assert digest(client.seed)==original_hash,"rejected original IDB was changed"
                assert not client.seed.with_suffix("").exists(),"rejected input was published"
            assert digest(idb)==original_hash,"N0 source IDB changed"
            results.append({"kind":kind,"status":"PASS","source_sha256":original_hash})
        finally:
            client.stop()
        assert not list((client.home/"idb").glob(".nexus-*")),"staging/verification residue"
    return {"legacy_cases":results,"warm_lease_released":True,"verified_snapshot_retained":True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--baseline",type=Path,required=True)
    parser.add_argument("--binary",type=Path,required=True)
    parser.add_argument("--case",choices=("E04","E16","E17","E22"),required=True)
    args=parser.parse_args()
    assert os.environ.get("IDA_TEST")=="1","BLOCKED: IDA_TEST=1 required"
    assert digest(args.baseline)==BASELINE_SHA,"BLOCKED: N0 baseline checksum mismatch"
    env=Environment(args.root)
    result={"case":args.case,"status":"FAIL"}
    # The outer verifier holds the environment lock for the whole Rust suite.
    try:
        if args.case=="E04": result.update(comparison(env,args.baseline,args.binary))
        elif args.case=="E16": result.update(entrypoints(env,args.binary))
        elif args.case=="E17": result.update(streams(env,args.binary))
        else: result.update(legacy_cache(env,args.baseline,args.binary))
        result["status"]="PASS"
        print(json.dumps(result))
    finally:
        (env.root/f"{args.case}-result.json").write_text(json.dumps(result,indent=2)+"\n")


if __name__=="__main__":
    main()
