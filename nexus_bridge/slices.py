"""Evaluated in a private module inside the owner, on its IDA thread only.

The counter covers public IDB notifications, not arbitrary trusted Python/native
code that bypasses them or changes this module. No IDA object leaves this thread.
"""
import uuid

# IDA 9.5 public IDB_Hooks notifications. Before/after pairs conservatively
# count twice; only equality matters. No query/flow-chart notification counts.
NOTIFICATIONS = (
    "renamed", "changing_cmt", "cmt_changed", "extra_cmt_changed",
    "changing_range_cmt", "range_cmt_changed", "moving_range_cmt",
    "changing_ti", "ti_changed", "changing_op_ti", "op_ti_changed",
    "changing_op_type", "op_type_changed", "local_types_changed",
    "local_type_renamed", "lt_udm_created", "lt_udm_deleted", "lt_udm_renamed",
    "lt_udm_changed", "lt_udt_expanded", "lt_edm_created", "lt_edm_deleted",
    "lt_edm_renamed", "lt_edm_changed", "frame_created", "frame_deleted",
    "frame_expanded", "frame_udm_created", "frame_udm_deleted",
    "frame_udm_renamed", "frame_udm_changed", "func_added", "deleting_func",
    "func_deleted", "func_updated", "func_noret_changed", "set_func_start",
    "set_func_end", "func_tail_appended", "deleting_func_tail",
    "func_tail_deleted", "tail_owner_changed", "stkpnts_changed",
    "thunk_func_created", "byte_patched", "make_code", "make_data",
    "destroyed_items", "adding_segm", "segm_added", "deleting_segm",
    "segm_deleted", "changing_segm_start", "segm_start_changed",
    "changing_segm_end", "segm_end_changed", "changing_segm_name",
    "segm_name_changed", "changing_segm_class", "segm_class_changed",
    "segm_attrs_updated", "segm_moved", "allsegs_moved", "sgr_changed",
    "sgr_deleted", "compiler_changed", "deleting_tryblks", "updating_tryblks",
    "tryblks_updated", "callee_addr_changed", "item_color_changed",
    "bookmark_changed", "flirt_applied", "idasgn_matched_ea",
    "dirtree_mkdir", "dirtree_rmdir", "dirtree_link", "dirtree_rminode",
    "dirtree_move", "dirtree_rank", "dirtree_ordering_changed",
    "dirtree_bulk_move", "dirtree_segm_moved",
)
counter = None
jobs = {}
watchers = {}
cleanup_handles = {}
incarnation = uuid.uuid4().hex


def attach_cleanup(instance):
    """Use the checked bridge's private gate sources inside the native owner."""
    import builtins
    import time
    import types
    from ida_nexus import DatabaseHandle
    sources = globals()['_target_gate_sources']
    modules = {}
    def isolated_import(name, *args, **kwargs):
        if name not in sources:
            return builtins.__import__(name, *args, **kwargs)
        if name not in modules:
            module = modules[name] = types.ModuleType(name)
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=isolated_import)
            exec(compile(sources[name], '<ida-cli checked gate>', 'exec'), module.__dict__)
        return modules[name]
    Target = isolated_import('target_coordination').Target
    Journal = isolated_import('target_journal').Journal
    identity = isolated_import('owner_identity')
    with Target(instance.idb_path) as target:
        with target.locked(deadline=time.monotonic()+5):
            target.business_admission()
            journal = Journal(target)
            journal.gate(identity.state_identity())
            journal.check_owner(identity.owner_key(instance))
            return DatabaseHandle.attach(instance)


def cleanup_disconnected(handle, context, expected_incarnation, release_handle):
    """Close an auxiliary lease only after a fresh owner protection check."""
    key = tuple(context)
    cleanup_handles[key] = handle
    def check():
        # Serialized after any in-flight native call on the same owner.
        try:
            handle.execute_python(
            "import sys\n"
            "m=sys.modules.get('_ida_cli_nexus_slices_v1')\n"
            f"result=m.release_lease({context!r}, {expected_incarnation!r}) if m else None",
                timeout=600)
        except Exception as exc:
            vars(handle)['_ida_cli_slice_cleanup_error'] = exc
            import logging
            logging.getLogger(__name__).exception('Nexus slice job cleanup failed')
        return handle.execute_python(
        "import sys\n"
        "g=sys.modules.get('_ida_cli_save_guard_v1')\n"
        "result=g.close_status() if g else {'close_safe': False}", timeout=5)['result']
    import time
    outcome = release_handle(handle, time.monotonic()+605, check=check)
    if outcome is None:
        uncertain('auxiliary lease release unconfirmed; exact handle retained')
    cleanup_handles.pop(key, None)
    if outcome['save_guard_error']:
        raise RuntimeError(outcome['save_guard_error'])
    if vars(handle).get('_ida_cli_slice_cleanup_error'):
        raise vars(handle)['_ida_cli_slice_cleanup_error']
    return outcome


def watch_lease(context):
    """No IDA objects cross threads; cleanup itself re-enters the public queue."""
    import socket
    import threading
    key = tuple(context)
    if key in watchers:
        return
    channel = socket.socket(socket.AF_UNIX)
    channel.settimeout(2)
    try:
        channel.connect(context[4])
        channel.sendall(context[1].encode("ascii"))
        if channel.recv(2) != b"ok":
            uncertain("bridge lifetime handshake failed")
    except BaseException:
        channel.close()
        raise
    channel.settimeout(None)
    watchers[key] = channel

    def disconnected():
        try:
            if channel.recv(1):
                raise RuntimeError("unexpected lifetime data")
            from ida_nexus import discover_databases
            entries = [item.instance for item in discover_databases()
                       if item.instance.record_id == context[2]]
            if entries:
                handle = attach_cleanup(entries[0])
                from _ida_cli_release_protocol_v1 import release_handle
                cleanup_disconnected(handle, context, incarnation, release_handle)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Nexus slice disconnect cleanup unconfirmed")
        finally:
            channel.close()
            watchers.pop(key, None)
    threading.Thread(target=disconnected, name="nexus-slice-lifetime", daemon=True).start()


def uncertain(detail):
    raise RuntimeError("一致性无法确认: " + detail)


def install():
    import ida_idp

    def changed(self, *_args):
        try:
            self.revision += 1
        except BaseException:
            self.healthy = False
        return 0

    def closing(self):
        # Only invalidate here. Kernel close removes registrations; explicit
        # task/lease release calls unhook outside notification dispatch.
        self.healthy = False
        return 0

    callbacks = {name: changed for name in NOTIFICATIONS}
    if any(not hasattr(ida_idp.IDB_Hooks, name) for name in callbacks):
        uncertain("IDA 9.5 notification set unavailable")
    callbacks["closebase"] = closing
    cls = type("NexusCounter", (ida_idp.IDB_Hooks,), callbacks)
    hook = cls()
    hook.revision, hook.healthy = 0, True
    hook.installation = uuid.uuid4().hex
    if not hook.hook():
        uncertain("hook installation failed")
    return hook


def stamp():
    import ida_ida
    if counter is None or not counter.healthy:
        uncertain("hook object unavailable")
    values = [counter.installation, counter.revision,
              ida_ida.inf_get_database_change_count()]
    if (not isinstance(values[0], str) or len(values[0]) != 32
            or any(type(v) is not int or v < 0 for v in values[1:])):
        uncertain("invalid counter state")
    return values


def release(job, context=None):
    global counter
    state = jobs.get(job)
    if state is not None and (context is None or state["context"] == context):
        jobs.pop(job)
    if not jobs and counter is not None:
        if not counter.unhook():
            uncertain("hook release failed")
        counter = None


def release_lease(context, expected_incarnation=None):
    if expected_incarnation is not None and expected_incarnation != incarnation:
        return
    for job in list(jobs):
        if jobs[job]["context"] == context:
            release(job, context)


def step(method, params, context, decompile, parse_address, rename=None):
    """One function (or one autoanalysis address) per scheduling turn."""
    global counter
    import ida_auto
    import ida_funcs
    import ida_idaapi
    if method == "run_auto_analysis":
        ida_auto.auto_make_step(0, ida_idaapi.BADADDR)
        if ida_auto.auto_is_ok():
            return {"ok": True, "value": {"completed": True,
                    "function_count": ida_funcs.get_func_qty()}}
        return {"more": True, "checkpoint": {"analysis": True}}
    job = params["_n5_job"]
    checkpoint = params.get("_n5_checkpoint")
    try:
        if checkpoint is None:
            if job in jobs:
                uncertain("duplicate initial slice")
            watch_lease(context)
            if counter is None:
                counter = install()
            state = {"context": context, "index": 0, "results": [], "errors": 0}
            jobs[job] = state
        else:
            state = jobs.get(job)
            current = stamp()
            if (state is None or state["context"] != context
                    or not isinstance(checkpoint, dict)
                    or checkpoint.get("installation") != current[0]
                    or type(checkpoint.get("index")) is not int
                    or checkpoint["index"] != state["index"]):
                uncertain("installation, owner, lease or continuation changed")
            previous = checkpoint.get("stamp")
            if (not isinstance(previous, list) or len(previous) != 3
                    or previous[0] != current[0]
                    or any(type(v) is not int or v < 0 for v in previous[1:])):
                uncertain("invalid continuation stamp")
            if previous != current:
                raise RuntimeError("数据库已变化: between function slices")
        stamp()  # Validate installation even for the first/empty batch.
        index = state["index"]
        done = False
        if method == "batch_decompile":
            # F2/P1: the Rust router already applied legacy serde_json Vec<Value>
            # decoding. Do not decode strings again: fallback text must stay text.
            addresses = params["addresses"]
            if not isinstance(addresses, list):
                addresses = [addresses]
            if index < len(addresses):
                raw = addresses[index]
                ea = parse_address(raw)
                if ea is None:
                    item = {"address": raw, "error": "invalid address", "success": False}
                else:
                    result = decompile(ea, True)
                    item = {"address": raw, "success": result["ok"]}
                    item["pseudocode" if result["ok"] else "error"] = (
                        result["value"]["code"] if result["ok"] else result["error"])
                state["results"].append(item)
                state["index"] += 1
            done = state["index"] >= len(addresses)
            value = state["results"]
        elif method == "batch_rename":
            entries = params["renames"]
            if index < len(entries):
                state["results"].append(rename(entries[index], parse_address))
                state["index"] += 1
            done = state["index"] >= len(entries)
            value = {"results": state["results"], "total": len(state["results"])}
        else:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                release(job, context)
                return {"ok": False, "error": "Decompiler not available"}
            func = ida_funcs.getn_func(index) if index < ida_funcs.get_func_qty() else None
            if func is not None:
                ea = func.start_ea
                name = ida_funcs.get_func_name(ea) or f"sub_{ea:x}"
                result = decompile(ea, True)
                state["index"] += 1
                if not result["ok"]:
                    state["errors"] += 1
                elif params["pattern"] in result["value"]["code"]:
                    state["results"].append({"address": hex(ea), "name": name,
                                            "pseudocode": result["value"]["code"]})
                    # Preserve the native limit=0 first-match behavior.
                    limit = params.get("limit")
                    done = len(state["results"]) >= min(20 if limit is None else limit, 100)
            done = done or state["index"] >= ida_funcs.get_func_qty()
            value = {"pattern": params["pattern"], "matches": state["results"],
                     "total_searched": state["index"], "decompile_errors": state["errors"]}
        if done:
            release(job, context)
            return {"ok": True, "value": value}
        end = stamp()
        return {"more": True, "checkpoint": {"installation": end[0],
                "index": state["index"], "stamp": end}}
    except BaseException:
        release(job, context)
        raise
