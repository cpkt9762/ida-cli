# Testing

## Run tests

```bash
just test         # Stdio JSONL integration test
just test-http    # HTTP / SSE integration test
just test-script  # IDAPython script execution test
just test-dsc /path/to/dyld_shared_cache_arm64e  # DSC loading test
just cargo-test   # Unit tests (no IDA required)
```

All integration tests require IDA Pro with a valid license. Run
`cargo build --bin ida-cli` first; the test harness then spawns the built
binary as a worker subprocess.

## What's Tested

**Stdio test** (`just test`)

- MCP protocol handshake
- Tool discovery (`tool_catalog`, `tool_help`)
- Database operations (`open_idb`, `close_idb`, `get_database_info`,
  `get_analysis_status`)
- Analysis tools (`list_functions`, `get_function_by_name`,
  `disassemble_function`, `search_instructions`,
  `search_instruction_operands`)
- Editing tools (`set_comment`, `rename_symbol`, `patch_bytes`,
  `patch_assembly`)
- Types / stack tools (`declare_c_type`, `apply_type`, `infer_type`,
  `get_stack_frame`, `create_stack_variable`, `delete_stack_variable`)
- Metadata tools (`list_segments`, `list_strings`, `list_imports`,
  `list_exports`, `list_structs`, `get_xrefs_to_struct_field`,
  `search_structs`)

**HTTP test** (`just test-http`)

- Streamable HTTP transport with SSE
- `tools/list` returns the full tool list
- Database operations work over HTTP (`open_idb`, `list_functions`,
  `close_idb` with `close_token`)

**Script test** (`just test-script`)

- Opens a binary and runs inline Python via `run_script`
- Verifies stdout / stderr capture
- Verifies Python error reporting (division by zero)
- Verifies file-based script execution (`.py` file path)

**DSC test** (`just test-dsc <path>`)

- Requires a real `dyld_shared_cache_arm64e` file
- Tests both sync (pre-existing `.i64`) and async (background `idat`) paths
- Polls `get_task_status` until completion
- Verifies the database is usable after loading (`list_functions`)

**Unit tests** (`just cargo-test`)

- `src/dsc.rs` — file type strings, `idat` args, script generation, Python
  string escaping
- `src/server/task.rs` — task registry lifecycle, deduplication,
  cancellation, ISO timestamps
- `shared/ida_install.rs` — install-path normalisation and version parsing

## Test Fixture

Tests use `test/fixtures/mini.c`, a minimal C program compiled into a
Mach-O binary. The integration tests open the raw binary via `open_idb`;
IDA auto-analyses it and writes an `.i64` alongside.

## Nexus N3 bridge, patch and lifecycle

N3 uses the fixed public Nexus client with the user-approved local
`client-cancel-unknown.patch`. Preparation verifies the patched `handle.py`
SHA-256 and records patch status. Only a validated upstream fix passing the
probe and N0/N3 gates permits removal; N9 packages must carry both local patches.

Prepare separate fresh external environments using the N0 command below.
The red control alone adds `--without-client-cancel-patch` to preparation and
`--expect-unpatched` to the probe command. It must exit 2. The normal patched
probe must exit 0. The red executes three probes; the green executes five,
including both causal response orderings. Neither replays execution. Each records `cancel-gap.json`, actual loaded source, versions and owned cleanup.
The green disconnect case sends exactly one control request and proves the old
operation stopped using a precise true ACK followed by an authoritative false
from a control request issued after that ACK. Cancelling
an already completed operation returns false and leaves the next operation intact.

```bash
timeout 30s "$N0_ROOT/venv/bin/python" scripts/nexus/probe_cancel_after_disconnect.py --root "$N0_ROOT"
```

Unknown identities are bounded at 64. `cancel_operation_outcome` adds structured
`cancelled/not_pending/failed` results, failure category and per-handle issuance
sequence; existing bool APIs keep their contract. The first true ACK captures
all cancellation sequences already issued. Only a later-issued authoritative
`not_pending` proves stopping; delayed older false, transport/parse failure and
successful execution responses cannot retire an unknown ID. The bridge uses
this public API with exact IDs, an independent two-slot proof queue and bounded
retry until the original deadline. Expiry limits new probes; authoritative evidence
already acquired, including a later explicit or deadline cancellation, is always
consumed by both cancel ACK handling and the supervisor. Final control connection
cleanup failure is returned as `cleanup_failure=transport` without discarding a
parsed authoritative result. It never replays. Stop evidence preserves
UnknownOutcome and its cause; early control evidence waits for the business
outcome. `cancel_active` remains active-only. Close clears identities.

The ambiguity probe uses three controlled outcomes without starting IDA. In a
fresh patched environment it must exit 0, distinguishing authoritative absence
from transport and JSON parsing failures. The original F1 baseline exits 2.

```bash
timeout 30s "$N0_ROOT/venv/bin/python" scripts/nexus/probe_cancel_proof_ambiguity.py --evidence "$N3_ROOT/ambiguity.json"
```

`nexus_bridge_regressions` uses the installed client, persistent bridge, two real
Unix sockets and Rust/N1, with file barriers for ACK-before-stream-loss,
stopped-before-uncertain, delayed success/false, lease isolation, CLI control
saturation, stale unknown cancellation, both early-open disconnect orderings and
proof acquired after expiry. This is **gate 13**, in addition to the twelve standard
gates. Set `F1_PYTHON` to the absolute `venv/bin/python` of a freshly prepared N0
environment with the current client patch. Missing or invalid `F1_PYTHON` is a
hard failure with preparation instructions, never a skip. `F1_ROOT` optionally
selects a short external evidence directory; otherwise it uses TMPDIR. No bridge
regression variable is needed for the twelve standard gates; cache lib tests create
and remove their own private directories under TMPDIR.

```bash
F1_PYTHON="$N0_ROOT/venv/bin/python" F1_ROOT="$N3_ROOT/r" timeout 30s cargo test --locked --test nexus_bridge_regressions -- --test-threads=1
```

Early disconnect callbacks carry the originating open attempt. Rust buffers at
most one exact lease per pending open until `opened`; a confirmed cleanup fails
only that open, and a late callback after failure/release has no registered lease
to invalidate. Healthy sibling leases and their operations retain their state.
No bridge code accesses authentication tokens or reconstructs private protocols.

The protocol suite uses fake public handles and two real local sockets. Set a
short private IPC directory outside the worktree. All protocol tests and N0
support tests use the prepared venv, without loading the IDA runtime.

```bash
N3_TEST_IPC_ROOT="$N3_ROOT/i" timeout 30s "$N0_ROOT/venv/bin/python" -m pytest tests/nexus_bridge -q
```

The real lifecycle verifier requires another fresh patched environment and
explicit absolute target/SDK paths. Its suite has a 180-second shell timeout
for multiple IDA starts, save/reopen and crash repair; an outer 210-second
supervisor leaves 30 seconds for owned cleanup. It runs this worktree's absolute
Rust integration executable via cargo and disables daemon discovery by exercising
only the internal router endpoint. It never invokes the installed CLI.

```bash
timeout 210s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_e2e.py \
  --root "$N0_ROOT" --target "$CARGO_TARGET_DIR" --sdk "$IDASDKDIR" --ipc-root "$N3_ROOT/i"
```

Exactly nine real tests and nine distinct PASS records are required: E02
(bridge readiness, missing dependency, wrong version, unsupported runtime), E03
(raw/existing IDB, deadline cancellation and persistence), E05 (two independent
bridge clients), E06-client, E06-bridge, E07-packed, E07-unpacked,
E05-concurrent-open (two ordinary concurrent opens) and E06-lease-fault (one
router's SSE lease fails while a sibling operation stays active). Missing IDA,
license or sample is BLOCKED, never an ignored pass. Results are in
`lifecycle-result.json`, `lifecycle.log`, `rust-evidence.jsonl` and the process
identity ledger. Cleanup may be rerun with `--cleanup`; it never scans or kills
by process name. No staging files or instance registration JSON may remain.
The cache copies to staging first, hashes that same snapshot, and uses N2's
publication arbitration so cancellation winning first cannot publish. Existing
cache IDBs require a matching full-hash input snapshot. Its default
Nexus output is the central cache IDB; custom output without a packed base is
not automatically recoverable upstream. Public tool migration is N4;
E08/E18/E19 full real-chain coverage remains later work.

## Nexus N0 isolation and baseline

N0 prepares and verifies the dependency environment only. Business handlers
still use the existing backend. The N3 lifecycle target is implemented; the other
`nexus_*_e2e` targets in the migration plan remain future work and cannot be counted
as executed tests.

Use a new worktree and an external, nonexistent environment directory. Install
GNU `timeout` first. Select an IDA 9.4+ installation with its existing legal
license available, Python 3.11+, and an already accepted `ida.reg`. Preparation
never accepts terms or copies `.hexlic` files. An external 0600 bootstrap copy
of the selected registry is reduced by IDA's public registry API to existing
EULA records and the selected Python library path. No database is opened during
that step. The profile marker prevents the helper from modifying user profiles.
Missing dependencies, rejected EULA/registry state, and failed commands are
errors; a zero IDA exit without the readiness marker also fails.

Preparation can take 180 seconds for dependency downloads, wheel builds and
fixture compilation; each child command has its own 30-second shell timeout.
Choose paths for the local machine; the scripts do not read environment files.

```bash
N0_ROOT="$(mktemp -d)/environment"
timeout 180s python3 scripts/prepare_nexus_env.py --root "$N0_ROOT" \
  --ida-dir "$IDADIR" --eula-registry "$N0_ACCEPTED_REGISTRY"
timeout 30s "$N0_ROOT/venv/bin/python" tests/test_nexus_n0_support.py -v
```

The preparation pins Nexus `0.13.4` at
`d60ff582fde90c59726336c0dbdf3e8286e9df7a`, Domain `0.5.1`, and the IDA-supplied
`idapro 0.0.10`. `scripts/nexus/requirements.lock` fixes the build/test dependency
closure. Wheel and sample SHA-256 values, `pip check`, the full package freeze,
all preparation commands/exit codes and logs are recorded in the external root.
The root contains independent `venv`, `profile`, `state`, `cli-home`, `fixtures`,
`backups` and `tmp` directories. Existing roots are refused, including failed
ones; create another root to retry preparation.

### Loopback DNS patch

Upstream 0.13.4 inherits `HTTPServer.server_bind`, whose `getfqdn()` reverse DNS
lookup can block startup. `scripts/nexus/loopback-bind.patch` is a local patch
against that exact source SHA, applied with `git apply --check` before wheel
construction. It calls `TCPServer.server_bind` and supplies numeric HTTP server
metadata. Loopback binding, authentication, Host validation and request handling
remain upstream implementations. It changes neither system DNS nor global
Python/IDA. When upstream fixes this, update the pinned source and remove the
patch only after the regression tests pass.

The original-source probe loads the pinned unpatched HTTP module from Git. The
fault flag injects a blocking reverse lookup in that test process only, allowing
reproduction even on hosts where natural loopback DNS is currently fast. A
natural successful probe does not mean the historical issue has disappeared.

```bash
timeout 20s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_n0.py --root "$N0_ROOT" dns --original
timeout 8s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_n0.py --root "$N0_ROOT" dns --original --fault
timeout 30s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_n0.py --root "$N0_ROOT" dns --fault
```

Only the injected original-source probe is expected to exit 124. Its
faulthandler output must show `server_bind -> getfqdn -> gethostbyaddr`. The
patched probe must return `READY` and exit zero. Test processes use no temporary
`sitecustomize`; a Python distribution's normal hook, if loaded, must be inside
the selected interpreter installation and is recorded in the evidence.

### Saved copies and bounded cleanup

Build the unmodified input SHA with matching SDK/runtime and an external
`CARGO_TARGET_DIR`; save its executable, SHA-256, source archive, build command
and `probe-runtime` output separately. Never use an unidentified installed CLI
as the old-version baseline. Run each repository check with shell timeout:
`cargo fmt --all -- --check`, `cargo check --locked`,
`cargo clippy --locked --all-targets -- -D warnings`, and
`cargo test --locked --lib`. Defaults are 30 seconds; announce the reason and
180-second limit before a cold Rust/FFI build. Report existing failures and
ignored tests explicitly. The old `just` recipes do not add these limits and
assume a repository-local target directory.

The real baseline suite can take 180 seconds for repeated IDA starts and saves.
It starts the fixed old executable directly as `serve-worker`, then uses Nexus
public handles on separate sample copies. Both paths assert functions, saved
annotations, closed packed backups, reopens, and unchanged backup hashes. It
does not discover or start the user's CLI daemon. Creation first fsyncs a
`process-intents/` marker, then registers the returned `Popen` in memory and
fsyncs its PID, precise birth and command in `processes.jsonl` before removing
the marker. A registration failure stops and waits for the held child. Python
SIGTERM/SIGINT exceptions are deferred through this window without blocking
signals in the spawned child. Nexus registration wraps its actual `Popen`,
including upstream failures after creation but before the spawner returns.

Cleanup visits both memory children and every valid ledger entry, continues
after ESRCH, and reports other errors together. macOS uses public libproc
`proc_pidinfo(PROC_PIDTBSDINFO)` microsecond births plus `kern.bootsessionuuid`;
Linux uses `/proc/<pid>/stat` field 22 plus `random/boot_id`. Births remain stable
across exec. SDK structure size, offsets, full return size and query errors are
checked; unknown identities never authorize signals. Historical second-level
`ps lstart` ledgers remain evidence only and are rejected by this cleanup.
The platform sources are Apple's SDK `sys/proc_info.h`/`libproc.h`,
[XNU proc_info.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c),
[XNU kern_sysctl.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sysctl.c),
and [Linux proc documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html).

SIGKILL cannot make process creation and filesystem registration atomic.
An unfinished intent, malformed/unterminated ledger line, old identity or failed
identity query prevents `CLEAN`, even if no live PID can be confirmed. Preserve
that environment for review; cleanup still handles other confirmed entries but
does not guess missing PIDs or clear uncertain evidence. No global `pkill` is used. Execute
the separate cleanup command after success, failure, or an outer forced timeout.
An environment lock rejects concurrent verification or cleanup in the same root;
use separate freshly prepared roots for independent suites.

```bash
timeout --kill-after=10s 180s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_n0.py \
  --root "$N0_ROOT" --legacy-binary "$N0_OLD_BINARY" baseline
timeout 30s python3 scripts/verify_nexus_n0.py --root "$N0_ROOT" cleanup
timeout 30s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_n0.py --root "$N0_ROOT" startup-timeout
timeout 30s python3 scripts/verify_nexus_n0.py --root "$N0_ROOT" cleanup
```

The startup-timeout case stops only its newly recorded disposable worker before
readiness, requires an explicit finite timeout error, and confirms cleanup. It
only prints `EXPECTED_TIMEOUT` after a nonempty set of workers was created,
durably registered, successfully sent SIGSTOP and waited for during cleanup.
A deadline consumed by discovery/locking before spawn fails the fault case;
its report has `status=FAIL`, `owned_workers=[]` and `clean=false`. Use
a fresh environment for each such case. For the outer interruption path, set
`--startup-budget 20` with an outer `timeout --kill-after=10s 2s`; expect exit
124 and require `startup-timeout-cleanup.json` plus independent cleanup success.
Check that this report contains a created and stopped worker: exit 124 alone
does not prove the interruption exercised worker cleanup. The support suite
also injects TERM at creation/registration boundaries, registration write/fsync
failures, corrupt ledgers, ESRCH, identity errors and PID generation changes.
These are E00/E01 and baseline-support evidence, not E03–E29 acceptance.

### Subsequent concurrency test design

The historical concurrency probe becomes the following maintained design for
later stages. Create A/B database copies, two independent clients sharing A,
and confirm instance identity before assertions. Use a remote started-file or
protocol barrier and an explicit release event, rather than timing guesses.
During cooperative work, require A's control channel and B's bounded query to
respond while A's second ordinary query queues. Record upstream's execution
timeout excluding queue time separately from the router's required total
deadline. Cancel by operation ID, verify the real cancellation error, then
query A again. In the artificial GIL-holding native case, expect the affected
worker health probe to time out, require B/router responsiveness, and verify
recovery after native return. Later fairness tests must insert a short query
between batch boundaries; process exit or a cancelled Rust future alone is
insufficient evidence. N0 does not claim these scenarios passed for ida-cli's
future Nexus bridge.


### N3-F1 历史阻塞诊断与基线红例

以下记录 `3c05a51` 的历史红例，不能作为当前实现失败或通过的证据。重现旧实现时使用全新 N0 venv（对应旧客户端补丁），设置 `F1_PYTHON` 为该 venv 的绝对 Python 路径、`F1_ROOT` 为独立测试目录，并沿用 N1 的 target 与 SDK 环境。`tests/nexus_bridge_regressions.rs` 使用真实常驻 bridge、两条 Unix socket 和 Rust/N1；公共客户端底层传输由测试 fixture 注入，未启动真实 IDA。缓存 barrier 只在 `cfg(test)` 生效。

- `timeout 30s "$F1_PYTHON" scripts/nexus/probe_cancel_proof_ambiguity.py --evidence "$F1_ROOT/ambiguity.json"`：应 exit 2，实际 3 种控制结果的公开观察相同；不读取生产 token，也不修改安装。
- `timeout 30s "$F1_PYTHON" -m pytest tests/nexus_bridge/test_causal_patch.py -q`：3 条基线失败，覆盖迟到成功、迟到旧 false、陈旧 unknown 不应干预 cancel_active。
- `timeout 30s cargo test --locked --test nexus_bridge_regressions -- --test-threads=1`：4 条基线失败，覆盖 ACK 早于断流、停止先于 uncertain、单 lease 断连、CLI 控制容量耗尽。
- `timeout 30s cargo test --locked --lib router::nexus_bridge::cache::f1_regressions -- --test-threads=1`：3 条基线失败，覆盖取消赢得发布、路径/内容快照不一致、已有 IDB 无输入证明。

后续 F1 获授权增加结构化公开取消结果，补齐 P1-1/P2-6 双通道贯通回归；F2 再覆盖早到 open 断连和到期后停止证明。当前预期为上文 gate 13 的十项全部通过。旧 `n3-fix1/check-env.sh` 的 `F1_PYTHON` 指向旧补丁 baseline-env，仅用于基线诊断；F1 最终验证命令显式覆盖为 continuation/probe-final-root 指向的新补丁 venv（早期绿例为 probe-v2-root）。F2 重新 prepare 新环境，不能直接 source 旧脚本充当最终验证。
