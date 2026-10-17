# Testing

N6 的完整工具与能力覆盖见 [能力对照表](plan/nexus-n6-capabilities.md) 和计划 N6 小节。
真实验证为四个独立套件：lifecycle 9、contract 4、concurrency 14、n6 4；历史结果
不能代替改动后的验证。正式结果、每条命令的 exit/uptime、失败历史与审计保存在外部
`/tmp/ida-nexus-run-20261015.98rmfb/n6/report.md`。

`--suite n6` 必须指定固定 N0 `--baseline`，检查 E04-N6、E20、N6-tools、E20-cancel
四个实际 PASS 场景。E04-N6 包含 73 项方法/写后读回对照（57 个方法）、x86 汇编成功/读回两项，
另有 N6-F1 的 18 项缺失元数据/地址边界/无栈帧严格对照；
N6-tools 从当前注册表生成工具及所有 aliases 对照，另检查 N7 明确拒绝和 backend_counts。
E20 对七类写入显式保存、关闭、重开并严格读回，还检查部分 batch、异常脚本及取消的
已发生副作用。普通/函数注释使用官方读取 API，保留 stderr 为空的断言。
23 个 dbg_* 覆盖真实 IDA 空闲调试器、断点及错误契约；活动 debuggee 的成功路径未覆盖，必须在 N8 全量验收前补齐。

使用新的 prepared root、独立 home/state/profile、样本副本与短 TMPDIR/IPC。
`--tmp-root` 必须解析到该环境的 tmp；不能复用已有 process ledger 的环境。
准备允许180秒，真实套件内层180秒；执行前说明外层210秒用于整套验证及精确清理。
所有其他检查默认30秒，逐次记录前后 uptime、完整 argv 和 exit；exit124不算通过。

```bash
ln -s "$N0_ROOT/tmp" "$N6_TMP"
uptime
timeout 210s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_e2e.py \
  --root "$N0_ROOT" --target "$CARGO_TARGET_DIR" --sdk "$IDASDKDIR" \
  --tmp-root "$N6_TMP" --ipc-root "$N6_TMP/i" --suite n6 --baseline "$N0_BASELINE"
result=$?; uptime; test "$result" -eq 0
```

`compare_nexus_n6.py` 先通过公开 auto_wait 完成分析、验证输入元数据、显式保存并关闭
seed IDB，再复制三份 SHA256 相同的文件。工具对照在重开后、等价分析/类型 setup 后
再次严格检查该完整 fixture 的元数据，原始响应先于比较落盘；意外缺失路径/大小/哈希必须失败。
E04-N6 的预建副本也运行同一 checkpoint。失败时在关闭前通过公开 API 记录 owner 的实际 IDB/root filename、原始 ida_nalt 返回值、磁盘 SHA256/mtime、PID/record_id 和同 state 的公开实例列表；预建记录含打开前的磁盘指纹。产品缺失分支将同类只读取证写入 owner 的 warn 日志，不补造元数据或等待全库分析。进程历史仅表示 adapter 已观测的数据库，不能证明附加前的历史；独立创建的 worker 另由测试账本证明。取证不读取 token 或环境变量。
`tests/support/n6_metadata_repro.py` 在全新 prepared 环境仅跑 tools/E04 的预建元数据步骤；`--inject-missing` 主动删自有 fixture 元数据以验证严格失败和取证落盘，不计自然 r9 复现。r9 根因不能由后续 PASS 关闭，结论以委托取证报告为准。
独立的 n6-edges fixture 则通过公开 SDK delinf 删除存储字段，并用真实无栈帧函数
对照合法缺失分支的空路径、零大小、零哈希与 -4/-5 错误结构；两类前提分别断言。
产品按旧 native 契约序列化缺失值，不恢复原始输入信息；不通过重复运行挑选通过结果。

比较器只登记两条批准规则：`build_callgraph.result.nodes` 按唯一 `address` 配对，
证据为 N0 同库8次出现两种顺序的 `n6/dev/preflight-result.json`；
`get_xrefs_to_struct_field.result.tid` 优先严格比较同一预建 IDB 副本，仍有分配差异时，
要求合法且结果内唯一、同会话稳定、可输入公开 get_udm_by_tid、完整实体严格一致。
实际例外使用与 witness 一并落盘。其他值、类型、edges、未登记数组、地址/偏移/大小
保持严格；Nexus nodes 按数值地址稳定排序。九项单测保留正反例：

```bash
uptime
timeout 30s python3 -B -m unittest discover -s tests -p test_nexus_n6_compare.py -v
result=$?; uptime; test "$result" -eq 0
```

结束必须 cleanup/assert_clean、登记文件为空和自有 socket 为零，失败/中断环境也要审计。
不得按进程名清理或操作其他客户端。无隐式 fallback 的全注册表/能力测试为
`n6_every_registered_tool_and_old_capability_has_an_explicit_path`，标准 lib 门禁覆盖它。
12项标准门禁、第13项（F1_PYTHON）、lib连续三轮、N0 support、bridge pytest、fix系列
与两个probe红绿对照继续保留；不能用N6新套件代替回归套件。

## Run tests

```bash
just test         # Stdio JSONL integration test
just test-http    # HTTP / SSE integration test
just test-script  # IDAPython script execution test
just test-dsc /path/to/dyld_shared_cache_arm64e  # DSC loading test
just cargo-test   # Unit tests (no IDA required)
just test-list-idbs  # list_idbs against a real, isolated daemon
just test-decompile-line-addresses  # decompile_function line_addresses, same setup
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

**list_idbs test** (`just test-list-idbs`, `tests/list_idbs_e2e.rs`)

- Starts a temporary `serve-http` daemon under an isolated `IDA_CLI_HOME`
  (never `~/.ida`) and stops it with `shutdown` through that home
- Two MCP sessions over the daemon's Unix socket each open one database;
  `list_idbs` (MCP and `ida-cli list-idbs`) lists both with distinct client
  ids, paths and worker pids, never a close token
- Closing one database removes only its entry; a shared database stays listed
  until its last reference is released
- Needs `IDA_TEST=1`, an IDA runtime and a C compiler; `IDA_CLI_E2E_BIN`
  tests another build (for example the release binary) and
  `LIST_IDBS_E2E_OUT` writes the transcript of every answer

**decompile line_addresses test** (`just test-decompile-line-addresses`,
`tests/decompile_line_addresses_e2e.rs`)

- Starts a temporary `serve-http` daemon under an isolated `IDA_CLI_HOME`,
  opens a small compiled fixture over MCP and decompiles one function with
  and without `line_addresses`, over MCP and over `ida-cli decompile`
- Checks that the default answer is still only `{code}`, that `lines` has one
  entry per pseudocode line with the same text as `code`, that addresses are
  ascending, unique and inside the function, and that every address on a line
  is one the decompiler maps to a statement (`get_pseudocode_at`)
- Needs `IDA_TEST=1`, an IDA runtime with Hex-Rays and a C compiler;
  `IDA_CLI_E2E_BIN` tests another build and `DECOMPILE_LINES_E2E_OUT` writes
  the answers

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
`client-cancel-unknown.patch`, then `client-close-proof.patch`. Preparation verifies the patched `handle.py`
SHA-256 and records patch status. Only a validated upstream fix passing the
probe and N0/N3 gates permits removal; N9 packages must carry all three local patches, including `loopback-bind.patch`.

Close proof uses `close_outcome`: nonfinal lease ACK, final owner lifetime proof,
or uncertainty. On uncertainty the bridge reports it before one bounded public
`wait_database_released` check; an unconfirmed release retains router tracking and
blocks another open of that path. Existing `close()` retains its legacy contract.
Prepare a fresh close red environment with `--without-client-close-patch` (cancel
patch still applied), then run the command below with `--expect-unpatched`: exit 2.
The fully patched fresh environment must exit 0; `close-proof.json` records the
real ACK, lost-ACK uncertainty, one release request and owned cleanup.

```sh
timeout 30s "$N0_ROOT/venv/bin/python" scripts/nexus/probe_close_release.py --root "$N0_ROOT"
```

Open failures emit warn diagnostics with component sizes/mtime and public owner
state/lifetime, without registry secrets. E22 failure evidence is saved before
candidate cleanup as `E22-<kind>-failure-diagnostics.json`. Run ten complete
contract suites on final HEAD in distinct fresh environments (inner 180s, outer
210s, each with uptime); no recurrence means only “未复现，取证已就位”.

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
selects a short external evidence directory; otherwise it uses TMPDIR. The N7
publication protocol regression belongs to this integration target, never the
standard lib gate. Its isolated integration-test child uses the real bridge/N1.
Enable `nexus-test-support` explicitly for gate 13 (15 cases); this feature only
enables protocol test support and the syscall barrier. Without it, an explicit
gate-13 invocation fails with Cargo's required-feature message. Standard lib
gates need neither F1_PYTHON nor F1_ROOT. Cache tests use private TMPDIR roots.

```bash
timeout 30s cargo clippy --locked --all-targets -- -D warnings
timeout 30s cargo clippy --locked --all-targets --features nexus-test-support -- -D warnings
F1_PYTHON="$N0_ROOT/venv/bin/python" F1_ROOT="$N3_ROOT/r" timeout 30s cargo test --locked --features nexus-test-support --test nexus_bridge_regressions -- --test-threads=1
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

## Nexus N4 output contract

N4 adds `tests/nexus_contract_e2e.rs`. Prepare a separate fresh patched environment
and use the fixed N0 binary recorded below; the verifier rejects a missing baseline
and the comparison driver verifies its SHA256. No installed CLI or old source is
used. Run from this worktree, with the same explicit target and SDK as N3:

```bash
timeout 210s "$N4_ROOT/venv/bin/python" scripts/verify_nexus_e2e.py \
  --root "$N4_ROOT" --target "$CARGO_TARGET_DIR" --sdk "$IDASDKDIR" \
  --ipc-root /tmp/n4-contract --suite contract --baseline "$N0_BASELINE"
```

The suite has four actual tests and four distinct PASS records: E04 compares 38
cases across all twelve initial methods; E16 exercises the shared runtime/error
cases through CLI, stdio MCP and HTTP MCP, including independent HTTP close tokens;
E17 checks Unicode, separate streams, script errors, concurrent response identity,
deadline cancellation and abandoned CLI lease release; E22 uses three databases
saved by N0, preserving user names/comments on a SHA256 match and preserving original
bytes when the recorded hash is missing or different. Warm references are independent
and must release before reopening. E22 has a 90-second inner driver timeout because
it builds three native baseline databases; other drivers have 30 seconds. The whole
suite remains bounded at 180 seconds, with the 210-second outer cleanup supervisor.
`contract.log`, `contract-result.json`, `E*-result.json`, `comparison.json`, per-client
logs and the process ledger provide evidence. The baseline error presentation and
cache envelopes remain transport-specific: CLI writes large JSON to its cache, while
MCP retains its existing inline response. Only input path spelling is normalized,
after verifying identical SHA256; output structure and text are compared exactly.

N4-F1 also runs `timeout 30s python3 tests/test_nexus_n4_fix.py -v` for
per-item decompiler exceptions, script C-string/truncation behavior, unverified
processor ABI availability and recursive JSON type equality. Rust regressions
cover zero-limit Nexus GC, rejected shutdown, enqueue admission/task identity,
lossless open delivery under injected broadcast lag, result allocation ownership,
and both event orders. The event helper buffers unmatched events; startup/barrier
budgets (15s) are distinct from response budgets (5s). Each verification records
`uptime`; failures are retained instead of being hidden by retries.

E04 includes N0 binary comparisons for NUL-leading and over-limit script errors,
and a public Hexrays_Hooks fault on an existing function: that item must fail while
a second valid function still decompiles. JSON scalar types and nested types must
match exactly. Only the already documented verified input path is normalized.

N4-F2 adds seven fault cases through the production Rust `Tools::open` /
`open_owned` path using an internal bridge wire fixture (no real IDB). They cover
zero-byte cancellation, cancellation/expiry before grant, bridge rejection,
remote error, total-deadline fallback with late acquisition, and control-lane
saturation after acquisition. Each case checks returned failure, recovered open
permit/reply slot, same-path reopen/close and confirmed cleanup of acquired leases.
These new subprocess fixtures serialize their startup to avoid adding a burst to
the parallel library suite. A pure N1 contract checks owner validation and cleanup
state after NotSent; the existing real lifecycle/contract suites remain required.

The separate test-maintenance commit gives the 16 MiB response a 25s transfer
budget, checks its full length and keeps its peer alive until connection state is
observed. Escaped-pipe startup has a 15s budget distinct from EOF/capacity assertions.
Late-success checks wait for the start marker (15s) before timing the response (5s);
P25 uses the shared event helper. Optional test-only `N4_F2_*_DELAY` variables inject
startup/transfer delays for red/green evidence. Five consecutive parallel library
runs record their own `uptime` and exit codes. The owner-lock regression checks
CLOEXEC, holds a child before exec, verifies immediate unlock on parent Drop, and
checks that the lock descriptor does not survive exec.

Known limits: run_script uses process-level __main__; clients and leases sharing
an owner share script globals, which closing a lease does not clear. This matches
the old per-IDB worker and is intended for trusted scripts, without client
isolation. N7a adds cross-router open locks around E22 verification/open and
coordinated generation GC (see below); independent external writers remain
outside the hash/open transaction. Deletion requires ownership/lock absence proof. Unverified processor ABIs use the public
short name with an IDA-version warning; the verified 9.5 E04 stays exact.

## Nexus N0 isolation and baseline

N0 prepares and verifies the dependency environment only. Business handlers
use their selected development path. N3 lifecycle and N4 contract targets are
implemented; other planned `nexus_*_e2e` targets remain future work and cannot be
counted as executed tests.

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
`cargo clippy --locked --all-targets -- -D warnings`,
`timeout 30s cargo clippy --locked --all-targets --features nexus-test-support -- -D warnings`, and
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

后续 F1 获授权增加结构化公开取消结果，补齐 P1-1/P2-6 双通道贯通回归；F2 再覆盖早到 open 断连和到期后停止证明。当前预期为上文 gate 13 的原十项回归保留；N4-F1 另加两项确定性事件助手回归。旧 `n3-fix1/check-env.sh` 的 `F1_PYTHON` 指向旧补丁 baseline-env，仅用于基线诊断；F1 最终验证命令显式覆盖为 continuation/probe-final-root 指向的新补丁 venv（早期绿例为 probe-v2-root）。F2 重新 prepare 新环境，不能直接 source 旧脚本充当最终验证。


### N4-F3 E22 与失败清理回归

E22 验证匹配旧库后保留原输入快照，再让活动 owner 保存数据库，随后验证 keep-warm 与最后释放。可用 `scripts/verify_nexus_e2e.py --suite contract --case E22` 单独运行，其他参数沿用完整 contract 命令；每轮必须全新 prepare，内层 180s、外层 210s。测试环境根目录的 `e22-reverify-save.inject` 仅由测试 bridge fixture 使用：若再次验证已打开的 packed IDB，就让该真实 owner 修改重复注释并保存，以确定性触发验证窗口。绿例必须保留快照且不再进入该窗口。所有样本和保存均在私有环境中。

第十三门禁现有 13 项，新增 P25 事件流断开后的 RAII 释放回归；失败时先救援测试 barrier、回收任务，再断言，红例也不遗留 Control 许可。库测试另覆盖已验证快照、owner 保存、取消、未关闭 probe 和发布冲突；原库内容与无覆盖断言保留。


## Nexus N5 concurrency acceptance

Use a fresh N0 prepared environment and a short root under the delegated evidence
folder. Both IPC paths and CLI home paths must fit macOS Unix sockets: a path of
104 bytes already exceeds the usable `sun_path` length. Do not reuse a suite root
with a process ledger. All IDA samples, profiles, CLI home and state are isolated.

`verify_nexus_e2e.py --suite concurrency` requires `--baseline` naming the fixed N0
binary. It runs exactly 14 tests and checks the complete PASS case set: E08–E15,
E18, E26, N5-hooks, N5-lifecycle, N5-reconnect and N5-compare. The test driver builds
its PyDLL fixture with `timeout 30s cc`; the fixture also exports 80 independent
functions for real search fairness. The suite uses marker/FIFO/protocol barriers,
separate 15-second startup and 3-second response budgets, and an inner 180-second
shell timeout. Announce an outer 210-second timeout for exact cleanup before use.

The comparator saves `n5-comparison.json`: 76 exact scalar-type/shape/value checks
against the fixed binary include repeated/invalid addresses, batch ordering,
search limits including zero, no matches, Unicode and injected decompiler errors.
N5-F1 adds JSON scalar strings and Rust u64 address grammar cases (prefix/case,
outer versus inner whitespace, signs, underscores, Unicode digits and overflow),
also exercising N4 address methods with the same strict CLI error rule as E04.
Hook tests cover real external rename/comment/type with unconsumed public events,
installation/state/module loss, shared lease references, killed bridge cleanup,
new-owner rejection and self decompilation. E11 keeps real startup analysis work
pending through a public import script; E12 tests explicit wait independently.
E26 holds the GIL through ctypes.PyDLL, checks pending cancellation and conflicting
writes, then releases the native FIFO into a cooperative cancellation boundary.
It does not establish arbitrary Hex-Rays GIL behavior.

Run the lifecycle 9 and contract 4 regressions separately with fresh prepared
roots. Keep E04 at 38 exact comparisons, both patch probes' red/green evidence,
the 12 standard gates plus gate 13, N0 support 37, bridge pytest 30 and N4 fix 5.
Run lib at least three consecutive times. Every invocation records uptime and its
exit status; retain failed runs and explain the changed variable before rerunning.
Audit each environment with cleanup/assert_clean and exact registered process
identities. A timeout, ignored replacement assertion or zero-test run is not PASS.

N5-F1 E18 pauses the consumer of a real socketpair relay on the business output
lane. It proves a blocked kernel send of the large real Nexus response, a full
unchanged 512-item bridge queue and one pending producer. Router/control/B remain
responsive. After resuming, all 513 test status messages arrive in order and A
serves another query. E10 additionally aborts an actual router continuation while
N1 reports Queued behind a barrier, then observes `_n5_cleanup` releasing the last
hook without closing its lease. The bridge callback regression covers an older
physical delivery after its successor starts and after that successor completes.

Each real suite and gate 13 must finish with no socket under its IPC root.
The bridge unlinks its own lifetime endpoint, and its Rust parent also removes
that exact endpoint on shutdown/termination/drop/readiness failure. Test
`Environment` journals exact socket paths with device/inode and owner birth;
after owned processes exit, cleanup can remove recorded leftovers from SIGKILL.
It refuses live owners or replacement files and never scans names to authorize
deletion. The suite-wide scan is an assertion only. Keep the socket journal,
process ledger and final zero-socket audit alongside the test logs.

N5-F2 adds array-text JSON boundaries (nonfinite/overflow, signed zero, duplicate
keys, Unicode surrogates, trailing input and the serde recursion boundary). Rust
uses the legacy `Vec<Value>` decoder before IDA sees the input. Nested invalid
addresses stay in Rust and are restored by position after the owner returns;
the intermediate adapter envelope does not consume their nesting budget. The
127-level accepted value uses the existing MCP text result for strict comparison;
the raw CLI response decoder's existing recursion limit remains unchanged.

Gate 13 now runs 14 tests: its added startup test exercises 12 combinations of
dropped future, Preparation cancellation or deadline at pre-readiness, lifetime
bind, pre-business-connect and pre-control-connect barriers. It waits for the
exact child to exit and for all three exact endpoints to disappear. Fixture
journalling precedes Bridge initialization, including a record immediately after
lifetime bind; N0 support tests interruption inside that initialization. The
old-attempt lib regression injects callbacks after real N1 dispatch and before
receiving/registering pending, as well as after pending and terminal completion.

Five offline encoding faults (surrogate, nonfinite, unsupported object, circular
object and excess response depth) must each return a diagnostic request error, then serve both leases and
the control lane on the same bridge. E08 repeats the surrogate and depth cases through real
Nexus, requires Failed plus confirmed stop and the preserved encoding cause,
then queries both leases without reconnecting. OS I/O failure still disconnects
the physical channel; encoding failure before any write does not.


## Nexus N7a cache and preprocessing acceptance

N7a-F1 外部差异逐字段登记（旧行为、新行为、影响和验证范围）：

| 字段/行为 | 旧行为 | 新行为 | 影响 | 验证范围 |
|---|---|---|---|---|
| `open_idb.result.path` | 平铺 basename/hash 缓存路径或直接 IDB 路径 | 新库位于 `generations/<unique>/input.i64`，有效 legacy 与直接 IDB 保留身份 | 调用方可见路径变化；force/GC 后缓存路径不永久；GUI 直接开 packed 文件不参与 flock | special 的 F3-cold 同库/owner、保存重开；直接 IDB 单测；GUI 真实行为留 N7c |
| `get_database_info.input_file_path` | 通常为原输入元数据路径 | 可能是代际 `input` 快照 | 不保证等于用户原始路径；status.open_path 仍为 canonical 请求路径 | E04 仅在输入 SHA256 相等后规范化本字段；不比较 open 返回路径，不扩大例外 |
| basename/hash 布局 | 外部脚本可按旧布局枚举/推导路径 | 新库由内容键索引选择最新代际 | 根级 glob/文件名推导须适配；编辑成果关闭后备份到缓存外，旧平铺库不搬家 | N6 夹具两种布局都显式枚举且仍要求恰好一个库 |
| `IdbStore::clean()` | 移除孤立索引并返回移除项 | 同时处理两种索引，恢复不删健康库契约，不做全量 GC | 健康库和 quarantine 数据不变；不确定/错误有日志 | F4 健康库、真实返回项和重复调用 |
| 预热 `cached_before`、list/统计 | 仅旧平铺观察 | 命中来自实际选库结果；当前代际与 legacy 元数据按键合并，错误可见 | 重复预热正确命中，新代际不再遗漏或重复计数；无法恢复原元数据时 list 使用 input 快照 | F5 单测观察身份一致；F3-cold 两次预热皆命中 |

special_inputs 的实际数量为 8，新增 F3-cold：A 在真实 opened 事件交给 router 发布索引前暂停，B 并发冷开；验证内容键 EX 正被持有、同一个 IDB/owner、写入互读、保存重开与重复预热命中。F1/F2/F7 回归见 `tests/test_nexus_n7_fix1.py`；F3/F4/F5/F6 的 Rust 回归名含 `n7_fix1`。S1 单独的 `nexus_n7_fix1` target 使用真实 bridge 和确定性客户端协议 fixture；短回归不额外 close/shutdown 即消费迟到 Released，长回归让 120s observer 实际结束后才投递证明，验证下次 open 收敛旧 guard（该 target 需提前说明并使用 150s shell timeout）。这些协议 fixture 不等同真实 IDA E2E。

S1 复跑前在仓库根目录，先用 `scripts/prepare_nexus_env.py` 完成全新离线 prepare，
并把 `S1_PYTHON` 改为该环境的绝对 `venv/bin/python`（含固定客户端补丁）。
本机需已安装 Rust、`timeout`、IDA 9.5 和匹配 SDK。下面每个用例独占短目录，
分别给 150s；两个 122s observer 用例串行合计需要约四分钟。不得用 lib 或 gate13 代替。

```bash
S1_PYTHON=/absolute/fresh-env/venv/bin/python
for S1_CASE in s1_dropped_close_releases_root_without_another_close s1_expired_observer_next_open_consumes_exact_proof s1_expired_uncertain_open_observer_consumes_exact_proof; do
  S1_ROOT=$(mktemp -d /tmp/n7s1.XXXXXX)
  mkdir -p "$S1_ROOT"/home "$S1_ROOT"/state "$S1_ROOT"/tmp "$S1_ROOT"/proof
  uptime
  env -i HOME="$HOME" USER="$USER" PATH="$PATH" LANG=C.UTF-8 IDADIR='/Applications/IDA Professional 9.5.app/Contents/MacOS' IDASDKDIR=/Users/pingzi/Developer/tools/ida-sdk-9.5/src CARGO_TARGET_DIR=/tmp/ida-nexus-run-20261015.98rmfb/n1/target IDA_CLI_NEXUS_DEV=1 IDA_NEXUS_PYTHON="$S1_PYTHON" IDA_NEXUS_IPC_ROOT="$S1_ROOT/ipc" F1_ROOT="$S1_ROOT/proof" IDA_CLI_HOME="$S1_ROOT/home" IDA_NEXUS_STATE_DIR="$S1_ROOT/state" TMPDIR="$S1_ROOT/tmp" timeout 150s cargo test --locked --test nexus_n7_fix1 "$S1_CASE" -- --exact --test-threads=1
  S1_EXIT=$?; uptime; test "$S1_EXIT" = 0 || break
done
```

F10 释放协调：每个自有 handle 新鲜检查保护后至多 release 一次；原/辅助请求
全部推进后才等待所需公开 owner lifetime。未知 ACK 保留精确责任，第三方 sibling
仍阻止 owner 证明，不重放或强关；辅助保护无法确认时不关闭。保存拒绝累积返回。

F11 在组内传播已经取得的公开 owner lifetime 证明，包括首成员期限耗尽后、
后续成员才证明释放的边界；核对 record_id、pid、started_at、IDB 路径和 backend，
不改写各 lease 原始 ACK。有效非最后 ACK 全部成立时，本组可释放，第三方仍可使用。
`timeout 30s "$S1_PYTHON" -B tests/test_nexus_release_matrix.py` 枚举 189 个可达状态，
逐组合断言 I1–I6、原始 ACK，并检查五种不同 owner 身份不能混用。
矩阵用协议 stub 和真实公开 lifetime API/隔离 flock；保护失败的具体 IDA 分支另由
`test_nexus_r9_guard.py` 和保存保护回归覆盖。`F11_SOURCE` 可指向输入版 bridge 归档，
`F11_MATRIX_RESULT` 可指定逐失败组合 JSON；3,280 个名义组合的排除统计也写入 JSON。

固定 N0 的预建副本对照在编辑前通过 `baseline_prebuilt_open` 检查元数据。
仅当空 `input_file_path`、size 0、MD5/SHA256 全零同时出现，且预建 seed 元数据
完整、seed 与副本 packed SHA256 均未变时，允许 N0 额外重开至多两次。
每次记录时间、uptime、原始打开/元数据响应与关闭前后磁盘哈希到
`baseline-reopens.jsonl`；磁盘改变或三次仍失败就失败，不恢复坏副本、不跳过比较。
r9 是 IDA 9.5 idalib 上游缺陷，旧 native 也受影响；此规则只用于 N6/E04-N6、
N6-tools 与 x86 的固定 N0 预建副本，不重试刻意缺元数据的 compatibility fixture
或 `n6_metadata_repro.py` 原始取证驱动。
Nexus 测试侧不加重试，只使用产品自动重开；比较器和两条既有字段例外不变。
全部 `test_nexus_*.py` 须每文件单独运行，并在 `env -i` 白名单下再各跑一次。

GC 对配置 state 注册只做只读文件名/公开 record_id 集合对照，用于拒绝；不碰 Nexus 锁和状态内容。合法 dead 注册由公开发现 reap，之后仍须 packed、无组件等完整检查；预算选足即停、最终删除也受本轮容量约束。manifest/journal 的数组、null、标量和错误字段类型只拒绝本条目，其他候选继续。

旧平铺缓存一律保留、继续计磁盘且可能长期超限，无自动迁移工具；force 不迁移用户修改、不回收旧空间。N8 全量验收前的 dry-run/可恢复迁移或离线清理途径已登记在计划，最终是否必须实现由用户裁定。本轮不操作真实旧缓存。

Use a fresh prepared environment, `IDA_TEST=1`, short `--ipc-root`, private
`IDA_CLI_HOME` / `IDA_NEXUS_STATE_DIR`, and the fixed N0 binary. Run
`verify_nexus_e2e.py --suite special_inputs` with the existing root/target/sdk
arguments under an announced outer 210s timeout (inner suite timeout 180s).
Exactly 8 tests and eight PASS case files are required: E19, E21-held,
E21-before-rename, E21-after-rename, E21-before-delete, E21-release, E21-lock, F3-cold.
Each Python driver uses 30s. The lock case exercises the actual Rust IdbStore
maintenance subprocess while a real router owns a lease, then releases and
reclaims after repeated checks. The suite alone configures GC grace to zero;
the release driver additionally checks a nonzero grace without guessing timing.

E19 queues a real router open through the optional trusted
`IDA_NEXUS_INPUT_PREPROCESSOR` executable, whose two arguments are input and a
private staging output. A marker confirms its descendant started; status and
another real database remain responsive before cancellation. Require cancelled
with confirmed stop, both exact process identities gone, no output or staging,
and another successful query. No real sbx/DSC sample is used here (N7b).

E21 uses independent public Nexus clients and real IDBs. Occupancy refuses GC;
force-refresh from the original input publishes a different directory and keeps
the held database's bytes/hash unchanged. Deterministic callbacks in the shared
maintenance implementation insert an opener after precheck, after rename and
before final delete. Original-path opens after isolation must fail explicitly;
they do not target the excluded quarantine-path scenario. After release/grace,
reclaim and normal reopening must succeed. Synthetic public-probe injections in
`timeout 30s python3 tests/test_nexus_n7_cache.py -v` separately exercise rollback,
corrupt journal, restart epoch, symlink refusal and all conservative states.
Keep the baseline missing-protection red evidence alongside green results.

Nexus cache layout is `generations/<id>/{input,input.i64,generation.json}` with a
content-key index. Root shared flock spans product preparation/publication and
tracked leases; GC uses exclusive nonblocking flock and an atomic non-replacing
whole-directory rename into `quarantine/`. Failed/cancelled opens retain both
locks until N1 confirms no lease was acquired or the exact lease is Released;
unknown outcomes retain protection. Same-IDB open locks cover bridge
verification through final open. GC rechecks original and isolated paths, then
waits `IDA_NEXUS_GC_GRACE_MS` (default 60000), with at least two observations and
a final check. Restart epoch/time rollback resets grace; invalid journals are
retained, restoration collisions retain both paths. Explicit IdbStore remove follows these checks; clean only removes orphaned
metadata under the root exclusion lock and never deletes healthy databases. `nexus_bridge/cache_store.py --root <cache> --epoch
<router-incarnation> --limit 0` is the same maintenance entrypoint; an epoch must
be stable across one router's passes and new after restart. Low-level explicit
cleanup reports refusals in JSON; router GC logs them. Legacy flat groups lack an
atomic directory container and remain untouched with a refusal reason.

Protection is conservative: any tracked lease postpones GC for the whole cache.
No finite-space guarantee exists for externally busy/unknown/legacy groups.
Public discovery sees only the configured state directory. An independent
opener directly using the quarantine path, or holding an unregistered FD at the
last check, remains outside protection. E22's external-writer hash/open window
remains; cooperating router opens/publications/GC use the shared lock family.
These are accepted limitations, not a claim of global external mutual exclusion.

After final commit run the 12+13 standard gates, three consecutive lib rounds,
N0 support, bridge pytest, n*_fix* tests and all three patch probes red/green.
Run fresh lifecycle 9, contract 4, concurrency 14, N6 4 and special 8 suites.
Record current HEAD, full commands, exits and uptime; assert cleanup CLEAN,
all registered process identities exited and zero residual sockets.

### N7a fix2 residual coverage

`tests/test_nexus_n7_fix2.py` covers public state-directory resolution (absolute
and tilde) and candidate-local numeric bounds. `nexus_n7_fix2_store` requires
`IDA_CLI_NEXUS_DEV=1` and checks mixed healthy/stale indices independently.
The gate-13 publication protocol pauses a real FIFO read after commit arbitration,
drops the waiter and waits for exact N1 Released plus retained-guard removal.
A second same-key preparation must wait, then consume the published index.
Both blocking publication jobs own the content EX guard themselves.

N2 fixture barriers have separate startup/dispatch (8s) and operation (10s)
bounds. Barrier waits also observe early operation completion and report whether
the Python worker started and which requests arrived. Existing post-barrier
response/cancellation assertions remain 1–2s. A startup socket regression holds
the worker before its first request and releases it explicitly. Validate the lib
gate three times concurrently with a fresh real E2E suite; do not serialize these
runs to hide scheduling failures.

Owner tool source explicitly installs a separately evaluated metadata capability
namespace. Missing/noncallable dependencies fail installation; first request,
reconnect and replacement owner all execute the same checked installation.

### r9 owner save protection

r9 is classified as an IDA 9.5 idalib upstream defect; its exact native trigger remains unknown. `save_guard.py` samples the public netnode
name before/after each owner operation and before close. Missing or unverifiable
Root Node permanently poisons that owner, refuses operations/adapter saves, and
sets public `DBFL_TEMP | DBFL_KILL`. Final close discards abnormal unpacked state;
the packed file remains at its last successful save and unsaved edits are lost.
Close still establishes the exact N1 release proof and returns an explicit error.
An owner hook checks automatic save/close as well; it does not rely on notification
return values as a veto. Initial-open failures now use the bounded retry below.

`tests/support/n7_r9_guard.py` takes a fresh prepared root, current binary and
private seed. It kills Root Node via public IDAPython in isolated owners, checks
both shared releases and save errors, original hashes, reopening metadata, open
rejection, and normal save/close persistence. `test_nexus_r9_guard.py` checks
first-transition attribution, probe errors, diagnostic isolation and close hooks.
Keep a baseline binary/bridge copy for red/green; injections are not natural r9.
Validate first-failure owner logs contain method, operation id, lease and previous
sample. Healthy operations add two name lookups and context/time updates; initial
installation reads four metadata fields. No full IDB hashes or discovery scans
are added to healthy requests.

User scripts directly calling IDA save APIs and independent clients' explicit
saves are outside coverage; TEMP/KILL only prevents automatic close writeback.
The owner guard cannot intercept Nexus startup/recovery before its installation;
the recovery protection below is explicitly post-recovery rollback.
Sampling bounds the first loss interval; it does not establish r9's root cause.

### Optional metadata diagnostics

Runtime diagnostic getter/sampler/JSON errors emit a warning and preserve the
completed get_database_info result; they never replay the business request.
Missing installation capabilities still fail explicitly. Root Node checks are
save protection, remain separate, and refuse open/save if missing or unverifiable.

IDA_CLI_NEXUS_FORENSIC_HASH defaults to 0 (unset is also off); only 1 enables
complete pre-open IDB SHA256 reads. Normal open and missing-metadata disk context
use stat fields (path, size, mtime, inode/device) without reading packed contents.
Opt-in hashing consumes the existing open deadline and is for directed forensics.
Explicit test/failure harness calls to idb_fingerprint or evidence context
forensic_hash=True also request a complete fingerprint. E22 integrity
verification still performs its required content checks independently of this
diagnostic switch. Root Node protection never depends on an IDB file hash.

tests/test_nexus_q1q2.py checks diagnostic failure results/warnings, installation
and business errors, default stat-only opens and opt-in read/hash counts.

### r9 root visibility investigation

The first failed Root check records the complete IDB/ID0 directory listings
(including locks), actual PATH_TYPE_CMD/IDB/ID0, flags before protection, packing
preferences and thread identity. Protection is armed before directory IO;
`flags_before_protection` retains the preceding flag values, while
`database_at_failure` and later protected-boundary logs describe the protected
session. Packing flags describe save preferences, not
proof of the input source. After arming protection, read-only rechecks target
50ms, 200ms and 1s within the operation deadline; scheduler delays are recorded.
Later visibility never clears a poisoned owner or authorizes a save.

`tests/support/r9_reopen.py` uses a private prepared root and seed copy for each
trial: A opens/edits/saves/releases, then a different owner B reopens. `--mode
immediate` uses public lifetime proof; `--mode wait` additionally waits for the
previous process and components to disappear. Use batches of 25 under timeout
180s, at least 100 trials per group. `--raw-first` probes Nexus before installing
any adapter guard. JSONL retains every trial and failed active ID0 snapshots;
exit 0 means the experiment completed, not that its root_failures count is zero.

`tests/support/r9_native.py` opens one private copy in a fresh idalib process,
without Nexus. It compares direct idapro, Domain, metadata getters, empty args
and Domain preimport; `--result` retains paths/flags/thread/rechecks and failed
live on-disk component copies. It discards instead of saving. These copies may
omit unflushed IDA memory and are not claimed to be memory snapshots.

Current directed evidence includes failures after the previous owner exited
and components disappeared, and a standalone Domain.open failure on a fresh
copy in the main thread with a complete active ID0. Direct idapro opens without
Domain or Nexus also fail, including before metadata getters. Waiting for
components is not an established fix. The precise upstream trigger is unresolved;
do not close r9 using a later PASS or relax E22-missing's unavailable assertion.

### r9 initial-open retry and post-recovery rollback

The approved product mitigation retries only a guard-confirmed first Root
sample failure, before any business request: TEMP|KILL, lease close plus public
owner-lifetime release proof, then a fresh open. There are at most three attempts,
all within the original open deadline. A mid-session loss never retries or
replays edits. Every failed attempt logs `Root Node initial-open failure` with
attempt/max, owner and full guard evidence; successful recovery logs
`automatic reopen succeeded after N attempts`. Owner evidence includes
`open_attempt`. Three failures explicitly report the count and retain originals.
GUI attachment does not automatically reopen or terminate the GUI owner.

All adapter opens take the N7a shared root lock and a database-specific exclusive
recovery-open lock. Public probe selects crashed/unpacked inputs before open.
Only these inputs create `$IDA_CLI_HOME/idb/recovery/<id>/snapshot`: immutable
0400 component/packed copies, original inode/device/size/SHA256 and a durable
journal. Normal packed opens do not copy/hash the IDB for this mitigation.
Nexus is allowed to recover and save internally. If the first Root check fails,
failed component bytes are captured before TEMP|KILL close removes them; after
lease AND public owner release, surviving products move to `quarantine-N`, and
original component contents/modes are restored with new recorded inodes.
This is post-recovery rollback: a bad packed product can briefly exist at the
original path before isolation. External openers do not honor our locks; public
occupancy rechecks narrow but cannot close that remaining race window.

Unknown release, changed inode/size/hash, unexpected directory entries, symlinks,
unexplained registrations or an external owner veto restoration. Preserve the
snapshot and scene and report the error; never overwrite uncertain files.
Partial filesystem/timeout failures also retain their journal and artifacts.
Snapshots, failed bytes and quarantined products are conservatively retained,
including after successful recovery. N7a GC counts their disk usage, reports
retention, and never deletes them automatically; it has no proof that their
forensic/rollback purpose has ended. Space grows with recovery events and failed
attempts. There is no automated migration/cleanup: archive or remove a reviewed
recovery directory only during explicit operator maintenance with all clients
stopped and original/isolated database occupancy independently established.
User scripts saving directly and other clients remain outside the guard.

`tests/test_nexus_open_recovery.py` tests ownership, identities, extra files,
external openers, deadlines, immutable snapshots, locks and GC retention.
`tests/support/n7_open_recovery.py --root <fresh-root>` runs six real bridge
scenarios including a malformed recovery packed saved before guard installation.
Use `--bridge <efbee3c-bridge-copy>` for the unchanged red assertions.
`r9_reopen.py --product-reopen` runs the product helper in both groups; JSON
reports natural initial failures separately from failures after retries. Run
at least 100 trials per group in bounded batches (each trial opens A and B).

### N7a-R R0 prototypes and current-product red baseline

R0 changes test/support only. `scripts/nexus/r0_run.py` refuses an existing case
root, runs each shard serially with shell `timeout`, and records argv, cwd,
environment variable names, source hashes, exit and before/after uptime through
`r0_record.py`. Use a new short `/tmp/n7r0.*` root, private HOME/state/IPC and a
fresh environment prepared by the existing preparer. Offline inputs may use
`r0_prepare.py --source <verified-fixed-source> --wheels <verified-wheels>` with
the preparer's ordinary remaining arguments; fixed SHA/wheel/patch checks remain.
Never run this on a user's environment, open IDB or installed CLI.

```sh
timeout 180s python3 scripts/nexus/r0_run.py --environment "$R0_ENV" --root "$R0_ROOT" --report "$R0_REPORT" --stage primitives --stage sdk --stage real
timeout 180s python3 scripts/nexus/r0_run.py --environment "$R0_ENV" --root "$R0_RUST_ROOT" --report "$R0_REPORT" --stage rust --idasdk "$IDASDK"
timeout 30s python3 scripts/nexus/r0_audit.py --root "$R0_ROOT" --root "$R0_RUST_ROOT" --output "$R0_REPORT/audit.json"
```

Cold Rust FFI builds may need the runner's per-command 180s allowance; each
fault shard is bounded at 120s and each ordinary check at 30s. Declare reasons
in progress before increasing a limit. An explicit `--target-dir` may reuse
only this task's private cache, with exactly one serial writer. Never count 124
as a pass. The Rust target is `--features nexus-test-support --test
nexus_r0_prototypes current_product_red_baselines -- --exact --test-threads=1`;
the runner checks and Clippies that actual feature/target. Format-check the
changed Rust test with `timeout 30s rustfmt --edition 2024 --check
tests/nexus_r0_prototypes.rs`. Python checks use compile/AST plus Ruff F/E9;
the shell launcher needs `sh -n`.

`r0_os` observes native birth/exec, escaped descendants, inherited/queued FDs,
public occupancy limitations, and separately labels injected U6/revocation
inputs. `r0_transfer` checks actual writer PID/epoch and action counts, not just
external lock exclusion. `r0_records` exercises bounded summaries/ref epochs and
durable crash boundaries; its I/O errors are injected. `r0_durable` additionally
exits inside writes for summary/intent/state at five flush/fsync/rename/directory
boundaries and recovers in a fresh process. Pending writes require a private
inode/content-bound ownership record; unknown/partial/conflicting slots remain
explicit errors. `r0_contract_checks` rejects OS/boot evidence for N1 consumers. `r0_install` runs from a
private complete bridge installation, challenges sitecustomize before launch,
and checks ordinary/-I/-P/PYTHONSAFEPATH, exact schema/closure, every member
permission/hash, omitted payload/dependency and mismatched preexisting pyc. The
loader executes only the verified in-memory source bytes; -B alone is insufficient.

`r0_sdk` generates and exercises a temporary three-file U1 candidate; production
patches stay unchanged. `r0_real_ida` uses one disposable tiny IDB and a second
independent public client; it verifies loaded v1 code/ABI/dependencies against
fixed source by whole-object equality, then deliberately removes Root only in that IDB to test TEMP|KILL
and packed-byte retention. Its owned workers are registered, waited and audited.
No large database, GUI or full-feature E2E belongs to this shard. `r0_v1_checks`
compares independent-interpreter keys and rejects missing/extra functions/hooks,
changed parameter/default/function-default values and dependency bindings/versions.
The key is for trusted-owner compatibility, not an arbitrary-code sandbox. SDK
regressions include parsed ACK vs all cleanup exception classes and each original
internal attach attempt: a later rejection/success never clears an earlier unknown.

The Rust harness uses actual RouterState/Tools/N1, production bridge and pinned
SDK. Only HTTP/SSE and native IDA input boundaries are controlled. F1 uses real
Tools open/close/reopen; F4 uses N1's wait_analysis acquisition path (direct IDBs
in Tools intentionally disable analysis); F2 disconnects a real SSE stream,
loses release ACKs and observes auxiliary cleanup plus unrelated B. The target
passes by asserting **current production defects**; no `Released`/private errors
are injected and no open/attach/guard/lifecycle method is replaced. Product fixes
must replace those expected-red assertions in the owning later milestone.

`r0_freeze.py --run <primitives-run.json> --os <os-case> --sdk <sdk-case> --rust
<rust-cases> --report <report-dir>` emits `capabilities.json` and
`contract-freeze.json` linked to actual evidence. It requires successful recorded
experiments. Audit after failed runs too: `r0_audit --cleanup-stale` can remove
only explicitly attributed dead test registrations/sockets; it sends no signal,
keeps stable lock files and reports unknown/live residue. Real macOS product
reboot, Linux product capability, full maintenance and R1–R7 remain later gates.

R0-F1 outputs belong in a new report/root; preserve the old R0 reports/logs.
The primitives runner includes durable/v1_checks/contract_checks. Baseline review
probe exit0 only means a counterexample completed; green tests assert safe
behavior against the new candidate and final validator, not their old fixed paths.

R0-F2 adds post-acquired AttachSucceeded/AttachFailed observer exception pairs,
pre-acquisition observer/transport separation, and an inside/outside-venv × four
modes × hashlib/json shadow matrix (plus normal layouts and canonical aliases).
Run the full SDK/install groups and a fresh real tiny IDB with the new candidate.
The real result binds the three actually imported candidate files by SHA256.
For unchanged groups, `r0_freeze.py --historical-validation <prior-validation.jsonl>`
verifies current dependency and log hashes and marks them `historical-fixed-bytes`;
SDK/install/real must be fresh. Historical records stay out of the new validation
log. This does not turn historical Rust/OS experiments into a new execution.
