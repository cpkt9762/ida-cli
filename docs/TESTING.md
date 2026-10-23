# Testing

N9 当前统一使用 Nexus，没有开发期开关。Rust 构建/检查不需要 IDA SDK。下文各阶段记录中的 SDK 与 native 比较描述属于历史证据；旧版本对照只调用固定 N0 二进制。最终 E29 与 E00–E28 统一总验收由编排者另行执行，N9 定向门禁不替代它们。

N9 定向回归：`tests/nexus_n9.rs` 与 `tests/test_nexus_n9.py` 在 PATH 不含 GNU timeout 的子环境核对维护成功/超时、TERM 回滚指引与精确收尸；N7 混合索引、N4 MCP/CLI、N1、R5 协议及四补丁安装链保留。`scripts/package_release.py` 打包完整 runtime-lock 资产；安装演练使用 `--bundle` 和私有前缀，检查实际加载的四个补丁输出及篡改负例。只读旧平铺元数据仍用于迁移，不是数据库执行后端。

历史 worker 池配置 `IDA_CLI_MAX_WORKERS`、`IDA_CLI_MAX_WORKERS_PER_TENANT`、`IDA_CLI_MAX_PENDING_PER_WORKER`、`IDA_CLI_MAX_CONCURRENT_SPAWNS` 已移除；为兼容状态 JSON，它们对应字段保留为 0，表示不适用。Nexus 实际准入仍由 `IDA_CLI_MAX_PENDING_PER_TENANT` 控制，保留容量由 `IDA_CLI_NEXUS_RETENTION_CAPACITY` 控制；pending/物理准入额度不随 retention 改变。

R6 的原语图不按初始成员数排除 owner 时序，逐轨迹 JSON 保留原始 ACK、错误、
I1–I6 检查和 I5 的 pending 前提；Rust `nexus_r3b` 另记录真实 HTTP detach 后继集合，
在同一 router 释放 owner barrier 后检查 I5。S1 已改用生产 custody/SDK/helper，
旧 transport 夹具不再拦截 `released` 作为 owner 证明。独立 explicit-save 回归精确检查
CLI/MCP 原有 `run_script` 失败正文，原 close 的错误与逐成员断言保留。

`origin` 对无 U6 能力的卷保留 `UnsupportedBootScope` 和诊断；无义务设备重绑定
用原生卷 UUID、协调目录/锁/代际身份核验，目标 EX 下先持久记录再接纳。
macOS 无 Unix 模式的本地卷仅在 `statfs.MNT_LOCAL`、挂载 uid 与对象 uid 均匹配，
且文件系统命中白名单、已实测通过非覆盖 rename 和 hardlink 时等价检查私有模式。
APFS/HFS+/网络卷继续严格检查。exFAT 的两项 API 实测均 errno45，按用户裁定拒绝：
在任何 Nexus probe/open/spawn 前报卷类型、缺失能力和 errno，清理本次自有探测文件，
不创建协调区或修改 IDB。这是与旧后端的已知差异；不模拟或覆盖发布。

维护 preview 包含 `unpublished_scratch` 的路径、大小、inode 和哈希。
显式离线证据 `cleanup_unpublished=true` 并批准当前计划哈希后，apply 才删除精确的
未引用 scratch；owner/checkpoint 引用或身份变化拒绝，没有自动 GC。
R6 运行与未完成项见外部 `n7a-refactor/r6/report.md`，不构成 R6/R7 验收。

R4-fix4 定向回归增加 `tests/nexus_bridge/test_legacy_scan_isolation.py` 与
`test_unpublished_creation.py`：前者实跑 OpenGate/Custodian.gate，坏的 home 盘点项
只作诊断，匹配目标的未结义务仍拒绝；后者以真实子进程退出覆盖四种记录的三个新增内部
创建/绑定边界及副本创建/写入/fsync/checkpoint，负例精确核 inode、字节、权限及外来工作槽。
Rust `concurrent_spawn_cannot_inherit_received_target_ofd` 在 recvmsg 返回后暂停，
并发启动真实子进程核对其文件描述符及独立 OFD fence；原 close-only 断言保留。
以上不是平台重启或最终验收结论，运行证据在外部 `n7a-refactor/r4-fix4/`。

N6 的完整工具与能力覆盖见 [能力对照表](plan/nexus-n6-capabilities.md) 和计划 N6 小节。
真实验证为四个独立套件：lifecycle 9、contract 4、concurrency 14、n6 4；历史结果
不能代替改动后的验证。正式结果、每条命令的 exit/uptime、失败历史与审计保存在外部
`/tmp/ida-nexus-run-20261015.98rmfb/n6/report.md`。

N6 验证器串行执行四个 `--exact` 子入口，每个仍用 `timeout 180s`，并逐条记录
argv、uptime 和退出码；要求四条 `1 passed / 0 failed / 0 ignored` 以及原四个 PASS
场景全部齐全。外层可用 `timeout 740s` 仅聚合这四个有界终态，不能把内层 124 计为通过。
冷构建须事先完成；其他四套 E2E 的单套件上限不变。

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
  --root "$N0_ROOT" --target "$CARGO_TARGET_DIR" \
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

## N1 retention and pending limits (RV8-1)

`IDA_CLI_NEXUS_RETENTION_CAPACITY` independently sets the coordinator's lifetime
business identity retention limit (positive integer, default **262144**). Unset,
invalid or zero values use the default, matching existing router configuration.
`IDA_CLI_MAX_PENDING_PER_TENANT` remains **512** by default: it still bounds the
legacy tenant's pending requests, Nexus business lane, physical acquisition/lease
slots, bridge live slots, concurrent open supervisors and uncertain-open guards.
Changing retention does not enlarge those pending/physical limits.

Completed and failed request/operation IDs remain reserved for the coordinator's
entire lifetime. U6 retirement stops charging the business quota but retains the
IDs against reuse. Internal diagnostic IDs have a separate `retention * 48`
budget; all IDs, including retired and internal IDs, share the absolute
`retention * 64` ceiling (saturating arithmetic). At defaults these limits are
262144 business, 12582912 internal and 16777216 total. Both public and internal
reservation paths enforce the absolute ceiling; no tombstones are evicted.

Router JSON `status`, the MCP HTTP daemon's `/statusz`, and human CLI `status`
show `nexus_retention`: `business_used/capacity`, `internal_used/capacity` and
`total_used/capacity`. The human form prints three `nexus_retention_<kind>` lines.
Business usage includes terminal operations and excludes U6-retired resources;
total usage still includes those IDs. This adds no MCP tool or remote status
query. When full, Busy identifies the exhausted budget and usage/limit, explains
lifetime retention, and directs an explicit daemon/bridge restart (optionally
with a larger retention configuration). Unknown-outcome work must not be replayed.

The observed workload retains about **4.5KB per business tombstone**; at
262144 entries this is approximately **1.15GB**, allocated on demand. This is
an estimate, not an RSS ceiling: larger request parameters retain more memory,
and internal IDs, allocator overhead and other lifecycle data also consume
memory. The business/internal/total limits count identities, not bytes. Choose
retention against available memory. Once any lifetime budget is full, new
reservations remain rejected until the daemon/bridge is restarted; increasing
`IDA_CLI_NEXUS_RETENTION_CAPACITY` takes effect only on the next coordinator.
No timeout or automatic eviction frees terminal IDs, and unknown-outcome work
must not be replayed after a restart.

Deterministic regressions cover the default 513th reservation, 513 completed
business operations plus their open, small retention Busy, lifetime duplicate
rejection, configuration independence, unchanged lane/physical limits, status
growth and both absolute-admission paths. Run only the affected targets here;
final E2E acceptance is a separate orchestrator step.

```bash
timeout 120s cargo test --locked --lib rv81_ -- --test-threads=1
timeout 120s cargo test --locked --test nexus_contract -- --test-threads=1
timeout 120s cargo test --locked --lib nexus_business_capacity_ -- --test-threads=1
```

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

N3 introduced the fixed public Nexus client with the user-approved local
`client-cancel-unknown.patch`, then `client-close-proof.patch`. Preparation verifies the patched `handle.py`
SHA-256 and records patch status. Only a validated upstream fix passing the
probe and N0/N3 gates permits removal. R1 adds a fourth patch and J adds launch-authorization as the fifth; N9 packages must
carry the complete declared chain, including `loopback-bind.patch`.

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
explicit absolute target paths. Its suite has a 180-second shell timeout
for multiple IDA starts, save/reopen and crash repair; an outer 210-second
supervisor leaves 30 seconds for owned cleanup. It runs this worktree's absolute
Rust integration executable via cargo and disables daemon discovery by exercising
only the internal router endpoint. It never invokes the installed CLI.

```bash
timeout 210s "$N0_ROOT/venv/bin/python" scripts/verify_nexus_e2e.py \
  --root "$N0_ROOT" --target "$CARGO_TARGET_DIR" --ipc-root "$N3_ROOT/i"
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
used. Run from this worktree, with the same explicit target as N3:

```bash
timeout 210s "$N4_ROOT/venv/bin/python" scripts/verify_nexus_e2e.py \
  --root "$N4_ROOT" --target "$CARGO_TARGET_DIR" \
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
GNU `timeout` first. Select an IDA 9.4 or 9.5 installation with its existing legal
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
`idapro 0.0.9` (9.4) or `0.0.10` (9.5). `scripts/nexus/requirements.lock` fixes the build/test dependency
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
  env -i HOME="$HOME" USER="$USER" PATH="$PATH" LANG=C.UTF-8 IDADIR='/Applications/IDA Professional 9.5.app/Contents/MacOS' IDASDKDIR=/Users/pingzi/Developer/tools/ida-sdk-9.5/src CARGO_TARGET_DIR=/tmp/ida-nexus-run-20261015.98rmfb/n1/target IDA_NEXUS_PYTHON="$S1_PYTHON" IDA_NEXUS_IPC_ROOT="$S1_ROOT/ipc" F1_ROOT="$S1_ROOT/proof" IDA_CLI_HOME="$S1_ROOT/home" IDA_NEXUS_STATE_DIR="$S1_ROOT/state" TMPDIR="$S1_ROOT/tmp" timeout 150s cargo test --locked --test nexus_n7_fix1 "$S1_CASE" -- --exact --test-threads=1
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
nexus_r0_prototypes current_product_lifecycle_regressions -- --exact --test-threads=1`;
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

`r0_sdk` generates and exercises a temporary three-file U1 candidate. This is the
historical R0 experiment, not the formal R1 SDK. `r0_real_ida` uses one disposable tiny IDB and a second
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


### N7a-R R5 receiver, lifetime and startup admission

R5 changes the production adapter while retaining fixed Nexus 0.13.4/d60ff58
and the three original client patches. `--lib r5_` exercises the actual N1
endpoint, event pump and bounded physical reader: 189 complete historical wire
sequences (including all 56 historically fatal rows), bad complete JSON lines,
wrong identities/families, duplicate terminals, late acquired resources/stop
proof, release observation sideband, real EOF/partial EOF and closed-peer writes.
Each replay records accepted/rejected inputs, authoritative A/B state and B
query/control availability. The historical static reachability exclusions remain;
this is receiver robustness evidence, not R6 dynamic coverage or owner convergence.
Unknown valid acquired leases remain owned by Python and explicitly diagnosed;
a bounded exact-identity diagnostic latch blocks further acquisitions for that
bridge incarnation without blocking existing sessions. R5 does not reconcile
that latch into custody or synthesize Released.

`tests/test_nexus_r5.py` shares a 12-row home table with Rust, checks public Nexus
state rules, exact protocol/hash/capability admission, seven deterministic
send/install barriers, bad AF_UNIX handshakes and listener recovery. Only the
failed connection closes; listener recovery may unlink its exact inode, retries
failed rebinds and refuses a foreign endpoint. Home preserves literal `~` and
symlink/`..` semantics. Missing HOME fallback is calculation-only; real runs use
a private HOME. State continues to use public `get_state_dir`.

R5-R1/R5-R2 regressions additionally replace real AF_UNIX paths during listen
and timeout setup (socket, regular file, symlink and disappearance), check failed
setup/close cleanup, and drive both handshake windows through real
`Bridge.invoke(cancel)` with public API barriers. Bound device/inode ownership
is immutable; healthy publication and every unlink recheck socket type and identity.
Cancellation intent precedes the blocking API call, while proof retries wait for
all public calls on that exact execution record. Pending, failed, exceptional and
replaced record/handle outcomes retain old A/B sockets without installing the new
connection, inventing stop evidence or contaminating a successor. A real proof
scheduler scan during a second in-flight public cancel must queue no extra call;
after return, the existing public stop-proof path remains usable.

`--features nexus-test-support --test nexus_r5` contains readiness-only rejection
cases (no grants/acquisitions; exact child/socket cleanup) and the separately
selected real tiny IDA chain. Admission requires wire2/schema1/release1/open1,
owner_observation0 and the complete current `protocol.contract()` (R1 extends
the R5 handle check to three module hashes and seven capabilities); capability
order is immaterial and duplicates fail. No helper,
custody or owner-observation capability is advertised. Member release progress
uses nonterminal release_observation schema1/release_protocol1; N1 remains the
only business-result authority. Owner v1 guard/lifecycle/slices code is unchanged.

Use shell timeout and before/after uptime for each command, a fresh short root,
private HOME/state/tmp/IPC, copied sample and a serial private Cargo target.
Run affected N1/transport/bridge and Python regressions, fmt/check/Clippy and
Python Ruff F/E9 plus syntax. Real tiny IDA permits 180s after recording why;
fault shards permit 120s. Do not rerun GUI/large/full E2E for this stage.
The mixed `nexus_r0_prototypes current_product_lifecycle_regressions` target now requires
F2 B=Active plus real SDK query/control success (`R5-production-isolation`),
while F1/F4 were historical `current-product-expected-red` cases (superseded by the final-fix green regressions below). `r0_freeze.py` records those
separately and the current installation closure is 19 members. Historical R0
freezes and logs remain immutable; neither replay nor the real tiny chain accepts
N7a or supplies R1/R3 custody, R2 release, R4 transactions, R6 or R7 evidence.

### N7a-R R1 installed SDK boundary

The formal client chain is `loopback-bind.patch` → `client-cancel-unknown.patch`
→ `client-close-proof.patch` → `client-acquisition.patch`, against Nexus
0.13.4/d60ff582fde90c59726336c0dbdf3e8286e9df7a and Domain 0.5.1. The fourth
static patch changes only `handle.py`, `_resolver.py`, and `options.py`.
`client-sdk-contract.json` declares all three expected hashes and capabilities;
prepare checks source and actual imported installed files, and bridge/Rust
readiness reject any missing/extra/mismatched module or capability before grants.
The preparer accepts read-only offline `--source`/`--wheels` inputs while retaining
fixed source/wheel hash checks. Always use a fresh external root.

`DatabaseHandle.open_outcome`/`attach_outcome` return the typed in-memory
`AcquisitionOutcome`/`AttachAttempt` contracts from `ida_nexus.handle`.
`AcquisitionObserver`, `AcquisitionStage`, and `ResolveEvent` live in
`ida_nexus.options`; launch payloads use `_resolver.LaunchEvent`. Callbacks are
synchronous and run without SDK ledger locks. `BeforeResolve` records retry
intent before resolution, and `BeforeAttach` is distinct from `AttachMayBeSent`.
Every attempt retains its original instance and unknown obligation even after
a later rejection/success/close. Outcomes carry the original cause plus separate
`observer_errors`; observer failures never trigger transport reconnect.
Do not serialize these objects: instances contain in-memory authentication data.

After SSE acquisition, the SDK retains the exact handle before callbacks or
monitor construction/start. `on_acquired`, `Acquired`, and error outcomes expose
that same handle. On failure it remains retained until explicit idempotent
`claim_acquired()` or close; no automatic close disguises responsibility.
Successful construction hands ownership to the caller. Claim/close/reentrant
callbacks are safe; pending locks never span callbacks or I/O. Legacy methods
preserve existing positional/keyword parameters, returns and exception types.
Legacy monitor failure exposes the original exception with `.handle`; additive
callback failures use `AcquiredFailure`/`StageObserverFailure` with `.cause`.

`LaunchIntent` precedes Popen; `Spawned` immediately delivers the real Popen,
PID and monotonic creation time before log/ready work. Native birth identity
must be captured by the observer; launcher exit is not owner-exit proof.
Parsed last/nonlast release ACKs latch `ack_kind`/`lease_released` before any
local cleanup. `cleanup_failure(s)` are independent. Close sends at most once,
including concurrent/reentrant calls and unknown results; same-thread reentry
returns a current snapshot, while a concurrent structured caller obeys its own
timeout. The close-lock owner publishes stable copies before transport cleanup
and after subsequent diagnostics; readers never wait on another state lock.
An exhausted concurrent wait returns the latest published ACK/owner facts with
per-call `close_in_progress=true` and `wait_failure="deadline"`. Those markers
never enter the cached outcome or the first caller's result. Before a valid ACK,
or after a lost/invalid ACK, the snapshot remains unknown.

`wait_for_database` keeps its existing public lifetime semantics: a normal False
return still raises the legacy timeout; an observation exception preserves its
original type, object and cause. A preceding release error takes priority over
observation errors/timeouts, then the observation error takes priority over
other local cleanup errors. All local cleanup attempts finish before raising.
Structured results retain ACK/`owner_pending` and independently report
`observation_failure="timeout"` or `"exception"` (plus
`observation_failure_type` and an owner_observation cleanup diagnostic for an
exception). Neither observation failure fabricates owner release.

Run `tests/support/r1_sdk.py` with `R0_CANDIDATE` pointing at the new installed
site-packages, plus `tests/nexus_bridge/test_acquisition_patch.py` and affected
Python/R5/N1/transport/bridge targets. The matrix preserves all twelve R0 SDK
behaviors and adds type/signature, original-instance, callback, thread, reentry,
claim/close concurrency and failed-second-resolve assertions. Real HTTP/SSE
faults are test boundaries, not production private-protocol replacement.

R2 adds public `DatabaseHandle.resolve_outcome(path, *, options=None,
observer=None)` in the same fourth patch and three-module SDK closure. It calls
the resolver at most once and never attaches or retries. `ResolutionOutcome`
retains the exact cause, original instance, launch events and legacy `recovery`;
it asserts neither custody nor owner exit. The initial legacy open remains at
most two attempts. After exact durable exit proof and original-budget admission,
the adapter may consume one separate post-exit allowance and explicitly attach
once using the returned recovery. Unknown attach and business calls never replay.
`tests/support/r2_sdk.py` checks this boundary in a new private case root. The
existing real SDK probe additionally verifies actual Spawned/Ready for normal
resolve and Ready rejection, followed by explicit cleanup and natural child exit.
Current installed hashes come from `scripts/nexus/client-sdk-contract.json`;
the earlier R1/R0 hashes above remain historical inputs.
The new probe requires a fresh prepared root and its own interpreter:

```sh
timeout 180s "$R1_ENV/venv/bin/python" scripts/nexus/probe_sdk_boundary.py --root "$R1_ENV"
```

It verifies actual module hashes, real IDA9.5 legacy and outcome tiny-database
chains, early callback failure/claim, last/nonlast ACKs and existing execute/wait
operation IDs. Unsupported old SDK with `--expect-unpatched` exits 2; formal
SDK exits 0. The three older probes keep their original red=2/green=0 meanings.
For ambiguity red, use the historical 3c05a51 cancel patch, not no-cancel SDK.
Never run two real probes against one prepared state/sample.

`r0_prepare.py` explicitly requests `--sdk-baseline r0`, preserving the exact
aa5 handle and frozen candidate generator output. This is experiment-only:
production readiness rejects it. Historical generator, three old patches and
evidence remain unchanged; do not regenerate history with formal R1 bytes.

Existing N1 execute/wait calls already pass their exact `operation_id`; no new
SDK parameter or temporary custody is introduced. Preparing guard/analysis/
verification RPC admission, durable launch/handle custody and proof helper are
R3a dependencies. Production acquisition remains on its existing path pending
that atomic admission. R2 owns two-phase Tools/N1 release; R4 owns transactions.
F1/F4 were explicit production expected-red cases at that milestone; current green regressions supersede that expectation. SDK raw facts, the F2
isolation green and these probes do not establish no-orphan or N7a acceptance.

### N7a-R R3a production custody (implementation, awaiting independent review)

R3a replaces the final-acquisition path described in the historical R1 paragraph
above. `open_outcome/on_acquired/claim_acquired` now transfers the same physical
handle into N1 `Preparing` before preparation. N1 owns parent state and exact
internal RPC grants; custody ACK alone permits no RPC. Tools publishes the
verified input index after reliable custody and releases open/content/path locks
before analysis. Dropped callers retain their supervised cleanup responsibility.

The verified installation includes `custody/bootstrap.py` as `bootstrap.py`, the
bridge dependency closure, the independent proof helper and target writer.
Rust starts one helper for its fixed absolute state-root identity, in a separate
session with private IPC/logs. Public owner lifetime produces immutable fsynced
proof; target authority durably adopts it before ACK. Original instances remain
available until the matching custody/producer closure. Startup intent is signed
before Popen; exact birth identity follows Popen before readiness. Missing source
or unsupported recovery remains explicitly blocked. Neither EOF nor PID absence
proves release. Orphan clock injection at 300 seconds records abandonment only.
Accepted helper finish is serialized against all requests and permanently fences
reconnect. The real startup regression directly issues a late heartbeat after
finish and requires local refusal, unchanged registry and no endpoint. Final
audits also inspect holders of every registered socket, including idle helpers
whose durable watch table is empty.

Admission is wire=2/schema=1/release=1/open=1/sdk_boundary=1,
owner_observation=custody=helper=target_gate=1, same_boot_exit=boot_retirement=0.
The fixed R1 three SDK hashes and four patches are unchanged. Only the implemented
`final_preparing_v1`, `internal_grant_v1`, `durable_public_proof_v1` and
`target_gate_base_v1` capabilities are added. Full same-boot OS qualification
remains Unsupported; cross-boot retirement is not enabled.

Use a new prepared formal SDK, private HOME/state/IPC/case roots and independent
`CARGO_TARGET_DIR`. Retain the ordinary toolchain/IDA SDK paths explicitly when
isolating HOME. Tests require `F1_PYTHON=R3A_PYTHON=<env>/venv/bin/python`;
the R1 suite also needs `R0_CANDIDATE=<env>/venv/lib/python3.14/site-packages`
and a new `R1_CASE_ROOT`. Set `R3A_CASE_ROOT`, `R5_ROOT`, `F1_ROOT` and
`N3_TEST_IPC_ROOT` inside the private test root. Real IDA requires `R5_ENV=<env>`
and the Environment process-ledger wrapper used by earlier real probes.

```sh
timeout 30s cargo test --locked --features nexus-test-support --test nexus_contract
timeout 120s cargo test --locked --features nexus-test-support --test nexus_r3a no_handle_terminal -- --test-threads=1
timeout 120s cargo test --locked --features nexus-test-support --test nexus_r3a direct_fixed_target_128 -- --test-threads=1
timeout 120s cargo test --locked --features nexus-test-support --test nexus_r3a managed_fixed_target_128 -- --test-threads=1
timeout 30s cargo test --locked --features nexus-test-support --test nexus_r5 readiness_rejects
timeout 30s "$R3A_PYTHON" -m pytest -q tests/nexus_bridge/test_custody_target.py tests/nexus_bridge/test_custody_helper.py
```

The 120-second allowance is for the explicit fault matrix or 128 actual
open/close/public-proof rounds. The real tiny Tools and startup targets allow
180 seconds for IDA initialization. `tools_future_drop` additionally requires
`IDA_NEXUS_PYTHON` and `IDA_NEXUS_IPC_ROOT`; there is no
separate backend selector. Python bootstrap attacks require
`R3A_INSTALLATION` naming an installation produced by the current Rust build.
Run fmt/check/all-target Clippy `-D warnings`, affected Python/R5/R1 and explicit
`nexus_bridge_regressions` targets with shell timeout and before/after uptime.
The latter intentionally keeps its old simulated acquisition adapter; it proves
transport regressions, while `nexus_r3a` proves the production custody chain.

R3a evidence is in `/tmp/ida-nexus-run-20261015.98rmfb/n7a-refactor/r3a/`:
`validation.jsonl`, case index, hashes, raw logs, process/lock audit and report.
F4 retains the original early-analysis failure, physical lease and failed
cleanup/no-detach facts, then converges via real public proof. It no longer loses
the acquired lease. Healthy direct/managed fixed-target runs each exercise 128
epochs, bounded files/bytes, at most 64 summaries and stable lock inodes; managed
GC checks both nonblocking locks and preserves the coordination namespace.
Reference holes, unclosed producers, old epochs, live/routine/retained quotas,
ENOSPC and interrupted compaction retain evidence or resume an exact intent.

This is R3a implementation evidence awaiting independent acceptance. R2 still
owns full two-phase release projection/immediate reopen (F1), R3b recovery and
auxiliary orchestration, R4 full file transactions/maintenance/fault matrices,
and R7 product acceptance. GUI/Linux/large database and cross-boot product tests
are outside this run. Historical R0 expected-red evidence stays frozen.

R3a fix1 review regressions live in `tests/nexus_bridge/test_custody_fix1.py`.
They cover retrying one reserved proof after partial writes or lost registry
updates, authorized helper/bridge producers, startup-owner binding, refused
admission stability, real GC quarantine/retirement across homes and target gates
for legacy verification and owner-side auxiliary attach. The latter evaluates
the same verified gate sources in private modules inside the owner; it does not
depend on the owner's installed bridge modules. Runtime RPCs release target EX.
These are gate foundations, not full R3b verification/auxiliary custody.

The production N1/bridge/helper/SDK r9 test
`r9_late_ordinal_retirement_and_public_proof_before_release_return` uses barriers
before/after the next ordinal and before the original release reply. It requires
the old receipt to leave the new watch active and both ordinals to settle.
The library test `accepted_finish_lost_ipc_reply_is_durably_fenced` uses a real
Unix relay to discard the accepted finish response before Rust receives a byte;
it also rejects finish with a pending parent, then tests late heartbeat and
same-incarnation restart against the durable finish tombstone.

Run both with the private environment variables above and shell timeout:

```sh
timeout 30s "$R3A_PYTHON" -B -m pytest tests/nexus_bridge/test_custody_fix1.py
timeout 120s cargo test --locked --features nexus-test-support --test nexus_r3a r9_late_ordinal -- --test-threads=1
timeout 30s cargo test --locked --features nexus-test-support --lib accepted_finish_lost_ipc_reply
```

The fixed `3acfefd` baseline's six safety-red cases and Q1/Q2 evidence, candidate
installation manifests, final-byte runs and failures are recorded separately in
`/tmp/ida-nexus-run-20261015.98rmfb/n7a-refactor/r3a-fix1/`. Original review/root
evidence remains read-only. Fix1 awaits independent review; it does not accept
R3a or start R2. SDK hashes/patches and Unsupported same-boot status are unchanged.


### N7a-R R2 ordinary release and owner resources

R2 uses wire2/schema1, release2/custody2/helper2, SDK boundary2 and a closed
installation of 28 source members plus its manifest. Current SDK module hashes
are authoritative in `scripts/nexus/client-sdk-contract.json`; the R1 hashes
and protocol paragraphs above describe their historical stage. Boot retirement1
names the consumer protocol, while each creation/consumption still needs a
qualified native physical-host/local-volume scope. Same-boot OS exit remains
Unsupported/false. OS-source injection is not a real reboot test.

`tests/nexus_r2.rs` exercises ordinary last/nonlast ACKs, lost ACK, guard refusal,
three fair bounded lanes, caller drop, queue saturation, guard timeout before
actual stop, same/cross-router immediate reopen, post-exit resolve counts and U6
retirement with original outcome/preflight/error/ACK/stop preserved. Run each
case in a fresh `R3A_CASE_ROOT`, HOME/state/tmp/IPC; do not run the entire target
against a single shared case directory. Set `R2_REAL_INPUT` only to a disposable
prepared fixture for the real IDA9.5 save/shared-lease/immediate-reopen case.
R2's implementation evidence and all failures are indexed in the external
`n7a-refactor/r2-handoff/` report directory; independent acceptance remains pending.

Ordinary valid ACK invalidates the lease token immediately; last/unknown retains
owner protection. Close does not wait for saving or guarantee that it succeeded.
Use `owner_observation_ref` with `wait_owner_exit` and an independent caller budget
before copying a database. The local socket RPC `wait_owner_exit` takes
`owner_observation_ref` and optional `timeout_secs` (default120, capped600), with
no path or lease acquisition. The CLI's existing `raw` command sends this RPC.
Public proof does not replace original caller errors;
verified boot retirement only settles current old-boot resources. Unknown attach,
detach and business effects never replay, and the original open budget never resets.

The library and MCP fixtures use the same Nexus path without a selector. Create the private `R5_ROOT` before receiver evidence output.
`F1_PYTHON`, `R3A_PYTHON`, `IDA_NEXUS_PYTHON` name the new formal SDK interpreter;
bootstrap tests also require `R3A_INSTALLATION` from the current Rust-produced
installation. The existing test-support process ledger records pre-spawn intent
and native birth when `R2_LEDGER` names a private append-only evidence file.

```sh
timeout 120s cargo test --locked --features nexus-test-support --lib -- --test-threads=1
timeout 30s cargo test --locked --features nexus-test-support --test nexus_r2 last_ack_finishes_lease_before_owner_exit -- --exact
timeout 30s cargo test --locked --features nexus-test-support --test nexus_r2 boot_source_injection_retires_only_current_resources_and_preserves_unknown_history -- --exact
timeout 30s "$R3A_PYTHON" -B tests/support/r2_sdk.py
```

The 120-second library allowance covers real pipe/process fault teardown; each
ordinary R2 case retains 30 seconds. Multiple-process R3a matrices/128 rounds use
120 seconds and fresh prepare/cold build/real tiny IDA use 180 seconds, with the
reason stated before running. These shell limits do not change product budgets.
Full auxiliary/r9/verification orchestration remains R3b, file transactions and
maintenance remain R4, and large databases/real cross-boot/platform E2E remain R7.

#### R2 targeted boundary regressions (RF1–RF6 / Q1)

Retirement evidence is a strict schema1 certificate bound to the exact target,
origin, acquisition, epoch, owner and lease. Every reread validates its digest
and qualified boot scope before admission/accounting; late writers recheck under
EX and cannot modify retired history. `test_boot_retirement.py` includes a queued
independent writer, corrupt-certificate rereads and unchanged historical bytes.
The Rust `late_real_ack_after_boot_retirement_never_rewrites_target` delays an
actual SDK ACK until after retirement. Boot-source injection remains a model of
OS inputs, with a consistent current boot for target writers, bridge creation
and the helper heartbeat; it is not a host reboot.

`dropped_close_detaches_once_after_late_native_stop_with_owner_held` drops the
caller, holds native execution past the old retry window, then supplies causal
stop through the public SDK while the owner lifetime stays held. Eligibility
waits consume no release attempt. Cleanup stop observation uses the existing
bounded proof pool with capped backoff after the original deadline, preserving
that deadline and the original outcome. Explicit protection failures and bounded
attempt exhaustion report CleanupBlocked without dropping resource protection.

The actual MCP/Unix CLI tests assert typed code/cause/retry/automatic_replay for
saving-refused NotSent and Uncertain outcomes, and proof-before-terminal ordering.
A public lifetime proof settles resources independently of the command's caller
result. Eight pending waits use one real listener and shared lanes; status/cancel
remain available, waits keep their own deadlines, and disconnect frees the
read-only observation slot. Control response encoding applies bounded backpressure.

`post_exit_final_signed_resolved_deadline_sends_zero_attach` spends the original
budget at the actual final Resolved/helper-signing return. The final attach is
refused while the consumed post-exit allowance, original instances, launch list
and prior outcome remain owned. No SDK patch/hash or resolve-count allowance
changes. Each Rust integration case still needs its own private case root;
late-stop uses the documented 120-second shell allowance.

R2 RR1-F1 adds
`post_exit_attach_attempt_ack_deadline_sends_zero_attach_and_settles_notsent`.
Its actual helper signs the final may_send fact while the original budget is
positive; a barrier delays that ACK return past the deadline. The callback then
refuses before HTTP, retains the signed fact and original instance, and consumes
the fixed SDK's real NotSent outcome before durable NoAttachClosed settlement.
This differs from the earlier final-Resolved barrier, which remains required.
Exact-clock models cover healthy, expired entry, exact deadline and late ACK.
Identical custody-retirement/public-proof ACKs coalesce only while queued/in flight, with
tracking bounded by the output queue plus its current write. The original ACK
still completes; duplicates cannot block the control reader's custody RPC reply.

### N7a-R R3b K2 orchestration (implementation, awaiting independent review)

The current adapter contract is wire2/schema1, release4/open2/custody4/helper2,
SDK boundary2 and target_gate1. The fixed SDK modules and four patches are
unchanged; partial installations and mismatched capability sets are rejected.
`nexus_r3b` exercises actual N1, installed bridge/helper and the fixed SDK over
controlled native IDA/HTTP inputs. `nexus_r3b_real` separately uses IDA9.5 and a
private small database; artificial Root failures and OS inputs are not real IDA
or host-reboot evidence.

Each retained parent reserves physical capacity before acquiring a final,
verification, root-retry or cleanup-only auxiliary handle. Ordinals never repeat,
the parent has at most two simultaneous physical slots, and every slot consumes
the original tenant limit. Verification does not publish the parent's final
lease. Root attempts share one original deadline and a three-attempt limit;
SDK internal and post-exit resolver allowances remain separate parent budgets.
Same-boot retry requires its own detach ACK, exact public owner proof and stopped
operations. Qualified U6 retires only old resources and preserves their history.

`acquired_ack_loss_then_public_proof` covers both lost custody ACK and public
proof before the first acquired callback, without new LeaseKeys or unauthorized
RPCs. Verification cancellation ends the caller's wait before owner exit while
keeping its copy. `cancelled_root_retry_restores` retains the existing Snapshot
and independent root SH/target references after the caller ends, then performs
accepted rollback through the existing fair cleanup pool. Failed file writes
remain blocked with the original scene, without replaying v1 rollback. Full
crash-atomic staging/transfer/maintenance remains R4.

`disconnected_primary_and_auxiliary` checks independent mixed outcomes, sibling
membership changes, explicit retry of NotSent auxiliary cleanup after the primary
ends, actual SDK/server/Python/N1 sets and operation-ID mapping, and no replay of
unknown detach. Owner-local slice handles use adapter custody when its lifetime
endpoint is live; a truly absent endpoint leaves the owner-local handle as C1
third-party responsibility. Public proof never replaces the original close or
save command error. Verification payload deletion additionally requires current
occupancy and file-identity checks; stable coordination/proof files remain.

The fix1 regression target `nexus_r3b_fix1` adds real N1/transport NotSent
capacity checks and installed bridge/helper/SDK auxiliary handoff windows. Gate,
probe, Options and pre-resolver failures retain their cause and close only the
exact resource-free reservation; Unknown and old ordinal obligations remain.
Custody4 requires `unstarted_absence_v1` and `verification_removal_v1` together;
old custody3 and partial capability upgrades fail admission.

Verification database payload is deleted by the Python authority holding target
EX after checking the current journal, public owners and database occupancy.
Rust consumes the exact completed-removal receipt and unchanged journal, never
an empty historical `closed` file. A new probe or journal responsibility blocks
consumption and input publication. Immutable input uses its original identity
and content binding; stable coordination and proof files remain.

`nexus_r3b_startup` exercises the actual legacy-copy preparation and
RetainedOpen.verification chain at LaunchIntent and PopenReturn before acquired,
with cancellation, EOF and callback failure. Run each phase/fault in a fresh SDK
environment. Public proof plus all producer closures completes late cleanup;
unproven LaunchIntent retains copy and capacity even after ObservationAbandoned.
These are actual private IDA startup cases, distinct from controlled HTTP inputs.

The fix2 `nexus_r3b_fix2` cases run individually with `--exact` and fresh
HOME/state/tmp/IPC per case, like the R2 matrix. Its test-only scheduling points
pause SDK completion after pending observation, last-watch retirement, and the
validated publication window; they do not change production predicates.
`test_verification_scope.py` separately exercises strict existing authority;
its foreign-epoch terminal flags are a declared journal boundary, not N1 proof.
Initialization is allowed once before persisted history; cleanup never recreates
missing/null scope or accepts boolean/float identities or incomplete parents.

The two completion inputs join under startups then N1, without await under a
synchronous lock. Other watches, an existing lease, or a still-running SDK actor
retain capacity. Verification provenance comes from the original N1 reservation
and inherited publish_parent flag across Root retries, independently of an old
retirement ACK; ordinary final retries never gain copy deletion authority.

The publication case uses real private IDA and a second independent normal
bridge/helper caller with public output_database. Content/open guards alone do
not exclude that target. Validation, input publication and exact input cleanup
therefore retain one target EX throughout; the later caller enters after commit.
This is the narrow verification publication fix, not a full R4 file transaction.

Run each integration target in a fresh private HOME/state/tmp/IPC and case root,
recording before/after uptime. Use `timeout 120s cargo test --locked --features
nexus-test-support --test nexus_r3b -- --test-threads=1`; allow 180s for the private
real-IDA target and cold build, with the reason stated before execution. Preserve
all nonzero/forced/124 runs. The external R3b report indexes frozen inputs,
commands, exits, hashes, identity gaps and the final resource audit. R3b acceptance
belongs to the independent reviewer and orchestrator.

The R3a acquisition fault matrix additionally interrupts observation transfer
after a real helper subscription and before Rust receives it. Cleanup re-signs
that same watch/receipt, preserves the original callback error, and sends no
attach. Actual SDK completion and exact public resource closure are separate
facts: only both can return an unleased startup reservation, so an intermediate
owner exit cannot free a slot while the SDK still resolves. A late disposed
callback remains cleanup-only. The old transport fixtures use explicit boundary
doubles and cannot provide production custody/proof evidence.

The fix3 `nexus_r3b_fix3` tests retain the ordinary `nexus_close_token` path.
They wait for the primary public proof, producer/consumer closure and retirement
ACK removal before resuming the original preflight, and compare the caller, N1
attempt and status's structured cause/NotSent facts. Each case needs its own
private root and `--exact`. Foreign lease/generation/ordinal/owner/watch/attempt
inputs and a real target-writer summary quota refusal are separate negative cases.
The test continuously consumes lifecycle events without enlarging the broadcast.

Release4 requires `retired_release_observation_v1` on both installed peers.
An exact public-proof tombstone plus N1's original acquisition/lease validates
a late observation; the target's bounded summary retains its complete binding
and nonce/attempt outcome without recreating resource references. Old summaries
cannot acquire missing authority. A failed observation write returns NotSent
before detach and exposes `observation_error` independently of the original cause.
SDK versions, three module hashes and four patches remain unchanged.

`test_writer_authorization.py` invokes the actual independent target writer with
real Target EX. Cleanup validates its existing scope before any default Journal
recovery; missing/foreign/conflicted/null/corrupt inputs preserve journal, payload
and controlled manifest references. Ordinary recovery and legal cleanup remain
positive controls. Its completed epoch flags and reference manifests are explicit
file-boundary fixtures, not N1/helper/public-owner proofs.

The fix4 `nexus_r3b_fix4` regression runs the ordinary close entry with the
production guard returning close_safe=true and a nonempty save refusal. It waits
for exact public proof/closure and removal of the retirement ACK before the real
target writer refuses its bounded summary write. Caller and top-level status
retain that known refusal while N1 keeps the original typed NotSent command
error and an independent observation_error. The native Root input is controlled;
the SDK, N1, installed bridge/helper/writer and guard execution are real.

Accepted release terminals now retain nonempty save diagnostics in the existing
exact-lease table even when sideband persistence fails. Empty/null later fields
do not clear them. Rust/N1/control-reader contract tests separately cover typed
nested causes, subsequent observations, foreign identities and rejected/duplicate
terminals; supplied wire fields in those tests do not replace production guard
evidence. Protocol versions and fixed SDK modules/patches are unchanged.

### R4 file transaction implementation (in progress)

R3b has independent acceptance through `5d8a215`; the historical paragraphs above
describe their original delivery state. The R4 adapter now requires open6,
custody5, target_gate3, `file_recovery_ack_v1`, `file_job_relay_v2` and
`stable_volume_rebinding_v1`;
fixed SDK bytes stay unchanged.
R4 is not yet accepted. Stage results and all failures are preserved in the
external `n7a-refactor/r4-implementation/` directory.

`test_recovery_publication.py` is the same partial-final assertion for frozen
baseline and current production. `test_recovery_transaction.py` runs actual
copy/rename/phase exits and fresh-process recovery, with an explicit absent-owner
input. `test_recovery_transfer.py` separately tests unique in-process move,
SCM_RIGHTS, ACK loss, crashes, duplicate rights and in-flight sender exit.
`test_recovery_resources.py` checks routine pins and retained source certificates.
`test_recovery_backups.py` invokes the fixed SDK's actual backup producer; its
file states are private inputs, not a native IDA recovery claim.

The existing exact R3b cancelled-parent restore case also uses the new installed
job through real Rust/N1, fixed SDK, bridge/helper and target writer. Its native
Root input remains controlled. The library's exact
`router::nexus_bridge::installation::tests::installed_maintenance_modes_offline_preview_and_apply`
uses a new test target and an explicit private offline test operator. It invokes
the installed absolute `open_recovery.py` via `maintenance-launch`, checks four
Python launch modes, no-write preview, rejected plans and apply. No real user
database or owner is an authorized maintenance target.

Use a fresh private HOME/state/tmp/IPC and `R3A_CASE_ROOT`; the maintenance test
also needs the prepared `R3A_PYTHON` and disposable `R3F1_SAMPLE`. File matrices
allow shell timeout120s; stage compilation allows180s, stated before execution.
Product barrier budgets are unchanged. The `file_job_` Rust/N1 cases exercise
sender/receiver exits, both exits, exact epoch rejection, duplicate rights and
lost ACK through the installed receiver. Continuous EventLog rejects Lagged;
each native supervisor is naturally reaped before its test runtime ends.
The U6 case injects only the OS scope input: real lost SDK ACK remains Uncertain,
current owner occupancy blocks file writes, and a later gate restores the same
transaction after that occupancy ends. It is not a real kernel reboot.

Creation and retained-resource certificate exits also recover in new processes.
`test_recovery_compaction.py` separates synthetic closed-epoch inputs from the
real helper proof test, and checks each durable deletion boundary and new refs.
`test_recovery_io.py` labels injected errno separately from real hostile files;
its 80/95/100 percent retained thresholds use actual file bytes.
The installed maintenance driver covers snapshotless/two-target permissions,
accepted-plan process-exit continuation, env-i/absolute entry/four launch modes,
tampered members and missing dependencies. Final-SHA regressions, physical U6,
and the remaining R4 gates are still required before claiming R4 complete.
`test_volume_identity.py` uses explicitly controlled device/boot inputs and real
files/locks to test identity-preserving remapping and interrupted v1 import.
The direct and managed Rust/N1 gate cases verify actual current SCM FD/root
identities while keeping the original logical CoordKey; native IDA is controlled
there. Neither layer supplies a real physical reboot or remount qualification.

Snapshot-constructor I/O errors stay before the SDK. An unchanged or normally
saved component set permits only a no-failure archive, preserving partial
evidence and the original error; unknown new components retain the file gate and
remain visible in status. Old queued file actions cannot inherit a new executor
token after AbortOffer. Late Ready replies reclaim only their exact transport
cache entry and never grant file execution or clear the caller's timeout.
Routine unlink failures retain errno/cause and block new admission; accepted
public proofs and producer/consumer closure writers continue independently.
The expanded installed maintenance driver uses timeout120s as an aggregate of
individually bounded 15s entries; this does not change any product barrier.
File-job v2 datagrams carry bounded readiness/binding/completion digests. The
receiver validates the full FrozenOffer from the same guarded transaction;
the sender validates the full durable Accepted record and completion hash.
`test_recovery_wire.py` tests large diagnostics, Unicode paths and receipt
tampering with actual kernel SCM; owner absence is an explicit component input.
The native `real_ida95_r9_file_job_restores_exact_components_before_retry_and_new_read`
case uses an actual IDA 9.5 small database and one injected Root observation;
it verifies exact component hashes before retry and a fresh request's saved-data
read. This supplies no natural-corruption or real-boot qualification.

`test_fact_publication.py` pauses an independent production Observer at its
immutable link boundary. Namespace accounting and fact scanning share the
producer directory OFD while publication holds it exclusively; namespace
creation also serializes with accounting. Publishers never wait for target EX
inside that lock. A real publisher exit releases only the directory lock:
pending bytes still block accounting and remain preserved. The fact payload
in this deterministic test is synthetic, not a public owner proof.

The library's `live_helper_rpc_never_reads_a_mutable_finish_inode` schedules an
actual helper registry replacement between Rust's open and metadata read.
Normal live RPCs use the helper protocol; only an exactly exited child permits
the durable finish-tombstone inspection before restart. The existing accepted
finish/lost-reply test remains a separate control, and neither child exit nor
the registry grants a public owner proof.

R4 fix1 adds `test_recovery_preview.py`: explicit read-only scans, another
terminal/active transaction's pending record, installed four-mode rejection,
approved exact pending recovery, and changed-plan/input/opener refusal.
`test_recovery_legacy.py` covers the archive pointer's five actual durable
boundaries for ready/failed/rolling-back sources plus exact-slot corruption.
`test_recovery_component_boundaries.py` runs each of six component methods
separately with shell120s; its coverage JSON names each reached copy/move and
intent/reservation/completion boundary. These fixtures use one chunk per file
and explicit absent-owner input, without claiming physical power-loss/boot.
Final evidence must include three full same-SHA library runs and all actual
inputs in each source snapshot; unchanged input bytes do not repair old gaps.

R4 fix2 retains the same 128-round, CoordKey, 32768-byte and product deadline
assertions. The verified bootstrap still hashes every installation member before
loading any member; it compiles only the already verified bytes actually imported,
without source reopening or bytecode caching. `R4_PARENT_SCHEDULE` is a test-only
caller/retirement scheduling input for the existing verification and real r9
tests. Their successor reservation must follow exact predecessor observer
retirement, independently of public proof, command ACK and caller result.
`test_recovery_backups.py` checks resolver failure against the same transaction's
published restored scene, including inode/metadata, and rejects same-byte inode
replacement. Actual wait, emergency waitpid and cached status after Tokio kill
are collected separately from public database lifetime. Evidence and remaining
physical boot/remount and independent-review gates are in `r4-fix2/`; these tests
do not accept R4 or start R6.

R7a-fix1 的 close 文本保持单个 legacy `content` 项。MCP stdio/HTTP 的生命周期字段为
`_meta.nexus.lifecycle`；CLI 成功为 `result.lifecycle`，错误为 `error.data.lifecycle`。
`close` ACK 与 owner 保存/退出仍分开；文件读取和 GC 夹具显式等待公开 owner proof、
producer/consumer 及 retirement ACK 结清。固定 N0 输出归一化和相等规则不变。
helper 默认预留 512 个 watch（每 parent 四个），live bytes 按每 slot 32KiB 有界计费，
mutable registry 另留四倍收尾空间；单份 immutable proof 与 IPC frame 保留原上限。

## Nexus E23 dedicated GUI

`scripts/verify_nexus_gui.py` runs one macOS Qt GUI on a newly prepared private
sample/IDB, HOME, IDAUSR and Nexus state. Build the explicit candidate with
`nexus-test-support` for existing native spawn/socket telemetry. It loads the
prepared upstream `ida_nexus_plugin.py`, uses GUI timer events independently of
Nexus, and exercises MCP open/close plus real flat CLI read/write calls. Require
one unchanged GUI record/PID/birth, both comment directions, nonlast detach ACK,
GUI responsiveness afterwards and identical IDB component hashes/inodes/mtime.
Only after these assertions does cleanup TERM/KILL the exact dedicated GUI
PID/birth, then wait for public owner proof and helper retirement. This does not
claim that GUI menu exit or upstream `qexit` is qualified.

```sh
uptime
timeout 180s env IDA_TEST=1 "$E23_ROOT/venv/bin/python" -B scripts/verify_nexus_gui.py \
  --root "$E23_ROOT" --binary "$CARGO_TARGET_DIR/debug/ida-cli"
timeout 30s python3 -B scripts/verify_nexus_gui.py --root "$E23_ROOT" --cleanup
uptime
```

Use a fresh physical `/private/tmp` prepared root for each run; do not reuse a
venv or process ledger. The result is exactly one `E23` PASS/FAIL/BLOCKED in
`e23-result.json`, with before/after uptime, binary/source identities, public
owner records, visibility/release witnesses and cleanup; control-capable close
tokens and Nexus authentication fields are never serialized. `native-processes.jsonl`
and `processes.jsonl` retain precise births; Python bind telemetry journals exact
socket inodes before interruption cleanup. A refused reused environment never
signals its existing processes. Run `test_nexus_gui_driver.py` for owner ambiguity,
scene replacement, incomplete creation evidence and reused-root refusal.

Missing GUI/authorization readiness is BLOCKED, never a skip. Inspect only this
instance's `gui/gui.log` and `gui/ida.log`; if IDA requests new terms or licensing,
stop and have the user prepare that private profile legally, then use a fresh
prepared root. The driver does not accept terms, copy licenses, patch installed
IDA, use the user's daemon, or close other GUI instances. Always run the cleanup
command after an interrupted outer timeout; unresolved creation identities remain
a failure requiring inspection, never guessed process-name cleanup.

### N8 legacy flat cache maintenance (implementation; review pending)

`ida-cli cache-legacy` is a local maintenance entrypoint, bypassing router,
logging and automatic daemon startup. Set `IDA_NEXUS_PYTHON` to the prepared
Nexus interpreter. `IDA_CLI_LEGACY_TIMEOUT_SECS` explicitly selects a 1–3600s
maintenance budget (default 1800s). Dry-run and action plans show the effective
`maintenance_timeout`; changing it requires a new reviewed plan/evidence. The
Rust supervisor forwards SIGTERM/SIGINT and allows 35s for rollback before its
last-resort kill. Use an outer timeout longer than the selected budget plus
that grace. The configured budget also bounds large input hashing and private
IDA-copy inspection; owner probes retain their short individual limit. Default is dry-run; it lists only root-level legacy `.i64`
groups, component names, byte counts, file hashes/identities, filename content
key, both index entries, packed state and public opener observations. Missing
SDK/state information is reported as unknown and cannot authorize execution.
It does not traverse `generations/`, `quarantine/` or recovery data.

Select `--mode migrate|clean --group <exact-flat-name> --backup <new-private-dir>`
to preview an exact plan. `--mode restore --backup <existing-backup>` previews
restoration, including after interruption. Every mode remains dry-run until
`--apply --offline-evidence <private-json>` is supplied. Backup must be outside
the cache, with a 0700 parent; existing backup directories and unknown files are
never overwritten. File bytes and both original index byte streams are copied,
fsynced and SHA256 verified before original data is changed. Migration additionally
opens a disposable packed copy without analysis/save, checks its embedded input
SHA256 against the existing flat input snapshot and checks that snapshot's
streaming BLAKE3 content key. Missing snapshots, components/unpacked databases,
unknown group members, symlinks and a pre-existing generation index refuse
migration. Clean also verifies a private packed copy, then removes the group
and its legacy index entry; any existing generation index remains unchanged.
Neither mode opens/saves the original IDB. Packed database bytes, including user
edits, are preserved exactly in backups and migrated generations. Generated
`{input,input.i64,generation.json}` and content-key pointers use the existing GC
format; existing healthy generations and quarantine are never processed.

The offline evidence is **operator-maintained exclusion**, matching explicit
manual offline maintenance, not an owner-release proof. Before apply the
operator must stop all routers/daemons, independent IDA/Nexus openers and remote
writers, and prevent new openers/automatic restarts for the entire window.
A single negative public probe cannot establish this. The JSON must contain
`schema=1`, `plan_sha256`, `root`, `router_homes`, `state_roots`, `boot_id` copied
from the reviewed plan, current `uid`, nonempty `operator` and `exclusion_method`,
`confirmation="I established and maintain this exclusive offline window"`,
`offline_scope` equal to the preview's `required_offline_scope`, and numeric
`started_at`/`expires_at` covering now with at most 3600 seconds between them.
Use repeated `--router-home` and `--state-root` to declare the complete inventory;
defaults are the selected IDA CLI home and `IDA_NEXUS_STATE_DIR`. These directories
must exist at canonical, absolute, symlink-free paths. Evidence is bound to
host boot, directory identities, action, selected group, backup path and exact
current files/indices; it is revalidated under locks and before each deletion.
This attestation cannot be auto-generated as proof by the tool.

Apply preserves old CLI startup-lock modes (including 0644) while requiring
a single-link regular file owned by this uid with no group/other write access.
It holds every declared `.startup.lock`, cache-root `.cache.lock` EX and
stable target EX until backup/publication/removal or rollback finishes. Live PID
or remaining router sockets, public owner discovery/registration incompleteness,
nonpacked/component locks, unsettled custody and recovery obligations veto it.
Public state checks run in fresh bounded processes for each declared state
root. Ordinary caught failures restore exact original bytes/indices under these
locks. Unknown replacement bytes cause a visible collision refusal and retain
all copies. SIGTERM/SIGINT are checked between streaming chunks and mutation stages;
owned helper process groups are reaped before rollback. Restore copies stage
verified bytes before non-replacing publication, so an interrupted restore
does not expose a partial original. If forced termination prevents rollback,
the CLI prints the backup/restore instructions; a missing completed manifest
means original files/indices were never changed by that attempt. After a hard
process interruption, explicitly preview/apply restore
with a fresh offline window. Restore is idempotent and retains backups; migration
products left by an interrupted/rolled-back operation stay available for the
existing GC rather than being recursively removed by this tool. Hash manifests
and verification copies remain in the private backup for review.

```sh
timeout 30s ida-cli cache-legacy --root "$CACHE" --state-root "$STATE"
timeout 30s ida-cli cache-legacy --root "$CACHE" --mode migrate --group "$GROUP" --backup "$BACKUP"
timeout 1840s ida-cli cache-legacy --root "$CACHE" --mode migrate --group "$GROUP" --backup "$BACKUP" --apply --offline-evidence "$EVIDENCE"
timeout 1840s ida-cli cache-legacy --root "$CACHE" --mode restore --backup "$BACKUP" --apply --offline-evidence "$RESTORE_EVIDENCE"
timeout 120s python3 -B tests/test_nexus_n8tool.py -v
```

Tests use private HOME/cache/state and synthetic bytes for deterministic safety
branches; `tests/support/n8tool_real.py` additionally creates an isolated real
small IDB with a comment and patched byte, invokes the built entrypoint,
reopens the migrated/restored IDB and reads both edits back. This targeted
validation does not replace N8 full E2E or independent review.


N8 工具返修的 R5 receiver 回归保持每个 socket 读取 2s 屏障。独立 Rig 在 N1
入队前通过同样有界的 2s fixture admission 同步，避免互不相关的测试同时
抢占全进程两个非等待 Encode 名额。单场景的全部 A/B peers、原189轨迹
和诊断断言仍走相同生产 N1/reader。合法的 Busy/NotSent 不产生 wire frame，
旧 fixture 却无界等首帧；超时现在打印阶段和 N1 open_progress。没有增加
生产编码容量或等待策略，也不重试 Busy、不放宽断言。

feature lib 的既有维护夹具还需要私有 `IDA_NEXUS_STATE_DIR`、`R3A_CASE_ROOT`、
`R3F1_SAMPLE`、静态测试 telemetry，以及 `R4_BASELINE_SOURCE` 指向固定
`5d8a215f92b4405e6db99af8e7f86c72ae95861f` 的 v1 producer 源码归档。

### N7b real sBPF and DSC directed cases

`nexus_n7b_e2e` has three independent exact cases: E24 first build/query/decompile/
cached reopen, E24 cancellation inside real sbx-launched IDAPython, and E25 new DSC
build/existing database/cached reopen. Each needs a fresh prepared environment,
`IDA_TEST=1`, its `rust-env.json`, private home/state/tmp/IPC, and explicit
`N7B_SBPF_SAMPLE` or `N7B_DSC_SAMPLE`. Samples remain read-only; sBPF is copied.
Use `N7B_E2E_BINARY` to name this checkout's absolute release binary for large DSC
inputs. It must exist; a supplied invalid path never selects another binary.

The DSC case selects `/usr/lib/system/libsystem_blocks.dylib`, adds
`libsystem_kernel.dylib` through Nexus, and retains the complete input bundle for
later dscu operations. The current system cache has about 6.56 GiB of companions.
Its source/member hashes and loader selection determine a distinct content key;
all copies, build and index publication use the existing root/content/open locks.
The retained `dsc-inputs` inventory is declared in `generation.json`; GC rejects
unexpected members, symlinks and incomplete packed groups. Legacy adjacent IDBs
and direct existing IDBs keep their original identity.

Run one exact case per fresh root, with before/after uptime. Ordinary real cases
use shell `timeout 180s`; allow `timeout 360s` for E25's complete bundle integrity,
offline IDA build and repeated loads (inner driver330s). No complete E2E matrix is
implied. Missing runtime/sample is a failure, never an ignored pass. Each driver
writes `<case>-result.json` and must finish with PASS plus cleanup CLEAN; the
Rust wrapper also requires one passed test and zero failures/ignored cases.
The cancel case blocks actual IDAPython on a FIFO, then requires confirmed stop,
exact sbx/idat identities gone, no output or staging/temp inputs, and a healthy
second library. It does not replace sbx/idat with a fake compiler.

`nexus_n7b` separately checks capability admission, generated offline-plugin
failure and task-owned temporary files. `test_nexus_n7b_cache.py` covers the
strict bundle inventory. These are deterministic contracts, not real E24/E25.
N7b delivery and independent acceptance are recorded in the external report.

N7b fix1 stores new DSC members once as private, non-overwriting SHA256 objects
under `dsc-members/<digest>/{data,verified.json}`. The data mode is 0400; each
`dsc-inputs/<loader-name>` is a same-volume hard link. Existing content identities
and the loader's generation path do not change. Old private-copy generations
remain readable and are not rewritten while they may be in use. Root SH plus
module-content EX remain; one additional member-store EX serializes publishing
and verification records. Under root EX, GC derives reference counts from all
generation/quarantine manifests and also requires nlink=1 before deleting an
unreferenced object. Unknown manifests, files, replacements or extra links retain
objects. Byte accounting deduplicates inodes.

Source SHA256 records bind dev/ino/size/mtime_ns/ctime_ns plus uid/mode/nlink.
Unchanged FD and path metadata allow reuse; changed source metadata requires a
new hash, while changes during reading or a symlink are refused. New immutable
objects bind the same fields to their write-time verified digest. A replaced
private inode/data binding is refused. Other namespace/ctime changes force hash
verification; serialized internal hard-link creation can refresh the binding
only while the same read-only FD/data/mtime binding remains unchanged. GC unlink
changes will therefore require verification on the next use. Old private-copy
inputs use the metadata-bound source cache after their first validation too.
Corrupt records, unsafe memo/receipt replacements and inconsistent data bindings
fail explicitly, without silently rebuilding them. This assumes the private cache and kernel
metadata are trusted; it does not defend against a same-privilege actor forging
verification records or kernel metadata.

`nexus_n7b_fix1` uses a controlled offline IDA boundary to prove that distinct
module generations share member inodes and refuse unknown objects. The unit
`nb2_regressions` and `storage::tests` cover unchanged metadata, source inode
replacement, timestamp-only changes, restored mtime after a write, private inode
replacement and forced verification after link changes. The payload-read counter
exists only in unit tests. `test_nexus_n7b_shared.py` exercises real filesystem
links/locks with a no-owner probe boundary, including last-reference reclamation,
unknown manifests, symlinks and unfinished/external references. These fixtures do
not claim native IDA or N1 owner proofs. The real E25 driver separately records
functional new-build/cache-hit intervals and unique/allocated cache bytes; it
adds no benchmark framework. Use short fresh environment names for SUN_LEN.

Metadata reuse is qualified for local APFS on macOS and ext4/XFS/Btrfs/tmpfs on
Linux. Other source/cache filesystems retain complete hashing with a diagnostic;
failed filesystem qualification is an error. Coarse or remotely cached timestamps
therefore cannot authorize a hash hit. Linux qualification is implementation
policy only; this delivery's real E25 evidence remains macOS/APFS.

唯一 Nexus 后端在 CLI 发现 daemon 或服务启动前拒绝已删除配置（包括空值）：`IDA_CLI_NEXUS_DEV`、`IDA_CLI_WORKER_BACKEND`、`IDA_CLI_SDK_VERSION`、`IDA_CLI_MAX_WORKERS`、`IDA_CLI_MAX_WORKERS_PER_TENANT`、`IDA_CLI_MAX_PENDING_PER_WORKER`、`IDA_CLI_MAX_CONCURRENT_SPAWNS`。请删除这些变量；按实际需求配置 `IDA_CLI_MAX_PENDING_PER_TENANT`、`IDA_CLI_NEXUS_RETENTION_CAPACITY` 或 `IDA_CLI_HELPER_CAPACITY`。它们是独立限制，不与旧 worker 数量一一对应。

支持的 IDA 运行时集合为 **9.4、9.5**，不接纳低版本或未知新版本。runtime-lock 为每版锁定自带 idapro wheel（9.4: 0.0.9；9.5: 0.0.10）及 SHA256，不跨版本借用。9.4 条目仅在安装后 `__init__.py`、`config.py` 与登记哈希一致时，允许 Domain 0.5.1 要求 idapro>=0.0.10 的这一条元数据冲突；两版运行代码字节相同，Domain 代码支持 IDA >=9.1 且检测新 API。闭包全哈希锁定并以 `--no-deps` 安装，其他 pip check 冲突仍失败。

安装器按应用名称数字版本逐段比较、尾零等价、同版本按规范路径升序选择最新项，打印其他候选；最新不兼容时报错并提示用 `IDADIR` 指定其他候选，不自动退选。启动器保存安装时路径，显式 `IDADIR` 可覆盖到另一受支持版本；probe-runtime/status 分别报告实际 `ida_version` 和 `installed_ida_version`，建议按目标版本重新安装。实际版本由无数据库的有界子进程加载内核核实，并在每次 open 后核对 owner。

N0 固定二进制链接 IDA 9.5，输出对照仅在 9.5 成立。9.4 下需要 N0 的 suite 明确 BLOCKED；contract 可用 `--case E16`、`E17`、`E22` 单独运行。E22 在 9.4 现场生成带标注的旧平铺布局库，核对缓存与预热契约，不宣称 N0 跨版本对照。

## N9-E2E release directed suite

`verify_nexus_e2e.py --suite release --baseline <fixed-N0-binary>` runs exactly
E27/E28/E29 as three separate Rust `--exact` entries; R7a's large seed case stays
separate. Prebuild `target/release/ida-cli` with `nexus-test-support` for exact
native creation evidence. Build without IDASDKDIR/IDALIB_SDK; use a new physical
/private/tmp prepared environment, private HOME/IDA_CLI_HOME, profile/state/IPC.
The verifier copies and hashes the N0 binary before use. IDA/license/N0 absence
is BLOCKED. At 9.4 the entire suite/E28 is BLOCKED because N0 links 9.5; E27 or
E29 can be selected with `--case` and the same fixed `--baseline` prerequisite.

Each real case has a shell `timeout 180s`; the three-case outer bound is **570s**
(3 * 180s plus 30s for aggregation and exact cleanup). A single case uses an
outer 210s. Compile/link beforehand. Each case writes its own result JSON,
PID/native birth ledger, negative assertion witness and socket evidence; the
summary requires exactly three actual test terminals and three PASS cases.
Partial PASS counts, 124, unknown inner terminals and zero tests never pass.
After interruption run the verifier's `--cleanup` on that exact environment.
No cleanup scans process names. A failed case retains diagnostics and is not
converted to PASS by cleanup.

E27 first asserts a definite CancelPending refusal while a cooperative script
holds its started barrier: the daemon and request stay alive, and external B
remains queryable with its original birth. It releases the barrier and requires
one successful terminal with no replay, then shutdown succeeds. Exact service
births, sockets, registrations and leases must be gone while external B remains
usable. The same artifact restarts, reads saved edits, has no old tasks/leases,
and shuts down cleanly again. A real additional held child must fail the exit
ledger assertion. The accepted N1 busy-shutdown refusal remains unchanged.

E28 creates its pre-migration backup during the case, checks N0 annotations,
migrates a separate copy, retains that scene and restores only the backup in
another directory using N0/9.5. It checks hashes, names/comments/decompilation
and absence of post-backup edits. A damaged disposable copy demonstrates the
backup equality assertion failing. N0 is never given the migrated copy.

E29 packages and installs the release under its own prefix, checks otool
libraries/load commands and cargo tree, rejected commands/variables (also with
an existing daemon), and failures after renaming only the private venv. Exact
creation ledgers prohibit legacy/native/idat query workers. A real disposable
extra child named idat demonstrates detection, then its held Popen is reaped.
After restoring the venv, list/decompile/write/save/close/reopen/readback and
shutdown must succeed naturally. CLI automatic startup now reports an exited
Nexus daemon immediately using the held Child; no alternate backend is tried.
Existing N9 patch-tamper regression remains the patch hash negative control.

RV9-6 scripting input is resolved once before database acquisition, including
CLI, queued jobs and MCP forwarding. Exactly one of code/file is required;
invalid/unreadable paths use the same InvalidPath text as MCP. File reads retain
the existing bounded Prepare class, original admission deadline and job tracking;
input failure starts no bridge or Nexus operation. `nexus_script_input` and the
library's router/MCP deadline barriers cover admission; the bridge rejects an
unresolved missing code instead of silently running an empty script.

The nexus_n9 maintenance fixture completes a separately bounded first execution
of its freshly written shell inode before the measured maintenance invocation.
This isolates macOS first-execution delay from the unchanged 1s product budget.
Expiry, rollback guidance and exact PID ESRCH assertions are retained. Directed
qualification runs that exact test 20 consecutive times against unchanged test
and product binaries, recording each command's uptime; no retry selects a pass.

Normal shutdown retains the existing bridge until the released paths' physical
owner proofs and the bridge/helper retirement counts converge, within a shared
15s wait. It observes the existing protocol and does not stop external owners.
Busy lease release still fails before this wait. Pending or blocked observations
return CancelPending with the bridge retained; no unproved cleanup is called
success. E27 exercises this path without a preparatory close command.

Bridge death during a cold open can leave the helper holding a signed launch
intent and parent reservation that Rust never tracked. Once the exact bridge
process is reaped, Rust tracks no resource, startup or retirement and no file job
is pending, shutdown (RPC and TERM/INT) waits for that helper-only state to stay
unchanged for 3s, skips the helper finish it would refuse, and exits. Nothing is
retired, proved or replayed: `helper-state.json` keeps the obligation, the helper
abandons it through its 300s orphan expiry, and status reports
`untracked_helper_obligations` with next_action
`shutdown_then_restart_helper_retains_obligations`. This router never replaces a
lost bridge, so opens fail at once with `bridge disconnected: ... ida-cli
shutdown`. Lib regression:
`final_shutdown_tests::shutdown_after_bridge_death_retains_untracked_helper_obligation`
(red on the old code: CancelPending after 15s). A tracked startup or resource, or
a live bridge, keeps the previous wait-and-refuse behaviour.

A signed LaunchIntent that Rust tracks (`launch` retained, no `Spawned`, no
public owner) is settled only by revoking its durable startup authorization.
The old H1 inference from waitpid + a 5s margin + empty process/public scans is
invalid: a forked child may remain pre-exec indefinitely and later open the IDB.
No scheduling delay supplies an upper bound.

J adds `launch-authorization.patch` to the fixed SDK chain. In the synchronous
pre-Popen `LaunchIntent` observer, the bridge creates/fsyncs a per-watch grant in
the helper's private IPC directory, includes its absolute path in the signed
launch identity, and returns it to the SDK. The SDK adds `--launch-authorization`
and `--launch-target`. Before `probe()` loads idalib, unpacking, `Database.open`
or database locking, the worker must exclusively create `<grant>.decision` and
fsync a complete `claimed` record plus directory. The helper, only after the
router waitpid of its exact bridge, competes for that same name with `O_EXCL` and
writes/fsyncs `revoked`. Exactly one creation wins. A missing grant, partial file,
permission failure or unknown record permits neither worker access nor journal
settlement. A late or duplicate claimant exits 78 and logs
`LaunchAuthorizationDenied`. A complete revoked decision may replay its ACK;
claiming is never reentrant. Grant/decision files are never deleted or reissued.

Only durable revocation produces `LaunchAbandonedUnspawned`: its signed launch,
watch/acquisition/epoch, exact grant path and revoked decision must match. The
target journal independently checks the decision on disk, refuses any known
owner/Spawned/lease/proof, and then uses the existing helper retire/journal
settle/parent retire path. Process-table and discovery absence carry no closure
authority. The remaining native scan fails closed on argv permission errors,
status/argv short reads and full PID buffers; only ESRCH or a validated zombie
is skipped. No worker is signalled or interrupted by this protocol.

If the worker already claimed, the helper retains the obligation, discovers the
public owner and follows the original public lifecycle. The managed 20s lease
grace only starts draining after server startup; `analysis_thread.join()` and
`database.close()` have no bound. A claimed worker stuck in open/close, or one
that dies before publication, remains pending. This patch neither bounds those
operations nor settles a claimed owner crash. Legacy live launch records without
authorization also remain pending unless the public lifecycle proves release;
a new SDK worker launched without these two arguments keeps its upstream behavior.
Old absence-only abandonment facts cannot newly authorize journal settlement.
Upgrade must rebuild the matching venv; preserve old evidence and confirm prior
owners have closed before switching versions. Already compacted historical facts
are not reinterpreted as proofs about ungoverned old workers.

W1 (`BeforeLaunchAck` fixture barrier: helper signed, Rust not yet tracking)
remains the existing retained-obligation
handoff. The synchronous observer cannot reach Popen until Rust signs/ACKs, so
bridge death in W1 cannot leave a spawned authorized child. It is not falsely
reported as revocation or an owner lifetime proof.

Tests: `bridge_loss_tests` uses explicit pre-claim and claimed worker barriers for
W2b, and the pre-Popen barrier for W2a. The live claimed owner must finish by its
public lifecycle; a dead unclaimed child settles by revocation. Helpers are never
manually killed for test cleanup. `test_launch_settle.py` covers journal rejection,
restart/idempotence, legacy records and torn decisions;
`test_launch_authorization.py` races claim/revoke and checks worker pre-IDB denial
and unchanged standalone SDK behavior. `test_process_table_fail_closed.py` injects
permissions, short reads and saturation. `test_delayed_launch.py` kills/waitpids a
private parent with an already-spawned child parked before exec for >5s, settles,
then releases the child: baseline H1 opens the real IDB after settlement, whereas
J denies it before IDB access. Read-only baseline helper/process/worker sources
may be selected with `J_RED_HELPER`, `J_RED_PROCESS`, `J_RED_JOURNAL`, `J_RED_WORKER`; the safety
assertion is identical in red and green runs.

Recovery from a lost bridge. This router never replaces its bridge, so the
`serve-http` daemon now leaves by itself (`RouterState::exit_after_bridge_loss`):
once the bridge is lost it polls the same gate `ida-cli shutdown` uses
(`wait_shutdown_ready`: empty custody, the helper-only rule above, or a settled
unspawned launch), takes the usual `shutdown_nexus` path and cancels the service
token, which removes socket and discovery files; the reason is logged whenever it
changes ("daemon retained until custody allows a safe shutdown"). Nothing is
forced: with unsettled custody (a live orphan owner, a tracked resource) the
daemon stays and requests keep their refusal. The stdio `serve` process does not
run this watcher: it is the MCP server of its client, cannot be replaced behind
that client's back, and keeps the explicit error (its message says it does not
exit by itself). A request refused before anything reached the lost bridge
carries JSON-RPC code `-32010` (`RPC_BRIDGE_LOST_NOT_DISPATCHED`, data
`bridge_lost.dispatched=false`, `nexus.code=bridge_lost_not_dispatched`); it is only emitted by
a daemon that has armed its self-exit. Its `nexus.retry` is
`reconnect_then_new_request`, consistent with the bridge-specific
`bridge_lost.retry=once_after_daemon_exit` recovery instruction.
Only the outer open entrance, before
acquisition or dispatch, creates `BridgeLostNotDispatched`. Generic `Disconnected`
and per-attempt `NotSent` never establish this whole-request guarantee: a yielded
operation is queued with execution stopped even though earlier slices completed.
Generation loss, client lease loss and next-slice NotSent after `_n5_checkpoint`
therefore report `OperationFailed`/"effects may remain; do not replay", retaining
the original cause. Both the delivery return and operation snapshot carry that
classification. In-flight uncertainty remains `UnknownOutcome`. Contract cases
`completed_write_continuation_*` cover write counts and both failure surfaces.
A dispatched request keeps `-32000` with
`UnknownOutcome`/"open outcome retained by N1; never replay" and is never retried.
The CLI (`send_recoverable`) treats only `-32010` specially, once: it waits (up to
180s) until nothing listens on the old socket, lets the existing discovery start
a fresh daemon, and resends the same request once. A second refusal, an unknown
outcome, an explicit `--socket` or `$IDA_MCP_SOCKET` (never started, replaced or
waited for), and a daemon that does not exit in time return the original error.
Applies to every single-request subcommand and `pipe` (per line);
`prewarm-many` always prints its per-item results and exits 1 if any item fails
(partial and complete failures use the same status), or 0 if all items succeed.
With `--queue`, success means acceptance with a task id; inspect `status` for
the eventual task results. Lib cases: `bridge_loss_tests::daemon_*` (self exit
in W2a; no early exit while a live orphan owner holds custody; unarmed process
never tags the retry code) and `cli::bridge_loss_recovery_tests`. Real
end-to-end evidence is recorded in the H report (W1, W2a, W2b; the first
ordinary `list-functions` after the loss succeeds).

### Symlinked temporary roots (K)

Verification must cover TMPDIR paths with symlink prefixes, including macOS's
actual `TMPDIR=$(getconf DARWIN_USER_TEMP_DIR)` under `/var/folders`, with
`IDA_NEXUS_IPC_ROOT` unset. Also run the private `/private/tmp` control. Keep
CLI home, state, IDA profile and sample copies private in both cases; use the
release binary for status, list-functions and shutdown, and check actual process
exit plus socket/discovery cleanup. W1/W2a/W2b must each run in both environments.

`test_launch_settle.py::SymlinkedLaunchRoot` exercises the real LaunchIntent
producer through a private link-to-real prefix and the system TMPDIR prefix. It
checks canonical grant spelling across the SDK callback, signed Rust payload,
helper and target journal, then revocation, denied late claim and full journal
retirement. A separate grant exercises claim through a prefix alias. SDK source
and output database paths already use the same realpath/abspath/expanduser rule
as target coordination; the bridge now normalizes the helper endpoint just as
proof_helper does before its strict Directory walk. The SDK patch is unchanged.
`test_launch_authorization.py` additionally rejects symlinked final directories,
symlinked grant files and nonprivate directories; O_NOFOLLOW checks remain intact.

For a reused prepared environment, set `N3_CASE_ROOT` to a fresh private root
with home/profile/state/tmp subdirectories and a copied test license. The fixture
validates modules against the original `N3_ENV_ROOT`, while process ledgers and
runtime state go to the case root. `ReadOnlyPreparedEnvironment` verifies that
separation without changing the prepared manifest's identity checks. The W2a
helper observation uses shutdown's existing serialized observation gate, so a
concurrent accepted finish is observed as finished rather than a second RPC.

### Final-fix harness requirements

E27 needs a release build with `nexus-test-support` to record exact daemon births;
missing creation evidence is BLOCKED. E29 must run against the formal release
artifact built without test features; use `verify_nexus_e2e.py --target` to select
that build. Run these cases separately when their artifact requirements differ.
E23 accepts a prepared environment containing `home`, and creates `gui-home` for
its own GUI. The existing process ledger / `gui` reuse refusal still applies.

`nexus_r3b_fix1` constructs its two-slot F2 router explicitly; it needs no
`IDA_CLI_MAX_PENDING_PER_TENANT` override. Nexus opens return distinct lease
handles, while `list_idbs` groups the same physical instance under its oldest
live handle. Client identities in holders and opened_by share the same space;
the active group is the one with the latest open time (not lexical handle order).

The retired `ida_e2e` target used deleted `serve-worker` and is removed. Its
open/database-info scenario is covered by `e04_fixed_n0_output_comparison`
(`list_functions`, database metadata comparison); patch/readback and
rename/prototype/lvar scenarios by `n6_e04_all_write_and_advanced_methods`
(per-method strict N0 comparison including readback and owner evidence), with
saved edits covered by `n6_e20_seven_categories_survive_save_close_reopen`.
The smoke dispatch scenario is superseded by
`n6_tools_and_aliases_preserve_mcp_contract` (every registered tool/alias).
Use the contract and n6 verifier suites with their prepared 9.5 environment
and fixed N0 baseline. These are real Nexus paths, with no legacy source.

IDA_TEST audit: only `list_idbs_e2e` and `decompile_line_addresses_e2e` still had
opt-out early returns after removing ida_e2e; they now fail explicitly with
BLOCKED if opt-in is absent. Run each with `IDA_TEST=1` and prepared private
HOME/IDA_CLI_HOME/IDAUSR/state/IPC plus IDA_NEXUS_PYTHON. The real
`nexus_{lifecycle,contract,concurrency,n6,special_inputs,n7b}_e2e` targets already
assert prerequisites (directly or in support/nexus_env.rs), never return early.
A cargo summary alone without these prerequisites is not real IDA evidence.

R0 current-product tests now assert green F1/F2/F4 lifecycle behavior. F1
accepts parsed detach ACK and reopens a newly published controlled owner after
public release. F4 reports analysis failure together with its acquired lease,
keeps explicit ReleaseRequired custody while native stop is unconfirmed, and
settles after public lifetime proof. F2 retains the other client's query/control
after lost ACK. Controlled R0 HTTP/IDA inputs are not real-IDB reopen evidence;
`real_ida95_saved_modification_immediate_reopen_and_shared_lease` provides that.

FA13 soak uses one formal release daemon and fresh socket connections for
2100 sequential list_functions/decompile_function/run_script requests. Record
RSS and retention at each 100-request boundary, require stable owner identity,
bounded live/closed diagnostics, and exact close/shutdown plus clean IPC.
CLI warm references must be explicitly closed before harness custody-zero
assertions; releasing one MCP token does not release the CLI's separate lease.
A verification read races only atomic custody.json replacement: retry at most
eight fully validated reads; corruption, identity mismatch and permanent churn
still fail. SDK completion can recover a lost handoff only by validating its
exact helper receipt and durable target binding, never by granting SDK work.
Closed diagnostic payloads may compact, while terminal identity tombstones
remain charged to the existing fixed retention quota.


Signal regression: run `tests/test_nexus_signals.py` under shell `timeout 120s`
with `N3_ENV_ROOT` pointing at a private prepared 9.5 environment and
`N9_PROBE_BINARY` at this build. TERM and INT both request confirmed Nexus
shutdown, with a 30s total budget. Busy/uncertain custody refuses visibly and
retains the service; complete or cancel work, inspect status/helper-state.json,
then retry shutdown. The test uses a script-start marker and release barrier,
checks refusal without terminating work, then retries after its definite terminal.
Idle HTTP and an uninitialized stdio peer must exit naturally; stdio runtime
teardown has a separate 1s bound for its uncancellable stdin reader.
Proof-helper TERM resets inherited ignore dispositions and uses the same durable
abandonment handoff as orphan expiry: unresolved obligations remain recorded,
publication failure is diagnostic, never fabricated owner-release proof.
A SIGKILL can leave stale b/c/h files. A new generation does not scan/delete
unrecorded old sockets: cleanup requires exact creator birth and inode evidence.

E07 packed recovery deliberately arms one test-only Root Node initial-open
failure after the crashed owner's disconnect and public proof. It requires
initial_root_retry within R9's existing three-attempt budget and exactly one
crash backup per actual acquisition ordinal (one crash restore, then its
initial Root retries). No extra or missing backup is allowed. The crash
marker still must contain exactly one write and the restored saved name must
match the packed base. This makes the formerly intermittent R9/E07 composition
explicit without widening backup-count or no-replay assertions.
E23 releases the independent CLI warm lease while the recorded GUI owner is
still alive, then confirms the scene is unchanged before exact GUI cleanup.


### sBPF profile isolation

`nexus_sbx_profile` uses isolated child environments and a recording offline
builder to reject profile-less flat/index entries, verify explicit arguments,
cache hits and different generation paths, and reject a mismatched manifest.
`tests/support/sbx_profile_real.py` runs one real profile case against a supplied
release binary in a prepared environment with a shared profile cache. Select
`default`, `analysis-inline`, `trace`, `optimized`, or `invalid`; run each with
shell `timeout 180s` and record uptime. It records actual sbx/idat argv and birth
identities, queries/decompiles, checks the second open uses no new build, and
starts the server in a private fake Cargo workspace to exclude target-aot output.
The default case also proves a client variable cannot reconfigure its server.
This is directed validation; it does not run or advance the full E2E matrix.


### Spawned worker death settlement (N; validated implementation)

The same-boot exit capability is separate from public owner lifetime and from
unspawned authorization revocation. A valid native birth and boot UUID must bind
the signed Spawned PID to the worker that claimed the single-use launch grant.
The fixed macOS console script calls CLI main, which calls worker main in the
same process; shebang interpretation/exec preserves that PID and birth. The
post-Database.open test gate must record that same PID, with an independent
native birth capture. This argument applies only to the verified fixed launch
chain; an arbitrary spawner or a launcher that forks requires worker self-attestation
in the claimed decision before this capability can be used.

A positive exit observation requires a validated recorded identity, an independent
current boot query matching that record, and either definite native ESRCH or a
complete current identity with the same boot and a different birth. Permission
errors, short reads, malformed identities, a live or stopped matching worker and
cross-boot observations retain custody. A zombie has exited and cannot execute
or touch the IDB; it may settle after native ESRCH (macOS can exclude zombies
from proc_pidinfo) or a full native SZOMB record with validated birth. This
uses a distinct native probe, never the diagnostic identity API's ambiguous None. Existing
qualified boot retirement remains a distinct path with its existing scope checks.

An independent immutable SpawnedOwnerDiedUnpublished fact must close only launch
observation, never synthesize PublicOwnerLifetime or LaunchAbandonedUnspawned.
The journal must verify the signed source, authorization and native death itself
under target EX. Restart settlement must serialize against a still-live old
helper's fact publication and must not write its mutable helper registry.
Database recovery and unknown request outcomes retain their existing handling.

The target writer publishes the new fact in a deterministic slot distinct from
helper sequence names. Target EX serializes competing gate/recovery writers;
the observation fact-view lock serializes this publication with old helper
publication. No recovery writer edits the old helper registry or claims its
identity. The journal independently reopens the original Spawned inode/hash,
revalidates launch/acquisition/watch/epoch, reads the claimed grant with the
SDK's strict descriptor reader, and checks native same-boot death. Known owner,
lease, attach or public-owner facts refuse this narrow closure. A complete
fact left by a crash before journal adoption is rechecked and reused.

The original daemon waits for SDK completion or bridge waitpid, adopts the
journal-selected consumer in its helper, retires the watch and parent, then
closes the acquisition. A new daemon's gate can settle the target while the old
helper remains alive. After independently committing the fact, gate verifies
the old helper's exact birth and uses its authenticated private RPC to adopt the
consumer, retire the watch and retire its parent reservation. Only that helper
writes its registry. Evidence GC remains pinned until the original daemon ACKs
its in-memory retirement or the exact helper exits, so concurrent consumers
cannot lose their source records. Legacy/offline helpers lacking this RPC are
explicitly diagnosed; their registry is retained without impersonation, and
GC waits for the existing 300-second orphan expiry. Death
never certifies a safe database close: ordinary database_state probing and IDA
crash recovery still run at the next open. No unknown request is replayed.


The worker gate is generated at test runtime from the hash-verified installed
SDK worker. The repository contains only a small generator and explicit fence;
complete SDK source, IDBs and generated native artifacts stay in caller-owned
private directories outside the repository. A unit check removes the three
insertions and requires byte-for-byte equality with the installed worker.
The generator rejects a nonprivate directory and any directory inside the repo.

Keep prepared runtime packages and all mutable test evidence separate. Executable
startup telemetry in a shared venv can override shell environment variables.
Use a fresh matching private runtime if that prevents read-only reuse; preserve
the pinned SDK hashes and the closed bootstrap's interpreter-prefix checks.
The optional existing test collector must remain opt-in for explicit collection;
ordinary gate tests leave its variables unset. Preserve any earlier accidental
shared log append as diagnostic evidence instead of truncating shared history.


Qualification: default lib 542, feature lib 564 (three private-root runs and one
native macOS TMPDIR run), contract 78, and Python 271 in each temporary-root
configuration. The six startup scenarios each pass three times, with separate
CONT public-lifetime controls and three restart cases that verify a still-live
old helper retires its own watch and parent. W1/W2a/W2b and the ordinary
production SDK path also pass under native TMPDIR. PID/birth and private process
audits require zero residuals; shared prepared-runtime ledgers stay unchanged
during the final isolated qualification. SDK module hashes and patches are
unchanged. The old complete-worker fixture is absent from the branch history;
only the private runtime generator remains.
