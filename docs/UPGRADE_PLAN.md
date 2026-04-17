# rmcp 0.17 Upgrade + New Tools Plan

## Overview

Two phases of work on `ida-cli`:

1. **Phase 1**: Upgrade rmcp 0.15 → 0.17 while preserving multi-IDB Router
2. **Phase 2**: Add 5 new reverse-engineering MCP tools

---

## Phase 1: rmcp 0.17 Upgrade (Preserve Router)

### Upstream Context

Upstream commit `3212c79` upgraded rmcp 0.15→0.17 but also **deleted the Router**.
We cherry-pick only the rmcp upgrade parts, keeping Router intact.

### 1.1 Cargo.toml

| Change | Detail |
|--------|--------|
| `rmcp` | `"0.15"` → `"0.17"` |
| `tokio` | Keep ALL features (process/io-util/time needed by Router) |

### 1.2 src/server/task.rs

| Change | Detail |
|--------|--------|
| New constants | `TERMINAL_TASK_CAP = 256`, `TASK_RETENTION_TTL_MS = 0` |
| `TaskState` new fields | `updated_at: Instant`, `updated_at_iso: String` |
| `create_keyed` rewrite | Functional dedup, `now_with_iso()`, `prune_terminal_tasks()`, `next_task_id("dsc")` |
| New `create_completed` method | For inline tasks; uses `next_task_id("task")` prefix |
| `update_message/complete/fail/cancel` | Add `refresh_updated(&mut entry.state)` |
| `complete/fail/cancel` | Add `prune_terminal_tasks(&mut entries)` |
| `next_task_id()` → `next_task_id(prefix)` | Parameterized prefix |
| New helpers | `now_with_iso()`, `refresh_updated()`, `prune_terminal_tasks()` |
| New tests (4) | `create_completed_uses_task_prefix`, `inline_completed_tasks_are_capped`, `keyed_terminal_tasks_are_capped`, `recently_completed_task_not_immediately_evicted` |

### 1.3 src/server/mod.rs

| Change | Detail |
|--------|--------|
| `task_state_to_mcp` | `last_updated_at: None` → `state.updated_at_iso.clone()` |
| `task_state_to_mcp` | `ttl: None` → `Some(task::TASK_RETENTION_TTL_MS)` |
| New helpers (4) | `call_tool_result_to_value`, `looks_like_call_tool_result`, `wrap_as_call_tool_result`, `task_payload_result_value` |
| `enqueue_task` else branch | Use `create_completed()` instead of manual inline task |
| `get_task_info` return type | `GetTaskInfoResult` → `GetTaskResult` (rmcp 0.17) |
| `get_task_result` return type | `rmcp::model::TaskResult` → `GetTaskPayloadResult` (rmcp 0.17) |
| `cancel_task` return type | `()` → `CancelTaskResult` (rmcp 0.17) |
| `SanitizedIdaServer` | Sync 3 method signatures above |
| New tests (2) | `task_payload_preserves_valid_call_tool_result`, `task_payload_wraps_content_array_shape_that_is_not_call_tool_result` |

### 1.4 src/main.rs

| Change | Detail |
|--------|--------|
| `ServeHttpArgs` | Add `--json_response` flag |
| `run_server_http` | Warning log if `--json-response` without `--stateless` |
| `StreamableHttpServerConfig` | Add `json_response: args.json_response && args.stateless` |

### 1.5 Files NOT Modified

| File | Reason |
|------|--------|
| `src/router/mod.rs` | Router core — preserve as-is |
| `src/router/protocol.rs` | Router protocol — preserve as-is |
| `src/server/requests.rs` | Keep all `db_handle: Option<String>` fields |

### 1.6 Verification

- `cargo check` — zero errors
- `cargo test` — all pass

---

## Phase 2: New MCP Tools

### 2.1 decompile_structured (P0)

Structured decompilation via embedded Python ctree walker.

| Field | Value |
|-------|-------|
| **Tool name** | `decompile_structured` |
| **Category** | `ToolCategory::Decompile` |
| **Implementation** | Embedded Python ctree walker script, executed via `run_script` |
| **Precedent** | `dsc_add_dylib` — same pattern: Rust 构造 Python 脚本 → `run_script` 执行 → 解析结果 |
| **Input** | `address`, `max_depth`, `include_types`, `include_addresses`, `db_handle` |
| **Output** | JSON AST: `{ function, address, return_type, num_args, lvars, body: {op, stmts/expr/cond/...} }` |

**Rationale**: idalib Rust bindings only wrap `CInsn`/`CBlock`; `cexpr_t` fields are not exposed. Extending the Rust FFI would take 2–4 days. Python ctree walker via `run_script` achieves the same result in ~half a day.

**Feasibility verified**: 2025-02-28 在 `metis-binary.i64` (Mach-O ARM64, 25711 functions) 上用 `run_script` 实测 ctree walker prototype，成功输出完整 JSON AST。函数 `sub_100015A98` (256 bytes, 12 lvars, 16 statements) 全部序列化通过。

#### 2.1.1 Architecture

```
MCP Client
  │
  ▼ call_tool("decompile_structured", {address, max_depth, ...})
  │
  ▼ server/mod.rs :: decompile_structured()
  │   ├─ Router mode? → route_or_err("run_script", {code, timeout_secs}) → 转发到目标 IDB
  │   └─ Local mode?  → self.worker.run_script(&script, timeout)
  │
  ▼ 构造 Python 脚本（地址 + 选项注入到模板常量）
  │
  ▼ IDAPython 执行: ida_hexrays.decompile → ctree walker → JSON stdout
  │
  ▼ Rust 侧解析 stdout JSON → 检查 {"error":...} → 返回 CallToolResult
```

#### 2.1.2 Files to Modify (4 files)

##### (A) `src/server/requests.rs` — 添加请求结构体

```rust
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DecompileStructuredRequest {
    #[schemars(description = "Optional database handle for multi-IDB routing. If omitted, uses the active database.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_handle: Option<String>,

    #[schemars(description = "Address of function to decompile (string/number)")]
    #[serde(alias = "addr")]
    pub address: Value,

    #[schemars(description = "Maximum AST depth to serialize (default: 20, max: 50). Deeper nodes are truncated to {op: '...', truncated: true}")]
    #[serde(default)]
    pub max_depth: Option<u32>,

    #[schemars(description = "Include expression type info on every node (default: false). Adds 'type' field to each cexpr_t node.")]
    #[serde(default)]
    pub include_types: Option<bool>,

    #[schemars(description = "Include raw address (ea) on every node (default: true)")]
    #[serde(default)]
    pub include_addresses: Option<bool>,
}
```

##### (B) `src/ida/handlers/disasm.rs` — 添加 Python 脚本生成函数

在现有 decompile handler 旁边添加（decompile/pseudocode_at 也在此文件中）：

```rust
/// Generate the IDAPython ctree walker script for decompile_structured.
pub fn decompile_structured_script(
    addr: u64,
    max_depth: u32,
    include_types: bool,
    include_addresses: bool,
) -> String {
    format!(
        r#"
import ida_hexrays
import ida_name
import json

EA = {addr:#x}
MAX_DEPTH = {max_depth}
INCLUDE_TYPES = {include_types}
INCLUDE_ADDRESSES = {include_addresses}

{body}
"#,
        addr = addr,
        max_depth = max_depth,
        include_types = if include_types { "True" } else { "False" },
        include_addresses = if include_addresses { "True" } else { "False" },
        body = DECOMPILE_STRUCTURED_PY,
    )
}
```

Python 脚本常量 `DECOMPILE_STRUCTURED_PY` 包含两个核心函数：

- `serialize_expr(e, depth)` — 序列化 `cexpr_t` 节点
  - 处理所有表达式 op: `cot_num`, `cot_str`, `cot_var`, `cot_obj`, `cot_call`, `cot_cast`, 以及通用一元/二元运算
  - `cot_var` → `{"op":"var", "var_idx": N}` (索引对应 lvars 数组)
  - `cot_obj` → `{"op":"obj", "name": "symbol_name", "obj_ea": "0x..."}` (全局符号引用)
  - `cot_call` → `{"op":"call", "target": {...}, "args": [...]}` (函数调用)
  - 可选 `type` 字段 (由 `INCLUDE_TYPES` 控制)

- `serialize_stmt(s, depth)` — 序列化 `cinsn_t` 节点
  - `cit_block` → `{"op":"block", "stmts": [...]}`
  - `cit_expr` → `{"op":"expr", "expr": {...}}`
  - `cit_if` → `{"op":"if", "cond": {...}, "then": {...}, "else": {...}}`
  - `cit_for` → `{"op":"for", "init": {...}, "cond": {...}, "step": {...}, "body": {...}}`
  - `cit_while` → `{"op":"while", "cond": {...}, "body": {...}}`
  - `cit_do` → `{"op":"do", "cond": {...}, "body": {...}}`
  - `cit_return` → `{"op":"return", "value": {...}}`
  - `cit_switch` → `{"op":"switch", "switch_expr": {...}, "cases": [...]}`
  - `cit_goto` → `{"op":"goto", "label": N}`
  - `cit_break` / `cit_continue` → `{"op":"break"}` / `{"op":"continue"}`

主入口逻辑：
1. `ida_hexrays.init_hexrays_plugin()` 检查 Hex-Rays
2. `ida_hexrays.decompile(EA)` 反编译
3. 遍历 `cfunc.lvars` 收集局部变量
4. `serialize_stmt(cfunc.body)` 递归序列化整棵 ctree
5. `print(json.dumps(result))` 输出 JSON

##### (C) `src/server/mod.rs` — 添加 tool handler

在 `#[tool_router] impl IdaMcpServer` 块中，靠近现有的 `decompile` 和 `pseudocode_at` 添加：

```rust
#[tool(
    description = "Decompile a function and return structured AST (ctree) as JSON. \
    Unlike 'decompile' which returns plain C pseudocode text, this returns \
    the full Hex-Rays ctree with nodes for every statement and expression \
    (if/while/call/asg/add/var/num/...), local variables with types, \
    and function signature. Useful for programmatic analysis of decompiled code."
)]
#[instrument(skip(self), fields(address = %req.address))]
async fn decompile_structured(
    &self,
    Parameters(req): Parameters<DecompileStructuredRequest>,
) -> Result<CallToolResult, McpError> {
    debug!("Tool call: decompile_structured");

    let addr = match Self::value_to_address(&req.address) {
        Ok(a) => a,
        Err(e) => return Ok(e.to_tool_result()),
    };
    let max_depth = req.max_depth.unwrap_or(20).min(50);
    let include_types = req.include_types.unwrap_or(false);
    let include_addresses = req.include_addresses.unwrap_or(true);
    let script = decompile_structured_script(addr, max_depth, include_types, include_addresses);

    // Router mode: forward as run_script (same as dsc_add_dylib pattern)
    if let ServerMode::Router(ref router) = self.mode {
        return self
            .route_or_err(router, req.db_handle.as_deref(),
                "run_script", json!({"code": script, "timeout_secs": 120}))
            .await;
    }

    // Local mode: execute directly
    match self.worker.run_script(&script, Some(120)).await {
        Ok(result) => {
            if !run_script_succeeded(&result) {
                let message = run_script_failure_message(&result);
                return Ok(ToolError::IdaError(message).to_tool_result());
            }
            let stdout = run_script_field(&result, "stdout").unwrap_or("{}");
            match serde_json::from_str::<Value>(stdout) {
                Ok(parsed) => {
                    if parsed.get("error").is_some() {
                        return Ok(ToolError::IdaError(
                            parsed["error"].as_str().unwrap_or("unknown").to_string()
                        ).to_tool_result());
                    }
                    Ok(CallToolResult::success(vec![Content::text(
                        serde_json::to_string_pretty(&parsed).unwrap_or_default(),
                    )]))
                }
                Err(_) => Ok(CallToolResult::success(vec![Content::text(stdout)])),
            }
        }
        Err(ToolError::Timeout(secs)) => {
            Ok(ToolError::IdaError(format!("decompile_structured timed out after {}s", secs)).to_tool_result())
        }
        Err(e) => Ok(e.to_tool_result()),
    }
}
```

##### (D) `src/tool_registry.rs` — 注册 tool 元数据

在 `pseudocode_at` ToolInfo 之后添加：

```rust
ToolInfo {
    name: "decompile_structured",
    category: ToolCategory::Decompile,
    short_desc: "Decompile function to structured AST (ctree JSON)",
    full_desc: "Decompile a function and return the Hex-Rays ctree as structured JSON. \
                Each node has an 'op' field (if/while/call/asg/add/var/num/...) with \
                recursive children. Includes local variables with types and function signature. \
                Useful for programmatic analysis rather than reading pseudocode text.",
    example: r#"{"address": "0x1000", "max_depth": 20, "include_types": true}"#,
    default: false,
    keywords: &["decompile", "structured", "ast", "ctree", "json", "hex-rays", "tree"],
},
```

在 `tool_schema()` 函数的 match 中添加：
```rust
"decompile_structured" => Some(schema::<DecompileStructuredRequest>()),
```

#### 2.1.3 Files NOT Modified

| File | Reason |
|------|--------|
| `src/router/mod.rs` | Router 转发走 `run_script`，不需要新路由 |
| `src/router/protocol.rs` | 同上 |
| `src/ida/handlers/script.rs` | 复用现有 `run_script` 基础设施 |
| `src/ida/mod.rs` | 不新增 handler 模块 |
| `Cargo.toml` | 无新依赖 |

#### 2.1.4 Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Python 脚本存储位置 | Rust `const &str` 常量 | 参照 `dsc_add_dylib_script()`，不依赖外部文件 |
| Router 模式转发 | 转发为 `run_script` | 参照 `dsc_add_dylib` 的 `route_or_err` 模式 |
| 深度限制 | `max_depth` 参数，默认 20，上限 50 | 防止大函数输出过大 |
| 类型信息 | `include_types` 可选，默认关 | 类型信息增加 ~30% 输出量，按需开启 |
| handler 文件 | 放入 `disasm.rs` | 现有 decompile/pseudocode_at handler 就在此文件 |
| 错误处理 | Python 侧输出 `{"error": "..."}` → Rust 侧检测 | 统一错误路径，与 `dsc_add_dylib` 一致 |
| 超时 | 固定 120 秒 | 大函数反编译 + ctree 遍历可能较慢 |

#### 2.1.5 Output Example (Verified)

对 `metis-binary` 中 `sub_100015A98` (Rust Arc drop logic) 的实测输出（截取）：

```json
{
  "function": "sub_100015A98",
  "address": "0x100015a98",
  "return_type": "__int64",
  "num_args": 1,
  "lvars": [
    {"idx": 0, "name": "a1", "type": "__int64", "is_arg": true},
    {"idx": 3, "name": "v3", "type": "atomic_ullong *", "is_arg": false},
    {"idx": 4, "name": "result", "type": "__int64", "is_arg": false}
  ],
  "body": {
    "op": "block",
    "ea": "0x100015aac",
    "stmts": [
      {
        "op": "expr", "ea": "0x100015aac",
        "expr": {
          "op": "asg",
          "x": {"op": "var", "var_idx": 3},
          "y": {"op": "ptr", "x": {"op": "cast", "x": {"op": "add", "x": {"op": "var", "var_idx": 0}, "y": {"op": "num", "value": 48}}, "cast_type": "atomic_ullong **"}}
        }
      },
      {
        "op": "if", "ea": "0x100015abc",
        "cond": {"op": "eq", "x": {"op": "call", "target": {"op": "helper"}, "args": [{"op": "var", "var_idx": 3}, {"op": "num", "value": 18446744073709551615}, {"op": "num", "value": 3}]}, "y": {"op": "num", "value": 1}},
        "then": {"op": "block", "stmts": [
          {"op": "expr", "expr": {"op": "call", "target": {"op": "obj", "name": "__ZN5alloc4sync16Arc$LT$T$C$A$GT$9drop_slow17h87973252af192533E", "obj_ea": "0x1000193f8"}, "args": [{"op": "var", "var_idx": 2}]}}
        ]}
      },
      {"op": "return", "value": {"op": "var", "var_idx": 4}}
    ]
  }
}
```

#### 2.1.6 Effort Estimate

| Step | Time |
|------|------|
| `requests.rs` 添加结构体 | 5 min |
| `disasm.rs` 添加 Python 脚本常量 + 生成函数 | 20 min |
| `server/mod.rs` 添加 tool handler | 15 min |
| `tool_registry.rs` 注册 | 5 min |
| 测试验证 | 15 min |
| **Total** | **~1 hour** |

### 2.2 batch_decompile (P1)

Batch decompile multiple functions in one call.

| Field | Value |
|-------|-------|
| **Tool name** | `batch_decompile` |
| **Implementation** | Loop over existing `worker.decompile()` |
| **Input** | `addresses` (addr array), `db_handle` (optional) |
| **Output** | `[{ address, code?, error? }, ...]` |

### 2.3 search_pseudocode (P1)

Regex search across decompiled pseudocode.

| Field | Value |
|-------|-------|
| **Tool name** | `search_pseudocode` |
| **Implementation** | Iterate function list → decompile → regex match |
| **Input** | `pattern` (regex), `limit`, `offset`, `timeout_secs`, `db_handle` |
| **Output** | `[{ function_name, address, matched_lines }, ...]` |

### 2.4 table_scan (P1)

Scan memory as a table of fixed-stride entries.

| Field | Value |
|-------|-------|
| **Tool name** | `table_scan` |
| **Implementation** | Read memory with `worker.get_bytes` at stride intervals |
| **Input** | `base_address`, `stride`, `count`, `entry_format` (optional), `db_handle` |
| **Output** | `[{ index, address, raw_bytes, values }, ...]` |

### 2.5 diff_functions (P2)

Diff two functions' decompiled pseudocode.

| Field | Value |
|-------|-------|
| **Tool name** | `diff_functions` |
| **Implementation** | Decompile both → text diff |
| **Input** | `addr1`, `addr2`, `db_handle` |
| **Output** | `{ function1, function2, diff_lines, similarity_ratio }` |

### Files Changed (Phase 2)

All 5 tools modify the same set of files:

| File | Change |
|------|--------|
| `src/server/mod.rs` | New `#[tool]` methods in `#[tool_router] impl IdaMcpServer` |
| `src/server/requests.rs` | New Request structs with `db_handle` and schemars |
| `src/tool_registry.rs` | Register new tools with category/keywords |
| `docs/TOOLS.md` | Document new tools |
