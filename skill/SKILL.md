---
name: ida
description: "IDA Pro reverse engineering and binary analysis. Use when writing IDAPython scripts, using IDA Domain API or idalib, analyzing binaries with IDA Pro (disassembly, decompilation, cross-references, type reconstruction, byte patching). Covers headless/batch analysis via idalib and idapro module, Hex-Rays decompiler, struct/enum creation, FLIRT signatures, and plugin development. Includes CLI tool (ida-cli) for direct Unix socket access without MCP protocol. Supports PE, ELF, Mach-O, and firmware binaries. Triggers: 'IDA Pro', 'IDAPython', 'IDA script', 'ida-domain', 'Hex-Rays', 'decompile with IDA', 'IDA analysis', 'idat', 'idalib', 'idapro', 'headless IDA', 'idapython script', 'IDA plugin', 'FLIRT signatures', 'IDA type library', 'ida_bytes', 'ida_funcs', 'ida_hexrays', 'reverse engineer binary', 'analyze PE', 'analyze ELF', 'IDA batch', 'IDA headless', 'open_database', 'idalib.hpp', 'ida-cli', 'ida cli'."
---

# IDA Pro Reverse Engineering

通用逆向工程方法论 + MCP 工具链 + Headless API。

---

## Part 1: 通用逆向方法论

### Key Principles

- **F5 first, disasm second (HARD RULE)** — MUST call `decompile` before `disasm` for any function analysis. Only fall back to `disasm` when decompile explicitly fails/errors or returns obvious artifacts. NEVER skip decompile and go straight to disasm for "convenience" or "safety".
- **Rename-as-you-go (HARD RULE)** — 每 decompile 一个函数，理解其功能后 **必须立即 `rename_symbol`**，不允许「先全部分析完再统一命名」。未命名的 `sub_XXXXX` 是技术债，会导致 caller 的伪代码不可读。`build_callgraph` 找叶子 → 自底向上 decompile → 每理解一个函数**立即 `rename_symbol`** → 重新 decompile caller。
- **迭代循环** — F5→标注类型→rename→再 F5→发现新偏移→验证 struct→又 F5… 复合效应
- **Constants are literal** — IDA 里看到 `0x6E` 就写 `110`，不解读物理含义
- **disasm when decompile disagrees** — diff 在 1-10 时切到 disasm 逐指令核对
- **Analysis log (HARD RULE)** — 逆向分析过程中 **必须维护分析日志**。每完成一个函数的逆向（decompile + rename + 理解功能），立即追加一条日志记录。分析结束时（`close_idb` 前）输出完整日志摘要。日志格式和规则见下方「分析日志规范」。

### 1. 反编译策略

**降级到 disasm 的条件：** F5 报错/超时（>5000 条指令）；伪代码有明显 artifact。

**Decompiler 四大谎言：**

| 谎言 | 伪代码表现 | 实际指令 |
|------|-----------|---------|
| **常量折叠** | `result = x * 1718750 / 1000000` | `MUL X8, X8, #110; UDIV X8, X8, #64` |
| **丢失 +1/-1** | `discount = bias * 110 / 64` | 除法后还有 `ADD X8, X8, #1` |
| **类型混淆** | `int v10 = *(int *)(ctx + 0x1DC)` | `LDR W8, [X0, #0x1DC]`（实际 u32） |
| **隐藏饱和运算** | `result = a - b` | `SUBS X8, X9, X10; CSEL X8, XZR, X8, LO` |

**伪代码质量迭代：**
```
初始 F5 → sub_XXXXX(v42, v38)
  ↓ rename_symbol 叶子
二次 F5 → parse_header(v42, v38)
  ↓ apply_type
三次 F5 → parse_header(ctx, buf)
  ↓ declare_c_type + rename_local_variable
最终 F5 → ctx->msg_type 可读
```

### 2. 命名与标注

**时机**：理解即命名，不要攒到最后。

**命名规范：**

| 前缀 | 含义 | 示例 |
|------|------|------|
| `check_`/`validate_` | 校验 | `check_permissions` |
| `parse_`/`deserialize_` | 反序列化 | `parse_config` |
| `compute_`/`calc_` | 计算 | `compute_checksum` |
| `dispatch_` | 分发入口 | `dispatch_command` |
| `init_`/`setup_` | 初始化 | `init_context` |

**复合效应**：rename callee 后，**重新 decompile caller** — 伪代码立即更新。

**跨会话持久化**：所有标注保存在 `.i64`。恢复分析时 `open_idb("<file>.i64")`，不是原始二进制。

### 2.5 分析日志规范 (HARD RULE)

**逆向过程中必须边分析边记录。** 这不是可选项——没有日志的逆向等于没做。

#### 何时记录

| 触发事件 | 必须记录 |
|---------|---------|
| rename 一个函数 | ✅ 函数地址、旧名 → 新名、功能摘要 |
| 发现关键结构体 | ✅ struct 名、字段布局、用途 |
| 识别算术公式 | ✅ 公式表达式、涉及的常量、验证状态 |
| 发现错误码映射 | ✅ error code → 含义 |
| 识别 dispatch/selector | ✅ selector 值 → handler 地址 → 功能 |
| 完成一个分析阶段 | ✅ 阶段总结 |

#### 日志格式

```
## Analysis Log: <binary_name>

### Functions Reversed

| # | Address | Old Name | New Name | Purpose |
|---|---------|----------|----------|---------|
| 1 | 0x1234 | sub_1234 | parse_header | 从输入 buffer 解析消息头 |
| 2 | 0x5678 | sub_5678 | compute_checksum | CRC32 校验: crc = update(crc, data, len) |

### Structs Identified

| Struct | Size | Key Fields | Used By |
|--------|------|-----------|---------|
| MsgHeader | 0x40 | +0x00: magic (u32), +0x04: msg_type (u16), +0x08: payload_len (u32) | parse_header, dispatch_command |

### Key Findings

- Dispatch: tag byte at msg_type field, 0x01=init, 0x02=query, 0x03=update
- Error 0x1770: InvalidInput (length == 0)
- Checksum computed over payload only, header excluded

### Open Questions

- sub_9ABC: 被 compute_checksum 调用，疑似 lookup table init，待确认
```

#### 规则

1. **实时记录** — rename 之后立即追加日志条目，不要等分析完再回忆
2. **每个 rename 必须有 Purpose** — 一句话说明函数做什么，不是重复函数名
3. **公式必须写出** — 识别到的算术公式用数学表达式记录，标注验证状态（✅ verified / ⚠️ unverified）
4. **Open Questions 必须列出** — 未完全理解的函数/逻辑记录在此，不要假装全懂
5. **分析结束时输出** — `close_idb` 前，输出完整分析日志作为本次逆向的交付物

### 3. 结构体逆向

从 F5 的 `*(ptr + 0xNNN)` 模式重建结构体。

**LDR → 字段类型（ARM64）：**
```
LDR X8, [X0, #0x130]     → u64  (64-bit, X register)
LDR W8, [X0, #0x144]     → u32  (32-bit, W register)
LDRH W8, [X0, #0x168]    → u16
LDRB W8, [X0, #0x178]    → u8
LDP X8, X9, [X0, #0x130] → 两个 u64
```

> decompile 可能把 `LDR W8` 显示为 `int`（signed），实际是 u32。必须 disasm 确认。

**增量验证循环：**
```
1. decompile → 收集所有 ptr+offset 模式
2. disasm → 指令宽度确认字段类型
3. read_dword/read_qword → 读实际值 + 语义交叉验证
4. declare_c_type → 定义 struct
5. apply_type → 应用到参数
6. 重新 decompile → *(ptr+0x1DC) 变成 obj->field_name
7. get_xrefs_to_struct_field → 找所有访问该字段的代码
8. 发现新 offset → 回到步骤 2
```

**数组检测**：连续等间距 load → `[type; N]`

### 4. 调用图导航

**不要线性读大函数。** Dispatch 函数 10KB+，先 `build_callgraph` 定向。

**Leaf-first 策略：**
```
1. build_callgraph(roots: [entry], max_depth: 3) → 找叶子
2. decompile 每个叶子 → 理解 + 立即 rename
3. decompile 父函数 → sub-call 显示有意义名字
4. 向上重复直到入口完全可读
```

**反模式**：先 decompile 入口 → 看到 48KB 的 `sub_XXXXX(v42, v38)` 墙 → 完全不可读。

### 5. 搜索定位

**字节搜索注意小端序（arm64/x86 = LE）：**
```
search_bytes(pattern: "6E 00 00 00")       # u32 0x6E (110)，LE
search_bytes(pattern: "80 96 98 00")       # u32 0x989680 (10,000,000)
```

**立即数**：`search_text(kind: "imm", targets: ["110", "10000"])`
**伪代码全文**：`search_pseudocode(pattern: "amount")`
**指令序列**：`search_instructions(patterns: ["MUL", "UDIV"])`

### 6. 公式提取

**翻译规则：**
1. 常量直译 — `0x6E` → `110`
2. 算术顺序严格跟 IDA — `a * 110 / 64 + 1` ≠ `(a * 110 + 64) / 64`
3. u128 精度 — 两个 u64 相乘先 `as u128`
4. 饱和运算 — 用 `saturating_mul`/`saturating_sub`
5. decompile might lie — diff 小时切 disasm

**IDA 伪代码算术模式：**

| 模式 | 含义 |
|------|------|
| `__umulh(a, b)` | u128 乘法高 64 位 |
| `__multi3(a, b)` | 编译器 u128 乘法 |
| `__udivti3(hi, lo, denom)` | u128 除法 |
| `SUBS + CSEL XZR` | saturating_sub |

**收敛方法论：**

| diff 范围 | 典型根因 | 修复策略 |
|-----------|---------|---------|
| > 100 | 错误的 scale 或公式 | 从 IDA 常量重写 |
| 10-100 | 错误的运算符/操作数 | disasm 确认 MUL/DIV/ADD/SUB |
| 1-10 | off-by-one / 饱和运算 | disasm 逐指令对比 |
| 0 | ✅ 精确匹配 | Done |

### 7. decompile_structured 算术链分析

当伪代码翻译后 diff > 0，手动对比效率低时：

```
1. decompile_structured(address: <func>, max_depth: 20, include_types: true)
   → JSON AST

2. 遍历 AST 找算术子树：
   op: "mul"/"div"/"add"/"sub" → 核心算术
   op: "call" → __umulh / __udivti3 等 u128 操作
   op: "num" → 常量值（直接翻译）
   op: "var" → 变量引用

3. 从 AST 直接生成代码表达式，避免人工翻译错误
4. 与 disasm 交叉验证算术链的完整性
```

**适用场景：** 复杂多步公式（5+步）、diff 反复非零、需要对比多个函数的公式。

---

## Part 2: MCP 工具速查

IDA MCP 服务器提供 73 个工具。高频工具参数和动态发现方法 → [mcp-tool-reference.md](references/mcp-tool-reference.md)

---

## Part 2.5: CLI 直接调用（非 MCP）

`ida-cli`（`~/.local/bin/ida-cli`）— 通过 Unix Socket 直连运行中的 ida-cli server，无需 MCP 协议。适用于脚本、自动化、pipe 组合。

### 零配置

Server 自动管理——首次 CLI 调用时自动启动，后续复用。无需手动 `serve-http &`。

### 命令发现

```bash
ida-cli --help                        # 列出全部子命令
ida-cli rename-symbol --help          # 查看具体命令参数
```

### 高频示例

```bash
# --path 必传，自动 spawn worker + 打开文件
ida-cli --path <file> list-functions --limit 20
ida-cli --path <file> get-function-by-name --name main
ida-cli --path <file> decompile-function --address 0x1234
ida-cli --path <file> disassemble-function --name func_name --count 20
ida-cli --path <file> rename-symbol --address 0x1234 --new-name parse_pool
ida-cli --path <file> get-callees --address 0x1234
ida-cli --path <file> build-callgraph --roots 0x1234 --max-depth 3
ida-cli --path <file> search-pseudocode --pattern "amount" --limit 10
ida-cli --path <file> get-xrefs-to --address 0x1234
ida-cli --path <file> batch-decompile --addresses "0x1234,0x5678"

# 输出格式
ida-cli --json --path <file> list-functions --limit 5     # pretty JSON
ida-cli --compact --path <file> list-functions --limit 5   # 单行 JSON

# Server 管理（无需 --path）
ida-cli server-start                  # 手动启动（一般不需要，自动管理）
ida-cli server-status                 # 运行状态
ida-cli server-stop                   # 停止
ida-cli server-logs                   # tail -f 日志

# IDB 缓存管理
ida-cli idb-list                      # 列出所有缓存的 IDB
ida-cli idb-info --hash <hash>        # 查看详情
ida-cli idb-remove --hash <hash>      # 删除缓存（同时删除所有相关文件 .i64/.id0/.id1/.nam/.til/.imcp）

# Raw JSON-RPC（任意方法）
ida-cli raw '{"method":"list_functions","params":{"path":"<file>","limit":5}}'

# Pipe 模式（多命令流水线）
echo '{"method":"status"}
{"method":"decompile_function","params":{"path":"<file>","address":"0x1234"}}' | ida-cli --json pipe
```

### 支持的文件类型

| 类型 | 示例 | 行为 |
|------|------|------|
| `.i64` / `.idb` | `target.i64` | 直接打开 IDA 数据库 |
| 原始二进制 | Mach-O / ELF / PE | IDA 自动分析 |

### 并发安全

**多文件并发**：每个文件独立 worker 进程，互不影响：

```bash
ida-cli --path binary_a.elf list-functions --limit 5 &
ida-cli --path binary_b.elf list-functions --limit 5 &
wait  # 并行打开 + 查询
ida-cli server-status   # worker_count: 2
ida-cli --path binary_a.elf close  # 只关 A，B 不受影响
```

**同文件多客户端并发**：多个 CLI 可同时操作同一个程序。worker 内部串行执行，router 通过 request ID 匹配响应，不会串台：

```bash
# 同时执行 3 个 rename —— 全部成功
ida-cli raw '{"method":"rename_symbol","params":{"path":"target.elf","current_name":"sub_1000","name":"main_loop","flags":0}}' &
ida-cli raw '{"method":"rename_symbol","params":{"path":"target.elf","current_name":"sub_2000","name":"parse_input","flags":0}}' &
ida-cli raw '{"method":"rename_symbol","params":{"path":"target.elf","current_name":"sub_3000","name":"handle_request","flags":0}}' &
wait

# 读写混合也安全：rename + decompile + disasm 同时发
ida-cli raw '{"method":"rename_symbol","params":{"path":"target.elf","current_name":"sub_4000","name":"send_response","flags":0}}' &
ida-cli --path target.elf decompile-function --address 0x5e8 &
ida-cli --path target.elf disassemble-function-at --address 0x700 --count 10 &
wait
```

**自动启动防竞态**：多个 CLI 同时冷启动时，文件锁保证只启动 1 个 server，其余等待就绪后复用。

### Server 故障恢复

CLI 请求超时或返回连接错误时，server 可能卡死。处理步骤：

```bash
# 1. 先尝试正常 shutdown
ida-cli server-stop

# 2. 如果 shutdown 也卡住（5s 无响应），强杀
pkill -9 -f "ida-cli"
rm -f ~/.ida/server.sock ~/.ida/server.pid ~/.ida/startup.lock

# 3. 下次 CLI 调用自动重新启动 server
ida-cli --path <file> list-functions --limit 5
```

**日志排查**：`ida-cli server-logs` 或 `cat ~/.ida/logs/server.log`。

---

## Part 3: 通用 Workflow

### Workflow 1: Binary Orientation（首次打开，30 秒）

```
1. get_database_info()                                    → arch, file type, functions
2. list_segments()                                        → code/data/rodata layout
3. list_exports()                                         → 找入口
4. list_imports()                                         → 导入符号/API
5. list_functions(limit: 50)                              → first batch
6. build_callgraph(roots: [entry_addr], max_depth: 2)     → top-level structure
```

### Workflow 2: Struct Reconstruction

```
1. decompile → 收集所有 ptr+offset 模式
2. disasm → 确认字段类型（LDR W vs X / MOV 宽度）
3. read_dword/read_qword → 读实际值，交叉验证语义
4. declare_c_type(decl: "struct Foo { ... }")
5. apply_type(addr: param, decl: "Foo *")
6. get_xrefs_to_struct_field(name: "Foo", member_name: "bar")
7. 重新 decompile → ptr+offset 变成 obj->field_name
```

### Workflow 3: Arithmetic Chain Verification

```
1. decompile_function(addr: func)                         → high-level formula
2. get_pseudocode_at(addr: suspicious_line)               → zoom in
3. disassemble_function_at(addr: func)                    → full disasm
4. search_instructions(patterns: ["MUL", "UDIV"])         → arithmetic ops
5. search_instruction_operands(patterns: ["#0x6E"])       → constant usage
6. 逐指令验证：operand width, saturation, order
7. convert_number(inputs: ["0x989680"])                   → verify constants
```

### Workflow 4: Error Code Mapping

```
1. search_text(kind: "imm", targets: ["0x0F00000000"])  → error constant loads
2. get_function_at_address(address: match) → 所属函数
3. get_pseudocode_at(address: match) → 条件上下文
4. set_comment(address: match, comment: "Error: InvalidAmount")
5. search_pseudocode(pattern: "return 0x") → 所有错误返回点
6. 复杂场景 → run_script 批量提取
```

### Workflow 5: Factory/Dispatch Table Analysis

```
1. list_strings(query: "factory") / list_strings(query: "registry")
2. get_xrefs_to_string → 谁构建/读取这个表
3. decompile table builder → 找 table base address
4. scan_memory_table(base: addr, stride: 24, count: 50) → 读取 entries
5. 每个 fn_ptr → get_address_info → decompile → handler 逻辑
```

### Workflow 6: Multi-Database Concurrent Analysis

```
1. Orchestrator: open_idb → db_handle + close_token（每个 IDB 独立 worker 进程）
2. Share db_handle with concurrent agents
3. Read ops (decompile, xrefs, callees) → 安全并行
   Write ops (rename_symbol, apply_type) → 串行避免冲突
4. 用 batch_decompile 减少往返
5. 完成后: close_idb(close_token)

支持同时调试：
6. 每个 IDB 可独立 dbg_load_debugger + dbg_start_process（各自的 debug server + 端口）
7. 所有 dbg_* 工具通过 db_handle 路由到对应 IDB 的调试会话
8. 两个调试会话完全隔离：断点、寄存器、内存、执行控制互不影响
9. 调试期间可对任意 IDB 执行反编译/反汇编（使用 rebase 后的地址）
```

### Workflow 7: Batch Annotation

```
1. batch_rename(renames: [
     {"address": "0x1000", "name": "parse_header"},
     {"address": "0x2000", "name": "dispatch_command"},
     {"address": "0x3000", "name": "handle_request"}
   ])                                               → 批量重命名，返回每条成功/失败

2. set_function_prototype(address: "0x1000",
     prototype: "int64_t __fastcall parse_header(MsgHeader *hdr)")
                                                   → 设置函数原型

3. set_function_comment(address: "0x1000",
     comment: "Parses message header from input buffer")
                                                   → 设置函数注释

4. rename_stack_variable(func_address: "0x2000",
     var_name: "v1", new_name: "cmd_type")         → 重命名栈变量

5. set_stack_variable_type(func_address: "0x2000",
     var_name: "cmd_type", type_str: "uint32_t")   → 设置栈变量类型

6. create_enum(decl: "enum ErrorCode { InvalidInput = 0, BufferOverflow = 1 };")
                                                   → 创建错误码枚举

7. batch_decompile(addresses: ["0x1000", "0x2000", "0x3000"])
                                                   → 验证所有标注已生效
```

### Workflow 8: Dynamic Debugging

#### 8a: start_process（控制目标进程生命周期）

```
1. open_idb(path: "target.i64")                           → db_handle
2. dbg_load_debugger(debugger: "mac", is_remote: true)    → 加载远程调试器
3. dbg_start_process(path: "/path/to/target", args: "", timeout: 30)
   → 启动进程并自动附加，返回 pid + ip
4. dbg_add_breakpoint(address: "0x<main_addr>")           → IDB 地址，IDA 自动 rebase
5. dbg_continue(timeout: 10)                              → 运行到断点
   → event_code=5 (BREAKPOINT)
6. dbg_get_registers()                                    → 检查寄存器状态
7. decompile_function(address: "<rebased_ip>")            → 调试期间反编译正常工作
8. dbg_step_into / dbg_step_over / dbg_run_to             → 执行控制
9. dbg_read_memory(address: "<addr>", size: 64)           → 读运行时内存
10. dbg_exit_process(timeout: 10)                         → 终止进程 + 清理 debug server
```

#### 8b: attach_process（附加到已运行进程）

```
1. 外部启动目标进程（或 HostDebugRunner）                 → 获取 PID
2. open_idb(path: "target.i64")
3. dbg_load_debugger(debugger: "mac", is_remote: true)
4. dbg_attach_process(pid: <PID>, timeout: 15)            → 附加
5. dbg_add_breakpoint / dbg_continue / ...                → 正常调试
6. dbg_detach_process(timeout: 10)                        → 分离，进程继续运行
```

#### 调试期间的分析能力

调试期间（进程挂起状态）以下操作全部可用：
- `decompile_function` / `decompile_structured` — 反编译 ✅
- `disassemble_function` / `disassemble_function_at` — 反汇编 ✅
- `list_functions` / `get_function_by_name` — 函数查询 ✅
- `get_xrefs_to` / `get_xrefs_from` — 交叉引用 ✅
- `rename_symbol` / `set_comment` — 标注 ✅

**注意**：使用按地址操作的工具时，需使用 rebase 后的运行时地址。

---

## Part 4: 错误恢复

### decompile 失败

```
→ get_pseudocode_at(address, end_address)   — 只看关键代码段
→ disassemble_function_at(address)          — 降级到反汇编
→ build_callgraph 找子函数 → 分别 decompile — 拆分分析
```

### get_analysis_status 返回 auto_is_ok=false

```
→ run_auto_analysis(timeout_secs: 120)   — 强制等待分析完成
→ 或重复调用 get_analysis_status 直到 auto_is_ok=true
→ 重要：xrefs/decompile 在分析完成前可能返回不完整结果！
```

### 工具超时

```
→ run_script 默认 120s，最大 600s：run_script(code: "...", timeout_secs: 300)
→ batch_decompile 对大型数据库可能较慢，分批处理
```

### Common Pitfalls

1. **先 decompile 根函数** → 48KB `sub_XXXXX` 墙 → 用 build_callgraph + leaf-first
2. **rename 后没重新 decompile caller** → caller 伪代码仍显示旧名
3. **信任 decompile 的精确算术** → diff 非零时必须 disasm 验证
4. **search_bytes 不考虑端序** → arm64/x86 是 LE，`0x6E` 搜 `6E 00 00 00`
5. **忽略 get_xrefs_to 结果数量** → 高频 helper 有 50+ xrefs，结合 build_callgraph 过滤
6. **不用 read_dword/read_qword 验证 offset** → decompile 显示 int64_t 实际可能是 u32
7. **打开原始二进制而非 .i64 恢复会话** → 所有标注丢失
8. **分析未完成就查询** → `get_analysis_status` 确认 `auto_is_ok=true`

---

## Part 5: Headless API

IDA Domain API (`pip install ida-domain`) + idalib + idapro headless 执行 → [headless-api.md](references/headless-api.md)

---

## Reference Files

> ⚠️ **按需加载，不要全读。** Reference 文件每个 96-727 行。**只读匹配当前任务的那一个**。大多数 MCP 逆向任务只需要 `mcp-tool-reference.md`。

| File | Lines | When to Load | NOT needed for |
|------|-------|-------------|----------------|
| [mcp-tool-reference.md](references/mcp-tool-reference.md) | 300 | **MCP 工具参数不确定时**（高频，默认首选） | — |
| [counterfactual-patch.md](references/counterfactual-patch.md) | 96 | 反事实 Patching 方法论 | 纯静态分析 |
| [headless-api.md](references/headless-api.md) | 124 | IDA Domain API / idapro headless 执行 | MCP 逆向（用不到 headless） |
| [idapython-cheatsheet.md](references/idapython-cheatsheet.md) | 727 | 写 IDAPython 脚本（`run_script`） | MCP 工具已够用时 |
| [ida-domain-api.md](references/ida-domain-api.md) | 680 | IDA Domain API 全量参考（Python headless） | MCP 逆向 |
| [idalib-headless.md](references/idalib-headless.md) | 385 | idalib C++ / idapro 模块 batch 分析 | MCP 逆向 |
| [binary-analysis-patterns.md](references/binary-analysis-patterns.md) | 312 | 恶意软件分析、漏洞挖掘、固件 RE | 简单静态分析 |
| [plugin-development.md](references/plugin-development.md) | 564 | IDA 插件开发 | 逆向分析任务 |
