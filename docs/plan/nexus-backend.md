# Nexus 唯一后端迁移与长任务治理计划

状态：在独立 worktree `../ida-cli-nexus`、分支 `feat/nexus-backend` 执行。N0 环境阶段已验收；N1 经 N1-F1 修复后，已在 `9148fba526bf403b9448b50131a3edc145c2229a` 完成编排者独立复验和原 reviewer 复审，纯契约阶段门禁通过。N2 经 F1–F5 修复后，已在 `a1cc1e527e237949e70c3c4b5b333a9f3478260a` 完成编排者独立复验和原 reviewer 复审，协议/模拟及真实 OS fixture 范围的门禁通过。N3 经 F1–F2 修复后，已在 `86a35fa68749eb20f12856c92e20f9ca3b391449` 完成编排者独立复验和原 reviewer 复审，常驻 bridge 与生命周期的真实 IDA E2E（E02 bridge 部分、E03、E05、E06、E07）通过。N4 经 F1–F3 修复后，已在 `b650ac0aa657cbe10e722f9c2551a6442721a04f` 完成编排者独立复验和原 reviewer 复审，首批工具在开发选择入口下经 Nexus 执行，E04、E16、E17、E22 真实 IDA E2E 通过，形成首个可用里程碑，后续按 N5 推进。本文不表示整个后端迁移或全部真实链路 E2E 已完成。

日期：2026-10-15。

执行约束：开发步骤必须委托给 Codex GPT-6.1 Sol，推理档位 `xhigh`；开发开始前必须新建 Git worktree 和分支。用户输入的 `xhign` 在本文统一为工具实际支持的 `xhigh`。

## 1. 目标与验收范围

用户已确认最终目标：Nexus 是 ida-cli 唯一的数据库管理与执行后端，统一承担数据库发现、GUI/headless 共享、客户端 lease、断线回收、操作执行和崩溃恢复。

保留现有 flat CLI、stdio MCP、Streamable HTTP MCP、结构化 JSON、调度、预热、内容寻址缓存和 sBPF/DSC 工作流。新后端承担完整的数据库操作执行，不能仅替换 `open/close`。

迁移过程和最终交付必须区分：

| 时期 | 旧实现的用途 | 完成条件 |
|---|---|---|
| 开发迁移期 | 暂时保留 `native-linked`、`idat-compat` 作为功能对照，必要的选择入口仅用于开发验证 | Nexus 覆盖全部承诺能力，完整功能 E2E 通过 |
| 收敛阶段 | 删除旧执行路径、运行时后端选择逻辑及旧后端专属依赖，再用清理后的产物复验 | 唯一 Nexus 路径的最终 E2E 和清理验收通过 |
| 最终交付 | 正常启动直接使用 Nexus，不再提供长期多后端配置或 legacy fallback | 安装、启动、工具调用、状态和错误均符合唯一后端契约 |
| 版本回退 | 使用已验证的旧发布产物、匹配运行时和迁移前数据库备份 | 独立完成版本级回退演练，不在新版本内切回旧后端 |

旧实现只在迁移期存在，不能以“方便回退”为理由留在最终运行路径中。真实用户环境的安装、重启和版本回退仍需用户授权；新开发分支完成唯一后端收敛本身属于本计划开发范围。

本文的 native 调用指 IDA/Hex-Rays 底层调用，与待删除的 `native-linked` 后端是两回事。sBPF/DSC 离线产物准备仍可使用必要的 sbx/idat；准备结束后的数据库会话、查询和编辑统一经 Nexus 执行。

本次开发还必须处理长任务对服务响应的影响：

1. 一个数据库执行长任务时，router 状态、任务状态和其他数据库仍可响应。
2. 可拆分的批量操作在批次间释放数据库执行权，让短查询能够插入。
3. 超时覆盖排队和执行；取消必须传递到真实操作，不能只停止 Rust 侧等待。
4. 对不可立即中断的 native 调用，准确报告仍在执行、取消待确认或结果未知，不能提前宣称已停止。
5. 不以强杀共享 Nexus worker 或 GUI 作为普通取消手段。

首个可交付里程碑：在新 worktree 中，通过真实 CLI 打通打开、函数查询、反编译、关闭、状态和取消，并证明 A 库长任务不阻塞 B 库及 router 控制请求。

完整交付要求：本文所有必需 E2E 门禁通过，相关高级工具、写入、GUI、sBPF、DSC 完成能力验收，并完成旧后端清理和清理后的重新验证。首个里程碑或迁移期双路径验证不能代替完整交付。

## 2. 已确认基线与能力边界

### 2.1 版本和证据

| 项目 | 评估时基线 |
|---|---|
| ida-cli | `52c0e6f6542a3f9053d5b2b97ee7785184a748ff`，本地分支 `p3-attach` |
| Nexus | `0.13.4`，`d60ff582fde90c59726336c0dbdf3e8286e9df7a` |
| IDA Domain | `0.5.1` |
| 真实验证环境 | IDA 9.5、Python 3.14.7、idapro 0.0.10 |
| Nexus 最低要求 | IDA 9.4+、Python 3.11+ |

这些是评估基线，不应在未来执行时不加检查地称为最新版。N0 必须再次记录实际依赖、源码 SHA、IDA 运行时及已构建二进制的版本。

此前隔离验证结果：

- registry、manager、数据库状态共 78 项测试通过。
- 9 项真实生命周期测试通过，覆盖共享、异常退出保存、两种崩溃恢复、分析取消/超时、自定义输出和多数据库保存。
- 另有 8 项并发行为断言通过，确认同库串行、跨库隔离、取消效果、执行预算不含排队，以及人工持 GIL 场景的控制请求限制。

历史证据只用于设计，不替代新实现的重新验收。临时位置可能被系统清理：

- `/tmp/ida-nexus-eval-20261014/evidence/lifecycle-unit.txt`
- `/tmp/ida-nexus-eval-20261014/evidence/lifecycle-e2e.txt`
- `/tmp/ida-nexus-concurrency-20261015.PgUJNv/check_concurrency.py`
- `/tmp/ida-nexus-concurrency-20261015.PgUJNv/result.log`

上述通过结果使用了临时 loopback DNS 绕过：本机 Python HTTPServer 启动时，`socket.getfqdn()` 的反向解析会阻塞。正式接入必须提供可复现、可维护的解决办法，不能依赖 `/tmp` 下的 `sitecustomize.py`，也不能把测试绕过描述成原版直接可用。

### 2.2 Nexus 解决和未解决的问题

| 问题 | 已确认行为 | 对接要求 |
|---|---|---|
| 同一 IDB 的普通操作 | `_run_operation` 和 `_run_sync` 串行加锁，最终 `execute_sync(MFF_WRITE)` 在 IDA 主线程执行 | 不承诺同库多个反编译并行 |
| 启动阶段后台自动分析 | 有分片及前台优先，当前目标为每片最多 256 步或 0.02 秒 | 复用分片机制；单个 native 步骤并无硬 20ms 上限 |
| 显式 `wait_autoanalysis()` | 内部逐步执行、支持取消，但整个请求持有操作锁 | 不能作为所有查询前无条件执行的阻塞屏障 |
| 长脚本或一次 native 反编译 | 不会自动拆片 | 上层拆分可拆任务；单次调用保留准确状态 |
| 控制 HTTP 请求 | 合作式长任务时可响应；native 持 GIL 时可能无法及时响应 | router 控制状态不能依赖同步询问该 worker |
| Nexus 执行 timeout | 从执行阶段开始，不包含前面排队 | router 维护总期限并主动取消 |
| 取消或连接中断 | 可能已经发生数据库修改 | 不承诺事务回滚，不自动重放写请求 |
| `flush_database` | 尽力刷新 unpacked 缓冲，不等于 packed `.i64` 保存 | 明确保存点及崩溃后恢复策略 |

### 2.3 现有实现的改动入口

| 文件 | 现状和用途 |
|---|---|
| `src/ida/loop_impl.rs` | 持有 `Option<idalib::IDB>`，现有 handlers 直接访问数据库 |
| `src/ida/backend.rs` | 目前主要抽象初始化和打开，不能单独承载远程执行迁移 |
| `src/main.rs:912` | worker stdin 循环等待当前 RPC 完成后才读下一条 |
| `src/router/mod.rs:930` | 持全局 `inner` 锁写 worker 管道，有背压扩散风险 |
| `src/router/mod.rs:1311` | async 路径直接执行同步 `resolve_open_path` |
| `src/sbpf.rs:82` | 同步 `Command::output()` 等待 sbx |
| `src/ida/handlers/disasm.rs:131` | `search_pseudocode` 在一次主线程操作内遍历、反编译多个函数 |
| `src/server/task.rs` | 现有取消主要 abort Rust task |
| `src/server/mod.rs:763` | 无 token 关闭路径直接关闭 active worker，需要收紧所有权语义 |
| `src/router/mod.rs:2102`、`src/idb_store.rs` | 当前缓存淘汰主要保护本 daemon warm pool |
| `src/ida/runtime.rs`、`src/ida/capabilities.rs` | 后端选择、支持能力声明 |
| `src/idat_compat.rs` | 可参考已有 Python 操作语义；不得直接保留其另起 idat 打开同库的方式 |
| `tests/ida_e2e.rs` | 现有真实 IDA 测试共享单个 worker 并串行加锁，不足以证明新后端的多客户端行为 |

行号对应评估 SHA；执行时以符号和实际源码为准。上述路径证明存在阻塞机制，尚不能据此判定用户历史上某一次慢调用的唯一原因。

## 3. 委托模型、角色和权限

### 3.1 固定执行配置

2026-10-15 已通过 Paseo `list_profiles`、`list_models` 和 `inspect_provider` 核对：

| 字段 | 本任务配置 |
|---|---|
| 展示名称 | Codex GPT-6.1 Sol |
| 委托 worker provider | `codex-worker` |
| model | `gpt-6.1-sol` |
| `create_agent.provider` | `codex-worker/gpt-6.1-sol` |
| `settings.modeId` | `full-access` |
| `settings.thinkingOptionId` | `xhigh` |
| `notifyOnFinish` | `true` |
| `workspaceId` | 同仓库默认省略；真实工作目录写入委托单 |
| 额外 features | 默认不设置，不从其他任务复制 |

开发、测试、修复以及本文规定的独立审查均使用这组模型配置，职责通过委托单区分。执行前再次发现 provider/model，缺失时报告阻塞，不静默换模型或推理档位。

创建本计划时，`sol-dev` profile 的配置与本任务不匹配，且其角色卡面向 Solana 套利仓库；后续 profile 可能变化，每次委托均重新发现并核对。本任务按用户已确认的上述固定配置执行，不修改全局 profile、schedule 或 daemon 配置，不把其他仓库的生产流程强加到 ida-cli。`full-access` 不是部署、推送或操作真实数据库的授权。

### 3.2 编排者和 worker 分工

- 编排者：用户明确授权的交互主 agent；负责创建 worktree、派单、核对阶段依赖、独立验收、处理冲突和决定是否进入下一阶段。
- 实现 worker：修改被指派文件并运行对应验证；不能创建其他 agent、改定时任务、控制其他会话或自行扩大任务。
- 审查 worker：新会话，只读审查指定 SHA 的 diff 和证据，输出缺陷及复现依据；修复另派实现任务。
- 编排默认串行。同一 worktree 同时只能有一个写入者；审查期间冻结该 worktree 的源码和 HEAD。
- 如后续需要并行，编排者为每个写入任务另建 worktree/分支，并指定互不重叠的文件所有权。不能让多个实现 worker 并发修改共享目录。
- 不调用 `create_workspace` 为每阶段自动复制工作区。只在跨仓库任务确实需要时显式指定其他 workspace。
- 未完成验收不得进入下一阶段；被阻塞 worker 输出原因、证据和需要的授权，不自行拉人。

所有派单记录应包含 agent ID、实际模型/档位、worktree、输入 SHA、产出 SHA、测试结果和证据目录。

### 3.3 每次委托的角色前言

编排者应将以下前言原样放在 `initialPrompt` 开头，再接七字段委托单。该前言适用于本文的 ida-cli 实现任务。

> 你是 ida-cli Nexus 接入项目的被委托实现 worker。使用 Codex GPT-6.1 Sol，推理档位 xhigh。先进入委托单指定的独立 worktree，核对实际路径、分支和基线 SHA。只处理本阶段范围，不修改原始工作区、其他 worktree、用户已有 daemon、全局安装和真实研究数据库。不创建或指挥其他 agent，不修改调度和 daemon 配置。涉及 Rust 时读取 rust-skills，涉及 IDA/Nexus 时读取适用 IDA 技能和官方接口资料。所有编译、检查、测试必须有 shell timeout；超出 30 秒须先写明理由和上限。使用独立测试目录、IDA_CLI_HOME、IDA_NEXUS_STATE_DIR 和测试样本副本。测试中保留有意义的断言，不得用跳过、吞错或删功能换取通过。完成后输出本地提交 SHA、变更摘要、验证命令及退出码、证据位置、限制和剩余问题。不得 push、部署、替换已安装程序或关闭其他客户端的数据库。遇到阻塞如实产出，不自行扩大授权。

审查任务使用独立前言：

> 你是 ida-cli Nexus 接入项目的只读审查 worker。使用 Codex GPT-6.1 Sol，推理档位 xhigh。核对委托单指定的 worktree 和提交 SHA，只读审查 diff、源码和验证证据，不改文件、不提交、不启动或停止其他人的进程，不创建其他 agent。优先检查数据库所有权、取消/期限、IPC 背压、共享缓存和结果兼容性。按严重程度报告问题，给出位置、触发条件和依据；没有发现问题时说明审查范围与未验证部分。

七字段委托单必须填写具体值，不能只贴“执行 N3”：

1. **目标**：本阶段可观察的行为和完成条件。
2. **工作区与基线**：绝对 worktree 路径、分支、输入提交 SHA。
3. **输入与依赖**：已验收阶段、接口契约、fixtures 和证据。
4. **修改范围与禁区**：文件所有权、允许修改内容、不得触碰内容。
5. **实施要求**：任务 ID、必做项、状态/错误/兼容约束。
6. **验证与验收**：具体 E2E 编号、命令、超时上限和成功断言。
7. **交付与阻塞处理**：本地提交、日志、剩余问题；只能由编排者推进后续阶段。

## 4. Git worktree 与分支强制要求

本计划文档可先写在当前工作区。任何实现代码、依赖修改或新的测试 harness，必须在新 worktree 开始。

建议主开发 worktree：仓库同级 `../ida-cli-nexus`；分支：`feat/nexus-backend`。

编排者在 N0 前执行：

1. 只读记录原工作区状态、HEAD、所有 worktree 和已有分支。
2. 确认目标目录和分支均未被占用；存在时不得覆盖、强制 reset 或借用已有任务目录。
3. 确认基线是否仍使用评估 SHA；若有后来已验收的功能需要纳入，明确记录新的基线及理由。
4. 用 `git worktree add -b` 创建全新分支和目录。
5. 在新目录再次核对 `pwd`、分支、HEAD、工作区状态后，才允许派实现任务。

以下为采用评估基线时的创建命令，执行前先完成上述检查：

```bash
git worktree add -b feat/nexus-backend ../ida-cli-nexus 52c0e6f6542a3f9053d5b2b97ee7785184a748ff
git -C ../ida-cli-nexus branch --show-current
git -C ../ida-cli-nexus rev-parse HEAD
git -C ../ida-cli-nexus status --short
```

计划文档若尚未进入基线提交，编排者应将经确认的文档复制进新 worktree，并单独记录其来源；不能假设 Git 自动带入原工作区未提交文件，也不能顺手提交其他人的改动。

所有阶段在新分支产生独立本地提交。每个提交说明行为变化和验证；不 push，不自动合入原分支。需要并行时，额外分支从最近已验收的集成 SHA 创建，合入前由编排者检查冲突和复跑相关测试。

失败阶段保留现场和提交用于排查。开发分支内的代码回滚使用可审计的 revert；交付后的运行回退按第 8.2 节使用旧发布版本与数据库备份，不依赖最终版本内的后端切换开关，不使用 `git reset --hard` 清空现场。

只有在提交已验收合入、没有未提交文件或未合入提交之后，才能由编排者清理本任务创建的 worktree。不得清理本任务开始前已有的 worktree；Paseo 管理的工作区归档可能删除其 worktree，归档前同样检查。

## 5. 目标架构与契约

下图表示最终交付架构；旧实现仅是迁移期对照，不属于该架构。

```text
CLI / stdio MCP / HTTP MCP
            |
Rust router：能力检查、排队、总期限、任务状态、缓存协调
            |
数据库会话接口：open / execute / cancel / release / status
            |
常驻 Python bridge -> Nexus 公共客户端 API
            |
Nexus worker / GUI 中的 IDB
```

### 5.1 后端和执行边界

- 最终版本的所有打开、附加和操作直接进入 Nexus，不保留后端选择逻辑。迁移期对照使用独立数据库副本，不让同一 canonical IDB 被新旧实现同时持有。
- 通过会话/操作接口抽象远程执行，不把 Rust `IDB` 指针跨线程或跨进程传递。
- bridge 只运行 Nexus 客户端，不加载 idapro/IDA；真正 IDA 操作经 Nexus 公共执行接口或 `remote_ida` 完成。
- 复用公共发现和 lease API，不在 Rust 中重新实现 Nexus 的私有注册文件、token 和 SSE 协议。
- bridge 长驻并复用 handle，不为每条 CLI 命令启动一次 Python/Nexus。
- bridge 的 IPC 读取、响应写入、操作执行相互分离；业务并发有界，状态和取消有独立处理容量。
- stdout 只承载协议消息，诊断走 stderr；所有错误保留来源，不能靠解析混杂日志判断成功。
- Nexus 依赖路径和版本必须可诊断。最终版本要求 Nexus 支持的 IDA 运行时；缺少 Nexus 或 IDA 版本不满足要求时明确失败，不切换旧实现。
- 不支持的方法在能力检查阶段拒绝，不按方法静默改用旧实现。能力声明仍用于处理许可证和运行时差异，不再用于三种后端之间的分流。
- 清理阶段移除旧后端参数、环境变量选择分支和 SDK 自动选择逻辑。旧配置应得到明确的移除/迁移提示，不能被静默接受或触发隐藏 fallback。

### 5.2 会话与 lease

- 持久 MCP opener 的 `close_token` 对应一个可追踪的逻辑会话；明确映射到 Nexus lease。一个 opener 释放不能影响其他 opener。
- 短 CLI 请求保留执行期间的 lease；返回、断线和取消分别测试释放行为。
- warm pool 使用独立保活引用，不依赖隐含“最后一个业务客户端”。
- 任务尚未完成或取消未确认时，保留必要的生命周期跟踪，不能先删引用再把仍在写库的任务当成结束。
- 正常关闭只释放自己的 lease。只有显式的独占关闭操作满足所有权条件后，才请求关闭 managed worker；不退出 GUI。
- 状态区分本 router 持有的会话与系统发现的 Nexus owner，不能把全局实例数当成本地引用数。
- 原来的无 token 关闭不能再无条件关闭其他 opener 使用的 active worker；多客户端情况返回明确错误及合法关闭方式。

### 5.3 请求、期限和取消

- 建立 `task_id / request_id / operation_id / lease_id / instance_id` 的关联；日志中不输出认证 token。
- 使用单调时钟维护总 deadline，覆盖输入准备、排队、连接和执行。剩余执行预算传给 Nexus，跨进程传递剩余时长而非裸单调时钟数值。
- 请求入队即有状态。内部至少区分 `queued`、`running`、`cancel_requested` 和终态，保留现有对外 JSON 的兼容映射。
- 排队中过期的请求不得执行，特别是修改数据库的请求。
- 运行中取消通过控制通道发送 `operation_id`，不能排在同一业务队列尾部。
- 只有收到完成/取消确认才宣称操作停止。客户端期限已到但 native 仍在执行时，标明取消待确认或执行结果未知。
- 连接丢失后不自动重放有副作用的请求；用户需要新请求时显式发起。
- 完成、取消、超时竞争采用明确的原子终态规则，迟到的响应不得覆盖已确定结果。
- router 控制接口读取自身状态，不同步等待被占满或持 GIL 的 IDA worker。

### 5.4 分片和一致性

- `search_pseudocode`、`batch_decompile` 以函数或有界函数批次为调度单位，不在单次 Python 调用中遍历全库。
- 每批结束后释放执行权，短请求获得服务机会；仅向一个独占长循环增加进度日志不算分片。
- 纯文本匹配、聚合和结果编码可在提取出普通数据后离开 IDA 主线程执行，不能把带线程亲和性的 IDA 对象交给任意线程。
- 单函数反编译保持串行和真实取消边界；不能把一个 native 调用包装成 async 就宣称可抢占。
- 分片过程中有其他客户端修改数据库时，检测修订变化并说明一致性范围；必要时中止为“数据库已变化”，不能静默返回混合状态。
- 如果增加可复用分析结果缓存，必须接入数据库修改事件或修订校验；现有响应落盘文件不是数据库结果缓存。

### 5.5 产物、预热和缓存

- 继续使用现有内容寻址路径，通过 Nexus 输出数据库选项落到中央缓存。
- sBPF/DSC 的准备、构建和已有库打开分别建模，外部构建进程可异步等待和取消。
- 淘汰/重建必须检查全局 owner，并与打开操作协调；一次“没有发现 owner”的查询不足以消除竞态。
- 优先采用可证明互斥的公共占用/锁机制。若无法证明安全，跳过该候选的自动删除/覆盖并报告原因，不修改 Nexus 私有锁文件。
- 不在另一个客户端持有数据库时让 sbx/idat 覆盖同一 `.i64`。
- 用户已保存的数据库不因切换后端重新分析或被新库覆盖；修改后保存与重开必须验证。

## 6. 分阶段开发委托

所有阶段使用第 3 节的固定模型配置。表中顺序为默认执行顺序，每阶段通过验收后才向下一阶段派单。

| 阶段 | 任务 | 前置 | 主要交付 | 门禁 |
|---|---|---|---|---|
| N0 | worktree、环境及可重现基线 | 用户启动开发 | 新分支、旧版本对照产物、备份、隔离 harness 设计、DNS 解决路径 | E00、E01 |
| N1 | Nexus 会话/任务契约 | N0 | 唯一后端目标、会话、能力、期限、状态和错误映射 | E02、E14、E15 的契约测试 |
| N2 | router 和预处理去阻塞 | N1 | 独立写队列、异步外部命令、控制通道 | E08、E18、E19 对应的协议/模拟验证 |
| N3 | Nexus bridge 与生命周期 | N1、N2 | 长驻 bridge、open/attach/release、状态 | E03、E05、E06、E07 |
| N4 | 首批工具及 JSON 对齐 | N3 | 基础读操作、反编译、脚本 | E04、E16、E17；首个里程碑 |
| N5 | 长任务分片与取消 | N4 | 批量公平调度、总 deadline、真实取消 | E09 至 E15、E26 |
| N6 | 写操作和高级工具 | N5 | 注释、命名、patch、类型及高级分析 | E04、E20 |
| N7 | GUI、缓存、sBPF/DSC | N6 | 共享协调、专用输入、产物复用 | E21 至 E25 |
| N8 | 全量功能验收与版本回退演练 | N7 | 完整功能证据、验证脚本、旧版本回退演练 | E00–E28 全部必需场景通过 |
| N9 | 删除旧执行路径、唯一后端打包与复验 | N8 完整通过 | Nexus 唯一运行路径、旧依赖清理、最终产物和文档 | E29；清理后重跑 E00–E28 |
| R | 独立审查和编排者验收 | 每阶段及 N9 后 | 审查报告、缺陷修复、最终证据 | 无未解决的阻断问题 |

N1/N2 在 bridge 尚未接通时先验收契约和模拟行为，这些结果不能标记为真实 E2E 通过。N3 之后逐项使用真实链路补验，N8 必须完成全部必需真实 E2E；E29 专门在 N9 清理后的产物上执行。

当前验收记录（2026-10-15）：

- N0/N0-F1：`aa33d973644fa6de4751c055cd7afef83179639c` 的 31 项支持测试、全新环境真实保存/备份副本重开、真实启动超时及外层中断清理经过编排者独立复跑；原 reviewer 确认 F1–F4 关闭、无新阻断问题。
- 环境验收范围为 macOS arm64、IDA 9.5；Linux 进程身份分支仍只有模拟验证。SIGKILL 未完成意图保守失败及身份查询/发信号非原子的限制保持公开。
- N0 留下的 Rust fmt 和 Clippy 欠项已在 N1 的独立维护提交处理；N0 环境门禁本身不作为这些检查通过的证据。
- N1 首个维护提交 `7cda84aecb1bb278cfb52c9cc5d60826a4b13d54` 完成格式和两项库级 lint 清理；追加四项 E2E harness lint 已在 `7e79f8ccd37eb42ba1313480b5a31ff3cbb47973` 等价修复。维护等价性已通过独立审查，未降低 lint 或删改功能断言。
- N1/N1-F1：契约实现 `dac4f9f40f9ac47f09e3bd9336dab512f29534c2` 的两项阻断经 `ac09810b32702568b3e7fec3fe899d104b617f40`、`9148fba526bf403b9448b50131a3edc145c2229a` 修复。编排者在最终 SHA 独立执行 fmt、check、全 target Clippy、库测试、契约测试、旧 E2E 编译和 diff 检查，全部退出码为 0；库测试 418 passed、2 原有 ignored，契约 53 passed、0 ignored。
- 编排者原始两条未知活体取消/期限失败复现，在最终 SHA 重新运行通过；另外三条独立延后失败、释放重试和断连关闭组合测试通过。原 reviewer `4a0c4799-6261-453f-8111-459a3f92c172` 确认 F1/P1、F2/P2 关闭，无新阻断，13 文件哈希匹配且工作区干净。编排者据此验收 N1 纯契约门禁。
- N1 验收证据为 `/tmp/ida-nexus-n1-fix1-parent-20261015.0v7ozadz/verification.md`、`acceptance.md` 和 `validation.jsonl`；实现报告为 `/tmp/ida-nexus-run-20261015.98rmfb/n1-fix1/report.md`。旧 `ida_e2e` 仅编译；真实 transport 背压、Nexus bridge、native 取消、主线程响应、公平调度和共享缓存仍须后续验证，不能由 N1 契约验收替代。
- N2/N2-F1–F5：输入 `52371c8763a7820c008d5315e45c2edde23b844a`，实现 `6ba86e46e0b023b6be8d1c2c73424af8c775408f`，经 F1 `69ed9ad61e1375fd060d3179ce677f4ffd028f50`、F2 `fab66160a193e3396fa9099dada1b896ad2b74c0`、F3 `9336d22f88e1c20e4a1e84f5d7f6612fa8a4131c`、F4 `86c90ebb90a134b76bac7daca209e867d83f5c61`、F5 `a1cc1e527e237949e70c3c4b5b333a9f3478260a` 修复。原审查 F01–F12，复审 R01–R09、A2，以及同类排查发现的 C1（52371c8 已存在，编排者授权纳入 N2）均已关闭。
- 编排者在最终 SHA 独立执行 12 项门禁，全部退出码为 0：fmt、check、全 target Clippy、库测试（465 passed、2 原有 ignored，连续三轮）、nexus_contract 57、nexus_transport 10、nexus_preprocess 12、nexus_fix_regressions 10、nexus_followup_regressions 9、nexus_compat_regressions 1、旧 E2E 编译、diff 检查。编排者各轮动态复现（decoder 饥饿、supervisor 启动窗口、过期控制帧及错误码、缓存失败保留结果，以及 F1 的 7 条回归）在最终 SHA 全部通过，未留下 probe 进程。原 reviewer `f1a0b1bb-c223-46ba-92b6-827ea3eab43b` 确认无新阻断，编排者据此验收 N2。
- N2 已知限制，不阻断：A1（prewarm 在 open 前观察缓存时，普通 I/O 失败仍会让 prewarm 失败）；B1/B2（MCP 业务成功后编码线程失败返回 tool error，不能证明数据库操作失败，也不允许重放）；对端持续不发换行时响应内存增长到 close/EOF；sBPF 可选错误仍按旧 RPC 字符串前缀分类；MCP 路径的 detect_sbpf_entry 仍另建 Preparation；并发 spawn 归并分支只有源码审查；Linux 分支和逃离自有 process group 的后代清理未在真实 OS 验证。
- N2 验收证据为 `/tmp/ida-nexus-n2-fix5-parent-20261015.Ge52zK/verification.md` 和 `validation.jsonl`，各轮复验在 `/tmp/ida-nexus-n2-fix*-parent-20261015.*`；实现报告为 `/tmp/ida-nexus-run-20261015.98rmfb/n2*/report.md`。旧 `ida_e2e` 仅编译；E08/E18/E19 的真实 Nexus 链路、native 取消和 N7 跨客户端缓存协调须在 N3 之后补验，不能由 N2 验收替代。
- N3/N3-F1–F2：输入 `b531c4cf71308d194ad9abc0a3a3e6144bd886c9`。首轮 `83b8aadb569497945226749aafaccf7e0d544ae4` 报告 Nexus 0.13.4 公共客户端在执行连接断开后无法取消原操作；用户 2026-10-15 裁定采用本地客户端补丁。实现 `3c05a512eafc7d0caa63a9d53a89eee6ca7b5d49`；F1 阻塞 `cc59d9a559ff267a705d30ded59ec48c7b290646`（公开 cancel_operation 的 false 无法区分权威答复与传输/解析失败），编排者在同一补丁授权内追加结构化方法 `cancel_operation_outcome`，原方法语义不变；修复 `f56d11695d3260b093bc8b679fc2ff50a76020c5`、F2 `223d720`、`86a35fa68749eb20f12856c92e20f9ca3b391449`。只读 reviewer `2c11b5e2-0854-4386-9427-c14aaaf41028` 的 P1-1～P1-4、P2-5～P2-9 及编排者发现的 G1 均已关闭，无新阻断。
- 编排者在最终 SHA 用 `env -i` 干净 shell（无 `F1_*`、短 TMPDIR）独立执行 12 项标准门禁，全部退出码为 0（库测试 468 passed、2 原有 ignored，连续四轮；contract 59）；第 13 项 `nexus_bridge_regressions` 按 TESTING 准备 `F1_PYTHON` 后 10 passed，缺少时明确失败。全新环境中补丁红绿对照成立：断连后取消 probe 未打补丁 exit 2、最终补丁 exit 0；歧义 probe 旧补丁 exit 2、最终补丁 exit 0。N0 支持 33、bridge pytest 22、真实 IDA 9.5 生命周期 E2E 9/9（E02、E03、E05、E05 并发普通 open、E06 客户端、E06 bridge、E06 同 router lease SSE 故障、E07 packed、E07 unpacked）；四个环境 cleanup CLEAN，登记进程全部退出。编排者据此验收 N3。
- N3 已知限制，不阻断：本地补丁 `scripts/nexus/client-cancel-unknown.patch` 需持续维护，只有上游等价修复通过两类 probe 和 N0/N3 重验后才能去除，N9 打包必须携带；E08/E18/E19 的完整真实链路、native 硬停止、GUI/跨平台和 Linux 未验证；缓存准备会完整复制并哈希输入，大型 DSC 的开销留待 N7；当前对无输入副本的旧缓存 IDB 一律拒绝，N4 必须按 E22 方针实现兼容。
- N2 遗留测试缺陷（测试代码，非生产缺陷），列为 N4 开工的第一个维护提交，修复需附先失败后通过的证据：T1，`tests/support/n2_f1_server.rs` 的 C1 回归对所有场景统一使用 700ms 超时，error 场景没有阻塞点，负载下会误触发 expect；T2，N2-F4 的 prewarm 测试把 Unix socket 建在 TMPDIR 下，TMPDIR 较长时超过 macOS 的 SUN_LEN，门禁结果依赖路径长度。
- N3 验收证据为 `/tmp/ida-nexus-n3f2-parent-20261016.yjPNYw/verification.md` 和 `validation.jsonl`，前两轮复验在 `/tmp/ida-nexus-n3-parent-20261015.9BMEyf/` 与 `/tmp/ida-nexus-n3f1-parent-20261015.oEP8Oq/`；实现报告为 `/tmp/ida-nexus-run-20261015.98rmfb/n3*/report.md`。
- N4/N4-F1–F3：输入 `973d562e37f6b26db3405529db6da860aceefb0e`。维护 `c49a1bf`（T1/T2）；实现 `9388a7b618d95639270c2be327e62bf862a7fda9`；F1 `59ec108cd2436230ca40c7bf3e6c319cac0e1cb2`（旧 GC 在 Nexus 模式暂停、Busy shutdown、open 订阅落后、enqueue 接纳与 task_id、反编译数组、run_script 截断与 NUL、严格类型比较器、全局锁内深复制、P12 乱序事件；F1 首次派发因委托单按文件限定范围而阻塞，改为按问题划界）；F2 `9ca9a67`（P2-9、T3、T4 测试预算）、`58ccfd0`（open 终态交付与期限兜底、lease 回收责任；T5 根因为 fork→exec 窗口共享锁文件描述，Drop 显式 LOCK_UN）；F3 `a6bc784`（P25 barrier RAII）、`b650ac0`（E22 owner 保存导致重复验证失败：首次验证后保留已验证输入快照，补 open 失败原因日志）。只读 reviewer `f0a94e7e-e847-48a8-8392-fd92685e05da` 的全部问题均已关闭，无新阻断。
- 编排者在最终 SHA 独立执行（外部负载低时段，load 1.6～7.6）：`env -i` 干净 shell 12 项标准门禁全部退出码为 0（库测试 485 passed、2 原有 ignored，连续三轮；contract 61）；第 13 项 13 passed；全新环境补丁红绿对照成立；N0 支持 33、bridge pytest 22；真实 IDA E2E：contract 套件在三个全新环境各 4/4（E04 严格对照 38/38、E16、E17、E22），lifecycle 9/9；七个环境 cleanup CLEAN，登记进程全部退出。早一轮复验在 E22 观察到一次失败，由 F3 复现并关闭。编排者据此验收 N4。
- N4 编排者方针与已知限制，不阻断：processor 长名称只在已验证的 IDA 9.5 ABI 上精确读取，其他版本回退公开短名称并 warn，open 不依赖该字段；Nexus 模式暂停旧 IDB 自动淘汰，N7 实现协调 GC 前不删除无法证明无人使用的库；`run_script` 在同一 owner 内共享 `__main__`，仅适用于受信任脚本；E22 最终哈希核对到 open 非原子，本地 path gate 不覆盖外部 opener，留给 N7；开发选择入口 `IDA_CLI_NEXUS_DEV` 及相关配置为 N9 必删项。外部高负载下部分时序测试（含 E04 驱动）会超时，已在测试中区分启动与响应预算，但不保证任意负载下满足实时预算。
- 本机准备环境时在线下载可能超过 30 秒；编排者复验使用仓库外的离线包装，仅替换依赖下载为本地 wheels（保留 `--require-hashes`）与 Nexus clone 为本地源码（脚本仍核验固定 SHA）。
- N4 验收证据为 `/tmp/ida-nexus-n4f3-parent-20261016.FYopPl/verification.md` 和 `validation.jsonl`，前几轮复验在 `/tmp/ida-nexus-n4*-parent-20261016.*`；实现报告为 `/tmp/ida-nexus-run-20261015.98rmfb/n4*/report.md`。

### N0：工作区、环境和证据基线

- 创建第 4 节的新 worktree/分支，记录实际绝对路径和 SHA。
- 检查现有测试、构建依赖、IDA SDK/运行时匹配关系；记录未修改代码时的 lint、测试及能力输出。
- 保存可执行的旧版本对照产物及源码 SHA、构建方式、匹配运行时，并制作关闭/保存完成后的数据库备份副本。对照和回退演练依赖这些固定产物，不依赖最终源码保留旧后端。
- 固定 Nexus/Domain 版本和依赖获取方式，测试环境使用独立 venv；不要依赖评估时的临时 venv。
- 2026-10-15 用户裁定将 `scripts/nexus/client-cancel-unknown.patch` 与 loopback DNS 补丁同样作为专用环境依赖补丁维护；只改固定上游 `d60ff582` 的客户端 `handle.py`，不改服务端、安装或私有锁。prepare 先检查补丁、再验证产物 SHA-256，环境检查报告补丁状态。N3-F1 新增公开结构化取消结果及因果序号；只有固定上游等价修复通过两种 probe、N0/N3 重新验收后才能移除；N9 打包必须携带。
- 对 DNS 问题给出最小复现及解决方案。若需补丁，固定补丁版本和来源，在专用环境测试，不能通过修改系统 DNS 或全局 Python 来掩盖。
- 将历史临时并发诊断转为可维护测试设计，记录原版行为和目标行为的区别。
- 验收：另一台具备对应 IDA 条件的环境能按说明准备隔离测试；缺依赖明确失败，不能显示“全部通过”。

### N1：Nexus 会话与任务契约

- 开工先用独立维护提交清理 N0 已记录的格式差异，以及 `src/tool_registry.rs` 的 `unnecessary_sort_by` 和 `src/cli/mod.rs` 的 `items_after_test_module`。追加维护范围包括 `tests/ida_e2e.rs` 的两处 `type_complexity`、一处 `await_holding_lock` 和一处 `expect_fun_call`：采用等价类型别名、明确释放 guard 的词法块和保留路径/底层错误的惰性诊断。保持 pending 登记先于发送、发送和 await 前释放锁，不替换锁原语或改变测试串行策略。
- 维护改动仅做格式/等价结构调整，保留全部功能、测试和断言，不降低 lint 要求；追加修复单独提交，全 target lint 通过后继续单独提交契约实现，不停留在维护阶段。
- 建立 Nexus 会话执行入口，列出方法能力与版本要求；如迁移期需要临时后端选择，将其标记为 N9 必删项，不作为最终用户功能。
- 定义执行返回值、错误、数据库断连、busy、排队超时和运行中取消的映射。
- 明确 request/operation/lease/instance 的关联与释放责任，覆盖任务终态竞争。
- 所有 API 形状先做契约测试；保持现有 CLI 输出与 MCP 包装，新增状态需有兼容策略。
- 验收：迁移期间保留可重复的旧版本对照，Nexus 尚未实现的方法明确拒绝；最终唯一后端的契约测试不得依赖旧后端常驻。

#### N1 接口交付与 N2/N3 消费约定

实现位于 `src/ida/nexus/`，从 `ida_mcp::nexus` 导出；确定性测试 target 是 `nexus_contract`。这是纯本地契约，没有 Python bridge、真实 Nexus transport 或新的后端选择开关。现有默认路径继续用于迁移期对照，N9 删除；契约通过不表示 N2/N3 或真实 E02/E14/E15 已完成。

`NexusSessions<C: Clock>` 维护本 router 的 lease、代际、操作和终态身份记录。它与现有主要用于 init/open 的 `IdaBackend` 分离，也不建立多后端执行框架。`UnconnectedNexus` 明确返回 `BridgeUnavailable`；能力或运行时检查失败也不能调用旧执行器。

| 边界 | N2/N3 的调用责任 |
|---|---|
| 接纳 | 在输入准备、hash、连接和排队之前调用 `AcceptedRequest::new`；保留同一对象，不在后续阶段重建期限。短请求可以没有 task_id；后台任务必须关联已有 task_id。 |
| 打开 | `open` 发出带 `OpenIdentity` 和剩余预算的命令；N3 通过公共 `DatabaseHandle.open` 获取 handle，再用完整响应身份、`SessionLease`、该 handle 的实际能力调用 `opened`。 |
| 打开后清理 | 迟到、已请求取消、结果未知或运行时不合要求的成功打开返回 `OpenDisposition::ReleaseRequired`；先保留真实 handle，再通过 `release/released` 完成清理，不补报旧请求成功。`opened` 校验错误时，新提供的 handle 仍由 N3 持有并清理。确定失败用 `open_failed`，不确定失败保留待协调记录。尚无 handle 时，`cancel_open` 只记录取消意向并保留有界 startup 跟踪，不能宣称 native/startup 已停止。 |
| 执行 | `queue` 先核对会话所有权、代际和该 lease 的方法能力；`dispatch` 在调用执行器之前复查期限和同实例占用。bridge 必须只在已附加的 handle 上执行，不能按 params 的 path 另开库。 |
| transport | `NexusBackend::send(command, attempt)` 只做有界入队，Ok 不代表已发送；`send_control(command, attempt)` 使用独立控制容量，不能排在业务队列后。N2/N3 必须原样保留并回传完整 `DeliveryAttempt`；入队后的单请求失败用 `delivery_failed`，不能误用 `complete(Failed)` 或全实例 `disconnected`。方法不得阻塞于 I/O、native 结果或远程状态。N2 保持本地锁的短临界区，网络等待在锁外。 |
| 结果 | 真实操作返回/停止后才调用 `complete`。`Completion::ExecutionTimedOut` 表示操作已返回超时结果；单请求 HTTP 超时用 `delivery_failed(attempt, Uncertain(...))`；只有真实 owner 连接断开才用 `disconnected`，不能冒充停止确认。 |
| 取消 | `cancel/expire` 发出精确 operation identity 的控制命令。公共 `cancel_operation` 的 bool 仅表示请求 ACK，使用 `delivery_acknowledged(attempt)`，不能转成 `Completion::Cancelled`；确认需要原执行调用返回已取消。UnknownOutcome 且 execution_stopped=false 仍须执行该控制责任，原未知结果/cause/NeverReplay 保持不变。 |
| 释放 | `release` 发出本 lease 的独立 attempt，公共 handle.close 确认后用 `released(attempt)`；只释放本逻辑会话。活动、排队或取消未确认的操作保留 lease。warm 引用和每个 close_token 单独映射 lease，N3 不读取 Nexus 私有 lease/token 文件。 |
| 显式关库 | `shutdown` 另用带期限和独立 operation identity 的 `ShutdownSpec`。只允许空闲、router 本地无其他引用的 managed owner；N3 仍必须调用公共 `shutdown_database` 的全局独占检查，不能把本地引用数当全局所有权。GUI 总是拒绝。拒绝响应使用当前完整 attempt 调用 `shutdown_rejected`；公共 shutdown 成功才调用 `shutdown_completed`，旧响应不能恢复/关闭后继请求。 |
| 状态 | `status/operation_status` 仅读本地内存，不能同步询问可能持 GIL 的 owner。Nexus Tasks 不使用现有 `TaskRegistry::cancel` 的旧 JoinHandle abort 语义。 |

身份中的 `ClientId` 来自已认证路由上下文，不能让请求体自行指定其他客户端；`LeaseId` 是本地 bridge handle 的非敏感 key，`InstanceId` 标识精确 owner。`generation` 非零，仅在确认 owner 被替换时推进，同 owner 多客户端共享相同代际。`request_id` 与 `operation_id` 在协调器生命周期内不可复用；task_id 可关联一个任务的多个分片操作，N2 必须以完整 operation identity 更新对应分片，再聚合任务，不能只按 task_id 接收迟到响应。重启时使用新的身份命名空间。

协调器容量有界；达到保留上限返回 Busy，不为了继续执行而丢弃终态身份记录。终态结果与仍有 native 执行的生命周期跟踪不同：`unknown_outcome` 对请求已确定，但 `execution_stopped=false` 时仍保留占用。N2/N5 后续做生命周期/保留策略时，不得在未停止前丢记录，或让旧 ID 在同命名空间重新生效。

N1-F1 将调用者结果、native 停止证据和单次投递状态分开。`DeliveryAttempt` 包含命令类型、完整 open/operation/lease 身份以及非零、单调递增的 sequence；重启必须更换身份命名空间。transport 回调是可信 N2/N3 事件，不接受客户端直接构造。`delivery_failed` 返回 true 表示本次转换生效，旧代际/旧 attempt/重复回调返回 false，伪造当前完整身份返回错误。`delivery_status(client, attempt)`、operation snapshot 的 cancel_delivery 和 session snapshot 的 control_delivery 提供投递状态与来源；同步入队失败通过同一个 `delivery_failed` 转换，返回与投递 snapshot 相同的错误。仅入队成功不代表 native 已开始。

| 命令的延后失败 | NotSent（必须证明该命令未到达） | Uncertain（可能已经执行） |
|---|---|---|
| Execute | failed，释放未执行占用，不自动重放；若真实断连已确定 unknown，只补未执行证据，不改旧结果 | unknown_outcome，保留占用和原 cause；同实例其他 lease 不变 |
| Open | 保留失败身份墓碑；反常迟到 handle 也返回 ReleaseRequired | 保留未知结果与跟踪，迟到 handle 返回 ReleaseRequired |
| Cancel | 保留原结果和占用，单独记录失败；调用者可显式重试新 attempt | 同样不代表停止；可显式再次请求精确 operation 的幂等停止控制 |
| Release | 回到原阶段（尤其 ReleaseRequired），允许显式新 attempt；若已真实断连则保持 Disconnected | 仍待释放确认，不恢复 Active、不重放；真实断连后迟到 released 仍仅确认本 lease |
| Shutdown | 恢复原阶段，清除 pending_shutdown；真实断连不能被恢复为 Active | 维持待确认；只有公共 API 的明确拒绝/成功可以解除未知关闭状态 |

`delivery_acknowledged` 仅记录当前 attempt 的 ACK，不能释放执行槽位、lease 或确认 shutdown；ACK 后再报 NotSent 是矛盾事件，明确拒绝。首次失败后不让重复失败重写来源，迟到真实生命周期确认仍可协调当前 attempt。`complete` 仅接受真实执行调用已返回/停止的证据，迟到完成对 unknown 只补 execution_stopped；`open_failed` 是明确打开失败，仍保留有界墓碑，若随后出现成功 handle 则跟踪并释放。`opened` 拒绝的任何新且未注册 handle（错误身份、零 generation、重复 acquisition、旧代际等）仍归 N3 持有并清理；不能丢弃句柄或关闭其他 lease。同一已注册 lease 的重复消息只丢消息，不重复关闭该 handle。

重复 cancel/expire 在相同 reason 的 Queued/Acknowledged 控制下不增发；失败后的显式调用才生成新 attempt。总 deadline 优先于 client reason，升级 deadline 也用新 attempt，旧 ACK/失败不能影响后继。停止或确证 owner 代际替换后不再发送旧控制；真实断连本身不是停止，当前代际的未知执行仍允许通过独立控制连接尝试停止。pending_shutdown 独立于 phase 保留：Disconnected 下仍阻止该 lease 的 release，且迟到 open 仍为 ReleaseRequired，直到匹配关闭结果解除责任。没有业务请求自动重放。释放确认和关闭拒绝/成功必须携带当前 attempt，不能仅凭 lease 或 task_id；旧失败不能恢复 Active，旧确认不能确认后继释放/关闭。

每个逻辑命令只保留最新 attempt：Open/Execute/Shutdown 各受 operation 保留容量约束，Cancel 每 operation 一条、Release 每 lease 一条。记录总数不超过三倍 coordinator capacity，重试替换记录；sequence 溢出明确 Busy，不复用 ID。N2/N3 负责有界 transport 本身及显式控制重试节奏，不能把 transport 结果当 native 已停止。

期限使用 `Instant`；不序列化该时钟值。保留现有 `timeout_secs` 兼容策略：默认 120 秒，open 上限 3600，其他方法上限 600；超大 u64 截断到上限，负数、字符串、浮点和 null 沿用旧 router 的默认值，0 表示立即过期。跨进程 `remaining_ms` 必须在 1..=3600000 内，小于 1ms 保守按耗尽处理。N2 在 dispatch 入队时建立本地剩余预算；同机内部 transport 另携带 CLOCK_MONOTONIC 绝对期限，接收方必须在实际 dispatch 时消费，编码、管道与 bridge 排队均不重新授予预算。std::Instant 本身不序列化。router 原总期限始终有效，负责到期控制请求。传输和 native 区间不能保证硬停止，等待期限过后仍须保留取消待确认/未知结果，不使用 Nexus 的执行 timeout 替代总 deadline。

| 当前状态/事件 | 结果与占用 |
|---|---|
| queued，期限耗尽或本地取消 | 不发送 execute，确定 timed_out/QueueExpired 或 cancelled，无副作用 |
| dispatch 成功入队 | running；包括已送往远端但仍在远端排队的情形，不承诺 native 已开始 |
| running，取消/总期限到达 | cancel_requested，仍占用实例和 lease；控制 enqueue 成功不代表停止 |
| 完成与取消确认竞争 | 首个有效确认决定唯一终态；请求取消期间仍可能先成功，取消不承诺回滚 |
| 总期限后才收到成功 | timed_out/DeadlineExpired，已确认停止但可能已有修改，不能自动重放 |
| 执行已发出后断线/不确定发送 | unknown_outcome，默认保留占用；迟到真实完成只可补停止证据，不覆写结果 |
| 旧 operation/代际响应 | 完整身份不匹配则拒绝，旧代际确认不影响后继实例；已有确定结果不可改写 |

错误分类见 `NexusErrorCode`，来源保存在 cause。所有错误均禁止自动重放；Busy、QueueExpired 允许显式新请求，尚未发出的 Disconnected 允许重新连接后新请求，CancelPending 要求观察原操作，其余默认 NeverReplay。已运行操作的失败统一包装 OperationFailed，保留底层原因，不把嵌套 Busy 误当成可重放写操作。

现有 `RpcRequest/RpcResponse`、地址字符串、分页字段及旧错误 JSON 保持原样。`RpcResponse::nexus_error` 在现有 error 对象里加 `data.nexus`；非法参数用 -32602，能力不足用 -32601，其余服务错误用 -32000。`ToolError::Nexus` 保留 MCP content/isError 包装，并添加 structuredContent.nexus。

例如：`{"jsonrpc":"2.0","id":"r2","error":{"code":-32000,"message":"Nexus UnknownOutcome: connection lost after write","data":{"nexus":{"code":"unknown_outcome","message":"connection lost after write","retry":"never_replay","automatic_replay":false,"cause":null}}}}`。

`server::task::nexus_task_state_json` 保留 task_id/status/message/created_at/updated_at/meta/result 字段；没有 task_id 的短操作明确拒绝任务投影。queued/running/cancel_requested 映射旧 running，succeeded 映射 completed，cancelled 仅用于已确认停止，timed_out/unknown_outcome/failed 映射 failed。详细状态和 `execution_stopped` 位于 `meta.nexus`；failed 不能被解释为 native 已停止。成功结果不改形。

N1 测试只用确定性单调时钟、记录执行器和 barrier；E02、E14、E15 的真实 bridge/IDA 验收仍属后续阶段。

### N2：router、IPC 和外部命令

- 全局状态锁只保护内存结构；每个连接使用独立有界写入队列，管道写入不能长期持全局锁。
- 后端响应按 request ID 匹配。控制输入持续被读取，普通业务仍遵守每 IDB 串行约束。
- sbx、idat 等外部命令使用异步子进程管理，定义超时、取消、日志和本任务进程树清理。
- 大文件 hash、同步文件处理及重型编码移出事件循环；限制后台工作并发，不能制造无限线程池排队。
- 验收：模拟一个 pipe 停止消费或构建命令阻塞时，router 和其他数据库仍可响应。

#### N2 接口交付与 N3 消费约定

- 生产 `route_request_prepared`、CLI path/open/route、MCP routed open、`serve-worker` 两个旧兼容入口已接连接自有 transport 或受限准备工作。旧 `RpcRequest/RpcResponse` 的外部 JSON 保留；旧执行器到 N9 删除，不新增长期多后端选择。`router::nexus_transport` 是 N3 的单一 Nexus 接入边界，当前未安装能力时明确 `BridgeUnavailable`。
- `RouterState::install_nexus_capabilities` 仅安装一次已验证的能力；`nexus_endpoint().take_lanes()` 仅交付一次业务/控制 receiver。`transition` 只做短的 N1 本地状态转换，禁止在 closure 中做远端等待、编码或阻塞 I/O。consumer drop 与延后失败调用 N1 `delivery_failed`；在 N1 锁内发生的 drop 暂存失败并保留 lane permit，由本次/下次 `transition` 刷新，数量不超过 lane 容量。
- Nexus endpoint 整体业务 lane 的容量使用 router `max_pending_per_tenant`（同 endpoint 的所有 lease 共用这个上限），控制 lane 是 8；旧连接仍分别使用 `max_pending_per_worker` 和 tenant 累计上限，未扩大任何限额；已交付但未丢弃的 `Delivery` 也持有许可。`send/send_control` 只做本地 `try_reserve`，饱和明确 Busy。控制必须由 N3 接独立物理连接或独立公共 Nexus API 调度入口，不能把两个 receiver 合并回一条堵塞的 pipe。N3 必须持续消费两条 lane，轮询本地 transition，并接入真实断连及停止证据。
- `NexusSessions::send_eligible(command, attempt)` 是只读发送资格检查，要求完整身份、当前 Queued attempt、当前 owner/generation 及各命令生命周期；ACK/已失败/已确认/被替换的投递不能再次发送。取消后的 Open/Execute 不得进入 adapter；UnknownOutcome 且仍活体的精确 Cancel/expire 继续允许。`Delivery::begin` 在公共 API 调用边界执行检查，拿到 command 即可能投递，drop 保守 Uncertain。调用与生命周期变化之间可能并发；adapter 必须使用精确 operation/lease 身份，不能把旧控制作用于后继。
- 内部 `Delivery::write` 在编码后和每次非阻塞 write poll 前再验证完整资格及本地期限（Open/Execute/Cancel/Release/Shutdown 一致；不能只依赖 timeout_at 的外层计时器）；锁不跨 I/O。wire v2 是 `nexus_frame:2`、`expires_monotonic_ns`、`attempt`、`payload` 的 JSON 行，含换行最多 16 MiB，不能交给旧 RPC parser。绝对期限由同机同次 boot 的 CLOCK_MONOTONIC 定义；N3 必须保留 `NexusWireFrame` 到实际调用前，再调用 `consume()`，该函数拒绝过期/未知版本，并更新 Open/Execute/Shutdown 的剩余预算。不得直接使用 wire 中编码前的 payload.remaining_ms。编码、管道等待和接收队列时间持续耗尽原期限；本协议不支持跨机器/跨 boot 转发。零写有证明时 NotSent；部分写、已可能发送或调用者在写入 poll 中离开时 Uncertain，禁止重放；部分帧后必须丢弃物理流。本地期限/资格失败保留 QueueExpired/Cancelled 等原错误码与 retry_advice；只有真实 I/O 错误或零写为 Disconnected。Uncertain 的 N1 快照仍按契约包装 UnknownOutcome 并保留原 cause，禁止重放。写成功仅证明完整发送，N3 仍负责完整 attempt 的 ACK 和生命周期/停止回调。
- 旧连接在 pending 登记后才暴露发送；router 全局单调 request ID 在同一进程内不复用，连接对象隔离代际，迟到响应不能作用后继连接。每连接 pending/写队列都受配置上限约束，tenant admission 在短 inner 锁中累计；发送历史由 waiter 独立持有，不因 EOF/close 清空 pending 而丢失；已就绪终态优先于取消。已可能发送的 waiter 退出后保留 pending 占用直到响应/EOF。零发送的排队取消释放 pending；部分帧失败封闭流。旧 worker 持续读取、64 项业务队列、单业务 executor、32 项响应队列；`__transport_status` 是本地状态，`__cancel` 明确不支持 native 抢占。共享物理输出堵塞时不承诺控制可送达。
- CLI 接入最多 128 个未分类输入、64 个业务连接、8 个本地状态/取消连接；输入/输出等待各有 5 秒上限，请求帧上限 16 MiB。合法响应不受该请求帧限制：小响应至多 64 KiB 在本地解析，大响应按至多 64 KiB 的独立块接收完整 JSON 行后，才获取原有 2 项独立 decoder 许可并在 OS 线程解析；未闭合/停滞帧不占 decoder、CPU 线程或跨连接解析许可，其他连接不等待它补齐。每个连接最多保存一条未解码帧，连接数受现有 worker/连接限额约束，解析线程及许可仍最多 2；帧缓冲与结果内存随实际收到的合法结果大小增长；对端持续不发换行时，内存会随接收字节一直增长到 close 或 EOF，这是已知限制。不新增响应字节上限（请求帧限额不变）。关闭连接丢弃部分帧，pending 按实际发送历史处理；解码后的 Value 仍按旧 CLI/MCP/cache 语义交付，结果本身的内存随合法结果大小增长。响应编码、请求解码各有独立 2 项 OS 线程容量，背压等待不误作协议损坏或 EOF。已分类业务不占控制 lane。重工作先获取许可再启动：Prepare 4、Encode 2、Metadata 1；运行中的 blocking closure 自持许可及 Preparation 输入工作计数，丢弃 waiter 不会释放它；文件读取、索引记录和 sBPF 后续查询/rename、DSC phase2 open 贯穿同一接纳期限/取消。旧 timeout_secs 保持秒级，正剩余向上表示；内部精确期限通过同机 metadata 和 native 队列接线保持，不重置总期限。CLI 控制编码有独立 2 项许可和独立 OS 线程，不排入业务 blocking pool。
- `status_snapshot` 只读本地内存；冷 probe 与缓存统计在受限后台刷新，未知能力不伪造 READY。冷缓存统计为 `null`，新增 `cache_statistics_refreshing/cache_statistics_error`，已有统计保留到新快照成功；对应 metrics 未知值为 `NaN`。显式 federation probe 仍是单独的远端查询，不属于本地状态保证。
- `preprocess::Preparation` 从接纳起计总 deadline；离线子进程 admission 8、活动进程 4。`sbpf::run_sbx_aot_i64`、`dsc::run_idat_offline` 及 DSC TaskRegistry 实际消费异步 supervisor。stdout/stderr 各保留最多 64 KiB 并持续排空；取消/超时/父 future drop 由 supervisor 发本任务自有 process group 信号、等待/回收并验证管道关闭。未回收 leader 锚定 PID/PGID，最后一次破坏信号后才回收；之后只读探测。spawn 后在任何异步移交前取得原始 stdout/stderr 观测所有权并建立独立读端；dup 初始化失败由 reaper 接管原读端，supervisor 首次 poll 前退出亦保留完整观测。runtime/supervisor 退出使用有限 emergency reaper，保留容量直到自有 group 消失且独立持有的 stdout/stderr（初始化失败时为原读端）确认 EOF，不在 runtime 线程同步 waitpid。
- 保证限定在未逃离自有 process group 的后代；未知/权限/管道不闭合等情况明确失败，不能报告 CLEAN 或 native 停止，不扫描名称或杀共享 Nexus owner。Darwin 的全 zombie group 可能向 kill 返回 EPERM，仅可靠非空且稳定的组成员快照及各成员停止证据可接受无需继续发信号；proc_listpids 返回 0（包括 EPERM）、截断、空/歧义结果、未知成员查询失败均不能证明停止。Darwin 可能对 zombie 的 PROC_PIDTBSDINFO 返回 ESRCH，仅对精确拥有、未回收的 leader 可另用 waitid(WNOWAIT) 正向确认；不得把这一证据借给其他成员。EPERM 本身不是清理成功。Linux 分支未在本轮真实 OS 验证。
- sbx/DSC 在唯一 sibling staging 中生成，取消与 hard-link 发布以原子状态仲裁；取消先赢则不得发布，发布 commit point 先赢则文件保留，后续 open/query 仍可取消；已经发送的 native 请求必须保留未知结果，不能假称停止。发布不覆盖已有缓存/用户文件。staging 创建先取得 8 项清理许可；Drop 只向有界清理队列交付目录和许可，独立清理线程跨 runtime 存活，CleanupReceipt 可等待完成或明确失败。sbx 成功/失败及 DSC 发布路径在继续后续工作前等待回执，不在事件循环同步 remove_dir_all。不可中断文件工作自持许可和跟踪到实际结束；超期如实标记后台未证实停止。缓存索引只提供本进程写入互斥与原子替换，不替代 N7 的跨客户端占用/GC 协调。
- 专用 `nexus_transport` 覆盖 E08/E18 的 started barrier、真实 UnixStream/pipe 背压、独立 lane、快速/乱序/迟到 ID、零写/部分写/EOF/drop 和 N1 延后失败；`nexus_preprocess` 覆盖 E19 的一次性 sbx/idat 替代进程、后代、管道饱和、队列/运行取消、总期限、父 future/runtime 退出及发布保护。证据只属于协议/模拟和真实 OS fixture，E08/E18/E19 须在 N3 后补真实 Nexus 链路。N2-F1 新增 nexus_fix_regressions 及库内系统调用/清理/真实调用点回归；保留原 N1/N2 断言。N2-F2 新增 nexus_followup_regressions，覆盖未闭合帧的跨连接解析隔离、首次 poll 前 runtime drop、控制帧过期零写/部分写分类；库内另覆盖 dup 系统调用故障和 sBPF 首次 open。N2-F3 保留 open 前及 open 本身的准入 Busy；成功 open 后的索引记录普通 I/O/解析错误（告警含路径/原因且保留损坏 index 原字节），以及索引、sBPF 检测/可选查询在本地可证明零发送的类型化 Busy，选择 warn 并跳过该可选步骤，不扩大容量或更改 blocking::run 的 try_acquire。sBPF entrypoint/callgraph/rename 的已收到普通业务错误仅 warn 并保留成功 open 的 handle，取消/总期限/WorkerClosed/可能发送未知结果继续传播，首次 open 的必需后续阶段失败统一清理 worker/path/ref 登记。响应缓存为尽力处理：目录/写入/缓存编码或后台线程启动失败均 warn 并返回原始完整成功值，缓存成功结构保持；调用方在缓存完成前保留原值，成功缓存后由受限后台 job 取走并析构原值；缓存或线程启动失败时原值仍完整 inline 返回，不深克隆大结果。后续最终 socket/MCP 编码或物理写失败仍是输出交付失败，不能证明原数据库操作失败或允许自动重放。旧 RPC 的业务错误与 transport 字符串分类集中在 optional_sbpf_failure，保留前缀歧义风险至后续协议替换。N2 等待独立复验和审查，未启动 N3。

- N2-F4：prewarm 成功取得临时引用后，以同步内存 token guard 覆盖观察失败、取消、期限与 future drop，不新增清理线程或队列。`cached_after` 的普通 I/O/本地 Busy 仅 warn，返回 `cached_after=false/cache_path=null`；沿用同一 Preparation 的取消/期限及可能发送错误继续传播，并释放本次引用。keep_warm 仅在 warm_pool 锁内成功安装 lease 后转交 token，替换 lease 释放旧 token；非 keep_warm 释放后，仅对本次新建且原子复核零引用的精确 handle 摘除并关闭，不经可变路径关闭其他客户端。引用 guard 的 Drop 只释放本次 token；新 worker 在错误/drop 后可留为零引用，交现有 idle GC 回收，不宣称 native 已停。同类 ensure_worker_prepared 的首次 open 引用在准备期间也由 guard 持有，失败只释放本次引用，其他客户端仍有引用时保留 worker；路由任务的临时引用同样覆盖 future drop。token 内存锁与异步状态锁顺序为 warm_pool → inner → references，持 token 锁时无 await/I/O/反向取锁。
- N2-F5：Router 模式 MCP `open_idb_routed` 在 spawn 返回后立即用同一 guard 持有 close_token，覆盖 open 错误、取消/期限、全部后续 await（含 detect_sbpf_entry）期间的 future drop 及非 Object 结果；只有完成响应构造、序列化成功且响应确实包含本次 token 时才转交客户端。沿用上游 Preparation 的取消与更短期限；准备与 open 阶段的默认总上限仍为 120 秒，不改变原错误文本。open 成功后，detect_sbpf_entry 仍经 `route_request` 另建 Preparation、沿用旧的尽力处理，不计入这个总期限，也不共享取消。open 失败时先释放本次引用，仅当该 token 与精确 worker 登记的初始 token 完全匹配（证明本次新建）且原子复核无其他引用时关闭；spawn 的所有复用分支都另发 token，复用 worker 即使原先零引用也保留。future drop 只同步释放引用，允许零引用 worker 交现有 GC，不宣称可能已发送的 native open 已停止。成功响应返回之后的客户端交付失败仍由既有客户端引用生命周期处理，不在本阶段扩大为跨客户端所有权协调。
- 以下 A1、B1、B2 是已知限制，不阻断 N2。A1：prewarm 在 open 前观察缓存时，普通 I/O 失败仍使 prewarm 失败，尚未取得引用，无所有权泄漏；此处 Busy 是前置准入。B1：`server::route_or_err` 在业务成功后，若编码线程启动或执行失败，仍返回 tool error。B2：`run_script` 本地 MCP 结果有相同边界。B1/B2 的此类错误不能证明数据库操作失败，不允许重放。

### N3：常驻 Python bridge 和 Nexus 生命周期

- 2026-10-15 用户裁定采用本地客户端补丁；编排者在同一授权范围追加允许公开结构化取消方法。`DatabaseHandle.cancel_operation_outcome` 新增 `cancelled/not_pending/failed`、失败类别、每 handle 取消序号和因果停止证明；原 `cancel_operation/cancel_active` 保留 bool 与异常语义。歧义 probe 区分服务端明确 false、连接故障和解析失败，后两者不证明停止。
- 补丁在执行连接异常后保留本 handle 的精确 operation ID（最多 64 项，满时拒绝新执行），取消继续走原有独立控制连接；不读取 token、不恢复私有字段、不重放。正常完成/明确错误不进入未知集合；`cancel_active` 恢复官方 active-only 选择，bridge 始终按精确 operation_id 调用新方法。
- 官方 `_server._run_operation` 在释放 backend lock 之后才移除精确 pending key，取消过的排队操作会在取得锁前被拒绝。补丁删除“后继成功即清理”：第一次 true ACK 记录当时所有已发取消请求的序号上界；只有此后才发出的另一次取消得到 HTTP 200、`cancelled=false`，才能移除未知 ID并证明停止。先发后到的 false、晚解析的成功响应及任何控制失败均不作数；handle close 清空记账。
- bridge 独立停止证明池保留 2 槽，失败轮转重试，容量满时保留待办；ACK 先于执行断流仍补安排证明，到原操作期限保留 UnknownOutcome/原 cause，不伪造停止。控制 `stopped` 早于业务 `uncertain` 时先缓冲，再经 N1 `execution_stopped` 仅补停止证据，绝不改变业务结果为成功。N1 `lease_disconnected` 仅影响精确 lease；整桥 EOF 才按 owner/generation 标记断连。Rust 控制解码使用独立等待式单槽，不争用 CLI 的 Control try许可；lane 容量不变。
- N3-F2 收紧三个边界：断连回调携带原 open attempt，Rust 在每个有界 pending open 内暂存至多一个完整 lease，opened 与回放断连在同一回调顺序锁内应用；注册回调前已断连且 runtime 查询失败时，公共 close 确认清理后仅使该 open 失败，清理不确定仍保留未知结果，不能影响健康 sibling。期限只停止新的证明探测，已经取得的权威停止证据必须消费；cancel_ack 直接补 N1 停止证据或缓冲到业务 uncertain，supervisor 即使已 expired 仍发布 stored proof 并清理 unknown。客户端最终 connection.close 失败不作废已解析的权威响应，以 `cleanup_failure=transport` 留诊断；response.close 失败仍保守视为控制失败。
- 标准十二项门禁不得依赖 F1_ROOT/F1_PYTHON；缓存库测试在 TMPDIR 自建并清理临时目录。新增第十三项 `timeout 30s cargo test --locked --test nexus_bridge_regressions -- --test-threads=1`：必须设置 F1_PYTHON 为全新 prepare 环境当前补丁的绝对 venv/bin/python；F1_ROOT 可指定短外置证据目录，未设置时用 TMPDIR。缺 Python 时明确报准备方式并失败，不 skip。该 target 十项贯通回归包含两种早到 open 断连与到期后证明；bridge pytest 另覆盖 HTTPConnection.close（与 HTTPResponse.close 独立）。旧 F1 check-env.sh 指向 baseline-env，仅为基线配置；F1 最终命令显式覆盖为 probe-final-root（早期 probe-v2-root）对应新补丁 venv，F2 重新准备环境，不复用旧脚本作为最终证明。
- `nexus_bridge/bridge.py` 作为独立可打包 Python 客户端目录，只加载 Nexus 公共客户端。每 router 复用一个进程，stdout 只写 readiness，诊断写 stderr；业务、控制使用两个 Unix socket，各自持续读取/写入。业务池 4，接纳容量沿用 N2 tenant 上限；控制接纳 8，取消池 4、释放池 2；停止确认另有容量 2 的独立线程池，不占取消处理容量。本地状态直接读内存，发现 owner 独立后台刷新。
- `src/router/nexus_bridge.rs` 消费 N2 的两条 lane，完整回传 DeliveryAttempt。Python executor 就绪后回传原 wire frame，Rust 在实际 grant 前调用 `NexusWireFrame::consume()` 并复核发送资格；最终小 grant 仅传剩余时长。总期限由 Rust 触发控制取消，执行 HTTP 连接使用 timeout=None 并等待真实结果。真实连接丢失进入 UnknownOutcome，桥接进程 EOF/异常使 N1 断连，不强杀共享 owner。
- readiness 校验 Nexus 0.13.4、Domain 0.5.1、补丁后 handle 哈希、Python 与 IDA 最低版本；每 router 能力只安装一次。open 后从实际 owner 查询 IDA 版本。公共 open/attach 获取真实 handle，lease key 为本地非敏感 UUID，instance_id 使用公共 record_id；其身份不可变，generation 在该 instance 命名空间为 1，替换 owner 有新的 record_id。
- `nexus_bridge::cache::prepare_open` 在原总期限内先复制 staging、对副本计算完整 hash，再决定内容寻址中央缓存路径，经 N2 `StagedArtifact::publish` 仲裁取消与发布，不覆盖已有输入；已有缓存必须有完整 hash 匹配的输入证明，孤立 IDB 拒绝复用；默认输出与既有缓存 `.dylib.i64` 路径一致，从而支持无 packed base 的公共修复流程。已有 IDB 保留 canonical 路径。公开 CLI/MCP 工具尚未切换，由 N4 消费内部接口。
- 可复现诊断 `scripts/nexus/probe_cancel_after_disconnect.py` 未打补丁对照实际 3 probes；补丁环境实际 5 probes（正常取消、响应断连、已结束操作取消不影响后继，以及两种因果乱序）。未打补丁的新环境 `--expect-unpatched` 退出 2；打补丁的新环境退出 0，断连后控制请求恰好 1 次，无 continued marker，无重放。这些 probe 不计作生命周期 E2E。
- `tests/nexus_lifecycle_e2e.rs` 实际 9 个场景覆盖 E02 bridge 部分、E03、E05、E06-client/bridge、E07-packed/unpacked，新增 E05-concurrent-open（两个普通 open 并发共享 owner）和 E06-lease-fault（同 router 两 lease，单 lease SSE 故障不影响 sibling 活动操作）。通过脚本核对数量、PASS 场景集合、保存重开、精确进程身份及注册清理。E08/E18/E19 的完整真实链路留待后续阶段，N2 既有模拟/OS fixture 门禁继续保留。
- 验收要求：同库两客户端共享；任一释放或异常退出不影响另一客户端；最后一个引用释放后保存可重开。本阶段实现和证据提交后，由编排者裁定 N3 验收及 N4 派发。

### N4：首批方法与输出兼容

- N4 开发接线使用临时环境选择 `IDA_CLI_NEXUS_DEV=1`，默认保持旧路径；此入口及 `nexus_tools` 中相关配置分支是 **N9 必删项**，不是最终用户功能。未实现的方法在 CLI 接纳和 MCP 工具分发阶段明确拒绝，无逐方法 fallback。
- 首批 12 个方法经 `NexusSessions::queue/dispatch` 的 Execute 进入常驻 bridge：数据库信息、分析状态、函数列表/定位、xrefs、三种反汇编、单函数反编译和 `run_script`。保留原请求结构、typed 参数解析、分页末页字段省略、地址及错误文本；大响应沿用已有 CLI response cache，MCP 保持原内联包装。
- `run_script` 保留全局命名空间、独立输出流、每流 1 MiB UTF-8 截断，以及 N0 的空异常字符串和 SystemExit/KeyboardInterrupt 包装语义；Nexus 内部取消中断继续向外传播，不吞掉停止证明。
- IDA 9.5 的 Python 绑定没有 processor 长名称访问器。业务代码通过公开 SDK `get_ph()` / `processor_t.psnames,plnames` 读取，限制 runtime 9.5、接口 900、64 位指针，并核对公开字段及当前 subtype；未验证的版本或 ABI 检查失败时使用公开 API 的短名称并记录带 IDA 版本的 warn，数据库信息与 open 保持可用。已验证 9.5 仍要求与 N0 长名称完全一致；未验证版本的 processor 字段可能与 N0 不同。
- N4-F1：Nexus 下暂停旧 IDB 自动淘汰，显式 remove/evict/clean 在无法证明本 router lease、外部 owner 与数据库锁均不存在时保守跳过并报告原因，协调 GC 留给 N7；默认旧路径不变。拒绝的 shutdown 不退出服务。enqueue 在接纳阶段检查能力，真实 task_id 经内部上下文关联到 N1 的 open/execute。
- N4-F1：open 使用按身份注册的有界单次响应，不依赖可落后的诊断 broadcast；取消与 opened 竞态仍由 supervisor 接收并释放 lease。操作轮询只读无结果元数据，最终 JSON move 出 N1 锁；原快照 API 保留。E04 比较递归区分所有 JSON 类型，新增 NUL/截断与有效函数反编译失败的对照。
- N4-F2：open supervisor 同时核对 N1 的权威结果并受 Preparation 总期限约束；零字节失败、grant 拒绝、not_sent/remote_error 不再遗失回复槽。未交付或迟到的 lease 由 guard 登记为 ReleaseRequired，bridge 保持释放责任；控制 lane Busy/NotSent 后按 N1 状态重试，未知结果不重放，也不宣称已停止。容量与 path gate 不因漏通知永久占用。
- N4-F2：独立测试维护提交分离 marker/fixture 启动和响应预算，保留大响应连接不被断开及完整送达、escaped pipe 容量保留等断言。MCP owner lock 已有 CLOEXEC，但 fork 到 exec 的窗口仍可继承同一文件描述符引用；guard Drop 显式解锁并验证子进程 exec 后无锁继承。该修复不扩大生产容量。
- N4-F3：旧缓存首次成功核对 SHA256、关闭 probe 并收到 opened 后，在交付 lease 前按 N2 无覆盖发布已验证的输入快照；取消/发布冲突保持拒绝与 lease 回收责任。后续 prewarm 使用该输入证明，不再复制已由活动 owner 保存的 packed IDB；缺失或不匹配证明仍不发布、不改原库。open 错误日志记录类别、原因和 operation，不记录 close token。P25 等待失败时用 RAII 释放 Control barrier。
- 已知限制：run_script 使用进程级 __main__，同 owner 的不同 lease/客户端共享脚本全局变量，关闭 lease 不清除；与旧 per-IDB worker 共享全局变量语义相同，仅适用于受信任脚本，不承诺客户端隔离。E22 最后核对原库 hash 与最终 open 之间不是原子操作，本地 path gate 不覆盖外部 opener，留给 N7 协调机制。
- 旧缓存先复制到隔离 verification IDB，通过 Nexus 读取其中记录的 SHA256；副本关闭确认后才判断匹配，且核对原 packed 文件未变。匹配后附加原库并关闭 autoanalysis；拒绝时不发布输入、不打开或覆盖原库。预热采用独立 lease，业务 opener 关闭不会释放 warm 引用。验证副本交付后须凭关闭确认才清理；启动或 close 结果未知时保留 staging 和 bridge 跟踪，不把未知状态当成停止。
- 真实验收 target 为 `tests/nexus_contract_e2e.rs`，对照脚本仅依赖固定 N0 二进制与隔离测试支持，不依赖旧实现源码。E04 只允许把已核验输入 SHA256 相同的 `input_file_path` 规范化；结构、地址、类型、错误和反编译文本均严格比较。N4 原交付开发对照 33 项，N4-F1 扩展为 38 项并启用严格类型检查；正式套件及最终证据见 N4-F1 报告，N4 是否验收由编排者裁定。
- 旧缓存兼容是硬性要求（E22）：已有缓存 IDB 没有输入副本时，通过 Nexus 读取该 IDB 自身记录的 input file SHA256，与当前输入 SHA256 比较；一致才接受复用。无法验证或不一致时明确拒绝，不重新分析，也不覆盖用户原库。N4 必须验证匹配复用保留用户修改、无法验证和不匹配均保留原文件；不得沿用 N3 对无副本 IDB 一律拒绝的暂定策略作为迁移完成证据。本条仅制定 N4 方针，N3-F2 不实现。
- 接通数据库信息、分析状态、函数列表/定位、xrefs、反汇编、单函数反编译及 `run_script`。
- 统一现有参数、分页、地址表示、stdout/stderr、错误和大响应落盘行为。
- 原有 IDAPython 实现可复用业务逻辑，执行入口必须改为已附加的 Nexus 数据库，不能另开 idat 同库。
- 每个方法同时通过直接 CLI、stdio MCP 和 HTTP MCP 路径验证。
- 验收：与 N0 固定的旧版本产物在等价数据库副本上的结果比较通过；形成首个可用里程碑。该对照方式在删除旧源码后仍可执行。

### N5：长任务、公平调度、期限与取消

- 原两轮公共接口诊断记录保留在外部 `n5/report-blocked.md`、`n5/report-blocked-2.md`，输入 `228aae87230145836f3dd7fa73df568f5598e14f`。编排者已批准同步 `IDB_Hooks` 方案及下面的健康承诺边界；历史阻塞已解除。N5 实现与最终验证见 `n5/report.md`，是否验收及进入 N6 由编排者裁定。
- `batch_decompile`、`search_pseudocode` 每片 **一个函数**；`run_auto_analysis` 每片一次公开 `auto_make_step(0, BADADDR)`。同一逻辑 operation 保持 request/task/operation/lease/总期限，片返回后确认停止、更新小 checkpoint、放回同实例 FIFO 尾部。已排队短请求先于续片；物理 Nexus operation ID 加投递序号，绝不复用或重放旧调用。每片不产生额外逻辑终态记录，不扩大容量。
- 函数反编译串行，不能抢占单个 native 调用。普通文本匹配、聚合目前也在该 IDA 执行区间内；只有普通 JSON checkpoint 跨线程/连接，未转交 IDA 对象。结果聚合保留在 owner 的私有模块，最终沿已有响应编码/落盘路径交付。
- 经公开 `execute_python` 在 owner 的 IDA 线程安装私有模块 `_ida_cli_nexus_slices_v1`，不在 `__main__` 放 hook。每次安装唯一 UUID；共享 counter/job 引用按 bridge、lease、instance、generation 归属。每片开始在同一 IDA 执行区间读取 `[installation, revision, database_change_count]`，严格比较上一片末 stamp；不同则“数据库已变化”。片内自身反编译产生的通知被纳入本片末基线，下一片只比较片间修改。其他分片任务或后台分析的可观测修改也保守中止，不能静默混合。
- 一致性失败与无法确认均返回既有 business-error envelope，经 router 转为明确错误，**丢弃整个任务的部分结果**。这是新增失败情况，不增加外部 JSON 字段。普通函数反编译失败仍逐项保留 error、success、顺序及重复地址；搜索保留 limit、total_searched、decompile_errors，包括旧版 limit=0 首个匹配即停止的行为。固定 N0 二进制逐类型严格对照覆盖这些情况及注入的部分反编译失败。
- 保证 fail-closed：安装失败、owner/实例/代际变化、模块/hook/唯一安装标识缺失或不一致、计数器读取失败或格式异常、bridge/lease 断连后新连接试图使用旧 checkpoint，均明确“一致性无法确认”。不靠重复 hook() 或 active 布尔值证明未漏事件。
- **已接受限制**：同 owner 受信任代码直接 unhook 或改写私有计数器不承诺检测；Hex-Rays 用户局部变量、仅 netnode 层修改等无所订阅通知的修改不承诺；native 绕过通知的写入不承诺。不是数据库事务快照或完整修改覆盖。沿用 N4 `run_script` 受信任代码模型。
- 最后一个任务成功/失败/确认取消后卸载；排队取消的残余任务由同 FIFO 的内部清理释放，取消未确认前仍保留引用。lease 释放先释放自己的 job，不能卸载其他 lease 的共享 counter。数据库关闭使 hook 无效，托管 owner 退出清除注册；GUI 留在 N7。
- bridge 有适配器自己的受限寿命 socket，owner 仅传普通 context 给监视线程。EOF（bridge 退出或单 lease 断连）后，监视线程以公开 discover/attach/execute_python 将精确 lease 清理送入同一 owner 的串行队列，等待 native 返回后才释放；从不在线程上直接调用 IDA/unhook。临时清理 lease 最后释放，不关闭其他客户端数据库。模块 incarnation 防止旧监视器清理重建模块的新任务。断连 handle 的正常释放同样经新的公开临时 lease 清理精确实例，不重放业务。
- 总期限从 Preparation 接受输入开始，涵盖准备/连接/队列/执行。Rust 连接等待受 Preparation 期限约束；每次 dispatch/grant 检查剩余预算，bridge 扣本地排队时间，owner 脚本开头再以同宿主 monotonic clock 检查，避免在其他公共客户端后排队过期的写请求执行。运行超时/取消只请求停止，必须收到执行返回或因果停止证明才释放占用；不可中断期间 `cancel_requested`、`execution_stopped=false`，冲突写请求 Busy。
- N1 首个确定终态原子获胜；取消请求不是终态。完成和取消确认竞争保留原契约，迟到结果只补停止证明，不覆盖结果；迟到 yield 不能重启已确定结果。native 永不返回时不能承诺取消时限；清理保持保守并报告未确认，不声称硬抢占。
- E11 单独验证真正启动分析：公开 import script 包装真实 auto_make_step，在 marker 释放前持续投放真实分析工作，前台查询先返回并显示未完成；还验证后台分析区间的修改通知中止分片。E12 单独测试显式等待切片的取消与总期限。E26 用真实 PyDLL/FIFO 持 GIL，恢复后进入明确 Python 取消边界；只证明人工 native 边界，不代表任意 Hex-Rays 调用的 GIL 行为。
- 同步 counter 订阅 IDA 9.5 公开通知（before/after 可重复计数，仅比较相等；回调只增计数、异常标不健康、返回 0）：

  `renamed`, `changing_cmt`, `cmt_changed`, `extra_cmt_changed`, `changing_range_cmt`, `range_cmt_changed`, `moving_range_cmt`
  `changing_ti`, `ti_changed`, `changing_op_ti`, `op_ti_changed`, `changing_op_type`, `op_type_changed`, `local_types_changed`
  `local_type_renamed`, `lt_udm_created`, `lt_udm_deleted`, `lt_udm_renamed`, `lt_udm_changed`, `lt_udt_expanded`, `lt_edm_created`
  `lt_edm_deleted`, `lt_edm_renamed`, `lt_edm_changed`, `frame_created`, `frame_deleted`, `frame_expanded`, `frame_udm_created`
  `frame_udm_deleted`, `frame_udm_renamed`, `frame_udm_changed`, `func_added`, `deleting_func`, `func_deleted`, `func_updated`
  `func_noret_changed`, `set_func_start`, `set_func_end`, `func_tail_appended`, `deleting_func_tail`, `func_tail_deleted`, `tail_owner_changed`
  `stkpnts_changed`, `thunk_func_created`, `byte_patched`, `make_code`, `make_data`, `destroyed_items`, `adding_segm`
  `segm_added`, `deleting_segm`, `segm_deleted`, `changing_segm_start`, `segm_start_changed`, `changing_segm_end`, `segm_end_changed`
  `changing_segm_name`, `segm_name_changed`, `changing_segm_class`, `segm_class_changed`, `segm_attrs_updated`, `segm_moved`, `allsegs_moved`
  `sgr_changed`, `sgr_deleted`, `compiler_changed`, `deleting_tryblks`, `updating_tryblks`, `tryblks_updated`, `callee_addr_changed`
  `item_color_changed`, `bookmark_changed`, `flirt_applied`, `idasgn_matched_ea`, `dirtree_mkdir`, `dirtree_rmdir`, `dirtree_link`
  `dirtree_rminode`, `dirtree_move`, `dirtree_rank`, `dirtree_ordering_changed`, `dirtree_bulk_move`, `dirtree_segm_moved`

- 另订阅 `closebase` 使健康状态无效；`database_change_count` 仅作字节/段修改的补充，不能代替重命名、注释、类型通知。公开异步事件订阅没有分片同步水位，故不以消费者进度证明一致性；真实测试故意积压事件至任务中止后才消费。
- N5-F1：批量 JSON 字符串只在解码成数组时展开，标量仍保留原字符串；batch 与 N4 方法共用严格 Rust u64 地址规则（ASCII 数字、可选正号、0x/0X、Rust Unicode 外围空白、溢出拒绝）。固定 N0 严格对照从 15 扩为 54，错误也按 E04 规则逐字比较。
- N5-F2/P1：数组字符串由 Rust 的同一 `serde_json::from_str::<Vec<Value>>` 解码，拒绝非 JSON 常量、不可表示的浮点数、孤立代理字符和超限嵌套，失败仍作为原字符串单项处理；保留浮点负零与重复键的旧规则。无效的复杂地址在 Rust 保留，向 owner 传递无效 null 占位，结束后按位置恢复原值，避免 adapter 信封扩大嵌套深度；不扩大容量或解析上限。严格对照 76 项；127 层成功解码值通过既有 MCP 文本结果比较，raw CLI 响应解析器原有递归上限保持不变。
- N5-F2/P1 隔离：Channel 在写出任何字节前编码；单请求结果的 JSON/UTF-8 失败转成带原 attempt 的 remote_error，N1 记录 Failed、停止确认和 cause，其他 lease/控制连接继续。只有实际 I/O 错误导致整桥断连；无自动重放。
- N5-F2/P2-a：用 N1 exact target 与最新 attempt 序号识别过期回调，覆盖 dispatch 已发布而 pending 尚未登记的窗口；未知/伪造身份不按过期放行。补契约与真实 event_received 回归。
- N5-F2/P2-b：startup guard 在 bind/spawn 起拥有专用目录与 Child，跨所有 startup await；丢弃 future 立即向该 Child 请求结束，独立 reaper 确认退出后只清理目录内精确 b/c/l socket。fixture 在初始化前登记父端点，在 lifetime bind 后立即登记精确 inode/owner。12 个阶段组合覆盖 drop、取消、到期；reap 不能确认则显式日志并保留路径，交所属环境精确 journal 清理，不进行名称扫描或跨环境 GC。
- N5-F1 E18 暂停真实 socketpair 的消费端，真实 Nexus 大响应阻塞于 kernel send 后填满原 512 项输出队列，再阻塞一个 producer；同时要求 router/control/B 响应，恢复后 513 个测试状态事件顺序完整且 A 可再查询。未扩大容量。E10 通过实际 router 取消 Queued 续片并保留 lease，观察自动 `_n5_cleanup` 释放 hook；旧物理 attempt 回调不得污染下一 attempt 或引发共享连接失效。
- N5-F1 寿命 socket 由 Python 正常退出精确 unlink，Rust 父端在关闭、终止、Drop 和启动失败时清理同一私有目录的精确端点。隔离环境按路径、device/inode 与 owner birth 台账处理强杀残留，拒绝替换文件/活 owner；套件与第 13 门禁分别断言 IPC 根目录 socket 为零。证据与未通过轮次保留于 `n5-fix1/report.md`；不清理其他环境的历史残留。
- 验收语句：短查询在长批量任务全部完成前得到执行，取消后的下一查询可继续；不可中断场景准确暴露状态。最终结果、实际数量、所有失败与修复原因、命令/退出码/uptime、旧版比较和精确进程审计集中在外部报告。

### N6：修改数据库与高级分析能力

- 迁移重命名、注释、字节 patch、类型声明/应用、结构体/枚举/栈变量及现有高级分析方法。
- 从当前 `capabilities.rs` 和工具注册表生成能力对照，逐项记录通过、明确不支持和原因，不能漏项后宣称全量完成。
- 核对反编译扩展字段；若最终选定基线包含 `line_addresses` 等新增能力，同样列入契约。
- 验证保存、关闭、重开后修改保留；失败和取消返回已发生副作用的事实，不宣称自动回滚。
- 验收：写入、类型和高级输出 E2E 通过，没有同 IDB 的隐式 native fallback。

### N7：GUI、缓存和专用输入

- 实现全局占用检查和缓存/重建协调，覆盖其他工具持有的 lease。
- 接通 sBPF 现有 sbx 流程和 DSC 构建/加载，复用完成的 `.i64`，保持配置与错误可诊断。
- 在独立测试 GUI 数据库上验证附加、修改可见性和释放后 GUI 继续存在。
- 验证未知、繁忙、崩溃和恢复中的库都不会被自动删除或覆盖。
- 验收：外部客户端持库期间拒绝重建/淘汰；释放后的安全操作可完成；真实 sBPF 和 DSC 样本通过。

### N8：全量功能验收与版本回退演练

- 用同一个 Nexus 候选产物跑 E00–E28，记录源码 SHA、产物标识和各套件结果。GUI、sBPF/DSC 或其他必需条件缺失时不得进入 N9。
- 完成与 N0 固定旧版本产物的功能对照；不得用同一数据库同时跑两个实现。
- 在隔离目录演练第 8.2 节的旧发布版本、匹配运行时和数据库备份回退，确认备份完整性及版本兼容性。
- 验收：全部承诺能力已迁移、必需功能 E2E 通过；旧源码尚在只是开发过渡，不能以此作为最终交付。

### N9 与 R：旧后端清理、唯一后端打包和最终复验

- 发布包必须携带 N0 loopback DNS 补丁及用户 2026-10-15 批准的客户端未知操作取消补丁、固定依赖和哈希校验；上游修复经 probe 与 N0/N3 重新验收后才可移除。

- 删除 `native-linked`、`idat-compat` 数据库执行路径，以及迁移期的后端选择入口、自动分流和 fallback。常规启动、CLI、MCP 和后台任务统一走 Nexus。
- 清点并移除仅为旧后端服务的 Rust idalib/FFI、SDK 构建要求、Cargo 依赖/锁文件项、vendored 代码及旧 worker 启动分支；先确认引用已迁移，不能通过删工具来消除依赖。
- 保留 sBPF/DSC 离线产物准备必要的 sbx/idat 调用，但它们不得继续承担普通查询、编辑或常驻数据库会话。Nexus 内部使用 IDA native SDK 不属于旧后端残留。
- 删除多后端选择文档、无效配置和仅用于分流的测试；将有价值的行为测试改为 Nexus 契约测试，旧版本对照改为调用独立基线产物。
- 安装/启动脚本直接定位 Nexus 专用 Python 环境并检查依赖。新版本没有“是否启用 Nexus”的开关；依赖缺失及不支持的旧 IDA 运行时明确报错。
- 完成 E29 清理验收后，用清理后的同一产物重跑 E00–E28。N8 的通过结果不能替代删除代码和依赖后的新验证。
- 独立审查重点检查所有权、锁、背压、取消、写请求重放、路径/脚本参数处理和缓存竞态。
- 修复审查问题后重跑受影响测试；编排者在最终 SHA 上独立执行关键 E2E。
- 验收：Nexus 唯一后端及版本级回退说明完整交付。开发分支中的默认运行路径收敛是本阶段必做项；安装到用户真实环境、重启服务、合并或 push 仍由用户另行决定。

## 7. E2E 设计

### 7.1 拟新增测试组织

以下路径为开发交付目标；N3 已实现 support、lifecycle、bridge 协议和 verify 脚本，其余 targets 仍属后续阶段，不能计作已执行：

| 路径 | 责任 |
|---|---|
| `tests/support/nexus_env.rs` | 独立样本、环境、进程、日志和清理 |
| `tests/nexus_lifecycle_e2e.rs` | 打开、共享、释放、异常退出、崩溃恢复 |
| `tests/nexus_concurrency_e2e.rs` | 控制响应、分片、公平、期限、取消和背压 |
| `tests/nexus_contract_e2e.rs` | CLI/MCP 输出、错误、读写和后端对照 |
| `tests/nexus_special_inputs_e2e.rs` | sBPF、DSC、缓存重建和占用保护 |
| `tests/nexus_release_e2e.rs` | 唯一后端产物、旧配置拒绝、缺依赖启动及版本级回退 |
| `tests/nexus_bridge/` | Python bridge 协议、调度和客户端模拟测试 |
| `scripts/verify_nexus_e2e.py` | 环境检查、执行套件、记录退出码和缺失条件 |

GUI 验证可由独立人工辅助套件完成，但必须留下具体步骤、样本、实例身份、结果及清理证据，不能以“文档说支持”代替。

### 7.2 隔离与执行规则

- 每轮用 `mktemp -d` 创建独立根目录；配置独立 `IDA_CLI_HOME`、`IDA_NEXUS_STATE_DIR`、IDA 测试 profile 和每个样本副本。
- 测试 profile 的授权/EULA 前置状态按用户已有合法配置准备；不自动接受新条款，不把凭据复制进仓库或日志。
- 只使用本次构建的绝对二进制路径，关闭对用户默认 daemon 的发现和 autostart 路径。
- 真实 IDA 测试使用 `IDA_TEST=1`；正式验证脚本必须检查实际执行数量。缺 IDA、许可、GUI 或专用样本标为 BLOCKED，不能静默 skip 后宣布通过。
- 新 E2E 不复用现有全局单 worker 的测试状态。共享场景必须启动独立客户端进程，跨库场景必须确认不同数据库实例。
- 用 marker、事件或协议 barrier 等待长请求已开始，避免只靠固定 sleep 猜测顺序。
- 控制响应采用有限 deadline 的成功/失败断言；不做 QPS/TPS 或延迟分位数基准。
- 同一 fixture 的场景串行运行，场景内部明确构造并发；避免测试之间竞争许可和数据库。
- `finally`/RAII 清理本次创建的客户端、bridge、worker、子进程和数据库。只按已记录的进程身份处理，不使用全局 `pkill`。
- 强制外层 timeout 时也要有编排者清理路径；不能假设测试进程被终止后 detached worker 自动消失。

### 7.3 用例矩阵

| ID | 场景与触发 | 必须验证 |
|---|---|---|
| E00 | 检查执行目录、分支及 SHA | 位于新 worktree；不是原工作区或其他任务目录；实际模型为指定配置 |
| E01 | 全新专用环境启动，包含 DNS 故障复现 | 不依赖临时 monkeypatch；就绪或明确有界失败；启动超时无孤儿进程 |
| E02 | Nexus 能力检查、缺依赖和不支持的 IDA 运行时 | 方法能力准确，错误可诊断；不静默回退或同库双持有 |
| E03 | 原始二进制及已有 IDB 打开/关闭/重开 | 路径正确、保存可见、最后释放后可重新打开 |
| E04 | 同样输入在独立副本上运行固定旧版本与 Nexus 产物 | 分页、地址、类型、错误、修改结果及输出结构符合契约；删除旧源码后对照仍可执行 |
| E05 | 两个独立客户端同时打开同库 | 共享 owner；A 释放后 B 仍可读写；最后释放保存 |
| E06 | 强制结束测试客户端或 bridge | 断开的 lease 回收；外部客户端仍可用；不误杀共享 owner |
| E07 | 测试 worker 分别在有/无 packed base 时崩溃 | 旧 handle 失效；重新打开恢复；备份/修复行为明确；写操作不重放 |
| E08 | A 长调用期间查询 router、任务状态和 B | 控制请求与 B 在截止时间内完成，不依赖 A 返回 |
| E09 | A 长调用时给 A 发普通短查询 | 正确排队且无结果串台；不宣称同 IDB 并行 |
| E10 | 全库搜索或批量反编译中插入短查询 | 短查询在批量全部完成前执行；结果完整、顺序及 limit 正确 |
| E11 | 启动后台分析期间提交前台查询 | 分片让出；状态明确，不把未完成分析当成完整结果 |
| E12 | 显式等待分析时取消/超时 | 真实操作收到取消；状态恢复可用；不等同于后台分片测试 |
| E13 | 合作式长脚本/循环执行时取消 | 状态经取消请求到确认终态；下一查询成功，B 不受影响 |
| E14 | 修改请求在队列中等待至总期限到达 | 请求不执行；标记/数据库修改均不存在；队列和引用回收 |
| E15 | 完成与取消竞争、排队取消、迟到响应 | 只有一个确定终态；无旧取消作用于后继操作、无写请求重放 |
| E16 | 经 CLI、stdio MCP、HTTP MCP 调用同组工具 | 每条真实入口输出/错误一致；HTTP close_token 不影响其他会话 |
| E17 | 大响应、Unicode、stdout/stderr、脚本异常 | 协议不混入日志；落盘/内联语义兼容；响应不丢失或串台 |
| E18 | 一个 worker/bridge 管道停止消费 | 有界背压；全局状态锁不被长期占用，其他连接正常 |
| E19 | 输入预处理或 sbx/idat 子进程阻塞并取消 | router 保持响应；本任务子进程正确清理，无后台继续覆盖产物 |
| E20 | 重命名、注释、patch、类型修改后关闭重开 | 修改持久化；错误或取消如实报告部分副作用 |
| E21 | 外部 Nexus 客户端持有中央缓存 IDB | GC/重建不会删除或覆盖该库；owner 变化竞态下仍保守正确 |
| E22 | 将旧版本保存的库交给 Nexus、缓存复用及预热 | 不重建用户修改；warm lease 释放正确；无锁残留 |
| E23 | 专用测试 IDA GUI 打开数据库后附加 | 不启动第二 owner；改动可见；释放不退出 GUI |
| E24 | 真实 sBPF 样本首次构建、缓存重开、取消构建 | sbx 产物可用，主要入口查询/反编译成功，缓存和取消语义正确 |
| E25 | 真实 DSC 样本的已有库和新构建路径 | 任务状态、加载、查询和重开正确；其他库不受长准备任务影响 |
| E26 | 人工 native 持 GIL，以及分片间外部改库 | 不虚报硬取消；router/B 正常；返回后恢复；混合修订被检测 |
| E27 | 关闭整个测试服务，再用产物重启 | lease/任务/子进程无泄漏；外部客户端继续可用；已保存结果可见 |
| E28 | 旧发布版本和迁移前备份的版本级回退 | 独立恢复目录中旧产物与匹配运行时可读取备份；保留迁移后数据，不依赖新版的旧后端开关 |
| E29 | 唯一 Nexus 后端的最终产物清理验收 | 不加载旧 Rust idalib/SDK 执行链；不接受后端选择；Nexus 缺失时明确失败，无隐藏 fallback；原工具功能仍通过 |

### 7.4 关键场景的具体编排

**共享与异常退出（E05/E06）**

1. 创建测试库 A，启动两个独立客户端，各自获取 lease。
2. 确认两者连接同一 Nexus instance；客户端一重命名，客户端二读到变更。
3. 正常释放客户端一，客户端二继续查询。
4. 重复场景并强制结束客户端一；再单独测试 bridge 异常退出且存在外部客户端。
5. 最后释放并重开，确认保存和进程/注册清理。

**总期限与取消（E13/E14/E15）**

1. 长操作到达 started barrier 后占用 A。
2. 提交带短总期限的修改请求，并验证它进入 queued。
3. 总期限到达后，应返回过期状态并撤销排队操作。
4. 解除长操作后，确认修改请求没有被延迟执行。
5. 对运行中的合作式操作发送取消，等待确认，再查询 A。
6. 用完成/取消 barrier 验证竞争，不用不确定的 sleep 成功率判定。

**批量公平性（E10）**

1. 准备足够多函数的测试库，启动跨多批次的伪代码搜索。
2. 第一批完成后提交一个短函数查询，同时查询 B。
3. 在批量任务结束前收到短查询结果，且 B 正常。
4. 对照一次完整执行的结果集合、顺序、limit 与错误计数。
5. 分片间重命名或修改类型，确认任务检测到修订变化或明确返回一致性范围。

**不可立即中断的 native 调用（E26）**

1. 用人工 `ctypes.PyDLL` 调用模拟持 GIL 的 native 区间。
2. 允许该 worker 的健康探测超时，但 router 状态和 B 必须正常。
3. 取消尚未确认时状态不得显示“操作已停止”，也不立即给同 IDB 派发冲突写请求。
4. native 返回后收敛到正确终态并恢复服务。
5. 该用例证明边界，不代表任意真实 Hex-Rays 调用都具有相同 GIL 行为。

**缓存与重建竞态（E21）**

1. 外部独立客户端持有中央缓存中的 IDB。
2. 触发低容量 GC 和针对同路径的重建；均不得损坏或覆盖活跃数据库。
3. 在检测与执行之间插入另一个 opener，验证互斥或明确拒绝。
4. 外部客户端释放后，再执行符合条件的缓存操作并重开。

**唯一后端收敛与版本回退（E28/E29）**

1. N8 完整验收后，核对 N0 保存的旧发布产物、匹配运行时和迁移前数据库备份；旧实现的源码可以随后删除。
2. 清理新版本的 legacy 执行路径、选择参数/环境变量及专属依赖，在不提供旧 Rust SDK/idalib 构建环境的条件下构建新 CLI。
3. 不传任何后端选择参数启动新产物，验证所有正常入口均连接 Nexus；旧选择配置应明确报移除/迁移错误。
4. 移走测试环境内的 Nexus 依赖再启动，确认明确失败且不会启动旧 native/idat 查询 worker；恢复依赖后复跑真实工具。
5. 保存并保留迁移后数据库，在另一个隔离恢复目录中使用旧产物、匹配运行时和迁移前备份完成回退演练。
6. 明确备份时间点之后的修改不在该备份内，不能把恢复旧备份描述成自动保留全部新修改，也不能覆盖迁移后现场。

### 7.5 命令和超时

本仓库当前没有 `paseo.json`，不要引用 Solana 套利仓库的脚本。N0 记录现有 `just`/测试脚本实际行为；N8 新增本文验证脚本后再作为统一入口。

所有命令在新 worktree 执行，使用其独立测试环境。常规检查默认 30 秒：

```bash
timeout 30s cargo fmt --all -- --check
timeout 30s cargo check --locked
timeout 30s cargo clippy --locked --all-targets -- -D warnings
timeout 30s cargo test --locked --lib
```

迁移期冷构建若涉及 Rust/FFI 全量编译，允许在执行前说明理由后使用 `timeout 180s cargo build --locked --bin ida-cli`。已有基线失败必须单独报告，不能删模块、放宽断言或抑制 lint 来制造通过。

真实 E2E 多次启动 IDA、保存和重开，单套件允许 180 秒；DSC 构建套件可用 300 秒。执行前必须在产出说明使用较长上限的具体原因。以下命令仅在拟新增 targets 已实现后可运行：

```bash
timeout 180s env IDA_TEST=1 cargo test --locked --test nexus_lifecycle_e2e -- --test-threads=1
timeout 180s env IDA_TEST=1 cargo test --locked --test nexus_concurrency_e2e -- --test-threads=1
timeout 180s env IDA_TEST=1 cargo test --locked --test nexus_contract_e2e -- --test-threads=1
timeout 300s env IDA_TEST=1 cargo test --locked --test nexus_special_inputs_e2e -- --test-threads=1
timeout 180s env IDA_TEST=1 cargo test --locked --test nexus_release_e2e -- --test-threads=1
```

迁移期由 harness 明确选择 Nexus 候选产物和独立环境；最终产物直接使用 Nexus，测试不得依赖任何后端选择参数。旧版本对照通过 N0 固定产物的独立绝对路径运行。单场景复跑使用 `cargo test --test <file> <name_filter>`，不能只传 name filter 导致所有 targets 被编译/执行。

总流程由验证脚本按套件分别施加超时并产生结果汇总，外层监督也要有上限及异常清理。命令退出码 124 表示超时，不能计为测试通过。

### 7.6 验收证据

每轮记录：

- 实际源码 SHA、工作区状态、构建产物位置和标识。
- IDA、SDK、Nexus、Domain、Python、sbx 版本；只记非敏感配置。
- 每个 E2E ID 的 PASS/FAIL/BLOCKED、命令、退出码、断言摘要及日志位置。
- 本轮创建的进程和数据库实例标识，清理后的检查结果。
- 脱敏的请求/响应样本、保存后重开的证据及崩溃恢复结果。
- 已知限制、未覆盖项和未解决缺陷，不使用“主要完成”掩盖缺口。

带用户路径、专用样本或环境细节的原始证据放在 worktree 外的本轮临时目录；仓库只提交可复现测试、公开可用 fixture 和脱敏说明。

## 8. 发布门禁、回退与最终交付

### 8.1 门禁

- M1：N0–N4 验收，最小端到端和跨库/控制响应成立。
- M2：N5 验收，总期限、取消、分片公平性及不可中断状态准确。
- M3：N6–N7 验收，所声明的完整工具、GUI、缓存和专用输入行为成立。
- M4：N8 完整功能 E2E 和版本级回退演练通过，允许开始删除旧实现。
- M5：N9 旧执行路径、选择逻辑及专属依赖清理完成，E29 和清理后的完整 E2E 通过；独立审查通过，编排者在最终 SHA 复验。

必需环境缺失即对应门禁 BLOCKED；可以提交阶段性工作，但不能声称完整迁移已完成。最终必须达到 Nexus 唯一后端，不能停在双后端可选状态。真实用户环境的安装/重启与远程发布不是文档更新或开发分支验收自动授权的动作。

### 8.2 版本级回退

1. N0 固定已验证的旧发布产物、匹配 IDA 运行时和迁移前数据库备份；缺少其中任何一项时，不宣称回退已就绪。
2. 回退前停止向本客户端会话派发新操作，等待完成或取得取消确认。保存并另存迁移后的数据库现场，释放自己的 lease；外部 owner 仍在时不强行关闭。
3. 在独立恢复目录中恢复迁移前备份，使用旧发布版本及匹配运行时启动。不要让旧 IDA 直接覆盖新运行时处理过的数据库。
4. 验证关键查询、历史标注和备份完整性，明确恢复时间点，以及未包含在旧备份内的后续修改。
5. 隔离演练通过后，真实环境切回旧发布版本仍需用户授权；不通过新版本内部的 legacy 后端开关实现回退。
6. 保留失败现场、迁移后数据、提交和证据，禁止为回退覆盖真实数据库或清空其他 worktree。

### 8.3 最终交付清单

- 独立 worktree/分支及本地提交序列。
- 实际使用 `codex-worker/gpt-6.1-sol`、`xhigh` 的阶段派单记录。
- Nexus 唯一数据库管理与执行后端、专用 Python 环境和版本检查。
- 旧 native-linked/idat-compat 执行路径、后端选择逻辑及专属依赖的删除清单和产物验证。
- 长任务调度、总期限、取消状态和控制通道实现。
- 工具能力对照、现有 JSON 兼容证据及保存/恢复验证。
- E00–E29 结果表，清理后的完整复验、独立审查报告和编排者复验结果。
- 直接使用 Nexus 的安装/启动说明、版本要求、限制及旧发布版本与备份回退说明。
- 无未说明的测试跳过、孤儿进程、共享数据库破坏或未解决阻断问题。

## 9. 参考入口

- [现有架构](../ARCHITECTURE.md)
- [现有测试说明](../TESTING.md)
- [多数据库说明](../MULTI_IDB.md)
- [运行时选择](../../src/ida/runtime.rs)
- [方法能力声明](../../src/ida/capabilities.rs)
- [router](../../src/router/mod.rs)
- [任务注册](../../src/server/task.rs)
- 上游源码：`HexRaysSA/ida-nexus @ d60ff582fde90c59726336c0dbdf3e8286e9df7a`，重点阅读 `ida_nexus/handle.py`、`_server.py`、`_runtime.py`、`_resolver.py`、`database_state.py` 及 `tests/test_idalib_e2e.py`。
