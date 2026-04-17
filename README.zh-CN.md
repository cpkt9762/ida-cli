# ida-cli

`ida-cli` 是一个无界面的 IDA CLI 与 skill-first 工具集，当前宿主平台支持 macOS 和 Linux，并会根据运行时自动选择后端。

[English README](README.md)

## 概览

`ida-cli` 现在主要围绕两个用户入口：

- 本地 `ida-cli` 命令行
- 给 agent 环境安装的 `ida-cli` skill

底层服务层在需要时由 CLI 自动拉起和管理。

## 支持矩阵

### 宿主平台

- 支持：macOS、Linux
- 不支持：Windows

### IDA 运行时策略

- `IDA < 9.0`：不支持
- `IDA 9.0 – 9.2`：走 `idat-compat`
  也就是 `idat` + IDAPython 兼容路径。
- `IDA 9.3+`：走 `native-linked`
  也就是 vendored `idalib` 的原生路径。

这个选择由 `probe-runtime` 在运行时决定。编译期仍然需要 IDA SDK，因为 vendored native 层要参与编译。

当前有两类运行时后端：

- `idat-compat`
  用于 IDA 9.0-9.2，通过 `idat` + IDAPython 工作。
- `native-linked`
  用于 IDA 9.3+，直接走 vendored `idalib`。

## 当前已经可用的能力

在支持的 IDA 9.x 运行时上，`ida-cli` 目前已经可以：

- 打开原始二进制并复用缓存数据库
- 列函数、按名字解析函数
- 按地址或函数反汇编
- 反编译函数
- 读取地址信息、段、字符串、导入、导出、入口点、全局符号
- 读取 bytes / string / int
- 查询地址的 xrefs to / from
- 搜索文本和字节模式
- 执行 IDAPython 代码

样本 `example2-devirt.bin` 已完成端到端验证：

- `list-functions` 找到 `main`，地址 `0x140001000`
- `decompile --addr 0x140001000` 成功

目前还没有做到的是 `idat-compat` 下的全部写操作和复杂类型编辑完全对齐。

## 快速开始

### 最推荐路径：直接安装 skill

默认入口应该是 `ida-cli` skill，而不是手动先装 CLI。

```bash
# 查看这个仓库暴露出来的 skill
npx -y skills add https://github.com/cpkt9762/ida-cli --list

# 给 Codex 安装 ida-cli skill
npx -y skills add https://github.com/cpkt9762/ida-cli --skill ida-cli --agent codex --yes --global
```

这条链路我已经本地验证过，CLI 能正确识别 `skill/SKILL.md` 里的 `ida-cli`，并安装到 `~/.agents/skills/ida-cli`。

安装完成后，skill 自带一个 bootstrap wrapper：

```bash
~/.agents/skills/ida-cli/scripts/ida-cli.sh --help
~/.agents/skills/ida-cli/scripts/ida-cli.sh probe-runtime
~/.agents/skills/ida-cli/scripts/ida-cli.sh --path /path/to/binary list-functions --limit 20
```

这个 wrapper 会在本机缺少 `ida-cli` 时自动安装，然后再执行实际命令。

### 直接安装 CLI（可选）

只有你明确想单独使用 CLI，而不是通过 skill 时，再走这条路。

```bash
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --add-path
```

常见变体：

```bash
# 安装指定版本
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3 --add-path

# 直接从分支/提交源码构建
curl -fsSL https://raw.githubusercontent.com/cpkt9762/ida-cli/master/scripts/install.sh | bash -s -- --ref master --build-from-source --add-path
```

说明：

- 安装器默认把 launcher 放到 `~/.local/bin/ida-cli`
- `--add-path` 会把这个目录追加到当前 shell 的 rc 文件
- 如果本地源码构建时没有设置 `IDASDKDIR` / `IDALIB_SDK`，脚本会自动拉取开源 `HexRaysSA/ida-sdk`
- 如果机器上并存多套 IDA，建议在安装或运行前显式导出 `IDADIR`

### 从源码构建

```bash
git clone https://github.com/cpkt9762/ida-cli.git
cd ida-cli

export IDADIR="/path/to/ida"
export IDASDKDIR="/path/to/ida-sdk"

cargo build --bin ida-cli
./target/debug/ida-cli --help
```

### 使用 CLI

```bash
./target/debug/ida-cli --path /path/to/example2-devirt.bin list-functions --limit 20
./target/debug/ida-cli --path /path/to/example2-devirt.bin decompile --addr 0x140001000
./target/debug/ida-cli --path /path/to/example2-devirt.bin raw '{"method":"get_xrefs_to","params":{"path":"/path/to/example2-devirt.bin","address":"0x140001000"}}'
```

### 查看运行时选中的后端

```bash
./target/debug/ida-cli probe-runtime
```

后端选择的示例输出：

```json
{"runtime":{"major":9,"minor":0,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

```json
{"runtime":{"major":9,"minor":3,"build":260213},"backend":"native-linked","supported":true,"reason":null}
```

## 构建要求

- Rust 1.77+
- LLVM/Clang
- macOS 或 Linux 宿主机
- 通过 `IDADIR` 指定 IDA 安装目录
- 通过 `IDASDKDIR` 或 `IDALIB_SDK` 指定 IDA SDK

SDK 路径支持两种布局：

- `/path/to/ida-sdk`
- `/path/to/ida-sdk/src`

## 运行时说明

### `idat-compat`

这是 IDA 9.0-9.2 的兼容后端。它通过 `idat` 启动批处理脚本，跑 IDAPython，把结构化结果返回给 CLI 运行时。

### `native-linked`

这是 IDA 9.3+ 的原生后端，直接链接 vendored `idalib`。

### 缓存和本地运行时路径

- 数据库缓存：`~/.ida/idb/`
- 日志：`~/.ida/logs/server.log`
- CLI 发现 socket：`/tmp/ida-cli.socket`
- 大响应缓存：`/tmp/ida-cli-out/`

## CI 与发布

现在的 GitHub Actions 已经改成在 Hosted Runner 上通过开源 `HexRaysSA/ida-sdk` 做编译和测试，不再依赖某台私有机器上的固定 IDA 目录。

当前工作流行为：

- `master` 上的 push / pull request 会跑校验
- 打 tag，例如 `v0.9.3`，会构建 Linux / macOS 的 release 资产
- release 会附带 `install.sh` 和各平台压缩包

release 里的二进制是用 SDK stub 构建出来的；真正启动时，安装器生成的 launcher 会优先通过 `IDADIR` 或常见安装路径去解析你本机的 IDA 运行时。

## 其他文档

- [docs/BUILDING.md](docs/BUILDING.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md)
- [docs/TOOLS.md](docs/TOOLS.md)

## License

MIT
