# ida-cli

`ida-cli` 是一个无界面的 IDA CLI / MCP 服务端，支持根据运行时自动选择后端。

[English README](README.md)

## 概览

`ida-cli` 提供三种使用方式：

- 通过 Unix Socket 的本地 CLI
- 通过 stdio 的 MCP
- 通过 Streamable HTTP 的 MCP

当前有两类运行时后端：

- `native-linked`
  直接使用 vendored `idalib`，适用于能够安全 in-process 打开数据库的较新运行时。
- `idat-compat`
  使用 `idat` + IDAPython 做兼容层，专门处理旧运行时上 `open_database_quiet()` 会崩溃的问题。

在当前分支里，像本机实测的 IDA 9.1 这类旧 9.x 运行时，会自动切到 `idat-compat`。

## 当前已经可用的能力

在实测的本机 IDA 9.1 环境中，`ida-cli` 已经可以：

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

### 安装 `ida-cli`

推荐直接用安装脚本。它会优先拉取最新 release；如果当前没有可用二进制资产，也可以回退到本地源码构建。

```bash
curl -fsSL https://raw.githubusercontent.com/gmh5225/ida-cli/master/scripts/install.sh | bash -s -- --add-path
```

常见变体：

```bash
# 安装指定版本
curl -fsSL https://raw.githubusercontent.com/gmh5225/ida-cli/master/scripts/install.sh | bash -s -- --tag v0.9.3 --add-path

# 直接从分支/提交源码构建
curl -fsSL https://raw.githubusercontent.com/gmh5225/ida-cli/master/scripts/install.sh | bash -s -- --ref master --build-from-source --add-path
```

说明：

- 安装器默认把 launcher 放到 `~/.local/bin/ida-cli`
- `--add-path` 会把这个目录追加到当前 shell 的 rc 文件
- 如果本地源码构建时没有设置 `IDASDKDIR` / `IDALIB_SDK`，脚本会自动拉取开源 `HexRaysSA/ida-sdk`
- 如果机器上并存多套 IDA，建议在安装或运行前显式导出 `IDADIR`

### 从源码构建

```bash
git clone https://github.com/gmh5225/ida-cli.git
cd ida-cli

export IDADIR="/path/to/ida/Contents/MacOS"
export IDASDKDIR="/path/to/ida-sdk"

cargo build --bin ida-cli
./target/debug/ida-cli serve
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

在当前 9.1 环境中的示例输出：

```json
{"runtime":{"major":9,"minor":0,"build":250226},"backend":"idat-compat","supported":true,"reason":null}
```

### 安装 skill

这里实测可用的是 `npx skills add`，不是 `npx skill add`。

```bash
# 查看这个仓库暴露出来的 skill
npx -y skills add https://github.com/gmh5225/ida-cli --list

# 给 Codex 安装 ida skill
npx -y skills add https://github.com/gmh5225/ida-cli --skill ida --agent codex --yes --global
```

这条链路我已经本地验证过，CLI 能正确识别 `skill/SKILL.md` 里的 `ida`，并安装到 `~/.agents/skills/ida`。

## 构建要求

- Rust 1.77+
- LLVM/Clang
- 通过 `IDADIR` 指定 IDA 安装目录
- 通过 `IDASDKDIR` 或 `IDALIB_SDK` 指定 IDA SDK

SDK 路径支持两种布局：

- `/path/to/ida-sdk`
- `/path/to/ida-sdk/src`

## 运行时说明

### `native-linked`

这是较新的原生后端，直接链接 vendored `idalib`。

### `idat-compat`

这是旧运行时兼容后端。它通过 `idat` 启动批处理脚本，跑 IDAPython，把结构化结果返回给 router。这样可以避开旧运行时上会直接把 worker 打崩的原生开库路径。

### 缓存和路径

- 数据库缓存：`~/.ida/idb/`
- 日志：`~/.ida/logs/server.log`
- CLI 发现 socket：`/tmp/ida-cli.socket`
- 大响应缓存：`/tmp/ida-cli-out/`

## CI 与发布

现在的 GitHub Actions 已经改成在 Hosted Runner 上通过开源 `HexRaysSA/ida-sdk` 做编译和测试，不再依赖某台私有机器上的固定 IDA 目录。

当前工作流行为：

- `master` 上的 push / pull request 会跑校验
- 打 tag，例如 `v0.9.3`，会构建 Linux / macOS / Windows 的 release 资产
- release 会附带 `install.sh` 和各平台压缩包

release 里的二进制是用 SDK stub 构建出来的；真正启动时，安装器生成的 launcher 会优先通过 `IDADIR` 或常见安装路径去解析你本机的 IDA 运行时。

## 其他文档

- [docs/BUILDING.md](docs/BUILDING.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md)
- [docs/TOOLS.md](docs/TOOLS.md)

## License

MIT
