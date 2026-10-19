# PathTrial — 网络诊断 CLI 与 Codex / Claude Code MCP 插件

**开源 Rust 网络诊断与故障排查工具（Network Diagnostics Tool）。** 检测 DNS、TCP、TLS、HTTP/3、QUIC、UDP、代理与 IPv4/IPv6 网络问题，为网站及 VPS 生成有证据依据的 JSON 报告；Codex 和 Claude Code 的本地 MCP 插件目前处于开发者预览阶段。

**语言 / Languages / Idiomas / Языки:** **简体中文** · [English](README.en.md) · [Español](README.es.md) · [Русский](README.ru.md)

[**下载 v1.4.0-rc.1 测试版**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) · [**报告 Bug**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**AI 集成指南**](docs/ai-integrations.md) · [**CLI 使用指南**](docs/cli.md)

> **当前版本：** PathTrial Core `v1.4.0-rc.1` 已公开发布为 Release Candidate，支持 CLI 和本地 MCP；AI Plugins 为 `v0.2.0`。预编译包支持 macOS Apple Silicon、macOS Intel、Linux x86_64，普通用户无需安装 Rust。README 提供四种语言，CLI 输出与报告尚未全面翻译。

> **欢迎测试与反馈：** Codex 和 Claude Code 插件已进入默认 `main` 分支。欢迎通过 [GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) 报告安装、兼容性或诊断问题，附上脱敏后的版本信息、复现步骤及预期和实际结果。

## PathTrial 能排查哪些网站、VPS 与 IPv4/IPv6 网络问题？

网络问题经常被一句“能 Ping 通”掩盖。PathTrial 把连接拆成 DNS、TCP、TLS、HTTP、UDP、QUIC 等阶段，保存每次测量的证据，并明确说明哪些原因尚未确认。

- **网站偶尔打不开**：分别检查域名解析、TCP 建连、TLS 握手和 HTTP 状态。
- **VPS 端口能连，代理却不能用**：检查 TCP、UDP Echo、QUIC、HTTP/3 和代理链路。
- **IPv4 与 IPv6 表现不同**：在相同端口、轮次和超时下比较成功率与延迟。

PathTrial 在本机运行，不上传报告，也不修改 DNS、路由、防火墙或代理设置。Codex 与 Claude Code 通过本地 MCP Server 调用同一套诊断能力。网络探测默认全部拒绝，必须显式授权目标。

## 快速安装 AI 插件

> **公开测试版（Release Candidate）：** 请先安装 PathTrial 核心，再安装 Codex 或 Claude Code 插件。插件不会自动安装诊断程序。网络探测默认拒绝，只有显式授权的目标才可测试。

### 第 1 步：安装 PathTrial（无需 Rust）

下载并检查 [v1.4.0-rc.1 正式发布的预编译安装脚本](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1)：

~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
pathtrial mcp --help
~~~

预期版本为 `1.4.0-rc.1`，且 `pathtrial mcp --help` 可正常执行。确保启动 Codex / Claude Code 时也能在 `PATH` 找到 `pathtrial`。

### 第 2 步：OpenAI Codex 插件

在 Codex CLI 安装默认 `main` 分支的 Marketplace 插件：

~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial
codex plugin add pathtrial@pathtrial
codex plugin list
codex mcp list
~~~

已完成 Codex v0.2 实际模型调用、授权本地 TCP 扫描及报告证据解释测试。第一次使用可以询问：*“请调用 `pathtrial_capabilities`，检查 PathTrial 的 9 个 MCP 工具。”*

### 第 2 步：Claude Code 插件

在 Claude Code 会话内使用以下插件命令，随后用 `/mcp` 检查工具：

~~~text
/plugin marketplace add gaochenyang666-droid/PathTrial
/plugin install pathtrial@pathtrial
/mcp
~~~

如需更多配置或故障排查，查看 [AI 集成指南](docs/ai-integrations.md)。

## 第一次使用

### 1. 授权你有权检测的目标

默认配置 `["mcp"]` 不允许任何网络探测，但离线解释和比较已有报告仍然可用。添加一个目标时，把插件配置中的 `args` 改成：

~~~json
["mcp", "--allow-target", "example.com:443"]
~~~

- Codex 已安装插件：编辑 `~/.codex/plugins/cache/pathtrial/pathtrial/0.2.0/mcp.json`。
- Claude Code 本地插件：编辑 `plugins/claude-code/pathtrial/.mcp.json`。
- 多个目标可以重复添加 `--allow-target`。
- 修改后重启 AI 客户端。
- 不要使用通配符，不要测试未经授权的设备。

### 2. 直接问 AI

**网站无法访问**

> 帮我使用 PathTrial 诊断 example.com，区分 DNS、TCP、TLS 和 HTTP 问题，最后用中文解释结果。

**IPv4 / IPv6 对比**

> 帮我比较我的 VPS 在 IPv4 和 IPv6 下的连接成功率与延迟，保持端口、轮次和超时一致，并引用实际测量证据。

**解释已有报告**

> 帮我分析这份 PathTrial JSON 报告，指出异常、真实 evidence ID 和仍无法确定的原因。

### 3. 阅读结果

重点查看 `PASS`、`WARN`、`FAIL`、`SKIP` 和 `INCONCLUSIVE`。`SKIP` 不代表通过，`INCONCLUSIVE` 表示证据不足。PathTrial 会记录 DNS、TCP、TLS、HTTP 等阶段，不会用单次 Ping 推断运营商封锁或具体丢包设备。

## 支持的诊断能力

DNS、IPv4/IPv6、TCP、TLS、HTTP、ICMP、路由追踪、UDP Echo、QUIC、HTTP/3、SOCKS5、HTTP CONNECT、直连与代理对照、双端采集关联。

## 不使用 AI？直接使用 PathTrial CLI

同一个 [v1.4.0-rc.1 公开测试版](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) 也可以独立运行 CLI，无需 Codex、Claude Code 或 Rust。可直接选择对应系统的预编译包：

- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)

每个包都有相应的 SHA-256 校验文件；可使用上面的安装脚本安装，或手动下载并校验。安装后试运行：

~~~bash
pathtrial --version
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

更多 HTTP、QUIC、UDP、代理、双端采集和退出码说明见 [CLI 使用指南](docs/cli.md)。

## 测试版状态与已知限制

- PathTrial Core：`v1.4.0-rc.1`，已公开发布为 Release Candidate，**不是稳定正式版**。
- AI Plugins：`0.2.0`，Codex / Claude Code 插件清单已包含在 `main`。
- 平台：macOS ARM64、macOS Intel、Linux x86_64 的 Release 构建均成功，附 SHA-256。
- 自动化测试：173 项通过，三平台 CI 通过；Codex v0.2 已完成模型工具调用及授权扫描测试。
- 网络目标必须由用户明确授权；Windows、图形界面和自动网络修复暂不支持。

查看 [工程验收矩阵](docs/ai-plugin-completeness.md) 和 [发行工作流](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39149532255)。后续社区兼容性和诊断问题欢迎通过 [Issue](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) 反馈。

## 常见网络诊断问题（FAQ）

### 网站打不开，如何判断是 DNS、TCP、TLS 还是 HTTP 故障？

对已获授权的目标运行 `pathtrial scan example.com --profile web --rounds 5 --redact-ips`，再用 `pathtrial http https://example.com/` 查看 HTTP 响应。各阶段结果分别记录；Ping 通不代表网站可以正常访问。

### PathTrial 能检查 VPS、IPv4/IPv6、SOCKS5 代理和 HTTP/3 吗？

支持分层诊断 IPv4/IPv6、TCP/TLS、SOCKS5 与 HTTP CONNECT 代理、QUIC 握手和 HTTP/3 请求。目标需要真实支持对应协议。详细操作见 [CLI 使用指南](docs/cli.md)，不能仅凭 UDP 超时认定故障根因。

### 如何在 Codex 或 Claude Code 中使用 PathTrial MCP 插件？

安装 [v1.4.0-rc.1 预编译核心](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) 后，按上方的[插件安装步骤](#快速安装-ai-插件)从默认 `main` 的 Marketplace 添加插件。MCP 依赖本地 `pathtrial`，网络探测必须显式授权目标。

### 安装 PathTrial 需要 Rust 吗？支持哪些系统？

无需 Rust。v1.4.0-rc.1 已提供 macOS Apple Silicon、macOS Intel、Linux x86_64 的预编译包；Windows 尚不支持。只有从源码开发或编译时才需要 Rust。

## 反馈 Bug 与参与贡献

遇到安装失败、错误结果、崩溃、文档不清或兼容性问题，请提交 [GitHub Issue](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md)。请删除真实 IP、域名、Token、密钥、Cookie、代理订阅和抓包中的敏感内容。

欢迎提交可复现的 Bug、测试和改进建议。提交代码前请阅读 [AGENTS.md](AGENTS.md)，并运行项目要求的格式、Clippy 和测试命令。

## 开发者文档与许可证

- [AI 集成与权限说明](docs/ai-integrations.md)
- [CLI 高级使用指南](docs/cli.md)
- [AI Plugins 完成度](docs/ai-plugin-completeness.md)
- [项目与 Schema 索引](llms.txt)
- [PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1) · [PR #2](https://github.com/gaochenyang666-droid/PathTrial/pull/2)

PathTrial 使用 [MIT License](LICENSE)。项目来源于一次 [RackNerd VPS 的 IPv4/IPv6 排障经历](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting)。历史案例数据并非 PathTrial 当时生成，阅读时请区分历史记录与工具测量。
