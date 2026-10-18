# PathTrial

**让 AI 用真实网络测量解释网络问题。**

**语言 / Languages / Idiomas / Языки:** **简体中文** · [English](README.en.md) · [Español](README.es.md) · [Русский](README.ru.md)

[**下载 CLI 测试版**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**报告 Bug**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**AI 集成指南**](docs/ai-integrations.md) · [**CLI 使用指南**](docs/cli.md)

> **状态：** 公开 CLI 为 `v1.3.0-rc.1`。AI Plugins 为 `v0.2.0` 开发者预览，对应核心 `1.4.0-rc.1`，尚无公开预编译包。README 已提供四种语言，终端输出和报告尚未全面翻译。

## 为什么使用 PathTrial？

网络问题经常被一句“能 Ping 通”掩盖。PathTrial 把连接拆成 DNS、TCP、TLS、HTTP、UDP、QUIC 等阶段，保存每次测量的证据，并明确说明哪些原因尚未确认。

- **网站偶尔打不开**：分别检查域名解析、TCP 建连、TLS 握手和 HTTP 状态。
- **VPS 端口能连，代理却不能用**：检查 TCP、UDP Echo、QUIC、HTTP/3 和代理链路。
- **IPv4 与 IPv6 表现不同**：在相同端口、轮次和超时下比较成功率与延迟。

PathTrial 在本机运行，不上传报告，也不修改 DNS、路由、防火墙或代理设置。Codex 与 Claude Code 通过本地 MCP Server 调用同一套诊断能力。网络探测默认全部拒绝，必须显式授权目标。

## 快速安装 AI 插件

> **Developer Preview：** 插件不会自动安装诊断程序。当前 AI 插件需要包含 `pathtrial mcp` 的 `1.4.0-rc.1` 可执行文件。公开的 `v1.3.0-rc.1` 不能运行 MCP，`v1.4.0-rc.1` 也还没有公开预编译 Release。
>
> 在这一发布条件完成前，插件安装需要 Rust 1.84+ 和一次源码构建。只想使用稳定 CLI 的用户可以跳到下方的“不使用 AI？直接使用 PathTrial CLI”。

### 第 0 步：准备兼容的 PathTrial 核心

~~~bash
git clone --branch codex/ai-plugins-v0.1 --depth 1 https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
cargo build --release --locked
export PATH="$PWD/target/release:$PATH"

pathtrial --version
pathtrial mcp --help
~~~

版本应显示 `1.4.0-rc.1`。启动 Codex 或 Claude Code 前，确保这个目录已在它们的 `PATH` 中。

### OpenAI Codex

远程 Marketplace 安装已在临时 `CODEX_HOME` 中验证。`codex plugin list` 应显示版本 `0.2.0`，`codex mcp list` 应显示 `pathtrial` 已启用。

~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial --ref codex/ai-plugins-v0.1
codex plugin add pathtrial@pathtrial

codex plugin list
codex mcp list
~~~

本版本的真实 Codex 模型会话已完成授权本地扫描和报告解释：TCP `1/1` 成功，证据 ID 为 `tcp_ipv4_001`，未授权目标返回 `target_not_allowed`。

现在可以对 Codex 说：

> 先调用 `pathtrial_capabilities`，确认 PathTrial 版本和 9 个 MCP 工具是否可用。

### Claude Code

Claude Code 运行时仍是 `UNVERIFIED`。官方 CLI `2.1.292` 已安装，`claude plugin validate` 已通过，但当前机器未登录 Claude 账号，真实模型会话尚未开始。默认 `main` 也没有 Marketplace 文件，因此这里只给出官方支持的本地插件加载方式。

~~~bash
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
~~~

进入会话后，用 `/mcp` 检查 `pathtrial` 是否已注册。本项目的清单和共享 Skills 已通过结构测试，真实 Claude Code 调用仍需用户环境验收。

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

公开版 `v1.3.0-rc.1` 可以直接下载，不需要 Rust。它不包含 MCP，不能用于 AI 插件。

- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)

每个包都有 SHA-256 文件，可在 [v1.3.0-rc.1 Release](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) 查看。推荐先下载并检查安装脚本，再运行：

~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh

~/.local/bin/pathtrial --version
~~~

第一次扫描：

~~~bash
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

`--redact-ips` 适合生成可分享报告。更多 HTTP、QUIC、UDP、代理、双端采集和退出码说明见 [CLI 使用指南](docs/cli.md)。

## 测试版状态与已知限制

- PathTrial Core：`1.4.0-rc.1` 开发版。
- AI Plugins：`0.2.0` 开发者预览。
- 公开预编译 CLI：`v1.3.0-rc.1`，不包含 MCP。
- 自动化验收：173 项测试通过，Ubuntu 24.04、macOS ARM、macOS Intel 三平台 CI 通过。
- Codex：`v0.2.0` 已完成真实模型调用、授权扫描、证据解释和未授权拒绝。
- Claude Code：官方 CLI、插件清单和 Marketplace 结构已验证；账号未登录，真实调用仍为 `UNVERIFIED`。
- AI Plugins 工程完成度为 `75.0%`。这是验收矩阵得分，不代表诊断准确率。

完整证据见 [AI Plugins 完成度矩阵](docs/ai-plugin-completeness.md)。当前不支持 Windows、图形界面、自动修复网络、自动抓包和具体网元级丢包定位。Fake-IP/TUN、公共 UDP 443 和 HTTP/3 的可达性仍可能受本地网络影响。

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
