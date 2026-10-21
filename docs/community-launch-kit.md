# PathTrial community launch drafts

Optional drafts for the maintainer. Nothing in this file has been posted. Check the latest version and follow each community's self-promotion rules.

## Show HN

Suggested title: Show HN: PathTrial – evidence-first Rust network diagnostics with local MCP tools

I maintain PathTrial (https://github.com/gaochenyang666-droid/PathTrial), an MIT-licensed Rust CLI for measuring DNS, TCP, TLS, HTTP, QUIC/HTTP3, proxy and IPv4/IPv6 behavior separately.

The public v1.5 release candidate ships prebuilt binaries for macOS Apple Silicon, macOS Intel and Linux x86_64. It has guided network diagnosis and a local MCP server with ten tools for Codex and Claude Code. MCP network probes require explicit target authorization, and the CLI does not automatically change system network settings.

We recently published three protocol-specific troubleshooting guides: https://gaochenyang666-droid.github.io/PathTrial/en/guides/

We welcome reproducible compatibility reports and substantive feedback on evidence handling, Linux/macOS networking edge cases and security boundaries. Please review any network report for sensitive details before sharing.

## r/rust

Suggested title: PathTrial: Rust network diagnostics CLI with evidence-linked reports (v1.5 RC)

I maintain PathTrial (https://github.com/gaochenyang666-droid/PathTrial). The CLI separates observed DNS/TCP/TLS/HTTP/QUIC conditions and possible root causes, records probe IDs in JSON, bounds tests and preserves explicit target authorization for its MCP interface. The v1.5 RC builds for three native Linux/macOS targets. I'm interested in Rust-specific feedback on network error classification, QUIC and cross-platform tests. Documentation: https://github.com/gaochenyang666-droid/PathTrial/blob/main/docs/cli.md.

## V2EX

建议标题：开源 Rust 网络诊断工具 PathTrial：分层分析 DNS、TCP、TLS、QUIC，并支持 Codex / Claude Code MCP

我是 PathTrial 的维护者。项目希望用真实测量解释网站打不开、VPS 端口连接失败、代理异常及 IPv4/IPv6 差异。报告引用实际 probe ID，明确区分已观察、可能原因和未证实项。

现在已经公开 v1.5.0-rc.1 测试版，支持 macOS ARM/Intel 和 Linux x86_64 的免 Rust 预编译安装。CLI 可独立运行，也支持 Codex / Claude Code 本地 MCP。网络探测默认需显式目标授权，不会自动修改网络配置。

欢迎反馈经脱敏的真实兼容性问题和复现步骤。

代码：https://github.com/gaochenyang666-droid/PathTrial
网站：https://gaochenyang666-droid.github.io/PathTrial/
排障教程：https://gaochenyang666-droid.github.io/PathTrial/guides/

## Ethical distribution

- Never post to a community that prohibits maintainer promotion.
- Disclose authorship, use a genuine personal account, avoid repeat posting or artificial engagement.
- Never invent usage numbers, reviews, success stories, or measurements.
- Wikipedia requires independent notability and is not an appropriate advertising channel.
