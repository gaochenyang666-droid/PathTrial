# PathTrial community launch kit (v1.4.0-rc.1)

**Status:** drafts prepared; **not posted to external communities**. Outreach must be submitted by the maintainer through their own account and in compliance with each community's current rules. Links and metrics below do not imply traffic, endorsements, backlinks or users that have not occurred.

- Source / download: https://github.com/gaochenyang666-droid/PathTrial
- Prebuilt v1.4.0-rc.1: https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1
- Product site (only after Pages is enabled): https://gaochenyang666-droid.github.io/PathTrial/
- Community testing: https://github.com/gaochenyang666-droid/PathTrial/issues/3
- Bug template: https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md
- Field report template: https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=field_report.md
- Feature request template: https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=feature_request.md

## 1. Hacker News: Show HN

**Where:** https://news.ycombinator.com/submit

**Community guidelines:** https://news.ycombinator.com/showhn.html

**Submit a link to the working GitHub repository / release, not a marketing landing page.** Show HN requires something readers can actually try. The title should begin with `Show HN:`. The maker should be available to answer real questions. Do not solicit votes or post duplicate promotions.

**Title**

Show HN: PathTrial – evidence-first network diagnostics CLI with local MCP tools

**Link**

https://github.com/gaochenyang666-droid/PathTrial

**Suggested first comment**

I built PathTrial after debugging confusing VPS and IPv4/IPv6 connectivity problems. A successful ping often said little about whether DNS, TCP, TLS, HTTP, UDP, or QUIC actually worked.

PathTrial is an open-source Rust CLI that performs bounded, per-layer diagnostics and exports JSON reports whose findings reference the measurements behind them. There are local MCP plugins for Codex and Claude Code; network probes are denied by default until the user explicitly authorizes a target.

The v1.4.0-rc.1 release has prebuilt macOS ARM/Intel and Linux x86_64 archives with SHA-256 files, so you can try the CLI without installing Rust.

I'm particularly looking for feedback on:
- false positives, incorrect inferences or missing evidence;
- permission/allowlist UX;
- installer portability and MCP tool discovery.

Code and download: https://github.com/gaochenyang666-droid/PathTrial
Reproducible test reports: https://github.com/gaochenyang666-droid/PathTrial/issues/3

## 2. V2EX：分享创造

**节点：** https://www.v2ex.com/go/create

**官方节点说明：** https://www.v2ex.com/help/node

**标题**

开源了一个 Rust 网络诊断工具 PathTrial：分层检查 DNS/TCP/TLS/QUIC，支持 Codex 和 Claude Code MCP

**正文**

最近做了一个开源项目 PathTrial，起因是之前排查 VPS、IPv4/IPv6 和代理连接问题时，发现只看 Ping 或 curl 的结果，很难分清到底是 DNS、TCP、TLS 还是应用层出了问题。

PathTrial 用 Rust 实现，按阶段执行有边界的网络探测，生成带 probe ID 的 JSON 报告。支持 DNS、TCP、TLS、HTTP、UDP Echo、QUIC、HTTP/3、SOCKS5 和 HTTP CONNECT；也做了 Codex / Claude Code 的本地 MCP 插件。

安全上采取默认拒绝：MCP 不会自动探测网络，必须明确授权目标。不会自动修改路由、DNS、防火墙、代理配置或上传报告。

现在公开了 v1.4.0-rc.1 测试版，macOS ARM、Intel 和 Linux x86_64 都有免 Rust 安装包及 SHA-256 校验文件。

GitHub：https://github.com/gaochenyang666-droid/PathTrial
下载：https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1

希望有网络运维、VPS、自托管或 MCP 使用经验的朋友帮忙试试。我特别想听听：诊断输出是否容易理解、有无误报、授权流程是否别扭，以及不同系统下的兼容性问题。

反馈 Issue：https://github.com/gaochenyang666-droid/PathTrial/issues/3

## 3. Reddit r/rust weekly project discussion

**Community:** https://www.reddit.com/r/rust/

**Important:** The subreddit announced that repository-only "code dump" showcase posts should go in the weekly **What's Everyone Working on this Week?** thread, not a standalone top-level promotional link. Check the current pinned thread and rules before posting.

**Short weekly-thread comment**

I've been building PathTrial, a small open-source Rust CLI for evidence-first network diagnostics (DNS/TCP/TLS/HTTP, UDP, QUIC, IPv4/IPv6 and proxies). It keeps the actual probe observations behind each finding rather than guessing a root cause from one timeout. The CLI also runs as a local MCP server for Codex / Claude Code, with a default-deny target allowlist.

The v1.4.0-rc.1 prerelease has macOS and Linux binaries: https://github.com/gaochenyang666-droid/PathTrial

I'd value Rust feedback on subprocess cancellation, bounded I/O, DNS pinning and portable release engineering. Please don't treat this as a request for votes.

## 4. GitHub subreddit: promotion thread

**Community thread example (check current moderator-posted thread before commenting):** https://www.reddit.com/r/github/comments/1jy8rea/promote_your_projects_here_selfpromotion/

**Suggested comment**

PathTrial is an MIT-licensed Rust network diagnostics CLI with local MCP plugins for Codex and Claude Code. It checks DNS, TCP, TLS, HTTP, QUIC, UDP and proxies, and makes evidence-backed JSON reports. macOS/Intel/ARM and Linux x86_64 release candidates are downloadable without Rust. Feedback is welcome, particularly on false positives and MCP usability: https://github.com/gaochenyang666-droid/PathTrial

## Publishing and follow-up checklist

- [ ] GitHub Pages live URL verified; only then put it in About > Website.
- [ ] Publish **one** relevant, helpful post where permitted; adapt examples for that community.
- [ ] Be present for questions. Answer criticism, acknowledge limits, and avoid inflated claims.
- [ ] Invite real test reports through dedicated Issue templates; never fabricate Issues, stars or external backlinks.
- [ ] Log the **actual published URL**, date and feedback summary in this file or an issue after posting.
- [ ] Prioritize reproducible defects; link fixes to issues, explain behavior and test evidence.
- [ ] Revisit feedback after a real release fix. Avoid reposting the same announcement.

### Publication log (verified external posts only)

| Community | Actual post URL | Date | Findings / follow-up |
| --- | --- | --- | --- |
| Not yet posted | — | — | Drafts prepared |

### Simple organic metrics (do not fabricate)

Track a weekly snapshot after launch: number of **real** outside Issues, confirmed reproducible bugs, feedback reports, fixes linked to issue numbers, and externally published references whose URLs have been checked. Avoid focusing on raw stars or encouraging coordinated votes.
