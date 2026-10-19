# AI Plugins 完成度矩阵

本矩阵独立于核心 CLI 的 14 模块评分。权重在开发前固定，不允许为凑分调整。

## 权重

| 维度 | 权重 |
| --- | ---: |
| MCP 协议与全部工具验收 | 20% |
| 安全与权限保护 | 25% |
| Codex 真实端到端验收 | 15% |
| Claude Code 真实端到端验收 | 15% |
| 预编译发行与安装体验 | 15% |
| 文档与跨平台 CI | 10% |

## 基线：v0.1，提交 032d8ff

| 维度 | 状态 | 得分 | 证据 |
| --- | --- | ---: | --- |
| MCP 协议与工具 | PARTIAL | 8.9 | 9 个工具中 4 个有 MCP 级测试 |
| 安全与权限 | PARTIAL | 10.0 | 有启动允许列表；DNS 检查后子进程会再次解析；无子进程硬超时 |
| Codex 端到端 | PARTIAL | 6.0 | marketplace 和插件安装验证；模型会话未调用 MCP |
| Claude Code 端到端 | UNVERIFIED | 0.0 | 本机无 `claude` CLI |
| 预编译发行 | PARTIAL | 3.0 | 本地构建和旧 Release；旧包不含 MCP |
| 文档与 CI | VERIFIED | 10.0 | 四语言入口、集成指南、三平台 CI |

**基线合计：37.9%。**

## 当前：v0.2，安全加固后

| 维度 | 状态 | 得分 | 证据 |
| --- | --- | ---: | --- |
| MCP 协议与工具 | VERIFIED | 20.0 | 9 个工具均有真实 MCP stdio 测试；21 项协议测试覆盖本地 QUIC、HTTP/3、UDP、SOCKS/HTTP CONNECT、断开和错误响应 |
| 安全与权限 | VERIFIED | 25.0 | DNS 全部候选检查、确定性 IP 绑定、代理双端授权、子进程硬超时、客户端断开取消、输出和消息上限、授权摘要脱敏、IP 与重定向脱敏、报告证据校验 |
| Codex 端到端 | VERIFIED | 15.0 | v0.2.0 真实模型会话完成 capabilities、授权 TCP 扫描 1/1、`tcp_ipv4_001` 解释和未授权 `target_not_allowed` 拒绝；QUIC/HTTP3/UDP 边界由 21 项 MCP 协议测试覆盖 |
| Claude Code 端到端 | UNVERIFIED | 0.0 | 默认 main 的 Marketplace 和插件安装成功，4 个 Skills 被发现，MCP 健康检查为 Connected；尚无真实模型工具调用验收证据 |
| 预编译发行 | VERIFIED | 15.0 | `v1.4.0-rc.1` 已公开，三平台免 Rust 安装、SHA-256、CLI、MCP 和报告解释通过三平台 release-smoke |
| 文档与 CI | VERIFIED | 10.0 | 四语言文档、集成指南、三平台 CI、173 项测试门禁 |

**当前合计：85.0%。**

## 未达到 100% 的原因

- Claude Code 的 CLI 与清单校验已通过；真实模型端到端验收仍待补充，按既定评分暂计 0 分。

## 可复核记录

- Codex capabilities 返回：`core_version=1.4.0-rc.1`、`plugin_version=0.2.0`、9 个工具。
- Codex v0.2 未授权调用返回：`target_not_allowed`。
- Codex v0.2 授权本地扫描和解释返回：`tcp_ipv4_001`，TCP 1/1 PASS。
- Claude Code 官方 CLI：2.1.292；插件清单和仓库 Marketplace 验证通过；默认 main 安装、4 个 Skills 和 MCP Connected 已验证。
- 公开发行：`v1.4.0-rc.1` 标签指向 `073e814`；三平台 release-smoke run `39209255302` 全部通过。
- MCP 测试：21 项，覆盖 9 个工具、超时、输出上限、消息上限、客户端断开、授权摘要脱敏、重定向和查询参数脱敏、证据引用和权限拒绝。
- 核心测试：173 项通过；提交 `0c39c53` 的 Ubuntu 24.04、macOS 15 和 macOS 15 Intel CI 全部通过。

状态定义与核心矩阵一致：VERIFIED、PARTIAL、UNVERIFIED、NOT IMPLEMENTED。

## v1.5 main 源码（已合并、未发布；不计入上方 v1.4 得分）

- MCP 工具从 9 个增加到 10 个，新增 `pathtrial_diagnose`。
- `local` 场景不要求网络目标授权；其他场景继续使用启动允许列表、DNS 确定性绑定和代理双端授权。
- diagnose 本地场景、授权 TCP 和未授权拒绝均有 MCP 级测试。
- [PR #5](https://github.com/gaochenyang666-droid/PathTrial/pull/5) 已合并；v1.5 源码有 225 项测试，包含诊断证据反查、域名及双栈授权、HTTP Host/SNI、子进程清理和延迟 FAIL 优先级回归测试。[三平台 CI 39235804316](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39235804316) 全部通过，旧版 v1.4 的 173 项是历史基线。
- 真实 Codex/Claude 模型对新工具的选择与解释尚未重跑，因此不把开发分支提前计为 100%。
