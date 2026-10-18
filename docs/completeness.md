# PathTrial 功能完成度矩阵

本文件在开发前确定权重与验收项，用于计算最终完成度。**不得为了凑分临时调整权重。**
状态定义：

- `VERIFIED`：实现完成，且有本地可重复测试或真实协议交互验证。
- `PARTIAL`：部分验收项通过，按通过项比例计分。
- `NOT IMPLEMENTED`：零分。
- `UNVERIFIED`：代码存在但缺少必要验证，不计为完成。

## 权重

| 维度 | 权重 |
| --- | ---: |
| 14 个模块的功能验收 | 70% |
| 跨平台验证（macOS arm64 / macOS x86_64 / Linux x86_64 / Windows x86_64） | 15% |
| 安全、隐私、探测预算与回归测试 | 10% |
| 文档、发布构建与安装体验 | 5% |

每个模块的功能分 = 70% / 14 = 5 个百分点。模块内各验收项等权。

## M01 系统环境与网卡

1. 操作系统、架构、内核
2. 网卡列表、地址、状态
3. 默认路由与目标路由
4. 隧道类接口提示与代理环境变量名（只记名字）
5. macOS / Linux 平台适配

## M02 DNS

1. 系统解析器 A/AAAA
2. 用户显式指定解析器
3. 多解析器结果对照
4. 解析耗时与 rcode 分类
5. Fake-IP 与 Split DNS 私有地址区分

## M03 IPv4 / IPv6

1. 本机地址族支持检测
2. 按地址族分别探测
3. 同窗口双栈对照
4. 缺一族时 SKIP 并写明原因

## M04 路由与 traceroute

1. 默认路由与目标路由
2. 逐跳路由检测
3. 每跳地址、RTT、超时、是否到达
4. 缺少工具或权限时 SKIP 并写明原因

## M05 ICMP

1. Ping 探测（不要求 root）
2. 发送/接收数量、丢包率、RTT
3. 中位数与抖动
4. 目标限制 ICMP 时的证据边界

## M06 TCP

1. 非阻塞 connect + 硬超时
2. 错误分类（超时/拒绝/不可达/重置）
3. 拒绝与超时的语义区分
4. 平均值/中位数/最大值，仅统计成功样本
5. 总预算与轮次上限

## M07 TLS

1. 握手与耗时
2. 协议版本与密码套件
3. 证书有效期、SAN、链长度
4. 传输失败与证书失败分开记录
5. SNI 覆盖（字面 IP 场景）

## M08 HTTP/HTTPS

1. 真实请求（GET，HTTP/1.1）
2. 分段计时：DNS / TCP / TLS / 首字节 / 总耗时
3. 状态码与预期状态码校验
4. 重定向记录但不跟随跨目标跳转
5. 4xx/5xx 不归类为底层网络不可达
6. 复用接口绑定与地址族选择

## M09 UDP

1. 应用层 Echo 客户端（序号 + 载荷匹配）
2. ICMP 不可达 / 超时 / 无效响应区分
3. 成功率、RTT、丢包统计
4. 可选 Echo 服务端（默认只监听回环）

## M10 QUIC / HTTP3

1. 真实 QUIC 握手
2. ALPN 与证书验证
3. 握手错误与应用错误分离
4. 不支持 QUIC 的目标判为 SKIP

## M11 代理检测

1. SOCKS5 无认证 CONNECT
2. HTTP CONNECT 隧道
3. 错误分类（代理不可达 / 拒绝 / 需要认证 / 隧道成功但目标 TLS 失败）
4. 直连与代理的同目标、同窗口对照
5. 不记录凭据

## M12 双端诊断

1. 客户端采集
2. 服务端采集
3. 离线关联（不依赖 SSH）
4. 时钟误差与缺失抓包的限制说明

## M13 对照分析

1. 两份报告的目标/端口/协议一致性检查
2. DNS、TCP、TLS、HTTP 差异
3. 采样条件不一致时拒绝严格比较

## M14 综合报告

1. JSON Schema 校验
2. 三种输出格式一致的状态逻辑
3. 每条 Finding 引用真实 probe ID
4. 脱敏模式
5. 证据边界与未证实项

## 验收记录（2026-10-17，v1.3.0-rc.1）

| 模块 | 状态 | 通过项 | 得分（满分 5） |
| --- | --- | ---: | ---: |
| M01 系统环境 | VERIFIED | 5/5 | 5.00 |
| M02 DNS | VERIFIED | 5/5 | 5.00 |
| M03 IPv4/IPv6 | VERIFIED | 4/4 | 5.00 |
| M04 路由与 traceroute | VERIFIED | 4/4 | 5.00 |
| M05 ICMP | VERIFIED | 4/4 | 5.00 |
| M06 TCP | VERIFIED | 5/5 | 5.00 |
| M07 TLS | VERIFIED | 5/5 | 5.00 |
| M08 HTTP | VERIFIED | 6/6 | 5.00 |
| M09 UDP | VERIFIED | 4/4 | 5.00 |
| M10 QUIC/HTTP3 | VERIFIED | 4/4 | 5.00 |
| M11 代理 | VERIFIED | 5/5 | 5.00 |
| M12 双端 | VERIFIED | 4/4 | 5.00 |
| M13 对照 | VERIFIED | 3/3 | 5.00 |
| M14 报告 | VERIFIED | 5/5 | 5.00 |

模块分：14 个 VERIFIED = **70.00 / 70**。

平台分（15）：macOS arm64 GitHub Actions 实测通过 3.75；macOS Intel GitHub Actions
实测通过 3.75；Ubuntu 24.04 GitHub Actions 实测通过 3.75；Windows 未实现 0 →
**11.25 / 15**。

安全、隐私、预算与回归（10）：预算与超时、脱敏、证据引用、Fake-IP 守卫、
134 项测试已在本地与 Linux CI 验证；QUIC 证书验证、ALPN 分离、双端任务标识和时间窗
检查、URL 查询串与凭据不进入报告；Windows 尚未验证，扣 1.0 → **9.0 / 10**。

文档与发布（5）：README、CHANGELOG、CONTRIBUTING、SECURITY、完整度矩阵、Release 工作流齐备；
尚未发布安装包或 Homebrew formula → **4.0 / 5**。

**合计：70.00 + 11.25 + 9.0 + 4.0 = 94.25%。**

本阶段验收依据：

- M10：本地 Quinn 服务端完成合法 QUIC 握手，rustls 证书校验通过，ALPN 协商为 h3，
  真实 HTTP/3 GET 收到 200 和响应体。测试另覆盖 500、证书失败、ALPN 不匹配、
  QUIC 成功但 HTTP/3 失败、IPv4、IPv6 和无监听端超时。
- M12：客户端与服务器独立写出 JSON，不需要 SSH。关联器检查任务标识、协议、端口、
  目标地址、Schema 版本和时间窗；一致、部分缺失、无两侧成功、任务不一致、
  端口不一致、地址不一致和时间窗不重叠均有本地测试。报告明确保留时钟同步和
  丢包位置为未证实项。
- M13：`compare` 接受 1.0 到当前版本的 JSON，检查目标、端口、profile、地址族、接口、
  超时和样本量；条件不同时退出码 3 并标记 `NOT DIRECTLY COMPARABLE`。

Linux CI 在本轮修复了两个只在 Linux 暴露的问题：`/proc/net/route` 网关字节序解析错误，
以及无 `CAP_NET_RAW` 时测试 accept 线程无限等待。修复后 Ubuntu 24.04、macOS ARM 和
macOS Intel 三个 Job 全部通过。

剩余缺口：Windows 尚未实现；当前 Mac 的 UDP 443 路径对公共 HTTP/3 目标超时，
公共 HTTP/3 验证仍需在可用 UDP 出口上重复。

## AI Plugins v0.2（独立验收）

AI 插件不计入上面的 94.25% 核心 CLI 评分，单独记录如下：

| 项目 | 状态 | 证据 |
| --- | --- | --- |
| MCP stdio 初始化、tools/list、tools/call | VERIFIED | 21 项 MCP 协议测试 |
| DNS 授权、确定性 IP 绑定与代理双端授权 | VERIFIED | 12 项安全与子进程单元测试和 MCP 集成测试 |
| 客户端断开取消、授权摘要脱敏、重定向脱敏 | VERIFIED | 断开测试、capabilities 隐私测试、查询参数和重定向测试 |
| 扫描、HTTP、QUIC、HTTP/3、代理、UDP、报告解释、报告比较 | VERIFIED | 9 个工具的 MCP 级本地协议测试 |
| 共享 Skills 一致性 | VERIFIED | 5 项插件结构测试与同步检查脚本 |
| Codex marketplace 与插件安装 | VERIFIED | 临时 `CODEX_HOME` 实际安装，`codex mcp list` 可见 |
| Codex 模型会话内真实工具调用 | VERIFIED | v0.2.0 完成 capabilities、未授权拒绝、授权扫描和 `tcp_ipv4_001` 解释 |
| Claude Code 清单校验与加载 | PARTIAL | 官方 CLI 2.1.292、插件和 Marketplace 验证通过；账号未登录，真实调用未开始 |
| 含 MCP 的预编译发行包 | PARTIAL | Release 工作流已加固，尚未公开发布 1.4.0 包 |
| Windows 插件 | UNVERIFIED | Windows 核心尚未实现 |

AI Plugins 独立权重与当前 75.0% 计算见
[ai-plugin-completeness.md](ai-plugin-completeness.md)。
