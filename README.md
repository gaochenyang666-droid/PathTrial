# PathTrial

**Evidence-First Network Diagnostics CLI** / **基于可验证证据的轻量级网络故障诊断工具**

PathTrial 按固定顺序执行网络检查，记录每一步的真实数据，最后生成一份可以用机器读取、
也可以直接贴进工单的诊断报告。它不修改任何系统配置，也不在没有证据时给出根因。

```
$ pathtrial scan example.com
01  系统环境      PASS    33 个网卡，IPv4 本地支持 true，IPv6 本地支持 true
02  DNS           PASS    A 解析 1 个地址，AAAA 解析 1 个地址
03  TCP 与 TLS    WARN    IPv4 8/20，IPv6 20/20；TLS 传输握手 4/4
04  双栈对照      WARN    IPv4 8/20，IPv6 20/20
05  报告          PASS    3 条结论，1 条建议
```

## 当前状态

本仓库是 **V1.2.0-rc.1**：五阶段固定检测、真实 HTTP、ICMP、traceroute、DNS 对照、
UDP Echo、SOCKS5、HTTP CONNECT、直连/代理对照和历史报告比较均已实现。测试覆盖本地
协议桩、真实 TLS 隧道、UDP 回环服务和黄金数据集。

尚未实现：QUIC/HTTP3 握手、双端抓包关联、Windows 平台。报告不会把未实现模块算作通过。

## 安装与构建

需要 Rust 稳定版（1.84 以上，与 `Cargo.toml` 的 `rust-version` 一致）。

```bash
cargo build --release
./target/release/pathtrial --version
```

也可以直接运行：

```bash
cargo run -- scan example.com
```

## 用法

```bash
pathtrial scan example.com
pathtrial scan example.com --rounds 20
pathtrial scan example.com --port 443
pathtrial scan example.com --profile web
pathtrial scan server.example.com --port 22 --profile tcp
pathtrial scan example.com --format json
pathtrial scan example.com --format markdown
pathtrial http https://example.com/ --expect-status 200
pathtrial ping 1.1.1.1 --count 5
pathtrial trace example.com --max-hops 15
pathtrial dns example.com --server 223.5.5.5
pathtrial udp --target 127.0.0.1:39001 --mode echo
pathtrial endpoint --udp-echo --bind 127.0.0.1:39001
pathtrial proxy https://example.com --proxy socks5://127.0.0.1:1080
pathtrial proxy https://example.com --proxy http://127.0.0.1:8080
pathtrial proxy https://example.com --proxy socks5://127.0.0.1:1080 --compare-direct
pathtrial compare old.json new.json
pathtrial compare old.json new.json --format markdown --out ./reports/diff
pathtrial --version
pathtrial --help
```

单点命令（`http` / `ping` / `trace` / `dns` / `udp` / `proxy`）各自输出一段摘要，
`--format json` 输出结构化的 `probes`，退出码语义与 `scan` 相同。需要 Markdown 时使用
`--format markdown`；`compare --out PREFIX` 会同时写出 `PREFIX.json` 和 `PREFIX.md`。

常用参数：

| 参数 | 作用 |
| --- | --- |
| `--rounds N` | 每个地址族的 TCP 轮次，1 到 200，默认 20 |
| `--port N` | 覆盖 profile 的默认端口 |
| `--profile web\|tcp\|ssh` | 只决定端口与是否启用 TLS，不改变阶段顺序 |
| `--tls` / `--no-tls` | 强制开启或关闭 TLS |
| `--sni NAME` | 目标是字面 IP 时指定 TLS 服务器名 |
| `--bind-interface en0` | 把探测绑定到物理网卡，绕过本地 TUN 代理（Linux 需要 root） |
| `--timeout-ms` / `--interval-ms` / `--max-seconds` | 单次超时、探测间隔、整次任务上限 |
| `--format summary\|json\|markdown` | stdout 输出格式 |
| `--out-dir DIR` / `--no-files` | 报告文件目录，或完全不写文件 |
| `--out PREFIX` | 指定固定输出前缀，写入 `PREFIX.json` 与 `PREFIX.md`，同名文件会被覆盖 |
| `--allow-insecure-tls` | 仅诊断用：证书校验失败后重试一次「不校验」握手，单独标注 |
| `--redact-ips` | 在报告里把 IP 替换成占位符 |

## 五个固定阶段

| # | 阶段 | 记录内容 |
| --- | --- | --- |
| 1 | 系统环境 | 操作系统、架构、内核、网卡与地址、默认路由、目标路由、隧道类接口、代理环境变量名 |
| 2 | DNS | 每个系统解析器的 A/AAAA 回答、耗时、rcode、CNAME 链、Fake-IP 迹象 |
| 3 | TCP 与 TLS | 每次建连结果与耗时、错误分类、TLS 握手耗时、协议版本、证书有效期与 SAN、证书校验结果 |
| 4 | 双栈对照 | 同一时间窗口内 IPv4 与 IPv6 的成功率、中位耗时、差异 |
| 5 | 报告 | 阶段状态、原始数据、结论、证据、未证实项、限制、人工验证建议 |

目标没有 AAAA 记录时，IPv6 记为 `SKIP`，不会当成 DNS 故障。
目标不是 TLS 服务时，TLS 记为 `SKIP`，不会当成握手失败。

## 状态与退出码

| 状态 | 含义 |
| --- | --- |
| `PASS` | 达到该检测项的明确通过条件 |
| `WARN` | 检测完成，但存在异常表现 |
| `FAIL` | 明确违反该检测项的预期条件 |
| `SKIP` | 不适用或缺少必要测试条件，不计入成功率 |
| `INCONCLUSIVE` | 已检测，但证据不足以定性，报告中必须写明原因 |

| 退出码 | 含义 |
| --- | --- |
| 0 | 扫描完成，没有 WARN/FAIL |
| 2 | 扫描完成，存在 WARN/FAIL |
| 3 | 扫描完成，但证据不足 |
| 1 | 工具自身失败（参数错误、I/O 错误） |

`compare` 的退出码只有两种正常结果：`0` 表示两份报告在目标、端口、协议、接口、超时和
样本量上可直接比较；`3` 表示条件不一致，输出 `NOT DIRECTLY COMPARABLE`。它不会把条件
差异解释成网络改善或恶化。

这个设计让 CI 可以区分「网络有问题」和「工具没跑起来」。

终端摘要、Markdown 报告和 JSON 使用同一套状态优先级，报告顶部会给出「总体判定」。判定同时
考虑所有 Finding 与所有阶段状态：某一项 PASS 不会掩盖同一次扫描中的 FAIL；UDP/QUIC 这类
未实现项显示 SKIP，也不会被算成失败。

## 证据规则

每条结论都是一个 `Finding`，固定包含：

```json
{
  "id": "F001",
  "rule_id": "R007",
  "claim": "IPv6 路径明显优于 IPv4（成功率 20/20 对 8/20）",
  "severity": "warn",
  "status": "WARN",
  "evidence": ["tcp_ipv4_001", "tcp_ipv6_001"],
  "not_established": ["具体丢包位置", "是否存在人为流量过滤"],
  "confidence": "moderate",
  "limits": ["两个地址族在同一轮窗口内交替测量"]
}
```

约束：

- `evidence` 里只能出现本报告中真实存在的 probe ID，集成测试会强制检查。
- `confidence` 由样本量规则生成，不是统计概率。汇总数据固定为 `low`。
- 少于 20 个样本不发布 P95；汇总数据不生成中位数。
- 阈值写在 `src/analysis/mod.rs` 顶部：建连 500 ms 起告警、1500 ms 起视为影响交互使用；
  协议族成功率差 20 个百分点或中位耗时相差 2 倍才判定为路径差异。

## 报告

每次扫描默认在当前目录写出带 run id 的文件名，避免两次扫描互相覆盖：

- `pathtrial-report-<run_id>.json`：符合 [`schemas/report.schema.json`](schemas/report.schema.json) 的完整数据。
- `pathtrial-report-<run_id>.md`：十节中文报告，可直接贴进 GitHub Issue 或 VPS 工单。

需要固定路径时用 `--out ./reports/run1`，工具会覆盖同名文件，并在 stderr 明确提示这一点。
`--format json` 时 stdout 只有 JSON，方便 CI 解析；文件路径会写到 stderr。

`pathtrial schema` 输出扫描报告的 Schema；`pathtrial schema --command` 输出单点命令的
信封 Schema（[`schemas/command.schema.json`](schemas/command.schema.json)）。`compare`
输出的是独立的比较文档，带有自己的 `schema_version: "1.0.0"`。

## 安全边界

- 不修改 DNS、路由、防火墙、系统代理或任何系统配置。
- 只探测用户显式给出的目标与其正常解析结果，不扫描网段、不做端口枚举。
- 不尝试登录、不猜测口令、不测试弱口令。
- 默认每个地址族 20 次、单次超时 3 秒、间隔 200 毫秒，并受 `--max-seconds` 总预算约束。
- 报告默认不含任何凭据。代理环境变量只记录「存在」这一事实，不记录值。
- URL 中的用户名、密码和查询字符串不会写入报告；代理认证请求只记录 `auth_required`。
- `--redact-ips` 会把 IP 替换成稳定的占位符，便于公开分享。

## 单点命令说明

| 命令 | 实际做什么 | 不做什么 |
| --- | --- | --- |
| `http URL` | 真实 GET 请求，记录 DNS/TCP/TLS/首字节/总耗时、状态码、协议版本、Location | 不跟随重定向；不下载大文件（默认最多 64 KB） |
| `ping HOST` | 调用系统 `ping`，记录丢包、RTT、抖动 | 不用原始套接字；ICMP 被限制时判 FAIL 并注明不代表 TCP |
| `trace HOST` | 调用系统 `traceroute -n`，解析逐跳地址与 RTT | 缺少工具时判 SKIP；中间节点不回应不等于业务丢包 |
| `dns HOST` | 系统解析器 + `--server` 指定解析器，比较 A/AAAA | 结果不同不等于 DNS 污染；Fake-IP 会单独提示 |
| `udp --target H:P` | 真实 UDP Echo，校验会话、序号与载荷，统计 RTT/抖动 | 只证明该端口的 Echo；不能推断 QUIC；无回应不定位原因 |
| `endpoint --udp-echo` | 临时 Echo 服务端，默认只监听回环 | 需要公开监听必须显式 `--allow-public-bind`；只用于测试 |
| `proxy URL --proxy P` | SOCKS5（无认证）或 HTTP CONNECT，逐段记录 TCP、协商、CONNECT、TLS、HTTP | 不支持代理认证；隧道成功不等于 HTTPS 可用 |
| `proxy ... --compare-direct` | 同一 URL、同一超时下交替执行直连和代理请求，分别统计 | 两条路径可能使用不同 DNS、出口和路由，差异不能单独归因于运营商 |
| `compare A.json B.json` | 比较目标、端口、协议、时间、TCP/TLS/HTTP/ICMP/UDP/代理指标和 Finding | 条件差异大时标记不可直接比较；缺失字段不补造样本 |

未实现的模块（QUIC、双端关联、Windows）在本版本中**没有命令入口**，工具不会以任何
形式报告它们通过。

## 已知限制

1. **Fake-IP 会污染结论。** 如果本机代理把域名改写成 198.18.x 之类的地址，TCP 阶段会被标记为
   `INCONCLUSIVE`，因为测到的不是公网路径。解决方式：关闭本地代理，或对字面 IP 使用
   `--bind-interface`。
2. **TUN 路由会劫持测量。** 只绑定源地址不足以绕开 TUN；需要 `--bind-interface`。
3. **DNS 仍走系统解析器。** 绑定网卡只作用于 TCP/TLS 探测；解析结果可能仍被本地软件改写，
   报告会标记 Fake-IP 迹象。
4. **样本量。** 默认 20 次只适合发现明显异常，不代表长时间稳定性。需要更长观察时请调大
   `--rounds` 并分时段多次运行。
5. **探测本身可能影响路径。** 高频探测与路径降级可能同时出现，本工具刻意保持低频。
6. **平台。** V1 只支持 macOS 与 Linux；Windows 未实现。
7. **`scan` 的 TLS 阶段只验证握手与证书**，不发送 HTTP 请求。需要业务验收时使用
   `http` 或 `proxy`；它们仍只证明请求与响应头部，不证明登录、上传等完整业务流程。

## FAQ 与常见误判

**扫描一个私有 IP，会不会被当成故障？**

不会。`pathtrial scan 192.168.1.1 --profile tcp` 会正常建立 TCP 连接并统计成功率，
报告里用一条 R014 说明「目标是私有地址，结论描述本地或内网路径」。私有地址本身不是异常。

**域名解析到 198.18.x，是不是 DNS 被污染？**

198.18.0.0/15 是本地代理常用的 Fake-IP 网段。工具会把它标为「疑似被本地代理改写」，
并把 TCP 阶段标成 INCONCLUSIVE，因为测到的是本地代理的应答，不是公网路径。
这只是嫌疑，不是确证：报告中同时列出「改写来源是哪一个进程」尚未证实。

**域名解析到 10.x 或 192.168.x，是 Fake-IP 吗？**

不一定。企业内网域名、Split DNS、hosts 文件都会产生私有地址解析。工具不再把私有地址
当作 Fake-IP 证据，只会提示「目标是私有地址」，并允许继续做 TCP/TLS 检测。

**为什么同一条命令两次结果不一样？**

跨境链路本身会随时间波动。每次报告都记录独立的 run id 与时间窗口，比较时必须使用同一
窗口内的数据。跨窗口的数字不能拼成一个成功率。

**端口返回 connection refused，说明什么？**

说明连接请求被明确拒绝：对方（或路径上的某台设备）回了 RST。但指定端口并没有连上，所以
这项 TCP 检查判为 FAIL，退出码 2。报告不会据此宣称「主机完整可达」或「服务健康」，
并保留「拒绝响应可能由中间设备生成」这一未证实项。它与全部超时是两种不同证据：超时没有
任何回应，拒绝有明确回应。

**扫描时 TCP 全部成功，但 TLS 失败，算通过吗？**

不算。TCP 与 TLS 分开统计：`--profile web` 下 TCP 成功而 TLS 握手失败会给出 R008（FAIL）。
`--profile ssh` 或 `tcp` 不做 TLS 检测，相关项显示 SKIP，不会被当成失败。

**为什么 IPv6 那一栏是 SKIP？**

目标没有 AAAA 记录，或者本机没有可用 IPv6。SKIP 表示「没有测」，不计入成功率也不计入失败。

**能不能用它判断是哪一跳在丢包？**

不能。它能证明「这一层有问题」以及「问题与哪个地址族或时间窗口相关」，无法定位具体网元。
需要定位时请配合双端抓包，并注意抓包本身也需要在两端同一时间进行。

**单次超时和总预算是怎么互相影响的？**

`--timeout-ms` 只约束一次 TCP connect；`--max-seconds` 约束整次任务。预算不够时工具会减少
轮次并在报告中写明，「没有测完」不会被伪装成全部通过。实测：`--timeout-ms 1200` 时，
失败样本的耗时集中在 1201 到 1206 毫秒，成功样本单独统计。

**UDP Echo 成功，能不能说明 Hysteria2 或 QUIC 可用？**

不能。Echo 只证明该端口存在一个会把相同载荷退回的应用层服务，并完成了这次会话校验。
QUIC 还有独立的 TLS 1.3 握手、证书验证、ALPN 和传输参数；这些都没有被 Echo 测试覆盖。
反之，Echo 超时也可能只是目标没有运行 Echo 服务，不能直接判成整条 UDP 路径故障。

**HTTP CONNECT 返回 407，是目标网站要求登录吗？**

不是。407 表示代理要求认证，PathTrial 不会猜测或发送凭据，只会记录 `auth_required`。
403 表示代理拒绝建立隧道，同样不是目标网站的 HTTP 403。只有隧道建立后收到的状态码才
属于目标响应。

**为什么两份报告被标成不可直接比较？**

`compare` 会检查目标、端口、profile、地址族、接口、超时、样本量和代理/直连属性。任一项
明显不同都会输出 `NOT DIRECTLY COMPARABLE`，并列出差异。它仍展示两侧观察值，但拒绝把
差异写成改善或恶化，因为条件已经改变。

## 测试

```bash
cargo test              # 单元测试 + 集成测试
cargo test --test golden   # 黄金数据集回归
cargo test --test schema   # JSON Schema 校验
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

黄金数据集在 `tests/fixtures/`，来自 2026 年 10 月一次真实的跨境链路排障记录，包含：

- 案例 A：IPv4 8/10 且平均 2476 ms，IPv6 10/10 且平均 323 ms，聚合数据，不得编造分布。
- 案例 B：TCP 18/20 成功但 TLS 0/20，必须与 TCP 结论分开。
- 案例 C：TCP 0/20，不得断言 IP 被封锁。
- 案例 D：ICMP 端口不可达、真实 UDP Echo、无效 QUIC 无响应三者不得混为一谈。
- 案例 E：单次超时只能给出 `INCONCLUSIVE`。

集成测试使用本地 TCP 监听器，不依赖公网。

## 设计说明

- **为什么要自己发 DNS 查询**：`getaddrinfo` 看不到解析器、rcode 和耗时，也无法识别 Fake-IP。
- **为什么 TLS 与证书分开记录**：传输握手完成但证书不被信任，和握手根本完不成，是两种完全不同的故障。
- **为什么要绑定网卡**：本机装 VPN 时，路由表会把探测送进 TUN，测出来的 1 毫秒是本地代理的回复，
  不是真实路径。
- **为什么输出 `SKIP` 而不是 `FAIL`**：没有服务端配合时，UDP 探测没有任何意义；把它算成失败会
  制造假结论。

## 发布状态

| 目标平台 | 构建 | 运行验证 |
| --- | --- | --- |
| macOS arm64 | 通过 | 本机真实网络扫描通过 |
| macOS x86_64 | 通过 | 未执行（构建机未安装 Rosetta，无法运行 Intel 二进制） |
| Linux x86_64 | 仅 CI 配置 | 未执行（本机无可信 Linux 交叉工具链） |

Linux 的构建与测试由 `.github/workflows/ci.yml` 在 `ubuntu-latest` 上以原生工具链执行。
仅存在工作流配置不等于 Linux 已经验证，转换正式版本前需要实际跑通一次。

## 公开分享前的检查

报告默认包含目标地址、DNS 解析器地址、网卡名、探测时间与逐次样本。这些是复核结论所必需的，
但同时也暴露了你的网络环境：

- 用 `--redact-ips` 把所有 IP 替换成稳定占位符；
- 发布前检查网卡名与解析器地址是否属于内网信息；
- 不要附带客户端配置、口令、私钥或订阅链接；
- 抓包文件不要与报告一起公开，除非已经逐包审查。

## 许可证

MIT，见 [LICENSE](LICENSE)。
