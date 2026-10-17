# PathTrial

**语言 / Languages / Idiomas:** **简体中文** · [English](README.en.md) · [Español](README.es.md)

**Evidence-First Network Diagnostics CLI｜基于真实证据的网络诊断工具**

> 🧪 **公开测试版（Release Candidate）｜v1.3.0-rc.1**  
> PathTrial 仍在测试中，可能有 Bug、兼容性问题或不准确的诊断提示。**欢迎下载试用、提出建议、帮忙找 Bug！** 即使不懂 Rust，只要告诉我们“运行了什么、预期怎样、实际怎样”，就很有帮助。
>
> [**下载测试版**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**报告 Bug / 提建议**](https://github.com/gaochenyang666-droid/PathTrial/issues/new/choose) · [**查看已知问题**](https://github.com/gaochenyang666-droid/PathTrial/issues) · [**真实排障案例**](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting)

## 这是什么？适合谁用？

遇到“网站打不开”“VPS 的端口能连但代理不能用”“IPv4 很慢，IPv6 却正常”，通常不能只靠一次 Ping 找到原因。**PathTrial 是一个免费、开源的终端小工具**：按明确的步骤测量 DNS、TCP、TLS、HTTP 等环节，把每一步结果和证据记录下来，生成可分享的网络诊断报告。

- **适合**：普通用户初步排查网络、VPS/服务器维护、自托管服务、代理连接和双栈 IPv4/IPv6 排障。
- **不用**：安装 Python、Node.js，注册账号，上传数据，启动常驻服务。
- **不会**：擅自修改 DNS、路由、防火墙或代理设置，也不会把猜测写成确定的故障原因。
- **注意**：这是命令行工具（CLI），目前没有图形界面；诊断不等于自动修复。

**一个简单例子：** 如果 TCP 连接成功，但 TLS 握手失败，PathTrial 会分别记录这两件事，而不是简单地说“网络通了”或“服务器坏了”。测试时请使用你拥有或获授权的目标。

## 第一步：下载 PathTrial

### 1. 选择系统（目前不支持 Windows）

| 你的电脑 | 下载 |
| --- | --- |
| Mac（Apple Silicon，M1/M2/M3/M4 等） | [macOS ARM64 安装包](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz) |
| Mac（Intel 芯片） | [macOS Intel 安装包](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz) |
| Linux（x86_64，如大部分 Intel/AMD VPS） | [Linux x86_64 安装包](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz) |

每个压缩包都有对应的 SHA-256 校验文件，可在 [Release 页面](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) 下载。

### 2. 安装（推荐：先查看脚本，再运行）

在 Mac 打开“终端”（Terminal）；在 Linux 打开终端。依次粘贴运行：

~~~bash
# 下载官方 Release 中的安装脚本
curl -fsSLo pathtrial-install.sh https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh

# 建议先看一下脚本内容
less pathtrial-install.sh

# 确认后安装；脚本会下载对应平台的压缩包并校验 SHA-256
sh pathtrial-install.sh
~~~

安装位置是 **~/.local/bin/pathtrial**，不需要 sudo。熟悉命令行的用户也可以选择一行安装：

~~~bash
curl -fsSL https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh | sh
~~~

后一种写法会直接执行网络下载的脚本，建议先审查脚本；**压缩包的校验并不等于脚本本身的来源审计**。

**不想运行安装脚本？** 在上面的表格中下载压缩包，解压后找到名为 `pathtrial` 的可执行文件；在终端进入它所在的目录，用 `./pathtrial --version` 测试。你也可以自行把它放到 PATH 中的目录。

## 第二步：确认安装成功

~~~bash
~/.local/bin/pathtrial --version
~/.local/bin/pathtrial --help
~~~

正常情况下版本应显示 **1.3.0-rc.1**。如果输入 `pathtrial` 提示“command not found”，说明安装目录可能不在 PATH 中。你可以直接使用 **~/.local/bin/pathtrial**，或者在当前终端运行：

~~~bash
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
~~~

上面的 PATH 修改仅针对当前终端会话。如果使用的是安装包解压版，请把命令中的可执行文件路径换成你自己的路径。

## 第三步：第一次诊断（从这里开始）

先运行一个普通网站的 TCP/TLS 检查：

~~~bash
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

如果尚未配置 PATH，将开头的 `pathtrial` 改为 `~/.local/bin/pathtrial`。

这条命令会按固定顺序检查：**系统环境 → DNS → TCP/TLS → IPv4/IPv6 对照 → 报告**。

- `example.com`：要检测的域名，换成你自己要排查的网站即可。
- `--profile web`：按 Web/TLS 场景检测。
- `--rounds 5`：先用较少轮次试跑，便于快速熟悉操作。
- `--redact-ips`：输出报告时对 IP 进行替换，便于后续分享。

**重要：`scan` 的 TLS 通过不等于网站能正常返回页面。** 真正检测网页 HTTP 响应，请继续运行：

~~~bash
pathtrial http https://example.com/
~~~

只想排查自己的 VPS SSH（比如 TCP 22 端口）：

~~~bash
pathtrial scan YOUR_VPS_IP --profile ssh --port 22 --rounds 5 --redact-ips
~~~

把 `YOUR_VPS_IP` 替换为你自己的服务器 IP，注意命令不要带尖括号。

## 第四步：看懂结果与报告

每个检测项都可能出现以下状态：

| 状态 | 用简单的话解释 |
| --- | --- |
| **PASS** | 这项检查达到预期 |
| **WARN** | 有响应，但存在值得注意的异常 |
| **FAIL** | 这项检查未达到预期 |
| **SKIP** | 本次不适用或没有条件检测；**不等于通过** |
| **INCONCLUSIVE** | 检测了，但证据还不足以确定结论 |

`scan` 默认会在**运行命令的当前目录**生成两个文件：

- `pathtrial-report-<run_id>.md`：适合人阅读、发给维护人员。
- `pathtrial-report-<run_id>.json`：保留结构化证据，适合机器处理或提交 Bug。

查看当前目录中的 Markdown 报告：

~~~bash
ls pathtrial-report-*.md
~~~

要在屏幕上直接输出 Markdown：

~~~bash
pathtrial scan example.com --format markdown --no-files
~~~

也可以用 `--format json` 输出 JSON。文件内包含诊断结果、测量证据，以及**还无法证实的原因**。不要仅凭一次结果判断运营商封锁、线路丢包位置或服务商责任。

程序退出码：`0` 表示没有发现 WARN/FAIL；`1` 为工具执行错误；`2` 表示有 WARN/FAIL；`3` 表示证据不足。**退出码不代表整个互联网是否正常。**

## 第五步：根据问题选择功能

先学会 `scan` 和 `http` 就足够。遇到特定问题时，再使用这些命令：

| 你想检查什么 | 复制这个命令（替换示例地址） |
| --- | --- |
| DNS 解析结果 | `pathtrial dns example.com --server 223.5.5.5` |
| Ping 与延迟 | `pathtrial ping 1.1.1.1 --count 5` |
| 路由逐跳情况 | `pathtrial trace example.com --max-hops 15` |
| 服务器 TCP/SSH | `pathtrial scan YOUR_VPS_IP --port 22 --profile ssh` |
| 网站是否返回 HTTP 200 | `pathtrial http https://example.com/ --expect-status 200` |
| QUIC 握手 | `pathtrial quic example.com --port 443 --alpn h3` |
| 真实 HTTP/3 请求 | `pathtrial http3 https://example.com` |
| 两份报告对照 | `pathtrial compare old.json new.json` |

**注意：** QUIC/HTTP3 需要目标真实支持相应协议，且你的 UDP 路径可用；握手超时不能直接证明目标没有 HTTP/3。

### 如果你在使用 SOCKS5 或 HTTP 代理

先确保你自己的代理已经运行并监听对应端口（这里使用本机 1080 作为示例）：

~~~bash
pathtrial proxy https://example.com/ --proxy socks5://127.0.0.1:1080
~~~

比较直连与代理路径：

~~~bash
pathtrial proxy https://example.com/ --proxy socks5://127.0.0.1:1080 --compare-direct
~~~

如果使用的是 HTTP CONNECT 代理，可将代理地址换成 `http://127.0.0.1:8080`。当前版本**不支持代理用户名/密码认证**；代理通过也不能自动证明服务器长期稳定。

### 想测试真实 UDP Echo？需要两个终端

终端 A：启动临时本机测试服务（默认仅监听回环）：

~~~bash
pathtrial endpoint --udp-echo --bind 127.0.0.1:39001
~~~

终端 B：发出 Echo 测试：

~~~bash
pathtrial udp --target 127.0.0.1:39001 --mode echo
~~~

结束后在终端 A 按 **Ctrl+C** 停止服务。

这只验证**本机回环**。如需测试 VPS，需要在你有权限的远端部署兼容 Echo 服务，并确认地址、防火墙和端口授权。**UDP Echo 不是 QUIC/Hysteria2 测试**。

### 双端采集（进阶，先用本机练习）

分别打开两个终端，再运行关联命令：

~~~bash
# 终端 A：监听本机测试端口
pathtrial collect --role server --task-id demo --listen 127.0.0.1:39001 --max-seconds 30 --output server.json

# 终端 B：发送测试连接（在终端 A 的时间窗口内运行）
pathtrial collect --role client --task-id demo --target 127.0.0.1:39001 --rounds 5 --output client.json

# 双方采集完成后，关联结果
pathtrial correlate client.json server.json
~~~

这是 TCP 连接事件关联，不是自动抓包；没有抓包和时钟校准时，不能定位具体丢包设备。

## 找到 Bug 了？欢迎直接告诉我们！

**这正是公开测试版最需要的帮助。** 遇到崩溃、卡住、错误诊断、命令不符合说明、某个系统无法运行、安装失败、翻译不清楚，都欢迎反馈。建议或功能需求也可以提 Issue。

**[点这里提交 Bug（GitHub Issues）](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md)**

按以下顺序说明就可以，不需要写复杂的技术报告：

1. **环境**：系统（如 macOS 15 / Ubuntu 24.04）、CPU（ARM64 或 x86_64）、PathTrial 版本。
2. **你输入了什么命令**：敏感 IP、域名、Token、密码请替换为占位符。
3. **你原本希望发生什么**。
4. **实际上发生了什么**：报错、退出码、截图或简短日志。
5. **能否重复出现**：偶尔一次、每次都出现，还是有特殊条件？

提交前**请删除真实公网/内网地址、用户名、域名、代理配置、订阅链接、密钥、Cookie 和抓包敏感内容**。即使使用 `--redact-ips`，也要人工检查日志和报告是否仍泄露其他信息。不要把私密配置直接上传到公开 Issue。

如果你不确定是不是 Bug，也欢迎发 Issue 讨论。开发者会根据可复现的证据排查，但测试版不承诺每个环境都能立即定位根因。

## 目前的测试范围与已知限制

- **支持**：macOS Apple Silicon、macOS Intel、Linux x86_64；这些平台已在原生 CI 中运行构建和测试。
- **暂不支持**：Windows、图形界面、自动修改网络配置、自动抓包和具体网元级丢包定位。
- **Fake-IP / TUN**：本地代理可能影响 DNS 和“直连”测量；检测到可疑地址时会提示证据不足。
- **ICMP 与 UDP**：Ping 不通不代表 TCP 不通；收到 ICMP 端口不可达也不代表 UDP Echo 成功。
- **HTTP/3**：本地可控服务已完成真实握手与请求测试，但公共网络 UDP 443 仍可能因用户所处线路而超时。
- **本次是预发布**：欢迎体验，不建议在自动化生产监控中把它当作唯一判断依据。

**版本与源码说明：** 下载安装包对应 [`v1.3.0-rc.1` 标签](https://github.com/gaochenyang666-droid/PathTrial/tree/v1.3.0-rc.1)。默认 `main` 的源码可能暂时滞后于该测试版；QUIC/HTTP3 与双端关联的开发记录见 [Milestone C PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1)。如果要编译出与下载版相同的源码版本，请切换到该标签，而不是直接假设 `main` 相同。

## 给开发者：从源码构建与测试

需要 Rust 稳定工具链。请使用对应的发行标签：

~~~bash
git clone https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
git checkout v1.3.0-rc.1
cargo build --release --locked
./target/release/pathtrial --version
~~~

运行测试：

~~~bash
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
~~~

如需查看更具体的参数，以各命令的 `--help` 为准。提交代码修复时，请尽量附带能够复现问题的测试。

## 项目由来、许可证与致谢

PathTrial 来源于一次 [RackNerd VPS 的 IPv4/IPv6 真实排障经历](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting)。原案例包含 TCP、TLS、UDP、QUIC、双端抓包及业务验收的历史记录；**历史数据并非 PathTrial 在当时生成的测量结果**。想按该案例一步步测试，可阅读 [PathTrial 复现指南](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting/blob/main/docs/使用-PathTrial-复现排障.md)。

源代码采用 [MIT License](LICENSE)。欢迎提交 Issue、复现步骤、文档改进和 Pull Request。**感谢每一位愿意帮忙测试、指出问题的使用者。**
