# PathTrial

**Evidence-First Network Diagnostics CLI**

**Languages:** [简体中文](README.md) · **English** · [Español](README.es.md) · [Русский](README.ru.md)

> **Public beta / Release Candidate — v1.3.0-rc.1**
>
> PathTrial is actively being tested. Bugs, misleading diagnostics, installation problems, and documentation issues are possible. **Please try it, report bugs, and suggest improvements.** You do not need to know Rust to help.
>
> [**Download beta**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**Report a bug**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Open issues**](https://github.com/gaochenyang666-droid/PathTrial/issues) · [**Real-world case study**](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting)

## What is PathTrial, and who is it for?

Why does a website fail even though its server responds to Ping? Why can a VPS accept a TCP connection while a proxy fails? Why might IPv6 work better than IPv4?

**PathTrial is a free, open-source command-line tool** that checks network layers separately (DNS, TCP, TLS, HTTP, and more), records the evidence, and produces reports you can inspect or attach to a support ticket.

- **Useful for:** beginners troubleshooting connectivity, VPS operators, self-hosted services, proxy setups, and IPv4/IPv6 comparisons.
- **No Rust needed to install:** prebuilt binaries are available for supported platforms. No account or cloud upload is required.
- **No hidden changes:** PathTrial does not change your DNS, routes, firewall, or proxy configuration.
- **Not an automatic repair tool:** it reports observed behavior and states what the evidence cannot establish.
- **CLI only:** there is no graphical interface yet. Test only systems you own or are authorized to test.

For example, if TCP succeeds but TLS fails, PathTrial reports those stages separately rather than calling the whole connection healthy.

## Step 1 — Download

### Pick your operating system

| Computer | Prebuilt download |
| --- | --- |
| Mac with Apple Silicon (M1/M2/M3/M4 and later) | [macOS ARM64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz) |
| Intel Mac | [macOS Intel x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz) |
| Linux on x86_64 (most Intel/AMD PCs and VPSs) | [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz) |

**Windows is not supported yet.** The [release page](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) also provides SHA-256 checksum files for each archive.

### Install without Rust (recommended)

Open **Terminal** on macOS or a shell on Linux, then run the following commands one at a time:

~~~sh
# Download the published installer
curl -fsSLo pathtrial-install.sh https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh

# Review the script before executing it
less pathtrial-install.sh

# Install: downloads the matching binary and verifies its SHA-256
sh pathtrial-install.sh
~~~

The installer places the executable at **~/.local/bin/pathtrial** without sudo. If you have reviewed and trust the installer, a one-line alternative is:

~~~sh
curl -fsSL https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh | sh
~~~

Executing a downloaded script directly has security implications. The archive checksum verifies the downloaded archive; it does not independently establish the installer's trustworthiness.

**Prefer manual installation?** Download an archive above, extract it, locate the executable named **pathtrial**, open a terminal in that directory and try **./pathtrial --version**. You can then place it in a directory on your PATH.

## Step 2 — Check the installation

~~~sh
~/.local/bin/pathtrial --version
~/.local/bin/pathtrial --help
~~~

For this beta, the expected version is **1.3.0-rc.1**. If the shell says **command not found**, use the full path above, or add the installer directory to PATH for the current session:

~~~sh
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
~~~

If you manually extracted the archive, substitute the actual executable path.

## Step 3 — Run your first diagnostic

Start with a short scan of a public example site:

~~~sh
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

If needed, replace **pathtrial** with **~/.local/bin/pathtrial**.

What the options mean:

- **example.com** — the domain to test. Replace it with your authorized target.
- **--profile web** — use the web/TLS diagnostic profile.
- **--rounds 5** — start with five connection attempts per applicable address family.
- **--redact-ips** — mask IP addresses in the resulting report before sharing it.

The fixed scan stages are **system information → DNS → TCP/TLS → IPv4/IPv6 comparison → report**.

**A successful TLS handshake does not prove an HTTP page loads.** Test an actual HTTP response separately:

~~~sh
pathtrial http https://example.com/
~~~

To troubleshoot your own VPS's SSH port:

~~~sh
pathtrial scan YOUR_VPS_IP --profile ssh --port 22 --rounds 5 --redact-ips
~~~

Replace **YOUR_VPS_IP** with your real server address. Do not include angle brackets.

## Step 4 — Understand the results and reports

| Status | Meaning |
| --- | --- |
| **PASS** | This particular check met its expected condition |
| **WARN** | The check received a result but found an anomaly |
| **FAIL** | The check did not meet its expected condition |
| **SKIP** | The check was not applicable or could not be performed; **not a pass** |
| **INCONCLUSIVE** | A check ran, but the evidence is insufficient for a conclusion |

By default, **scan** writes two files in your **current working directory**:

- `pathtrial-report-<run_id>.md` — a readable Markdown report for people and support tickets.
- `pathtrial-report-<run_id>.json` — structured evidence for analysis or bug reports.

To find the Markdown file:

~~~sh
ls pathtrial-report-*.md
~~~

To display Markdown directly without writing report files:

~~~sh
pathtrial scan example.com --format markdown --no-files
~~~

Use **--format json** for JSON output. Every conclusion should distinguish its supporting observations from causes that have **not** been established. A single failed probe does not identify an ISP, a filtering device, or the exact hop where traffic was lost.

Exit codes: **0** no WARN/FAIL, **1** tool error, **2** WARN/FAIL present, **3** inconclusive. An exit code is not an overall internet-health score.

## Step 5 — Choose a specific test

Start with **scan** and **http**. Use more specific commands only when you need them:

| Goal | Example |
| --- | --- |
| Compare DNS resolver answers | pathtrial dns example.com --server 223.5.5.5 |
| Ping and latency | pathtrial ping 1.1.1.1 --count 5 |
| Trace the route | pathtrial trace example.com --max-hops 15 |
| Check TCP/SSH on your VPS | pathtrial scan YOUR_VPS_IP --port 22 --profile ssh |
| Expect an HTTP 200 response | pathtrial http https://example.com/ --expect-status 200 |
| Test an actual QUIC handshake | pathtrial quic example.com --port 443 --alpn h3 |
| Request a page over HTTP/3 | pathtrial http3 https://example.com |
| Compare two saved reports | pathtrial compare old.json new.json |

**For QUIC/HTTP3:** the destination must support that protocol and your UDP path must work. A handshake timeout alone does not prove the destination lacks HTTP/3.

### SOCKS5 or HTTP CONNECT proxy

If you already run an authorized local SOCKS5 proxy on port 1080:

~~~sh
pathtrial proxy https://example.com/ --proxy socks5://127.0.0.1:1080
~~~

Compare direct and proxy paths:

~~~sh
pathtrial proxy https://example.com/ --proxy socks5://127.0.0.1:1080 --compare-direct
~~~

For an HTTP CONNECT proxy, use a URL such as **http://127.0.0.1:8080** instead. Proxy username/password authentication is not supported in this beta. A successful proxy request does not prove long-term stability.

### Real UDP Echo: two terminal windows

**Terminal A** — start a temporary loopback-only server:

~~~sh
pathtrial endpoint --udp-echo --bind 127.0.0.1:39001
~~~

**Terminal B** — run the client:

~~~sh
pathtrial udp --target 127.0.0.1:39001 --mode echo
~~~

Press **Ctrl+C** in Terminal A to stop the server. This checks **local loopback only**. Remote tests require a compatible Echo server on a machine you are authorized to use. UDP Echo success does **not** establish QUIC or Hysteria2 success.

### Two-ended collection (advanced)

You can first try this on one machine using two terminals:

~~~sh
# Terminal A: listening side
pathtrial collect --role server --task-id demo --listen 127.0.0.1:39001 --max-seconds 30 --output server.json

# Terminal B: run within Terminal A's time window
pathtrial collect --role client --task-id demo --target 127.0.0.1:39001 --rounds 5 --output client.json

# After both collections finish
pathtrial correlate client.json server.json
~~~

This correlates **TCP connection events**, not packet captures. Without packet captures and clock synchronization, it cannot locate a specific device that dropped packets.

## AI Plugins for Codex and Claude Code

PathTrial AI Plugins v0.1 connects both clients to one local MCP server and one
shared set of skills. Probe tools are denied unless the target is explicitly
allowlisted.

- Integration guide: [docs/ai-integrations.md](docs/ai-integrations.md)
- Codex plugin: [plugins/codex/pathtrial](plugins/codex/pathtrial)
- Claude Code plugin: [plugins/claude-code/pathtrial](plugins/claude-code/pathtrial)
- Example: `pathtrial mcp --allow-target example.com:443`

The public `v1.3.0-rc.1` binary predates MCP. Use a `1.4.0-rc.1` build from this
branch for plugin validation. Claude Code runtime validation remains incomplete;
see the integration guide.

## Found a bug? Please tell us!

**The purpose of this public beta is to learn from real usage.** Reports of crashes, hangs, incorrect results, installation failures, unsupported environments, unclear instructions, or translation errors are all welcome. Feature suggestions are welcome too.

**[Open a bug report on GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md)**

A good report includes:

1. **Environment:** OS/version, CPU architecture, PathTrial version.
2. **Steps to reproduce:** the exact command, with sensitive details replaced by placeholders.
3. **Expected behavior:** what you thought would happen.
4. **Actual behavior:** error text, exit code, or screenshot.
5. **Frequency:** always, sometimes, or only under particular conditions.

**Protect your privacy:** remove passwords, tokens, SSH keys, subscription links, cookies, private URLs, and sensitive public/private addresses before posting. **--redact-ips** does not automatically sanitize every other field in your logs or reports.

The issue template may have Chinese field names. You can submit your report in **English or Spanish** (or Chinese).

## Supported platforms and known limitations

- **Available:** macOS Apple Silicon, macOS Intel, Linux x86_64; builds and tests have run on corresponding native CI runners.
- **Not yet available:** Windows, a graphical UI, automatic network repair, automatic packet capture, or identification of the exact device dropping traffic.
- **Fake-IP / TUN:** local proxy software can alter DNS and apparent direct paths; the tool reports when evidence may be misleading.
- **ICMP and UDP:** Ping failure does not prove TCP failure; ICMP Port Unreachable is not a successful UDP Echo response.
- **HTTP/3:** real requests have passed against a controlled local server; a particular public UDP 443 route may still time out.
- **Beta caution:** do not rely on this preview as your only production monitoring or troubleshooting signal.

**Source-version note:** the downloadable binary is built from [v1.3.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/tree/v1.3.0-rc.1). The repository's default **main** branch may temporarily lag behind the release; advanced features were developed in [Milestone C PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1).

**Language note:** these READMEs are translations of the **documentation**. They do **not** mean that all CLI output or generated reports are available in English or Spanish yet.

## For developers — Build from source

**For AI readers and coding agents:** [llms.txt](llms.txt) indexes project documentation and schemas; [AGENTS.md](AGENTS.md) describes development and evidence rules.

Rust stable is needed **only for source builds**, not for the downloads above. Check out the matching release tag:

~~~sh
git clone https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
git checkout v1.3.0-rc.1
cargo build --release --locked
./target/release/pathtrial --version
~~~

Run the checks:

~~~sh
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
~~~

Consult each subcommand's **--help** for more options. Please include a reproducible test when contributing a code fix.

## Background, license, and thanks

PathTrial grew out of a [real RackNerd VPS IPv4/IPv6 troubleshooting case](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting). The historical measurements predate the tool and **must not** be presented as measurements taken by PathTrial. There is also a [Chinese step-by-step case reproduction guide](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting/blob/main/docs/使用-PathTrial-复现排障.md).

Source code is released under the [MIT License](LICENSE). Issues, documentation corrections, and pull requests are welcome. **Thank you for helping test PathTrial.**
