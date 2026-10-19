# PathTrial — Open-source Network Diagnostics CLI & MCP Plugins for Codex / Claude Code
**PathTrial is an open-source Rust network diagnostics CLI and local MCP server** for DNS troubleshooting, website connectivity checks, VPS port testing, proxy failures, and IPv4/IPv6, TCP, TLS, UDP, QUIC and HTTP/3 diagnostics. It exports evidence-backed JSON reports, runs independently on macOS and Linux, and integrates with Codex and Claude Code through local MCP plugins.
**Languages:** [简体中文](README.md) · **English** · [Español](README.es.md) · [Русский](README.ru.md)
[**Download v1.5.0-rc.1 prerelease**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1) · [**Report a bug**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**AI integration guide**](docs/ai-integrations.md) · [**CLI guide**](docs/cli.md)
> **Current release:** PathTrial Core `v1.5.0-rc.1` is a public release candidate with guided `diagnose` and local MCP support. AI Plugins `0.3.0` exposes ten tools. Prebuilt downloads cover macOS Apple Silicon, macOS Intel and Linux x86_64; installation does not require Rust.
> **Previous version:** [v1.4.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) remains available (nine MCP tools). v1.5 adds `pathtrial_diagnose`, and `pathtrial_explain_report` now accepts guided diagnosis reports.
> **Community beta testers welcome:** Codex and Claude Code plugins are now available on the default `main` branch. Please [report installation, compatibility or diagnostic issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) with redacted versions, reproduction steps and expected versus observed results.
## Diagnose DNS failures, VPS ports, proxies and IPv4/IPv6
A successful Ping does not prove that DNS, TCP, TLS, HTTP and the application are all healthy. PathTrial measures each layer separately, records the evidence, and states which causes remain unproven.
- **A website opens intermittently:** separate DNS, TCP connection, TLS handshake and HTTP status.
- **A VPS accepts connections but the proxy fails:** inspect TCP, UDP Echo, QUIC, HTTP/3 and proxy paths.
- **IPv4 and IPv6 behave differently:** compare success rates and latency with the same target, port, rounds and timeout.
PathTrial runs locally. It does not upload reports or change DNS, routes, firewall rules or proxy settings. Codex and Claude Code use the same diagnostic engine through a local MCP server. Every network probe is denied until its target is explicitly authorized.
## Guided diagnosis entry point (v1.5 release candidate)
The v1.5 prerelease includes `pathtrial diagnose`, combining DNS, TCP, TLS, HTTP, latency, packet loss, dual-stack, UDP/QUIC, proxy, and local-network checks into ten common problem categories:
~~~bash
pathtrial diagnose --scenario web example.com
pathtrial diagnose --scenario vps YOUR_VPS_IP --port 22
pathtrial diagnose --scenario latency example.com --rounds 10
pathtrial diagnose --scenario proxy --url https://example.com/ --proxy socks5://127.0.0.1:1080
pathtrial diagnose --scenario local
~~~
Focused scenarios also include `dns`, `tcp`, `tls`, `http`, `dual-stack` and `udp-quic`. Reports separate `observed`, `possible`, `not_established` and `next_checks`; hypotheses are never presented as confirmed root causes.
## Install the AI plugins
> **Public release candidate:** Install the PathTrial executable before installing the Codex or Claude Code plugin. A plugin does not install the diagnostic engine. Network probes are denied by default until a target is explicitly authorized.
### Step 1: Install PathTrial (no Rust required)
Download and review the installer included in the [v1.5.0-rc.1 release](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1):
~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
pathtrial mcp --help
~~~
Confirm version `1.4.0-rc.1` and a working `pathtrial mcp --help`. The `pathtrial` executable must also be visible in the `PATH` inherited by your AI client.
### Step 2: Choose an AI client
#### OpenAI Codex plugin
Install the plugin from the default `main` marketplace:
~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial
codex plugin add pathtrial@pathtrial
codex plugin list
codex mcp list
~~~
The v1.5 plugin `0.3.0` includes ten MCP tools and allows `pathtrial_explain_report` to explain guided diagnose results. First prompt: *“Call `pathtrial_capabilities` and verify the available MCP tools.”*
#### Claude Code plugin
Inside Claude Code, add the repository marketplace and install the plugin. Use `/mcp` to inspect the tools:
~~~text
/plugin marketplace add gaochenyang666-droid/PathTrial
/plugin install pathtrial@pathtrial
/mcp
~~~
See the [AI integration guide](docs/ai-integrations.md) for authorization and troubleshooting.
## First use
### 1. Authorize a target you are allowed to test
PathTrial MCP denies all network probes by default; analyzing existing JSON reports needs no network authorization. **For terminal-launched clients, set a temporary allowlist before starting your AI client**, rather than editing a version-specific marketplace plugin cache:
~~~bash
# Replace example.com:443 with your own authorized target
export PATHTRIAL_MCP_ALLOW_TARGETS="example.com:443"
codex
# To use Claude Code instead, run claude from this same terminal
~~~
`PATHTRIAL_MCP_ALLOW_TARGETS` accepts multiple explicit `host:port` entries separated by commas or spaces. The MCP server must inherit the variable. **Desktop apps launched via a GUI may not inherit the terminal environment**; use the client's MCP environment settings or an explicit `--allow-target` argument. See the [AI integration guide](docs/ai-integrations.md).
Do not use wildcards or scan systems without permission. Restart the AI client after changing authorization.
### 2. Ask in natural language
**Website is unreachable**
> Use PathTrial to diagnose example.com. Separate DNS, TCP, TLS and HTTP failures, then explain the result in plain English.
**Compare IPv4 and IPv6**
> Compare IPv4 and IPv6 success rates and latency for my VPS. Keep the port, rounds and timeout identical, and cite the measured evidence.
**Explain an existing report**
> Analyze this PathTrial JSON report. Identify anomalies, real evidence IDs and causes that the report cannot establish.
### 3. Read the result
Check `PASS`, `WARN`, `FAIL`, `SKIP` and `INCONCLUSIVE`. `SKIP` is not a pass. `INCONCLUSIVE` means the evidence is insufficient. PathTrial records each network layer and does not infer an ISP block or a specific lossy device from one Ping.
## Diagnostic coverage
DNS, IPv4/IPv6, TCP, TLS, HTTP, ICMP, route tracing, UDP Echo, QUIC, HTTP/3, SOCKS5, HTTP CONNECT, direct-versus-proxy comparison and two-ended collection correlation.
## Use PathTrial without an AI client
The same [public v1.5.0-rc.1 release candidate](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1) works as a standalone CLI without Rust, Codex or Claude Code. Choose a prebuilt archive:
- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)
Each archive has a SHA-256 checksum file. Use the installer above, or download and verify the archive yourself:
~~~bash
pathtrial --version
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~
See the [CLI guide](docs/cli.md) for HTTP, QUIC, UDP, proxies, two-ended collection and exit codes.
## Beta status and known limits
- Core: `v1.5.0-rc.1` publicly released as a **release candidate, not a stable release**.
- AI Plugins: `0.3.0` (ten tools); the previous v1.4 plugin used `0.2.0` (nine tools).
- Prebuilt archives: macOS ARM64, macOS Intel and Linux x86_64, all built successfully with SHA-256 files.
- Automated verification: the [v1.5 three-platform release workflow](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39255364100) passed packaging and MCP smoke tests. Codex HTTP/local model sessions were validated, and the project reported completing Claude Code model-session testing.
- Network probing requires explicit target authorization. Windows, a GUI and automatic network repair are not supported.
See the [engineering acceptance matrix](docs/ai-plugin-completeness.md) and [release workflow](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39149532255). Please [report reproducible beta issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md).
## Network diagnostics FAQ
### Website not loading: how do I tell DNS, TCP, TLS and HTTP failures apart?
For an authorized target, run `pathtrial scan example.com --profile web --rounds 5 --redact-ips`, followed by `pathtrial http https://example.com/` to inspect its HTTP response. Results are recorded by protocol layer; a successful Ping does not prove that the website works.
### Can PathTrial troubleshoot a VPS, IPv4/IPv6, SOCKS5 proxies and HTTP/3?
Yes. The CLI offers IPv4/IPv6, TCP/TLS, SOCKS5 and HTTP CONNECT proxy checks, QUIC handshakes, and real HTTP/3 requests when the server supports them. See the [CLI guide](docs/cli.md). A UDP timeout alone cannot establish the root cause.
### How do I use PathTrial with Codex or Claude Code via MCP?
Install the [v1.5.0-rc.1 prebuilt core](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1), then follow the [plugin steps](#install-the-ai-plugins) to add the marketplace from `main`. MCP runs through the local `pathtrial` executable; network targets must be explicitly authorized.
### Do I need Rust to install PathTrial? Is Windows supported?
No. The v1.5.0-rc.1 release provides prebuilt binaries for macOS Apple Silicon, macOS Intel and Linux x86_64. Windows is not yet supported. Rust is only needed for source development or compilation.
### How is PathTrial different from ping or curl?
`ping` primarily tests ICMP reachability and `curl` is commonly used for HTTP requests. PathTrial separates DNS, TCP, TLS, HTTP, UDP and QUIC measurements into bounded probes, cites actual observations in JSON reports and does not claim a root cause from a single failure.
## Report bugs and contribute
Use [GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) for installation failures, incorrect results, crashes, unclear documentation and compatibility problems. Remove real IP addresses, domains, tokens, keys, cookies, proxy subscriptions and sensitive capture data before posting.
Reproducible bugs, tests and improvements are welcome. Read [AGENTS.md](AGENTS.md) before submitting code, then run the required formatting, Clippy and test checks.
## Developer documentation and license
- [AI integration and authorization](docs/ai-integrations.md)
- [Advanced CLI guide](docs/cli.md)
- [AI Plugins completeness](docs/ai-plugin-completeness.md)
- [Project and schema index](llms.txt)
- [PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1) · [PR #2](https://github.com/gaochenyang666-droid/PathTrial/pull/2)
PathTrial is released under the [MIT License](LICENSE). The project grew out of a [RackNerd VPS IPv4/IPv6 troubleshooting case](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting). Historical case data was not generated by PathTrial; separate the historical record from tool measurements.
