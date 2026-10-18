# PathTrial

**Let AI diagnose your network with real evidence.**

**Languages:** [简体中文](README.md) · **English** · [Español](README.es.md) · [Русский](README.ru.md)

[**Download CLI beta**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**Report a bug**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**AI integration guide**](docs/ai-integrations.md) · [**CLI guide**](docs/cli.md)

> **Status:** the public CLI is `v1.3.0-rc.1`. AI Plugins `v0.2.0` is a developer preview for core `1.4.0-rc.1`, with no public prebuilt package yet. The README is available in four languages; CLI output and generated reports are not fully translated.

## Why PathTrial?

A successful Ping does not prove that DNS, TCP, TLS, HTTP and the application are all healthy. PathTrial measures each layer separately, records the evidence, and states which causes remain unproven.

- **A website opens intermittently:** separate DNS, TCP connection, TLS handshake and HTTP status.
- **A VPS accepts connections but the proxy fails:** inspect TCP, UDP Echo, QUIC, HTTP/3 and proxy paths.
- **IPv4 and IPv6 behave differently:** compare success rates and latency with the same target, port, rounds and timeout.

PathTrial runs locally. It does not upload reports or change DNS, routes, firewall rules or proxy settings. Codex and Claude Code use the same diagnostic engine through a local MCP server. Every network probe is denied until its target is explicitly authorized.

## Install the AI plugins

> **Developer Preview:** installing a plugin does not install the diagnostic program. The current plugin requires a `1.4.0-rc.1` executable that supports `pathtrial mcp`. The public `v1.3.0-rc.1` binary cannot run MCP, and no public prebuilt `v1.4.0-rc.1` release exists.
>
> Until that release is available, the preview requires Rust 1.84+ and one source build. If you only need the stable CLI, skip to “Use PathTrial without an AI client”.

### Step 0: prepare a compatible PathTrial core

~~~bash
git clone --branch codex/ai-plugins-v0.1 --depth 1 https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
cargo build --release --locked
export PATH="$PWD/target/release:$PATH"

pathtrial --version
pathtrial mcp --help
~~~

The version should be `1.4.0-rc.1`. Make sure this directory is present in the `PATH` inherited by Codex or Claude Code.

### OpenAI Codex

Remote marketplace installation was verified with a temporary `CODEX_HOME`. `codex plugin list` should show version `0.2.0`, and `codex mcp list` should show `pathtrial` enabled.

~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial --ref codex/ai-plugins-v0.1
codex plugin add pathtrial@pathtrial

codex plugin list
codex mcp list
~~~

Then ask Codex:

> Call `pathtrial_capabilities` first and confirm the PathTrial version and all nine MCP tools.

### Claude Code

Claude Code runtime validation is still `UNVERIFIED`. The default `main` branch has no marketplace file, and remote branch installation has not been tested in a real Claude Code client. Use the officially supported local plugin loading flow:

~~~bash
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
~~~

Inside the session, open `/mcp` and check whether `pathtrial` is registered. The manifest and shared Skills pass structural tests; live Claude Code calls still require validation in a real environment.

## First use

### 1. Authorize a target you are allowed to test

The default `["mcp"]` configuration denies every network probe. Offline report explanation and comparison still work. To authorize one target, change the plugin’s `args` to:

~~~json
["mcp", "--allow-target", "example.com:443"]
~~~

- Installed Codex plugin: edit `~/.codex/plugins/cache/pathtrial/pathtrial/0.2.0/mcp.json`.
- Local Claude Code plugin: edit `plugins/claude-code/pathtrial/.mcp.json`.
- Repeat `--allow-target` for additional targets.
- Restart the AI client after editing the file.
- Do not use wildcards or test systems without permission.

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

The public `v1.3.0-rc.1` CLI can be installed without Rust. It does not include MCP and cannot be used by the AI plugins.

- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)

SHA-256 files are available on the [v1.3.0-rc.1 Release page](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1). Review the installer before running it:

~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh

~/.local/bin/pathtrial --version
~~~

Run a first scan:

~~~bash
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

`--redact-ips` produces a report that is safer to share. See the [CLI guide](docs/cli.md) for HTTP, QUIC, UDP, proxy, two-ended collection and exit-code details.

## Beta status and known limits

- PathTrial Core: `1.4.0-rc.1` development version.
- AI Plugins: `0.2.0` developer preview.
- Public prebuilt CLI: `v1.3.0-rc.1`, without MCP.
- Automated verification: 173 tests passed, with CI on Ubuntu 24.04, macOS ARM and macOS Intel.
- Codex: real model-driven calls passed on the `v0.1.0` baseline. `v0.2.0` passed installation and protocol checks; its model session was not rerun.
- Claude Code: manifest and plugin structure are verified. Live client loading and calls remain `UNVERIFIED`.
- AI Plugins engineering score: `74.0%`. This is an acceptance score, not diagnostic accuracy.

See the [AI Plugins completeness matrix](docs/ai-plugin-completeness.md) for evidence. Windows, a graphical interface, automatic network repair, automatic packet capture and exact loss-device attribution are not available. Fake-IP/TUN behavior, public UDP 443 and HTTP/3 reachability can still depend on the local network.

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
