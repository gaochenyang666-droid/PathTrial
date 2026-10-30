# PathTrial CLI Guide

This guide covers the standalone command-line interface. For Codex and Claude Code installation, authorization and MCP tools, see [AI integration](ai-integrations.md).

## Versions

- Public prebuilt CLI: `v1.5.0-rc.1`
- Published release candidate: `v1.5.0-rc.1` includes the guided `diagnose` subcommand in all three prebuilt distributions.
- MCP core included in the public release: `1.5.0-rc.1`
- AI Plugins: `0.3.0` (ten MCP tools)
- Core `1.5.0-rc.1` and AI Plugin `0.3.0` are compatible. The older [v1.4.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) release remains available.
- `v1.5.0-rc.1` includes `pathtrial mcp`; the older `v1.3.0-rc.1` does not.

Run `pathtrial --help` or `pathtrial <command> --help` for the options supported by your installed binary.

## Installation

Download an archive from the [v1.5.0-rc.1 release](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1), or review and run the release installer:

~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh

~/.local/bin/pathtrial --version
~~~

The installer uses `~/.local/bin/pathtrial` and does not require sudo. If `pathtrial` is not found, use the full path or add the directory to `PATH`:

~~~bash
export PATH="$HOME/.local/bin:$PATH"
~~~

Published `v1.5.0-rc.1` archives cover macOS Apple Silicon, macOS Intel, and Linux x86_64. Windows x86_64 is built by the release workflow for a later tag and installed with `scripts/install.ps1`. See [Windows](windows.md). That published tag does not contain `pathtrial-x86_64-pc-windows-msvc.tar.gz`.

## Status and exit codes

PathTrial uses five result states:

- `PASS`: the check met its expected condition.
- `WARN`: a response was observed, with an actionable concern.
- `FAIL`: the check did not meet its expected condition.
- `SKIP`: the check was not applicable. This is not a pass.
- `INCONCLUSIVE`: a measurement exists, but the evidence is insufficient for a conclusion.

Exit codes:

- `0`: no WARN or FAIL findings.
- `1`: tool execution error.
- `2`: a WARN or FAIL finding was recorded.
- `3`: the scan completed without enough evidence for a conclusion.

An exit code describes this run. It does not describe the general health of the internet or the remote service.

See the [troubleshooting guides](https://gaochenyang666-droid.github.io/PathTrial/en/guides/) for symptom-driven examples.

## Basic scan

~~~bash
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

The fixed scan order is system environment, DNS, TCP/TLS, IPv4/IPv6 comparison and report generation. Useful options:

- `--profile web`: Web and TLS-oriented checks.
- `--profile tcp`: TCP checks without TLS.
- `--profile ssh`: SSH port checks.
- `--rounds 5`: number of measurement rounds.
- `--timeout-ms 3000`: timeout for one connection attempt.
- `--max-seconds 30`: total wall-clock budget.
- `--redact-ips`: replace IP literals in output.

Use a target you own or have permission to test.

## Guided diagnosis

The published v1.5 release candidate provides `diagnose` for common user-facing scenarios. It composes the existing scanners and keeps source probe IDs prefixed as `<source>:<probe_id>`.

~~~bash
pathtrial diagnose --scenario web example.com
pathtrial diagnose --scenario vps VPS_IP --port 22
pathtrial diagnose --scenario latency example.com --rounds 10
pathtrial diagnose --scenario proxy --url https://example.com/ \
  --proxy socks5://127.0.0.1:1080
pathtrial diagnose --scenario local
~~~

Focused scenarios:

- `dns`
- `tcp`
- `tls`
- `http`
- `dual-stack`
- `udp-quic`

Useful options:

- `--format summary|json|markdown`
- `--rounds 1..50`
- `--timeout-ms`
- `--max-seconds`
- `--redact-ips`
- `--bind-interface`
- `--sni`
- `--requested-host` to keep the original hostname in the report
- `--http-host` to set the Host header when the connection target is a literal IP
- `--target-ip`, `--connect-ipv4` and `--connect-ipv6` to bind authorized addresses
- `--server` for DNS comparison
- `--latency-warn-ms` and `--latency-fail-ms` for environment-specific latency thresholds

The diagnosis separates `observed`, `possible`, `not_established` and `next_checks`. A possible cause is a hypothesis. It is not reported as a confirmed root cause.

The local scenario performs read-only inspection of interfaces, default routes, DHCP lease facts and available Wi-Fi metrics. Missing OS tools or permissions produce `SKIP` or `INCONCLUSIVE`, never a configuration change.

## HTTP

`scan` verifies transport and TLS behavior. It does not prove that the website returns the expected page.

~~~bash
pathtrial http https://example.com/
pathtrial http https://example.com/ --expect-status 200
pathtrial http https://example.com/ --format json
~~~

The result records DNS, TCP, TLS, time to first byte and the final total separately. A 4xx or 5xx response is an application response, not automatically a TCP failure.

## DNS, Ping and route tracing

~~~bash
pathtrial dns example.com --server 1.1.1.1
pathtrial ping 1.1.1.1 --count 5
pathtrial trace example.com --max-hops 15
~~~

Ping failure does not prove TCP failure. A timeout in a traceroute does not identify the device that dropped application traffic.

## QUIC and HTTP/3

~~~bash
pathtrial quic example.com --port 443 --alpn h3
pathtrial http3 https://example.com
~~~

The target must support QUIC/HTTP3 and the local UDP path must work. A handshake timeout does not prove that the server lacks HTTP/3. Certificate failures, ALPN mismatches and HTTP/3 application failures are reported separately.

## Proxy checks

Start an authorized proxy first. SOCKS5 without authentication:

~~~bash
pathtrial proxy https://example.com/ --proxy socks5://127.0.0.1:1080
~~~

HTTP CONNECT:

~~~bash
pathtrial proxy https://example.com/ --proxy http://127.0.0.1:8080
~~~

Compare direct and proxied paths while alternating requests:

~~~bash
pathtrial proxy https://example.com/ \
  --proxy socks5://127.0.0.1:1080 \
  --compare-direct
~~~

Proxy username/password authentication is not supported in this beta. A proxy success does not prove long-term stability or that the target application is healthy.

## UDP Echo

This checks an application-level Echo service. It does not test QUIC or Hysteria2.

Terminal A:

~~~bash
pathtrial endpoint --udp-echo --bind 127.0.0.1:39001
~~~

Terminal B:

~~~bash
pathtrial udp --target 127.0.0.1:39001 --mode echo --rounds 5
~~~

Stop Terminal A with `Ctrl+C`. For a remote machine, run a compatible Echo service only on infrastructure you control or are authorized to test.

## Two-ended collection

Two-ended collection correlates TCP connection events. It is not a packet capture.

Terminal A:

~~~bash
pathtrial collect --role server \
  --task-id demo \
  --listen 127.0.0.1:39001 \
  --max-seconds 30 \
  --output server.json
~~~

Terminal B, while Terminal A is still listening:

~~~bash
pathtrial collect --role client \
  --task-id demo \
  --target 127.0.0.1:39001 \
  --rounds 5 \
  --output client.json
~~~

Correlate both records:

~~~bash
pathtrial correlate client.json server.json
~~~

Without packet captures and synchronized clocks, the result cannot identify the exact device that dropped packets.

## Offline report view

`report render` reads a saved JSON file and writes HTML, SVG, or text. It does not contact the network and does not add samples.

~~~bash
pathtrial report render report.json --format html --out report.html --redact-ips
pathtrial report render report.json --format svg --out report.svg
~~~

`--redact-ips` masks addresses in the output only. The input file stays unchanged. HTML and SVG have no remote stylesheet or script.

## Local baseline

Baselines are opt-in and stay in the user data directory (`~/.local/share/pathtrial/baselines`, or `%LOCALAPPDATA%\pathtrial\baselines`). `baseline path` prints that directory.

~~~bash
pathtrial baseline save report.json --redact-ips
pathtrial baseline compare later.json --format json
~~~

The identity is the scan target, port, and profile, or the diagnose scenario and target. A different identity is not compared. `better`, `worse`, and `same` are used only when the two files are directly comparable; otherwise the relation is `not_established`. Evidence IDs come from the current file. Nothing is invented when no baseline exists. `--redact-ips` masks addresses inside the stored report copy. The identity key still contains the original target so the next compare can find the file. Exit code 2 means at least one `worse` relation. Exit code 3 means the files are not comparable.

## Temporary peer

On a machine you control:

~~~bash
sh scripts/peer.sh demo 0.0.0.0:39002 0.0.0.0:39001 120
~~~

The same action without the script:

~~~bash
pathtrial endpoint --peer \
  --task-id demo \
  --listen 0.0.0.0:39002 \
  --bind 0.0.0.0:39001 \
  --allow-public-bind \
  --max-seconds 120 \
  --output pathtrial-peer-collect.json
~~~

Loopback does not need `--allow-public-bind`. The peer does not change firewall, DNS, or routes, and the UDP echo does not store payloads. Stop it with Ctrl+C or wait for `--max-seconds`. Then copy the collect JSON and correlate it with the client file:

~~~bash
pathtrial correlate client.json pathtrial-peer-collect.json
~~~

## Reports and redaction

By default, `scan` writes unique Markdown and JSON report files in the current directory. Use `--no-files` to keep reports out of the filesystem, or select a format:

~~~bash
pathtrial scan example.com --format markdown --no-files
pathtrial scan example.com --format json
~~~

`--redact-ips` uses stable placeholders for IP literals. It does not automatically remove domains, interface names, DNS server addresses, local paths, proxy URLs or other environment details. Review reports before sharing them publicly.

## Privacy

Do not attach API keys, private keys, proxy passwords, subscription links, cookies or unredacted private network reports to an issue. Test only systems you own or are explicitly authorized to test.

## Development checks

For a source checkout:

~~~bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --release --locked
~~~

See [AGENTS.md](../AGENTS.md) for repository rules and [llms.txt](../llms.txt) for the project index.
