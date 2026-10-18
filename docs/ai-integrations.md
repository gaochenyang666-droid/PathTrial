# PathTrial AI Plugins

PathTrial AI Plugins v0.2 connects Codex and Claude Code to the existing
PathTrial diagnostic engine through one local MCP stdio server.

## Architecture

```text
Codex plugin ─┐
              ├─ shared Skills → pathtrial mcp → PathTrial probes → evidence report
Claude plugin ┘
```

- **PathTrial Core** performs DNS, TCP, TLS, HTTP, UDP Echo, QUIC, HTTP/3 and
  proxy measurements with the existing Rust implementation.
- **PathTrial MCP** exposes validated tool calls over stdio. Probe tools are
  blocked unless the target matches a startup allowlist. Capabilities reports
  only an address-free summary of that allowlist.
- **AI Plugins** contain client-specific manifests and the same shared Skills.

The plugin version is `0.2.0`. It is independent of the PathTrial CLI version.

## Requirements

- macOS ARM, macOS Intel or Linux x86_64.
- A `pathtrial` executable that includes the `mcp` subcommand.
- No OpenAI or Anthropic API key for local diagnostics.
- Network access only to targets the user explicitly authorizes.

The current `v1.3.0-rc.1` release predates the MCP subcommand. Until a later
binary is published, build from this branch:

```bash
cargo build --release --locked
export PATH="$PWD/target/release:$PATH"
pathtrial mcp --allow-target example.com:443
```

## Probe authorization

The MCP server starts with an empty allowlist. It permits capabilities,
report explanation and report comparison, and denies every probe until the
target is added:

```bash
pathtrial mcp --allow-target example.com:443
pathtrial mcp --allow-target 203.0.113.10:22 --allow-target api.example.com:443
```

The same rules can be supplied through
`PATHTRIAL_MCP_ALLOW_TARGETS`, separated by commas or spaces.

An entry without a port authorizes any port for that exact host or IP. A
hostname rule only authorizes public resolved addresses. A private, loopback
or Fake-IP target needs an exact IP and port entry. Wildcards are rejected.

The server also enforces:

- Maximum 50 rounds and 60 seconds per tool call.
- Ports limited to `1..65535`.
- DNS is resolved once, every candidate is validated, and the probe uses the
  returned literal IP. The original domain remains the TLS SNI and HTTP Host.
- Child probes have a separate hard timeout and bounded stdout/stderr readers.
  A client disconnect cancels and reaps the running probe child.
- MCP input messages are capped at 12 MiB; child output is capped at 8 MiB per
  stream.
- No CIDR, range scan, port enumeration or credential attempt.
- No shell execution, sudo, SSH login, firewall, DNS, route or proxy changes.
- No long-running listener, background service or report upload.
- Query strings, redirect query strings, URL user information and fragments are
  removed from reports and MCP tool results.

## Codex plugin

Plugin path:

```text
plugins/codex/pathtrial/
```

The repo marketplace is:

```text
.agents/plugins/marketplace.json
```

Add the marketplace and install the plugin from a trusted checkout:

```bash
codex plugin marketplace add /path/to/PathTrial
codex plugin add pathtrial@pathtrial
codex plugin list
```

The Codex desktop app can also show the repo marketplace in the Plugins
Directory. Restart Codex after changing `mcp.json`.

The plugin `mcp.json` starts:

```json
{
  "type": "stdio",
  "command": "pathtrial",
  "args": ["mcp"]
}
```

Add authorized targets to the `args` array:

```json
"args": ["mcp", "--allow-target", "example.com:443"]
```

## Claude Code plugin

Plugin path:

```text
plugins/claude-code/pathtrial/
```

The Claude marketplace is:

```text
.claude-plugin/marketplace.json
```

Expected install experience:

```text
/plugin marketplace add gaochenyang666-droid/PathTrial
/plugin install pathtrial@pathtrial
```

Validate and load the local package:

```bash
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
```

Add authorized targets to `plugins/claude-code/pathtrial/.mcp.json` in the
same way as the Codex plugin.

## MCP tools

| Tool | Network access | Purpose |
| --- | --- | --- |
| `pathtrial_capabilities` | No | Version, platform, modules, schemas, limits and an address-free authorization summary |
| `pathtrial_scan` | Authorized target only | Fixed five-stage scan |
| `pathtrial_http` | Authorized target only | Real HTTP/HTTPS request with phase timings |
| `pathtrial_quic` | Authorized target only | QUIC handshake, certificate, ALPN and timing |
| `pathtrial_http3` | Authorized target only | Real HTTP/3 GET after QUIC |
| `pathtrial_proxy_test` | Authorized target and proxy | SOCKS5, HTTP CONNECT and optional direct comparison |
| `pathtrial_udp_echo` | Authorized target only | Application-level Echo request and response check |
| `pathtrial_compare_reports` | No | Structured report comparison with comparability checks |
| `pathtrial_explain_report` | No | Deterministic evidence extraction from a report object |

All tool results include text content for the model and a `structuredContent`
object for deterministic downstream use.

`pathtrial_capabilities` reports the number of allow rules and whether the
configuration contains a hostname rule, a non-public literal address or a
portless rule. It does not return the configured hosts, addresses or ports.

`redact_ips=true` masks target and result IP literals in the MCP summary and
structured object. `insecure=true` is available only for explicit local
diagnostic tests; use normal certificate verification for real targets.
`compare_direct` requires a literal IP target in MCP so both paths remain bound
to the same authorized address.

## Examples

### Website not opening

```text
帮我检查 authorized.example.com 为什么打不开，先用低轮次扫描，再决定是否测试 HTTP 或 TLS。
```

Expected tool sequence:

1. `pathtrial_capabilities`
2. `pathtrial_scan` with `profile=web`
3. `pathtrial_http` if application status matters
4. Evidence summary with probe IDs and limitations

### IPv4 and IPv6 comparison

```text
帮我比较这台 VPS 的 IPv4 和 IPv6 连接情况，保持端口、轮次和超时一致。
```

Expected tool sequence:

1. Two `pathtrial_scan` calls with `address_family=ipv4` and `ipv6`
2. `pathtrial_compare_reports`
3. A conclusion gated by the comparability verdict

### Explain a report

```text
帮我分析这份 PathTrial JSON 报告，引用真实 evidence ID，并说明还缺什么证据。
```

Expected tool call: `pathtrial_explain_report`.

### English example

```text
Diagnose why this authorized host is unreachable. Start with a small scan,
separate TCP, TLS and HTTP evidence, and do not claim a packet-loss location.
```

## First use

1. Verify `pathtrial --version`.
2. Confirm `pathtrial mcp --help` lists `--allow-target`.
3. Add one exact target to the plugin MCP arguments.
4. Restart the AI client.
5. Call `pathtrial_capabilities` and review the authorization summary.
6. Try one target outside the allowlist and confirm `target_not_allowed`.
7. Run one low-round scan against the authorized target.
8. Review the structured report before requesting broader tests.

## Updates and removal

Codex:

```bash
codex plugin marketplace upgrade pathtrial
codex plugin remove pathtrial@pathtrial
codex plugin marketplace remove pathtrial
```

Claude Code:

```text
/plugin marketplace update pathtrial
/plugin uninstall pathtrial@pathtrial
/plugin marketplace remove pathtrial
```

The PathTrial CLI can remain installed after plugin removal.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `pathtrial` not found | Install the CLI or add its directory to `PATH` |
| `target_not_allowed` | Add the exact host or IP and port to the MCP arguments, then restart the client |
| Private IP denied | Authorize the exact IP and port; a public hostname rule doesn't cover loopback |
| No tools listed | Restart the client and check `codex mcp list` or the Claude `/mcp` panel |
| `SKIP` result | A required precondition was absent; it is not a pass |
| `HTTP 403/500` | The server answered; inspect the application status separately from network reachability |
| QUIC handshake succeeds but HTTP/3 fails | Keep the failure at the HTTP/3 stage |
| Compare says not directly comparable | Use the same target, port, protocol, family, interface, timeout and sample count |

## Current verification status

| Item | Status |
| --- | --- |
| MCP initialize, tools/list, tools/call | Verified by 21 local protocol tests |
| Target allowlist rejection | Verified |
| Local scan, HTTP and report analysis through MCP | Verified |
| Shared skills identical in both plugins | Verified |
| Codex marketplace add and plugin install | Verified with a temporary `CODEX_HOME` |
| Codex MCP registration visible in `codex mcp list` | Verified |
| Codex model-driven tool calls in a live session | VERIFIED for v0.2.0: capabilities, authorized TCP scan 1/1, real `tcp_ipv4_001` explanation and unauthorized `target_not_allowed` denial |
| Claude Code manifest validation and live tool call | PARTIAL: official CLI 2.1.292 installed; plugin and marketplace validation pass; a live model tool call has not yet been recorded |
| Precompiled release containing `pathtrial mcp` | UNVERIFIED for `v1.3.0-rc.1`; build from this branch |
| Windows plugin support | UNVERIFIED, Windows core support is not implemented |

## Reporting bugs

Open an issue at
<https://github.com/gaochenyang666-droid/PathTrial/issues> with:

- PathTrial version and plugin version.
- Client name and version.
- The tool name and the exact redacted arguments.
- The JSON-RPC error or `structuredContent.error` object.
- Relevant limitations and `not_established` items.

Do not attach API keys, private keys, proxy passwords or unredacted private
network reports.

## References

- Codex plugin packaging: <https://developers.openai.com/plugins/build/plugins>
- Codex skills: <https://developers.openai.com/plugins/concepts/skills>
- Claude Code plugins: <https://code.claude.com/docs/en/plugins/overview>
- Claude Code manifest: <https://code.claude.com/docs/en/plugins/manifest-reference>
- Claude Code marketplace: <https://code.claude.com/docs/en/plugins/create-marketplace>
