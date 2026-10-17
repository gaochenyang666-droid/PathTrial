# Changelog

All notable changes to PathTrial. The format follows Keep a Changelog, and the
project uses semantic versioning for both the binary and the report schema.

## [1.2.0-rc.1] - 2026-10-17

Milestone B: UDP echo and proxy tunnels.

### Added

- **M09 UDP Echo**: `udp --target HOST:PORT --mode echo` sends datagrams with a
  magic marker, session id and sequence number, and only counts a byte-identical
  reply as a success. ICMP unreachable, timeout, wrong sequence, invalid payload
  and duplicates are separate categories. `endpoint --udp-echo` provides a
  loopback-only echo service for repeatable tests.
- **M11 SOCKS5**: `proxy URL --proxy socks5://host:port` performs the RFC 1928
  no-auth greeting, CONNECT and then the real request through the tunnel.
  Authentication requests are reported, never guessed. Literal IPv4 and IPv6
  targets use ATYP 1 and 4; names use ATYP 3 for proxy-side resolution.
- **M11 HTTP CONNECT**: `http://` proxies perform a bounded CONNECT exchange,
  classify 403, 407 and 5xx separately, then run a real TLS and HTTP exchange
  inside the tunnel. Proxy errors are never reported as target authentication
  failures.
- **B4 direct/proxy comparison**: `--compare-direct` alternates direct and
  proxied requests with the same URL and timeout, records both success rates
  and medians, and states that DNS, egress and routing can differ.
- **B5 report comparison**: `compare A.json B.json` checks target, port,
  profile, family, interface, timeout and sample size before presenting metric
  changes. Incompatible conditions produce `NOT DIRECTLY COMPARABLE`.
- Proxy credentials in the proxy URL are rejected instead of silently ignored.

### Changed

- Report schema **1.4.0** adds the `proxy` probe kind and `path_comparison`
  detail. Version 1.3.0 added `udp_echo` and `proxy_exchange`. All changes are
  additive.
- Proxy stage timings are measured separately. The previous build split one
  exchange in half, which could not be traced to real phase boundaries.
- URL userinfo and query strings are removed from reports and terminal output.
- `endpoint` refuses non-loopback binds unless `--allow-public-bind` is given.

### Verified

- 121 tests (65 unit, 41 CLI, 13 golden, 2 schema).
- Real SOCKS5 handshake against a local protocol double: tunnel + HTTP 200,
  IPv6 ATYP 4, bad version, CONNECT refusal, malformed bound address,
  auth-required and closed-port paths.
- Real HTTP CONNECT protocol exchange: 200, 403, 407, closed proxy, TLS failure
  after a successful tunnel, and a real rustls handshake carrying HTTPS 200.
- Real UDP echo: 5/5 with the local endpoint; a closed port reports
  `icmp_unreachable` with the correct limitations. IPv6 loopback is exercised
  when the host provides it.
- `compare` accepts older fixtures, rejects different targets, and writes JSON
  plus Markdown without overwriting existing files.

### Not verified in this increment

- Linux CI is configured for Ubuntu plus Intel and Apple Silicon macOS runners,
  but it has not been executed from this machine.
- QUIC, dual-end correlation and Windows remain out of scope.

## [1.1.0-rc.1] - 2026-10-17

Feature increment: real application-layer checks land as new subcommands.

### Added

- **M08 HTTP/HTTPS**: real GET over the same interface/family logic as `scan`.
  Records DNS, TCP, TLS, time-to-first-byte and total timings, status code,
  HTTP version and Location. Redirects are recorded but not followed. 4xx/5xx
  are HTTP answers, never reported as transport failure; `--expect-status`
  turns a mismatch into FAIL.
- **M05 ICMP**: `ping` drives the system `ping` binary (no root needed), records
  loss, RTT min/avg/max and jitter, and states that ICMP silence does not imply
  TCP failure.
- **M04 traceroute**: `trace` drives `traceroute -n`, parses hops, per-hop RTT
  and timeouts, and reports SKIP with a reason when the tool is missing.
- **M02 DNS comparison**: `dns HOST --server ADDR...` compares the system
  resolvers with explicit servers, and never equates a difference with
  poisoning. Fake-IP answers are called out separately.
- `CommandReport` envelope for single-purpose commands: status, summary, probes
  and limitations in one JSON document.

### Changed

- Report schema **1.2.0** adds `http`, `icmp` and `trace` probe details. The
  change is additive; existing fields and rules are unchanged.
- DNS resolution is now bounded by two query timeouts and resolvers are
  deduplicated globally (scutil lists one entry per DNS scope).
- TLS probe timing now reports handshake time separately from total time.

### Not implemented in this release

- M09 UDP echo, M10 QUIC, M11 SOCKS5/HTTP CONNECT, M12 dual-end correlation and
  Windows support. No command exposes them, so nothing can claim they passed.

### Verified

- 87 tests (52 unit, 20 CLI, 13 golden, 2 schema).
- macOS arm64: real HTTP (local 200/404/refused), DNS, ICMP and traceroute runs.
- macOS x86_64 and Linux: build/CI only in this increment.

## [1.0.0-rc.2] - 2026-10-17

### Fixed

- **R015 semantics.** A connection refused used to be reported as PASS because
  "something answered". That was wrong: the requested port is not connectable.
  R015 now fails the TCP check, the stage is FAIL, and the process exits 2. The
  claim records the refusal and does not assert that the remote host or its
  service is healthy; "the RST may come from an intermediate device" stays in
  `not_established`.
- A mixed refusal/timeout result is described by R004 with both error classes,
  not as a pure refusal.
- Fake-IP targets no longer produce TCP/TLS/latency verdicts: those numbers
  describe the local proxy, so the analysis now keeps only the R002 warning and
  states that the downstream conclusions were deliberately omitted.
- The overall verdict now also considers stage statuses, so a failing stage
  cannot hide behind an unrelated PASS. Terminal, Markdown and JSON share the
  same precedence.
- Added an overall verdict line to the terminal summary and the Markdown report.
- `--bind-interface` with an unknown interface is now a tool error (exit 1)
  instead of a scan where every probe fails for a configuration reason.

### Added

- Golden fixtures J (refused plus timeouts), K (partial refusals) and L (healthy
  target), plus CLI tests for closed ports, profile differences, per-attempt
  timeout bounds and budget-driven round reduction.

### Verified

- 71 tests (42 unit, 14 CLI, 13 golden, 2 schema).
- macOS arm64: built and exercised against real network targets.
- macOS x86_64: release build succeeds; runtime not exercised here because
  Rosetta is not installed on the build machine.
- Linux: CI workflow only. A local cross build would require a third-party
  Homebrew cross toolchain; that tap was not trusted or installed.

## [1.0.0-rc.1] - 2026-10-17

Release candidate: feature complete for the five-stage V1 scope.

### Added

- `--bind-interface` to pin probe egress to a physical interface. macOS uses
  `IP_BOUND_IF` / `IPV6_BOUND_IF`, Linux uses `SO_BINDTODEVICE`. Binding failure
  is reported as an error; the tool never silently falls back to the default
  route.
- `--sni` so a literal IP target can be tested with a real TLS server name.
- `--out PREFIX` for an explicit report path, with documented overwrite
  behaviour.
- Report files are now named `pathtrial-report-<run_id>.json/.md` so consecutive
  scans never overwrite each other.
- Address scopes (public, private, shared CGNAT, loopback, link-local,
  benchmark, documentation, unspecified) in `net::scope_of`.
- Rule R014: a non-public target is recorded as a normal measurement of a local
  or intranet path instead of being marked inconclusive.
- Latency findings now carry a confidence derived from the number of
  *successful* samples, and state that limit explicitly.
- Golden fixtures F (certificate failure), G (single success), H (latency gap
  with equal success rates).

### Changed

- R002 now only fires for `198.18.0.0/15` and `0.0.0.0`. RFC 1918 answers are no
  longer treated as evidence of Fake-IP rewriting.
- A hostname resolving into private space is measured normally and annotated,
  rather than being forced to INCONCLUSIVE.
- TCP, TLS transport and certificate verification remain three separate
  records; run summaries keep them separate as well.
- Report schema bumped to **1.1.0**. The change is additive: the only new field
  is the optional `configuration.bind_interface`. Reports from 1.0.0 remain
  readable, and `schema_version` is checked by tests.

### Fixed

- Bound TCP connects ignored `--timeout-ms`: `SO_SNDTIMEO` does not bound
  `connect()` on macOS, and one attempt observed in the field took about 70 s.
  The connect path now uses a non-blocking socket, a deadline anchored before
  `connect`, and `poll` with the remaining time.
- `poll` returning `EINTR` is retried instead of being reported as a failure,
  and a `connect` returning `EINTR` is treated as in-progress.
- `--max-seconds` no longer interacts with the per-attempt timeout: the budget
  reduces rounds between attempts, never the timeout of a single attempt.

### Verified

- 57 tests (39 unit, 7 CLI, 9 golden, 2 schema).
- `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` are clean.
- Release binary is about 1.5 MiB.
- Timeout audit on a lossy IPv4 path with `--timeout-ms 1200`: failed attempts
  took 1201 to 1206 ms, successful attempts were counted separately.

## [0.1.0] - 2026-10-17

First working build: five fixed stages, DNS/TCP/TLS probes, IPv4/IPv6
comparison, deterministic rules, JSON/Markdown reports, five golden fixtures.
