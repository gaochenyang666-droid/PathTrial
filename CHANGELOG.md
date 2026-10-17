# Changelog

All notable changes to PathTrial. The format follows Keep a Changelog, and the
project uses semantic versioning for both the binary and the report schema.

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
