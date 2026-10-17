# Security policy

## Reporting a vulnerability

Please open a private security advisory or contact the maintainer directly
rather than filing a public issue. Include the version (`pathtrial --version`),
platform, and a minimal reproduction.

## What PathTrial does with data

- Probes are sent only to the target the user names (and the addresses its
  normal DNS resolution returns).
- No telemetry, no analytics, no remote API calls.
- Reports contain the target, timings, error categories, certificate metadata
  and local interface names. They never contain credentials.
- Proxy environment variables are noted by name only, never by value.
- `--redact-ips` replaces every IP literal with a stable placeholder
  (`<ipv4-1>`, `<ipv6-1>`, ...), including addresses embedded in error text.

## Deliberate design choices with security impact

- `--allow-insecure-tls` performs a second handshake without certificate
  verification. It exists only to separate "transport failed" from "trust
  failed", is off by default, and every such probe is labelled
  `insecure_retry: true` in the report.
- The tool never edits DNS, routes, firewall rules, proxies or any other system
  configuration.
- `--bind-interface` on Linux requires `CAP_NET_RAW` because `SO_BINDTODEVICE`
  is privileged. The failure is reported, never bypassed.

## Scope

PathTrial is a diagnostic client. It does not protect you from a hostile
network, and its measurements describe one client, one path and one time
window. Treat reports as evidence, not as a security audit.
