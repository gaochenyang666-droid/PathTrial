---
name: ipv4-ipv6-comparison
description: Compare IPv4 and IPv6 reachability for the same authorized target without turning unlike measurements into a false improvement claim.
---

# IPv4 and IPv6 comparison

Use this skill for reports such as “IPv4 is slow but IPv6 works”, “the VPS has different IPv4 and IPv6 entries”, or “DNS returns both families”.

## Required checks

1. Confirm both address families are actually assigned and reachable.
2. Run `pathtrial_scan` twice with `address_family` set to `ipv4` and `ipv6`.
3. Keep the same target, port, profile, timeout, max seconds and rounds.
4. Record the actual probe time window. Do not call two measurements a same-minute comparison unless the windows overlap.
5. Call `pathtrial_compare_reports` with the two report objects.
6. Read its comparability verdict before describing a change.

## Fake-IP and TUN

If an address is in `198.18.0.0/15`, suspect a local proxy rewrite. Mark the result `INCONCLUSIVE` unless the user deliberately measured the local proxy path. Do not turn a local Fake-IP response into a public-path conclusion.

## Reporting

State separately:

- IPv4 sample count, success count and median when available.
- IPv6 sample count, success count and median when available.
- Missing family, DNS limitation or Fake-IP suspicion.
- What remains unproven, including packet-loss location and whether a middlebox filtered traffic.

Do not say “IPv6 fixed the network” from one comparison.
