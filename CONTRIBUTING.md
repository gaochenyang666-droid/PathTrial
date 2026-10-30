# Contributing

## Ground rules

1. **No fabricated data.** Fixtures must come from real observations, or be
   clearly labelled as synthetic input. Never edit a recorded result to make a
   test pass.
2. **Every conclusion needs evidence.** A new rule must cite probe IDs that the
   run actually produced, and must state what it does *not* establish.
3. **No silent fallbacks.** If interface binding, DNS or TLS cannot be done as
   requested, report it. Do not degrade to a different measurement and keep the
   original label.
4. **Keep scope explicit.** Windows x86_64 is in scope with the limits in
   `docs/windows.md`. Do not mark an unsupported Windows probe VERIFIED.
   Automatic packet-capture analysis stays out of scope. QUIC and dual-end
   reports must preserve their documented evidence limits.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --locked --all-targets -- --test-threads=1
cargo build --release
scripts/sync-plugin-skills.sh --check
```

All checks must pass before a change is proposed. CI runs them on Ubuntu 24.04,
macOS ARM, macOS Intel, and Windows x86_64. A Windows job that has not gone
green yet is not a VERIFIED Windows result.

MCP protocol tests live in `tests/mcp.rs`; plugin manifest and Skills checks
live in `tests/plugins.rs`. The shared Skills under
`plugins/shared/skills/` are authoritative. Run `scripts/sync-plugin-skills.sh`
after editing them and commit both generated copies.

## Adding or changing a rule

1. Pick the next `R0NN` identifier and document the threshold as a named
   constant at the top of `src/analysis/mod.rs`.
2. Give the finding a claim, evidence, `not_established`, confidence and limits.
3. Add a fixture under `tests/fixtures/` and a test in `tests/golden.rs`.
4. If the report shape changes, update `schemas/report.schema.json` and bump the
   schema version. Additive changes are a minor bump; removed or renamed fields
   require a major bump and a compatibility note in `CHANGELOG.md`.

## Adding a probe

- Record one `Probe` per attempt with a stable ID.
- Classify errors into the existing `NetError` categories; add a new category
  only when the distinction changes a conclusion.
- Keep probes bounded: no scanning, no credential attempts, and respect
  `--max-seconds`.
- Never write to system configuration.
- QUIC probes must separate transport, certificate, ALPN and HTTP/3 failures.
- Dual-end collection must write independent JSON and must not claim a packet
  loss location without capture evidence.

## Fixtures

`tests/fixtures/` is the regression contract. Each file is aggregate data with
an explicit `provenance` field. When only aggregates exist, the analyser must
not invent medians or percentiles, and the test must assert that limitation.

## Commit messages

Use conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Keep the
reason in the body when the change touches measurement semantics.
