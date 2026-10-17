# PathTrial repository instructions

## Product rule

Every diagnostic conclusion must trace to recorded probe data. Missing evidence
must remain `SKIP` or `INCONCLUSIVE`, never a guessed root cause.

## Development

Run before proposing changes:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets -- --test-threads=1
cargo build --release --locked
```

## Plugins

- Shared skills are authoritative under `plugins/shared/skills/`.
- After editing them, run `scripts/sync-plugin-skills.sh`.
- Codex package: `plugins/codex/pathtrial/`.
- Claude Code package: `plugins/claude-code/pathtrial/`.
- MCP entrypoint: `pathtrial mcp`.
- Probe tools require an exact `--allow-target` rule. Never add a wildcard or
  silent fallback.
- Do not add a generic file-reading or shell-execution MCP tool.

## Git

- Do not rewrite history or force push.
- Do not move or overwrite existing release tags.
- Do not auto-merge pull requests.
- Keep generated reports, credentials and private network logs out of commits.
