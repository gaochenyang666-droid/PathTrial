# PathTrial for Claude Code

This plugin bundles four skills and a local stdio MCP server.

## Requirements

- Install the PathTrial CLI from GitHub Releases or build it with Cargo.
- Verify `pathtrial --version` works in the environment that starts Claude Code.
- No Anthropic API key is required for local diagnostics.

## Probe authorization

Active probes are denied until the target is allowlisted in `.mcp.json`:

```json
"args": ["mcp", "--allow-target", "example.com:443"]
```

Repeat `--allow-target` for multiple targets. A desktop app that does not inherit the shell can use `~/.config/pathtrial/allow-targets` (or `%APPDATA%\pathtrial\allow-targets`). One explicit target per line, no wildcards. `pathtrial mcp --print-allow-path` prints the path only. The server itself enforces this boundary. Report explanation and report comparison do not require network authorization.

## Local validation

```bash
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
```

Install from the repository marketplace after reviewing the plugin files:

```text
/plugin marketplace add gaochenyang666-droid/PathTrial
/plugin install pathtrial@pathtrial
```

## Security

The server uses stdio, writes protocol messages only to stdout, logs to stderr, performs no shell execution, does not use sudo, does not scan ranges, does not modify system settings and does not upload reports.
