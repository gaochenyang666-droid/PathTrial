# PathTrial for Codex

This portable plugin bundles four skills and the local PathTrial MCP server.

## Requirements

- Install the PathTrial CLI from GitHub Releases or build it with Cargo.
- Verify `pathtrial --version` works in the environment that starts Codex.
- No OpenAI API key is required.

## Probe authorization

The MCP server denies all active probes unless targets are explicitly allowlisted. Add exact targets to the `args` array in `mcp.json`, then restart Codex or reload the plugin:

```json
"args": ["mcp", "--allow-target", "example.com:443"]
```

Repeat `--allow-target` for multiple targets. Report explanation and report comparison work without network authorization.

## Install

Add the repository marketplace from a trusted checkout:

```bash
codex plugin marketplace add /path/to/PathTrial
codex plugin list
```

Install from the Plugins Directory in the Codex desktop app. Restart Codex after changing `mcp.json`.

## Security

The server uses stdio, writes protocol messages only to stdout, logs to stderr, performs no shell execution, does not use sudo, does not scan ranges, does not modify system settings and does not upload reports.
