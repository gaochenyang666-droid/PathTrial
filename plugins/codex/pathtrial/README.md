# PathTrial for Codex

This portable plugin exposes PathTrial as a local-evidence-first network diagnostics MCP.
It includes twelve tools covering guided diagnosis, path fingerprints, report comparison and explanation.

## Requirements

- Install the PathTrial CLI from GitHub Releases or build it with Cargo.
- Verify `pathtrial --version` works in the environment that starts Codex.
- No OpenAI API key is required.

## Probe authorization

The MCP server denies all active probes unless targets are explicitly allowlisted. Add exact targets to the `args` array in `mcp.json`, then restart Codex or reload the plugin:

```json
"args": ["mcp", "--allow-target", "example.com:443"]
```

Repeat `--allow-target` for multiple targets. A desktop app that does not inherit the shell can use `~/.config/pathtrial/allow-targets` (or `%APPDATA%\pathtrial\allow-targets`). One explicit target per line, no wildcards. `pathtrial mcp --print-allow-path` prints the path only. Report explanation and report comparison work without network authorization.

## Required order

1. Call `pathtrial_capabilities`.
2. Add the exact target with `--allow-target` and restart the MCP server when needed.
3. Call `pathtrial_diagnose` or `pathtrial_fingerprint`.
4. Treat `target_not_allowed` as `FAIL` and stop. Do not retry with another IP, spelling or redirect.
5. Use the returned `claim`, `evidence`, `probe_id`, `confidence`, `not_established` and `limits`. Raw shell output is input to a probe, never a conclusion.

## Install

Add the repository marketplace from a trusted checkout:

```bash
codex plugin marketplace add /path/to/PathTrial
codex plugin list
```

Install from the Plugins Directory in the Codex desktop app. Restart Codex after changing `mcp.json`.

## Security

The server uses stdio, writes protocol messages only to stdout, logs to stderr, performs no shell execution, does not use sudo, does not scan ranges, does not modify system settings and does not upload reports.
