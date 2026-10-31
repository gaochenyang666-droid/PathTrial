---
name: setup
description: Check the PathTrial CLI and MCP authorization before the first diagnostic run.
---

# PathTrial setup

1. Check that `pathtrial --version` succeeds. If the command is missing, point the user to the GitHub Releases download page. Do not download or execute a binary silently.
2. Call `pathtrial_capabilities` first and report the available modules, unsupported features and current allowlist.
   Confirm `pathtrial_diagnose`, `pathtrial_fingerprint` and `pathtrial_fingerprint_diff` are listed.
3. Explain that the next step is an exact target allowlist. Probe tools are denied until the MCP server is launched with that allowlist, for example:

```bash
pathtrial mcp --allow-target example.com:443
```

4. Confirm the user understands that this is a local process, uses no API key, stores no credentials and does not modify system settings.
5. For a local network snapshot, `pathtrial_diagnose` with `scenario=local` requires no target authorization. It reads interfaces, routes, DHCP lease facts and available Wi-Fi metrics without changing them.
6. Desktop apps may not inherit `PATHTRIAL_MCP_ALLOW_TARGETS`. Tell the user to create a user-owned allow file instead of editing a marketplace cache. One explicit host or `host:port` per line. No wildcards or CIDR.
   - Linux and macOS: `$XDG_CONFIG_HOME/pathtrial/allow-targets` or `~/.config/pathtrial/allow-targets`
   - Windows: `%APPDATA%\pathtrial\allow-targets`
   - `pathtrial mcp --print-allow-path` prints that path and does not print the rules. A missing file stays default-deny.
7. `v1.6.0` is the prerelease that packages Windows x86_64. `v1.5.0-rc.1` does not include that archive. On Windows, `--bind-interface` is unsupported and must not fall back to another interface. ICMP jitter, per-target routes, and Wi-Fi dBm are not established. Do not describe `SKIP` as a pass.
8. If a probe returns `target_not_allowed`, classify it as `FAIL` and stop. Do not retry another IP, hostname variant or redirect.
