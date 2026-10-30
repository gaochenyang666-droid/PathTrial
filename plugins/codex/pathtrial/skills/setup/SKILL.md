---
name: setup
description: Check the PathTrial CLI and MCP authorization before the first diagnostic run.
---

# PathTrial setup

1. Check that `pathtrial --version` succeeds. If the command is missing, point the user to the GitHub Releases download page. Do not download or execute a binary silently.
2. Call `pathtrial_capabilities` and report the available modules, unsupported features and current allowlist.
   Confirm `pathtrial_diagnose` is listed and that `pathtrial diagnose --help` succeeds.
3. Explain that probe tools are denied until the MCP server is launched with an exact target allowlist, for example:

```bash
pathtrial mcp --allow-target example.com:443
```

4. Confirm the user understands that this is a local process, uses no API key, stores no credentials and does not modify system settings.
5. For a local network snapshot, `pathtrial_diagnose` with `scenario=local` requires no target authorization. It reads interfaces, routes, DHCP lease facts and available Wi-Fi metrics without changing them.
6. Desktop apps may not inherit `PATHTRIAL_MCP_ALLOW_TARGETS`. Tell the user to create a user-owned allow file instead of editing a marketplace cache. One explicit host or `host:port` per line. No wildcards or CIDR.
   - Linux and macOS: `$XDG_CONFIG_HOME/pathtrial/allow-targets` or `~/.config/pathtrial/allow-targets`
   - Windows: `%APPDATA%\pathtrial\allow-targets`
   - `pathtrial mcp --print-allow-path` prints that path and does not print the rules. A missing file stays default-deny.
7. Windows x86_64 is a build target with limits. The published `v1.5.0-rc.1` assets do not include a Windows binary. On Windows, `--bind-interface` is unsupported and must not fall back to another interface. ICMP jitter, per-target routes, and Wi-Fi dBm are not established. Do not describe `SKIP` as a pass.
