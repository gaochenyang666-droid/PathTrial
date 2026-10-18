---
name: setup
description: Check the PathTrial CLI and MCP authorization before the first diagnostic run.
---

# PathTrial setup

1. Check that `pathtrial --version` succeeds. If the command is missing, point the user to the GitHub Releases download page. Do not download or execute a binary silently.
2. Call `pathtrial_capabilities` and report the available modules, unsupported features and current allowlist.
3. Explain that probe tools are denied until the MCP server is launched with an exact target allowlist, for example:

```bash
pathtrial mcp --allow-target example.com:443
```

4. Confirm the user understands that this is a local process, uses no API key, stores no credentials and does not modify system settings.
5. If the user wants Windows support, report it as unavailable rather than suggesting an incompatible binary.
