# PathTrial

Evidence-first, reproducible network diagnostics CLI written in Rust.

This is a short English entry page. The full reference remains in
[README.md](README.md).

## Download and build

See [GitHub Releases](https://github.com/gaochenyang666-droid/PathTrial/releases)
or build from source:

```bash
cargo build --release --locked
./target/release/pathtrial --version
```

## AI Plugins

PathTrial AI Plugins v0.1 connects Codex and Claude Code to the same local MCP
server and shared skills.

- Integration guide: [docs/ai-integrations.md](docs/ai-integrations.md)
- Codex plugin: [plugins/codex/pathtrial](plugins/codex/pathtrial)
- Claude Code plugin: [plugins/claude-code/pathtrial](plugins/claude-code/pathtrial)

Start the MCP server with an explicit target allowlist:

```bash
pathtrial mcp --allow-target example.com:443
```

No OpenAI or Anthropic API key is required for local diagnostics.
