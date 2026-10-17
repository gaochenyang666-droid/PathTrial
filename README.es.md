# PathTrial

Herramienta de diagnóstico de red reproducible y basada en evidencia, escrita
en Rust. Esta es una entrada breve en español; la referencia completa está en
[README.md](README.md).

## Descarga

Consulta [GitHub Releases](https://github.com/gaochenyang666-droid/PathTrial/releases)
o compila el proyecto:

```bash
cargo build --release --locked
./target/release/pathtrial --version
```

## Plugins de IA

PathTrial AI Plugins v0.1 conecta Codex y Claude Code con un único servidor MCP
local y skills compartidos.

- Guía de integración: [docs/ai-integrations.md](docs/ai-integrations.md)
- Plugin de Codex: [plugins/codex/pathtrial](plugins/codex/pathtrial)
- Plugin de Claude Code: [plugins/claude-code/pathtrial](plugins/claude-code/pathtrial)

Inicia el servidor MCP con una lista explícita de destinos autorizados:

```bash
pathtrial mcp --allow-target example.com:443
```

No se necesita una clave de API de OpenAI ni de Anthropic para el diagnóstico
local.
