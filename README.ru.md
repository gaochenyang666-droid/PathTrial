# PathTrial

Кроссплатформенная утилита диагностики сети на Rust с воспроизводимыми
доказательствами. Это краткая страница на русском языке; полное руководство
находится в [README.md](README.md).

## Загрузка

Смотрите [GitHub Releases](https://github.com/gaochenyang666-droid/PathTrial/releases)
или соберите проект:

```bash
cargo build --release --locked
./target/release/pathtrial --version
```

## Плагины для ИИ

PathTrial AI Plugins v0.1 подключает Codex и Claude Code к одному локальному
MCP-серверу и общим навыкам.

- Руководство: [docs/ai-integrations.md](docs/ai-integrations.md)
- Плагин Codex: [plugins/codex/pathtrial](plugins/codex/pathtrial)
- Плагин Claude Code: [plugins/claude-code/pathtrial](plugins/claude-code/pathtrial)

Запустите MCP-сервер с явным списком разрешённых целей:

```bash
pathtrial mcp --allow-target example.com:443
```

Для локальной диагностики не требуются ключи API OpenAI или Anthropic.
