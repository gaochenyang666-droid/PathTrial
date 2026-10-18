# PathTrial

**Позвольте ИИ диагностировать сеть по результатам реальных измерений.**

**Языки:** [简体中文](README.md) · [English](README.en.md) · [Español](README.es.md) · **Русский**

[**Скачать тестовый CLI**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**Сообщить об ошибке**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Руководство по интеграции с ИИ**](docs/ai-integrations.md) · [**Руководство по CLI**](docs/cli.md)

> **Статус:** публичный CLI имеет версию `v1.3.0-rc.1`. AI Plugins `v0.2.0` является предварительной версией для разработчиков и работает с ядром `1.4.0-rc.1`; публичного готового пакета пока нет. README доступен на четырёх языках, но вывод CLI и отчёты переведены не полностью.

## Зачем нужен PathTrial?

Успешный Ping не доказывает исправность DNS, TCP, TLS, HTTP и приложения. PathTrial проверяет каждый уровень отдельно, сохраняет доказательства и прямо указывает, какие причины пока не установлены.

- **Сайт открывается не всегда:** отдельно проверяются DNS, TCP-соединение, TLS и состояние HTTP.
- **VPS принимает подключения, но прокси не работает:** проверяются TCP, UDP Echo, QUIC, HTTP/3 и путь через прокси.
- **IPv4 и IPv6 ведут себя по-разному:** сравниваются успешность и задержка при одинаковом узле, порте, числе раундов и тайм-ауте.

PathTrial работает локально. Он не загружает отчёты и не меняет DNS, маршруты, межсетевой экран или настройки прокси. Codex и Claude Code используют один локальный MCP-сервер. Любая сетевая проверка запрещена до явного разрешения узла.

## Установка плагинов ИИ

> **Предварительная версия для разработчиков:** установка плагина не устанавливает программу диагностики. Текущему плагину нужен исполняемый файл `1.4.0-rc.1` с поддержкой `pathtrial mcp`. Публичный бинарник `v1.3.0-rc.1` не умеет запускать MCP, а публичного готового пакета `v1.4.0-rc.1` пока нет.
>
> До появления такого пакета для предварительной версии нужны Rust 1.84 или новее и одна сборка из исходного кода. Если нужен только стабильный CLI, перейдите к разделу «Использование PathTrial без ИИ-клиента».

### Шаг 0. Подготовьте совместимое ядро PathTrial

~~~bash
git clone --branch codex/ai-plugins-v0.1 --depth 1 https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
cargo build --release --locked
export PATH="$PWD/target/release:$PATH"

pathtrial --version
pathtrial mcp --help
~~~

Версия должна быть `1.4.0-rc.1`. Перед запуском Codex или Claude Code убедитесь, что этот каталог входит в их `PATH`.

### OpenAI Codex

Установка из удалённого Marketplace проверена с временным `CODEX_HOME`. Команда `codex plugin list` должна показать версию `0.2.0`, а `codex mcp list` должна показать включённый сервер `pathtrial`.

~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial --ref codex/ai-plugins-v0.1
codex plugin add pathtrial@pathtrial

codex plugin list
codex mcp list
~~~

Реальный сеанс модели Codex `v0.2.0` выполнил разрешённую локальную проверку и объяснение отчёта: TCP завершился успешно `1/1`, получен идентификатор `tcp_ipv4_001`, а неразрешённый узел отклонён с `target_not_allowed`.

После этого можно попросить Codex:

> Сначала вызови `pathtrial_capabilities` и подтверди версию PathTrial и доступность всех девяти инструментов MCP.

### Claude Code

Реальная работа в Claude Code пока имеет статус `UNVERIFIED`. Официальный CLI `2.1.292` установлен, `claude plugin validate` проходит, но на этой машине нет входа в аккаунт Claude, поэтому сеанс модели ещё не запускался. В ветке `main` по умолчанию также нет файла Marketplace. Используйте официальную локальную загрузку плагина:

~~~bash
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
~~~

В сеансе откройте `/mcp` и проверьте, зарегистрирован ли `pathtrial`. Манифест и общие Skills проходят структурные тесты, но реальные вызовы из Claude Code ещё требуют проверки в пользовательской среде.

## Первое использование

### 1. Разрешите проверку узла, на которую у вас есть право

Конфигурация по умолчанию `["mcp"]` запрещает все сетевые проверки. Объяснение и сравнение готовых отчётов работают без сети. Чтобы разрешить один узел, измените `args` в настройках плагина:

~~~json
["mcp", "--allow-target", "example.com:443"]
~~~

- Установленный плагин Codex: измените `~/.codex/plugins/cache/pathtrial/pathtrial/0.2.0/mcp.json`.
- Локальный плагин Claude Code: измените `plugins/claude-code/pathtrial/.mcp.json`.
- Для нескольких узлов повторите `--allow-target`.
- После изменения перезапустите ИИ-клиент.
- Не используйте шаблоны и не проверяйте системы без разрешения.

### 2. Задайте вопрос обычным языком

**Сайт недоступен**

> Используй PathTrial, чтобы проверить example.com. Раздели проблемы DNS, TCP, TLS и HTTP и объясни результат по-русски.

**Сравнение IPv4 и IPv6**

> Сравни успешность и задержку IPv4 и IPv6 для моего VPS. Сохрани одинаковые порт, число раундов и тайм-аут и укажи фактические измерения.

**Объяснение готового отчёта**

> Проанализируй этот JSON-отчёт PathTrial. Укажи аномалии, реальные идентификаторы доказательств и причины, которые отчёт не позволяет установить.

### 3. Прочитайте результат

Обратите внимание на `PASS`, `WARN`, `FAIL`, `SKIP` и `INCONCLUSIVE`. `SKIP` не означает успех. `INCONCLUSIVE` означает недостаток доказательств. PathTrial фиксирует каждый сетевой уровень и не делает вывод о блокировке провайдера или конкретном устройстве с потерями по одному Ping.

## Поддерживаемая диагностика

DNS, IPv4/IPv6, TCP, TLS, HTTP, ICMP, трассировка маршрута, UDP Echo, QUIC, HTTP/3, SOCKS5, HTTP CONNECT, сравнение прямого и прокси-подключения, корреляция сбора данных с двух сторон.

## Использование PathTrial без ИИ-клиента

Публичный CLI `v1.3.0-rc.1` устанавливается без Rust. В нём нет MCP, поэтому он не подходит для плагинов ИИ.

- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)

Файлы SHA-256 находятся на [странице версии v1.3.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1). Перед запуском просмотрите установочный скрипт:

~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh

~/.local/bin/pathtrial --version
~~~

Первая проверка:

~~~bash
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

Параметр `--redact-ips` делает отчёт более безопасным для публикации. Подробности о HTTP, QUIC, UDP, прокси, сборе данных с двух сторон и кодах завершения находятся в [руководстве по CLI](docs/cli.md).

## Статус тестовой версии и известные ограничения

- PathTrial Core: версия разработки `1.4.0-rc.1`.
- AI Plugins: предварительная версия `0.2.0`.
- Публичный готовый CLI: `v1.3.0-rc.1`, без MCP.
- Автоматические проверки: 173 теста пройдены, CI работает на Ubuntu 24.04, macOS ARM и macOS Intel.
- Codex: версия `v0.2.0` прошла реальный сеанс модели, разрешённую проверку, объяснение доказательств и отказ для неразрешённого узла.
- Claude Code: официальный CLI, манифест и структура Marketplace проверены. Вход в аккаунт отсутствует, поэтому реальные вызовы остаются `UNVERIFIED`.
- Инженерная готовность AI Plugins: `75.0%`. Это оценка приёмки, а не точность диагностики.

Полные доказательства находятся в [матрице готовности AI Plugins](docs/ai-plugin-completeness.md). Windows, графический интерфейс, автоматическое исправление сети, автоматический захват пакетов и точное определение устройства с потерями пока недоступны. Поведение Fake-IP/TUN, публичный UDP 443 и доступность HTTP/3 могут зависеть от локальной сети.

## Ошибки и участие в разработке

Создавайте [GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) при сбоях установки, неверных результатах, зависаниях, непонятной документации и проблемах совместимости. Перед публикацией удалите реальные IP-адреса, домены, токены, ключи, Cookie, ссылки на прокси-подписки и чувствительные данные захвата.

Приветствуются воспроизводимые ошибки, тесты и улучшения. Перед отправкой кода прочитайте [AGENTS.md](AGENTS.md) и выполните требуемые проверки форматирования, Clippy и тестов.

## Документация для разработчиков и лицензия

- [Интеграция с ИИ и разрешения](docs/ai-integrations.md)
- [Расширенное руководство по CLI](docs/cli.md)
- [Готовность AI Plugins](docs/ai-plugin-completeness.md)
- [Индекс проекта и схем](llms.txt)
- [PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1) · [PR #2](https://github.com/gaochenyang666-droid/PathTrial/pull/2)

PathTrial распространяется по [лицензии MIT](LICENSE). Проект вырос из [реального разбора IPv4/IPv6 на VPS RackNerd](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting). Исторические данные не были получены самим PathTrial, поэтому их следует отличать от измерений инструмента.
