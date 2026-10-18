# PathTrial — диагностика сети CLI и MCP-плагины

**Бесплатная утилита диагностики сети с открытым исходным кодом на Rust.** Проверяет DNS, TCP, TLS, HTTP/3, QUIC, UDP, прокси и IPv4/IPv6 для сайтов и VPS, создавая JSON-отчёты с проверяемыми результатами. Локальные MCP-плагины для Codex и Claude Code доступны в предварительной версии для разработчиков.

**Языки:** [简体中文](README.md) · [English](README.en.md) · [Español](README.es.md) · **Русский**

[**Скачать тестовый CLI**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**Сообщить об ошибке**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Руководство по интеграции с ИИ**](docs/ai-integrations.md) · [**Руководство по CLI**](docs/cli.md)

> **Статус:** публичный CLI имеет версию `v1.3.0-rc.1`. AI Plugins `v0.2.0` является предварительной версией для разработчиков и работает с ядром `1.4.0-rc.1`; публичного готового пакета пока нет. README доступен на четырёх языках, но вывод CLI и отчёты переведены не полностью.

> **Попробуйте AI-плагины:** Плагины Codex и Claude Code доступны в ветке разработки AI Plugins v0.2.0. Сообщайте об ошибках установки, совместимости и диагностики через [GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md), указав версии и шаги воспроизведения без конфиденциальных данных. **Публичных готовых пакетов v1.4 с MCP пока нет: нужны Rust 1.84+ и сборка из исходников.**

## Какие сетевые проблемы помогает диагностировать PathTrial?

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

Плагин Claude Code можно загрузить локально. Пока файлы плагина не объединены с веткой `main`, выполните следующие команды из корня репозитория этой ветки разработки:

~~~bash
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
~~~

В сеансе откройте `/mcp`, проверьте регистрацию инструментов `pathtrial`, затем попробуйте диагностику или анализ отчёта.

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
- Claude Code: предусмотрены локальная загрузка плагина, конфигурация MCP и общие Skills.

Полные доказательства находятся в [матрице готовности AI Plugins](docs/ai-plugin-completeness.md). Windows, графический интерфейс, автоматическое исправление сети, автоматический захват пакетов и точное определение устройства с потерями пока недоступны. Поведение Fake-IP/TUN, публичный UDP 443 и доступность HTTP/3 могут зависеть от локальной сети.

## Частые вопросы по диагностике сети

### Сайт не открывается: как отличить сбой DNS, TCP, TLS от HTTP?

Для разрешённой цели выполните `pathtrial scan example.com --profile web --rounds 5 --redact-ips` и затем `pathtrial http https://example.com/`. Каждый этап фиксируется отдельно; успешный Ping не гарантирует работу сайта.

### Можно ли диагностировать VPS, IPv4/IPv6, SOCKS5-прокси и HTTP/3?

Да. CLI проверяет IPv4/IPv6, TCP/TLS, прокси SOCKS5 и HTTP CONNECT, QUIC-рукопожатие и HTTP/3-запросы при поддержке сервером. См. [руководство по CLI](docs/cli.md). По одному тайм-ауту UDP нельзя достоверно установить причину.

### Как подключить PathTrial к Codex или Claude Code через MCP?

См. [инструкцию по установке AI-плагинов](#установка-ai-плагинов). Плагины вызывают локальный движок на Rust. Публичная версия CLI `v1.3.0-rc.1` не содержит MCP; для предварительного выпуска нужно собрать ядро `1.4.0-rc.1` и явно разрешить целевой узел.

### Нужен ли Rust для установки? Работает ли PathTrial в Windows?

Готовые CLI-пакеты для macOS Apple Silicon, macOS Intel и Linux x86_64 не требуют Rust. Windows пока не поддерживается. Rust нужен для сборки из исходников и текущей предварительной MCP-интеграции.

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
