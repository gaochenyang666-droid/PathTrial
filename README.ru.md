# PathTrial — открытый инструмент диагностики сети | CLI и MCP-плагины для Codex и Claude Code

**PathTrial — открытая CLI-утилита для диагностики сети на Rust с локальным MCP-сервером.** Она проверяет DNS, доступность сайтов, порты VPS, прокси и соединения IPv4/IPv6, TCP, TLS, UDP, QUIC и HTTP/3. Результаты сохраняются в JSON-отчётах с измеренными данными. Программа работает самостоятельно на macOS и Linux и через MCP-плагины Codex и Claude Code.

**Языки:** [简体中文](README.md) · [English](README.en.md) · [Español](README.es.md) · **Русский**

[**Скачать v1.4.0-rc.1**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) · [**Сообщить об ошибке**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Руководство по интеграции с ИИ**](docs/ai-integrations.md) · [**Руководство по CLI**](docs/cli.md)

> **Текущая версия:** PathTrial Core `v1.4.0-rc.1` опубликована как кандидат на выпуск (RC) с поддержкой CLI и локального MCP. Версия AI Plugins — `0.2.0`. Готовые пакеты есть для macOS Apple Silicon, macOS Intel и Linux x86_64, Rust для установки не нужен. README доступны на четырёх языках; вывод CLI и отчёты локализованы не полностью.

> **Исходный код `main` (ещё не выпущен):** PR #5 объединён; ядро `1.5.0-rc.1` и плагин `0.3.0` добавляют `diagnose` и десятый MCP-инструмент. Пакет v1.4 **не содержит** этих функций; для тестирования соберите ядро v1.5 из `main`.

> **Приглашаем к тестированию:** плагины Codex и Claude Code доступны в основной ветке `main`. [Сообщайте об ошибках установки, совместимости и диагностики](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md), указывая версии, шаги воспроизведения и ожидаемый/фактический результат без конфиденциальных данных.

## Диагностика DNS, портов VPS, прокси и IPv4/IPv6

Успешный Ping не доказывает исправность DNS, TCP, TLS, HTTP и приложения. PathTrial проверяет каждый уровень отдельно, сохраняет доказательства и прямо указывает, какие причины пока не установлены.

- **Сайт открывается не всегда:** отдельно проверяются DNS, TCP-соединение, TLS и состояние HTTP.
- **VPS принимает подключения, но прокси не работает:** проверяются TCP, UDP Echo, QUIC, HTTP/3 и путь через прокси.
- **IPv4 и IPv6 ведут себя по-разному:** сравниваются успешность и задержка при одинаковом узле, порте, числе раундов и тайм-ауте.

PathTrial работает локально. Он не загружает отчёты и не меняет DNS, маршруты, межсетевой экран или настройки прокси. Codex и Claude Code используют один локальный MCP-сервер. Любая сетевая проверка запрещена до явного разрешения узла.

## Комплексная диагностика (исходный код v1.5 в main, ещё не выпущен)

В объединённой ветке `main` доступна команда `pathtrial diagnose`, объединяющая DNS, TCP, TLS, HTTP, задержку, потери, двойной стек, UDP/QUIC, прокси и локальную сеть в десять типовых сценариев:

~~~bash
pathtrial diagnose --scenario web example.com
pathtrial diagnose --scenario vps YOUR_VPS_IP --port 22
pathtrial diagnose --scenario latency example.com --rounds 10
pathtrial diagnose --scenario proxy --url https://example.com/ --proxy socks5://127.0.0.1:1080
pathtrial diagnose --scenario local
~~~

Также доступны `dns`, `tcp`, `tls`, `http`, `dual-stack` и `udp-quic`. Отчёт отдельно содержит `observed`, `possible`, `not_established` и `next_checks`; гипотеза не выдаётся за подтверждённую причину.

## Установка плагинов ИИ

> **Публичный кандидат на выпуск:** сначала установите исполняемый файл PathTrial, затем плагин Codex или Claude Code. Плагин сам по себе не устанавливает диагностическую программу. Сетевые проверки требуют явного разрешения цели.

### Шаг 1. Установка PathTrial (без Rust)

Скачайте и просмотрите установочный скрипт из [выпуска v1.4.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1):

~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
pathtrial mcp --help
~~~

Проверьте версию `1.4.0-rc.1` и работу `pathtrial mcp --help`. Исполняемый файл должен быть доступен через `PATH`, который наследует ИИ-клиент.

### Шаг 2. Выберите ИИ-клиент

#### Плагин OpenAI Codex

Установите плагин из Marketplace основной ветки `main`:

~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial
codex plugin add pathtrial@pathtrial
codex plugin list
codex mcp list
~~~

Codex v0.2 уже успешно выполнил реальные вызовы модели, разрешённую локальную TCP-проверку и анализ отчёта. Публичный плагин v1.4 содержит девять инструментов MCP. В плагине `main` версии 0.3 добавлен `pathtrial_diagnose`, всего десять инструментов. Первый запрос: *«Вызови `pathtrial_capabilities` и проверь доступные инструменты MCP».*

#### Плагин Claude Code

Внутри Claude Code добавьте Marketplace и установите плагин. Просмотрите инструменты с помощью `/mcp`:

~~~text
/plugin marketplace add gaochenyang666-droid/PathTrial
/plugin install pathtrial@pathtrial
/mcp
~~~

Порядок настройки разрешений и решения проблем — в [руководстве по интеграции](docs/ai-integrations.md).

## Первое использование

### 1. Разрешите проверку узла, на которую у вас есть право

PathTrial MCP по умолчанию запрещает все сетевые проверки; анализ существующих JSON-отчётов не требует доступа к сети. **При запуске ИИ-клиента из терминала временно задайте разрешённые цели до его запуска**, не редактируя кэш определённой версии плагина:

~~~bash
# Замените example.com:443 своей разрешённой целью
export PATHTRIAL_MCP_ALLOW_TARGETS="example.com:443"
codex
# Для Claude Code вместо codex запустите claude в этом терминале
~~~

`PATHTRIAL_MCP_ALLOW_TARGETS` принимает несколько явных целей `host:port`, разделённых запятыми или пробелами. MCP-сервер должен наследовать переменную. **Приложения, запущенные через графический интерфейс, могут не наследовать окружение терминала**; настройте окружение MCP-клиента или используйте параметр `--allow-target`. См. [руководство по интеграции](docs/ai-integrations.md).

Не используйте шаблоны и не проверяйте чужие устройства без разрешения. Перезапустите клиент после изменения настроек.

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

[Публичный кандидат на выпуск v1.4.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) работает как самостоятельный CLI без Rust, Codex или Claude Code. Выберите пакет для своей платформы:

- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.4.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)

У каждого архива есть файл контрольной суммы SHA-256. Можно использовать установочный скрипт выше или скачать архив и проверить его вручную.

~~~bash
pathtrial --version
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

Подробности о HTTP, QUIC, UDP, прокси, сборе данных с двух сторон и кодах завершения — в [руководстве по CLI](docs/cli.md).

## Статус тестовой версии и известные ограничения

- Ядро: `v1.4.0-rc.1`, опубликованный **кандидат на выпуск**, не стабильная версия.
- AI Plugins: опубликованное ядро v1.4 использует `0.2.0` (9 инструментов); невыпущенный плагин `0.3.0` в `main` (10 инструментов) требует ядро v1.5, собранное из исходников.
- Готовые пакеты: macOS ARM64, macOS Intel и Linux x86_64; сборка успешна, файлы SHA-256 доступны.
- Проверки: историческая база v1.4 — 173 теста; объединённый код v1.5 прошёл 225 тестов и [CI на трёх платформах](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39235804316). Новый инструмент пока не проверен в реальных модельных сессиях Codex/Claude.
- Для сетевой диагностики требуется явное разрешение. Windows, графический интерфейс и автоматическое исправление сети не поддерживаются.

Подробности см. в [матрице приёмки](docs/ai-plugin-completeness.md) и [отчёте о сборке](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39149532255). [Сообщайте о воспроизводимых ошибках](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md).

## Частые вопросы по диагностике сети

### Сайт не открывается: как отличить сбой DNS, TCP, TLS от HTTP?

Для разрешённой цели выполните `pathtrial scan example.com --profile web --rounds 5 --redact-ips` и затем `pathtrial http https://example.com/`. Каждый этап фиксируется отдельно; успешный Ping не гарантирует работу сайта.

### Можно ли диагностировать VPS, IPv4/IPv6, SOCKS5-прокси и HTTP/3?

Да. CLI проверяет IPv4/IPv6, TCP/TLS, прокси SOCKS5 и HTTP CONNECT, QUIC-рукопожатие и HTTP/3-запросы при поддержке сервером. См. [руководство по CLI](docs/cli.md). По одному тайм-ауту UDP нельзя достоверно установить причину.

### Как подключить PathTrial к Codex или Claude Code через MCP?

Установите [готовое ядро v1.4.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1), затем используйте [инструкцию по плагинам](#установка-плагинов-ии) и Marketplace из `main`. MCP вызывает локальную программу `pathtrial`; сетевые проверки требуют разрешения цели.

### Нужен ли Rust для установки? Работает ли PathTrial в Windows?

Нет. Готовые бинарные файлы v1.4.0-rc.1 существуют для macOS Apple Silicon, macOS Intel и Linux x86_64. Windows пока не поддерживается. Rust нужен только при сборке из исходного кода.

### Чем PathTrial отличается от ping и curl?

`ping` в основном проверяет ICMP-доступность, а `curl` часто используют для HTTP-запросов. PathTrial разделяет измерения DNS, TCP, TLS, HTTP, UDP и QUIC на ограниченные проверки, указывает фактические данные в JSON-отчётах и не делает вывод о причине по одному неудачному тесту.

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
