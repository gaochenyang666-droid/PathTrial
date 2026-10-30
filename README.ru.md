# PathTrial — открытый инструмент диагностики сети | CLI и MCP для Codex, Claude Code и Cursor
[**Руководства по диагностике сети (на английском)**](https://gaochenyang666-droid.github.io/PathTrial/en/guides/): порты VPS, QUIC/HTTP3 и IPv4/IPv6.
**PathTrial — открытая CLI-утилита для диагностики сети на Rust с локальным MCP-сервером.** Она проверяет DNS, доступность сайтов, порты VPS, прокси и соединения IPv4/IPv6, TCP, TLS, UDP, QUIC и HTTP/3. Результаты сохраняются в JSON-отчётах с измеренными данными. Программа работает самостоятельно на macOS и Linux и через MCP в Codex, Claude Code и Cursor.
**Языки сайта:** [简体中文](https://gaochenyang666-droid.github.io/PathTrial/) · [English](https://gaochenyang666-droid.github.io/PathTrial/en/) · [Español](https://gaochenyang666-droid.github.io/PathTrial/es/) · [Русский](https://gaochenyang666-droid.github.io/PathTrial/ru/)
**Языки:** [简体中文](README.md) · [English](README.en.md) · [Español](README.es.md) · **Русский**
[**Скачать v1.5.0-rc.1**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1) · [**Сообщить об ошибке**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Руководство по интеграции с ИИ**](docs/ai-integrations.md) · [**Руководство по CLI**](docs/cli.md)
> **Текущая версия:** PathTrial Core `v1.5.0-rc.1` выпущена как кандидат на выпуск с командой `diagnose` и локальным MCP. Версия AI Plugins — `0.3.0` (десять инструментов). Опубликованные пакеты есть для macOS Apple Silicon, macOS Intel и Linux x86_64, Rust для них не нужен. Windows x86_64 собирается в последующем выпуске; в `v1.5.0-rc.1` этого архива нет.
> **Предыдущий выпуск:** [v1.4.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) остаётся доступным (девять MCP-инструментов). v1.5 добавляет `pathtrial_diagnose` и поддержку отчётов diagnose в `pathtrial_explain_report`.
> **Приглашаем к тестированию:** плагины Codex и Claude Code доступны в основной ветке `main`. [Сообщайте об ошибках установки, совместимости и диагностики](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md), указывая версии, шаги воспроизведения и ожидаемый/фактический результат без конфиденциальных данных.
## Диагностика DNS, портов VPS, прокси и IPv4/IPv6
Успешный Ping не доказывает исправность DNS, TCP, TLS, HTTP и приложения. PathTrial проверяет каждый уровень отдельно, сохраняет доказательства и прямо указывает, какие причины пока не установлены.
- **Сайт открывается не всегда:** отдельно проверяются DNS, TCP-соединение, TLS и состояние HTTP.
- **VPS принимает подключения, но прокси не работает:** проверяются TCP, UDP Echo, QUIC, HTTP/3 и путь через прокси.
- **IPv4 и IPv6 ведут себя по-разному:** сравниваются успешность и задержка при одинаковом узле, порте, числе раундов и тайм-ауте.
PathTrial работает локально. Он не загружает отчёты и не меняет DNS, маршруты, межсетевой экран или настройки прокси. Codex и Claude Code используют один локальный MCP-сервер. Любая сетевая проверка запрещена до явного разрешения узла.
## Комплексная диагностика (выпущенный кандидат v1.5)
Кандидат v1.5 содержит команду `pathtrial diagnose` для проверки DNS, TCP, TLS, HTTP, задержки, потерь, IPv4/IPv6, UDP/QUIC, прокси и локальной сети в десяти категориях:
~~~bash
pathtrial diagnose --scenario web example.com
pathtrial diagnose --scenario vps YOUR_VPS_IP --port 22
pathtrial diagnose --scenario latency example.com --rounds 10
pathtrial diagnose --scenario proxy --url https://example.com/ --proxy socks5://127.0.0.1:1080
pathtrial diagnose --scenario local
~~~
Также доступны `dns`, `tcp`, `tls`, `http`, `dual-stack` и `udp-quic`. Отчёт отдельно содержит `observed`, `possible`, `not_established` и `next_checks`; гипотеза не выдаётся за подтверждённую причину.
## Установка плагинов ИИ
> **Публичный кандидат на выпуск:** сначала установите исполняемый файл PathTrial, затем плагин Codex, Claude Code или Cursor. Плагин сам по себе не устанавливает диагностическую программу. Сетевые проверки требуют явного разрешения цели.
### Шаг 1. Установка PathTrial (без Rust)
Скачайте и просмотрите установочный скрипт из [выпуска v1.5.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1):
~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
pathtrial mcp --help
~~~
Проверьте версию `1.5.0-rc.1` и работу `pathtrial mcp --help`. Исполняемый файл должен быть доступен через `PATH`, который наследует ИИ-клиент.
### Шаг 2. Выберите ИИ-клиент
#### Плагин OpenAI Codex
Установите плагин из Marketplace основной ветки `main`:
~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial
codex plugin add pathtrial@pathtrial
codex plugin list
codex mcp list
~~~
Плагин v1.5 `0.3.0` содержит десять MCP-инструментов; `pathtrial_explain_report` также объясняет отчёты diagnose. Первый запрос: *«Вызови `pathtrial_capabilities` и проверь доступные MCP-инструменты».*
#### Плагин Claude Code
Внутри Claude Code добавьте Marketplace и установите плагин. Просмотрите инструменты с помощью `/mcp`:
~~~text
/plugin marketplace add gaochenyang666-droid/PathTrial
/plugin install pathtrial@pathtrial
/mcp
~~~
Порядок настройки разрешений и решения проблем — в [руководстве по интеграции](docs/ai-integrations.md).
#### Cursor
Публичный Marketplace Cursor пока не содержит этот пакет. Плагин лежит в `plugins/cursor/pathtrial/`: `.cursor-plugin/plugin.json`, `mcp.json`, который только запускает `pathtrial mcp`, общие Skills и одно правило доказательств. Не добавляйте разрешённые цели в `mcp.json`.

Локальная загрузка — это описанный Cursor способ для плагина вне Marketplace. В Enterprise локальный импорт могут отключить:

~~~bash
mkdir -p "${HOME}/.cursor/plugins/local"
rm -rf "${HOME}/.cursor/plugins/local/pathtrial"
cp -R plugins/cursor/pathtrial "${HOME}/.cursor/plugins/local/pathtrial"
~~~

Выполните Developer: Reload Window, откройте Customize и проверьте Skills, правило и MCP-сервер. Имя может отображаться как `plugin-pathtrial-pathtrial`.

Если нужен только MCP-сервер, запишите ту же конфигурацию в `.cursor/mcp.json` проекта или в `~/.cursor/mcp.json` (в Windows: `%USERPROFILE%\.cursor\mcp.json`). Из этого репозитория:

~~~bash
sh scripts/install-cursor-mcp.sh /path/to/your/project
~~~

Настольный Cursor может не унаследовать `PATHTRIAL_MCP_ALLOW_TARGETS`. Используйте файл allow-targets выше и перезагрузите окно. Первый запрос: *«Вызови `pathtrial_capabilities` и проверь доступные MCP-инструменты».* Установка в Cursor Desktop и вызов инструмента моделью здесь не выполнялись, поэтому статус — PARTIAL. Подробности в [руководстве по интеграции](docs/ai-integrations.md).
## Первое использование
### 1. Разрешите проверку узла, на которую у вас есть право
PathTrial MCP по умолчанию запрещает все сетевые проверки; анализ существующих JSON-отчётов не требует доступа к сети. **При запуске ИИ-клиента из терминала временно задайте разрешённые цели до его запуска**, не редактируя кэш определённой версии плагина:
~~~bash
# Замените example.com:443 своей разрешённой целью
export PATHTRIAL_MCP_ALLOW_TARGETS="example.com:443"
codex
# Для Claude Code вместо codex запустите claude в этом терминале
~~~
`PATHTRIAL_MCP_ALLOW_TARGETS` принимает несколько явных целей `host:port`, разделённых запятыми или пробелами. MCP-сервер должен наследовать переменную. **Приложение, запущенное с рабочего стола, может не унаследовать окружение терминала.** Не редактируйте `mcp.json` в кэше Marketplace. Запишите по одной явной цели в строке пользовательского файла. Подстановки и префиксы CIDR отклоняются. Если файла нет, проверки по-прежнему запрещены по умолчанию:

~~~bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/pathtrial"
printf '%s\n' 'example.com:443' >> "${XDG_CONFIG_HOME:-$HOME/.config}/pathtrial/allow-targets"
pathtrial mcp --print-allow-path
~~~

В Windows файл — `%APPDATA%\pathtrial\allow-targets`. `--print-allow-path` печатает путь и не печатает правила. После изменения файла перезапустите клиент. См. [руководство по интеграции](docs/ai-integrations.md).
Не проверяйте чужие устройства без разрешения.
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
[Публичный кандидат на выпуск v1.5.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1) работает как самостоятельный CLI без Rust, Codex или Claude Code. Выберите пакет для своей платформы:
- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)
У каждого опубликованного архива есть файл SHA-256. macOS и Linux используют `scripts/install.sh`. Windows x86_64 использует `scripts/install.ps1`. Скрипт проверяет SHA-256 и копирует `pathtrial.exe` в `%LOCALAPPDATA%\PathTrial`. Он не меняет PATH, брандмауэр, DNS и маршруты. В `v1.5.0-rc.1` нет архива Windows; запуск скрипта для этого тега завершит загрузку ошибкой. Это не успешная установка. Ограничения — в [Windows](docs/windows.md).

~~~powershell
# Только после того, как выбранный выпуск содержит pathtrial-x86_64-pc-windows-msvc.tar.gz
$env:PATHTRIAL_VERSION = "v1.5.0-rc.1"
powershell -File .\scripts\install.ps1
& "$env:LOCALAPPDATA\PathTrial\pathtrial.exe" --version
~~~

После установки:

~~~bash
pathtrial --version
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

Локальный просмотр отчёта, локальная база и временный узел на машине, которой вы управляете:

~~~bash
pathtrial report render report.json --format html --out report.html --redact-ips
pathtrial report render report.json --format svg --out report.svg
pathtrial baseline path
pathtrial baseline save report.json --redact-ips
pathtrial baseline compare later.json --format json
sh scripts/peer.sh demo 0.0.0.0:39002 0.0.0.0:39001 120
~~~

`report render` читает один локальный JSON. Сеть не используется, исходный файл не меняется. `--redact-ips` маскирует адреса только в этом представлении. `baseline save` сохраняет этот отчёт в локальном каталоге данных. `baseline compare` использует только его и текущий отчёт. Если прогоны прямо сопоставимы, отношение будет better, worse или same, со ссылкой на идентификаторы доказательств текущего файла. Иначе отношение — `not_established`; история не выдумывается. Код выхода 2 означает worse. Код 3 означает, что файлы несопоставимы. `peer.sh` поднимает UDP echo и ограниченный по времени collect-сервер на указанных адресах. Он не меняет брандмауэр, DNS и маршруты и не сохраняет UDP-нагрузку. Для адресов вне loopback нужен `--allow-public-bind`. Подробности о HTTP, QUIC, UDP, прокси, сборе с двух сторон и кодах завершения — в [руководстве по CLI](docs/cli.md).
## Статус тестовой версии и известные ограничения
- Ядро: `v1.5.0-rc.1`, опубликованный **кандидат на выпуск**, не стабильная версия.
- AI Plugins: `0.3.0` (10 инструментов); предыдущий плагин v1.4 — `0.2.0` (9 инструментов).
- Готовые пакеты: macOS ARM64, macOS Intel и Linux x86_64; сборка успешна, файлы SHA-256 доступны.
- Проверки: [трёхплатформенный выпуск v1.5](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39255364100) прошёл сборку и тестирование MCP. Реальные сеансы Codex проверены, проект сообщил о завершении проверки Claude Code.
- Для сетевой диагностики требуется явное разрешение. Графического интерфейса и автоматического исправления сети нет. Windows x86_64 собирается последующим выпуском; в активах `v1.5.0-rc.1` этого архива нет. Ограничения: [Windows](docs/windows.md). Команды `report render`, `baseline` и `peer.sh` приведены в разделе [Использование PathTrial без ИИ-клиента](#использование-pathtrial-без-ии-клиента).
Подробности см. в [матрице приёмки](docs/ai-plugin-completeness.md) и [отчёте о сборке](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39149532255). [Сообщайте о воспроизводимых ошибках](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md).
## Частые вопросы по диагностике сети
### Сайт не открывается: как отличить сбой DNS, TCP, TLS от HTTP?
Для разрешённой цели выполните `pathtrial scan example.com --profile web --rounds 5 --redact-ips` и затем `pathtrial http https://example.com/`. Каждый этап фиксируется отдельно; успешный Ping не гарантирует работу сайта.
### Можно ли диагностировать VPS, IPv4/IPv6, SOCKS5-прокси и HTTP/3?
Да. CLI проверяет IPv4/IPv6, TCP/TLS, прокси SOCKS5 и HTTP CONNECT, QUIC-рукопожатие и HTTP/3-запросы при поддержке сервером. См. [руководство по CLI](docs/cli.md). По одному тайм-ауту UDP нельзя достоверно установить причину.
### Как подключить PathTrial к Codex, Claude Code или Cursor через MCP?
Установите [готовое ядро v1.5.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1), затем следуйте [инструкции по плагинам](#установка-плагинов-ии). Codex и Claude Code используют Marketplace из `main`. Cursor использует локальный пакет или `.cursor/mcp.json`. MCP вызывает локальную программу `pathtrial`; сетевые проверки требуют разрешения цели.
### Нужен ли Rust для установки? Работает ли PathTrial в Windows?
Опубликованные файлы v1.5.0-rc.1 есть для macOS Apple Silicon, macOS Intel и Linux x86_64, Rust для них не нужен. Windows x86_64 ставится через `scripts/install.ps1`, когда в выпуске появится этот архив. В `v1.5.0-rc.1` его нет. До этого сборка на Windows требует Rust. `--bind-interface` на Windows завершается ошибкой и не переключается на другой интерфейс.
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
