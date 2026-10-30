# PathTrial — Diagnóstico de redes de código abierto | CLI y plugins MCP para Codex, Claude Code y Cursor
[**Guías de diagnóstico (en inglés)**](https://gaochenyang666-droid.github.io/PathTrial/en/guides/): puertos VPS, QUIC/HTTP3 e IPv4/IPv6.
**PathTrial es una herramienta CLI de diagnóstico de redes de código abierto en Rust, con servidor MCP local.** Analiza problemas de DNS, conectividad de sitios web, puertos de VPS, proxies y conexiones IPv4/IPv6, TCP, TLS, UDP, QUIC y HTTP/3. Genera informes JSON con pruebas verificables, funciona sin IA en macOS y Linux e incluye MCP para Codex, Claude Code y Cursor.
**Idiomas del sitio web:** [简体中文](https://gaochenyang666-droid.github.io/PathTrial/) · [English](https://gaochenyang666-droid.github.io/PathTrial/en/) · [Español](https://gaochenyang666-droid.github.io/PathTrial/es/) · [Русский](https://gaochenyang666-droid.github.io/PathTrial/ru/)
**Idiomas:** [简体中文](README.md) · [English](README.en.md) · **Español** · [Русский](README.ru.md)
[**Descargar v1.5.0-rc.1**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1) · [**Informar de un error**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Guía de integración con IA**](docs/ai-integrations.md) · [**Guía del CLI**](docs/cli.md)
> **Versión actual:** PathTrial Core `v1.5.0-rc.1` es una versión candidata pública con diagnóstico guiado y servidor MCP local. AI Plugins `0.3.0` incluye diez herramientas. Los binarios publicados cubren macOS Apple Silicon, macOS Intel y Linux x86_64; no hace falta Rust. Windows x86_64 se empaqueta en el flujo de publicación de una versión posterior; `v1.5.0-rc.1` no incluye ese archivo.
> **Versión anterior:** [v1.4.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.4.0-rc.1) sigue disponible (nueve herramientas MCP). v1.5 añade `pathtrial_diagnose` y permite explicar informes diagnose mediante `pathtrial_explain_report`.
> **Prueba la versión candidata:** los plugins Codex y Claude Code están en la rama predeterminada `main`. Puedes [informar de errores de instalación, compatibilidad o diagnóstico](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) indicando versiones, pasos y resultados esperados y observados, sin datos sensibles.
## Diagnóstico de DNS, puertos VPS, proxies e IPv4/IPv6
Que un Ping funcione no demuestra que DNS, TCP, TLS, HTTP y la aplicación estén sanos. PathTrial mide cada capa por separado, conserva las pruebas y explica qué causas siguen sin demostrarse.
- **Una web abre de forma intermitente:** separa DNS, conexión TCP, TLS y estado HTTP.
- **El VPS acepta conexiones, pero el proxy falla:** revisa TCP, UDP Echo, QUIC, HTTP/3 y la ruta del proxy.
- **IPv4 e IPv6 se comportan de forma distinta:** compara éxito y latencia con el mismo destino, puerto, rondas y tiempo de espera.
PathTrial se ejecuta localmente. No sube informes ni modifica DNS, rutas, cortafuegos o ajustes de proxy. Codex y Claude Code utilizan el mismo motor mediante un servidor MCP local. Todas las pruebas de red se bloquean hasta autorizar el destino de forma explícita.
## Diagnóstico guiado (versión candidata v1.5)
La versión candidata v1.5 incluye `pathtrial diagnose`, que reúne DNS, TCP, TLS, HTTP, latencia, pérdida, doble pila, UDP/QUIC, proxy y red local en diez categorías:
~~~bash
pathtrial diagnose --scenario web example.com
pathtrial diagnose --scenario vps YOUR_VPS_IP --port 22
pathtrial diagnose --scenario latency example.com --rounds 10
pathtrial diagnose --scenario proxy --url https://example.com/ --proxy socks5://127.0.0.1:1080
pathtrial diagnose --scenario local
~~~
También incluye `dns`, `tcp`, `tls`, `http`, `dual-stack` y `udp-quic`. El informe separa `observed`, `possible`, `not_established` y `next_checks`; una hipótesis no se presenta como causa confirmada.
## Instalar los plugins de IA
> **Versión candidata pública:** instala primero el ejecutable PathTrial y después el plugin de Codex, Claude Code o Cursor. El plugin no instala el programa principal. Las pruebas de red requieren una autorización explícita para cada destino.
### Paso 1: Instalar PathTrial (sin Rust)
Descarga y revisa el instalador oficial del [lanzamiento v1.5.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1):
~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
pathtrial mcp --help
~~~
Comprueba la versión `1.5.0-rc.1` y que funcione `pathtrial mcp --help`. El ejecutable también debe estar en el `PATH` que recibe tu cliente de IA.
### Paso 2: Elegir un cliente de IA
#### Plugin de OpenAI Codex
Instala el plugin desde el Marketplace de la rama predeterminada `main`:
~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial
codex plugin add pathtrial@pathtrial
codex plugin list
codex mcp list
~~~
El plugin v1.5 `0.3.0` ofrece diez herramientas MCP, y `pathtrial_explain_report` también admite informes diagnose. Puedes pedirle: *«Llama a `pathtrial_capabilities` y comprueba las herramientas MCP disponibles».*
#### Plugin de Claude Code
Dentro de Claude Code, añade el Marketplace e instala el plugin. Consulta las herramientas con `/mcp`:
~~~text
/plugin marketplace add gaochenyang666-droid/PathTrial
/plugin install pathtrial@pathtrial
/mcp
~~~
Para permisos y resolución de problemas, consulta la [guía de integración](docs/ai-integrations.md).
#### Cursor
El Marketplace público de Cursor todavía no incluye este paquete. El plugin está en `plugins/cursor/pathtrial/` y contiene `.cursor-plugin/plugin.json`, un `mcp.json` que solo ejecuta `pathtrial mcp`, las Skills compartidas y una regla de evidencia. No pongas destinos permitidos dentro de `mcp.json`.

Carga local, que es la vía documentada por Cursor para un plugin que aún no está en el Marketplace. Enterprise puede desactivar las importaciones locales:

~~~bash
mkdir -p "${HOME}/.cursor/plugins/local"
rm -rf "${HOME}/.cursor/plugins/local/pathtrial"
cp -R plugins/cursor/pathtrial "${HOME}/.cursor/plugins/local/pathtrial"
~~~

Ejecuta Developer: Reload Window, abre Customize y comprueba las Skills, la regla y el servidor MCP. El nombre puede aparecer como `plugin-pathtrial-pathtrial`.

Si solo quieres el servidor MCP, escribe la misma configuración en `.cursor/mcp.json` del proyecto o en `~/.cursor/mcp.json` (`%USERPROFILE%\.cursor\mcp.json` en Windows). Desde este repositorio:

~~~bash
sh scripts/install-cursor-mcp.sh /path/to/your/project
~~~

La aplicación de escritorio de Cursor puede no heredar `PATHTRIAL_MCP_ALLOW_TARGETS`. Usa el archivo allow-targets de arriba y vuelve a cargar la ventana. Primera petición: *«Llama a `pathtrial_capabilities` y comprueba las herramientas MCP disponibles».* Esta entrega no instaló el paquete en Cursor Desktop ni registró una llamada real del modelo, así que el estado es PARTIAL. Detalles en la [guía de integración](docs/ai-integrations.md).
## Primer uso
### 1. Autorizar un destino que tengas permiso para probar
PathTrial MCP bloquea todas las pruebas de red de forma predeterminada; analizar informes JSON existentes no requiere acceso a la red. **Si inicias el cliente desde una terminal, configura temporalmente los destinos permitidos antes de abrirlo**, sin editar la caché de una versión del plugin:
~~~bash
# Sustituye example.com:443 por un destino autorizado
export PATHTRIAL_MCP_ALLOW_TARGETS="example.com:443"
codex
# Para Claude Code, ejecuta claude en su lugar desde esta terminal
~~~
`PATHTRIAL_MCP_ALLOW_TARGETS` admite varios destinos `host:port` separados por comas o espacios. El servidor MCP debe heredar esta variable. **Una aplicación de escritorio puede no heredar el entorno de la terminal.** No edites el `mcp.json` de la caché del Marketplace. Escribe un destino explícito por línea en un archivo del usuario. Los comodines y los prefijos CIDR se rechazan. Si el archivo no existe, todo sigue denegado por defecto:

~~~bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/pathtrial"
printf '%s\n' 'example.com:443' >> "${XDG_CONFIG_HOME:-$HOME/.config}/pathtrial/allow-targets"
pathtrial mcp --print-allow-path
~~~

En Windows el archivo es `%APPDATA%\pathtrial\allow-targets`. `--print-allow-path` muestra la ruta y no muestra las reglas. Reinicia el cliente después de cambiar el archivo. Consulta la [guía de integración](docs/ai-integrations.md).
No analices sistemas sin autorización.
### 2. Pregunta en lenguaje natural
**La web no responde**
> Usa PathTrial para diagnosticar example.com. Separa los fallos de DNS, TCP, TLS y HTTP y explica el resultado en español.
**Comparar IPv4 e IPv6**
> Compara la tasa de éxito y la latencia de IPv4 e IPv6 de mi VPS. Mantén el mismo puerto, número de rondas y tiempo de espera, y cita las mediciones reales.
**Explicar un informe existente**
> Analiza este informe JSON de PathTrial. Señala anomalías, identificadores de evidencia reales y causas que el informe no puede demostrar.
### 3. Leer el resultado
Revisa `PASS`, `WARN`, `FAIL`, `SKIP` e `INCONCLUSIVE`. `SKIP` no significa que la prueba haya pasado. `INCONCLUSIVE` indica que faltan pruebas. PathTrial registra cada capa y no deduce un bloqueo del operador ni un equipo concreto de pérdida a partir de un solo Ping.
## Cobertura de diagnóstico
DNS, IPv4/IPv6, TCP, TLS, HTTP, ICMP, trazado de rutas, UDP Echo, QUIC, HTTP/3, SOCKS5, HTTP CONNECT, comparación directa y mediante proxy, y correlación de capturas en ambos extremos.
## Usar PathTrial sin un cliente de IA
La [versión candidata pública v1.5.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1) también funciona como CLI independiente sin Rust, Codex ni Claude Code. Descarga el paquete de tu sistema:
- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.5.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)
Cada archivo publicado tiene una suma SHA-256. macOS y Linux usan `scripts/install.sh`. Windows x86_64 usa `scripts/install.ps1`. El script comprueba SHA-256 y copia `pathtrial.exe` a `%LOCALAPPDATA%\PathTrial`. No cambia PATH, el cortafuegos, DNS ni las rutas. `v1.5.0-rc.1` no contiene el archivo de Windows; ejecutarlo contra esa etiqueta falla la descarga y eso no es una instalación correcta. Los límites están en [Windows](docs/windows.md).

~~~powershell
# Solo cuando la versión elegida ya incluye pathtrial-x86_64-pc-windows-msvc.tar.gz
$env:PATHTRIAL_VERSION = "v1.5.0-rc.1"
powershell -File .\scripts\install.ps1
& "$env:LOCALAPPDATA\PathTrial\pathtrial.exe" --version
~~~

Después de instalar:

~~~bash
pathtrial --version
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

Vista sin conexión, línea base local y un par temporal en una máquina que controles:

~~~bash
pathtrial report render report.json --format html --out report.html --redact-ips
pathtrial report render report.json --format svg --out report.svg
pathtrial baseline path
pathtrial baseline save report.json --redact-ips
pathtrial baseline compare later.json --format json
sh scripts/peer.sh demo 0.0.0.0:39002 0.0.0.0:39001 120
~~~

`report render` lee un JSON local. No usa la red y no modifica el archivo de entrada. `--redact-ips` enmascara direcciones solo en esa vista. `baseline save` guarda ese informe en el directorio de datos local. `baseline compare` usa solo ese archivo y el informe actual. Si se pueden comparar directamente, el resultado es better, worse o same y cita los identificadores de evidencia del archivo actual. Si no, la relación es `not_established`; no se inventa historial. El código de salida 2 indica una relación worse. El código 3 indica que no son comparables. `peer.sh` ofrece UDP echo y un servidor collect con tiempo limitado en las direcciones que indiques. No cambia el cortafuegos, DNS ni las rutas, y no guarda las cargas UDP. Las direcciones que no son de loopback necesitan `--allow-public-bind`. Consulta la [guía del CLI](docs/cli.md) para HTTP, QUIC, UDP, proxies, recopilación en ambos extremos y códigos de salida.
## Estado de la beta y límites conocidos
- Núcleo: `v1.5.0-rc.1`, publicado como **versión candidata**, no estable.
- AI Plugins: `0.3.0` (10 herramientas); el plugin anterior v1.4 era `0.2.0` (9 herramientas).
- Paquetes: macOS ARM64, macOS Intel y Linux x86_64, compilados correctamente con SHA-256.
- Verificación: la [publicación v1.5 en tres plataformas](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39255364100) superó las compilaciones y pruebas MCP. Se verificaron las sesiones reales de Codex; el proyecto informó que completó la sesión de Claude Code.
- Las pruebas de red requieren permisos explícitos. No hay interfaz gráfica ni reparación automática. Windows x86_64 se construye en el flujo de publicación posterior; los activos de `v1.5.0-rc.1` no incluyen ese binario. Límites: [Windows](docs/windows.md). Los comandos `report render`, `baseline` y `peer.sh` están en la sección [Usar PathTrial sin un cliente de IA](#usar-pathtrial-sin-un-cliente-de-ia).
Consulta la [matriz de aceptación](docs/ai-plugin-completeness.md) y el [flujo de publicación](https://github.com/gaochenyang666-droid/PathTrial/actions/runs/39149532255). Puedes [informar de errores reproducibles](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md).
## Preguntas frecuentes sobre diagnóstico de red
### Si no abre una web, ¿cómo diferenciar un fallo de DNS, TCP, TLS o HTTP?
Para un destino autorizado, ejecuta `pathtrial scan example.com --profile web --rounds 5 --redact-ips` y después `pathtrial http https://example.com/`. Cada capa se mide por separado; recibir respuesta a un Ping no demuestra que el sitio funcione.
### ¿Sirve para VPS, IPv4/IPv6, proxies SOCKS5 y HTTP/3?
Sí. El CLI permite analizar IPv4/IPv6, TCP/TLS, proxies SOCKS5 y HTTP CONNECT, handshakes QUIC y peticiones HTTP/3 reales cuando el destino admite el protocolo. Consulta la [guía del CLI](docs/cli.md). Un timeout UDP por sí solo no identifica la causa.
### ¿Cómo utilizar PathTrial con Codex, Claude Code o Cursor mediante MCP?
Instala el [núcleo precompilado v1.5.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.5.0-rc.1) y sigue la [guía del plugin](#instalar-los-plugins-de-ia). Codex y Claude Code usan el Marketplace de `main`. Cursor usa el paquete local o `.cursor/mcp.json`. MCP emplea el ejecutable local `pathtrial` y solo prueba destinos autorizados.
### ¿Necesito Rust? ¿Funciona en Windows?
Los binarios publicados de v1.5.0-rc.1 cubren macOS Apple Silicon, macOS Intel y Linux x86_64 sin Rust. Windows x86_64 usa `scripts/install.ps1` cuando una versión posterior incluya ese archivo. `v1.5.0-rc.1` no lo incluye. Hasta entonces, compilar en Windows requiere Rust. `--bind-interface` en Windows es un error y no cambia de interfaz.
### ¿En qué se diferencia PathTrial de ping y curl?
`ping` comprueba principalmente la conectividad ICMP y `curl` se usa habitualmente para HTTP. PathTrial separa las pruebas de DNS, TCP, TLS, HTTP, UDP y QUIC, cita las mediciones reales en informes JSON y no deduce una causa definitiva de un único fallo.
## Informar de errores y contribuir
Usa [GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) para fallos de instalación, resultados incorrectos, cierres inesperados, documentación confusa y problemas de compatibilidad. Elimina direcciones IP reales, dominios, tokens, claves, cookies, suscripciones de proxy y capturas sensibles antes de publicar.
Se aceptan errores reproducibles, pruebas y mejoras. Lee [AGENTS.md](AGENTS.md) antes de enviar código y ejecuta las comprobaciones de formato, Clippy y pruebas.
## Documentación para desarrolladores y licencia
- [Integración con IA y autorización](docs/ai-integrations.md)
- [Guía avanzada del CLI](docs/cli.md)
- [Completitud de AI Plugins](docs/ai-plugin-completeness.md)
- [Índice del proyecto y los esquemas](llms.txt)
- [PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1) · [PR #2](https://github.com/gaochenyang666-droid/PathTrial/pull/2)
PathTrial se distribuye bajo la [licencia MIT](LICENSE). El proyecto nació de un [caso real de diagnóstico IPv4/IPv6 en un VPS RackNerd](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting). Los datos históricos no fueron generados por PathTrial; conviene separar el registro histórico de las mediciones de la herramienta.
