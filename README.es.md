# PathTrial — Diagnóstico de red CLI y plugins MCP

**Herramienta gratuita y de código abierto para el diagnóstico de redes, escrita en Rust.** Comprueba DNS, TCP, TLS, HTTP/3, QUIC, UDP, proxies y conectividad IPv4/IPv6 de sitios web y servidores VPS; genera informes JSON con pruebas verificables. Los plugins MCP locales para Codex y Claude Code están en versión preliminar.

**Idiomas:** [简体中文](README.md) · [English](README.en.md) · **Español** · [Русский](README.ru.md)

[**Descargar la beta del CLI**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**Informar de un error**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Guía de integración con IA**](docs/ai-integrations.md) · [**Guía del CLI**](docs/cli.md)

> **Estado:** el CLI público es `v1.3.0-rc.1`. AI Plugins `v0.2.0` es una vista previa para desarrolladores del núcleo `1.4.0-rc.1` y todavía no tiene un paquete precompilado público. El README está disponible en cuatro idiomas; la salida del CLI y los informes no están totalmente traducidos.

> **Prueba los plugins de IA:** Los plugins de Codex y Claude Code están disponibles en la rama de desarrollo AI Plugins v0.2.0. Comparte errores de instalación, compatibilidad o diagnóstico en [GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) con versiones, pasos y resultados, eliminando datos sensibles. **Todavía no hay binarios públicos v1.4 con MCP; esta versión requiere Rust 1.84+ y compilar desde el código fuente.**

## ¿Qué problemas de red puede diagnosticar PathTrial?

Que un Ping funcione no demuestra que DNS, TCP, TLS, HTTP y la aplicación estén sanos. PathTrial mide cada capa por separado, conserva las pruebas y explica qué causas siguen sin demostrarse.

- **Una web abre de forma intermitente:** separa DNS, conexión TCP, TLS y estado HTTP.
- **El VPS acepta conexiones, pero el proxy falla:** revisa TCP, UDP Echo, QUIC, HTTP/3 y la ruta del proxy.
- **IPv4 e IPv6 se comportan de forma distinta:** compara éxito y latencia con el mismo destino, puerto, rondas y tiempo de espera.

PathTrial se ejecuta localmente. No sube informes ni modifica DNS, rutas, cortafuegos o ajustes de proxy. Codex y Claude Code utilizan el mismo motor mediante un servidor MCP local. Todas las pruebas de red se bloquean hasta autorizar el destino de forma explícita.

## Instalar los plugins de IA

> **Vista previa para desarrolladores:** instalar un plugin no instala el programa de diagnóstico. El plugin actual necesita un ejecutable `1.4.0-rc.1` compatible con `pathtrial mcp`. El binario público `v1.3.0-rc.1` no puede ejecutar MCP y todavía no existe una versión precompilada pública de `v1.4.0-rc.1`.
>
> Mientras no exista ese paquete, la vista previa requiere Rust 1.84 o posterior y compilar el proyecto una vez. Si solo necesitas el CLI estable, ve a “Usar PathTrial sin un cliente de IA”.

### Paso 0: preparar un núcleo PathTrial compatible

~~~bash
git clone --branch codex/ai-plugins-v0.1 --depth 1 https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
cargo build --release --locked
export PATH="$PWD/target/release:$PATH"

pathtrial --version
pathtrial mcp --help
~~~

La versión debe ser `1.4.0-rc.1`. Comprueba que este directorio esté en el `PATH` que recibe Codex o Claude Code.

### OpenAI Codex

La instalación desde el Marketplace remoto se verificó con un `CODEX_HOME` temporal. `codex plugin list` debe mostrar la versión `0.2.0` y `codex mcp list` debe mostrar `pathtrial` habilitado.

~~~bash
codex plugin marketplace add gaochenyang666-droid/PathTrial --ref codex/ai-plugins-v0.1
codex plugin add pathtrial@pathtrial

codex plugin list
codex mcp list
~~~

La sesión real del modelo con Codex `v0.2.0` completó un análisis local autorizado y la explicación del informe: TCP tuvo `1/1` éxitos, se obtuvo el identificador `tcp_ipv4_001` y un destino no autorizado fue rechazado con `target_not_allowed`.

Después pide a Codex:

> Llama primero a `pathtrial_capabilities` y confirma la versión de PathTrial y las nueve herramientas MCP.

### Claude Code

El plugin de Claude Code permite la carga local. Hasta que los archivos se integren en la rama `main`, ejecuta lo siguiente desde la raíz del repositorio de desarrollo:

~~~bash
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
~~~

Dentro de la sesión, utiliza `/mcp` para comprobar si las herramientas `pathtrial` están registradas y realiza una prueba de diagnóstico o análisis de informes.

## Primer uso

### 1. Autorizar un destino que tengas permiso para probar

La configuración predeterminada `["mcp"]` bloquea todas las pruebas de red. La explicación y comparación de informes siguen funcionando sin conexión. Para autorizar un destino, cambia `args` en la configuración del plugin a:

~~~json
["mcp", "--allow-target", "example.com:443"]
~~~

- Plugin de Codex instalado: edita `~/.codex/plugins/cache/pathtrial/pathtrial/0.2.0/mcp.json`.
- Plugin local de Claude Code: edita `plugins/claude-code/pathtrial/.mcp.json`.
- Repite `--allow-target` para añadir más destinos.
- Reinicia el cliente de IA después de editar el archivo.
- No uses comodines ni pruebes sistemas sin autorización.

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

El CLI público `v1.3.0-rc.1` se instala sin Rust. No incluye MCP y no se puede usar con los plugins de IA.

- [macOS Apple Silicon](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz)
- [macOS Intel](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz)
- [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz)

Los archivos SHA-256 están en la [página de la versión v1.3.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1). Revisa el instalador antes de ejecutarlo:

~~~bash
curl -fsSLo pathtrial-install.sh \
  https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh
less pathtrial-install.sh
sh pathtrial-install.sh

~/.local/bin/pathtrial --version
~~~

Primer análisis:

~~~bash
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

`--redact-ips` genera un informe más seguro para compartir. Consulta la [guía del CLI](docs/cli.md) para HTTP, QUIC, UDP, proxy, capturas en ambos extremos y códigos de salida.

## Estado de la beta y límites conocidos

- PathTrial Core: versión de desarrollo `1.4.0-rc.1`.
- AI Plugins: vista previa para desarrolladores `0.2.0`.
- CLI precompilado público: `v1.3.0-rc.1`, sin MCP.
- Verificación automática: 173 pruebas superadas y CI en Ubuntu 24.04, macOS ARM y macOS Intel.
- Codex: `v0.2.0` superó una sesión real del modelo, un análisis autorizado, la explicación de pruebas y el rechazo de destinos no autorizados.
- Claude Code: se proporcionan carga local del plugin, configuración MCP y Skills compartidas.

Consulta la [matriz de completitud de AI Plugins](docs/ai-plugin-completeness.md). No están disponibles Windows, una interfaz gráfica, la reparación automática de la red, la captura automática de paquetes ni la atribución exacta del equipo que pierde tráfico. Fake-IP/TUN, UDP 443 público y HTTP/3 todavía pueden depender de la red local.

## Preguntas frecuentes sobre diagnóstico de red

### Si no abre una web, ¿cómo diferenciar un fallo de DNS, TCP, TLS o HTTP?

Para un destino autorizado, ejecuta `pathtrial scan example.com --profile web --rounds 5 --redact-ips` y después `pathtrial http https://example.com/`. Cada capa se mide por separado; recibir respuesta a un Ping no demuestra que el sitio funcione.

### ¿Sirve para VPS, IPv4/IPv6, proxies SOCKS5 y HTTP/3?

Sí. El CLI permite analizar IPv4/IPv6, TCP/TLS, proxies SOCKS5 y HTTP CONNECT, handshakes QUIC y peticiones HTTP/3 reales cuando el destino admite el protocolo. Consulta la [guía del CLI](docs/cli.md). Un timeout UDP por sí solo no identifica la causa.

### ¿Cómo utilizar PathTrial con Codex o Claude Code mediante MCP?

Sigue las [instrucciones de instalación](#instalar-los-plugins-de-ia). Los plugins usan el motor local en Rust. El CLI público `v1.3.0-rc.1` no incluye MCP; la vista previa requiere compilar el núcleo `1.4.0-rc.1` y autorizar el destino expresamente.

### ¿Necesito Rust? ¿Funciona en Windows?

Los paquetes CLI públicos ya compilados no requieren Rust y admiten macOS Apple Silicon, macOS Intel y Linux x86_64. Windows aún no está disponible. Para compilar o probar MCP en desarrollo sí se necesita Rust.

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
