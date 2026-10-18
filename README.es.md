# PathTrial

**Evidence-First Network Diagnostics CLI | Herramienta de diagnóstico de red basada en pruebas**

**Idiomas:** [简体中文](README.md) · [English](README.en.md) · **Español** · [Русский](README.ru.md)

> **Versión de prueba pública (Release Candidate) — v1.3.0-rc.1**
>
> PathTrial sigue en fase de pruebas. Es posible encontrar errores, problemas de compatibilidad o diagnósticos imprecisos. **¡Te invitamos a probarlo, encontrar errores y proponer mejoras!** No necesitas saber Rust para colaborar.
>
> [**Descargar la beta**](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) · [**Informar de un error**](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) · [**Ver incidencias**](https://github.com/gaochenyang666-droid/PathTrial/issues) · [**Caso real**](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting)

> **¿Qué versión debo instalar?** La beta pública [v1.3.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) permite utilizar el CLI sin compilar. La versión **v1.4.0-rc.1 / AI Plugins v0.2.0**, con MCP, sigue en desarrollo en el [PR #2](https://github.com/gaochenyang666-droid/PathTrial/pull/2): **todavía no existe un paquete precompilado público de v1.4**. El binario v1.3 no admite `pathtrial mcp`.

> **Prueba los plugins de IA:** Las integraciones de Codex y Claude Code están disponibles en la [rama de desarrollo AI Plugins v0.2.0](https://github.com/gaochenyang666-droid/PathTrial/tree/codex/ai-plugins-v0.1). Aún no hay paquetes MCP públicos precompilados para v1.4: necesitas Rust 1.84+ y compilar desde el código fuente. Consulta la [guía de instalación](https://github.com/gaochenyang666-droid/PathTrial/blob/codex/ai-plugins-v0.1/README.es.md) e [informa de errores](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md) con las versiones, los pasos y los resultados esperados y reales, sin datos sensibles.

## ¿Qué es PathTrial y para quién sirve?

¿Por qué una web no funciona aunque responda al Ping? ¿Por qué un VPS acepta conexiones TCP, pero el proxy falla? ¿Por qué IPv6 funciona y IPv4 es lento?

**PathTrial es una herramienta gratuita y de código abierto para la terminal**. Comprueba por separado distintas capas de la conexión (DNS, TCP, TLS, HTTP y más), conserva las pruebas de cada comprobación y genera informes que puedes revisar o adjuntar a una solicitud de soporte.

- **Para quién:** personas que investigan problemas de red, administradores de VPS, servicios autoalojados, usuarios de proxy y quienes comparan IPv4 e IPv6.
- **No necesitas Rust para instalarlo:** existen ejecutables ya compilados para los sistemas compatibles. No requiere cuenta ni subir datos a la nube.
- **No cambia tu configuración:** no modifica DNS, rutas, cortafuegos ni ajustes de proxy.
- **No repara la red automáticamente:** muestra lo observado y diferencia los hechos de las causas que todavía no se han demostrado.
- **Solo terminal (CLI):** todavía no hay interfaz gráfica. Utiliza la herramienta únicamente con sistemas propios o para los que tengas autorización.

Por ejemplo, si TCP conecta, pero falla el intercambio TLS, PathTrial registra ambos resultados por separado.

## Plugins de IA para Codex y Claude Code (vista previa para desarrolladores)

PathTrial AI Plugins v0.2.0 permite que **Codex y Claude Code** utilicen el mismo servidor MCP local y las mismas Skills. El núcleo Rust realiza las mediciones reales; la IA interpreta las pruebas guardadas. **El servidor de diagnóstico no requiere una clave de API de IA, pero sí necesitas acceso a cada cliente de IA.**

**Estado del desarrollo:** v1.4.0-rc.1 superó 173 pruebas y CI en Ubuntu 24.04 y macOS ARM/Intel. Las nueve herramientas MCP tienen pruebas locales de protocolo; Codex v0.2 ha realizado llamadas reales del modelo y pruebas de conexión autorizadas. Más detalles en la [matriz de pruebas](https://github.com/gaochenyang666-droid/PathTrial/blob/codex/ai-plugins-v0.1/docs/ai-plugin-completeness.md).

**Compilar la vista previa (requiere Rust 1.84+; para usar solamente el CLI, instala v1.3):**

~~~sh
git clone https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
git checkout codex/ai-plugins-v0.1
cargo build --release --locked
export PATH="$PWD/target/release:$PATH"
pathtrial --version
pathtrial mcp --help
~~~

**Plugin de Codex:** comprueba que el PATH de Codex incluya el nuevo ejecutable y después:

~~~sh
codex plugin marketplace add gaochenyang666-droid/PathTrial --ref codex/ai-plugins-v0.1
codex plugin add pathtrial@pathtrial
codex plugin list
codex mcp list
~~~

**Plugin de Claude Code:** con Claude Code instalado, carga el plugin local desde la raíz del repositorio:

~~~sh
claude plugin validate ./plugins/claude-code/pathtrial
claude --plugin-dir ./plugins/claude-code/pathtrial
~~~

**Autorización explícita:** `pathtrial mcp` bloquea por defecto todas las pruebas de red, pero permite analizar y comparar informes sin conexión. Para un destino autorizado, configura `args` en el `mcp.json` de Codex o el `.mcp.json` de Claude Code como `["mcp", "--allow-target", "example.com:443"]` y reinicia el cliente. No utilices comodines ni pruebes sistemas sin permiso. Lee antes la guía completa.

**Ejemplos:** «¿Por qué mi web tarda demasiado?» «Compara IPv4 e IPv6 de mi VPS». «Analiza este informe JSON y cita los identificadores de prueba reales».

**Enlaces:** [guía completa de instalación y resolución de problemas](https://github.com/gaochenyang666-droid/PathTrial/blob/codex/ai-plugins-v0.1/docs/ai-integrations.md) · [plugin Codex](https://github.com/gaochenyang666-droid/PathTrial/tree/codex/ai-plugins-v0.1/plugins/codex/pathtrial) · [plugin Claude Code](https://github.com/gaochenyang666-droid/PathTrial/tree/codex/ai-plugins-v0.1/plugins/claude-code/pathtrial) · [PR #2](https://github.com/gaochenyang666-droid/PathTrial/pull/2)

## Paso 1 — Descargar PathTrial

### Elige tu sistema operativo

| Equipo | Descarga precompilada |
| --- | --- |
| Mac con Apple Silicon (M1/M2/M3/M4 y posteriores) | [macOS ARM64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-aarch64-apple-darwin.tar.gz) |
| Mac con procesador Intel | [macOS Intel x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-apple-darwin.tar.gz) |
| Linux x86_64 (la mayoría de equipos y VPS Intel/AMD) | [Linux x86_64](https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/pathtrial-x86_64-unknown-linux-gnu.tar.gz) |

**Windows todavía no está disponible.** En la [página de la versión](https://github.com/gaochenyang666-droid/PathTrial/releases/tag/v1.3.0-rc.1) encontrarás también los archivos de verificación SHA-256 de cada paquete.

### Instalar sin Rust (recomendado)

Abre **Terminal** en macOS o una terminal en Linux y ejecuta estas instrucciones una por una:

~~~sh
# Descargar el instalador publicado
curl -fsSLo pathtrial-install.sh https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh

# Revisar el script antes de ejecutarlo
less pathtrial-install.sh

# Instalar: descarga el archivo correcto y comprueba su SHA-256
sh pathtrial-install.sh
~~~

El programa se instala en **~/.local/bin/pathtrial**, sin sudo. Si ya has revisado el instalador y confías en él, puedes usar una sola línea:

~~~sh
curl -fsSL https://github.com/gaochenyang666-droid/PathTrial/releases/download/v1.3.0-rc.1/install.sh | sh
~~~

Ejecutar directamente un script descargado supone un riesgo de seguridad. La verificación SHA-256 confirma el contenido del paquete descargado, pero no sustituye una revisión de la procedencia del propio instalador.

**¿Prefieres instalarlo manualmente?** Descarga el paquete correspondiente, descomprímelo, busca el ejecutable **pathtrial** y abre una terminal en su carpeta. Prueba **./pathtrial --version**. Después puedes moverlo a un directorio de tu PATH.

## Paso 2 — Comprobar la instalación

~~~sh
~/.local/bin/pathtrial --version
~/.local/bin/pathtrial --help
~~~

La versión esperada de esta beta es **1.3.0-rc.1**. Si aparece **command not found**, usa la ruta completa anterior o añade el directorio al PATH durante la sesión actual:

~~~sh
export PATH="$HOME/.local/bin:$PATH"
pathtrial --version
~~~

Si descargaste y extrajiste el paquete manualmente, utiliza la ruta real del ejecutable.

## Paso 3 — Tu primer diagnóstico

Empieza con un análisis corto de una web de ejemplo:

~~~sh
pathtrial scan example.com --profile web --rounds 5 --redact-ips
~~~

Si es necesario, sustituye **pathtrial** por **~/.local/bin/pathtrial**.

¿Qué significa cada opción?

- **example.com:** dominio que se analiza; cámbialo por un destino para el que tengas autorización.
- **--profile web:** perfil de comprobación web/TLS.
- **--rounds 5:** realiza cinco intentos por familia de direcciones cuando corresponda.
- **--redact-ips:** oculta las direcciones IP del informe para facilitar su publicación.

El análisis sigue cinco fases fijas: **entorno del sistema → DNS → TCP/TLS → comparación IPv4/IPv6 → informe**.

**Que TLS funcione no significa que la página responda correctamente por HTTP.** Para realizar una solicitud HTTP real, usa:

~~~sh
pathtrial http https://example.com/
~~~

Para comprobar el puerto SSH de tu propio VPS:

~~~sh
pathtrial scan YOUR_VPS_IP --profile ssh --port 22 --rounds 5 --redact-ips
~~~

Sustituye **YOUR_VPS_IP** por la dirección real de tu servidor. No añadas corchetes angulares.

## Paso 4 — Entender los resultados y el informe

| Estado | Significado |
| --- | --- |
| **PASS** | La comprobación concreta cumple la condición esperada |
| **WARN** | Hay un resultado, pero se ha detectado alguna anomalía |
| **FAIL** | La comprobación no cumple la condición esperada |
| **SKIP** | No procede o no ha sido posible realizarla; **no significa que haya pasado** |
| **INCONCLUSIVE** | Se ha realizado, pero faltan pruebas suficientes para sacar una conclusión |

Por defecto, **scan** crea dos archivos en el **directorio desde el que ejecutaste el comando**:

- **pathtrial-report-<run_id>.md:** informe Markdown para leer o enviar a soporte.
- **pathtrial-report-<run_id>.json:** datos estructurados para análisis o incidencias.

Para encontrar el archivo Markdown:

~~~sh
ls pathtrial-report-*.md
~~~

Si quieres mostrar el informe directamente en la terminal, sin guardar archivos:

~~~sh
pathtrial scan example.com --format markdown --no-files
~~~

Utiliza **--format json** para obtener JSON. Cada conclusión debe mostrar las pruebas que la respaldan y lo que **todavía no se ha demostrado**. Una sola prueba fallida no identifica al proveedor, al dispositivo que filtra ni al salto exacto donde se pierden los paquetes.

Códigos de salida: **0** sin WARN/FAIL, **1** error de la herramienta, **2** existe algún WARN/FAIL y **3** conclusión insuficiente. No son una puntuación de salud de toda tu conexión a Internet.

## Paso 5 — Elegir una prueba concreta

Empieza por **scan** y **http**. Si necesitas investigar algo específico, usa estas opciones:

| Qué quieres comprobar | Ejemplo |
| --- | --- |
| Comparar resoluciones DNS | pathtrial dns example.com --server 223.5.5.5 |
| Ping y latencia | pathtrial ping 1.1.1.1 --count 5 |
| Ruta y saltos de red | pathtrial trace example.com --max-hops 15 |
| TCP/SSH de tu VPS | pathtrial scan YOUR_VPS_IP --port 22 --profile ssh |
| Comprobar un HTTP 200 | pathtrial http https://example.com/ --expect-status 200 |
| Intercambio QUIC real | pathtrial quic example.com --port 443 --alpn h3 |
| Solicitud HTTP/3 real | pathtrial http3 https://example.com |
| Comparar dos informes | pathtrial compare old.json new.json |

**Sobre QUIC/HTTP3:** el destino debe ser compatible y la ruta UDP tiene que funcionar. Que venza el tiempo de espera no demuestra, por sí solo, que el servidor carezca de HTTP/3.

### Proxy SOCKS5 o HTTP CONNECT

Si ya utilizas un proxy SOCKS5 local autorizado en el puerto 1080:

~~~sh
pathtrial proxy https://example.com/ --proxy socks5://127.0.0.1:1080
~~~

Compara la conexión directa y la conexión mediante proxy:

~~~sh
pathtrial proxy https://example.com/ --proxy socks5://127.0.0.1:1080 --compare-direct
~~~

Para un proxy HTTP CONNECT, utiliza una dirección como **http://127.0.0.1:8080**. Esta beta no admite autenticación de proxy con usuario y contraseña. Que funcione una solicitud no demuestra estabilidad a largo plazo.

### UDP Echo real: dos ventanas de terminal

**Terminal A:** inicia un servidor temporal que solo escucha en la interfaz de bucle local:

~~~sh
pathtrial endpoint --udp-echo --bind 127.0.0.1:39001
~~~

**Terminal B:** ejecuta la prueba:

~~~sh
pathtrial udp --target 127.0.0.1:39001 --mode echo
~~~

Detén el servidor de la Terminal A con **Ctrl+C**. Esto solo comprueba el **bucle local**. Para probar un servidor remoto, necesitas ejecutar allí un servicio Echo compatible y contar con autorización. **UDP Echo no demuestra que QUIC o Hysteria2 funcionen.**

### Recopilación en ambos extremos (avanzado)

Puedes practicar primero en el mismo equipo con dos terminales:

~~~sh
# Terminal A: escucha conexiones
pathtrial collect --role server --task-id demo --listen 127.0.0.1:39001 --max-seconds 30 --output server.json

# Terminal B: inicia la prueba mientras A sigue escuchando
pathtrial collect --role client --task-id demo --target 127.0.0.1:39001 --rounds 5 --output client.json

# Cuando terminen las dos recopilaciones
pathtrial correlate client.json server.json
~~~

Esto relaciona **eventos de conexiones TCP**, no capturas de paquetes. Sin capturas y sincronización de relojes, no permite saber qué dispositivo perdió los paquetes.

## ¿Has encontrado un error? ¡Cuéntanoslo!

**Esta beta pública existe precisamente para aprender de las pruebas reales.** Son bienvenidos los avisos sobre cierres inesperados, bloqueos, diagnósticos incorrectos, errores de instalación, incompatibilidades, instrucciones confusas y problemas de traducción. También aceptamos propuestas de funciones.

**[Abrir un informe de error en GitHub Issues](https://github.com/gaochenyang666-droid/PathTrial/issues/new?template=bug_report.md)**

Un informe útil debería indicar:

1. **Entorno:** sistema operativo y versión, arquitectura de CPU y versión de PathTrial.
2. **Cómo reproducirlo:** el comando utilizado, con los datos sensibles sustituidos.
3. **Resultado esperado:** qué pensabas que iba a ocurrir.
4. **Resultado real:** error, código de salida o captura de pantalla.
5. **Frecuencia:** siempre, a veces o solo con determinadas condiciones.

**Protege tus datos:** elimina contraseñas, tokens, claves SSH, enlaces de suscripción, cookies, URL privadas y direcciones sensibles antes de publicar. La opción **--redact-ips** no borra automáticamente toda la información privada de los registros e informes.

La plantilla de GitHub puede tener campos en chino, pero puedes enviar el informe en **español o inglés** (también en chino).

## Plataformas y limitaciones conocidas

- **Disponibles:** macOS Apple Silicon, macOS Intel y Linux x86_64. Sus compilaciones y pruebas se han ejecutado en entornos CI nativos.
- **Pendientes:** Windows, interfaz gráfica, reparación automática de la red, captura automática de paquetes e identificación exacta del equipo que pierde los paquetes.
- **Fake-IP / TUN:** el software de proxy local puede alterar DNS y las rutas aparentemente directas. PathTrial indica cuando las pruebas pueden resultar engañosas.
- **ICMP y UDP:** un Ping fallido no implica que TCP falle; recibir ICMP Port Unreachable tampoco equivale a recibir una respuesta válida de UDP Echo.
- **HTTP/3:** las solicitudes reales funcionan en un servidor local controlado; una ruta pública concreta por UDP 443 podría agotar el tiempo de espera.
- **Advertencia sobre la beta:** no la utilices como única señal para monitorización o decisiones críticas en producción.

**Nota sobre versiones:** el programa descargable procede de la [etiqueta v1.3.0-rc.1](https://github.com/gaochenyang666-droid/PathTrial/tree/v1.3.0-rc.1). La rama **main** puede ir temporalmente por detrás de esa versión. El desarrollo de las funciones avanzadas se documentó en [Milestone C PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1).

**Nota sobre idiomas:** estas traducciones se refieren a la **documentación README**. No significa que toda la salida de la herramienta o los informes generados estén traducidos al español o al inglés.

## Para desarrolladores — Compilar desde el código fuente

**Para lectores de IA y agentes de programación:** [llms.txt](llms.txt) reúne los documentos y esquemas; [AGENTS.md](AGENTS.md) establece las reglas de desarrollo y de uso de pruebas.

Solo necesitas Rust estable **si compilas desde el código fuente**, no si utilizas los paquetes precompilados. Para reproducir la versión publicada:

~~~sh
git clone https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
git checkout v1.3.0-rc.1
cargo build --release --locked
./target/release/pathtrial --version
~~~

Pruebas y comprobaciones:

~~~sh
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
~~~

Consulta la ayuda **--help** de cada comando para ver más opciones. Si contribuyes una corrección, intenta incluir una prueba que reproduzca el problema.

## Origen del proyecto, licencia y agradecimientos

PathTrial nació de un [caso real de diagnóstico IPv4/IPv6 en un VPS de RackNerd](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting). Esas mediciones históricas son anteriores al desarrollo de PathTrial y **no deben presentarse como resultados obtenidos con esta herramienta**. También existe una [guía en chino para reproducir las pruebas del caso](https://github.com/gaochenyang666-droid/racknerd-ipv6-troubleshooting/blob/main/docs/使用-PathTrial-复现排障.md).

El código fuente se distribuye bajo la [licencia MIT](LICENSE). Agradecemos incidencias, correcciones de documentación y pull requests. **¡Gracias por ayudarnos a probar PathTrial!**
