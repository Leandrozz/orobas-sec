# Configuración: variables de entorno

Esta tabla sale de leer `src/`, `bin/` y `distro/lanzador/`. Con el lanzador de Docker casi todo esto ya viene resuelto: no hace falta que definas nada salvo, si querés, `OROBAS_API_KEY` (también la podés cargar con `/orobas`).

El archivo de configuración de proveedores (`config.json`) no es una variable: su ruta sí (`CYBER_CONFIG`). Dentro de él van `defaultModel` (el modelo base, el del bucle del agente), `strongModel` (el modelo fuerte, el que consultan `deep_reason` y `delegate` con `strong`), `providers` (con `baseUrl`, `apiKeyEnv` y `models` con sus tarifas; un modelo puede llevar `idleTimeoutMs` para tolerar más silencio), `mcp` (servidores MCP por stdio) y `playwright` (dónde está Playwright; ver `CYBER_PLAYWRIGHT`).

## Usar tu plan de ChatGPT

orobas-sec admite **Sign in with ChatGPT** para la edición de código abierto que corre en tu máquina. Necesitás una cuenta elegible de ChatGPT Plus o Pro. Ejecutá `cyber login chatgpt` o abrí `/chatgpt` en la TUI, elegí **Continue with ChatGPT** y autorizá la app en el navegador. Si no se abre, copiá la URL que muestra la terminal. El callback escucha en `127.0.0.1`; en Docker usa el puerto que publica el lanzador junto al puente del navegador. Si Docker corre en una máquina remota, reenviá ese puerto a la máquina del navegador antes de autorizar.

El ingreso usa registro dinámico de OpenAI, PKCE, un estado y un nonce nuevos para cada intento. El identificador del cliente y los tokens quedan cifrados en el almacén de secretos de orobas-sec. Para esto hace falta el llavero del sistema o `CYBER_SECRETS_KEY`; la sesión no se guarda en texto plano. No toma credenciales de otras aplicaciones. `cyber logout chatgpt` intenta revocar el refresh token y borra los tokens locales; conserva el registro del cliente para volver a ingresar.

Después de entrar, elegí un modelo de la lista con `/modelo` o indicá `-m chatgpt/<modelo>`. El catálogo proviene de `GET /v1/models` con tu sesión. El uso del plan se administra en [Manage usage](https://chatgpt.com/settings/usage). Si no concediste `chatgpt.tokens.use.direct`, entrá de nuevo y habilitá el permiso; también podés usar otro proveedor ya configurado.

En pruebas locales solamente, `CHATGPT_AUTH_URL` y `CHATGPT_BASE_URL` apuntan el OAuth y Responses a servidores simulados. No son necesarios para el uso normal.

## Modelo y proveedores

| Variable | Qué hace | Por defecto |
| --- | --- | --- |
| `CYBER_MODEL` | Modelo base (el del bucle), en formato `proveedor/modelo`. Va después de `-m` y antes de `defaultModel`. | `defaultModel` de `config.json`; si tampoco está, `orobas/glm-5.3-flash` |
| `CYBER_STRONG_MODEL` | Modelo fuerte, en formato `proveedor/modelo`. Lo que elija el operador en la sesión (`/modelo fuerte`) va primero. | `strongModel` de `config.json`; si tampoco está, `orobas/cyber-ultra-1.0` con la suscripción, o el mismo modelo base con otro proveedor |
| `CYBER_CONFIG` | Ruta del `config.json` de proveedores, tarifas y MCP. | `$XDG_CONFIG_HOME/elevate-cyber/config.json` (o `~/.config/elevate-cyber/config.json`) |
| `CYBER_CONFIG_BASE` | Ruta de una configuración base de solo lectura (la imagen de Docker deja `/opt/elevate-cyber/distro/config.ejemplo.json`). Va debajo de la del usuario: gana el usuario, por proveedor y por modelo, y las actualizaciones de la base siguen llegando. Un modelo copiado a mano a tu `config.json` conserva su tarifa vieja y no recibe las nuevas. | sin definir |
| `OROBAS_API_KEY` | Clave de la suscripción orobas. Tiene prioridad sobre la guardada con `/orobas`. | sin definir: se usa la clave del almacén cifrado |
| `OROBAS_BASE_URL` | Endpoint de la suscripción orobas. | `https://cyber.elevateai.ar/api/v1` |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY` | Claves de los proveedores predefinidos. `ollama` no pide clave. Un proveedor propio declara su variable en `apiKeyEnv` dentro de `config.json`. | sin definir |

## Carpetas

| Variable | Qué hace | Por defecto |
| --- | --- | --- |
| `CYBER_DATA_DIR` | Carpeta de datos (sesiones, hallazgos, memoria, artefactos). | Linux: `$XDG_DATA_HOME/elevate-cyber` o `~/.local/share/elevate-cyber`; macOS: `~/Library/Application Support/elevate-cyber`; Windows: `%LOCALAPPDATA%\elevate-cyber` |
| `CYBER_CREDENTIALS_DIR` | Carpeta de las credenciales cifradas (`*.secreto`). | `$XDG_CONFIG_HOME/elevate-cyber` o `~/.config/elevate-cyber` |
| `XDG_CONFIG_HOME` | Base de la carpeta de configuración y credenciales (también la lee el guardado de HackerOne). | `~/.config` |
| `XDG_DATA_HOME` | Base de la carpeta de datos en Linux. | `~/.local/share` |
| `XDG_RUNTIME_DIR` | Dónde van el socket y el log del daemon (en una subcarpeta privada por usuario). | directorio temporal del sistema |
| `LOCALAPPDATA` | Base de la carpeta de datos en Windows. | `~\AppData\Local` |
| `CYBER_PROYECTO_HOST` | Ruta real del proyecto en tu máquina. Dentro del contenedor, el proyecto está en `/proyecto`; el lanzador pasa acá la ruta de afuera para que el proyecto tenga siempre el mismo identificador. Si está definida, el cliente se considera «en contenedor». | sin definir |

## Credenciales y cifrado

| Variable | Qué hace | Por defecto |
| --- | --- | --- |
| `CYBER_SECRETS_KEY` | Llave de cifrado de las credenciales: base64 de 32 bytes. La pone el lanzador desde el llavero del sistema (en Windows, protegida con DPAPI). Si está mal formada, falla en vez de guardar en claro. | sin definir: se busca en el llavero con `secret-tool`; sin llavero, las credenciales se guardan sin cifrar con permiso 0600 |
| `H1_USERNAME`, `H1_API_TOKEN` | Credenciales de HackerOne tomadas del entorno (por ejemplo en CI). Tienen prioridad sobre las guardadas. Hacen falta las dos. | sin definir |
| `CYBER_PLATAFORMAS_HOME` | `HOME` aislado donde las CLIs de las plataformas (gh, supabase, aws, etc.) guardan su login. | en contenedor: `<carpeta de credenciales>/plataformas`; fuera de contenedor, el `HOME` real |

Las claves `CYBER_SECRETS_KEY`, `OROBAS_API_KEY` y `H1_API_TOKEN` no se le pasan a los servidores MCP que el agente arranca (`src/mcp.ts`).

## Red y herramientas

| Variable | Qué hace | Por defecto |
| --- | --- | --- |
| `CYBER_LISTENER_HOST` | IP donde las sondas abren un canal de escucha (recepción de callbacks). Solo la fija el operador; el modelo no elige dónde escuchar. | sin definir: sin canal |
| `CYBER_LISTENER_PORT` | Puerto de ese canal. | elegido por el sistema |
| `CYBER_PLAYWRIGHT` | Dónde está Playwright: el `index.mjs`, la carpeta del paquete (`…/node_modules/playwright`) o la carpeta donde hiciste el `npm install`. Va antes que la clave `playwright` de `config.json` y que las instalaciones conocidas. Si la ruta no sirve, el error lo dice y no se busca en otro lado. `cyber toolbox` muestra cuál se usa y de dónde salió, sin importarlo. | la clave `playwright` de `config.json`; si no, `~/.local/share/cyber-browser/node_modules/playwright`, `/opt/cyber-browser/node_modules/playwright` y por último donde lo encuentre Node desde el harness (sus `node_modules`, `NODE_PATH`, carpetas globales) |
| `CYBER_CHROMIUM` | Ruta al ejecutable de Chromium. | busca en rutas conocidas |
| `CYBER_CHROMIUM_ARGS` | Argumentos extra para Chromium, separados por espacios. | ninguno |

En la imagen Docker estas tres vienen definidas (`/opt/cyber-browser/.../playwright/index.mjs`, `/usr/bin/chromium`, `--no-sandbox`).

Para no tocar la shell, Playwright también se señala en `config.json` con la misma forma de ruta: `"playwright": "/ruta/node_modules/playwright"` (al lado de `defaultModel`).

## Terminal y TUI

| Variable | Qué hace | Por defecto |
| --- | --- | --- |
| `CYBER_ANIMATIONS` | `0` omite la animación del sello al abrir. | animación activa (salvo `TERM=dumb`, sesión retomada o con contenido) |
| `CYBER_GRAPHICS` | Forma de dibujar el sello: `auto`, `kitty`, `sixel`, `iterm2`, `braille`, `ascii` u `off` (sin imágenes, usa Braille). | detección automática |
| `CYBER_CELL_SIZE` | Tamaño de la celda de la terminal en píxeles, `ANCHOxALTO` (por ejemplo `8x17`). Hace falta para Sixel si la terminal no lo informa. | se usa 10x20 como estimación y Sixel cae a Braille |
| `CYBER_CONSOLE` | `conhost` marca la consola clásica de Windows: bordes en ASCII, sello en ASCII y enlaces sin OSC 8. El lanzador de Windows lo pone cuando no hay Windows Terminal (`WT_SESSION`). | sin definir |
| `NO_COLOR` | Si existe, sin colores ni imágenes. | sin definir |
| `TERM` | `dumb` desactiva enlaces clickeables, animación e imágenes. | el de tu terminal |
| `TERM_PROGRAM`, `TERM_FEATURES`, `KITTY_WINDOW_ID`, `TMUX`, `STY` | Solo se leen para detectar capacidades gráficas (Kitty, iTerm2, WezTerm, Ghostty, Sixel) y para no usar imágenes en tmux o screen. | los de tu terminal |
| `LC_ALL`, `LC_MESSAGES`, `LANG` | Idioma de los mensajes: si empieza con `es`, español; si no, inglés. Se consultan en ese orden. | español si no se puede determinar |
| `DISPLAY`, `WAYLAND_DISPLAY` | Indican si hay entorno gráfico, para decidir si un login de plataforma puede abrir el navegador. | los del sistema |

## Privacidad

| Variable | Qué hace |
| --- | --- |
| `CYBER_TRAZAS` | Modo de trazas: `no` (por defecto: no se guarda ni se comparte nada), `local` o `compartir`. Las trazas son todo el material de entrenamiento: cada pedido al modelo y su respuesta, el registro de cada turno, la trayectoria de cada sesión y la cita de los consentimientos. Con `compartir` van al servicio orobas, con los secretos tapados (sólo de las sesiones con el proveedor orobas). Con `local` no sale contenido al servicio y el material queda en JSONL en `…/elevate-cyber/proyectos/<id>/trazas` (formato en su `LEEME.md`). Con `no` no sale contenido ni se arma material. Siguen valiendo `0`, `false`, `off` y `cantidades` como `no`; un valor desconocido también es `no`. Manda sobre `"trazas"` de `config.json`, que se cambia con `/datos` o `/config`. El servicio aplica el más restrictivo entre éste y el de la cuenta (cyber.elevateai.ar/cuenta/trazas), y el agente también. Los lanzadores de Docker la pasan al contenedor al crearlo. |

## Lanzador de Docker (`distro/lanzador/`)

Las leen `cyber` (sh) y `cyber.ps1`. Con `OROBAS_API_KEY` definida en tu shell, el lanzador se la pasa al contenedor.

| Variable | Qué hace | Por defecto |
| --- | --- | --- |
| `CYBER_IMAGE` | Imagen a correr. | la que fija el release, por digest; en una copia de desarrollo del lanzador, `ghcr.io/leandrozz/orobas-sec:latest` |
| `CYBER_NO_UPDATE` | Si tiene valor, el lanzador no consulta nada al arrancar: ni imagen nueva ni el último release de GitHub (que con una imagen fijada mira una vez por día, sólo con terminal y sin mandar datos). | sin definir: busca |
| `CYBER_PRUEBA_WT` | Solo para pruebas del lanzador de Windows: un número de build (por ejemplo `19041`) que habilita el paso a Windows Terminal fuera de Windows y con la entrada redirigida. | sin definir |
| `CYBER_RELEASES_URL` | De dónde bajan los releases `cyber --actualizar` y los instaladores (un espejo, o pruebas en `http://127.0.0.1`). La seguridad no depende de la URL sino de la firma: sólo se acepta lo firmado con la clave que trae el lanzador. | `https://github.com/Leandrozz/orobas-sec/releases` |
| `CYBER_CERRAR_DOCKER` | `0` o `1`: si cerrar Docker Desktop al salir cuando lo abrió el lanzador. Gana sobre `cyber --cerrar-docker si\|no` para esa corrida. | `cyber --cerrar-docker`; si no se fijó, sí cierra |

El lanzador de Windows guarda sus preferencias en `%APPDATA%\elevate-cyber\lanzador.conf`; con `windows_terminal=no` (la respuesta «Dejá de preguntar») no ofrece instalar Windows Terminal. Para volver a activar la pregunta, borrá esa línea.

El lanzador de sh también reenvía al contenedor `LANG`, `LC_ALL`, `TERM`, `COLORTERM`, `TERM_PROGRAM`, `KITTY_WINDOW_ID` y `WT_SESSION`.

## Internas y de pruebas

| Variable | Qué hace |
| --- | --- |
| `CYBER_SIN_MONTAJES` | `1` permite arrancar dentro de Docker sin las carpetas de datos y credenciales montadas. Sin ellas, lo que se guarde se pierde al cerrar el contenedor: por eso el arranque se niega por defecto. Está pensada para pruebas. |
| `CYBER_TEST_DEMORA_ARRANQUE` | Milisegundos de espera artificial al arrancar el daemon. Solo la usan las pruebas. |
