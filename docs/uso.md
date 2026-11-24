# Uso

Referencia de la herramienta tal como está hoy.

## Instalar y abrir

Se instala con `install.sh` (Linux y macOS) o `install.ps1` (Windows) de un release firmado: el README dice cómo, y [releases.md](releases.md) qué verifican. En el modo nativo, `cyber` corre el agente con tu Node. En el modo contenedor, `cyber` es el lanzador (un solo archivo, en `distro/lanzador/`): arranca Docker, monta tu proyecto, tus credenciales y tus datos, y abre la TUI en la imagen. Hay uno para Linux y macOS (`cyber`, sh) y otro para Windows (`cyber.ps1`, con `cyber.cmd` que lo llama).

Parate en la carpeta del proyecto y corré:

```sh
cyber
```

Actualizar y desinstalar, en los dos modos:

| Comando | Qué hace |
| --- | --- |
| `cyber --actualizar` | Busca el último release publicado; si es más nuevo, verifica la firma de su `SHA256SUMS` y la suma de lo que baja, y recién entonces lo instala (nativo) o reemplaza el lanzador y baja su imagen (contenedor). Con terminal pregunta; sin terminal sólo actualiza con `--si` (en el modo contenedor, la imagen sí se baja). Nunca baja de versión. |
| `cyber --version` | La versión instalada. |
| `sh ~/.local/share/orobas-sec/install.sh --desinstalar` | Saca lo que instaló el instalador (en el modo nativo también `cyber --desinstalar`); tus datos quedan. |

Opciones del lanzador (sólo en el modo contenedor):

| Comando | Qué hace |
| --- | --- |
| `cyber --instalar` | Copia el lanzador al PATH del usuario (en sh, `~/.local/bin/cyber`). |
| `cyber --cerrar-docker si\|no` | Si cerrar Docker Desktop al salir cuando lo abrió el lanzador. Sin valor muestra el estado. |

En Windows (desde Windows 10 2004), si abrís `cyber` desde la consola clásica (conhost), el lanzador lo reabre en Windows Terminal cuando está instalado; si no, te ofrece instalarlo con `winget` (o abre la Store). Con «No, esta vez no» seguís en la consola clásica, y con «Dejá de preguntar» no se vuelve a ofrecer. Esto pasa solo al abrir la interfaz: no con comandos (`cyber jobs`), ni con `-p`, ni con la salida redirigida, ni por SSH.

Desde el código, sin Docker: `npm ci` y `bin/cyber` (ver [desarrollo.md](desarrollo.md)). Dentro de un contenedor, el programa se niega a arrancar si no están montadas las carpetas de datos y credenciales, para no perder sesiones.

## Subcomandos

`cyber --help` imprime esta lista (sale de `cliHelp()` en `src/manual.ts`). Cuando no hay subcomando, abre la TUI.

| Comando | Qué hace |
| --- | --- |
| `cyber` | Abre la TUI Foco con una sesión nueva. |
| `cyber -c` | Retoma la última sesión, aunque siga trabajando. |
| `cyber -s <id>` | Retoma una sesión por ID (alcanza con el prefijo que muestran los avisos). |
| `cyber --resumen` | Lista las sesiones recientes de todos tus proyectos y abre la que elijas. |
| `cyber -p "texto"` | Un turno sin TUI; la respuesta va a stdout y los avisos de herramientas a stderr. Al final imprime uso y costo. |
| `cyber -p "texto" --detach` | Deja el turno trabajando en segundo plano y vuelve. No sirve con Docker. |
| `cyber -s <id> --continuar` | Retoma un turno interrumpido (caída o reinicio). |
| `cyber jobs` | Sesiones del proyecto y su estado. |
| `cyber scope [add\|excluir\|quitar <reglas> \| limpiar]` | Ver o editar el alcance autorizado. |
| `cyber findings [id [estado motivo]]` | Hallazgos registrados; con un id, el detalle; con estado y motivo, lo cambia. |
| `cyber informe [en]` | Genera el informe Markdown del proyecto; con `en`, los textos fijos en inglés. |
| `cyber costos` | Gasto de API del proyecto. |
| `cyber tope [USD\|sin]` | Tope de gasto del proyecto, sumando todas sus sesiones. |
| `cyber uso` | Uso completo del proyecto; lo exporta a `cyber-informes/uso-<fecha>.json`. |
| `cyber memoria [consulta]` | Busca en la memoria del proyecto. |
| `cyber evidencia [hash]` | Artefactos guardados; con hash, su contenido. |
| `cyber cobertura` | Cobertura de la evaluación de la última sesión. |
| `cyber grafo [faltantes \| vecinos <nodo> \| caminos <a> → <b> \| hallazgo <id> \| exportar json\|dot\|mermaid]` | Grafo de hechos de la última sesión (o la de `-s`): resumen, lo que falta probar, vecinos, caminos, el subgrafo de un hallazgo; exportar a `cyber-informes/`. |
| `cyber extension` | Muestra cómo instalar y emparejar la extensión de Chromium (carpeta `extension/`). |
| `cyber toolbox` | Escáneres, navegador, plataformas vinculadas y modelo, con cómo instalar lo que falte. |
| `cyber orobas` | Vincula, actualiza o revoca la clave de orobas. |
| `cyber hackerone` | Vincula, actualiza o revoca tu cuenta de HackerOne. |
| `cyber <plataforma>` | Vincula o revoca `github`, `vercel`, `supabase`, `aws`, `gcloud`, `azure`, `cloudflare` o `kubernetes`. |
| `cyber login hackerone` | Pide usuario y token de la API y los guarda cifrados. |
| `cyber login <plataforma>` | Vincula la plataforma con el login de su propia CLI. |
| `cyber logout hackerone` | Borra las credenciales de HackerOne. `logout <plataforma>` solo te indica cerrar la sesión con la CLI de esa plataforma. |
| `cyber h1 [buscar <texto> \| todos \| alcance <programa>]` | Programas de HackerOne; `alcance` carga el de uno. |
| `cyber daemon [stop]` | Corre el daemon en primer plano, o lo detiene. |

El agente también entiende pedidos hablados («cloná este repo», «subí el presupuesto a 5», «armá el informe»): usa sus propias herramientas para lo mismo que hacen estos comandos.

### Flags

| Flag | Qué hace | Por defecto |
| --- | --- | --- |
| `-m`, `--model proveedor/modelo` | Modelo base de la sesión (el del bucle). `faux` simula respuestas. | `CYBER_MODEL`, o `defaultModel` de la configuración, o `orobas/glm-5.3-flash` |
| `-b`, `--presupuesto USD` | Tope de gasto por sesión; `sin` lo quita. | 2.00 |
| `-r`, `--peticiones N` | Tope de peticiones HTTP de la sesión; `sin` lo quita. | sin tope; 2000 si el alcance es de un programa de HackerOne |
| `--ritmo N` | Máximo de peticiones por segundo; `sin` lo quita. | sin ritmo; 5 si el alcance es de un programa de HackerOne |
| `--agente texto` | User-Agent propio. | `ElevateAICyber/0.1`; con tu usuario de HackerOne si el alcance es de un programa |
| `--cabecera "Nombre: valor"` | Cabecera fija para cada pedido al objetivo; repetible y guardada por proyecto. | ninguna |
| `-C`, `--dir carpeta` | Carpeta del proyecto. | la actual |
| `-c`, `--continue` | Retoma la última sesión. | |
| `-s`, `--session id` | Retoma una sesión. | |
| `-p`, `--print texto` | Un turno sin TUI. | |
| `--detach`, `--continuar`, `--resumen` | Ver la tabla de subcomandos. | |
| `-h`, `--help` | Imprime la ayuda. | |

`--chequeo` es una opción interna del lanzador: verifica que estén montadas las carpetas.

## Comandos de la TUI

Escribí `/` y aparece la lista; Tab completa. Salen de `TUI_COMMANDS` en `src/manual.ts` y de los alias de `src/tui/foco.ts`.

| Comando | Qué hace |
| --- | --- |
| `/sesiones` | Sesiones del proyecto: retomar, nueva, ramificar, renombrar. Dentro: `/jobs` (`/trabajos`, su estado) y `/continuar` (retoma un turno interrumpido). |
| `/hallazgos` (también `/findings`) | Lista de hallazgos, detalle por id o cambio de estado. Dentro: `/verificar`, `/verificacion`, `/evidencia`, `/cobertura`, `/grafo`, `/memoria`. |
| `/informe [en]` | Genera el informe Markdown; con `en`, en inglés. Dentro: `/trayectorias`, `/datos`. |
| `/datos [compartir \| local \| no \| subir]` | Trazas: muestra qué incluyen, qué modo rige y dónde quedan las locales; cambia el modo (también desde `/config`, fila «Trazas») o sube las sesiones anteriores del proyecto (sólo en `compartir`). Por línea de comandos: `cyber datos …`. |
| `/alcance` (también `/scope`) | Alcance autorizado: ver, `add`, `excluir`, `quitar`, `limpiar`, `referencia` (documentación o código público que el agente sólo lee con `reference_read`, nunca prueba). Cada cambio, venga de donde venga, se avisa con lo que entra y sale. Un laboratorio local: `localhost`, `127.0.0.1` y `::1` son la misma máquina; `127.0.0.1:8899` cubre sólo ese puerto y `localhost` todos. El que levanta el agente en loopback lo suma él con su puerto, sin pedirte cita; una IP de tu red (`192.168.1.20:8080`, `10.0.0.0/8`, `host.docker.internal`) la sumás vos. Dentro: `/senuelos`, `/identidad`, `/consentimiento`, `/permisos`, `/agente`, `/deteccion`. |
| `/limites` | Topes y gasto. Dentro: `/presupuesto <USD>` o `sin`, `/peticiones <N>` o `sin`, `/ritmo <N>` o `sin`, `/costos`. |
| `/modelo [nombre]` | Sin argumento lista los modelos; con uno, cambia el de la sesión, el modelo base del bucle (por ejemplo `/modelo glm`). Un modelo caro se respeta, pero se avisa cuánto cuesta cada paso. |
| `/modelo fuerte [nombre\|defecto]` | Modelo fuerte: el que consulta el agente con `deep_reason` para decidir algo difícil, y el de los subagentes que delega con `strong`. Por defecto `cyber-ultra-1.0`. |
| `/router auto\|fijo\|estado` (también `/modelo router`) | Router de modelos. En `auto` (por defecto en sesiones nuevas) el bucle corre siempre con el modelo de la sesión, el ejecutor, y ante una decisión (un pedido nuevo, un candidato, un hallazgo, una objeción de cierre, falta de avance) el ejecutor escribe un traspaso compacto y el fuerte trabaja sobre él con contexto propio: una consulta, o un tramo con herramientas para comprobar un candidato. Lo que sólo es leer, planificar o redactar va primero a un modelo estándar; si se niega, al sin barandas. `estado` muestra quién corrió cuántos pasos, las negativas, el gasto y el ahorro contra todo el bucle en el fuerte. `/router medio <modelo>\|no`: modelo opcional para leer código sobre un traspaso. El pie dice quién trabaja. |
| `/razonamiento si\|no\|defecto\|bajo\|medio\|alto\|max` (también `/effort`) | Razonamiento previo del modelo: prenderlo, apagarlo o elegir cuánto razona. Sin argumento abre un menú con los niveles que tiene el modelo de la sesión. |
| `/ultra [tarea]` | Reparte una tarea entre varios harnesses en paralelo. |
| `/conexiones` | Cuentas y servicios conectados. Dentro: `/github`, `/vercel`, `/supabase`, `/aws`, `/gcloud`, `/azure`, `/cloudflare`, `/kubernetes` (iniciar sesión o revocar), `/orobas`, `/hackerone`, `/h1 [alcance <programa>]` y `/correo`. |
| `/herramientas` (también `/toolbox`) | Qué escáneres están instalados. Dentro: `/perfil`, `/escaneres si\|no`, `/mcp`. |
| `/diseño` (también `/diseno`, `/layout`) | Cómo se ve: pestañas, ventanas, mouse, tema y efecto descifrado. Dentro: `/ventanas`, `/pestañas`, `/tema`. |
| `/config` | Todos los ajustes del proyecto, incluida «Investigación automática» (apagada por defecto). Dentro: `/idioma`. |
| `/inicio` | Repite el inicio guiado. |
| `/novedades` | Lo nuevo de la TUI. |
| `/ayuda` (también `/help`) | Teclas y comandos. |
| `/limpiar` (también `/clear`) | Limpia la pantalla y vuelve al sello; conserva sesión y memoria. No funciona con un turno en curso. |
| `/salir` (también `/quit`) | Salir. |

Cada grupo abre un menú sin argumento; `/limites presupuesto 5` va directo al miembro. `/cola`, `/ya` y `/orquesta` no salen en la lista de `/` pero siguen andando.

Lo que escribís mientras el agente trabaja queda en cola y sale junto como el turno siguiente; arriba del editor se ve `en cola (N) «…»` hasta que el agente lo toma, y al tomarlo avisa. Reenviar el mismo texto mientras espera no lo encola dos veces. Si no querés esperar, Ctrl+Y (o `/ya texto`, o «mandar ya» en `/cola`) corta el turno como Esc (la llamada en curso cierra con su resultado) y arranca uno nuevo con lo que esperaba en cola y tu mensaje, en ese orden. Con `!` adelante, en cambio, el mensaje le llega al modelo sin cortar el turno.

Una sesión reabierta, también la que se reanuda sola tras una caída, conserva su tope de gasto (`/presupuesto`).

## Teclas

| Tecla | Acción |
| --- | --- |
| Enter | Envía el mensaje. |
| Ctrl+J, Alt+Enter (o Shift+Enter en terminales con protocolo kitty) | Salto de línea. |
| Tab | Completa el comando de la lista de `/`. |
| Ctrl+PgUp y Ctrl+PgDn, o Ctrl+N y Ctrl+P (además de Alt+1…9 y Alt+Izquierda/Derecha) | Cambiar de pestaña. |
| Tab y Shift+Tab (o Alt+Arriba/Abajo) | En una pestaña con el detalle completo, elegir la acción. |
| Flechas arriba y abajo | Historial, o moverse por la lista de `/` si está abierta. |
| Esc | Detiene el turno en curso. |
| Ctrl+Y (o Ctrl+Enter en terminales que lo distinguen) | Corta el turno en curso y manda ya lo escrito, después de lo que había en cola; con el editor vacío, manda la cola. |
| Ctrl+C | Detiene el turno; sin turno, borra lo escrito; dos veces seguidas (en 1,5 s) sale. |
| Ctrl+D | Sale, con el editor vacío. |
| Ctrl+L | Igual que `/clear`. |
| Izquierda, derecha, Inicio, Fin, y Ctrl+Izquierda o Alt+Izquierda (y derecha) | Mover el cursor, por letra o por palabra. |

## Ventanas

La TUI puede mostrar varias cosas a la vez, cada una en su recuadro con el nombre de la sesión y la pestaña. `/diseño ventanas` (o `/ventanas`) elige la forma: una (la de siempre), lado a lado, principal y lateral, tres o 2×2. Cada ventana tiene sus pestañas y muestra una sesión; dos ventanas pueden mostrar la misma. La activa lleva `●` en el título y el borde en acento; el editor de abajo es uno solo y escribe en la sesión de esa ventana (`para <sesión>:`). Cada ventana pide unas 40 columnas y 8 filas: si no entran, se esconden las que sobran y el borde avisa. La forma, las pestañas de cada ventana, los divisores y la lista se recuerdan y son las mismas en todos los proyectos.

| Tecla | Acción |
| --- | --- |
| F6 y Shift+F6 | Pasar a la ventana siguiente o a la anterior. |
| F2 | Mostrar la lista de sesiones a la izquierda y enfocarla; con ella enfocada, esconderla. |
| Flechas arriba y abajo, Enter, Esc | Con la lista enfocada: recorrer, elegir y volver al editor. Elegir una sesión la abre en la ventana activa (`+ nueva` abre una sesión nueva); elegir una pestaña la activa. |
| Ctrl+Shift+Izquierda/Derecha | Pasar la pestaña activa a la ventana de al lado. |
| Ctrl+Alt+Izquierda/Derecha | Correr el divisor dos columnas. |

En la lista (F2), debajo de cada sesión, aparecen sus subagentes y los harnesses de `/ultra` que están corriendo en ella; las corridas anteriores (sólo lectura) van en un grupo aparte, al final. Enter abre uno en la ventana activa; si es de otra sesión, la ventana pasa a esa sesión (el borrador no se pierde). Un subagente muestra su objetivo, lo que va haciendo y, al terminar, el informe, que es el último texto del subagente (no hay transcripción completa). Un harness muestra su tarea, la rama y el final de su salida, y se actualiza solo cada 3 segundos mientras está a la vista. Nunca se abren solos: al arrancar uno hay un aviso, y al terminar la ventana queda con `✓` o `✗` en el borde (`⋯` mientras trabaja).

Si tu terminal no manda esas combinaciones, `/ventanas` también mueve la pestaña y cambia el ancho. Con el mouse prendido, un clic activa una ventana (o elige una fila de la lista) y arrastrar el borde mueve el divisor; una selección no cruza de una ventana a otra.

En la lista, `◆` marca las sesiones abiertas (con sus pestañas debajo) y `⚠` las que esperan tu respuesta. Cerrar una ventana, o achicar la forma, no cierra su sesión: sigue conectada y en la lista. Si una sesión que no estás mirando pide un permiso de shell, no te cambia de ventana: su recuadro dice `⚠ … espera respuesta`, arriba del editor aparece un aviso, y el pedido se abre cuando pasás a su ventana (lo que escribías no se pierde).

Al salir con un turno en curso, el turno sigue en segundo plano y `cyber -c` vuelve a él, también con Docker y también si cerraste la última ventana de esa carpeta. En `cyber -p` dentro de Docker, Ctrl+C deja el turno terminando en segundo plano (como fuera de Docker).

### Varias ventanas de terminal en la misma carpeta

Podés abrir `cyber` en dos o más terminales sobre la misma carpeta: todas comparten un mismo contenedor y ven las mismas sesiones y el mismo trabajo en curso. Cerrar una ventana no afecta a las otras. Si cerrás la última mientras el agente está trabajando, cyber te avisa y el turno termina en segundo plano; al volver a abrir cyber en esa carpeta lo encontrás terminado. Si abrís cyber en otra carpeta, esa tiene su propio contenedor. Si actualizás la imagen con otras ventanas abiertas, esas siguen con la versión anterior hasta que las cierres todas.

## Novedades

Al abrir cyber, lo nuevo que todavía no viste sale en un panel «Novedades» (hasta 3, las más recientes); se marcan vistas por máquina. La primera vez que usás cyber no se muestran. `/novedades` (`/news`) las lista todas, de la más nueva a la más vieja. Con más de una ventana, la barra de estado recuerda `F6 ventana · F2 lista · /ventanas`.

## Cuentas

- **orobas**: la clave de la suscripción. Cargala con `/orobas` (o `cyber orobas`); se guarda cifrada. Si definís `OROBAS_API_KEY`, esa gana.
- **HackerOne**: usuario y token personal de la API (HackerOne no ofrece OAuth). `/hackerone` o `cyber login hackerone`. Después `cyber h1` lista tus programas y `cyber h1 alcance <programa>` carga su alcance. Sin token, `cyber h1 alcance <programa>` (o «vamos con https://hackerone.com/<programa>/policy_scopes») carga el de un programa público desde el CSV que publica HackerOne; el código fuente del programa queda como lectura de referencia y un laboratorio local que ya estaba en el alcance se conserva.
- **Cyber Bounty**: creá una clave de agente `bb_` en `https://cyber.elevateai.ar/bounty/agentes` y cargala con `cyber login cyber-bounty` (entrada oculta, almacén de credenciales) o `CYBER_BOUNTY_KEY`. No sirve `OROBAS_API_KEY`. `cyber logout cyber-bounty` borra la guardada. Pedile al agente los programas (`cyber_bounty_programs`) y nombrá cuál querés cargar (`cyber_bounty_scope`). Se importan exclusiones, política y conducta; el ritmo HTTP sólo se ajusta hacia abajo. La cabecera, ventana y prohibición de acciones destructivas quedan en las notas y hay que respetarlas también en herramientas externas. Para enviar, `cyber_bounty_submit` arma una vista previa completa desde un hallazgo verificado y su evidencia HTTP/curl. Revisala y mandá un mensaje nuevo con el código mostrado, dentro de 15 minutos: un «dale» no alcanza. Si cambia el hallazgo o el alcance, hace falta otra vista previa; si el programa se pausa, hay que recargarlo. `cyber_bounty_status` consulta el id del reporte o un hallazgo enviado. El envío queda registrado en los eventos del proyecto para no repetirlo. Si la API pide verificar identidad, hacelo en `https://cyber.elevateai.ar/cuenta`.
- **Plataformas** (`github`, `vercel`, `supabase`, `aws`, `gcloud`, `azure`, `cloudflare`, `kubernetes`): se vinculan con `/<plataforma>`, `cyber <plataforma>` o `cyber login <plataforma>`. Se usa el login de la CLI oficial de cada una; en Docker ese login queda en la carpeta de credenciales (`plataformas/`), así sobrevive al contenedor. La imagen trae `gh`, `supabase`, `kubectl` y `aws`; el resto no viene por tamaño. Si no se puede abrir un navegador, el agente te da una URL y un código para aprobar donde quieras.

### Cabeceras citadas por el programa

Al cargar un alcance, buscá «Revisá en la política las cabeceras citadas» en `/alcance`. Si la mención viene de un activo, aparece junto a ese activo. Si viene del texto general importado, aparece en las notas del programa. Son propuestas sin aplicar: revisá la política original y confirmá nombre y valor antes de configurarlas. Si el texto es ambiguo, no inventes un valor.

Para identificar todos los pedidos al objetivo, usá `--cabecera "X-HackerOne: tu-usuario"` (repetible), `/alcance cabecera X-HackerOne: tu-usuario`, o pedíselo al agente para que lo registre con `session_settings` y una cita de tu mensaje. `/alcance` muestra las cabeceras vigentes; `/alcance cabecera quitar X-HackerOne` la saca. Se guardan por proyecto y alcanzan al cliente HTTP, las sondas, el navegador propio y los escáneres HTTP. Las trazas HTTP conservan sus valores de identificación; las credenciales de las identidades siguen tapadas. Una cabecera fija `User-Agent` gana sobre el valor por defecto o `--agente`. `Authorization`, `Cookie` y otras cabeceras de credenciales se rechazan: cargalas como identidades. nmap sólo permite escaneo de puertos sin sondas de versión ni scripts cuando hay cabeceras fijas; el harness te avisa si pedís un modo que no puede identificarse.

La detección reconoce declaraciones como `X-HackerOne-Research: [H1 username]`. Una indicación genérica como «identificate con tu usuario» requiere lectura manual. El aviso es informativo. Si el programa exige una cabecera en cada pedido, el aviso por sí solo no satisface esa condición.

## Dónde viven los datos

| Qué | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Datos (sesiones, hallazgos, memoria, artefactos) | `$XDG_DATA_HOME/elevate-cyber` o `~/.local/share/elevate-cyber` | `~/Library/Application Support/elevate-cyber` | `%LOCALAPPDATA%\elevate-cyber` |
| Credenciales cifradas y configuración | `$XDG_CONFIG_HOME/elevate-cyber` o `~/.config/elevate-cyber` | `~/.config/elevate-cyber` (el lanzador usa esa ruta) | `%APPDATA%\elevate-cyber` |
| Informes y exportaciones | `cyber-informes/` dentro del proyecto | igual | igual |

Cada proyecto tiene su subcarpeta en `datos/proyectos/<nombre>-<hash>/`. Lo único que se escribe dentro de tu proyecto es `cyber-informes/`. `CYBER_DATA_DIR` y `CYBER_CREDENTIALS_DIR` cambian las rutas (ver [configuracion.md](configuracion.md)). El detalle de lo que hay adentro está en [arquitectura.md](arquitectura.md).

Las credenciales van en archivos `<nombre>.secreto`, cifrados con AES-256-GCM. La llave sale del llavero del sistema (Secret Service en Linux, Keychain en macOS, DPAPI en Windows). Sin llavero se guardan sin cifrar con permiso 0600, y el lanzador te avisa una vez.

Si tu proyecto tenía una carpeta `.cyber/` de una versión anterior, sus datos se mudan solos a la carpeta de datos la primera vez que arranca bien: se copia, se verifica y recién entonces se borra.

## Verificación de candidatos

Un verificador independiente (otro agente, con contexto limpio) reproduce cada candidato con una petición propia y un control antes de darlo por verificado. Por defecto corre solo, con un tope de USD 1 de gasto del verificador por sesión (después espera `/verificar`; se cambia con `/verificacion`), al cierre de cada turno, sobre los candidatos de la sesión que todavía no vio con esa evidencia: avisa en una línea qué va a verificar y hasta cuánto gasta (USD 0,50 por candidato) y, al terminar, qué dio y cuánto costó. No repite un candidato que ya vio si su evidencia no cambió (cambiar el título o el resumen no cuenta; evidencia nueva, sí), ni uno nuevo con la misma evidencia y el mismo activo. Un candidato cuyo activo quedó fuera del alcance vigente no se manda al modelo: se avisa una vez. `/verificacion` (o `/config` → «Verificación automática») elige el modo, que se guarda en `config.json` como `"verificacion"`: `automatica` (el de siempre), `a-pedido` (sólo con `/verificar`) o `tope <USD>` (automática hasta ese gasto del verificador por sesión; después espera `/verificar`). `/verificar` y `/verificar <id>` verifican a mano en cualquier modo.

Cada veredicto trae sus comprobaciones, visibles en `/verificar`, `/hallazgos` y el informe: **alcance del programa** (la regla que cubre el activo y si da recompensa, según el CSV o la API de HackerOne, o la exclusión del programa citada), **política** (si la cargada nombra esa clase como fuera de alcance), **coherencia** (la evidencia demuestra el impacto que se afirma), **código abierto** (si sigue en la rama principal y en la última versión, o qué commit o PR lo arregló) y **duplicados** (avisos del repositorio, CVE del banco local). Lo que no se pudo mirar dice «no comprobado», nunca aprobado. Un activo excluido o fuera del programa, o una evidencia que no demuestra el impacto, no se dan por verificados.

## Presupuesto y tope de gasto

- **Por sesión**: 2.00 USD por defecto. Cambialo con `-b`, con `/presupuesto <USD>` o quitalo con `sin`.
- **Por proyecto**: `cyber tope <USD>` fija un tope que suma todas las sesiones del proyecto; `cyber tope sin` lo quita; sin argumento muestra el actual y lo gastado. Sirve para repartir presupuesto por persona.
- `/costos` y `cyber costos` muestran el desglose (entrada, caché, salida) por sesión y por subagente; `cyber uso` exporta todo.

## Informes

`/informe` o `cyber informe` genera un Markdown a partir de la evidencia ya guardada (no vuelve a tocar el objetivo) y lo escribe en `cyber-informes/<fecha>.md` dentro del proyecto, con permiso 0600. Las credenciales que aparezcan se tachan. `cyber uso` escribe `cyber-informes/uso-<fecha>.json`.

Los hallazgos verificados van en su sección, de mayor a menor severidad, y los candidatos sin verificar en otra aparte («no se envían sin verificar»); pistas, descartados e informativos, en el anexo. Cada hallazgo trae estado, severidad con el puntaje y el vector CVSS 3.1 si está registrado (sin vector, muestra el rango de la estimación), activo, las versiones que dicen las respuestas de la evidencia (`Server`, `X-Powered-By`, `generator`), lo observado, la interpretación registrada, los pasos con cada petición y su respuesta guardadas y el mismo pedido como `curl` copiable (cada identidad va como variable de entorno, `${IDENTIDAD_ANA}`, nunca su valor), un apartado de impacto que avisa si no se escribió aparte, una remediación genérica para la clase (rotulada como tal) y los límites declarados.

`/informe en`, `cyber informe en` o pedírselo al agente («armá el informe en inglés») generan la versión en inglés, en `cyber-informes/<fecha>-en.md`: cambian los textos fijos, los nombres de estado y severidad (`verified`, `high`) y los marcadores de redacción (`<identity ana>`, `[credential redacted]`). Lo que escribió el agente o el operador en los hallazgos (título, resumen, motivo, límites, clase) queda en el idioma en que se escribió. Sirve para enviar a HackerOne o a un cliente que no lee castellano.

## Grafo de hechos

El harness arma, mientras el agente trabaja, un grafo de lo que ya se sabe del objetivo: hosts y servicios, rutas canónicas con su método (`GET /api/usuarios/{n}`), los parámetros que aceptan, qué obtuvo cada identidad en cada ruta, los objetos cuyos ids le llegaron a cada una, tecnologías con versión, cookies (por nombre y banderas, nunca el valor), credenciales encontradas en el código (dónde están, nunca el valor), archivos y funciones del fuente bajado, hallazgos y cómo se encadenan, hipótesis y CVE cruzados. Lo alimenta solo, sin pedirle nada al modelo: cada respuesta HTTP, cada id cosechado y cada prueba cruzada, cada sonda, lectura de fuente, recon y hallazgo. Cada hecho guarda de dónde salió (la herramienta, el hash del intercambio o artefacto que lo prueba, quién lo escribió —el agente, un subagente, el verificador— y cuándo) y un estado: **observado** (lo vio el harness), **inferido** (sólo visto en un enlace, un contrato o el código, o dicho por el agente), **verificado** o **refutado**.

Para el agente es la herramienta `grafo` (siempre a mano): `faltantes` le dice qué falta probar con nombres reales (objetos de una identidad que otra nunca pidió, rutas que respondieron a una y la otra no probó, escrituras sin probar sobre recursos que responden, redirecciones sin destino externo, parámetros sin sondear, rutas vistas y nunca pedidas, hipótesis abiertas); `vecinos`, `caminos` y `hallazgo` lo dejan mirar alrededor de un nodo. Con `grafo_anotar` (del catálogo) registra una hipótesis o una relación, que queda inferida: sólo el harness la vuelve observada, y un hallazgo verificado o descartado la confirma o la refuta. Los hallazgos vinculados quedan como aristas «habilita», y la regla de cierre propone escaladas con los nodos reales («open redirect en `/salir` según `?url` + flujo OAuth visto en `GET /oauth/authorize` → probá el robo del código»). El verificador y el informe muestran la cadena con su evidencia.

`/grafo` (en el grupo de `/hallazgos`) o `cyber grafo` te muestran lo mismo, y lo de fuera del alcance marcado:

| Uso | Qué muestra |
| --- | --- |
| `/grafo` | Resumen: cuánto hay de cada cosa, servicios, tecnologías, identidades (rutas que les respondieron y que les negaron), hallazgos, cadenas, hipótesis y cuántas pruebas concretas faltan. |
| `/grafo faltantes [tipo]` | Lo que falta probar, lo más profundo primero; `tipo` filtra (`objeto`, `identidad`, `escritura`, `redireccion`, `parametro`, `ruta`, `hipotesis`). |
| `/grafo vecinos <nodo>` | Un nodo y sus relaciones, con estado y evidencia. El nodo se nombra como se lo piensa: `/api/usuarios/7`, `GET /api/usuarios/{n}`, `ana`, el id de un objeto, el prefijo de un hallazgo o un CVE. |
| `/grafo caminos <a> → <b>` | Hasta tres caminos más cortos entre dos nodos. |
| `/grafo hallazgo <id>` | El subgrafo de un hallazgo: dónde se observó, quién accede ahí, su cadena y las escaladas propuestas. |
| `/grafo exportar json\|dot\|mermaid` | Escribe el grafo en `cyber-informes/grafo-<fecha>.<ext>` (0600) para verlo con Graphviz o Mermaid, o procesarlo. Mermaid se recorta a 400 nodos; el JSON va entero. |

Las salidas son tablas (TOON), en orden estable, con tope y por páginas (`página 2`). Es por programa, como la memoria: lo de otro programa que trabajaste en la misma carpeta no se ve. Al retomar una sesión sigue ahí (antes, el mapa de rutas probadas se perdía al cerrar). La primera vez que se abre un proyecto de antes del grafo, entra lo que ya había: hallazgos, ids cosechados, pruebas cruzadas, hipótesis de la memoria y la superficie de los intercambios guardados, cada cosa en el programa de su sesión.

El grafo no autoriza nada: el alcance se mira con el vigente cada vez que se lee, y lo que quedó afuera (o es un señuelo marcado) no se propone nunca; al agente ni siquiera se le nombra, sólo se le cuenta. Lo que dice el objetivo entra como dato acotado (rutas canónicas, nombres de parámetro, nunca valores de cuerpos ni cabeceras de credencial) y cada salida para el modelo lo aclara en su primera línea. Nada tuyo entra: tus identidades van por nombre y tus valores quedan tapados antes de guardar. Crece con tope (60.000 nodos y 250.000 aristas por programa; lo que no entra se avisa con el evento `grafo.tope`). `CYBER_GRAFO=no` lo apaga entero.

## Salir de la caja negra: código de la web y del programa

Pedile al agente que «baje el código» de una web del alcance o que mire el fuente del programa. `web_source_pull` deja en `fuente-web/<host>/` lo que sirve la web (página, scripts y los chunks que cargan después), el código original si la web publica mapas de fuente (`fuentes/`) y un `manifiesto.json` con la URL, el sha256 y el intercambio de cada archivo; todo por el cliente HTTP, así que cuenta peticiones y respeta alcance, ritmo, tope y señuelos (lo de otros hosts no se baja y se dice). Sobre esa carpeta, o sobre un repositorio clonado en la del proyecto, `code_crypto` marca las funciones propias que importan para romper algo (derivación de claves y tokens, hashes, firmas, cifrado, aleatoriedad, secretos fijos, permisos y montos que decide el cliente) con archivo:línea y cómo se prueba cada una, y `hash_crack` confirma offline una derivación contra un valor propio observado (por ejemplo, que tu token es `sha256(email:hora)`). En la caja, REA (`rea.analyze_javascript_application`) arma además el grafo de módulos y rutas de ese JavaScript. Lo que sale del código es una pista hasta que el agente lo muestra con una petición propia. Lo bajado lleva código del objetivo: no lo publiques.

## Banco de CVE/CWE y habilidades

El agente puede cruzar el stack que ve en el objetivo con el banco local de vulnerabilidades (vulndb: todos los CVE publicados con CVSS, CWE y marcas de explotación, más el catálogo CWE). Son tres herramientas del catálogo, sólo lectura y sin tocar el objetivo: `cve_search` (por producto, texto, CWE, año, CVSS, KEV o exploit público), `cve_detail` (descripción, versiones afectadas, referencias, y con la versión vista responde si aplica, no aplica o no se puede determinar) y `cwe_detail` (una clase de debilidad con sus CVE recientes de ejemplo). La habilidad `cve-stack` (`skills/cve-stack/SKILL.md`) le dice cuándo usarlas y cómo registrar el resultado: una versión en rango es una pista, no un hallazgo; sólo lo observado sin daño y dentro del alcance llega a candidato.

Las habilidades son guías cortas en Markdown con frontmatter (`name`, `description`, `tools`): el prompt lleva nombre y descripción, y el agente lee el cuerpo con `skill_load`, que además carga las herramientas declaradas. Las del repo viven en `skills/`; las tuyas, en `skills/` dentro de la carpeta de configuración (junto a `config.json`).

Cinco guías de método cubren `autorizacion` (objeto, función, rol), `autenticacion` (login, sesiones y recuperación), `logica-de-negocio` (precios, estados y carreras), `inyecciones` (consultas, expresiones y rutas) y `ssrf-y-salidas` (webhooks e importadores con receptor propio). El agente las lee con `skill_load` cuando la situación coincide; el método base sigue en el prompt. Todas exigen pruebas dentro del alcance, datos propios y evidencia antes de registrar un candidato; para el vector remiten a `severidad`.

El prompt pide consultar `grafo faltantes` antes de elegir el siguiente paso o cerrar, `grafo hallazgo <id>` para buscar eslabones y `grafo caminos` cuando dos hechos podrían unirse. Si una hipótesis sobre código necesita un harness ejecutable, el agente propone en el cierre una investigación, el motivo y un tope. `/config` → «Investigación automática» (o `/investigacion-auto si`) permite abrirla sin un pedido nuevo: el tope es el menor entre USD 2 y la mitad del presupuesto restante de la sesión. Apagada, `investigation_start` sigue exigiendo una cita textual del operador. Sin presupuesto definido o con gasto sin contabilizar, la apertura automática se rechaza.

La habilidad `severidad` documenta las ocho métricas base de CVSS 3.1 y cómo fundamentarlas con los artefactos guardados. En `finding_record` y `finding_update`, el campo opcional `cvss` es el vector completo. Su puntaje determina la severidad. Si incluye métricas temporales o ambientales definidas, el informe identifica el grupo empleado. Los hallazgos anteriores conservan su estimación. La revisión al cierre señala candidatos medios o superiores pendientes de vector y cobertura parcial cuando el grafo tiene pendientes y quedó sin consultar.


Si el banco trae señales de explotación (`epss`, `epss_percentile`, `kev`, `kev_date_added`, `kev_ransomware`, `ssvc`), el agente las ve: EPSS como porcentaje, la fecha de alta en KEV, «ransomware» (marca `R` en `cve_search`) y la decisión SSVC de CISA; `cve_search` ordena primero lo que más se explota (ransomware, KEV, EPSS). Sin esos campos todo sigue igual.

### CVEs nuevos

Lo publicado esta semana tarda en llegar al banco. Por eso el harness baja solo el feed público de Zero Wire (Cloudflare Radar): los 100 CVE críticos y los 100 altos más recientes, como mucho cada 6 h por proyecto (la caché vive en la base del proyecto; si falla, reintenta a la hora y avisa una sola vez). El pedido va a una URL fija con su propio User-Agent y no lleva nada del objetivo.

Cada CVE nuevo se cruza con las tecnologías de la sesión: lo que mostraron las respuestas del objetivo (`Server`, `X-Powered-By`, `X-Generator`, `X-Jenkins`, el `generator` del HTML, los plugins y temas de WordPress, jQuery, Angular, Next.js…), los nombres del alcance (`gitlab.ejemplo.com`, la nota de un activo, la del programa) y los productos que el agente consultó en vulndb. El cruce es conservador: palabras de producto distintivas (nunca «server», «plugin», «web», «api»; PHP o Express sólo con una versión al lado), un plugin no cuenta como el producto («WordPress Newsletters plugin» no es WordPress), un título «Producto: …» dice de quién es el CVE, y si la versión vista queda fuera del rango que publica el texto se descarta. Si vulndb ya conoce el CVE, sus productos afectados confirman o descartan el cruce.

Lo que cruza se avisa una vez por CVE y sesión: a vos, con el link («CVE nuevo crítico que podría aplicar a PHP 8.3.10 en app.ejemplo.com: CVE-… (9.2) — … · link»), y al agente en su próximo turno, en un bloque `<cves_nuevos>` que le pide confirmar producto y versión antes de probar y no registrar hallazgos sin evidencia. Un turno en curso no se corta. Queda el evento `cve.nuevo`.

`/cves` (en el grupo de `/hallazgos`; `cyber cves` en la CLI) muestra el estado del feed, las tecnologías de la sesión, los cruces (avisados y descartados, con el motivo) y los últimos críticos aunque no crucen, con su link; `/cves actualizar` lo baja ya. El agente tiene `cve_recent` en el catálogo para pedir los últimos CVEs de un producto o los que cruzan. Se apaga con `"cveFeed": false` en `config.json` o `CYBER_CVE_FEED=no`; en el modo simulado no baja solo, y en el benchmark ciego (sin banco) tampoco existe.

El banco no viene en la imagen Docker: `cyber toolbox` dice si está disponible. Lo busca como `vulndb` en el PATH del harness o en `CYBER_VULNDB`. Sin él, las herramientas explican qué falta y el agente sigue sin ese cruce.
