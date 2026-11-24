# Orobas en integración continua

`cyber ci` corre Orobas sin nadie mirando: en cada pull request, por horario o a pedido, contra **tu** staging o el
entorno efímero del PR. Evalúa sólo lo que el equipo autorizó en un archivo versionado, con topes duros de gasto y de
tiempo, y le devuelve al pipeline un código de salida estable. Sólo hacen fallar el job los hallazgos que el
**verificador independiente** reprodujo con una prueba y un control; los candidatos se informan aparte y no bloquean.

Salidas: SARIF 2.1.0 para la pestaña de seguridad, un JSON propio estable, un resumen en Markdown para el comentario del
PR (uno solo, que se edita), JUnit opcional y el registro de lo que hizo. Nada de lo que sale lleva secretos.

- [Inicio rápido con GitHub Actions](#inicio-rápido-con-github-actions)
- [Autorizar el alcance](#autorizar-el-alcance)
- [Referencia de la configuración](#referencia-de-la-configuración)
- [Variables de entorno y opciones](#variables-de-entorno-y-opciones)
- [Códigos de salida](#códigos-de-salida)
- [Salidas](#salidas)
- [Línea de base: huellas, supresiones, comparación y retest](#línea-de-base-huellas-supresiones-comparación-y-retest)
- [Sólo lo que cambió](#sólo-lo-que-cambió)
- [La GitHub Action](#la-github-action)
- [Ejemplos completos](#ejemplos-completos)
- [GitLab CI, la imagen genérica y otros CI](#gitlab-ci-la-imagen-genérica-y-otros-ci)
- [Cuenta, modelos y trazas](#cuenta-modelos-y-trazas)
- [Seguridad del uso en CI y modelo de amenaza](#seguridad-del-uso-en-ci-y-modelo-de-amenaza)
- [Qué está probado y qué no](#qué-está-probado-y-qué-no)

## Inicio rápido con GitHub Actions

1. Escribí `.orobas/ci.yml` en tu repositorio (`cyber ci ejemplo` imprime uno comentado) y validalo:

   ```sh
   cyber ci validar        # todos los errores juntos, con línea y columna
   cyber ci huella         # la huella del alcance: sha256:…
   ```

2. Quien administra el repositorio autoriza ese alcance: *Settings → Secrets and variables → Actions → Variables* (mejor
   en un *environment* protegido, ver [abajo](#autorizar-el-alcance)), variable `OROBAS_ALCANCE_AUTORIZADO` con la huella.
3. Cargá los secretos: `OROBAS_API_KEY` (o la clave de tu proveedor) y los de las identidades de prueba que nombra el
   archivo.
4. Copiá [distro/ci/github/staging.yml](../distro/ci/github/staging.yml) a `.github/workflows/orobas.yml`, con la
   acción fijada por el SHA del tag y la misma versión en `version`.
5. Abrí un PR. Si algo falla, el comentario del PR y el resumen del job dicen qué y por qué.

## Autorizar el alcance

En una sesión interactiva, el alcance lo dicta el operador con sus palabras. En CI no hay operador: el alcance lo
autoriza **quien versiona el archivo**, y la corrida además exige una **confirmación explícita fuera del archivo**: la
huella del alcance en `OROBAS_CI_AUTORIZACION` (o `--autorizo-alcance`). Sin las dos, no corre (código 2).

- La huella es el SHA-256 de las reglas tal como están escritas (con las variables `${…}` sin expandir y sus patrones
  `permitido`) y de las exclusiones. No cambia con el nombre de una regla, el orden, el presupuesto ni la consigna; sí
  cambia con cualquier cosa que cambie **a quién se le pega**.
- Si un PR cambia el alcance, la huella cambia y la corrida se niega: «la autorización es para otro alcance». Para
  aceptar el cambio, quien administra el repositorio actualiza la variable. Ésa es la barrera: cambiar el archivo no
  alcanza para atacar a otro con las credenciales del repositorio.
- La autorización queda registrada en la sesión como el consentimiento de la corrida: evento `ci.autorizacion` (huella,
  de dónde vino la confirmación, archivo y huella del archivo, repositorio, commit, ref y evento), y como fuente del
  alcance (`ci:.orobas/ci.yml@<commit>`). Va en `registro.jsonl` y en `resultado.json` (`autorizacion`).
- El alcance queda **sellado**: ninguna herramienta, importación ni pedido lo puede cambiar durante la corrida, y el
  agente no tiene `scope_edit`. Todo destino fuera del alcance se rechaza en el cliente HTTP, en los escáneres y en el
  navegador; los intentos frenados quedan en `trafico.intentos_fuera_de_alcance` y en el registro.

Recomendado en GitHub: guardá la huella y los secretos en un **environment** con *required reviewers* o con
*deployment branches* limitado a las ramas protegidas, protegé `.orobas/` y `.github/workflows/` con CODEOWNERS, y
exigí revisión en la rama principal.

## Referencia de la configuración

`.orobas/ci.yml` (también se acepta JSON). El YAML admitido es el subconjunto de un archivo de configuración: mapas y
listas en bloque, valores en línea (`[a, b]`, `{env: X}`), textos con `|` y `>`, comillas y comentarios. Se rechazan
tabulaciones, anclas, alias, etiquetas, claves repetidas y más de un documento, con línea y columna. Una clave
desconocida es un error, con la sugerencia más parecida.

| Clave | Tipo | Por defecto | Qué es |
| --- | --- | --- | --- |
| `version` | `1` | — (obligatoria) | Versión del formato. |
| `nombre` | texto `[a-z0-9_-]` | `orobas-ci` | Nombre de esta configuración: el marcador del comentario del PR y la categoría del SARIF. |
| `objetivo.alcance` | lista de reglas | — (obligatoria, al menos una) | Lo único que se toca. Ver reglas abajo. |
| `objetivo.excluir` | lista de reglas | `[]` | Gana siempre sobre el alcance. |
| `objetivo.comprobar` | booleano | `true` | Antes de evaluar, pedir la raíz de cada destino: si ninguno responde, código 3. |
| `identidades` | lista | `[]` | Identidades de prueba, por cabeceras o por login. Ver abajo. |
| `evaluacion.perfil` | `general`, `api`, `web`, `superficie`, `completo` | `general` | Qué buscar (la consigna base). `superficie` es una pasada rápida y barata. |
| `evaluacion.consigna` | texto | — | Indicaciones del equipo, que se suman a la consigna (hasta 8000 caracteres). |
| `evaluacion.capacidades` | `bounty`, `pentest` | `bounty` | Perfil de capacidades del harness. `pentest` habilita payloads extensos y subidas con contenido activo. |
| `evaluacion.solo_lectura` | booleano | `false` | Sólo salen GET, HEAD y OPTIONS, por cualquier vía. |
| `evaluacion.escaneres` | booleano | `false` | Escáneres externos (nmap, ffuf, nuclei, sqlmap…), si están instalados. |
| `evaluacion.solo_cambios.activo` | `auto`, `si`, `no` | `auto` | Concentrarse en las rutas que cambió el PR (`auto`: sólo en PRs y MRs). |
| `evaluacion.solo_cambios.base` | ref de git | la base del PR | Contra qué comparar. |
| `evaluacion.solo_cambios.acotar_alcance` | booleano | `false` | Además de enfocar, acotar el alcance a esas rutas (el login de las identidades queda adentro). |
| `evaluacion.solo_cambios.rutas_siempre` | lista de rutas | `[]` | Rutas que se suman siempre (por ejemplo `/login`). |
| `presupuesto.usd` | número | — (obligatorio) | Tope duro de gasto de la corrida entera: agente, subagentes, verificador y retest. |
| `presupuesto.minutos` | número 1–360 | — (obligatorio) | Tope duro de tiempo. |
| `presupuesto.verificacion_usd` | número | 40 % de `usd` | Reservado para el verificador: la exploración no lo puede gastar. |
| `presupuesto.por_candidato_usd` | número | `0.5` | Tope del verificador por candidato. |
| `presupuesto.peticiones` | entero | sin tope | Tope de peticiones HTTP. |
| `presupuesto.ritmo` | número | sin ritmo | Peticiones por segundo como máximo. |
| `modelo.nombre` | `proveedor/modelo` | el del harness | El modelo (`orobas/…`, `anthropic/…`, `openai/…`, `ollama/…`, cualquiera configurado). |
| `modelo.tarifas` | `{entrada, salida, cache_lectura, cache_escritura}` | — | USD por millón de tokens, para un proveedor que no publica tarifas. Sin tarifa conocida no hay tope duro y no se corre. |
| `modelo.router` | `auto`, `fijo` | `fijo` | El router de modelos del harness. En CI, por defecto fijo: el gasto es más predecible. |
| `trazas` | `compartir`, `local`, `no` | `no` | Modo de trazas de la corrida (ver [abajo](#cuenta-modelos-y-trazas)). |
| `politica.fallar_desde` | severidad o `nunca` | `alta` | Desde qué severidad verificada falla el job: `informativa`, `baja`, `media`, `alta`, `critica`. |
| `politica.solo_nuevos` | booleano | `false` | Que bloqueen sólo los verificados nuevos respecto de la corrida anterior. |
| `linea_base.supresiones` | ruta | `.orobas/supresiones.yml` | El archivo de supresiones. Sin archivo, ninguna. |
| `linea_base.retest_ausentes` | booleano | `true` | Retestear los verificados de la corrida anterior que no reaparecieron. |
| `salidas.carpeta` | ruta | `orobas-ci` | Dónde se escriben las salidas. |
| `salidas.junit` | booleano | `false` | Escribir también `junit.xml`. |
| `salidas.sarif_candidatos` | booleano | `false` | Incluir los candidatos en el SARIF (como `review`). Por defecto la pestaña de seguridad sólo recibe lo verificado. |

### Reglas del alcance

Cada regla es **una** de estas:

```yaml
- url: https://staging.ejemplo.com          # esquema, host, puerto (el del esquema si no está) y prefijo de ruta
  nombre: web                               # opcional: nombre estable del destino (huellas, ubicación en el SARIF)
- host: api.staging.ejemplo.com             # un host: todos sus puertos…
  puertos: [443, 8443]                      # …o sólo éstos
- cidr: 10.20.0.0/28                         # una red (mínimo /16 en IPv4 y /64 en IPv6)
  puertos: [8080]                           # con puertos se expande a host:puerto (hasta 4096 destinos)
- url: ${PREVIEW_URL}                       # una variable de entorno…
  permitido: ["https://pr-*.preview.ejemplo.com"]   # …sólo si el valor cumple un patrón
```

- En CI el alcance es explícito: sin comodines `*.dominio`, sin usuario y contraseña en la URL, sin consulta ni
  fragmento.
- Una regla con `${VARIABLE}` exige `permitido`: patrones de origen (`[esquema://]host[:puerto]`) donde `*` es una o más
  letras, dígitos o guiones **dentro de una etiqueta** (no cruza puntos) o el puerto entero (`http://127.0.0.1:*`). Un
  patrón que no fija el dominio («`https://*.app`») o que autorizaría a cualquiera en un alojamiento compartido
  («`https://*.vercel.app`») se rechaza: fijá una parte propia (`https://miapp-*-miequipo.vercel.app`).
- Un servicio levantado en el propio job (`http://127.0.0.1:8080`) es un destino válido.

### Identidades

Los valores **nunca** van en el archivo: van por referencia a una variable de entorno (o un secreto del CI expuesto como
tal). Un valor escrito literal es un error.

```yaml
identidades:
  - nombre: ana                                   # minúsculas: así se llama en las peticiones del agente
    cabeceras:
      authorization: { env: STAGING_TOKEN_ANA, formato: "Bearer {}" }
      x-tenant: { env: STAGING_TENANT }
  - nombre: beto                                  # o un inicio de sesión que hace el harness antes de empezar
    login:
      url: https://api.staging.ejemplo.com/login  # dentro del alcance
      cuerpo:                                     # JSON; lo que parece secreto tiene que ser { env: … }
        email: { env: STAGING_BETO_EMAIL }
        password: { env: STAGING_BETO_CLAVE }
        recordar: true
      token: data.token                           # ruta al token en la respuesta…
      # cookie: true                              # …o guardar las cookies que pone la respuesta
      cabecera: authorization                     # por defecto authorization (o cookie)
      formato: "Bearer {}"                        # por defecto «Bearer {}» (o «{}» con cookie)
```

El agente usa cada identidad por su nombre y nunca ve sus valores. Un login que responde 4xx es un error de
configuración (2); uno que no responde o responde 5xx, de infraestructura (3).

## Variables de entorno y opciones

Las banderas ganan sobre las variables, y las variables sobre el archivo. **Ninguna cambia el alcance.**

| Bandera | Variable | Qué pisa |
| --- | --- | --- |
| `--config ARCHIVO` | `OROBAS_CI_CONFIG` | El archivo de configuración. |
| `--config-ref COMMIT` | `OROBAS_CI_CONFIG_REF` | Leer la configuración y las supresiones de ese commit (la base de un PR de un fork). |
| `--autorizo-alcance HUELLA` | `OROBAS_CI_AUTORIZACION` | La confirmación del alcance. |
| `--anterior ARCHIVO` | `OROBAS_CI_ANTERIOR` | `resultado.json` de la corrida anterior (comparación y retest). |
| `--retest` | — | Modo retest. |
| `--salida CARPETA` | `OROBAS_CI_SALIDA` | `salidas.carpeta`. |
| `--presupuesto USD` | `OROBAS_CI_PRESUPUESTO_USD` | `presupuesto.usd`. |
| `--minutos N` | `OROBAS_CI_MINUTOS` | `presupuesto.minutos`. |
| `--modelo P/M` | `OROBAS_CI_MODELO` | `modelo.nombre`. |
| `--fallar-desde SEV` | `OROBAS_CI_FALLAR_DESDE` | `politica.fallar_desde`. |
| `--solo-cambios si\|no\|auto` | `OROBAS_CI_SOLO_CAMBIOS` | `evaluacion.solo_cambios.activo`. |
| `--solo-lectura` | `OROBAS_CI_SOLO_LECTURA` | `evaluacion.solo_lectura`. |
| `--junit` | — | `salidas.junit`. |
| `--trazas MODO` | `OROBAS_CI_TRAZAS` | `trazas`. |
| `--conservar-datos` | — | No borrar la carpeta de datos de la corrida (para depurar; tiene los intercambios crudos). |
| `-C, --dir CARPETA` | — | La raíz del repositorio. |

Subcomandos: `cyber ci validar`, `cyber ci huella`, `cyber ci ejemplo`, `cyber ci comentar [--resumen R] [--pr N]`.

## Códigos de salida

Estables y documentados: un pipeline puede decidir por ellos.

| Código | Estado | Cuándo |
| --- | --- | --- |
| 0 | `ok` | La corrida terminó entera y no hay hallazgos verificados que bloqueen según la política. |
| 1 | `hallazgos` | Hay hallazgos **verificados** desde `fallar_desde`, sin supresión vigente (y nuevos, con `solo_nuevos`). |
| 2 | `configuracion` | Archivo inválido, sin alcance, sin autorización o con la de otro alcance, variables de identidades faltantes, clave del proveedor faltante, cuenta sin verificar, tarifa desconocida o login rechazado. No se evaluó nada. |
| 3 | `infraestructura` | Falló el proveedor de modelos (caído, sin saldo, clave rechazada), el objetivo no respondió, o hubo un error interno. La corrida **no es concluyente**: nunca se lee como «todo bien». |
| 4 | `incompleto` | Se agotó el presupuesto, el tiempo o el tope de pasos antes de terminar, quedaron candidatos sin verificar, o (en un retest) hay hallazgos conocidos que no se pudieron confirmar ni como arreglados ni como persistentes. |

Si hay hallazgos que bloquean, sale **1** aunque además haya fallado algo (lo verificado es un hecho); la salida y el
resumen avisan que la corrida no terminó entera. Si no, gana 2, después 3, después 4. Un agente que corta por falta
de avance (repetía lo mismo) termina con lo que encontró y lo avisa.

## Salidas

En `orobas-ci/` (o `salidas.carpeta`):

| Archivo | Qué es |
| --- | --- |
| `resultado.json` | El resultado completo en el formato propio `orobas-ci/1`. Esquema: [distro/ci/orobas-ci-resultado.schema.json](../distro/ci/orobas-ci-resultado.schema.json). Estable: un campo nuevo puede aparecer; uno que está no cambia de nombre ni de sentido sin pasar a `orobas-ci/2`. |
| `resultado.sarif` | SARIF 2.1.0 (validado contra el esquema oficial de OASIS en las pruebas). |
| `resumen.md` | El comentario del PR: resultado, verificados con sus pasos (`curl`), prueba y control, candidatos aparte, comparación, qué se probó y qué no, gasto y duración. |
| `junit.xml` | Con `--junit`: un caso por verificado (falla si bloquea), por retest, candidatos omitidos y «la corrida terminó entera». |
| `registro.jsonl` | Lo que hizo la corrida, una línea por evento: autorización, alcance, cada petición (método, URL, estado, identidad), cada herramienta y lo que se rechazó (fuera del alcance, sólo lectura), veredictos y gasto. |
| `trazas/` | Sólo con `trazas: local`: el material de entrenamiento tapado (ver [trazas](#cuenta-modelos-y-trazas)). |

Lo principal de `resultado.json`: `resultado` (código, estado, motivo, cuántos bloquean), `corrida` (fechas, sesión,
repositorio, commit, PR, cómo terminó la exploración), `autorizacion`, `alcance`, `gasto` (USD con seis decimales, tope,
verificador, solicitudes y tokens), `trafico`, `cobertura` (rutas probadas, sin probar, y el modo «sólo lo que
cambió»), `hallazgos` (cada uno con su `huella`, estado, severidad, clase canónica con CWE, destino, método, ruta,
pasos de reproducción con `curl`, prueba y control del verificador, comparación, supresión y si bloquea),
`comparacion`, `supresiones`, `retest` y `avisos`.

En el SARIF, cada resultado verificado lleva la huella en `partialFingerprints["orobasHuella/v1"]` (así GitHub reconoce
la misma alerta entre corridas), la petición y la respuesta en `webRequest` y `webResponse`, el `curl` y el control en
las propiedades, y la ubicación en la regla del alcance de `.orobas/ci.yml` (o, en un PR, en el archivo y la línea donde
se declaró la ruta afectada). Las reglas son por clase y severidad, con `security-severity` para que GitHub muestre
crítica, alta, media o baja. Los verificados de una corrida anterior que no se confirmaron arreglados siguen en el SARIF:
la alerta no se cierra por no volver a verlos.

**Nada de lo que sale lleva secretos.** Cada texto pasa por el tapado del harness: las identidades quedan como
`<identidad ana>` (en el `curl`, como variable `${IDENTIDAD_ANA}`), los secretos de la sesión (del operador y del
objetivo) como `‹SECRETO_n›`, y lo que el redactor del informe reconoce (cookies, `Authorization`, campos sensibles,
tokens con forma conocida) como `[credencial omitida]`. Al final, cada valor que la corrida leyó de una variable de
entorno (identidades, logins y la clave del proveedor) se busca literal, codificado para URL, escapado para JSON y en
base64. La carpeta de datos de la corrida (con los intercambios crudos) es temporal y se borra al terminar: no va al
caché ni a los artefactos.

## Línea de base: huellas, supresiones, comparación y retest

**Huella.** Cada hallazgo tiene una huella `orobas:v1:…` estable entre corridas y entre entornos: sale del destino (el
`nombre` de la regla, o la regla tal como está escrita, con la variable sin expandir: el entorno efímero de cada PR da
la misma), la clase canónica (control de acceso, XSS, inyección SQL…; por palabras clave, no por el título que escribió
el modelo esa vez), el método, la ruta normalizada (ids, uuids, correos, fechas y tokens como `{id}`) y los nombres de
los parámetros de consulta.

**Supresiones** (`.orobas/supresiones.yml`), versionadas:

```yaml
version: 1
supresiones:
  - huella: orobas:v1:3f2a9c1e0b4d5e6f7a8b9c0d
    motivo: Riesgo aceptado hasta migrar el servicio de pedidos (ticket SEC-142)
    autor: equipo de pagos
    vence: 2027-03-31          # obligatorio: toda supresión vence
```

Una supresión vigente hace que ese hallazgo no bloquee (sigue en las salidas, marcado; en el SARIF como `accepted`).
Vencida, deja de valer sola y el hallazgo vuelve a bloquear; la salida lo avisa. A más de un año, vale pero se avisa.

**Comparación.** Con `--anterior` (la acción lo trae del caché), cada verificado es `nuevo` o `persiste`. Un verificado
de la corrida anterior que no reapareció **no** se da por resuelto: una evaluación con un modelo no recorre siempre lo
mismo. Con `retest_ausentes` (por defecto) se vuelve a probar; si el retest lo confirma, queda en `resueltos`; si no,
en `sin_confirmar`.

**Retest** (`cyber ci --retest --anterior resultado.json`, o `modo: retest` en la acción): por cada verificado conocido
repite la petición que lo demostró (con el host del entorno actual, por el destino de su huella, y la identidad por su
nombre), la guarda como evidencia, y lo vuelve a pasar por el verificador independiente, que hace su propia prueba y su
control. Verificado otra vez: `persiste` (bloquea según la política). Descartado: `arreglado`, con la evidencia del
control negativo (la prueba ahora da como el control). Cualquier otra cosa: `sin-confirmar`, nunca arreglado. Es lo
que cierra el ciclo con el equipo de desarrollo.

## Sólo lo que cambió

En un PR (`solo_cambios.activo: auto`), la corrida compara contra la base (`git diff base...HEAD`; en GitHub hace falta
`actions/checkout` con `fetch-depth: 0`) e infiere las rutas HTTP afectadas:

- de las líneas agregadas que declaran rutas: Express, Fastify, Koa y Hono; Flask y FastAPI; Django; Spring; Laravel;
  Rails; ASP.NET; Go (`net/http`, chi, gin, echo);
- del enrutado por archivos: Next.js (`app/` y `pages/`), SvelteKit, Nuxt, Remix y Astro.

Con rutas, la consigna se concentra en ellas (y en lo que las habilita, como el login); con `acotar_alcance`, además el
alcance se acota a esas rutas. Si no se puede inferir nada (o no hay base), **se dice** en el resumen y se evalúa todo el
alcance. Las rutas cambiadas que no se llegaron a probar quedan en «sin probar».

## La GitHub Action

`action.yml` en la raíz de este repositorio: una acción compuesta. Usala **fijada por el SHA** del commit del tag
(`uses: Leandrozz/orobas-sec@<sha> # vX.Y.Z`): el `install.sh` de esa misma revisión trae la clave pública de los
releases y verifica la firma de `SHA256SUMS` y la suma del paquete de la versión que pidas en `version` antes de
instalar. No acepta `latest` ni ramas.

| Entrada | Por defecto | Qué es |
| --- | --- | --- |
| `version` | — (obligatoria) | Versión fija `vX.Y.Z` del agente. |
| `autorizacion` | — (obligatoria) | La huella del alcance (`${{ vars.OROBAS_ALCANCE_AUTORIZADO }}`). |
| `config` | `.orobas/ci.yml` | El archivo de configuración. |
| `modo` | `evaluar` | `evaluar` o `retest`. |
| `forks` | `omitir` | PRs de forks: `omitir` no corre; `base` corre con la configuración y supresiones de la base. |
| `comentar` | `true` | Comentario único en el PR (necesita `pull-requests: write`). |
| `subir-sarif` | `true` | SARIF a la pestaña de seguridad (necesita `security-events: write`). |
| `cache` | `true` | Guardar el resultado (tapado) para comparar con la próxima corrida. |
| `salida` | `orobas-ci` | Carpeta de las salidas. |
| `argumentos` | — | Opciones extra de `cyber ci` (por ejemplo `--solo-lectura --junit`). |
| `node-version` | `24` | Node para el agente (22.19 o más nuevo). |
| `github-token` | `github.token` | Para comentar y subir el SARIF. |

Salidas: `codigo`, `sarif`, `resumen`, `corrio`. El job termina con el código de la corrida.

Qué hace, en orden: instala Node; decide si corre (versión fija, forks) y con qué claves de caché; restaura la corrida
anterior del caché; instala el agente verificado; corre `cyber ci`; sube las salidas y el registro como artefacto del
job (30 días); sube el SARIF; crea o edita el comentario del PR (un fallo acá avisa y no cambia el resultado); guarda la
corrida en el caché (sólo si llegó a evaluar: 0, 1 o 4); y sale con el código. Las acciones de terceros van fijadas
por SHA, y ninguna entrada se interpola dentro de un script (pasan por variables de entorno).

**Permisos mínimos** en el trabajo (y `permissions: {}` en el workflow): `contents: read` siempre;
`pull-requests: write` sólo si comenta; `security-events: write` sólo si sube el SARIF. La acción no necesita nada más.

**Caché.** Se guarda sólo `.orobas-ci-cache/anterior.json` (el `resultado.json` ya tapado), por archivo de
configuración y ref; un PR puede restaurar el de su rama base. Nunca se guardan los datos crudos de la corrida.

### PRs de forks

En `pull_request` desde un fork, GitHub no pasa secretos ni permisos de escritura: Orobas no puede correr (no hay clave)
y la acción **lo omite por defecto** (`forks: omitir`, el job sale 0 con un aviso). No uses `pull_request_target` para
correr sobre el código de un fork salvo que entiendas el riesgo: ese evento sí tiene secretos. Si igual lo necesitás,
`forks: base` toma la configuración y las supresiones de la **rama base** (`--config-ref <sha de la base>`), no del PR,
así el PR no puede cambiar el alcance ni suprimir hallazgos; el alcance sigue sellado y la huella sigue exigida.

## Ejemplos completos

En [distro/ci/github/](../distro/ci/github/), listos para copiar a `.github/workflows/`:

- [staging.yml](../distro/ci/github/staging.yml): cada PR contra un staging fijo, con comentario y SARIF.
- [efimero.yml](../distro/ci/github/efimero.yml): un trabajo despliega la vista previa del PR y otro evalúa su URL
  (`${PREVIEW_URL}` con `permitido`), sólo lo que cambió.
- [nocturna.yml](../distro/ci/github/nocturna.yml): todas las noches contra staging, con más presupuesto y JUnit.
- [retest.yml](../distro/ci/github/retest.yml): retest a pedido de lo que encontró la última corrida.

El de staging fijo:

```yaml
name: Orobas
on:
  pull_request:
  workflow_dispatch:
permissions: {}
concurrency:
  group: orobas-${{ github.ref }}
  cancel-in-progress: true
jobs:
  seguridad:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    environment: staging
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0
      - uses: Leandrozz/orobas-sec@<sha-del-tag> # vX.Y.Z
        with:
          version: vX.Y.Z
          autorizacion: ${{ vars.OROBAS_ALCANCE_AUTORIZADO }}
        env:
          OROBAS_API_KEY: ${{ secrets.OROBAS_API_KEY }}
          STAGING_TOKEN_ALICIA: ${{ secrets.STAGING_TOKEN_ALICIA }}
```

El del entorno efímero, con la configuración que acepta la URL de cada PR sin cambiar la huella:

```yaml
# .orobas/ci.yml
version: 1
nombre: preview
objetivo:
  alcance:
    - url: ${PREVIEW_URL}
      nombre: preview
      permitido: ["https://pr-*.preview.ejemplo.com"]
identidades:
  - nombre: alicia
    cabeceras:
      authorization: { env: PREVIEW_TOKEN_ALICIA, formato: "Bearer {}" }
evaluacion:
  solo_cambios:
    activo: si
    rutas_siempre: [/login]
presupuesto:
  usd: 2
  minutos: 20
```

## GitLab CI, la imagen genérica y otros CI

**GitLab.** [distro/ci/gitlab-ci.yml](../distro/ci/gitlab-ci.yml) es un trabajo para copiar: instala la versión fija
(`OROBAS_VERSION`) verificando la firma con la clave pública que queda en tu repositorio (`OROBAS_CLAVE_PUBLICA`, la de
[releases.md](releases.md)), corre `cyber ci`, guarda el resultado en el caché, comenta en el MR si definís
`OROBAS_CI_GITLAB_TOKEN` (un token de proyecto con permiso `api`; el del job no alcanza), y publica las salidas como
artefactos y el JUnit como reporte. No corre en MRs desde forks. Las variables con secretos van enmascaradas y
protegidas.

**Imagen genérica.** [distro/ci/Dockerfile](../distro/ci/Dockerfile) se construye desde un checkout del tag del release
e instala esa versión verificada ([distro/ci/instalar-verificado.sh](../distro/ci/instalar-verificado.sh)):

```sh
git checkout vX.Y.Z
docker build -f distro/ci/Dockerfile --build-arg OROBAS_VERSION=vX.Y.Z -t orobas-ci:vX.Y.Z .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" \
  -e OROBAS_API_KEY -e OROBAS_CI_AUTORIZACION -e STAGING_TOKEN_ALICIA orobas-ci:vX.Y.Z
```

El contenedor corre `cyber ci` en la carpeta montada y sale con su código. Sirve para Jenkins, Buildkite, CircleCI,
Azure Pipelines o Drone. Sin Docker: `sh distro/ci/instalar-verificado.sh vX.Y.Z "ssh-ed25519 …"` y después `cyber ci`.

## Cuenta, modelos y trazas

Funciona con el plan Libre y con la suscripción:

- **Suscripción** (`orobas/…`): la clave de la cuenta en `OROBAS_API_KEY`, por un secreto del CI. Los mensajes de cuenta
  e identidad son los del harness: sin clave, «Falta la clave de orobas…»; con la cuenta sin verificar, el mismo aviso
  que en la TUI. Las tarifas salen del servicio antes de empezar (sin tarifa no hay tope duro: código 3 si el servicio no
  responde).
- **Claves propias** (`anthropic/…`, `openai/…`, `deepseek/…`, `openrouter/…` o un proveedor de tu `config.json`): la
  variable de su clave. Si el proveedor no publica tarifas, declaralas en `modelo.tarifas`.
- **Modelo local** (`ollama/…` o uno sin clave): costo cero; el tope en dinero no lo limita y rige el de tiempo.
- El modelo fuerte (para `deep_reason`) se usa si su tarifa es conocida; si no, hace de fuerte el mismo modelo.
- Una solicitud con costo desconocido se avisa en las salidas: el tope no la cuenta.

**Trazas.** `trazas` en el archivo (o `OROBAS_CI_TRAZAS`, o `--trazas`) fija el modo de la corrida; sin eso es `no`: una
corrida de CI no arma material de entrenamiento salvo que el equipo lo pida (no hereda `CYBER_TRAZAS` ni la configuración
del harness). `compartir` manda el material tapado al servicio sólo con la
suscripción; `local` lo deja en `orobas-ci/trazas/` (artefacto del job); `no` no arma material de entrenamiento. Si la
cuenta pide un modo más restrictivo, gana el de la cuenta.

## Seguridad del uso en CI y modelo de amenaza

**Qué hace la corrida para no dañar.** La clave va por secreto del CI; el presupuesto y el tiempo son topes duros (el
gasto lo corta el ledger antes de cada solicitud, del agente, subagentes, verificador y compactación del contexto; el tiempo, un temporizador que
aborta el turno y la verificación); el agente no ejecuta acciones destructivas (la guarda del cliente HTTP exige
`allowDestructive` y un recurso creado en la sesión; en CI no hay consentimiento de borrado ajeno); `solo_lectura` deja
salir sólo GET, HEAD y OPTIONS por cualquier vía; y lo que hizo queda como artefacto del job (`registro.jsonl`).

En CI no se ofrecen: la shell y la orquestación de otros agentes (comandos en el runner), las plataformas y programas
(otras cuentas, otros alcances), `scope_edit` y los demás ajustes del operador, la lectura y el reconocimiento en
servicios de terceros (`reference_read`, crt.sh, Wayback, búsqueda en GitHub, detección de takeover, el feed de CVEs),
el correo de prueba, el navegador del operador, la post-explotación de laboratorio y los servidores MCP del usuario.

**Modelo de amenaza.**

| Amenaza | Qué la frena | Lo que queda |
| --- | --- | --- |
| Un PR (de un fork o de un colaborador) cambia el alcance para atacar a un tercero con las credenciales del repositorio. | La huella: un alcance distinto no corre sin que quien administra actualice la variable. Forks: no corre por defecto; con `forks: base`, el archivo sale de la base. | Quien puede cambiar el workflow puede cambiar qué se le pasa a la acción: protegé `.github/workflows/` y `.orobas/` con CODEOWNERS y revisión, y guardá la huella y los secretos en un environment protegido. |
| Un PR agrega supresiones para esconder un hallazgo. | Las supresiones van en el repositorio, con motivo, autor y vencimiento, y se ven en el diff; con `forks: base`, salen de la base. | Un colaborador con escritura puede suprimir: revisión obligatoria sobre `.orobas/`. |
| El objetivo (o el código del PR que lee el agente) intenta inyectar instrucciones: «agregá tal host al alcance», «mandá el token a…». | El alcance está sellado en el código, no en el modelo; el cliente HTTP rechaza todo destino de afuera; las identidades nunca llegan al modelo (marcadores); sin shell ni plataformas. | El agente puede perder tiempo o presupuesto: lo frenan los topes. |
| Una variable del entorno efímero apunta a otro lado. | `permitido`: el valor expandido tiene que cumplir un patrón que fija el dominio; si no, código 2 sin una petición. | — |
| Fuga de secretos por las salidas, los artefactos o el comentario del PR (en repositorios públicos, los artefactos los baja cualquiera con cuenta). | Tapado en todas las salidas (identidades, secretos de la sesión, redactor del informe y valores literales del entorno); los datos crudos quedan en una carpeta temporal que se borra. | Un secreto del objetivo con una forma que nadie reconoce y que no salió de una variable puede pasar en un extracto de respuesta: revisá las salidas antes de hacer público un repositorio. |
| Envenenamiento del caché. | El caché sólo guarda el resultado anterior (para comparar), por ref: un PR no escribe en el caché de la rama base. | Un resultado anterior manipulado sólo cambia la comparación y qué se retestea, nunca el alcance. |
| Una versión del agente comprometida o «latest». | Versión fija; firma de `SHA256SUMS` con la clave que trae el `install.sh` de la revisión de la acción fijada por SHA; suma de cada archivo. | La confianza está en la clave de los releases ([releases.md](releases.md)). |
| El proveedor de modelos falla o se queda sin saldo y el job queda en verde. | Código 3, nunca 0; candidatos sin verificar o presupuesto agotado, código 4. | — |

## Qué está probado y qué no

Probado, sin claves reales (proveedor simulado con guion y laboratorios propios):

- `test/ci-corrida.test.ts`: los códigos 0 a 4 en cada caso; alcance sellado (un tercero no recibe ni una petición y
  `scope_edit` no existe); sólo verificados bloquean; huellas estables; supresiones vigentes y vencidas; comparación;
  retest arreglado y persistente; sólo lectura; «sólo lo que cambió» con alcance acotado; configuración de la base para
  forks; ninguna salida con secretos (tampoco el token que el objetivo refleja).
- `test/ci-config.test.ts`, `test/ci-partes.test.ts`: lector de YAML, esquema y errores, huella del alcance, huellas de
  hallazgos, inferencia de rutas, supresiones, SARIF validado contra el esquema oficial, JSON contra el propio, Markdown,
  JUnit, tapado, y el comentario contra un doble de las API de GitHub y GitLab (crear, editar el mismo, paginar, volver a
  crear si no puede editar).
- `test/ci-accion.test.ts`: los pasos de la acción, el instalador verificado y la plantilla de GitLab contra releases
  firmados con una clave de prueba; acciones fijadas por SHA, permisos mínimos y ninguna entrada interpolada en un script.
- Fuera de las pruebas: actionlint (con shellcheck) sobre `action.yml` y los ejemplos; la acción corrida en un contenedor
  limpio con un release armado y firmado de la rama; la imagen genérica construida y corrida.

Sin GitHub real no se pudo probar: que el runner de GitHub ejecute la acción compuesta de punta a punta, el caché de
Actions (restaurar y guardar), la subida del SARIF y cómo lo muestra la pestaña de seguridad (deduplicación por
`partialFingerprints`, ubicaciones), el comentario contra la API real (permisos del `GITHUB_TOKEN` en PRs) y el
comportamiento con PRs de forks y `pull_request_target`. Tampoco hay todavía un release firmado con la clave real.
