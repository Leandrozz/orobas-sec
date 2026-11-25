# Orobas · Elevate AI Cyber

Agente de pentest y bug bounty para la terminal, de [Elevate AI](https://cyber.elevateai.ar). Es un harness propio en TypeScript sobre Node: bucle del agente con subagentes y un verificador independiente, alcance autorizado que el código aplica en cada petición, cliente HTTP y sondas propias, caja de herramientas de escáneres, navegador por identidad, integración con HackerOne y plataformas de nube, hallazgos con evidencia por hash, informes en Markdown y contabilidad del uso de modelos con tope de gasto. Corre como un daemon por proyecto con una TUI mínima (Foco) como cliente.

> **Uso autorizado.** Usalo solamente contra sistemas propios o sobre los que tengas autorización escrita de sus responsables (un programa de bug bounty, un contrato de pentest, tu laboratorio). El operador carga el alcance y el agente se niega a salir de él, pero la responsabilidad de tener permiso es tuya.

## Instalar

### Linux y macOS

En tu home y sin sudo (necesita Node 22.19 o más nuevo; no instala herramientas de seguridad):

```sh
curl -fsSL https://github.com/Leandrozz/orobas-sec/releases/latest/download/install.sh | sh
```

El instalador es el de un release con tag e instala **esa** versión: antes de tocar nada muestra qué va a hacer, baja
`SHA256SUMS` y su firma, verifica la firma con la clave pública que trae adentro (`ssh-keygen -Y verify`, de OpenSSH)
y la suma SHA-256 de cada archivo. Ante cualquier falla no instala nada. Opciones: `--version vX.Y.Z`,
`--modo nativo|contenedor`, `--prefix DIR`, `--bin DIR`, `--si` (sin preguntas); con `| sh -s -- --si` se pasan por
la línea de arriba.

### Windows

En Windows, Orobas corre en el modo contenedor: el agente y sus herramientas viven en la imagen de Docker
`ghcr.io/leandrozz/orobas-sec` (pública: no hace falta cuenta ni login en ghcr.io) y en tu perfil se instala sólo el
lanzador `cyber`, sin permisos de administrador. Hace falta:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/), con contenedores Linux (lo predeterminado). Si
  no está andando cuando corrés `cyber`, te ofrece abrirlo.
- `ssh-keygen` de OpenSSH 8.1 o más nuevo, para verificar la firma: viene con Windows 11 (*Configuración → Sistema →
  Características opcionales → Cliente OpenSSH*) y con [Git for Windows](https://git-scm.com/download/win). El que
  trae Windows 10 suele ser más viejo; con Git for Windows instalado alcanza.

En PowerShell:

```powershell
irm https://github.com/Leandrozz/orobas-sec/releases/latest/download/install.ps1 -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File .\install.ps1
```

`install.ps1` muestra qué va a hacer y pide confirmación; baja `SHA256SUMS` y su firma, verifica la firma con la clave
que trae adentro y la suma de `cyber-lanzador.ps1`, `cyber.cmd` e `install.ps1`, y recién entonces instala el lanzador
(`cyber-lanzador.ps1` y `cyber.cmd`) en `%LOCALAPPDATA%\elevate-cyber\bin`, te ofrece sumar esa carpeta a tu PATH de
usuario y guarda el instalador en `%LOCALAPPDATA%\orobas-sec`. Opciones: `-Version vX.Y.Z`, `-Prefix DIR`, `-Bin DIR`
y `-Si` (sin preguntas: no toca el PATH, te dice cómo).

Después abrí una terminal nueva, entrá a la carpeta de tu proyecto y escribí `cyber`. **La primera vez baja la imagen**
(varios GB, con los escáneres, el navegador y los analizadores adentro; se ve el avance y tarda según tu conexión); las
siguientes arranca directo. Es la imagen que fija el release, por digest: no cambia hasta que actualices.

### Verificá antes de ejecutar

Las líneas de arriba confían en GitHub y en TLS para el instalador mismo. Para no confiar en nada más que en la
clave (en Windows, lo mismo desde Git Bash con `install.ps1` en lugar de `install.sh`, y al final
`powershell -ExecutionPolicy Bypass -File .\install.ps1`):

```sh
v=vX.Y.Z   # la versión que quieras, de https://github.com/Leandrozz/orobas-sec/releases
base=https://github.com/Leandrozz/orobas-sec/releases/download/$v
curl -fsSLO "$base/install.sh" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.sig"
echo 'orobas-sec namespaces="orobas-sec-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfKpWK3+u7xt/H1nXdYudXF4DWUorU16LWu7ACfcP+R' > firmantes
ssh-keygen -Y verify -f firmantes -I orobas-sec -n orobas-sec-release -s SHA256SUMS.sig < SHA256SUMS
grep '  install.sh$' SHA256SUMS | sha256sum -c -    # en macOS: shasum -a 256 -c -
less install.sh                                     # leelo
sh install.sh
```

La clave pública de los releases es `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfKpWK3+u7xt/H1nXdYudXF4DWUorU16LWu7ACfcP+R` (huella
`SHA256:CPDZhvVsZmr2nSQi2uvxgKpGmQ6K+mApWAvbkWPH27s`). Es la misma en este README, en [docs/releases.md](docs/releases.md) y
dentro de cada instalador y lanzador.

### Modos, actualizar y desinstalar

**Dos modos.** Por defecto, *nativo*: el agente corre con tu Node, desde el paquete del release (con sus dependencias
adentro), y corre comandos en tu máquina con tus permisos; `cyber toolbox` te dice qué escáneres faltan y cómo
instalarlos, si los querés. Con `--modo contenedor` se instala el lanzador `cyber`, que corre el agente en la imagen
de Docker (fijada por digest en cada release) con los escáneres, el navegador y los analizadores adentro del
contenedor; es el único modo en Windows (o el nativo dentro de WSL).

**Actualizar:** `cyber --actualizar` busca el último release publicado, verifica su firma y sus sumas igual que el
instalador y recién entonces reemplaza (nunca baja de versión; sin terminal, sólo con `--si`); en el modo contenedor
después baja la imagen nueva. **Desinstalar:** `sh ~/.local/share/orobas-sec/install.sh --desinstalar` (en Windows,
`powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\orobas-sec\install.ps1" -Desinstalar`); no borra tus
sesiones, hallazgos ni credenciales, y te dice dónde están.

Cómo se arma y firma cada release, y por qué con `ssh-keygen`: [docs/releases.md](docs/releases.md).

## Empezar desde el código

Requiere **Node 22.19 o más** (usa `node:sqlite` y ejecuta los `.ts` directamente) en Linux o macOS; en Windows, dentro de WSL o con la imagen de Docker.

```sh
npm ci
bin/cyber            # TUI Foco en la carpeta actual
bin/cyber --help
bin/cyber -m faux    # modelo simulado: prueba la interfaz sin proveedor ni gasto
```

Los modelos se eligen con `-m proveedor/modelo` o en la configuración (`~/.config/elevate-cyber/config.json`). Hay endpoints conocidos para la suscripción de Elevate AI (`orobas/…`, con la cuenta de [cyber.elevateai.ar](https://cyber.elevateai.ar/cuenta)), OpenAI, Anthropic, DeepSeek, OpenRouter y Ollama, y se puede declarar cualquier API compatible con OpenAI o Anthropic. Las claves nunca van al archivo: la configuración nombra la variable de entorno que la contiene. Detalle en [docs/configuracion.md](docs/configuracion.md).

## Integración continua

`cyber ci` corre Orobas en cada pull request (o por horario) contra tu staging o el entorno efímero del PR, sin nadie
mirando: alcance explícito en `.orobas/ci.yml` y autorizado con su huella, topes duros de gasto y de tiempo, y sólo los
hallazgos que el verificador independiente reprodujo hacen fallar el job. Salidas en SARIF 2.1.0, JSON propio, un
comentario del PR que se edita y JUnit; supresiones con vencimiento, comparación con la corrida anterior y retest de lo
arreglado. Códigos de salida: 0 sin hallazgos que bloqueen, 1 hallazgos verificados, 2 configuración, 3 proveedor o
infraestructura, 4 presupuesto o tiempo agotado.

```yaml
- uses: Leandrozz/orobas-sec@<sha-del-tag> # vX.Y.Z
  with:
    version: vX.Y.Z
    autorizacion: ${{ vars.OROBAS_ALCANCE_AUTORIZADO }}
  env:
    OROBAS_API_KEY: ${{ secrets.OROBAS_API_KEY }}
```

Guía, referencia de la configuración, ejemplos (staging fijo, entorno efímero por PR, nocturna), GitLab, la imagen
genérica y el modelo de amenaza: [docs/ci.md](docs/ci.md).

## Imagen de Docker y lanzador

`distro/Dockerfile` arma una imagen con el agente, los escáneres, el navegador y las herramientas de análisis: la base va fijada por digest y cada herramienta que baja de terceros, con versión y SHA-256 (`distro/fijados.txt`; el build falla si una suma no coincide). `distro/lanzador/` trae un lanzador `cyber` para Linux y macOS (sh) y otro para Windows (PowerShell) que arranca Docker, monta el proyecto, las credenciales y los datos, y abre la TUI.

```sh
docker build -f distro/Dockerfile -t orobas-sec .
CYBER_IMAGE=orobas-sec distro/lanzador/cyber
```

La imagen de cada release es `ghcr.io/leandrozz/orobas-sec` (pública, linux/amd64 y linux/arm64): la arma el workflow
de release de este repositorio desde el mismo commit del tag, con las etiquetas `vX.Y.Z` y `latest`, y los lanzadores
del release la fijan por digest ([docs/releases.md](docs/releases.md), «Imagen»).

Una copia del lanzador sacada del código no se actualiza sola (no trae la clave de los releases); la de un release sí, verificando la firma. Ver [docs/uso.md](docs/uso.md) y [docs/releases.md](docs/releases.md).

## Privacidad

Sin telemetría por defecto: el agente no guarda ni comparte trazas de tus sesiones, y las herramientas que corre (semgrep, las de ProjectDiscovery, npm) van con las métricas y los chequeos de versión apagados. Si querés, `/datos local` guarda el material de cada sesión en tu PC y `/datos compartir` lo manda a Elevate AI para mejorar el agente (sólo con los modelos de la suscripción y con los secretos tapados). Cada pedido al modelo viaja al proveedor que elegiste: eso no depende de este modo. Detalle en [docs/configuracion.md](docs/configuracion.md) (`CYBER_TRAZAS`).

## Documentación

- [Uso](docs/uso.md): subcomandos, flags, comandos de la TUI, teclas, cuentas, datos, presupuesto e informes.
- [Configuración](docs/configuracion.md): proveedores, modelos y todas las variables de entorno.
- [Herramientas](docs/herramientas.md): qué puede hacer el agente, herramienta por herramienta.
- [Arquitectura](docs/arquitectura.md): cómo encajan las piezas, los datos en disco y los límites de seguridad.
- [Desarrollo](docs/desarrollo.md): requisitos, pruebas, mapa de carpetas y estilo.
- [Releases](docs/releases.md): instalación verificable, firma de los releases y versiones fijadas de la imagen.
- [Integración continua](docs/ci.md): `cyber ci`, la GitHub Action, GitLab, códigos de salida y modelo de amenaza.
- [Banco de CVE](docs/benchmark.md): ocho CVE reales con oráculo y versión corregida, para medir el agente de forma reproducible.
- [Cambios](CHANGELOG.md).

## Pruebas

```sh
npm run typecheck
LANG=es_AR.UTF-8 npm test
```

Las pruebas no salen a internet ni usan claves: los servicios se simulan. Varias comparan textos de la interfaz en castellano, por eso el `LANG`.

## Licencia y seguridad

Apache-2.0: ver [LICENSE](LICENSE) y [NOTICE](NOTICE). Para reportar una vulnerabilidad del propio agente, seguí [SECURITY.md](SECURITY.md); para contribuir, [CONTRIBUTING.md](CONTRIBUTING.md).
