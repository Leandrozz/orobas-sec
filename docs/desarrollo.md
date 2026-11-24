# Desarrollo

Para quien contribuye al código.

## Requisitos

- **Node 22.19 o más** (`engines` en `package.json`). Hace falta porque el código y los tests son `.ts` que Node ejecuta directamente, quitando los tipos (type stripping), y porque se usa `node:sqlite`. La imagen Docker usa `node:26-bookworm-slim` (`distro/Dockerfile`).
- Con un Node más viejo los tests `.ts` no corren, y `npm test` puede **terminar en verde sin haber ejecutado esos tests**. Antes de fiarte de un verde, mirá `node --version` y la cantidad de tests que informa la salida.
- `npm ci` instala las dependencias: una sola de ejecución (`@toon-format/toon`) y, de desarrollo, `typescript` y `@types/node`.
- Docker, solo si querés construir o probar la imagen y el lanzador de verdad.

## Correr, probar, tipar

| Qué | Comando |
| --- | --- |
| Abrir la TUI desde el código | `bin/cyber` (o `npm start`) |
| Todos los tests | `npm test` |
| Un test | `node --disable-warning=ExperimentalWarning test/<nombre>.test.ts` |
| Chequeo de tipos | `npm run typecheck` (`tsc -p .`, sin emitir; cubre `src` y `test`) |

`npm test` corre `node --test test/` con `--import ./test/datos-tmp.ts` precargado. Un test suelto también corre solo con `node test/<nombre>.test.ts`, porque cada uno importa `./datos-tmp.ts` en su primera línea.

El modelo `faux` (`-m faux`) simula respuestas, para probar sin proveedor ni gasto.

## Mapa de carpetas

| Carpeta | Qué hay |
| --- | --- |
| `bin/` | `cyber`, el ejecutable que llama a `src/cli.ts`. |
| `src/` | El código: agente, daemon, cliente, proveedores, alcance, hallazgos, sondas, plataformas. Ver [arquitectura.md](arquitectura.md). |
| `src/tui/` | La TUI Foco: editor, teclas, pantalla, Markdown, imágenes y el sello (`assets/`). |
| `src/importers/` | Importadores de HAR y Postman. |
| `test/` | Tests (`*.test.ts`), el laboratorio web de pruebas (`lab-web.ts`) y `fixtures/`. |
| `fixtures/` | Datos de ejemplo (HAR, OpenAPI, Postman) usados por tests e importadores. |
| `install.sh`, `install.ps1` | Los instaladores oficiales (de un release firmado). Ver [releases.md](releases.md). |
| `scripts/release/` | Arma los archivos de un release (`armar.sh`) y cambia la clave pública de los releases (`fijar-clave.sh`). |
| `distro/` | Distribución: `Dockerfile` (lo que baja de terceros, con versión y SHA-256: `fijados.txt`, `bajar-fijado.sh`, `semgrep-requisitos.txt`, `navegador/`), `imagen-release.txt`, `config.ejemplo.json` y `lanzador/`. |
| `extension/` | Extensión de Chromium que deja al agente usar tu navegador. |
| `docs/` | Documentación (ver [README.md](README.md)). |
| `vendor/` | Material de referencia incluido en el repositorio (`rea-skill`). |

## Convenciones de tests

- **Nunca tocan tus datos reales.** `test/datos-tmp.ts` define `CYBER_DATA_DIR` y `CYBER_CREDENTIALS_DIR` en carpetas temporales. `npm test` lo precarga con `--import`, y cada test lo importa además en su primera línea (`import "./datos-tmp.ts";`) para que también sea seguro cuando se corre suelto. Un test nuevo tiene que empezar igual.
- Los tests no ejecutan el `gh` verdadero ni otras CLIs de plataformas.
- Usan `node:test` y `node:assert/strict`, con nombres en español: `test/<tema>.test.ts`.
- Los tests de red levantan servidores locales (`node:http`, `test/lab-web.ts`) en lugar de pegarle a Internet.

## Imagen Docker y paquete

Desde la raíz del repositorio:

```sh
docker build -f distro/Dockerfile -t elevate-cyber .
```

La imagen parte de Node (fijada por digest), instala nmap, sqlmap y Chromium con `apt`, baja los binarios de httpx, nuclei, subfinder, katana, dnsx, ffuf, gitleaks, `gh`, `supabase`, `kubectl`, `aws`, jadx y apktool con la versión y la SHA-256 de `distro/fijados.txt` (el build falla si una suma no coincide), instala semgrep con cada dependencia fijada por suma y Playwright sin navegadores (usa el Chromium del sistema) desde su lockfile, copia `bin/`, `src/` y `distro/`, y corre como el usuario `node`. Para subir versiones: `scripts/actualizar-fijados.sh` y `scripts/semgrep-requisitos.sh` (ver [releases.md](releases.md)). El `ENTRYPOINT` es `bin/cyber -C /proyecto`. El comentario de uso al principio del Dockerfile muestra un `docker run` con solo `-v "$PWD:/proyecto"`: con eso el programa se niega a arrancar, porque faltan los montajes de datos y credenciales. Usá el lanzador, o agregá los dos montajes que el mensaje de error indica. Para probar el lanzador contra una imagen local, apuntalo con `CYBER_IMAGE`.

La instalación para usuarios es la de un release firmado (`install.sh`, `install.ps1`; [releases.md](releases.md)). `scripts/release/armar.sh vX.Y.Z SALIDA` arma esos archivos localmente, sin firmar, para probarlos.

## Mensajes de commit

Español, una sola línea de asunto que describe qué cambia y, cuando hace falta, por qué o con qué límite. Se escriben en indicativo y sin prefijos tipo `feat:`. Ejemplos del historial:

- `Docker: sin las carpetas de datos montadas no arranca, para no perder sesiones`
- `Tests: ninguno toca los datos reales del usuario ni ejecuta el gh verdadero`
- `Enlaces clickeables: el corte de línea no parte el OSC 8 (se cierra y reabre) y la puntuación final queda fuera del enlace`
- `Integra los enlaces clickeables de arranque-y-claves (PR #2)`

Los cambios visibles para el usuario también van a [../CHANGELOG.md](../CHANGELOG.md).
