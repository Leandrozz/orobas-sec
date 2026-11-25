# Releases, firma e instalación

Cómo se instala Orobas de forma verificable, cómo se arma y firma un release, y qué hace quien lo mantiene. La
regla de fondo: **nada en la cadena confía en «lo último que haya en main»**. Se instala una versión fija, de un
release con tag, y sólo después de verificar una firma con una clave pública que el instalador trae adentro.

## Qué trae un release

Cada tag `vX.Y.Z` produce un release (primero en borrador) con:

| Archivo | Qué es |
| --- | --- |
| `orobas-sec-vX.Y.Z.tar.gz` | El agente para el modo nativo, con sus dependencias de producción adentro (`npm ci --omit=dev --ignore-scripts`). Reproducible: mismas fechas, dueños y orden. |
| `install.sh`, `install.ps1` | Los instaladores (Linux y macOS; Windows), con la versión del release adentro. |
| `cyber-lanzador.sh`, `cyber-lanzador.ps1`, `cyber.cmd` | Los lanzadores del modo contenedor, con la versión y la imagen fijada por digest, y el `cyber.cmd` que instala `install.ps1` para que `cyber` ande desde cmd y PowerShell. Los trae todo release que arma el workflow (ver «Imagen»). |
| `SHA256SUMS` | La SHA-256 de cada archivo de arriba. |
| `SHA256SUMS.sig` | La firma de `SHA256SUMS` (`ssh-keygen -Y sign`, espacio de nombres `orobas-sec-release`). |

`scripts/release/armar.sh vX.Y.Z SALIDA` arma todo menos la firma; el workflow `.github/workflows/release.yml` del
repositorio público, al empujar un tag, arma y publica la imagen, corre `armar.sh` con el digest de esa imagen, firma y
crea el release en borrador.

## Qué verifica el instalador

1. Baja `SHA256SUMS` y `SHA256SUMS.sig` de la versión pedida (por defecto, la del instalador).
2. Verifica la firma con la clave pública que trae adentro (`ssh-keygen -Y verify`), y que la lista firmada nombre
   `orobas-sec-vX.Y.Z.tar.gz` de esa misma versión (una lista firmada de otra versión no sirve).
3. Baja cada archivo que va a usar y compara su SHA-256 con la de la lista firmada (`install.ps1`:
   `cyber-lanzador.ps1`, `cyber.cmd` y él mismo).
4. Recién ahí instala, en el home y sin sudo. Ante cualquier falla no instala nada, borra lo que bajó y sale con error.

`cyber --actualizar` hace lo mismo con el último release publicado (`/releases/latest`, que no incluye borradores ni
prereleases): en el modo nativo corre el instalador guardado; en el modo contenedor, el lanzador se verifica y se
reemplaza solo, y después baja su imagen. Nunca baja de versión, y sin terminal no hace nada salvo con `--si`.

### Por qué `ssh-keygen -Y` y no otra cosa

- **ssh-keygen** viene con OpenSSH, que ya está en Linux, macOS, Windows 11 (y Git for Windows): nadie tiene que
  instalar nada para verificar. Firmas Ed25519, formato documentado (`PROTOCOL.sshsig`), con espacio de nombres para
  que una firma de releases no sirva para otra cosa. Hace falta OpenSSH 8.1 o más nuevo.
- **minisign** es igual de bueno criptográficamente, pero casi nadie lo tiene instalado, y pedir que lo instalen para
  verificar el instalador corta el camino corto.
- **GPG** no viene en macOS ni en Windows y su manejo de claves es más fácil de hacer mal.
- **Las attestations de GitHub** (`gh attestation verify`) prueban qué workflow armó cada archivo, sin claves que
  cuidar. No las usamos como mecanismo del instalador porque piden `gh` instalado y con sesión iniciada, red hacia la
  API de GitHub y Sigstore en el momento de instalar, y la confianza queda en «lo que corrió el workflow del
  repositorio»: quien pueda cambiar el workflow o empujar un tag consigue una attestation válida. Con una clave
  propia, además hace falta la clave, que vive en un entorno con aprobación manual. Se pueden sumar después como
  complemento (`actions/attest-build-provenance`, con permisos `id-token: write` y `attestations: write`).

## Verificar a mano (sin correr nada antes)

```sh
v=vX.Y.Z
base=https://github.com/Leandrozz/orobas-sec/releases/download/$v
curl -fsSLO "$base/install.sh" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.sig"
echo 'orobas-sec namespaces="orobas-sec-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfKpWK3+u7xt/H1nXdYudXF4DWUorU16LWu7ACfcP+R' > firmantes
ssh-keygen -Y verify -f firmantes -I orobas-sec -n orobas-sec-release -s SHA256SUMS.sig < SHA256SUMS
grep '  install.sh$' SHA256SUMS | sha256sum -c -    # en macOS: shasum -a 256 -c -
less install.sh                               # leelo
sh install.sh
```

La huella de la clave es `SHA256:CPDZhvVsZmr2nSQi2uvxgKpGmQ6K+mApWAvbkWPH27s` (`ssh-keygen -lf` sobre la clave). Compará la
clave con la de este documento, la del README y la que trae `install.sh`: tienen que ser la misma.

## Para quien mantiene el proyecto

### Una vez: la clave de firma

1. Generá la clave en tu máquina, **fuera de cualquier repositorio** (por ejemplo en `~/.config/orobas-firma/`), sin
   frase de paso porque la usa un workflow:

   ```sh
   mkdir -p ~/.config/orobas-firma && chmod 700 ~/.config/orobas-firma
   ssh-keygen -t ed25519 -N '' -C orobas-sec-release -f ~/.config/orobas-firma/release
   ```

   Guardá una copia de la privada en tu gestor de contraseñas. Si se pierde, los lanzadores ya instalados no aceptan
   releases firmados con otra (ver «Rotar la clave»).
2. Poné la pública en el repositorio y commiteá: `scripts/release/fijar-clave.sh ~/.config/orobas-firma/release.pub`
   (cambia install.sh, install.ps1, los dos lanzadores, el README y este documento; nunca copia la privada).
3. En el repositorio público, *Settings → Environments → New environment* `release`: con *Required reviewers* (vos)
   y *Deployment branches and tags* limitado a los tags `v*`. Ahí, *Environment secrets → Add secret*
   `OROBAS_FIRMA_RELEASE` con el contenido de `~/.config/orobas-firma/release` (la privada, entera). El secreto no
   va como secreto del repositorio: así sólo lo ve el trabajo que firma, después de que lo apruebes.
4. El primer release crea el paquete `orobas-sec` en ghcr.io. Antes de publicar ese borrador, dejalo público (ver
   «Imagen»): el modo contenedor lo baja sin login.

### Cada release

1. Que `main` del público tenga lo que querés publicar (CI en verde).
2. `git tag -s vX.Y.Z` (o sin `-s`) sobre un commit de `main` y `git push origin vX.Y.Z`.
3. El workflow arma y publica la imagen, arma los archivos con su digest, y cuando GitHub lo pida aprobás el trabajo
   `firmar`: firma, comprueba la firma con la clave que trae `install.sh` y crea el release **en borrador**.
4. Revisá el borrador (archivos, notas, la imagen que nombra) y publicalo a mano. Recién publicado lo ven
   `/releases/latest`, los instaladores y `cyber --actualizar`.

### Imagen

El modo contenedor usa la imagen pública `ghcr.io/leandrozz/orobas-sec`, fijada **por digest** en los lanzadores de
cada release. La arma **sólo** el workflow de release del repositorio público, desde el mismo commit del tag, y nadie
tiene que commitear un digest a mano:

1. `comprobar`: el tag es `vX.Y.Z` y apunta a un commit de `main`. Hasta acá no se publica nada.
2. `imagen`: `distro/Dockerfile` en dos runners nativos (amd64 y arm64, sin emulación ni caché), cada uno subido sólo
   por digest.
3. `indice`: junta los dos en un índice multiplataforma con la etiqueta `vX.Y.Z` (y `latest` si no es un
   prerelease), comprueba que tenga linux/amd64 y linux/arm64 y le pasa a `armar` el digest de arriba del índice.
4. `armar`: `armar.sh vX.Y.Z dist --imagen ghcr.io/leandrozz/orobas-sec@sha256:DIGEST` lo pone en los dos lanzadores
   y comprueba que el release traiga `cyber-lanzador.sh`, `cyber-lanzador.ps1` y `cyber.cmd` con esa imagen.

Esos trabajos tienen `packages: write` (los de la imagen) o sólo lectura, y ninguno ve la clave: `firmar` sigue siendo
el único. Los lanzadores de un release bajan la imagen por digest y sin login (ni token de GitHub): Docker comprueba
que sea exactamente esa. `latest` sólo la usa una copia de desarrollo del lanzador.

- El paquete tiene que ser **público**. La primera vez, en
  `https://github.com/users/Leandrozz/packages/container/orobas-sec/settings`, *Danger Zone → Change visibility →
  Public*. Para comprobarlo sin tu sesión de ghcr.io:
  `DOCKER_CONFIG=$(mktemp -d) docker manifest inspect ghcr.io/leandrozz/orobas-sec:vX.Y.Z` (tiene que listar las dos
  plataformas, sin `unauthorized`).
- Un release armado a mano (sin el workflow) fija la imagen con `--imagen` o con `distro/imagen-release.txt`; sin
  ninguna de las dos sale sin modo contenedor (sin lanzadores) en vez de apuntar a `latest`.
- Lo que la imagen baja de terceros está fijado con versión y SHA-256 en `distro/fijados.txt` (y semgrep con sus
  dependencias en `distro/semgrep-requisitos.txt`); la base, por digest en el `FROM`. Para subir versiones:
  `scripts/actualizar-fijados.sh --dir DIR` (busca versiones publicadas hace al menos 7 días, baja, calcula y
  contrasta con las sumas del autor y con el digest de GitHub, y reescribe el archivo) y
  `scripts/semgrep-requisitos.sh VERSION DIR`. Revisá el diff y construí la imagen antes de commitear. La firma GPG
  de AWS CLI se verifica a mano con la clave que publica AWS en su documentación (huella
  `FB5D B77F D5C1 18B8 0511 ADA8 A631 0ACC 4672 475C`).
- Para la base: el digest del índice de `node:VERSION-bookworm-slim` (`docker buildx imagetools inspect`).

### Rotar la clave

Los lanzadores instalados sólo aceptan releases firmados con la clave que traen. Para cambiarla sin dejarlos
varados: publicá un release firmado con la clave **vieja** que ya traiga la **nueva** (`fijar-clave.sh` con la nueva
y el secreto todavía con la vieja); el siguiente, ya con el secreto nuevo. Si la clave vieja se filtró, no hay forma
segura de mover a los instalados: avisá que reinstalen verificando a mano.
