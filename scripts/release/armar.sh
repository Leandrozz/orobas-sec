#!/bin/sh
# Arma los archivos de un release en SALIDA (un directorio que no puede existir):
#   orobas-sec-vX.Y.Z.tar.gz   el agente con sus dependencias de producción (npm ci --omit=dev --ignore-scripts),
#                              para el modo nativo; adentro, VERSION con el tag
#   install.sh, install.ps1    los instaladores, con la versión (y el repositorio, con --repo) puestos
#   cyber-lanzador.sh/.ps1     los lanzadores del modo contenedor, con la versión y la imagen fijada por digest
#   cyber.cmd                  (--imagen, o si no distro/imagen-release.txt), y el cyber.cmd que llama al de Windows;
#                              sin una imagen fijada el release sale sin modo contenedor (sin lanzadores): nunca con
#                              una imagen «latest»
#   SHA256SUMS                 la suma de cada uno. La firma (SHA256SUMS.sig) la agrega el workflow de release.
#
#   scripts/release/armar.sh vX.Y.Z SALIDA [--repo DUEÑO/REPO] [--revision COMMIT] [--imagen REPOSITORIO@sha256:DIGEST]
#
# --imagen es la que acaba de publicar el workflow de release (su digest de arriba del índice multiplataforma): así el
# release fija la imagen que se armó de ese mismo commit, sin un commit a mano entre medio. Mal escrita, frena.
# El contenido sale del commit (HEAD por defecto) con git archive: nada sin trackear. Necesita git, node/npm,
# GNU tar y sha256sum (los runners Linux de GitHub los tienen). El paquete es reproducible: mismas fechas,
# dueños y orden en el tar, y gzip sin nombre ni hora.
set -eu

uso() { echo 'Uso: scripts/release/armar.sh vX.Y.Z SALIDA [--repo DUEÑO/REPO] [--revision COMMIT] [--imagen REPOSITORIO@sha256:DIGEST]' >&2; exit 2; }
morir() { printf 'armar.sh: %s\n' "$*" >&2; exit 1; }

[ $# -ge 2 ] || uso
VERSION=$1
SALIDA=$2
shift 2
REPO=
REVISION=HEAD
IMAGEN_ARG=
CON_IMAGEN=
while [ $# -gt 0 ]; do
  case $1 in
    --repo) [ $# -ge 2 ] || uso; REPO=$2; shift 2 ;;
    --revision) [ $# -ge 2 ] || uso; REVISION=$2; shift 2 ;;
    --imagen) [ $# -ge 2 ] || uso; IMAGEN_ARG=$2; CON_IMAGEN=1; shift 2 ;;
    *) uso ;;
  esac
done
printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || morir "versión inválida: $VERSION (vX.Y.Z)"
[ -z "$REPO" ] || printf '%s\n' "$REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || morir "--repo inválido: $REPO"
[ ! -e "$SALIDA" ] || morir "$SALIDA ya existe."

AQUI=$(cd "$(dirname "$0")" && pwd)
RAIZ=$(git -C "$AQUI" rev-parse --show-toplevel)
COMMIT=$(git -C "$RAIZ" rev-parse --verify "$REVISION^{commit}")
EPOCA=$(git -C "$RAIZ" show -s --format=%ct "$COMMIT")

umask 022
TRABAJO=$(mktemp -d "${TMPDIR:-/tmp}/armar-release.XXXXXX")
trap 'rm -rf "$TRABAJO"' EXIT
mkdir "$TRABAJO/arbol"
git -C "$RAIZ" archive --format=tar "$COMMIT" | tar -x -C "$TRABAJO/arbol"
A="$TRABAJO/arbol"
for f in install.sh install.ps1 distro/lanzador/cyber distro/lanzador/cyber.ps1 package.json package-lock.json src/cli.ts; do
  [ -f "$A/$f" ] || morir "falta $f en $COMMIT"
done

# Pone un valor en la línea marcada de un archivo y comprueba que cambió exactamente una línea.
fijar() {
  archivo=$1 antes=$2 despues=$3
  n=$(grep -cxF -- "$antes" "$archivo" || true)
  [ "$n" = 1 ] || morir "$archivo: esperaba una línea «$antes» y hay $n"
  awk -v a="$antes" -v d="$despues" '$0 == a { print d; next } { print }' "$archivo" >"$archivo.nuevo"
  cat "$archivo.nuevo" >"$archivo"
  rm -f "$archivo.nuevo"
  [ "$(grep -cxF -- "$despues" "$archivo")" = 1 ] || morir "$archivo: no quedó «$despues»"
}

# Las cuatro copias de la clave pública tienen que ser la misma (scripts/release/fijar-clave.sh las cambia juntas).
clave_sh() { sed -n "s/^CLAVE_PUBLICA='\(.*\)'\$/\1/p" "$1"; }
clave_ps() { sed -n "s/^\$ClavePublica = '\(.*\)'\$/\1/p" "$1"; }
CLAVE=$(clave_sh "$A/install.sh")
for c in "$(clave_sh "$A/distro/lanzador/cyber")" "$(clave_ps "$A/install.ps1")" "$(clave_ps "$A/distro/lanzador/cyber.ps1")"; do
  [ -n "$CLAVE" ] && [ "$c" = "$CLAVE" ] || morir 'la clave pública no es la misma en install.sh, install.ps1 y los lanzadores.'
done
case $CLAVE in *REEMPLAZAR*) echo "armar.sh: aviso: la clave pública es el marcador (copia de desarrollo); los instaladores de este release no van a verificar nada." >&2 ;; esac

# Imagen del modo contenedor: sólo fijada por digest. --imagen gana sobre distro/imagen-release.txt.
POR_DIGEST='^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$'
if [ -n "$CON_IMAGEN" ]; then
  printf '%s\n' "$IMAGEN_ARG" | grep -Eq "$POR_DIGEST" || morir "--imagen inválida: «$IMAGEN_ARG» (REPOSITORIO@sha256:DIGEST)"
  IMAGEN=$IMAGEN_ARG
else
  IMAGEN=$(sed -n '/^[[:space:]]*#/d; /^[[:space:]]*$/d; p' "$A/distro/imagen-release.txt" 2>/dev/null | head -n 1 | tr -d '[:space:]')
fi
if printf '%s\n' "$IMAGEN" | grep -Eq "$POR_DIGEST"; then
  CONTENEDOR=1
  [ -f "$A/distro/lanzador/cyber.cmd" ] || morir "falta distro/lanzador/cyber.cmd en $COMMIT"
else
  CONTENEDOR=
  echo "armar.sh: aviso: distro/imagen-release.txt no fija una imagen por digest: el release sale sin modo contenedor (sin lanzadores)." >&2
fi

ORIGEN='https://github.com/Leandrozz/orobas-sec/releases'
DESTINO=$ORIGEN
[ -z "$REPO" ] || DESTINO="https://github.com/$REPO/releases"
fijar "$A/install.sh" "VERSION_INSTALADOR=''  # la completa scripts/release/armar.sh con el tag del release" "VERSION_INSTALADOR='$VERSION'"
fijar "$A/install.sh" "RELEASES_URL_ORIGEN='$ORIGEN'" "RELEASES_URL_ORIGEN='$DESTINO'"
fijar "$A/install.ps1" "\$VersionInstalador = ''  # la completa scripts/release/armar.sh con el tag del release" "\$VersionInstalador = '$VERSION'"
fijar "$A/install.ps1" "\$ReleasesUrlOrigen = '$ORIGEN'" "\$ReleasesUrlOrigen = '$DESTINO'"
fijar "$A/distro/lanzador/cyber" "VERSION_LANZADOR=''  # la completa el release (scripts/release/armar.sh); vacía en una copia de desarrollo" "VERSION_LANZADOR='$VERSION'"
fijar "$A/distro/lanzador/cyber" "RELEASES_URL=\${CYBER_RELEASES_URL:-$ORIGEN}" "RELEASES_URL=\${CYBER_RELEASES_URL:-$DESTINO}"
fijar "$A/distro/lanzador/cyber.ps1" "\$VersionLanzador = ''  # la completa el release (scripts/release/armar.sh); vacía en una copia de desarrollo" "\$VersionLanzador = '$VERSION'"
fijar "$A/distro/lanzador/cyber.ps1" "\$ReleasesUrl = if (\$env:CYBER_RELEASES_URL) { \$env:CYBER_RELEASES_URL } else { '$ORIGEN' }" "\$ReleasesUrl = if (\$env:CYBER_RELEASES_URL) { \$env:CYBER_RELEASES_URL } else { '$DESTINO' }"
if [ -n "$CONTENEDOR" ]; then
  fijar "$A/distro/lanzador/cyber" "IMAGEN_RELEASE=''    # la imagen que fija ese release, por digest; vacía en una copia de desarrollo" "IMAGEN_RELEASE='$IMAGEN'"
  fijar "$A/distro/lanzador/cyber.ps1" "\$ImagenRelease = ''    # la imagen que fija ese release, por digest; vacía en una copia de desarrollo" "\$ImagenRelease = '$IMAGEN'"
fi
sh -n "$A/install.sh"
sh -n "$A/distro/lanzador/cyber"

# El paquete del modo nativo: lo que el agente usa al correr, más sus dependencias de producción.
P="$TRABAJO/orobas-sec-$VERSION"
mkdir "$P"
for f in bin src skills extension distro docs README.md LICENSE NOTICE SECURITY.md CHANGELOG.md package.json package-lock.json; do
  [ ! -e "$A/$f" ] || cp -R "$A/$f" "$P/"
done
rm -f "$P/distro/GUIA-EQUIPO.md"
printf '%s\n' "$VERSION" >"$P/VERSION"
(cd "$P" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error >/dev/null) || morir 'npm ci falló'
rm -rf "$P/node_modules/.package-lock.json"
mkdir -p "$P/node_modules"
node --disable-warning=ExperimentalWarning "$P/src/cli.ts" --version | grep -qxF "orobas-sec $VERSION" || morir 'el paquete no responde --version con la versión del release'

mkdir -p "$SALIDA"
tar --sort=name --mtime="@$EPOCA" --owner=0 --group=0 --numeric-owner --mode='go-w' \
  -C "$TRABAJO" -cf - "orobas-sec-$VERSION" | gzip -n -9 >"$SALIDA/orobas-sec-$VERSION.tar.gz"
cp "$A/install.sh" "$A/install.ps1" "$SALIDA/"
if [ -n "$CONTENEDOR" ]; then
  cp "$A/distro/lanzador/cyber" "$SALIDA/cyber-lanzador.sh"
  cp "$A/distro/lanzador/cyber.ps1" "$SALIDA/cyber-lanzador.ps1"
  cp "$A/distro/lanzador/cyber.cmd" "$SALIDA/cyber.cmd"
fi
chmod 644 "$SALIDA"/*
# sha256sum marca el modo con un caracter: ' ' (texto) en Linux, '*' (binario) en Windows/MSYS; se normaliza a ' '.
(cd "$SALIDA" && LC_ALL=C ls | LC_ALL=C sort | xargs sha256sum | sed 's/^\([0-9a-f]\{64\}\) \*/\1  /' >"$TRABAJO/SHA256SUMS")
mv "$TRABAJO/SHA256SUMS" "$SALIDA/SHA256SUMS"

echo "Release $VERSION de ${COMMIT%"${COMMIT#????????????}"} en $SALIDA:"
(cd "$SALIDA" && cat SHA256SUMS)
[ -n "$CONTENEDOR" ] && echo "Imagen fijada: $IMAGEN" || echo 'Sin modo contenedor (ni --imagen ni distro/imagen-release.txt fijan una imagen).'
echo 'Falta firmar SHA256SUMS (lo hace el workflow de release): ssh-keygen -Y sign -n orobas-sec-release -f CLAVE SHA256SUMS'
