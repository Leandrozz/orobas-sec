#!/bin/sh
# Instalador de Orobas (orobas-sec) para Linux y macOS. Instala en tu home, sin sudo.
#
# Instala una versión FIJA desde un release con tag: baja SHA256SUMS y su firma, verifica la firma con la
# clave pública de abajo (ssh-keygen -Y verify) y la suma SHA-256 de cada archivo que usa, y recién entonces
# instala. Ante cualquier falla no instala nada, no deja restos y sale con error.
#
#   sh install.sh [--version vX.Y.Z] [--modo nativo|contenedor] [--prefix DIR] [--bin DIR] [--si]
#   sh install.sh --actualizar [--si]    instala el último release publicado, verificado igual
#   sh install.sh --desinstalar [--si]   saca lo que instaló este instalador (no tus datos)
#   sh install.sh --ayuda
#
# Modos:
#   nativo (por defecto)  el agente corre con tu Node (22.19 o más nuevo). No instala herramientas de
#                         seguridad: «cyber toolbox» te dice cuáles faltan, y las instalás vos si las querés.
#   contenedor            instala el lanzador «cyber», que corre el agente en la imagen de Docker (escáneres,
#                         navegador y analizadores quedan adentro del contenedor). Necesita Docker.
#
# Arriba sólo hay constantes y el estado vacío; todo lo que actúa está en funciones, y el trap y main() van en
# las dos últimas líneas: con «curl … | sh», una descarga cortada no ejecuta la mitad.

VERSION_INSTALADOR=''  # la completa scripts/release/armar.sh con el tag del release
RELEASES_URL_ORIGEN='https://github.com/Leandrozz/orobas-sec/releases'
# Clave pública que firma SHA256SUMS de cada release (ssh-keygen -Y sign -n orobas-sec-release).
# Es la misma en install.sh, install.ps1 y los dos lanzadores: scripts/release/fijar-clave.sh la cambia en todos.
CLAVE_PUBLICA='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfKpWK3+u7xt/H1nXdYudXF4DWUorU16LWu7ACfcP+R'
ESPACIO_FIRMA=orobas-sec-release
NODE_MINIMO=22.19
MARCA='orobas-sec: comando instalado por install.sh'

# Lo que limpiar() mira para decidir qué borrar. Arranca vacío acá, antes del trap: limpiar() puede correr antes
# de que main() asigne nada (con --ayuda o con un error temprano), y nada del entorno puede decidir qué se borra.
# Con PREFIX_CREADO=1 en el entorno, «sh install.sh --prefix ~» borraba el home entero.
TMPD=
NUEVA=
PREFIX=
BIN=
PREFIX_CREADO=
BIN_CREADO=
COMANDO_CREADO=

main() {
  set -eu
  umask 022
  RELEASES_URL=${CYBER_RELEASES_URL:-$RELEASES_URL_ORIGEN}
  RELEASES_URL=${RELEASES_URL%/}
  VERSION=
  MODO=
  PREFIX=
  BIN=
  SI=
  ACCION=instalar
  while [ $# -gt 0 ]; do
    case $1 in
      --version | --modo | --prefix | --bin)
        [ $# -ge 2 ] || morir "falta el valor de $1"
        opcion "$1" "$2"
        shift 2 ;;
      --version=* | --modo=* | --prefix=* | --bin=*) opcion "${1%%=*}" "${1#*=}"; shift ;;
      --si | --yes | -y | --no-interactivo) SI=1; shift ;;
      --actualizar) ACCION=actualizar; shift ;;
      --desinstalar) ACCION=desinstalar; shift ;;
      -h | --ayuda | --help) ayuda; return 0 ;;
      *) morir "opción desconocida: $1 (mirá --ayuda)" ;;
    esac
  done

  [ -n "${HOME:-}" ] && [ -d "$HOME" ] || morir 'HOME no está definido o no existe.'
  plataforma
  PREFIX=$(absoluta "${PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/orobas-sec}")
  CONF="$PREFIX/instalacion.conf"
  PREVIA=
  if [ -f "$CONF" ]; then
    grep -qx '# orobas-sec: instalacion hecha por install.sh' "$CONF" || morir "$CONF no es de este instalador: no lo toco."
    PREVIA=$(leer_conf version)
    [ -n "$MODO" ] || MODO=$(leer_conf modo)
    [ -n "$BIN" ] || BIN=$(leer_conf bin)
  fi
  BIN=$(absoluta "${BIN:-$HOME/.local/bin}")
  MODO=${MODO:-nativo}
  case $MODO in nativo | contenedor) ;; *) morir "modo desconocido: $MODO (nativo o contenedor)" ;; esac
  for r in "$PREFIX" "$BIN"; do
    case $r in
      / | "$HOME" | "$HOME/") morir "No uso $r como carpeta de instalación: elegí una carpeta propia." ;;
      *"'"* | *'
'*) morir "La ruta $r tiene comillas simples o saltos de línea: elegí otra." ;;
    esac
  done

  trap 'exit 130' INT
  trap 'exit 143' TERM
  TMPD=$(mktemp -d "${TMPDIR:-/tmp}/orobas-sec.XXXXXX") || morir 'No pude crear una carpeta temporal.'

  case $ACCION in
    desinstalar) desinstalar; return ;;
    actualizar)
      [ -n "$PREVIA" ] || morir "No hay una instalación de este instalador en $PREFIX: instalá primero."
      [ -z "$VERSION" ] || morir '--actualizar instala el último release publicado: no se combina con --version.'
      herramientas_base
      VERSION=$(ultimo_release)
      if [ "$VERSION" = "$PREVIA" ]; then
        echo "Ya tenés la última versión publicada ($VERSION)."
        return 0
      fi
      if version_menor "$VERSION" "$PREVIA"; then
        echo "El último release publicado ($VERSION) es más viejo que el instalado ($PREVIA): no bajo de versión."
        echo "Para volver a una versión anterior a propósito: sh $PREFIX/install.sh --version $VERSION"
        return 0
      fi ;;
  esac

  [ -n "$VERSION" ] || VERSION=$VERSION_INSTALADOR
  [ -n "$VERSION" ] || morir 'Este instalador no viene de un release: decí qué versión instalar con --version vX.Y.Z.'
  version_valida "$VERSION" || morir "versión inválida: $VERSION (tiene que ser vX.Y.Z)"
  instalar
}

opcion() {
  case $1 in
    --version) VERSION=$2 ;;
    --modo) MODO=$2 ;;
    --prefix) PREFIX=$2 ;;
    --bin) BIN=$2 ;;
  esac
}

ayuda() {
  cat <<'FIN'
Instalador de Orobas (orobas-sec) para Linux y macOS. Instala en tu home, sin sudo, una versión fija de un
release con tag, después de verificar la firma de SHA256SUMS y la suma de cada archivo.

  sh install.sh [--version vX.Y.Z] [--modo nativo|contenedor] [--prefix DIR] [--bin DIR] [--si]
  sh install.sh --actualizar [--si]     instala el último release publicado, verificado igual
  sh install.sh --desinstalar [--si]    saca lo que instaló este instalador (no tus datos)

  --version     versión a instalar (por defecto, la de este instalador)
  --modo        nativo (por defecto: con tu Node, sin herramientas de seguridad) o contenedor (Docker)
  --prefix      dónde instalar (por defecto ~/.local/share/orobas-sec)
  --bin         dónde poner el comando cyber (por defecto ~/.local/bin)
  --si          no preguntar (sin terminal, sin --si, no hace nada)
FIN
  echo
  echo "Variables: CYBER_RELEASES_URL cambia de dónde baja (por defecto $RELEASES_URL_ORIGEN);"
  echo "           la seguridad no depende de la URL sino de la firma."
}

morir() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

# Lo que quedó a medio hacer se borra: descargas, una versión extraída sin terminar y, si esta corrida las
# creó y no terminó, la carpeta de instalación y el comando (la carpeta del comando, sólo si quedó vacía).
# Sólo borra lo que creó esta corrida: el temporal de mktemp, la extracción dentro de $PREFIX/versiones, y
# $PREFIX o $BIN/cyber si esta corrida los creó (las marcas arrancan vacías arriba y las pone instalar()).
limpiar() {
  codigo=$1
  case ${TMPD##*/} in orobas-sec.?*) rm -rf "$TMPD" ;; esac
  case $NUEVA in "$PREFIX"/versiones/.nueva.?*) rm -rf "$NUEVA" ;; esac
  if [ "$codigo" != 0 ]; then
    [ -z "$COMANDO_CREADO" ] || [ -z "$BIN" ] || rm -f "$BIN/cyber"
    [ -z "$PREFIX_CREADO" ] || [ -z "$PREFIX" ] || rm -rf "$PREFIX"
    [ -z "$BIN_CREADO" ] || [ -z "$BIN" ] || rmdir "$BIN" 2>/dev/null || true
  fi
  exit "$codigo"
}

absoluta() {
  case $1 in
    '~') printf '%s\n' "$HOME" ;;
    '~/'*) printf '%s/%s\n' "$HOME" "${1#'~/'}" | sed 's#/$##' ;;
    /*) printf '%s\n' "${1%/}" ;;
    '') morir 'ruta vacía' ;;
    *) printf '%s/%s\n' "$(pwd)" "${1%/}" ;;
  esac
}

leer_conf() { sed -n "s/^$1=//p" "$CONF" | head -n 1; }

plataforma() {
  SO=$(uname -s 2>/dev/null || echo desconocido)
  ARQ=$(uname -m 2>/dev/null || echo desconocida)
  case $SO in
    Linux | Darwin) ;;
    MINGW* | MSYS* | CYGWIN*) morir 'En Windows usá install.ps1 (modo contenedor) o este instalador dentro de WSL.' ;;
    *) morir "Sistema no soportado: $SO. Hay instalador para Linux, macOS y Windows (install.ps1)." ;;
  esac
}

tiene() { command -v "$1" >/dev/null 2>&1; }

version_valida() { printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; }

# ¿$1 es anterior a $2? Compara mayor, menor y parche (lo que sigue a «-» no cuenta).
version_menor() {
  a=${1#v}; a=${a%%-*}; b=${2#v}; b=${b%%-*}
  ia=0
  while [ $ia -lt 3 ]; do
    x=${a%%.*}; y=${b%%.*}
    [ "$x" -lt "$y" ] && return 0
    [ "$x" -gt "$y" ] && return 1
    a=${a#*.}; b=${b#*.}
    ia=$((ia + 1))
  done
  return 1
}

node_ok() {
  tiene node && node -e '
const [a, b] = process.versions.node.split(".").map(Number);
const [x, y] = process.argv[1].split(".").map(Number);
process.exit(a > x || (a === x && b >= y) ? 0 : 1);' "$NODE_MINIMO" 2>/dev/null
}

# Revisa todo lo que hace falta y, si falta algo, lo dice entero (qué y cómo conseguirlo) sin instalar nada.
herramientas_base() {
  falta=
  tiene curl || falta="$falta
  - curl: instalalo con tu gestor de paquetes (apt install curl, dnf install curl, pacman -S curl)."
  tiene ssh-keygen || falta="$falta
  - ssh-keygen (OpenSSH 8.1 o más nuevo), para verificar la firma: apt install openssh-client, dnf install
    openssh-clients, pacman -S openssh. En macOS ya viene."
  tiene sha256sum || tiene shasum || tiene openssl || falta="$falta
  - sha256sum (coreutils), shasum u openssl, para la suma SHA-256."
  for h in tar gzip mktemp awk; do tiene "$h" || falta="$falta
  - $h"; done
  if [ "$ACCION" != desinstalar ] && [ "${MODO:-nativo}" = nativo ] && ! node_ok; then
    if tiene node; then hay="tenés $(node --version 2>/dev/null)"; else hay='no está instalado'; fi
    falta="$falta
  - Node $NODE_MINIMO o más nuevo ($hay). No lo instalo yo: bajalo de https://nodejs.org o usá nvm,
    fnm o el gestor de paquetes de tu sistema. Otra opción: --modo contenedor (con Docker)."
  fi
  if [ "$ACCION" != desinstalar ] && [ "${MODO:-nativo}" = contenedor ] && ! tiene docker; then
    falta="$falta
  - Docker (el modo contenedor corre el agente en una imagen): https://docs.docker.com/get-docker/
    Podman también sirve si tenés el comando «docker» (podman-docker). Otra opción: el modo nativo."
  fi
  [ -z "$falta" ] || morir "Antes de instalar falta:$falta"
}

# Interactivo: hay terminal (aun con «curl | sh», por /dev/tty) y no se pidió --si.
confirmar() {
  [ -z "$SI" ] || return 0
  if (: </dev/tty) 2>/dev/null; then
    printf '%s [S/n] ' "$1" >/dev/tty
    read -r r </dev/tty || r=n
    case $r in '' | s | S | si | sí | y | Y) return 0 ;; *) echo 'No hice nada.'; exit 1 ;; esac
  fi
  morir 'No hay una terminal para confirmar: revisá lo de arriba y volvé a correr con --si.'
}

# https siempre; http sólo hacia esta misma máquina (pruebas). La seguridad está en la firma, no en la URL.
protocolos() {
  case $RELEASES_URL in
    https://*) PROTO='=https' ;;
    http://127.0.0.1:* | http://localhost:* | http://127.0.0.1/* | http://localhost/*) PROTO='=http,https' ;;
    *) morir "CYBER_RELEASES_URL tiene que ser https: $RELEASES_URL" ;;
  esac
}

bajar() {
  protocolos
  curl -fsSL --proto "$PROTO" --proto-redir "$PROTO" --retry 2 --connect-timeout 20 --max-time 900 -o "$2" "$1" 2>"$TMPD/curl.err" ||
    morir "No pude bajar $1 ($(head -n 1 "$TMPD/curl.err"))."
}

suma() {
  if tiene sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif tiene shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  else openssl dgst -sha256 -r "$1" | cut -d' ' -f1
  fi
}

# El último release publicado (no borradores ni prereleases): GitHub redirige /releases/latest a /releases/tag/vX.Y.Z.
ultimo_release() {
  protocolos
  u=$(curl -fsSIL --proto "$PROTO" --proto-redir "$PROTO" --connect-timeout 20 --max-time 60 -o /dev/null -w '%{url_effective}' "$RELEASES_URL/latest" 2>"$TMPD/curl.err") ||
    morir "No pude consultar el último release en $RELEASES_URL/latest ($(head -n 1 "$TMPD/curl.err"))."
  v=${u##*/tag/}
  printf '%s\n' "$v" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || morir "No entendí cuál es el último release (respuesta: $u)."
  printf '%s\n' "$v"
}

huella() {
  case $CLAVE_PUBLICA in *REEMPLAZAR*) echo 'sin clave'; return ;; esac
  printf '%s\n' "$CLAVE_PUBLICA" >"$TMPD/clave.pub"
  ssh-keygen -lf "$TMPD/clave.pub" 2>/dev/null | cut -d' ' -f2
}

# Baja SHA256SUMS y su firma, y verifica la firma con la clave de este instalador. Además exige que la lista
# nombre el paquete de esta versión: así una lista firmada de otra versión no sirve para esta.
verificar_lista() {
  case $CLAVE_PUBLICA in
    *REEMPLAZAR*) morir 'Este instalador no trae la clave pública de los releases (es una copia de desarrollo): no puedo verificar nada.' ;;
  esac
  base="$RELEASES_URL/download/$VERSION"
  bajar "$base/SHA256SUMS" "$TMPD/SHA256SUMS"
  bajar "$base/SHA256SUMS.sig" "$TMPD/SHA256SUMS.sig"
  printf 'orobas-sec namespaces="%s" %s\n' "$ESPACIO_FIRMA" "$CLAVE_PUBLICA" >"$TMPD/firmantes"
  if ! ssh-keygen -Y verify -f "$TMPD/firmantes" -I orobas-sec -n "$ESPACIO_FIRMA" -s "$TMPD/SHA256SUMS.sig" \
    <"$TMPD/SHA256SUMS" >"$TMPD/firma.out" 2>&1; then
    case $(cat "$TMPD/firma.out") in
      *'illegal option'* | *'unknown option'* | *'invalid option'*) morir 'Tu ssh-keygen no sabe verificar firmas (-Y verify): hace falta OpenSSH 8.1 o más nuevo.' ;;
    esac
    morir "La firma de SHA256SUMS de $VERSION no es válida para la clave de este instalador ($(huella)). No instalo nada."
  fi
  esperada_de "orobas-sec-$VERSION.tar.gz" >/dev/null || morir "El SHA256SUMS firmado no es el de $VERSION. No instalo nada."
}

# La suma que la lista firmada da para el archivo $1 (exactamente una línea «suma␠␠nombre»).
esperada_de() {
  s=$(awk -v f="$1" 'length($1) == 64 && $2 == f && NF == 2 { print $1 }' "$TMPD/SHA256SUMS")
  [ -n "$s" ] && [ "$(printf '%s\n' "$s" | wc -l | tr -d ' ')" = 1 ] || return 1
  printf '%s\n' "$s" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$s"
}

# Baja y verifica cada archivo que va a usar la instalación. Los nombres llegan como argumentos:
# una variable sin comillas («for f in $lista») no se separa en palabras en zsh, el shell de macOS.
bajar_archivos() {
  for f do
    # Una versión ya extraída con la suma firmada no se vuelve a bajar (correr dos veces no cambia nada).
    case $f in *.tar.gz) [ ! -f "$PREFIX/versiones/$VERSION/src/cli.ts" ] || [ "$(cat "$PREFIX/versiones/$VERSION/.sha256-release" 2>/dev/null)" != "$(esperada_de "$f")" ] || continue ;; esac
    bajar_verificado "$f"
  done
}

# Baja un archivo del release y lo compara con la suma firmada.
bajar_verificado() {
  if ! esperada=$(esperada_de "$1"); then
    [ "$1" != cyber-lanzador.sh ] || morir "El release $VERSION no trae el modo contenedor (no fijó una imagen): usá --modo nativo u otro release. No instalo nada."
    morir "El release $VERSION no trae $1 en SHA256SUMS (release incompleto). No instalo nada."
  fi
  bajar "$RELEASES_URL/download/$VERSION/$1" "$TMPD/$1"
  [ "$(suma "$TMPD/$1")" = "$esperada" ] || morir "La suma SHA-256 de $1 no coincide con la firmada. No instalo nada."
}

# ¿Lo que hay en $1 lo puso este instalador (el envoltorio nativo o un lanzador)?
es_nuestro() {
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  head -n 3 "$1" | grep -Eq "$MARCA|Lanzador de Elevate AI Cyber para Linux y macOS"
}

camino_path() {
  case ":${PATH:-}:" in *":$BIN:"*) return 0 ;; esac
  case $BIN in "$HOME"/*) b="\$HOME/${BIN#"$HOME"/}" ;; *) b=$BIN ;; esac
  echo
  echo "$BIN no está en tu PATH. Agregalo (no toco los archivos de tu shell):"
  case $(basename "${SHELL:-sh}") in
    zsh) echo "  echo 'export PATH=\"$b:\$PATH\"' >> ~/.zshrc" ;;
    bash) if [ "$SO" = Darwin ]; then echo "  echo 'export PATH=\"$b:\$PATH\"' >> ~/.bash_profile"; else echo "  echo 'export PATH=\"$b:\$PATH\"' >> ~/.bashrc"; fi ;;
    fish) echo "  fish_add_path $b" ;;
    *) echo "  export PATH=\"$b:\$PATH\"   (en el archivo de inicio de tu shell)" ;;
  esac
  echo "y abrí una terminal nueva."
}

instalar() {
  herramientas_base
  if [ "$MODO" = nativo ]; then archivos="orobas-sec-$VERSION.tar.gz install.sh"; else archivos="cyber-lanzador.sh install.sh"; fi
  if [ -e "$BIN/cyber" ] || [ -L "$BIN/cyber" ]; then
    es_nuestro "$BIN/cyber" || morir "Ya existe $BIN/cyber y no lo instaló este instalador: no lo piso. Movelo o elegí otra carpeta con --bin."
    reemplaza=' (reemplaza el que instaló este instalador)'
  else
    reemplaza=
  fi

  echo "Orobas $VERSION · modo $MODO · $SO $ARQ"
  [ -z "$PREVIA" ] || echo "Instalada ahora: $PREVIA"
  echo
  echo 'Voy a hacer esto:'
  echo "  1. Bajar de $RELEASES_URL/download/$VERSION/"
  echo "       SHA256SUMS, SHA256SUMS.sig, $(echo "$archivos" | sed 's/ /, /g')"
  echo "     y verificar la firma (clave $(huella)) y la suma SHA-256 de cada uno."
  if [ "$MODO" = nativo ]; then
    echo "  2. Instalar el agente en $PREFIX/versiones/$VERSION (con sus dependencias, que vienen en el paquete)."
    echo "  3. Crear el comando $BIN/cyber$reemplaza."
    echo
    echo 'No usa sudo, no toca los archivos de tu shell y no instala herramientas de seguridad: «cyber toolbox»'
    echo 'te dice cuáles faltan. En este modo el agente corre comandos en tu máquina, con tus permisos.'
  else
    echo "  2. Instalar el lanzador como $BIN/cyber$reemplaza."
    echo "  3. Guardar este instalador en $PREFIX (para --desinstalar)."
    echo
    echo 'No usa sudo ni toca los archivos de tu shell. La primera vez que corras «cyber», el lanzador baja la'
    echo 'imagen de Docker (varios GB), con los escáneres y analizadores adentro del contenedor.'
  fi
  echo
  confirmar '¿Sigo?'

  verificar_lista
  if [ "$MODO" = nativo ]; then
    bajar_archivos "orobas-sec-$VERSION.tar.gz" install.sh
  else
    bajar_archivos cyber-lanzador.sh install.sh
  fi
  echo "Firma y sumas verificadas ($(huella))."

  [ -d "$PREFIX" ] || { mkdir -p "$PREFIX"; PREFIX_CREADO=1; }
  [ -d "$BIN" ] || { mkdir -p "$BIN"; BIN_CREADO=1; }
  [ -e "$BIN/cyber" ] || COMANDO_CREADO=1
  if [ "$MODO" = nativo ]; then
    instalar_nativo
  else
    instalar_contenedor
  fi
  cp "$TMPD/install.sh" "$PREFIX/.install.sh.nuevo"
  mv -f "$PREFIX/.install.sh.nuevo" "$PREFIX/install.sh"
  {
    echo '# orobas-sec: instalacion hecha por install.sh'
    echo 'formato=1'
    echo "version=$VERSION"
    echo "modo=$MODO"
    echo "bin=$BIN"
    echo "anterior=$PREVIA"
  } >"$PREFIX/.instalacion.conf.nuevo"
  mv -f "$PREFIX/.instalacion.conf.nuevo" "$CONF"
  PREFIX_CREADO=
  BIN_CREADO=
  COMANDO_CREADO=

  echo
  echo "Listo: Orobas $VERSION ($MODO). Probá con: cyber --help"
  camino_path
  echo
  echo "Actualizar:   cyber --actualizar"
  echo "Desinstalar:  sh $PREFIX/install.sh --desinstalar"
}

instalar_nativo() {
  paquete="$TMPD/orobas-sec-$VERSION.tar.gz"
  esperada=$(esperada_de "orobas-sec-$VERSION.tar.gz")
  destino="$PREFIX/versiones/$VERSION"
  if [ ! -f "$paquete" ] && [ -f "$destino/src/cli.ts" ]; then
    echo "La versión $VERSION ya estaba extraída y verificada: no la vuelvo a escribir."
  else
    mkdir -p "$PREFIX/versiones"
    NUEVA=$(mktemp -d "$PREFIX/versiones/.nueva.XXXXXX")
    tar -xzf "$paquete" -C "$NUEVA" || morir "No pude extraer $paquete."
    raiz="$NUEVA/orobas-sec-$VERSION"
    [ -f "$raiz/src/cli.ts" ] && [ -d "$raiz/node_modules" ] || morir "El paquete de $VERSION no tiene la forma esperada."
    printf '%s\n' "$esperada" >"$raiz/.sha256-release"
    # Antes de cambiar nada: que arranque con este Node.
    node --disable-warning=ExperimentalWarning "$raiz/src/cli.ts" --version >"$TMPD/version.out" 2>&1 ||
      morir "El agente de $VERSION no arranca con tu Node ($(node --version)): $(head -n 3 "$TMPD/version.out")"
    rm -rf "$destino"
    mv "$raiz" "$destino"
    rm -rf "$NUEVA"
    NUEVA=
  fi
  ln -sfn "versiones/$VERSION" "$PREFIX/actual"
  {
    echo '#!/bin/sh'
    echo "# $MARCA (modo nativo). Lo reescribe el instalador: no lo edites."
    echo 'case "${1:-}" in'
    echo "  --actualizar | --desinstalar) exec sh '$PREFIX/install.sh' --prefix '$PREFIX' \"\$@\" ;;"
    echo 'esac'
    echo "exec node --disable-warning=ExperimentalWarning '$PREFIX/actual/src/cli.ts' \"\$@\""
  } >"$BIN/.cyber.nuevo"
  chmod 755 "$BIN/.cyber.nuevo"
  mv -f "$BIN/.cyber.nuevo" "$BIN/cyber"
  # Quedan la versión nueva y la anterior (para volver atrás con --version); las demás se borran.
  for d in "$PREFIX"/versiones/*; do
    [ -d "$d" ] || continue
    v=${d##*/}
    [ "$v" = "$VERSION" ] || [ "$v" = "$PREVIA" ] || rm -rf "$d"
  done
}

instalar_contenedor() {
  sh -n "$TMPD/cyber-lanzador.sh" || morir 'El lanzador del release no pasa sh -n.'
  cp "$TMPD/cyber-lanzador.sh" "$BIN/.cyber.nuevo"
  chmod 755 "$BIN/.cyber.nuevo"
  mv -f "$BIN/.cyber.nuevo" "$BIN/cyber"
  rm -rf "$PREFIX/versiones" "$PREFIX/actual"
  imagen=$(sed -n "s/^IMAGEN_RELEASE='\(.*\)'.*/\1/p" "$BIN/cyber" | head -n 1)
  [ -z "$imagen" ] || echo "Imagen fijada por este release: $imagen"
}

desinstalar() {
  [ -f "$CONF" ] || morir "No hay una instalación de este instalador en $PREFIX (falta $CONF)."
  echo "Orobas $PREVIA (modo $MODO), instalado en $PREFIX"
  echo
  echo 'Voy a borrar:'
  echo "  - $PREFIX (versiones instaladas y este instalador)"
  if es_nuestro "$BIN/cyber"; then echo "  - $BIN/cyber"; quitar_bin=1; else quitar_bin=; fi
  echo
  echo 'No toco tus datos (sesiones, hallazgos, configuración y credenciales). Si los querés borrar, están en:'
  echo "  ${XDG_CONFIG_HOME:-$HOME/.config}/elevate-cyber"
  if [ "$SO" = Darwin ]; then echo "  $HOME/Library/Application Support/elevate-cyber"; else echo "  ${XDG_DATA_HOME:-$HOME/.local/share}/elevate-cyber"; fi
  [ "$MODO" != contenedor ] || echo 'Las imágenes de Docker tampoco: docker image ls ghcr.io/leandrozz/orobas-sec, y docker image rm las que no quieras.'
  echo
  confirmar '¿Desinstalo?'
  [ -z "$quitar_bin" ] || rm -f "$BIN/cyber"
  rm -rf "$PREFIX"
  echo 'Desinstalado.'
}

# El trap de limpieza va afuera de main(): en zsh un trap EXIT puesto dentro de una función ve
# $? = 0 en vez del código de salida, y un error saldría con código 0. Lo que limpiar() lee ya arrancó vacío arriba.
trap 'limpiar $?' EXIT

main "$@"
