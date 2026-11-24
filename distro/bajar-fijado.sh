#!/bin/sh
# Baja el archivo de NOMBRE que fija distro/fijados.txt para esta arquitectura y frena (sale con error y lo borra)
# si su SHA-256 no es la fijada. Imprime la ruta de lo que bajó, en la carpeta actual. Lo usa distro/Dockerfile.
#   bajar-fijado.sh NOMBRE [ARQ]        ARQ: amd64 o arm64 (por defecto TARGETARCH o la de dpkg)
# FIJADOS cambia el archivo (por defecto el que está al lado de este script).
set -eu
[ $# -ge 1 ] || { echo 'Uso: bajar-fijado.sh NOMBRE [ARQ]' >&2; exit 2; }
nombre=$1
arq=${2:-${TARGETARCH:-$(dpkg --print-architecture 2>/dev/null || echo desconocida)}}
fijados=${FIJADOS:-$(dirname "$0")/fijados.txt}
lineas=$(awk -v n="$nombre" -v a="$arq" '$1 == n && ($3 == a || $3 == "all") && NF == 5' "$fijados")
[ "$(printf '%s\n' "$lineas" | grep -c .)" = 1 ] || { echo "bajar-fijado: $nombre ($arq) tiene que figurar exactamente una vez en $fijados" >&2; exit 1; }
# shellcheck disable=SC2086
set -- $lineas
version=$2 suma=$4 url=$5
printf '%s\n' "$suma" | grep -Eq '^[0-9a-f]{64}$' || { echo "bajar-fijado: la suma de $nombre no es SHA-256" >&2; exit 1; }
case $url in https://*) ;; *) echo "bajar-fijado: $nombre no se baja por https: $url" >&2; exit 1 ;; esac
archivo=$(basename "$url")
curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 30 -o "$archivo" "$url" || { rm -f "$archivo"; echo "bajar-fijado: no pude bajar $url" >&2; exit 1; }
if ! printf '%s  %s\n' "$suma" "$archivo" | sha256sum -c - >/dev/null 2>&1; then
  rm -f "$archivo"
  echo "bajar-fijado: la SHA-256 de $nombre $version ($arq) no es la fijada en $fijados: no sigo." >&2
  exit 1
fi
echo "bajar-fijado: $nombre $version ($arq) verificado" >&2
printf '%s\n' "$(pwd)/$archivo"
