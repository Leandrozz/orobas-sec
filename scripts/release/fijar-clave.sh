#!/bin/sh
# Cambia la clave pública de los releases en todo el repositorio: install.sh, install.ps1, los dos lanzadores,
# el README público y docs/releases.md (donde esté la clave actual o su huella). Usa sólo «tipo base64» del .pub:
# el comentario (que suele ser un correo) no se copia.
#   scripts/release/fijar-clave.sh CLAVE.pub
# Sólo la parte pública: la privada nunca entra al repositorio (ver docs/releases.md).
set -eu
[ $# = 1 ] && [ -f "$1" ] || { echo 'Uso: scripts/release/fijar-clave.sh CLAVE.pub' >&2; exit 2; }
RAIZ=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$RAIZ"
case $(head -c 64 "$1") in *PRIVATE*) echo 'Eso es una clave privada: pasá el .pub.' >&2; exit 1 ;; esac
NUEVA=$(awk 'NR == 1 { print $1, $2 }' "$1")
printf '%s\n' "$NUEVA" | grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' || { echo 'Hace falta una clave pública ssh-ed25519 (ssh-keygen -t ed25519).' >&2; exit 1; }
VIEJA=$(sed -n "s/^CLAVE_PUBLICA='\(.*\)'\$/\1/p" install.sh)
[ -n "$VIEJA" ] || { echo 'No encontré la clave actual en install.sh.' >&2; exit 1; }
huella() { printf '%s\n' "$1" >"$T/k.pub"; ssh-keygen -lf "$T/k.pub" | cut -d' ' -f2; }
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
case $VIEJA in *REEMPLAZAR*) HV='SHA256:REEMPLAZAR-POR-LA-HUELLA-DE-LA-CLAVE' ;; *) HV=$(huella "$VIEJA") ;; esac
HN=$(huella "$NUEVA")
for f in $(git grep -lF -e "$VIEJA" -e "$HV" -- . ':!scripts/release/fijar-clave.sh'); do
  awk -v a="$VIEJA" -v b="$NUEVA" -v ha="$HV" -v hb="$HN" '
    { while ((i = index($0, a)) > 0) $0 = substr($0, 1, i - 1) b substr($0, i + length(a))
      while ((i = index($0, ha)) > 0) $0 = substr($0, 1, i - 1) hb substr($0, i + length(ha))
      print }' "$f" >"$T/nuevo"
  cat "$T/nuevo" >"$f"
  echo "actualizado: $f"
done
for f in install.sh distro/lanzador/cyber; do grep -qxF "CLAVE_PUBLICA='$NUEVA'" "$f" || { echo "No quedó la clave en $f." >&2; exit 1; }; done
for f in install.ps1 distro/lanzador/cyber.ps1; do grep -qxF "\$ClavePublica = '$NUEVA'" "$f" || { echo "No quedó la clave en $f." >&2; exit 1; }; done
echo "Clave de los releases: $NUEVA"
echo "Huella: $HN"
echo 'Revisá con git diff y commiteá. La privada va al secreto OROBAS_FIRMA_RELEASE del entorno «release» (docs/releases.md).'
