#!/bin/sh
# Instala una versión FIJA de Orobas en un CI que no es GitHub Actions (GitLab, Jenkins, la imagen genérica de
# distro/ci/Dockerfile): baja SHA256SUMS y su firma del release, verifica la firma con la clave pública que le pasás
# (la de docs/releases.md, copiada en tu repositorio), comprueba la suma de install.sh y recién entonces lo corre. El
# install.sh del release vuelve a verificar el paquete con la clave que trae adentro. Nada de «latest» ni de main.
#
#   sh distro/ci/instalar-verificado.sh vX.Y.Z "ssh-ed25519 AAAA…" [PREFIJO]
#
# Deja el comando en PREFIJO/bin/cyber (por defecto $HOME/.local/share/orobas-sec). CYBER_RELEASES_URL cambia de
# dónde baja (sólo https, o http hacia esta misma máquina para pruebas); la seguridad está en la firma.
set -eu
VERSION=${1:-}
CLAVE=${2:-}
PREFIJO=${3:-${HOME}/.local/share/orobas-sec}
URL=${CYBER_RELEASES_URL:-https://github.com/Leandrozz/orobas-sec/releases}
URL=${URL%/}
morir() { printf 'instalar-verificado: %s\n' "$*" >&2; exit 1; }
printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || morir "la versión tiene que ser vX.Y.Z fija (vino «$VERSION»)"
printf '%s\n' "$CLAVE" | grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' || morir 'falta la clave pública de los releases (ssh-ed25519 …, la de docs/releases.md)'
case $URL in https://*) P='=https' ;; http://127.0.0.1:* | http://localhost:*) P='=http,https' ;; *) morir "CYBER_RELEASES_URL tiene que ser https" ;; esac
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
for f in SHA256SUMS SHA256SUMS.sig install.sh; do
  curl -fsSL --proto "$P" --proto-redir "$P" --retry 2 --connect-timeout 20 --max-time 300 -o "$T/$f" "$URL/download/$VERSION/$f" || morir "no pude bajar $f de $VERSION"
done
printf 'orobas-sec namespaces="orobas-sec-release" %s\n' "$CLAVE" >"$T/firmantes"
ssh-keygen -Y verify -f "$T/firmantes" -I orobas-sec -n orobas-sec-release -s "$T/SHA256SUMS.sig" <"$T/SHA256SUMS" >/dev/null 2>&1 ||
  morir "la firma de SHA256SUMS de $VERSION no es válida para esa clave: no instalo nada"
esperada=$(awk 'length($1) == 64 && $2 == "install.sh" && NF == 2 { print $1 }' "$T/SHA256SUMS")
[ -n "$esperada" ] || morir 'el SHA256SUMS firmado no lista install.sh'
if command -v sha256sum >/dev/null 2>&1; then real=$(sha256sum "$T/install.sh" | cut -d' ' -f1); else real=$(shasum -a 256 "$T/install.sh" | cut -d' ' -f1); fi
[ "$real" = "$esperada" ] || morir 'la suma de install.sh no coincide con la firmada: no instalo nada'
sh "$T/install.sh" --version "$VERSION" --modo nativo --prefix "$PREFIJO" --bin "$PREFIJO/bin" --si
"$PREFIJO/bin/cyber" --version
