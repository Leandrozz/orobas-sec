#!/bin/sh
# Regenera distro/semgrep-requisitos.txt: semgrep VERSION con todas sus dependencias en versión exacta y la SHA-256
# de cada wheel para Linux amd64 y arm64 con Python 3.11 (el de Debian bookworm, la base de la imagen). La imagen
# lo instala con pip --require-hashes --no-deps --only-binary=:all:, así que no entra nada que no esté acá.
# Sólo baja wheels (nunca ejecuta código de un paquete) y contrasta cada suma con la que publica PyPI.
#   scripts/semgrep-requisitos.sh VERSION DIR      (DIR: dónde bajar; mejor fuera de /tmp si es RAM)
# Necesita python3 con venv. Revisá el diff y construí la imagen antes de commitear.
set -eu
[ $# = 2 ] || { echo 'Uso: scripts/semgrep-requisitos.sh VERSION DIR' >&2; exit 2; }
VERSION=$1
DIR=$(mkdir -p "$2" && cd "$2" && pwd)
RAIZ=$(cd "$(dirname "$0")/.." && pwd)
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "versión inválida: $VERSION" >&2; exit 1; }
[ -x "$DIR/venv/bin/python" ] || python3 -I -m venv "$DIR/venv"
for a in x86_64 aarch64; do
  rm -rf "$DIR/$a"
  mkdir -p "$DIR/$a"
  set --
  for y in $(seq 17 36); do set -- "$@" --platform "manylinux_2_${y}_$a"; done
  (cd "$DIR" && ./venv/bin/python -I -m pip download --quiet --disable-pip-version-check --no-cache-dir --only-binary=:all: \
    --python-version 3.11 --implementation cp --abi cp311 --abi abi3 --abi none "$@" --platform "manylinux2014_$a" \
    -d "$DIR/$a" "semgrep==$VERSION")
done
cd "$DIR"
python3 -I - "$VERSION" "$RAIZ/distro/semgrep-requisitos.txt" <<'PY'
import hashlib, json, os, re, sys, urllib.request
version, salida = sys.argv[1], sys.argv[2]
paquetes = {}
for arq in ("x86_64", "aarch64"):
    for archivo in sorted(os.listdir(arq)):
        if not archivo.endswith(".whl"):
            sys.exit(f"no es un wheel: {archivo}")
        nombre, ver = archivo.split("-")[:2]
        with open(os.path.join(arq, archivo), "rb") as f:
            suma = hashlib.sha256(f.read()).hexdigest()
        p = paquetes.setdefault(nombre.lower(), {"version": ver, "sumas": {}})
        if p["version"] != ver:
            sys.exit(f"{nombre}: versiones distintas según la arquitectura ({p['version']} y {ver})")
        p["sumas"][archivo] = suma
for nombre, p in paquetes.items():
    with urllib.request.urlopen(f"https://pypi.org/pypi/{nombre}/{p['version']}/json", timeout=60) as r:
        publicadas = {u["filename"]: u["digests"]["sha256"] for u in json.load(r)["urls"]}
    for archivo, suma in p["sumas"].items():
        if publicadas.get(archivo) != suma:
            sys.exit(f"{archivo}: la suma no coincide con la que publica PyPI")
lineas = [
    f"# semgrep {version} para la imagen (distro/Dockerfile), con todas sus dependencias en versión exacta y la SHA-256",
    "# de cada wheel para Linux amd64 y arm64 con Python 3.11 (Debian bookworm), contrastada con la que publica PyPI.",
    "# Generado por scripts/semgrep-requisitos.sh: no lo edites a mano.",
]
for nombre in sorted(paquetes):
    p = paquetes[nombre]
    sumas = sorted(set(p["sumas"].values()))
    lineas.append(f"{nombre}=={p['version']} \\")
    lineas.extend(f"    --hash=sha256:{s}" + (" \\" if i < len(sumas) - 1 else "") for i, s in enumerate(sumas))
with open(salida, "w", encoding="utf-8") as f:
    f.write("\n".join(lineas) + "\n")
print(f"{salida}: semgrep {version}, {len(paquetes)} paquetes, sumas contrastadas con PyPI.")
PY
