#!/bin/sh
# Propone subir las versiones fijadas de lo que la imagen baja de terceros (distro/fijados.txt): busca la última
# versión publicada hace al menos 7 días, baja cada archivo a --dir, calcula su SHA-256, lo contrasta con las sumas
# que publica el autor (y con el digest que GitHub calcula al subirlo) y reescribe el archivo. No commitea ni
# construye nada: una persona revisa «git diff distro/fijados.txt», construye la imagen y recién ahí commitea.
#   scripts/actualizar-fijados.sh --dir DIR [--min-dias 7] [--version NOMBRE=VERSION]… [NOMBRE…]
#   scripts/actualizar-fijados.sh --revisar        sólo revisa el formato
# Con GITHUB_TOKEN en el entorno, la API de GitHub no limita tan rápido (no hace falta ningún permiso).
set -eu
cd "$(dirname "$0")/.."
exec node --disable-warning=ExperimentalWarning scripts/fijados.ts "$@"
