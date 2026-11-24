#!/usr/bin/env bash
# Los pasos de la GitHub Action de Orobas (action.yml, en la raíz del repositorio). Cada paso es un subcomando:
#
#   accion.sh preparar    decide si se corre (PRs de forks), con qué configuración y con qué claves de caché
#   accion.sh instalar    instala la versión FIJA pedida con el install.sh de esta misma acción (release firmado)
#   accion.sh correr      corre «cyber ci» y deja el código y las salidas del paso
#   accion.sh comentar    crea o edita el comentario del PR (un fallo acá avisa y no cambia el resultado)
#   accion.sh terminar    sale con el código de la corrida
#
# Las entradas llegan por variables de entorno (INPUT_*), nunca interpoladas en el script: así un valor no puede
# inyectar comandos. Fuera de GitHub Actions sirve para probar: GITHUB_OUTPUT, GITHUB_ENV y GITHUB_PATH son archivos.
set -euo pipefail

AQUI=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RAIZ_ACCION=${GITHUB_ACTION_PATH:-$(cd "$AQUI/../.." && pwd)}
PREFIJO=${OROBAS_CI_PREFIJO:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/orobas-sec}
CACHE_DIR=${OROBAS_CI_CACHE_DIR:-.orobas-ci-cache}

salida() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"; printf '  %s=%s\n' "$1" "$2"; }
aviso() { printf '::warning title=Orobas::%s\n' "$*"; }
error() { printf '::error title=Orobas::%s\n' "$*"; }
nota() { printf '::notice title=Orobas::%s\n' "$*"; }

# Del evento del PR: si viene de un fork y cuál es el commit base. Sin evento (push, schedule): nada.
evento() {
  if [ -z "${GITHUB_EVENT_PATH:-}" ] || [ ! -f "$GITHUB_EVENT_PATH" ]; then
    echo "no no"
    return
  fi
  # shellcheck disable=SC2016 # es JavaScript: las comillas simples son a propósito
  node -e '
    const e = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    const pr = e.pull_request;
    if (!pr) { console.log("no no"); process.exit(0); }
    const fork = !!(pr.head && pr.head.repo && (pr.head.repo.fork || (pr.base && pr.base.repo && pr.head.repo.full_name !== pr.base.repo.full_name)));
    console.log(`${fork ? "si" : "no"} ${(pr.base && pr.base.sha) || "no"}`);
  ' "$GITHUB_EVENT_PATH"
}

preparar() {
  local version=${INPUT_VERSION:-} modo=${INPUT_MODO:-evaluar} forks=${INPUT_FORKS:-omitir} config=${INPUT_CONFIG:-.orobas/ci.yml}
  if ! printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    error "«version» tiene que ser una versión fija vX.Y.Z de un release firmado (vino «${version}»). No se instala «latest» ni nada de main."
    exit 2
  fi
  case $modo in evaluar | retest) ;; *) error "«modo» tiene que ser evaluar o retest (vino «${modo}»)."; exit 2 ;; esac
  case $forks in omitir | base) ;; *) error "«forks» tiene que ser omitir o base (vino «${forks}»)."; exit 2 ;; esac
  local fork base_sha
  read -r fork base_sha < <(evento)
  local correr=si ref=""
  if [ "$fork" = si ]; then
    if [ "$forks" = omitir ]; then
      nota "PR de un fork: no se corre (forks: omitir). Con secretos, un PR de un fork podría atacar a otro con las credenciales del repositorio; ver docs/ci.md, «PRs de forks»."
      correr=no
    else
      # La configuración y las supresiones salen de la base, no del PR: el PR no puede cambiar a quién se ataca.
      [ "$base_sha" != no ] || { error "PR de un fork sin commit base en el evento: no corro."; exit 2; }
      git fetch --no-tags --depth=1 origin "$base_sha" >/dev/null 2>&1 || true
      git cat-file -e "${base_sha}^{commit}" 2>/dev/null || { error "No pude traer el commit base ${base_sha} para leer la configuración de la base."; exit 2; }
      ref=$base_sha
      nota "PR de un fork: la configuración y las supresiones salen de la base (${base_sha:0:12}), no del PR."
    fi
  fi
  # Claves de caché: por archivo de configuración y ref; un PR también puede restaurar la última de su base.
  local id
  id=$(printf '%s' "$config" | sha256sum | cut -c1-12)
  salida correr "$correr"
  salida config_ref "$ref"
  salida fork "$fork"
  salida clave "orobas-ci-${id}-${GITHUB_REF:-local}-${GITHUB_RUN_ID:-0}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "claves<<FIN_CLAVES"
      echo "orobas-ci-${id}-${GITHUB_REF:-local}-"
      [ -z "${GITHUB_BASE_REF:-}" ] || echo "orobas-ci-${id}-refs/heads/${GITHUB_BASE_REF}-"
      echo "FIN_CLAVES"
    } >>"$GITHUB_OUTPUT"
  fi
}

instalar() {
  local version=${INPUT_VERSION:?falta INPUT_VERSION}
  printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { error "versión inválida: ${version}"; exit 2; }
  [ -f "$RAIZ_ACCION/install.sh" ] || { error "No encuentro install.sh en la acción (${RAIZ_ACCION})."; exit 3; }
  mkdir -p "$PREFIJO"
  # El install.sh de esta acción (fijada por SHA en el workflow) trae la clave pública de los releases: verifica la
  # firma de SHA256SUMS y la suma del paquete antes de instalar. Ante cualquier falla no instala nada.
  if ! sh "$RAIZ_ACCION/install.sh" --version "$version" --modo nativo --prefix "$PREFIJO" --bin "$PREFIJO/bin" --si; then
    error "No se pudo instalar Orobas ${version} verificado (firma o suma). No corro nada sin verificar."
    exit 3
  fi
  local instalada
  instalada=$("$PREFIJO/bin/cyber" --version 2>&1 | head -n 1)
  case $instalada in *"$version"*) ;; *) error "Se instaló «${instalada}» y se pidió ${version}."; exit 3 ;; esac
  [ -z "${GITHUB_PATH:-}" ] || echo "$PREFIJO/bin" >>"$GITHUB_PATH"
  echo "Instalado: ${instalada} en ${PREFIJO}."
}

correr() {
  local cyber=${OROBAS_CI_CYBER:-$PREFIJO/bin/cyber}
  local config=${INPUT_CONFIG:-.orobas/ci.yml} carpeta=${INPUT_SALIDA:-orobas-ci}
  local -a args=(ci --config "$config" --salida "$carpeta")
  [ "${INPUT_MODO:-evaluar}" != retest ] || args+=(--retest)
  [ -z "${INPUT_CONFIG_REF:-}" ] || args+=(--config-ref "$INPUT_CONFIG_REF")
  if [ -f "$CACHE_DIR/anterior.json" ]; then args+=(--anterior "$CACHE_DIR/anterior.json"); fi
  if [ -n "${INPUT_ARGUMENTOS:-}" ]; then
    local -a extra
    read -r -a extra <<<"$INPUT_ARGUMENTOS"
    args+=("${extra[@]}")
  fi
  [ -n "${OROBAS_CI_AUTORIZACION:-}" ] || aviso "Falta la entrada «autorizacion» (la huella del alcance): la corrida va a terminar con código 2. Ver docs/ci.md, «Autorizar el alcance»."
  local codigo=0
  "$cyber" "${args[@]}" || codigo=$?
  # Sin resultado escrito no hay nada que leer: es infraestructura, nunca «todo bien».
  if [ ! -f "$carpeta/resultado.json" ]; then
    error "cyber ci terminó con ${codigo} sin escribir ${carpeta}/resultado.json."
    [ "$codigo" -ne 0 ] || codigo=3
  fi
  salida codigo "$codigo"
  [ -f "$carpeta/resultado.sarif" ] && salida sarif "$carpeta/resultado.sarif"
  [ -f "$carpeta/resumen.md" ] && salida resumen "$carpeta/resumen.md"
  # La próxima corrida compara contra ésta (sólo si llegó a evaluar: 0, 1 o 4).
  case $codigo in 0 | 1 | 4)
    mkdir -p "$CACHE_DIR"
    cp "$carpeta/resultado.json" "$CACHE_DIR/anterior.json"
    salida guardar_cache si ;;
  *) salida guardar_cache no ;;
  esac
  [ -z "${GITHUB_ENV:-}" ] || echo "OROBAS_CI_CODIGO=${codigo}" >>"$GITHUB_ENV"
}

comentar() {
  local cyber=${OROBAS_CI_CYBER:-$PREFIJO/bin/cyber} carpeta=${INPUT_SALIDA:-orobas-ci}
  [ -f "$carpeta/resumen.md" ] || { aviso "No hay resumen para comentar."; return 0; }
  if ! "$cyber" ci comentar --salida "$carpeta"; then
    aviso "No pude comentar en el PR (¿falta pull-requests: write?). El resumen igual está en el job."
  fi
}

terminar() {
  local codigo=${OROBAS_CI_CODIGO:-}
  if [ -z "$codigo" ]; then
    [ "${INPUT_CORRIO:-si}" = no ] && exit 0
    error "La corrida no dejó un código de salida."
    exit 3
  fi
  case $codigo in
    0) echo "Orobas: sin hallazgos que bloqueen." ;;
    1) error "Orobas: hay hallazgos verificados que bloquean (ver el resumen y la pestaña de seguridad)." ;;
    2) error "Orobas: error de configuración o de autorización." ;;
    3) error "Orobas: falló el proveedor de modelos o el objetivo; la corrida no es concluyente." ;;
    4) error "Orobas: se agotó el presupuesto o el tiempo antes de terminar." ;;
  esac
  exit "$codigo"
}

case ${1:-} in
  preparar | instalar | correr | comentar | terminar) "$1" ;;
  *) echo "Uso: accion.sh preparar|instalar|correr|comentar|terminar" >&2; exit 2 ;;
esac
