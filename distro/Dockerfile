# Elevate AI Cyber con su caja de herramientas y Chromium. Construir desde la raíz del repo:
#   docker build -f distro/Dockerfile -t orobas-sec .
# La imagen de los releases (ghcr.io/leandrozz/orobas-sec, pública) la arma y publica, para amd64 y arm64, el workflow
# de release (.github/workflows/release.yml), que fija su digest en los lanzadores del release (docs/releases.md).
# Correr sobre una carpeta de proyecto (ahí quedan sesiones, hallazgos y artefactos):
#   docker run -it --rm -e OROBAS_API_KEY -v "$PWD:/proyecto" orobas-sec
# Base fijada por digest (el índice multiplataforma de node:26.13.1-bookworm-slim): el tag es sólo para leerlo.
# Para subirla: docs/releases.md, «Imagen».
FROM node:26.13.1-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1
# Lo define BuildKit (amd64 o arm64); elige el archivo de cada herramienta en distro/fijados.txt.
ARG TARGETARCH
# Enlaza el paquete publicado con el repositorio: quien tiene acceso al repo puede bajar la imagen.
LABEL org.opencontainers.image.source="https://github.com/Leandrozz/orobas-sec" org.opencontainers.image.description="Elevate AI Cyber con su caja de herramientas y Chromium"
# procps: REA (más abajo) necesita «ps» para supervisar sus procesos hijos.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip git nmap sqlmap chromium fonts-liberation procps \
 && rm -rf /var/lib/apt/lists/*
# Lo que se baja de terceros tiene versión exacta y SHA-256 en distro/fijados.txt: bajar-fijado.sh baja cada archivo y
# hace fallar el build si la suma no coincide. scripts/actualizar-fijados.sh propone versiones nuevas (revisar el diff).
COPY distro/fijados.txt distro/bajar-fijado.sh /opt/fijados/
# Escáneres: los binarios que publican sus autores, sin compilar nada.
RUN set -eu; cd /tmp; b=/opt/fijados/bajar-fijado.sh; \
  for n in httpx nuclei subfinder katana dnsx; do f=$($b $n); unzip -oq "$f" "$n" -d /usr/local/bin; rm "$f"; done; \
  f=$($b ffuf); tar -xzf "$f" -C /usr/local/bin ffuf; rm "$f"; \
  chmod +x /usr/local/bin/httpx /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/katana /usr/local/bin/dnsx /usr/local/bin/ffuf
# Análisis estático: gitleaks (binario de su release) y semgrep en un venv propio, con semgrep y cada dependencia en
# versión exacta y con su SHA-256 (distro/semgrep-requisitos.txt; pip --require-hashes no instala nada que no esté ahí).
COPY distro/semgrep-requisitos.txt /opt/fijados/
RUN set -eu; cd /tmp; b=/opt/fijados/bajar-fijado.sh; \
  f=$($b gitleaks); tar -xzf "$f" -C /usr/local/bin gitleaks; rm "$f"; chmod +x /usr/local/bin/gitleaks; \
  apt-get update && apt-get install -y --no-install-recommends python3-venv && rm -rf /var/lib/apt/lists/*; \
  python3 -m venv /opt/semgrep; \
  /opt/semgrep/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary=:all: -r /opt/fijados/semgrep-requisitos.txt; \
  ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep; \
  SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --version
# Plataformas: las CLIs oficiales que el agente usa con platform_cli (GitHub, Supabase, Kubernetes, AWS).
# Vercel, Google Cloud, Azure y Cloudflare no vienen por tamaño (Vercel solo son 370 MB).
RUN set -eu; cd /tmp; b=/opt/fijados/bajar-fijado.sh; \
  f=$($b gh); mkdir gh; tar -xzf "$f" -C gh --strip-components=2 --wildcards '*/bin/gh'; mv gh/gh /usr/local/bin/gh; rm -rf gh "$f"; \
  f=$($b supabase); tar -xzf "$f" -C /usr/local/bin supabase; rm "$f"; \
  f=$($b kubectl); mv "$f" /usr/local/bin/kubectl; \
  f=$($b awscli); unzip -q "$f"; ./aws/install; rm -rf aws "$f"; \
  chmod +x /usr/local/bin/gh /usr/local/bin/supabase /usr/local/bin/kubectl
# Apps móviles (apk_analyze): Java de Debian, y jadx y apktool fijados (las mismas versiones que
# src/instalar-herramientas.ts, MOVIL, que instala lo mismo dentro de una caja vieja con /toolbox_install).
# Los argumentos de la JVM de jadx son los de su script.
RUN set -eu; cd /tmp; b=/opt/fijados/bajar-fijado.sh; mkdir -p /usr/share/man/man1; \
  apt-get update && apt-get install -y --no-install-recommends openjdk-17-jre-headless && rm -rf /var/lib/apt/lists/*; \
  f=$($b jadx); mkdir -p /opt/jadx && unzip -q "$f" -d /opt/jadx && rm "$f"; \
  printf '#!/bin/sh\nexec java -XX:+IgnoreUnrecognizedVMOptions -Xms256M -XX:MaxRAMPercentage=70.0 -XX:ParallelGCThreads=3 -Djdk.util.zip.disableZip64ExtraFieldValidation=true -cp "/opt/jadx/lib/*" jadx.cli.JadxCLI "$@"\n' > /usr/local/bin/jadx; \
  f=$($b apktool); mv "$f" /opt/apktool.jar; \
  printf '#!/bin/sh\nexec java -jar /opt/apktool.jar "$@"\n' > /usr/local/bin/apktool; \
  chmod +x /usr/local/bin/jadx /usr/local/bin/apktool
# Harness y fuzzing (harness_build, fuzz_run y poc_run; src/fuzzing.ts, sólo en la caja): clang 16 de Debian con
# compiler-rt (libFuzzer, ASan, UBSan, MSan, LSan), llvm-symbolizer y lo mínimo para compilar proyectos C/C++
# (build-essential, cmake, autotools, pkg-config, meson y ninja). Versiones fijas por bookworm (16.0.6). Suma
# ~700 MB sin comprimir (~150 MB de paquetes). Los enlaces de /usr/local/bin son los que usa src/fuzzing.ts (FUZZ).
# La prueba compila el corte de red que lleva cada harness (distro/fuzz/sin-red.c) y un fuzzer con ASan+UBSan;
# en amd64 además lo corre y comprueba que no abre sockets de red (arm64 se construye emulado: sólo compila).
COPY distro/fuzz/sin-red.c /opt/fuzz/sin-red.c
RUN set -eu; apt-get update && apt-get install -y --no-install-recommends clang-16 libclang-rt-16-dev llvm-16 \
      build-essential cmake autoconf automake libtool pkg-config meson ninja-build \
 && rm -rf /var/lib/apt/lists/*; \
  for tool in clang clang++ llvm-symbolizer llvm-cov llvm-profdata; do ln -sf /usr/lib/llvm-16/bin/$tool /usr/local/bin/$tool; done; \
  cd /tmp; \
  printf '#include <stddef.h>\n#include <stdint.h>\n#include <unistd.h>\n#include <sys/socket.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n  int u = socket(AF_UNIX, SOCK_STREAM, 0);\n  if (u < 0 || socket(AF_INET, SOCK_STREAM, 0) >= 0) __builtin_trap();\n  close(u);\n  return 0;\n}\n' > prueba.c; \
  clang -c -g -O1 -fsanitize=address,undefined /opt/fuzz/sin-red.c -o sin-red.o; \
  clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined prueba.c sin-red.o -Wl,--export-dynamic-symbol=socket -o prueba; \
  if [ "$(dpkg --print-architecture)" = amd64 ]; then ASAN_OPTIONS=detect_leaks=0 ./prueba -runs=3; fi; \
  rm -f prueba prueba.c sin-red.o
# Playwright sin navegadores: controla el Chromium del sistema. Versión fija: npm ci instala exactamente
# distro/navegador/package-lock.json y verifica el sha512 de cada paquete; sin scripts de instalación.
COPY distro/navegador/package.json distro/navegador/package-lock.json /opt/cyber-browser/
RUN cd /opt/cyber-browser && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --ignore-scripts --no-audit --no-fund --cache /tmp/navegador-npm \
 && rm -rf /tmp/navegador-npm && test -f /opt/cyber-browser/node_modules/playwright/index.mjs
# REA (ingeniería inversa; el servidor MCP «rea» que Orobas incorpora sólo dentro de la caja, src/rea.ts).
# Versión fija: npm ci instala exactamente distro/rea/package-lock.json y verifica el sha512 de cada paquete
# (rea-agents 6.8.0: sha512-9QDeRnGq…ZPZ9ww==, el «integrity» que publica npm); después se comprueba la versión
# y que este Node cumpla lo que pide REA. Sin scripts de instalación: el binario opcional de Frida no se baja
# (Orobas no ofrece instrumentación). De la caja usa ps, apktool (decode_android_resources) y Chromium, por un
# envoltorio con las banderas del contenedor (REA no acepta argumentos de lanzamiento) que lo hace salir por
# el proxy de alcance de Orobas: el navegador de REA no llega a hosts fuera del alcance. El jadx de la caja
# no le sirve: sus herramientas de Android piden jadx-headless-mcp 0.7.1 y un JDK completo, que no vienen.
COPY distro/rea/package.json distro/rea/package-lock.json /opt/rea/
RUN cd /opt/rea && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --cache /tmp/rea-npm && rm -rf /tmp/rea-npm \
 && grep -q '"integrity": "sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww=="' package-lock.json \
 && node -e 'const p=require("/opt/rea/node_modules/rea-agents/package.json"),semver=require("/opt/rea/node_modules/semver");if(p.version!=="6.8.0"||!semver.satisfies(process.version,p.engines.node)){console.error("REA "+p.version+" no corre con Node "+process.version+" ("+p.engines.node+")");process.exit(1)}' \
 && test -f /opt/rea/node_modules/rea-agents/scripts/rea.mjs \
 && printf '#!/bin/sh\n# Chromium de REA: sale sólo por el proxy de alcance de Orobas (src/rea.ts), loopback incluido; sin él no arranca.\n[ -n "$CYBER_REA_PROXY" ] || { echo "chromium-rea: falta CYBER_REA_PROXY, el proxy de alcance de Orobas" >&2; exit 1; }\nexec /usr/bin/chromium --no-sandbox --disable-dev-shm-usage --proxy-server="$CYBER_REA_PROXY" --proxy-bypass-list="<-loopback>" "$@"\n' > /usr/local/bin/chromium-rea && chmod +x /usr/local/bin/chromium-rea
WORKDIR /opt/elevate-cyber
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --omit=dev
COPY bin ./bin
COPY src ./src
# Habilidades del agente (skill_load): cve-stack, orquestacion, movil.
COPY skills ./skills
COPY distro ./distro
# La extensión de Chromium: «cyber extension» la copia a la carpeta de credenciales del host.
COPY extension ./extension
# Lo que lee help_search: el README, las guías y la documentación de herramientas (src/manual.ts).
# CONTINUAR.md no va: son notas internas de desarrollo, no manual de uso.
COPY README.md ./
COPY docs/herramientas.md ./docs/herramientas.md
# Corre como el usuario «node» (uid 1000, el habitual del host) para poder escribir en la carpeta montada.
RUN mkdir -p /proyecto && chown node:node /proyecto \
 && mkdir -p /home/node/.config /home/node/.local/share && chmod 1777 /home/node /home/node/.config /home/node/.local /home/node/.local/share
# git (que usa el agente por la herramienta shell) desconfía de /proyecto montado con otro dueño.
RUN git config --system --add safe.directory '*' && git config --system core.filemode false
USER node
# Chromium: --no-sandbox porque el contenedor no tiene espacios de nombres de usuario; --disable-dev-shm-usage porque /dev/shm mide 64 MB.
# La imagen trae una base de proveedores y tarifas de solo lectura (CYBER_CONFIG_BASE), que se mezcla debajo
# de la configuración del usuario. Lo que se guarda (config.json, extensión, credenciales de HackerOne sin
# llavero, logins de las plataformas, sesiones, hallazgos) va a la carpeta montada, así sobrevive al contenedor.
ENV CYBER_PLAYWRIGHT=/opt/cyber-browser/node_modules/playwright/index.mjs CYBER_CHROMIUM=/usr/bin/chromium CYBER_CHROMIUM_ARGS="--no-sandbox --disable-dev-shm-usage" \
    CYBER_CONFIG_BASE=/opt/elevate-cyber/distro/config.ejemplo.json XDG_CONFIG_HOME=/home/node/.config \
    CYBER_PLATAFORMAS_HOME=/home/node/.config/elevate-cyber/plataformas CYBER_DATA_DIR=/home/node/.local/share/elevate-cyber HOME=/home/node
VOLUME ["/proyecto"]
# Sin telemetría ni chequeos de versión de las herramientas de la imagen (las mismas variables que pone el agente en
# cada proceso hijo, src/exec.ts SIN_TELEMETRIA; sirven también para lo que se corra a mano en el contenedor).
ENV DO_NOT_TRACK=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 NO_UPDATE_NOTIFIER=1 \
  NPM_CONFIG_UPDATE_NOTIFIER=false NEXT_TELEMETRY_DISABLED=1
ENTRYPOINT ["/opt/elevate-cyber/bin/cyber", "-C", "/proyecto"]