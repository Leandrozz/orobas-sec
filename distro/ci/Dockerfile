# Imagen genérica para correr Orobas en cualquier CI (Jenkins, Buildkite, CircleCI, Azure Pipelines, Drone…) o a mano.
# Se construye desde un checkout FIJO de orobas-sec (el commit del tag del release) e instala ESA versión verificada
# por firma con distro/ci/instalar-verificado.sh: nada de «latest» ni de main.
#
#   git checkout vX.Y.Z
#   docker build -f distro/ci/Dockerfile --build-arg OROBAS_VERSION=vX.Y.Z -t orobas-ci:vX.Y.Z .
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" -e OROBAS_API_KEY -e OROBAS_CI_AUTORIZACION -e <identidades> orobas-ci:vX.Y.Z
#
# El contenedor corre «cyber ci» en la carpeta montada (la raíz de tu repositorio) y sale con su código (0 a 4).
# Misma base que la imagen del proyecto, fijada por digest.
FROM node:26.13.1-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1
ARG OROBAS_VERSION
# De dónde bajar el release (por defecto, los de GitHub). La seguridad no depende de la URL sino de la firma.
ARG CYBER_RELEASES_URL=
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client \
  && rm -rf /var/lib/apt/lists/*
COPY distro/ci/instalar-verificado.sh /usr/local/lib/orobas/instalar-verificado.sh
# La clave pública de los releases sale del install.sh de este mismo checkout (scripts/release/fijar-clave.sh la pone).
COPY install.sh /usr/local/lib/orobas/install.sh
RUN set -eu; \
  test -n "${OROBAS_VERSION:-}" || { echo 'Falta --build-arg OROBAS_VERSION=vX.Y.Z'; exit 1; }; \
  clave=$(sed -n "s/^CLAVE_PUBLICA='\(.*\)'\$/\1/p" /usr/local/lib/orobas/install.sh); \
  HOME=/root sh /usr/local/lib/orobas/instalar-verificado.sh "$OROBAS_VERSION" "$clave" /opt/orobas-sec; \
  chmod -R a+rX /opt/orobas-sec
# Se instala como root en /opt (sólo lectura para el resto); se corre con el usuario del CI para poder escribir las
# salidas en la carpeta montada: docker run --user "$(id -u):$(id -g)" …
ENV PATH=/opt/orobas-sec/bin:$PATH HOME=/tmp
WORKDIR /repo
ENTRYPOINT ["cyber", "ci"]
