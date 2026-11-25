#!/bin/sh
# Un fallo de Docker no debe contarse como un control negativo.
set -eu
container=$(docker compose ps -q app) || exit 2
test -n "$container" || exit 2
health=$(docker inspect --format '{{.State.Status}}:{{.State.Health.Status}}' "$container") || exit 2
test "$health" = running:healthy || exit 2
seed=$(docker compose ps -a -q seed) || exit 2
test -n "$seed" || exit 2
test "$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$seed")" = exited:0 || exit 2
worker=$(docker compose run -d --no-deps -T oracle) || exit 2
test -n "$worker" || exit 2
trap 'docker rm -f "$worker" >/dev/null 2>&1 || true' EXIT HUP INT TERM
status=$(docker wait "$worker") || exit 2
docker logs "$worker" >&2 || exit 2
health=$(docker inspect --format '{{.State.Status}}:{{.State.Health.Status}}' "$container") || exit 2
test "$health" = running:healthy || exit 2
test "$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$seed")" = exited:0 || exit 2
case "$status" in
  0|1|2) exit "$status" ;;
  *) exit 2 ;;
esac
