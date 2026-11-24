import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const LANZADOR = resolve("distro/lanzador/cyber");
// docker falso: anota sus argumentos en $T/log y responde según las variables F_*.
const DOCKER_FALSO = `echo "$*" >>"$T/log"
case "$1 $2" in
"ps "*) case " $* " in *" --format {{.Names}} "*) n=$(($(cat "$T/pscount" 2>/dev/null || echo 0) + 1)); echo $n >"$T/pscount"; { [ -z "$F_CORRIENDO" ] || [ "$n" -le "\${F_CORRIENDO_TRAS:-0}" ] || echo "$F_CORRIENDO"; }; cat "$T/creado" 2>/dev/null ;; *" --format "*) [ -z "$F_PUERTOS" ] || printf '%s\\n' "$F_PUERTOS" ;; *) [ -z "$F_OTRO" ] || [ -e "$T/libre" ] || echo abc123 ;; esac ;;
"inspect "*) echo '["ghcr.io/x@sha256:aaa111"]' ;;
"desktop stop") [ -z "$F_SIN_DSTOP" ] || exit 1 ;;
"info "*) [ -z "$F_INFO_COLGADO" ] || sleep 30; [ -z "$F_INFO_FALLA" ] || [ -e "$T/arrancado" ] ;;
"image inspect") if [ -n "$F_IMAGEN_VIEJA" ]; then echo '["otra"]'; exit 0; fi; if [ -n "$F_SIN_IMAGEN" ] && [ ! -e "$T/bajada" ]; then exit 1; fi; if [ -n "$F_SIN_DIGEST" ]; then echo '[]'; else echo '["ghcr.io/x@sha256:aaa111"]'; fi ;;
"buildx imagetools") [ -n "$F_BUILDX" ] && printf '{\\n  "digest": "%s",\\n  "manifests": [{"digest": "sha256:fff999"}]\\n}\\n' "$F_BUILDX" || exit 1 ;;
"manifest inspect") [ -z "$F_COLGADO" ] || { echo $$ >>"$T/pids"; exec sleep 30; }; [ -z "$F_LENTO" ] || sleep "$F_LENTO"; echo '{"Descriptor": {"mediaType": "m", "digest": "'"\${F_REMOTO:-sha256:aaa111}"'", "size": 1}}' ;;
"pull "*) echo "pull-dc=$DOCKER_CONFIG" >>"$T/dclog"; echo "Pulling layers"; if [ -n "$F_NO_AUTORIZADO" ] && [ ! -e "$T/login" ]; then echo "unauthorized" >&2; exit 1; fi; if [ -n "$F_BUENO" ] && [ "$(cat "$T/stdin" 2>/dev/null)" != "$F_BUENO" ]; then echo "unauthorized" >&2; exit 1; fi; : >"$T/bajada" ;;
"login "*) echo "login-dc=$DOCKER_CONFIG" >>"$T/dclog"; cp "$DOCKER_CONFIG/config.json" "$T/cfg" 2>/dev/null; cat >"$T/stdin"; [ -z "$F_LOGIN_RED" ] || { echo "dial tcp: lookup ghcr.io: no such host" >&2; exit 1; }; [ -z "$F_LOGIN_RECHAZO" ] || { echo "Error response from daemon: Get ghcr.io: unauthorized" >&2; exit 1; }; : >"$T/login" ;;
"logout "*) : ;;
"run "*)
  echo "run-dc=$DOCKER_CONFIG ctx=$DOCKER_CONTEXT" >>"$T/dclog"
  case " $* " in *" --chequeo "*) [ -z "$F_CHEQUEO_VIEJO" ] || { echo "TypeError [ERR_PARSE_ARGS_UNKNOWN_OPTION]: Unknown option '--chequeo'" >&2; exit 1; }; [ -n "$F_SIN_MARCA" ] || echo compartido; exit 0 ;; esac
  for a in "$@"; do case "$a" in 127.0.0.1:*) for o in $F_OCUPADO; do case "$a" in *:$o:47615) echo "docker: Error response from daemon: driver failed programming external connectivity: Bind for 127.0.0.1:$o failed: \${F_ERROR:-port is already allocated}." >&2; exit 125 ;; esac; done ;; esac; done
  echo "KEY=$CYBER_SECRETS_KEY" >>"$T/entorno"
  [ -z "$F_NOMBRE_USADO" ] || { for a in "$@"; do case "$a" in cyber-p-*) echo "docker: Error response from daemon: Conflict. The container name \\"/$a\\" is already in use by container \\"abc\\". You have to remove (or rename) that container to be able to reuse that name." >&2 ;; esac; done; exit 125; }
  for a in "$@"; do case "$a" in cyber-p-*) echo "$a" >>"$T/creado" ;; esac; done ;;
"exec "*)
  [ -z "$F_BLOQUEA" ] || { echo $$ >>"$T/bloqueado"; exec sleep 20; }
  [ -z "$F_75" ] || exit 75
  if [ -n "$F_CIERRE" ] && { [ "$F_CIERRE" = siempre ] || [ ! -e "$T/cerro" ]; }; then : >"$T/cerro"; rm -f "$T/creado"; exit 1; fi
  if [ -n "$F_REABRIR" ] && [ ! -e "$T/reabierto" ]; then : >"$T/reabierto"; mkdir -p "$HOME/.local/share/elevate-cyber" "$T/otra ruta"; printf '%s\\tabc\\n' "\${F_RUTA:-$T/otra ruta}" >"$HOME/.local/share/elevate-cyber/reabrir.txt"; exit 75; fi
  exit "\${F_EXEC_CODIGO:-0}" ;;
esac`;

function entorno(extra: Record<string, string> = {}, secretTool = true) {
  const t = mkdtempSync(join(tmpdir(), "cyber-lanz-"));
  const bin = join(t, "bin");
  mkdirSync(bin);
  const falso = (nombre: string, cuerpo: string) => {
    writeFileSync(join(bin, nombre), `#!/bin/sh\n${cuerpo}\n`);
    chmodSync(join(bin, nombre), 0o755);
  };
  falso("docker", DOCKER_FALSO);
  if (secretTool) falso("secret-tool", 'echo "$*" >>"$T/llavero"; case "$*" in *"account ghcr"*) [ -z "$F_ST_COLGADO" ] || { echo $$ >>"$T/pids"; exec sleep 30; }; [ "$1" = store ] && cat >"$T/ghcr"; [ "$1" = lookup ] && { cat "$T/ghcr" 2>/dev/null || printf "%s" "$F_GHCR"; } ;; *) [ -z "$F_LLAVE_COLGADA" ] || exec sleep 30; [ "$1" = lookup ] && { [ -n "$F_LLAVE" ] || exit 1; printf "%s" "$F_LLAVE"; } ;; esac; exit 0');
  falso("systemctl", 'echo "systemctl $*" >>"$T/log"; case "$*" in *list-unit-files*) [ -z "$F_DESKTOP" ] || echo docker-desktop.service ;; *start*) : >"$T/arrancado" ;; esac');
  falso("sudo", 'echo "sudo $*" >>"$T/log"; : >"$T/arrancado"');
  falso("security", 'echo "security $*" >>"$T/log"; case "$1" in find-generic-password) cat "$T/macllave" 2>/dev/null ;; -i) cat >"$T/securitystdin"; sed -n "s/.* -w //p" "$T/securitystdin" >"$T/macllave" ;; esac');
  falso("osascript", 'echo "osascript $*" >>"$T/log"');
  falso("open", 'echo "open $*" >>"$T/log"; : >"$T/arrancado"');
  const proyecto = join(t, "mi proyecto");
  mkdirSync(proyecto);
  const env: Record<string, string> & { HOME: string; F_LLAVE: string } = { PATH: `${bin}:/usr/bin:/bin`, HOME: join(t, "home"), T: t, LANG: "es_AR.UTF-8", F_LLAVE: "S".repeat(43) + "=", ...extra };
  mkdirSync(env.HOME);
  const correr = (args: string[] = [], entrada = "", script = LANZADOR) => spawnSync("sh", [script, ...args], {
    cwd: proyecto, env, encoding: "utf8",
    // Una entrada vacía representa fin de archivo en los pedidos interactivos del lanzador.
    input: entrada || undefined, stdio: [entrada ? "pipe" : "ignore", "pipe", "pipe"],
  });
  const leer = (f: string) => (existsSync(join(t, f)) ? readFileSync(join(t, f), "utf8") : "");
  const darwin = () => falso("uname", "echo Darwin");
  return { t, proyecto, env, correr, leer, darwin };
}

test("lanzador: sin docker sale con 1 y muestra el enlace de instalación", () => {
  const e = entorno();
  const r = spawnSync("/bin/sh", [LANZADOR], { cwd: e.proyecto, env: { ...e.env, PATH: join(e.t, "vacio") }, encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /docs\.docker\.com\/get-docker/);
});

test("lanzador: docker detenido, n no lo arranca; s usa docker-desktop, systemctl, o open en macOS", () => {
  let e = entorno({ F_INFO_FALLA: "1", CYBER_NO_UPDATE: "1" });
  assert.equal(e.correr([], "n\n").status, 1);
  assert.doesNotMatch(e.leer("log"), /systemctl|sudo|open|run/);
  e = entorno({ F_INFO_FALLA: "1", CYBER_NO_UPDATE: "1", F_DESKTOP: "1" });
  e.correr([], "s\n");
  assert.match(e.leer("log"), /systemctl --user start docker-desktop/);
  e = entorno({ F_INFO_FALLA: "1", CYBER_NO_UPDATE: "1" });
  e.correr([], "s\n");
  assert.match(e.leer("log"), /sudo systemctl start docker/);
  e = entorno({ F_INFO_FALLA: "1", CYBER_NO_UPDATE: "1" });
  e.darwin();
  e.correr([], "s\n");
  assert.match(e.leer("log"), /open -a Docker/);
});

test("lanzador: imagen distinta, n no hace pull y s sí", () => {
  let e = entorno({ F_REMOTO: "sha256:abc123" });
  e.correr([], "n\n");
  assert.doesNotMatch(e.leer("log"), /^pull/m);
  e = entorno({ F_REMOTO: "sha256:abc123" });
  e.correr([], "s\n");
  assert.match(e.leer("log"), /^pull ghcr\.io\/leandrozz\/elevate-cyber:latest/m);
});

test("lanzador: Enter responde que sí a la actualización y el aviso dice [S/n]", () => {
  const e = entorno({ F_REMOTO: "sha256:abc123" });
  const r = e.correr([], "\n");
  assert.match(r.stderr, /Hay una imagen nueva\. ¿Actualizo\? \[S\/n\]/);
  assert.match(e.leer("log"), /^pull /m);
});

test("lanzador: manifest inspect lento no pregunta y avisa que no pudo buscar", () => {
  const e = entorno({ F_LENTO: "18" });
  const r = e.correr([], "");
  assert.match(r.stderr, /No pude buscar actualizaciones/);
  assert.doesNotMatch(r.stderr, /\[S\/n\]/);
  assert.doesNotMatch(e.leer("log"), /^pull/m);
});

test("lanzador: pull no autorizado pide usuario y token; el token llega por stdin, no por argumentos", () => {
  const e = entorno({ F_SIN_IMAGEN: "1", F_NO_AUTORIZADO: "1" }, false);
  e.correr([], "mi-usuario\nTOKEN-SECRETO\n");
  assert.match(e.leer("log"), /^login ghcr\.io -u mi-usuario --password-stdin$/m);
  assert.equal(e.leer("stdin").trim(), "TOKEN-SECRETO");
  assert.doesNotMatch(e.leer("log"), /TOKEN-SECRETO/);
});

test("lanzador: CYBER_TRAZAS entra al contenedor si está definida, y nunca en --chequeo", () => {
  for (const [extra, pasa] of [[{ CYBER_TRAZAS: "local" }, true], [{}, false]] as const) {
    const e = entorno({ CYBER_NO_UPDATE: "1", ...extra });
    const r = e.correr([]);
    assert.equal(r.status, 0, r.stderr);
    const [chequeo, run] = e.leer("log").split("\n").filter((l) => l.startsWith("run "));
    assert.equal(/ -e CYBER_TRAZAS( |$)/.test(run!), pasa);
    assert.doesNotMatch(chequeo!, /CYBER_TRAZAS/);
  }
});

test("lanzador: el docker run monta carpetas, pasa variables y nunca el valor de la llave", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", OROBAS_API_KEY: "k" });
  const r = e.correr(["--foo"]);
  assert.equal(r.status, 0, r.stderr);
  const lineas = e.leer("log").split("\n").filter((l) => l.startsWith("run "));
  assert.equal(lineas.length, 2);
  assert.match(lineas[0]!, / --chequeo$/);
  const run = lineas[1]!;
  assert.ok(run.includes(`-v ${e.proyecto}:/proyecto`));
  assert.ok(run.includes(`-v ${e.env.HOME}/.config/elevate-cyber:/home/node/.config/elevate-cyber`));
  assert.ok(run.includes(`-v ${e.env.HOME}/.local/share/elevate-cyber:/home/node/.local/share/elevate-cyber`));
  for (const v of ["CYBER_PROYECTO_HOST", "CYBER_DATOS_HOST", "CYBER_CREDENCIALES_HOST", "CYBER_SECRETS_KEY", "LANG", "LC_ALL", "OROBAS_API_KEY"]) assert.match(run, new RegExp(`-e ${v}( |$)`));
  for (const v of ["TERM", "COLORTERM", "TERM_PROGRAM", "KITTY_WINDOW_ID", "WT_SESSION", "CYBER_STREAMER", "CYBER_STREAMER_OBS"]) assert.doesNotMatch(run, new RegExp(`-e ${v}( |$)`), "la identidad de la terminal es de cada ventana: va en el exec, no en el run -d");
  assert.doesNotMatch(lineas[0]!, /OROBAS_API_KEY/, "--chequeo no recibe la clave de orobas");
  assert.match(run, /--user \d+:\d+/);
  assert.match(run, / --add-host=host\.docker\.internal:host-gateway /);
  assert.match(run, / -p 127\.0\.0\.1:47615:47615 /);
  assert.match(run, / -e CYBER_PUERTO_HOST=47615 /, "el puerto publicado en el host viaja al contenedor");
  assert.doesNotMatch(lineas[0]!, / -p /, "--chequeo no publica puertos");
  assert.doesNotMatch(lineas[0]!, /CYBER_PUERTO_HOST/, "--chequeo tampoco lo fija");
  assert.match(run, /^run -d --rm --init --name cyber-p-[0-9a-f]{12} /);
  assert.match(run, / -e CYBER_COMPARTIDO=1 /);
  assert.match(run, / daemon$/);
  assert.doesNotMatch(run, /--foo/);
  const ex = e.leer("log").split("\n").filter((l) => l.startsWith("exec "));
  assert.equal(ex.length, 1);
  assert.match(ex[0]!, /^exec -i -e CYBER_VENTANA=[0-9a-f]{8} -e LANG -e LC_ALL -e TERM -e COLORTERM -e TERM_PROGRAM -e KITTY_WINDOW_ID -e WT_SESSION -e CYBER_STREAMER -e CYBER_STREAMER_HOSTS -e CYBER_STREAMER_PUBLICOS -e CYBER_STREAMER_USO -e CYBER_STREAMER_OBS cyber-p-[0-9a-f]{12} \/opt\/elevate-cyber\/bin\/cyber -C \/proyecto --foo$/);
  assert.ok(!e.leer("log").includes(e.env.F_LLAVE));
  assert.ok(e.leer("entorno").includes(`KEY=${e.env.F_LLAVE}`));
  assert.equal(statSync(`${e.env.HOME}/.config/elevate-cyber`).mode & 0o777, 0o700);
});

const puertoDelRun = (e: ReturnType<typeof entorno>) => e.leer("log").split("\n").filter((l) => l.startsWith("run ") && !l.endsWith(" --chequeo")).map((l) => l.match(/ -p 127\.0\.0\.1:(\d+):47615 /)?.[1]);

test("lanzador: el puerto de la extensión saltea los que publican otros cyber-*, y CYBER_DATOS_HOST es la carpeta de datos", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_PUERTOS: ":::47616->47615/tcp\n[::1]:47617->47615/tcp, 0.0.0.0:8080->80/tcp\n127.0.0.1:47615->47615/tcp" });
  assert.equal(e.correr().status, 0);
  assert.deepEqual(puertoDelRun(e), ["47618"]);
  assert.match(e.leer("log"), / -e CYBER_PUERTO_HOST=47618 /, "CYBER_PUERTO_HOST sigue al puerto elegido");
  // la variable no lleva valor en argv: lo da el entorno, y apunta a la carpeta de datos que se monta
  const datos = `${e.env.HOME}/.local/share/elevate-cyber`;
  assert.ok(e.leer("log").includes(`-v ${datos}:/home/node/.local/share/elevate-cyber`));
  const raro = entorno({ CYBER_NO_UPDATE: "1", F_PUERTOS: Array.from({ length: 20 }, (_, i) => `127.0.0.1:${47615 + i}->47615/tcp`).join("\n") });
  const r = raro.correr();
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(puertoDelRun(raro), [undefined]);
  assert.doesNotMatch(raro.leer("log"), /CYBER_PUERTO_HOST/, "sin -p no se fija");
  assert.match(r.stderr, /No hay un puerto libre/);
});

test("lanzador: ante «port is already allocated» reintenta con el siguiente puerto y no muestra el error; otros errores sí", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_OCUPADO: "47615 47616" });
  const r = e.correr();
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(puertoDelRun(e), ["47615", "47616", "47617"]);
  assert.doesNotMatch(r.stderr, /already allocated/);
  assert.match(e.leer("log"), /^rm -f cyber-p-[0-9a-f]{12}$/m);
  // un puerto tomado por un proceso que no es Docker da otros textos: también se reintenta
  const otros = entorno({ CYBER_NO_UPDATE: "1", F_OCUPADO: "47615 47616", F_ERROR: "address already in use" });
  assert.equal(otros.correr().status, 0);
  assert.deepEqual(puertoDelRun(otros), ["47615", "47616", "47617"]);
  const reservado = entorno({ CYBER_NO_UPDATE: "1", F_OCUPADO: "47615", F_ERROR: "An attempt was made to access a socket in a way forbidden by its access permissions" });
  assert.equal(reservado.correr().status, 0);
  assert.deepEqual(puertoDelRun(reservado), ["47615", "47616"]);
  // si fallan los 20, abre sin -p (y avisa)
  const todos = entorno({ CYBER_NO_UPDATE: "1", F_OCUPADO: Array.from({ length: 20 }, (_, i) => 47615 + i).join(" ") });
  const t = todos.correr();
  assert.equal(t.status, 0, t.stderr);
  assert.equal(puertoDelRun(todos).length, 21);
  assert.equal(puertoDelRun(todos).at(-1), undefined);
});

test("lanzador: sin OROBAS_API_KEY no la pasa; en macOS no usa --user; sin llavero avisa una sola vez", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" }, false);
  e.darwin();
  rmSync(join(e.t, "bin", "security"));
  const r1 = e.correr();
  const run = e.leer("log").split("\n").filter((l) => l.startsWith("run "))[1]!;
  assert.doesNotMatch(run, /OROBAS_API_KEY|--user|CYBER_SECRETS_KEY/);
  assert.match(r1.stderr, /Sin llavero/);
  assert.doesNotMatch(e.correr().stderr, /Sin llavero/);
});

test("lanzador: con llavero vacío genera una llave de 32 bytes y la guarda", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_LLAVE: "" });
  e.correr();
  assert.match(e.leer("llavero"), /^store .*service elevate-cyber account llave$/m);
  assert.match(e.leer("entorno"), /^KEY=[A-Za-z0-9+/]{43}=$/m);
});

test("lanzador: código 75 con reabrir.txt lanza un segundo run con la otra ruta y la sesión", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_REABRIR: "1" });
  const r = e.correr(["--resumen"]);
  assert.equal(r.status, 0, r.stderr);
  const log = e.leer("log").split("\n");
  const runs = log.filter((l) => l.startsWith("run ") && !l.endsWith("--chequeo"));
  const execs = log.filter((l) => l.startsWith("exec "));
  assert.equal(runs.length, 2);
  assert.ok(runs[1]!.includes(`-v ${e.t}/otra ruta:/proyecto`));
  assert.equal(execs.length, 2);
  assert.ok(execs[1]!.includes(`cyber-p-${hash(`${e.t}/otra ruta`)} `));
  assert.match(execs[1]!, / -s abc$/);
  assert.ok(!existsSync(`${e.env.HOME}/.local/share/elevate-cyber/reabrir.txt`));
});

test("lanzador: código 75 sin reabrir.txt sale con 75 y un mensaje", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_75: "1" });
  const r = e.correr();
  assert.equal(r.status, 75);
  assert.match(r.stderr, /reabrir\.txt/);
});

test("lanzador: --instalar copia el script con permiso de ejecución", () => {
  const e = entorno();
  assert.equal(e.correr(["--instalar"]).status, 0);
  const destino = join(e.env.HOME, ".local/bin/cyber");
  assert.equal(readFileSync(destino, "utf8"), readFileSync(LANZADOR, "utf8"));
  assert.ok(statSync(destino).mode & 0o100);
});

test("lanzador: --actualizar sin terminal hace pull sin preguntar y no se reemplaza solo", () => {
  const e = entorno({ F_REMOTO: "sha256:abc123" });
  const copia = join(e.t, "cyber");
  copyFileSync(LANZADOR, copia);
  const r = e.correr(["--actualizar"], "", copia);
  assert.equal(r.status, 0, r.stderr);
  assert.match(e.leer("log"), /^pull /m);
  assert.doesNotMatch(e.leer("log"), /^run /m);
  assert.match(r.stderr, /Sin terminal no reemplazo el lanzador \(sólo actualizo la imagen\)\. Para hacerlo igual: cyber --actualizar --si/);
  assert.equal(readFileSync(copia, "utf8"), readFileSync(LANZADOR, "utf8"));
});

test("lanzador: una copia de desarrollo (sin la clave de los releases) no se reemplaza ni con --si, y la imagen igual se actualiza", () => {
  const e = entorno({});
  const copia = join(e.t, "cyber");
  copyFileSync(LANZADOR, copia);
  const r = e.correr(["--actualizar", "--si"], "", copia);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /copia de desarrollo \(sin la clave de los releases\): no se reemplaza solo/);
  assert.match(e.leer("log"), /^pull /m);
  assert.equal(readFileSync(copia, "utf8"), readFileSync(LANZADOR, "utf8"));
});

test("lanzador: nunca se baja de main; la imagen por defecto sólo vale en una copia de desarrollo", () => {
  const f = readFileSync(LANZADOR, "utf8");
  assert.doesNotMatch(f, /raw\.githubusercontent\.com|\/main\//);
  assert.match(f, /^RELEASES_URL=\$\{CYBER_RELEASES_URL:-https:\/\/github\.com\/Leandrozz\/orobas-sec\/releases\}$/m);
  assert.match(f, /^IMAGEN=\$\{CYBER_IMAGE:-\$\{IMAGEN_RELEASE:-ghcr\.io\/leandrozz\/elevate-cyber:latest\}\}$/m);
});

test("lanzador: con una imagen fijada por digest no consulta el manifiesto al arrancar", () => {
  const e = entorno({ F_REMOTO: "sha256:otra" });
  const copia = join(e.t, "cyber");
  writeFileSync(copia, readFileSync(LANZADOR, "utf8").replace(/^IMAGEN_RELEASE=''.*$/m, `IMAGEN_RELEASE='ghcr.io/x/y@sha256:${"a".repeat(64)}'`));
  const r = e.correr([], "s\n", copia);
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(e.leer("log"), /manifest inspect|buildx|^pull /m);
  assert.match(e.leer("log"), new RegExp(`^run .*ghcr\\.io/x/y@sha256:${"a".repeat(64)} daemon$`, "m"));
});

const hash = (ruta: string) => createHash("sha256").update(ruta).digest("hex").slice(0, 12);
const runsDeUsuario = (log: string) => log.split("\n").filter((l) => l.startsWith("run ") && !l.endsWith("--chequeo"));

test("lanzador: macOS guarda la llave nueva por stdin de security -i, nunca en argv", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" }, false);
  e.darwin();
  e.correr();
  const llave = e.leer("entorno").match(/^KEY=(.+)$/m)?.[1] ?? "";
  assert.match(llave, /^[A-Za-z0-9+/]{43}=$/);
  assert.ok(!e.leer("log").includes(llave));
  assert.ok(e.leer("securitystdin").includes(`-w ${llave}`));
  assert.match(e.leer("log"), /^security -i$/m);
});

test("lanzador: un reabrir.txt viejo se borra antes de correr y no reabre nada", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_75: "1" });
  const datos = join(e.env.HOME, ".local/share/elevate-cyber");
  mkdirSync(datos, { recursive: true });
  writeFileSync(join(datos, "reabrir.txt"), "/otra ruta\tabc\n");
  const r = e.correr();
  assert.equal(r.status, 75);
  assert.equal(runsDeUsuario(e.leer("log")).length, 1);
  assert.ok(!existsSync(join(datos, "reabrir.txt")));
});

test("lanzador: reabrir.txt con una carpeta que no existe sale con 75 sin lanzar otro run", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_REABRIR: "1", F_RUTA: "/no/existe" });
  const r = e.correr();
  assert.equal(r.status, 75);
  assert.match(r.stderr, /No existe la carpeta a reabrir/);
  assert.equal(runsDeUsuario(e.leer("log")).length, 1);
});

test("lanzador: imagen local sin digest no consulta el manifiesto", () => {
  const e = entorno({ F_SIN_DIGEST: "1", F_REMOTO: "sha256:abc123" });
  e.correr([], "s\n");
  assert.doesNotMatch(e.leer("log"), /^manifest/m);
});

test("lanzador: el pull muestra su avance; sin usuario o token no hay login y se avisa", () => {
  let e = entorno({ F_SIN_IMAGEN: "1" });
  assert.match(e.correr().stderr, /Pulling layers/);
  e = entorno({ F_SIN_IMAGEN: "1", F_NO_AUTORIZADO: "1" });
  const r = e.correr([], "");
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Sin usuario o token/);
  assert.doesNotMatch(e.leer("log"), /^login/m);
});

test("lanzador: responder n a abrir Docker pide abrirlo y volver a correr", () => {
  const e = entorno({ F_INFO_FALLA: "1" });
  assert.match(e.correr([], "n\n").stderr, /Abrí Docker y volvé a correr cyber/);
});

test("lanzador: una imagen vieja que no conoce --chequeo da un mensaje claro y sale con 1", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_CHEQUEO_VIEJO: "1" });
  const r = e.correr();
  assert.equal(r.status, 1);
  assert.match(r.stderr, /imagen local es vieja.*cyber --actualizar/);
  assert.doesNotMatch(r.stderr, /ERR_PARSE_ARGS/);
  assert.equal(runsDeUsuario(e.leer("log")).length, 0);
});

test("lanzador: una imagen que entiende --chequeo pero no imprime «compartido» se trata como vieja", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_SIN_MARCA: "1" });
  const r = e.correr();
  assert.equal(r.status, 1);
  assert.match(r.stderr, /imagen local es vieja.*cyber --actualizar/);
  assert.equal(runsDeUsuario(e.leer("log")).length, 0);
  const en = entorno({ CYBER_NO_UPDATE: "1", F_SIN_MARCA: "1", LANG: "en_US.UTF-8" });
  assert.match(en.correr().stderr, /Your local image is too old for this launcher: run cyber --actualizar/);
});

test("lanzador: si el exec falla porque el contenedor se cerró, lo recrea una sola vez y vuelve a entrar", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_CIERRE: "1" });
  const r = e.correr();
  assert.equal(r.status, 0, r.stderr);
  assert.equal(runsDeUsuario(e.leer("log")).length, 2);
  assert.equal(e.leer("log").split("\n").filter((l) => l.startsWith("exec ")).length, 2);
  // si el contenedor se vuelve a cerrar no insiste: un solo reintento y sale con el código del exec
  const siempre = entorno({ CYBER_NO_UPDATE: "1", F_CIERRE: "siempre" });
  assert.equal(siempre.correr().status, 1);
  assert.equal(runsDeUsuario(siempre.leer("log")).length, 2);
});

test("lanzador: el digest de buildx (índice) coincide con RepoDigests y no pregunta; sin buildx se usa el primer Descriptor", () => {
  // El índice reporta su propio digest arriba y los de cada plataforma debajo: solo el de arriba está en RepoDigests.
  let e = entorno({ F_BUILDX: "sha256:aaa111", F_REMOTO: "sha256:distinto" });
  let r = e.correr([], "");
  assert.doesNotMatch(r.stderr, /\[S\/n\]|No pude buscar/);
  assert.doesNotMatch(e.leer("log"), /^pull/m);
  e = entorno({ F_BUILDX: "sha256:otro" });
  assert.match(e.correr([], "n\n").stderr, /Hay una imagen nueva/);
  e = entorno({ F_REMOTO: "sha256:aaa111" }); // sin buildx: cae a manifest inspect
  r = e.correr([], "");
  assert.doesNotMatch(r.stderr, /\[S\/n\]|No pude buscar/);
});

test("lanzador: con varios Descriptor toma el primero (el de arriba), como el de Windows", () => {
  const e = entorno();
  writeFileSync(join(e.t, "bin", "docker"), `#!/bin/sh\n${DOCKER_FALSO.replace(/"manifest inspect"\)[^\n]*\n/, `"manifest inspect") echo '[{"Descriptor": {"digest": "sha256:aaa111"}},{"Descriptor": {"digest": "sha256:zzz999"}}]' ;;\n`)}\n`);
  const r = e.correr([], "");
  assert.doesNotMatch(r.stderr, /\[S\/n\]|No pude buscar/);
});

test("lanzador: docker info colgado se corta a los 10 s y se trata como no andando", () => {
  const e = entorno({ F_INFO_COLGADO: "1", CYBER_NO_UPDATE: "1" });
  const inicio = Date.now();
  const r = e.correr([], "n\n");
  assert.ok(Date.now() - inicio < 20_000, "no esperó los 30 s del docker colgado");
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Docker no está andando/);
});

test("lanzador: la carpeta de datos queda 0700", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" });
  e.correr();
  assert.equal(statSync(`${e.env.HOME}/.local/share/elevate-cyber`).mode & 0o777, 0o700);
});

const dcs = (e: ReturnType<typeof entorno>) => [...e.leer("dclog").matchAll(/^(login|pull)-dc=(.*)$/gm)].map((m) => [m[1]!, m[2]!] as const);
const conf = (e: ReturnType<typeof entorno>) => join(e.env.HOME, ".docker/config.json");

test("lanzador: primera vez con llavero pide el token, lo valida con un DOCKER_CONFIG temporal, lo guarda y no toca ~/.docker", () => {
  const e = entorno({ F_SIN_IMAGEN: "1", F_NO_AUTORIZADO: "1" });
  const r = e.correr([], "mi-usuario\nTOKEN-SECRETO\n");
  assert.equal(r.status, 0, r.stderr);
  assert.match(e.leer("llavero"), /^store --label Elevate AI Cyber · ghcr\.io service elevate-cyber account ghcr$/m);
  assert.equal(e.leer("ghcr"), "mi-usuario:TOKEN-SECRETO");
  assert.equal(e.leer("stdin").trim(), "TOKEN-SECRETO");
  assert.ok(!existsSync(conf(e)));
  const ops = dcs(e); // el primer pull va sin credenciales; login y el pull siguiente, con el temporal
  assert.deepEqual(ops.map((o) => o[0]), ["pull", "login", "login", "pull"]);
  for (const [, dc] of ops.slice(1)) assert.match(dc, /dc\./);
  assert.doesNotMatch(e.leer("log") + e.leer("llavero"), /TOKEN-SECRETO/);
});

test("lanzador: con credenciales en el llavero no pregunta y login y pull usan un DOCKER_CONFIG que ya no existe", () => {
  const e = entorno({ F_REMOTO: "sha256:abc123", F_GHCR: "u:T0KEN" });
  const r = e.correr([], "s\n");
  assert.doesNotMatch(r.stderr, /Usuario de GitHub/);
  const ops = dcs(e);
  assert.equal(ops.at(-1)![0], "pull");
  assert.ok(ops.every((o) => o[0] === "login" || o[0] === "pull"));
  for (const [, dc] of ops) {
    assert.match(dc, /dc\./);
    assert.ok(!existsSync(dc));
  }
  assert.ok(!existsSync(conf(e)));
  assert.doesNotMatch(e.leer("log"), /T0KEN/);
});

test("lanzador: token vencido en el llavero avisa, pide uno nuevo una vez y lo reemplaza", () => {
  const e = entorno({ F_SIN_IMAGEN: "1", F_GHCR: "u:VIEJO", F_BUENO: "NUEVO" });
  const r = e.correr([], "u2\nNUEVO\n");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /ya no sirve/);
  assert.equal(r.stderr.match(/Usuario de GitHub/g)?.length, 1);
  assert.equal(e.leer("ghcr"), "u2:NUEVO");
});

const PLANO = (e: ReturnType<typeof entorno>) => {
  mkdirSync(join(e.env.HOME, ".docker"));
  writeFileSync(conf(e), JSON.stringify({ auths: { "ghcr.io": { auth: Buffer.from("viejo:PLANO").toString("base64") } } }, null, 2));
};

test("lanzador: token sin cifrar en config.json y s lo pasa al llavero y hace docker logout", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" });
  PLANO(e);
  const r = e.correr([], "s\n");
  assert.match(r.stderr, /¿Lo paso al llavero\? \[S\/n\]/);
  assert.equal(e.leer("ghcr"), "viejo:PLANO");
  assert.match(e.leer("log"), /^logout ghcr\.io$/m);
});

test("lanzador: token sin cifrar y n lo deja y no vuelve a preguntar", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" });
  PLANO(e);
  e.correr([], "n\n");
  assert.ok(!existsSync(join(e.t, "ghcr")));
  assert.doesNotMatch(e.leer("log"), /^logout/m);
  assert.doesNotMatch(e.correr([], "s\n").stderr, /¿Lo paso al llavero/);
  assert.ok(!existsSync(join(e.t, "ghcr")));
});

test("lanzador: sin secret-tool hace docker login común y avisa una sola vez", () => {
  const e = entorno({ F_SIN_IMAGEN: "1", F_NO_AUTORIZADO: "1" }, false);
  const r = e.correr([], "u\nTOK\n");
  assert.match(r.stderr, /docker-credential-secretservice/);
  assert.match(e.leer("dclog"), /^login-dc=$/m);
  rmSync(join(e.t, "bajada"));
  rmSync(join(e.t, "login"));
  assert.doesNotMatch(e.correr([], "u\nTOK\n").stderr, /docker-credential-secretservice/);
});

test("lanzador: un manifest inspect colgado con credenciales muere al cortar el límite y no deja DOCKER_CONFIG", () => {
  const e = entorno({ F_COLGADO: "1", F_GHCR: "u:T0KEN" });
  const r = e.correr([], "");
  assert.match(r.stderr, /No pude buscar actualizaciones/);
  assert.doesNotMatch(r.stderr, /ya no sirve|Usuario de GitHub/);
  const pids = e.leer("pids").split("\n").filter(Boolean).map(Number);
  assert.ok(pids.length > 0);
  for (const pid of pids) assert.throws(() => process.kill(pid, 0), `el docker ${pid} sigue vivo`);
  for (const [, dc] of dcs(e)) assert.ok(!existsSync(dc));
});

test("lanzador: el login temporal escribe credsStore vacío para que ningún helper lo guarde afuera", () => {
  const e = entorno({ F_REMOTO: "sha256:abc123", F_GHCR: "u:T0KEN" });
  e.correr([], "n\n");
  assert.match(e.leer("cfg"), /"credsStore":\s*""/);
});

test("lanzador: login sin red no dice que el token no sirve, no pide otro y conserva el guardado", () => {
  let e = entorno({ F_SIN_IMAGEN: "1", F_GHCR: "u:T0KEN", F_LOGIN_RED: "1" });
  let r = e.correr([], "x\ny\n");
  assert.equal(r.status, 1);
  assert.match(r.stderr, /No pude conectar con ghcr\.io/);
  assert.doesNotMatch(r.stderr, /ya no sirve|Usuario de GitHub/);
  assert.ok(!existsSync(join(e.t, "ghcr")));
  e = entorno({ F_GHCR: "u:T0KEN", F_LOGIN_RED: "1" });
  r = e.correr([], "x\ny\n");
  assert.match(r.stderr, /No pude buscar actualizaciones/);
  assert.doesNotMatch(r.stderr, /ya no sirve|Usuario de GitHub/);
  e = entorno({ F_SIN_IMAGEN: "1", F_GHCR: "u:VIEJO", F_LOGIN_RECHAZO: "1" });
  r = e.correr([], "x\ny\n");
  assert.match(r.stderr, /ya no sirve/);
  assert.equal(r.stderr.match(/Usuario de GitHub/g)?.length, 1);
});

test("lanzador: un llavero que no responde no cuelga el arranque ni marca el aviso", () => {
  const e = entorno({ F_ST_COLGADO: "1", F_SIN_IMAGEN: "1", F_NO_AUTORIZADO: "1" });
  const inicio = Date.now();
  const r = e.correr([], "u\nTOK\n");
  assert.ok(Date.now() - inicio < 25_000);
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /docker-credential-secretservice/);
  assert.ok(!existsSync(join(e.env.HOME, ".config/elevate-cyber/.token-sin-cifrar")));
  assert.equal(e.leer("stdin").trim(), "TOK");
});

test("lanzador: un DOCKER_CONFIG del usuario sin credenciales guardadas no se borra ni se pisa", () => {
  const e = entorno({ F_REMOTO: "sha256:abc123" });
  const suyo = join(e.t, "mi-docker");
  mkdirSync(suyo);
  writeFileSync(join(suyo, "marca"), "x");
  e.env.DOCKER_CONFIG = suyo;
  e.env.DOCKER_CONTEXT = "mio";
  e.correr([], "s\n");
  assert.ok(existsSync(join(suyo, "marca")));
  assert.match(e.leer("dclog"), new RegExp(`^run-dc=${suyo} ctx=mio$`, "m"));
});

test("lanzador: con credenciales y un DOCKER_CONFIG del usuario, lo autenticado usa el temporal y el run vuelve al del usuario", () => {
  const e = entorno({ F_REMOTO: "sha256:abc123", F_GHCR: "u:T0KEN" });
  const suyo = join(e.t, "mi-docker");
  mkdirSync(suyo);
  writeFileSync(join(suyo, "marca"), "x");
  e.env.DOCKER_CONFIG = suyo;
  e.correr([], "s\n");
  assert.ok(existsSync(join(suyo, "marca")));
  const ops = dcs(e);
  assert.ok(ops.length > 0);
  for (const [, dc] of ops) assert.match(dc, /dc\./);
  assert.match(e.leer("dclog"), new RegExp(`^run-dc=${suyo} ctx=$`, "m"));
});

test("lanzador: un 401 suelto en una dirección no invalida el token guardado", () => {
  const e = entorno({ F_SIN_IMAGEN: "1", F_GHCR: "u:T0KEN", F_LOGIN_RED: "1" });
  writeFileSync(join(e.t, "bin", "docker"), readFileSync(join(e.t, "bin", "docker"), "utf8").replace("no such host", "dial tcp 10.0.0.401:443: i/o timeout"));
  const r = e.correr([], "x\ny\n");
  assert.doesNotMatch(r.stderr, /ya no sirve|Usuario de GitHub/);
  // "HTTP/1.1 401" y "status: 401" sí son un rechazo.
  for (const msg of ["Error: HTTP/1.1 401 sin sesion", "request failed, status: 401"]) {
    const f = entorno({ F_SIN_IMAGEN: "1", F_GHCR: "u:T0KEN", F_LOGIN_RED: "1" });
    writeFileSync(join(f.t, "bin", "docker"), readFileSync(join(f.t, "bin", "docker"), "utf8").replace("dial tcp: lookup ghcr.io: no such host", msg));
    assert.match(f.correr([], "x\ny\n").stderr, /ya no sirve/, msg);
  }
});

// Contenedor falso que queda corriendo: se lanza el lanzador sin esperarlo para poder matarlo.
const lanzarBloqueado = async (e: ReturnType<typeof entorno>, extra: Record<string, string> = {}) => {
  const { spawn } = await import("node:child_process");
  const hijo = spawn("sh", [LANZADOR], { cwd: e.proyecto, env: { ...e.env, F_BLOQUEA: "1", CYBER_NO_UPDATE: "1", ...extra }, stdio: "ignore" });
  const hasta = async (ok: () => boolean, ms: number) => { for (const fin = Date.now() + ms; Date.now() < fin && !ok(); ) await new Promise((r) => setTimeout(r, 100)); };
  await hasta(() => e.leer("bloqueado") !== "", 8000);
  return { hijo, hasta };
};
const nombreDe = (e: ReturnType<typeof entorno>) => [...e.leer("log").matchAll(/^exec .* (cyber-p-[0-9a-f]{12}) \/opt/gm)].at(-1)?.[1];
const ventanaDe = (e: ReturnType<typeof entorno>) => [...e.leer("log").matchAll(/^exec .*CYBER_VENTANA=([0-9a-f]{8}) /gm)].at(-1)?.[1];
const vigilantes = () => {
  return readdirSync("/proc").filter((p) => /^\d+$/.test(p)).filter((p) => { try { return readFileSync(`/proc/${p}/cmdline`, "utf8").includes("--vigilar"); } catch { return false; } });
};
const limpiar = (e: ReturnType<typeof entorno>) => { for (const p of e.leer("bloqueado").split("\n").filter(Boolean)) try { process.kill(Number(p)); } catch {} };

test("lanzador: un contenedor por carpeta (mismo nombre si se repite, otro si cambia), con una ventana nueva en cada exec", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" });
  assert.equal(e.correr().status, 0);
  assert.equal(e.correr().status, 0);
  const otra = join(e.t, "otro");
  mkdirSync(otra);
  assert.equal(spawnSync("sh", [LANZADOR], { cwd: otra, env: e.env, encoding: "utf8" }).status, 0);
  const nombres = [...e.leer("log").matchAll(/^run -d --rm --init --name (cyber-p-[0-9a-f]{12}) /gm)].map((m) => m[1]);
  // la segunda vez el contenedor ya corre: solo exec
  assert.deepEqual(nombres, [`cyber-p-${hash(e.proyecto)}`, `cyber-p-${hash(otra)}`]);
  assert.deepEqual([...e.leer("log").matchAll(/^exec .* (cyber-p-[0-9a-f]{12}) \/opt/gm)].map((m) => m[1]), [`cyber-p-${hash(e.proyecto)}`, `cyber-p-${hash(e.proyecto)}`, `cyber-p-${hash(otra)}`]);
  assert.notEqual(hash(e.proyecto), hash(otra));
  const ventanas = [...e.leer("log").matchAll(/CYBER_VENTANA=([0-9a-f]{8}) /g)].map((m) => m[1]);
  assert.equal(new Set(ventanas).size, 3);
});

test("lanzador: con el contenedor del proyecto ya corriendo solo hace exec; si el nombre se ganó en una carrera, entra igual con el código del exec", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" });
  e.env.F_CORRIENDO = `cyber-p-${hash(e.proyecto)}`;
  assert.equal(e.correr().status, 0);
  assert.doesNotMatch(e.leer("log"), /^run -d/m);
  assert.match(e.leer("log"), /^exec /m);
  const c = entorno({ CYBER_NO_UPDATE: "1", F_NOMBRE_USADO: "1", F_EXEC_CODIGO: "3" });
  c.env.F_CORRIENDO = `cyber-p-${hash(c.proyecto)}`;
  c.env.F_CORRIENDO_TRAS = "1";
  const r = c.correr();
  assert.equal(r.status, 3, r.stderr);
  assert.match(c.leer("log"), /^run -d .*daemon\nps .*\nexec /m);
  assert.doesNotMatch(r.stderr, /already in use/);
});

test("lanzador: si el contenedor del proyecto aparece corriendo recién en el 3er sondeo, la ventana espera y termina con exec", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_NOMBRE_USADO: "1", F_CORRIENDO_TRAS: "2" });
  e.env.F_CORRIENDO = `cyber-p-${hash(e.proyecto)}`;
  const r = e.correr();
  assert.equal(r.status, 0, r.stderr);
  assert.match(e.leer("log"), /^run -d .*daemon\n(ps .*\n){2}exec /m);
  assert.doesNotMatch(r.stderr, /no arrancó/);
});

test("lanzador: ante un error de puerto no hace rm -f si el contenedor del proyecto ya corre (es de otra ventana)", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_OCUPADO: "47615", F_CORRIENDO_TRAS: "1" });
  e.env.F_CORRIENDO = `cyber-p-${hash(e.proyecto)}`;
  const r = e.correr();
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(puertoDelRun(e), ["47615", "47616"]);
  assert.doesNotMatch(e.leer("log"), /^rm -f/m);
});

test("lanzador: el run de --chequeo no recibe CYBER_SECRETS_KEY", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" });
  e.correr();
  const chequeo = e.leer("log").split("\n").find((l) => l.endsWith(" --chequeo"))!;
  assert.doesNotMatch(chequeo, /CYBER_SECRETS_KEY/);
  assert.match(runsDeUsuario(e.leer("log"))[0]!, /-e CYBER_SECRETS_KEY/);
});

test("lanzador: si el contenedor corre con otra imagen avisa que cierren las otras ventanas y entra igual", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_IMAGEN_VIEJA: "1" });
  e.env.F_CORRIENDO = `cyber-p-${hash(e.proyecto)}`;
  const r = e.correr();
  assert.equal(r.status, 0);
  assert.match(r.stderr, /otra ventana de este proyecto con la versión anterior; cerralas para usar la nueva/);
  assert.match(e.leer("log"), /^exec /m);
});

for (const senal of ["SIGKILL", "SIGHUP"] as const) {
  test(`lanzador: si muere el lanzador (${senal}) el vigilante despide su ventana con despedir-ventana y no detiene el contenedor`, async () => {
    const e = entorno();
    const { hijo, hasta } = await lanzarBloqueado(e);
    const nombre = nombreDe(e);
    const ventana = ventanaDe(e);
    assert.ok(nombre && ventana, e.leer("log"));
    assert.equal(vigilantes().length > 0, true);
    hijo.kill(senal);
    const orden = `exec ${nombre} /opt/elevate-cyber/bin/cyber despedir-ventana ${ventana}`;
    await hasta(() => e.leer("log").includes(orden), 8000);
    limpiar(e);
    assert.match(e.leer("log"), new RegExp(`^${orden}$`, "m"));
    assert.doesNotMatch(e.leer("log"), /^stop /m);
    assert.doesNotMatch(e.leer("log") + e.leer("entorno"), /OROBAS/);
  });
}

test("lanzador: el vigilante no recibe la llave ni OROBAS_API_KEY ni por argv ni por entorno", async () => {
  const e = entorno({}, true);
  const { hijo } = await lanzarBloqueado(e, { OROBAS_API_KEY: "OROBAS-SECRETA" });
  const nombre = nombreDe(e)!;
  const v = vigilantes().find((p) => readFileSync(`/proc/${p}/cmdline`, "utf8").includes(nombre))!;
  assert.ok(v, "no encontré su vigilante");
  const mem = readFileSync(`/proc/${v}/environ`, "utf8") + readFileSync(`/proc/${v}/cmdline`, "utf8");
  hijo.kill("SIGKILL");
  limpiar(e);
  assert.doesNotMatch(mem, /OROBAS|CYBER_SECRETS_KEY/);
});

const abriendo = { F_INFO_FALLA: "1", CYBER_NO_UPDATE: "1", F_DESKTOP: "1" };

test("lanzador: cierra Docker Desktop al salir si lo abrió, la preferencia es sí y no hay otros contenedores", () => {
  const e = entorno(abriendo);
  const r = e.correr([], "s\n");
  assert.match(e.leer("log"), /^desktop stop$/m);
  assert.match(r.stderr, /Cerré Docker Desktop porque lo había abierto cyber \(desactivalo con: cyber --cerrar-docker no\)/);
  // sin docker desktop: Linux cae a systemctl --user, macOS a osascript
  const l = entorno({ ...abriendo, F_SIN_DSTOP: "1" });
  l.correr([], "s\n");
  assert.match(l.leer("log"), /^systemctl --user stop docker-desktop$/m);
  const m = entorno({ F_INFO_FALLA: "1", CYBER_NO_UPDATE: "1", F_SIN_DSTOP: "1" });
  m.darwin();
  m.correr([], "s\n");
  assert.match(m.leer("log"), /^osascript -e quit app "Docker"$/m);
});

test("lanzador: no cierra Docker si ya andaba, con preferencia no, con CYBER_CERRAR_DOCKER=0, con otro contenedor o con el servicio de sistema", () => {
  const nada = (e: ReturnType<typeof entorno>, intento = false) => {
    e.correr([], "s\n");
    assert.doesNotMatch(e.leer("log"), intento ? /osascript|systemctl --user stop/ : /desktop stop|osascript|systemctl --user stop/);
  };
  nada(entorno({ CYBER_NO_UPDATE: "1" }));
  let e = entorno(abriendo);
  mkdirSync(join(e.env.HOME, ".config/elevate-cyber"), { recursive: true });
  writeFileSync(join(e.env.HOME, ".config/elevate-cyber/lanzador.conf"), "cerrar_docker=no\n");
  nada(e);
  nada(entorno({ ...abriendo, CYBER_CERRAR_DOCKER: "0" }));
  nada(entorno({ F_INFO_FALLA: "1", CYBER_NO_UPDATE: "1", F_SIN_DSTOP: "1" }), true); // sudo systemctl start docker: no se detiene
  // el entorno gana sobre la preferencia guardada
  e = entorno({ ...abriendo, CYBER_CERRAR_DOCKER: "1" });
  mkdirSync(join(e.env.HOME, ".config/elevate-cyber"), { recursive: true });
  writeFileSync(join(e.env.HOME, ".config/elevate-cyber/lanzador.conf"), "cerrar_docker=no\n");
  e.correr([], "s\n");
  assert.match(e.leer("log"), /^desktop stop$/m);
});

test("lanzador: ABRI, ACTUALIZAR, LLAVERO_MAL y las demás del entorno no deciden nada (ni cerrar un Docker que ya andaba)", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_DESKTOP: "1", ABRI: "1", ACTUALIZAR: "1", LLAVERO_MAL: "1", REINTENTO: "1", ENT: "/dev/zero" });
  const r = e.correr([], "s\n");
  assert.equal(r.status, 0, r.stderr);
  assert.match(e.leer("log"), /^exec /m, "abre la ventana: ACTUALIZAR del entorno no lo deja en «sólo actualizar»");
  assert.doesNotMatch(e.leer("log"), /^pull /m);
  assert.doesNotMatch(e.leer("log"), /desktop stop|systemctl --user stop/, "Docker ya andaba: no lo cierra");
  assert.doesNotMatch(r.stderr, /El llavero no respondió|Cerré Docker Desktop/);
});

test("lanzador: el vigilante espera a que no quede ningún cyber-p-* para cerrar Docker Desktop", async () => {
  const e = entorno({ ...abriendo, F_OTRO: "1" });
  e.correr([], "s\n");
  await new Promise((r) => setTimeout(r, 4000));
  assert.doesNotMatch(e.leer("log"), /desktop stop/);
  assert.match(e.leer("log"), /^ps --filter name=cyber-p- -q$/m);
  writeFileSync(join(e.t, "libre"), "");
  // el vigilante sondea cada 30 s
  for (const fin = Date.now() + 40000; Date.now() < fin && !/desktop stop/.test(e.leer("log")); ) await new Promise((r) => setTimeout(r, 200));
  assert.match(e.leer("log"), /^desktop stop$/m);
});

test("lanzador: --cerrar-docker guarda la preferencia en lanzador.conf, sin valor muestra el estado y no necesita docker", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1" });
  const conf = join(e.env.HOME, ".config/elevate-cyber/lanzador.conf");
  assert.match(e.correr(["--cerrar-docker"]).stdout, /Cerrar Docker Desktop al salir.*sí/);
  const r = e.correr(["--cerrar-docker", "no"]);
  assert.equal(r.status, 0);
  assert.equal(readFileSync(conf, "utf8"), "cerrar_docker=no\n");
  assert.match(e.correr(["--cerrar-docker", "x"]).stdout, /Cerrar Docker Desktop al salir.*no/);
  assert.equal(statSync(join(e.env.HOME, ".config/elevate-cyber")).mode & 0o777, 0o700);
  assert.doesNotMatch(e.leer("log"), /./);
  e.correr(["--cerrar-docker", "si"]);
  assert.equal(readFileSync(conf, "utf8"), "cerrar_docker=si\n");
  assert.match(e.correr(["--cerrar-docker"]).stdout, /sí/);
  assert.match(spawnSync("/bin/sh", [LANZADOR, "--cerrar-docker", "no"], { env: { ...e.env, PATH: "/usr/bin:/bin" }, encoding: "utf8" }).stdout, /Guardado/);
});

test("lanzador: un llavero bloqueado al pedir la llave de cifrado no cuelga: corre sin llave y avisa", () => {
  const e = entorno({ CYBER_NO_UPDATE: "1", F_LLAVE_COLGADA: "1", F_LLAVE: "" });
  const inicio = Date.now();
  const r = e.correr();
  assert.ok(Date.now() - inicio < 25_000);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /llavero no respondió/);
  assert.match(e.leer("entorno"), /^KEY=$/m);
  assert.doesNotMatch(e.leer("llavero"), /^store .*account llave$/m, "tras un corte por tiempo no se crea ni guarda otra llave");
});
