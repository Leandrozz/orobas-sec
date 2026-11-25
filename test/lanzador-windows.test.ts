import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const hash = (ruta: string) => createHash("sha256").update(ruta).digest("hex").slice(0, 12);

const hayPwsh = spawnSync("pwsh", ["-NoProfile", "-Command", "1"]).status === 0;
const skip = !hayPwsh && "pwsh no está en el PATH";
const ps1 = join(process.cwd(), "distro/lanzador/cyber.ps1");

// docker falso: anota cada invocación en args.log y responde según FAKE_*
const FAKE = `#!/bin/sh
{ printf '%s|' "$@"; echo; } >> "$FAKE_DIR/args.log"
case "$1" in
  ps) case " $* " in
    *" --format {{.Names}} "*) n=$(($(cat "$FAKE_DIR/pscount" 2>/dev/null || echo 0) + 1)); echo $n > "$FAKE_DIR/pscount"; { [ -z "$FAKE_CORRIENDO" ] || [ "$n" -le "\${FAKE_CORRIENDO_TRAS:-0}" ] || echo "$FAKE_CORRIENDO"; }; cat "$FAKE_DIR/creado" 2>/dev/null ;;
    *" --format "*) [ -z "$FAKE_PUERTOS" ] || printf '%s\\n' "$FAKE_PUERTOS" ;;
    *) m=$(($(cat "$FAKE_DIR/otrocount" 2>/dev/null || echo 0) + 1)); echo $m > "$FAKE_DIR/otrocount"; [ "$m" -gt "\${FAKE_OTRO:-0}" ] || echo abc ;; esac ;;
  inspect) if [ -n "$FAKE_IMAGEN_VIEJA" ]; then echo '["otra"]'; else echo '["x/y@sha256:aaa"]'; fi ;;
  exec)
    case " $* " in *" despedir-ventana "*) exit 0 ;; esac
    [ -z "$FAKE_MAL75" ] || exit 75
    if [ -n "$FAKE_CIERRE" ] && { [ "$FAKE_CIERRE" = siempre ] || [ ! -e "$FAKE_DIR/cerro" ]; }; then : > "$FAKE_DIR/cerro"; rm -f "$FAKE_DIR/creado"; exit 1; fi
    if [ -n "$FAKE_REABRIR" ] && [ ! -f "$FAKE_DIR/reabierto" ]; then
      touch "$FAKE_DIR/reabierto"; mkdir -p "$LOCALAPPDATA/elevate-cyber"; printf '%s\\t%s\\n' "$FAKE_REABRIR" abc > "$LOCALAPPDATA/elevate-cyber/reabrir.txt"; exit 75
    fi
    exit "\${FAKE_EXEC_CODIGO:-0}" ;;
  info) [ -z "$FAKE_INFO_SLEEP" ] || sleep "$FAKE_INFO_SLEEP"; [ -z "$FAKE_INFO_FAIL" ] ;;
  buildx) [ -n "$FAKE_BUILDX" ] && printf '{\\n  "digest": "sha256:%s",\\n  "manifests": [{"digest": "sha256:fff999"}]\\n}\\n' "$FAKE_BUILDX" || exit 1 ;;
  image) [ -z "$FAKE_SIN_IMAGEN" ] || exit 1; if [ -n "$FAKE_SIN_DIGEST" ]; then echo null; else echo '["x/y@sha256:aaa"]'; fi ;;
  manifest) sleep "\${FAKE_MANIFEST_SLEEP:-0}"; echo '{"Descriptor":{"digest":"sha256:'"\${FAKE_REMOTO:-aaa}"'"}}' ;;
  pull) if [ -n "$FAKE_UNAUTH" ] && [ ! -f "$FAKE_DIR/logueado" ]; then echo unauthorized; exit 1; fi ;;
  login) cat > "$FAKE_DIR/login-stdin" && touch "$FAKE_DIR/logueado" ;;
  run)
    for a; do [ "$a" = --chequeo ] && { [ -z "$FAKE_CHEQUEO_VIEJO" ] || { echo "TypeError [ERR_PARSE_ARGS_UNKNOWN_OPTION]: Unknown option '--chequeo'" >&2; exit 1; }; [ -n "$FAKE_SIN_MARCA" ] || echo compartido; exit 0; }; done
    for a; do case "$a" in 127.0.0.1:*) for o in $FAKE_OCUPADO; do case "$a" in *:$o:47615) echo "Bind for 127.0.0.1:$o failed: port is already allocated" >&2; exit 125 ;; esac; done ;; esac; done
    [ -z "$FAKE_NOMBRE_USADO" ] || { echo "docker: Error response from daemon: Conflict. The container name \\"/x\\" is already in use by container \\"abc\\". You have to remove (or rename) that container to be able to reuse that name." >&2; exit 125; }
    for a; do case "$a" in cyber-p-*) echo "$a" >> "$FAKE_DIR/creado" ;; esac; done ;;
esac
`;

function correr(opts: { env?: NodeJS.ProcessEnv; args?: string[]; previo?: string; input?: string; sinDocker?: boolean; wt?: boolean | "falla"; winget?: "ok" | "falla" | "sin-wt"; dir?: string; script?: string } = {}) {
  const dir = opts.dir ?? mkdtempSync(join(tmpdir(), "cyber-ps-"));
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  if (!opts.sinDocker) {
    writeFileSync(join(bin, "docker"), FAKE);
    chmodSync(join(bin, "docker"), 0o755);
  }
  const FAKE_WT = `#!/bin/sh\n{ printf '%s|' "$@"; echo; } >> "$FAKE_DIR/wt.log"\n`;
  if (opts.wt) {
    writeFileSync(join(bin, "wt.exe"), opts.wt === "falla" ? `${FAKE_WT}exit 1\n` : FAKE_WT);
    chmodSync(join(bin, "wt.exe"), 0o755);
  }
  if (opts.winget) {
    // con "ok" el winget falso «instala» wt.exe (el mismo falso de arriba)
    const crea = opts.winget === "ok" ? `printf '%s' '${FAKE_WT.replace(/'/g, "'\\''")}' > "$FAKE_DIR/bin/wt.exe"; chmod +x "$FAKE_DIR/bin/wt.exe"\n` : "";
    writeFileSync(join(bin, "winget"), `#!/bin/sh\n{ printf '%s|' "$@"; echo; } >> "$FAKE_DIR/winget.log"\n${crea}exit ${opts.winget === "falla" ? 1 : 0}\n`);
    chmodSync(join(bin, "winget"), 0o755);
  }
  if (opts.previo) {
    mkdirSync(join(dir, "local", "elevate-cyber"), { recursive: true });
    writeFileSync(join(dir, "local", "elevate-cyber", "reabrir.txt"), opts.previo);
  }
  const proyecto = join(dir, "Mis objetivos");
  mkdirSync(proyecto, { recursive: true });
  const sinDocker = process.env.PATH!.split(":").filter((p) => !existsSync(join(p, "docker"))).join(":");
  const r = spawnSync("pwsh", ["-NoProfile", "-File", opts.script ?? ps1, ...(opts.args ?? [])], {
    cwd: proyecto,
    input: opts.input ?? "",
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: opts.sinDocker ? sinDocker : `${bin}:${process.env.PATH}`,
      FAKE_DIR: dir,
      APPDATA: join(dir, "roaming"),
      LOCALAPPDATA: join(dir, "local"),
      HOME: dir,
      CYBER_NO_UPDATE: "1",
      WT_SESSION: "",
      TERM_PROGRAM: "",
      ConEmuANSI: "",
      SSH_CONNECTION: "",
      SSH_CLIENT: "",
      TERM: "",
      ...opts.env,
    },
  });
  const log = existsSync(join(dir, "args.log")) ? readFileSync(join(dir, "args.log"), "utf8").trim().split("\n") : [];
  const wt = existsSync(join(dir, "wt.log")) ? readFileSync(join(dir, "wt.log"), "utf8").trim().split("\n") : [];
  const winget = existsSync(join(dir, "winget.log")) ? readFileSync(join(dir, "winget.log"), "utf8").trim().split("\n") : [];
  return { r, log, dir, proyecto, wt, winget, runs: log.filter((l) => l.startsWith("run|") && !l.includes("|--chequeo|")), execs: log.filter((l) => l.startsWith("exec|") && !l.includes("|despedir-ventana|")) };
}

test("lanzador windows: docker run con el proyecto, sin --user, sin la llave en argv", { skip }, () => {
  const { r, runs, execs, log, proyecto, dir } = correr({ env: { WT_SESSION: "x", OROBAS_API_KEY: "secreto-orobas" } });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(runs.length, 1);
  assert.match(runs[0]!, new RegExp(`^run\\|-d\\|--rm\\|--init\\|--name\\|cyber-p-${hash(proyecto)}\\|`));
  assert.ok(runs[0]!.endsWith("|daemon|"), runs[0] ?? "");
  assert.ok(runs[0]!.includes("|-e|CYBER_COMPARTIDO=1|"));
  const a = runs[0]!.split("|");
  assert.ok(proyecto.includes(" "));
  assert.ok(a.includes(`${proyecto}:/proyecto`), runs[0]!); // la ruta con espacios llega como un solo argumento
  assert.ok(a.includes(`${join(dir, "roaming", "elevate-cyber")}:/home/node/.config/elevate-cyber`));
  assert.ok(a.includes(`${join(dir, "local", "elevate-cyber")}:/home/node/.local/share/elevate-cyber`));
  for (const n of ["CYBER_PROYECTO_HOST", "CYBER_DATOS_HOST", "CYBER_CREDENCIALES_HOST", "CYBER_SECRETS_KEY", "LANG", "LC_ALL", "OROBAS_API_KEY"]) {
    assert.equal(a[a.indexOf(n) - 1], "-e", n);
  }
  for (const n of ["TERM", "COLORTERM", "TERM_PROGRAM", "KITTY_WINDOW_ID", "WT_SESSION", "CYBER_STREAMER", "CYBER_STREAMER_OBS"]) assert.ok(!a.includes(n), `${n} es de cada ventana: va en el exec, no en el run -d`);
  for (const v of ["CYBER_STREAMER", "CYBER_STREAMER_HOSTS", "CYBER_STREAMER_PUBLICOS", "CYBER_STREAMER_USO", "CYBER_STREAMER_OBS"]) assert.ok(execs[0]!.split("|").includes(v));
  assert.ok(execs[0]!.split("|").includes("WT_SESSION") && execs[0]!.split("|").includes("TERM"), "el exec sí las lleva")
  assert.ok(!a.includes("--user"));
  assert.equal(a[a.indexOf("-p") + 1], "127.0.0.1:47615:47615");
  assert.equal(a[a.indexOf("CYBER_PUERTO_HOST=47615") - 1], "-e", "el puerto publicado en el host viaja al contenedor");
  assert.ok(!log.find((l) => l.includes("|--chequeo|"))!.split("|").includes("-p"), "--chequeo no publica puertos");
  assert.ok(!log.find((l) => l.includes("|--chequeo|"))!.includes("CYBER_PUERTO_HOST"), "--chequeo tampoco lo fija");
  const chequeo = log.find((l) => l.includes("|--chequeo|"))!;
  assert.ok(!chequeo.includes("CYBER_SECRETS_KEY") && !chequeo.includes("OROBAS_API_KEY"), "--chequeo no recibe ni la llave ni la clave de orobas");
  assert.equal(execs.length, 1);
  assert.match(execs[0]!, new RegExp(`^exec\\|-i\\|-e\\|CYBER_VENTANA=[0-9a-f]{8}\\|-e\\|LANG\\|.*\\|cyber-p-${hash(proyecto)}\\|/opt/elevate-cyber/bin/cyber\\|-C\\|/proyecto\\|$`));
  assert.ok(!runs[0]!.includes("CYBER_CONSOLE"), "con WT_SESSION no se pasa CYBER_CONSOLE");
  const llave = readFileSync(join(dir, "roaming", "elevate-cyber", "llave.dpapi"), "utf8").trim();
  assert.equal(Buffer.from(llave, "base64").length, 32);
  assert.ok(!r.stdout.includes(llave) && !runs.join().includes(llave) && !runs.join().includes("secreto-orobas"));
});

test("lanzador windows: sin WT_SESSION pasa CYBER_CONSOLE=conhost en el exec (no en el run -d) y sin OROBAS_API_KEY no la pasa", { skip }, () => {
  const { runs, execs } = correr({ env: { WT_SESSION: "", TERM_PROGRAM: "", ConEmuANSI: "", OROBAS_API_KEY: "" } });
  assert.ok(execs[0]!.includes("|-e|CYBER_CONSOLE=conhost|"));
  assert.ok(!runs[0]!.includes("CYBER_CONSOLE"));
  assert.ok(!runs[0]!.includes("OROBAS_API_KEY"));
});

test("lanzador windows: sin docker sale con 1 y muestra el enlace", { skip }, () => {
  const { r } = correr({ sinDocker: true });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /docker\.com\/products\/docker-desktop/);
});

test("lanzador windows: Docker apagado y respuesta n sale sin abrirlo", { skip }, () => {
  const { r, runs } = correr({ env: { FAKE_INFO_FAIL: "1" }, input: "n\n" });
  assert.equal(r.status, 1);
  assert.equal(runs.length, 0);
});

test("lanzador windows: digest distinto, n no baja y s baja; manifest lento no pregunta", { skip }, () => {
  const env = { CYBER_NO_UPDATE: "", FAKE_REMOTO: "bbb" };
  assert.ok(!correr({ env, input: "n\n" }).log.some((l) => l.startsWith("pull|")));
  assert.ok(correr({ env, input: "s\n" }).log.some((l) => l.startsWith("pull|")));
  const lento = correr({ env: { CYBER_NO_UPDATE: "", FAKE_MANIFEST_SLEEP: "18" } });
  assert.match(lento.r.stdout, /No pude buscar actualizaciones|Could not check for updates/);
  assert.equal(lento.runs.length, 1);
});

test("lanzador windows: sin imagen y unauthorized pide usuario y token y hace login por stdin", { skip }, () => {
  // Una imagen privada de ghcr.io: la pública nunca pide token.
  const { r, log, dir } = correr({ env: { CYBER_IMAGE: "ghcr.io/ejemplo/privada:latest", FAKE_SIN_IMAGEN: "1", FAKE_UNAUTH: "1" }, input: "usuario1\ntoken-secreto\n" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(log.includes("login|ghcr.io|-u|usuario1|--password-stdin|"), log.join("|") + r.stdout + r.stderr);
  assert.equal(readFileSync(join(dir, "login-stdin"), "utf8").trim(), "token-secreto");
  assert.ok(!log.join("\n").includes("token-secreto"));
});

test("lanzador windows: con la imagen pública muestra que baja la imagen y un rechazo de ghcr.io no pide usuario ni token", { skip }, () => {
  for (const imagen of ["ghcr.io/leandrozz/orobas-sec:latest", `ghcr.io/leandrozz/orobas-sec@sha256:${"b".repeat(64)}`]) {
    const { r, log } = correr({ env: { CYBER_IMAGE: imagen, FAKE_SIN_IMAGEN: "1", FAKE_UNAUTH: "1" }, input: "usuario1\ntoken-secreto\n" });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /Bajando la imagen|Pulling the image/);
    assert.match(r.stdout, /docker logout ghcr\.io/);
    assert.doesNotMatch(r.stdout, /read:packages/);
    assert.ok(log.includes(`pull|${imagen}|`), log.join("\n"));
    assert.ok(!log.some((l) => l.startsWith("login|")), "no hace login");
  }
});

test("lanzador windows: código 75 con reabrir.txt relanza con la otra ruta y -s", { skip }, () => {
  const otra = mkdtempSync(join(tmpdir(), "cyber-otra-"));
  const { runs, execs } = correr({ env: { FAKE_REABRIR: otra } });
  assert.equal(runs.length, 2);
  assert.ok(runs[1]!.split("|").includes(`${otra}:/proyecto`));
  assert.equal(execs.length, 2);
  assert.ok(execs[1]!.includes(`|cyber-p-${hash(otra)}|`));
  assert.ok(execs[1]!.endsWith("|-s|abc|"));
});

const puertos = (runs: string[]) => runs.map((l) => l.split("|").find((x) => x.startsWith("127.0.0.1:"))?.split(":")[1]);

test("lanzador windows: el puerto de la extensión saltea los que publican otros cyber-*", { skip }, () => {
  const { r, runs } = correr({ env: { FAKE_PUERTOS: "127.0.0.1:47615->47615/tcp\n:::47616->47615/tcp, [::1]:47617->47615/tcp" } });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual(puertos(runs), ["47618"]);
  assert.ok(runs[0]!.split("|").includes("CYBER_PUERTO_HOST=47618"), "CYBER_PUERTO_HOST sigue al puerto elegido");
});

test("lanzador windows: ante «port is already allocated» reintenta con el siguiente puerto sin mostrar el error", { skip }, () => {
  const { r, runs, log } = correr({ env: { FAKE_OCUPADO: "47615 47616" } });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual(puertos(runs), ["47615", "47616", "47617"]);
  assert.doesNotMatch(r.stdout + r.stderr, /already allocated/);
  assert.ok(log.some((l) => l.startsWith("rm|-f|cyber-p-")));
});

test("lanzador windows: ante un error de puerto no borra el contenedor si ya corre (es de otra ventana)", { skip }, () => {
  const proyecto = (d: string) => join(d, "Mis objetivos");
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-"));
  const { r, log } = correr({ dir, env: { FAKE_OCUPADO: "47615", FAKE_CORRIENDO: `cyber-p-${hash(proyecto(dir))}`, FAKE_CORRIENDO_TRAS: "1" } });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(!log.some((l) => l.startsWith("rm|")), log.join("\n"));
});

test("lanzador windows: --instalar copia cyber-lanzador.ps1 y cyber.cmd (que lo llama) a LOCALAPPDATA\\elevate-cyber\\bin", { skip }, () => {
  const { r, dir } = correr({ args: ["--instalar"], sinDocker: true });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(!existsSync(join(dir, "local", "elevate-cyber", "bin", "cyber.ps1")), "con ese nombre PowerShell lo preferiría al .cmd");
  for (const f of ["cyber-lanzador.ps1", "cyber.cmd"]) assert.ok(existsSync(join(dir, "local", "elevate-cyber", "bin", f)));
});

test("lanzador windows: --instalar alcanza con el .ps1 solo: escribe el cyber.cmd que llama a cyber-lanzador.ps1", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-"));
  const suelto = join(dir, "bajado", "cyber.ps1");
  mkdirSync(join(dir, "bajado"));
  copyFileSync(ps1, suelto);
  const { r } = correr({ dir, script: suelto, args: ["--instalar"], sinDocker: true });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const cmd = join(dir, "local", "elevate-cyber", "bin", "cyber.cmd");
  assert.match(readFileSync(cmd, "utf8"), /cyber-lanzador\.ps1/);
  assert.ok(existsSync(join(dir, "local", "elevate-cyber", "bin", "cyber-lanzador.ps1")));
});

test("lanzador windows: --instalar avisa si un perfil de PowerShell define su propio cyber", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-"));
  mkdirSync(join(dir, "WindowsPowerShell"));
  writeFileSync(join(dir, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"), 'function cyber { docker run -it --rm -v "${PWD}:/proyecto" ghcr.io/ejemplo/vieja @args }\n');
  const { r } = correr({ dir, args: ["--instalar"], sinDocker: true });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /define su propio «cyber»|defines its own "cyber"/);
  const limpio = correr({ args: ["--instalar"], sinDocker: true });
  assert.doesNotMatch(limpio.r.stdout, /define su propio|defines its own/);
});

test("lanzador windows: --actualizar sin consola no se reemplaza solo y nunca baja de main", () => {
  const f = readFileSync(ps1, "utf8");
  assert.doesNotMatch(f, /raw\.githubusercontent\.com|\/main\//);
  assert.match(f, /if \(-not \$conSi -and \[Console\]::IsInputRedirected\) \{/);
  assert.match(f, /else \{ 'https:\/\/github\.com\/Leandrozz\/orobas-sec\/releases' \}/);
});

test("lanzador windows: --actualizar baja la imagen sin preguntar", { skip }, () => {
  const { r, log } = correr({ args: ["--actualizar"] });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(log.some((l) => l.startsWith("pull|")));
});

test("lanzador windows: un reabrir.txt viejo se borra antes de correr", { skip }, () => {
  const { r, runs } = correr({ env: { FAKE_MAL75: "1" }, previo: "/viejo\tzzz\n" });
  assert.equal(r.status, 75);
  assert.equal(runs.length, 1);
});

test("lanzador windows: una imagen local sin digest no pregunta ni baja", { skip }, () => {
  const { r, log, runs } = correr({ env: { CYBER_NO_UPDATE: "", FAKE_SIN_DIGEST: "1", LANG: "" }, input: "s\n" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(!log.some((l) => l.startsWith("pull|") || l.startsWith("manifest|")));
  assert.equal(runs.length, 1);
});

test("lanzador windows: código 75 sin reabrir.txt válido sale con 75 y un mensaje", { skip }, () => {
  const { r, runs } = correr({ env: { FAKE_MAL75: "1" } });
  assert.equal(r.status, 75);
  assert.equal(runs.length, 1);
});

test("lanzador windows: una imagen vieja que no conoce --chequeo da un mensaje claro y sale con 1", { skip }, () => {
  const { r, runs } = correr({ env: { FAKE_CHEQUEO_VIEJO: "1" } });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /imagen local es vieja|too old/);
  assert.doesNotMatch(r.stdout + r.stderr, /ERR_PARSE_ARGS/);
  assert.equal(runs.length, 0);
});

test("lanzador windows: una imagen que entiende --chequeo pero no imprime «compartido» se trata como vieja", { skip }, () => {
  const { r, runs } = correr({ env: { FAKE_SIN_MARCA: "1" } });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /imagen local es vieja.*cyber --actualizar|too old for this launcher: run cyber --actualizar/);
  assert.equal(runs.length, 0);
});

test("lanzador windows: si el exec falla porque el contenedor se cerró, lo recrea una sola vez y vuelve a entrar", { skip }, () => {
  const e = correr({ env: { FAKE_CIERRE: "1" } });
  assert.equal(e.r.status, 0, e.r.stdout + e.r.stderr);
  assert.equal(e.runs.length, 2);
  assert.equal(e.execs.length, 2);
  // si el contenedor se vuelve a cerrar no insiste: un solo reintento
  const siempre = correr({ env: { FAKE_CIERRE: "siempre" } });
  assert.equal(siempre.r.status, 1);
  assert.equal(siempre.runs.length, 2);
});

test("lanzador windows: el digest de buildx coincide con RepoDigests y no pregunta; sin buildx cae al Descriptor", { skip }, () => {
  const con = correr({ env: { CYBER_NO_UPDATE: "", FAKE_BUILDX: "aaa", FAKE_REMOTO: "bbb" }, input: "n\n" });
  assert.doesNotMatch(con.r.stdout, /imagen nueva|new image|No pude buscar|Could not check/);
  const otro = correr({ env: { CYBER_NO_UPDATE: "", FAKE_BUILDX: "ccc" }, input: "n\n" });
  assert.match(otro.r.stdout, /imagen nueva|new image/);
  const sin = correr({ env: { CYBER_NO_UPDATE: "", FAKE_REMOTO: "aaa" }, input: "n\n" });
  assert.doesNotMatch(sin.r.stdout, /imagen nueva|new image|No pude buscar|Could not check/);
});

test("lanzador windows: docker info colgado se corta a los 10 s", { skip }, () => {
  const inicio = Date.now();
  const { r } = correr({ env: { FAKE_INFO_SLEEP: "30" }, input: "n\n" });
  assert.ok(Date.now() - inicio < 25_000);
  assert.equal(r.status, 1);
});

test("lanzador windows: un contenedor por carpeta (mismo nombre si se repite, otro si cambia) y una ventana nueva en cada exec", { skip }, () => {
  const a = correr();
  const b = correr({ dir: a.dir });
  const c = correr();
  assert.equal(b.runs.length, 1, "la segunda vez el contenedor ya corre: solo exec");
  assert.equal(b.execs.length, 2);
  const nombre = (l: string) => l.split("|").find((x) => x.startsWith("cyber-p-"));
  assert.equal(nombre(b.execs[0]!), nombre(b.execs[1]!));
  assert.notEqual(nombre(a.execs[0]!), nombre(c.execs[0]!));
  const ventana = (l: string) => l.split("|").find((x) => x.startsWith("CYBER_VENTANA="));
  assert.notEqual(ventana(b.execs[0]!), ventana(b.execs[1]!));
});

test("lanzador windows: el nombre se calcula sobre la ruta en minúsculas, sin barra final y en UTF-8", { skip }, () => {
  const fn = readFileSync(ps1, "utf8").match(/function NombreProyecto[\s\S]*?\n\}\n/)![0];
  const nombre = (ruta: string) => spawnSync("pwsh", ["-NoProfile", "-Command", `$EsWin = $true; ${fn}; NombreProyecto '${ruta}'; $script:Nombre`], { encoding: "utf8" }).stdout.trim();
  assert.equal(nombre("C:\\PROYÉCTOS\\Ñandú\\"), `cyber-p-${hash("c:\\proyéctos\\ñandú")}`);
  assert.equal(nombre("c:\\proyéctos\\ñandú"), nombre("C:\\PROYÉCTOS\\Ñandú\\"));
});

test("lanzador windows: si el nombre ya existe (otra ventana ganó la carrera) espera, entra con exec y devuelve su código", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-"));
  const nombre = `cyber-p-${hash(join(dir, "Mis objetivos"))}`;
  const { r, log, execs, runs } = correr({ dir, env: { FAKE_NOMBRE_USADO: "1", FAKE_EXEC_CODIGO: "3", FAKE_CORRIENDO: nombre, FAKE_CORRIENDO_TRAS: "2" } });
  assert.equal(r.status, 3, r.stdout + r.stderr);
  assert.equal(runs.length, 1);
  assert.equal(execs.length, 1);
  assert.doesNotMatch(r.stdout + r.stderr, /already in use/);
  assert.ok(log.filter((l) => l.startsWith("ps|")).length >= 3, "esperó hasta que corriera");
});

test("lanzador windows: si el contenedor nunca arranca avisa y sale con 1 sin hacer exec", { skip }, () => {
  const { r, execs } = correr({ env: { FAKE_NOMBRE_USADO: "1" } });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /no arrancó|did not start/);
  assert.equal(execs.length, 0);
});

test("lanzador windows: con el contenedor de otra imagen avisa que cierren las otras ventanas y entra igual", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-"));
  const { r, execs, runs } = correr({ dir, env: { FAKE_IMAGEN_VIEJA: "1", FAKE_CORRIENDO: `cyber-p-${hash(join(dir, "Mis objetivos"))}` } });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /otra ventana de este proyecto con la versión anterior; cerralas para usar la nueva|Another window of this project runs the previous version/);
  assert.equal(runs.length, 0);
  assert.equal(execs.length, 1);
});

test("lanzador windows: cyber.cmd llama a cyber-lanzador.ps1 (o a cyber.ps1 si no está instalado) y el .ps1 conserva el BOM", () => {
  const cmd = readFileSync(join(process.cwd(), "distro/lanzador/cyber.cmd"), "utf8");
  assert.match(cmd, /cyber-lanzador\.ps1/);
  assert.match(cmd, /-File "%L%" %\*/);
  assert.deepEqual([...readFileSync(ps1).subarray(0, 3)], [0xef, 0xbb, 0xbf]);
});

test("lanzador windows: --cerrar-docker conserva las otras claves de lanzador.conf (instalar=)", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-conf-"));
  mkdirSync(join(dir, "roaming", "elevate-cyber"), { recursive: true });
  const conf = join(dir, "roaming", "elevate-cyber", "lanzador.conf");
  writeFileSync(conf, "instalar=no\n");
  const { r } = correr({ args: ["--cerrar-docker", "no"], sinDocker: true, env: { APPDATA: join(dir, "roaming") } });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(readFileSync(conf, "utf8").trim().split(/\r?\n/).sort().join(","), "cerrar_docker=no,instalar=no");
});

test("lanzador windows: Instalar no se copia sobre sí mismo, borra cyber.ps1 viejo solo con el cyber.cmd nuevo y la pregunta excluye los comandos especiales", () => {
  const f = readFileSync(ps1, "utf8");
  assert.match(f, /if \(\$PSCommandPath -ne \$nuevoPs1\) \{ Copy-Item/);
  assert.match(f, /EscribirCmd \$nuevoCmd/);
  assert.match(f, /Get-Content \$nuevoCmd -Raw\) -match 'cyber-lanzador/);
  assert.match(f, /function EscribirCmd\(\$ruta\) \{[^}]*cyber-lanzador\.ps1[^}]*WriteAllText\(\$ruta/);
  assert.match(f, /function ActualizarCmd[\s\S]*?EscribirCmd \$viejo/);
  // el lanzador nuevo se baja a un temporal, se verifica (firma, suma y sintaxis) y recién ahí pisa este, con Move-Item
  assert.match(f, /VerificarLista \$dir \$nuevo[\s\S]*?SumaDe \$tmp\) -ne \$esperada[\s\S]*?ParseFile\(\$tmp[\s\S]*?Copy-Item \$tmp \$destino[\s\S]*?Move-Item \$destino \$PSCommandPath/);
  assert.doesNotMatch(f, /-OutFile \$PSCommandPath/);
  assert.match(f, /-in '--actualizar', '--actualizar-imagen', '--resumen', '--vigilar', '--cerrar-docker', '--instalar'/);
});

test("lanzador windows: el vigilante se lanza con -ExecutionPolicy Bypass", () => {
  const fuente = readFileSync(ps1, "utf8");
  assert.match(fuente, /@\('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File'/);
});

test("lanzador windows: el vigilante despide su ventana (no detiene el contenedor) y cierra Docker Desktop solo si corresponde, esperando a que no quede ningún cyber-p-*", { skip }, () => {
  const vigilar = (abri: string, env: Record<string, string> = {}, conf?: string) => {
    const dir = mkdtempSync(join(tmpdir(), "cyber-ps-conf-"));
    if (conf) {
      mkdirSync(join(dir, "roaming", "elevate-cyber"), { recursive: true });
      writeFileSync(join(dir, "roaming", "elevate-cyber", "lanzador.conf"), conf);
    }
    return correr({ args: ["--vigilar", "99999999", "cyber-p-abc123456789", "1a2b3c4d", abri], env: { ...(conf ? { APPDATA: join(dir, "roaming") } : {}), ...env } }).log;
  };
  const cierra = (log: string[]) => log.some((l) => l.startsWith("desktop|stop|"));
  const log = vigilar("1");
  assert.ok(log.includes("exec|cyber-p-abc123456789|/opt/elevate-cyber/bin/cyber|despedir-ventana|1a2b3c4d|"), log.join("\n"));
  assert.ok(!log.some((l) => l.startsWith("stop|")), "nunca docker stop");
  assert.ok(log.includes("ps|--filter|name=cyber-p-|-q|"));
  assert.ok(cierra(log));
  const sinAbrir = vigilar("0");
  assert.ok(!cierra(sinAbrir), "no lo abrió el lanzador");
  assert.ok(sinAbrir.some((l) => l.includes("|despedir-ventana|")) && !sinAbrir.some((l) => l.startsWith("ps|")));
  const espera = vigilar("1", { FAKE_OTRO: "1" }); // un cyber-p-* corre en la primera consulta y ya no en la siguiente
  assert.ok(espera.filter((l) => l === "ps|--filter|name=cyber-p-|-q|").length >= 2, espera.join("\n"));
  assert.ok(cierra(espera));
  assert.ok(!cierra(vigilar("1", { CYBER_CERRAR_DOCKER: "0" })));
  assert.ok(!cierra(vigilar("1", {}, "cerrar_docker=no\n")));
  assert.ok(cierra(vigilar("1", { CYBER_CERRAR_DOCKER: "1" }, "cerrar_docker=no\n")), "el entorno gana");
});

test("lanzador windows: --cerrar-docker guarda la preferencia en lanzador.conf y sin valor muestra el estado", { skip }, () => {
  const { r, dir } = correr({ args: ["--cerrar-docker", "no"], sinDocker: true });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(readFileSync(join(dir, "roaming", "elevate-cyber", "lanzador.conf"), "utf8").trim(), "cerrar_docker=no");
  const estado = correr({ args: ["--cerrar-docker"], sinDocker: true });
  assert.match(estado.r.stdout, /Cerrar Docker Desktop al salir.*: sí|Close Docker Desktop on exit.*: yes/);
});

test("lanzador windows: código 75 hacia una carpeta que no existe avisa y sale con 75", { skip }, () => {
  const { r, runs } = correr({ env: { FAKE_REABRIR: "/no/existe/xyz" } });
  assert.equal(r.status, 75);
  assert.equal(runs.length, 1);
  assert.match(r.stdout, /\/no\/existe\/xyz/);
});

test("lanzador windows: con la entrada redirigida usa -i, no -it, y pasa --add-host", { skip }, () => {
  const { runs, execs } = correr();
  const a = execs[0]!.split("|");
  assert.ok(a.includes("-i") && !a.includes("-it"));
  assert.ok(runs[0]!.split("|").includes("--add-host=host.docker.internal:host-gateway"));
});

test("lanzador windows: TERM_PROGRAM o ConEmuANSI=ON evitan CYBER_CONSOLE=conhost", { skip }, () => {
  assert.ok(!correr({ env: { WT_SESSION: "", TERM_PROGRAM: "WezTerm" } }).execs[0]!.includes("CYBER_CONSOLE=conhost"));
  assert.ok(!correr({ env: { WT_SESSION: "", TERM_PROGRAM: "", ConEmuANSI: "ON" } }).execs[0]!.includes("CYBER_CONSOLE=conhost"));
});

test("lanzador windows: al salir no deja la llave ni CYBER_PROYECTO_HOST en el entorno de la sesión", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-"));
  mkdirSync(join(dir, "bin"));
  writeFileSync(join(dir, "bin", "docker"), FAKE);
  chmodSync(join(dir, "bin", "docker"), 0o755);
  const r = spawnSync("pwsh", ["-NoProfile", "-Command", `& '${ps1}'; "K=[$env:CYBER_SECRETS_KEY] P=[$env:CYBER_PROYECTO_HOST] L=[$env:LANG]"`], {
    cwd: dir, input: "", encoding: "utf8",
    env: { ...process.env, PATH: `${join(dir, "bin")}:${process.env.PATH}`, FAKE_DIR: dir, APPDATA: join(dir, "r"), LOCALAPPDATA: join(dir, "l"), CYBER_NO_UPDATE: "1", LANG: "" },
  });
  assert.match(r.stdout, /K=\[\] P=\[\] L=\[\]/);
});

test("lanzador windows: un error terminante después de poner la llave tampoco deja el entorno sucio", { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-ps-"));
  mkdirSync(join(dir, "bin"));
  writeFileSync(join(dir, "bin", "docker"), FAKE);
  chmodSync(join(dir, "bin", "docker"), 0o755);
  // una función docker que revienta solo en «run» (el chequeo): el error corta el script con la llave ya puesta
  const cmd = `function docker { if ($args[0] -eq 'run') { throw 'boom' } else { & (Get-Command docker -CommandType Application) @args } }; try { & '${ps1}' } catch {}; "K=[$env:CYBER_SECRETS_KEY] P=[$env:CYBER_PROYECTO_HOST]"`;
  const r = spawnSync("pwsh", ["-NoProfile", "-Command", cmd], {
    cwd: dir, input: "", encoding: "utf8",
    env: { ...process.env, PATH: `${join(dir, "bin")}:${process.env.PATH}`, FAKE_DIR: dir, APPDATA: join(dir, "r"), LOCALAPPDATA: join(dir, "l"), CYBER_NO_UPDATE: "1" },
  });
  assert.match(r.stdout, /K=\[\] P=\[\]/);
});

test("lanzador windows: en conhost con wt.exe relanza en Windows Terminal y no corre docker", { skip }, () => {
  const { r, wt, runs, proyecto } = correr({ wt: true, env: { CYBER_PRUEBA_WT: "19041" }, args: ["-c"] });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(wt.length, 1);
  assert.ok(wt[0]!.startsWith(`-d|${proyecto}|powershell|-NoProfile|-ExecutionPolicy|Bypass|-File|`), wt[0] ?? "");
  assert.ok(wt[0]!.endsWith("|-c|"), wt[0] ?? "");
  assert.equal(runs.length, 0);
  assert.match(r.stdout, /Windows Terminal/);
});

test("lanzador windows: con WT_SESSION, sin CYBER_PRUEBA_WT o con --actualizar no relanza", { skip }, () => {
  const a = correr({ wt: true, env: { WT_SESSION: "x", CYBER_PRUEBA_WT: "19041" } });
  const b = correr({ wt: true, env: {} });
  const c = correr({ wt: true, env: { CYBER_PRUEBA_WT: "19041" }, args: ["--actualizar"] });
  for (const x of [a, b, c]) assert.equal(x.wt.length, 0);
  assert.equal(a.runs.length, 1);
  assert.equal(b.runs.length, 1);
});

test("lanzador windows: los ; de los argumentos llegan escapados a wt", { skip }, () => {
  const { wt } = correr({ wt: true, env: { CYBER_PRUEBA_WT: "19041" }, args: ["-m", "a;b"] });
  assert.ok(wt[0]!.includes("|a\\;b|"), wt[0] ?? "");
});

const W = { CYBER_PRUEBA_WT: "19041" };

test("lanzador windows: «d» guarda windows_terminal=no y la próxima vez no pregunta", { skip }, () => {
  const a = correr({ env: W, input: "d\n" });
  assert.match(readFileSync(join(a.dir, "roaming", "elevate-cyber", "lanzador.conf"), "utf8"), /windows_terminal=no/);
  assert.equal(a.runs.length, 1);
  const b = correr({ dir: a.dir, env: W, winget: "ok", input: "" });
  assert.doesNotMatch(b.r.stdout, /Windows Terminal/);
  assert.deepEqual(b.winget, []);
});

test("lanzador windows: «n» no instala ni guarda nada y sigue", { skip }, () => {
  const { r, dir, winget, runs } = correr({ env: W, winget: "ok", input: "n\n" });
  assert.equal(winget.length, 0);
  assert.match(r.stdout, /Windows Terminal/);
  const conf = join(dir, "roaming", "elevate-cyber", "lanzador.conf");
  assert.ok(!existsSync(conf) || !/windows_terminal/.test(readFileSync(conf, "utf8")));
  assert.equal(runs.length, 1);
});

test("lanzador windows: Windows 10 anterior a 2004 no pregunta", { skip }, () => {
  const { r, winget } = correr({ env: { CYBER_PRUEBA_WT: "18363" }, winget: "ok", input: "s\n" });
  assert.doesNotMatch(r.stdout, /Windows Terminal/);
  assert.equal(winget.length, 0);
});

test("lanzador windows: «s» con winget instala y relanza en Windows Terminal", { skip }, () => {
  const { winget, wt, runs } = correr({ env: W, winget: "ok", input: "s\n" });
  assert.equal(winget[0], "install|--id|Microsoft.WindowsTerminal|-e|--accept-package-agreements|--accept-source-agreements|");
  assert.equal(wt.length, 1);
  assert.equal(runs.length, 0);
});

test("lanzador windows: si winget falla avisa y sigue en conhost", { skip }, () => {
  const { r, runs, execs } = correr({ env: W, winget: "falla", input: "s\n" });
  assert.match(r.stdout, /No pude instalar Windows Terminal|Could not install Windows Terminal/);
  assert.equal(runs.length, 1);
  assert.ok(execs[0]!.includes("CYBER_CONSOLE=conhost"));
});

test("lanzador windows: sin winget manda a la Store y sigue", { skip }, () => {
  const { r, runs } = correr({ env: W, input: "s\n" });
  assert.match(r.stdout, /Store|aka\.ms\/terminal/);
  assert.equal(runs.length, 1);
});

test("lanzador windows: comandos, -p, --continuar, -h y salida redirigida no relanzan ni preguntan", { skip }, () => {
  for (const args of [["jobs"], ["findings"], ["-p", "x"], ["--continuar"], ["--detach"], ["--help"], ["-s", "abc", "informe"]]) {
    const x = correr({ wt: true, env: W, args });
    assert.equal(x.wt.length, 0, args.join(" "));
    assert.equal(x.runs.length, 1, args.join(" "));
    const y = correr({ env: W, winget: "ok", input: "s\n", args });
    assert.equal(y.winget.length, 0, args.join(" "));
    assert.doesNotMatch(y.r.stdout, /Windows Terminal/, args.join(" "));
  }
});

test("lanzador windows: los flags de la TUI con valor (-s, -m) sí relanzan", { skip }, () => {
  for (const args of [["-s", "abc"], ["-m", "x", "-c"], ["-c", "-m", "x"], ["-c", "-s", "abc"], ["--streamer", "--obs", "vivo.txt"]]) assert.equal(correr({ wt: true, env: W, args }).wt.length, 1, args.join(" "));
});

test("lanzador windows: si wt.exe falla avisa y sigue en conhost con docker", { skip }, () => {
  const { r, runs, execs } = correr({ wt: "falla", env: W });
  assert.match(r.stdout, /No pude abrir Windows Terminal|Could not open Windows Terminal/);
  assert.equal(runs.length, 1);
  assert.ok(execs[0]!.includes("CYBER_CONSOLE=conhost"));
});

test("lanzador windows: por SSH o con TERM definido no relanza y no es conhost", { skip }, () => {
  const entornos: Record<string, string>[] = [{ SSH_CONNECTION: "1 2 3 4" }, { SSH_CLIENT: "1 2 3" }, { TERM: "xterm-256color" }];
  for (const env of entornos) {
    const x = correr({ wt: true, env: { ...W, ...env } });
    assert.equal(x.wt.length, 0, JSON.stringify(env));
    assert.equal(x.runs.length, 1);
    assert.ok(!x.execs[0]!.includes("CYBER_CONSOLE=conhost"), x.execs[0] ?? "");
  }
});

test("lanzador windows: «dale» no apaga la pregunta para siempre", { skip }, () => {
  const { dir } = correr({ env: W, input: "dale\n" });
  const conf = join(dir, "roaming", "elevate-cyber", "lanzador.conf");
  assert.ok(!existsSync(conf) || !/windows_terminal/.test(readFileSync(conf, "utf8")));
});

test("lanzador windows: Enter vacío es sí: instala y relanza", { skip }, () => {
  const { winget, wt, runs } = correr({ env: W, winget: "ok", input: "\n" });
  assert.equal(winget.length, 1);
  assert.equal(wt.length, 1);
  assert.equal(runs.length, 0);
});

test("lanzador windows: winget ok pero sin wt.exe todavía dice que quedó instalado, no que falló", { skip }, () => {
  const { r, wt, runs } = correr({ env: W, winget: "sin-wt", input: "s\n" });
  assert.match(r.stdout, /quedó instalado|is installed/);
  assert.doesNotMatch(r.stdout, /No pude instalar|Could not install/);
  assert.equal(wt.length, 0);
  assert.equal(runs.length, 1);
});
