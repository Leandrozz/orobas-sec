// cyber --actualizar del lanzador de Linux y macOS contra un servidor de releases falso: sólo se reemplaza con un
// release cuya firma verifica con la clave del lanzador y cuyo cyber-lanzador.sh tiene la suma firmada.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, copyFileSync, cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { BASICAS, borrar, carpetaPrueba, type Clave, ejecutable, firmar, hay, levantarServidor, marcarUltimo, nuevaClave, pathCon, publicar, repoFalso, sinTerminal, vacia } from "./releases-falsos.ts";

const skip = !hay("ssh-keygen") || !hay("curl") || !hay("git") ? "faltan ssh-keygen, curl o git" : false;
const IMAGEN = `ghcr.io/ejemplo/orobas@sha256:${"cd".repeat(32)}`;
let base = "";
let clave: Clave;
let otra: Clave;
let releases = "";

before(() => {
  if (skip) return;
  base = carpetaPrueba("actualizador");
  clave = nuevaClave(base, "clave");
  otra = nuevaClave(base, "otra");
  const repo = repoFalso(base, clave, IMAGEN);
  releases = join(base, "releases");
  mkdirSync(releases);
  publicar(repo, releases, "v1.0.0", clave);
  publicar(repo, releases, "v1.1.0", clave);
});
after(() => {
  if (base) borrar(base);
});

// docker falso: anota todo y dice que sí. Sin secret-tool en el PATH (no toca el llavero de quien corre las pruebas).
const DOCKER = '#!/bin/sh\necho "$*" >>"$T/log"\nexit 0\n';

let n = 0;
async function escenario(opciones: { ultimo?: string; instalado?: string; preparar?: (srv: string) => void } = {}) {
  const d = join(base, `e${++n}`);
  mkdirSync(d);
  const srv = join(d, "srv");
  cpSync(releases, srv, { recursive: true });
  marcarUltimo(srv, opciones.ultimo ?? "v1.1.0");
  opciones.preparar?.(srv);
  const servidor = await levantarServidor(srv);
  ejecutable(join(d, "falsos/docker"), DOCKER);
  const home = join(d, "home");
  const tmp = join(d, "tmp");
  mkdirSync(home);
  mkdirSync(tmp);
  const lanzador = join(d, "bin/cyber");
  mkdirSync(join(d, "bin"));
  copyFileSync(join(srv, opciones.instalado ?? "v1.0.0", "cyber-lanzador.sh"), lanzador);
  const original = readFileSync(lanzador, "utf8");
  const env = { PATH: `${join(d, "falsos")}:${pathCon(join(d, "sistema"), BASICAS)}`, HOME: home, TMPDIR: tmp, T: d, LANG: "es_AR.UTF-8", CYBER_RELEASES_URL: servidor.url };
  const actualizar = (...args: string[]) => {
    const [p, a] = sinTerminal("sh", [lanzador, "--actualizar", ...args]);
    return spawnSync(p, a, { encoding: "utf8", env, cwd: d });
  };
  const log = () => {
    try {
      return readFileSync(join(d, "log"), "utf8");
    } catch {
      return "";
    }
  };
  return { d, srv, servidor, lanzador, original, env, tmp, actualizar, log, actual: () => readFileSync(lanzador, "utf8") };
}

test("actualizador: con --si se reemplaza por el lanzador firmado del último release y el nuevo baja su imagen", { skip }, async () => {
  const e = await escenario();
  try {
    const r = e.actualizar("--si");
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Lanzador actualizado a v1\.1\.0\./);
    assert.equal(e.actual(), readFileSync(join(e.srv, "v1.1.0/cyber-lanzador.sh"), "utf8"));
    assert.match(e.actual(), /^VERSION_LANZADOR='v1\.1\.0'$/m);
    assert.match(e.log(), new RegExp(`^pull ${IMAGEN}$`, "m"));
    assert.ok(vacia(e.tmp), "no deja temporales");
    const otraVez = e.actualizar("--si");
    assert.match(otraVez.stdout, /El lanzador ya está al día \(v1\.1\.0\)/);
  } finally {
    e.servidor.cerrar();
  }
});

const fallas: [string, (srv: string) => void, RegExp][] = [
  ["una firma alterada", (srv) => writeFileSync(join(srv, "v1.1.0/SHA256SUMS.sig"), readFileSync(join(srv, "v1.1.0/SHA256SUMS.sig"), "utf8").replace(/^(.{20})./m, "$1Z")), /La firma del release v1\.1\.0 no es válida/],
  ["una firma de otra clave", (srv) => firmar(otra, join(srv, "v1.1.0/SHA256SUMS")), /La firma del release v1\.1\.0 no es válida/],
  ["la lista firmada de la versión anterior", (srv) => {
    for (const f of ["SHA256SUMS", "SHA256SUMS.sig"]) cpSync(join(srv, "v1.0.0", f), join(srv, "v1.1.0", f));
  }, /La firma del release v1\.1\.0 no es válida/],
  ["un lanzador que no coincide con la suma firmada", (srv) => appendFileSync(join(srv, "v1.1.0/cyber-lanzador.sh"), "echo agregado\n"), /no coincide con la suma firmada/],
  ["un release sin lanzador", (srv) => {
    const f = join(srv, "v1.1.0/SHA256SUMS");
    writeFileSync(f, readFileSync(f, "utf8").replace(/^.*cyber-lanzador.*\n/gm, ""));
    firmar(clave, f);
  }, /no trae el lanzador \(cyber-lanzador\.sh\)/],
];
for (const [nombre, preparar, mensaje] of fallas) {
  test(`actualizador: con ${nombre} no se reemplaza, no baja la imagen y sale con error`, { skip }, async () => {
    const e = await escenario({ preparar });
    try {
      const r = e.actualizar("--si");
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stderr, mensaje);
      assert.equal(e.actual(), e.original);
      assert.doesNotMatch(e.log(), /^pull /m);
      assert.ok(vacia(e.tmp));
    } finally {
      e.servidor.cerrar();
    }
  });
}

test("actualizador: sin terminal y sin --si no se reemplaza, pero baja la imagen", { skip }, async () => {
  const e = await escenario();
  try {
    const r = e.actualizar();
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stderr, /Sin terminal no reemplazo el lanzador/);
    assert.equal(e.actual(), e.original);
    assert.deepEqual(e.servidor.pedidos(), [], "ni siquiera consulta los releases");
    assert.match(e.log(), new RegExp(`^pull ${IMAGEN}$`, "m"));
  } finally {
    e.servidor.cerrar();
  }
});

test("actualizador: no baja de versión si el último release publicado es más viejo", { skip }, async () => {
  const e = await escenario({ ultimo: "v1.0.0", instalado: "v1.1.0" });
  try {
    const r = e.actualizar("--si");
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /más viejo que este lanzador; no bajo de versión: v1\.0\.0 < v1\.1\.0/);
    assert.equal(e.actual(), e.original);
  } finally {
    e.servidor.cerrar();
  }
});

const SCRIPT = spawnSync("sh", ["-c", "command -v script"], { encoding: "utf8" }).stdout.trim();
const hayScript = !!SCRIPT && spawnSync(SCRIPT, ["--version"]).status === 0;
test("actualizador: con terminal pregunta antes de reemplazarse; «n» lo deja como está", { skip: skip || (!hayScript && "falta script (util-linux)") }, async () => {
  const e = await escenario();
  try {
    // script(1) le da una terminal al lanzador; la respuesta entra por esa terminal.
    const conTerminal = (respuesta: string) => spawnSync(SCRIPT, ["-qec", `sh '${e.lanzador}' --actualizar`, "/dev/null"], { encoding: "utf8", env: e.env, cwd: e.d, input: respuesta, timeout: 60_000 });
    const no = conTerminal("n\n");
    assert.match(no.stdout, /¿Actualizo el lanzador de v1\.0\.0 a v1\.1\.0\? \[S\/n\]/);
    assert.equal(e.actual(), e.original);
    const si = conTerminal("s\n");
    assert.match(si.stdout, /Lanzador actualizado a v1\.1\.0\./);
    assert.match(e.actual(), /^VERSION_LANZADOR='v1\.1\.0'$/m);
  } finally {
    e.servidor.cerrar();
  }
});
