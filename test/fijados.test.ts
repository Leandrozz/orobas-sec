// Lo que la imagen baja de terceros: distro/fijados.txt (formato y contenido), distro/bajar-fijado.sh (frena si la
// suma no coincide) y la propuesta de versiones nuevas de scripts/fijados.ts contra un servidor local.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { test } from "node:test";
import { aplicar, leerFijados, proponer, revisar } from "../scripts/fijados.ts";
import { borrar, carpetaPrueba, ejecutable } from "./releases-falsos.ts";

const FIJADOS = readFileSync("distro/fijados.txt", "utf8");
const DOCKERFILE = readFileSync("distro/Dockerfile", "utf8");
const sha = (texto: string | Buffer) => createHash("sha256").update(texto).digest("hex");

test("fijados: distro/fijados.txt está bien formado y cada herramienta tiene amd64 y arm64 (o all), https y SHA-256", () => {
  const f = leerFijados(FIJADOS);
  assert.deepEqual(revisar(f), []);
  assert.ok(f.fuentes.size >= 13);
  for (const a of f.artefactos) assert.doesNotMatch(a.sha256, /^0+$/, `${a.nombre} ${a.arq} sin suma real`);
  // Cada herramienta contrasta con al menos una fuente del autor o de GitHub.
  for (const fuente of f.fuentes.values()) assert.ok(fuente.sumas.length > 0, fuente.nombre);
});

test("fijados: el Dockerfile baja todo por bajar-fijado.sh, con la base fijada por digest y sin «latest»", () => {
  const f = leerFijados(FIJADOS);
  assert.match(DOCKERFILE, /^FROM node:[\d.]+-bookworm-slim@sha256:[0-9a-f]{64}$/m);
  assert.doesNotMatch(DOCKERFILE, /releases\/latest|latest\(\)|stable\.txt|pipx install|npm install /);
  assert.match(DOCKERFILE, /COPY distro\/fijados\.txt distro\/bajar-fijado\.sh \/opt\/fijados\//);
  for (const nombre of f.fuentes.keys()) {
    const enBucle = new RegExp(`for n in [^;]*\\b${nombre}\\b[^;]*; do f=\\$\\(\\$b \\$n\\)`).test(DOCKERFILE);
    assert.ok(enBucle || DOCKERFILE.includes(`f=$($b ${nombre})`), `el Dockerfile no baja ${nombre} con bajar-fijado.sh`);
  }
  // curl sólo en apt (ca-certificates curl …): ninguna descarga directa.
  assert.doesNotMatch(DOCKERFILE.replace(/apt-get install[^\n]*/g, ""), /\bcurl\b/);
  assert.ok(statSync("distro/bajar-fijado.sh").mode & 0o100);
});

test("fijados: semgrep y Playwright van con cada paquete fijado por suma", () => {
  const req = readFileSync("distro/semgrep-requisitos.txt", "utf8");
  const paquetes = req.split("\n").filter((l) => /^[A-Za-z0-9_.-]+==/.test(l));
  assert.ok(paquetes.some((l) => /^semgrep==\d+\.\d+\.\d+ \\$/.test(l)));
  for (const bloque of req.split(/\n(?=[A-Za-z0-9_.-]+==)/).filter((b) => /^[A-Za-z0-9_.-]+==/.test(b))) {
    assert.match(bloque, /--hash=sha256:[0-9a-f]{64}/, bloque.split("\n")[0] ?? bloque);
  }
  assert.match(DOCKERFILE, /pip install [^\n]*--require-hashes --no-deps --only-binary=:all: -r \/opt\/fijados\/semgrep-requisitos\.txt/);
  const lock = JSON.parse(readFileSync("distro/navegador/package-lock.json", "utf8")) as { packages: Record<string, { version?: string; integrity?: string }> };
  assert.equal(lock.packages["node_modules/playwright"]?.version, "1.64.0");
  for (const [ruta, p] of Object.entries(lock.packages)) if (ruta) assert.match(p.integrity ?? "", /^sha512-/, ruta);
  assert.match(DOCKERFILE, /npm ci --ignore-scripts[^\n]*\n[^\n]*playwright\/index\.mjs/);
});

test("fijados: leer y revisar marcan cada error con su línea", () => {
  assert.throws(() => leerFijados("x 1.0 amd64 abc\n"), /fijados\.txt:1: se esperan 5 campos/);
  assert.throws(() => leerFijados("@ x origen=url:https://a\n"), /fijados\.txt:1: se espera «@ NOMBRE origen=… sumas=…»/);
  assert.throws(() => leerFijados("@ x origen=a sumas=github\n@ x origen=a sumas=github\n"), /dos líneas @/);
  const s = "a".repeat(64);
  const malo = leerFijados([
    "@ x origen=github:o/r sumas=github",
    `x 1.0.0 amd64 ${s} https://e.test/x-1.0.0-amd64`,
    `x 1.0.0 amd64 ${s} https://e.test/x-1.0.0-amd64-otra`,
    `y 2.0.0 arm64 ${"z".repeat(64)} http://e.test/y-2.0.0`,
    `x 1.0.0 ppc ${s} https://e.test/sin-version`,
  ].join("\n"));
  const errores = revisar(malo).join("\n");
  assert.match(errores, /fijados\.txt:3 \(x amd64\): repetido/);
  assert.match(errores, /fijados\.txt:4 \(y arm64\): falta la línea «@ y …»/);
  assert.match(errores, /\(y arm64\): la suma no es SHA-256/);
  assert.match(errores, /\(y arm64\): la URL no es https/);
  assert.match(errores, /fijados\.txt:5 \(x ppc\): arquitectura desconocida/);
  assert.match(errores, /\(x ppc\): la URL no nombra la versión 1\.0\.0/);
  assert.match(errores, /x: falta amd64 o arm64|y: falta amd64 o arm64/);
});

test("fijados: bajar-fijado.sh baja el archivo de la arquitectura, y frena y lo borra si la suma no es la fijada", () => {
  const d = carpetaPrueba("bajar-fijado");
  try {
    const fuente = join(d, "fuente");
    mkdirSync(fuente);
    writeFileSync(join(fuente, "h_1.0.0_amd64.zip"), "binario amd64");
    writeFileSync(join(fuente, "h_1.0.0_arm64.zip"), "binario arm64");
    writeFileSync(join(fuente, "j-1.0.0.jar"), "java");
    // curl falso: copia de la carpeta fuente el archivo que nombra la URL (sin red).
    ejecutable(join(d, "bin/curl"), '#!/bin/sh\nwhile [ $# -gt 1 ]; do [ "$1" = -o ] && o=$2; shift; done\ncp "$FUENTE/$(basename "$1")" "$o"\n');
    const fijados = join(d, "fijados.txt");
    writeFileSync(fijados, [
      `h 1.0.0 amd64 ${sha("binario amd64")} https://e.test/h_1.0.0_amd64.zip`,
      `h 1.0.0 arm64 ${"0".repeat(64)} https://e.test/h_1.0.0_arm64.zip`,
      `j 1.0.0 all ${sha("java")} https://e.test/j-1.0.0.jar`,
      `p 1.0.0 all ${sha("x")} http://e.test/p-1.0.0`,
      `d 1.0.0 all ${sha("x")} https://e.test/d-1.0.0`,
      `d 1.0.0 all ${sha("x")} https://e.test/d-1.0.0`,
    ].join("\n"));
    const trabajo = join(d, "trabajo");
    mkdirSync(trabajo);
    const bajar = (...args: string[]) => spawnSync("sh", [join(process.cwd(), "distro/bajar-fijado.sh"), ...args], { cwd: trabajo, encoding: "utf8", env: { PATH: `${join(d, "bin")}:/usr/bin:/bin`, FUENTE: fuente, FIJADOS: fijados } });
    const bien = bajar("h", "amd64");
    assert.equal(bien.status, 0, bien.stderr);
    assert.equal(bien.stdout.trim(), join(trabajo, "h_1.0.0_amd64.zip"));
    assert.equal(readFileSync(join(trabajo, "h_1.0.0_amd64.zip"), "utf8"), "binario amd64");
    const mal = bajar("h", "arm64");
    assert.equal(mal.status, 1);
    assert.match(mal.stderr, /la SHA-256 de h 1\.0\.0 \(arm64\) no es la fijada/);
    assert.ok(!existsSync(join(trabajo, "h_1.0.0_arm64.zip")), "borra lo que no coincide");
    assert.equal(bajar("j", "arm64").status, 0, "all sirve para cualquier arquitectura");
    assert.match(bajar("p", "amd64").stderr, /no se baja por https/);
    assert.match(bajar("d", "amd64").stderr, /exactamente una vez/);
    assert.match(bajar("nada", "amd64").stderr, /exactamente una vez/);
    const conTarget = spawnSync("sh", [join(process.cwd(), "distro/bajar-fijado.sh"), "h"], { cwd: trabajo, encoding: "utf8", env: { PATH: `${join(d, "bin")}:/usr/bin:/bin`, FUENTE: fuente, FIJADOS: fijados, TARGETARCH: "amd64" } });
    assert.equal(conTarget.status, 0, "toma la arquitectura de TARGETARCH");
  } finally {
    borrar(d);
  }
});

test("fijados: proponer baja la versión nueva, la contrasta con la lista del autor y aplicar sólo cambia esas líneas", async () => {
  const d = carpetaPrueba("proponer");
  const archivos: Record<string, Buffer | string> = {
    "/ultima.txt": "v2.0.0\n",
    "/dl/v2.0.0/x_2.0.0_linux_amd64.zip": "x nuevo amd64",
    "/dl/v2.0.0/x_2.0.0_linux_arm64.zip": "x nuevo arm64",
  };
  archivos["/dl/v2.0.0/x_2.0.0_checksums.txt"] = `${sha("x nuevo amd64")}  x_2.0.0_linux_amd64.zip\n${sha("x nuevo arm64")}  x_2.0.0_linux_arm64.zip\n`;
  const servidor = createServer((q, r) => {
    const cuerpo = archivos[q.url ?? ""];
    r.writeHead(cuerpo === undefined ? 404 : 200);
    r.end(cuerpo ?? "no");
  });
  await new Promise<void>((listo) => servidor.listen(0, "127.0.0.1", listo));
  const p = (servidor.address() as { port: number }).port;
  try {
    const base = `http://127.0.0.1:${p}`;
    const texto = [
      "# comentario que queda",
      `@ x origen=url:${base}/ultima.txt sumas=lista:${base}/dl/v{v}/x_{v}_checksums.txt`,
      `x 1.0.0 amd64 ${"a".repeat(64)} ${base}/dl/v1.0.0/x_1.0.0_linux_amd64.zip`,
      `x 1.0.0 arm64 ${"b".repeat(64)} ${base}/dl/v1.0.0/x_1.0.0_linux_arm64.zip`,
      "",
    ].join("\n");
    const f = leerFijados(texto);
    const r = await proponer(f, { dir: join(d, "bajadas"), minDias: 7 });
    assert.deepEqual(r.errores, []);
    assert.equal(r.propuestas.length, 1);
    assert.equal(r.propuestas[0]!.a, "2.0.0");
    assert.deepEqual(r.propuestas[0]!.archivos.map((a) => a.comprobado), [["x_2.0.0_checksums.txt"], ["x_2.0.0_checksums.txt"]]);
    assert.equal(readFileSync(join(d, "bajadas/x/2.0.0/amd64/x_2.0.0_linux_amd64.zip"), "utf8"), "x nuevo amd64");
    const nuevo = aplicar(f, r.propuestas);
    assert.equal(nuevo, texto.replace(`x 1.0.0 amd64 ${"a".repeat(64)} ${base}/dl/v1.0.0/x_1.0.0_linux_amd64.zip`, `x 2.0.0 amd64 ${sha("x nuevo amd64")} ${base}/dl/v2.0.0/x_2.0.0_linux_amd64.zip`).replace(`x 1.0.0 arm64 ${"b".repeat(64)} ${base}/dl/v1.0.0/x_1.0.0_linux_arm64.zip`, `x 2.0.0 arm64 ${sha("x nuevo arm64")} ${base}/dl/v2.0.0/x_2.0.0_linux_arm64.zip`));
    // Si la lista del autor dice otra cosa, no se propone nada para esa herramienta.
    archivos["/dl/v2.0.0/x_2.0.0_linux_arm64.zip"] = "x nuevo arm64, alterado";
    const mal = await proponer(f, { dir: join(d, "bajadas2"), minDias: 7 });
    assert.equal(mal.propuestas.length, 0);
    assert.match(mal.errores.join("\n"), /x: x_2\.0\.0_linux_arm64\.zip: la suma no coincide con/);
    // Ya al día: nada que proponer.
    const alDia = await proponer(f, { dir: join(d, "bajadas3"), minDias: 7, versiones: { x: "1.0.0" } });
    assert.deepEqual(alDia.al_dia, ["x 1.0.0"]);
  } finally {
    servidor.close();
    borrar(d);
  }
});

test("fijados: actualizar-fijados.sh --revisar acepta el archivo del repositorio", () => {
  const r = spawnSync("sh", ["scripts/actualizar-fijados.sh", "--revisar"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /herramientas, \d+ archivos, bien/);
});
