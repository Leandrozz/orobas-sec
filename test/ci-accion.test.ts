import "./datos-tmp.ts";
// La GitHub Action (action.yml + distro/ci/accion.sh), la plantilla de GitLab y el instalador verificado de CI, todo
// local: releases armados con scripts/release/armar.sh y firmados con una clave de prueba, servidos por un servidor de
// releases falso. Lo que no se puede probar sin GitHub real (que el runner corra la acción compuesta, el caché, la
// subida del SARIF) queda dicho en docs/ci.md.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { leerYaml } from "../src/ci/yaml.ts";
import { borrar, carpetaPrueba, type Clave, ejecutable, hay, levantarServidor, nuevaClave, publicar, RAIZ, repoFalso, type Servidor } from "./releases-falsos.ts";
import { git, limpiar, repo } from "./ci-guion.ts";

const skip = !hay("ssh-keygen") || !hay("curl") || !hay("git") || !hay("bash") ? "faltan ssh-keygen, curl, git o bash" : false;
const ACCION = join(RAIZ, "distro/ci/accion.sh");
let base = "";
let clave: Clave;
let otra: Clave;
let falso = "";
let servidor: Servidor;

before(async () => {
  if (skip) return;
  base = carpetaPrueba("ci-accion");
  clave = nuevaClave(base, "clave");
  otra = nuevaClave(base, "otra");
  falso = repoFalso(base, clave);
  const srv = join(base, "srv");
  mkdirSync(srv);
  publicar(falso, srv, "v1.2.3", clave);
  publicar(falso, srv, "v9.9.9", otra);
  servidor = await levantarServidor(srv);
});
after(() => {
  servidor?.cerrar();
  if (base) borrar(base);
  limpiar();
});

/** Corre un paso de accion.sh con un entorno de Actions de mentira (archivos para las salidas). */
function paso(subcomando: string, env: Record<string, string>, cwd = base) {
  const d = join(base, `p${Math.random().toString(36).slice(2, 8)}`);
  mkdirSync(d);
  const archivos = { GITHUB_OUTPUT: join(d, "output"), GITHUB_ENV: join(d, "env"), GITHUB_PATH: join(d, "path") };
  for (const f of Object.values(archivos)) writeFileSync(f, "");
  mkdirSync(join(d, "home"));
  const r = spawnSync("bash", [ACCION, subcomando], { encoding: "utf8", cwd, env: { PATH: process.env.PATH!, HOME: join(d, "home"), RUNNER_TEMP: join(d, "runner"), ...archivos, ...env } });
  const salidas = Object.fromEntries(readFileSync(archivos.GITHUB_OUTPUT, "utf8").split("\n").filter((l) => /^[a-z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  return { ...r, salidas, archivos, d, texto: `${r.stdout}${r.stderr}` };
}

test("acción · preparar: sólo versiones fijas; un PR de fork no corre por defecto y, con «base», lee la configuración de la base", { skip }, () => {
  for (const v of ["latest", "main", "v1.2", "1.2.3", "v1.2.3-rc1"]) {
    const r = paso("preparar", { INPUT_VERSION: v });
    assert.equal(r.status, 2, v);
    assert.match(r.texto, /::error title=Orobas::«version» tiene que ser una versión fija vX\.Y\.Z/);
  }
  const normal = paso("preparar", { INPUT_VERSION: "v1.2.3", GITHUB_REF: "refs/pull/4/merge", GITHUB_RUN_ID: "77", GITHUB_BASE_REF: "main" });
  assert.equal(normal.status, 0, normal.texto);
  assert.equal(normal.salidas.correr, "si");
  assert.match(normal.salidas.clave!, /^orobas-ci-[0-9a-f]{12}-refs\/pull\/4\/merge-77$/);
  assert.match(readFileSync(normal.archivos.GITHUB_OUTPUT, "utf8"), /claves<<FIN_CLAVES\norobas-ci-[0-9a-f]{12}-refs\/pull\/4\/merge-\norobas-ci-[0-9a-f]{12}-refs\/heads\/main-\nFIN_CLAVES/);

  const dir = repo({ ".orobas/ci.yml": "version: 1\n" });
  const baseSha = git(dir, "rev-parse", "HEAD").trim();
  const evento = join(dir, "evento.json");
  writeFileSync(evento, JSON.stringify({ pull_request: { number: 9, head: { repo: { full_name: "extrana/repo", fork: true } }, base: { sha: baseSha, repo: { full_name: "duena/repo" } } } }));
  const omitir = paso("preparar", { INPUT_VERSION: "v1.2.3", GITHUB_EVENT_PATH: evento }, dir);
  assert.equal(omitir.status, 0);
  assert.equal(omitir.salidas.correr, "no");
  assert.equal(omitir.salidas.fork, "si");
  assert.match(omitir.texto, /PR de un fork: no se corre/);
  const deBase = paso("preparar", { INPUT_VERSION: "v1.2.3", INPUT_FORKS: "base", GITHUB_EVENT_PATH: evento }, dir);
  assert.equal(deBase.status, 0, deBase.texto);
  assert.equal(deBase.salidas.correr, "si");
  assert.equal(deBase.salidas.config_ref, baseSha);
  writeFileSync(evento, JSON.stringify({ pull_request: { number: 9, head: { repo: { full_name: "duena/repo", fork: false } }, base: { sha: baseSha, repo: { full_name: "duena/repo" } } } }));
  assert.equal(paso("preparar", { INPUT_VERSION: "v1.2.3", GITHUB_EVENT_PATH: evento }, dir).salidas.fork, "no");
  assert.equal(paso("preparar", { INPUT_VERSION: "v1.2.3", INPUT_FORKS: "todos" }).status, 2);
});

test("acción · instalar: instala la versión pedida verificada por firma; con otra firma no instala nada", { skip }, () => {
  const ok = paso("instalar", { INPUT_VERSION: "v1.2.3", GITHUB_ACTION_PATH: falso, CYBER_RELEASES_URL: servidor.url });
  assert.equal(ok.status, 0, ok.texto);
  assert.match(ok.texto, /Instalado: orobas-sec v1\.2\.3/);
  const bin = readFileSync(ok.archivos.GITHUB_PATH, "utf8").trim();
  assert.ok(existsSync(join(bin, "cyber")));
  const mala = paso("instalar", { INPUT_VERSION: "v9.9.9", GITHUB_ACTION_PATH: falso, CYBER_RELEASES_URL: servidor.url });
  assert.equal(mala.status, 3);
  assert.match(mala.texto, /no es válida para la clave/);
  assert.match(mala.texto, /::error title=Orobas::No se pudo instalar Orobas v9\.9\.9 verificado/);
  assert.equal(readFileSync(mala.archivos.GITHUB_PATH, "utf8"), "");
  assert.ok(!existsSync(join(mala.d, "runner", "orobas-sec", "bin", "cyber")));
});

test("acción · correr, comentar y terminar: argumentos, código, caché y salidas del paso", { skip }, () => {
  const dir = repo({ ".orobas/ci.yml": "version: 1\n" });
  // Un «cyber» de mentira: anota sus argumentos, escribe las salidas y sale con el código que se le pide.
  const cyber = join(dir, "cyber-falso");
  ejecutable(cyber, `#!/bin/sh
printf '%s\\n' "$@" > "${dir}/argumentos"
[ "$1 $2" = "ci comentar" ] && { echo comentado; exit \${COMENTAR:-0}; }
mkdir -p orobas-ci
[ -n "\${SIN_SALIDA:-}" ] || { echo '{"formato":"orobas-ci/1"}' > orobas-ci/resultado.json; echo '{}' > orobas-ci/resultado.sarif; echo '# r' > orobas-ci/resumen.md; }
exit \${CODIGO:-0}
`);
  const env = { OROBAS_CI_CYBER: cyber, OROBAS_CI_AUTORIZACION: "sha256:x", INPUT_CONFIG: ".orobas/ci.yml", INPUT_SALIDA: "orobas-ci" };
  const uno = paso("correr", { ...env, CODIGO: "1", INPUT_ARGUMENTOS: "--solo-lectura --junit", INPUT_CONFIG_REF: "abc123" }, dir);
  assert.equal(uno.status, 0, "el paso no falla: el código lo devuelve «terminar»");
  assert.equal(uno.salidas.codigo, "1");
  assert.equal(uno.salidas.sarif, "orobas-ci/resultado.sarif");
  assert.equal(uno.salidas.guardar_cache, "si");
  assert.deepEqual(readFileSync(join(dir, "argumentos"), "utf8").trim().split("\n"), ["ci", "--config", ".orobas/ci.yml", "--salida", "orobas-ci", "--config-ref", "abc123", "--solo-lectura", "--junit"]);
  assert.match(readFileSync(uno.archivos.GITHUB_ENV, "utf8"), /^OROBAS_CI_CODIGO=1$/m);
  // La próxima corrida compara contra ésta, y un retest la usa.
  const dos = paso("correr", { ...env, INPUT_MODO: "retest" }, dir);
  assert.deepEqual(readFileSync(join(dir, "argumentos"), "utf8").trim().split("\n").slice(-3), ["--retest", "--anterior", ".orobas-ci-cache/anterior.json"]);
  assert.equal(dos.salidas.codigo, "0");
  // Una configuración rota (2) no pisa la línea de base; sin resultado escrito, es infraestructura (3), nunca 0.
  assert.equal(paso("correr", { ...env, CODIGO: "2" }, dir).salidas.guardar_cache, "no");
  const sinSalida = paso("correr", { ...env, SIN_SALIDA: "1" }, join(repo({}), "."));
  assert.equal(sinSalida.salidas.codigo, "3");
  assert.match(sinSalida.texto, /sin escribir orobas-ci\/resultado\.json/);
  // Un argumento con comillas o «;» no ejecuta nada: va como texto.
  paso("correr", { ...env, INPUT_ARGUMENTOS: "--modelo x;touch${IFS}pwned" }, dir);
  assert.ok(!existsSync(join(dir, "pwned")));
  assert.ok(paso("correr", { ...env, OROBAS_CI_AUTORIZACION: "" }, dir).texto.includes("Falta la entrada «autorizacion»"));

  assert.equal(paso("comentar", { ...env }, dir).status, 0);
  const sinPermiso = paso("comentar", { ...env, COMENTAR: "3" }, dir);
  assert.equal(sinPermiso.status, 0, "un comentario que falla no cambia el resultado");
  assert.match(sinPermiso.texto, /::warning title=Orobas::No pude comentar/);

  for (const codigo of ["0", "1", "2", "3", "4"]) assert.equal(paso("terminar", { OROBAS_CI_CODIGO: codigo }).status, Number(codigo));
  assert.equal(paso("terminar", { INPUT_CORRIO: "no" }).status, 0, "un PR de fork omitido no falla");
  assert.equal(paso("terminar", { INPUT_CORRIO: "si" }).status, 3, "corrió y no dejó código: no es «todo bien»");
});

test("instalador verificado de CI y plantilla de GitLab: instalan la versión fija con la clave dada; con otra clave, nada", { skip }, () => {
  const correrSh = (script: string[], env: Record<string, string>) => {
    const home = join(base, `h${Math.random().toString(36).slice(2, 8)}`);
    mkdirSync(home);
    return spawnSync("sh", script, { encoding: "utf8", env: { PATH: process.env.PATH!, HOME: home, CYBER_RELEASES_URL: servidor.url, ...env } });
  };
  const prefijo = join(base, "verificado");
  const ok = correrSh([join(RAIZ, "distro/ci/instalar-verificado.sh"), "v1.2.3", clave.texto, prefijo], {});
  assert.equal(ok.status, 0, ok.stderr + ok.stdout);
  assert.match(ok.stdout, /orobas-sec v1\.2\.3/);
  const conOtra = correrSh([join(RAIZ, "distro/ci/instalar-verificado.sh"), "v1.2.3", otra.texto, join(base, "prefijo-otra")], {});
  assert.notEqual(conOtra.status, 0);
  assert.match(conOtra.stderr, /no es válida para esa clave: no instalo nada/);
  assert.ok(!existsSync(join(base, "prefijo-otra")));
  assert.match(correrSh([join(RAIZ, "distro/ci/instalar-verificado.sh"), "latest", clave.texto], {}).stderr, /fija/);

  // La plantilla de GitLab: su instalación (before_script) corre tal cual, con la clave y la versión de sus variables.
  const plantilla = leerYaml(readFileSync(join(RAIZ, "distro/ci/gitlab-ci.yml"), "utf8")).valor as { variables: Record<string, string>; orobas: { before_script: string[]; script: string[]; rules: unknown[]; image: string } };
  assert.match(plantilla.orobas.image, /@sha256:[0-9a-f]{64}$/);
  assert.equal(plantilla.variables.OROBAS_CLAVE_PUBLICA, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfKpWK3+u7xt/H1nXdYudXF4DWUorU16LWu7ACfcP+R", "scripts/release/fijar-clave.sh la reemplaza junto con las demás");
  const instalar = plantilla.orobas.before_script[1]!;
  const home = join(base, "gitlab-home");
  mkdirSync(home);
  const g = spawnSync("sh", ["-c", `${instalar}\ncyber --version`], { encoding: "utf8", env: { PATH: process.env.PATH!, HOME: home, CYBER_RELEASES_URL: servidor.url, OROBAS_VERSION: "v1.2.3", OROBAS_CLAVE_PUBLICA: clave.texto } });
  assert.equal(g.status, 0, g.stderr + g.stdout);
  assert.match(g.stdout, /orobas-sec v1\.2\.3/);
  mkdirSync(join(base, "gitlab-mala"));
  const gMala = spawnSync("sh", ["-c", instalar], { encoding: "utf8", env: { PATH: process.env.PATH!, HOME: join(base, "gitlab-mala"), CYBER_RELEASES_URL: servidor.url, OROBAS_VERSION: "v1.2.3", OROBAS_CLAVE_PUBLICA: otra.texto } });
  assert.notEqual(gMala.status, 0);
  assert.equal(spawnSync("sh", ["-c", instalar], { encoding: "utf8", env: { PATH: process.env.PATH!, HOME: home, OROBAS_VERSION: "vX.Y.Z", OROBAS_CLAVE_PUBLICA: clave.texto } }).status, 2);
  // Un MR desde un fork no corre.
  assert.ok(JSON.stringify(plantilla.orobas.rules).includes("CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_PROJECT_ID"));
  assert.match(plantilla.orobas.script[0]!, /cyber ci --salida orobas-ci --junit/);
});

const SHA = /^[\w.-]+\/[\w.-]+(\/[\w./-]+)?@[0-9a-f]{40}$/;

test("acción y ejemplos: acciones de terceros fijadas por SHA, permisos mínimos y ninguna entrada interpolada en un script", () => {
  const accion = leerYaml(readFileSync(join(RAIZ, "action.yml"), "utf8")).valor as { inputs: Record<string, { required?: boolean }>; runs: { using: string; steps: Array<{ uses?: string; run?: string; env?: Record<string, string> }> } };
  assert.equal(accion.runs.using, "composite");
  assert.equal(accion.inputs.version!.required, true);
  assert.equal(accion.inputs.autorizacion!.required, true);
  for (const s of accion.runs.steps) {
    if (s.uses) assert.match(s.uses, SHA, s.uses);
    if (s.run) {
      assert.ok(!/\$\{\{/.test(s.run), `script con interpolación: ${s.run}`);
      assert.match(s.run, /^bash "\$GITHUB_ACTION_PATH\/distro\/ci\/accion\.sh" (preparar|instalar|correr|comentar|terminar)$/);
    }
  }
  const texto = readFileSync(join(RAIZ, "action.yml"), "utf8");
  for (const usado of texto.matchAll(/^\s*-?\s*uses: (\S+)/gm)) assert.match(usado[1]!, SHA);
  for (const archivo of ["staging.yml", "efimero.yml", "nocturna.yml", "retest.yml"]) {
    const fuente = readFileSync(join(RAIZ, "distro/ci/github", archivo), "utf8");
    const flujo = leerYaml(fuente).valor as { permissions: unknown; jobs: Record<string, { permissions?: Record<string, string>; steps?: Array<{ uses?: string; with?: Record<string, unknown>; run?: string }> }> };
    assert.deepEqual(flujo.permissions, {}, `${archivo}: nada por defecto`);
    for (const [nombre, job] of Object.entries(flujo.jobs)) {
      for (const [permiso, valor] of Object.entries(job.permissions ?? {})) {
        assert.ok(["contents:read", "pull-requests:write", "security-events:write"].includes(`${permiso}:${valor}`), `${archivo}/${nombre}: ${permiso}: ${valor}`);
      }
      for (const s of job.steps ?? []) {
        if (s.uses?.startsWith("Leandrozz/orobas-sec@")) {
          assert.match(String(s.with?.version), /^vX\.Y\.Z$/, "versión fija (a completar)");
          assert.match(String(s.with?.autorizacion), /^\$\{\{ vars\.OROBAS_ALCANCE_AUTORIZADO \}\}$/);
        } else if (s.uses) assert.match(s.uses, SHA, `${archivo}: ${s.uses}`);
        if (s.uses?.startsWith("actions/checkout@")) assert.equal(s.with?.["persist-credentials"], false, `${archivo}: checkout sin credenciales persistidas`);
        if (s.run) assert.ok(!/\$\{\{/.test(s.run), `${archivo}: script con interpolación`);
      }
    }
  }
  // El Dockerfile genérico parte de la base fijada por digest e instala con el instalador verificado.
  const docker = readFileSync(join(RAIZ, "distro/ci/Dockerfile"), "utf8");
  assert.match(docker, /^FROM node:[\d.]+-bookworm-slim@sha256:[0-9a-f]{64}$/m);
  assert.match(docker, /instalar-verificado\.sh "\$OROBAS_VERSION" "\$clave"/);
});
