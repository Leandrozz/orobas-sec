// install.ps1 y el --actualizar del lanzador de Windows contra un servidor de releases falso, con pwsh (en Linux
// también: CYBER_PRUEBA_WINDOWS deja correr install.ps1 fuera de Windows). Sin pwsh corren sólo las pruebas estáticas.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { delimiter, join, parse } from "node:path";
import { after, before, test } from "node:test";
import { BASICAS, borrar, carpetaPrueba, type Clave, ejecutable, firmar, hay, levantarServidor, marcarUltimo, nuevaClave, pathCon, publicar, RAIZ, repoFalso, vacia } from "./releases-falsos.ts";

const PS1 = ["install.ps1", "distro/lanzador/cyber.ps1"];
const leer = (f: string) => readFileSync(join(RAIZ, f), "utf8");
const comun = (texto: string) => {
  const i = texto.indexOf("# --- común: verificación de releases");
  const j = texto.indexOf("# --- fin común ---");
  assert.ok(i >= 0 && j > i, "falta el bloque común");
  return texto.slice(i, j);
};

test("windows: install.ps1 y el lanzador comparten el mismo bloque de verificación, la misma clave y el BOM", () => {
  assert.equal(comun(leer(PS1[0]!)), comun(leer(PS1[1]!)));
  const claves = PS1.map((f) => /^\$ClavePublica = '(.*)'$/m.exec(leer(f))?.[1]);
  const sh = ["install.sh", "distro/lanzador/cyber"].map((f) => /^CLAVE_PUBLICA='(.*)'$/m.exec(leer(f))?.[1]);
  assert.ok(claves[0]);
  assert.deepEqual([...claves, ...sh], Array(4).fill(claves[0]));
  for (const f of PS1) assert.deepEqual([...readFileSync(join(RAIZ, f)).subarray(0, 3)], [0xef, 0xbb, 0xbf], `${f} sin BOM`);
  for (const f of [...PS1, "install.sh", "distro/lanzador/cyber"]) assert.doesNotMatch(leer(f), /raw\.githubusercontent\.com|\/main\//, f);
  // La firma se verifica con ssh-keygen -Y verify y el contenido exacto de SHA256SUMS por stdin (sin el fin de línea que agrega un pipe).
  assert.match(comun(leer(PS1[0]!)), /'-Y', 'verify', '-f', \$firmantes, '-I', 'orobas-sec', '-n', \$EspacioFirma/);
  assert.match(comun(leer(PS1[0]!)), /ReadAllBytes\(\$entrada\)/);
});

test("windows: el cyber.cmd del release es el que escribe el lanzador, e install.ps1 lo baja y verifica como el resto", () => {
  // El lanzador escribe cyber.cmd él mismo (--instalar, y al migrar una instalación vieja); install.ps1 instala el del
  // release, verificado. Tienen que ser el mismo archivo, byte por byte, con fines de línea de Windows.
  const lineas = /^\s*\$lineas = (.*)$/m.exec(leer("distro/lanzador/cyber.ps1"))?.[1];
  assert.ok(lineas, "falta EscribirCmd en el lanzador");
  const escrito = [...lineas.matchAll(/'([^']*)'/g)].map((m) => m[1]).join("\r\n") + "\r\n";
  assert.equal(readFileSync(join(RAIZ, "distro/lanzador/cyber.cmd"), "latin1"), escrito);
  assert.match(leer("install.ps1"), /foreach \(\$f in 'cyber-lanzador\.ps1', 'cyber\.cmd', 'install\.ps1'\)/);
  assert.doesNotMatch(leer("install.ps1"), /EscribirCmd/, "install.ps1 no inventa su cyber.cmd: instala el firmado");
  assert.match(leer("scripts/release/armar.sh"), /cp "\$A\/distro\/lanzador\/cyber\.cmd" "\$SALIDA\/cyber\.cmd"/);
});

const hayPwsh = spawnSync("pwsh", ["-NoProfile", "-Command", "1"]).status === 0;
const skip = !hayPwsh ? "pwsh no está en el PATH" : !hay("ssh-keygen") || !hay("git") ? "faltan ssh-keygen o git" : false;
const enWindows = process.platform === "win32";
// Un argumento entre comillas simples para pwsh -Command.
const comillas = (s: string) => `'${s.replace(/'/g, "''")}'`;
const IMAGEN = `ghcr.io/ejemplo/orobas@sha256:${"ef".repeat(32)}`;
let base = "";
let clave: Clave;
let otra: Clave;
let releases = "";

before(() => {
  if (skip) return;
  base = carpetaPrueba("windows");
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

// docker falso: anota sus argumentos y dice que sí (la imagen ya está, info anda).
const DOCKER = `#!/bin/sh\n{ printf '%s|' "$@"; echo; } >>"$FAKE_DIR/docker.log"\ncase "$1" in image) echo '["x/y@sha256:aaa"]' ;; esac\nexit 0\n`;
// El mismo fake en .cmd: en Windows pwsh no ejecuta el script sh sin extensión.
const DOCKER_CMD = `@echo off\r\nsetlocal enabledelayedexpansion\r\nset "s="\r\nfor %%a in (%*) do set "s=!s!%%a|"\r\n>>"%FAKE_DIR%\\docker.log" echo !s!\r\nif "%~1"=="image" echo ["x/y@sha256:aaa"]\r\nexit /b 0\r\n`;

let n = 0;
async function escenario(preparar?: (srv: string) => void, ultimo = "v1.1.0") {
  const d = join(base, `e${++n}`);
  mkdirSync(d);
  const srv = join(d, "srv");
  cpSync(releases, srv, { recursive: true });
  marcarUltimo(srv, ultimo);
  preparar?.(srv);
  const servidor = await levantarServidor(srv);
  ejecutable(join(d, "falsos/docker"), DOCKER);
  writeFileSync(join(d, "falsos/docker.cmd"), DOCKER_CMD);
  const tmp = join(d, "tmp");
  mkdirSync(tmp);
  const env: Record<string, string> = {
    PATH: `${join(d, "falsos")}${delimiter}${process.env.PATH}`,
    HOME: d,
    TMPDIR: tmp,
    APPDATA: join(d, "roaming"),
    LOCALAPPDATA: join(d, "local"),
    FAKE_DIR: d,
    CYBER_PRUEBA_WINDOWS: "1",
    CYBER_NO_UPDATE: "1",
    CYBER_RELEASES_URL: servidor.url,
    WT_SESSION: "x",
  };
  // Sin SYSTEMROOT/SystemDrive el ssh-keygen de Windows no arranca; los traemos del sistema real.
  for (const k of ["SYSTEMROOT", "SystemDrive", "WINDIR", "USERPROFILE", "PUBLIC", "ALLUSERSPROFILE", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "CommonProgramFiles", "PATHEXT", "ComSpec"]) {
    if (process.env[k]) env[k] = process.env[k]!;
  }
  // -Command con la salida en UTF-8: con -File la consola emite en la página de códigos del sistema
  // (cp1252/cp850) y los acentos de los mensajes no matchean lo que el test espera.
  const pwsh = (script: string, args: string[], extra: Record<string, string> = {}) =>
    spawnSync("pwsh", ["-NoProfile", "-Command", `[Console]::OutputEncoding=[Text.Encoding]::UTF8; & '${script.replace(/'/g, "''")}' ${args.join(" ")}`], { encoding: "utf8", env: { ...env, ...extra }, cwd: d, input: "", timeout: 120_000 });
  const instalar = (args: string[], extra: Record<string, string> = {}) => pwsh(join(srv, "v1.0.0/install.ps1"), ["-Version", "v1.0.0", ...args], extra);
  const bin = join(d, "local/elevate-cyber/bin");
  const prefijo = join(d, "local/orobas-sec");
  const docker = () => (existsSync(join(d, "docker.log")) ? readFileSync(join(d, "docker.log"), "utf8") : "");
  return { d, srv, servidor, env, tmp, pwsh, instalar, bin, prefijo, docker };
}

// Que una instalación fallida no dejó carpetas. Fuera de Windows, ni LOCALAPPDATA (como antes de #44); en Windows se
// miran sólo las nuestras, porque #44 vio que ahí LOCALAPPDATA puede aparecer sin que lo cree el instalador.
function sinCarpetas(e: { d: string; prefijo: string }) {
  assert.ok(!existsSync(join(e.d, "local/elevate-cyber")) && !existsSync(e.prefijo), "no crea carpetas");
  if (!enWindows) assert.ok(!existsSync(join(e.d, "local")), "no crea LOCALAPPDATA");
}

test("windows: install.ps1 con firma y sumas válidas instala el lanzador y cyber.cmd en el perfil, y desinstala", { skip }, async () => {
  const e = await escenario();
  try {
    const r = e.instalar(["-Si"]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /Voy a hacer esto|I will do this/);
    assert.match(r.stdout, /Firma y sumas verificadas|Signature and checksums verified/);
    assert.equal(readFileSync(join(e.bin, "cyber-lanzador.ps1"), "utf8"), readFileSync(join(e.srv, "v1.0.0/cyber-lanzador.ps1"), "utf8"));
    assert.match(readFileSync(join(e.bin, "cyber.cmd"), "utf8"), /cyber-lanzador\.ps1/);
    assert.deepEqual(readFileSync(join(e.bin, "cyber.cmd")), readFileSync(join(e.srv, "v1.0.0/cyber.cmd")), "el cyber.cmd firmado del release");
    assert.match(readFileSync(join(e.prefijo, "instalacion.conf"), "utf8"), /^version=v1\.0\.0\r?$/m);
    assert.match(r.stdout, /no está en tu PATH|is not in your PATH/, "con -Si no toca el PATH: dice cómo");
    assert.ok(vacia(e.tmp));
    // Otra vez: idempotente.
    assert.equal(e.instalar(["-Si"]).status, 0);
    const d = e.pwsh(join(e.prefijo, "install.ps1"), ["-Desinstalar", "-Si"]);
    assert.equal(d.status, 0, d.stdout + d.stderr);
    assert.ok(!existsSync(e.prefijo));
    assert.ok(!existsSync(join(e.bin, "cyber-lanzador.ps1")) && !existsSync(join(e.bin, "cyber.cmd")));
  } finally {
    e.servidor.cerrar();
  }
});

const fallas: [string, (srv: string) => void, RegExp][] = [
  ["una suma que no coincide", (srv) => appendFileSync(join(srv, "v1.0.0/cyber-lanzador.ps1"), "# agregado\n"), /cyber-lanzador\.ps1 no coincide|cyber-lanzador\.ps1 does not match/],
  ["una firma de otra clave", (srv) => firmar(otra, join(srv, "v1.0.0/SHA256SUMS")), /no es válida para la clave|is not valid for this file's key/],
  ["una firma alterada", (srv) => writeFileSync(join(srv, "v1.0.0/SHA256SUMS.sig"), readFileSync(join(srv, "v1.0.0/SHA256SUMS.sig"), "utf8").replace(/^(.{20})./m, "$1Z")), /no es válida para la clave|is not valid for this file's key/],
  ["un cyber.cmd que no coincide con la suma", (srv) => appendFileSync(join(srv, "v1.0.0/cyber.cmd"), "@echo agregado\r\n"), /cyber\.cmd no coincide|cyber\.cmd does not match/],
  ["un release sin cyber.cmd", (srv) => {
    const f = join(srv, "v1.0.0/SHA256SUMS");
    writeFileSync(f, readFileSync(f, "utf8").replace(/^.*  cyber\.cmd\n/m, ""));
    firmar(clave, f);
  }, /no trae cyber\.cmd|has no cyber\.cmd/],
  ["un release sin modo contenedor", (srv) => {
    const f = join(srv, "v1.0.0/SHA256SUMS");
    writeFileSync(f, readFileSync(f, "utf8").replace(/^.*cyber-lanzador.*\n/gm, ""));
    firmar(clave, f);
  }, /no trae cyber-lanzador\.ps1|has no cyber-lanzador\.ps1/],
  ["la lista firmada de otra versión", (srv) => {
    for (const f of ["SHA256SUMS", "SHA256SUMS.sig"]) cpSync(join(srv, "v1.1.0", f), join(srv, "v1.0.0", f));
  }, /no es el de v1\.0\.0|not the one for v1\.0\.0/],
];
for (const [nombre, preparar, mensaje] of fallas) {
  test(`windows: install.ps1 con ${nombre} no instala nada ni deja restos`, { skip }, async () => {
    const e = await escenario(preparar);
    try {
      const r = e.instalar(["-Si"]);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stdout + r.stderr, mensaje);
      sinCarpetas(e);
      assert.ok(vacia(e.tmp));
    } finally {
      e.servidor.cerrar();
    }
  });
}

test("windows: si ssh-keygen muere al arrancar (sin SYSTEMROOT) el error es el de la firma, no «The pipe is being closed»", { skip: skip || (!enWindows && "sólo vale en Windows: en Linux y macOS ssh-keygen arranca sin SYSTEMROOT, la firma es válida y la instalación sigue") }, async () => {
  const e = await escenario();
  try {
    // El env mínimo de antes: sin las variables del sistema el ssh-keygen de Windows muere al arrancar.
    const env = {
      PATH: e.env.PATH,
      HOME: e.d,
      TMPDIR: join(e.d, "tmp"),
      APPDATA: join(e.d, "roaming"),
      LOCALAPPDATA: join(e.d, "local"),
      FAKE_DIR: e.d,
      CYBER_PRUEBA_WINDOWS: "1",
      CYBER_NO_UPDATE: "1",
      CYBER_RELEASES_URL: e.servidor.url,
      WT_SESSION: "x",
    };
    const r = spawnSync("pwsh", ["-NoProfile", "-Command", "[Console]::OutputEncoding=[Text.Encoding]::UTF8; & '" + join(e.srv, "v1.0.0/install.ps1").replace(/'/g, "''") + "' -Version v1.0.0 -Si"], { encoding: "utf8", env, cwd: e.d, input: "", timeout: 120_000 });
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout + r.stderr, /no es válida para la clave|is not valid for this file's key/);
    assert.doesNotMatch(r.stdout + r.stderr, /pipe is being closed/);
    sinCarpetas(e);
  } finally {
    e.servidor.cerrar();
  }
});

test("windows: install.ps1 sin consola y sin -Si, o sin Docker ni ssh-keygen, explica y no instala", { skip }, async () => {
  const e = await escenario();
  try {
    const sinSi = e.instalar([]);
    assert.equal(sinSi.status, 1);
    assert.match(sinSi.stdout, /No hay una consola para confirmar|No console to confirm/);
    const path = pathCon(join(e.d, "sistema"), BASICAS.filter((h) => h !== "ssh-keygen"));
    // La carpeta de pwsh sola (en el PATH entero también está ssh-keygen): en Windows con la ruta de Windows (cygpath,
    // como la dejó #44); en Linux y macOS, la del binario real, porque /usr/bin/pwsh es un enlace (como antes de #44).
    const carpeta = enWindows ? "cygpath -w \"$(dirname \"$(command -v pwsh)\")\"" : "dirname \"$(readlink -f \"$(command -v pwsh)\")\"";
    const pwshDir = spawnSync("sh", ["-c", carpeta], { encoding: "utf8" }).stdout.trim();
    const falta = e.instalar(["-Si"], { PATH: `${path}${delimiter}${pwshDir}`, WINDIR: "", ProgramFiles: "", "ProgramFiles(x86)": "" });
    assert.equal(falta.status, 1);
    assert.match(falta.stdout, /Docker Desktop/);
    assert.match(falta.stdout, /ssh-keygen/);
    assert.deepEqual(e.servidor.pedidos(), []);
    sinCarpetas(e);
  } finally {
    e.servidor.cerrar();
  }
});

// New-Item -Force crea los padres de -Bin y -Prefix. Si la instalación falla después, install.ps1 borra lo que creó
// esta corrida: los padres sólo si quedaron vacíos, y nunca una carpeta que ya existía.
test("windows: si la instalación falla después de crear carpetas, borra las que creó y nunca una que ya existía", { skip }, async () => {
  const e = await escenario();
  try {
    const ya = join(e.d, "ya");
    mkdirSync(ya);
    writeFileSync(join(ya, "dato"), "no se borra");
    writeFileSync(join(e.d, "archivo"), "no es una carpeta");
    // -Bin dos niveles nuevos adentro de una carpeta que ya existe; -Prefix debajo de un archivo, para que New-Item
    // falle después de crear -Bin con sus padres.
    const r = e.instalar(["-Si", "-Bin", comillas(join(ya, "n1", "n2", "bin")), "-Prefix", comillas(join(e.d, "archivo", "p"))]);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /Firma y sumas verificadas|Signature and checksums verified/, "falla después de verificar, al crear las carpetas");
    assert.ok(!existsSync(join(ya, "n1")), "borra las carpetas que creó");
    assert.equal(readFileSync(join(ya, "dato"), "utf8"), "no se borra");
    assert.equal(readFileSync(join(e.d, "archivo"), "utf8"), "no es una carpeta");
    assert.ok(vacia(e.tmp));
  } finally {
    e.servidor.cerrar();
  }
});

test("windows: la limpieza de install.ps1 anota sólo carpetas que no existían y las borra de la más honda a la más alta, sólo si quedaron vacías", { skip }, () => {
  const ya = join(base, "limpieza", "ya");
  mkdirSync(ya, { recursive: true });
  writeFileSync(join(ya, "dato"), "no se borra");
  const b = join(ya, "a", "b");
  const honda = join(ya, "a", "c", "e");
  // Las dos funciones salen del install.ps1 del repositorio (sin correr el resto del script).
  const script = [
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8",
    `$ast = [Management.Automation.Language.Parser]::ParseFile(${comillas(join(RAIZ, "install.ps1"))}, [ref]$null, [ref]$null)`,
    "foreach ($f in $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) { if ('CarpetasNuevas', 'BorrarSiVacias' -contains $f.Name) { . ([ScriptBlock]::Create($f.Extent.Text)) } }",
    `$nuevas = @(CarpetasNuevas @(${comillas(b)}, ${comillas(honda)}, ${comillas(ya)}))`,
    `New-Item -ItemType Directory -Force ${comillas(b)}, ${comillas(honda)} | Out-Null`,
    `Set-Content -LiteralPath ${comillas(join(ya, "a", "c", "ajeno"))} -Value 'no se borra'`,
    "BorrarSiVacias $nuevas",
    "$nuevas | ForEach-Object { Write-Output $_ }",
  ].join("\n");
  const r = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", input: "", timeout: 60_000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual(r.stdout.trim().split(/\r?\n/).sort(), [b, join(ya, "a"), honda, join(ya, "a", "c")].sort(), "anota las cuatro nuevas y no «ya»");
  assert.ok(!existsSync(b) && !existsSync(honda), "borra las que quedaron vacías");
  assert.equal(readFileSync(join(ya, "a", "c", "ajeno"), "utf8").trim(), "no se borra", "una nueva con algo adentro queda, y su padre también");
  assert.equal(readFileSync(join(ya, "dato"), "utf8"), "no se borra");
});

test("windows: install.ps1 no instala en la raíz, en tu perfil ni en LOCALAPPDATA entero (-Desinstalar borra -Prefix entero)", { skip }, async () => {
  const e = await escenario();
  try {
    for (const args of [["-Prefix", comillas(e.d)], ["-Prefix", comillas(join(e.d, "local"))], ["-Bin", comillas(e.d)], ["-Prefix", comillas(parse(e.d).root)]]) {
      const r = e.instalar(["-Si", ...args]);
      assert.equal(r.status, 1, `${args.join(" ")}: ${r.stdout}${r.stderr}`);
      assert.match(r.stdout, /No uso esta carpeta para instalar|I will not install into this folder/, args.join(" "));
    }
    assert.deepEqual(e.servidor.pedidos(), []);
    sinCarpetas(e);
  } finally {
    e.servidor.cerrar();
  }
});

test("windows: el lanzador con --actualizar --si se reemplaza por el firmado del último release y baja su imagen", { skip }, async () => {
  const e = await escenario();
  try {
    const lanzador = join(e.d, "bin/cyber-lanzador.ps1");
    mkdirSync(join(e.d, "bin"));
    copyFileSync(join(e.srv, "v1.0.0/cyber-lanzador.ps1"), lanzador);
    const r = e.pwsh(lanzador, ["--actualizar", "--si"]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /Lanzador actualizado a v1\.1\.0|Launcher updated to v1\.1\.0/);
    assert.equal(readFileSync(lanzador, "utf8"), readFileSync(join(e.srv, "v1.1.0/cyber-lanzador.ps1"), "utf8"));
    assert.match(e.docker(), new RegExp(`^pull\\|${IMAGEN.replace(/[.]/g, "\\.")}\\|$`, "m"));
  } finally {
    e.servidor.cerrar();
  }
});

test("windows: el lanzador no se reemplaza con una firma de otra clave, ni sin consola y sin --si", { skip }, async () => {
  const e = await escenario((srv) => firmar(otra, join(srv, "v1.1.0/SHA256SUMS")));
  try {
    const lanzador = join(e.d, "bin/cyber-lanzador.ps1");
    mkdirSync(join(e.d, "bin"));
    copyFileSync(join(e.srv, "v1.0.0/cyber-lanzador.ps1"), lanzador);
    const original = readFileSync(lanzador, "utf8");
    const mala = e.pwsh(lanzador, ["--actualizar", "--si"]);
    assert.equal(mala.status, 1, mala.stdout);
    assert.match(mala.stdout, /No actualicé el lanzador|Launcher not updated/);
    assert.equal(readFileSync(lanzador, "utf8"), original);
    assert.doesNotMatch(e.docker(), /^pull/m);
    const sola = e.pwsh(lanzador, ["--actualizar"]);
    assert.equal(sola.status, 0, sola.stdout + sola.stderr);
    assert.match(sola.stdout, /Sin consola no reemplazo el lanzador|Without a console I do not replace/);
    assert.equal(readFileSync(lanzador, "utf8"), original);
    assert.match(e.docker(), /^pull\|/m, "la imagen sí se baja");
  } finally {
    e.servidor.cerrar();
  }
});
