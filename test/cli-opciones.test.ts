import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

// Los errores de uso salen antes de tocar datos, daemon o red: alcanza con correr el punto de entrada.
const cli = (...args: string[]) =>
  spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", "src/cli.ts", ...args], { encoding: "utf8", env: { ...process.env, LANG: "es_AR.UTF-8", CYBER_PROYECTO_HOST: "" }, timeout: 30_000 });

test("cli: una opción del lanzador que llega al agente explica que el «cyber» no es el lanzador, en los dos idiomas", () => {
  for (const opcion of ["--actualizar", "--instalar", "--cerrar-docker"]) {
    const r = cli(opcion);
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, new RegExp(`«cyber ${opcion}» es del lanzador`));
    assert.match(r.stderr, /Get-Command cyber -All/);
    assert.match(r.stderr, /belongs to the launcher/);
    // El lanzador se instala desde un release firmado, no desde main.
    assert.match(r.stderr, /github\.com\/Leandrozz\/orobas-sec\/releases\/latest/);
    assert.doesNotMatch(r.stderr, /\/main\//);
    assert.doesNotMatch(r.stderr, /at parseArgs|node:internal/);
  }
});

test("cli: una opción desconocida da una línea con el código (que el lanzador reconoce) y no un stack", () => {
  const r = cli("--no-existe");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Opción desconocida: --no-existe \[ERR_PARSE_ARGS_UNKNOWN_OPTION\]/);
  assert.match(r.stderr, /--help/);
  assert.doesNotMatch(r.stderr, /at parseArgs|node:internal/);
  const sinValor = cli("-m");
  assert.equal(sinValor.status, 2);
  assert.match(sinValor.stderr, /\[ERR_PARSE_ARGS_INVALID_OPTION_VALUE\]/);
});

test("cli: --version imprime la versión sin tocar datos ni daemon (la del release si hay VERSION, si no la del paquete)", () => {
  const r = cli("--version");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^orobas-sec \d+\.\d+\.\d+ \(desarrollo\)\n$/);
});
