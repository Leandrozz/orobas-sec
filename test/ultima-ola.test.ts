import "./datos-tmp.ts";
// Última tanda de la revisión de la rama: candado en Docker, espera de la mudanza, socket privado, secretos cifrados, MCP y permisos.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon, socketPath } from "../src/daemon.ts";
import { dataDir, lockProject, migrateLegacy, projectId, registerProject, runtimeDir } from "../src/datos.ts";
import { resolveProvider } from "../src/providers.ts";
import { credentialsDir, forgetKey, readSecret, secretState, secretsKey, writeSecret } from "../src/secretos.ts";
import { projectPaths } from "../src/store.ts";

const CLI = join(import.meta.dirname, "..", "src", "cli.ts");
const saved = { ...process.env };
afterEach(() => {
  for (const name of Object.keys(process.env)) if (!(name in saved)) delete process.env[name];
  Object.assign(process.env, saved);
  forgetKey();
});
const project = () => mkdtempSync(join(tmpdir(), "cyber-ola-"));
const lockFile = (cwd: string) => join(projectPaths(cwd).root, "daemon.lock");

// C1
test("Docker: leave() apaga el daemon y suelta el candado; fuera de Docker solo se desconecta", async () => {
  const cwd = project();
  const a = new Daemon({ cwd, autoResume: false });
  await a.listen();
  try {
    let client = await connectDaemon(cwd, { spawn: false });
    await client.leave();
    assert.ok(existsSync(lockFile(cwd)), "sin CYBER_PROYECTO_HOST el daemon sigue vivo");
    process.env.CYBER_PROYECTO_HOST = "/h/proyecto";
    client = await connectDaemon(cwd, { spawn: false });
    await client.leave();
    assert.ok(!existsSync(lockFile(cwd)), "el candado se soltó antes de salir");
    const b = new Daemon({ cwd, autoResume: false }); // otro contenedor: no hay ProjectLocked
    await b.close();
  } finally {
    await a.close();
  }
});

test("Docker: el cliente recibe SIGTERM o SIGHUP, hace leave() y el candado queda suelto", async () => {
  for (const signal of ["SIGTERM", "SIGHUP"] as const) {
    const cwd = project();
    const a = new Daemon({ cwd, autoResume: false });
    await a.listen();
    const script = join(cwd, "cliente.mjs");
    writeFileSync(script, `import { connectDaemon } from ${JSON.stringify(join(import.meta.dirname, "../src/client.ts"))};\nawait connectDaemon(${JSON.stringify(cwd)}, { spawn: false });\nconsole.log("listo");\nsetInterval(() => {}, 1000);\n`);
    const child = spawn(process.execPath, ["--disable-warning=ExperimentalWarning", script], { env: { ...process.env, CYBER_PROYECTO_HOST: "/h/proyecto" }, stdio: ["ignore", "pipe", "inherit"] });
    try {
      await new Promise((resolve) => child.stdout.once("data", resolve));
      assert.ok(existsSync(lockFile(cwd)));
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill(signal);
      await exited;
      assert.ok(!existsSync(lockFile(cwd)), `${signal}: el candado se soltó`);
      await new Daemon({ cwd, autoResume: false }).close(); // otro contenedor: sin ProjectLocked
    } finally {
      child.kill("SIGKILL");
      await a.close();
    }
  }
});

test("Docker: cyber -p sale con el candado suelto y el error de falta de clave dice «cyber orobas»", () => {
  const cwd = project();
  const env: NodeJS.ProcessEnv = { ...process.env, CYBER_PROYECTO_HOST: cwd, CYBER_CREDENTIALS_DIR: mkdtempSync(join(tmpdir(), "cred-")), LC_ALL: "es_AR.UTF-8" };
  delete env.OROBAS_API_KEY;
  delete env.CYBER_SECRETS_KEY;
  const run = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", CLI, "-p", "hola", "-m", "orobas/x", "-C", cwd], { encoding: "utf8", env, timeout: 30_000 });
  assert.match(run.stderr, /usá cyber orobas/);
  assert.doesNotMatch(run.stderr, /usá \/orobas/);
  assert.ok(!existsSync(lockFile(cwd)), "el candado quedó suelto al salir");
});

test("Docker: un candado vivo ajeno escribe arranque.err con el mensaje de esperar", () => {
  const cwd = project();
  const release = lockProject(cwd);
  try {
    spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", CLI, "daemon", "-C", cwd], { timeout: 20_000, env: { ...process.env, CYBER_PROYECTO_HOST: cwd, LC_ALL: "es_AR.UTF-8" } });
    assert.match(readFileSync(join(runtimeDir(cwd), "arranque.err"), "utf8"), /30 s.*esperá unos segundos/);
  } finally {
    release();
  }
});

// I4
test("cliente: un daemon que tarda más de 6 s en arrancar (mudanza larga) no se da por caído", async () => {
  const cwd = project();
  process.env.CYBER_TEST_DEMORA_ARRANQUE = "7500";
  const client = await connectDaemon(cwd);
  try {
    assert.ok(client.hello.build);
  } finally {
    await client.ask("shutdown", { force: true }).catch(() => undefined);
    client.close();
  }
});

test("migrateLegacy renueva el latido del candado mientras copia y verifica", () => {
  const cwd = project();
  mkdirSync(join(cwd, ".cyber", "memory"), { recursive: true });
  writeFileSync(join(cwd, ".cyber", "memory", "a.md"), "nota");
  const release = lockProject(cwd);
  try {
    const old = new Date(Date.now() - 25_000);
    utimesSync(lockFile(cwd), old, old);
    assert.equal(migrateLegacy(cwd).moved, true);
    assert.ok(Date.now() - statSync(lockFile(cwd)).mtimeMs < 5000);
  } finally {
    release();
  }
});

// I5
test("runtimeDir: por usuario, 0700, corto y un socket de nombre largo sigue bajo 100 bytes", () => {
  process.env.XDG_RUNTIME_DIR = mkdtempSync(join(tmpdir(), "rt-"));
  const cwd = mkdtempSync(join(tmpdir(), "cyber-" + "x".repeat(120)));
  const dir = runtimeDir(cwd);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.match(dir, /elevate-cyber-\d+\/[0-9a-f]{16}$/);
  assert.ok(socketPath(cwd).length < 100, socketPath(cwd));
});

test("runtimeDir: rechaza una carpeta adelantada con otros permisos o un enlace", () => {
  const base = mkdtempSync(join(tmpdir(), "rt-"));
  process.env.XDG_RUNTIME_DIR = base;
  const parent = join(base, `elevate-cyber-${process.getuid!()}`);
  mkdirSync(parent, { mode: 0o755 });
  chmodSync(parent, 0o755);
  assert.throws(() => runtimeDir(project()), /carpeta privada|private folder/);
  const other = mkdtempSync(join(tmpdir(), "rt-"));
  process.env.XDG_RUNTIME_DIR = other;
  symlinkSync(mkdtempSync(join(tmpdir(), "ajena-")), join(other, `elevate-cyber-${process.getuid!()}`));
  assert.throws(() => runtimeDir(project()), /carpeta privada|private folder/);
});

// I6
function fakeKeyring(env: Record<string, string> = {}) {
  const bin = mkdtempSync(join(tmpdir(), "bin-"));
  const log = join(bin, "log");
  writeFileSync(log, "");
  writeFileSync(join(bin, "secret-tool"), `#!/bin/sh\necho "$1" >> "${log}"\ncase "$1" in\n lookup) [ -n "$ST_SLEEP" ] && sleep "$ST_SLEEP"; [ -n "$ST_KEY" ] && { printf '%s' "$ST_KEY"; exit 0; }; exit \${ST_RC:-1};;\n store) cat >"${bin}/guardada"; exit 0;;\nesac\n`, { mode: 0o755 });
  process.env.PATH = `${bin}:/usr/bin:/bin`;
  delete process.env.CYBER_SECRETS_KEY;
  process.env.CYBER_CREDENTIALS_DIR = mkdtempSync(join(tmpdir(), "cred-"));
  Object.assign(process.env, env);
  return { calls: () => readFileSync(log, "utf8").split("\n").filter(Boolean) };
}
const KEY = Buffer.alloc(32, 7).toString("base64");
const encrypted = (name = "orobas") => {
  process.env.CYBER_SECRETS_KEY = KEY;
  writeSecret(name, "oro_abc");
  delete process.env.CYBER_SECRETS_KEY;
};

test("secretos: existe, no se puede descifrar → «locked»; no existe → «none»", () => {
  fakeKeyring();
  assert.equal(secretState("orobas"), "none");
  encrypted();
  assert.equal(secretState("orobas"), "locked");
  assert.equal(readSecret("orobas"), undefined);
  process.env.CYBER_SECRETS_KEY = KEY;
  assert.equal(secretState("orobas"), "ok");
});

test("secretos: writeSecret no pisa un archivo cifrado si no hay llave", () => {
  fakeKeyring();
  encrypted();
  const path = join(credentialsDir(), "orobas.secreto");
  const before = readFileSync(path, "utf8");
  assert.throws(() => writeSecret("orobas", "otra"), /cifrada|encrypted/);
  assert.equal(readFileSync(path, "utf8"), before);
});

test("secretos: leer nunca genera una llave; escribir sí, una sola vez", () => {
  const ring = fakeKeyring();
  assert.equal(secretsKey(), undefined);
  assert.equal(secretState("orobas"), "none");
  assert.deepEqual(ring.calls().filter((c) => c === "store"), []);
  assert.equal(writeSecret("orobas", "oro_abc").encrypted, true);
  assert.equal(ring.calls().filter((c) => c === "store").length, 1);
  assert.equal(readSecret("orobas"), "oro_abc"); // la llave quedó en memoria del proceso
  assert.equal(ring.calls().filter((c) => c === "lookup").length, 2); // la de leer y la de escribir; la lectura posterior sale de memoria
});

test("secretos: si el llavero falla por otra razón que «no hay entrada» no se inventa otra llave", () => {
  const ring = fakeKeyring({ ST_RC: "2" });
  assert.throws(() => writeSecret("orobas", "oro_abc"), /llavero|keyring/);
  assert.deepEqual(ring.calls().filter((c) => c === "store"), []);
  assert.equal(existsSyncSecret(), false);
});
const existsSyncSecret = () => existsSync(join(credentialsDir(), "orobas.secreto"));

test("secretos: secret-tool colgado se corta a los ~3 s", () => {
  fakeKeyring({ ST_SLEEP: "10" });
  const started = Date.now();
  assert.throws(() => secretsKey(), /llavero|keyring/);
  assert.ok(Date.now() - started < 6000);
});

test("cuenta: el estado dice «cifrada, llavero bloqueado» y guardar se rechaza", async () => {
  fakeKeyring();
  encrypted();
  const cwd = project();
  const daemon = new Daemon({ cwd, autoResume: false });
  await daemon.listen();
  const client = await connectDaemon(cwd, { spawn: false });
  try {
    assert.match((await client.ask("account", { service: "orobas", action: "status" })).join(), /cifrada, llavero bloqueado|encrypted, keyring locked/);
    await assert.rejects(client.ask("account", { service: "orobas", action: "save", value: "nueva" }), /cifrada|encrypted/);
  } finally {
    client.close();
    await daemon.close();
  }
});

// I7 (regla del 22/11/2026: la cuenta la piden sólo los modelos de la suscripción)
for (const [nombre, cambio, pide] of [
  ["con una clave propia de otro proveedor y sin clave de orobas, la TUI no la pide", { provider: "anthropic", apiKeyEnv: "ANTHROPIC_API_KEY" }, false],
  ["con un modelo local y sin clave de orobas, la TUI no la pide", { provider: "ollama", apiKeyEnv: undefined }, false],
  ["con un modelo de la suscripción y sin clave de orobas, la TUI la pide", { provider: "orobas", apiKeyEnv: "OROBAS_API_KEY" }, true],
] as const) {
  test(nombre, async () => {
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OROBAS_API_KEY;
    fakeKeyring();
    const cwd = project();
    const provider = resolveProvider("faux");
    provider.model = { ...provider.model, ...cambio };
    const daemon = new Daemon({ cwd, autoResume: false, resolve: () => provider });
    await daemon.listen();
    const client = await connectDaemon(cwd, { spawn: false });
    try {
      await client.attach({ session: "new" });
      assert.equal(client.status.needsKey, pide);
      assert.equal(client.status.hasKey, false);
    } finally {
      client.close();
      await daemon.close();
    }
  });
}

// M2
test("carpetas de datos y de credenciales quedan 0700 aunque ya existieran", () => {
  const cred = mkdtempSync(join(tmpdir(), "cred-"));
  chmodSync(cred, 0o755);
  process.env.CYBER_CREDENTIALS_DIR = cred;
  credentialsDir();
  assert.equal(statSync(cred).mode & 0o777, 0o700);
  const data = mkdtempSync(join(tmpdir(), "datos-"));
  chmodSync(data, 0o755);
  process.env.CYBER_DATA_DIR = data;
  const cwd = project();
  registerProject(cwd);
  assert.equal(statSync(dataDir()).mode & 0o777, 0o700);
  assert.equal(statSync(join(data, "proyectos", projectId(cwd))).mode & 0o777, 0o700);
});
