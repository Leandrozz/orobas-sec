import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { credentialsDir, readSecret, writeSecret } from "../src/secretos.ts";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { connectDaemon } from "../src/client.ts";
import { Daemon, socketPath } from "../src/daemon.ts";
import { hostname } from "node:os";
import { backupOnNewVersion, dataDir, shown, hostPath, lockProject, migrateLegacy, ProjectLocked, projectId, runtimeDir } from "../src/datos.ts";
import { Findings } from "../src/findings.ts";
import { Ledger } from "../src/ledger.ts";
import { ScopeStore } from "../src/scope.ts";
import { generateReport } from "../src/report.ts";
import { openStore, projectPaths } from "../src/store.ts";

test("projectId: estable, distinto por ruta y normalizado en Windows", () => {
  assert.equal(projectId("/home/a/mis objetivos"), projectId("/home/a/mis objetivos"));
  assert.notEqual(projectId("/home/a/mis objetivos"), projectId("/home/a/otro"));
  assert.equal(projectId("C:\\Users\\José\\Obj"), projectId("c:/users/josé/obj/"));
});

test("hostPath: CYBER_PROYECTO_HOST solo vale para /proyecto", () => {
  process.env.CYBER_PROYECTO_HOST = "/h/x";
  try {
    assert.equal(hostPath("/proyecto"), "/h/x");
    assert.notEqual(hostPath("/otro"), "/h/x");
  } finally {
    delete process.env.CYBER_PROYECTO_HOST;
  }
});

test("socket en runtimeDir, fuera del proyecto y de la carpeta de datos", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-sock-"));
  assert.ok(socketPath(cwd).startsWith(runtimeDir(cwd)));
  assert.ok(!socketPath(cwd).startsWith(cwd));
  assert.ok(!socketPath(cwd).startsWith(dataDir()));
  assert.ok(projectPaths(cwd).root.startsWith(dataDir()));
});

test("lockProject: el segundo falla mientras el primero vive y se puede retomar al liberar", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-lock-"));
  const release = lockProject(cwd);
  assert.throws(() => lockProject(cwd), /ya está abierto|already open/);
  release();
  lockProject(cwd)();
});

test("lockProject: un candado sin latido reciente se toma", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-lock-"));
  lockProject(cwd);
  const lock = join(projectPaths(cwd).root, "daemon.lock");
  const old = new Date(Date.now() - 60_000);
  utimesSync(lock, old, old);
  lockProject(cwd)();
});

test("generateReport escribe en <cwd>/cyber-informes/", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-inf-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  const report = await generateReport({ paths, db, artifacts, findings, scope: new ScopeStore(db), ledger: new Ledger(db) });
  db.close();
  assert.equal(join(report.path, ".."), join(cwd, "cyber-informes"));
  assert.ok(existsSync(report.path));
});

function foreignLock(cwd: string, body: string, ageMs: number) {
  const lock = join(projectPaths(cwd).root, "daemon.lock");
  mkdirSync(projectPaths(cwd).root, { recursive: true });
  writeFileSync(lock, body);
  const at = new Date(Date.now() - ageMs);
  utimesSync(lock, at, at);
  return lock;
}
const fresh = () => mkdtempSync(join(tmpdir(), "cyber-lock-"));

test("lockProject: candado reciente de otro host se rechaza", () => {
  const cwd = fresh();
  foreignLock(cwd, JSON.stringify({ host: "otra-maquina", pid: process.pid }), 0);
  assert.throws(() => lockProject(cwd), /ya está abierto|already open/);
});

test("lockProject: pid muerto en el mismo host se toma de inmediato", () => {
  const cwd = fresh();
  foreignLock(cwd, JSON.stringify({ host: hostname(), pid: 2 ** 22 + 12345 }), 0);
  lockProject(cwd)();
});

test("lockProject: candado vencido de otro host se toma", () => {
  const cwd = fresh();
  foreignLock(cwd, JSON.stringify({ host: "otra-maquina", pid: 1 }), 31_000);
  lockProject(cwd)();
});

test("lockProject: archivo vacío y reciente se respeta, no se borra", () => {
  const cwd = fresh();
  const lock = foreignLock(cwd, "", 0);
  assert.throws(() => lockProject(cwd), /ya está abierto|already open/);
  assert.ok(existsSync(lock));
});

test("lockProject: sin enlaces duros (EPERM) publica con creación exclusiva", () => {
  const cwd = fresh();
  const noLink = () => {
    throw Object.assign(new Error("sin enlaces"), { code: "EPERM" });
  };
  const release = lockProject(cwd, noLink);
  const lock = join(projectPaths(cwd).root, "daemon.lock");
  assert.equal(JSON.parse(readFileSync(lock, "utf8")).pid, process.pid);
  assert.throws(() => lockProject(cwd, noLink), /ya está abierto|already open/);
  release();
  assert.ok(!existsSync(lock));
});

test("lockProject: un candado tomado por otro no lo borra el dueño anterior", () => {
  const cwd = fresh();
  const release = lockProject(cwd);
  const lock = join(projectPaths(cwd).root, "daemon.lock");
  const theirs = JSON.stringify({ host: "otra-maquina", pid: 7, desde: "2030-01-01T00:00:00.000Z" });
  writeFileSync(lock, theirs);
  release();
  assert.equal(readFileSync(lock, "utf8"), theirs);
});

const sha256 = (data: string) => createHash("sha256").update(data).digest("hex");
function legacyProject() {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-mud-"));
  const old = join(cwd, ".cyber");
  mkdirSync(join(old, "memory", "records"), { recursive: true });
  mkdirSync(join(old, "artifacts", "sha256"), { recursive: true });
  mkdirSync(join(old, "informes"), { recursive: true });
  const db = new DatabaseSync(join(old, "cyber.db"));
  db.exec("pragma journal_mode=WAL; create table sessions(id text); create table findings(id text); create table events(id text); insert into sessions values('a'),('b')");
  db.close();
  writeFileSync(join(old, "memory", "records", "a.toon"), "nota");
  writeFileSync(join(old, "artifacts", "sha256", sha256("arte")), "arte");
  writeFileSync(join(old, "informes", "r.md"), "# r");
  writeFileSync(join(old, "uso-1.json"), "{}");
  return cwd;
}
const sessions = (cwd: string) => {
  const db = new DatabaseSync(projectPaths(cwd).db);
  try {
    return (db.prepare("select count(*) n from sessions").get() as { n: number }).n;
  } finally {
    db.close();
  }
};

test("migrateLegacy: copia, verifica y borra .cyber", () => {
  const cwd = legacyProject();
  assert.deepEqual(migrateLegacy(cwd), { moved: true, notice: undefined });
  const p = projectPaths(cwd);
  assert.equal(sessions(cwd), 2);
  assert.equal(readFileSync(join(p.records, "a.toon"), "utf8"), "nota");
  assert.equal(sha256(readFileSync(join(p.artifacts, sha256("arte")), "utf8")), sha256("arte"));
  assert.ok(existsSync(join(cwd, "cyber-informes", "r.md")) && existsSync(join(cwd, "cyber-informes", "uso-1.json")));
  assert.ok(!existsSync(join(cwd, ".cyber")));
});

test("migrateLegacy: un artefacto corrupto en el destino no borra nada", () => {
  const cwd = legacyProject();
  const r = migrateLegacy(cwd, (root) => writeFileSync(join(root, "artifacts", "sha256", sha256("arte")), "corrupto"));
  assert.equal(r.moved, false);
  assert.ok(r.notice);
  assert.ok(existsSync(join(cwd, ".cyber", "cyber.db")));
  // al reintentar sin falla, termina bien y sin duplicar
  assert.equal(migrateLegacy(cwd).moved, true);
  assert.equal(sessions(cwd), 2);
});

test("migrateLegacy: una copia parcial sin marca se completa sin duplicar", () => {
  const cwd = legacyProject();
  const root = projectPaths(cwd).root;
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "mudanza.parcial"), "");
  const partial = new DatabaseSync(join(root, "cyber.db"));
  partial.exec("create table sessions(id text); insert into sessions values('a')");
  partial.close();
  assert.equal(migrateLegacy(cwd).moved, true);
  assert.equal(sessions(cwd), 2);
});

test("migrateLegacy: base vacía en el destino sin marcas se aparta y se migra; con datos no se pisa", () => {
  const cwd = legacyProject();
  const root = projectPaths(cwd).root;
  openStore(projectPaths(cwd)).close(); // lo que dejó el build anterior: base nueva y vacía
  const moved = migrateLegacy(cwd);
  assert.equal(moved.moved, true);
  assert.match(moved.notice ?? "", /cyber\.db\.vacia-/);
  assert.equal(sessions(cwd), 2);
  assert.ok(readdirSync(root).some((f) => f.startsWith("cyber.db.vacia-")));

  const otro = legacyProject();
  const db = openStore(projectPaths(otro));
  db.exec("insert into sessions(id,started_at,model) values('z','x','m')");
  db.close();
  const r = migrateLegacy(otro);
  assert.equal(r.moved, false);
  assert.ok(r.notice);
  assert.ok(existsSync(join(otro, ".cyber", "cyber.db")));
  assert.equal(sessions(otro), 1);
});

test("migrateLegacy: una .cyber que reaparece con datos que el destino no tiene sobrevive", () => {
  const cwd = legacyProject();
  assert.equal(migrateLegacy(cwd).moved, true);
  // misma ruta: se recrea .cyber en cwd con una sesión extra
  const old = join(cwd, ".cyber");
  mkdirSync(old, { recursive: true });
  const db = new DatabaseSync(join(old, "cyber.db"));
  db.exec("create table sessions(id text); insert into sessions values('a'),('nueva')");
  db.close();
  const r = migrateLegacy(cwd);
  assert.equal(r.moved, false);
  assert.ok(r.notice);
  assert.ok(existsSync(join(old, "cyber.db")));
  // si ya está todo en el destino, se borra
  const ok = new DatabaseSync(join(old, "cyber.db"));
  ok.exec("delete from sessions where id='nueva'");
  ok.close();
  assert.equal(migrateLegacy(cwd).moved, true);
  assert.ok(!existsSync(old));
});

test("migrateLegacy: con un daemon viejo escuchando no se muda", async () => {
  const cwd = legacyProject();
  const server = createServer();
  await new Promise<void>((done) => server.listen(join(cwd, ".cyber", "daemon.sock"), done));
  try {
    const r = migrateLegacy(cwd);
    assert.equal(r.moved, false);
    assert.ok(r.notice);
    assert.ok(existsSync(join(cwd, ".cyber", "cyber.db")));
  } finally {
    server.close();
  }
});

test("migrateLegacy: credenciales viejas pasan al almacén; si ya había, gana el almacén", () => {
  const cwd = legacyProject();
  const h1 = join(cwd, ".cyber", "config", "elevate-cyber");
  mkdirSync(h1, { recursive: true });
  writeFileSync(join(h1, "hackerone.json"), JSON.stringify({ username: "u", token: "t" }));
  mkdirSync(join(cwd, ".cyber", "plataformas", "gh"), { recursive: true });
  writeFileSync(join(cwd, ".cyber", "plataformas", "gh", "s"), "sesion");
  const first = migrateLegacy(cwd);
  assert.equal(first.moved, true, first.notice ?? "");
  assert.deepEqual(JSON.parse(readSecret("hackerone")!), { username: "u", token: "t" });
  assert.equal(readFileSync(join(credentialsDir(), "plataformas", "gh", "s"), "utf8"), "sesion");
  assert.ok(!existsSync(join(cwd, ".cyber")));

  const otro = legacyProject();
  mkdirSync(join(otro, ".cyber", "config", "elevate-cyber"), { recursive: true });
  writeFileSync(join(otro, ".cyber", "config", "elevate-cyber", "hackerone.json"), JSON.stringify({ username: "x", token: "y" }));
  const r = migrateLegacy(otro);
  assert.equal(r.moved, true);
  assert.ok(r.notice);
  assert.equal(JSON.parse(readSecret("hackerone")!).username, "u");
  assert.ok(!existsSync(join(otro, ".cyber")));
});

test("backupOnNewVersion: respalda al cambiar de build, deja 3 y no repite el mismo", () => {
  const cwd = fresh();
  openStore(projectPaths(cwd)).close();
  const dir = join(projectPaths(cwd).root, "respaldos");
  backupOnNewVersion(cwd, "b1");
  const made = backupOnNewVersion(cwd, "b2");
  assert.ok(made && /cyber-b1-\d+\.db$/.test(made));
  assert.equal(backupOnNewVersion(cwd, "b2"), undefined);
  for (const b of ["b3", "b4", "b5"]) backupOnNewVersion(cwd, b);
  const left = readdirSync(dir);
  assert.equal(left.length, 3);
  assert.ok(!left.some((f) => f.startsWith("cyber-b1-")));
});

test("migrateLegacy: tras un fallo el daemon no abre la base nueva y el reintento no borra nada del destino", async () => {
  const cwd = legacyProject();
  const r = migrateLegacy(cwd, (root) => writeFileSync(join(root, "artifacts", "sha256", sha256("arte")), "corrupto"));
  assert.equal(r.moved, false);
  const server = createServer(); // un daemon viejo vivo hace que el siguiente intento también quede pendiente
  await new Promise<void>((done) => server.listen(join(cwd, ".cyber", "daemon.sock"), done));
  try {
    assert.throws(() => new Daemon({ cwd, autoResume: false }), /No se mudó|was not moved/);
  } finally {
    server.close();
  }
  assert.equal(sessions(cwd), 2); // la base parcial quedó tal cual: nadie escribió ahí
  rmSync(join(cwd, ".cyber", "daemon.sock"), { force: true });
  assert.equal(migrateLegacy(cwd).moved, true);
  const root = projectPaths(cwd).root;
  const apartada = readdirSync(root).find((f) => /^cyber\.db\.parcial-\d+$/.test(f));
  assert.ok(apartada);
  assert.ok(readdirSync(join(root, "artifacts", "sha256")).some((f) => f.includes(".parcial-")));
  assert.equal(sessions(cwd), 2);
});

test("migrateLegacy: si no se puede comprobar el daemon viejo, no se muda", () => {
  const cwd = legacyProject();
  writeFileSync(join(cwd, ".cyber", "daemon.sock"), "");
  assert.equal(migrateLegacy(cwd, undefined, () => null).moved, false);
  assert.ok(existsSync(join(cwd, ".cyber", "cyber.db")));
  assert.equal(migrateLegacy(cwd, undefined, () => 3).moved, true);
});

test("migrateLegacy: una base corrupta en el destino devuelve aviso, no lanza", () => {
  const cwd = legacyProject();
  mkdirSync(projectPaths(cwd).root, { recursive: true });
  writeFileSync(projectPaths(cwd).db, "esto no es sqlite, ".repeat(500));
  const r = migrateLegacy(cwd);
  assert.equal(r.moved, false);
  assert.ok(r.notice);
  assert.ok(existsSync(join(cwd, ".cyber", "cyber.db")));
});

test("migrateLegacy: un archivo desconocido de .cyber termina en legacy-sobrante", () => {
  const cwd = legacyProject();
  writeFileSync(join(cwd, ".cyber", "raro.txt"), "no lo conocía");
  assert.equal(migrateLegacy(cwd).moved, true);
  assert.equal(readFileSync(join(projectPaths(cwd).root, "legacy-sobrante", "raro.txt"), "utf8"), "no lo conocía");
  assert.ok(!existsSync(join(cwd, ".cyber")));
});

test("lockProject: el respaldo sin enlaces crea el archivo 0600", () => {
  const cwd = fresh();
  const release = lockProject(cwd, () => {
    throw Object.assign(new Error("x"), { code: "ENOTSUP" });
  });
  assert.equal(statSync(join(projectPaths(cwd).root, "daemon.lock")).mode & 0o777, 0o600);
  release();
});

test("cliente: con un daemon viejo corriendo el error trae el paso a seguir", async () => {
  const cwd = legacyProject();
  const server = createServer();
  await new Promise<void>((done) => server.listen(join(cwd, ".cyber", "daemon.sock"), done));
  try {
    await assert.rejects(connectDaemon(cwd), /cerrá la otra sesión|close the other cyber session/);
  } finally {
    server.close();
  }
  assert.ok(existsSync(join(cwd, ".cyber", "cyber.db")));
});

test("cliente: con una base nueva con datos el error dice qué mover", async () => {
  const cwd = legacyProject();
  const db = openStore(projectPaths(cwd));
  db.exec("insert into sessions(id,started_at,model) values('z','x','m')");
  db.close();
  await assert.rejects(connectDaemon(cwd), /mové|move .* aside/);
  assert.ok(existsSync(join(cwd, ".cyber", "cyber.db")));
  assert.equal(sessions(cwd), 1);
});

test("migrateLegacy: un sobrante con el mismo nombre y otro contenido se guarda con sufijo", () => {
  const cwd = legacyProject();
  const dir = join(projectPaths(cwd).root, "legacy-sobrante");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "raro.txt"), "otro");
  writeFileSync(join(cwd, ".cyber", "raro.txt"), "nuevo");
  assert.equal(migrateLegacy(cwd).moved, true);
  assert.equal(readFileSync(join(dir, "raro.txt"), "utf8"), "otro");
  assert.ok(readdirSync(dir).some((f) => /^raro\.txt-\d+$/.test(f)));
});

test("Daemon: con el candado tomado lanza ProjectLocked y no mueve nada", () => {
  const cwd = legacyProject();
  const release = lockProject(cwd);
  try {
    assert.throws(() => new Daemon({ cwd, autoResume: false }), ProjectLocked);
    assert.ok(existsSync(join(cwd, ".cyber", "cyber.db")));
    assert.ok(!existsSync(projectPaths(cwd).db));
    assert.ok(!existsSync(join(projectPaths(cwd).root, "mudanza.parcial")));
  } finally {
    release();
  }
});

test("cyber daemon: con el candado tomado no escribe arranque.err", () => {
  const cwd = legacyProject();
  const release = lockProject(cwd);
  try {
    const run = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "src", "cli.ts"), "daemon", "-C", cwd], { timeout: 20_000 });
    assert.notEqual(run.status, 0);
    assert.ok(!existsSync(join(runtimeDir(cwd), "arranque.err")));
  } finally {
    release();
  }
});

test("Daemon: si el constructor falla libera el candado", () => {
  const cwd = legacyProject();
  mkdirSync(projectPaths(cwd).root, { recursive: true });
  writeFileSync(projectPaths(cwd).db, "no es sqlite ".repeat(500));
  assert.throws(() => new Daemon({ cwd, autoResume: false }), /No se mudó|was not moved/);
  lockProject(cwd)();
});

test("migrateLegacy: el aviso de «tienen datos» muestra las rutas del host", () => {
  const otro = legacyProject();
  const db = openStore(projectPaths(otro));
  db.exec("insert into sessions(id,started_at,model) values('z','x','m')");
  db.close();
  const real = projectPaths(otro).root;
  const host = "C:\\Users\\x\\AppData\\Local\\elevate-cyber";
  process.env.CYBER_DATOS_HOST = host;
  try {
    const r = migrateLegacy(otro);
    assert.equal(r.moved, false);
    const rel = real.slice(dataDir().length).split("/").filter(Boolean).join("\\");
    assert.ok((r.notice ?? "").includes(`${host}\\${rel}\\cyber.db`), r.notice ?? "");
    assert.ok(!(r.notice ?? "").includes(dataDir()), r.notice ?? "");
  } finally {
    delete process.env.CYBER_DATOS_HOST;
  }
});

test("shown: muestra rutas del host y deja intactas las ajenas", () => {
  process.env.CYBER_DATOS_HOST = "C:\\Users\\x\\datos";
  try {
    assert.equal(shown(join(dataDir(), "proyectos", "a"), "/proyecto"), "C:\\Users\\x\\datos\\proyectos\\a");
    assert.equal(shown("/otra/cosa", "/proyecto"), "/otra/cosa");
  } finally {
    delete process.env.CYBER_DATOS_HOST;
  }
});
