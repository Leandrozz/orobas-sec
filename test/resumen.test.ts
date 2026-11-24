import "./datos-tmp.ts";
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { dataDir, projectId } from "../src/datos.ts";
import { listSessions } from "../src/resumen.ts";

const dir = mkdtempSync(join(tmpdir(), "cyber-resumen-"));
const projects: Record<string, unknown> = {};
function addProject(nombre: string, sessions: [string, string, string][], corrupt = false) {
  const ruta = join(dir, nombre);
  const id = projectId(ruta);
  mkdirSync(join(dataDir(), "proyectos", id), { recursive: true });
  const file = join(dataDir(), "proyectos", id, "cyber.db");
  if (corrupt) writeFileSync(file, "esto no es sqlite");
  else {
    const db = new DatabaseSync(file);
    db.exec("create table sessions(id text primary key, started_at text not null, model text not null, title text); create table messages(session_id text not null, seq integer not null, json text not null, primary key(session_id, seq))");
    for (const [sid, at, title] of sessions) db.prepare("insert into sessions values(?,?,?,?)").run(sid, at, "m", title);
    db.close();
  }
  projects[id] = { ruta, nombre, ultimoUso: "x" };
  return ruta;
}
const rutaA = addProject("a", [["sa1", "2026-01-01T10:00:00Z", "uno"], ["sa2", "2026-01-03T10:00:00Z", "tres"]]);
addProject("b", [["sb1", "2026-01-02T10:00:00Z", "dos"]]);
addProject("rota", [], true);
writeFileSync(join(dataDir(), "proyectos.json"), JSON.stringify(projects));

test("listSessions junta los proyectos, por fecha descendente, y saltea la base corrupta", () => {
  assert.deepEqual(listSessions().map((s) => s.session), ["sa2", "sb1", "sa1"]);
});

test("elegir una sesión de otro proyecto dentro de Docker imprime el contrato y sale con 75", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-otro-"));
  const run = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "../src/cli.ts"), "--resumen", "-C", cwd], { input: "1\n", encoding: "utf8", env: { ...process.env, CYBER_PROYECTO_HOST: cwd } });
  assert.equal(run.status, 75);
  assert.match(run.stdout, new RegExp(`CYBER_REABRIR\\t${rutaA}\\tsa2\\n`));
  const file = join(dataDir(), "reabrir.txt");
  assert.equal(readFileSync(file, "utf8"), `${rutaA}\tsa2\n`);
  assert.equal(statSync(file).mode & 0o777, 0o600);
});

test("una ruta con tabulación no se reabre: sin archivo ni contrato", () => {
  const rutaMala = addProject("m\tala", [["sm1", "2026-02-01T10:00:00Z", "mala"]]);
  writeFileSync(join(dataDir(), "proyectos.json"), JSON.stringify(projects));
  rmSync(join(dataDir(), "reabrir.txt"), { force: true });
  const cwd = mkdtempSync(join(tmpdir(), "cyber-otro-"));
  const run = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "../src/cli.ts"), "--resumen", "-C", cwd], { input: "1\n", encoding: "utf8", env: { ...process.env, CYBER_PROYECTO_HOST: cwd } });
  assert.notEqual(run.status, 75);
  assert.ok(!run.stdout.includes("CYBER_REABRIR"));
  assert.ok(!existsSync(join(dataDir(), "reabrir.txt")));
  assert.ok(rutaMala.includes("\t"));
});
