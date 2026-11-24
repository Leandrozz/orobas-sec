import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { Findings } from "../src/findings.ts";
import { Ledger } from "../src/ledger.ts";
import type { Message } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";
import { logEvent, openStore, projectPaths } from "../src/store.ts";
import { exportTrajectories, followUp } from "../src/trayectorias.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};

test("seguimiento del operador: seguí, corrección, nuevo, fin", () => {
  assert.equal(followUp("seguí con eso"), "seguí");
  assert.equal(followUp("Dale, continuá"), "seguí");
  assert.equal(followUp("no, eso está mal: la ruta era otra"), "corrección");
  assert.equal(followUp("Pará, frená ahí"), "corrección");
  assert.equal(followUp("ahora revisá el login"), "nuevo");
  assert.equal(followUp(undefined), "fin");
});

test("la exportación trae la sesión entera, tachada y con etiquetas; anónimo reemplaza los hosts del alcance", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-tray-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new" });
    const host = [...daemon.hosts.values()][0]!;
    host.engine.scope.edit({ include: ["tienda.ejemplo.test"] });
    provider.faux!.queue = [
      { toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }] },
      { text: "Hay 2 candidatos en tienda.ejemplo.test con la cookie session=SECRETO-LARGO-123456." },
      { text: "Listo, sigo." },
    ];
    client.send("Revisá permisos en tienda.ejemplo.test");
    await until(() => !host.engine.agent.running && host.engine.agent.messages.length >= 3);
    client.send("seguí");
    await until(() => !host.engine.agent.running && host.engine.agent.messages.length >= 5);

    const plain = await client.view("trayectorias");
    assert.match(plain[0]!, /^TRAYECTORIAS · 1 sesión · 2 turnos/);
    const anon = await client.view("trayectorias", "anonimo");
    assert.match(anon[2]!, /host-1/);
    const files = readdirSync(join(cwd, "cyber-informes")).filter((name) => name.startsWith("trayectorias-"));
    assert.equal(files.length, 2);
    const anonFile = files.find((name) => name.endsWith("-anonimo.jsonl"))!;
    const lines = readFileSync(join(cwd, "cyber-informes", anonFile), "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    const record = JSON.parse(lines[0]!);
    assert.equal(record.version, 1);
    assert.ok(record.system.includes("Orobas"), "trae el prompt del sistema");
    assert.deepEqual(record.scope.include, ["host-1"]);
    assert.equal(record.labels.turns, 2);
    assert.equal(record.sesion.model, "faux/faux");
    assert.ok(record.labels.consumo, "el consumo de tokens no se tacha");
    const [first, second] = record.turns;
    assert.equal(first.operator, "Revisá permisos en host-1");
    assert.equal(first.labels.follow_up, "seguí");
    assert.equal(second.labels.follow_up, "fin");
    const call = first.messages.find((m: any) => m.role === "assistant" && m.tool_calls.length);
    assert.deepEqual(call.tool_calls[0].arguments, { name: "atlas-permisos" });
    const result = first.messages.find((m: any) => m.role === "tool");
    assert.equal(result.name, "fixture_run");
    assert.equal(result.is_error, false);
    assert.ok(result.content.length > 0);
    const text = JSON.stringify(record);
    assert.doesNotMatch(text, /SECRETO-LARGO-123456/, "la cookie pegada en la respuesta queda tachada");
    assert.doesNotMatch(text, /tienda\.ejemplo\.test/, "el host del alcance no aparece en la versión anónima");
    assert.equal(first.labels.end, "respuesta");
    assert.ok(first.labels.steps >= 2);
    client.close();
  } finally {
    daemon.close();
  }
});

/* ---------- A qué turno va cada evento ---------- */

const user = (content: string, at: number): Message => ({ role: "user", content, at });
const reply = (content: string, at: number): Message => ({ role: "assistant", content, toolCalls: [], stopReason: "stop", provider: "faux", model: "faux", requestId: "r", at });

test("la exportación informa los pedidos pendientes junto al subtotal conocido", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-tray-costo-"));
  const db = openStore(projectPaths(cwd));
  try {
    for (const id of ["parcial", "vacia"]) {
      db.prepare("insert into sessions(id, started_at, model) values(?,?,?)").run(id, "2026-01-01", "faux");
    }
    const insertar = db.prepare(`insert into requests(provider,account,request_id,session_id,worker,model,at,stop_reason,
      input,cache_write,cache_read,output,cost_input,cost_cache_write,cost_cache_read,cost_output)
      values('faux','local',?,'parcial','principal','faux','2026-01-01','stop',2,0,0,0,?,?,?,?)`);
    insertar.run("con-precio", "123456000000", "0", "0", "0");
    insertar.run("sin-precio", null, null, null, null);
    const source = { db, ledger: new Ledger(db), findings: new Findings(db, () => undefined), scope: undefined };
    const result = exportTrajectories(source, "ejemplo", cwd);
    const rows = readFileSync(result.path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    const labels = Object.fromEntries(rows.map((row) => [row.sesion.id, row.labels]));
    assert.equal(labels.parcial.cost_usd, "0.123456");
    assert.equal(labels.parcial.cost_unknown_requests, 1);
    assert.match(labels.vacia.cost_usd, /^0(?:\.0+)?$/);
    assert.equal(labels.vacia.cost_unknown_requests, 0);
  } finally {
    db.close();
  }
});

/** Agrega mensajes con el seq por sesión, como el motor. */
function conversation(db: DatabaseSync) {
  const next = new Map<string, number>();
  return (session: string, message: Message) => {
    const seq = next.get(session) ?? 0;
    next.set(session, seq + 1);
    db.prepare("insert into messages(session_id,seq,json) values(?,?,?)").run(session, seq, JSON.stringify(message));
    return seq;
  };
}

function exportBySession(db: DatabaseSync, cwd: string) {
  const result = exportTrajectories({ db, ledger: new Ledger(db), findings: new Findings(db, () => undefined), scope: undefined }, "p", join(cwd, "cyber-informes"));
  const records = readFileSync(result.path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  return new Map(records.map((record: any) => [record.sesion.id, record.turns.map((turn: any) => ({ end: turn.labels.end, changed: turn.labels.findings_changed.map((item: any) => item.id) }))]));
}

/** Dos sesiones intercaladas: los eventos de B tienen events.seq mayor que todos los mensajes de B (0..5). */
const EXPECTED = (a: string, b: string) => ({
  A: [{ end: "respuesta", changed: [a] }, { end: "respuesta", changed: [] }],
  B: [{ end: "respuesta", changed: [b] }, { end: "detenido", changed: [] }, { end: "respuesta", changed: [] }],
});

test("trayectorias: cada evento cae en su turno aunque events.seq (de toda la base) supere los mensajes de la sesión", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-tray-seq-"));
  const db = openStore(projectPaths(cwd));
  try {
    const findings = new Findings(db, () => undefined);
    const say = conversation(db);
    for (const id of ["A", "B"]) db.prepare("insert into sessions(id, started_at, model) values(?,?,?)").run(id, new Date().toISOString(), "faux/faux");
    const now = Date.now();
    say("A", user("a1", now));
    say("A", reply("ok a1", now));
    for (let i = 0; i < 8; i++) logEvent(db, "A", "relleno", { i }); // empuja el autoincremental de events
    const fa = findings.record({ title: "pista A", kind: "idor", asset: "https://a.test/x", summary: "s", state: "pista" }, "A");
    say("A", user("a2", now));
    say("A", reply("ok a2", now));
    say("B", user("b1", now));
    say("B", reply("ok b1", now));
    const fb = findings.record({ title: "pista B", kind: "idor", asset: "https://b.test/y", summary: "s", state: "pista" }, "B");
    say("B", user("b2", now));
    say("B", reply("ok b2", now));
    logEvent(db, "B", "turn.aborted", {});
    say("B", user("b3", now));
    say("B", reply("ok b3", now));

    const rows = db.prepare("select seq, msg_seq from events where session_id='B' and type in ('finding.changed','turn.aborted') order by seq").all() as Array<{ seq: number; msg_seq: number }>;
    assert.ok(rows.every((row) => row.seq > 5), "el caso del bug: events.seq de B por encima de su último mensaje");
    assert.deepEqual(rows.map((row) => row.msg_seq), [1, 3], "msg_seq: el último mensaje de la sesión al registrar (findings.ts y logEvent)");

    const turns = exportBySession(db, cwd);
    const expected = EXPECTED(fa.id, fb.id);
    assert.deepEqual(turns.get("A"), expected.A);
    assert.deepEqual(turns.get("B"), expected.B);
  } finally {
    db.close();
  }
});

test("trayectorias: una base de antes de msg_seq se migra y sus eventos se ubican por hora, no por events.seq", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-tray-viejo-"));
  const paths = projectPaths(cwd);
  mkdirSync(paths.root, { recursive: true });
  const old = new DatabaseSync(paths.db);
  old.exec(`
    create table sessions(id text primary key, started_at text not null, model text not null, title text);
    create table messages(session_id text not null, seq integer not null, json text not null, primary key(session_id, seq));
    create table events(seq integer primary key autoincrement, session_id text, type text not null, at text not null, payload text not null);`);
  const say = conversation(old);
  const t0 = Date.parse("2026-11-01T10:00:00.000Z");
  const min = (n: number) => t0 + n * 60_000;
  const event = (session: string, type: string, at: number, payload: unknown) =>
    old.prepare("insert into events(session_id,type,at,payload) values(?,?,?,?)").run(session, type, new Date(at).toISOString(), JSON.stringify(payload));
  for (const id of ["A", "B"]) old.prepare("insert into sessions(id, started_at, model) values(?,?,?)").run(id, new Date(t0).toISOString(), "faux/faux");
  say("A", user("a1", min(0)));
  say("A", reply("ok a1", min(1)));
  for (let i = 0; i < 8; i++) event("A", "relleno", min(2), { i });
  event("A", "finding.changed", min(3), { id: "fa", state: "pista" });
  say("A", user("a2", min(10)));
  say("A", reply("ok a2", min(11)));
  say("B", user("b1", min(20)));
  say("B", reply("ok b1", min(21)));
  event("B", "finding.changed", min(22), { id: "fb", state: "pista" });
  say("B", user("b2", min(30)));
  say("B", reply("ok b2", min(31)));
  event("B", "turn.aborted", min(32), {});
  say("B", user("b3", min(40)));
  say("B", reply("ok b3", min(41)));
  old.close();

  openStore(paths).close();
  const db = openStore(paths); // la migración es idempotente
  try {
    const columns = (db.prepare("pragma table_info(events)").all() as Array<{ name: string }>).filter((column) => column.name === "msg_seq");
    assert.equal(columns.length, 1);
    const legacy = db.prepare("select seq, msg_seq from events where session_id='B' order by seq").all() as Array<{ seq: number; msg_seq: number | null }>;
    assert.ok(legacy.every((row) => row.seq > 5 && row.msg_seq === null), "filas viejas: sin msg_seq y con events.seq por encima de los mensajes de B");

    const turns = exportBySession(db, cwd);
    const expected = EXPECTED("fa", "fb");
    assert.deepEqual(turns.get("A"), expected.A);
    assert.deepEqual(turns.get("B"), expected.B);

    logEvent(db, "B", "nuevo", {});
    assert.equal((db.prepare("select msg_seq from events where type='nuevo'").get() as { msg_seq: number }).msg_seq, 5, "lo nuevo ya guarda msg_seq en la base migrada");
  } finally {
    db.close();
  }
});
