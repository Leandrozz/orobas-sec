import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { connectDaemon } from "../src/client.ts";
import { bugcrowdScope, intigritiScope } from "../src/bugcrowd.ts";
import { bountyScope } from "../src/cyber-bounty.ts";
import { Daemon } from "../src/daemon.ts";
import { Engine } from "../src/engine.ts";
import { Findings } from "../src/findings.ts";
import { consultStrong } from "../src/fuerte.ts";
import { translateAssets } from "../src/hackerone.ts";
import { createOperatorTools } from "../src/operador.ts";
import { resolveProvider } from "../src/providers.ts";
import { bloqueReglas, extraerReglas } from "../src/reglas-programa.ts";
import { parseRule, ScopeStore, scopeView } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { createTools } from "../src/tools.ts";
import { Vault } from "../src/vault.ts";
import { HttpClient } from "../src/http.ts";
import { Ledger } from "../src/ledger.ts";

const cita = "Local-only findings are out of scope.";
const honesto = "The setup component is trusted and assumed honest.";
const atacante = "The attacker starts unauthenticated outside the victim machine.";
const signal = new AbortController().signal;
const carpeta = () => mkdtempSync(join(tmpdir(), "cyber-reglas-"));

test("las cuatro importaciones extraen citas con fuente, sin llevar la política completa", async () => {
  const h1 = translateAssets([{ type: "URL", identifier: "https://demo.test", eligible: true, instruction: cita }], "demo");
  assert.equal(h1.reglas.exclusiones[0]?.cita, cita);
  assert.match(h1.reglas.exclusiones[0]!.fuente, /HackerOne demo/);
  const fake = async () => new Response(JSON.stringify({ data: { targets: [{ name: "demo.test" }], policy: `${cita}\n${honesto}\n${atacante}\n${"texto inocuo ".repeat(200)}` } }), { status: 200 });
  const bg = await bugcrowdScope("simulado", "demo", fake as typeof fetch);
  assert.equal(bg.reglas?.honestos[0]?.cita, honesto);
  assert.equal(bg.reglas?.posicionAtacante[0]?.cita, atacante);
  const it = await intigritiScope("simulado", "demo", (async () => new Response(JSON.stringify({ endpoints: [{ uri: "demo.test", type: "inScope" }], policy: cita, rulesOfEngagement: honesto }))) as typeof fetch);
  assert.equal(it.reglas?.exclusiones[0]?.cita, cita);
  const cyber = bountyScope({ id: "demo", name: "Demo", scope_revision: 1, accepting_reports: true, status: "open", policy: `${cita}\n${honesto}`, conduct: { max_requests_per_second: 1, destructive_actions: false, agent_header: "", test_window: "siempre" }, scope: { include: [{ kind: "host", value: "demo.test" }], exclude: [] } });
  assert.equal(cyber.reglas.honestos[0]?.cita, honesto);
  const bloque = bloqueReglas(extraerReglas([{ texto: `${cita}\n${honesto}\n${atacante}\n${"relleno ".repeat(1000)}`, fuente: "política" }]));
  assert.ok(!bloque.includes("relleno"));
  assert.ok(Math.ceil(bloque.length / 4) < 100, `bloque: ${Math.ceil(bloque.length / 4)} tokens aproximados`);
  const saturado = bloqueReglas({ exclusiones: Array.from({ length: 6 }, (_, i) => ({ cita: `Out of scope: ${"x".repeat(140)}${i}`, fuente: "política" })), honestos: Array.from({ length: 3 }, (_, i) => ({ cita: `Trusted component ${i}: ${"x".repeat(125)}`, fuente: "política" })), posicionAtacante: Array.from({ length: 3 }, (_, i) => ({ cita: `Attacker position ${i}: ${"x".repeat(125)}`, fuente: "política" })) });
  assert.ok(Math.ceil(saturado.length / 4) < 650, "el tope de citas mantiene chico incluso el peor bloque permitido");
});

test("el operador cita reglas, persisten en alcance y el candidato justifica su exclusión", async (t) => {
  const dir = carpeta();
  const paths = projectPaths(dir);
  const db = openStore(paths);
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  const scope = new ScopeStore(db, "s1");
  scope.save({ source: "manual", include: [parseRule("demo.test")], exclude: [], notes: "" });
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  const tools = createTools({ vault: new Vault(db, paths.records, paths.notes), artifacts, scope, findings, sessionId: "s1" });
  const settings = createOperatorTools({ scope, ledger: new Ledger(db), http: new HttpClient(artifacts, () => scope.current()), operatorTexts: () => [`Anotá: ${cita}`], h1: () => ({}), report: async () => [] }).find((tool) => tool.name === "session_settings")!;
  await assert.rejects(() => settings.execute({ regla_exclusion: honesto, pedido: `Anotá: ${cita}` }, signal) as Promise<unknown>, /cita debe estar textual/);
  await settings.execute({ regla_exclusion: cita, pedido: `Anotá: ${cita}` }, signal);
  scope.agregarRegla("honestos", honesto);
  assert.equal(new ScopeStore(db, "s1").current()?.reglas?.exclusiones[0]?.fuente, "operador");
  assert.match(scopeView(scope.current()).join("\n"), /Partes asumidas honestas/);
  scope.edit({ include: ["otro.test"] });
  assert.equal(scope.current()?.reglas?.exclusiones[0]?.cita, cita);
  const evidencia = artifacts.put("respuesta simulada", "text/plain", "prueba").hash;
  const record = tools.find((tool) => tool.name === "finding_record")!;
  const update = tools.find((tool) => tool.name === "finding_update")!;
  const base = { state: "candidato", title: "Caso elegible", kind: "control de acceso", asset: "https://demo.test/x", summary: "Respuesta ajena", evidence: [evidencia] };
  assert.throws(() => record.execute(base, signal), /falta exclusion_cercana/);
  assert.throws(() => record.execute({ ...base, exclusion_cercana: cita }, signal), /falta por_que_no_aplica/);
  assert.throws(() => record.execute({ ...base, exclusion_cercana: "otra", por_que_no_aplica: "no es local" }, signal), /cita exacta/);
  const pista = record.execute({ ...base, state: "pista", evidence: [], fuera_modelo_confianza: honesto }, signal);
  assert.match((pista as { text: string }).text, /como pista/);
  const id = findings.list()[0]!.id;
  assert.throws(() => update.execute({ id, state: "candidato", exclusion_cercana: cita, por_que_no_aplica: "no es local", evidence: [evidencia] }, signal), /fuera del modelo/);
  update.execute({ id, fuera_modelo_confianza: "" }, signal);
  update.execute({ id, state: "candidato", exclusion_cercana: cita, por_que_no_aplica: "El caso afecta el servicio remoto, no una instalación local.", evidence: [evidencia] }, signal);
  assert.equal(findings.get(id)?.exclusionCercana, cita);
});

test("/alcance reglas agrega la cita a la sesión visible", async (t) => {
  const dir = carpeta();
  const daemon = new Daemon({ cwd: dir, resolve: () => resolveProvider("faux"), autoResume: false });
  await daemon.listen();
  const cliente = await connectDaemon(dir, { spawn: false });
  t.after(async () => { cliente.close(); await daemon.close(); rmSync(dir, { recursive: true, force: true }); });
  await cliente.attach({ model: "faux" });
  const vista = (await cliente.view("scope", `reglas exclusion ${cita}`)).join("\n");
  assert.match(vista, /Local-only findings are out of scope/);
  assert.match(vista, /operador: \/alcance reglas/);
  assert.match((await cliente.view("scope")).join("\n"), /Local-only findings are out of scope/);
});

test("checkpoint, traspaso y deep_reason reciben el bloque compacto", async (t) => {
  const provider = resolveProvider("faux");
  const dir = carpeta();
  const engine = new Engine({ cwd: dir, provider, strong: provider, autoVerify: false });
  t.after(() => { engine.close(); rmSync(dir, { recursive: true, force: true }); });
  engine.scope.save({ source: "manual", include: [parseRule("demo.test")], exclude: [], notes: "", reglas: extraerReglas([{ texto: `${cita}\n${honesto}\n${atacante}`, fuente: "prueba" }]) });
  assert.match(engine.agent.system, /Una cadena que exige comprometer una parte que el programa da por honesta/);
  assert.match(engine.agent.system, /grieta abierta dentro de las reglas del programa/);
  provider.faux!.queue = [{ text: "uno" }, { text: "dos" }, { text: "tres" }, { text: "cuatro" }];
  for (const mensaje of ["a", "b", "c", "d"]) await engine.send(mensaje);
  provider.faux!.queue = [{ text: "OBJETIVO: seguir." }];
  assert.equal(await engine.compact(), true);
  assert.match(engine.agent.messages[0]!.content, /Local-only findings are out of scope/);
  const handoff = await (engine as any).writeHandoff({ rol: "fuerte", forma: "consulta", nivel: "red", motivo: "operador", detalle: "revisar" }, signal);
  assert.match(handoff.texto, /setup component is trusted/);
  let sistema = "";
  const simulado = { ...provider, transport: async (request: any) => { sistema = request.system; return { role: "assistant" as const, content: "listo", toolCalls: [], stopReason: "stop" as const, at: Date.now(), provider: "faux", model: "faux", requestId: "x" }; } };
  await consultStrong(engine, "pregunta", signal, "fuerte", simulado);
  assert.match(sistema, /The attacker starts unauthenticated/);
  const bloque = bloqueReglas(engine.scope.current()?.reglas);
  assert.ok(Math.ceil(bloque.length / 4) < 100);
});

test("un candidato registrado antes de cargar las reglas acepta escalation y cvss sin exclusion_cercana", async (t) => {
  const dir = carpeta();
  const paths = projectPaths(dir);
  const db = openStore(paths);
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  const scope = new ScopeStore(db, "s1");
  scope.save({ source: "manual", include: [parseRule("demo.test")], exclude: [], notes: "" });
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  const tools = createTools({ vault: new Vault(db, paths.records, paths.notes), artifacts, scope, findings, sessionId: "s1" });
  const record = tools.find((tool) => tool.name === "finding_record")!;
  const update = tools.find((tool) => tool.name === "finding_update")!;
  const evidencia = artifacts.put("respuesta simulada", "text/plain", "prueba").hash;
  record.execute({ state: "candidato", severity: "media", title: "Caso de antes de las reglas", kind: "control de acceso", asset: "https://demo.test/x", summary: "Respuesta ajena", evidence: [evidencia] }, signal);
  const id = findings.list()[0]!.id;
  scope.agregarRegla("exclusiones", cita);
  // src/cierre.ts promete que «limitada» con su nota «se acepta siempre», y pide cvss a los candidatos sin vector.
  update.execute({ id, escalation: "limitada", escalation_note: "Falta una segunda cuenta para escalar." }, signal);
  update.execute({ id, cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" }, signal);
  update.execute({ id, state: "candidato", summary: "Respuesta ajena, confirmada dos veces." }, signal);
  assert.equal(findings.get(id)?.escalation?.state, "limitada");
  assert.match(findings.get(id)?.cvss ?? "", /^CVSS:3\.1\//);
  // Pasar una pista a candidato sigue pidiendo la revisión de la exclusión cercana.
  record.execute({ state: "pista", title: "Reflejo sin probar", kind: "xss", asset: "https://demo.test/y", summary: "Reflejo en un parámetro" }, signal);
  const pista = findings.list().find((item) => item.state === "pista")!.id;
  assert.throws(() => update.execute({ id: pista, state: "candidato", evidence: [evidencia] }, signal), /falta exclusion_cercana/);
});

test("reimportar el programa conserva las citas que agregó el operador", async (t) => {
  const dir = carpeta();
  const db = openStore(projectPaths(dir));
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  const scope = new ScopeStore(db, "s1");
  const delPrograma = "Denial of service attacks are out of scope.";
  const importar = () => scope.saveProgram({ source: "hackerone:demo", include: [parseRule("demo.test")], exclude: [], notes: "", reglas: extraerReglas([{ texto: delPrograma, fuente: "HackerOne demo, activo 1" }]) });
  importar();
  scope.agregarRegla("exclusiones", cita, "operador: /alcance reglas");
  scope.agregarRegla("honestos", honesto);
  const { saved } = importar();
  assert.deepEqual(saved.reglas?.exclusiones.map((item) => item.cita), [delPrograma, cita]);
  assert.deepEqual(saved.reglas?.honestos.map((item) => item.fuente), ["operador"]);
  // Las del programa no se duplican ni se arrastran: las trae la importación nueva.
  const sinCitas = scope.saveProgram({ source: "hackerone:demo", include: [parseRule("demo.test")], exclude: [], notes: "", reglas: extraerReglas([]) }).saved;
  assert.deepEqual(sinCitas.reglas?.exclusiones.map((item) => item.cita), [cita]);
});

test("frases reales de programas: untrusted no es parte honesta y self-hosted no es exclusión", () => {
  // Instrucciones de activos del CSV público de HackerOne (basecamp, nextcloud) y el modelo de amenazas de
  // Node.js (SECURITY.md, la política del programa nodejs en HackerOne).
  const campfire = "[Campfire](https://once.com/campfire) is an installable, self-hosted group chat system designed, built, and backed by 37signals.";
  const nextcloud = "Note that usercontent.apps.nextcloud.com serves potentially untrusted user content and is always setting a Content-Type of attachment.";
  const pares = "Node.js treats data from remote network peers as untrusted, and bugs in parsers or protocol implementations may be security vulnerabilities.";
  const codigo = "Code is trusted by Node.js.";
  const elementos = "Vulnerabilities that require the compromise of these trusted elements are outside the scope of the Node.js threat model.";
  const politica = "Is excluded by policy (e.g., experimental features)";
  const negadas = ["Third-party integrations are not trusted.", "Nothing is excluded from this program.", "Webhooks from non-trusted senders are rejected.", "No se asume que el servidor de correo sea honesto."];
  const reglas = extraerReglas([{ texto: [campfire, nextcloud, pares, codigo, elementos, politica, ...negadas].join("\n"), fuente: "prueba" }]);
  assert.deepEqual(reglas.honestos.map((item) => item.cita), [codigo, elementos]);
  assert.deepEqual(reglas.exclusiones.map((item) => item.cita), [elementos, politica]);
  // Lo que sí excluye un programa sigue entrando, con su negación propia («not eligible», «no se paga»).
  const reales = extraerReglas([{ texto: "Server-side Denial of Service is out of scope as per our Policy.\nIssues that only affect self-hosted instances are not rewarded.\nLos reportes de clickjacking no se pagan.", fuente: "prueba" }]);
  assert.equal(reales.exclusiones.length, 3);
});

test("cyber scope sesiones lista aunque el proyecto todavía no tenga sesiones", async (t) => {
  const dir = carpeta();
  const daemon = new Daemon({ cwd: dir, resolve: () => resolveProvider("faux"), autoResume: false });
  await daemon.listen();
  const cliente = await connectDaemon(dir, { spawn: false });
  t.after(async () => { cliente.close(); await daemon.close(); rmSync(dir, { recursive: true, force: true }); });
  for (const verbo of ["sesiones", "proyecto", "todos"]) assert.match((await cliente.view("scope", verbo)).join("\n"), /ALCANCE POR SESIÓN|SCOPE PER SESSION/);
  // Sin sesiones, lo que necesita un alcance sigue explicando por qué no hay.
  await assert.rejects(() => cliente.view("scope", `reglas exclusion ${cita}`), /No hay sesiones|There are no sessions/);
});
