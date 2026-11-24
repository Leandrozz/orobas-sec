// Pruebas del cierre de la tanda ofensiva: profile_set del operador, github_search con gh
// inyectable, sección «Detección (purple)» del informe y borrador de submission de HackerOne.
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { DetectionLedger } from "../src/deteccion.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { createOperatorTools } from "../src/operador.ts";
import { Ledger } from "../src/ledger.ts";
import { draftReport } from "../src/hackerone.ts";
import { createReconTools } from "../src/recon.ts";
import { generateReport } from "../src/report.ts";
import { ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const signal = new AbortController().signal;

function setup() {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-cierre-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  return { cwd, paths, db, artifacts, findings, close: () => { db.close(); rmSync(cwd, { recursive: true, force: true }); } };
}

test("profile_set: muestra sin argumentos; cambia citando al operador que nombró el perfil; rechaza un perfil no nombrado", async (t) => {
  const context = setup();
  t.after(() => context.close());
  let current = "bounty" as string;
  const tools = Object.fromEntries(createOperatorTools({
    scope: {} as never,
    ledger: {} as never,
    http: {} as never,
    operatorTexts: () => ["pasate al modo defensa para probar las detecciones"],
    h1: () => ({}),
    report: async () => [],
    profile: { get: () => current as never, set: (value) => (current = value) },
  }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const shown = await tools.profile_set!.execute({}, signal);
  assert.match(shown.text, /perfil bounty/);
  const changed = await tools.profile_set!.execute({ perfil: "defensa", pedido: "pasate al modo defensa para probar las detecciones" }, signal);
  assert.equal(changed.details!.perfil, "defensa");
  assert.match(changed.text, /perfil defensa/);
  assert.match(changed.text, /detección: sí/);
  assert.equal(current, "defensa");
  // El operador no nombró el perfil en su mensaje: se rechaza adivinarlo (la cita no coincide).
  await assert.rejects(async () => tools.profile_set!.execute({ perfil: "pentest", pedido: "cambiá lo que quieras" }, signal), /pedido.*no coincide|Sólo el operador/i);
});

test("github_search: dorks vía gh inyectable, deduplicación por repo, pistas de secretos y falla de gh como «sin respuesta»", async (t) => {
  const context = setup();
  t.after(() => context.close());
  let calls = 0;
  const responses = [
    "", // .env: vacío
    '{"repo":"org/repo-a","path":"certs/server.pem","url":"https://github.com/org/repo-a/blob/main/certs/server.pem"}\n{"repo":"org/repo-b","path":".env.example","url":"https://github.com/x"}',
    "", // error de gh (exitCode != 0)
    "",
    '{"repo":"org/repo-a","path":"config/token.json","url":""}',
  ];
  const tools = Object.fromEntries(createReconTools({
    artifacts: context.artifacts,
    runGh: async () => {
      calls++;
      const raw = responses[calls - 1]!;
      if (calls === 3) return { exitCode: 1, stdout: "", stderr: "gh: not logged in" };
      return { exitCode: 0, stdout: raw, stderr: "" };
    },
  }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const result = await tools.github_search!.execute({ dominio: "ejemplo.test" }, signal);
  assert.ok(calls >= 4);
  assert.match(result.text, /org\/repo-a/);
  assert.match(result.text, /pistas? para el operador/); // server.pem y token.json huelen a secreto
  assert.match(result.text, /artefacto|Resultados completos/);
  // Todos los dorks fallando: mensaje claro, no «sin resultados»
  let failCalls = 0;
  const failing = Object.fromEntries(createReconTools({
    artifacts: context.artifacts,
    runGh: async () => { failCalls++; return { exitCode: 1, stdout: "", stderr: "gh: rate limit" }; },
  }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const failed = await failing.github_search!.execute({ dominio: "otra.test" }, signal);
  assert.ok(failCalls >= 4);
  assert.match(failed.text, /gh api falló/);
  // Dominio inválido: rechazo claro
  await assert.rejects(async () => tools.github_search!.execute({ dominio: "no un dominio" }, signal), /Dominio inválido/);
});

test("informe: sección Detección (purple) con señales y gaps; sin señales, texto de apertura", async (t) => {
  const context = setup();
  t.after(() => context.close());
  context.db.exec("create table if not exists detection(id text primary key, accion text not null, esperada text not null, detectada integer not null, at text not null)");
  const ledger = new DetectionLedger(context.db);
  ledger.expect("h1", "sigma:sqli-error");
  ledger.expect("h2", "snort:idor-read");
  ledger.hit("h1");
  const scope = new ScopeStore(context.db);
  const http = new HttpClient(context.artifacts, () => scope.current());
  void http;
  const report = await generateReport({ ...context, findings: context.findings, scope, ledger: new Ledger(context.db) });
  assert.match(report.markdown, /## Detección \(purple\)/);
  assert.match(report.markdown, /\| sigma:sqli-error \| h1 \| detectada \|/);
  assert.match(report.markdown, /\| snort:idor-read \| h2 \| sin detectar \(gap\)/);
  assert.match(report.markdown, /Total: 1\/2 señales detectadas/);
  assert.match(report.markdown, /gap de detección/);
  // Sin señales: texto de apertura, tabla vacía
  const clean = setup();
  t.after(() => clean.close());
  const empty = await generateReport({ ...clean, findings: clean.findings, scope: new ScopeStore(clean.db), ledger: new Ledger(clean.db) });
  assert.match(empty.markdown, /## Detección \(purple\)/);
  assert.match(empty.markdown, /Sin señales de detección registradas/);
});

test("draftReport: título con activo, cuerpo con resumen/motivo/pasos/límites y severidad mapeada; severidad desconocida rechaza", () => {
  const draft = draftReport({ title: "Recurso de otro usuario", summary: "Se infiere acceso entre cuentas.", motive: "Sin control de dueño.", steps: ["GET /items/2 con cuenta de otro", "200 con datos"], limits: "Dos cuentas de prueba.", asset: "api.ejemplo.test/items/2", severity: "alta" });
  assert.equal(draft.title, "Recurso de otro usuario — api.ejemplo.test/items/2");
  assert.match(draft.vulnerability_information, /Se infiere acceso/);
  assert.match(draft.vulnerability_information, /Motivo:/);
  assert.match(draft.vulnerability_information, /Pasos:\n1\. GET \/items\/2/);
  assert.match(draft.vulnerability_information, /Límites:/);
  assert.equal(draft.severity_rating, "high");
  const low = draftReport({ title: "x", summary: "y", asset: "a", severity: "media" });
  assert.equal(low.severity_rating, "medium");
  assert.throws(() => draftReport({ title: "x", summary: "y", asset: "a", severity: "desconocida" }), /Severidad desconocida/);
});
test("github_search: los resultados con olor a secreto quedan como pista registrada", async (t) => {
  const context = setup();
  t.after(() => context.close());
  const pistas: Array<{ title: string; kind: string }> = [];
  const tools = Object.fromEntries(createReconTools({
    artifacts: context.artifacts,
    runGh: async () => ({ exitCode: 0, stdout: '{"repo":"org/repo","path":"config/.env","url":"https://github.com/org/repo"}', stderr: "" }),
    findingRecord: (input) => {
      pistas.push({ title: input.title, kind: input.kind });
      return `p${pistas.length}`;
    },
  }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const result = await tools.github_search!.execute({ dominio: "ejemplo.test" }, signal);
  assert.equal(pistas.length, 3, "un tope de tres pistas por llamada, para no inundar");
  assert.match(pistas[0]!.kind, /secreto/);
  assert.match(String(result.text), /Registradas como pista: p1/);
});
