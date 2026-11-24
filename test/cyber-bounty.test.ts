import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { CyberBounty, bountyDraft, bountyScope, type BountyProgram } from "../src/cyber-bounty.ts";
import { createOperatorTools, type OperatorContext } from "../src/operador.ts";
import { ScopeStore } from "../src/scope.ts";
import type { Finding, Findings } from "../src/findings.ts";
import { HttpClient, PROGRAM_LIMIT, PROGRAM_RATE } from "../src/http.ts";
import type { Artifacts } from "../src/artifacts.ts";

const key = "bb_prueba_sin_valor";
const programa = (): BountyProgram => ({ id: "demo", name: "Programa Demo", status: "abierto", accepting_reports: true, scope_revision: 7, policy: "No toques datos ajenos.", authorization: { by: "Responsable", role: "titular", at: "2026-01-01" }, conduct: { max_requests_per_second: 2, destructive_actions: false, agent_header: "X-Cyber-Agent: prueba", test_window: "de 9 a 18" }, scope: { include: [{ kind: "host", value: "api.ejemplo.com" }], exclude: [{ kind: "url", value: "api.ejemplo.com/privado" }] } });
const json = (body: unknown, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers });

test("Cyber: conserva autorización estructurada y redacta claves sólo al mostrar respuestas", async () => {
  const p = programa();
  const client = new CyberBounty(key, async () => json(p));
  const response = await client.program("demo");
  assert.deepEqual(response.body.authorization, p.authorization);
  const scope = bountyScope(response.body);
  assert.match(scope.notes, /Responsable/);
  assert.match(scope.notes, /titular/);
  assert.match(scope.notes, /2026-01-01/);
  const s = escenario();
  try {
    s.cambiar({ policy: `No divulgues ${key}` });
    const output = await s.cargar();
    assert.match(s.scope.current()!.notes, /Responsable/);
    assert.ok(!output.text.includes(key));
    assert.ok(!s.scope.current()!.notes.includes(key));
    assert.ok(!(await s.call("programs")).text.includes(key));
  } finally { s.db.close(); }
});

test("Cyber: elimina repeticiones sin etiqueta de secretos aprendidos en cualquier campo", () => {
  const s = escenario();
  try {
    const secreto = "credencial-repetida-123456";
    s.finding.title = `Acceso indebido ${secreto}`;
    s.finding.asset = `https://api.ejemplo.com/${secreto}`;
    s.finding.summary = `Se observó ${secreto}`;
    s.finding.limits = `No divulgar ${secreto}`;
    s.finding.evidence.push("segundo");
    const draft = bountyDraft(s.finding, (ref) => Buffer.from(ref === "segundo" ? `password=${secreto}` : `curl https://api.ejemplo.com/${secreto}`), new CyberBounty(key).redactor);
    for (const field of ["title", "asset", "summary", "steps", "poc"] as const) {
      assert.ok(!draft[field].includes(secreto), field);
      assert.match(draft[field], /credencial omitida/);
    }
  } finally { s.db.close(); }
});

test("Cyber conserva el campo numérico de la plataforma al previsualizar un vector", () => {
  const s = escenario();
  try {
    const leer = () => Buffer.from("GET /inventario HTTP/1.1");
    const redactor = new CyberBounty(key).redactor;
    for (const cvss of [7.2, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"]) {
      assert.equal(bountyDraft({ ...s.finding, cvss }, leer, redactor).cvss, 7.2);
    }
  } finally { s.db.close(); }
});

function escenario() {
  const db = new DatabaseSync(":memory:");
  const scope = new ScopeStore(db);
  let tiempo = Date.parse("2026-11-20T12:00:00Z");
  const mensajes = [{ text: "Cargá el programa demo", at: new Date(tiempo - 1000).toISOString() }];
  const evidencia = Buffer.from(`GET /cuentas/2 HTTP/1.1\nHost: api.ejemplo.com\nAuthorization: Bearer ${key}\n\n`);
  const finding = { id: "hallazgo-1", rev: 1, state: "verificado", title: "Acceso a cuentas de otra persona", kind: "control de acceso", severity: "alta", asset: "https://api.ejemplo.com/cuentas/2", summary: "La otra cuenta puede leer los datos.", evidence: ["sha256:prueba"], limits: "Sólo dos cuentas propias", decidedBy: "operador", reason: "reproducido", sessionId: "sesion", createdAt: "", updatedAt: "" } as Finding;
  let program = programa();
  let unchanged = true;
  let error = false;
  const requests: Array<{ url: string; init: RequestInit }> = [];
  const enviados: Array<{ finding: string; report: string }> = [];
  const fetchImpl: typeof fetch = async (input, init = {}) => {
    const url = String(input);
    requests.push({ url, init });
    if (error) return json({ error: { code: "unverified_person", message: `Verificá tu identidad en cyber.elevateai.ar/cuenta. ${key}` } }, 403);
    if (init.method === "POST") return json({ id: "reporte-1", status: "en_triage", checks: [{ id: "prueba", ok: true }] }, 201);
    if (url.endsWith("/reports/reporte-1")) return json({ id: "reporte-1", status: "en_triage", checks: [] });
    if (url.endsWith("/programs")) return json({ object: "list", data: [program] });
    if (new Headers(init.headers).has("if-none-match") && unchanged) return new Response(null, { status: 304 });
    return json(program, 200, { ETag: '"7-abierto"' });
  };
  const http = { rate: 1 } as HttpClient;
  const context: OperatorContext = {
    scope, http, ledger: {} as OperatorContext["ledger"], h1: () => ({}), report: async () => [],
    operatorTexts: () => mensajes.map((m) => m.text), operatorMessages: () => mensajes,
    findings: { get: () => finding } as unknown as Findings, artifacts: { read: () => evidencia },
    bounty: () => new CyberBounty(key, fetchImpl), now: () => tiempo,
    bountyEvent: (finding, report) => enviados.push({ finding, report }),
  };
  const tools = createOperatorTools(context);
  const call = async (name: string, args = {}) => tools.find((t) => t.name === `cyber_bounty_${name}`)!.execute(args, new AbortController().signal);
  return { db, scope, finding, evidencia, requests, mensajes, enviados, http, context, call,
    avanzar: (ms: number) => { tiempo += ms; }, cambiar: (p: Partial<BountyProgram>) => { program = { ...program, ...p }; unchanged = false; }, error: () => { error = true; },
    cargar: () => call("scope", { slug: "demo", pedido: mensajes[0]!.text }),
    previa: async () => { const result = await call("submit", { hallazgo: finding.id }); return { result, code: /Código de aprobación: ([a-f0-9]+)/.exec(result.text)![1]! }; },
    aprobar: (code: string, at?: string) => { tiempo += 1; const pedido = `Enviá este reporte con el código ${code}`; mensajes.push({ text: pedido, at: at ?? new Date(tiempo).toISOString() }); return { hallazgo: finding.id, pedido }; },
  };
}

test("Cyber: convierte los cuatro tipos, exclusiones y omitidos; conserva política y conducta", () => {
  const p = programa();
  p.scope.include.push({ kind: "wildcard", value: "*.ejemplo.com" }, { kind: "cidr", value: "203.0.113.0/24" }, { kind: "url", value: "web.ejemplo.com/api" }, { kind: "host", value: "no es host" });
  const scope = bountyScope(p);
  assert.deepEqual(scope.include.map((r) => r.kind), ["host", "wildcard", "cidr", "url"]);
  assert.equal(scope.exclude[0]?.value, "https://api.ejemplo.com/privado");
  assert.deepEqual(scope.skipped, ["host: no es host"]);
  for (const text of ["No toques datos ajenos", "scope_revision: 7", "2 peticiones/s", "prohibidas", "X-Cyber-Agent", "de 9 a 18", "Responsable"]) assert.ok(scope.notes.includes(text));
  p.scope.exclude.push({ kind: "host", value: "no es host" });
  assert.throws(() => bountyScope(p), /exclusiones/);
});

test("Cyber: al reabrir conserva el ritmo del programa y los defaults sin aflojar al operador", () => {
  const db = new DatabaseSync(":memory:");
  try {
    const store = new ScopeStore(db);
    const p = programa();
    p.conduct.max_requests_per_second = 0.5;
    const rules = bountyScope(p);
    store.save({ source: "cyber:demo", include: rules.include, exclude: rules.exclude, notes: rules.notes });
    const reopened = new ScopeStore(db);
    const http = new HttpClient({} as Artifacts, () => reopened.current());
    http.operator = () => "operador-local";
    assert.equal(http.conduct().rate, 0.5);
    assert.equal(http.conduct().limit, PROGRAM_LIMIT);
    assert.equal(http.conduct().scanners, false);
    assert.equal(http.conduct().program, "demo");
    assert.match(http.conduct().userAgent, /Cyber: operador-local/);
    assert.ok(!http.conduct().userAgent.includes("HackerOne"));
    http.rate = 0.2;
    assert.equal(http.conduct().rate, 0.2);
    http.rate = Infinity;
    assert.equal(http.conduct().rate, 0.5);
    const current = reopened.current()!;
    reopened.save({ ...current, notes: "sin conducta importada" });
    http.rate = undefined;
    assert.equal(http.conduct().rate, PROGRAM_RATE);
  } finally { db.close(); }
});

test("Cyber: alcance vacío o programa no nombrado no se importan; nunca afloja el ritmo", async () => {
  const s = escenario();
  try {
    s.mensajes[0]!.text = "Cargá algún programa";
    await assert.rejects(() => s.cargar(), /nombrar/);
    s.mensajes[0]!.text = "Cargá demo";
    s.cambiar({ scope: { include: [], exclude: [] } });
    await assert.rejects(() => s.cargar(), /activos importables/);
    s.cambiar(programa());
    await s.cargar();
    assert.equal(s.http.rate, 1);
    assert.equal(s.scope.current()?.source, "cyber:demo");
  } finally { s.db.close(); }
});

for (const caso of ["sin código", "código incorrecto", "mensaje anterior", "vencido", "cambió el reporte", "cambió alcance", "pausado", "texto pegado"] as const) {
  test(`Cyber: rechaza aprobación ${caso} sin hacer POST`, async () => {
    const s = escenario();
    try {
      await s.cargar();
      const { code } = await s.previa();
      let args = s.aprobar(code);
      if (caso === "sin código") { args = s.aprobar("dale nomás"); }
      if (caso === "código incorrecto") { args = s.aprobar("000000000000"); }
      if (caso === "mensaje anterior") { s.mensajes.pop(); args = s.aprobar(code, "2026-11-20T11:59:59Z"); }
      if (caso === "vencido") s.avanzar(15 * 60_000 + 1);
      if (caso === "cambió el reporte") s.finding.summary += " Cambió la prueba.";
      if (caso === "cambió alcance") s.cambiar({ scope_revision: 8 });
      if (caso === "pausado") s.cambiar({ accepting_reports: false, status: "pausado" });
      if (caso === "texto pegado") { s.mensajes.at(-1)!.text = `> ${args.pedido}`; }
      await assert.rejects(() => s.call("submit", args));
      assert.equal(s.requests.filter((r) => r.init.method === "POST").length, 0);
    } finally { s.db.close(); }
  });
}

test("Cyber: preview sin envío, aprobación fresca, 304, cabeceras e idempotencia; código de un uso y estado", async () => {
  const keys: string[] = [];
  for (let intento = 0; intento < 2; intento++) {
    const s = escenario();
    try {
      await s.cargar();
      const { result, code } = await s.previa();
      assert.ok(result.text.includes('"poc"'));
      assert.ok(!result.text.includes(key));
      assert.equal(s.requests.filter((r) => r.init.method === "POST").length, 0);
      const args = s.aprobar(code);
      const sent = await s.call("submit", args);
      assert.match(sent.text, /reporte-1/);
      assert.deepEqual(s.enviados, [{ finding: "hallazgo-1", report: "reporte-1" }]);
      const post = s.requests.find((r) => r.init.method === "POST")!;
      const headers = new Headers(post.init.headers);
      assert.equal(headers.get("authorization"), `Bearer ${key}`);
      assert.equal(headers.get("content-type"), "application/json");
      keys.push(headers.get("idempotency-key")!);
      assert.match(keys.at(-1)!, /^[A-Za-z0-9._:-]{8,80}$/);
      assert.equal(new Headers(s.requests.at(-2)!.init.headers).get("if-none-match"), '"7-abierto"');
      const body = JSON.parse(String(post.init.body));
      assert.equal(body.asset, s.finding.asset);
      assert.equal(body.severity, "alta");
      assert.equal(body.evidence[0].sha256, createHash("sha256").update(s.evidencia).digest("hex"));
      assert.match(body.poc, /GET \/cuentas\/2 HTTP\/1.1/);
      assert.ok(!String(post.init.body).includes(key));
      await assert.rejects(() => s.call("submit", args), /ya se envió/);
      assert.match((await s.call("status", { hallazgo: s.finding.id })).text, /en_triage/);
    } finally { s.db.close(); }
  }
  assert.equal(keys[0], keys[1]);
});

test("Cyber: error 403 muestra el mensaje del servidor sin clave; rechaza clave oro_ y slug inválido", async () => {
  const s = escenario();
  try {
    s.error();
    await assert.rejects(() => s.call("programs"), (err: Error) => { assert.match(err.message, /Verificá tu identidad en cyber.elevateai.ar\/cuenta/); assert.ok(!err.message.includes(key)); return true; });
    assert.throws(() => new CyberBounty("oro_no_corresponde"), /clave de agente/);
    await assert.rejects(() => new CyberBounty(key).program("../otro"), /inválido/);
  } finally { s.db.close(); }
});

test("Cyber: rechaza hallazgo sin verificar, informativo, sin prueba y activo excluido", async () => {
  const s = escenario();
  try {
    await s.cargar();
    s.finding.state = "candidato";
    await assert.rejects(() => s.previa(), /verificados/);
    s.finding.state = "verificado";
    s.finding.severity = "informativa";
    await assert.rejects(() => s.previa(), /informativa/);
    s.finding.severity = "alta";
    s.finding.evidence = [];
    await assert.rejects(() => s.previa(), /reproducible/);
    s.finding.evidence = ["sha256:prueba"];
    s.finding.asset = "https://api.ejemplo.com/privado/datos";
    await assert.rejects(() => s.previa(), /fuera del alcance/);
    await assert.rejects(() => s.call("status"), /Indicá/);
  } finally { s.db.close(); }
});
