import "./datos-tmp.ts";
// Cadenas de hallazgos: vínculos entre hallazgos (vista, informe, verificador) y la regla de cierre
// que objeta la escalada conocida de un hallazgo bajo o medio, una acción por vez y sin repetirse.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { CHAINS, chainFor, parseSetCookie } from "../src/cadenas.ts";
import { ClosingGate } from "../src/cierre.ts";
import { Findings, findingsView } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { Ledger } from "../src/ledger.ts";
import { generateReport } from "../src/report.ts";
import { parseRule, type Scope, ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-cadenas-"));

function setup() {
  const cwd = tmp();
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  return { cwd, paths, db, artifacts, findings, close: () => { db.close(); rmSync(cwd, { recursive: true, force: true }); } };
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

/** Laboratorio de cadenas: pedidos por id (lectura ajena abierta, escritura cerrada), login con cookie sin HttpOnly, búsqueda que refleja, redirect abierto y un authorize de OAuth. */
function chainLab(): Server {
  return createServer((req, res) => {
    const url = new URL(req.url!, "http://x");
    req.resume();
    req.on("end", () => {
      const json = (status: number, body: unknown, headers: Record<string, string> = {}) => void res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
      if (/^\/api\/orders\/\d+$/.test(url.pathname)) return req.method === "GET" ? json(200, { id: Number(url.pathname.split("/").pop()) }) : json(403, { error: "no" });
      if (url.pathname === "/api/login" && req.method === "POST") return json(200, { ok: true }, { "set-cookie": "session=abc123def; Path=/" });
      if (url.pathname === "/buscar") return void res.writeHead(200, { "content-type": "text/html" }).end(`<h1>${url.searchParams.get("q") ?? ""}</h1>`);
      if (url.pathname === "/go") return void res.writeHead(302, { location: url.searchParams.get("url") ?? "/" }).end();
      if (url.pathname === "/oauth/authorize") return json(200, { login: true });
      if (url.pathname === "/api/perfil") return json(200, { ok: true });
      json(404, { error: "no" });
    });
  });
}

test("cadenas: vínculos entre hallazgos en las dos direcciones, cadena ordenada, quitar, errores y vista", () => {
  const { artifacts, findings, close } = setup();
  try {
    const evidence = [artifacts.put("observación sintética", "text/plain", "test").hash];
    const low = findings.record({ title: "Open redirect en /go", kind: "open redirect", severity: "baja", asset: "https://example.test/go", summary: "Redirige a cualquier destino.", evidence }, "s1");
    const high = findings.record({ title: "Robo del código OAuth vía /go", kind: "oauth", severity: "alta", asset: "https://example.test/oauth/authorize", summary: "El code sale hacia afuera.", evidence, related: [{ id: low.id.slice(0, 8), role: "escala" }] }, "s1");
    assert.deepEqual(high.related, [{ id: low.id, role: "escala" }]);
    // El vínculo inverso se calcula: desde el bajo, «habilita» al alto.
    assert.deepEqual(findings.linksOf(low.id).map(({ finding, role }) => [finding.id, role]), [[high.id, "habilita"]]);
    assert.deepEqual(findings.chainOf(high.id).map((item) => item.id), [low.id, high.id]);

    const side = findings.record({ title: "XSS en /buscar", kind: "xss", severity: "media", asset: "https://example.test/buscar", summary: "Refleja sin escapar.", evidence }, "s1");
    const linked = findings.update(side.id, { related: [{ id: high.id.slice(0, 8), role: "relacionado" }] }, "s1");
    assert.equal(linked.rev, 2);
    assert.deepEqual(findings.chainOf(side.id).map((item) => item.id), [low.id, high.id, side.id]);

    assert.throws(() => findings.update(side.id, { related: [{ id: low.id.slice(0, 8), role: "causa" }] }, "s1"), /Rol de vínculo inválido «causa»/);
    assert.throws(() => findings.update(side.id, { related: [side.id.slice(0, 8)] }, "s1"), /no se vincula consigo mismo/);
    assert.throws(() => findings.update(side.id, { related: ["ffffffff"] }, "s1"), /No existe el hallazgo ffffffff para vincular/);
    const unlinked = findings.update(side.id, { related: [{ id: high.id.slice(0, 8), role: "quitar" }] }, "s1");
    assert.equal(unlinked.related, undefined);
    assert.deepEqual(findings.linksOf(side.id), []);

    assert.throws(() => findings.update(side.id, { escalation: "limitada" }, "s1"), /hace falta escalation_note/);
    assert.throws(() => findings.update(side.id, { escalation: "quizás", escalationNote: "x" }, "s1"), /Escalada inválida/);
    assert.equal(findings.update(side.id, { escalation: "limitada", escalationNote: "el lab no tiene login" }, "s1").escalation?.state, "limitada");

    const detail = findingsView(findings, low.id.slice(0, 8));
    assert.ok(detail.includes(`Vínculo: habilita a ${high.id.slice(0, 8)} «Robo del código OAuth vía /go» (candidato, alta)`), detail.join("\n"));
    assert.ok(detail.includes(`Cadena: ${low.id.slice(0, 8)} baja → ${high.id.slice(0, 8)} alta`), detail.join("\n"));
    assert.ok(findingsView(findings, side.id.slice(0, 8)).includes("Escalada: limitada — el lab no tiene login"));
    const list = findingsView(findings, "", "s1");
    assert.ok(list.some((line) => line.includes(low.id.slice(0, 8)) && line.endsWith(`⛓ ${high.id.slice(0, 8)}`)), list.join("\n"));
    assert.ok(list.some((line) => line.includes(side.id.slice(0, 8)) && !line.includes("⛓")));
  } finally {
    close();
  }
});

test("cadenas: la tabla reconoce cada clase de partida y deja afuera lo que ya es la escalada", () => {
  assert.deepEqual(CHAINS.map((rule) => rule.id), ["redirect-oauth", "xss-sesion", "csrf-email", "idor-escritura", "ssrf-interno"]);
  const cases: Array<[string, string, string | undefined]> = [
    ["open redirect", "Redirección abierta en /go", "redirect-oauth"],
    ["redirección", "Unvalidated redirect en el logout", "redirect-oauth"],
    ["xss", "XSS almacenado en comentarios", "xss-sesion"],
    ["inyección", "Cross-site scripting reflejado en /buscar", "xss-sesion"],
    ["csrf", "Cambio de perfil sin token anti-CSRF", "csrf-email"],
    ["control de acceso", "IDOR: lectura de pedidos ajenos", "idor-escritura"],
    ["control de acceso", "Escritura de pedidos ajenos con PUT", undefined],
    ["idor", "Mass assignment del rol", undefined],
    ["ssrf", "SSRF en el importador de URLs", "ssrf-interno"],
    ["configuración", "Cabeceras de seguridad ausentes", undefined],
  ];
  for (const [kind, title, expected] of cases) assert.equal(chainFor({ kind, title })?.id, expected, `${kind} · ${title}`);
  assert.deepEqual(parseSetCookie("session=abc; Path=/\ntheme=dark; HttpOnly; Path=/"), [{ name: "session", httpOnly: false }, { name: "theme", httpOnly: true }]);
});

test("cadenas: el cierre objeta la escalada de un IDOR de lectura una sola vez por intento y la da por intentada con la escritura", async () => {
  const { artifacts, findings, close } = setup();
  const server = chainLab();
  const base = await listen(server);
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  try {
    await http.send({ url: `${base}/api/orders/1` });
    await http.send({ url: `${base}/api/orders/2` });
    const idor = findings.record({ title: "IDOR: lectura de pedidos ajenos", kind: "control de acceso", cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", asset: `${base}/api/orders/2`, summary: "El pedido 2 es de otro usuario y responde 200.", evidence: ["h2"].map((id) => http.hashOf(id)!) }, "s1");
    const gate = new ClosingGate({ http, findings, sessionId: "s1", budgetLeft: () => 0.9 });
    // El hallazgo cubre la familia sin escritura; lo que queda es su escalada.
    assert.deepEqual(gate.open(), []);
    assert.deepEqual(gate.escalations().map((crack) => crack.key), [`escalada:idor-escritura:${idor.id.slice(0, 8)}`]);
    const first = gate.objection(2)!;
    assert.match(first.text, /^\[sistema\] Antes de cerrar: queda el 90% del presupuesto y un hallazgo tiene una escalada conocida sin intentar:\n/);
    assert.match(first.text, /es un IDOR de lectura y su escalada conocida es escritura sobre el recurso ajeno en la misma familia/);
    assert.match(first.text, /\/api\/orders\/\{n\}/);
    assert.match(first.text, /escalation «limitada»/);
    assert.equal(first.cracks.length, 1);
    // Sin intentarla, se repite como mucho maxPerCrack (2) veces.
    assert.ok(gate.objection(2));
    assert.equal(gate.objection(2), undefined);

    // Otra regla, otro arranque: la escritura sobre la misma familia después de la objeción cuenta como intento.
    const fresh = new ClosingGate({ http, findings, sessionId: "s1", budgetLeft: () => 0.9 });
    assert.ok(fresh.objection(1));
    await http.send({ url: `${base}/api/orders/2`, method: "PUT", headers: { "content-type": "application/json" }, body: "{\"note\":\"x\"}" });
    assert.equal(fresh.objection(1), undefined, "ya la intentó: no se repite");
    // Y como el intento queda en el tráfico, ni siquiera figura como pendiente.
    assert.deepEqual(fresh.escalations(), []);
  } finally {
    server.close();
    close();
  }
});

test("cadenas: XSS nombra la cookie sin HttpOnly; «limitada» con nota, un hallazgo vinculado o la falta de OAuth la cierran; el SSRF fuera de alcance se pide al operador una vez", async () => {
  const { db, artifacts, findings, close } = setup();
  const server = chainLab();
  const base = await listen(server);
  let scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  try {
    await http.send({ url: `${base}/api/login`, method: "POST", headers: { "content-type": "application/json" }, body: "{\"email\":\"ana@x.test\"}" });
    await http.send({ url: `${base}/buscar?q=%3Cb%3E` });
    const xss = findings.record({ title: "XSS reflejado en /buscar", kind: "xss", cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", asset: `${base}/buscar`, summary: "q se refleja sin escapar.", evidence: [http.hashOf("h2")!] }, "s1");
    const gate = new ClosingGate({ http, findings, sessionId: "s1", budgetLeft: () => 0.8 });
    const objection = gate.objection(2)!;
    assert.match(objection.text, /XSS \(reflejado o almacenado\)/);
    assert.match(objection.text, /«session» sin HttpOnly \(h1, \/api\/login\)/);
    findings.update(xss.id, { escalation: "limitada", escalationNote: "la sesión es por bearer, no hay cookie que leer" }, "s1");
    assert.deepEqual(gate.escalations(), []);
    assert.equal(gate.objection(2), undefined);

    // CSRF: un hallazgo vinculado (la toma de cuenta) cierra su escalada.
    const csrf = findings.record({ title: "Perfil sin token anti-CSRF", kind: "csrf", severity: "baja", asset: `${base}/api/perfil`, summary: "Acepta el POST desde otro origen.", evidence: [http.hashOf("h1")!] }, "s1");
    assert.deepEqual(gate.escalations().map((crack) => crack.key), [`escalada:csrf-email:${csrf.id.slice(0, 8)}`]);
    findings.record({ title: "Toma de cuenta por cambio de email", kind: "toma de cuenta", severity: "alta", asset: `${base}/api/perfil/email`, summary: "El email cambia sin token.", evidence: [http.hashOf("h1")!], related: [{ id: csrf.id.slice(0, 8), role: "escala" }] }, "s1");
    assert.deepEqual(gate.escalations(), []);

    // Open redirect: sin flujo OAuth en el tráfico no hay escalada que pedir; con el authorize visto, sí.
    await http.send({ url: `${base}/go?url=https://example.org/` });
    const redirect = findings.record({ title: "Open redirect en /go", kind: "open redirect", severity: "baja", asset: `${base}/go`, summary: "Redirige a cualquier dominio.", evidence: [http.hashOf("h3")!] }, "s1");
    assert.deepEqual(gate.escalations(), []);
    await http.send({ url: `${base}/oauth/authorize?client_id=app&response_type=code&redirect_uri=${encodeURIComponent(`${base}/callback`)}` });
    const [oauth] = gate.escalations();
    assert.equal(oauth?.key, `escalada:redirect-oauth:${redirect.id.slice(0, 8)}`);
    assert.match(oauth!.text, /flujo OAuth \(GET \/oauth\/authorize\)/);
    findings.update(redirect.id, { escalation: "intentada", escalationNote: "el redirect_uri exige coincidencia exacta" }, "s1");

    // SSRF: el alcance no incluye destinos internos → pedírselo al operador, una sola vez.
    const ssrf = findings.record({ title: "SSRF en el importador", kind: "ssrf", severity: "media", asset: `${base}/api/importar`, summary: "El servidor pidió la URL dada.", evidence: [http.hashOf("h1")!] }, "s1");
    const asked = new ClosingGate({ http, findings, sessionId: "s1", budgetLeft: () => 0.8 });
    const ssrfObjection = asked.objection(1)!;
    assert.match(ssrfObjection.text, /No lo amplíes vos: pedile al operador/);
    // Después queda, una sola vez, el recordatorio de informe por el vector que falta (#49).
    assert.match(asked.objection(1)!.text, /^\[sistema\] Antes de presentar el informe\. Los candidatos [0-9a-f]{8} \(media\), [0-9a-f]{8} \(alta\) tienen severidad estimada sin vector/);
    assert.equal(asked.objection(1), undefined, "pedirle al operador se objeta una sola vez");
    // Si el alcance nombra la metadata, la acción es probarla.
    scope = { ...scope, rev: 2, include: [...scope.include, parseRule("169.254.169.254")] };
    const [inScope] = asked.escalations();
    assert.equal(inScope?.key, `escalada:ssrf-interno:${ssrf.id.slice(0, 8)}`);
    assert.match(inScope!.text, /El alcance incluye 169\.254\.169\.254/);
    assert.equal(inScope!.max, undefined);
    void db;
  } finally {
    server.close();
    close();
  }
});

test("cadenas: el motor objeta la escalada al cerrar y acepta «limitada»; si queda sin intentar, el operador se entera", async () => {
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const server = chainLab();
  const base = await listen(server);
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  const run = async (fix: boolean) => {
    const provider = resolveProvider("faux");
    const engine = new Engine({ cwd: tmp(), provider, budgetPico: 2n * 10n ** 12n, coverageObjections: 0, autoVerify: false, grafo: false, closingGate: { maxPerCrack: 1 } });
    engine.scope.edit({ include: [`${base}/`] });
    const notices: string[] = [];
    engine.onNotice = (text) => notices.push(text);
    try {
      const evidence = engine.artifacts.put("respuesta con <b> sin escapar", "text/plain", "test").hash;
      const xss = engine.findings.record({ title: "XSS reflejado en /buscar", kind: "xss", cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", asset: `${base}/buscar`, summary: "q se refleja sin escapar.", evidence: [evidence] }, engine.sessionId);
      provider.faux!.queue = [
        call("http_request", { url: `${base}/buscar?q=hola` }),
        { text: "Terminé." },
        ...(fix ? [call("finding_update", { id: xss.id.slice(0, 8), escalation: "limitada", escalation_note: "el laboratorio no tiene sesión por cookie" })] : []),
        { text: "Cierro." },
      ];
      await engine.send("Mirá la búsqueda");
      const objections = engine.agent.messages.filter((m) => m.role === "user" && String(m.content).startsWith("[sistema] Antes de cerrar:")).map((m) => String(m.content));
      const events = engine.db.prepare("select type,payload from events where session_id=? and type like 'cierre.%' order by seq").all(engine.sessionId) as Array<{ type: string; payload: string }>;
      return { objections, events, notices, finding: engine.findings.get(xss.id)!, last: String(engine.agent.messages.findLast((m) => m.role === "assistant")?.content ?? "") };
    } finally {
      await engine.close();
    }
  };
  try {
    const fixed = await run(true);
    assert.equal(fixed.objections.length, 1, fixed.objections.join("\n---\n"));
    assert.match(fixed.objections[0]!, /un hallazgo tiene una escalada conocida sin intentar/);
    assert.deepEqual(fixed.events.map((row) => row.type), ["cierre.objetado"]);
    assert.match(fixed.events[0]!.payload, /escalada:xss-sesion:/);
    assert.equal(fixed.finding.escalation?.state, "limitada");
    assert.match(fixed.last, /Cierro/);
    assert.deepEqual(fixed.notices.filter((text) => /escalada/.test(text)), []);

    const left = await run(false);
    assert.equal(left.objections.length, 1);
    assert.deepEqual(left.events.map((row) => row.type), ["cierre.objetado", "cierre.escaladas"]);
    assert.equal(left.notices.filter((text) => /^Cierra con 1 escalada conocida sin intentar: xss-sesion:/.test(text)).length, 1, left.notices.join("\n"));
  } finally {
    server.close();
  }
});

test("cadenas: el informe muestra la cadena por hallazgo y una sección con su severidad, en los dos idiomas", async () => {
  const { paths, db, artifacts, findings, close } = setup();
  try {
    const evidence = [artifacts.put("observación sintética", "text/plain", "test").hash];
    const low = findings.record({ title: "Open redirect en /go", kind: "open redirect", severity: "baja", asset: "https://example.test/go", summary: "Redirige afuera.", evidence }, "s1");
    const high = findings.record({ title: "Robo del código OAuth", kind: "oauth", severity: "alta", asset: "https://example.test/oauth/authorize", summary: "El code sale.", evidence, related: [{ id: low.id, role: "escala" }] }, "s1");
    const context = { paths, db, artifacts, findings, scope: new ScopeStore(db), ledger: new Ledger(db), now: new Date("2026-11-20T10:00:00.000Z") };
    const pending = (await generateReport(context)).markdown;
    assert.match(pending, new RegExp(`Cadena: habilita a ${high.id.slice(0, 8)} «Robo del código OAuth» \\(alta, candidato\\)\\.`));
    assert.match(pending, new RegExp(`Cadena: es la escalada de ${low.id.slice(0, 8)} «Open redirect en /go» \\(baja, candidato\\)\\.`));
    assert.match(pending, /## Cadenas\n\nHallazgos vinculados/);
    assert.match(pending, new RegExp(`- ${low.id.slice(0, 8)} «Open redirect en /go» \\(baja, candidato\\) → ${high.id.slice(0, 8)} «Robo del código OAuth» \\(alta, candidato\\)\\. Severidad de la cadena: alta, pendiente de verificar ${low.id.slice(0, 8)} \\(candidato\\), ${high.id.slice(0, 8)} \\(candidato\\)\\.`));
    findings.verdict(low.id, "verificado", "reproducido", evidence, "verificador:1");
    findings.verdict(high.id, "verificado", "reproducido", evidence, "verificador:2");
    assert.match((await generateReport(context)).markdown, /Severidad de la cadena: alta, con todos sus eslabones verificados\./);
    const english = (await generateReport({ ...context, lang: "en" })).markdown;
    assert.match(english, /## Chains\n/);
    assert.match(english, new RegExp(`Chain: enables ${high.id.slice(0, 8)}`));
    assert.match(english, /Chain severity: high, with every link verified\./);
    // Sin vínculos no hay sección.
    const lone = setup();
    try {
      lone.findings.record({ title: "Suelto", kind: "xss", severity: "media", asset: "https://example.test/x", summary: "s", evidence: [lone.artifacts.put("x", "text/plain", "test").hash] }, "s1");
      assert.doesNotMatch((await generateReport({ paths: lone.paths, db: lone.db, artifacts: lone.artifacts, findings: lone.findings, scope: new ScopeStore(lone.db), ledger: new Ledger(lone.db) })).markdown, /## Cadenas|Cadena:/);
    } finally {
      lone.close();
    }
  } finally {
    close();
  }
});

test("cadenas: el verificador recibe la cadena del candidato con el estado de cada eslabón", async () => {
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider, autoVerify: false, closingGate: false, coverageObjections: 0 });
  try {
    const evidence = [engine.artifacts.put("observación sintética", "text/plain", "test").hash];
    const low = engine.findings.record({ title: "Open redirect en /go", kind: "open redirect", severity: "baja", asset: "https://example.test/go", summary: "Redirige afuera.", evidence, state: "pista" }, engine.sessionId);
    const high = engine.findings.record({ title: "Robo del código OAuth", kind: "oauth", severity: "alta", asset: "https://example.test/oauth/authorize", summary: "El code sale.", evidence, related: [{ id: low.id, role: "escala" }] }, engine.sessionId);
    provider.faux!.queue = [{ toolCalls: [{ name: "verdict", arguments: { state: "candidato", reason: "el eslabón previo es una pista sin verificar" } }] }, { text: "Listo." }];
    const verdict = await engine.verifier.verify(high.id);
    assert.equal(verdict.state, "candidato");
    const transcript = JSON.parse(engine.artifacts.read(verdict.transcript).toString("utf8")) as Array<{ role: string; content: string }>;
    const prompt = transcript.find((message) => message.role === "user")!.content;
    assert.match(prompt, new RegExp(`Cadena:\\n- es la escalada de ${low.id.slice(0, 8)} · pista · baja · open redirect: Open redirect en /go`));
  } finally {
    await engine.close();
  }
});
