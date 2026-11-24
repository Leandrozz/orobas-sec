import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { Ledger } from "../src/ledger.ts";
import { generateReport, parseReportLang } from "../src/report.ts";
import { ReportRedactor } from "../src/redact.ts";
import { parseRule, ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

function setup() {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-informe-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  const scope = new ScopeStore(db);
  const ledger = new Ledger(db);
  return { paths, db, artifacts, findings, scope, ledger, close: () => { db.close(); rmSync(cwd, { recursive: true, force: true }); } };
}

test("informe: evidencia HTTP local, estados, costos, identidad y anexo sin credenciales", async () => {
  const context = setup();
  let requests = 0;
  const server = createServer((request, response) => {
    requests++;
    request.resume();
    request.on("end", () => response.writeHead(200, { "content-type": "application/json", "set-cookie": "sid=COOKIE-REPORT-SECRET; Path=/; HttpOnly" }).end(JSON.stringify({ owner: 2, access_token: "RESPONSE-REPORT-SECRET", reflected: "QUERY-REPORT-SECRET", details: "x".repeat(2100), refresh_token: "TRUNCATED-REPORT-SECRET" })));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  context.scope.edit({ include: [base], exclude: [`${base}/admin`] });
  const http = new HttpClient(context.artifacts, () => context.scope.current());
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer IDENTITY-REPORT-SECRET" } });
  try {
    const first = await http.send({ url: `${base}/items/2?access_token=QUERY-REPORT-SECRET`, method: "POST", headers: { "content-type": "application/json", "x-api-key": "HEADER-REPORT-SECRET" }, body: JSON.stringify({ owner: 2, password: "BODY-REPORT-SECRET" }) }, "ana");
    const second = await http.send({ url: `${base}/items/2`, headers: { authorization: "Bearer RAW-REPORT-SECRET" } });
    const finding = context.findings.record({ title: "Recurso de otro usuario", kind: "control de acceso", asset: `${base}/items/2`, summary: "Se infiere acceso entre cuentas. Reflejos: RESPONSE-REPORT-SECRET, COOKIE-REPORT-SECRET, RAW-REPORT-SECRET, BODY-REPORT-SECRET, HEADER-REPORT-SECRET, TRUNCATED-REPORT-SECRET.", evidence: [first.artifact, second.artifact], severity: "alta", limits: "Sólo dos cuentas de prueba." }, "s1");
    context.findings.decide(finding.id, "verificado", "reproducido por operador");
    context.findings.record({ title: "Cabeceras de seguridad ausentes", kind: "cabeceras ausentes", asset: base, summary: "Sin impacto demostrado", evidence: [first.artifact], severity: "informativa" }, "s1");
    context.findings.record({ title: "Ruta por revisar", kind: "ruta", asset: `${base}/todo`, summary: "Falta revisar", state: "pista" }, "s1");
    const discarded = context.findings.record({ title: "Control descartado", kind: "otro", asset: base, summary: "Control", evidence: [second.artifact] }, "s1");
    context.findings.decide(discarded.id, "descartado", "sin diferencia");
    context.db.prepare("insert into requests(provider,account,request_id,session_id,worker,model,at,stop_reason,input,cache_read,cache_write,output,cost_input,cost_cache_read,cost_cache_write,cost_output) values('faux','test','r1','s1','verificador:1','faux','2026-11-01T12:00:00.000Z','stop',10,0,0,10,'1000000000','0','0','2000000000')").run();
    context.db.prepare("insert into requests(provider,account,request_id,session_id,worker,model,at,stop_reason) values('faux','test','r2','s1','sub:1','faux','2026-11-02T12:00:00.000Z','pendiente')").run();
    const result = await generateReport({ ...context, now: new Date("2026-11-11T15:10:00.000Z") });
    assert.equal(requests, 2, "generar el informe no vuelve a pedir evidencia");
    assert.match(result.markdown, /USD 0\.003000 \(2 solicitudes/);
    assert.match(result.markdown, /Costo pendiente de determinar: 1 solicitudes/);
    assert.match(result.markdown, /\| verificado \| 0 \| 0 \| 0 \| 1 \| 0 \| 1 \|/);
    assert.match(result.markdown, /Observado en la evidencia[\s\S]*HTTP 200[\s\S]*Interpretación registrada[\s\S]*Se infiere acceso/);
    assert.match(result.markdown, /POST http:\/\/127\.0\.0\.1:[0-9]+\/items\/2/);
    assert.match(result.markdown, /authorization: <identidad ana>/);
    assert.match(result.markdown, /"owner": 2/);
    assert.match(result.markdown, /Decidido por: operador/);
    assert.match(result.markdown, /Fragmento de respuesta recortado/);
    assert.match(result.markdown, /Límites declarados: Sólo dos cuentas/);
    assert.doesNotMatch(result.markdown, /(?:QUERY|RESPONSE|COOKIE|RAW|BODY|HEADER|TRUNCATED|IDENTITY)-REPORT-SECRET/);
    const [main, appendix] = result.markdown.split("## Anexo:");
    assert.doesNotMatch(main!, /Cabeceras de seguridad ausentes|Ruta por revisar|Control descartado/);
    assert.match(appendix!, /Cabeceras de seguridad ausentes/);
    assert.match(appendix!, /Ruta por revisar/);
    assert.match(appendix!, /Control descartado/);
    assert.equal(readFileSync(result.path, "utf8"), result.markdown);
    assert.equal(context.artifacts.read(result.artifact.hash).toString("utf8"), result.markdown);
    assert.equal(context.db.prepare("select producer from artifacts where hash=?").get(result.artifact.hash)!.producer, "informe");
    assert.notEqual((await generateReport({ ...context, now: new Date("2026-11-11T15:10:00.000Z") })).path, result.path, "no pisa un informe anterior");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    context.close();
  }
});

test("informe en inglés: textos fijos, estados, severidades y marcadores traducidos; lo escrito por el agente queda igual; archivo -en.md", async () => {
  const context = setup();
  const server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      if (request.url === "/api/users" && request.method === "POST") return response.writeHead(201, { "content-type": "application/json", location: "/api/users/4711" }).end(JSON.stringify({ id: 4711 }));
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ owner: 2, access_token: "RESPONSE-EN-SECRET", details: "x".repeat(2100) }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  context.scope.save({ source: "programa de prueba", include: [parseRule(base)], exclude: [parseRule(`${base}/admin`)], notes: "Sólo cuentas propias." });
  const http = new HttpClient(context.artifacts, () => context.scope.current());
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer IDENTITY-EN-SECRET" } });
  try {
    const first = await http.send({ url: `${base}/items/2`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ owner: 2, password: "BODY-EN-SECRET" }) }, "ana");
    await http.send({ url: `${base}/api/users`, method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const finding = context.findings.record({ title: "Recurso de otro usuario", kind: "control de acceso", asset: `${base}/items/2`, summary: "Se infiere acceso entre cuentas.", evidence: [first.artifact], severity: "alta", limits: "Sólo dos cuentas de prueba." }, "s1");
    context.findings.decide(finding.id, "verificado", "reproducido por operador");
    context.findings.record({ title: "Cabeceras de seguridad ausentes", kind: "cabeceras ausentes", asset: base, summary: "Sin impacto demostrado", evidence: [first.artifact], severity: "informativa" }, "s1");
    const now = new Date("2026-11-14T15:10:00.000Z");
    const result = await generateReport({ ...context, now, lang: "en" });
    const { markdown } = result;
    assert.equal(result.lang, "en");
    assert.match(result.path, /2026-11-14T15-10-00-000Z-en\.md$/);
    assert.match((await generateReport({ ...context, now, lang: "en" })).path, /-en-1\.md$/, "no pisa un informe anterior en inglés");
    assert.match((await generateReport({ ...context, now })).path, /2026-11-14T15-10-00-000Z\.md$/, "la versión en castellano conserva su nombre");
    assert.ok(markdown.startsWith("# Security assessment report\n\nGenerated: 2026-11-14T15:10:00.000Z"));
    for (const heading of ["## Executive summary", "### Scope", "## Verified findings", "#### Observed in the evidence", "#### Recorded interpretation", "#### Steps to reproduce", "## Cleanup", "## Appendix: leads, discarded and informational"]) assert.ok(markdown.includes(`\n${heading}\n`), heading);
    assert.match(markdown, /\| State \| informational \| low \| medium \| high \| critical \| Total \|/);
    assert.match(markdown, /\| verified \| 0 \| 0 \| 0 \| 1 \| 0 \| 1 \|/);
    assert.match(markdown, /\| lead \| 0 \| 0 \| 0 \| 0 \| 0 \| 0 \|/);
    assert.match(markdown, /Authorized scope in force: revision 1, .*Source: programa de prueba\./);
    assert.match(markdown, /- Included: http:/);
    assert.match(markdown, /- Excluded: http:.*\/admin/);
    assert.match(markdown, /Scope notes: Sólo cuentas propias\./);
    assert.match(markdown, /State: verified\. Severity: high\. Class: control de acceso\./, "la clase la escribió el agente y queda");
    assert.match(markdown, /Decided by: operator\. Decision date: /);
    assert.match(markdown, /Reason for the decision: reproducido por operador\./);
    assert.match(markdown, /### [0-9a-f]{8} — Recurso de otro usuario/);
    assert.match(markdown, /Recorded interpretation\n\nSe infiere acceso entre cuentas\./);
    assert.match(markdown, /Use the named test identities; authentication values were omitted\./);
    assert.match(markdown, /1\. Send the request saved in sha256:/);
    assert.match(markdown, /authorization: <identity ana>/);
    assert.match(markdown, /\[credential redacted\]/);
    assert.match(markdown, /Recorded response:/);
    assert.match(markdown, /Response excerpt truncated; see the original artifact in the project\./);
    assert.match(markdown, /Stated limits: Sólo dos cuentas de prueba\.\n/, "el punto final del texto libre no se duplica");
    assert.match(markdown, /\| Date \| Request \| Identifiers \| HTTP \|/);
    assert.match(markdown, /POST http:\/\/127\.0\.0\.1:[0-9]+\/api\/users \| 4711 \| 201 \|/);
    assert.match(markdown, /\| ID \| State \| Severity \| Title and asset \| Decision and limits \|/);
    assert.match(markdown, /\| candidate \| informational \| Cabeceras de seguridad ausentes — http:.*\| agent, .*No reason stated\. Limits: not stated\. \|/);
    assert.match(markdown, /Informational records describe observed conditions/);
    assert.doesNotMatch(markdown, /<identidad |credencial omitida/);
    assert.doesNotMatch(markdown, /Informe de evaluación|Resumen ejecutivo|Alcance autorizado|Hallazgos para revisión|Observado en la evidencia|Pasos para reproducir|Para limpiar|Anexo:|Límites declarados|Decidido por/);
    assert.doesNotMatch(markdown, /(?:RESPONSE|IDENTITY|BODY)-EN-SECRET/);
    assert.equal(readFileSync(result.path, "utf8"), markdown);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    context.close();
  }
});

test("informe: parseReportLang acepta es/en y rechaza otro idioma", () => {
  assert.equal(parseReportLang(undefined), "es");
  assert.equal(parseReportLang(""), "es");
  assert.equal(parseReportLang(" ES "), "es");
  assert.equal(parseReportLang("en"), "en");
  assert.equal(parseReportLang("inglés"), "en");
  assert.throws(() => parseReportLang("fr"), /Uso: \/informe \[en\]/);
});

test("informe: «Para limpiar» lista las escrituras que devolvieron un identificador y las direcciones de correo, sin los inicios de sesión", async () => {
  const context = setup();
  const server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      if (request.url === "/api/users" && request.method === "POST") return response.writeHead(201, { "content-type": "application/json", location: "/api/users/4711" }).end(JSON.stringify({ id: 4711, name: "prueba" }));
      if (request.url === "/api/login" && request.method === "POST") return response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ session_id: "abcdef0123456789abcdef", user_id: 4711 }));
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ id: 4711 }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  context.scope.edit({ include: [base] });
  const http = new HttpClient(context.artifacts, () => context.scope.current());
  try {
    await http.send({ url: `${base}/api/users`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "prueba" }) });
    await http.send({ url: `${base}/api/login`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "prueba" }) });
    await http.send({ url: `${base}/api/users/4711` });
    context.db.exec("create table if not exists mail_addresses(address text primary key, label text not null, mailbox text not null, created_at integer not null, session_id text)");
    context.db.prepare("insert into mail_addresses(address,label,mailbox,created_at,session_id) values(?,?,?,?,?)").run("lean+prueba1@example.com", "prueba1", "lean@example.com", Date.now(), "s1");
    const report = (await generateReport(context)).markdown;
    const section = report.split("## Para limpiar")[1]!.split("## Anexo:")[0]!;
    assert.match(section, /POST http:\/\/127\.0\.0\.1:[0-9]+\/api\/users \| 4711 \| 201 \|/);
    assert.doesNotMatch(section, /\/api\/login/, "un inicio de sesión no es un recurso creado");
    assert.doesNotMatch(section, /abcdef0123456789abcdef/);
    assert.match(section, /lean\+prueba1@example\.com \(prueba1\)/);
    const rows = section.split("\n").filter((line) => line.startsWith("| ") && !line.startsWith("| Fecha") && !line.startsWith("| ---"));
    assert.equal(rows.length, 1, "el GET no es una creación");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    context.close();
  }
});

test("informe: proyecto vacío y evidencia ajena a HTTP no inventan reproducción", async () => {
  const context = setup();
  try {
    const empty = await generateReport(context);
    assert.match(empty.markdown, /No hay hallazgos verificados/);
    assert.match(empty.markdown, /No hay alcance autorizado registrado/);
    const text = context.artifacts.put("nota manual", "text/plain", "test");
    const missing = context.artifacts.put("será retirado", "text/plain", "test");
    const finding = context.findings.record({ title: "Candidato con nota", kind: "manual", asset: "example.test", summary: "No reproducido", evidence: [text.hash, missing.hash] }, "s1");
    context.db.prepare("delete from artifacts where hash=?").run(missing.hash);
    const report = (await generateReport(context)).markdown;
    assert.match(report, /sin intercambio HTTP interpretable/);
    assert.match(report, /Artefacto no disponible/);
    assert.match(report, /No se pudieron derivar pasos HTTP/);
    assert.match(report, new RegExp(finding.id.slice(0, 8)));
  } finally { context.close(); }
});

test("informe: secretos de URL, formularios, texto libre y redactor de identidades", async () => {
  const context = setup();
  try {
    const artifact = context.artifacts.put(JSON.stringify({ request: { method: "POST", url: "https://USER-URL-SECRET:PASS-URL-SECRET@example.test/login?api_key=KEY-URL-SECRET", headers: { Cookie: "session=SESSION-FORM-SECRET", "content-type": "application/x-www-form-urlencoded" }, body: "password=PASS-FORM-SECRET&name=ana" }, response: { status: 200, headers: {}, body: "token=TOKEN-TEXT-SECRET", bodyBytes: 23, truncated: false } }), "application/json", "http");
    context.findings.record({ title: "Login", kind: "autenticación", asset: "https://example.test/login", summary: "USER-URL-SECRET PASS-URL-SECRET KEY-URL-SECRET SESSION-FORM-SECRET PASS-FORM-SECRET TOKEN-TEXT-SECRET KNOWN-IDENTITY-SECRET", evidence: [artifact.hash] }, "s1");
    const report = (await generateReport({ ...context, redact: (text) => text.replaceAll("KNOWN-IDENTITY-SECRET", "<identidad ana>") })).markdown;
    assert.doesNotMatch(report, /(?:URL|FORM|TEXT|IDENTITY)-SECRET/);
    assert.match(report, /name=ana/);
    assert.match(report, /identidad ana/);
    assert.match(report, /POST https:\/\/example\.test\/login/);
  } finally { context.close(); }
});

test("informe: redacta secretos de JSON embebido, HTML y XML antes de mostrar fragmentos", async () => {
  const context = setup();
  try {
    const body = '<script>config={"token":"SCRIPT-SECRET"}</script><input name="password" value="HTML-SECRET"><meta name="csrf-token" content="META-SECRET"><access_token>XML-SECRET</access_token>';
    const artifact = context.artifacts.put(JSON.stringify({ request: { method: "GET", url: "https://example.test/", headers: {} }, response: { status: 200, headers: { "content-type": "text/html" }, body, bodyBytes: body.length, truncated: false } }), "application/json", "http");
    context.findings.record({ title: "Datos en la respuesta", kind: "exposición", asset: "https://example.test/", summary: "SCRIPT-SECRET HTML-SECRET META-SECRET XML-SECRET", evidence: [artifact.hash] }, "s1");
    const report = (await generateReport(context)).markdown;
    assert.doesNotMatch(report, /(?:SCRIPT|HTML|META|XML)-SECRET/);
    assert.match(report, /HTTP 200/);
  } finally { context.close(); }
});

test("informe: incluye activos probados sin hallazgos y redacta secretos de evidencia no citada", async () => {
  const context = setup();
  let requests = 0;
  const server = createServer((_request, response) => {
    requests++;
    response.writeHead(200, { "content-type": "application/json" }).end('{"token":"UNLINKED-SECRET"}');
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  context.scope.edit({ include: [base] });
  try {
    const http = new HttpClient(context.artifacts, () => context.scope.current());
    await http.send({ url: `${base}/health` });
    const note = context.artifacts.put("nota", "text/plain", "test");
    context.findings.record({ title: "Nota del operador", kind: "manual", asset: "otro.test", summary: "Reflejo UNLINKED-SECRET", evidence: [note.hash] }, "s1");
    const result = await generateReport(context);
    assert.ok(result.markdown.includes(`Activos con respuestas HTTP guardadas en el proyecto: ${base}`));
    assert.doesNotMatch(result.markdown, /UNLINKED-SECRET/);
    assert.equal(requests, 1);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    context.close();
  }
});

test("informe: redacta variantes codificadas y formatos de credenciales sin alterar códigos HTTP", () => {
  const redactor = new ReportRedactor();
  const sources = [
    "password=SECRETO%20FORMULARIO\nReflejado: SECRETO FORMULARIO",
    '<input name=password value=HTMLSECRET>',
    'Content-Disposition: form-data; name="password"\r\n\r\nMULTIPARTSECRET\r\n--boundary--',
    "Cookie: sid=COOKIESECRET",
    JSON.stringify({ data: JSON.stringify({ token: "NESTEDSECRET" }) }),
    "https://x.test/?token=FIRSTSECRET&token=SECONDSECRET\nReflejado SECONDSECRET",
    "https://x.test/#FRAGMENTSECRET\nReflejado FRAGMENTSECRET",
  ];
  for (const source of sources) redactor.text(source);
  const body = redactor.text('{"code":200,"ok":true}');
  const result = redactor.finish(sources.join("\n") + `\nHTTP 200\n${body}`);
  assert.doesNotMatch(result, /SECRETO(?:%20| )FORMULARIO|HTMLSECRET|MULTIPARTSECRET|COOKIESECRET|NESTEDSECRET|FIRSTSECRET|SECONDSECRET|FRAGMENTSECRET/);
  assert.doesNotMatch(result, /omitida\] omitida\]/);
  assert.match(result, /HTTP 200/);
  assert.match(result, /"code": 200/);
  assert.match(result, /"ok": true/);
});

test("informe: un valor de un carácter no se aprende como secreto y el JSON del informe sigue siendo legible", () => {
  const redactor = new ReportRedactor();
  // Campos cortos que no son credenciales: antes se aprendían y se tapaban en todo el informe, y dejaban el JSON roto.
  redactor.text(JSON.stringify({ password: "{", token: "#", clave: "|", secret: "ok", apiKey: "GET", auth: "CLAVE-LARGA-123456" }));
  const record = { turno: 3, nota: "cuerpo {\"a\":1} con | y #", clave: "CLAVE-LARGA-123456" };
  const salida = redactor.finish(JSON.stringify(record));
  assert.doesNotMatch(salida, /CLAVE-LARGA-123456/, "la credencial de verdad se tapa");
  const vuelta = JSON.parse(salida) as typeof record;
  assert.equal(vuelta.turno, 3);
  assert.match(vuelta.nota, /con \| y #/, "los signos sueltos quedan intactos");
});
