import "./datos-tmp.ts";
// Canario persistente: un valor único por campo que se siembra en un registro; el cliente HTTP avisa si
// reaparece en otra ruta o ante otra identidad, y si salió sin escapar en HTML (XSS almacenado).
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { CANARY_PROBE, CANARY_SCAN_BYTES, Canaries, type CanaryHit, classifyEscape, createCanaryTools, fieldSlug, routePath } from "../src/canario.ts";
import { Coverage } from "../src/coverage.ts";
import { HttpClient } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { labServer } from "./lab-web.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-canarios-"));

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

/**
 * Libro de visitas de laboratorio: guarda comentarios por API y los muestra en varias vistas. /comments
 * no escapa, /comments/seguro escapa, /admin/comments (sólo beto) no escapa, /grande los pone después
 * del tope de bytes que se revisa.
 */
function guestbook(): Server {
  const comments: Array<{ by: string; text: string }> = [];
  const esc = (text: string) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  return createServer((req, res) => {
    const url = new URL(req.url!, "http://x");
    const who = req.headers.authorization === "Bearer t-ana" ? "ana" : req.headers.authorization === "Bearer t-beto" ? "beto" : "";
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const html = (body: string) => void res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(body);
      const json = (status: number, body: unknown) => void res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
      if (url.pathname === "/api/comments" && req.method === "POST") {
        if (!who) return json(401, { error: "sin token" });
        const body = JSON.parse(raw || "{}");
        comments.push({ by: who, text: String(body.text ?? "") });
        return json(201, { ok: true, text: body.text });
      }
      if (url.pathname === "/api/comments") return json(200, comments);
      if (url.pathname === "/comments") return html(`<ul>${comments.map((c) => `<li>${c.text}</li>`).join("")}</ul>`);
      if (url.pathname === "/comments/seguro") return html(`<ul>${comments.map((c) => `<li title="${esc(c.text)}">${esc(c.text)}</li>`).join("")}</ul>`);
      if (url.pathname === "/admin/comments") return who === "beto" ? html(`<table>${comments.map((c) => `<tr><td>${c.by}</td><td>${c.text}</td></tr>`).join("")}</table>`) : json(403, { error: "no" });
      if (url.pathname === "/grande") return html(`${"x".repeat(CANARY_SCAN_BYTES + 100)}${comments.map((c) => c.text).join(" ")}`);
      json(404, { error: "no" });
    });
  });
}

function setup(base: string[]) {
  const cwd = tmp();
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "", include: base.map((url) => parseRule(`${url}/`)), exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
  http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto" } });
  const canaries = new Canaries(db, "s1");
  const hits: CanaryHit[] = [];
  canaries.onHit = (hit) => hits.push(hit);
  http.canarios = canaries;
  return { db, artifacts, http, canaries, hits, close: () => { db.close(); rmSync(cwd, { recursive: true, force: true }); } };
}

test("canarios: cómo salió el sufijo de prueba (literal, entidades, parcial, codificado, sin caracteres)", () => {
  const token = "orbcabc123_nombre";
  const at = (text: string) => classifyEscape(text, text.indexOf(token) + token.length);
  assert.equal(at(`<p>${token}<"'></p>`), "sin escapar");
  assert.equal(at(`<p>${token}&lt;&quot;&#39;&gt;</p>`), "escapado");
  assert.equal(at(`<p>${token}&#60;&#34;&#x27;&#62;</p>`), "escapado");
  assert.equal(at(`<a title="${token}&lt;"'&gt;">`), "parcial");
  assert.equal(at(`{"a":"${token}\\u003c\\u0022\\u0027\\u003e"}`), "codificado");
  assert.equal(at(`{"a":"${token}<\\"'>"}`), "sin escapar");
  assert.equal(at(`<p>${token}</p>`), "sin caracteres");
  // Un filtro que saca las comillas deja «<>»: sigue sin escapar. Sin «<», una comilla literal rompe el atributo.
  assert.equal(at(`<p>${token}<></p>`), "sin escapar");
  assert.equal(at(`<a title="${token}"'&gt;">`), "parcial");
  assert.equal(at(`<a href="/x">${token}</a>`), "sin caracteres");
  assert.equal(fieldSlug("Nombre visible (público)"), "nombrevisiblepublico");
  assert.equal(routePath("POST /api/users/42/perfil"), "/api/users/{n}/perfil");
  assert.equal(routePath("https://x.test/api/perfil?x=1"), "/api/perfil");
});

test("canarios: la siembra se anota; reaparece en otra ruta y ante otra identidad, con su escapado; el reflejo y la misma vista no cuentan; la cobertura de inyección lo acepta", async () => {
  const server = guestbook();
  const lab = labServer();
  const base = await listen(server);
  const labBase = await listen(lab);
  const { db, http, canaries, hits, close } = setup([base, labBase]);
  const coverage = new Coverage(db, http);
  const events = (type: string) => (db.prepare("select payload from events where type=? order by seq").all(type) as Array<{ payload: string }>).map((row) => JSON.parse(row.payload));
  try {
    // Sin canarios activos no se mira nada.
    await http.send({ url: `${base}/comments` });
    assert.equal(canaries.size, 0);
    assert.deepEqual(canaries.hits(), []);

    // Forma simple (sin caracteres de prueba): sirve igual para ver dónde reaparece.
    const plain = canaries.create("apodo", "POST /api/comments");
    assert.match(plain.token, /^orbc[a-z0-9]{6}_apodo$/);
    await http.send({ url: `${base}/api/comments`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text: plain.token }) }, "ana");
    assert.deepEqual(canaries.list()[0]!.sown.map((item) => [item.method, item.path, item.identity]), [["POST", "/api/comments", "ana"]]);
    assert.equal(events("canario.sembrado").length, 1);
    assert.equal(hits.length, 0, "el eco de la misma petición no es una reaparición");
    assert.match(coverage.minimumEvidence("inyeccion") ?? "", /ningún parámetro recibió comillas/);
    await http.send({ url: `${base}/comments` }, "ana");
    assert.equal(hits.length, 1);
    assert.deepEqual({ path: hits[0]!.path, identity: hits[0]!.identity, escape: hits[0]!.escape, html: hits[0]!.html, unescapedHtml: hits[0]!.unescapedHtml, otherRoute: hits[0]!.otherRoute }, { path: "/comments", identity: "ana", escape: "sin caracteres", html: true, unescapedHtml: false, otherRoute: true });
    assert.equal(coverage.minimumEvidence("inyeccion"), undefined, "un canario reaparecido es inyección probada");

    // Con caracteres de prueba: dice si cada vista escapa.
    const probe = canaries.create("comentario", "POST /api/comments");
    await http.send({ url: `${base}/api/comments`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text: `${probe.token}${CANARY_PROBE}` }) }, "ana");
    const before = hits.length;
    // La misma ruta de la siembra con la misma identidad no es «otra» vista.
    await http.send({ url: `${base}/api/comments` }, "ana");
    assert.equal(hits.length, before);
    // Otra identidad, misma ruta: los dos canarios, en JSON (no HTML).
    await http.send({ url: `${base}/api/comments` }, "beto");
    const beto = hits.slice(before);
    assert.deepEqual(beto.map((hit) => [hit.token, hit.escape, hit.html, hit.otherIdentity, hit.otherRoute]).sort(), [[plain.token, "sin caracteres", false, true, false], [probe.token, "sin escapar", false, true, false]].sort());
    // Vista HTML sin escapar: XSS almacenado probable.
    await http.send({ url: `${base}/comments` }, "ana");
    const raw = hits.at(-1)!;
    assert.deepEqual([raw.token, raw.escape, raw.unescapedHtml, raw.path], [probe.token, "sin escapar", true, "/comments"]);
    assert.match(raw.snippet, /<li>orbc[a-z0-9]{6}_comentario<"'><\/li>/);
    // Vista que escapa.
    await http.send({ url: `${base}/comments/seguro` }, "ana");
    assert.ok(hits.some((hit) => hit.token === probe.token && hit.path === "/comments/seguro" && hit.escape === "escapado" && !hit.unescapedHtml));
    // Panel de otro rol: otra ruta y otra identidad.
    await http.send({ url: `${base}/admin/comments` }, "beto");
    const admin = hits.find((hit) => hit.token === probe.token && hit.path === "/admin/comments")!;
    assert.deepEqual([admin.identity, admin.sownBy, admin.otherIdentity, admin.otherRoute, admin.unescapedHtml], ["beto", ["ana"], true, true, true]);
    assert.match(admin.exchange, /^h\d+$/);
    assert.ok(admin.artifact.startsWith("sha256:"));
    // La misma reaparición no se repite.
    const count = hits.length;
    await http.send({ url: `${base}/comments` }, "ana");
    assert.equal(hits.length, count);
    const logged = events("canario.reaparecido");
    assert.equal(logged.length, count);
    const last = logged.at(-1)!;
    assert.deepEqual([last.reaparecio_en, last.identidad, last.sembrado_en, last.sin_escapar_html], ["GET /admin/comments", "beto", "POST /api/comments", true]);
    assert.equal(canaries.hits().length, count);

    // Reflejo: el canario viaja en la petición y vuelve en su respuesta (/buscar del laboratorio web). No es almacenado.
    const echo = canaries.create("busqueda", "GET /buscar");
    await http.send({ url: `${labBase}/buscar?q=${encodeURIComponent(`${echo.token}${CANARY_PROBE}`)}` });
    assert.equal(hits.length, count);
    assert.equal(canaries.list().find((item) => item.id === echo.id)!.sown[0]!.path, "/buscar");

    // Costo acotado: lo que está después de CANARY_SCAN_BYTES no se mira.
    await http.send({ url: `${base}/grande` }, "ana");
    assert.ok(!hits.some((hit) => hit.path === "/grande"));

    // La herramienta lista declarado, sembrado y reaparecido.
    const [, list] = createCanaryTools(canaries);
    const view = await list!.execute({}, new AbortController().signal);
    assert.match(view.text, new RegExp(`${probe.id} ${probe.token} · campo comentario · declarado en POST /api/comments`));
    assert.match(view.text, /sembrado: POST \/api\/comments \(ana, h\d+\)/);
    assert.match(view.text, /reapareció: GET \/admin\/comments \(beto, h\d+\) · sin escapar en HTML/);
  } finally {
    server.close();
    lab.close();
    close();
  }
});

test("canarios: sin canarios activos el cliente HTTP no llama al observador; canary_new da las tres formas y los canarios sobreviven a otra sesión", async () => {
  const server = guestbook();
  const base = await listen(server);
  const { db, http, canaries, close } = setup([base]);
  try {
    let calls = 0;
    http.canarios = { size: 0, observe: () => { calls++; return []; } } as unknown as Canaries;
    await http.send({ url: `${base}/comments` });
    assert.equal(calls, 0);
    http.canarios = canaries;
    const [create] = createCanaryTools(canaries);
    const made = await create!.execute({ field: "bio", route: "PUT /api/perfil" }, new AbortController().signal);
    const token = String(made.details!.token);
    assert.match(made.text, new RegExp(`valor \\(con caracteres de prueba\\): ${token}<"'>`));
    assert.match(made.text, new RegExp(`simple .*: ${token}\\n`));
    assert.match(made.text, new RegExp(`email .*: ${token}@example\\.com`));
    await assert.rejects(Promise.resolve().then(() => create!.execute({ field: "", route: "x" }, new AbortController().signal)), /Falta el campo/);
    // Otra sesión del mismo proyecto vigila los mismos canarios: el segundo orden aparece tarde.
    const later = new Canaries(db, "s2");
    assert.equal(later.size, 1);
    assert.equal(later.list()[0]!.token, token);
  } finally {
    server.close();
    close();
  }
});

test("canarios: el motor avisa al agente en el turno en curso y, si no hay turno, en el próximo; y al operador", async () => {
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const server = guestbook();
  const base = await listen(server);
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider, budgetPico: 2n * 10n ** 12n, coverageObjections: 0, autoVerify: false, closingGate: false });
  engine.scope.edit({ include: [`${base}/`] });
  engine.http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
  engine.http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto" } });
  const notices: string[] = [];
  engine.onNotice = (text) => notices.push(text);
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  try {
    assert.ok(engine.catalog.available.has("canary_new") && engine.catalog.available.has("canary_list"));
    const canary = engine.canaries.create("comentario", "POST /api/comments");
    provider.faux!.queue = [
      call("http_request", { method: "POST", url: `${base}/api/comments`, identity: "ana", headers: { "content-type": "application/json" }, body: JSON.stringify({ text: `${canary.token}${CANARY_PROBE}` }) }),
      call("http_request", { url: `${base}/comments`, identity: "beto" }),
      { text: "Listo." },
    ];
    await engine.send("Sembrá el comentario y mirá la lista");
    const steered = engine.agent.messages.filter((m) => m.role === "user" && String(m.content).startsWith("[sistema] Canario reapareció")).map((m) => String(m.content));
    assert.equal(steered.length, 1, engine.agent.messages.map((m) => `${m.role}: ${String((m as { content?: unknown }).content ?? "").slice(0, 120)}`).join("\n"));
    assert.match(steered[0]!, new RegExp(`«${canary.token}» \\(campo comentario, sembrado en POST /api/comments por ana\\) salió en GET /comments \\(h\\d+, identidad beto\\), otra identidad que la de la siembra\\. SIN ESCAPAR en HTML: XSS almacenado probable`));
    assert.ok(notices.some((text) => text.startsWith(`Canario ${canary.token} (sembrado en POST /api/comments) reapareció en GET /comments ante beto: sin escapar en HTML — XSS almacenado probable.`)), notices.join("\n"));

    // Sin turno en curso (p. ej. una petición del verificador): viaja con el próximo mensaje.
    await engine.http.send({ url: `${base}/admin/comments` }, "beto");
    provider.faux!.queue = [{ text: "Visto." }];
    await engine.send("¿Qué más?");
    const next = engine.agent.messages.findLast((m) => m.role === "user" && String(m.content).startsWith("¿Qué más?"))!;
    assert.match(String(next.content), /\n\n<canarios>\n\[sistema\] Canario reapareció: .* salió en GET \/admin\/comments \(h\d+, identidad beto\)[\s\S]*<\/canarios>/);
    const title = engine.db.prepare("select title from sessions where id=?").get(engine.sessionId) as { title: string };
    assert.doesNotMatch(title.title, /canarios/);
  } finally {
    await engine.close();
    server.close();
  }
});
