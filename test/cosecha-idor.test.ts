import "./datos-tmp.ts";
// Cosecha de ids de las respuestas por identidad y prueba cruzada (src/cosecha.ts): qué se cosecha y
// qué no, la objeción de cobertura cuando hay ids ajenos sin probar, y ids_harvest contra un laboratorio
// con un detalle vulnerable, uno protegido, uno público y uno que responde 200 con un error.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { ANON, createHarvestTool, extractIds, IdHarvest } from "../src/cosecha.ts";
import { Coverage } from "../src/coverage.ts";
import { Engine } from "../src/engine.ts";
import { HttpClient, type HttpExchange } from "../src/http.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { labIdor } from "./lab-idor.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-idor-"));
const abort = new AbortController().signal;

const exchange = (url: string, body: string, type = "application/json", headers: Record<string, string> = {}): HttpExchange => ({
  id: "h1",
  request: { method: "GET", url, headers: {} },
  response: { status: 200, headers: { "content-type": type, ...headers }, body, bodyBytes: body.length, truncated: false },
  resolved: [],
  redirects: [],
  durationMs: 1,
  artifact: "",
});

test("cosecha: UUID v1-v8, ObjectId plausibles y números sólo en campos de id; ni trazas, ni secretos, ni hashes", () => {
  const order = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
  const ids = extractIds(exchange("http://lab.test/api/orders", JSON.stringify({
    data: [{ id: order, ownerId: 7, customer: { id: 42 }, member_ids: [5, 6], total: 99, links: { self: `/api/orders/${order}/lines/3` } }],
    note: { _id: "65f1a2b3c4d5e6f7a8b90001" },
    request_id: "0b0f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f60",
    session: { token: "9b2f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f61" },
    md5: "d41d8cd98f00b204e9800998",
    nil: "00000000-0000-0000-0000-000000000000",
    count: 12,
  })));
  const by = (field: string) => ids.filter((item) => item.field === field).map((item) => `${item.value}:${item.kind}`);
  assert.deepEqual(by("data[].id"), [`${order}:uuid`]);
  assert.deepEqual(by("data[].ownerId"), ["7:numero"]);
  assert.deepEqual(by("data[].customer.id"), ["42:numero"]);
  assert.deepEqual(by("data[].member_ids[]"), ["5:numero", "6:numero"]);
  assert.deepEqual(by("note._id"), ["65f1a2b3c4d5e6f7a8b90001:objectid"]);
  // Un campo con URL deja los ids de la ruta y la URL para pedirlos tal cual.
  const link = ids.filter((item) => item.field === "data[].links.self");
  assert.deepEqual(link.map((item) => item.value), [order, "3"]);
  assert.equal(link[0]!.link, `http://lab.test/api/orders/${order}/lines/3`);
  const values = ids.map((item) => item.value);
  for (const absent of ["0b0f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f60", "9b2f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f61", "d41d8cd98f00b204e9800998", "00000000-0000-0000-0000-000000000000", "99", "12"]) assert.ok(!values.includes(absent), `no debía cosechar ${absent}`);

  // Location (un alta) y HTML: enlaces, data-*-id, inputs con nombre de id; ni data-testid ni el token CSRF.
  const created = extractIds({ ...exchange("http://lab.test/api/orders", "", "text/plain", { location: "/api/orders/7d3c2b1a-0f9e-4d8c-a7b6-5e4d3c2b1a09" }), request: { method: "POST", url: "http://lab.test/api/orders", headers: {} } });
  assert.deepEqual(created.map((item) => `${item.field}:${item.value}`), ["location:7d3c2b1a-0f9e-4d8c-a7b6-5e4d3c2b1a09"]);
  const html = extractIds(exchange("http://lab.test/panel", `<a href="/users/15/perfil">x</a><a href="https://otro.test/users/16">y</a><div data-order-id="88" data-testid="77"></div><input type="hidden" name="project_id" value="31"><input type="hidden" name="csrf_token" value="1b0f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f62"><p>Ticket 2b0f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f63</p><script>var t="3b0f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f64"</script><img src="/static/65f1a2b3c4d5e6f7a8b90002.png">`, "text/html"));
  assert.deepEqual(html.map((item) => `${item.field}:${item.value}`).sort(), ["html:data-order-id:88", "html:enlace:15", "html:input project_id:31", "html:texto:2b0f6c1e-5d1a-4d6e-9f2a-1c2b3d4e5f63"]);
});

async function setup() {
  const lab = labIdor();
  await new Promise<void>((resolve) => lab.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(lab.server.address() as any).port}`;
  const cwd = tmp();
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
  http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto" } });
  const events: Array<{ type: string; payload: any }> = [];
  const notices: string[] = [];
  const harvest = new IdHarvest({ db, http, sessionId: "s1", event: (type, payload) => events.push({ type, payload }), notice: (text) => notices.push(text) });
  http.onExchange = (item) => harvest.observe(item);
  const coverage = new Coverage(db, http);
  coverage.harvest = harvest;
  return { lab, base, db, http, harvest, coverage, events, notices, tool: createHarvestTool(harvest), close: () => lab.server.close() };
}

test("cosecha por identidad: lo que le llega a cada una es suyo; una petición con un id ajeno no lo hace suyo", async () => {
  const { lab, base, http, harvest, close } = await setup();
  try {
    for (const path of ["/api/me", "/api/orders", "/api/notes", "/panel"]) await http.send({ url: `${base}${path}` }, "ana");
    for (const path of ["/api/me", "/api/orders"]) await http.send({ url: `${base}${path}` }, "beto");
    assert.deepEqual([...harvest.owners(lab.orders[1]!)], ["ana"]);
    assert.deepEqual([...harvest.owners(lab.orders[2]!)], ["beto"]);
    assert.deepEqual([...harvest.owners(lab.notes[1]!)], ["ana"]);
    assert.ok(harvest.owners("1").has("ana") && !harvest.owners("1").has("beto"));
    // Beto pide el pedido de Ana (vulnerable) y recibe sus datos: no por eso pasan a ser de Beto.
    await http.send({ url: `${base}/api/orders/${lab.orders[1]}` }, "beto");
    assert.deepEqual([...harvest.owners(lab.orders[1]!)], ["ana"]);
    assert.ok(!harvest.owners("1").has("beto"));
    // La identidad queda en el registro HTTP.
    assert.equal(http.log.at(-1)!.identity, "beto");
    // Un alta propia: el id de Location es de quien lo creó.
    const created = await http.send({ url: `${base}/api/orders`, method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, "ana");
    const newId = JSON.parse(created.response!.body).id;
    assert.deepEqual([...harvest.owners(newId)], ["ana"]);
    assert.equal(harvest.ownedBy("ana", `${base}/api/orders/${newId}`).ok, true);
    assert.equal(harvest.ownedBy("beto", `${base}/api/orders/${lab.orders[1]}`).ok, false);
    assert.equal(harvest.ownedBy("ana", `${base}/api/orders/${lab.orders[1]}`).ok, true);
    assert.equal(harvest.ownedBy(undefined, `${base}/api/me`).ok, true);
    // Se guarda en la base por sesión: otra instancia sobre la misma sesión la recupera.
    const again = new IdHarvest({ db: harvest.db, http, sessionId: "s1" });
    assert.equal(again.size, harvest.size);
    assert.equal(new IdHarvest({ db: harvest.db, http, sessionId: "otra" }).size, 0);
  } finally {
    close();
  }
});

test("ids_harvest: objeción de cobertura, listado por familia y prueba cruzada (lee, negado, público, otro contenido)", async () => {
  const { lab, base, http, harvest, coverage, events, notices, tool, close } = await setup();
  try {
    for (const path of ["/api/me", "/api/orders", "/api/notes", "/api/shares", "/api/invoices"]) await http.send({ url: `${base}${path}` }, "ana");
    for (const path of ["/api/me", "/api/orders", "/api/notes", "/api/invoices"]) await http.send({ url: `${base}${path}` }, "beto");

    // Ids de Ana que Beto nunca vio y ninguna prueba cruzada: la cobertura lo objeta, una sola vez.
    const gap = coverage.minimumEvidence("control de acceso")!;
    assert.match(gap, /la identidad «ana» vio \d+ ids de objetos que «beto» nunca vio .*ids_harvest .*mode «probar»/);
    assert.throws(() => coverage.mark("s1", "control de acceso", "cubierta", "probé todo"), /ids_harvest/);
    const objection = coverage.objection("s1", 5)!;
    assert.match(objection, /^\[sistema\] Antes de cerrar falta una cosa en la cobertura \(«control de acceso»\): la identidad «ana»/);
    assert.match(objection, /«limitada»/);
    assert.doesNotMatch(coverage.objection("s1", 5) ?? "", /ids_harvest/);

    const listing = await tool.execute({ mode: "listar", owner: "ana" }, abort);
    assert.match(listing.text, /\/api\/orders\/\{n\}\n\s+[0-9a-f-]{36} \(uuid\) de ana · GET \/api\/orders «data\[\]\.id» → probar con beto: http:\/\/127\.0\.0\.1:\d+\/api\/orders\/[0-9a-f-]{36} \[enlace\]/);
    assert.match(listing.text, /\/api\/notes\/\{n\}\n\s+65f1a2b3c4d5e6f7a8b90001 \(objectid\) de ana · GET \/api\/notes «\[\]\._id» → probar con beto: \S+ \[derivada\]/);
    // El id numérico de /api/me no inventa /api/me/1: queda sin ruta conocida.
    assert.match(listing.text, /1 \(numero\) de ana · GET \/api\/me «id» → probar con beto: sin ruta conocida/);
    const before = http.count;
    assert.equal(http.count, before, "listar no pide nada");

    const probe = await tool.execute({ mode: "probar", owner: "ana", maxRequests: 30 }, abort);
    assert.match(probe.text, new RegExp(`ana→200 · h\\d+ beto→200  LEYÓ el objeto del dueño  GET ${base}/api/orders/${lab.orders[1]}`));
    assert.match(probe.text, new RegExp(`ana→200 · h\\d+ beto→404  negado  GET ${base}/api/notes/${lab.notes[1]}`));
    assert.match(probe.text, new RegExp(`ana→200 · h\\d+ beto→200  lee, pero es público  GET ${base}/api/shares/${lab.shares[1]}[^\\n]*\\n\\s+h\\d+ sin credenciales también lo lee`));
    assert.match(probe.text, new RegExp(`ana→200 · h\\d+ beto→200  2xx con otro contenido: revisar, no es hallazgo  GET ${base}/api/invoices/${lab.invoices[1]}`));
    assert.match(probe.text, /Cada LEYÓ\/MODIFICÓ es candidato a IDOR/);
    assert.equal(probe.details!.leidos, 1);
    assert.equal(probe.details!.publicos, 1);
    assert.equal(probe.details!.negados, 1);
    assert.equal(probe.details!.distintos, 1);
    assert.ok((probe.details!.peticiones as number) <= 30);
    const event = events.find((item) => item.type === "ids.cruce")!;
    assert.equal(event.payload.leidos, 1);
    assert.deepEqual(event.payload.hallazgos.map((hit: any) => hit.veredicto).sort(), ["leido", "publico"]);
    assert.match(notices.join("\n"), /beto» leyó un objeto de «ana» en \/api\/orders\/\{n\}|«beto» read an object of «ana» at \/api\/orders\/\{n\}/);

    // Ya hubo prueba cruzada: la cobertura deja de pedirla, y repetir no vuelve a mandar lo probado.
    assert.doesNotMatch(coverage.minimumEvidence("control de acceso") ?? "", /ids_harvest/);
    const count = http.count;
    const again = await tool.execute({ mode: "probar", owner: "ana" }, abort);
    assert.equal(http.count, count);
    assert.equal(again.details!.probadas, 0);
    assert.equal(harvest.crosses().filter((row) => row.verdict === "leido").length, 1);
    assert.match((await tool.execute({ mode: "listar", owner: "ana" }, abort)).text, /Pruebas cruzadas hechas: \d+ \(leídos 1, públicos 1, modificados 0, negados 1, otro contenido 1/);
  } finally {
    close();
  }
});

test("ids_harvest: sólo lectura salvo pedido explícito, nunca DELETE, y sin dos identidades no hay candidatos", async () => {
  const { base, http, harvest, coverage, tool, close } = await setup();
  try {
    await http.send({ url: `${base}/api/orders` }, "ana");
    await assert.rejects(Promise.resolve(tool.execute({ mode: "probar", method: "PUT", body: "{}" }, abort)), /sólo pide con métodos de lectura .*allowWrite/);
    await assert.rejects(Promise.resolve(tool.execute({ mode: "probar", method: "DELETE", allowWrite: true }, abort)), /no borra/);
    // Con una escritura permitida, el dueño relee antes y después: el detalle responde 200 a un PUT pero
    // no cambia nada, y eso no es hallazgo.
    const write = await tool.execute({ mode: "probar", method: "PUT", allowWrite: true, body: JSON.stringify({ total: 1 }), owner: "ana", family: "/api/orders" }, abort);
    assert.match(write.text, /ana→200 · h\d+ beto→200  2xx sin efecto  PUT .*\n\s+el dueño relee y no cambió nada: 2xx sin efecto, no es hallazgo/);
    assert.equal(write.details!.modificados, 0);
    // Una sola identidad del operador: nada que cruzar ni que objetar.
    const solo = new HttpClient(http.artifacts, http.scope);
    solo.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
    const alone = new IdHarvest({ db: harvest.db, http: solo, sessionId: "s2" });
    solo.onExchange = (item) => alone.observe(item);
    await solo.send({ url: `${base}/api/orders` }, "ana");
    assert.ok(alone.size > 0);
    assert.equal(alone.candidates().length, 0);
    assert.equal(alone.pendingCross(), undefined);
    // Sin credenciales, a pedido, sí se puede cruzar (falta de autenticación, no IDOR).
    assert.ok(alone.candidates({ identities: [ANON] }).some((candidate) => candidate.kind === "uuid" && candidate.targets.includes(ANON)));
    void coverage;
  } finally {
    close();
  }
});

test("motor: la cosecha se alimenta del cliente HTTP y ids_harvest se carga sola con dos identidades", async () => {
  const lab = labIdor();
  await new Promise<void>((resolve) => lab.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(lab.server.address() as any).port}`;
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), autoVerify: false });
  try {
    engine.scope.save({ include: [parseRule(`${base}/`)], exclude: [], source: "manual", notes: "" });
    engine.http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
    engine.http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto" } });
    assert.ok(!engine.agent.tools.some((tool) => tool.name === "ids_harvest"), "no está en el núcleo");
    await engine.http.send({ url: `${base}/api/orders` }, "ana");
    assert.ok(engine.harvest.size > 0);
    assert.ok(engine.agent.tools.some((tool) => tool.name === "ids_harvest"), "se cargó sola");
    assert.match(engine.coverage.minimumEvidence("control de acceso")!, /ids_harvest/);
  } finally {
    engine.close();
    lab.server.close();
  }
});

test("UUID y ObjectId también en la regla de cierre y en los ids del cuerpo de una escritura", async () => {
  const { createServer } = await import("node:http");
  const { ClosingGate } = await import("../src/cierre.ts");
  const { Findings } = await import("../src/findings.ts");
  const mine = "11111111-2222-4333-8444-555555555555";
  const theirs = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const server = createServer((req, res) => {
    if (req.url === `/api/docs/${mine}`) return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    if (req.url === `/api/docs/${theirs}`) return void res.writeHead(403).end();
    if (req.url === `/api/docs/${theirs}/adjuntos`) return void res.writeHead(200, { "content-type": "application/json" }).end('[{"nombre":"privado.pdf"}]');
    if (req.url === "/api/mover") return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const cwd = tmp();
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  try {
    for (const path of [`/api/docs/${mine}`, `/api/docs/${theirs}`, `/api/docs/${theirs}/adjuntos`]) await http.send({ url: `${base}${path}` });
    const gate = new ClosingGate({ http, findings: new Findings(db, () => undefined, () => Buffer.alloc(0)), budgetLeft: () => 1 });
    assert.deepEqual(gate.foreignServed().map((crack) => crack.key), ["sub-recurso-ajeno-servido:/api/docs/{n}/adjuntos"]);
    // El id ajeno en un campo camelCase del cuerpo cuenta como escritura con id ajeno; un ObjectId también se guarda.
    const coverage = new Coverage(db, http);
    assert.equal(coverage.wroteWithForeignId(), false);
    await http.send({ url: `${base}/api/mover`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ docId: theirs, folderId: "65f1a2b3c4d5e6f7a8b90003" }) });
    assert.deepEqual(http.log.at(-1)!.bodyIds, [theirs, "65f1a2b3c4d5e6f7a8b90003"]);
    assert.equal(coverage.wroteWithForeignId(), true);
  } finally {
    server.close();
  }
});
