import "./datos-tmp.ts";
// Regla de cierre honesta (punto 93): con presupuesto sobrante y una grieta concreta en el tráfico,
// el harness no acepta el cierre y nombra la grieta; un hallazgo que la nombre la cierra.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { ClosingGate } from "../src/cierre.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-cierre-"));

test("cierre: nombra las grietas del tráfico, un hallazgo las cierra, y no objeta sin presupuesto sobrante ni más de dos veces", async () => {
  const server = createServer((req, res) => {
    const json = (status: number, body = "{}") => void res.writeHead(status, { "content-type": "application/json" }).end(body);
    if (req.url === "/api/items/1") return json(200, '{"id":1}');
    if (req.url === "/api/items/2" && req.method === "GET") return json(403);
    if (req.url === "/api/items/2" && req.method === "PUT") return json(200, '{"id":2}');
    if (req.url === "/api/items/2/attachments") return json(200, '[{"id":9}]');
    if (req.url === "/api/notes/5") return json(200, '{"id":5}');
    if (req.url === "/api/secret" && req.method === "GET") return json(403);
    if (req.url === "/api/secret" && req.method === "POST") return json(201, '{"ok":true}');
    if (req.url === "/api/docs/7") return json(403);
    if (req.url === "/api/docs/7/") return json(200, '{"id":7}');
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const cwd = tmp();
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "", include: [parseRule(`${base}/`)], exclude: [] };
  const artifacts = new Artifacts(db, join(cwd, "artifacts"));
  const http = new HttpClient(artifacts, () => scope);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  let left: number | undefined = 0.9;
  const gate = new ClosingGate({ http, findings, budgetLeft: () => left });
  try {
    for (const [method, path] of [["GET", "/api/items/1"], ["GET", "/api/items/2"], ["PUT", "/api/items/2"], ["GET", "/api/items/2/attachments"], ["GET", "/api/notes/5"], ["GET", "/api/secret"], ["POST", "/api/secret"], ["GET", "/api/docs/7"], ["GET", "/api/docs/7/"]] as const) {
      await http.send({ url: `${base}${path}`, method, ...(method === "GET" ? {} : { headers: { "content-type": "application/json" }, body: "{}" }) });
    }
    const keys = gate.cracks().map((crack) => crack.key);
    for (const expected of [
      "escritura-con-id-ajeno:PUT /api/items/{n}",
      "sub-recurso-ajeno-servido:/api/items/{n}/attachments",
      "escritura-sobre-negado:POST /api/secret",
      "forma-de-ruta-servida:/api/docs/7",
      "familia-sin-escritura:/api/notes/{n}",
    ]) assert.ok(keys.includes(expected), `${expected} en ${keys.join(" | ")}`);
    // La forma servida no se cuenta además como id ajeno servido: es el mismo id.
    assert.ok(!keys.some((key) => key.startsWith("sub-recurso-ajeno-servido:/api/docs")));

    // Sin tráfico en el turno no se objeta; con presupuesto por debajo de la mitad tampoco.
    assert.equal(gate.objection(0), undefined);
    left = 0.4;
    assert.equal(gate.objection(9), undefined);
    left = undefined;
    assert.equal(gate.objection(9), undefined);
    left = 0.9;

    // Objeta nombrando una sola grieta: ruta, código y qué hacer; las demás quedan contadas.
    // El mismo PUT no se reporta dos veces (id ajeno y escritura sobre negado son la misma grieta acá).
    assert.ok(!keys.includes("escritura-sobre-negado:PUT /api/items/2"), keys.join(" | "));
    const first = gate.objection(9)!;
    assert.match(first.text, /^\[sistema\] Antes de cerrar: queda el 90% del presupuesto y el tráfico muestra una grieta concreta sin resolver:\n/);
    assert.equal(first.cracks.length, 1);
    assert.match(first.text, /PUT \/api\/items\/\{n\} aceptó el id 2 con HTTP 200, y ese id te lo negaron al leerlo en \/api\/items\/\{n\} \(HTTP 403\)/);
    assert.doesNotMatch(first.text, /attachments/, "una grieta por objeción");
    assert.match(first.text, /Una sola acción: .*finding_record.* Hay \d+ más/);
    assert.doesNotMatch(first.text, /seguir probando/i);

    // Un hallazgo sobre el recurso cierra su familia y sus hijos, en cualquier estado.
    const finding = findings.record({ title: "PUT sobre item ajeno", kind: "control de acceso", asset: `${base}/api/items/2`, summary: "El PUT fue aceptado.", evidence: [], state: "pista" }, "s1");
    assert.ok(finding.id);
    const open = gate.open().map((crack) => crack.key);
    assert.ok(!open.some((key) => key.includes("/api/items/")), open.join(" | "));
    assert.ok(open.includes("escritura-sobre-negado:POST /api/secret"));

    // Cada grieta se objeta dos veces como mucho (sin intentarla) y después se deja cerrar, pero sigue abierta para el aviso.
    const pendingCracks = gate.objectionable().length;
    let rounds = 0;
    while (gate.objection(9) && rounds < 30) rounds++;
    assert.ok(rounds <= 2 * pendingCracks && rounds >= pendingCracks, `rondas: ${rounds} para ${pendingCracks} grietas`);
    assert.equal(gate.objection(9), undefined);
    assert.ok(gate.open().length >= 3);

    // Sin margen de peticiones HTTP tampoco objeta.
    const fresh = new ClosingGate({ http, findings, budgetLeft: () => 0.9 });
    http.limit = http.count + 2;
    assert.equal(fresh.objection(9), undefined);
    http.limit = undefined;
    assert.ok(fresh.objection(9));
  } finally {
    server.close();
    db.close();
  }
});

test("cierre: el motor objeta el cierre con la grieta concreta y acepta cuando un hallazgo la nombra", async () => {
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const server = createServer((req, res) => {
    const json = (status: number, body = "{}") => void res.writeHead(status, { "content-type": "application/json" }).end(body);
    if (req.url === "/api/items/1") return json(200, '{"id":1}');
    if (req.url === "/api/items/2" && req.method === "GET") return json(403);
    if (req.url === "/api/items/2" && req.method === "PUT") return json(200, '{"id":2}');
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const provider = resolveProvider("faux");
  // Sin objeciones de cobertura, para ver sólo la regla de cierre; presupuesto de USD 2 del que el simulado no gasta nada.
  const engine = new Engine({ cwd: tmp(), provider, budgetPico: 2n * 10n ** 12n, coverageObjections: 0, grafo: false, autoVerify: false });
  engine.scope.edit({ include: [`${base}/`] });
  const notices: string[] = [];
  engine.onNotice = (text) => notices.push(text);
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  try {
    provider.faux!.queue = [
      call("http_probe", { urls: [`${base}/api/items/1`, `${base}/api/items/2`], methods: ["GET", "PUT"] }),
      { text: "Terminé: la API protege los recursos ajenos." },
      call("finding_record", { state: "candidato", title: "PUT aceptado sobre un item ajeno", cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", kind: "control de acceso", asset: `${base}/api/items/2`, summary: "El PUT sobre el item 2 devolvió 200 aunque la lectura da 403.", evidence: ["h1"] }),
      { text: "Cierro: registré el candidato." },
    ];
    await engine.send("Evaluá la API");
    const tools = engine.agent.messages.filter((m) => m.role === "tool") as Array<{ content: string; isError?: boolean }>;
    assert.equal(engine.findings.list().length, 1, tools.map((tool) => tool.content).join("\n---\n"));
    const objections = engine.agent.messages.filter((m) => m.role === "user" && String(m.content).startsWith("[sistema] Antes de cerrar: queda el"));
    assert.equal(objections.length, 1, objections.map((m) => String(m.content)).join("\n---\n"));
    assert.match(String(objections[0]!.content), /queda el 100% del presupuesto/);
    assert.match(String(objections[0]!.content), /PUT \/api\/items\/\{n\} aceptó el id 2 con HTTP 200/);
    const last = engine.agent.messages.findLast((m) => m.role === "assistant")!;
    assert.match(String(last.content), /Cierro: registré el candidato/);
    const events = (engine.db.prepare("select type,payload from events where session_id=? and type like 'cierre.%' order by seq").all(engine.sessionId) as Array<{ type: string; payload: string }>);
    assert.deepEqual(events.map((row) => row.type), ["cierre.objetado"]);
    assert.match(events[0]!.payload, /escritura-con-id-ajeno:PUT \/api\/items\/\{n\}/);
    assert.deepEqual(notices.filter((text) => text.startsWith("Cierra con")), []);
    assert.equal(engine.findings.list().length, 1);
  } finally {
    await engine.close();
    server.close();
  }
});

test("cierre: si la grieta queda sin hallazgo, el operador se entera al cerrar y la regla se puede apagar", async () => {
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const server = createServer((req, res) => {
    const json = (status: number, body = "{}") => void res.writeHead(status, { "content-type": "application/json" }).end(body);
    if (req.url === "/api/notes/5") return json(200, '{"id":5}');
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  const run = async (closingGate: { maxPerCrack: number } | false) => {
    const provider = resolveProvider("faux");
    const engine = new Engine({ cwd: tmp(), provider, budgetPico: 2n * 10n ** 12n, coverageObjections: 0, grafo: false, autoVerify: false, closingGate });
    engine.scope.edit({ include: [`${base}/`] });
    const notices: string[] = [];
    engine.onNotice = (text) => notices.push(text);
    try {
      provider.faux!.queue = [call("http_probe", { urls: [`${base}/api/notes/5`] }), { text: "Terminé." }, { text: "Insisto: terminé." }, { text: "Cierro." }];
      await engine.send("Mirá la API");
      const objections = engine.agent.messages.filter((m) => m.role === "user" && String(m.content).startsWith("[sistema] Antes de cerrar: queda el"));
      const events = (engine.db.prepare("select type from events where session_id=? and type like 'cierre.%' order by seq").all(engine.sessionId) as Array<{ type: string }>).map((row) => row.type);
      return { objections: objections.map((m) => String(m.content)), events, notices, faux: provider.faux!.queue.length };
    } finally {
      await engine.close();
    }
  };
  try {
    const gated = await run({ maxPerCrack: 1 });
    assert.equal(gated.objections.length, 1);
    assert.match(gated.objections[0]!, /\/api\/notes\/\{n\} respondió 2xx y no se probó POST, PUT, PATCH ni DELETE/);
    assert.deepEqual(gated.events, ["cierre.objetado", "cierre.grietas"]);
    assert.equal(gated.notices.filter((text) => /^Cierra con 1 grieta del tráfico sin hallazgo que la nombre: familia-sin-escritura:\/api\/notes\/\{n\}/.test(text)).length, 1);
    assert.equal(gated.faux, 1, "con una objeción, la última respuesta de la cola no se usó");
    const off = await run(false);
    assert.equal(off.objections.length, 0);
    assert.deepEqual(off.events, []);
    assert.deepEqual(off.notices.filter((text) => text.startsWith("Cierra con")), []);
  } finally {
    server.close();
  }
});
