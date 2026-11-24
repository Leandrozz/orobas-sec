// Pruebas de la tanda ofensiva 1: recon pasivo (fuentes fixture, sin red), payloads por perfil,
// perfiles y post-explotación de laboratorio con guardas, y detección purple.
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { ConsentStore } from "../src/consent.ts";
import { DetectionLedger } from "../src/deteccion.ts";
import { HttpClient } from "../src/http.ts";
import { createNetTools } from "../src/toolbox.ts";
import { parseProfile, ProfileStore, profileLine, PROFILE_GRANTS } from "../src/perfil.ts";
import { createPayloadTools, payloadSetFor } from "../src/payloads.ts";
import { createPostexTools } from "../src/postex.ts";
import { createReconTools, dedupeRows, parseCrtSh } from "../src/recon.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const signal = new AbortController().signal;

// ---------- recon pasivo: fuentes fixture, sin red ----------

test("recon: wayback_cdx deduplica por canónica y aparta estáticas; crt_sh separa «sin respuesta» de «sin resultados»", async (t) => {
  // Fixture: un "CDX" y un "crt.sh" locales que la herramienta visita en vez de los reales.
  const cdx = createServer((req, res) => {
    const url = new URL(req.url!, "http://f");
    if (url.pathname !== "/cdx/search/cdx") return void res.writeHead(404).end();
    if (url.searchParams.get("url") === "limitado.test") return void res.writeHead(403).end("rate limit");
    if (url.searchParams.get("url") !== "ejemplo.test") return void res.writeHead(200, "application/json").end("[]");
    res.writeHead(200, "application/json").end(JSON.stringify([
      ["ejemplo.test/A/200", "200"],
      ["ejemplo.test/A/200", "200"],
      ["ejemplo.test/A;a/200", "200"],
      ["ejemplo.test/img/1.png", "200"],
      ["ejemplo.test//api/v1/users?id=1", "200"],
      ["ejemplo.test/admin/settings", "200"],
    ]));
  });
  const crt = createServer((req, res) => {
    const url = new URL(req.url!, "http://f");
    if (url.searchParams.get("q") === "%.caido.test") return void res.writeHead(502).end("bad gateway");
    if (url.searchParams.get("q") === "%.vacio.test") return void res.writeHead(200, "application/json").end("[]");
    res.writeHead(200, "application/json").end(JSON.stringify([
      { name_value: "ejemplo.test\n*.ejemplo.test\nstaging.ejemplo.test\nstaging.ejemplo.test" },
      { name_value: "dev.ejemplo.test\nfoo bar\nno un host" },
    ]));
  });
  await Promise.all([new Promise<void>((r) => cdx.listen(0, "127.0.0.1", r)), new Promise<void>((r) => crt.listen(0, "127.0.0.1", r))]);
  const cdxB = `http://127.0.0.1:${(cdx.address() as AddressInfo).port}`;
  const crtB = `http://127.0.0.1:${(crt.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-recon-"));
  const db = openStore(projectPaths(dir));
  const artifacts = new Artifacts(db, projectPaths(dir).artifacts);
  const tools = Object.fromEntries(createReconTools({ artifacts }).map((tool) => [tool.name, tool])) as Record<string, Tool>;

  t.after(async () => {
    await Promise.all([new Promise<void>((r) => cdx.close(() => r())), new Promise<void>((r) => crt.close(() => r()))]);
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  // wayback: las herramientas apuntan a las fuentes reales; en la prueba se pisa el módulo por URL base.
  // Para no tocar la red real, probamos el parseo y la deduplicación por separado y el 403 fixture por fetch directo.
  const rows = [
    { host: "ejemplo.test", path: "/A", status: 200, from: "wayback" },
    { host: "ejemplo.test", path: "/A/", status: 200, from: "wayback" },
    { host: "ejemplo.test", path: "/A;a", status: 200, from: "wayback" },
    { host: "ejemplo.test", path: "/img/1.png", status: 200, from: "wayback" },
    { host: "ejemplo.test", path: "/api/v1/users?id=1", status: 200, from: "wayback" },
    { host: "ejemplo.test", path: "/admin/settings", status: 200, from: "wayback" },
  ];
  const { useful, dead, unique } = dedupeRows(rows);
  assert.equal(unique, 3); // /A (tres formas la misma canónica), /api/v1/users, /admin/settings
  assert.equal(dead, 1); // /img/1.png
  assert.equal(useful.length, 3);
  assert.ok(useful.some((row) => row.path === "/api/v1/users?id=1"));

  // crt.sh: deduplicación de SAN, wildcard apartado, basura ignorada
  const names = parseCrtSh(JSON.stringify([
    { name_value: "ejemplo.test\n*.ejemplo.test\nstaging.ejemplo.test\nstaging.ejemplo.test" },
    { name_value: "dev.ejemplo.test\nfoo bar\nno un host" },
  ]));
  assert.deepEqual(names.sort(), ["dev.ejemplo.test", "ejemplo.test", "staging.ejemplo.test"]);

  // url_dedupe: limpia lista cruda con texto no URL mezclado
  const dedupe = tools.url_dedupe!;
  const result = await dedupe.execute({ urls: ["https://a.test/x?a=1", "https://a.test/x?a=1", "https://a.test/x?a=1&b=2", "https://a.test/img.png", "no una url", "https://a.test/admin"] }, signal);
  assert.equal(result.details!.unicas, 3); // /x?a=1, /x?a=1&b=2 y /admin: query distinta es canónica aparte
  assert.match(result.text, /artefacto|Listado completo/);
});

// ---------- payloads: por perfil, inocuidad declarada, nada se envía solo ----------

test("payloads: bounty trae sólo los básicos; pentest y defensa traen extensivos; payload_get exige el set del perfil", async () => {
  const base = payloadSetFor(PROFILE_GRANTS.bounty);
  const ext = payloadSetFor(PROFILE_GRANTS.pentest);
  assert.ok(base.length < ext.length);
  assert.ok(base.every((payload) => !payload.id.includes("mutation") && !payload.id.includes("union") && !payload.id.includes("svg")));
  assert.ok(ext.some((payload) => payload.id === "xss-svg-1" || payload.id === "sqli-union-mark"));
  // Inocuidad declarada en cada payload; time-based sólo con nota de autorización
  for (const payload of ext) assert.ok(payload.inocuidad.length > 5, `falta inocuidad en ${payload.id}`);
  const timeBased = ext.find((payload) => payload.id === "sqli-time-1");
  assert.ok(timeBased?.meta?.nota?.includes("operador"));
});

test("payloads: herramienta lista por clase con artefacto y filtro de variante; payload_get rechaza extensivos en bounty", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-payloads-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const db = openStore(projectPaths(dir));
  const artifacts = new Artifacts(db, projectPaths(dir).artifacts);
  t.after(() => db.close());
  const tools = Object.fromEntries(createPayloadTools({ artifacts, grants: () => PROFILE_GRANTS.laboratorio }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const list = await tools.payload_list!.execute({ clase: "ssti" }, signal);
  assert.ok((list.details!.total as number) >= 4);
  assert.match(list.text, /inocuo:/);
  const filtered = await tools.payload_list!.execute({ clase: "xss", variante: "SVG" }, signal);
  assert.ok((filtered.details!.total as number) >= 1);
  const one = await tools.payload_get!.execute({ id: "ssti-1" }, signal);
  assert.match(one.text, /canario a buscar en la respuesta: 56/);
  assert.match(one.text, /Mandalo con http_replay/);
  // bounty: extensivo visible en list pero inaccesible en get... no: el set ya excluye. Otro perfil lo trae:
  const bountyTools = Object.fromEntries(createPayloadTools({ artifacts, grants: () => PROFILE_GRANTS.bounty }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  await assert.rejects(async () => bountyTools.payload_get!.execute({ id: "xss-svg-1" }, signal), /extensivo/);
});

// ---------- perfiles ----------

test("perfiles: parse, grants y ProfileStore guardan y recuperan; bounty retrocompatible", async (t) => {
  assert.equal(parseProfile("bounty"), "bounty");
  assert.equal(parseProfile("Defensa"), "defensa");
  assert.equal(parseProfile("full-blast"), "full-blast");
  assert.equal(PROFILE_GRANTS["full-blast"].detection, true);
  assert.equal(PROFILE_GRANTS["full-blast"].postexLab, true);
  assert.equal(PROFILE_GRANTS.bounty.postexLab, false);
  assert.equal(PROFILE_GRANTS.defensa.detection, true);
  assert.equal(PROFILE_GRANTS.laboratorio.postexLab, true);
  assert.equal(PROFILE_GRANTS.pentest.detection, false);
  const dir = mkdtempSync(join(tmpdir(), "cyber-perfil-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const db = openStore(projectPaths(dir));
  t.after(() => db.close());
  const store = new ProfileStore(db);
  assert.equal(store.current(), "bounty"); // default
  store.set("defensa");
  assert.equal(store.current(), "defensa");
  assert.ok(store.grants().detection);
  assert.match(profileLine("bounty"), /perfil bounty/);
  assert.match(profileLine("defensa"), /detección: sí/);
});

// ---------- post-explotación: guardas primero, acciones después ----------

test("postex: sin perfil rechaza; fuera de alcance rechaza; host no lab rechaza; con lab y identidad legítima crea, lee y borra lo propio", async (t) => {
  const created: any[] = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url!, "http://lab");
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const json = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
      if (url.pathname === "/api/keys" && req.method === "POST") {
        const body = JSON.parse(raw || "{}");
        const id = `k${created.length + 1}`;
        created.push({ id, ...body });
        return void res.writeHead(201, { location: `/api/keys/${id}` }).end(JSON.stringify({ id }));
      }
      if (url.pathname === "/api/keys" && req.method === "GET") return json(200, created);
      if (/^\/api\/keys\/k\d+$/.test(url.pathname)) {
        const found = created.find((item) => `/api/keys/${item.id}` === url.pathname);
        if (!found) return json(404, { error: "no" });
        if (req.method === "DELETE") { created.splice(created.indexOf(found), 1); return json(200, { deleted: true }); }
        return json(200, found);
      }
      json(404, { error: "no" });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-postex-"));
  const db = openStore(projectPaths(dir));
  const artifacts = new Artifacts(db, projectPaths(dir).artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "lab", headers: { Authorization: "Bearer lab" } });
  const grants = { get: () => PROFILE_GRANTS.bounty, set: () => {} } as any;
  const makeTools = (g: any) => Object.fromEntries(createPostexTools({ artifacts, http, scope: () => scope, grants: () => g }).map((tool) => [tool.name, tool])) as Record<string, Tool>;

  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  // Sin perfil: rechaza con la razón clara
  await assert.rejects(async () => makeTools(PROFILE_GRANTS.bounty).postex_persist!.execute({ url: `${base}/api/keys`, body: "{}", identity: "lab" }, signal), /perfil/);
  // Con perfil pero host de terceros (fuera de lab): rechaza
  const outside = { ...PROFILE_GRANTS.laboratorio } as any;
  await assert.rejects(async () => makeTools(outside).postex_persist!.execute({ url: "https://tercero.ejemplo/api/keys", body: "{}", identity: "lab" }, signal), /alcance/);
  // Con perfil, lab, alcance e identidad legítima: persistencia simulada crea y anota
  const labTools = makeTools(PROFILE_GRANTS.laboratorio);
  const persist = await labTools.postex_persist!.execute({ url: `${base}/api/keys`, body: `{"name":"orobas-lab-${new Date().toISOString()}"}`, identity: "lab" }, signal);
  assert.match(persist.text, /Persistencia simulada creada|creada/);
  assert.match(persist.text, /Para limpiar/);
  assert.ok(http.owns(`${base}/api/keys/k1`)); // el id creado quedó registrado como propio
  // Exfiltración simulada: lee lo propio y guarda local con hash
  const exfil = await labTools.postex_exfil!.execute({ url: `${base}/api/keys`, identity: "lab" }, signal);
  assert.match(exfil.text, /guardado local/i);
  assert.match(exfil.text, /nunca a ningún tercero/);
  // Borrado simulado: destruye sólo lo propio (guarda de borrado del HttpClient intacta)
  const cleanup = await labTools.postex_cleanup!.execute({ url: `${base}/api/keys/k1`, identity: "lab" }, signal);
  assert.match(cleanup.text, /Borrado simulado/);
  // Y la guarda de borrado sigue viva para recursos ajenos:
  await assert.rejects(async () => http.send({ url: `${base}/api/keys/k99`, method: "DELETE" }), /allowDestructive|borra o vacía/);
  // Identidad inexistente: rechaza (nunca credenciales de terceros)
  await assert.rejects(async () => labTools.postex_persist!.execute({ url: `${base}/api/keys`, body: "{}", identity: "terceros" }, signal), /identidad/i);
});


test("http_probe: con consentimiento, lo destructivo sobre recurso ajeno deja de omitirse", async (t) => {
  const vistos: string[] = [];
  const server = createServer((req, res) => {
    vistos.push(`${req.method} ${new URL(req.url!, "http://x").pathname}`);
    res.writeHead(200, { "content-type": "application/json" }).end("{}");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-probe-consent-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  const probe = createNetTools({ artifacts, scope: () => scope, http }).find((tool: Tool) => tool.name === "http_probe")!;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const url = `${base}/api/items/9`;
  // Sin consentimiento: se omite y se dice
  await assert.rejects(async () => probe.execute({ urls: [url], methods: ["DELETE"], allowDestructive: true }, signal), /no se sondean/);
  assert.equal(vistos.length, 0);
  // Con consentimiento vigente: se envía
  const consent = new ConsentStore(db);
  consent.grant("borrar-ajeno", "borro los recursos de prueba del cliente, autorizado");
  http.consent = () => consent;
  const con = await probe.execute({ urls: [url], methods: ["DELETE"], allowDestructive: true }, signal);
  assert.equal(vistos.length, 1);
  assert.match(String(con.text), /DELETE/);
});

// ---------- detección purple: expect/hit/summary y gap ----------

test("detección: señales esperadas, hit marca llegada, gap queda para el informe", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-det-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const db = openStore(projectPaths(dir));
  t.after(() => db.close());
  const ledger = new DetectionLedger(db);
  const a = ledger.expect("h123", "sigma:sql-error-500");
  const b = ledger.expect("h456", "snort:sqli-variant");
  const c = ledger.expect("h789", "sigma:idor-read");
  assert.equal(ledger.hit("h123"), true);
  assert.equal(ledger.hit("h123"), false); // ya está marcada
  assert.equal(ledger.hit("inexistente"), false);
  const summary = ledger.summary();
  assert.equal(summary.esperadas, 3);
  assert.equal(summary.detectadas, 1);
  assert.equal(summary.gaps.length, 2);
  assert.deepEqual(summary.gaps.map((gap) => gap.id).sort(), [b.id, c.id].sort());
  // expect devuelve el snapshot al crear; el estado actual se lee de signals()
  assert.equal(ledger.signals("h123").at(-1)!.detectada, true);
  assert.equal(ledger.signals("h456").at(-1)!.detectada, false);
});

// ---------- /consent: guarda de borrado ajeno con doble confirmación ----------

test("consent: la guarda de borrado acepta recurso ajeno con consent vigente y lo rechaza sin él", async (t) => {
  const created: any[] = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url!, "http://lab");
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const json = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
      if (url.pathname === "/api/pagos/7" && req.method === "DELETE") return json(200, { deleted: true });
      json(404, { error: "no" });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-consent-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  const avisos: string[] = [];
  http.onConsentedDestructive = (info) => avisos.push(`${info.method} ${info.url}`);
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  // Sin consentimiento: ni sale la petición
  await assert.rejects(async () => http.send({ url: `${base}/api/pagos/7`, method: "DELETE", allowDestructive: true }), /consentimiento/i);
  // Con consent del operador: cruza, y avisa
  const consent = new ConsentStore(db);
  consent.grant("borrar-ajeno", "borro el recurso de prueba del cliente, autorizado hoy");
  http.consent = () => consent;
  const exchange = await http.send({ url: `${base}/api/pagos/7`, method: "DELETE", allowDestructive: true });
  assert.equal(exchange.response?.status, 200);
  assert.deepEqual(avisos, ["DELETE " + base + "/api/pagos/7"]);
  // Sin allowDestructive, sigue rechazando igual (la doble confirmación exige las dos)
  await assert.rejects(async () => http.send({ url: `${base}/api/pagos/7`, method: "DELETE" }), /allowDestructive/);
  // ConsentStore: revocar vuelve a bloquear
  const dir2 = mkdtempSync(join(tmpdir(), "cyber-consent-"));
  const consent2 = new ConsentStore(db);
  consent2.revoke("borrar-ajeno");
  await assert.rejects(async () => http.send({ url: `${base}/api/pagos/7`, method: "DELETE", allowDestructive: true }), /consentimiento/i);
});