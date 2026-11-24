import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, get } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { setTimeout as wait } from "node:timers/promises";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { HttpClient } from "../src/http.ts";
import { startProbeListener } from "../src/listener.ts";
import { createProbeTools } from "../src/probes.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const signal = new AbortController().signal;
const named = (name: string) => ({ kind: "OBJECT", name });
const schema = {
  queryType: { name: "Query" }, mutationType: { name: "Mutation" },
  types: [
    { ...named("Query"), fields: [{ name: "user", args: [{ name: "id", type: { kind: "NON_NULL", ofType: { kind: "SCALAR", name: "ID" } } }], type: named("User") }] },
    { ...named("Mutation"), fields: [{ name: "renameUser", args: [{ name: "name", type: { kind: "SCALAR", name: "String" } }], type: named("User") }] },
    { ...named("User"), fields: [{ name: "owner", args: [], type: named("User") }] },
  ],
};

async function setup(t: TestContext, channel = false) {
  const requests: Array<{ path: string; headers: Record<string, any>; body: any }> = [];
  let uses = 0;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, "http://local");
    let raw = "";
    for await (const chunk of req) raw += chunk;
    let body: any = {};
    try { body = JSON.parse(raw); } catch { body = Object.fromEntries(new URLSearchParams(raw)); }
    requests.push({ path: url.pathname, headers: req.headers, body });
    const json = (status: number, value: unknown) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(value)); };
    if (["/graphql", "/closed-graphql", "/denied-graphql"].includes(url.pathname)) {
      if (body.query?.includes("SondaControl")) return json(200, { data: { __typename: "Query" } });
      if (body.query?.includes("__schema")) return url.pathname === "/graphql" ? json(200, { data: { __schema: schema } }) : json(200, { errors: [{ message: "GraphQL introspection disabled" }] });
      if (url.pathname === "/denied-graphql" && !req.headers.authorization) return json(200, { data: { user: null }, errors: [{ message: "Unauthorized" }] });
      return json(200, { data: { user: { id: "2", name: "Beto" } } });
    }
    if (url.pathname === "/preview") {
      if (!body.destination) return json(400, { error: "Falta URL" });
      // El objetivo del laboratorio visita únicamente el oyente local de la prueba.
      const destination = new URL(body.destination);
      if (destination.hostname !== "127.0.0.1") return json(400, { error: "Sólo laboratorio" });
      await new Promise<void>((resolve) => {
        const outgoing = get(destination, (incoming) => { incoming.resume(); incoming.on("end", resolve); });
        outgoing.on("error", () => resolve());
      });
      return json(200, { fetched: true });
    }
    if (url.pathname === "/reponer") { uses = 0; return json(200, { uses }); }
    if (url.pathname === "/state") return json(200, { uses });
    if (url.pathname === "/coupon") {
      if (uses) return json(409, { error: "Ya usado" });
      await wait(35);
      uses++;
      return json(200, { applied: true, uses });
    }
    if (url.pathname.startsWith("/csrf")) {
      if (!req.headers.cookie) return json(401, { error: "Falta cookie" });
      if (url.pathname === "/csrf-protected" && (req.headers.origin !== "https://tienda.test" || req.headers.referer !== "https://tienda.test/form" || req.headers["x-csrf-token"] !== "prueba" || body.csrf !== "prueba")) return json(403, { error: "Origen o token" });
      return json(200, { saved: true });
    }
    if (url.pathname === "/strings") {
      if (typeof body.note !== "string") return json(422, { error: "Tipo inválido" });
      return json(200, body);
    }
    return json(200, { ok: true });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-sondas-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "bearer", headers: { Authorization: "Bearer prueba" } });
  http.setIdentity({ name: "cookie", headers: { Cookie: "session=prueba", Origin: "https://tienda.test", Referer: "https://tienda.test/form", "X-CSRF-Token": "prueba" } });
  const tools = Object.fromEntries(createProbeTools({ http, artifacts, listener: channel ? { host: "127.0.0.1" } : undefined }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return { base, http, tools, artifacts, requests };
}

test("graphql_probe: descubre esquema, compara operaciones sin introspección y distingue errores con HTTP 200", async (t) => {
  const { base, tools, http, requests } = await setup(t);
  const probe = tools.graphql_probe!;
  const open = await probe.execute({ url: base, identity: "bearer", delayMs: 0 }, signal);
  assert.equal(open.details!.introspeccion, "habilitada");
  assert.match(open.text, /Query.user\(id:ID!\).*User/);
  assert.match(open.text, /Mutation.renameUser\(name:String\)/);
  assert.match(open.text, /otras cuentas/);
  assert.equal(open.details!.peticiones, 2);
  const closed = await probe.execute({ url: `${base}/closed-graphql`, identity: "bearer", operations: [{ query: 'mutation { renameUser(name:"prueba") { id } }' }], delayMs: 0 }, signal);
  assert.equal(closed.details!.introspeccion, "deshabilitada o restringida");
  assert.equal(closed.details!.peticiones, 4);
  assert.equal(closed.details!.senales, 1);
  assert.match(closed.text, /mutación.*sin autenticación/);
  assert.equal(requests.at(-1)!.headers.authorization, undefined);
  assert.equal(requests.at(-2)!.headers.authorization, "Bearer prueba");
  const denied = await probe.execute({ url: `${base}/denied-graphql`, identity: "bearer", operations: [{ query: "{ user(id:2) { id } }" }], delayMs: 0 }, signal);
  assert.equal(denied.details!.senales, 0);
  const count = http.count;
  await assert.rejects(async () => probe.execute({ url: base, maxRequests: 31 }, signal), /maxRequests/);
  assert.equal(http.count, count);
  const capped = await probe.execute({ url: base, operations: [{ query: "{ user { id } }" }], maxRequests: 2, delayMs: 0 }, signal);
  assert.equal(capped.details!.peticiones, 2);
  assert.equal(capped.details!.operaciones, 0);
  const deniedScope = await probe.execute({ url: "http://fuera-del-alcance.invalid/graphql", delayMs: 0 }, signal);
  assert.equal(deniedScope.details!.peticiones, 0);
  assert.match(deniedScope.text, /Fuera del alcance/);
});

test("outbound_probe: callback propio con evidencia, cierre del oyente y comparación sin canal", async (t) => {
  const { base, tools, artifacts } = await setup(t, true);
  const result = await tools.outbound_probe!.execute({ url: `${base}/preview`, method: "POST", param: "destination", baseline: "", delayMs: 0, waitMs: 50 }, signal);
  assert.equal(result.details!.visitas, 1);
  assert.equal(result.details!.peticiones, 2);
  assert.match(result.text, /Callback recibido/);
  const hash = (result.details!.callbacks as string[])[0]!;
  const inbound = JSON.parse(artifacts.read(hash).toString());
  assert.match(inbound.request.url, /^\/cyber-outbound\/[0-9a-f]{48}$/);
  assert.equal(inbound.response.status, 204);
  const listener = await startProbeListener({ host: "127.0.0.1" }, artifacts);
  const port = new URL(listener.url).port;
  await listener.close();
  const reopened = await startProbeListener({ host: "127.0.0.1", port: Number(port) }, artifacts);
  await reopened.close();
  for (const host of ["0.0.0.0", "::", "0:0:0:0:0:0:0:0"]) await assert.rejects(() => startProbeListener({ host }, artifacts), /concreta/);
  const plain = await setup(t);
  const fallback = await plain.tools.outbound_probe!.execute({ url: `${plain.base}/preview`, method: "POST", param: "destination", baseline: "", urls: [`${plain.base}/ok`, `${plain.base}/extra`], maxRequests: 2, delayMs: 0 }, signal);
  assert.equal(fallback.details!.canal, false);
  assert.equal(fallback.details!.visitas, 0);
  assert.equal(fallback.details!.peticiones, 2);
  assert.match(fallback.text, /Sin canal declarado.*no comprueba/);
  assert.match(fallback.text, /recortaron 1/);
});

test("race_probe: cupón de un uso acepta más en paralelo y el estado difiere del control", async (t) => {
  const { base, tools, http } = await setup(t);
  const params = { url: `${base}/coupon`, body: { coupon: "UNO" }, n: 4, delayMs: 0, reset: { url: `${base}/reponer` }, stateUrl: `${base}/state`, stateField: "uses", expected: 1, maxRequests: 14 };
  const result = await tools.race_probe!.execute(params, signal);
  assert.equal(result.details!.peticiones, 14);
  assert.equal(result.details!.comparables, true);
  const serial = result.details!.secuencial as any;
  const parallel = result.details!.paralelo as any;
  assert.equal(serial.aceptadas, 1);
  assert.equal(serial.coincideEsperado, true);
  assert.equal(parallel.aceptadas, 4);
  assert.equal(parallel.estadoFinal, 4);
  assert.equal(parallel.coincideEsperado, false);
  assert.match(result.text, /NO coincide/);
  await assert.rejects(async () => tools.race_probe!.execute({ ...params, maxRequests: 13 }, signal), /necesita 14/);
  const before = http.count;
  http.limit = before + 2;
  const budget = await tools.race_probe!.execute(params, signal);
  assert.equal(budget.details!.peticiones, 0);
  const parallelBudget = await Promise.all(Array.from({ length: 8 }, () => http.send({ url: `${base}/ok` })));
  assert.equal(parallelBudget.filter((exchange) => exchange.response).length, 2);
  assert.equal(http.count, before + 2);
});

test("csrf_check: variantes por cookie, token de identidad retirado y bearer sin peticiones", async (t) => {
  const { base, tools, http, artifacts, requests } = await setup(t);
  const check = tools.csrf_check!;
  const control = await http.send({ url: `${base}/csrf-protected`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Ana", csrf: "prueba" }) }, "cookie");
  const protectedResult = await check.execute({ id: control.id, delayMs: 0 }, signal);
  const variants = protectedResult.details!.variantes as any[];
  assert.deepEqual(variants.map((row) => row.aceptada), [true, false, false, false, false]);
  assert.equal(protectedResult.details!.peticiones, 5);
  const noOrigin = requests.at(-4)!;
  assert.equal(noOrigin.headers.origin, undefined);
  assert.equal(noOrigin.headers.referer, undefined);
  const noToken = requests.at(-2)!;
  assert.equal(noToken.headers["x-csrf-token"], undefined);
  assert.equal(noToken.body.csrf, undefined);
  assert.equal(noToken.headers.cookie, "session=prueba");
  const foreignEvidence = JSON.parse(artifacts.read(http.hashOf(variants[2].id)!).toString());
  assert.equal(foreignEvidence.request.headers.origin, "https://csrf.invalid");
  const weak = await check.execute({ url: `${base}/csrf-weak`, method: "POST", body: { name: "Ana" }, identity: "cookie", delayMs: 0 }, signal);
  assert.ok((weak.details!.variantes as any[]).every((row) => row.aceptada));
  const before = http.count;
  const bearer = await check.execute({ url: `${base}/csrf-weak`, identity: "bearer", headers: { cookie: "session=prueba" } }, signal);
  assert.equal(bearer.details!.peticiones, 0);
  assert.equal(http.count, before);
  assert.match(bearer.text, /No aplica.*bearer/);
  const padded = await check.execute({ url: `${base}/csrf-weak`, headers: { cookie: "session=prueba", Authorization: " Bearer prueba " } }, signal);
  assert.equal(padded.details!.peticiones, 0);
  assert.equal(http.count, before);
});

test("body_probe: sólo cadenas prueba vacío, larga, otro tipo y caracteres especiales con tope", async (t) => {
  const { base, tools, requests } = await setup(t);
  const result = await tools.body_probe!.execute({ url: `${base}/strings`, body: { note: "hola" }, maxRequests: 5 }, signal);
  assert.equal(result.details!.peticiones, 5);
  assert.equal(result.details!.mutaciones, 4);
  assert.deepEqual(requests.map((entry) => entry.body.note), ["hola", "", "x".repeat(4096), 0, "ñ€𝄞\"'<>\u0000"]);
  assert.match(result.text, /vacía/);
  assert.match(result.text, /muy larga/);
  assert.match(result.text, /otro tipo.*estado 200 → 422/);
  assert.match(result.text, /caracteres especiales/);
  assert.ok(result.text.length < 2200);
  const capped = await tools.body_probe!.execute({ url: `${base}/strings`, body: { note: "hola" }, maxRequests: 2 }, signal);
  assert.equal(capped.details!.peticiones, 2);
  assert.match(capped.text, /recortaron 3/);
});
