import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { Coverage } from "../src/coverage.ts";
import { HttpClient } from "../src/http.ts";
import { createHarTools, importHar } from "../src/importers/har.ts";
import { createPostmanTools } from "../src/importers/postman.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { createWebTools } from "../src/webtools.ts";
import { labServer } from "./lab-web.ts";

const abort = new AbortController().signal;

test("HAR: ruta y artefacto cargan superficie vista e identidades pendientes sin reenviar ni mostrar secretos", async () => {
  let received = 0;
  let cookie = "";
  const server = createServer((req, res) => { received++; cookie = req.headers.cookie ?? ""; res.end("ok"); });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const port = (server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-import-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  const source = readFileSync(new URL("../fixtures/sample.har", import.meta.url), "utf8").replaceAll("PORT", String(port));
  writeFileSync(join(cwd, "sample.har"), source);
  const tool = createHarTools({ http, artifacts, cwd })[0]!;
  try {
    const output = await tool.execute({ path: "sample.har" }, abort);
    assert.equal(received, 0);
    assert.equal(http.count, 0);
    assert.equal(http.log.length, 0);
    assert.equal(http.surface().length, 3, "la misma ruta en dos hosts conserva dos filas");
    const item = http.surface().find((row) => row.host === `127.0.0.1:${port}` && row.path === "/api/items/{n}")!;
    assert.equal(item.state, "visto");
    assert.deepEqual(item.methods, []);
    assert.deepEqual(item.seenMethods, ["GET"]);
    assert.deepEqual(item.params, ["?view"]);
    assert.deepEqual(http.surface().find((row) => row.path === "/api/items")!.params, ["name", "password"]);
    assert.match(output.text, /POST \/api\/items/);
    assert.match(output.text, /outside\.example.*1 entradas/);
    assert.doesNotMatch(JSON.stringify(output), /har-token-privado|har-cookie-privada|clave-privada/);
    assert.deepEqual(http.identityNames(), []);
    assert.equal(http.proposedIdentities().length, 2);
    assert.doesNotMatch(JSON.stringify(http.proposedIdentities()), /har-token-privado|har-cookie-privada/);
    const artifact = artifacts.put(source, "application/json", "fixture");
    await tool.execute({ artifact: artifact.hash }, abort);
    assert.equal(http.proposedIdentities().length, 2, "reimportar no duplica propuestas");
    const name = http.proposedIdentities().find((identity) => identity.headers.includes("cookie"))!.name;
    await assert.rejects(http.send({ url: `${base}/api/items` }, name), /No existe la identidad/);
    http.approveIdentity(name);
    await http.send({ url: `${base}/api/items` }, name);
    assert.equal(cookie, "session=har-cookie-privada");
    assert.equal(received, 1);
    assert.equal(http.surface().find((row) => row.path === "/api/items")!.state, "probado");
    const result = await http.send({ url: "https://outside.example/" }, name);
    assert.match(result.error!, /sólo está aprobada/);
    assert.equal(http.count, 1);
    assert.equal(http.redactIdentities("har-token-privado har-cookie-privada"), `<identidad har-127-0-0-1> <identidad ${name}>`);
  } finally {
    db.close();
    await new Promise<void>((done) => server.close(() => done()));
  }
});

test("HAR: valida todas las entradas antes de importar y no expone valores en errores", async () => {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cyber-import-")));
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const http = new HttpClient(artifacts, () => undefined);
  try {
    assert.throws(() => importHar({ log: { version: "1.2", entries: [{ request: { method: "GET", url: "https://example.test/a", headers: [] } }, { request: { url: "token-secret", headers: [] } }] } }, http), /entrada 2/);
    assert.deepEqual(http.surface(), []);
    assert.deepEqual(http.proposedIdentities(), []);
    const bad = artifacts.put('{"token":"token-secret"', "application/json", "fixture");
    const tool = createHarTools({ http, artifacts })[0]!;
    assert.throws(() => tool.execute({ artifact: bad.hash }, abort), /^Error: HAR inválido: el contenido no es JSON\.$/);
    assert.throws(() => importHar({ log: { version: "1.2", entries: [{ request: { method: "GET", url: "file:///etc/passwd", headers: [] } }] } }, http), /HAR inválido/);
  } finally { db.close(); }
});


test("superficie importada: la cobertura sigue pidiendo pruebas propias", () => {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cyber-import-")));
  const db = openStore(paths);
  const http = new HttpClient(new Artifacts(db, paths.artifacts), () => undefined);
  const coverage = new Coverage(db, http);
  try {
    for (const path of ["/robots.txt", "/api/items/1", "/api/login", "/config", "/backup"]) http.observe({ url: `https://example.test${path}`, method: "POST", bodyKeys: ["password"] });
    assert.match(coverage.minimumEvidence("reconocimiento")!, /menos de cinco/);
    assert.match(coverage.minimumEvidence("control de acceso")!, /no se pidió ningún recurso/);
    assert.match(coverage.minimumEvidence("configuracion")!, /no se consultó ninguna ruta/);
    assert.match(coverage.minimumEvidence("autenticacion")!, /no hubo ningún POST/);
    assert.match(coverage.minimumEvidence("logica de negocio")!, /no se envió ningún cuerpo/);
    assert.ok(coverage.unvisitedCommon().includes("/robots.txt"));
    assert.equal(http.log.length, 0);
    assert.equal(http.count, 0);
  } finally { db.close(); }
});

const fixture = (name: string) => JSON.parse(readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8"));

async function setup() {
  let requests = 0;
  const server = labServer();
  server.on("request", () => requests++);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-postman-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(base)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  return { cwd, base, artifacts, http, requests: () => requests, close: () => { server.close(); db.close(); } };
}

test("Postman: carpetas, entorno, parámetros y ejemplos vistos sin ejecutar scripts ni peticiones", async () => {
  const ctx = await setup();
  try {
    const environment = fixture("sample.postman-environment.json");
    environment.values[0].value = ctx.base;
    writeFileSync(join(ctx.cwd, "environment.json"), JSON.stringify(environment));
    writeFileSync(join(ctx.cwd, "collection.json"), JSON.stringify(fixture("sample.postman.json")));
    const tool = createPostmanTools(ctx)[0]!;
    const result = await tool.execute({ path: "collection.json", environmentPath: "environment.json" }, abort);
    assert.equal(result.details!.operaciones, 3);
    assert.deepEqual(result.details!.fueraDeAlcance, ["fuera.invalid"]);
    assert.match(result.text, /Scripts no ejecutados: 1/);
    assert.equal(ctx.requests(), 0);
    assert.equal(ctx.http.count, 0);
    assert.equal(ctx.http.log.length, 0);
    assert.deepEqual(ctx.http.identityNames(), []);
    const rows = ctx.http.surface();
    const get = rows.find((row) => row.path === "/api/items/{n}")!;
    assert.equal(get.host, new URL(ctx.base).host);
    assert.equal(get.state, "visto");
    assert.deepEqual(get.methods, []);
    assert.deepEqual(get.seenMethods, ["GET"]);
    assert.ok(get.params.includes("?limit"));
    assert.ok(get.params.includes("{id}"));
    assert.ok(!get.params.includes("?disabled"));
    const body = ctx.http.observed.find((row) => row.method === "POST")!.body!;
    assert.deepEqual(JSON.parse(body), { title: "mate", qty: 2, password: "<credencial>", nested: { token: "<credencial>" } });
    assert.doesNotMatch(JSON.stringify([result, ctx.http.observed, rows]), /clave-ejemplo|token-entorno-privado|token-coleccion/);
    const count = ctx.http.observed.length;
    const artifact = ctx.artifacts.put(JSON.stringify(fixture("sample.postman.json")), "application/json", "fixture");
    const envArtifact = ctx.artifacts.put(JSON.stringify(environment), "application/json", "fixture");
    await tool.execute({ artifact: artifact.hash, environmentArtifact: envArtifact.hash }, abort);
    assert.equal(ctx.http.observed.length, count, "reimportar no duplica operaciones");
  } finally { ctx.close(); }
});

test("Postman: valida toda la colección antes de cargar operaciones y no filtra errores con secretos", async () => {
  const ctx = await setup();
  try {
    const tool = createPostmanTools(ctx)[0]!;
    const collection = fixture("sample.postman.json");
    collection.item.push({ request: { method: "POST", url: "{{sin_definir}}/items" } });
    const ref = ctx.artifacts.put(JSON.stringify(collection), "application/json", "fixture");
    await assert.rejects(async () => tool.execute({ artifact: ref.hash }, abort), /variables sin resolver/);
    assert.equal(ctx.http.observed.length, 0);
    const broken = ctx.artifacts.put('{"token":"secreto-no-mostrar",', "application/json", "fixture");
    await assert.rejects(async () => tool.execute({ artifact: broken.hash }, abort), (error: Error) => {
      assert.match(error.message, /JSON válido/);
      assert.doesNotMatch(error.message, /secreto-no-mostrar/);
      return true;
    });
    const unsupported = ctx.artifacts.put('{"info":{"schema":"v1"},"item":[]}', "application/json", "fixture");
    await assert.rejects(async () => tool.execute({ artifact: unsupported.hash }, abort), /Postman v2.1/);
    const cyclic = fixture("sample.postman.json");
    cyclic.variable = [{ key: "base", value: "{{base}}" }];
    const cycle = ctx.artifacts.put(JSON.stringify(cyclic), "application/json", "fixture");
    await assert.rejects(async () => tool.execute({ artifact: cycle.hash }, abort), /variables sin resolver o cíclicas/);
    assert.equal(ctx.requests(), 0);
  } finally { ctx.close(); }
});

test("Postman: los valores secretos de entorno tampoco aparecen reflejados en ruta o cuerpo", async () => {
  const ctx = await setup();
  try {
    const collection = { info: fixture("sample.postman.json").info, item: [{ request: { method: "POST", url: `${ctx.base}/recover/{{opaque}}`, body: { mode: "raw", raw: '{"echo":"{{opaque}}","qty":2}' } } }] };
    const environment = { values: [{ key: "opaque", type: "secret", value: "secreto-reflejado" }] };
    const artifact = ctx.artifacts.put(JSON.stringify(collection), "application/json", "fixture");
    const env = ctx.artifacts.put(JSON.stringify(environment), "application/json", "fixture");
    const result = await createPostmanTools(ctx)[0]!.execute({ artifact: artifact.hash, environmentArtifact: env.hash }, abort);
    assert.doesNotMatch(JSON.stringify([result, ctx.http.observed, ctx.http.surface()]), /secreto-reflejado/);
    assert.deepEqual(JSON.parse(ctx.http.observed[0]!.body!), { echo: "<credencial>", qty: 2 });
    assert.equal(ctx.requests(), 0);
  } finally { ctx.close(); }
});

test("OpenAPI local: servidores, referencias internas, parámetros heredados y cuerpo al mapa sin red", async () => {
  const ctx = await setup();
  try {
    writeFileSync(join(ctx.cwd, "openapi.json"), JSON.stringify(fixture("sample.openapi.json")));
    const tool = createWebTools(ctx).find((tool) => tool.name === "openapi_import")!;
    const result = await tool.execute({ path: "openapi.json", baseUrl: ctx.base }, abort);
    assert.equal(result.details!.operaciones, 2);
    assert.match(result.text, /GET\s+\/items\/\{id\}\s+auth\s+params: \{id\} \?limit/);
    assert.match(result.text, /POST\s+\/items\s+pública\s+cuerpo: title, qty, password/);
    const get = ctx.http.surface().find((row) => row.path === "/v1/items/{n}")!;
    assert.equal(get.host, new URL(ctx.base).host);
    assert.ok(get.params.includes("?limit"));
    assert.ok(get.params.includes("{id}"));
    assert.equal(get.state, "visto");
    assert.deepEqual(JSON.parse(ctx.http.observed.find((row) => row.method === "POST")!.body!), { title: "mate", qty: 2, password: "<credencial>" });
    assert.equal(ctx.requests(), 0);
    assert.equal(ctx.http.count, 0);
    assert.equal(ctx.http.log.length, 0);
    await assert.rejects(async () => tool.execute({ path: "openapi.json" }, abort), /servidor absoluto o baseUrl/);
    const spec = fixture("sample.openapi.json");
    spec.servers = [{ url: "https://fuera.invalid/api" }];
    spec.paths["/externa"] = { $ref: `${ctx.base}/openapi.json` };
    const ref = ctx.artifacts.put(JSON.stringify(spec), "application/json", "fixture");
    const external = await tool.execute({ artifact: ref.hash }, abort);
    assert.match(external.text, /Hosts fuera del alcance: fuera.invalid/);
    assert.equal(external.details!.referenciasExternas, 1);
    assert.equal(ctx.requests(), 0, "las referencias externas no se descargan");
  } finally { ctx.close(); }
});


test("HAR: una credencial de una entrada posterior no queda reflejada en superficie", () => {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cyber-import-")));
  const db = openStore(paths);
  const http = new HttpClient(new Artifacts(db, paths.artifacts), () => undefined);
  try {
    const output = importHar({ log: { version: "1.2", entries: [
      { request: { method: "POST", url: "https://example.test/reset/HAR-REFLECTED-SECRET?HAR-REFLECTED-SECRET=x", headers: [], postData: { text: '{"HAR-REFLECTED-SECRET":1}' } } },
      { request: { method: "GET", url: "https://example.test/", headers: [{ name: "Authorization", value: "Bearer HAR-REFLECTED-SECRET" }] } },
    ] } }, http);
    assert.doesNotMatch(JSON.stringify(output), /HAR-REFLECTED-SECRET/);
    assert.doesNotMatch(JSON.stringify(http.surface()), /HAR-REFLECTED-SECRET/);
    assert.doesNotMatch(JSON.stringify(http.observed), /HAR-REFLECTED-SECRET/);
    assert.equal(http.count, 0);
    assert.equal(http.proposedIdentities().length, 1);
    http.setIdentity({ name: "ana", headers: { authorization: "Bearer ana" } });
    assert.equal(http.redactIdentities(http.redactIdentities("ana")), "<identidad ana>", "el enmascarado preserva nombres de identidad");
    // Un trozo de cookie que no es credencial («lang=es») no convierte cada «es» del texto en una marca.
    http.setIdentity({ name: "nav", headers: { cookie: "lang=es; theme=dark; sid=SESION-LARGA-123456" } });
    assert.equal(http.redactIdentities("el mensaje es: está, dark, SESION-LARGA-123456"), "el mensaje es: está, dark, <identidad nav>");
  } finally { db.close(); }
});

test("importadores: secretos indirectos, claves y reflejos se eliminan también de los ejemplos", async () => {
  const ctx = await setup();
  try {
    const secret = "privado.[(abc)]+$";
    const environment = { values: [{ key: "opaque", type: "secret", value: "{{value}}" }, { key: "value", value: secret }] };
    const collection = {
      info: fixture("sample.postman.json").info,
      auth: { type: "bearer", bearer: [{ key: "token", value: "{{opaque}}" }] },
      item: [{ request: {
        method: "POST", url: `${ctx.base}/reset/{{opaque}}?{{opaque}}=1`,
        body: { mode: "raw", raw: '{"password":"clave-reflejada","echo":"clave-reflejada","opaque":"{{opaque}}","{{opaque}}":"x"}' },
      } }],
    };
    const ref = ctx.artifacts.put(JSON.stringify(collection), "application/json", "fixture");
    const env = ctx.artifacts.put(JSON.stringify(environment), "application/json", "fixture");
    const result = await createPostmanTools(ctx)[0]!.execute({ artifact: ref.hash, environmentArtifact: env.hash }, abort);
    const neutralEnv = ctx.artifacts.put(JSON.stringify({ values: [{ key: "opaque", value: secret }] }), "application/json", "fixture");
    const byAuth = await createPostmanTools(ctx)[0]!.execute({ artifact: ref.hash, environmentArtifact: neutralEnv.hash }, abort);
    const visible = JSON.stringify([result, byAuth, ctx.http.observed, ctx.http.surface()]);
    assert.ok(!visible.includes(secret));
    assert.ok(!visible.includes(encodeURIComponent(secret)));
    assert.doesNotMatch(visible, /clave-reflejada/);
    const body = JSON.parse(ctx.http.observed[0]!.body!);
    assert.equal(body.echo, "<credencial>");
    assert.equal(body.opaque, "<credencial>");
    assert.equal(body["<credencial>"], "x");
    const rawBody = { info: collection.info, item: [{ request: { method: "POST", url: `${ctx.base}/reset/password-en-ruta`, body: { mode: "raw", raw: '{"password":"password-en-ruta"}' } } }] };
    const rawRef = ctx.artifacts.put(JSON.stringify(rawBody), "application/json", "fixture");
    const rawResult = await createPostmanTools(ctx)[0]!.execute({ artifact: rawRef.hash }, abort);
    assert.doesNotMatch(JSON.stringify([rawResult, ctx.http.observed]), /password-en-ruta/);
    // El formato password también declara un secreto cuando el nombre del campo es neutro.
    const spec = { openapi: "3.0.3", servers: [{ url: ctx.base }], paths: { "/pin": { post: { requestBody: { content: { "application/json": {
      schema: { type: "object", properties: { pin: { type: "string", format: "password" }, echo: { type: "string" }, password: { type: "string" }, copy: { type: "string" } } },
      example: { pin: "pin-reflejado", echo: "pin-reflejado", password: "password-reflejado", copy: "password-reflejado" },
    } } } } } } };
    const api = ctx.artifacts.put(JSON.stringify(spec), "application/json", "fixture");
    await createWebTools(ctx).find((tool) => tool.name === "openapi_import")!.execute({ artifact: api.hash }, abort);
    assert.doesNotMatch(JSON.stringify(ctx.http.observed), /pin-reflejado|password-reflejado/);
    assert.equal(ctx.requests(), 0);
  } finally { ctx.close(); }
});
