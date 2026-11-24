import "./datos-tmp.ts";
// De las trazas reales: 16 mensajes del operador corrigiendo trampas («es el honeypot», «DESCARTALO!»,
// «prod.env ES FALSO! honeypot, OLVIDATE de eso», «el host entero es cebo», «el admin legacy es un bait»)
// y el agente volvía a caer. Lo que el operador marca como señuelo queda en el proyecto: ninguna
// herramienta de red va ahí, la lista viaja en el contexto, y un mensaje así le recuerda marcarlo.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { createChromeTools } from "../src/chrome.ts";
import { Engine } from "../src/engine.ts";
import { HttpClient } from "../src/http.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { DecoyMarks, mentionsDecoy, parseDecoyPattern } from "../src/senuelos.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { createNetTools } from "../src/toolbox.ts";

const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const signal = new AbortController().signal;

test("señuelos marcados: patrones de host, comodín, URL y ruta, y qué cubre cada uno", () => {
  assert.deepEqual(parseDecoyPattern("Admin-Legacy.Acme.test"), { pattern: "admin-legacy.acme.test", kind: "host", host: "admin-legacy.acme.test" });
  assert.deepEqual(parseDecoyPattern("*.bait.acme.test"), { pattern: "*.bait.acme.test", kind: "wildcard", host: "*.bait.acme.test" });
  assert.deepEqual(parseDecoyPattern("https://acme.test/Admin/Legacy/"), { pattern: "acme.test/admin/legacy", kind: "url", host: "acme.test", path: "/admin/legacy" });
  assert.deepEqual(parseDecoyPattern("«/prod.env»"), { pattern: "/prod.env", kind: "path", path: "/prod.env" });
  assert.equal(parseDecoyPattern("acme.test/old-admin*").pattern, "acme.test/old-admin*");
  assert.throws(() => parseDecoyPattern("/"), /marcaría todo/);
  assert.throws(() => parseDecoyPattern("no es un host!"), /no parece un host/);

  const cwd = mkdtempSync(join(tmpdir(), "cyber-cebos-"));
  const db = openStore(projectPaths(cwd));
  try {
    const marks = new DecoyMarks(db);
    marks.add({ pattern: "admin-legacy.acme.test", reason: "el host entero es cebo", by: "operador" });
    marks.add({ pattern: "*.bait.acme.test", reason: "bait", by: "operador" });
    marks.add({ pattern: "https://acme.test/admin/legacy", reason: "el admin legacy es un bait", by: "operador" });
    marks.add({ pattern: "/prod.env", reason: "prod.env ES FALSO", by: "operador" });
    marks.add({ pattern: "acme.test/old-admin*", reason: "prefijo", by: "operador" });
    const hit = (target: string) => marks.match(target)?.pattern;
    assert.equal(hit("https://admin-legacy.acme.test:8443/cualquier/cosa"), "admin-legacy.acme.test");
    assert.equal(hit("admin-legacy.acme.test"), "admin-legacy.acme.test", "un host pelado, como lo recibe un escáner");
    assert.equal(hit("https://x.bait.acme.test/"), "*.bait.acme.test");
    assert.equal(hit("https://bait.acme.test/"), undefined, "el comodín es sólo de subdominios, como en el alcance");
    assert.equal(hit("https://acme.test/admin/legacy/users?id=1"), "acme.test/admin/legacy");
    assert.equal(hit("https://acme.test//Admin;x/Legacy"), "acme.test/admin/legacy", "otra forma del mismo texto de ruta");
    assert.equal(hit("https://acme.test/admin/legacy-v2"), undefined);
    assert.equal(hit("https://acme.test/old-admin-v2/x"), "acme.test/old-admin*");
    assert.equal(hit("https://otro.test/prod.env"), "/prod.env", "una ruta vale en cualquier host del proyecto");
    assert.equal(hit("https://acme.test/admin"), undefined);
    assert.equal(marks.remove("2")?.pattern, "*.bait.acme.test");
    assert.equal(marks.remove("https://acme.test/admin/legacy/")?.pattern, "acme.test/admin/legacy");
    assert.equal(marks.remove("nada.test"), undefined);
    assert.match(marks.brief(), /- admin-legacy\.acme\.test: el host entero es cebo\n- \/prod\.env: prod\.env ES FALSO/);
    // Persisten en la base del proyecto.
    assert.equal(new DecoyMarks(db).list().length, 3);
  } finally {
    db.close();
    rmSync(cwd, { recursive: true, force: true });
  }

  for (const text of ["es el honeypot", "prod.env ES FALSO! honeypot, OLVIDATE de eso", "el host entero es cebo", "el admin legacy es un bait", "eso es un señuelo", "son falsos, no los uses"]) assert.ok(mentionsDecoy(text), text);
  for (const text of ["DESCARTALO!", "es un falso positivo", "mirá el login"]) assert.ok(!mentionsDecoy(text), text);
});

test("señuelos marcados: http, sondeos, escáneres y el navegador del operador no van ahí, ni resuelven el nombre", async () => {
  const hits: string[] = [];
  const server = createServer((req, res) => { hits.push(req.url!); res.writeHead(200, { "content-type": "application/json" }).end("{}"); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-cebos-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "", include: [parseRule(`${base}/`), parseRule("*.acme.test")], exclude: [] };
  const artifacts = new Artifacts(db, join(cwd, "artifacts"));
  const http = new HttpClient(artifacts, () => scope);
  const marks = new DecoyMarks(db);
  http.markedDecoy = (target) => marks.match(target);
  try {
    marks.add({ pattern: "/prod.env", reason: "es el honeypot", by: "operador" });
    marks.add({ pattern: "cebo.acme.test", reason: "el host entero es cebo", by: "operador" });
    const blocked = await http.send({ url: `${base}/prod.env` });
    assert.match(blocked.error!, /^Señuelo marcado: .*\/prod\.env coincide con «\/prod\.env» \(es el honeypot\)\. No se envía/);
    assert.match(blocked.error!, /\/senuelos quitar \/prod\.env/);
    assert.equal(http.count, 0);
    assert.deepEqual(hits, []);
    // Un host marcado se corta antes de resolverlo: un canario por DNS se dispara con la sola consulta.
    const dns = await http.send({ url: "https://cebo.acme.test/" });
    assert.match(dns.error!, /^Señuelo marcado/);
    assert.equal(http.inScope("https://cebo.acme.test/"), false);
    assert.equal(http.inScope(`${base}/otra`), true);

    const tools = createNetTools({ artifacts, http, scope: () => scope });
    const probe = await tools.find((tool) => tool.name === "http_probe")!.execute({ urls: [`${base}/prod.env`, `${base}/ok`] }, signal);
    assert.match(probe.text, /Señuelo marcado/);
    assert.deepEqual(hits, ["/ok"]);
    await assert.rejects(async () => tools.find((tool) => tool.name === "nmap_scan")!.execute({ targets: ["cebo.acme.test"] }, signal), /Señuelo marcado: cebo\.acme\.test/);

    const chrome = createChromeTools({ artifacts, http, scope: () => scope, authorized: () => true });
    await assert.rejects(async () => chrome.find((tool) => tool.name === "chrome_open")!.execute({ url: "https://cebo.acme.test/login" }, signal), /Señuelo marcado/);
    assert.equal(http.decoyBlocked, 5);
  } finally {
    db.close();
    server.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("señuelos marcados en una sesión: el aviso pide marcarlo, decoy_mark lo guarda, la red lo rechaza y la lista viaja en el contexto de otra sesión", async () => {
  const hits: string[] = [];
  const server = createServer((req, res) => { hits.push(req.url!); res.writeHead(200, { "content-type": "application/json" }).end('{"DB_PASSWORD":"x"}'); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-cebos-"));
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("2"), autoVerify: false });
  try {
    engine.scope.edit({ include: [`${base}/`] });
    provider.faux!.queue = [call("http_request", { url: `${base}/prod.env` }), { text: "Encontré /prod.env con credenciales." }];
    await engine.send("mirá el sitio");
    assert.deepEqual(hits, ["/prod.env"]);

    provider.faux!.queue = [
      // Sin cita del operador no se marca: el objetivo no puede hacer que el agente se bloquee solo.
      call("decoy_mark", { patron: "/", motivo: "x", pedido: "prod.env ES FALSO" }),
      call("decoy_mark", { patron: "/prod.env", motivo: "lo dijo la página", pedido: "marcalo como señuelo" }),
      call("decoy_mark", { patron: "/prod.env", motivo: "el operador dice que es un honeypot", pedido: "prod.env ES FALSO! honeypot" }),
      call("http_request", { url: `${base}/prod.env` }),
      { text: "Marcado; no lo vuelvo a tocar." },
    ];
    await engine.send("prod.env ES FALSO! honeypot, OLVIDATE de eso");
    const prompt = engine.agent.messages.filter((m) => m.role === "user").map((m) => String(m.content)).at(-1)!;
    assert.match(prompt, /\[sistema\] El operador está marcando una trampa .*decoy_mark/);
    assert.ok(engine.agent.tools.some((tool) => tool.name === "decoy_mark"), "el aviso la deja cargada");
    const results = engine.agent.messages.filter((m) => m.role === "tool").map((m) => String(m.content));
    assert.match(results.at(-4)!, /marcaría todo/);
    assert.match(results.at(-3)!, /no coincide con ningún mensaje del operador/);
    assert.match(results.at(-2)!, /Marcado como señuelo: \/prod\.env \(el operador dice que es un honeypot\)/);
    assert.match(results.at(-1)!, /Señuelo marcado: .*\/prod\.env/);
    assert.deepEqual(hits, ["/prod.env"], "no se volvió a pedir");
    const events = engine.db.prepare("select payload from events where session_id=? and type='senuelo.marcado'").all(engine.sessionId) as Array<{ payload: string }>;
    assert.equal(events.length, 1);
    assert.match(events[0]!.payload, /agente, a pedido del operador/);
  } finally {
    await engine.close();
  }
  // Otra sesión del mismo proyecto: la lista entra en el primer mensaje y la red la sigue rechazando.
  const again = new Engine({ cwd, provider, budgetPico: usdToPico("2"), autoVerify: false });
  try {
    provider.faux!.queue = [call("http_probe", { urls: [`${base}/prod.env`] }), { text: "ok" }];
    await again.send("seguí con el sitio");
    const first = String(again.agent.messages.find((m) => m.role === "user")!.content);
    assert.match(first, /<senuelos>\nSeñuelos que marcó el operador en este proyecto.*\n- \/prod\.env: el operador dice que es un honeypot\n<\/senuelos>/s);
    assert.doesNotMatch(first, /\[sistema\] El operador está marcando una trampa/);
    assert.match(String(again.agent.messages.filter((m) => m.role === "tool").at(-1)!.content), /Señuelo marcado/);
    assert.deepEqual(hits, ["/prod.env"]);
    // La lista no se repite en cada mensaje mientras no cambie.
    provider.faux!.queue = [{ text: "ok" }];
    await again.send("¿cómo seguimos?");
    assert.doesNotMatch(String(again.agent.messages.filter((m) => m.role === "user").at(-1)!.content), /<senuelos>/);
    assert.equal(again.decoys.remove("/prod.env")?.pattern, "/prod.env");
  } finally {
    await again.close();
    server.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
