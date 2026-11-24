import "./datos-tmp.ts";
// De la auditoría de una corrida real: el agente no podía leer el JavaScript minificado y adivinó el
// cuerpo de una escritura 90 veces. Ahora saca el contrato del bundle y los intentos a ciegas tienen tope.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { FUZZ_LIMIT } from "../src/http.ts";
import { extractApi } from "../src/jsanalisis.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";

// Minificado, en una sola línea, como sale de un empaquetador.
const BUNDLE = 'var a=function(e){return fetch("/api/shopcart/item",{method:"POST",headers:{"x-csrf-token":t,"content-type":"application/json"},body:JSON.stringify({productId:e.id,sizeId:e.size,quantity:1})})},b=e=>n.get(`/api/orders/${e.orderId}/invoice`),c=(e,t)=>n.patch(`/api/customer/${e}`,{firstName:t.firstName,phone:t.phone}),d="/img/logo.png",f="/checkout",g=n.get("/api/customer");' + "x".repeat(3000);

test("contrato desde JavaScript minificado: rutas, métodos, campos y cabeceras; con identificador primero", () => {
  const api = extractApi(BUNDLE);
  const by = Object.fromEntries(api.operations.map((op) => [op.path, op]));
  assert.deepEqual(by["/api/shopcart/item"]!.methods, ["POST"]);
  assert.deepEqual(by["/api/shopcart/item"]!.keys.slice(0, 3), ["productId", "sizeId", "quantity"]);
  assert.ok(by["/api/orders/{orderId}/invoice"]!.object);
  assert.deepEqual(by["/api/customer/{e}"]!.methods, ["PATCH"]);
  assert.ok(by["/api/customer/{e}"]!.keys.includes("firstName"));
  assert.ok(!("/img/logo.png" in by), "un archivo estático no es una ruta de API");
  assert.ok(api.headers.includes("x-csrf-token"));
  assert.ok(api.operations[0]!.object, "primero las rutas con identificador de objeto");
});

async function lab() {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      hits.push(`${req.method} ${req.url}`);
      if (req.url === "/") return void res.writeHead(200, { "content-type": "text/html" }).end('<html><script src="/static/app.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script><img src="/imgs/logo.png"><a href="/cuenta">x</a></html>');
      if (req.url === "/static/app.js") return void res.writeHead(200, { "content-type": "application/javascript" }).end(BUNDLE);
      if (req.url === "/api/shopcart/item" && req.method === "POST") {
        let body: Record<string, unknown> = {};
        try { body = JSON.parse(raw); } catch {}
        return "productId" in body ? void res.writeHead(200, { "content-type": "application/json" }).end('{"ok":true}') : void res.writeHead(400, { "content-type": "application/json" }).end('{"error":"invalid body"}');
      }
      res.writeHead(404, { "content-type": "application/json" }).end('{"error":"not found"}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { hits, base: `http://127.0.0.1:${(server.address() as { port: number }).port}`, close: () => server.close() };
}

test("tope de intentos a ciegas: se cierra el endpoint, js_endpoints trae el contrato y lo reabre", async () => {
  const target = await lab();
  const cwd = mkdtempSync(join(tmpdir(), "cyber-contrato-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), budgetPico: usdToPico("1") });
  const tool = (name: string) => engine.agent.tools.find((item) => item.name === name)!;
  const signal = new AbortController().signal;
  try {
    engine.scope.edit({ include: [`${target.base}/`] });
    const post = (body: object) => engine.http.send({ url: `${target.base}/api/shopcart/item`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    for (let i = 0; i < FUZZ_LIMIT; i++) assert.equal((await post({ [`campo${i}`]: 1 })).response?.status, 400);
    const sent = target.hits.length;
    await assert.rejects(() => post({ otro: 1 }), /12 intentos sin ninguna respuesta exitosa.*buscá su contrato \(js_endpoints/);
    assert.equal(target.hits.length, sent, "el intento 13 no sale");
    // Una sonda sistemática (auth_probe, body_probe…) no está sujeta al tope.
    assert.equal((await engine.http.send({ url: `${target.base}/api/shopcart/item`, method: "POST", body: "{}", systematic: true })).response?.status, 400);

    const result = await tool("js_endpoints").execute({ url: `${target.base}/` }, signal);
    assert.match(result.text, /POST\s+\/api\/shopcart\/item\s+campos: productId, sizeId, quantity/);
    assert.match(result.text, /con identificador de objeto: 2/);
    assert.match(result.text, /fuera del alcance, no bajados: www\.googletagmanager\.com/);
    assert.ok(!target.hits.some((hit) => hit.includes("gtm")));
    // Con el contrato, el endpoint se reabre y la petición bien armada pasa.
    assert.equal((await post({ productId: 7, sizeId: 2, quantity: 1 })).response?.status, 200);

    // artifact_read: búsqueda con contexto dentro de una sola línea enorme, y varias cosas en una llamada.
    const js = engine.http.log.find((entry) => entry.url.endsWith("/static/app.js"))!;
    const read = await tool("artifact_read").execute({ hash: js.id, search: "orders/|x-csrf", context: 30 }, signal);
    assert.match(read.text, /@\d+: ….*api\/orders\/\$\{e\.orderId\}/);
    assert.equal(read.details?.coincidencias, 2);
    assert.ok(read.text.length < 600, "no devuelve la línea entera");

    // Cobertura: una imagen enlazada no cuenta como ruta sin visitar; una página sí.
    assert.deepEqual(engine.http.unvisitedLinks(), ["/cuenta"]);
  } finally {
    engine.close();
    target.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("sin tope de pasos por defecto: el turno sigue mientras avance", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-pasos-"));
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("5"), coverageObjections: 0 });
  try {
    provider.faux!.queue = [...Array.from({ length: 90 }, (_, i) => ({ toolCalls: [{ name: "memory_search", arguments: { query: `q${i}` } }] })), { text: "fin" }];
    await engine.send("Buscá mucho");
    assert.equal(engine.agent.messages.at(-1)!.content, "fin");
    assert.ok(!engine.agent.messages.some((m) => m.role === "assistant" && /Límite de pasos/.test(m.errorMessage ?? "")));
  } finally {
    engine.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
