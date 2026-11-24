import "./datos-tmp.ts";
// De las trazas reales: coverage_mark falló 152 de 331 veces (46 %). «hay rutas enlazadas sin visitar:
// /imgs/logo.png, /css/min/…/landing.css, /js/min/…» (estáticos con ;jsessionid), «sólo probaste un id en
// cada familia» (31), «ningún parámetro de consulta recibió comillas» (9), «hay rutas de compra» (9), «no se
// consultó ninguna ruta de respaldo» (6), y 93 objeciones de cobertura repetidas. Las guardas siguen, con
// menos falsos positivos: una sola acción por objeción, nunca la misma dos veces, y «limitada» cierra.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { ClosingGate } from "../src/cierre.ts";
import { Coverage } from "../src/coverage.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient, isScriptAsset, isStaticAsset } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

async function lab(handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void, scopePath = "/") {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-honesta-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "", include: [parseRule(`${base}${scopePath}`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  const coverage = new Coverage(db, http);
  return { base, http, coverage, db, close: () => { db.close(); server.close(); } };
}

const json = (res: import("node:http").ServerResponse, status: number, body = "{}") => void res.writeHead(status, { "content-type": "application/json" }).end(body);

test("estáticos: imágenes, estilos, fuentes, mapas, medios y bundles no son rutas sin visitar, con ;jsessionid, versión o compresión", () => {
  for (const link of ["/imgs/logo-long.svg", "/imgs/logo.png;jsessionid=ABC123", "/css/min/2024/landing.css?v=3", "/css/app.css.gz", "/fonts/x.woff2", "/js/min/app.min.js;jsessionid=Z", "/static/app.js.map", "/media/intro.mp4", "/_next/static/chunks/main.js", "/_next/image?url=%2Fa.png&w=64", "/IMG/FOTO.JPG"]) assert.ok(isStaticAsset(link), link);
  for (const link of ["/cuenta", "/api/items/1", "/admin", "/descargas/informe.pdf", "/static-page", "/css-guide"]) assert.ok(!isStaticAsset(link), link);
  assert.ok(isScriptAsset("/js/min/app.min.js;jsessionid=Z"));
  assert.ok(!isScriptAsset("/css/app.css"));
});

test("reconocimiento: los estáticos enlazados no traban; los bundles sin leer piden js_endpoints, una sola vez", async () => {
  const page = `<html><img src="/imgs/logo.png;jsessionid=AB12"><link href="/css/min/v9/landing.css;jsessionid=AB12"><script src="/js/min/app.js;jsessionid=AB12"></script><a href="/cuenta">c</a></html>`;
  const { base, http, coverage, close } = await lab((req, res) => {
    if (req.url === "/") return void res.writeHead(200, { "content-type": "text/html" }).end(page);
    if (req.url?.startsWith("/js/")) return void res.writeHead(200, { "content-type": "application/javascript" }).end("fetch('/api/x')");
    json(res, req.url === "/robots.txt" ? 200 : 404);
  });
  try {
    for (const path of ["/", "/robots.txt", "/a", "/b", "/c"]) await http.send({ url: `${base}${path}` });
    assert.deepEqual(http.unvisitedLinks(), ["/cuenta"]);
    assert.match(coverage.minimumEvidence("reconocimiento")!, /1 ruta enlazada sin visitar: \/cuenta/);
    await http.send({ url: `${base}/cuenta` });
    assert.match(coverage.minimumEvidence("reconocimiento")!, /carga 1 script y no se leyó ninguno: js_endpoints/);
    // js_endpoints baja los bundles con el mismo cliente: con uno leído, ya está.
    await http.send({ url: `${base}/js/min/app.js;jsessionid=AB12` });
    assert.equal(coverage.minimumEvidence("reconocimiento"), undefined);
  } finally {
    close();
  }
});

test("control de acceso: alcanza con una familia explorada; 404, estáticos y UUID se tratan bien", async () => {
  const { base, http, coverage, close } = await lab((req, res) => {
    if (/^\/api\/users\/(1|2)$/.test(req.url!)) return json(res, 200);
    if (req.url === "/api/invoices/7") return json(res, 200);
    if (req.url === "/api/docs/3f2a6c1e-0b1d-4c2e-9a7b-1234567890ab") return json(res, 200);
    if (req.url === "/api/docs/9d2a6c1e-0b1d-4c2e-9a7b-1234567890ab") return json(res, 403);
    if (req.url?.startsWith("/imgs/")) return void res.writeHead(200, { "content-type": "image/png" }).end("x");
    json(res, 404);
  });
  try {
    await http.send({ url: `${base}/imgs/2024/05/logo.png` });
    assert.match(coverage.minimumEvidence("control de acceso")!, /no se pidió ningún recurso por id/, "una imagen con números en la ruta no es un recurso");
    await http.send({ url: `${base}/api/ghost/5` });
    assert.deepEqual(coverage.familiesWithOneId(), [], "una familia que sólo dio 404 no exige otro id");
    assert.doesNotMatch(coverage.minimumEvidence("control de acceso")!, /un id/);
    await http.send({ url: `${base}/api/users/1` });
    await http.send({ url: `${base}/api/invoices/7` });
    assert.match(coverage.minimumEvidence("control de acceso")!, /sólo probaste un id en cada familia de rutas \(\/api\/users\/\{n\}, \/api\/invoices\/\{n\}\): pedí un segundo id de \/api\/users\/\{n\}/);
    // Una familia explorada alcanza: no se exige un segundo id en cada una.
    await http.send({ url: `${base}/api/users/2` });
    assert.deepEqual(coverage.familiesWithOneId(), ["/api/invoices/{n}"]);
    assert.match(coverage.minimumEvidence("control de acceso")!, /no se probó PUT, PATCH ni DELETE/);
    // Los UUID también son ids: el ajeno se ve, y una escritura que lo lleva en el cuerpo lo cubre.
    await http.send({ url: `${base}/api/docs/3f2a6c1e-0b1d-4c2e-9a7b-1234567890ab` });
    await http.send({ url: `${base}/api/docs/9d2a6c1e-0b1d-4c2e-9a7b-1234567890ab` });
    assert.deepEqual(coverage.foreignIds(), [{ path: "/api/docs/{n}", id: "9d2a6c1e-0b1d-4c2e-9a7b-1234567890ab", status: 403 }]);
    assert.match(coverage.minimumEvidence("control de acceso")!, /ninguna escritura llevó uno/);
    await http.send({ url: `${base}/api/docs/copy`, method: "POST", body: JSON.stringify({ doc_id: "9D2A6C1E-0B1D-4C2E-9A7B-1234567890AB" }) });
    assert.equal(coverage.wroteWithForeignId(), true);
  } finally {
    close();
  }
});

test("inyección, compras y respaldos: el cuerpo cuenta, la palabra suelta no, y lo que está fuera del alcance no se exige", async () => {
  const { base, http, coverage, close } = await lab((req, res) => json(res, req.url?.startsWith("/app/api/") ? 200 : 404), "/app");
  try {
    // Una API que recibe todo en el cuerpo JSON: la comilla en un valor anidado cuenta como sonda.
    await http.send({ url: `${base}/app/api/search`, method: "POST", body: JSON.stringify({ filter: { name: "x" } }) });
    assert.match(coverage.minimumEvidence("inyeccion")!, /ningún parámetro recibió comillas, < > ni \.\.\/ \(ni en la consulta ni en el cuerpo\): param_probe sobre/);
    await http.send({ url: `${base}/app/api/search`, method: "POST", body: JSON.stringify({ filter: { name: "x'\"<" } }) });
    assert.equal(coverage.minimumEvidence("inyeccion"), undefined);
    // Un parámetro de archivo en el cuerpo de un formulario, con ../, también cuenta.
    await http.send({ url: `${base}/app/api/view?file=a.txt` });
    assert.match(coverage.minimumEvidence("inyeccion")!, /parámetros de archivo sin probar con \.\.\//);
    await http.send({ url: `${base}/app/api/view`, method: "POST", body: "file=..%2F..%2Fetc%2Fpasswd" });
    assert.equal(coverage.minimumEvidence("inyeccion"), undefined);

    // «/border.css» o «/sort-order» no son rutas de compra; un historial de pedidos de sólo lectura tampoco exige precio.
    http.observe({ url: `${base}/app/api/sort-order`, method: "POST", bodyKeys: ["by"] });
    http.observe({ url: `${base}/app/border.css`, method: "GET" });
    await http.send({ url: `${base}/app/api/orders/history` });
    assert.equal(coverage.minimumEvidence("logica de negocio"), undefined);
    // Con un carrito que acepta escrituras, la cantidad anidada ({items:[{qty}]}) cuenta.
    http.observe({ url: `${base}/app/api/cart`, method: "POST", bodyKeys: ["items"] });
    assert.match(coverage.minimumEvidence("logica de negocio")!, /rutas de compra con escritura \(\/app\/api\/cart\)/);
    await http.send({ url: `${base}/app/api/cart`, method: "POST", body: JSON.stringify({ items: [{ productId: 1, qty: -1 }] }) });
    assert.equal(coverage.minimumEvidence("logica de negocio"), undefined);

    // El alcance es /app: /.env, /backup o /debug quedan afuera y no se pueden exigir.
    assert.equal(coverage.minimumEvidence("configuracion"), undefined);
  } finally {
    close();
  }
});

test("objeción: una sola acción, la más profunda primero, nunca repetida; «limitada» cierra la categoría", async () => {
  const { base, http, coverage, close } = await lab((req, res) => {
    if (req.url === "/api/items/1") return json(res, 200);
    if (req.url === "/api/items/2") return json(res, 403);
    json(res, 404);
  });
  try {
    await http.send({ url: `${base}/api/items/1` });
    await http.send({ url: `${base}/api/items/2` });
    const first = coverage.objection("s", 2)!;
    assert.equal(first.split("\n").length, 3, first);
    assert.match(first, /^\[sistema\] Antes de cerrar falta una cosa en la cobertura \(«control de acceso»\): viste ids que no son de tu cuenta/);
    assert.match(first, /marcá «control de acceso» como «limitada» con una nota corta/);
    // La misma acción no se repite: la siguiente objeción pide otra cosa.
    const second = coverage.objection("s", 2)!;
    assert.doesNotMatch(second, /ids que no son de tu cuenta/);
    const seen = new Set([first, second]);
    for (let i = 0; i < 20; i++) {
      const next = coverage.objection("s", 2);
      if (!next) break;
      assert.ok(!seen.has(next), `repetida: ${next}`);
      seen.add(next);
    }
    assert.equal(coverage.objection("s", 2), undefined, "agotadas las acciones, el cierre se acepta");

    // En otra sesión, «limitada» se acepta aunque falte evidencia, y una categoría marcada no se objeta más.
    for (const category of ["reconocimiento", "autenticacion", "control_de_acceso", "inyeccion", "logica-de-negocio"]) assert.equal(coverage.mark("t", category, "limitada", "sin otra cuenta").state, "limitada");
    const last = coverage.objection("t", 2)!;
    assert.match(last, /«configuracion»/);
    assert.doesNotMatch(last, /Siguen sin marcar/);
    coverage.mark("t", "configuracion", "limitada", "el alcance no deja ver respaldos");
    assert.equal(coverage.objection("t", 2), undefined);
    assert.deepEqual(coverage.pending("t"), [], "sin modo purple, «deteccion» no queda pendiente");
  } finally {
    close();
  }
});

test("cierre: una grieta por objeción, y la que el agente ya intentó no se le vuelve a objetar", async () => {
  const { base, http, db, close } = await lab((req, res) => {
    if (req.url === "/api/notes/5") return json(res, 200);
    if (req.url === "/api/tags/1") return json(res, 200);
    json(res, 405);
  });
  try {
    const findings = new Findings(db, () => undefined);
    const gate = new ClosingGate({ http, findings, budgetLeft: () => 0.9 });
    await http.send({ url: `${base}/api/notes/5` });
    await http.send({ url: `${base}/api/tags/1` });
    const first = gate.objection(2)!;
    assert.equal(first.cracks.length, 1);
    assert.match(first.text, /Hay 1 más/);
    const tried = first.cracks[0]!;
    // El agente probó la escritura (405) y no registró nada: no se le insiste con esa grieta.
    await http.send({ url: `${base}${tried.path.replace("{n}", "5")}`, method: "PUT", body: "{}" });
    const second = gate.objection(2)!;
    assert.notEqual(second.cracks[0]!.key, tried.key);
    const third = gate.objection(2);
    assert.ok(!third || third.cracks[0]!.key !== tried.key);
  } finally {
    close();
  }
});
