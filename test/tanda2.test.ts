// Pruebas de la tanda 2: ws_probe (handshake con variantes), sourcemap_recover, takeover_check
// (tabla de fingerprints y flujo DNS) y h1_report_submit (envío con cita del operador).
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { createWsProbe } from "../src/ws-probe.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { createOperatorTools } from "../src/operador.ts";
import { createJsTools } from "../src/jsanalisis.ts";
import { createReconTools, takeoverFingerprint } from "../src/recon.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const signal = new AbortController().signal;

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "cyber-t2-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  return { dir, paths, db, artifacts, findings, close: () => { db.close(); rmSync(dir, { recursive: true, force: true }); } };
}

// ---------- takeover: tabla + flujo DNS ----------

test("takeover: la tabla reconoce S3 y GitHub Pages con su respuesta; el flujo DNS-only corre sobre un host real", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-t2-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const tools = Object.fromEntries(createReconTools({ artifacts: new Artifacts(db, paths.artifacts) }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  // Tabla: firma del servicio con recurso de baja; sin la respuesta, sin señal.
  assert.equal(takeoverFingerprint("bucket.s3.amazonaws.com", "NoSuchBucket: The specified bucket does not exist."), "S3");
  assert.equal(takeoverFingerprint("bucket.s3.amazonaws.com", "contenido normal"), undefined);
  assert.equal(takeoverFingerprint("site.github.io", "There isn't a GitHub Pages site here."), "GitHub Pages");
  assert.equal(takeoverFingerprint("cualquiera.example", "lo que sea"), undefined);
  // Flujo: 127.0.0.1 resuelve directo sin CNAME (rama sin señales, sin tocar nada más)
  const result = await tools.takeover_check!.execute({ hosts: ["127.0.0.1"] }, signal);
  assert.match(String(result.text), /resuelve directo, sin CNAME/);
  await assert.rejects(async () => tools.takeover_check!.execute({ hosts: [] }, signal), /al menos un host/);
});

// ---------- ws_probe: cuatro variantes contra el in-scope; nada contra el de afuera ----------

test("ws_probe: control aceptado, sin identidad rechazado, origin ajeno aceptado (señal); fuera de alcance no genera handshakes", async (t) => {
  const handshakes: Array<{ origin?: string; auth?: string }> = [];
  const server = createServer((req, res) => res.writeHead(404).end());
  server.on("upgrade", (req, socket) => {
    handshakes.push({ origin: req.headers.origin, auth: req.headers.authorization });
    const foreign = req.headers.origin === "https://sitio-ajeno.invalid";
    if (!req.headers.authorization && !foreign) {
      socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      socket.end();
      return;
    }
    const accept = createHash("sha1").update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const base = `ws://127.0.0.1:${port}/socket`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-ws-"));
  const db = openStore(projectPaths(dir));
  const artifacts = new Artifacts(db, projectPaths(dir).artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`http://127.0.0.1:${port}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "ana", headers: { Authorization: "Bearer t-ana" } });
  const tools = { ws_probe: createWsProbe({ http, artifacts }) } as unknown as Record<string, Tool>;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const result = await tools.ws_probe!.execute({ url: base }, signal);
  const text = String(result.text);
  assert.match(text, /Handshake de/);
  assert.match(text, /origin ajeno[^\n]*ACEPTADO/); // señal CSWSH del lab
  assert.match(text, /sin identidad[^\n]*rechazado/);
  assert.match(text, /Señales:.*Origin ajeno/);
  await assert.rejects(async () => tools.ws_probe!.execute({ url: "ws://fuera-del-alcance.invalid/socket" }, signal), /Fuera del alcance/);
  assert.equal(handshakes.length, 4, "cuatro handshakes in-scope; ninguno fuera de alcance");
});

// ---------- sourcemap_recover: .map con fuentes, secretos y rutas ----------

test("sourcemap_recover: recupera el .map declarado y marca pistas de secretos del sourcesContent", async (t) => {
  const server = createServer((req, res) => {
    const url = new URL(req.url!, "http://lab");
    if (url.pathname === "/app.js") {
      return void res.writeHead(200, { "content-type": "application/javascript" }).end(`(()=>{fetch("/api/items/1")})()\n//# sourceMappingURL=http://${req.headers.host}/app.js.map`);
    }
    if (url.pathname === "/app.js.map") {
      return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
        version: 3,
        sources: ["src/app.ts"],
        sourcesContent: ["const API_KEY = 'sk_live_orobas123456';\nfetch('/api/admin/users')"],
      }));
    }
    res.writeHead(200, { "content-type": "text/html" }).end('<script src="/app.js"></script>');
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-map-"));
  const db = openStore(projectPaths(dir));
  const artifacts = new Artifacts(db, projectPaths(dir).artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  const tools = Object.fromEntries(createJsTools({ http, artifacts }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  t.after(async () => {
    server.closeAllConnections?.();
    await new Promise<void>((r) => server.close(() => r()));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const result = await tools.sourcemap_recover!.execute({ url: base }, signal);
  const text = String(result.text);
  assert.match(text, /1 mapa[s]? recuperados?/);
  assert.match(text, /olor a secreto/);
  assert.match(text, /pistas? para el operador/);
  assert.match(text, /peticiones HTTP: 3/); // página + app.js + app.js.map
});

// ---------- h1_report_submit: hallazgo verificado → payload → envío con fetch fake ----------

test("h1_report_submit: sólo hallazgo verificado; el pedido cita al operador que nombró el programa; el POST sale con el payload", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-h1-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  const posted: Array<{ url: string; init: RequestInit }> = [];
  const fetchFake = (async (url: unknown, init?: RequestInit) => {
    posted.push({ url: String(url), init: init ?? {} });
    return new Response(JSON.stringify({ data: { id: "1234" } }), { status: 201, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  // Un artefacto real de evidencia para el candidato verificado.
  const artifact = artifacts.put("evidencia", "text/plain", "test");
  const finding = findings.record({ title: "Recurso de otro usuario", kind: "control de acceso", asset: `${base}/items/2`, summary: "Se infiere acceso entre cuentas.", evidence: [artifact.hash], severity: "alta" }, "s1");
  findings.decide(finding.id, "verificado", "reproducido por el operador");
  function base(): string { return "http://lab"; }
  const tools = Object.fromEntries(createOperatorTools({
    scope: {} as never,
    ledger: {} as never,
    http: {} as never,
    operatorTexts: () => ["dale, mandalo a mercadolibre"],
    h1: () => ({ credentials: { username: "u", token: "t" }, fetch: fetchFake }),
    report: async () => [],
    findings,
  }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const sent = await tools.h1_report_submit!.execute({ hallazgo: finding.id.slice(0, 8), handle: "mercadolibre", pedido: "dale, mandalo a mercadolibre" }, signal);
  assert.match(String(sent.text), /Enviado a HackerOne «mercadolibre»/);
  assert.match(String(sent.text), /hackerone\.com\/reports\/1234/);
  assert.equal(posted.length, 1);
  assert.ok(new URL(String(posted[0]!.url)).pathname.endsWith("/reports"));
  assert.ok(String((posted[0]!.init.headers as Record<string, string>).authorization).startsWith("Basic "));
  // Sin verificación: rechaza.
  const lead = findings.record({ title: "Otro", kind: "otro", asset: `${base}/x`, summary: "s", state: "pista" }, "s1");
  void lead;
  const candidatoPendiente = findings.record({ title: "Sin verificar", kind: "otro", asset: `${base}/y`, summary: "s", evidence: [artifact.hash], severity: "baja" }, "s1");
  await assert.rejects(async () => tools.h1_report_submit!.execute({ hallazgo: candidatoPendiente.id.slice(0, 8), handle: "mercadolibre", pedido: "dale, mandalo a mercadolibre" }, signal), /verificado/);
  // El operador no nombró ese handle: no se adivina.
  const other = Object.fromEntries(createOperatorTools({
    scope: {} as never, ledger: {} as never, http: {} as never, findings,
    operatorTexts: () => ["dale, mandalo a mercadolibre"],
    h1: () => ({ credentials: { username: "u", token: "t" }, fetch: fetchFake }),
    report: async () => [],
  }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  await assert.rejects(async () => (other.h1_report_submit!).execute({ hallazgo: finding.id.slice(0, 8), handle: "otro-programa", pedido: "dale, mandalo a mercadolibre" }, signal), /nombró el programa/);
});


