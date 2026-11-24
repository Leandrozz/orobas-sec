// Pruebas de la tanda 3: js_wayback_diff (CDX fake), syslog con match automático,
// bugcrowd/intigriti (fetch inyectable) y code_semgrep/gitleaks según binario presente.
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createSocket } from "node:dgram";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { DetectionLedger } from "../src/deteccion.ts";
import { startSyslogChannel } from "../src/syslog.ts";
import { HttpClient } from "../src/http.ts";
import { createCodeTools } from "../src/codigo.ts";
import { createJsTools } from "../src/jsanalisis.ts";
import { which } from "../src/exec.ts";
import { ScopeStore } from "../src/scope.ts";
import { bugcrowdPrograms, bugcrowdScope, intigritiPrograms, intigritiScope, intigritiToken, importBBScope } from "../src/bugcrowd.ts";
import { parseRule } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const signal = new AbortController().signal;

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "cyber-t3-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  return { dir, db, artifacts, close: () => { db.close(); rmSync(dir, { recursive: true, force: true }); } };
}

// ---------- js_wayback_diff: CDX y snapshot fake por fetch global ----------

test("js_wayback_diff: rutas retiradas entre versiones aparecen como pista; el objetivo se toca una vez", async (t) => {
  const { dir, db, artifacts, close } = setup();
  t.after(() => close());
  const server = createServer((req, res) => {
    if (new URL(req.url!, "http://x").pathname === "/app.js") return void res.writeHead(200, { "content-type": "application/javascript" }).end('fetch("/api/v2/items");fetch("/api/admin/users");');
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  const [tool] = createJsTools({ http, artifacts }).filter((tool: Tool) => tool.name === "js_wayback_diff");
  t.after(async () => { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); });
  assert.ok(tool, "js_wayback_diff existe");
  const jsViejo = 'fetch("/api/v2/items");fetch("/api/export");';
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    const url = String(input);
    if (url.includes("/cdx/search/cdx")) return new Response(JSON.stringify([["timestamp", "original"], ["20190101", "x.test/app.js"]]), { status: 200 });
    if (url.includes("web.archive.org/web/")) return new Response(jsViejo, { status: 200 });
    return originalFetch(input as never);
  }) as unknown as typeof fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  const result = await tool!.execute({ url: `${base}/app.js` }, signal);
  const text = String(result.text);
  assert.match(text, /Historia de/);
  assert.match(text, /\/api\/export/); // la ruta vieja que el actual ya no trae
  assert.match(text, /pistas?/i);
  assert.match(text, /peticiones HTTP: 1/); // el objetivo: una petición (el .js actual)
});

// ---------- syslog: match automático de señales ----------

test("syslog: la línea que matchea una señal esperada la marca automáticamente; las que no, no", async (t) => {
  const { dir, db, close } = setup();
  t.after(() => close());
  const ledger = new DetectionLedger(db);
  ledger.expect("h1", "sigma:sqli-error");
  ledger.expect("h2", "sigma:idor-read");
  const channel = await startSyslogChannel({ host: "127.0.0.1" }, ledger);
  t.after(async () => { await channel.close(); });
  const sender = createSocket("udp4");
  sender.send(Buffer.from("IDS: sigma:sqli-error en POST /buscar"), channel.port, "127.0.0.1");
  await new Promise((r) => setTimeout(r, 150));
  const summary = ledger.summary();
  assert.equal(summary.esperadas, 2);
  assert.equal(summary.detectadas, 1);
  assert.equal(summary.gaps.length, 1);
  assert.equal(summary.gaps[0]?.esperada, "sigma:idor-read");
  assert.equal(channel.hits.length, 1);
  assert.ok(channel.lines.at(-1)!.includes("sigma:sqli-error"));
  sender.close();
});

// ---------- bugcrowd / intigriti: fetch inyectable ----------

test("bugcrowd e intigriti: programas y alcance con exclusiones; import al ScopeStore", async (t) => {
  const { dir, db, artifacts, close } = setup();
  t.after(() => close());
  const fetchFake = (async (input: unknown) => {
    const url = String(input);
    if (url.endsWith("/disclosures/programs")) return new Response(JSON.stringify([{ handle: "tienda", name: "Tienda", status: "public" }]), { status: 200 });
    if (url.endsWith("/disclosures/programs/tienda")) return new Response(JSON.stringify({ data: { targets: [{ name: "api.tienda.test", category: "API" }, { name: "staging.tienda.test", in_scope: false }] } }), { status: 200 });
    if (url.includes("/authentication/v1/token")) return new Response(JSON.stringify({ access_token: "int-token" }), { status: 200 });
    if (url.endsWith("/programs/prog")) return new Response(JSON.stringify({ endpoints: [{ uri: "api.prog.com", type: "InScope" }] }), { status: 200 });
    if (url.includes("/researcher/v1/programs")) return new Response(JSON.stringify([{ id: "prog", name: "Prog", status: "Open", maxBounty: 500 }]), { status: 200 });
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  const programs = await bugcrowdPrograms("t", fetchFake, signal);
  assert.equal(programs[0]?.handle, "tienda");
  const scope = await bugcrowdScope("t", "tienda", fetchFake, signal);
  assert.equal(scope.include.length, 1);
  assert.equal(scope.exclude.length, 1);
  assert.ok(scope.include[0]!.value.startsWith("api.tienda.test"));
  const token = await (await import("../src/bugcrowd.ts")).intigritiToken({ clientId: "x", clientSecret: "y" }, fetchFake, signal);
  assert.equal(typeof token, "string");
  const intScope = await intigritiScope(token, "prog", fetchFake, signal);
  assert.equal(intScope.include.length, 1);
  const intPrograms = await intigritiPrograms(token, fetchFake, signal);
  assert.equal(intPrograms.length, 1);
  // Import al alcance del proyecto: rev nueva con source plataforma:handle
  const saved = await importBBScope("bugcrowd", scope, new ScopeStore(db), "tienda");
  assert.match(saved.join("\n"), /1 dentro, 1 excluidos/);
  function originalFetch(input: unknown): unknown { return undefined; }
});

// ---------- code_semgrep / code_gitleaks ----------

test("code_semgrep y code_gitleaks: con binario corren; sin binario, error con instrucción de instalación", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-code-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "x.ts"), "const a = 1;\n");
  const tools = Object.fromEntries(createCodeTools({ cwd: dir }).map((tool: Tool) => [tool.name, tool])) as Record<string, Tool>;
  if (which("gitleaks")) {
    const result = await tools.code_gitleaks!.execute({}, signal);
    assert.match(String(result.text), /Gitleaks:/);
  } else {
    await assert.rejects(async () => tools.code_gitleaks!.execute({}, signal), /no está instalado/);
  }
  if (which("semgrep")) {
    const result = await tools.code_semgrep!.execute({ pattern: "$X = $Y", lang: "ts" }, signal);
    assert.match(String(result.text), /Semgrep:/);
  } else {
    await assert.rejects(async () => tools.code_semgrep!.execute({ pattern: "$X = $Y", lang: "ts" }, signal), /no está instalado/);
  }
});
