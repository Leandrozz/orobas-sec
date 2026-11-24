import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { Engine } from "../src/engine.ts";
import { HttpClient } from "../src/http.ts";
import { createProbeTools } from "../src/probes.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { createWebTools } from "../src/webtools.ts";
import { labServer } from "./lab-web.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-"));
const abort = new AbortController().signal;

async function setup() {
  const server = labServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const paths = projectPaths(tmp());
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
  http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto" } });
  const tools = Object.fromEntries([...createWebTools({ artifacts, http }), ...createProbeTools({ artifacts, http })].map((tool) => [tool.name, tool])) as Record<string, Tool>;
  return { server, base, http, tools, close: () => server.close() };
}

test("web: matriz de acceso, repetición con cambios, mapa del sitio e importación OpenAPI", async () => {
  const { base, tools, http, close } = await setup();
  try {
    const matrix = await tools.access_matrix!.execute({ urls: [`${base}/api/items/1`, `${base}/api/items/2`] }, abort);
    assert.match(matrix.text, /\(sin credenciales\)\s+ana\s+beto/);
    assert.match(matrix.text, /items\/1\s+401\s+200\s+200 idéntica.*todas las identidades ven lo mismo/);
    assert.equal(matrix.details!.sospechosas, 2);

    const replay = await tools.http_replay!.execute({ id: "h2", path: "/api/items/3" }, abort);
    assert.match(replay.text, /GET\s+.*\/api\/items\/3\s+200/);
    assert.match(replay.text, /diferencia contra h2: mismo estado y tamaño; cuerpo distinto/);

    const map = await tools.site_map!.execute({ url: `${base}/`, depth: 1 }, abort);
    assert.match(map.text, /Formularios \(1\)\n\s+POST \/api\/login\s+campos: email, password/);
    assert.match(map.text, /Rutas de API en scripts \(2\)\n\s+\/api\/items\/\n\s+\/api\/login/);
    assert.ok(http.surface().some((row) => row.path === "/perfil"));

    const spec = await tools.openapi_import!.execute({ url: base }, abort);
    assert.match(spec.text, /GET\s+\/api\/items\/\{id\}\s+auth\s+params: \{id\}/);
    assert.match(spec.text, /POST\s+\/api\/login\s+pública\s+cuerpo: email, password/);
    assert.equal(spec.details!.operaciones, 2);
  } finally {
    close();
  }
});

test("sondas: autenticación con enumeración y acceso, parámetro con error del servidor y reflejo, JWT, secretos, huella", async () => {
  const { base, tools, http, close } = await setup();
  try {
    const auth = await tools.auth_probe!.execute({ url: `${base}/api/login`, userField: "email", passwordField: "password", users: ["ana@x.test"], passwords: ["mala", "ana-ok"], delayMs: 0 }, abort);
    assert.match(auth.text, /\[inexistente\] nadie-.*401.*usuario inexistente/);
    assert.match(auth.text, /ana@x.test \/ mala\s+401.*contraseña incorrecta.*← distinto al inexistente/);
    assert.match(auth.text, /ana@x.test \/ ana-ok\s+200.*← ENTRÓ/);
    assert.equal(auth.details!.entraron, 1);
    assert.equal(auth.details!.enumeracion, true);

    const control = await http.send({ url: `${base}/api/carrito`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ productId: 1, qty: 2, price: 1000, gift: false }) }, "ana");
    const mutated = await tools.body_probe!.execute({ id: control.id }, abort);
    assert.match(mutated.text, /price=1 \(precio mínimo\).*ACEPTÓ y devolvió el valor alterado/);
    assert.match(mutated.text, /qty=-1 \(negativo\).*aceptó \(2xx\)/); // el servidor lo corrige a 1: aceptó pero no devolvió el valor
    assert.match(mutated.text, /productId=2 \(id vecino\).*ACEPTÓ/);
    assert.match(mutated.text, /gift=true \(invertido\)\s+idéntica\s+aceptó \(2xx\)$/m); // el servidor lo ignora: aceptó, no lo devolvió
    assert.ok((mutated.details!.aceptadas as number) >= 8);

    const probe = await tools.param_probe!.execute({ url: `${base}/buscar?q=mate`, param: "q", families: ["sql", "html"] }, abort);
    assert.match(probe.text, /sql\s+"'"\s+estado 200 → 500.*error del servidor, 5xx/);
    assert.match(probe.text, /html\s+"<b>x<\/b>".*reflejada literal/);
    assert.ok((probe.details!.marcadas as number) >= 5);

    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: 1, role: "user" })).toString("base64url");
    const signature = createHmac("sha256", "secret").update(`${header}.${payload}`).digest("base64url");
    const jwt = await tools.jwt_inspect!.execute({ token: `Bearer ${header}.${payload}.${signature}` }, abort);
    assert.match(jwt.text, /firma simétrica/);
    assert.match(jwt.text, /sin exp/);
    assert.match(jwt.text, /reclamo role = "user"/);
    assert.match(jwt.text, /se verifica con el secreto «secret»/);

    const secrets = await tools.secrets_scan!.execute({ text: '{"db":{"password":"F3nix-Db-2026"},"aws":"AKIAABCDEFGHIJKLMNOP","url":"postgres://app:clave@db.local/x"}' }, abort);
    assert.match(secrets.text, /clave de acceso AWS: 1/);
    assert.match(secrets.text, /URL con credenciales: 1/);
    assert.match(secrets.text, /campo password\/secret\/token con valor: 1/);
    assert.doesNotMatch(secrets.text, /F3nix-Db-2026/); // enmascarado

    const print = await tools.tech_fingerprint!.execute({ url: `${base}/api/items/1` }, abort);
    assert.match(print.text, /server: lab\/1.0\s+← cabecera server/);
    assert.match(print.text, /sin Content-Security-Policy/);
  } finally {
    close();
  }
});

test("catálogo: núcleo chico, búsqueda, carga por demanda y restauración al retomar", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider });
  const names = () => engine.agent.tools.map((tool) => tool.name);
  // 31: help_search (el manual propio siempre a mano), js_endpoints (sin el contrato de la API el agente adivina),
  // skill_load (las habilidades se leen a pedido y cargan sus herramientas), shell (se usa en cada turno),
  // deep_reason (el modelo base tiene que tener a mano al fuerte para decidir) y grafo (lo ya observado, para no
  // repetir pruebas: cargarlo a demanda rompería el prefijo cacheado a mitad de sesión), a conciencia.
  assert.ok(names().length <= 31, `núcleo demasiado grande: ${names().length}`);
  assert.ok(names().includes("grafo"));
  assert.ok(names().includes("deep_reason"));
  assert.ok(names().includes("shell"));
  assert.ok(names().includes("graphql_probe"));
  assert.ok(["outbound_probe", "race_probe", "csrf_check"].every((name) => !names().includes(name) && engine.catalog.available.has(name)));
  assert.ok(!names().includes("nmap_scan") && !names().includes("jwt_inspect"));
  assert.match(engine.agent.system, /Catálogo por demanda[\s\S]*jwt_inspect \(Inspeccionar JWT\)[\s\S]*escáneres: nmap_scan/);
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  provider.faux!.queue = [call("tool_search", { query: "jwt token" }), call("tools_load", { names: ["jwt_inspect", "no_existe"] }), { text: "ok" }];
  await engine.send("Cargá la inspección de tokens");
  const tools = engine.agent.messages.filter((m) => m.role === "tool").map((m) => m.content as string);
  assert.match(tools[0]!, /^jwt_inspect — Decodifica un JWT/);
  assert.match(tools[1]!, /Cargadas: jwt_inspect.*No existen: no_existe/);
  assert.ok(names().includes("jwt_inspect"));
  const sessionId = engine.sessionId;
  engine.close();
  const again = new Engine({ cwd, provider, resume: sessionId });
  assert.ok(again.agent.tools.some((tool) => tool.name === "jwt_inspect"), "la herramienta cargada vuelve al retomar");
  again.close();
});

test("pasos: aviso al llegar a tres cuartos del tope y corte al tope", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider, maxSteps: 4 });
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  provider.faux!.queue = Array.from({ length: 6 }, (_, i) => call("memory_search", { query: `q${i}` }));
  await engine.send("Buscá");
  const warnings = engine.agent.messages.filter((m) => m.role === "user" && String(m.content).startsWith("[sistema] Pasos: usaste 3 de 4"));
  assert.equal(warnings.length, 1);
  assert.ok(engine.agent.messages.some((m) => m.role === "assistant" && /Límite de pasos/.test(m.errorMessage ?? "")));
  // El turno no termina en silencio: el modelo devolvió otra llamada en vez del cierre, así que lo arma el harness.
  const last = engine.agent.messages.at(-1)!;
  assert.equal(last.role, "assistant");
  assert.match(String(last.content), /^Corté el turno: Límite de pasos por turno alcanzado\. Hice \d+ pasos/);
  engine.close();
});

test("verificador: reproduce con peticiones propias, exige control negativo y el agente principal recibe el veredicto en el próximo turno", async () => {
  const { base, close } = await setup();
  const provider = resolveProvider("faux");
  // Sin objeciones de cobertura: la cola simulada debe llegar intacta al verificador.
  const engine = new Engine({ cwd: tmp(), provider, coverageObjections: 0 });
  engine.scope.edit({ include: [`${base}/`] });
  engine.http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  try {
    provider.faux!.queue = [
      // Agente principal: una lectura y un candidato con esa evidencia.
      call("http_request", { url: `${base}/api/items/2`, identity: "ana" }),
      call("finding_record", { state: "candidato", title: "Recurso de otro usuario legible", kind: "control de acceso", asset: `${base}/api/items/2`, summary: "ana lee el recurso 2", evidence: ["h1"] }),
      { text: "Registrado." },
      // Verificador (contexto propio): intenta dictar sin reproducir, se le rechaza; reproduce, hace control y dicta.
      call("verdict", { state: "verificado", reason: "la evidencia existe" }),
      call("artifact_read", { hash: "h1", limit: 5 }),
      call("http_request", { url: `${base}/api/items/2`, identity: "ana" }),
      call("http_request", { url: `${base}/api/items/2` }),
      // Cita la misma petición como prueba y control: no distingue nada, se le rechaza.
      call("verdict", { state: "verificado", reason: "reproducido", prueba: "h2", control: "h2", causa: "credenciales" }),
      call("verdict", { state: "verificado", reason: "reproducido con h2 (200); sin credenciales h3 da 401", prueba: "h2", control: "h3", causa: "quitar las credenciales de ana", titulo: "Recurso de otro usuario legible por cualquier cuenta" }),
      { text: "Veredicto dado." },
      // Próximo turno del agente principal.
      { text: "Visto." },
    ];
    await engine.send("Mirá el recurso 2");
    const finding = engine.findings.list()[0]!;
    assert.equal(finding.state, "verificado");
    assert.equal(finding.decidedBy, "verificador:1");
    assert.equal(finding.evidence.length, 3); // la original más prueba y control del verificador
    assert.match(finding.reason, /control|401/);
    assert.equal(finding.title, "Recurso de otro usuario legible por cualquier cuenta"); // el verificador corrigió el enunciado
    const events = engine.db.prepare("select type from events where session_id=? and type like 'verification.%' order by seq").all(engine.sessionId) as Array<{ type: string }>;
    assert.deepEqual(events.map((e) => e.type), ["verification.started", "verification.verdict"]);
    // El rechazo del primer veredicto quedó en la transcripción del verificador, no en la del agente principal.
    assert.ok(!engine.agent.messages.some((m) => m.role === "tool" && m.name === "verdict"));
    await engine.send("¿Cómo quedó?");
    const last = engine.agent.messages.filter((m) => m.role === "user").at(-1)!;
    assert.match(String(last.content), /<verificacion>\n- \w{8} Recurso de otro usuario legible por cualquier cuenta: verificado — reproducido/);
    assert.equal(provider.faux!.queue.length, 0);
  } finally {
    engine.close();
    close();
  }
});
