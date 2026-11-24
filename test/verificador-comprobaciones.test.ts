// Qué valida el verificador (reporte de Nico, 22/11): alcance según la fuente del programa (regla, recompensa,
// exclusiones citadas), la política cargada, coherencia entre evidencia e impacto, código abierto (¿ya está
// arreglado?) y duplicados públicos. Cada comprobación queda visible en el veredicto; lo que no se pudo mirar
// dice «no comprobado», nunca aprobado.
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { blocksVerified, checksLines, modelChecks, programChecks } from "../src/comprobaciones.ts";
import { Engine } from "../src/engine.ts";
import { importScope, publicScope, translateAssets } from "../src/hackerone.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule, type Scope, ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const h1Scope = (notes = "Programa HackerOne «tienda». Leé la política completa del programa antes de probar: este alcance es sólo la lista de activos."): Scope => ({
  rev: 4, at: "", source: "hackerone:tienda", notes,
  include: [parseRule("*.tienda.com", "con recompensa · severidad máx. critical"), parseRule("blog.tienda.com", "sin recompensa")],
  exclude: [parseRule("staging.tienda.com", "no elegible · entorno de prueba, no reportar")],
});

test("alcance del programa: regla y recompensa, exclusión citada, fuera, ruta suelta y política", () => {
  const finding = (asset: string, kind = "control de acceso", title = "IDOR") => ({ asset, kind, title });
  const inside = programChecks(h1Scope(), finding("https://api.tienda.com/orders/2"));
  assert.equal(inside.alcance.resultado, "ok");
  assert.match(inside.alcance.detalle, /dentro por la regla «\*\.tienda\.com» — «con recompensa · severidad máx\. critical»: elegible para reportar y con recompensa/);
  assert.match(inside.alcance.fuente!, /hackerone:tienda \(alcance del programa en HackerOne\)/);
  assert.match(programChecks(h1Scope(), finding("https://blog.tienda.com/x")).alcance.detalle, /sin recompensa/);
  const excluded = programChecks(h1Scope(), finding("https://staging.tienda.com/admin"));
  assert.equal(excluded.alcance.resultado, "excluido");
  assert.match(excluded.alcance.detalle, /el programa lo excluye: «staging\.tienda\.com» — «no elegible · entorno de prueba, no reportar»/);
  assert.equal(programChecks(h1Scope(), finding("https://otra.com/x")).alcance.resultado, "fuera");
  assert.equal(programChecks(h1Scope(), finding("/api/orders/2")).alcance.resultado, "no comprobado", "una ruta sin host no se aprueba ni se rechaza");
  assert.equal(programChecks(undefined, finding("https://api.tienda.com/")).alcance.resultado, "no comprobado");
  // Política: la del CSV no trae tipos fuera de alcance → no comprobado; una cargada que nombra la clase, citada.
  assert.equal(inside.politica.resultado, "no comprobado");
  const policy = programChecks(h1Scope("Fuera de alcance: self-XSS, clickjacking sin acciones sensibles y falta de cabeceras. Todo lo demás se acepta."), finding("https://api.tienda.com/perfil", "xss", "Self-XSS en el perfil"));
  assert.equal(policy.politica.resultado, "posible fuera de alcance");
  assert.match(policy.politica.detalle, /la política dice: «Fuera de alcance: self-XSS, clickjacking/);
  assert.equal(programChecks(h1Scope("Out of scope: clickjacking."), finding("https://api.tienda.com/x")).politica.resultado, "ok");
});

test("lo que dicta el verificador: lo que falta o no tiene detalle queda «no comprobado»; excluido o incoherente no es verificado", () => {
  assert.deepEqual(modelChecks(undefined).coherencia, { resultado: "no comprobado", detalle: "el verificador no lo informó" });
  assert.equal(modelChecks({ coherencia: { resultado: "ok" } }).coherencia.resultado, "no comprobado", "un «ok» sin decir qué miró no vale");
  assert.equal(modelChecks({ coherencia: { resultado: "aprobado", detalle: "x" } }).coherencia.resultado, "no comprobado");
  assert.deepEqual(modelChecks({ duplicados: { resultado: "posible duplicado", detalle: "GHSA del mismo endpoint", fuente: "https://github.com/org/app/security/advisories/GHSA-aaaa" } }).duplicados, { resultado: "posible duplicado", detalle: "GHSA del mismo endpoint", fuente: "https://github.com/org/app/security/advisories/GHSA-aaaa" });
  assert.equal(modelChecks({ codigo_abierto: { resultado: "no aplica" } }).codigoAbierto.resultado, "no aplica");
  const base = { ...programChecks(h1Scope(), { asset: "https://staging.tienda.com/x", kind: "k", title: "t" }), ...modelChecks({}) };
  assert.match(blocksVerified(base)!, /fuera del alcance del programa/);
  const incoherent = { ...programChecks(h1Scope(), { asset: "https://api.tienda.com/x", kind: "k", title: "t" }), ...modelChecks({ coherencia: { resultado: "falla", detalle: "afirma lectura de datos y la respuesta es un 403" } }) };
  assert.match(blocksVerified(incoherent)!, /no demuestra el impacto/);
  assert.equal(checksLines(incoherent).length, 5);
});

test("HackerOne: la recompensa del CSV y de la API llega a la nota de la regla; uno de código abierto avisa leer lo reciente", async () => {
  const imported = translateAssets([{ type: "URL", identifier: "api.tienda.com", eligible: true, bounty: true }, { type: "URL", identifier: "blog.tienda.com", eligible: true, bounty: false }, { type: "URL", identifier: "otro.tienda.com", eligible: true }], "tienda");
  assert.deepEqual(imported.include.map((rule) => rule.note), ["con recompensa", "sin recompensa", undefined]);
  const csv = "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at\napi.tienda.com,URL,,true,true,,,,critical,,,\nhttps://github.com/tienda/app,SOURCE_CODE,,false,true,,,,high,,,\n";
  const fetchCsv = (async () => new Response(csv, { status: 200, headers: { "content-type": "text/csv" } })) as unknown as typeof fetch;
  assert.match((await publicScope("tienda", fetchCsv)).include[0]!.note!, /^con recompensa · severidad máx\. critical$/);
  const db = openStore(projectPaths(mkdtempSync(join(tmpdir(), "cyber-h1-abierto-"))));
  try {
    const lines = await importScope(undefined, new ScopeStore(db, "s1"), "tienda", fetchCsv);
    assert.ok(lines.some((line) => /Es de código abierto: antes de probar, leé lo reciente del repositorio \(commits y PRs mergeados, CHANGELOG, roadmap, documentación\)/.test(line)), lines.join("\n"));
  } finally {
    db.close();
  }
});

test("veredicto con comprobaciones: el verificador lee fuentes públicas, las del programa las pone el harness y todo queda en el motivo", async (t) => {
  const server = createServer((req, res) => res.writeHead(req.headers.authorization ? 200 : 401, { "content-type": "application/json" }).end(req.headers.authorization ? "{\"owner\":\"bob\"}" : "{}"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const read: string[] = [];
  const fakeFetch = (async (url: string | URL) => (read.push(String(url)), new Response(JSON.stringify([{ ghsa_id: "GHSA-aaaa-bbbb-cccc", summary: "IDOR en pedidos" }]), { status: 200, headers: { "content-type": "application/json" } }))) as unknown as typeof fetch;
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-verif-compr-")), provider, autoVerify: false, closingGate: false, coverageObjections: 0, reference: { fetch: fakeFetch, lookup: async () => ["140.82.112.6"], sleep: async () => {} } });
  t.after(async () => { server.close(); await engine.close(); });
  engine.scope.save({ source: "hackerone:tienda", include: [parseRule(`127.0.0.1:${port}`, "con recompensa · severidad máx. high")], exclude: [], notes: "", reference: [parseRule("https://github.com/tienda/app")] });
  engine.http.setIdentity({ name: "ana", headers: { authorization: "Bearer x" } });
  const evidence = engine.artifacts.put("evidencia", "text/plain", "prueba").hash;
  const finding = engine.findings.record({ title: "IDOR en pedidos", kind: "control de acceso", asset: `http://127.0.0.1:${port}/api/orders/2`, summary: "ana lee el pedido de bob", evidence: [evidence], severity: "alta" }, engine.sessionId);
  const comprobaciones = (coherencia: string) => ({ coherencia: { resultado: coherencia, detalle: coherencia === "falla" ? "afirma escritura y sólo se ve lectura" : "la respuesta trae el pedido de bob con la sesión de ana" }, codigo_abierto: { resultado: "ok", detalle: "sigue igual en main y en v2.3.0", fuente: "https://api.github.com/repos/tienda/app/commits?path=src/orders.ts" }, duplicados: { resultado: "posible duplicado", detalle: "un aviso del repo nombra el mismo endpoint", fuente: "https://github.com/tienda/app/security/advisories/GHSA-aaaa-bbbb-cccc" } });
  provider.faux!.queue = [
    { toolCalls: [{ name: "reference_read", arguments: { url: "https://api.github.com/repos/tienda/app/security-advisories" } }] },
    { toolCalls: [{ name: "http_request", arguments: { url: `http://127.0.0.1:${port}/api/orders/2`, identity: "ana" } }, { name: "http_request", arguments: { url: `http://127.0.0.1:${port}/api/orders/2` } }] },
    // Primero dice que la evidencia no demuestra el impacto y aun así pide «verificado»: se rechaza.
    { toolCalls: [{ name: "verdict", arguments: { state: "verificado", reason: "reproducido", prueba: "h1", control: "h2", causa: "sin la sesión de ana da 401", comprobaciones: comprobaciones("falla") } }] },
    { toolCalls: [{ name: "verdict", arguments: { state: "verificado", reason: "reproducido con prueba y control", prueba: "h1", control: "h2", causa: "sin la sesión de ana da 401", comprobaciones: comprobaciones("ok") } }] },
    { text: "Listo." },
  ];
  const verdict = await engine.verifier.verify(finding.id);
  assert.deepEqual(read, ["https://api.github.com/repos/tienda/app/security-advisories"], "el verificador puede leer fuentes públicas (reference_read) aunque el agente no la haya cargado");
  const transcript = JSON.parse(engine.artifacts.read(verdict.transcript).toString("utf8")) as Array<{ role: string; content: unknown; isError?: boolean }>;
  assert.ok(transcript.some((message) => message.role === "tool" && message.isError && /no demuestra el impacto/.test(String(message.content))), "el «verificado» incoherente se rechazó");
  const prompt = String(transcript.find((message) => message.role === "user")!.content);
  assert.match(prompt, /Comprobaciones del harness: alcance del programa: ok — dentro por la regla «127\.0\.0\.1:\d+» — «con recompensa · severidad máx\. high»: elegible para reportar y con recompensa/);
  assert.match(prompt, /Código del programa \(lectura de referencia\): https:\/\/github\.com\/tienda\/app/);
  assert.equal(verdict.state, "verificado");
  const reason = engine.findings.get(finding.id)!.reason;
  assert.match(reason, /^reproducido con prueba y control\nComprobaciones: alcance del programa: ok — .*con recompensa \[hackerone:tienda \(alcance del programa en HackerOne\)\]; política del programa: no comprobado — .*; coherencia: ok — la respuesta trae el pedido de bob .*; código abierto: ok — sigue igual en main y en v2\.3\.0 \[https:\/\/api\.github\.com\/repos\/tienda\/app\/commits\?path=src\/orders\.ts\]; duplicados: posible duplicado — un aviso del repo nombra el mismo endpoint \[https:\/\/github\.com\/tienda\/app\/security\/advisories\/GHSA-aaaa-bbbb-cccc\]\.$/);
  const event = JSON.parse((engine.db.prepare("select payload from events where type='verification.verdict' order by seq desc limit 1").get() as { payload: string }).payload);
  assert.equal(event.comprobaciones.duplicados.resultado, "posible duplicado");
});
