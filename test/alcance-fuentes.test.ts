import "./datos-tmp.ts";
// Alcance («autoscope»): reportes reales del 22/11 (Matomo, Tools for Humanity, Kubernetes en HackerOne).
//  a) la página policy_scopes es una tabla que el agente leía mal; HackerOne publica el mismo alcance
//     como CSV para los programas públicos (verificado con un GET de sólo lectura el 22/11).
//  b) github.com, api.github.com y raw.githubusercontent.com quedaban fuera de alcance cuando el
//     programa es de código abierto y hay que LEER el código: reference_read lee fuentes de
//     referencia, sólo con GET y sin nada del objetivo; probar sigue atado al alcance.
//  c) una página que redirige a /login chocaba con el alcance o se trababa.
//  d) un laboratorio local pasó a «fuera de alcance» a mitad de sesión sin que nadie lo dijera.
//  e) el error al elegir un proveedor que no existe no decía qué valores valen.
// Todo es sintético: dominios .test, un servidor local propio y fetch simulados.
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { Engine, pickModel, SYSTEM_PROMPT } from "../src/engine.ts";
import { parseCsv, programHandle, publicScope, translateAssets } from "../src/hackerone.ts";
import { SESSION_STEPS, summarize } from "../src/http.ts";
import { resolveProvider } from "../src/providers.ts";
import { createReferenceTool, referenceDecision, REFERENCE_CAP } from "../src/referencia.ts";
import { decide, parseRule, scopeBrief, scopeView, type Scope } from "../src/scope.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-alcance-fuentes-"));
const load = (source: string, ...rules: string[]) => ({ source, include: rules.map((rule) => parseRule(rule)), exclude: [], notes: "" });
const scopeOf = (source: string, include: string[], extra: Partial<Scope> = {}): Scope => ({ rev: 1, at: "", notes: "", source, include: include.map((rule) => parseRule(rule)), exclude: [], ...extra });
const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const toolText = (engine: Engine, name: string) => String(engine.agent.messages.findLast((m) => m.role === "tool" && m.name === name)?.content ?? "");
type FetchCall = { url: string; init?: RequestInit };

/** Un CSV con la forma real del export de HackerOne (cabecera verificada el 22/11), con datos inventados. */
const CSV = [
  "identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at",
  `https://github.com/tienda-org/tienda,SOURCE_CODE,"El núcleo, con ""comillas"" y comas",true,true,,,,critical,,2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
  `cloud.tienda.test,URL,"Instancia en la nube.
Con salto de línea.",true,true,not_defined,not_defined,not_defined,critical,"php, mysql",2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
  `*.api.tienda.test,WILDCARD,,true,true,,,,high,,2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
  `https://*.cdn.tienda.test/,URL,,true,true,,,,low,,2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
  `tienda.test,URL,Sitio institucional: fuera,false,false,,,,critical,,2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
  `https://github.com/tienda-org/docker,URL,,true,true,,,,critical,,2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
  `org.tienda.app,GOOGLE_PLAY_APP_ID,,false,true,,,,medium,,2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
  `Tier 1,OTHER,,true,true,,,,critical,,2020-01-01 00:00:00 UTC,2024-01-01 00:00:00 UTC`,
].join("\r\n");

function csvFetch(calls: FetchCall[], body = CSV, type = "text/csv; charset=utf-8", status = 200): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return new Response(body, { status, headers: { "content-type": type } });
  }) as typeof fetch;
}

test("a) CSV: comillas dobles, comas y saltos de línea dentro de un campo", () => {
  assert.deepEqual(parseCsv('a,b\r\n"x, ""y""",\nz\n'), [["a", "b"], ['x, "y"', ""], ["z"]]);
  assert.deepEqual(parseCsv('"uno\ndos",tres'), [["uno\ndos", "tres"]]);
});

test("a) el alcance público de HackerOne sale del CSV del programa, sin credenciales: código a referencia, nada de github.com como objetivo", async () => {
  const calls: FetchCall[] = [];
  const imported = await publicScope("tienda", csvFetch(calls));
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, "https://hackerone.com/teams/tienda/assets/download_csv.csv");
  assert.equal(calls[0]!.init?.method ?? "GET", "GET");
  const headers = new Headers(calls[0]!.init?.headers);
  assert.equal(headers.get("authorization"), null, "sin credenciales");
  assert.equal(headers.get("cookie"), null);
  assert.deepEqual(imported.include.map((rule) => rule.value).sort(), ["*.api.tienda.test", "*.cdn.tienda.test", "cloud.tienda.test"]);
  assert.deepEqual(imported.exclude.map((rule) => rule.value), ["tienda.test"]);
  assert.deepEqual(imported.reference.map((rule) => rule.value).sort(), ["https://github.com/tienda-org/docker", "https://github.com/tienda-org/tienda"]);
  assert.ok(!imported.include.some((rule) => /github/.test(rule.value)), "el código del programa se lee, no se ataca github.com");
  assert.ok(imported.skipped.some((line) => /GOOGLE_PLAY_APP_ID/.test(line)) && imported.skipped.some((line) => /Tier 1/.test(line)));
  assert.match(imported.include.find((rule) => rule.value === "cloud.tienda.test")!.note ?? "", /severidad máx\. critical/);
  // Un programa privado o inexistente devuelve otra cosa (una página HTML): se dice en claro.
  await assert.rejects(publicScope("privado", csvFetch([], "<html>login</html>", "text/html")), /no es público|no existe|token/i);
  // El handle sale también de la URL de la página del programa.
  assert.equal(programHandle("https://hackerone.com/tienda/policy_scopes?type=team"), "tienda");
  assert.equal(programHandle("tienda"), "tienda");
  assert.throws(() => programHandle("https://evil.test/tienda"), /HackerOne/);
  // La traducción es la misma que la de la API con token.
  assert.deepEqual(translateAssets([{ type: "URL", identifier: "a.tienda.test, b.tienda.test", eligible: true }], "tienda").include.map((rule) => rule.value), ["a.tienda.test", "b.tienda.test"]);
});

test("a) /h1 alcance sin token carga el CSV público desde el daemon (también con la URL de la página)", async () => {
  const cwd = tmp();
  const calls: FetchCall[] = [];
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), autoResume: false, fetch: csvFetch(calls), h1Credentials: () => undefined });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ model: "faux" });
    const lines = (await client.ask("h1", { action: "alcance", handle: "https://hackerone.com/tienda/policy_scopes" })).join("\n");
    assert.match(lines, /CSV público del programa, sin token/);
    assert.match(lines, /3 dentro, 1 excluidos, 2 de código fuente/);
    assert.deepEqual(calls.map((item) => item.url), ["https://hackerone.com/teams/tienda/assets/download_csv.csv"]);
    // La lista de programas sí necesita el token, y lo dice junto con lo que se puede hacer sin él.
    await assert.rejects(client.ask("h1"), /Falta iniciar sesión en HackerOne[\s\S]*sin token/i);
    client.close();
  } finally {
    await daemon.close();
  }
});

test("a) h1_scope_load sin token carga el alcance público (también desde la URL de policy_scopes)", async () => {
  const calls: FetchCall[] = [];
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), autoVerify: false, cveFeed: false, h1: () => ({ fetch: csvFetch(calls) }) });
  try {
    engine.catalog.load("h1_scope_load");
    engine.provider.faux!.queue = [call("h1_scope_load", { handle: "https://hackerone.com/tienda/policy_scopes", pedido: "vamos con https://hackerone.com/tienda/policy_scopes" }), { text: "listo" }];
    await engine.send("vamos con https://hackerone.com/tienda/policy_scopes");
    assert.match(toolText(engine, "h1_scope_load"), /CSV público/);
    assert.equal(engine.scope.current()?.source, "hackerone:tienda");
    assert.equal(decide(engine.scope.current(), "https://cloud.tienda.test/").allowed, true);
    assert.equal(decide(engine.scope.current(), "https://github.com/tienda-org/tienda").allowed, false, "github.com no es objetivo");
    assert.match(scopeView(engine.scope.current()).join("\n"), /Lectura de referencia[\s\S]*github\.com\/tienda-org\/tienda/);
    assert.match(scopeBrief(engine.scope.current()), /reference_read/);
  } finally {
    await engine.close();
  }
});

/** fetch simulado para reference_read: anota cada pedido y responde lo que diga `route`. */
function referenceFetch(calls: FetchCall[], route: (url: string) => Response = () => new Response("<?php // código", { headers: { "content-type": "text/plain; charset=utf-8" } })): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return route(String(url));
  }) as typeof fetch;
}

test("b) referencia: leer código del programa con GET, sin credenciales del objetivo; probar sigue atado al alcance", async () => {
  const calls: FetchCall[] = [];
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), autoVerify: false, cveFeed: false, reference: { fetch: referenceFetch(calls), lookup: async () => ["140.82.112.3"], sleep: async () => {} } });
  try {
    engine.scope.save({ ...load("hackerone:tienda", "cloud.tienda.test"), reference: [parseRule("https://github.com/tienda-org/tienda")] });
    // El operador cargó una identidad del objetivo: nunca viaja a una fuente de referencia.
    engine.http.setIdentity({ name: "tester", headers: { cookie: "sesion=secreta-del-objetivo", authorization: "Bearer token-del-objetivo" } });
    engine.catalog.load("reference_read");
    engine.provider.faux!.queue = [call("reference_read", { url: "https://raw.githubusercontent.com/tienda-org/tienda/main/core/Access.php" }), { text: "leído" }];
    await engine.send("leé el control de acceso del código");
    assert.match(toolText(engine, "reference_read"), /HTTP 200[\s\S]*<\?php/);
    assert.equal(calls.length, 1);
    const sent = calls[0]!;
    assert.equal(sent.url, "https://raw.githubusercontent.com/tienda-org/tienda/main/core/Access.php");
    assert.equal(sent.init?.method, "GET");
    assert.equal(sent.init?.body, undefined, "sin cuerpo");
    assert.equal(sent.init?.redirect, "manual");
    const headers = new Headers(sent.init?.headers);
    assert.deepEqual([...headers.keys()].sort(), ["accept", "user-agent"], "sólo user-agent y accept: nada del objetivo");
    assert.doesNotMatch(JSON.stringify(sent.init), /secreta-del-objetivo|token-del-objetivo/);
    // Probar el objetivo sigue estrictamente atado al alcance: http_request no llega a GitHub y dice por dónde se lee.
    const blocked = await engine.http.send({ url: "https://raw.githubusercontent.com/tienda-org/tienda/main/x.php" });
    assert.match(blocked.error ?? "", /Fuera del alcance[\s\S]*reference_read/);
  } finally {
    await engine.close();
  }
});

test("b) referencia: no sirve para atacar (métodos, cuerpos, cabeceras, payloads, puertos, hosts, exclusiones, ritmo y tope)", async () => {
  const scope = scopeOf("hackerone:tienda", ["cloud.tienda.test"], { exclude: [parseRule("https://github.com/tienda-org/privado")], reference: [parseRule("docs.tienda.test")] });
  const ok = (url: string) => referenceDecision(scope, url);
  for (const url of ["https://github.com/tienda-org/tienda/blob/main/README.md", "https://api.github.com/repos/tienda-org/tienda/contents/core?ref=main", "https://raw.githubusercontent.com/tienda-org/tienda/main/a.php", "https://docs.tienda.test/guia/permisos", "https://hackerone.com/tienda/policy_scopes", "https://hackerone.com/teams/tienda/assets/download_csv.csv"]) {
    assert.equal(ok(url).allowed, true, `${url}: ${ok(url).reason}`);
  }
  const refused: Array<[string, RegExp]> = [
    ["https://cloud.tienda.test/admin", /no es una fuente de referencia.*http_request/s],
    ["https://evil.test/", /no es una fuente de referencia/],
    ["http://raw.githubusercontent.com/a/b/main/x", /https/],
    ["https://raw.githubusercontent.com:8443/a/b/main/x", /puerto/],
    ["https://user:pass@github.com/a/b", /credenciales/],
    ["https://github.com/tienda-org/tienda/search?q=%27%20or%201=1--", /consulta|caracteres/],
    ["https://github.com/tienda-org/tienda/blob/main/<script>", /caracteres/],
    ["https://raw.githubusercontent.com/a/b/main/%2e%2e/%2e%2e/etc/passwd", /caracteres/],
    ["https://api.github.com/repos/a/b/contents/x?ref=main&callback=alert(1)", /consulta/],
    ["https://github.com/tienda-org/tienda;jsessionid=1", /caracteres/],
    ["https://github.com/tienda-org/privado/blob/main/x", /[Ee]xcluido/],
    ["https://hackerone.com/otro-programa/policy_scopes", /no es una fuente de referencia/],
    ["https://hackerone.com/reports/123", /no es una fuente de referencia/],
  ];
  for (const [url, reason] of refused) {
    const decision = ok(url);
    assert.equal(decision.allowed, false, `${url} no debería pasar`);
    assert.match(decision.reason, reason, url);
  }
  assert.match(referenceDecision(undefined, "https://github.com/a/b").reason, /alcance/);
  // Un programa sólo de código (todo SOURCE_CODE) no tiene nada que probar, pero su código se lee.
  const codeOnly = scopeOf("hackerone:libreria", [], { reference: [parseRule("https://github.com/libreria-org/libreria")] });
  assert.equal(referenceDecision(codeOnly, "https://raw.githubusercontent.com/libreria-org/libreria/main/src/a.c").allowed, true);
  assert.equal(decide(codeOnly, "https://github.com/libreria-org/libreria").allowed, false, "y nada se prueba");

  // La herramienta: sólo url; métodos, cuerpos y cabeceras no existen ni se aceptan.
  const calls: FetchCall[] = [];
  let slept = 0;
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), autoVerify: false, cveFeed: false, reference: { fetch: referenceFetch(calls, (url) => (/redir-afuera/.test(url) ? new Response(null, { status: 302, headers: { location: "https://evil.test/x" } }) : /redir-raw/.test(url) ? new Response(null, { status: 301, headers: { location: "https://raw.githubusercontent.com/tienda-org/tienda/main/x.php" } }) : /binario/.test(url) ? new Response(new Uint8Array([0, 1, 2]), { headers: { "content-type": "application/octet-stream" } }) : new Response("ok", { headers: { "content-type": "text/plain" } }))), lookup: async (host) => (host === "docs.tienda.test" ? ["10.0.0.5"] : ["140.82.112.3"]), sleep: async (ms) => { slept += ms; } } });
  try {
    engine.scope.save({ ...load("hackerone:tienda", "cloud.tienda.test"), reference: [parseRule("docs.tienda.test")] });
    engine.catalog.load("reference_read");
    engine.provider.faux!.queue = [
      call("reference_read", { url: "https://github.com/tienda-org/tienda", method: "POST", body: "x=1", headers: { cookie: "a=b" } }),
      call("reference_read", { url: "https://github.com/tienda-org/tienda/redir-afuera" }),
      call("reference_read", { url: "https://github.com/tienda-org/tienda/redir-raw" }),
      call("reference_read", { url: "https://github.com/tienda-org/tienda/binario" }),
      call("reference_read", { url: "https://docs.tienda.test/guia" }),
      { text: "fin" },
    ];
    await engine.send("leé el código");
    const results = engine.agent.messages.filter((m) => m.role === "tool" && m.name === "reference_read").map((m) => String(m.content));
    assert.match(results[0]!, /sólo lee.*method.*body.*headers/s);
    assert.match(results[1]!, /evil\.test.*no se siguió/s);
    assert.match(results[2]!, /HTTP 200/);
    assert.match(results[3]!, /binari/);
    assert.match(results[4]!, /privada/);
    assert.ok(!calls.some((item) => /evil\.test|docs\.tienda\.test/.test(item.url)), "ni la redirección afuera ni el host que resuelve a una IP privada se pidieron");
    assert.ok(calls.every((item) => item.init?.method === "GET" && item.init?.body === undefined));
    assert.ok(slept >= 1000 * (calls.length - 1), `ritmo: ${slept} ms de espera para ${calls.length} pedidos`);
  } finally {
    await engine.close();
  }
  // Tope por sesión: pasado el tope no sale ni un pedido más.
  const capped: FetchCall[] = [];
  const tool = createReferenceTool({ scope: () => scope, artifacts: { put: () => ({ hash: "sha256:x" }) } as never, fetch: referenceFetch(capped), lookup: async () => ["140.82.112.3"], sleep: async () => {} });
  for (let i = 0; i < REFERENCE_CAP; i++) await tool.execute({ url: `https://github.com/tienda-org/tienda/blob/main/f${i}.php` }, new AbortController().signal);
  await assert.rejects(async () => tool.execute({ url: "https://github.com/tienda-org/tienda/blob/main/otro.php" }, new AbortController().signal), /tope/);
  assert.equal(capped.length, REFERENCE_CAP);
});

function server(handler: (path: string) => { status: number; headers?: Record<string, string>; body?: string }): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const srv = createServer((req, res) => {
      const out = handler(req.url ?? "/");
      res.writeHead(out.status, { "content-type": "text/html", ...out.headers }).end(out.body ?? "");
    });
    srv.listen(0, "127.0.0.1", () => resolve({ server: srv, base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` }));
  });
}

test("a) en el programa de la propia plataforma de código, su host pelado es objetivo; sus repositorios, lectura", () => {
  const imported = translateAssets([
    { type: "URL", identifier: "github.com", eligible: true },
    { type: "URL", identifier: "https://gitlab.com/", eligible: true },
    { type: "WILDCARD", identifier: "*.github.com", eligible: true },
    { type: "URL", identifier: "https://github.com/github/docs", eligible: true },
  ], "github");
  assert.deepEqual(imported.include.map((rule) => rule.value).sort(), ["*.github.com", "github.com", "https://gitlab.com"].sort());
  assert.deepEqual(imported.reference.map((rule) => rule.value), ["https://github.com/github/docs"]);
});

test("c) una página que pide iniciar sesión: se detecta, se le dice al operador cómo cargar la sesión y se sigue", async () => {
  const { server: srv, base } = await server((path) =>
    path.startsWith("/panel") ? { status: 302, headers: { location: "https://sso.otra.test/login?next=%2Fpanel" } }
    : path.startsWith("/cuenta") ? { status: 302, headers: { location: "/login?next=/cuenta" } }
    : path.startsWith("/afuera") ? { status: 302, headers: { location: "https://otra.test/landing" } }
    : path.startsWith("/login") ? { status: 200, body: "<form action=/login method=post><input name=user><input type=password name=pass></form>" }
    : { status: 200, body: "hola" });
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), autoVerify: false, cveFeed: false });
  const notices: string[] = [];
  engine.onNotice = (text) => notices.push(text);
  try {
    engine.scope.save(load("manual", base));
    // Redirección a un login fuera del alcance: no choca, no se sigue, y el resto del trabajo sigue.
    const sso = await engine.http.send({ url: `${base}/panel`, followRedirects: true });
    assert.equal(sso.error, undefined, "no es un error de alcance");
    assert.equal(sso.response?.status, 302);
    assert.match(summarize(sso), /iniciar sesión fuera del alcance/);
    assert.match(summarize(sso), /no se siguió, pero el resto del trabajo sigue/);
    // Las mismas salidas que adentro: la sesión del operador (también la de su navegador) o una cuenta de prueba propia si el registro del sitio está en alcance.
    assert.match(summarize(sso), /chrome_session/);
    assert.match(summarize(sso), /registro está abierto y dentro del alcance, creá una cuenta de prueba propia con mail_address y mail_wait/);
    const manual = await engine.http.send({ url: `${base}/panel`, followRedirects: false });
    assert.equal(manual.notFollowed, sso.notFollowed);
    assert.deepEqual(manual.redirects, []);
    // Después del SSO de afuera, el cliente sigue trabajando con el mismo origen.
    const after = await engine.http.send({ url: `${base}/` });
    assert.equal(after.response?.status, 200);
    // Login en el mismo host, siguiendo la redirección.
    const own = await engine.http.send({ url: `${base}/cuenta`, followRedirects: true });
    assert.equal(own.response?.status, 200);
    assert.match(summarize(own), /Pide iniciar sesión: redirige a/);
    // Una redirección fuera del alcance que no es un login tampoco se sigue ni es un error.
    const out = await engine.http.send({ url: `${base}/afuera`, followRedirects: true });
    assert.equal(out.error, undefined);
    assert.match(summarize(out), /fuera del alcance.*no se siguió/s);
    assert.doesNotMatch(summarize(out), /iniciar sesión/);
    // Ninguna salida le prohíbe al modelo crear su cuenta de prueba ni probar el login con credenciales inventadas.
    for (const exchange of [sso, own]) assert.doesNotMatch(summarize(exchange), /no crees|no creás|inventes|no crea/i);
    // Al operador, una vez por origen: no se sigue afuera, qué sesión puede aportar y que el agente se registra si puede.
    const told = notices.filter((text) => /iniciar sesión/.test(text));
    assert.equal(told.length, 1, notices.join(" | "));
    assert.match(told[0]!, /fuera del alcance.*no sigo esa redirección, y el resto del trabajo sigue/);
    assert.match(told[0]!, /\/identity/);
    assert.match(told[0]!, /chrome_session/);
    assert.match(told[0]!, /creo una cuenta de prueba propia/);
    assert.doesNotMatch(told[0]!, /no creo|no crea/i);
  } finally {
    await engine.close();
    srv.close();
  }
});

test("un login dentro del alcance: sesión cargada, cuenta de prueba propia si el registro está abierto, o avisar si está cerrado", async () => {
  const { server: srv, base } = await server(() => ({ status: 302, headers: { location: "/login" } }));
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), cveFeed: false });
  try {
    engine.scope.save(load("manual", base));
    const avisos: string[] = [];
    engine.onNotice = (text) => avisos.push(text);
    const intercambio = await engine.http.send({ url: `${base}/panel` });
    assert.equal(intercambio.auth, `${base}/login`);
    assert.equal(intercambio.notFollowed, undefined);
    // Al operador.
    assert.equal(avisos.length, 1);
    assert.match(avisos[0]!, /pide iniciar sesión \(redirige a /);
    assert.match(avisos[0]!, /ya cargaste una sesión/);
    assert.match(avisos[0]!, /registro del sitio está abierto y dentro del alcance, creo una cuenta de prueba propia/);
    assert.match(avisos[0]!, /\/correo/);
    assert.match(avisos[0]!, /cerrado o pide invitación, pago, teléfono o documento/);
    assert.match(avisos[0]!, /sigo con lo que no la requiere/);
    // Al modelo: (a) la sesión del operador, (b) su cuenta de prueba, (c) avisar y seguir.
    const texto = summarize(intercambio);
    assert.match(texto, /si el operador cargó una sesión para este sitio, usala \(http_identities/);
    assert.match(texto, /si no, y el registro está abierto y dentro del alcance, creá una cuenta de prueba propia con mail_address y mail_wait/);
    assert.match(texto, /si el registro está cerrado o pide algo que no podés dar \(invitación, pago, teléfono, documento\), avisale al operador y seguí con lo que no requiere sesión/);
    assert.doesNotMatch(texto, /no crees|inventes/i);
  } finally {
    await engine.close();
    srv.close();
  }
});

test("el aviso de login nombra las mismas herramientas que el prompt de sistema para crear cuentas", () => {
  for (const name of ["mail_address", "mail_wait", "tools_load", "/correo", "chrome_session"]) {
    assert.ok(SESSION_STEPS.includes(name), `el aviso nombra ${name}`);
    assert.ok(SYSTEM_PROMPT.includes(name), `el prompt de sistema nombra ${name}`);
  }
  assert.match(SYSTEM_PROMPT, /Si el registro de cuentas está abierto, creá una segunda cuenta propia/);
});

test("d) el alcance no cambia en silencio: cada cambio se avisa con lo que entra y sale, y el error dice qué revisión lo sacó", async () => {
  const lab = "http://127.0.0.1:8899";
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), autoVerify: false, cveFeed: false, h1: () => ({ fetch: csvFetch([]) }) });
  const notices: string[] = [];
  engine.onNotice = (text) => notices.push(text);
  try {
    engine.scope.save(load("manual", lab));
    assert.deepEqual(notices, [], "la primera carga no saca nada: no hace falta avisar");
    // Cargar el programa a mitad de sesión ya no tira el laboratorio local: se conserva y se dice.
    notices.length = 0;
    engine.catalog.load("h1_scope_load");
    engine.provider.faux!.queue = [call("h1_scope_load", { handle: "tienda", pedido: "vamos con el programa tienda" }), { text: "listo" }];
    await engine.send("vamos con el programa tienda");
    assert.equal(decide(engine.scope.current(), `${lab}/index.php`).allowed, true, "el laboratorio sigue");
    assert.match(toolText(engine, "h1_scope_load"), /[Cc]onserv.*127\.0\.0\.1:8899/s);
    assert.ok(notices.some((text) => /rev \d+ → rev \d+/.test(text) && /hackerone:tienda/.test(text)), notices.join(" | "));
    // El operador lo saca: aviso explícito, y el error del cliente HTTP dice qué revisión lo sacó.
    notices.length = 0;
    const before = engine.scope.current()!.rev;
    engine.scope.edit({ remove: [lab] });
    assert.ok(notices.some((text) => /sale/.test(text) && /127\.0\.0\.1:8899/.test(text)), notices.join(" | "));
    const blocked = await engine.http.send({ url: `${lab}/index.php` });
    assert.match(blocked.error ?? "", new RegExp(`autorizado hasta la rev ${before}.*rev ${engine.scope.current()!.rev}`, "s"));
    // Como manda el prompt de sistema: si el operador lo vuelve a pedir, se carga con scope_edit citándolo.
    assert.match(blocked.error ?? "", /si lo pidió de nuevo, cargalo con scope_edit citando ese mensaje/);
    // Y el agente, en su próximo mensaje, ve qué cambió.
    engine.provider.faux!.queue = [{ text: "ok" }];
    await engine.send("seguí");
    assert.match(String(engine.agent.messages.findLast((m) => m.role === "user")!.content), /<alcance>[\s\S]*sale[\s\S]*127\.0\.0\.1:8899/);
  } finally {
    await engine.close();
  }
});

test("e) elegir un proveedor que no existe: el error dice qué valores valen", () => {
  const models = ["orobas/glm-5.3-flash", "orobas/deepseek-v4.1-flash", "orobas/auto"];
  assert.throws(() => pickModel("abl/glm", models, "orobas/glm-5.3-flash", ["orobas"]), (error: Error) => {
    assert.match(error.message, /«abl»/);
    assert.match(error.message, /orobas/);
    assert.match(error.message, /glm-5\.3-flash/);
    assert.doesNotMatch(error.message, /openai|anthropic|openrouter|ollama/, "los de fábrica sin clave no valen");
    return true;
  });
  // Uno propio configurado y listo sí aparece.
  assert.throws(() => pickModel("abl/x", models, "orobas/glm-5.3-flash", ["orobas", "milocal"]), /milocal/);
  assert.equal(pickModel("milocal/qwen", models, "orobas/glm-5.3-flash", ["orobas", "milocal"]), "milocal/qwen");
  // Ollama local no pide clave: como en main, se elige sin declararlo (aunque no se liste en el error).
  assert.equal(pickModel("ollama/qwen3", models, "orobas/glm-5.3-flash", ["orobas"]), "ollama/qwen3");
  // Sin barra y sin coincidencia: los modelos de la cuenta y cómo se escribe otro proveedor.
  assert.throws(() => pickModel("abl", models, "orobas/glm-5.3-flash", ["orobas"]), /Disponibles: glm-5\.3-flash.*proveedor\/modelo/s);
  // El de configuración también: resolveProvider con uno desconocido.
  const config = join(tmp(), "config.json");
  writeFileSync(config, JSON.stringify({ providers: { milocal: { baseUrl: "http://127.0.0.1:9/v1" } } }));
  const previous = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = config;
  try {
    assert.throws(() => resolveProvider("abl/x"), (error: Error) => /«abl»/.test(error.message) && /orobas/.test(error.message) && /milocal/.test(error.message) && !/openrouter|ollama/.test(error.message));
  } finally {
    if (previous === undefined) delete process.env.CYBER_CONFIG;
    else process.env.CYBER_CONFIG = previous;
  }
});
