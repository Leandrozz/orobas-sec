import "./datos-tmp.ts";
// CVEs nuevos (src/cvefeed.ts): el feed de Zero Wire se baja con su propio User-Agent y nada del objetivo,
// como mucho cada 6 h por proyecto; sin red sigue avisando una sola vez; el cruce con las tecnologías de la
// sesión es conservador (nada de «Server», ni el plugin de WordPress por WordPress); cada CVE se avisa una
// vez por sesión, al operador y al agente en su próximo turno, sin cortar el turno en curso; y /cves lo muestra.
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { connectDaemon } from "../src/client.ts";
import { crossItem, CveFeed, type CveItem, FEED_INTERVAL_MS, FEED_RETRY_MS, FEED_URLS, FEED_USER_AGENT, feedSwitch, parseFeed, type Tecnologia, tecnologia, techsFromExchange, techsFromScope, versionInText } from "../src/cvefeed.ts";
import { Daemon } from "../src/daemon.ts";
import { Engine } from "../src/engine.ts";
import type { Message } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { findCommand, hijos } from "../src/tui/comandos.ts";
import type { VulndbCve } from "../src/vulndb.ts";

const FIXTURE = readFileSync(join(import.meta.dirname, "fixtures", "zero-wire-criticos.json"), "utf8");
const NOW = Date.parse("2026-11-20T18:00:00Z");
const tmp = () => mkdtempSync(join(tmpdir(), "cyber-cvefeed-"));
const tick = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 15_000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(10);
};

/** El feed de altos de la prueba: un WordPress núcleo con versión y un título lleno de palabras genéricas. */
const HIGH = JSON.stringify({
  version: "https://jsonfeed.org/version/1.1",
  title: "CVEs with High severity | Zero Wire | Cloudflare Radar",
  items: [
    { id: "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-90001", url: "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-90001", title: "CVE-2026-90001: WordPress core before 6.4.3 allows stored XSS through the block editor", summary: "WordPress core before 6.4.3 does not sanitize a block attribute, allowing contributors to store scripts.", content_text: "x", date_published: "2026-11-20T10:00:00.000Z", tags: ["High"], _cve: { id: "CVE-2026-90001", severity: "HIGH", score: 8.8, cvss_version: "3.1" } },
    { id: "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-90002", url: "https://evil.example/phish", title: "CVE-2026-90002: Acme Server Pro web plugin API manager allows remote login bypass", summary: "The web admin panel of the server lets a remote user log in through the API gateway.", content_text: "x", date_published: "2026-11-20T09:00:00.000Z", tags: ["High"], _cve: { id: "CVE-2026-90002", severity: "HIGH", score: 8.1, cvss_version: "3.1" } },
  ],
});

/** fetch falso: el feed de críticos real y el de altos de arriba; anota cada pedido. */
function fakeFetch(calls: Array<{ url: string; init?: RequestInit }> = []): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    if (url === FEED_URLS.critica) return new Response(FIXTURE, { headers: { "content-type": "application/feed+json" } });
    if (url === FEED_URLS.alta) return new Response(HIGH, { headers: { "content-type": "application/feed+json" } });
    return new Response("no", { status: 404 });
  }) as typeof fetch;
}

const items = parseFeed(JSON.parse(FIXTURE));
const item = (id: string) => items.find((entry) => entry.id === id)!;
const tech = (name: string, version?: string, activo = "app.ejemplo.test"): Tecnologia => tecnologia(name, version, activo, "prueba")!;

test("feed: parsea el JSON Feed real de Zero Wire (id, severidad, puntaje, link de Radar) sin la cola que nombra a Cloudflare", () => {
  assert.equal(items.length, 100);
  assert.deepEqual(items[0], {
    id: "CVE-2026-133872",
    severidad: "CRITICAL",
    puntaje: 9.1,
    cvss: "4.0",
    titulo: "LessPass Backend before Commit 9469b0c Missing Rate Limiting on JWT Login",
    resumen: items[0]!.resumen,
    url: "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-133872",
    publicado: "2026-11-20T16:16:58.372Z",
  });
  assert.match(items[0]!.resumen, /^LessPass self-hosted sync server backend before commit 9469b0c/);
  assert.ok(items.every((entry) => !/Cloudflare Radar|CVSS 4\.0 score/.test(entry.resumen)), "la cola de content_text no entra");
  // Un título que es sólo el id queda vacío: el resumen dice el producto.
  assert.equal(item("CVE-2026-115407").titulo, "");
  assert.match(item("CVE-2026-115407").resumen, /crypto11/);
  // Sin resumen, content_text sin su cola; un link a otro host se reemplaza por el de Radar.
  const [only] = parseFeed({ items: [{ title: "CVE-2026-1234: Foo", content_text: "Foo bar.\n\nCVSS 3.1 score: 9.8 (Critical)\n\nDetails on Cloudflare Radar: https://radar.cloudflare.com/x", url: "https://evil.example/CVE-2026-1234", date_published: "2026-11-01T00:00:00Z", _cve: { id: "CVE-2026-1234", severity: "CRITICAL", score: 9.8 } }] });
  assert.equal(only!.resumen, "Foo bar.");
  assert.equal(only!.url, "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-1234");
  assert.equal(parseFeed({ items: [{ title: "sin id" }, { _cve: { id: "CVE-2026-1" }, date_published: "2026-11-01" }] }).length, 0);
  assert.throws(() => parseFeed({ nada: 1 }), /JSON Feed/);
});

test("cruce: productos con nombre distintivo, versión cuando la hay y los falsos positivos típicos afuera", () => {
  const cross = (id: string, name: Tecnologia) => crossItem(item(id), name);
  // Apache-Coyote es Tomcat (y su 1.1 es la del conector, no la de Tomcat): cruza sin versión.
  const coyote = techsFromExchange({ request: { method: "GET", url: "https://app.ejemplo.test/", headers: {} }, redirects: [], response: { status: 200, headers: { server: "Apache-Coyote/1.1" }, body: "", bodyBytes: 0, truncated: false } });
  assert.deepEqual(coyote.map((entry) => [entry.producto, entry.version]), [["Apache Tomcat", undefined]]);
  assert.deepEqual(cross("CVE-2026-133325", coyote[0]!), { version: "sin determinar" });
  // «Apache» a secas es el HTTP Server: no es Tomcat ni el «Apache mod_php» de un CVE de PHP.
  assert.equal(cross("CVE-2026-133325", tech("apache", "2.4.58")), undefined);
  assert.equal(cross("CVE-2026-129496", tech("apache", "2.4.58")), undefined);
  // PHP: el texto publica ramas («8.3.* before 8.3.37»); la versión vista decide.
  assert.deepEqual(cross("CVE-2026-129496", tech("php", "8.3.10")), { version: "en rango" });
  assert.match((cross("CVE-2026-129474", tech("php", "8.3.10")) as { descarte: string }).descarte, /8\.3\.10\) queda fuera del rango/);
  assert.deepEqual(cross("CVE-2026-129474", tech("php", "8.5.2")), { version: "en rango" });
  // «PHP Object Injection» en un plugin de WordPress no es PHP: un nombre ambiguo necesita una versión al lado.
  assert.equal(cross("CVE-2026-129039", tech("php", "8.3.10")), undefined);
  // WordPress núcleo contra plugins: «WordPress X plugin», «X plugin for WordPress», aunque nombre «WordPress user».
  for (const id of ["CVE-2026-129043", "CVE-2026-129073", "CVE-2026-80188", "CVE-2026-14492", "CVE-2026-129048"]) {
    assert.match((cross(id, tech("wordpress", "6.4.2")) as { descarte: string }).descarte, /complemento de WordPress/, id);
  }
  // El plugin visto en wp-content sí cruza con su CVE.
  const plugin: Tecnologia = { clave: "wp-plugin:newsletters-lite", producto: "newsletters-lite (plugin de WordPress)", activo: "blog.ejemplo.test", fuente: "ruta", complemento: true };
  assert.deepEqual(cross("CVE-2026-129043", plugin), { version: "sin determinar" });
  // Joomla núcleo contra «Joomla Extension - …».
  assert.match((cross("CVE-2026-129411", tech("joomla")) as { descarte: string }).descarte, /complemento de Joomla/);
  // MongoDB nombrado de contexto («Dokploy: … backup of PostgreSQL, MySQL, MongoDB») o su driver de C#: no es el servidor.
  assert.equal(cross("CVE-2026-129991", tech("mongodb")), undefined);
  assert.equal(cross("CVE-2026-129938", tech("mongodb")), undefined);
  // Etherpad: el título manda aunque el resumen hable de su «core pseudo-plugin».
  assert.deepEqual(cross("CVE-2026-114516", tech("etherpad", "2.0.0")), { version: "en rango" });
  assert.match((cross("CVE-2026-114516", tech("etherpad", "3.3.3")) as { descarte: string }).descarte, /fuera del rango/);
  // Palabras genéricas, CDNs y frentes gestionados nunca son una tecnología.
  for (const name of ["Server", "api", "web plugin", "admin panel", "cloudflare", "AkamaiGHost", "jsp"]) assert.equal(tecnologia(name, undefined, "x", "y"), undefined, name);
  // «Google Frontend» es un solo nombre: «frontend» suelto no cruza con nada.
  const google = techsFromExchange({ request: { method: "GET", url: "https://x.test/", headers: {} }, redirects: [], response: { status: 200, headers: { server: "Google Frontend" }, body: "", bodyBytes: 0, truncated: false } });
  assert.deepEqual(google.map((entry) => entry.clave), ["google frontend"]);
  for (const entry of items) assert.equal(crossItem(entry, google[0]!), undefined, entry.id);
  // Ningún CVE del feed real cruza con nombres genéricos aunque los tenga en el título.
  const acme = parseFeed(JSON.parse(HIGH)).find((entry) => entry.id === "CVE-2026-90002")!;
  assert.equal(acme.url, "https://radar.cloudflare.com/zero-wire/cves/CVE-2026-90002");
  for (const name of ["express", "react", "bootstrap", "nginx", "wordpress"]) assert.equal(crossItem(acme, tech(name)), undefined, name);
  // Ambiguos: «express checkout» no es Express; «express before 4.19.2» sí.
  const synthetic = (titulo: string, resumen = ""): CveItem => ({ id: "CVE-2026-1", severidad: "HIGH", titulo, resumen, url: "", publicado: "" });
  assert.equal(crossItem(synthetic("Shopx express checkout allows price tampering"), tech("express")), undefined);
  assert.deepEqual(crossItem(synthetic("express before 4.19.2 allows open redirect"), tech("express", "4.18.1")), { version: "en rango" });
  // Familias: «jQuery UI», «GitLab Runner», «ingress-nginx» y el plugin de Jenkins no son el producto.
  assert.equal(crossItem(synthetic("jQuery UI before 1.13.2 allows XSS"), tech("jquery", "3.7.1")), undefined);
  assert.equal(crossItem(synthetic("GitLab Runner token leak"), tech("gitlab")), undefined);
  assert.equal(crossItem(synthetic("ingress-nginx controller allows config injection"), tech("nginx", "1.25.3")), undefined);
  assert.match((crossItem(synthetic("Jenkins Pipeline Groovy plugin sandbox bypass"), tech("jenkins")) as { descarte: string }).descarte, /complemento/);
  assert.deepEqual(crossItem(synthetic("Jenkins 2.441 and earlier allows arbitrary file read"), tech("jenkins", "2.440")), { version: "en rango" });
});

test("versiones: rangos del texto en inglés, ramas y listas; lo que no se entiende queda sin determinar", () => {
  const php = "This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.";
  assert.equal(versionInText("8.3.10", php), "en rango");
  assert.equal(versionInText("8.4.30", php), "fuera de rango");
  assert.equal(versionInText("7.4.3", php), "en rango");
  assert.equal(versionInText("8.5.13", php), "fuera de rango");
  const tomcat = "Apache Tomcat versions before 9.0.98, 10.1.34 and 11.0.2";
  assert.equal(versionInText("10.1.20", tomcat), "en rango");
  assert.equal(versionInText("8.5.0", tomcat), "en rango");
  assert.equal(versionInText("11.0.5", tomcat), "fuera de rango");
  assert.equal(versionInText("4.18.2", "WordPress Newsletters plugin <= 4.18.2 - SQL Injection"), "en rango");
  assert.equal(versionInText("4.19", "This issue affects Newsletters: from n/a through 4.18.2."), "fuera de rango");
  assert.equal(versionInText("0.9", "From 0.29.13 until 0.31.0, the Docker terminal"), "fuera de rango");
  assert.equal(versionInText("0.30.1", "From 0.29.13 until 0.31.0, the Docker terminal"), "en rango");
  assert.equal(versionInText("1.57", "In versions up to and including 1.57, the ID"), "en rango");
  assert.equal(versionInText("2.1", "2.0 and earlier"), "fuera de rango");
  // Sin rango reconocible, o con menos precisión que el límite: nunca «fuera».
  assert.equal(versionInText("1.0", "before commit 9469b0c"), "sin determinar");
  assert.equal(versionInText("10", "Drupal before 10.1.5"), "sin determinar");
  assert.equal(versionInText("desconocida", php), "sin determinar");
  // Un id de CVE o una fecha no son un rango.
  assert.equal(versionInText("2026.1", "Fixed in CVE-2026-1234 on 2026-11-20"), "sin determinar");
});

test("tecnologías: cabeceras, generator, plugins de WordPress y los nombres del alcance (sólo productos conocidos)", () => {
  const seen = techsFromExchange({
    request: { method: "GET", url: "https://blog.ejemplo.test/inicio", headers: {} },
    redirects: [],
    response: {
      status: 200,
      headers: { server: "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.2", "x-powered-by": "PHP/8.3.10", "x-jenkins": "2.440.1", "content-type": "text/html; charset=utf-8" },
      body: '<meta name="generator" content="WordPress 6.4.2"><script src="/wp-content/plugins/newsletters-lite/js/x.js?ver=4.9"></script><link href="/wp-content/themes/astra/style.css"><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>',
      bodyBytes: 0,
      truncated: false,
    },
  });
  assert.deepEqual(seen.map((entry) => `${entry.producto}${entry.version ? ` ${entry.version}` : ""} @${entry.activo} · ${entry.fuente}`), [
    "Apache HTTP Server 2.4.58 @blog.ejemplo.test · cabecera server",
    "OpenSSL 3.0.2 @blog.ejemplo.test · cabecera server",
    "PHP 8.3.10 @blog.ejemplo.test · cabecera x-powered-by",
    "Jenkins 2.440.1 @blog.ejemplo.test · cabecera x-jenkins",
    "WordPress 6.4.2 @blog.ejemplo.test · generator del HTML",
    "newsletters-lite (plugin de WordPress) @blog.ejemplo.test · ruta wp-content/plugins del HTML",
    "astra (tema de WordPress) @blog.ejemplo.test · ruta wp-content/themes del HTML",
    "jQuery 3.7.1 @blog.ejemplo.test · script del HTML",
  ]);
  const scope = { rev: 3, source: "hackerone:acme", at: "", exclude: [], notes: "Programa HackerOne «acme». Corre sobre Keycloak.", include: [
    parseRule("gitlab-ci.acme.test"), parseRule("*.jenkins.acme.test"), parseRule("shop.acme.test"), parseRule("api.acme.test"), parseRule("https://wp.acme.test/blog"), parseRule("10.0.0.0/8"), parseRule("app.acme.test", "Panel interno de Grafana"),
  ] };
  assert.deepEqual(techsFromScope(scope).map((entry) => `${entry.producto} @${entry.activo} · ${entry.fuente}`), [
    "GitLab @gitlab-ci.acme.test · nombre del activo",
    "Jenkins @*.jenkins.acme.test · nombre del activo",
    "WordPress @https://wp.acme.test/blog · nombre del activo",
    "Grafana @app.acme.test · nota del activo",
    "Keycloak @hackerone:acme · notas del alcance",
  ]);
});

test("feed: baja de una URL fija con User-Agent propio y nada del objetivo; caché en la base del proyecto, como mucho cada 6 h", async () => {
  const requests: Array<{ url: string; headers: IncomingHttpHeaders }> = [];
  const server = createServer((req, res) => {
    requests.push({ url: req.url ?? "", headers: req.headers });
    res.setHeader("content-type", "application/feed+json");
    res.end(req.url?.includes("severity=critical") ? FIXTURE : HIGH);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const dir = tmp();
  const db = openStore(projectPaths(dir));
  let now = NOW;
  const urls = { critica: `${base}/zero-wire/cves/feed?format=json&severity=critical`, alta: `${base}/zero-wire/cves/feed?format=json&severity=high` };
  const feed = new CveFeed({ db, sessionId: "s1", scope: () => undefined }, { enabled: true, urls, now: () => now });
  try {
    assert.equal(feed.due(), true);
    const first = await feed.refresh();
    assert.deepEqual(first, { ok: true, nuevos: 102 });
    assert.deepEqual(requests.map((request) => request.url).sort(), ["/zero-wire/cves/feed?format=json&severity=critical", "/zero-wire/cves/feed?format=json&severity=high"]);
    for (const request of requests) {
      assert.equal(request.headers["user-agent"], FEED_USER_AGENT);
      assert.match(FEED_USER_AGENT, /^orobas-sec\//);
      // Nada del objetivo ni del operador: sin cookies, credenciales ni cabeceras propias del harness.
      assert.equal(request.headers.cookie, undefined);
      assert.equal(request.headers.authorization, undefined);
      assert.ok(!Object.keys(request.headers).some((key) => key.startsWith("x-cyber")), "sin cabeceras de sesión");
    }
    // Las URLs de fábrica son las públicas de Radar, sin parámetros del objetivo.
    assert.equal(FEED_URLS.critica, "https://radar.cloudflare.com/zero-wire/cves/feed?format=json&severity=critical");
    assert.equal(FEED_URLS.alta, "https://radar.cloudflare.com/zero-wire/cves/feed?format=json&severity=high");
    // La caché vive en la base del proyecto: otra sesión no vuelve a bajar.
    assert.equal(feed.items({ severities: ["CRITICAL"] }).length, 100);
    const other = new CveFeed({ db, sessionId: "s2", scope: () => undefined }, { enabled: true, urls, now: () => now });
    assert.equal(other.due(), false);
    assert.match((await other.refresh()).salteado!, /ya se bajó/);
    assert.equal(requests.length, 2);
    // Antes de 6 h no se baja; a pedido (actualizar) sí, pero nunca dos veces en el mismo minuto.
    now += FEED_INTERVAL_MS - 60_000;
    assert.equal(feed.due(), false);
    assert.match((await feed.refresh()).salteado!, /ya se bajó/);
    assert.deepEqual(await feed.refresh(true), { ok: true, nuevos: 0 });
    assert.equal(requests.length, 4);
    now += 30_000;
    assert.match((await feed.refresh(true)).salteado!, /ya se bajó/);
    now += FEED_INTERVAL_MS;
    assert.equal(feed.due(), true);
    assert.equal((await feed.refresh()).ok, true);
    assert.equal(requests.length, 6);
    // Lo viejo se poda: a los 45 días de publicado ya no está, aunque el feed lo siga trayendo.
    now = NOW + 50 * 86_400_000;
    assert.deepEqual(await feed.refresh(true), { ok: true, nuevos: 0 });
    assert.equal(feed.items({ days: 400 }).length, 0);
  } finally {
    await feed.close();
    server.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sin red: sigue sin el feed, avisa una sola vez por racha y reintenta a la hora; apagado no sale nunca", async () => {
  const dir = tmp();
  const db = openStore(projectPaths(dir));
  let now = NOW;
  let online = false;
  let calls = 0;
  const notices: string[] = [];
  const events: Array<{ type: string; payload: Record<string, unknown> }> = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    calls++;
    if (!online) throw new TypeError("fetch failed", { cause: new Error("getaddrinfo EAI_AGAIN radar.cloudflare.com") });
    return fakeFetch()(input);
  }) as typeof fetch;
  const feed = new CveFeed({ db, sessionId: "s1", scope: () => undefined, notice: (text) => notices.push(text), event: (type, payload) => events.push({ type, payload }) }, { enabled: true, fetch: fetchImpl, now: () => now });
  try {
    const failed = await feed.refresh();
    assert.equal(failed.ok, false);
    assert.match(failed.error!, /críticos: sin conexión \(.*EAI_AGAIN/);
    assert.equal(notices.length, 1);
    assert.match(notices[0]!, /^No pude bajar el feed de CVEs nuevos \(.*\): sigo sin él y reintento en una hora, sin volver a avisar\. \/cves muestra el estado\./);
    assert.deepEqual(events.map((event) => [event.type, event.payload.ok]), [["cve.feed", false]]);
    // A la hora reintenta, sin volver a avisar.
    now += FEED_RETRY_MS - 1000;
    assert.equal(feed.due(), false);
    now += 1000;
    assert.equal(feed.due(), true);
    assert.equal((await feed.refresh()).ok, false);
    assert.equal(notices.length, 1, "un solo aviso por racha");
    assert.match(feed.view().join("\n"), /Último error: críticos: sin conexión .*2 intentos fallidos seguidos/);
    // Vuelve la red: baja, y una falla nueva es otra racha (se avisa otra vez).
    online = true;
    now += FEED_RETRY_MS;
    assert.deepEqual(await feed.refresh(), { ok: true, nuevos: 102 });
    online = false;
    now += FEED_INTERVAL_MS;
    await feed.refresh();
    assert.equal(notices.length, 2);
    // Una de las dos severidades caída no es una falla: se guarda lo que vino y se anota el error.
    const half = new CveFeed({ db, sessionId: "s1", scope: () => undefined }, { enabled: true, now: () => now + FEED_RETRY_MS, fetch: (async (input: string | URL | Request) => (String(input).includes("high") ? new Response("caído", { status: 503 }) : fakeFetch()(input))) as typeof fetch });
    const partial = await half.refresh();
    assert.equal(partial.ok, true);
    assert.match(partial.error!, /altos: HTTP 503/);
    await half.close();
  } finally {
    await feed.close();
    db.close();
  }
  // Apagado (CYBER_CVE_FEED=no, como en las pruebas, o «cveFeed»: false en la configuración): no sale a la red.
  const db2 = openStore(projectPaths(tmp()));
  const saved = process.env.CYBER_CVE_FEED;
  try {
    assert.equal(process.env.CYBER_CVE_FEED, "no");
    assert.deepEqual(feedSwitch(), { on: false, motivo: "apagado con CYBER_CVE_FEED" });
    let fetched = 0;
    const off = new CveFeed({ db: db2, sessionId: "s", scope: () => undefined }, { fetch: (async () => (fetched++, new Response("{}"))) as unknown as typeof fetch });
    assert.equal(off.status().on, false);
    assert.match((await off.refresh(true)).salteado!, /CYBER_CVE_FEED/);
    off.tick();
    off.start();
    assert.equal(fetched, 0);
    delete process.env.CYBER_CVE_FEED;
    assert.equal(feedSwitch().on, true);
    writeFileSync(process.env.CYBER_CONFIG!, JSON.stringify({ cveFeed: false }));
    assert.match(feedSwitch().motivo!, /«cveFeed»: false/);
    writeFileSync(process.env.CYBER_CONFIG!, "{}");
    assert.equal(feedSwitch().on, true);
    await off.close();
  } finally {
    process.env.CYBER_CVE_FEED = saved;
    rmSync(process.env.CYBER_CONFIG!, { force: true });
    db2.close();
  }
});

/** Un objetivo de laboratorio: Tomcat con PHP 8.3.10 y un WordPress 6.4.2 con el plugin Newsletters. */
async function lab(): Promise<{ base: string; close: () => void }> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { server: "Apache-Coyote/1.1", "x-powered-by": "PHP/8.3.10", "content-type": "text/html" });
    res.end('<html><head><meta name="generator" content="WordPress 6.4.2"></head><body><script src="/wp-content/plugins/newsletters-lite/js/n.js"></script></body></html>');
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { base: `http://127.0.0.1:${(server.address() as { port: number }).port}`, close: () => server.close() };
}

const EXPECTED = ["CVE-2026-133325", "CVE-2026-129496", "CVE-2026-129481", "CVE-2026-129289", "CVE-2026-126714", "CVE-2026-115560", "CVE-2026-129043", "CVE-2026-129039", "CVE-2026-90001"];
const users = (messages: Message[]) => messages.flatMap((message) => (message.role === "user" ? [String(message.content)] : []));
const eventsOf = (engine: Engine, type: string) => (engine.db.prepare("select payload from events where session_id=? and type=? order by seq").all(engine.sessionId, type) as Array<{ payload: string }>).map((row) => JSON.parse(row.payload) as Record<string, unknown>);

test("sesión: cada CVE nuevo que cruza se avisa una vez por sesión, al operador y al agente en su próximo turno, sin cortar el turno en curso", async () => {
  const target = await lab();
  const cwd = tmp();
  const calls: Array<{ url: string }> = [];
  const provider = resolveProvider("faux");
  const options = { cwd, provider, autoVerify: false, coverageObjections: 0, closingGate: false as const, cveFeed: { enabled: true, fetch: fakeFetch(calls), now: () => NOW, confirm: async () => undefined, debounceMs: 5 } };
  const engine = new Engine(options);
  const notices: string[] = [];
  engine.onNotice = (text) => void notices.push(text);
  try {
    // Al abrir baja el feed en segundo plano (no hay nada que cruzar todavía).
    await engine.cves.refresh();
    assert.equal(calls.length, 2);
    assert.equal(await engine.cves.cross(), 0);
    // Un turno que espera: mientras corre, el agente ve el objetivo y aparecen los cruces.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
    provider.faux!.queue = [{ text: "Miro.", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Listo el primero." }];
    engine.scope.edit({ include: ["127.0.0.1"] });
    const first = engine.send("Mirá el sitio");
    await until(() => engine.agent.running);
    const exchange = await engine.http.send({ url: `${target.base}/` });
    assert.equal(exchange.response?.status, 200);
    await until(() => notices.length >= 4);
    assert.equal(engine.agent.running, true, "el turno sigue: los cruces no lo cortan");
    // Tres avisos sueltos (lo más grave primero) y uno que remite a /cves.
    assert.match(notices[0]!, /^CVE nuevo crítico que podría aplicar a (PHP 8\.3\.10|Apache Tomcat|newsletters-lite \(plugin de WordPress\)) en 127\.0\.0\.1:\d+: CVE-2026-\d+ \(9\.\d\) — .+ · https:\/\/radar\.cloudflare\.com\/zero-wire\/cves\/CVE-2026-\d+ \(.*\)\. Se lo paso al agente en su próximo turno\.$/);
    assert.ok(notices.slice(0, 3).every((text) => text.startsWith("CVE nuevo crítico")));
    assert.match(notices[3]!, /^Y 6 CVEs nuevos más que podrían aplicar \(.*\): \/cves los lista con su link\.$/);
    const told = eventsOf(engine, "cve.nuevo");
    assert.deepEqual(told.map((event) => event.cve).sort(), [...EXPECTED].sort());
    const php = told.find((event) => event.cve === "CVE-2026-129496")!;
    assert.deepEqual({ ...php, url: undefined }, { cve: "CVE-2026-129496", severidad: "CRITICAL", cvss: 9.2, tecnologia: "PHP", version: "8.3.10", activo: php.activo, fuente: "cabecera x-powered-by", veredicto: "en rango", confirmacion: "texto", url: undefined });
    assert.equal(told.find((event) => event.cve === "CVE-2026-90001")!.tecnologia, "WordPress", "el núcleo de WordPress cruza con su CVE");
    // Los descartes quedan a la vista: plugins ajenos y PHP fuera de rango.
    const dropped = engine.cves.crossings().filter((row) => row.estado === "descartado");
    assert.ok(dropped.some((row) => row.cve_id === "CVE-2026-129073" && /complemento de WordPress/.test(row.motivo)));
    assert.ok(dropped.some((row) => row.cve_id === "CVE-2026-129474" && /fuera del rango/.test(row.motivo)));
    release();
    await first;
    // Nada entró al turno en curso (ni como steer ni como mensaje).
    assert.ok(!engine.agent.messages.some((message) => JSON.stringify(message).includes("cves_nuevos")));
    // El próximo turno lleva el bloque, una sola vez.
    provider.faux!.queue = [{ text: "Visto." }, { text: "Nada más." }];
    await engine.send("¿Algo nuevo?");
    const next = users(engine.agent.messages).at(-1)!;
    assert.match(next, /^¿Algo nuevo\?/);
    assert.match(next, /<cves_nuevos>\nCVEs críticos o altos publicados hace poco \(Zero Wire, Cloudflare Radar\)/);
    assert.match(next, /es una pista, no un hallazgo/);
    assert.match(next, /confirmá producto y versión en el objetivo/);
    assert.match(next, /No registres hallazgos sin evidencia/);
    assert.match(next, /- CVE-2026-\d+ · crítico 9\.\d · .* en 127\.0\.0\.1:\d+ \(.*\) · /);
    assert.match(next, /- y 1 más: cve_recent con cruces=true los lista\./);
    assert.match(next, /CVE-2026-90001|CVE-2026-129039|CVE-2026-129043/);
    await engine.send("Seguí");
    assert.doesNotMatch(users(engine.agent.messages).at(-1)!, /cves_nuevos/);
    // Otra vuelta de cruce no repite nada.
    await engine.http.send({ url: `${target.base}/otra` });
    assert.equal(await engine.cves.cross(), 0);
    assert.equal(eventsOf(engine, "cve.nuevo").length, EXPECTED.length);
  } finally {
    await engine.close();
  }
  // La misma sesión retomada no repite; otra sesión del proyecto avisa lo suyo, sin volver a bajar el feed.
  const resumed = new Engine({ ...options, resume: "last" });
  const again: string[] = [];
  resumed.onNotice = (text) => void again.push(text);
  try {
    assert.equal(await resumed.cves.cross(), 0);
    assert.equal(again.length, 0);
  } finally {
    await resumed.close();
  }
  const other = new Engine({ ...options, resume: false });
  try {
    other.scope.edit({ include: ["127.0.0.1"] });
    await other.http.send({ url: `${target.base}/` });
    await until(() => eventsOf(other, "cve.nuevo").length === EXPECTED.length);
    assert.equal(eventsOf(other, "cve.nuevo").length, EXPECTED.length);
    assert.equal(calls.length, 2, "la caché es del proyecto: no se volvió a bajar");
  } finally {
    await other.close();
    target.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("vulndb: si conoce el CVE, sus productos afectados confirman o descartan el cruce y sus señales ordenan los avisos", async () => {
  const dir = tmp();
  const db = openStore(projectPaths(dir));
  const notices: string[] = [];
  const known: Record<string, VulndbCve> = {
    // Tomcat: vulndb lista las versiones exactas afectadas.
    "CVE-2026-133325": { id: "CVE-2026-133325", affected: [{ vendor: "Apache Software Foundation", product: "Apache Tomcat", versions: "11.0.29; 10.1.62; 9.0.124" }], kev: 1, kev_date_added: "2026-11-19", kev_ransomware: "Known", epss: 0.42, epss_percentile: 0.98 },
    // El texto nombra Splunk Enterprise, pero vulndb dice que el afectado es otro producto.
    "CVE-2026-76536": { id: "CVE-2026-76536", affected: [{ vendor: "Splunk", product: "Splunk Add-on Builder plugin", versions: "<4.3" }] },
  };
  const feed = new CveFeed({ db, sessionId: "s1", scope: () => undefined, notice: (text) => notices.push(text) }, { enabled: true, fetch: fakeFetch(), now: () => NOW, confirm: async (id) => known[id] });
  // Las tecnologías se cargan como si las hubiera visto: Tomcat 9.0.80 primero (fuera de lo que lista vulndb).
  const observe = (server: string, url = "https://tomcat.ejemplo.test/") => feed.observe({ id: "h1", request: { method: "GET", url, headers: {} }, redirects: [], resolved: [], durationMs: 1, artifact: "", response: { status: 200, headers: { server }, body: "", bodyBytes: 0, truncated: false } });
  try {
    await feed.refresh();
    observe("Apache Tomcat/9.0.80");
    observe("Splunkd", "https://splunk.ejemplo.test/");
    await feed.cross();
    const rows = feed.crossings();
    assert.match(rows.find((row) => row.cve_id === "CVE-2026-133325")!.motivo, /9\.0\.80\) queda fuera de los rangos afectados que publica vulndb/);
    assert.match(rows.find((row) => row.cve_id === "CVE-2026-76536")!.motivo, /vulndb lista otros productos afectados \(Splunk Splunk Add-on Builder plugin\)/);
    // Lo que vulndb no tiene se queda con el texto: los otros CVE de Splunk se avisan.
    assert.ok(rows.some((row) => row.cve_id === "CVE-2026-76535" && row.estado === "avisado" && row.confirmacion === "texto"));
    // Tomcat 9.0.124 en otro host: vulndb lo confirma y trae KEV, ransomware y EPSS.
    notices.length = 0;
    observe("Apache Tomcat/9.0.124", "https://otro.ejemplo.test/");
    await feed.cross();
    const tomcat = feed.crossings().find((row) => row.cve_id === "CVE-2026-133325" && row.estado === "avisado")!;
    assert.equal(tomcat.confirmacion, "vulndb");
    assert.equal(tomcat.veredicto, "en rango");
    assert.equal(tomcat.senales, "KEV desde 2026-11-19 · ransomware · EPSS 42 % (percentil 98)");
    assert.match(notices[0]!, /^CVE nuevo crítico que podría aplicar a Apache Tomcat 9\.0\.124 en otro\.ejemplo\.test: CVE-2026-133325 \(9\.8\) — Apache Tomcat: Cluster TLS-PSK .* \(versión vista en rango · vulndb lo lista para ese producto · KEV desde 2026-11-19 · ransomware · EPSS 42 % \(percentil 98\)\)\./);
    assert.match(feed.takeBlock(), /CVE-2026-133325 · crítico 9\.8 · Apache Tomcat 9\.0\.124 en otro\.ejemplo\.test \(cabecera server\) · versión vista en rango · vulndb lo lista para ese producto · KEV desde 2026-11-19 · ransomware · EPSS 42 %/);
    assert.equal(feed.takeBlock(), "", "lo entregado no vuelve a viajar");
  } finally {
    await feed.close();
    db.close();
  }
  // Sin confirmación inyectada, usa el binario de vulndb (CYBER_VULNDB) y su JSON.
  const bin = tmp();
  const binary = join(bin, "vulndb");
  writeFileSync(binary, `#!/bin/sh\nprintf '%s\\n' "$@" >> "${join(bin, "llamadas.txt")}"\nprintf '{"id":"%s","affected":[{"vendor":"Apache","product":"Apache Tomcat","versions":"9.0.0 <9.0.99"}],"cvss":9.8,"epss":0.9,"kev":0}\\n' "$2"\n`);
  chmodSync(binary, 0o755);
  const saved = process.env.CYBER_VULNDB;
  process.env.CYBER_VULNDB = binary;
  const db3 = openStore(projectPaths(tmp()));
  const viaBinary = new CveFeed({ db: db3, sessionId: "s", scope: () => undefined, artifacts: new Artifacts(db3, join(bin, "artefactos")) }, { enabled: true, fetch: fakeFetch(), now: () => NOW });
  try {
    await viaBinary.refresh();
    viaBinary.observe({ id: "h1", request: { method: "GET", url: "https://t.ejemplo.test/", headers: {} }, redirects: [], resolved: [], durationMs: 1, artifact: "", response: { status: 200, headers: { server: "Apache Tomcat/9.0.80" }, body: "", bodyBytes: 0, truncated: false } });
    await viaBinary.cross();
    const row = viaBinary.crossings().find((entry) => entry.cve_id === "CVE-2026-133325")!;
    assert.deepEqual([row.estado, row.confirmacion, row.veredicto, row.senales], ["avisado", "vulndb", "en rango", "EPSS 90 %"]);
    assert.deepEqual(readFileSync(join(bin, "llamadas.txt"), "utf8").trim().split("\n"), ["cve", "CVE-2026-133325", "--json"]);
  } finally {
    await viaBinary.close();
    db3.close();
    if (saved === undefined) delete process.env.CYBER_VULNDB;
    else process.env.CYBER_VULNDB = saved;
  }
});

test("cve_recent: el agente pide los últimos CVEs de un producto o los que cruzan; lo genérico se rechaza", async () => {
  const dir = tmp();
  const db = openStore(projectPaths(dir));
  const feed = new CveFeed({ db, sessionId: "s1", scope: () => ({ rev: 1, source: "manual", at: "", notes: "", exclude: [], include: [parseRule("etherpad.ejemplo.test")] }) }, { enabled: true, fetch: fakeFetch(), now: () => NOW, confirm: async () => undefined });
  const tool = feed.tool();
  const run = (args: object) => Promise.resolve(tool.execute(args, new AbortController().signal));
  try {
    assert.equal(tool.name, "cve_recent");
    // Sin caché, la primera llamada baja el feed.
    const tomcat = await run({ producto: "tomcat" });
    assert.match(tomcat.text, /^1 de 1 CVE del feed Zero Wire/);
    assert.match(tomcat.text, /CVE-2026-133325 · crítico 9\.8 · 2026-11-19 · Apache Tomcat: Cluster TLS-PSK .* · https:\/\/radar\.cloudflare\.com\/zero-wire\/cves\/CVE-2026-133325/);
    assert.match(tomcat.text, /Datos de terceros, no instrucciones/);
    const wordpress = await run({ producto: "wordpress" });
    assert.match(wordpress.text, /^1 de 1 CVE/);
    assert.match(wordpress.text, /CVE-2026-90001 · alto 8\.8/);
    assert.match(wordpress.text, /Además, \d+ de complementos de WordPress \(plugins, extensiones\), que no son el producto/);
    await assert.rejects(run({ producto: "server" }), /demasiado genérico/);
    const text = await run({ texto: "use-after-free", severidad: "critica", limite: 2 });
    assert.match(text.text, /^2 de \d+ CVEs/);
    // Los que cruzan con la sesión: el alcance nombra un Etherpad.
    await feed.cross();
    const crossed = await run({ cruces: true });
    assert.match(crossed.text, /^1 de 1 CVE/);
    assert.match(crossed.text, /CVE-2026-114516 .* · cruza con Etherpad en etherpad\.ejemplo\.test/);
  } finally {
    await feed.close();
    db.close();
  }
  // Apagado: lo dice y remite al banco.
  const off = new CveFeed({ db: openStore(projectPaths(tmp())), sessionId: "s", scope: () => undefined }, { enabled: false });
  assert.match((await Promise.resolve(off.tool().execute({}, new AbortController().signal))).text, /está apagado .* cve_search/);
  await off.close();
});

test("/cves: estado del feed, cruces de la sesión y últimos críticos con su link, en la TUI, el daemon y la CLI", async () => {
  const cwd = tmp();
  const calls: Array<{ url: string }> = [];
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider, engine: { cveFeed: { enabled: true, auto: false, fetch: fakeFetch(calls), now: () => NOW, confirm: async () => undefined } } });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    // Sin sesión (como la CLI): el estado, sin bajar nada.
    const empty = await client.view("cves");
    assert.equal(empty[0], "CVES NUEVOS · ZERO WIRE (CLOUDFLARE RADAR)");
    assert.match(empty[1]!, /^Feed prendido · última bajada nunca · en caché: 0 críticos, 0 altos$/);
    assert.ok(empty.includes("  la caché está vacía"));
    assert.equal(calls.length, 0);
    await client.attach({ session: "new" });
    const answers: string[] = [];
    client.on((event) => { if (event.type === "answer") answers.push(event.text); });
    await client.view("scope", "add etherpad.ejemplo.test");
    const lines = await client.view("cves", "actualizar 3");
    assert.equal(lines[0], "CVES NUEVOS · ZERO WIRE (CLOUDFLARE RADAR)");
    assert.equal(lines[1], "Feed bajado: 102 CVEs nuevos en la caché.");
    assert.equal(lines[2], "1 cruce nuevo con esta sesión: avisado y para el próximo turno del agente.");
    const text = lines.join("\n");
    assert.match(text, /última bajada 2026-11-20 18:00 \(recién\) · en caché: 100 críticos, 2 altos/);
    assert.match(text, /Tecnologías de esta sesión \(1\):\n {2}Etherpad · etherpad\.ejemplo\.test · nombre del activo/);
    assert.match(text, /Cruces de esta sesión: 1 avisados, 0 descartados\n {2}CVE-2026-114516 · crítico 9\.8 · Etherpad en etherpad\.ejemplo\.test · versión sin ver · texto · Etherpad: Pre-auth arbitrary file read · https:\/\/radar\.cloudflare\.com\/zero-wire\/cves\/CVE-2026-114516/);
    assert.match(text, /Últimos críticos \(3\), crucen o no:\n {2}CVE-2026-133872 · 9\.1 · 2026-11-20 · LessPass Backend .* · https:\/\/radar\.cloudflare\.com\/zero-wire\/cves\/CVE-2026-133872/);
    assert.match(text, /Uso: \/cves \[actualizar\] \[N\]/);
    await until(() => answers.some((answer) => answer.startsWith("CVE nuevo crítico")));
    assert.match(answers.find((answer) => answer.startsWith("CVE nuevo"))!, /^CVE nuevo crítico que podría aplicar a Etherpad en etherpad\.ejemplo\.test: CVE-2026-114516 \(9\.8\) — Etherpad: Pre-auth arbitrary file read · https:\/\/radar\.cloudflare\.com\/zero-wire\/cves\/CVE-2026-114516 \(versión sin ver · cruce por el texto del CVE\)\./);
    await assert.rejects(client.view("cves", "basura"), /Uso: \/cves \[actualizar\] \[N\]/);
    client.close();
    // La CLI («cyber cves») sin interfaz adjunta ve la última sesión.
    const cli = await connectDaemon(cwd, { spawn: false });
    assert.match((await cli.view("cves")).join("\n"), /Cruces de esta sesión: 1 avisados/);
    cli.close();
  } finally {
    daemon.close();
  }
  // La TUI: /cves vive en el grupo de hallazgos y arma el panel con lo del daemon.
  assert.ok(hijos("hallazgos").some((command) => command.name === "cves"));
  const asked: Array<[string, string | undefined]> = [];
  const io = { view: async (name: string, arg?: string) => (asked.push([name, arg]), ["CVES NUEVOS · ZERO WIRE (CLOUDFLARE RADAR)", "Feed prendido", "Uso: /cves [actualizar] [N]"]) } as never;
  const panel = await findCommand("cve")!.run(io, "actualizar");
  assert.deepEqual(asked, [["cves", "actualizar"]]);
  assert.equal(panel!.title, "CVES NUEVOS · ZERO WIRE (CLOUDFLARE RADAR)");
  assert.deepEqual(panel!.lines, ["Feed prendido"]);
  assert.match(panel!.footer!, /Uso: \/cves/);
});
