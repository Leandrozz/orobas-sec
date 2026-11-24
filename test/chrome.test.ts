import "./datos-tmp.ts";
// Navegador del operador: puente local con la extensión, alcance comprobado de este lado,
// pedido del operador, y la sesión cargada como identidad sin que el modelo vea las cookies.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import { test } from "node:test";
import { createHash, createHmac } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { CHROME_PORT, CHROME_PORTS, ChromeBridge, createChromeTools, extensionGuide } from "../src/chrome.ts";
import { Engine } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";

const TOKEN = "a".repeat(48);
const ORIGIN = "chrome-extension://abcdefghijklmnop";
const mac = (text: string, token = TOKEN) => createHmac("sha256", token).update(text).digest("hex");
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const NONCE_HEADERS = { origin: ORIGIN, "x-orobas": "1" };
/** Pide un desafío y devuelve las cabeceras firmadas, como la extensión (sin mandar el código): el MAC cubre puerto, método, ruta, desafío y cuerpo. */
async function signed(base: string, path: string, options: { token?: string; nonce?: string; origin?: string; method?: string; body?: string; port?: number; ext?: string } = {}) {
  const nonce = options.nonce ?? ((await (await fetch(`${base}/nonce`, { headers: NONCE_HEADERS })).json()) as { nonce: string }).nonce;
  const port = options.port ?? Number(new URL(base).port);
  return { origin: options.origin ?? ORIGIN, "x-orobas": "1", "x-orobas-nonce": nonce, "x-orobas-mac": mac(["ext", port, options.method ?? "GET", path, nonce, sha(options.body ?? "")].join("\n"), options.token), "x-orobas-ext": options.ext ?? "e".repeat(32) };
}
const proof = (port: number, status: number, ext: string, body: string) => mac(["srv", port, status, ext, sha(body)].join("\n"));
// El «/.dockerenv» de los tests: un archivo cualquiera que exista.
const DOCKERENV = join(tmpdir(), `dockerenv-${process.pid}`);
writeFileSync(DOCKERENV, "");

/** Hace de extensión: pregunta, ejecuta sobre pestañas simuladas y responde. */
function fakeExtension(port: number, state: { tabs: Array<{ id: number; url: string; title: string }>; calls: string[] }) {
  let stop = false;
  const base = `http://127.0.0.1:${port}`;
  const view = (tab: { id: number; url: string; title: string }) => ({ tab: tab.id, url: tab.url, title: tab.title, text: "Hola Ana. Proyectos: Atlas", forms: [], links: [`${new URL(tab.url).origin}/proyectos`, "https://tracker.example/pixel"], buttons: ["Guardar"] });
  const loop = (async () => {
    while (!stop) {
      const response = await fetch(`${base}/poll`, { headers: await signed(base, "/poll") }).catch(() => undefined);
      if (!response || response.status !== 200) continue;
      const command = (await response.json()) as { id: string; cmd: string; args: any; rules: any };
      state.calls.push(command.cmd);
      const tab = state.tabs.find((item) => item.id === command.args.tab);
      let data: unknown;
      if (command.cmd === "tabs") data = state.tabs.map((item) => ({ ...item, active: false }));
      else if (command.cmd === "read") data = view(tab!);
      else if (command.cmd === "cookies") data = { origin: new URL(tab!.url).origin, cookie: "session=valor-secreto-de-la-sesion; csrf=abc", count: 2 };
      else if (command.cmd === "traffic") data = [{ method: "POST", url: `${new URL(tab!.url).origin}/api/proyectos`, status: 201, type: "xmlhttprequest", bodyKeys: ["nombre", "equipo"] }, { method: "GET", url: "https://tracker.example/pixel", status: 200, type: "xmlhttprequest", bodyKeys: [] }];
      else if (command.cmd === "act") data = { log: ["click: «Guardar»"], ...view(tab!) };
      const body = JSON.stringify({ id: command.id, ok: true, data });
      await fetch(`${base}/result`, { method: "POST", headers: { ...(await signed(base, "/result", { method: "POST", body })), "content-type": "application/json" }, body });
    }
  })();
  return { stop: async () => { stop = true; await Promise.race([loop, new Promise((r) => setTimeout(r, 300))]); } };
}

test("el puente sólo le habla a la extensión emparejada", async () => {
  const bridge = new ChromeBridge({ token: TOKEN, port: 0 });
  await bridge.start();
  try {
    const base = `http://127.0.0.1:${bridge.port}`;
    assert.equal((await fetch(`${base}/poll`, { headers: await signed(base, "/poll", { token: "otro" }) })).status, 401, "HMAC equivocado");
    assert.equal((await fetch(`${base}/poll`, { headers: await signed(base, "/poll", { origin: "https://sitio-cualquiera.example" }) })).status, 401, "una página web no puede hablarle");
    assert.equal((await fetch(`${base}/nonce`, { headers: { origin: "https://sitio-cualquiera.example", "x-orobas": "1" } })).status, 401);
    assert.equal((await fetch(`${base}/poll`, { headers: { "x-orobas-token": TOKEN, origin: ORIGIN, "x-orobas": "1" } })).status, 401, "mandar el código a secas ya no sirve");
    assert.equal(bridge.connected, false, "nada de lo anterior cuenta como extensión conectada");
    // Un desafío vale una sola vez, y el puente prueba que conoce el código sobre la respuesta exacta.
    const ok = await signed(base, "/result", { method: "POST", body: "{}" });
    const first = await fetch(`${base}/result`, { method: "POST", headers: ok, body: "{}" });
    assert.equal(first.status, 204);
    assert.equal(first.headers.get("x-orobas-proof"), proof(bridge.port, 204, ok["x-orobas-ext"], ""), "el puente prueba que conoce el código");
    assert.equal((await fetch(`${base}/result`, { method: "POST", headers: ok, body: "{}" })).status, 401, "un desafío usado no se repite");
    assert.equal((await fetch(`${base}/poll`, { headers: await signed(base, "/poll", { nonce: "f".repeat(32) }) })).status, 401, "un desafío que el puente no emitió");
  } finally {
    bridge.close();
  }
});

test("el MAC cubre puerto, ruta y cuerpo: un relevo o un cuerpo cambiado en tránsito no pasan", async () => {
  const bridge = new ChromeBridge({ token: TOKEN, port: 0 });
  await bridge.start();
  try {
    const base = `http://127.0.0.1:${bridge.port}`;
    const body = JSON.stringify({ id: "c1", ok: true, data: "bueno" });
    // Firmado para otro puerto (un impostor relevando lo que la extensión firmó para él).
    assert.equal((await fetch(`${base}/poll`, { headers: await signed(base, "/poll", { port: bridge.port + 1 }) })).status, 401, "puerto distinto");
    // Cuerpo cambiado en tránsito.
    assert.equal((await fetch(`${base}/result`, { method: "POST", headers: await signed(base, "/result", { method: "POST", body }), body: body.replace("bueno", "falso") })).status, 401, "cuerpo distinto");
    // Firmado para otra ruta.
    assert.equal((await fetch(`${base}/result`, { method: "POST", headers: await signed(base, "/poll", { method: "POST", body }), body })).status, 401, "ruta distinta");
    // Firmado para otro método.
    assert.equal((await fetch(`${base}/poll`, { headers: await signed(base, "/poll", { method: "POST" }) })).status, 401, "método distinto");
    // Lo correcto sí pasa, y la prueba del puente cubre el cuerpo que mandó (un cuerpo ajeno con esa cabecera no la satisface).
    const good = await signed(base, "/result", { method: "POST", body });
    const response = await fetch(`${base}/result`, { method: "POST", headers: good, body });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("x-orobas-proof"), proof(bridge.port, 204, good["x-orobas-ext"], ""));
    assert.notEqual(response.headers.get("x-orobas-proof"), proof(bridge.port + 1, 204, good["x-orobas-ext"], ""), "la prueba va atada al puerto");
    // /poll con una orden: la prueba cubre exactamente el cuerpo recibido.
    (bridge as any).lastSeen = Date.now();
    const poll = await signed(base, "/poll");
    const asked = bridge.request("tabs", {}, {});
    const answered = await fetch(`${base}/poll`, { headers: poll });
    const text = await answered.text();
    assert.equal(answered.status, 200);
    assert.equal(answered.headers.get("x-orobas-proof"), proof(bridge.port, 200, poll["x-orobas-ext"], text));
    assert.notEqual(answered.headers.get("x-orobas-proof"), proof(bridge.port, 200, poll["x-orobas-ext"], text.replace("tabs", "cookies")), "otro cuerpo, otra prueba");
    const { id } = JSON.parse(text) as { id: string };
    const done = JSON.stringify({ id, ok: true, data: [] });
    await fetch(`${base}/result`, { method: "POST", headers: await signed(base, "/result", { method: "POST", body: done }), body: done });
    await asked;
  } finally {
    bridge.close();
  }
});

test("/nonce exige el encabezado propio y sólo lo atiende a una extensión; una extensión vieja recibe el aviso", async () => {
  const bridge = new ChromeBridge({ token: TOKEN, port: 0 });
  await bridge.start();
  try {
    const base = `http://127.0.0.1:${bridge.port}`;
    const sin = await fetch(`${base}/nonce`, { headers: { origin: ORIGIN } });
    assert.equal(sin.status, 401, "sin el encabezado no hay desafío (una página no pasa el preflight)");
    assert.match(((await sin.json()) as { error: string }).error, /actualizala o recargala/);
    assert.equal((await fetch(`${base}/nonce`)).status, 401, "ni siquiera sin Origin");
    assert.equal((await fetch(`${base}/nonce`, { headers: { origin: "https://sitio-cualquiera.example", "x-orobas": "1" } })).status, 401);
    const bien = await fetch(`${base}/nonce`, { headers: NONCE_HEADERS });
    assert.equal(bien.status, 200);
    assert.match(((await bien.json()) as { nonce: string }).nonce, /^[a-f0-9]{32}$/);
    // Protocolo viejo: MAC sólo sobre el desafío, sin el encabezado.
    const nonce = ((await (await fetch(`${base}/nonce`, { headers: NONCE_HEADERS })).json()) as { nonce: string }).nonce;
    const viejo = await fetch(`${base}/poll`, { headers: { origin: ORIGIN, "x-orobas-nonce": nonce, "x-orobas-mac": mac(`ext:${nonce}`), "x-orobas-ext": "e".repeat(32) } });
    assert.equal(viejo.status, 401);
  } finally {
    bridge.close();
  }
});

test("CYBER_PUERTO_HOST es el puerto del MAC (contenedor), y sin él vale el propio", async () => {
  const before = process.env.CYBER_PUERTO_HOST;
  const bridge = new ChromeBridge({ token: TOKEN, port: 0 });
  await bridge.start();
  try {
    const base = `http://127.0.0.1:${bridge.port}`;
    process.env.CYBER_PUERTO_HOST = "47633";
    assert.equal((await fetch(`${base}/poll`, { headers: await signed(base, "/poll") })).status, 401, "firmado con el puerto interno, con el del host publicado no vale");
    const publicado = await fetch(`${base}/poll`, { headers: await signed(base, "/poll", { port: 47633 }), signal: AbortSignal.timeout(500) }).catch(() => undefined);
    assert.equal(publicado, undefined, "firmado con el puerto del host: pasa (queda esperando una orden)");
    delete process.env.CYBER_PUERTO_HOST;
    assert.equal((await fetch(`${base}/result`, { method: "POST", headers: await signed(base, "/result", { method: "POST", body: "{}" }), body: "{}" })).status, 204, "sin la variable, el puerto propio");
  } finally {
    bridge.close();
    if (before === undefined) delete process.env.CYBER_PUERTO_HOST; else process.env.CYBER_PUERTO_HOST = before;
  }
});

test("en contenedor sin CYBER_PUERTO_HOST se rechaza todo y se avisa del lanzador; con la variable funciona", async () => {
  const before = { host: process.env.CYBER_PROYECTO_HOST, port: process.env.CYBER_PUERTO_HOST };
  process.env.CYBER_PROYECTO_HOST = "/tmp/proyecto";
  delete process.env.CYBER_PUERTO_HOST;
  const bridge = new ChromeBridge({ token: TOKEN, port: 0, dockerenv: DOCKERENV });
  try {
    await bridge.start();
    const base = `http://127.0.0.1:${bridge.port}`;
    const nonce = await fetch(`${base}/nonce`, { headers: NONCE_HEADERS });
    assert.equal(nonce.status, 503, "sin la variable no se reparten desafíos");
    assert.match(((await nonce.json()) as { error: string }).error, /lanzador/);
    for (const port of [bridge.port, CHROME_PORT]) {
      // Aunque la extensión tuviera un desafío (emitido a mano) y firmara con el 47615 por defecto, no pasa.
      (bridge as any).nonces.set("a".repeat(32), Date.now() + 30_000);
      assert.equal((await fetch(`${base}/poll`, { headers: await signed(base, "/poll", { nonce: "a".repeat(32), port }) })).status, 401);
    }
    await assert.rejects(bridge.request("tabs", {}, {}), /lanzador/);
    process.env.CYBER_PUERTO_HOST = "47633";
    assert.equal((await fetch(`${base}/nonce`, { headers: NONCE_HEADERS })).status, 200, "con la variable, desafíos");
    assert.equal((await fetch(`${base}/result`, { method: "POST", headers: await signed(base, "/result", { method: "POST", body: "{}", port: 47633 }), body: "{}" })).status, 204);
  } finally {
    bridge.close();
    if (before.host === undefined) delete process.env.CYBER_PROYECTO_HOST; else process.env.CYBER_PROYECTO_HOST = before.host;
    if (before.port === undefined) delete process.env.CYBER_PUERTO_HOST; else process.env.CYBER_PUERTO_HOST = before.port;
  }
});

test("navegador del operador: pedido, alcance, sesión como identidad y tráfico como contrato", async () => {
  const bridge = new ChromeBridge({ token: TOKEN, port: 0 });
  await bridge.start();
  const state = { tabs: [{ id: 7, url: "https://app.tienda.test/panel", title: "Panel" }, { id: 9, url: "https://mail.example/inbox", title: "Correo personal" }], calls: [] as string[] };
  const extension = fakeExtension(bridge.port, state);
  const cwd = mkdtempSync(join(tmpdir(), "cyber-chrome-"));
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("1"), chrome: bridge, coverageObjections: 0 });
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  const results = () => engine.agent.messages.filter((m) => m.role === "tool").map((m) => m.content as string);
  try {
    engine.scope.edit({ include: ["*.tienda.test"] });
    // Sin que el operador lo pida, no se usa su navegador.
    provider.faux!.queue = [call("tools_load", { names: ["chrome_tabs", "chrome_read", "chrome_act", "chrome_session", "chrome_traffic", "chrome_open"] }), call("chrome_tabs", {}), { text: "pregunto" }];
    await engine.send("Probá el panel de la tienda");
    assert.match(results()[1]!, /no autorizó su navegador en este proyecto.*\/navegador si/);
    assert.deepEqual(state.calls, []);

    provider.faux!.queue = [
      call("chrome_tabs", {}),
      call("chrome_read", { tab: 7 }),
      call("chrome_session", { tab: 7 }),
      call("chrome_traffic", { tab: 7 }),
      call("chrome_act", { tab: 7, actions: [{ type: "navigate", url: "https://otro-sitio.example/" }] }),
      call("chrome_open", { url: "https://mail.example/" }),
      call("chrome_act", { tab: 7, actions: [{ type: "click", text: "Guardar" }] }),
      { text: "listo" },
    ];
    await engine.send("Ya estoy logueado, usá mi navegador");
    const out = results().slice(2);
    assert.match(out[0]!, /^7  https:\/\/app\.tienda\.test\/panel/);
    assert.doesNotMatch(out[0]!, /mail\.example|Correo personal/, "las pestañas fuera del alcance no se ven");
    assert.match(out[1]!, /Hola Ana/);
    assert.doesNotMatch(out[1]!, /tracker\.example/, "enlaces fuera del alcance afuera");
    assert.match(out[2]!, /identidad «tienda-navegador» \(2 cookies, sólo para https:\/\/app\.tienda\.test\)/);
    assert.ok(!JSON.stringify(engine.agent.messages).includes("valor-secreto-de-la-sesion"), "el modelo no ve la cookie");
    assert.equal(engine.http.authentication("tienda-navegador").cookie, true);
    assert.match(out[3]!, /POST\s+201\s+https:\/\/app\.tienda\.test\/api\/proyectos\s+campos: nombre, equipo/);
    assert.doesNotMatch(out[3]!, /tracker/);
    assert.match(out[4]!, /Fuera del alcance/);
    assert.match(out[5]!, /Fuera del alcance/);
    assert.match(out[6]!, /click: «Guardar»/);
    assert.ok(!(state.calls as string[]).includes("navigate") && !(state.calls as string[]).includes("open"), "lo que está fuera del alcance ni se le pide a la extensión");
  } finally {
    await extension.stop();
    engine.close();
    bridge.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("una pestaña que sale del alcance no se sigue, pero el resto del pedido sí; un login externo orienta a la sesión o a una cuenta propia", async (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-chrome-alcance-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), cveFeed: false });
  const bridge = new ChromeBridge({ token: TOKEN, seenFile: false });
  try {
    engine.scope.edit({ include: ["tienda.test"] });
    const context = { http: engine.http, artifacts: engine.artifacts, scope: () => engine.scope.current(), authorized: () => true, bridge };
    const act = createChromeTools(context).find((tool) => tool.name === "chrome_act")!;
    // background.js manda sólo el host, sin esquema ni contenido de la pestaña externa.
    let left = "sso.otra.test";
    const view = (tab: number, url: string) => ({ tab, url, title: "Panel", text: "panel de la tienda", forms: [], links: [], buttons: [] });
    const request = t.mock.method(bridge, "request", async (cmd: string, args: { tab?: number; url?: string }) =>
      cmd === "open" ? view(9, args.url!) : args.tab === 7 ? { tab: 7, left, log: ["click «Continuar»"] } : view(args.tab!, "https://tienda.test/panel"));
    const { signal } = new AbortController();
    const args = { tab: 7, actions: [{ type: "click", text: "Continuar" }, { type: "navigate", url: "https://tienda.test/panel" }, { type: "click", text: "Guardar" }] };
    const login = await act.execute(args, signal);
    // La salida no se lee ni se sigue, y se dice qué hacer para tener sesión.
    assert.match(login.text, /La pestaña 7 quedó en sso\.otra\.test, fuera del alcance: no se lee ni se sigue/);
    assert.match(login.text, /inicio de sesión externo/);
    assert.match(login.text, /chrome_session/);
    assert.match(login.text, /registro propio dentro del alcance, creá una cuenta de prueba tuya con mail_address y mail_wait/);
    assert.doesNotMatch(login.text, /no creás|no crees|credenciales/);
    // El resto del pedido siguió: navigate abrió una pestaña nueva del alcance y el último clic fue ahí.
    assert.match(login.text, /continuó en una pestaña nueva, la 9/);
    assert.match(login.text, /pestaña 9 · https:\/\/tienda\.test\/panel/);
    assert.deepEqual(request.mock.calls.map(({ arguments: call }) => [call[0], (call[1] as { tab?: number }).tab ?? null]), [["act", 7], ["open", null], ["act", 9]]);
    assert.equal(login.details?.pestaña, 9);
    // Una salida que no es un login: sin consejo de sesión, con cómo seguir en el navegador.
    request.mock.resetCalls();
    left = "documentacion.otra.test";
    const fuera = await act.execute({ tab: 7, actions: [{ type: "click", text: "Docs" }] }, signal);
    assert.match(fuera.text, /fuera del alcance/);
    assert.match(fuera.text, /chrome_open/);
    assert.doesNotMatch(fuera.text, /inicio de sesión/);
    assert.deepEqual(request.mock.calls.map(({ arguments: call }) => call[0]), ["act"]);
  } finally {
    await engine.close();
    bridge.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("sin extensión vista nunca, falla rápido y dice cómo instalarla", async () => {
  const bridge = new ChromeBridge({ token: TOKEN, port: 0, seenFile: false, firstMs: 200 });
  try {
    const started = Date.now();
    await assert.rejects(() => bridge.request("tabs", {}, {}), (error: Error & { code?: string }) => error.code === "sin-emparejar" && /orobas-sec extension/.test(error.message));
    assert.ok(Date.now() - started < 2000, "no espera los 35 s de una extensión dormida");
  } finally {
    bridge.close();
  }
});

test("dos puentes en el mismo host toman puertos distintos del rango", async () => {
  const a = new ChromeBridge({ token: TOKEN });
  const b = new ChromeBridge({ token: TOKEN });
  try {
    await a.start();
    await b.start();
    assert.ok(a.port >= CHROME_PORT && a.port < CHROME_PORT + CHROME_PORTS);
    assert.ok(b.port >= CHROME_PORT && b.port < CHROME_PORT + CHROME_PORTS);
    assert.notEqual(a.port, b.port);
  } finally {
    a.close();
    b.close();
  }
});

test("en contenedor escucha en 0.0.0.0", async () => {
  const before = process.env.CYBER_PROYECTO_HOST;
  process.env.CYBER_PROYECTO_HOST = "/tmp/proyecto";
  const bridge = new ChromeBridge({ token: TOKEN, port: 0, dockerenv: DOCKERENV });
  try {
    await bridge.start();
    assert.equal(((bridge as any).server.address() as { address: string }).address, "0.0.0.0");
  } finally {
    bridge.close();
    if (before === undefined) delete process.env.CYBER_PROYECTO_HOST; else process.env.CYBER_PROYECTO_HOST = before;
  }
});

test("con CYBER_PROYECTO_HOST pero sin /.dockerenv no abre 0.0.0.0", async () => {
  const before = process.env.CYBER_PROYECTO_HOST;
  process.env.CYBER_PROYECTO_HOST = "/tmp/proyecto";
  const bridge = new ChromeBridge({ token: TOKEN, port: 0, dockerenv: join(tmpdir(), "no-existe-dockerenv") });
  try {
    await bridge.start();
    assert.equal(((bridge as any).server.address() as { address: string }).address, "127.0.0.1");
  } finally {
    bridge.close();
    if (before === undefined) delete process.env.CYBER_PROYECTO_HOST; else process.env.CYBER_PROYECTO_HOST = before;
  }
});

test("una extensión ya vista se espera en cada pedido (dormida), y tras esperarla entera el siguiente no vuelve a esperar", async () => {
  const bridge = new ChromeBridge({ token: TOKEN, port: 0, seenFile: false, wakeMs: 400 });
  try {
    const started = Date.now();
    await assert.rejects(() => bridge.request("tabs", {}, {}, 30_000, Date.now() - 3_600_000), (error: Error & { code?: string }) => error.code === "dormido" && /abra Chromium|open Chromium/.test(error.message));
    assert.ok(Date.now() - started >= 350, "la esperó");
    const again = Date.now();
    await assert.rejects(() => bridge.request("tabs", {}, {}, 30_000, Date.now() - 3_600_000), (error: Error & { code?: string }) => error.code === "dormido");
    assert.ok(Date.now() - again < 300, "recién la esperó entera: no repite la espera");
  } finally {
    bridge.close();
  }
});

test("dos /poll simultáneos reciben dos órdenes, y sin código no hay nada", async () => {
  const bridge = new ChromeBridge({ token: TOKEN, port: 0 });
  await bridge.start();
  const base = `http://127.0.0.1:${bridge.port}`;
  try {
    assert.equal((await fetch(`${base}/poll`, { headers: { "x-orobas": "1" } })).status, 401, "el código sigue siendo obligatorio");
    (bridge as any).lastSeen = Date.now();
    const polls = [fetch(`${base}/poll`, { headers: await signed(base, "/poll") }), fetch(`${base}/poll`, { headers: await signed(base, "/poll") })];
    await new Promise((r) => setTimeout(r, 100));
    const asked = [bridge.request("tabs", {}, {}), bridge.request("read", { tab: 1 }, {})];
    const commands = await Promise.all((await Promise.all(polls)).map((response) => response.json() as Promise<{ id: string; cmd: string }>));
    assert.deepEqual(commands.map((command) => command.cmd).sort(), ["read", "tabs"]);
    for (const command of commands) { const body = JSON.stringify({ id: command.id, ok: true, data: command.cmd }); await fetch(`${base}/result`, { method: "POST", headers: await signed(base, "/result", { method: "POST", body }), body }); }
    assert.deepEqual((await Promise.all(asked)).sort(), ["read", "tabs"]);
  } finally {
    bridge.close();
  }
});

test("en contenedor sin puerto explícito escucha en 47615, sin escanear", async () => {
  const before = process.env.CYBER_PROYECTO_HOST;
  process.env.CYBER_PROYECTO_HOST = "/tmp/proyecto";
  const bridge = new ChromeBridge({ token: TOKEN, dockerenv: DOCKERENV });
  try {
    await bridge.start();
    assert.equal(bridge.port, CHROME_PORT);
  } finally {
    bridge.close();
    if (before === undefined) delete process.env.CYBER_PROYECTO_HOST; else process.env.CYBER_PROYECTO_HOST = before;
  }
});

test("con todos los puertos del rango ocupados, el error lo dice", async () => {
  const held: Server[] = [];
  const bridge = new ChromeBridge({ token: TOKEN });
  try {
    for (let port = CHROME_PORT; port < CHROME_PORT + CHROME_PORTS; port++) {
      const server = createServer();
      // Si otro proceso ya tiene el puerto, igual está ocupado.
      await new Promise<void>((resolve) => { server.once("error", () => resolve()); server.listen(port, "127.0.0.1", () => { held.push(server); resolve(); }); });
    }
    await assert.rejects(() => bridge.start(), new RegExp(`${CHROME_PORT} a ${CHROME_PORT + CHROME_PORTS - 1}.*en uso`));
  } finally {
    bridge.close();
    for (const server of held) server.close();
  }
});

test("extensionGuide en contenedor copia la extensión a la carpeta de credenciales y muestra la ruta del host", () => {
  const dir = mkdtempSync(join(tmpdir(), "ext-"));
  const cred = join(dir, "cred");
  const antes = { ...process.env };
  try {
    mkdirSync(join(cred, "extension"), { recursive: true });
    writeFileSync(join(cred, "extension", "viejo.js"), "x");
    writeFileSync(DOCKERENV, "");
    Object.assign(process.env, { CYBER_CREDENTIALS_DIR: cred, CYBER_PROYECTO_HOST: "C:\\p", CYBER_CREDENCIALES_HOST: "C:\\Users\\x\\AppData\\Roaming\\elevate-cyber" });
    const guia = extensionGuide(join(import.meta.dirname, "..", "extension"), DOCKERENV).join("\n");
    assert.ok(guia.includes(": C:\\Users\\x\\AppData\\Roaming\\elevate-cyber\\extension\n"), guia);
    assert.ok(existsSync(join(cred, "extension", "manifest.json")));
    assert.ok(!existsSync(join(cred, "extension", "viejo.js")));
    assert.ok(readFileSync(join(cred, "extension", "manifest.json"), "utf8").includes("manifest_version"));
    assert.equal(guia.split("C:\\Users\\x\\AppData\\Roaming\\elevate-cyber\\extension").length, 2, "una sola vez");
    // lanzador viejo: sin CYBER_CREDENCIALES_HOST no se muestra la ruta interna
    delete process.env.CYBER_CREDENCIALES_HOST;
    const vieja = extensionGuide(join(import.meta.dirname, "..", "extension"), DOCKERENV).join("\n");
    assert.match(vieja, /cyber --actualizar/);
    assert.ok(!vieja.includes(cred), vieja);
    // la copia falla (el destino es un archivo): la guía igual trae el código
    process.env.CYBER_CREDENCIALES_HOST = "C:\\h";
    rmSync(join(cred, "extension"), { recursive: true });
    writeFileSync(join(cred, "extension"), "no soy carpeta");
    const rota = extensionGuide(join(import.meta.dirname, "..", "extension"), DOCKERENV).join("\n");
    assert.match(rota, /no pude copiar|could not copy/);
    assert.match(rota, /[a-f0-9]{32,}/);
  } finally {
    for (const k of ["CYBER_CREDENTIALS_DIR", "CYBER_PROYECTO_HOST", "CYBER_CREDENCIALES_HOST"]) { if (antes[k] === undefined) delete process.env[k]; else process.env[k] = antes[k]; }
    rmSync(dir, { recursive: true, force: true });
  }
});
