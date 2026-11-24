import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { Artifacts } from "../src/artifacts.ts";
import { browserPaths, BrowserSession, browserStatus, createBrowserTools } from "../src/browser.ts";
import { nodePlaywright, playwrightLocation } from "../src/sesion-chromium.ts";
import { HttpClient } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { labServer } from "./lab-web.ts";

const { playwright, chromium } = browserPaths();
const skip = !existsSync(playwright) ? `Playwright no está disponible en ${playwright}; instalalo aparte o señalalo con CYBER_PLAYWRIGHT (carpeta del paquete o index.mjs) o con la clave «playwright» de config.json.`
  : !existsSync(chromium) ? `Chromium no está disponible en ${chromium}; configurá CYBER_CHROMIUM.` : false;

async function setup(options: ConstructorParameters<typeof BrowserSession>[1] = {}) {
  const server = labServer();
  const seen: Array<{ url: string; authorization?: string; cookie?: string }> = [];
  server.on("request", (req) => seen.push({ url: req.url!, authorization: req.headers.authorization, cookie: req.headers.cookie }));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-browser-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana", cookie: "session=browser-1" } });
  http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto", cookie: "session=browser-2" } });
  const browser = new BrowserSession(http, options);
  return {
    base, browser, http, scope, artifacts, seen,
    close: async () => {
      await browser.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
      rmSync(cwd, { recursive: true, force: true });
    },
  };
}

/** Un paquete «playwright» falso: si alguien lo importara, la prueba falla. */
function paqueteFalso(raiz: string): string {
  const paquete = join(raiz, "node_modules", "playwright");
  mkdirSync(paquete, { recursive: true });
  writeFileSync(join(paquete, "index.mjs"), 'throw new Error("El diagnóstico no debe importar este módulo")');
  return paquete;
}

/** Cambia variables de entorno durante una prueba y las restaura al terminar. */
function entorno(t: { after: (fn: () => void) => void }, valores: Record<string, string | undefined>): void {
  const antes = Object.fromEntries(Object.keys(valores).map((clave) => [clave, process.env[clave]]));
  for (const [clave, valor] of Object.entries(valores)) valor === undefined ? delete process.env[clave] : (process.env[clave] = valor);
  t.after(() => { for (const [clave, valor] of Object.entries(antes)) valor === undefined ? delete process.env[clave] : (process.env[clave] = valor); });
}

test("Playwright: CYBER_PLAYWRIGHT acepta el index.mjs, la carpeta del paquete o la del npm install, sin importarlo", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "modulo-prueba-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const paquete = paqueteFalso(dir);
  const archivo = join(paquete, "index.mjs");
  entorno(t, { CYBER_PLAYWRIGHT: archivo });
  assert.equal(playwrightLocation().path, archivo);
  assert.equal(browserStatus()[0], `playwright ✓ ${archivo} (CYBER_PLAYWRIGHT)`);
  process.env.CYBER_PLAYWRIGHT = paquete;
  assert.equal(playwrightLocation().path, archivo);
  assert.equal(browserPaths().playwright, archivo);
  assert.equal(playwrightLocation().problem, undefined);
  process.env.CYBER_PLAYWRIGHT = dir;
  assert.equal(playwrightLocation().path, archivo);
});

test("Playwright: una ruta señalada que no sirve se dice con su origen y cómo configurarlo, sin caer a otra", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "modulo-prueba-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  entorno(t, { CYBER_PLAYWRIGHT: join(dir, "no-existe") });
  const { problem } = playwrightLocation();
  assert.match(problem!, /no está disponible.*CYBER_PLAYWRIGHT apunta a/);
  assert.match(problem!, /CYBER_PLAYWRIGHT=\/ruta\/node_modules\/playwright/);
  assert.match(problem!, /"playwright": "\/ruta\/node_modules\/playwright" en ~\/\.config\/elevate-cyber\/config\.json/);
  assert.match(browserStatus()[0]!, /^playwright ✗ /);
  // Una carpeta vacía tampoco: no tiene index.mjs.
  process.env.CYBER_PLAYWRIGHT = dir;
  assert.match(playwrightLocation().problem!, /no está disponible en .*index\.mjs/);
});

test("Playwright: la clave «playwright» de config.json se usa sin variable, y la variable le gana", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "modulo-prueba-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const desdeConfig = paqueteFalso(join(dir, "config"));
  const desdeVariable = paqueteFalso(join(dir, "variable"));
  const config = join(dir, "config.json");
  writeFileSync(config, JSON.stringify({ defaultModel: "orobas/auto", playwright: desdeConfig }));
  entorno(t, { CYBER_PLAYWRIGHT: undefined, CYBER_CONFIG: config, CYBER_CONFIG_BASE: undefined });
  const configurado = playwrightLocation();
  assert.equal(configurado.path, join(desdeConfig, "index.mjs"));
  assert.match(configurado.source, /clave «playwright» de .*config\.json/);
  assert.equal(configurado.problem, undefined);
  process.env.CYBER_PLAYWRIGHT = desdeVariable;
  assert.equal(playwrightLocation().path, join(desdeVariable, "index.mjs"));
});

test("Playwright: la resolución de Node lo encuentra en un node_modules de más arriba", () => {
  const dir = mkdtempSync(join(tmpdir(), "modulo-prueba-"));
  try {
    const paquete = paqueteFalso(dir);
    mkdirSync(join(dir, "a", "b"), { recursive: true });
    assert.equal(nodePlaywright(pathToFileURL(join(dir, "a", "b", "modulo.mjs")).href), join(paquete, "index.mjs"));
    assert.equal(nodePlaywright(pathToFileURL(join(tmpdir(), `sin-playwright-${process.pid}`, "modulo.mjs")).href) === join(paquete, "index.mjs"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("navegador: si falta Playwright explica cómo instalarlo aparte", async () => {
  const { browser, base, close } = await setup();
  const previous = process.env.CYBER_PLAYWRIGHT;
  process.env.CYBER_PLAYWRIGHT = join(tmpdir(), `cyber-playwright-ausente-${process.pid}`, "index.mjs");
  try {
    await assert.rejects(browser.open(`${base}/browser`), /Playwright no está disponible[\s\S]*Instalalo aparte[\s\S]*CYBER_PLAYWRIGHT/);
  } finally {
    if (previous === undefined) delete process.env.CYBER_PLAYWRIGHT;
    else process.env.CYBER_PLAYWRIGHT = previous;
    await close();
  }
});

test("navegador: ejecuta JavaScript, descubre formularios y deja las llamadas de API como evidencia", { skip }, async () => {
  const { browser, base, http, artifacts, seen, close } = await setup();
  try {
    const page = await browser.open(`${base}/browser/redirect?url=${encodeURIComponent("/browser?echo=1")}`, "ana");
    assert.equal(page.title, "Laboratorio JS");
    assert.equal(page.url, `${base}/browser?echo=1`);
    assert.match(page.text, /Usuario: 1; cookie: true/);
    assert.match(page.text, /Eco: .*<credencial>/);
    assert.match(JSON.stringify(page.forms), /term/);
    assert.match(JSON.stringify(page.links), /\/perfil/);
    assert.match(JSON.stringify(page.requests), /\/browser\/who/);
    assert.doesNotMatch(JSON.stringify(page), /t-ana|session=browser-1/);
    const xhr = http.log.find((entry) => entry.url === `${base}/browser/who?echo=1`);
    assert.equal(xhr?.status, 200);
    assert.ok(xhr?.hash);
    const exchange = JSON.parse(artifacts.read(xhr!.hash).toString());
    assert.equal(JSON.parse(exchange.response.body).user, 1);
    assert.doesNotMatch(artifacts.read(xhr!.hash).toString(), /t-ana|browser-1/);
    assert.ok(http.surface().some((row) => row.path === "/browser/who" && row.methods.includes("GET")));
    assert.equal(http.count, seen.length);
    assert.ok(seen.some((entry) => entry.authorization === "Bearer t-ana" && entry.cookie?.includes("session=browser-1")));
  } finally {
    await close();
  }
});

test("navegador: clic, escritura, envío y espera producen un nuevo resumen y una captura PNG", { skip }, async () => {
  const { browser, base, http, artifacts, close } = await setup();
  try {
    const page = await browser.open(`${base}/browser`, "ana");
    const result = await browser.act([
      { type: "click", text: "Recordar" },
      { type: "fill", selector: "[name=term]", value: "mate" },
      { type: "submit", selector: "#search" },
      { type: "wait", ms: 100 },
    ], page.id);
    assert.match(result.text, /Guardado: mate/);
    assert.match(result.text, /recordada: true/);
    const sent = http.log.find((entry) => entry.url === `${base}/browser/save`);
    assert.equal(sent?.method, "POST");
    assert.deepEqual(sent?.bodyKeys, ["term"]);
    const capture = await browser.capture(page.id);
    assert.equal(capture.mediaType, "image/png");
    assert.ok(capture.bytes > 100);
    assert.deepEqual(artifacts.read(capture.hash).subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  } finally {
    await close();
  }
});

test("navegador: conserva la sesión por identidad y no comparte cookies con otra identidad o con anónimo", { skip }, async () => {
  const { browser, base, http, close } = await setup();
  try {
    const ana = await browser.open(`${base}/browser`, "ana");
    await browser.act([{ type: "click", selector: "#remember" }, { type: "wait", ms: 100 }], ana.id);
    const beto = await browser.open(`${base}/browser`, "beto");
    assert.match(beto.text, /Usuario: 2; cookie: true; recordada: false/);
    const anonymous = await browser.open(`${base}/browser`);
    assert.match(anonymous.text, /Usuario: 0; cookie: false; recordada: false/);
    const returned = await browser.act([{ type: "click", selector: "#refresh" }, { type: "wait", ms: 100 }], ana.id);
    assert.match(returned.text, /Usuario: 1; cookie: true; recordada: true/);
    http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-beto", cookie: "session=browser-2" } });
    await assert.rejects(browser.act([{ type: "click", selector: "#refresh" }], ana.id), /identidad|browser_open/i);
    await assert.rejects(browser.capture(ana.id), /identidad|browser_open/i);
    const changed = await browser.open(`${base}/browser`, "ana");
    assert.match(changed.text, /Usuario: 2; cookie: true; recordada: false/);
  } finally {
    await close();
  }
});

test("navegador: bloquea subrecursos, redirecciones y rutas excluidas antes de que lleguen al servidor", { skip }, async () => {
  const outside = labServer();
  let outsideHits = 0;
  outside.on("request", () => outsideHits++);
  await new Promise<void>((resolve) => outside.listen(0, "127.0.0.1", resolve));
  const external = `http://127.0.0.1:${(outside.address() as { port: number }).port}`;
  const { browser, base, scope, seen, close } = await setup();
  scope.exclude.push(parseRule(`${base}/outside`));
  try {
    const page = await browser.open(`${base}/browser?external=${encodeURIComponent(external)}`, "ana");
    assert.equal(outsideHits, 0);
    assert.ok(!seen.some((entry) => entry.url === "/outside"));
    assert.match(JSON.stringify(page.blocked), /directo/);
    assert.match(JSON.stringify(page.blocked), /redirigido/);
    assert.match(JSON.stringify(page.blocked), /imagen/);
    assert.match(JSON.stringify(page.blocked), /outside/);
    await assert.rejects(browser.open(`${external}/browser`), /alcance/i);
    assert.equal(outsideHits, 0);
  } finally {
    await close();
    await new Promise<void>((resolve) => outside.close(() => resolve()));
  }
});

test("navegador: respeta los topes de páginas, tiempo y peticiones y cierra sin reabrirse", { skip }, async () => {
  const { browser, base, http, close } = await setup({ maxPages: 1, actionTimeoutMs: 1500 });
  try {
    const page = await browser.open(`${base}/browser`, "ana");
    // La otra cuenta abre su propia instancia, sin que la una tenga que esperar a la otra.
    const otra = await browser.open(`${base}/browser`, "beto");
    assert.match(otra.text, /Usuario: 2/);
    await assert.rejects(browser.act([{ type: "click", selector: "#inexistente" }], page.id), /tiempo|timeout/i);
    http.limit = http.count;
    const count = http.count;
    const limited = await browser.act([{ type: "click", selector: "#refresh" }, { type: "wait", ms: 50 }], page.id);
    assert.equal(http.count, count);
    assert.match(JSON.stringify(limited.blocked), /tope|peticiones/i);
    await browser.close();
    await assert.rejects(browser.open(`${base}/browser`), /cerrad/i);
  } finally {
    await close();
  }
});

test("navegador: no guarda capturas que superen el tope de bytes", { skip }, async () => {
  const { browser, base, close } = await setup({ maxCaptureBytes: 100, actionTimeoutMs: 5000 });
  try {
    const page = await browser.open(`${base}/browser`, "ana");
    await assert.rejects(browser.capture(page.id), /captura.*tope.*100/i);
  } finally {
    await close();
  }
});

test("navegador: una credencial corta no rompe el JSON, los ids ni las referencias de evidencia", { skip }, async () => {
  const { browser, base, http, artifacts, close } = await setup();
  try {
    http.setIdentity({ name: "corta", headers: { "x-test": "1" } });
    const page = await browser.open(`${base}/browser`);
    assert.equal(page.title, "Laboratorio JS");
    assert.match(page.text, /Usuario: 0/);
    assert.ok(page.requests.length > 0);
    for (const request of page.requests) {
      assert.ok(Number.isInteger(request.status) && request.status >= 100 && request.status <= 599);
      assert.ok(artifacts.read(request.artifact).length > 0);
    }
    const again = await browser.act([{ type: "wait", ms: 0 }], page.id);
    assert.equal(again.id, page.id);
  } finally {
    await close();
  }
});

test("navegador: cancelar una herramienta corta la espera y cierra la sesión", { skip }, async () => {
  const { browser, base, close } = await setup();
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const page = await browser.open(`${base}/browser`);
    const act = createBrowserTools(browser).find((tool) => tool.name === "browser_act")!;
    const pending = Promise.resolve(act.execute({ id: page.id, actions: [{ type: "wait", ms: 5000 }] }, controller.signal));
    const rejected = assert.rejects(pending, /cerrad|closed|abort/i);
    timer = setTimeout(() => controller.abort(), 50);
    await rejected;
    await assert.rejects(browser.open(`${base}/browser`), /cerrad/i);
  } finally {
    clearTimeout(timer);
    await close();
  }
});
