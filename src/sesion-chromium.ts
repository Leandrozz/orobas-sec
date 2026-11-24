// Chromium recibe respuestas del cliente propio: ningún destino elude alcance ni contabilidad.
import { existsSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer, type Server } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { Tool } from "./agent.ts";
import type { HttpClient } from "./http.ts";
import { configPath } from "./providers.ts";
import { decide } from "./scope.ts";

// Playwright y Chromium se instalan aparte del proyecto. Para Playwright, en orden: CYBER_PLAYWRIGHT, la
// clave «playwright» de config.json, las instalaciones conocidas y la resolución normal de Node. Lo que
// señala el operador (variable o clave) manda: si está mal, se dice, sin caer en silencio a otra.
const PLAYWRIGHT_CANDIDATES = [
  join(homedir(), ".local", "share", "cyber-browser", "node_modules", "playwright", "index.mjs"),
  "/opt/cyber-browser/node_modules/playwright/index.mjs",
];
const PLAYWRIGHT_HOW = "Instalalo aparte (PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --prefix ~/.local/share/cyber-browser playwright; no hace falta descargar navegadores) o señalá una instalación que ya tengas, con la carpeta del paquete (…/node_modules/playwright) o su index.mjs: CYBER_PLAYWRIGHT=/ruta/node_modules/playwright en el entorno, o \"playwright\": \"/ruta/node_modules/playwright\" en ~/.config/elevate-cyber/config.json.";

/** Una ruta señalada puede ser el index.mjs, la carpeta del paquete o la carpeta donde se hizo el npm install. */
function playwrightEntry(path: string): string {
  try {
    if (!statSync(path).isDirectory()) return path;
  } catch { return path; }
  for (const inside of [join(path, "index.mjs"), join(path, "node_modules", "playwright", "index.mjs")]) if (existsSync(inside)) return inside;
  return join(path, "index.mjs");
}

/** La clave «playwright» de la configuración del operador (y, debajo, la de la imagen). */
function configuredPlaywright(): { path: string; source: string } | undefined {
  for (const file of [configPath(), process.env.CYBER_CONFIG_BASE]) {
    if (!file || !existsSync(file)) continue;
    try {
      const value = (JSON.parse(readFileSync(file, "utf8").replace(/^\uFEFF/, "")) as { playwright?: unknown }).playwright;
      if (typeof value === "string" && value.trim()) return { path: value.trim(), source: `la clave «playwright» de ${file}` };
    } catch { /* un config.json inválido lo reporta quien lo usa para los modelos */ }
  }
  return undefined;
}

/**
 * `playwright` donde lo buscaría Node desde el propio harness: los node_modules de su carpeta y de las de
 * arriba, NODE_PATH y las carpetas globales. Sin importarlo: sólo se mira que esté su index.mjs.
 */
export function nodePlaywright(from: string = import.meta.url): string | undefined {
  try {
    for (const dir of createRequire(from).resolve.paths("playwright") ?? []) {
      const entry = join(dir, "playwright", "index.mjs");
      if (existsSync(entry)) return entry;
    }
  } catch { /* sin rutas de búsqueda: no hay candidata */ }
  return undefined;
}

/** Dónde está Playwright y quién lo dijo. `problem` explica por qué no sirve y cómo configurarlo. */
export function playwrightLocation(): { path: string; source: string; problem?: string } {
  const env = process.env.CYBER_PLAYWRIGHT?.trim();
  const chosen = env ? { path: env, source: "CYBER_PLAYWRIGHT" } : configuredPlaywright();
  if (chosen) {
    const path = playwrightEntry(chosen.path);
    return { path, source: chosen.source, problem: problemaPlaywright(path, `${chosen.source} apunta a ${chosen.path}`) };
  }
  const found = PLAYWRIGHT_CANDIDATES.find((path) => existsSync(path));
  if (found) return { path: found, source: "instalación conocida", problem: problemaPlaywright(found, found) };
  const resolved = nodePlaywright();
  if (resolved && existsSync(resolved)) return { path: resolved, source: "resolución de Node", problem: problemaPlaywright(resolved, resolved) };
  return { path: PLAYWRIGHT_CANDIDATES[0]!, source: "ninguna", problem: `Playwright no está disponible: no está en CYBER_PLAYWRIGHT ni en la configuración, ni en ${PLAYWRIGHT_CANDIDATES.join(" ni en ")}, y Node no lo resuelve desde el harness. ${PLAYWRIGHT_HOW}` };
}
const CHROMIUM_CANDIDATES = [
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/snap/bin/chromium",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
];

export function browserPaths(): { playwright: string; chromium: string } {
  const chromium = process.env.CYBER_CHROMIUM ?? CHROMIUM_CANDIDATES.find((path) => existsSync(path)) ?? CHROMIUM_CANDIDATES[0]!;
  return { playwright: playwrightLocation().path, chromium };
}

/** Comprueba el archivo sin importar ni ejecutar código de la instalación externa. */
function problemaPlaywright(ruta: string, origen: string): string | undefined {
  try {
    const estado = statSync(ruta, { throwIfNoEntry: false });
    if (!estado) return `Playwright no está disponible en ${ruta} (${origen}). ${PLAYWRIGHT_HOW}`;
    if (!estado.isFile()) return `La ruta de Playwright ${ruta} (${origen}) no es un archivo ni una carpeta con index.mjs. ${PLAYWRIGHT_HOW}`;
  } catch {
    return `No se pudo consultar ${ruta} (${origen}). Revisá la ruta y sus permisos.`;
  }
}

/** Estado del navegador para `cyber toolbox`. */
export function browserStatus(): string[] {
  const { chromium } = browserPaths();
  const playwright = playwrightLocation();
  return [
    `playwright ${playwright.problem ? `✗ ${playwright.problem}` : `✓ ${playwright.path}${playwright.source === "instalación conocida" ? "" : ` (${playwright.source})`}`}`,
    `chromium   ${existsSync(chromium) ? `✓ ${chromium}` : `✗ no instalado · instalá Chromium con el gestor de paquetes, o CYBER_CHROMIUM=<ejecutable>`}`,
  ];
}

export interface BrowserOptions {
  maxPages?: number;
  actionTimeoutMs?: number;
  maxCaptureBytes?: number;
  /** Instancia privada separada para esta sesión: no comparte cookies ni storage con las demás. */
  incognito?: boolean;
}
export type BrowserAction = { type: "click" | "fill" | "submit" | "wait"; selector?: string; text?: string; value?: string; ms?: number };
// El módulo es opcional y externo al proyecto; su API queda encerrada en este adaptador.
type External = any;
type Tab = { id: string; identity?: string; fingerprint: string; context: External; page: External; cdp?: External; origins: Set<string>; requests: object[]; blocked: string[]; pending: Set<Promise<void>> };

export class ChromiumWorkspaceSession {
  readonly http: HttpClient;
  readonly options: Required<BrowserOptions>;
  private browser?: External;
  private proxy?: Server;
  private tabs = new Map<string, Tab>();
  private current?: Tab;
  private pages = 0;
  private closed = false;
  private queue: Promise<unknown> = Promise.resolve();
  private closing?: Promise<void>;

  constructor(http: HttpClient, options: BrowserOptions = {}) {
    this.http = http;
    this.options = { maxPages: 12, actionTimeoutMs: 10_000, maxCaptureBytes: 2 * 1024 * 1024, incognito: false, ...options };
    for (const value of Object.values(this.options)) if (typeof value === "number" && (!Number.isInteger(value) || value <= 0)) throw new Error("Los topes del navegador deben ser enteros positivos");
  }

  private serial<T>(work: () => Promise<T>): Promise<T> {
    const task = this.queue.then(async () => {
      if (this.closed) throw new Error("El navegador está cerrado");
      try { return await work(); } catch (error) { throw new Error(this.http.redact((error as Error).message)); }
    });
    this.queue = task.catch(() => {});
    return task;
  }

  private async timed<T>(tab: Tab, work: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([work, new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          void tab.context.close().catch(() => {});
          this.tabs.delete(tab.identity ?? "");
          if (this.current === tab) this.current = undefined;
          reject(new Error("Tiempo de espera agotado; se cerró la página"));
        }, this.options.actionTimeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }

  private redactValues(value: any): any {
    if (typeof value === "string") return this.http.redact(value);
    if (Array.isArray(value)) return value.map((item) => this.redactValues(item));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.redactValues(item)]));
    return value;
  }

  private async launch(): Promise<void> {
    if (this.browser) return;
    const { chromium: executablePath } = browserPaths();
    const { path, problem } = playwrightLocation();
    if (problem) throw new Error(problem);
    const { chromium } = await import(pathToFileURL(path).href);
    if (!existsSync(executablePath)) throw new Error(`Chromium no está instalado (busqué ${executablePath}). Instalalo con el gestor de paquetes o configurá CYBER_CHROMIUM con la ruta al ejecutable.`);
    if (this.closed) throw new Error("El navegador está cerrado");
    // Reservamos el puerto: otro servicio local no puede convertirse en la salida del navegador.
    const proxy = createServer((socket) => { socket.on("error", () => {}); socket.destroy(); });
    this.proxy = proxy;
    proxy.on("error", () => {});
    try {
      await new Promise<void>((resolve, reject) => {
        proxy.once("error", reject);
        proxy.listen(0, "127.0.0.1", () => { proxy.off("error", reject); resolve(); });
      });
      if (this.closed) throw new Error("El navegador está cerrado");
      const address = proxy.address();
      if (!address || typeof address === "string") throw new Error("No se pudo reservar el bloqueo de red del navegador");
      this.browser = await chromium.launch({ executablePath, headless: true, args: [
        // Las rutas se satisfacen con HttpClient. El proxy rechaza toda salida directa.
        `--proxy-server=http://127.0.0.1:${address.port}`, "--proxy-bypass-list=<-loopback>", "--host-resolver-rules=MAP * ~NOTFOUND",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-background-networking",
        ...(this.options.incognito ? ["--incognito", "--no-first-run", "--no-default-browser-check"] : []),
        // Argumentos del operador (p. ej. --no-sandbox dentro de un contenedor); nunca del modelo.
        ...(process.env.CYBER_CHROMIUM_ARGS?.split(/\s+/).filter(Boolean) ?? []),
      ] });
    } catch (error) {
      await this.closeProxy();
      throw error;
    }
  }

  private async closeProxy(): Promise<void> {
    const proxy = this.proxy;
    this.proxy = undefined;
    if (proxy) await new Promise<void>((resolve) => proxy.close(() => resolve()));
  }

  private async tab(identity: string | undefined, url: URL): Promise<Tab> {
    const headers = this.http.identityHeaders(identity);
    const key = identity ?? "";
    const fingerprint = JSON.stringify(headers);
    let tab = this.tabs.get(key);
    if (tab && tab.fingerprint !== fingerprint) {
      await tab.context.close();
      await Promise.allSettled([...tab.pending]);
      this.tabs.delete(key);
      tab = undefined;
    }
    if (!tab) {
      if (this.pages >= this.options.maxPages) throw new Error(`Tope de páginas de la sesión alcanzado (${this.options.maxPages})`);
      await this.launch();
      const context = await this.browser.newContext({ serviceWorkers: "block", acceptDownloads: false, viewport: { width: 1280, height: 720 } });
      if (typeof context.routeWebSocket !== "function") { await context.close(); throw new Error("Actualizá Playwright aparte: se necesita routeWebSocket para bloquear canales sin alcance HTTP"); }
      tab = { id: `b${++this.pages}`, identity, fingerprint, context, page: undefined, origins: new Set(), requests: [], blocked: [], pending: new Set() };
      const owned = tab;
      const block = (message: string) => { if (owned.blocked.length < 100) owned.blocked.push(this.http.redact(message)); };
      await context.routeWebSocket("**/*", (socket: External) => { block(`WebSocket bloqueado: ${socket.url()}`); socket.close(); });
      await context.addInitScript(() => {
        // Una ventana nueva no tiene id de evidencia; los canales ajenos a HTTP quedan deshabilitados.
        window.open = () => null;
        for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "WebTransport"]) Object.defineProperty(globalThis, name, { value: undefined, configurable: false });
      });
      owned.page = await context.newPage();
      const cdp = await context.newCDPSession(owned.page);
      owned.cdp = cdp;
      // Fetch pausa también cada salto de redirección, que route() deja pasar después del primero.
      cdp.on("Fetch.requestPaused", (event: External) => {
        const work = (async () => {
          const request = event.request;
          const target = request.url;
          try {
            if (this.closed) throw new Error("El navegador está cerrado");
            if (owned.fingerprint !== JSON.stringify(this.http.identityHeaders(owned.identity))) throw new Error("La identidad cambió; volvé a abrir la página con browser_open");
            const requested = new URL(target);
            if (!/^https?:$/.test(requested.protocol)) throw new Error(`Protocolo bloqueado: ${requested.protocol}`);
            // Lo que la página carga de terceros (analítica, widgets) se descarta acá: nunca sale y
            // no deja un intercambio en el registro, que es para peticiones de verdad.
            if (!this.http.inScope(target)) {
              this.http.blocked++;
              throw new Error("fuera del alcance (no enviada)");
            }
            const headers: Record<string, string> = Object.fromEntries(Object.entries(request.headers).map(([name, value]) => [name.toLowerCase(), String(value)]));
            // Sólo los orígenes abiertos explícitamente reciben cabeceras de la identidad.
            if (owned.origins.has(requested.origin)) {
              for (const [name, value] of Object.entries(this.http.identityHeaders(owned.identity))) {
                if (name.toLowerCase() !== "cookie") headers[name.toLowerCase()] = value;
              }
            }
            const { exchange, body, rawHeaders } = await this.http.forward({ url: target, method: request.method, headers, body: request.postData, timeoutMs: 30_000, maxBodyBytes: 2 * 1024 * 1024 });
            if (exchange.error) throw new Error(exchange.error);
            if (["Document", "XHR", "Fetch"].includes(event.resourceType) || /json/i.test(rawHeaders["content-type"] ?? "")) {
              if (owned.requests.length < 200) owned.requests.push({ id: exchange.id, method: request.method, url: this.http.redact(target), status: exchange.response?.status, artifact: exchange.artifact, type: event.resourceType.toLowerCase() });
            }
            for (const name of ["content-encoding", "content-length", "transfer-encoding", "connection"]) delete rawHeaders[name];
            const responseHeaders = Object.entries(rawHeaders).flatMap(([name, value]) => value.split("\n").map((value) => ({ name, value })));
            // Frames y workers pueden crear otros targets CDP: se bloquean hasta poder capturarlos completos.
            responseHeaders.push({ name: "content-security-policy", value: "frame-src 'none'; worker-src 'none'; object-src 'none'" });
          await cdp.send("Fetch.fulfillRequest", { requestId: event.requestId, responseCode: exchange.response!.status, responseHeaders, body: body.toString("base64") });
          } catch (error) {
            block(`${target}: ${(error as Error).message}`);
            await cdp.send("Fetch.failRequest", { requestId: event.requestId, errorReason: "BlockedByClient" }).catch(() => {});
          }
        })();
        owned.pending.add(work);
        void work.finally(() => owned.pending.delete(work));
      });
      await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] });
      context.on("page", (page: External) => { if (page !== owned.page) void page.close().catch(() => {}); });
      owned.page.setDefaultTimeout(this.options.actionTimeoutMs);
      owned.page.setDefaultNavigationTimeout(this.options.actionTimeoutMs);
      this.tabs.set(key, owned);
    }
    if (!tab.origins.has(url.origin)) {
      const cookie = Object.entries(headers).find(([name]) => name.toLowerCase() === "cookie")?.[1];
      if (cookie) await tab.context.addCookies(cookie.split(";").flatMap((part) => {
        const index = part.indexOf("=");
        return index < 1 ? [] : [{ name: part.slice(0, index).trim(), value: part.slice(index + 1).trim(), url: url.origin }];
      }));
      tab.origins.add(url.origin);
    }
    this.current = tab;
    return tab;
  }

  private selected(id?: string): Tab {
    const tab = id ? [...this.tabs.values()].find((entry) => entry.id === id) : this.current;
    if (!tab) throw new Error("Abrí una página con browser_open o indicá un id de página válido");
    if (tab.fingerprint !== JSON.stringify(this.http.identityHeaders(tab.identity))) throw new Error("La identidad cambió; volvé a abrir la página con browser_open");
    return tab;
  }

  private async snapshot(tab: Tab): Promise<any> {
    // No esperamos quietud indefinida: muchas SPA consultan en bucle.
    const deadline = Date.now() + Math.min(this.options.actionTimeoutMs, 1000);
    while (tab.pending.size && Date.now() < deadline) await Promise.race([Promise.allSettled([...tab.pending]), new Promise((resolve) => setTimeout(resolve, 25))]);
    await tab.page.waitForLoadState("networkidle", { timeout: Math.min(this.options.actionTimeoutMs, 1000) }).catch(() => {});
    const data = await this.timed<any>(tab, tab.page.evaluate(() => ({
      title: document.title.slice(0, 300), url: location.href,
      text: (document.body?.innerText ?? "").replace(/\s+/g, " ").slice(0, 4000),
      forms: Array.from(document.forms).slice(0, 20).map((form) => ({ action: form.action, method: form.method, fields: Array.from(form.querySelectorAll("input,textarea,select,button")).slice(0, 40).map((field) => ({ name: field.getAttribute("name"), id: field.id, type: field.getAttribute("type") ?? field.tagName.toLowerCase() })) })),
      links: Array.from(document.querySelectorAll("a[href]")).slice(0, 80).map((a) => ({ text: (a.textContent ?? "").trim().slice(0, 120), url: (a as HTMLAnchorElement).href })),
    })));
    for (const link of data.links) {
      try { const url = new URL(link.url); if (decide(this.http.scope(), url.href).allowed) this.http.linked.add(this.http.redact(url.pathname + url.search)); } catch {}
    }
    return { id: tab.id, ...this.redactValues(data), requests: tab.requests, blocked: tab.blocked, limitations: "Frames, workers, WebSocket, WebRTC y ventanas nuevas bloqueados; máximo 2 MiB por respuesta." };
  }

  open(url: string, identity?: string): Promise<any> {
    return this.serial(async () => {
      const target = new URL(url);
      if (!/^https?:$/.test(target.protocol) || !decide(this.http.scope(), url).allowed) throw new Error(`Fuera del alcance: ${url}`);
      const tab = await this.tab(identity, target);
      await tab.page.goto(url, { waitUntil: "domcontentloaded" });
      return this.snapshot(tab);
    });
  }

  act(actions: BrowserAction[], id?: string): Promise<any> {
    return this.serial(async () => {
      if (!Array.isArray(actions) || actions.length < 1 || actions.length > 8) throw new Error("Pasá entre 1 y 8 acciones");
      const tab = this.selected(id);
      for (const action of actions) {
        if (this.closed) throw new Error("El navegador está cerrado");
        if (action.type === "wait") {
          if (action.selector) await tab.page.locator(action.selector).first().waitFor({ state: "visible" });
          else {
            const ms = action.ms ?? 100;
            if (!Number.isFinite(ms) || ms < 0 || ms > this.options.actionTimeoutMs) throw new Error("La espera supera el tope por acción");
            await tab.page.waitForTimeout(ms);
          }
          continue;
        }
        if (!action.selector && !(action.type === "click" && action.text)) throw new Error("Indicá selector, o texto para hacer clic");
        const locator = action.selector ? tab.page.locator(action.selector).first() : tab.page.getByText(action.text, { exact: true }).first();
        if (action.type === "click") await locator.click();
        else if (action.type === "fill") { if (typeof action.value !== "string" || action.value.length > 8000) throw new Error("Valor de campo inválido (máximo 8000 caracteres)"); await locator.fill(action.value); }
        else if (action.type === "submit") await this.timed(tab, locator.evaluate((element: HTMLFormElement) => { if (!(element instanceof HTMLFormElement)) throw new Error("El selector debe apuntar a un formulario"); element.requestSubmit(); }));
        else throw new Error(`Acción desconocida: ${action.type}`);
      }
      return this.snapshot(tab);
    });
  }

  capture(id?: string): Promise<{ hash: string; bytes: number; mediaType: string }> {
    return this.serial(async () => {
      const tab = this.selected(id);
      const texts = await this.timed<string[]>(tab, tab.page.evaluate(() => Array.from(document.querySelectorAll("body,body *")).map((element) => Array.from(element.childNodes).filter((node) => node.nodeType === Node.TEXT_NODE).map((node) => node.textContent ?? "").join(""))));
      const mask = [tab.page.locator('input,textarea,[contenteditable="true"],canvas,video')];
      for (const [index, text] of texts.entries()) if (text && this.http.redact(text) !== text) mask.push(tab.page.locator("body,body *").nth(index));
      const bytes = await tab.page.screenshot({ type: "png", fullPage: false, timeout: this.options.actionTimeoutMs, animations: "disabled", mask });
      if (bytes.length > this.options.maxCaptureBytes) throw new Error(`La captura supera el tope de ${this.options.maxCaptureBytes} bytes`);
      return this.http.artifacts.put(bytes, "image/png", "browser_capture");
    });
  }


  /** ¿Tiene la página «id»? La vista pública del gestor consulta al mismo adaptador que navegó. */
  hasTab(id: string): boolean {
    return this.tabs.has(id) || this.current?.id === id;
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    return this.closing = (async () => {
      try {
        await this.browser?.close();
        await this.queue;
        await this.browser?.close();
        await Promise.allSettled([...this.tabs.values()].flatMap((tab) => [...tab.pending]));
        this.tabs.clear();
      } finally { await this.closeProxy(); }
    })();
  }
}
