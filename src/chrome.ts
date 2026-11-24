// El navegador del operador, manejado por la extensión de Chromium (carpeta extension/).
// La extensión se conecta a este proceso por 127.0.0.1 con un código de emparejamiento y ejecuta
// lo que le pide el agente, sólo en pestañas de sitios dentro del alcance. Sirve para lo que no se
// puede hacer desde el navegador propio: sesiones ya iniciadas, login con terceros, captcha, 2FA.
// El alcance se comprueba dos veces: acá, antes de pedir nada, y en la extensión, antes de tocar
// la pestaña. Las cookies de la sesión nunca llegan al modelo: quedan como identidad.
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cpSync, existsSync, readdirSync, mkdirSync, renameSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { dirname, join } from "node:path";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { identityBase } from "./credenciales.ts";
import { shown } from "./datos.ts";
import { credentialsDir } from "./secretos.ts";
import { t } from "./idioma.ts";
import { type HttpClient, isLoginUrl } from "./http.ts";
import { configPath } from "./providers.ts";
import { decide, type Scope } from "./scope.ts";
import type { BrowserState } from "./navegador.ts";

const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

export const CHROME_PORT = 47615;
/** Cuántos puertos seguidos prueba el puente (y sondea la extensión): uno por cyber. */
export const CHROME_PORTS = 20;

/** Código de emparejamiento: estable entre sesiones, vive junto a la configuración del operador. */
export function pairingToken(): string {
  const path = join(dirname(configPath()), "extension.json");
  try {
    const saved = JSON.parse(readFileSync(path, "utf8")) as { token?: string };
    if (saved.token && /^[a-f0-9]{32,}$/.test(saved.token)) return saved.token;
  } catch { /* se crea */ }
  const token = randomBytes(24).toString("hex");
  if (!existsSync(dirname(path))) mkdirSync(dirname(path), { recursive: true });
  try {
    // «wx»: si otro contenedor llegó primero, se queda con el suyo y acá se lo relee.
    writeFileSync(path, JSON.stringify({ token }, null, 2), { mode: 0o600, flag: "wx" });
    return token;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    try {
      const saved = JSON.parse(readFileSync(path, "utf8")) as { token?: string };
      if (saved.token && /^[a-f0-9]{32,}$/.test(saved.token)) return saved.token;
    } catch { /* roto: se reemplaza abajo */ }
    writeFileSync(path, JSON.stringify({ token }, null, 2), { mode: 0o600 });
    return token;
  }
}

type Pending = {
  id: string; cmd: string; args: object; rules: object; resolve: (data: any) => void; reject: (error: Error) => void; timer: NodeJS.Timeout;
  /** Un /poll se la llevó: la extensión la está haciendo. */
  taken: boolean;
  /** Ya venció una vez sin que nadie la tomara y se volvió a esperar. */
  retried: boolean;
};

/** Por qué falló un pedido al navegador del operador: cada caso se explica distinto. */
export type ChromeFailure = "sin-emparejar" | "dormido" | "no-tomada" | "colgada" | "cerrado";
export class ChromeError extends Error {
  readonly code: ChromeFailure;
  constructor(code: ChromeFailure, message: string) {
    super(message);
    this.code = code;
  }
}

/** Sin noticias de la extensión por este tiempo, se la da por dormida: su /poll vuelve cada 20 s como mucho. */
const ALIVE_MS = 35_000;

/** Marca de la máquina: cuándo habló la extensión con algún agente (con cualquier proyecto). Junto a la configuración, aparte del código. */
export const seenMarkerPath = () => join(dirname(configPath()), "extension-visto.json");
const markerCache = new Map<string, { at: number; value: number }>();
/** Lee la marca (ms; 0 si no hay), con un caché corto: el pie de la TUI la pregunta seguido. */
export function readSeenMarker(path: string = seenMarkerPath(), fresh = false): number {
  const now = Date.now();
  const cached = markerCache.get(path);
  if (cached && !fresh && now - cached.at < 10_000) return cached.value;
  let value = 0;
  try { value = Number((JSON.parse(readFileSync(path, "utf8")) as { visto?: unknown }).visto) || 0; } catch { /* sin marca */ }
  markerCache.set(path, { at: now, value });
  return value;
}
function writeSeenMarker(path: string, at: number): void {
  // Se escribe entera y se renombra: varios agentes (y contenedores) pueden escribirla a la vez.
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, JSON.stringify({ visto: at }), { mode: 0o600 });
  renameSync(temp, path);
  markerCache.set(path, { at: Date.now(), value: at });
}

/** Qué hace un pedido, para los mensajes de error: «leer la pestaña 7». */
function describe(cmd: string, args: { tab?: unknown; url?: unknown }): string {
  const tab = args.tab !== undefined ? ` ${t("la pestaña", "tab")} ${String(args.tab)}` : "";
  const url = typeof args.url === "string" ? ` ${args.url.slice(0, 120)}` : "";
  const verbs: Record<string, string> = { tabs: t("listar las pestañas", "list the tabs"), open: t(`abrir${url}`, `open${url}`), navigate: t(`llevar${tab} a${url}`, `navigate${tab} to${url}`), read: t(`leer${tab}`, `read${tab}`), act: t(`actuar en${tab}`, `act on${tab}`), cookies: t(`tomar la sesión de${tab}`, `take the session of${tab}`), traffic: t(`leer el tráfico de${tab}`, `read the traffic of${tab}`), capture: t(`capturar${tab}`, `capture${tab}`), release: t("soltar las pestañas", "release the tabs") };
  return `«${cmd}»: ${verbs[cmd] ?? cmd}`;
}

/** Servidor local al que la extensión le pregunta si hay algo para hacer. */
export class ChromeBridge {
  private server?: Server;
  private readonly queue: Pending[] = [];
  private readonly sent = new Map<string, Pending>();
  private readonly waiting: Array<(command: Pending | undefined) => void> = [];
  private readonly fixedPort: boolean;
  private lastSeen = 0;
  private seq = 0;
  /** Cuándo se esperó a la extensión el tiempo entero sin que apareciera: el pedido siguiente no vuelve a esperar 35 s. */
  private gaveUpAt = 0;
  /** Desafíos emitidos y todavía sin usar: cada uno vale una sola vez y poco tiempo. */
  private readonly nonces = new Map<string, number>();
  private readonly dockerenv: string;
  /** Cuánto se espera a una extensión que ya se vio (dormida: la alarma la despierta cada 30 s) y a una que nunca se vio. */
  private readonly wakeMs: number;
  private readonly firstMs: number;
  /** Marca de la máquina: la extensión se vio alguna vez (con cualquier proyecto). false: no se lee ni escribe (pruebas). */
  private readonly seenFile: string | false;
  private seenFileAt = 0;
  private readonly seenHooks = new Set<(at: number) => void>();
  private readonly changeHooks = new Set<() => void>();
  private expiry?: NodeJS.Timeout;
  port = 0;
  readonly token: string;

  constructor(options: { token?: string; port?: number; dockerenv?: string; wakeMs?: number; firstMs?: number; seenFile?: string | false } = {}) {
    this.dockerenv = options.dockerenv ?? "/.dockerenv";
    this.token = options.token ?? pairingToken();
    this.port = options.port ?? CHROME_PORT;
    this.fixedPort = options.port !== undefined;
    this.wakeMs = options.wakeMs ?? 35_000;
    this.firstMs = options.firstMs ?? 5_000;
    this.seenFile = options.seenFile ?? seenMarkerPath();
  }

  /** La extensión preguntó hace poco: hay un navegador emparejado y despierto. */
  get connected(): boolean {
    return Date.now() - this.lastSeen < ALIVE_MS;
  }

  /** El puente ya escucha: la extensión lo puede encontrar. */
  get listening(): boolean {
    return !!this.server;
  }

  /** Última vez que la extensión habló con este proceso (ms; 0 si nunca). */
  get seenAt(): number {
    return this.lastSeen;
  }

  /** Última vez que la extensión habló con algún agente de esta máquina (ms; 0 si nunca o sin marca). */
  machineSeen(): number {
    return Math.max(this.seenFile ? readSeenMarker(this.seenFile) : 0, this.lastSeen);
  }

  /** Conectado, dormido (se vio alguna vez: en el proyecto, `known`, o en la máquina) o sin emparejar. */
  state(known = 0): BrowserState {
    if (this.connected) return "conectado";
    return Math.max(known, this.machineSeen()) > 0 ? "dormido" : "sin-emparejar";
  }

  /** Cada vez que la extensión habla (para recordarlo en el proyecto). Devuelve cómo desuscribirse. */
  onSeen(hook: (at: number) => void): () => void {
    this.seenHooks.add(hook);
    return () => this.seenHooks.delete(hook);
  }

  /** Cuando pasa de conectado a dormido o al revés (para el pie de la TUI). */
  onChange(hook: () => void): () => void {
    this.changeHooks.add(hook);
    return () => this.changeHooks.delete(hook);
  }

  private changed(): void {
    for (const hook of this.changeHooks) { try { hook(); } catch { /* quien escucha no rompe el puente */ } }
  }

  /** La extensión habló: se anota, se avisa si estaba dormida y se programa el aviso de cuando se duerma. */
  private seen(): void {
    const was = this.connected;
    const now = Date.now();
    this.lastSeen = now;
    for (const hook of this.seenHooks) { try { hook(now); } catch { /* idem */ } }
    if (this.seenFile && now - this.seenFileAt > 60_000) {
      this.seenFileAt = now;
      try { writeSeenMarker(this.seenFile, now); } catch { /* sin marca de máquina: queda la del proyecto */ }
    }
    clearTimeout(this.expiry);
    this.expiry = setTimeout(() => this.changed(), ALIVE_MS + 50);
    this.expiry.unref();
    if (!was) this.changed();
  }

  /** Puerto por el que la extensión llegó en el host: en contenedor lo fija el lanzador (CYBER_PUERTO_HOST), afuera es el propio. */
  private get macPort(): number | undefined {
    const published = Number(process.env.CYBER_PUERTO_HOST);
    if (Number.isInteger(published) && published > 0 && published < 65536) return published;
    // En contenedor sin la variable no hay puerto confiable: se cierra todo (un 47615 por defecto permitiría un relevo pasivo).
    return this.inContainer ? undefined : this.port;
  }

  private get inContainer(): boolean {
    return !!process.env.CYBER_PROYECTO_HOST && existsSync(this.dockerenv);
  }

  private get launcherTooOld(): string {
    return t("Falta CYBER_PUERTO_HOST: actualizá el lanzador de cyber (cyber --actualizar) para emparejar el navegador.", "CYBER_PUERTO_HOST is missing: update the cyber launcher (cyber --actualizar) to pair the browser.");
  }

  /** HMAC sobre campos unidos con «\n»: todos de formato fijo (hex, número, método, ruta), sin ambigüedad. */
  private mac(...fields: Array<string | number>): string {
    return createHmac("sha256", this.token).update(fields.join("\n")).digest("hex");
  }

  /** El código nunca viaja: la extensión firma, con un desafío de un solo uso, método, ruta, puerto y cuerpo (un relevo a otro puerto o con otro cuerpo no vale). */
  private authorized(req: IncomingMessage, body: Buffer): boolean {
    const port = this.macPort;
    if (port === undefined) return false;
    const nonce = String(req.headers["x-orobas-nonce"]);
    const expires = this.nonces.get(nonce);
    this.nonces.delete(nonce);
    if (!expires || expires < Date.now()) return false;
    const given = Buffer.from(String(req.headers["x-orobas-mac"] ?? ""));
    const expected = Buffer.from(this.mac("ext", port, String(req.method), String(req.url), nonce, sha256(body)));
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  async start(): Promise<void> {
    if (this.server) return;
    const server = createServer((req, res) => {
      // Sólo una extensión del navegador, y sólo con el código: una página web cualquiera no puede hablarle.
      const origin = String(req.headers.origin ?? "");
      if (origin && !origin.startsWith("chrome-extension://")) return void res.writeHead(401).end();
      // Un encabezado propio fuerza el preflight de CORS, que una página web no pasa; y avisa a una extensión vieja.
      if (req.headers["x-orobas"] !== "1") return void res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ error: t("La extensión de Orobas es de una versión vieja: actualizala o recargala en chrome://extensions.", "The Orobas extension is out of date: update or reload it in chrome://extensions.") }));
      if (req.method === "GET" && req.url === "/nonce") {
        if (this.macPort === undefined) return void res.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ error: this.launcherTooOld }));
        const now = Date.now();
        for (const [key, expires] of this.nonces) if (expires < now) this.nonces.delete(key);
        if (this.nonces.size >= 256) return void res.writeHead(429).end();
        const nonce = randomBytes(16).toString("hex");
        this.nonces.set(nonce, now + 30_000);
        return void res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ nonce, proto: 1 }));
      }
      const serve = (body: Buffer) => {
        if (!this.authorized(req, body)) return void res.writeHead(401).end();
        // Prueba de que este puente conoce el código, atada a la respuesta exacta y al puerto, para que la extensión no le obedezca a un impostor.
        const extNonce = String(req.headers["x-orobas-ext"] ?? "");
        const reply = (status: number, text = "") => {
          const headers: Record<string, string> = { "x-orobas-proof": this.mac("srv", this.macPort!, status, extNonce, sha256(text)) };
          if (text) headers["content-type"] = "application/json";
          res.writeHead(status, headers).end(text);
        };
        this.seen();
        if (req.method === "GET" && req.url === "/poll") {
          const next = this.queue.shift();
          const deliver = (command: Pending | undefined) => {
            if (!command) return void reply(204);
            command.taken = true;
            this.sent.set(command.id, command);
            reply(200, JSON.stringify({ id: command.id, cmd: command.cmd, args: command.args, rules: command.rules }));
          };
          if (next) return deliver(next);
          // Varios /poll pueden esperar a la vez: cada orden va a uno distinto.
          const leave = () => { const at = this.waiting.indexOf(waiter); if (at >= 0) this.waiting.splice(at, 1); };
          const timer = setTimeout(() => { leave(); deliver(undefined); }, 20_000);
          const waiter = (command: Pending | undefined) => { clearTimeout(timer); leave(); deliver(command); };
          this.waiting.push(waiter);
          req.on("close", () => { if (!res.writableEnded) { clearTimeout(timer); leave(); } });
          return;
        }
        if (req.method === "POST" && req.url === "/result") {
          try {
            const result = JSON.parse(body.toString("utf8")) as { id: string; ok: boolean; data?: unknown; error?: string };
            const pending = this.sent.get(result.id);
            if (pending) {
              this.sent.delete(result.id);
              clearTimeout(pending.timer);
              if (result.ok) pending.resolve(result.data);
              else pending.reject(new Error(result.error ?? "La extensión no pudo hacerlo"));
            }
          } catch { /* resultado ilegible: la orden vence sola */ }
          return void reply(204);
        }
        res.writeHead(404).end();
      };
      if (req.method === "POST" && req.url === "/result") {
        const chunks: Buffer[] = [];
        let size = 0;
        req.on("data", (chunk: Buffer) => { chunks.push(chunk); size += chunk.length; if (size > 12 * 1024 * 1024) req.destroy(); });
        req.on("end", () => serve(Buffer.concat(chunks)));
        return;
      }
      serve(Buffer.alloc(0));
    });
    // En contenedor: 0.0.0.0 (el lanzador lo publica sólo en 127.0.0.1 del host). Afuera: el primer puerto libre del rango.
    const inContainer = this.inContainer;
    const host = inContainer ? "0.0.0.0" : "127.0.0.1";
    const first = this.port;
    const last = this.fixedPort || inContainer ? first : first + CHROME_PORTS - 1;
    for (let port = first; ; port++) {
      try {
        await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => { server.off("error", reject); resolve(); }); });
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EADDRINUSE") throw error;
        if (port >= last) throw new Error(first === last ? `El puerto ${first} ya está en uso: otro proceso tiene el puente del navegador.` : `Los puertos ${first} a ${last} están en uso: ya hay ${CHROME_PORTS} agentes de orobas-sec con el navegador. Cerrá alguno (orobas-sec daemon stop en su carpeta) y probá de nuevo.`);
      }
    }
    this.port = (server.address() as { port: number }).port;
    server.unref();
    this.server = server;
  }

  /**
   * Espera a que la extensión pregunte. Si ya se la vio alguna vez (en este proyecto, `known`, o en la
   * máquina) está dormida o Chromium cerrado: la alarma la despierta cada 30 s, así que se la espera
   * hasta 35 s, siempre (salvo que se la haya esperado entera hace poco y siga sin aparecer). Si nunca
   * se vio, se falla rápido con los pasos para emparejarla.
   */
  private async awaitExtension(known: number, signal?: AbortSignal): Promise<void> {
    if (this.connected) return;
    const paired = Math.max(known, this.machineSeen()) > 0;
    const recentlyFailed = this.gaveUpAt > this.lastSeen && Date.now() - this.gaveUpAt < 120_000;
    const limit = recentlyFailed ? 0 : paired ? this.wakeMs : this.firstMs;
    const started = Date.now();
    while (!this.connected && Date.now() - started < limit) {
      if (signal?.aborted) throw new ChromeError("cerrado", t("Cancelado mientras esperaba al navegador del operador: no se le pidió nada.", "Cancelled while waiting for the operator's browser: nothing was asked."));
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (this.connected) return;
    this.gaveUpAt = Date.now();
    const cmd = extCmd(this.dockerenv);
    if (!paired) throw new ChromeError("sin-emparejar", t(`La extensión de Orobas nunca se conectó a un agente en esta máquina: el operador tiene que correr «${cmd}» y seguir los pasos (una sola vez): cargar la carpeta en chrome://extensions y pegar el código en el ícono de Orobas. Si ya la había emparejado, que abra Chromium o toque el ícono de Orobas y reintentá en unos segundos. No sigas probando chrome_* hasta que te avise.`, `The Orobas extension has never connected to an agent on this machine: the operator has to run "${cmd}" and follow the steps (once): load the folder in chrome://extensions and paste the code in the Orobas icon. If it was already paired, they should open Chromium or click the Orobas icon, and retry in a few seconds. Do not keep trying chrome_* until they tell you.`));
    const waited = recentlyFailed ? t(`ya la esperé ${Math.round(this.wakeMs / 1000)} s hace ${Math.round((Date.now() - this.gaveUpAt) / 1000) || 1} s`, `I already waited ${Math.round(this.wakeMs / 1000)} s for it`) : t(`la esperé ${Math.round(limit / 1000)} s`, `I waited ${Math.round(limit / 1000)} s for it`);
    throw new ChromeError("dormido", t(`El navegador del operador no contesta (${waited}): la extensión está dormida y no se despertó, o Chromium está cerrado. Pedile al operador que abra Chromium o toque el ícono de Orobas (eso la despierta) y reintentá; /navegador le muestra el estado. Si el ícono dice «código incorrecto», que corra «${cmd}» de nuevo.`, `The operator's browser does not answer (${waited}): the extension is asleep and did not wake up, or Chromium is closed. Ask the operator to open Chromium or click the Orobas icon (that wakes it up) and retry; /navegador shows them the status. If the icon says "wrong code", they should run "${cmd}" again.`));
  }

  /**
   * Le pide algo a la extensión y espera el resultado. Si la orden vence sin que ningún /poll la tome (la
   * extensión se durmió), se la deja en la cola y se espera una vez más; si la tomó y no contestó, la
   * página tardó o se colgó, y se dice qué orden era. `known`: cuándo vio el proyecto la extensión.
   * Cancelada (`signal`) antes de que la extensión la tome, sale de la cola: no se hace después.
   */
  async request<T = any>(cmd: string, args: object, rules: object, timeoutMs = 30_000, known = 0, signal?: AbortSignal): Promise<T> {
    await this.start();
    if (this.macPort === undefined) throw new Error(this.launcherTooOld);
    await this.awaitExtension(known, signal);
    return new Promise<T>((resolve, reject) => {
      const id = `c${++this.seq}`;
      const what = describe(cmd, args as { tab?: unknown; url?: unknown });
      const expire = () => {
        if (!pending.taken && !pending.retried) {
          // Nadie la tomó: la extensión se durmió entre su último /poll y ahora. La alarma la despierta.
          pending.retried = true;
          pending.timer = setTimeout(expire, Math.max(timeoutMs, this.wakeMs));
          return;
        }
        this.sent.delete(id);
        const at = this.queue.findIndex((item) => item.id === id);
        if (at >= 0) this.queue.splice(at, 1);
        const seconds = Math.round((Date.now() - started) / 1000);
        if (pending.taken) reject(new ChromeError("colgada", t(`El navegador del operador tomó la orden ${what} y no respondió en ${seconds} s: la página tardó o se colgó (o se cerró la pestaña). Mirá la pestaña con chrome_read antes de repetir: una acción puede haberse hecho igual.`, `The operator's browser took the order ${what} and did not answer in ${seconds} s: the page was slow or hung (or the tab was closed). Look at the tab with chrome_read before repeating: an action may have happened anyway.`)));
        else reject(new ChromeError("no-tomada", t(`El navegador del operador no tomó la orden ${what} en ${seconds} s, ni esperando de nuevo: la extensión se durmió y no volvió, está ocupada con otras órdenes, o se cerró Chromium. Pedile al operador que abra Chromium o toque el ícono de Orobas; /navegador le muestra el estado.`, `The operator's browser did not take the order ${what} in ${seconds} s, not even after waiting again: the extension fell asleep and did not come back, is busy with other orders, or Chromium was closed. Ask the operator to open Chromium or click the Orobas icon; /navegador shows them the status.`)));
      };
      const started = Date.now();
      const pending: Pending = { id, cmd, args, rules, resolve, reject, timer: setTimeout(expire, timeoutMs), taken: false, retried: false };
      signal?.addEventListener("abort", () => {
        if (pending.taken) return;
        const at = this.queue.indexOf(pending);
        if (at >= 0) this.queue.splice(at, 1);
        clearTimeout(pending.timer);
        reject(new ChromeError("cerrado", t(`Cancelado: la orden ${what} no llegó a salir hacia el navegador del operador.`, `Cancelled: the order ${what} never reached the operator's browser.`)));
      }, { once: true });
      const waiter = this.waiting.shift();
      if (waiter) waiter(pending);
      else this.queue.push(pending);
    });
  }

  close(): void {
    this.server?.close();
    this.server = undefined;
    this.gaveUpAt = 0;
    clearTimeout(this.expiry);
    for (const pending of [...this.queue, ...this.sent.values()]) { clearTimeout(pending.timer); pending.reject(new ChromeError("cerrado", "Puente cerrado")); }
    this.queue.length = 0;
    this.sent.clear();
    for (const waiter of [...this.waiting]) waiter(undefined);
  }
}

let shared: ChromeBridge | undefined;
/** El puente compartido del proceso (uno por daemon). Con `create: false`, sólo si ya existe. */
export function chromeBridge(create: false): ChromeBridge | undefined;
export function chromeBridge(create?: true): ChromeBridge;
export function chromeBridge(create = true): ChromeBridge | undefined {
  return create ? (shared ??= new ChromeBridge()) : shared;
}

interface ChromeContext {
  http: HttpClient;
  artifacts: Artifacts;
  scope: () => Scope | undefined;
  /**
   * ¿El operador autorizó su navegador en este proyecto? Lo da sólo él (/navegador si, o pidiéndolo con
   * sus palabras): nada que devuelva una herramienta o el objetivo cuenta.
   */
  authorized: () => boolean;
  /** Cuándo vio este proyecto la extensión por última vez (ms; 0 si nunca): decide si se la espera. */
  seenBefore?: () => number;
  bridge?: ChromeBridge | (() => ChromeBridge);
}

const str = { type: "string" };
const TAB = { type: "integer", description: "Id de pestaña que devolvió chrome_tabs o chrome_open. No lo adivines ni pruebes números: los demás son pestañas ajenas o fuera del alcance." };

/** Errores de la extensión que dicen que esa pestaña no se puede usar: se contestan con las que sí. */
const TAB_REFUSED = /La pestaña \d+ (está fuera del alcance|la usa otro agente)|No tab with id|Invalid tab ID|no existe la pestaña/i;

export function createChromeTools(context: ChromeContext): Tool[] {
  const bridge = () => (typeof context.bridge === "function" ? context.bridge() : context.bridge ?? chromeBridge());
  const rules = () => {
    const scope = context.scope();
    if (!scope?.include.length) throw new Error("No hay alcance definido: sin alcance no se toca el navegador del operador.");
    return { include: scope.include.map(({ kind, value }) => ({ kind, value })), exclude: scope.exclude.map(({ kind, value }) => ({ kind, value })) };
  };
  const consent = () => {
    if (!context.authorized()) {
      throw new Error("El operador no autorizó su navegador en este proyecto. Pedile que escriba /navegador si o que te lo pida con sus palabras («usá mi navegador»): queda autorizado para todas las sesiones del proyecto. No sigas probando chrome_* hasta entonces.");
    }
  };
  const inScope = (url: string) => {
    const decision = decide(context.scope(), url);
    if (!decision.allowed) throw new Error(`Fuera del alcance: ${decision.reason}`);
    context.http.refuseDecoy(url);
  };
  const ask = async <T = any>(cmd: string, args: object, timeoutMs?: number, signal?: AbortSignal) => {
    consent();
    return bridge().request<T>(cmd, args, rules(), timeoutMs, context.seenBefore?.() ?? 0, signal);
  };
  /** Una URL del alcance para sugerir en chrome_open, si se puede armar una. */
  const sampleUrl = (): string | undefined => {
    const scope = context.scope();
    const candidates = (scope?.include ?? []).flatMap((rule) => (rule.kind === "url" ? [rule.value] : rule.kind === "host" ? [`https://${rule.value}/`] : rule.kind === "wildcard" ? [`https://${rule.value.slice(2)}/`, `https://www.${rule.value.slice(2)}/`, `https://app.${rule.value.slice(2)}/`] : []));
    return candidates.find((url) => decide(scope, url).allowed);
  };
  /**
   * Un pedido sobre una pestaña. Si la extensión dice que esa pestaña no existe, está fuera del alcance o
   * es de otro agente, el error trae las que sí se pueden usar (y cómo abrir una), para no probar ids de a uno.
   */
  const onTab = async <T = any>(cmd: string, args: { tab: unknown; [key: string]: unknown }, timeoutMs?: number, signal?: AbortSignal): Promise<T> => {
    try {
      return await ask<T>(cmd, args, timeoutMs, signal);
    } catch (error) {
      if (!TAB_REFUSED.test((error as Error).message)) throw error;
      let valid = "";
      try {
        const tabs = (await ask<Array<{ id: number; url: string; title: string }>>("tabs", {}, 15_000, signal)).filter((tab) => decide(context.scope(), tab.url).allowed);
        valid = tabs.length
          ? `Pestañas que sí podés usar: ${tabs.slice(0, 12).map((tab) => `${tab.id} (${tab.url.slice(0, 100)}${tab.title ? ` · ${tab.title.slice(0, 40)}` : ""})`).join("; ")}.`
          : "No hay ninguna pestaña del alcance abierta.";
      } catch { valid = "Listalas con chrome_tabs."; }
      const example = sampleUrl();
      throw new Error(`La pestaña ${String(args.tab)} no existe, está fuera del alcance o la usa otro agente: no se toca. ${valid} No pruebes otros números: usá una de ésas o abrí una nueva con chrome_open${example ? ` (p. ej. url: "${example}")` : " y una URL del alcance"}.`);
    }
  };
  const redact = (text: string) => context.http.redactIdentities(text);
  type View = { tab: number; url: string; title: string; text: string; forms: Array<{ action: string; method: string; fields: Array<{ name: string; type: string; value?: string }> }>; links: string[]; buttons: string[]; log?: string[]; left?: string };
  /** Qué hacer cuando una pestaña salió del alcance: no se sigue ahí, pero el trabajo no termina. */
  const leftNote = (view: View): string => {
    let login = false;
    // La extensión sólo devuelve el host si la pestaña salió del alcance. No trae la ruta ni el contenido.
    try { login = isLoginUrl(new URL(view.left!.includes("://") ? view.left! : `https://${view.left}`)); } catch { /* la extensión puede devolver «otro sitio» */ }
    const session = login
      ? " Parece un inicio de sesión externo. Para una sesión: si hay una identidad cargada para el sitio (http_identities), usala; si el operador tiene cuenta, pedile que inicie sesión él en esa pestaña y, cuando vuelva al sitio, tomala con chrome_session; si el sitio tiene registro propio dentro del alcance, creá una cuenta de prueba tuya con mail_address y mail_wait. Si no hay forma, avisale al operador y seguí con lo que no requiere sesión."
      : "";
    return `La pestaña ${view.tab} quedó en ${view.left}, fuera del alcance: no se lee ni se sigue ahí, y no se toca mientras esté afuera.${session} Para seguir en el navegador, abrí otra pestaña del alcance con chrome_open (o navigate en este mismo pedido, que abre una nueva).`;
  };
  const render = (view: View): string => {
    if (view.left) return [...(view.log ?? []), leftNote(view)].join("\n");
    // La extensión ya filtró; se vuelve a comprobar acá, que es donde está la autoridad.
    inScope(view.url);
    const links = view.links.filter((link) => decide(context.scope(), link).allowed);
    return redact([
      ...(view.log?.length ? ["Acciones:", ...view.log.map((line) => `  ${line}`), ""] : []),
      `pestaña ${view.tab} · ${view.url}`,
      `título: ${view.title}`,
      ...(view.forms.length ? ["formularios:", ...view.forms.map((form) => `  ${form.method} ${form.action} · ${form.fields.map((field) => `${field.name}(${field.type})`).join(", ")}`)] : []),
      ...(view.buttons.length ? [`botones: ${[...new Set(view.buttons)].slice(0, 40).join(" · ")}`] : []),
      ...(links.length ? [`enlaces del alcance (${links.length}): ${links.slice(0, 40).join(" ")}`] : []),
      "",
      view.text.slice(0, 4000),
    ].join("\n"));
  };
  const tool = (name: string, label: string, description: string, properties: Record<string, object>, required: string[], execute: (params: any, signal?: AbortSignal) => Promise<ToolResult>): Tool => ({ name, label, description, parameters: { type: "object", properties, required }, execute });

  return [
    tool("chrome_tabs", "Pestañas del operador", `Lista las pestañas abiertas en el navegador del operador que están dentro del alcance (las demás no se ven ni se tocan): de acá salen los ids para chrome_read, chrome_act, chrome_session, chrome_traffic y chrome_capture; si no hay una del sitio, abrila con chrome_open. El navegador del operador tiene sus sesiones ya iniciadas: usalo cuando el objetivo pide login con terceros, captcha o 2FA, o cuando el operador diga que ya está logueado. Requiere la extensión de Orobas («${extCmd()}») y que el operador lo haya autorizado en el proyecto (/navegador si).`, {}, [], async (_params, signal) => {
      const tabs = (await ask<Array<{ id: number; url: string; title: string; active: boolean }>>("tabs", {}, undefined, signal)).filter((tab) => decide(context.scope(), tab.url).allowed);
      return { text: tabs.length ? tabs.map((tab) => `${tab.id}  ${tab.url}  ${tab.title}${tab.active ? "  (a la vista)" : ""}`).join("\n") : "El operador no tiene ninguna pestaña abierta en un sitio del alcance. Abrí una con chrome_open o pedile que entre al sitio.", details: { pestañas: tabs.length } };
    }),
    tool("chrome_open", "Abrir pestaña del operador", "Abre una pestaña nueva en el navegador del operador, con su sesión, en una URL del alcance, y devuelve lo que se ve y su id (úsalo en las demás chrome_*). Es la forma de llegar a un sitio del alcance que el operador no tiene abierto.", { url: str }, ["url"], async (params, signal) => {
      inScope(params.url);
      const view = await ask<View>("open", { url: params.url }, 40_000, signal);
      return { text: render(view), details: { pestaña: view.tab } };
    }),
    tool("chrome_read", "Leer pestaña del operador", "Devuelve lo que se ve en una pestaña del operador (id de chrome_tabs o chrome_open): texto, formularios (sin valores de contraseñas), botones y enlaces del alcance.", { tab: TAB }, ["tab"], async (params, signal) => {
      const view = await onTab<View>("read", { tab: params.tab }, undefined, signal);
      return { text: render(view), details: { pestaña: view.tab } };
    }),
    tool("chrome_act", "Actuar en pestaña del operador", "Ejecuta hasta 8 acciones en una pestaña del operador, con su sesión real: navigate (url del alcance), click (por text o selector), fill (selector y value), submit (selector del formulario), wait (ms). No completa contraseñas (las escribe el operador) y no hace clic en botones de borrar, pagar o transferir. Lo que hagas acá ocurre de verdad en la cuenta del operador: actuá sólo sobre lo que pidió.", { tab: TAB, actions: { type: "array", minItems: 1, maxItems: 8, items: { type: "object", properties: { type: { type: "string", enum: ["navigate", "click", "fill", "submit", "wait"] }, url: str, selector: str, text: str, value: { type: "string", maxLength: 2000 }, ms: { type: "integer", minimum: 0, maximum: 10000 } }, required: ["type"] } } }, ["tab", "actions"], async (params, signal) => {
      const actions = params.actions as Array<{ type: string; url?: string; text?: string; selector?: string }>;
      let tab = params.tab;
      let view: View | undefined;
      let batch: typeof actions = [];
      // Si una acción saca la pestaña del alcance, esa salida no se sigue, pero el resto del pedido sí: un
      // navigate al alcance sigue en una pestaña nueva, y lo que iba sobre la página de afuera queda sin hacer (y se dice).
      const before: string[] = [];
      const skipped: string[] = [];
      const flush = async () => {
        if (!batch.length) return;
        if (view?.left) skipped.push(...batch.map((action) => `${action.type}${action.text ? ` «${action.text}»` : action.selector ? ` ${action.selector}` : ""}`));
        else view = await onTab<View>("act", { tab, actions: batch }, 60_000, signal);
        batch = [];
      };
      for (const action of actions) {
        if (action.type !== "navigate") { batch.push(action); continue; }
        await flush();
        if (!action.url) throw new Error("navigate necesita url");
        inScope(action.url);
        if (view?.left) {
          before.push(render(view));
          view = await ask<View>("open", { url: action.url }, 40_000, signal);
          before.push(`Lo que seguía del pedido continuó en una pestaña nueva, la ${view.tab} (${action.url.slice(0, 120)}): usá ese id de acá en adelante.`);
          tab = view.tab;
          continue;
        }
        view = await onTab<View>("navigate", { tab, url: action.url }, 40_000, signal);
      }
      await flush();
      const text = [...before, ...(skipped.length ? [`Sin hacer, porque la pestaña estaba fuera del alcance: ${skipped.join(", ")}.`] : []), render(view!)];
      return { text: text.join("\n"), details: { pestaña: tab, acciones: actions.length, ...(skipped.length ? { sinHacer: skipped.length } : {}) } };
    }),
    tool("chrome_session", "Tomar la sesión del operador", "Carga como identidad la sesión que el operador tiene iniciada en una pestaña del alcance (sus cookies para ese origen). El valor no se muestra: queda una identidad con nombre, limitada a ese origen, para usar con identity en http_request, http_probe, access_matrix o browser_open. Es la forma de trabajar autenticado sin pedirle tokens ni HAR.", { tab: TAB }, ["tab"], async (params, signal) => {
      const session = await onTab<{ origin: string; cookie: string; count: number }>("cookies", { tab: params.tab }, undefined, signal);
      inScope(session.origin);
      if (!session.cookie) return { text: `La pestaña ${params.tab} no tiene cookies para ${session.origin}: el operador no inició sesión ahí.`, details: { cookies: 0 } };
      const base = `${identityBase(new URL(session.origin).hostname)}-navegador`;
      const taken = new Set(context.http.identityNames());
      let name = base;
      for (let n = 2; taken.has(name); n++) name = `${base}-${n}`;
      context.http.setIdentity({ name, headers: { cookie: session.cookie }, origin: session.origin });
      return { text: `Sesión del operador cargada como identidad «${name}» (${session.count} cookies, sólo para ${session.origin}). Usala con identity: "${name}".`, details: { identidad: name, cookies: session.count } };
    }),
    tool("chrome_traffic", "Tráfico de una pestaña del operador", "Peticiones que hizo la aplicación en una pestaña del operador desde que la estás usando: método, URL, estado y nombres de los campos del cuerpo. Es el contrato real de la API: quedan como superficie conocida. Hacé la acción en la página (o pedile al operador que la haga) y después leé el tráfico.", { tab: TAB, clear: { type: "boolean", description: "Vaciar la lista después de leerla" } }, ["tab"], async (params, signal) => {
      const list = (await onTab<Array<{ method: string; url: string; status?: number; type: string; bodyKeys: string[] }>>("traffic", { tab: params.tab, clear: params.clear }, undefined, signal)).filter((entry) => decide(context.scope(), entry.url).allowed);
      const api = list.filter((entry) => entry.type === "xmlhttprequest" || entry.method !== "GET");
      for (const entry of api) { try { context.http.observe({ url: entry.url, method: entry.method, bodyKeys: entry.bodyKeys }); } catch { /* URL que no se puede registrar */ } }
      const lines = api.slice(-80).map((entry) => `${entry.method.padEnd(6)} ${entry.status ?? "…"}  ${entry.url.slice(0, 160)}${entry.bodyKeys.length ? `  campos: ${entry.bodyKeys.join(", ")}` : ""}`);
      return { text: redact(lines.length ? lines.join("\n") : "Todavía no hubo peticiones de la aplicación en esa pestaña. Hacé una acción y volvé a leer."), details: { peticiones: api.length } };
    }),
    tool("chrome_capture", "Capturar pestaña del operador", "Guarda como artefacto un PNG de lo que se ve en una pestaña del operador (la trae al frente).", { tab: TAB }, ["tab"], async (params, signal) => {
      const shot = await onTab<{ png: string }>("capture", { tab: params.tab }, undefined, signal);
      const bytes = Buffer.from(shot.png.replace(/^data:image\/png;base64,/, ""), "base64");
      if (bytes.length > 4 * 1024 * 1024) throw new Error("La captura supera 4 MiB.");
      const artifact = context.artifacts.put(bytes, "image/png", "chrome_capture");
      return { text: `Captura guardada: ${artifact.hash} (${bytes.length} bytes).`, details: { artefacto: artifact.hash } };
    }),
  ];
}

const enContenedor = (dockerenv = "/.dockerenv") => !!process.env.CYBER_PROYECTO_HOST && existsSync(dockerenv);
export const extCmd = (dockerenv = "/.dockerenv") => (enContenedor(dockerenv) ? "cyber extension" : "orobas-sec extension");

/** Copia src sobre dest sin borrar antes (una extensión ya cargada en el navegador no se rompe) y quita sólo lo que ya no está en src. */
function syncDir(src: string, dest: string): void {
  cpSync(src, dest, { recursive: true });
  for (const e of readdirSync(dest, { withFileTypes: true })) {
    if (!existsSync(join(src, e.name))) rmSync(join(dest, e.name), { recursive: true, force: true });
    else if (e.isDirectory()) syncDir(join(src, e.name), join(dest, e.name));
  }
}

/** En contenedor la carpeta de la imagen no la ve el navegador del host: se copia a la carpeta de credenciales (montada) y se muestra su ruta del host. */
function extensionFolder(folder: string, dockerenv: string): string {
  if (!enContenedor(dockerenv)) return folder;
  if (!process.env.CYBER_CREDENCIALES_HOST) return t("(actualizá el lanzador de cyber con «cyber --actualizar» para ver la carpeta)", "(update the cyber launcher with \"cyber --actualizar\" to see the folder)");
  try {
    const dest = join(credentialsDir(), "extension");
    syncDir(folder, dest);
    return shown(dest);
  } catch (e) {
    return t(`(no pude copiar la extensión: ${(e as Error).message})`, `(could not copy the extension: ${(e as Error).message})`);
  }
}

/** Pasos para instalar y emparejar la extensión; los muestra «cyber extension» / «orobas-sec extension». */
export function extensionGuide(folder: string, dockerenv = "/.dockerenv"): string[] {
  const where = extensionFolder(folder, dockerenv);
  return [
    t("EXTENSIÓN DE OROBAS PARA CHROMIUM", "OROBAS EXTENSION FOR CHROMIUM"),
    t("Le da al agente tu navegador, con tus sesiones, sólo en sitios del alcance.", "It gives the agent your browser, with your sessions, on in-scope sites only."),
    "",
    t("1. Abrí chrome://extensions en Chromium, Chrome, Brave o Edge.", "1. Open chrome://extensions in Chromium, Chrome, Brave or Edge."),
    t("2. Activá «Modo de desarrollador» (arriba a la derecha).", "2. Turn on \"Developer mode\" (top right)."),
    t(`3. «Cargar descomprimida» y elegí la carpeta: ${where}`, `3. \"Load unpacked\" and pick the folder: ${where}`),
    t("4. Tocá el ícono de Orobas, pegá este código y «Conectar»:", "4. Click the Orobas icon, paste this code and press \"Connect\":"),
    "",
    `   ${pairingToken()}`,
    "",
    t("Es una sola vez, y el mismo código sirve para todos tus cyber (Docker o en tu máquina) a la vez. Después, en cada proyecto: /navegador si (o decile al agente «usá mi navegador»); queda autorizado para todas sus sesiones y /navegador muestra si está conectado.", "It is a one-time step, and the same code works for all your cyber (Docker or on your machine) at once. Then, in each project: /navegador si (or tell the agent \"use my browser\"); it stays allowed for all its sessions and /navegador shows whether it is connected."),
    t("Una pestaña en uso muestra «ON» en el ícono; desde ahí lo pausás cuando quieras.", "A tab in use shows \"ON\" on the icon; pause it from there whenever you want."),
    t("No completa contraseñas ni hace clic en borrar, pagar o transferir.", "It does not fill in passwords or click delete, pay or transfer."),
  ];
}
