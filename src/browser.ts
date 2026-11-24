// Cada sesión («cuenta A», «cuenta B», una ventana de trabajo) tiene su adaptador propio:
// contexto, cola, cookies y cierre no se comparten. El incognito es otra instancia aislada.
// Un error o una espera en una pestaña no tumba a las demás.
import type { Tool } from "./agent.ts";
import type { HttpClient } from "./http.ts";
import { ChromiumWorkspaceSession, type BrowserOptions as ChromiumOptions } from "./sesion-chromium.ts";

export { browserPaths, browserStatus } from "./sesion-chromium.ts";

export type BrowserAction = { type: "click" | "fill" | "submit" | "wait"; selector?: string; text?: string; value?: string; ms?: number };
export interface BrowserOptions extends Omit<ChromiumOptions, "incognito"> {
  incognito?: boolean;
}

export interface OpenOptions {
  session?: string;
  incognito?: boolean;
}

interface Workspace {
  key: string;
  identity?: string;
  incognito: boolean;
  inc: ChromiumWorkspaceSession;
}

export class BrowserSession {
  readonly http: HttpClient;
  readonly options: BrowserOptions;
  private readonly workspaces = new Map<string, Workspace>();
  private current?: Workspace;
  private closed = false;

  constructor(http: HttpClient, options: BrowserOptions = {}) {
    this.http = http;
    this.options = { incognito: false, ...options };
  }

  private workspace(identity: string | undefined, options: OpenOptions): Workspace {
    if (this.closed) throw new Error("El navegador está cerrado");
    const incognito = !!options.incognito;
    const session = options.session?.trim();
    const key = incognito ? `incognito:${session || identity || "principal"}` : (session || identity || "principal");
    const existing = this.workspaces.get(key);
    if (existing && existing.incognito === incognito) return existing;
    const inc = new ChromiumWorkspaceSession(this.http, { ...this.options, incognito });
    const ws: Workspace = { key, identity, incognito, inc };
    this.workspaces.set(key, ws);
    return ws;
  }

  async open(url: string, identity?: string, options: OpenOptions = {}): Promise<any> {
    const ws = this.workspace(identity, options);
    const page = await ws.inc.open(url, identity);
    this.current = ws;
    return { ...page, session: ws.key, incognito: ws.incognito };
  }

  async act(actions: BrowserAction[], id?: string): Promise<any> {
    const ws = this.selected(id);
    return ws.inc.act(actions, undefined);
  }

  async read(id?: string, waitMs = 0): Promise<any> {
    const ws = this.selected(id);
    return ws.inc.act([{ type: "wait", ms: waitMs || 0 }], undefined);
  }

  async capture(id?: string): Promise<{ hash: string; bytes: number; mediaType: string }> {
    const ws = this.selected(id);
    return ws.inc.capture(id);
  }

  tabsStatus(): Array<{ id: string; identity?: string; incognito: boolean; current: boolean }> {
    return [...this.workspaces.values()].map((ws) => ({
      id: ws.key,
      identity: ws.identity,
      incognito: ws.incognito,
      current: this.current === ws,
    }));
  }

  private selected(id?: string): Workspace {
    if (this.closed) throw new Error("El navegador está cerrado");
    if (id !== undefined) {
      const wantedKey = id.startsWith("incognito:") ? id : `incognito:${id}`;
      const found = [...this.workspaces.values()].find((ws) => ws.key === id || ws.key === wantedKey || ws.inc.hasTab(id));
      if (!found) throw new Error("No existe la pestaña «" + id + "»; usá browser_tabs para verlas");
      this.current = found;
      return found;
    }
    if (this.current) return this.current;
    throw new Error("Abrí una página con browser_open o indicá una sesión");
  }

  async closeTab(id?: string): Promise<string> {
    const ws = this.selected(id);
    await ws.inc.close();
    this.workspaces.delete(ws.key);
    if (this.current === ws) this.current = [...this.workspaces.values()].at(-1);
    return `Sesión ${ws.key} cerrada`;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const ws of this.workspaces.values()) await ws.inc.close().catch(() => {});
    this.workspaces.clear();
    this.current = undefined;
  }
}

export function createBrowserTools(browser: BrowserSession): Tool[] {
  const str = { type: "string" };
  const tabId = { type: "string", description: "Id de pestaña; sin id usa la actual" };
  const strInteger = { type: "integer", minimum: 1, maximum: 10000 };
  const wrap = <T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> => {
    if (signal?.aborted) return browser.close().then(() => { throw new Error("cancelado"); });
    const cancelada = new Promise<never>((_, reject) => {
      const abort = () => { void browser.close().then(() => reject(new Error("cancelado"))); };
      signal?.addEventListener("abort", abort, { once: true });
    });
    return Promise.race([operation(), cancelada]) as Promise<T>;
  };
  return [
    {
      name: "browser_open",
      label: "Abrir navegador",
      description: "Abre una aplicación JavaScript por identidad (opcional `session` para aislar cuentas separadas). Devuelve id, texto, formularios, enlaces y tráfico de API. `incognito` crea otra instancia privada: no comparte ventanas ni cookies con las otras.",
      parameters: { type: "object", properties: { url: str, identity: str, session: { ...str, description: "Nombre del espacio: cuenta A, cuenta B etc" }, incognito: { type: "boolean", description: "Nueva instancia privada aislada" } }, required: ["url"] },
      execute: async (params, signal) => wrap(() => browser.open(String(params.url), params.identity as string | undefined, { session: params.session as string | undefined, incognito: !!params.incognito }), signal).then((page) => ({ text: JSON.stringify(page) })),
    },
    {
      name: "browser_act",
      label: "Actuar en pestaña",
      description: "Sobre una pestaña ya abierta: hasta ocho acciones (clic por texto o selector, escribir, enviar un formulario o esperar). Cola propia por sesión, sin que una detenga a las demás.",
      parameters: { type: "object", properties: { id: tabId, actions: { type: "array", minItems: 1, maxItems: 8, items: { type: "object", properties: { type: { type: "string", enum: ["click", "fill", "submit", "wait"] }, selector: str, text: str, value: str, ms: strInteger }, required: [] } } }, required: ["actions"] },
      execute: async (params, signal) => wrap(() => browser.act(params.actions as BrowserAction[], params.id as string | undefined), signal).then((page) => ({ text: JSON.stringify(page) })),
    },
    {
      name: "browser_read",
      label: "Leer pestaña",
      description: "Relee lo visible (formularios, enlaces, tráfico) de la pestaña actual sin cambiar de página, o la que indiques por sesión.",
      parameters: { type: "object", properties: { id: tabId, waitMs: strInteger }, required: [] },
      execute: async (params, signal) => wrap(() => browser.read(params.id as string | undefined, Number(params.waitMs ?? 0)), signal).then((page) => ({ text: JSON.stringify(page) })),
    },
    {
      name: "browser_tabs",
      label: "Sesiones del navegador",
      description: "Lista espacios abiertos y marca el actual: nombre de sesión, identidad y si es una instancia incógnita. Útil para A+B en paralelo.",
      parameters: { type: "object", properties: {}, required: [] },
      execute: () => ({ text: JSON.stringify(browser.tabsStatus()) }),
    },
    {
      name: "browser_capture",
      label: "Capturar pestaña",
      description: "Cuando el informe necesita evidencia visual, guarda una PNG de la ventana activa con los campos sensibles enmascarados. Máximo 2 MiB.",
      parameters: { type: "object", properties: { id: tabId }, required: [] },
      execute: async (params, signal) => wrap(() => browser.capture(params.id as string | undefined), signal).then((artifact) => ({ text: JSON.stringify(artifact), details: { artefacto: artifact.hash } })),
    },
    {
      name: "browser_close",
      label: "Cerrar sesión",
      description: "Al terminar con una ventana, indicá su sesión para liberar sus contextos y procesos. Sin argumento cierra la actual.",
      parameters: { type: "object", properties: { id: tabId }, required: [] },
      execute: async (params, signal) => wrap(() => browser.closeTab(params.id as string | undefined), signal).then((text) => ({ text: String(text) })),
    },
  ];
}
