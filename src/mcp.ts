// MCP por stdio, sin SDK: los procesos son de la sesión y se abren al descubrir sus herramientas.
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { t } from "./idioma.ts";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Tool, ToolResult } from "./agent.ts";
import { configPath } from "./providers.ts";

export interface McpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  /** Carpeta de trabajo del proceso (sólo servidores incorporados; la configuración del operador no la usa). */
  cwd?: string;
  /** No hereda el entorno del harness: sólo lo mínimo para correr, más `env` (sólo servidores incorporados). */
  entornoMinimo?: boolean;
}

/** Herramienta que un servidor incorporado ofrece antes de arrancar; sólo éstas se exponen de él. */
export interface McpOferta {
  name: string;
  label: string;
  description: string;
  /** Esquema provisorio hasta que el servidor arranque y mande el suyo. */
  parameters?: object;
}

/**
 * Servidor que trae el harness, no el operador: arranca al primer uso, expone sólo su oferta y cada
 * llamada pasa por su política (revisar antes de mandar, salida acotada después).
 */
export interface McpIncorporado {
  config: McpServerConfig;
  /** Lo que muestra /mcp en vez del comando. */
  resumen: string;
  oferta: McpOferta[];
  /** Encabeza la descripción de cada herramienta (en vez del aviso de análisis local). */
  aviso?: string;
  /** Revisa (y puede reescribir) los argumentos; si no pasan, tira y no se manda nada al servidor. */
  revisar(tool: string, args: Record<string, unknown>): Record<string, unknown>;
  /** Lo que ve el modelo del resultado crudo. */
  salida(tool: string, result: unknown): ToolResult;
  /** Antes de arrancar el proceso (puede completar `config.env`); una vez por conexión. */
  preparar?(): Promise<void>;
  /** Al cerrar la sesión. */
  cerrar?(): Promise<void>;
}

export interface McpManagerOptions {
  incorporados?: Record<string, McpIncorporado>;
  /** Motivo por el que una entrada del operador no se arranca; undefined si se puede. */
  bloqueo?: (name: string, config: McpServerConfig) => string | undefined;
}
export interface McpTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}
export interface McpOptions {
  timeoutMs?: number;
  maxFrameBytes?: number;
}

type Pending = { resolve: (value: any) => void; reject: (error: Error) => void; clean: () => void };
const VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
const LOCAL_ONLY = "Análisis local de binarios, archivos y código. El alcance de HttpClient no cubre esta herramienta: no la uses contra destinos de red.";
const record = (value: unknown): value is Record<string, any> => !!value && typeof value === "object" && !Array.isArray(value);

/** Lo único que hereda un servidor incorporado: con qué correr y dónde escribir lo suyo. */
const MINIMAL_ENV = ["PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "JAVA_HOME", "SystemRoot", "TEMP", "TMP"];
function minimalEnv(): Record<string, string> {
  const env: Record<string, string> = { TERM: "dumb" };
  for (const name of MINIMAL_ENV) if (process.env[name]) env[name] = process.env[name]!;
  return env;
}

function withSignal<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return work;
  if (signal.aborted) return Promise.reject(new Error("Solicitud MCP cancelada"));
  return new Promise((resolve, reject) => {
    const aborted = () => { signal.removeEventListener("abort", aborted); reject(new Error("Solicitud MCP cancelada")); };
    signal.addEventListener("abort", aborted, { once: true });
    work.then((value) => { signal.removeEventListener("abort", aborted); resolve(value); }, (error) => { signal.removeEventListener("abort", aborted); reject(error); });
  });
}

export function readMcpConfig(): Record<string, McpServerConfig> {
  const path = configPath();
  if (!existsSync(path)) return {};
  try {
    const config: unknown = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
    if (!record(config)) throw new Error("se esperaba un objeto");
    const servers = config.mcp ?? {};
    if (!record(servers)) throw new Error("mcp debe ser un objeto");
    const result: Record<string, McpServerConfig> = Object.create(null);
    for (const [name, entry] of Object.entries(servers)) {
      if (!/^[a-zA-Z0-9_-]+$/.test(name) || !record(entry) || typeof entry.command !== "string" || !entry.command.trim()) throw new Error(`servidor MCP inválido: ${name}`);
      if (entry.args !== undefined && (!Array.isArray(entry.args) || entry.args.some((arg: unknown) => typeof arg !== "string"))) throw new Error(`args de ${name} debe ser una lista de cadenas`);
      if (entry.env !== undefined && (!record(entry.env) || Object.values(entry.env).some((value) => typeof value !== "string"))) throw new Error(`env de ${name} debe contener cadenas`);
      result[name] = { command: entry.command, args: entry.args ?? [], env: entry.env ?? {} };
    }
    return result;
  } catch (error) {
    throw new Error(`Configuración MCP inválida en ${path}: ${(error as Error).message}`);
  }
}

/** Guarda los servidores en la configuración (clave «mcp»), sin tocar el resto del archivo. */
export function writeMcpConfig(servers: Record<string, McpServerConfig>): void {
  const path = configPath();
  let config: Record<string, unknown> = {};
  if (existsSync(path)) {
    // Un archivo que no se puede leer nunca se pisa: se perderían el resto de la configuración y los proveedores.
    try {
      const parsed: unknown = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
      if (!record(parsed)) throw new Error("se esperaba un objeto");
      config = parsed;
    } catch (error) { throw new Error(t(`No toqué ${path}: no es un JSON válido (${(error as Error).message}). Arreglalo a mano.`, `Left ${path} untouched: it is not valid JSON (${(error as Error).message}). Fix it by hand.`)); }
  }
  const mcp: Record<string, McpServerConfig> = {};
  for (const [name, entry] of Object.entries(servers)) {
    mcp[name] = { command: entry.command, ...(entry.args?.length ? { args: entry.args } : {}), ...(entry.env && Object.keys(entry.env).length ? { env: entry.env } : {}) };
  }
  config.mcp = mcp;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`);
}

export class McpClient {
  private readonly config: McpServerConfig;
  private readonly timeoutMs: number;
  private readonly maxFrameBytes: number;
  private child?: ChildProcessWithoutNullStreams;
  private pending = new Map<number, Pending>();
  private seq = 0;
  private buffer: Buffer = Buffer.alloc(0);
  private writes: Promise<void> = Promise.resolve();
  private queuedBytes = 0;
  private ready?: Promise<void>;
  private closing?: Promise<void>;
  private ended?: Promise<void>;
  private stopped = false;
  private failure?: Error;
  private cached?: McpTool[];
  private listing?: Promise<McpTool[]>;
  private revision = 0;

  /** Para la vista del operador: cómo está la conexión y cuántas herramientas se conocen. */
  state(): { state: string; tools?: number; error?: string } {
    if (this.stopped) return { state: "cerrado" };
    if (this.failure) return { state: "falló", error: this.failure.message };
    if (this.child) return { state: "conectado", ...(this.cached ? { tools: this.cached.length } : {}) };
    return { state: "sin iniciar" };
  }

  constructor(config: McpServerConfig, options: McpOptions = {}) {
    this.config = config;
    // REA puede gastar 330 s arrancando un motor; el cliente deja margen para devolver evidencia.
    this.timeoutMs = options.timeoutMs ?? 600_000;
    this.maxFrameBytes = options.maxFrameBytes ?? 16 * 1024 * 1024;
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs < 1 || !Number.isInteger(this.maxFrameBytes) || this.maxFrameBytes < 128) throw new Error("Límites MCP inválidos");
  }

  private start(): void {
    if (this.stopped) throw new Error("El cliente MCP está cerrado");
    if (this.failure) throw this.failure;
    if (this.child) return;
    // Las claves de Cyber no le sirven a un servidor de terceros.
    const { CYBER_SECRETS_KEY: _k, OROBAS_API_KEY: _o, H1_API_TOKEN: _h, CYBER_BOUNTY_KEY: _b, ...inherited } = process.env;
    // Un incorporado arranca con lo mínimo: ni tokens de plataformas ni variables del operador que pueda leer.
    const base = this.config.entornoMinimo ? minimalEnv() : inherited;
    const child = spawn(this.config.command, this.config.args ?? [], { env: { ...base, ...this.config.env }, ...(this.config.cwd ? { cwd: this.config.cwd } : {}), shell: false, stdio: "pipe", detached: process.platform !== "win32" });
    this.child = child;
    this.ended = new Promise((resolve) => child.once("close", () => resolve()));
    child.stdout.on("data", (chunk: Buffer) => this.receive(chunk));
    // stderr no es parte del protocolo y puede traer secretos del entorno.
    child.stderr.resume();
    child.stdin.on("error", () => this.fail(new Error("Se cerró la entrada del servidor MCP")));
    child.on("error", () => this.fail(new Error("No se pudo iniciar el servidor MCP; revisá command y args")));
    child.once("exit", (code, signal) => this.fail(new Error(`El servidor MCP terminó (${signal ?? code ?? "sin código"})`)));
    child.stdout.once("end", () => { if (!this.stopped) this.fail(new Error("El servidor MCP cerró stdout")); });
  }

  private fail(error: Error): void {
    this.failure ??= error;
    for (const [id, pending] of this.pending) {
      this.pending.delete(id);
      pending.clean();
      pending.reject(error);
    }
    if (!this.stopped) void this.close();
  }

  private receive(chunk: Buffer): void {
    if (this.stopped) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    for (;;) {
      const newline = this.buffer.indexOf(10);
      if (newline < 0) break;
      if (newline > this.maxFrameBytes) { this.fail(new Error("El mensaje MCP supera el tope de bytes")); return; }
      const frame = this.buffer.subarray(0, newline).toString("utf8").trim();
      this.buffer = this.buffer.subarray(newline + 1);
      if (!frame) continue;
      try {
        const message: unknown = JSON.parse(frame);
        if (!record(message) || message.jsonrpc !== "2.0") throw new Error("Mensaje JSON-RPC inválido");
        if (typeof message.method === "string") {
          if (message.id !== undefined) {
            // No anunciamos sampling, roots ni acceso al entorno del cliente.
            const reply = message.method === "ping" ? { result: {} } : { error: { code: -32601, message: "Método no disponible en este cliente" } };
            void this.write({ jsonrpc: "2.0", id: message.id, ...reply }).catch((error) => this.fail(error));
          } else if (message.method === "notifications/tools/list_changed") {
            this.revision++;
            this.cached = undefined;
          } else if (message.method === "notifications/cancelled" && record(message.params)) {
            const pending = this.pending.get(message.params.requestId);
            if (pending) {
              this.pending.delete(message.params.requestId);
              pending.clean();
              pending.reject(new Error("El servidor MCP canceló la solicitud"));
            }
          }
          continue;
        }
        if (typeof message.id !== "number") throw new Error("Respuesta MCP sin id válido");
        const pending = this.pending.get(message.id);
        if (!pending) continue; // una respuesta tardía a una cancelación no completa otra solicitud
        this.pending.delete(message.id);
        pending.clean();
        if (record(message.error)) pending.reject(new Error(`MCP ${message.error.code}: ${String(message.error.message ?? "error del servidor")}`));
        else if (Object.hasOwn(message, "result")) pending.resolve(message.result);
        else pending.reject(new Error("Respuesta MCP sin result ni error"));
      } catch (error) {
        this.fail(new Error(`Protocolo MCP inválido: ${(error as Error).message}`));
        return;
      }
    }
    if (this.buffer.length > this.maxFrameBytes) this.fail(new Error("El mensaje MCP supera el tope de bytes"));
  }

  private write(message: object, live: () => boolean = () => true): Promise<void> {
    if (this.stopped || !this.child || this.failure) return Promise.reject(this.failure ?? new Error("El cliente MCP está cerrado"));
    const frame = Buffer.from(JSON.stringify(message) + "\n");
    if (frame.length > this.maxFrameBytes || this.queuedBytes + frame.length > 2 * this.maxFrameBytes) return Promise.reject(new Error("La cola MCP supera el tope de bytes"));
    this.queuedBytes += frame.length;
    const writing = this.writes.then(async () => {
      if (!live()) return;
      if (this.stopped || this.failure) throw this.failure ?? new Error("El cliente MCP está cerrado");
      // El callback espera al pipe: no acumulamos escrituras sin límite si el servidor deja de leer.
      await new Promise<void>((resolve, reject) => this.child!.stdin.write(frame, (error) => error ? reject(error) : resolve()));
    }).finally(() => { this.queuedBytes -= frame.length; });
    this.writes = writing.catch(() => {});
    return writing;
  }

  private request(method: string, params: object, signal?: AbortSignal): Promise<any> {
    if (signal?.aborted) return Promise.reject(new Error("Solicitud MCP cancelada"));
    if (this.pending.size >= 128) return Promise.reject(new Error("Demasiadas solicitudes MCP pendientes"));
    this.start();
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      const cancel = (reason: string) => {
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id);
        pending.clean();
        void this.write({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason } }).catch(() => {});
        reject(new Error(reason));
      };
      const aborted = () => cancel("Solicitud MCP cancelada; la ejecución remota puede seguir en curso");
      const timer = setTimeout(() => cancel("Tiempo de espera MCP agotado; la ejecución remota puede seguir en curso"), this.timeoutMs);
      const clean = () => { clearTimeout(timer); signal?.removeEventListener("abort", aborted); };
      this.pending.set(id, { resolve, reject, clean });
      signal?.addEventListener("abort", aborted, { once: true });
      void this.write({ jsonrpc: "2.0", id, method, params }, () => this.pending.has(id)).catch((error) => {
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id);
        pending.clean();
        pending.reject(error);
      });
    });
  }

  async initialize(signal?: AbortSignal): Promise<void> {
    if (this.stopped) throw new Error("El cliente MCP está cerrado");
    if (signal?.aborted) throw new Error("Solicitud MCP cancelada");
    this.ready ??= (async () => {
      const result = await this.request("initialize", { protocolVersion: VERSIONS[0], capabilities: {}, clientInfo: { name: "elevate-ai-cyber", version: "0.1.0" } });
      if (!record(result) || !VERSIONS.includes(result.protocolVersion) || !record(result.capabilities)) throw new Error("El servidor MCP negoció una versión o capacidades inválidas");
      await this.write({ jsonrpc: "2.0", method: "notifications/initialized" });
    })().catch(async (error) => { await this.close(); throw error; });
    return withSignal(this.ready, signal);
  }

  async listTools(signal?: AbortSignal): Promise<McpTool[]> {
    await this.initialize(signal);
    if (this.cached) return this.cached;
    if (this.listing) return withSignal(this.listing, signal);
    const revision = this.revision;
    this.listing = (async () => {
      const tools: McpTool[] = [];
      const cursors = new Set<string>();
      const names = new Set<string>();
      let cursor: string | undefined;
      do {
        const result = await this.request("tools/list", cursor ? { cursor } : {}, signal);
        if (!record(result) || !Array.isArray(result.tools)) throw new Error("tools/list devolvió una lista inválida");
        for (const tool of result.tools) {
          if (!record(tool) || typeof tool.name !== "string" || !/^[a-zA-Z0-9_.-]+$/.test(tool.name) || !record(tool.inputSchema) || (tool.description !== undefined && typeof tool.description !== "string") || names.has(tool.name)) throw new Error("tools/list devolvió una herramienta inválida o repetida");
          names.add(tool.name);
          tools.push({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema });
        }
        if (tools.length > 10_000 || cursors.size >= 100) throw new Error("El catálogo MCP supera el tope de herramientas o páginas");
        cursor = result.nextCursor;
        if (cursor !== undefined && (typeof cursor !== "string" || !cursor || cursors.has(cursor))) throw new Error("tools/list repitió un cursor o devolvió uno inválido");
        if (cursor) cursors.add(cursor);
      } while (cursor);
      if (revision === this.revision) this.cached = tools;
      return tools;
    })();
    try { return await this.listing; } finally { this.listing = undefined; }
  }

  async callTool(name: string, args: object, signal?: AbortSignal): Promise<any> {
    if (signal?.aborted) throw new Error("Solicitud MCP cancelada");
    await this.initialize(signal);
    return this.request("tools/call", { name, arguments: args }, signal);
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    for (const pending of this.pending.values()) { pending.clean(); pending.reject(new Error("El cliente MCP está cerrado")); }
    this.pending.clear();
    this.buffer = Buffer.alloc(0);
    const child = this.child;
    this.closing = (async () => {
      if (!child) return;
      const kill = (signal: NodeJS.Signals) => {
        try {
          if (process.platform !== "win32" && child.pid) process.kill(-child.pid, signal);
          else child.kill(signal);
        } catch {}
      };
      child.stdin.destroy();
      kill("SIGTERM");
      const timer = setTimeout(() => kill("SIGKILL"), 500);
      try { await this.ended; } finally { clearTimeout(timer); }
    })();
    return this.closing;
  }
}

export class McpManager {
  private readonly config: Record<string, McpServerConfig>;
  private readonly builtin: Record<string, McpIncorporado>;
  private readonly bloqueo?: (name: string, config: McpServerConfig) => string | undefined;
  private readonly clients = new Map<string, McpClient>();
  /** Herramientas que un incorporado ofreció y su política no expone, por servidor. */
  private readonly hidden = new Map<string, string[]>();
  private stopped = false;

  constructor(config: Record<string, McpServerConfig> = readMcpConfig(), options: McpManagerOptions = {}) {
    this.config = config;
    this.builtin = Object.assign(Object.create(null), options.incorporados ?? {});
    this.bloqueo = options.bloqueo;
  }

  private blocked(name: string): string | undefined {
    const config = Object.hasOwn(this.config, name) ? this.config[name] : undefined;
    return config && !this.builtin[name] ? this.bloqueo?.(name, config) : undefined;
  }

  /** Servidores que se pueden usar: los del operador (salvo bloqueados o tapados por un incorporado) y los incorporados. */
  names(): string[] {
    return [...Object.keys(this.config).filter((name) => !this.builtin[name] && !this.blocked(name)), ...Object.keys(this.builtin)];
  }
  /** Los que trae el harness. */
  builtins(): string[] { return Object.keys(this.builtin); }
  /** Un incorporado no arranca para buscar: su oferta ya está en el catálogo y arranca al primer uso. */
  lazy(name: string): boolean { return !!this.builtin[name]; }
  /** Lo que ofrecen los incorporados antes de arrancar. */
  offers(): Array<McpOferta & { server: string }> {
    return Object.entries(this.builtin).flatMap(([server, item]) => item.oferta.map((offer) => ({ ...offer, server })));
  }
  /** Copia de la configuración del operador, para guardarla (los incorporados no se guardan). */
  all(): Record<string, McpServerConfig> { return Object.fromEntries(Object.keys(this.config).map((name) => [name, { ...this.config[name]! }])); }

  /** Suma un servidor (o reemplaza su configuración; la conexión vieja se cierra). */
  add(name: string, config: McpServerConfig): void {
    if (this.stopped) throw new Error("La sesión MCP está cerrada");
    if (this.builtin[name]) throw new Error(t(`«${name}» viene incorporado en el harness; elegí otro nombre.`, `“${name}” is built into the harness; pick another name.`));
    const next = { command: config.command, args: config.args ?? [], env: config.env ?? {} };
    const reason = this.bloqueo?.(name, next);
    if (reason) throw new Error(reason);
    const previous = this.clients.get(name);
    this.clients.delete(name);
    void previous?.close();
    this.config[name] = next;
  }

  /** Quita un servidor del operador y cierra su proceso. Los incorporados no se quitan. */
  async remove(name: string): Promise<void> {
    if (!Object.hasOwn(this.config, name)) {
      if (this.builtin[name]) throw new Error(t(`«${name}» viene incorporado en el harness: no se quita.`, `“${name}” is built into the harness: it cannot be removed.`));
      return;
    }
    delete this.config[name];
    if (this.builtin[name]) return;
    const client = this.clients.get(name);
    this.clients.delete(name);
    await client?.close();
  }

  /** Estado de cada servidor, para /mcp. */
  status(): Array<{ name: string; command: string; state: string; tools?: number; error?: string }> {
    const own = Object.keys(this.config).map((name) => {
      const config = this.config[name]!;
      const command = [config.command, ...(config.args ?? [])].join(" ");
      if (this.builtin[name]) return { name, command, state: "tapado por el incorporado" };
      const reason = this.blocked(name);
      if (reason) return { name, command, state: "bloqueado", error: reason };
      const client = this.clients.get(name);
      return { name, command, ...(client ? client.state() : { state: "sin iniciar" }) };
    });
    const builtin = Object.entries(this.builtin).map(([name, item]) => {
      const client = this.clients.get(name);
      const hidden = this.hidden.get(name)?.length;
      const state = client ? client.state() : { state: "sin iniciar" };
      return { name, command: `${item.resumen}${hidden ? ` · ${t(`${hidden} herramientas suyas fuera de la política`, `${hidden} of its tools outside the policy`)}` : ""}`, ...state };
    });
    return [...own, ...builtin];
  }

  async tools(server?: string, signal?: AbortSignal): Promise<Tool[]> {
    if (this.stopped) throw new Error("La sesión MCP está cerrada");
    const selected = server === undefined ? this.names() : [server];
    const groups = await Promise.all(selected.map(async (name) => {
      const builtin = this.builtin[name];
      const config = builtin?.config ?? (Object.hasOwn(this.config, name) ? this.config[name] : undefined);
      if (!config) throw new Error(`No existe el servidor MCP «${name}»`);
      const reason = this.blocked(name);
      if (reason) throw new Error(reason);
      let client = this.clients.get(name);
      if (!client) {
        if (builtin?.preparar) await builtin.preparar();
        // Otra llamada pudo crearlo mientras se preparaba.
        client = this.clients.get(name) ?? new McpClient(config);
        this.clients.set(name, client);
      }
      const connection = client;
      const listed = await connection.listTools(signal);
      if (builtin) return this.policyTools(name, builtin, connection, listed);
      return listed.map((tool): Tool => ({
        name: `${name}.${tool.name}`,
        label: `MCP ${name}: ${tool.name}`,
        description: `${LOCAL_ONLY}\n${tool.description ?? tool.name}`,
        parameters: tool.inputSchema,
        replay: "never",
        execute: async (args, signal) => {
          const result = await connection.callTool(tool.name, args, signal);
          return { text: JSON.stringify(result), isError: result?.isError === true, details: { servidor: name, isError: result?.isError === true } };
        },
      }));
    }));
    return groups.flat();
  }

  /** Sólo lo ofrecido, con la política del incorporado antes y después de cada llamada. */
  private policyTools(name: string, builtin: McpIncorporado, connection: McpClient, listed: McpTool[]): Tool[] {
    const offered = new Map(builtin.oferta.map((offer) => [offer.name, offer]));
    this.hidden.set(name, listed.filter((tool) => !offered.has(tool.name)).map((tool) => tool.name));
    return listed.filter((tool) => offered.has(tool.name)).map((tool): Tool => {
      const offer = offered.get(tool.name)!;
      // La descripción del servidor es de un tercero: va recortada y después de la nuestra.
      const theirs = (tool.description ?? "").replace(/\s+/g, " ").trim();
      return {
        name: `${name}.${tool.name}`,
        label: offer.label,
        description: [offer.description, builtin.aviso, theirs ? `Del servidor: ${theirs.length > 700 ? `${theirs.slice(0, 700)}…` : theirs}` : ""].filter(Boolean).join("\n"),
        parameters: tool.inputSchema,
        replay: "never",
        execute: async (args, signal) => {
          const checked = builtin.revisar(tool.name, record(args) ? args : {});
          const result = await connection.callTool(tool.name, checked, signal);
          return builtin.salida(tool.name, result);
        },
      };
    });
  }

  async close(): Promise<void> {
    this.stopped = true;
    await Promise.all([...this.clients.values()].map((client) => client.close()));
    await Promise.allSettled(Object.values(this.builtin).map((item) => item.cerrar?.()));
  }
}
