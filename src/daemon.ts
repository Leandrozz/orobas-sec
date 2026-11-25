// Daemon del proyecto: dueño de las sesiones y de la base. Las interfaces se conectan por
// un socket Unix y pueden irse; el agente sigue trabajando y al volver se recupera el estado.
import { existsSync, mkdirSync, readdirSync, statSync, unlinkSync, writeFileSync, readFileSync } from "node:fs";
import { connect, createServer, type Server, type Socket } from "node:net";
import { basename, join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { AgentEvent } from "./agent.ts";
import { Artifacts } from "./artifacts.ts";
import { Engine, type EngineOptions, findSession, isStatusPing, queueKey, SYSTEM_PROMPT } from "./engine.ts";
import { Findings, findingsView } from "./findings.ts";
import { clearCredentials, HackerOne, importScope, loadCredentials, programHandle, programLines, saveCredentials } from "./hackerone.ts";
import { t } from "./idioma.ts";
import { deleteSecret, readSecret, secretState, writeSecret } from "./secretos.ts";
import { ScopeStore, scopeTag, scopeView } from "./scope.ts";
import { Grafo } from "./grafo.ts";
import { comandoGrafo } from "./grafo-consultas.ts";
import { propuestasDeEscalada } from "./cadenas.ts";
import { DecoyMarks } from "./senuelos.ts";
import { toolboxStatus } from "./toolbox.ts";
import { reaStatus } from "./rea.ts";
import { fuzzStatus } from "./fuzzing.ts";
import { findBinary, platform, redactSecrets, platformState, revokePlatform, startDevice } from "./plataformas.ts";
import { Ledger, storedBudget } from "./ledger.ts";
import { installTool } from "./instalar-herramientas.ts";
import { capsOf, parseReasoning, reasoningStatus, reasoningUsage } from "./operador.ts";
import { parseProfile, profileLine, ProfileStore } from "./perfil.ts";
import { ConsentStore, CONSENT_KINDS, citaTapada, consentHash, sendConsent } from "./consent.ts";
import { comparteConServicio, guardaLocal, guardarModoTrazas, leerModo, MODOS_TRAZAS, modoTrazas } from "./privacidad-trazas.ts";
import { anotar } from "./trazas-locales.ts";
import { avisoTrazasLocales, avisoTrazasPrimeraVez, lineasTrazas } from "./trazas-vista.ts";
import { refrescarModoCuenta } from "./cuenta.ts";
import { detectHost, type Connector, type Mailbox, mailboxes, saveMailboxes, testMailbox } from "./correo.ts";
import { generateReport, parseReportLang, reportSavedLines } from "./report.ts";
import type { Message } from "./llm.ts";
import { usd, usdToPico } from "./money.ts";
import { configPath, apiKey, orobasBaseUrl, type Provider, resolveProvider } from "./providers.ts";
import { chatgptOp, chatgptState } from "./chatgpt.ts";
import { isSubscription } from "./cuenta.ts";
import { backupOnNewVersion, lockProject, migrateLegacy, registerProject, runtimeDir, sharedFolderWarning } from "./datos.ts";
import { logEvent, openStore, projectPaths } from "./store.ts";
import { parseVerifySetting, readVerifySetting, saveVerifySetting, verifySettingLine } from "./verificacion.ts";
import { Vault } from "./vault.ts";
import { costDetail, costLine, evidenceView, jobsView, memoryView, usageLine, usageExport } from "./views.ts";
import { writeMcpConfig } from "./mcp.ts";

import { buildTrajectories, exportTrajectories, SHARE_KIND, SHARE_SENTENCE, shareTrajectories, trajectoriesLines } from "./trayectorias.ts";
import { origenDeTraza } from "./secretos-sesion.ts";
import { type DeviceStart, startDeviceLink, waitDeviceKey } from "./vincular.ts";
import { hostname } from "node:os";
import { CLIENT_VERSION } from "./llm.ts";
import { inicioDone, inicioPending, markInicio, resetInicio } from "./inicio.ts";
import { type HarnessId, HARNESSES, harnessStatus, ultraPrompt } from "./orquesta.ts";
import { vulndbStatus } from "./vulndb.ts";
import { CveFeed, type CveFeedOptions } from "./cvefeed.ts";
import { browserStatus } from "./browser.ts";
import { allProjectsRows, encodeRows, forkSession, renameSession, sessionDetail, sessionRows, sessionState, sessionsView } from "./sesiones.ts";
import { fileURLToPath } from "node:url";
import { chromeBridge, extCmd, extensionGuide, readSeenMarker, type ChromeBridge } from "./chrome.ts";
import { BrowserAccess, browserLines } from "./navegador.ts";
import { CabecerasPrograma, leerCabecera, lineasCabeceras } from "./cabeceras-programa.ts";
import { diagnosticarMejoras, redactarConModelo } from "./mejoras.ts";

/** El cambio ya rige en esta sesión; si no se pudo guardar, el error lo dice. */
function guardarMcp(servers: Parameters<typeof writeMcpConfig>[0]): void {
  try { writeMcpConfig(servers); } catch (error) {
    throw new Error(`${(error as Error).message} ${t("El cambio está activo en esta sesión pero no se guardó.", "The change is active in this session but was not saved.")}`);
  }
}

export const socketPath = (cwd: string) => join(runtimeDir(cwd), "daemon.sock");

/** Tope de gasto de una sesión nueva cuando nadie pidió otro. */
const DEFAULT_BUDGET = "2.00";

/** /herramientas: la caja por secciones. REA y el fuzzing dicen su versión adentro de la caja y «sólo en la caja» afuera. */
export function toolboxView(rea: string[] = reaStatus(), caja: string[] = toolboxStatus(), fuzz: string[] = fuzzStatus()): string[] {
  return ["CAJA DE HERRAMIENTAS", ...caja, "", t("INGENIERÍA INVERSA (habilidad ingenieria-inversa)", "REVERSE ENGINEERING (ingenieria-inversa skill)"), ...rea, "", t("HARNESS Y FUZZING (habilidad harness-fuzzing)", "HARNESS AND FUZZING (harness-fuzzing skill)"), ...fuzz, "", "BANCO DE CVE/CWE (habilidad cve-stack)", vulndbStatus(), "", "NAVEGADOR", ...browserStatus(), "", "OTROS HARNESSES (orquestación: /ultra)", ...harnessStatus()];
}

/** Cambia cuando cambia el código: un cliente nuevo no habla con un daemon viejo. */
export function buildId(): string {
  let newest = 0;
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) walk(join(dir, entry.name));
      else newest = Math.max(newest, statSync(join(dir, entry.name)).mtimeMs);
    }
  };
  walk(import.meta.dirname);
  return String(Math.floor(newest));
}

export interface Status {
  /** Pie de la TUI cuando el modelo usa el plan de ChatGPT. */
  chatgptPlan?: string;
  running: boolean;
  interrupted: boolean;
  usage: string;
  cost: string;
  /** Fracción del tope de sesión ya gastada; sin tope, no viene. */
  budget?: number;
  notes: number;
  /** El modelo de la sesión es de la suscripción y falta la clave de orobas. */
  needsKey: boolean;
  /** Hay una clave de orobas cargada (aunque el modelo de la sesión no la pida). */
  hasKey?: boolean;
  /** Modelo de la sesión (proveedor/modelo) y perfil de capacidades, para el pie de la TUI. */
  model?: string;
  profile?: string;
  /** Mensajes del operador esperando a que termine el turno. */
  queued?: number;
  /** Los mismos, para mostrarlos: el comienzo de cada uno y su clave (para no reenviar uno que ya espera). */
  queue?: Array<{ text: string; key: string }>;
  /** Caracteres de razonamiento previo recibidos en la solicitud en curso: el modelo trabaja aunque no escriba. */
  thinking?: number;
  /** Sesión abierta y su título, para el pie y el menú de sesiones. */
  session?: string;
  title?: string;
  /** Navegador del operador: estado de la extensión, si está autorizado en el proyecto y la etiqueta corta del pie. Sin esto, no se usa. */
  browser?: { state: "conectado" | "dormido" | "sin-emparejar"; authorized: boolean; label: string };
  /** Router de modelos, para el pie: «router: ejecutor», «router: fuerte·tramo (candidato)» o «router: fijo»; `active` mientras trabaja otro rol. */
  router?: { label: string; short: string; active: boolean };
  /** Modo investigar, para el pie, sólo con una investigación abierta: «inv: harness-1 · h3/7 · USD 1,20»; `activa` mientras corre. */
  investigacion?: { label: string; short: string; activa: boolean };
}

export interface Snapshot {
  sessionId: string;
  project: string;
  model: string;
  resumed: boolean;
  projectRequests: number;
  messages: Message[];
  /** Texto del asistente recibido hasta ahora en el turno en curso. */
  partial: string;
  /** Herramientas en ejecución: id → etiqueta. */
  tools: Record<string, string>;
  status: Status;
  /** Avisos para el operador al abrir: carpeta compartida (home o raíz), alcance de una sesión vieja. No bloquean. */
  avisos?: string[];
}

/** Lo que el daemon envía a una interfaz. */
export type ServerEvent =
  /** `clients`: otras conexiones abiertas (ventanas, sesiones) además de la que saluda. */
  | { ev: "hello"; build: string; pid: number; busy: boolean; clients?: number }
  | { ev: "attached"; snapshot: Snapshot }
  | { ev: "agent"; event: AgentEvent }
  | { ev: "recall"; ids: string[] }
  | { ev: "notice"; text: string }
  /** Respuesta del harness al operador (p. ej. «¿cómo vamos?» durante un turno), sin pasar por el modelo. */
  | { ev: "answer"; text: string }
  | { ev: "status"; status: Status }
  | { ev: "reply"; id: number; lines?: string[]; error?: string }
  /** Pedido de permiso de shell: el operador ve la línea y acepta, acepta siempre o rechaza. */
  | { ev: "confirm"; id: number; command: string; cwd: string; kind: string; risky: boolean; reasons: string[]; prefix: string };

/** Una sesión viva dentro del daemon, con las interfaces conectadas a ella. */
class Host {
  readonly engine: Engine;
  readonly clients = new Set<Socket>();
  partial = "";
  tools: Record<string, string> = {};
  thinking = 0;
  private thinkingTold = 0;
  /** Veces que una interfaz se adjuntó: a partir de la segunda, la sesión se ve como retomada. */
  attached = 0;

  constructor(engine: Engine) {
    this.engine = engine;
    engine.onNotice = (text) => this.broadcast({ ev: "answer", text });
    // La extensión se conectó o se durmió, o cambió la autorización: el pie de la TUI lo muestra.
    engine.onBrowserChange = () => this.broadcast({ ev: "status", status: this.status() });
    // El router empezó o terminó un encargo (o cambió de modo): el pie lo muestra, sin avisos en el chat.
    engine.onRouterChange = () => this.broadcast({ ev: "status", status: this.status() });
    // Una investigación cambió de estado o de fase: el pie lo muestra, sin avisos en el chat.
    engine.onInvestigacionChange = () => this.broadcast({ ev: "status", status: this.status() });
    // El shell pide permiso acá: el aviso llega a todas las interfaces y la respuesta vuelve por «confirm».
    engine.onShellAsk = (info) => this.broadcast({ ev: "confirm", ...info });
    engine.agent.on((event) => {
      if (event.type === "text") { if (!event.worker) this.partial += event.delta; }
      else if (event.type === "reasoning") {
        this.thinking += event.chars;
        // El estado se manda de a ratos, no por cada trozo: cada 400 caracteres alcanza para ver que avanza.
        if (this.thinking - this.thinkingTold < 400) return;
        this.thinkingTold = this.thinking;
        return this.broadcast({ ev: "status", status: this.status() });
      }
      else if (event.type === "retry") { this.partial = ""; this.thinking = this.thinkingTold = 0; }
      else if (event.type === "message" && event.message.role === "assistant") { this.partial = ""; this.thinking = this.thinkingTold = 0; }
      else if (event.type === "tool_start") this.tools[event.id] = event.label;
      else if (event.type === "tool_end") delete this.tools[event.id];
      else if (event.type === "idle") this.tools = {};
      // Los resultados completos de herramientas no viajan a la interfaz: sólo su resumen.
      const slim: AgentEvent = event.type === "tool_end" ? { ...event, text: event.isError ? event.text.slice(0, 200) : "" } : event;
      this.broadcast({ ev: "agent", event: slim });
      if (event.type === "request_start") return;
      if (event.type !== "text") this.broadcast({ ev: "status", status: this.status() });
    });
  }

  status(): Status {
    const { engine } = this;
    const chatgpt = engine.agent.model.provider === "chatgpt" ? chatgptState() : undefined;
    return {
      running: engine.agent.running,
      interrupted: engine.interrupted,
      usage: usageLine(engine.ledger, engine.sessionId),
      cost: costLine(engine.ledger, engine.sessionId),
      ...(engine.ledger.budgetPico ? { budget: Number((engine.ledger.totals(engine.sessionId).knownPico * 1000n) / engine.ledger.budgetPico) / 1000 } : {}),
      notes: engine.vault.count(),
      model: `${engine.agent.model.provider}/${engine.agent.model.id}`,
      profile: engine.profile.current(),
      ...(chatgpt ? { chatgptPlan: !chatgpt.linked ? "ChatGPT · desconectado · /chatgpt" : chatgpt.limitReached ? "ChatGPT · límite alcanzado · /chatgpt" : "Using ChatGPT plan · /chatgpt" } : {}),
      queued: engine.queue.length,
      ...(engine.queue.length ? { queue: engine.queue.map((text) => ({ text: text.replace(/\n\n<terminal>[\s\S]*$/, "").replace(/\s+/g, " ").trim().slice(0, 200), key: queueKey(text) })) } : {}),
      ...(this.thinking ? { thinking: this.thinking } : {}),
      session: engine.sessionId,
      title: (engine.db.prepare("select title from sessions where id=?").get(engine.sessionId) as { title: string | null } | undefined)?.title ?? undefined,
      ...((browser) => (browser ? { browser } : {}))(engine.browserBadge()),
      router: { label: engine.routerPie(), short: engine.routerPieCorto(), active: !!engine.routerActive },
      ...((investigacion) => (investigacion ? { investigacion } : {}))(engine.investigar?.pie()),
      // Sólo los modelos de la suscripción piden la cuenta de orobas (ver cuenta.ts): sin clave, la TUI la pide
      // antes del primer mensaje. Los locales y las claves propias no la piden. El modo simulado tampoco, salvo
      // que la prueba lo configure así.
      needsKey: (isSubscription(engine.provider.model) || engine.provider.model.apiKeyEnv === "OROBAS_API_KEY") && !apiKey("OROBAS_API_KEY"),
      hasKey: !!apiKey("OROBAS_API_KEY"),
    };
  }

  snapshot(): Snapshot {
    const { engine } = this;
    return {
      sessionId: engine.sessionId,
      project: engine.project,
      model: `${engine.provider.model.provider}/${engine.provider.model.id}`,
      resumed: engine.resumed || this.attached++ > 0,
      projectRequests: engine.ledger.totals().requests,
      messages: engine.agent.messages,
      partial: this.partial,
      tools: this.tools,
      status: this.status(),
    };
  }

  broadcast(event: ServerEvent): void {
    const line = `${JSON.stringify(event)}\n`;
    for (const client of this.clients) client.write(line);
  }
}

export interface DaemonOptions {
  cwd: string;
  /** Apagarse tras este tiempo sin interfaces ni turnos en curso. 0 = nunca. */
  idleMs?: number;
  /** Al arrancar, retomar solo los turnos que quedaron interrumpidos por una caída. Por defecto sí. */
  autoResume?: boolean;
  /** Sustituciones para pruebas. */
  fetch?: typeof fetch;
  /** Conexión al servidor de correo, sustituible en pruebas. */
  mailConnector?: Connector;
  h1Credentials?: () => { username: string; token: string } | undefined;
  /** Sustituye la resolución de proveedores (pruebas). */
  resolve?: (spec?: string) => Provider;
  engine?: { compactAt?: number; retryBaseMs?: number; cveFeed?: CveFeedOptions | false; chrome?: ChromeBridge; strong?: Provider; resolve?: (spec: string) => Provider; routerModels?: EngineOptions["routerModels"]; autoVerify?: boolean };
  onClose?: () => void;
}

/** Señuelos marcados del proyecto, para el operador. */
function decoyLines(decoys: import("./senuelos.ts").DecoyMarks): string[] {
  const list = decoys.list();
  if (!list.length) return [t("Señuelos marcados en este proyecto: ninguno.", "Decoys marked in this project: none.")];
  return [
    t(`Señuelos marcados en este proyecto (${list.length}): ninguna herramienta de red va ahí.`, `Decoys marked in this project (${list.length}): no network tool goes there.`),
    ...list.map((mark, index) => `  ${index + 1}. ${mark.pattern} — ${mark.reason} · ${mark.by} · ${mark.at.slice(0, 16).replace("T", " ")}`),
  ];
}

export class Daemon {
  readonly options: DaemonOptions;
  readonly path: string;
  readonly hosts = new Map<string, Host>();
  private server: Server | undefined;
  private unlock: (() => void) | undefined;
  private sockets = new Set<Socket>();
  private db: DatabaseSync;
  private view: { db: DatabaseSync; vault: Vault; artifacts: Artifacts; ledger: Ledger; scope: ScopeStore; findings: Findings };
  /** Vinculación por dispositivo en curso (código pedido, clave todavía no reclamada). */
  private device: DeviceStart | undefined;
  private idleTimer: NodeJS.Timeout | undefined;
  private build = buildId();
  closed = false;

  constructor(options: DaemonOptions) {
    this.options = options;
    this.path = socketPath(options.cwd);
    registerProject(options.cwd);
    const paths = projectPaths(options.cwd);
    this.unlock = lockProject(options.cwd); // antes de mudar o respaldar: dos arranques simultáneos no se pisan
    if (process.env.CYBER_TEST_DEMORA_ARRANQUE) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(process.env.CYBER_TEST_DEMORA_ARRANQUE)); // solo pruebas: simula una mudanza larga
    try {
      const moved = migrateLegacy(options.cwd);
      if (moved.pendiente) throw new Error(moved.notice); // con la mudanza sin terminar no se abre la base nueva: se escribiría en el lugar equivocado
      if (moved.notice) process.stderr.write(`${moved.notice}\n`);
      backupOnNewVersion(options.cwd, this.build);
      this.db = openStore(paths);
    } catch (error) {
      this.unlock();
      throw error;
    }
    const artifacts = new Artifacts(this.db, paths.artifacts);
    this.db.exec("create table if not exists consents(kind text primary key, at text not null, hash text not null, pedido text not null, sent_at text, sent_resultado text)");
    this.view = {
      db: this.db,
      vault: new Vault(this.db, paths.records, paths.notes),
      artifacts,
      ledger: new Ledger(this.db),
      scope: new ScopeStore(this.db),
      findings: new Findings(this.db, (hash) => artifacts.find(hash), (hash) => artifacts.read(hash)),
    };
  }

  /** Abre el socket. Falla si ya hay otro daemon vivo en este proyecto. */
  async listen(): Promise<void> {
    try {
      await this.listenSocket();
    } catch (error) {
      this.unlock?.();
      throw error;
    }
  }

  private async listenSocket(): Promise<void> {
    if (existsSync(this.path)) {
      const alive = await new Promise<boolean>((resolve) => {
        const probe = connect(this.path);
        probe.once("connect", () => (probe.destroy(), resolve(true)));
        probe.once("error", () => resolve(false));
      });
      if (alive) throw new Error("Ya hay un daemon de Cyber en este proyecto");
      unlinkSync(this.path); // socket huérfano de un proceso que murió
    }
    this.server = createServer((socket) => this.accept(socket));
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.path, resolve);
    });
    writeFileSync(join(runtimeDir(this.options.cwd), "daemon.pid"), `${process.pid}\n`);
    logEvent(this.db, null, "daemon.started", { pid: process.pid });
    if (this.options.autoResume !== false) this.resumeInterrupted();
    this.armIdle();
  }

  /** Sesiones cuyo último evento de turno fue un inicio: el proceso anterior murió trabajando. */
  interruptedSessions(): string[] {
    return (
      this.db
        .prepare(
          `select s.id from sessions s where (select type from events e where e.session_id=s.id and e.type like 'turn.%' order by e.seq desc limit 1)='turn.started'`,
        )
        .all() as Array<{ id: string }>
    ).map((row) => row.id);
  }

  /** Retoma los turnos interrumpidos con la política de reanudación del agente (lo seguro se repite, lo demás queda desconocido). */
  resumeInterrupted(): string[] {
    const resumed: string[] = [];
    for (const id of this.interruptedSessions()) {
      try {
        const host = this.open({ session: id });
        if (!host.engine.interrupted) continue;
        logEvent(this.db, id, "turn.autoresume", {});
        host.engine.resumeTurn().catch((error: Error) => host.broadcast({ ev: "notice", text: error.message }));
        resumed.push(id);
      } catch (error) {
        logEvent(this.db, id, "turn.autoresume.failed", { error: (error as Error).message });
      }
    }
    return resumed;
  }

  private busy(): boolean {
    return [...this.hosts.values()].some((host) => host.engine.agent.running);
  }

  private armIdle(): void {
    clearTimeout(this.idleTimer);
    if (!this.options.idleMs || this.closed) return;
    this.idleTimer = setTimeout(() => {
      if (this.sockets.size === 0 && !this.busy()) this.close();
      else this.armIdle();
    }, this.options.idleMs);
    this.idleTimer.unref();
  }

  private accept(socket: Socket): void {
    this.sockets.add(socket);
    let host: Host | undefined;
    let pending = "";
    const send = (event: ServerEvent) => socket.write(`${JSON.stringify(event)}\n`);
    send({ ev: "hello", build: this.build, pid: process.pid, busy: this.busy(), clients: this.sockets.size - 1 });
    socket.setEncoding("utf8");
    socket.on("data", async (chunk: string) => {
      pending += chunk;
      let newline: number;
      while ((newline = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (!line.trim()) continue;
        let request: any;
        try {
          request = JSON.parse(line);
          const result = await this.handle(request, host, send);
          if (result instanceof Host) {
            host?.clients.delete(socket);
            host = result;
            host.clients.add(socket);
            const snapshot = host.snapshot();
            // La carpeta compartida se avisa cada vez que se abre; lo de la sesión, sólo la primera.
            // Trazas: el aviso de la primera vez en la máquina (una sola vez) o, en modo local, dónde queda el material.
            const trazas = projectPaths(this.options.cwd).trazas;
            const avisoTrazas = avisoTrazasPrimeraVez(trazas) ?? (host.attached === 1 ? avisoTrazasLocales(trazas) : undefined);
            const avisos = [...[sharedFolderWarning(this.options.cwd), avisoTrazas].filter((text): text is string => !!text), ...(host.attached === 1 ? host.engine.notices : [])];
            send({ ev: "attached", snapshot: avisos.length ? { ...snapshot, avisos } : snapshot });
          } else if (request.id !== undefined) send({ ev: "reply", id: request.id, lines: result ?? [] });
        } catch (error) {
          if (request?.id !== undefined) send({ ev: "reply", id: request.id, error: (error as Error).message });
          else send({ ev: "notice", text: (error as Error).message });
        }
      }
    });
    const gone = () => {
      host?.clients.delete(socket);
      this.sockets.delete(socket);
      this.armIdle();
    };
    socket.on("close", gone);
    socket.on("error", gone);
  }

  private open(request: { session?: string; model?: string; budget?: string; requests?: string; rate?: string; agent?: string; cabeceras?: string[] }): Host {
    const which = request.session ?? "new";
    const existing = which === "new" ? undefined : findSession(this.db, which);
    if (which !== "new" && which !== "last" && !existing) throw new Error(`No existe la sesión ${which}`);
    const cabeceras = new CabecerasPrograma(this.db);
    // Se valida el lote completo antes de persistirlo: un error de formato no deja un cambio parcial.
    for (const linea of request.cabeceras ?? []) leerCabecera(linea);
    for (const linea of request.cabeceras ?? []) cabeceras.poner(linea);
    if (existing && this.hosts.has(existing)) return this.hosts.get(existing)!;
    const stored = existing ? (this.db.prepare("select model from sessions where id=?").get(existing) as { model: string }).model : undefined;
    const provider = (this.options.resolve ?? resolveProvider)(request.model ?? stored);
    // El tope pedido gana; si no se pidió, el que tenía la sesión (también al reanudarla sola tras una
    // caída); sólo una sesión nueva o una vieja que nunca lo guardó arranca con el de fábrica.
    const saved = existing ? storedBudget(this.db, existing) : undefined;
    const budgetPico = request.budget !== undefined ? (request.budget === "sin" ? undefined : usdToPico(request.budget)) : saved !== undefined ? (saved === "sin" ? undefined : saved) : usdToPico(DEFAULT_BUDGET);
    const engine = new Engine({
      cwd: this.options.cwd,
      provider,
      resume: existing ?? false,
      budgetPico,
      httpLimit: amount(request.requests),
      httpRate: amount(request.rate),
      userAgent: request.agent || undefined,
      ...this.options.engine,
    });
    const host = new Host(engine);
    this.hosts.set(engine.sessionId, host);
    return host;
  }

  /**
   * /cves: estado del feed de CVEs nuevos, cruces de la sesión y los últimos críticos. Con una sesión
   * abierta usa su feed (y «actualizar» además cruza); desde la CLI, la sesión de -s o la última, sin cruzar.
   */
  /** El grafo de hechos de una sesión: el del motor si está abierta; si no, uno de sólo lectura sobre la base. */
  private grafoDe(host: Host | undefined, id: string): Grafo {
    if (host?.engine.grafo) return host.engine.grafo;
    const marcas = new DecoyMarks(this.db);
    return new Grafo(this.db, { sesion: id, etiqueta: () => scopeTag(this.view.scope.of(id).current()), alcance: () => this.view.scope.of(id).current(), senuelo: (destino) => !!marcas.match(destino), soloLectura: true });
  }

  /**
   * /grafo y `cyber grafo`: el grafo de hechos de la sesión adjunta, o de la última (o la de -s) en sólo lectura.
   * Las exportaciones van a la carpeta de informes del proyecto.
   */
  private grafo(arg: string, host: Host | undefined, session?: string): string[] {
    const id = host?.engine.sessionId ?? (session ? findSession(this.db, session) : findSession(this.db, "last"));
    if (session && !id) throw new Error(`No existe la sesión ${session}`);
    if (!id) return [t("Todavía no hay sesiones en este proyecto: el grafo se arma mientras el agente trabaja.", "There are no sessions in this project yet: the graph is built while the agent works.")];
    if (host && !host.engine.grafo) return [t("El grafo de hechos está apagado en esta sesión (CYBER_GRAFO=no).", "The fact graph is off in this session (CYBER_GRAFO=no).")];
    const vista = this.grafoDe(host, id).ver();
    const exports = projectPaths(this.options.cwd).exports;
    return comandoGrafo(vista, arg, {
      identidades: host?.engine.http.identityNames(),
      propuestas: (nodo) => propuestasDeEscalada(vista, this.view.findings.get(nodo.id), this.view.scope.of(id).current()),
      guardar: (nombre, texto) => {
        mkdirSync(exports, { recursive: true });
        const ruta = join(exports, nombre);
        writeFileSync(ruta, texto, { mode: 0o600, flag: "wx" });
        return ruta;
      },
    });
  }

  private async cves(arg: string, host: Host | undefined, session?: string): Promise<string[]> {
    const words = arg.split(/\s+/).filter(Boolean);
    const unknown = words.find((word) => !/^(\d+|actualizar|bajar|refresh|update)$/i.test(word));
    if (unknown) throw new Error(t(`No entiendo «${unknown}». Uso: /cves [actualizar] [N]`, `I don't understand «${unknown}». Usage: /cves [actualizar] [N]`));
    const limit = Math.min(50, Math.max(1, Number(words.find((word) => /^\d+$/.test(word)) ?? 10)));
    let feed = host?.engine.cves;
    if (!feed) {
      const id = session ? findSession(this.db, session) : findSession(this.db, "last");
      if (session && !id) throw new Error(`No existe la sesión ${session}`);
      const options = this.options.engine?.cveFeed;
      feed = new CveFeed({ db: this.db, sessionId: id ?? "", scope: () => (id ? this.view.scope.of(id).current() : undefined), artifacts: this.view.artifacts }, options === false ? { enabled: false } : { fetch: this.options.fetch, ...options });
    }
    const lines: string[] = [];
    if (words.some((word) => /^(actualizar|bajar|refresh|update)$/i.test(word))) {
      const result = await feed.refresh(true);
      lines.push(result.salteado ? t(`No bajé el feed: ${result.salteado}.`, `Did not download the feed: ${result.salteado}.`) : result.ok ? t(`Feed bajado: ${result.nuevos} CVE${result.nuevos === 1 ? "" : "s"} nuevo${result.nuevos === 1 ? "" : "s"} en la caché${result.error ? ` (con error: ${result.error})` : ""}.`, `Feed downloaded: ${result.nuevos} new CVE${result.nuevos === 1 ? "" : "s"} cached${result.error ? ` (with error: ${result.error})` : ""}.`) : t(`No pude bajar el feed: ${result.error}.`, `Could not download the feed: ${result.error}.`));
      if (host) {
        const told = await feed.cross();
        if (told) lines.push(t(`${told} cruce${told === 1 ? "" : "s"} nuevo${told === 1 ? "" : "s"} con esta sesión: avisado${told === 1 ? "" : "s"} y para el próximo turno del agente.`, `${told} new match${told === 1 ? "" : "es"} with this session: reported and queued for the agent's next turn.`));
      }
    }
    const view = feed.view(limit);
    return [view[0]!, ...lines, ...view.slice(1)];
  }

  /** Qué pasa en vivo con una sesión abierta en este daemon, si lo está. */
  private liveState(id: string): { running: boolean; interrupted: boolean } | undefined {
    const live = this.hosts.get(id);
    return live ? { running: live.engine.agent.running, interrupted: live.engine.interrupted } : undefined;
  }

  /**
   * Alcance al que apunta un pedido: el de la sesión adjunta; sin interfaz adjunta (la CLI), el de la
   * sesión que nombra «session» o el de la última. El alcance es de cada sesión: sin sesiones no hay
   * dónde cargarlo.
   */
  private scopeFor(request: { session?: string }, host: Host | undefined): { store: ScopeStore; label?: string } {
    if (host) return { store: host.engine.scope };
    const id = findSession(this.db, request.session ? String(request.session) : "last");
    if (!id) {
      if (request.session) throw new Error(`No existe la sesión ${request.session}`);
      throw new Error(t("No hay sesiones en este proyecto y el alcance es de cada sesión: abrí una (cyber) y cargalo ahí con /alcance o pidiéndoselo al agente.", "There are no sessions in this project and scope belongs to each session: open one (cyber) and load it there with /scope or by asking the agent."));
    }
    const title = (this.db.prepare("select title from sessions where id=?").get(id) as { title: string | null } | undefined)?.title;
    return { store: this.hosts.get(id)?.engine.scope ?? this.view.scope.of(id), label: t(`Sesión ${id.slice(0, 8)}${title ? ` «${title.slice(0, 60)}»` : ""} (otra: -s <id>)`, `Session ${id.slice(0, 8)}${title ? ` “${title.slice(0, 60)}”` : ""} (another: -s <id>)`) };
  }

  /** El alcance vigente de cada sesión del proyecto, una línea por sesión: para que el operador vea qué programa tiene cada una. */
  private scopeSessions(current?: string): string[] {
    const rows = this.db
      .prepare("select s.id, s.title, (select json from scope c where c.session_id=s.id order by c.rev desc limit 1) json, (select max(rev) from scope c where c.session_id=s.id) rev from sessions s order by s.started_at desc limit 40")
      .all() as Array<{ id: string; title: string | null; json: string | null; rev: number | null }>;
    const lines = rows.filter((row) => row.json).map((row) => {
      const scope = JSON.parse(row.json!) as { source: string; include: Array<{ value: string }> };
      const hosts = scope.include.slice(0, 3).map((rule) => rule.value).join(", ") || t("vacío", "empty");
      return `${row.id === current ? "▸" : " "} ${row.id.slice(0, 8)}  rev ${row.rev}  ${scope.source.padEnd(24)} ${hosts}${scope.include.length > 3 ? ", …" : ""}${row.title ? `  · ${row.title.slice(0, 40)}` : ""}`;
    });
    const legacy = this.view.scope.current();
    return [
      t("ALCANCE POR SESIÓN", "SCOPE PER SESSION"),
      ...(lines.length ? lines : [t("  ninguna sesión tiene alcance todavía", "  no session has a scope yet")]),
      ...(legacy?.include.length ? [t(`Alcance viejo del proyecto (de antes de que fuera por sesión): rev ${legacy.rev} · ${legacy.source}. Una sesión lo toma con /alcance recuperar ${legacy.rev}.`, `Old project scope (from before it was per session): rev ${legacy.rev} · ${legacy.source}. A session takes it with /scope recuperar ${legacy.rev}.`)] : []),
    ];
  }

  /** Devuelve la sesión a adjuntar, las líneas de una respuesta, o nada. */
  private async hackerone(request: { action?: string; handle?: string; session?: string }, host?: Host): Promise<string[]> {
    const credentials = (this.options.h1Credentials ?? loadCredentials)();
    // Sin token, el alcance de un programa público sale de su CSV; la lista de programas sí necesita el token.
    if (request.action === "alcance") {
      if (!request.handle) throw new Error("Falta el programa: cyber h1 alcance <programa>");
      const { store, label } = this.scopeFor(request, host);
      const api = credentials ? new HackerOne(credentials, this.options.fetch) : undefined;
      return [...(label ? [label] : []), ...(await importScope(api, store, programHandle(request.handle), this.options.fetch))];
    }
    if (!credentials) throw new Error("Falta iniciar sesión en HackerOne: usá /hackerone (o cyber hackerone). Sin token igual podés cargar el alcance de un programa público: /h1 alcance <programa>.");
    const api = new HackerOne(credentials, this.options.fetch);
    return [...programLines(await api.programs(), request.action, request.handle), "Buscar: cyber h1 buscar <texto> · todos: cyber h1 todos · cargar el alcance: cyber h1 alcance <programa> · o pedíselo al agente: «vamos con el programa X»"];
  }

  /** Estado, alta y baja de credenciales. El secreto llega sólo en `value` y nunca se registra ni se devuelve. */
  /** Casillas de correo de prueba: estado, agregar (se prueba antes de guardar) y quitar. La contraseña sólo viaja acá. */
  private async mailAccount(request: { action?: string; address?: string; value?: string; host?: string; alias?: string }): Promise<string[]> {
    const list = mailboxes();
    if (request.action === "status") return list.length ? list.map((box) => `${box.direccion}${box.alias ? ` (se registra como ${box.alias})` : ""} · ${box.host}`) : [t("sin vincular", "not linked")];
    const address = String(request.address ?? "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) throw new Error(t("Falta la dirección de la casilla.", "Missing mailbox address."));
    if (request.action === "remove") {
      saveMailboxes(list.filter((box) => box.direccion !== address));
      return [t(`Casilla ${address} quitada de esta máquina.`, `Mailbox ${address} removed from this machine.`)];
    }
    if (request.action !== "add") throw new Error("Acción desconocida");
    const value = String(request.value ?? "").trim();
    if (!value) throw new Error(t("Falta la contraseña de aplicación.", "Missing app password."));
    const alias = String(request.alias ?? "").trim().toLowerCase();
    if (alias && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(alias)) throw new Error(t("El alias no es una dirección válida.", "The alias is not a valid address."));
    const box: Mailbox = { direccion: address, clave: value, host: String(request.host ?? "").trim() || await detectHost(address), puerto: 993, ...(alias && { alias }) };
    const count = await testMailbox(box, this.options.mailConnector);
    saveMailboxes([...list.filter((item) => item.direccion !== address), box]);
    return [t(`Listo: la casilla ${address} abre (${count} mensajes en la bandeja) y quedó guardada, cifrada. El agente sólo lee los mails que lleguen a las direcciones de prueba que él mismo genere.`, `Done: mailbox ${address} opens (${count} messages in the inbox) and was saved, encrypted. The agent only reads mail sent to the test addresses it generates.`)];
  }

  private async account(request: { service?: string; action?: string; value?: string; username?: string }): Promise<string[]> {
    const { service, action } = request;
    if (service !== "orobas" && service !== "hackerone") throw new Error("Servicio desconocido: orobas o hackerone");
    const orobas = service === "orobas";
    const override = orobas && process.env.OROBAS_API_KEY
      ? [t("Tenés OROBAS_API_KEY definida en la terminal y gana sobre esta clave; quitala para usar la guardada", "You have OROBAS_API_KEY set in your terminal and it wins over this key; unset it to use the stored one")]
      : [];
    const status = (): string => {
      const name = orobas ? "orobas" : "hackerone";
      if (secretState(name) === "locked") return t("cifrada, llavero bloqueado", "encrypted, keyring locked");
      if (orobas) {
        const key = readSecret("orobas");
        return key ? t(`clave cargada (termina en …${key.slice(-4)})`, `key loaded (ends in …${key.slice(-4)})`) : t("sin vincular", "not linked");
      }
      const credentials = loadCredentials();
      return credentials ? t(`vinculado como ${credentials.username}`, `linked as ${credentials.username}`) : t("sin vincular", "not linked");
    };
    let lines: string[];
    if (action === "status") lines = [status()];
    else if (orobas && action === "device_start") {
      // Entrar por el sitio: el código se muestra y la clave llega sola cuando la persona aprueba.
      this.device = await startDeviceLink(`Elevate AI Cyber ${CLIENT_VERSION} en ${hostname()}`, this.options.fetch);
      lines = [
        t(`Abrí ${this.device.verification_uri_complete} y entrá con tu llave.`, `Open ${this.device.verification_uri_complete} and sign in with your key.`),
        t(`Código: ${this.device.user_code}`, `Code: ${this.device.user_code}`),
        t(`Vence en ${Math.round(this.device.expires_in / 60)} minutos. Cuando apruebes, la clave llega sola acá.`, `Expires in ${Math.round(this.device.expires_in / 60)} minutes. Once you approve, the key arrives here on its own.`),
      ];
    } else if (orobas && action === "device_wait") {
      if (!this.device) throw new Error(t("No hay una vinculación en curso: empezá con «Entrar por el sitio».", "No link in progress: start with “Sign in on the site”."));
      const pending = this.device;
      const outcome = await waitDeviceKey(pending, { fetchImpl: this.options.fetch });
      this.device = undefined;
      if (outcome.state !== "listo") throw new Error(outcome.detail);
      const saved = writeSecret("orobas", outcome.key);
      lines = [
        t(`Vinculado${outcome.name ? ` como ${outcome.name}` : ""}: clave nueva guardada${saved.encrypted ? ", cifrada" : ""} (termina en …${outcome.key.slice(-4)}).`, `Linked${outcome.name ? ` as ${outcome.name}` : ""}: new key saved${saved.encrypted ? ", encrypted" : ""} (ends in …${outcome.key.slice(-4)}).`),
        t("La podés ver y revocar en cyber.elevateai.ar/cuenta.", "You can see and revoke it at cyber.elevateai.ar/cuenta."),
      ];
    } else if (action === "revoke") {
      if (orobas) deleteSecret("orobas");
      else clearCredentials();
      lines = [t("Credenciales borradas de esta máquina.", "Credentials deleted from this machine.")];
    } else if (action === "save") {
      const value = String(request.value ?? "").trim();
      if (!value) throw new Error(t("Falta el valor.", "Missing value."));
      // shortcut: orobas no tiene un endpoint barato de validación; si la clave es mala, el primer turno lo dice.
      if (orobas) lines = [writeSecret("orobas", value).encrypted ? t("Clave guardada, cifrada.", "Key saved, encrypted.") : t("Clave guardada.", "Key saved.")];
      else {
        const username = String(request.username ?? "").trim();
        if (!username) throw new Error(t("Falta el usuario.", "Missing username."));
        const programs = await new HackerOne({ username, token: value }, this.options.fetch).programs();
        const where = saveCredentials({ username, token: value });
        lines = [t(`Listo: credenciales válidas, guardadas ${where}. ${programs.length} programas accesibles.`, `Done: valid credentials, saved ${where}. ${programs.length} programs accessible.`)];
      }
    } else throw new Error("Acción desconocida: status, save o revoke");
    for (const host of this.hosts.values()) host.broadcast({ ev: "status", status: host.status() });
    return [...lines, ...override];
  }

  /** Estado, vinculación por dispositivo y revocación de una plataforma. `link` termina cuando la CLI sale. */
  private async platformAccount(request: { name?: string; action?: string }, send: (event: ServerEvent) => void): Promise<string[]> {
    const spec = platform(String(request.name ?? ""));
    if (request.action === "status") {
      const state = await platformState(spec);
      return [!state.installed ? t(`sin instalar: ${spec.install}`, `not installed: ${spec.install}`) : state.linked === false ? t("sin vincular", "not linked") : t(`vinculada${state.account ? ` · ${state.account}` : ""}`, `linked${state.account ? ` · ${state.account}` : ""}`)];
    }
    if (request.action === "revoke") return revokePlatform(spec.name);
    if (request.action !== "link") throw new Error("Acción desconocida: status, link o revoke");
    if (!findBinary(spec.binary)) throw new Error(t(`Falta instalar ${spec.binary}. ${spec.install}`, `${spec.binary} is not installed. ${spec.install}`));
    if (!spec.device) return [t(`${spec.label} no tiene login por dispositivo: corré «cyber login ${spec.name}» en tu terminal${spec.env.length ? ` o definí ${spec.env[0]}` : ""}.`, `${spec.label} has no device login: run "cyber login ${spec.name}" in your terminal${spec.env.length ? ` or set ${spec.env[0]}` : ""}.`)];
    const { child, found, output } = await startDevice(spec);
    if (!found.url) {
      child.kill("SIGTERM");
      throw new Error(t(`No pude iniciar el login de ${spec.label}: ${redactSecrets(output()).trim().slice(-300) || "sin salida"}`, `Could not start the ${spec.label} login: ${redactSecrets(output()).trim().slice(-300) || "no output"}`));
    }
    send({ ev: "notice", text: t(`Para vincular ${spec.label}: abrí ${found.url}${found.code ? ` e ingresá el código ${found.code}` : ""} y aprobá el acceso.`, `To link ${spec.label}: open ${found.url}${found.code ? ` and enter the code ${found.code}` : ""} and approve access.`) });
    await new Promise<void>((done) => (child.exitCode === null ? child.once("exit", () => done()) : done()));
    return [`${spec.label}: ${(await platformState(spec)).linked ? t("vinculada.", "linked.") : t("no quedó vinculada.", "not linked.")}`];
  }

  private async handle(request: any, host: Host | undefined, send: (event: ServerEvent) => void): Promise<Host | string[] | undefined> {
    const need = (): Host => {
      if (!host) throw new Error("Primero hay que adjuntarse a una sesión");
      return host;
    };
    switch (request.op) {
      case "attach":
        return this.open(request);
      case "send": {
        const { engine } = need();
        const text = String(request.text ?? "");
        if (request.interrupt === true) {
          // «Mandalo ya»: corta el turno en curso de forma ordenada y el mensaje (con la cola) sale enseguida.
          engine.interrupt(text).catch((error: Error) => need().broadcast({ ev: "notice", text: error.message }));
          need().broadcast({ ev: "status", status: need().status() });
          return undefined;
        }
        if (engine.agent.running) {
          // Durante un turno: «¿cómo vamos?» se contesta al instante; «!…» interrumpe al modelo con el
          // mensaje; todo lo demás se encola y sale junto como el turno siguiente.
          if (text.startsWith("!") && text.length > 1) {
            const reply = engine.steer(text.slice(1).trim());
            if (reply) need().broadcast({ ev: "answer", text: reply });
          } else if (isStatusPing(text)) {
            const reply = engine.steer(text);
            if (reply) need().broadcast({ ev: "answer", text: reply });
          } else {
            const { repeated } = engine.enqueue(text);
            if (repeated) send({ ev: "answer", text: t("Ese mensaje ya estaba en cola: no lo encolé de nuevo. Ctrl+Y (o /ya) lo manda ya.", "That message was already queued: not queued again. Ctrl+Y (or /ya) sends it now.") });
            need().broadcast({ ev: "status", status: need().status() });
          }
        } else {
          engine.send(text).catch((error: Error) => need().broadcast({ ev: "notice", text: error.message }));
          if (engine.lastRecall.length) need().broadcast({ ev: "recall", ids: engine.lastRecall.map((hit) => hit.id) });
        }
        return undefined;
      }
      case "datos":
      case "trazas": {
        // Modo de trazas (compartir, local o no), dónde quedan las locales y subir lo de antes. «trazas» es la
        // fila de /config: sin valor muestra el estado y con valor lo cambia.
        const store = new ConsentStore(this.view.db);
        const value = String(request.value ?? "").trim().toLowerCase();
        const action = String(request.action ?? (value ? "modo" : "status"));
        const key = apiKey("OROBAS_API_KEY");
        const dir = projectPaths(this.options.cwd).trazas;
        const sessionId = host?.engine?.sessionId ?? null;
        if (action === "modo" || action === "revoke") {
          const modo = action === "revoke" ? "no" : leerModo(value);
          if (!modo || (action === "modo" && !(MODOS_TRAZAS as readonly string[]).includes(value))) throw new Error("Modos de trazas: compartir, local o no.");
          const aviso = guardarModoTrazas(modo);
          logEvent(this.db, sessionId, "trazas.modo", { modo });
          // Elegir «compartir» a mano queda como permiso explícito también en el servicio (deshace un «trayectorias-no» de antes).
          let nota = "";
          if (modo === "compartir" && key) {
            const saved = store.grant(SHARE_KIND, SHARE_SENTENCE);
            try { store.markSent(SHARE_KIND, await sendConsent(SHARE_KIND, saved.pedido, saved.hash, saved.at, key)); }
            catch (error) { nota = ` No pude registrarlo en el servicio (${String((error as Error).message).slice(0, 80)}); el modo rige igual.`; }
          }
          await refrescarModoCuenta();
          return [`${t(`Trazas: «${modo}».`, `Traces: “${modo}”.`)}${nota}`, ...(aviso ? [aviso] : []), ...lineasTrazas(dir)];
        }
        if (action === "share") {
          // Subir ahora las sesiones anteriores del proyecto: sólo en «compartir».
          await refrescarModoCuenta();
          if (!comparteConServicio()) throw new Error(t(`Las trazas están en «${modoTrazas()}»: no se sube nada. Para compartir: /datos compartir.`, `Traces are in “${modoTrazas()}” mode: nothing is uploaded. To share: /datos compartir.`));
          if (!key) throw new Error("Falta la clave de orobas: usá /orobas.");
          const { lines } = buildTrajectories(
            { db: this.db, ledger: host?.engine.ledger ?? this.view.ledger, findings: this.view.findings, scope: this.view.scope.project(), sessionScope: (id) => this.view.scope.of(id).current() },
            basename(this.options.cwd),
            { anonymize: true, system: SYSTEM_PROMPT, redact: (text, de) => { for (const live of this.hosts.values()) text = live.engine.http.redactIdentities(live.engine.secretos.vistaTrazas(text, origenDeTraza(de))); return text; } },
          );
          const outcome = await shareTrajectories(lines, { apiKey: key, base: orobasBaseUrl(), consentHash: store.get(SHARE_KIND)?.hash });
          logEvent(this.db, sessionId, "datos.compartido", { sesiones: outcome.sent, fallidas: outcome.failed });
          return [
            `Subidas ${outcome.sent} de ${lines.length} sesiones (anónimas, credenciales tachadas).`,
            ...(outcome.errors.length ? [`No se pudieron subir ${outcome.failed}:`, ...outcome.errors.map((line) => `- ${line}`)] : []),
          ];
        }
        await refrescarModoCuenta();
        return lineasTrazas(dir);
      }
      case "queue": {
        const { engine } = need();
        const action = String(request.action ?? "list");
        if (action === "clear") {
          const dropped = engine.clearQueue();
          need().broadcast({ ev: "status", status: need().status() });
          return [dropped.length ? `Cola vaciada: ${dropped.length} mensaje${dropped.length === 1 ? "" : "s"} descartado${dropped.length === 1 ? "" : "s"}.` : "La cola ya estaba vacía."];
        }
        if (action === "ya") {
          if (!engine.queue.length) return [t("Nada en cola para mandar.", "Nothing queued to send.")];
          const count = engine.queue.length;
          engine.interrupt().catch((error: Error) => need().broadcast({ ev: "notice", text: error.message }));
          need().broadcast({ ev: "status", status: need().status() });
          return [t(`Corto el turno y mando ya ${count === 1 ? "el mensaje en cola" : `los ${count} mensajes en cola`}.`, `Stopping the turn and sending ${count === 1 ? "the queued message" : `the ${count} queued messages`} now.`)];
        }
        if (!engine.queue.length) return [engine.agent.running ? t("Nada en cola. Lo que escribas ahora espera a que termine el turno; Ctrl+Y (o /ya) lo manda cortando el turno; con «!» adelante le llega al modelo sin cortarlo.", "Nothing queued. What you type now waits for the turn to end; Ctrl+Y (or /ya) sends it by stopping the turn; with «!» in front it reaches the model without stopping it.") : t("Nada en cola y ningún turno en curso: lo que escribas sale de inmediato.", "Nothing queued and no turn running: what you type goes out right away.")];
        return [`${engine.queue.length} mensaje${engine.queue.length === 1 ? "" : "s"} en cola, salen juntos cuando termine el turno:`, ...engine.queue.map((text, index) => `${index + 1}. ${text.replace(/\s+/g, " ").slice(0, 160)}`)];
      }
      case "resume": {
        const { engine } = need();
        if (!engine.interrupted) throw new Error("No hay un turno interrumpido para continuar");
        engine.resumeTurn().catch((error: Error) => need().broadcast({ ev: "notice", text: error.message }));
        return undefined;
      }
      case "abort":
        need().engine.abort();
        return undefined;
      case "budget": {
        const { ledger } = need().engine;
        if (request.value) ledger.budgetPico = request.value === "sin" ? undefined : usdToPico(request.value);
        need().broadcast({ ev: "status", status: need().status() });
        return [ledger.budgetPico === undefined ? "Sesión sin tope de gasto." : `Tope de sesión: USD ${usd(ledger.budgetPico, 2)}. Uso: /presupuesto <USD> o /presupuesto sin`];
      }
      case "tope": {
        const ledger = host?.engine.ledger ?? this.view.ledger;
        if (request.value) ledger.setProjectBudget(request.value === "sin" ? undefined : usdToPico(request.value));
        const cap = ledger.projectBudget();
        return [cap === undefined ? "Proyecto sin tope de gasto. Fijarlo: cyber tope <USD>" : `Tope del proyecto: USD ${usd(cap, 2)} · gastado hasta ahora USD ${usd(ledger.knownPicoAll())} entre todas las sesiones. Quitarlo: cyber tope sin`];
      }
      case "verify": {
        const { engine } = need();
        const which = String(request.value ?? "").trim();
        if (engine.agent.running) throw new Error("Esperá a que termine el turno en curso");
        // La verificación automática del cierre del turno corre con el agente ya quieto: no se larga otra en
        // paralelo sobre los mismos candidatos (sus eventos se mezclaban y parecía que verificaba otra cosa).
        const waited = !!engine.autoVerification;
        if (engine.autoVerification) await engine.autoVerification.catch(() => undefined);
        const after = waited ? ["Esperé a que terminara la verificación automática del cierre del turno."] : [];
        // Sin id: los candidatos de esta sesión. Con id, exactamente ése, de cualquier sesión del proyecto (lo
        // elige el operador): si no existe o el prefijo es ambiguo, el error lista los ids que sí; nunca se toma otro.
        const target = which && which !== "todos" ? engine.findings.resolve(which, { sessionId: engine.sessionId, state: "candidato" }) : undefined;
        if (target && target.state !== "candidato") return [`${target.id.slice(0, 8)}  ya está como ${target.state}${target.decidedBy.startsWith("verificador") ? ` (lo decidió ${target.decidedBy})` : ""}${target.reason ? `: ${target.reason}` : ""}. Sólo se verifican candidatos.`, ...after];
        const pending = engine.verifier.pending().length;
        const results = target ? [await engine.verifier.verify(target.id).catch((error: Error) => ({ finding: target, error: error.message }))] : await engine.verifier.verifyAll();
        if (!results.length) return ["No hay candidatos de esta sesión pendientes de verificación. Uno de otra sesión: /verificar <id>."];
        const lines = results.map((result) => ("error" in result ? `${result.finding.id.slice(0, 8)}  no terminó: ${result.error}` : `${result.finding.id.slice(0, 8)}  ${result.state.padEnd(10)} ${result.reason}  [${result.requests} solicitudes, USD ${result.costUsd}]`));
        lines.push(...after);
        const stopped = results.some((result) => "error" in result && "exhausted" in result && result.exhausted);
        return stopped ? [...lines, `Corté la tanda: el proveedor no tiene saldo. Quedan ${Math.max(0, pending - results.length + 1)} sin verificar.`] : lines;
      }
      case "requests": {
        const { http } = need().engine;
        if (request.value) http.limit = amount(request.value);
        const { limit, program } = http.conduct();
        const origin = http.limit === undefined && program ? ` (por defecto para el programa ${program})` : "";
        return [limit === undefined ? `Sin tope de peticiones HTTP (${http.count} enviadas).` : `Tope de peticiones HTTP: ${limit}${origin}; enviadas ${http.count}. Uso: /peticiones <N> o /peticiones sin`];
      }
      case "rate": {
        const { http } = need().engine;
        if (request.value) http.rate = amount(request.value);
        const { rate, program } = http.conduct();
        const origin = http.rate === undefined && program ? ` (por defecto para el programa ${program})` : "";
        return [rate === undefined ? "Sin ritmo máximo de peticiones." : `Ritmo máximo: ${rate} peticiones por segundo${origin}. Uso: /ritmo <N> o /ritmo sin`];
      }
      case "model": {
        const { engine } = need();
        const value = String(request.value ?? "").trim();
        const short = (spec: string) => spec.slice(spec.indexOf("/") + 1);
        if (value) {
          const spec = await engine.setModel(value);
          need().broadcast({ ev: "status", status: need().status() });
          const cost = engine.stepCost();
          return [`Modelo de la sesión: ${spec}. Desde la próxima solicitud; el razonamiento elegido se mantiene. La primera respuesta tarda más: el modelo nuevo lee toda la conversación sin caché.`, ...(cost ? [`Costo: ${cost.text}.${cost.expensive ? ` Es caro para el bucle: conviene un base barato y éste como fuerte (/modelo fuerte ${short(spec)}).` : ""}`] : [])];
        }
        const { current, models, others } = await engine.availableModels();
        const cost = engine.stepCost();
        return [
          `Modelo actual: ${current}${cost ? ` · ${cost.text}` : ""}`,
          `Modelo fuerte (deep_reason y delegate con strong): ${engine.strongSpec()}`,
          `Disponibles: ${models.map((spec) => (spec === current ? `${short(spec)} (actual)` : short(spec))).join(" · ") || "los que declare la configuración"}`,
          ...(others.length ? [`Otros proveedores listos: ${others.join(", ")} (con /modelo proveedor/modelo)`] : []),
          "Cambiar: /modelo <nombre>, por ejemplo /modelo glm; el fuerte, /modelo fuerte <nombre>. También se lo podés pedir al agente.",
        ];
      }
      case "strong": {
        // Modelo fuerte: el que consultan deep_reason y delegate con strong. «defecto» vuelve al de fábrica.
        const { engine } = need();
        const value = String(request.value ?? "").trim();
        if (value) {
          const spec = await engine.setStrongModel(value);
          return [`Modelo fuerte de la sesión: ${spec}. Lo usan deep_reason y delegate con strong; el bucle sigue con ${engine.agent.model.provider}/${engine.agent.model.id}.`];
        }
        return [`Modelo fuerte: ${engine.strongSpec()} · base (bucle): ${engine.agent.model.provider}/${engine.agent.model.id}`, "Cambiar: /modelo fuerte <nombre> o /modelo fuerte defecto."];
      }
      case "models": {
        // Para el selector de la TUI: una fila por modelo con nombre, tipo, contexto, tarifa y estado, separados por tabulador.
        const { engine } = need();
        const { current, models, others, details } = await engine.availableModels();
        const cell = (value: unknown) => String(value ?? "").replace(/[\t\n]/g, " ");
        return [
          `current\t${current}`,
          ...models.map((spec) => { const d = details[spec]; return ["model", spec, d?.name, d?.kind, d?.context, d?.price, d?.status].map(cell).join("\t"); }),
          ...others.map((provider) => `other\t${provider}`),
        ];
      }
      case "mcp": {
        const { engine } = need();
        const action = String(request.action ?? "status");
        const name = String(request.name ?? "").trim();
        if (action === "status") return engine.mcp.status().map((server) => [server.name, server.command, server.state, server.tools ?? "", server.error ?? ""].join("\t"));
        if (!/^[a-zA-Z0-9_-]+$/.test(name)) throw new Error("Nombre de servidor MCP inválido: letras, números, guion y guion bajo.");
        if (action === "probe") {
          const tools = await engine.mcp.tools(name, AbortSignal.timeout(30_000));
          return [`${name}: ${tools.length} herramienta${tools.length === 1 ? "" : "s"}: ${tools.map((tool) => tool.name.slice(name.length + 1)).join(", ") || "ninguna"}`];
        }
        if (action === "add") {
          const command = String(request.command ?? "").trim();
          const args = Array.isArray(request.args) ? request.args.map(String) : [];
          if (!command) throw new Error("Falta el comando del servidor MCP.");
          engine.mcp.add(name, { command, args });
          guardarMcp(engine.mcp.all());
          return [`Servidor MCP «${name}» agregado: ${[command, ...args].join(" ")}. Sus herramientas se descubren con tool_search; guardado en ${configPath()}.`];
        }
        if (action === "remove") {
          if (!engine.mcp.names().includes(name) && !Object.hasOwn(engine.mcp.all(), name)) throw new Error(`No existe el servidor MCP «${name}».`);
          await engine.mcp.remove(name);
          guardarMcp(engine.mcp.all());
          return [`Servidor MCP «${name}» quitado y cerrado. Guardado en ${configPath()}.`];
        }
        throw new Error("Uso: /mcp · /mcp agregar <nombre> <comando> [args] · /mcp probar <nombre> · /mcp quitar <nombre>");
      }
      case "decoys": {
        const { http } = need().engine;
        const value = String(request.value ?? "").trim().toLowerCase();
        if (/^(permitir|si|sí|on)$/.test(value)) http.decoysAllowed = true;
        else if (/^(bloquear|no|off)$/.test(value)) http.decoysAllowed = false;
        else if (value) throw new Error("Uso: /senuelos permitir | bloquear");
        return [`Señuelos detectados en esta sesión: ${http.decoysSeen}. Seguir sus rutas y usar sus credenciales: ${http.decoysAllowed ? "permitido (lo habilitaste vos)" : "bloqueado"}. Uso: /senuelos permitir | bloquear`, ...decoyLines(need().engine.decoys), t("Marcar: /senuelos marcar <host | *.dominio | URL | /ruta> [motivo] · quitar: /senuelos quitar <patrón | n> · ver: /senuelos lista", "Mark: /senuelos marcar <host | *.domain | URL | /path> [reason] · remove: /senuelos quitar <pattern | n> · list: /senuelos lista")];
      }
      case "decoy_marks": {
        // Señuelos que marca el operador: por proyecto, y ninguna herramienta de red va ahí. Op aparte
        // de «decoys» porque ese valor se recuerda como ajuste y una marca no se repite al abrir.
        const { engine } = need();
        const value = String(request.value ?? "").trim();
        const [verb = "", ...rest] = value.split(/\s+/);
        const usage = t("Uso: /senuelos marcar <host | *.dominio | URL | /ruta> [motivo] · /senuelos quitar <patrón | n> · /senuelos lista", "Usage: /senuelos marcar <host | *.domain | URL | /path> [reason] · /senuelos quitar <pattern | n> · /senuelos lista");
        if (!verb || /^(lista|listar|ver|list|marcados)$/i.test(verb)) return [...decoyLines(engine.decoys), usage];
        if (/^(marcar|mark|agregar|add)$/i.test(verb)) {
          const [pattern, ...reason] = rest;
          if (!pattern) throw new Error(usage);
          const mark = engine.decoys.add({ pattern, reason: reason.join(" "), by: "operador", session: engine.sessionId });
          return [t(`Marcado como señuelo: ${mark.pattern} (${mark.reason}). Ninguna herramienta de red va ahí y el agente lo ve en su contexto.`, `Marked as decoy: ${mark.pattern} (${mark.reason}). No network tool goes there and the agent sees it in its context.`), ...decoyLines(engine.decoys)];
        }
        if (/^(quitar|sacar|desmarcar|unmark|remove)$/i.test(verb)) {
          if (!rest.length) throw new Error(usage);
          const gone = engine.decoys.remove(rest.join(" "));
          if (!gone) throw new Error(t(`No hay un señuelo marcado «${rest.join(" ")}». /senuelos lista para verlos.`, `No marked decoy «${rest.join(" ")}». /senuelos lista to see them.`));
          return [t(`Quitado: ${gone.pattern}. Las herramientas vuelven a poder ir ahí si el alcance lo permite.`, `Removed: ${gone.pattern}. Tools can go there again if the scope allows it.`), ...decoyLines(engine.decoys)];
        }
        throw new Error(usage);
      }
      case "reasoning": {
        const { engine } = need();
        const value = String(request.value ?? "").trim();
        const caps = capsOf(engine.agent.model);
        if (value) {
          const chosen = parseReasoning(value);
          if (!chosen) throw new Error(`Uso: /razonamiento ${reasoningUsage(caps)}`);
          engine.setReasoning(chosen.value);
        }
        return [reasoningStatus(engine.agent.model.reasoning, engine.agent.model.id, caps)];
      }
      case "router": {
        // Router de modelos: sin valor (o «estado»), el panel; «auto» o «fijo» lo cambian.
        const { engine } = need();
        const value = String(request.value ?? "").trim().toLowerCase();
        if (/^(auto|automatico|automático)$/.test(value)) engine.setRouter("auto");
        else if (/^(fijo|fixed|off|no)$/.test(value)) engine.setRouter("fijo");
        else if (value && !/^(estado|status)$/.test(value)) throw new Error(t("Uso: /router auto | fijo | estado · /router medio <modelo> | no", "Usage: /router auto | fijo | estado · /router medio <model> | no"));
        if (value) need().broadcast({ ev: "status", status: need().status() });
        return engine.routerStatus();
      }
      case "investigar": {
        // Modo investigar: sin valor (o «estado»), el panel; «pausa», «seguir [usd]», «cerrar»; otra cosa abre una.
        const { engine } = need();
        if (!engine.investigar) throw new Error(t("El modo investigar está apagado en esta sesión.", "Investigation mode is off in this session."));
        const lines = await engine.investigar.comando(String(request.value ?? ""));
        need().broadcast({ ev: "status", status: need().status() });
        return lines;
      }
      case "router_medio": {
        // Modelo medio del router: lee y razona sobre código con un traspaso. Opcional.
        const { engine } = need();
        const value = String(request.value ?? "").trim();
        const spec = value ? await engine.setMediumModel(value) : engine.mediumSpec();
        return [
          spec ? t(`Modelo medio del router: ${spec}. Lee código sobre un traspaso cuando la sesión es de revisión de código o de una app móvil.`, `Router mid model: ${spec}. It reads code on a handoff when the session is a code review or a mobile app.`) : t("Sin modelo medio: el código lo lee el ejecutor.", "No mid model: the executor reads the code."),
          t("Uso: /router medio <modelo> | no | defecto", "Usage: /router medio <model> | no | defecto"),
        ];
      }
      case "verificacion": {
        // Cuándo corre solo el verificador: ajuste del operador, en config.json (vale para todos los proyectos).
        const value = String(request.value ?? "").trim();
        if (value) {
          const chosen = parseVerifySetting(value);
          if (!chosen) throw new Error("Uso: /verificacion automatica | a-pedido | tope <USD>");
          saveVerifySetting(chosen);
        }
        return [verifySettingLine(readVerifySetting())];
      }
      case "investigation_auto": {
        const { engine } = need();
        const value = String(request.value ?? "").trim().toLowerCase();
        if (value) {
          if (!/^(si|sí|no)$/.test(value)) throw new Error("Uso: /investigacion-auto si | no");
          engine.setInvestigationAuto(value !== "no");
        }
        return [`Investigación automática: ${engine.investigationAuto ? "activa" : "apagada"}. Uso: /investigacion-auto si | no`];
      }
      case "scanners": {
        const { http } = need().engine;
        if (request.value) http.scanners = /^(si|sí|on)$/i.test(request.value) ? true : /^(no|off)$/i.test(request.value) ? false : http.scanners;
        const { scanners, program } = http.conduct();
        return [`Escáneres externos (nmap, ffuf, sqlmap, nuclei, katana, httpx): ${scanners ? "habilitados" : "apagados"}${http.scanners === undefined && program ? ` (por defecto para el programa ${program}: revisá su política antes de habilitarlos)` : ""}. Uso: /escaneres si | no`];
      }
      case "perfil": {
        // Sin sesión adjunta igual se ve el perfil del proyecto (es de proyecto, no de sesión); cambiarlo con sesión lo aplica al engine.
        const value = String(request.value ?? "").trim().toLowerCase();
        if (value) {
          const profile = parseProfile(value);
          if (!profile) throw new Error("Uso: /perfil bounty | pentest | laboratorio | defensa");
          if (host?.engine) host.engine.setProfile(profile);
          else new ProfileStore(this.view.db).set(profile);
        }
        const current = host?.engine?.profile.current() ?? new ProfileStore(this.view.db).current();
        return [profileLine(current), "Uso: /perfil bounty | pentest | laboratorio | defensa | full-blast (lo cambia el operador; cada perfil habilita distinto arsenal, full-blast todo contra lo que el alcance autorice)"];
      }
      case "deteccion": {
        const engine = host?.engine;
        if (!engine) return ["El modo detección se mira desde una sesión (cyber -c). Se abre con perfil «laboratorio» o «defensa» (/perfil) y señales declaradas por acción (detection_expect). Con CYBER_SYSLOG_HOST el canal de syslog marca las señales solas."];
        if (!engine.detection) return ["El modo detección no está activo: se abre con perfil «laboratorio» o «defensa» (/perfil) y señales declaradas por acción (detection_expect). Con CYBER_SYSLOG_HOST el canal de syslog marca las señales solas."];
        const summary = engine.detection.summary();
        const rows = engine.detection.signals().slice(0, 20).map((signal) => `  ${signal.id}  «${signal.esperada}» por «${signal.accion}»  ${signal.detectada ? "detectada" : "GAP: nunca llegó"}`);
        return [
          `detección (purple): ${summary.detectadas}/${summary.esperadas} señales detectadas, ${summary.gaps.length} gap(s).`,
          ...rows,
          `Cada señal esperada que no llega es un gap (hallazgo detection-gap). El canal syslog${engine.syslog ? ` está abierto en el puerto ${engine.syslog.port}` : " no está abierto (CYBER_SYSLOG_HOST lo declara el operador)"}.`,
        ];
      }
      case "consent": {
        const store = new ConsentStore(this.view.db);
        if (host?.engine) host.engine.http.consent = () => store;
        const value = String(request.value ?? "").trim();
        if (!value) return [...store.view(), "", "Uso: /consent borrar-ajeno si «cita del mensaje tuyo» · /consent borrar-ajeno no (revoca) · /consent subida-activa si «cita» (upload_probe sube SVG con script y XML con entidades externas en perfil bounty)"];
        const parts = value.split(/\s+/);
        const kind = parts[0] ?? "";
        if (!CONSENT_KINDS.includes(kind as (typeof CONSENT_KINDS)[number])) throw new Error(`Consentimiento desconocido «${kind}». Válidos: ${CONSENT_KINDS.join(", ")}`);
        const action = parts[1] ?? "";
        if (action === "no" || action === "off") {
          store.revoke(kind);
          return [`Consentimiento «${kind}» revocado. ${kind === "subida-activa" ? "upload_probe vuelve a subir sólo archivos inertes en perfil bounty." : "El borrado de lo ajeno vuelve a la guarda normal."}`];
        }
        if (action !== "si" && action !== "sí" && action !== "on") {
          return [...store.view(), "", `Uso: /consent ${kind} si «tu mensaje con la autorización» · quitar: /consent ${kind} no`];
        }
        // Otorgar exige cita textual del operador: es una acción que amplía permisos.
        const quote = value.slice(value.indexOf(action) + action.length).trim().replace(/^«|»$/g, "").replace(/^["']|["']$/g, "");
        if (!quote) throw new Error(`Uso: /consent ${kind} si «tu mensaje con la autorización»`);
        const saved = store.grant(kind, quote);
        // La cita es parte de las trazas: va tapada en «compartir» (con la vista de trazas: también lo que la sesión
        // vio del objetivo), queda en la PC en «local» y no sale en «no».
        const tapar = (text: string) => (host?.engine ? host.engine.http.redactIdentities(host.engine.secretos.vistaTrazas(text, "operador")) : text);
        if (guardaLocal()) {
          try { anotar(projectPaths(this.options.cwd).trazas, "consentimientos.jsonl", { sesion: host?.engine?.sessionId ?? null, proyecto: basename(this.options.cwd), kind, hash: saved.hash, otorgado: saved.at, cita: citaTapada(quote, tapar) }); }
          catch { /* el consentimiento vale igual: está en la base del proyecto */ }
        }
        let resultado: string;
        // Sin cuenta de orobas no hay a quién mandarlo: queda sólo en la base del proyecto, sin ningún pedido de red.
        // (Antes salía igual, con «Bearer undefined», y fallaba.)
        const clave = apiKey("OROBAS_API_KEY");
        if (!clave) resultado = "sólo local: sin cuenta de orobas no se envía a ningún servidor";
        else try {
          resultado = `enviado a los servidores: ${await sendConsent(kind, quote, saved.hash, saved.at, clave, fetch, { tapar })}`;
          store.markSent(kind, resultado);
        } catch (error) {
          resultado = `sólo local, sin enviar (fallo: ${String(error).slice(0, 120)}); se reintenta con el próximo /consent`;
          store.markSent(kind, `fallo: ${String(error).slice(0, 60)}`);
        }
        logEvent(this.db, host?.engine?.sessionId ?? null, "consent.otorgado", { kind, hash: saved.hash });
        return [`Consentimiento «${kind}» registrado (hash ${saved.hash}). ${resultado}.`, kind === "subida-activa" ? "upload_probe puede subir SVG con script y documentos con entidades externas; cada archivo subido queda en «Para limpiar» del informe." : "Doble confirmación: cada petición destructiva sobre recurso ajeno además exige allowDestructive del modelo. Los eventos quedan en el registro y viajan a los servidores."];
      }

      case "agent": {

        const { http } = need().engine;
        if (request.value) http.userAgent = request.value === "defecto" ? undefined : request.value;
        return [`User-Agent: ${http.conduct().userAgent}. Uso: /agente <texto> o /agente defecto`];
      }
      case "cabeceras": {
        const store = new CabecerasPrograma(this.db);
        const value = String(request.value ?? "").trim();
        if (value) {
          if (/^quitar\s+/i.test(value)) store.quitar(value.replace(/^quitar\s+/i, ""));
          else store.poner(value);
          logEvent(this.db, host?.engine.sessionId ?? null, "cabeceras.cambio", { nombres: Object.keys(store.listar()) });
        }
        return [...lineasCabeceras(store.listar()), "Uso: /alcance cabecera Nombre: valor · /alcance cabecera quitar Nombre"];
      }
      case "view": {
        const arg = String(request.arg ?? "");
        if (request.name === "mejoras") {
          const words = arg.split(/\s+/).filter(Boolean);
          const wanted = words.find((word) => /^\d+$/.test(word));
          if (words.some((word) => word !== wanted && word !== "modelo")) throw new Error("Uso: cyber mejoras [1..100] [--modelo]");
          const report = diagnosticarMejoras(this.db, this.options.cwd, wanted ? Number(wanted) : 10);
          if (!words.includes("modelo") || report.modo === "no" || !report.patrones.length) return report.lineas;
          return [...report.lineas, "", "REDACCIÓN OPTATIVA DEL MODELO FUERTE", await redactarConModelo(report, this.options.cwd)];
        }
        if (request.name === "cobertura") {
          const engine = host?.engine;
          if (!engine) return ["Sin sesión abierta: la cobertura se mira desde una sesión (cyber -c)."];
          return engine.coverage.view(engine.sessionId);
        }
        if (request.name === "cves") return this.cves(arg, host, request.session);
        if (request.name === "grafo") return this.grafo(arg, host, request.session);
        this.view.vault.reindex();
        if (request.name === "costos") {
          const sessionId = host?.engine.sessionId ?? findSession(this.db, "last") ?? "";
          const ledger = host?.engine.ledger ?? this.view.ledger;
          const cap = ledger.projectBudget();
          return [...costDetail(ledger, sessionId, basename(this.options.cwd)), cap === undefined ? "Proyecto sin tope de gasto (cyber tope <USD>)." : `Tope del proyecto: USD ${usd(cap, 2)} · gastado en todas las sesiones USD ${usd(ledger.knownPicoAll())}.`];
        }
        if (request.name === "uso") return usageExport(host?.engine.ledger ?? this.view.ledger, basename(this.options.cwd), this.options.cwd);
        if (request.name === "trayectorias") {
          const words = arg.split(/\s+/).filter(Boolean);
          const anonymize = words.some((word) => /^(anonimo|anónimo|anon)$/i.test(word));
          const sessions = words.filter((word) => !/^(anonimo|anónimo|anon)$/i.test(word));
          const result = exportTrajectories(
            { db: this.db, ledger: host?.engine.ledger ?? this.view.ledger, findings: this.view.findings, scope: this.view.scope.project(), sessionScope: (id) => this.view.scope.of(id).current() },
            basename(this.options.cwd), projectPaths(this.options.cwd).exports,
            // Exportar trayectorias es armar material de entrenamiento: va con la vista de trazas, como el modo local.
            { anonymize, sessions, system: SYSTEM_PROMPT, redact: (text, de) => { for (const live of this.hosts.values()) text = live.engine.http.redactIdentities(live.engine.secretos.vistaTrazas(text, origenDeTraza(de))); return text; } },
          );
          return trajectoriesLines(result, anonymize);
        }
        if (request.name === "memoria") return memoryView(this.view, arg, scopeTag(host?.engine.scope.current()));
        if (request.name === "evidencia") return evidenceView(this.view, arg);
        // Con sesión (la adjunta, o -s en la CLI), los hallazgos y el informe son los de esa sesión; «todos»
        // muestra el proyecto entero. La CLI sin sesión ve el proyecto entero.
        const session = host?.engine.sessionId ?? (request.session ? findSession(this.db, String(request.session)) : undefined);
        if (request.session && !session) throw new Error(`No existe la sesión ${request.session}`);
        if (request.name === "findings") return findingsView(this.view.findings, arg, session);
        if (request.name === "informe") {
          const words = arg.split(/\s+/).filter(Boolean);
          const whole = words.some((word) => /^(todos|todo|proyecto|all|project)$/i.test(word));
          const lang = parseReportLang(words.filter((word) => !/^(todos|todo|proyecto|all|project)$/i.test(word)).join(" "));
          const grafo = session && (!host || host.engine.grafo) ? this.grafoDe(host, session).ver() : undefined;
          return reportSavedLines(await generateReport({ ...this.view, paths: projectPaths(this.options.cwd), lang, sessionId: whole ? undefined : session, ...(grafo ? { grafo } : {}), redact: (text) => {
            for (const live of this.hosts.values()) text = live.engine.http.redactIdentities(text);
            return text;
          } }));
        }
        if (request.name === "scope") {
          if (/^cabeceras?(?:\s|$)/i.test(arg)) {
            const value = arg.replace(/^cabeceras?\s*/i, "");
            return await this.handle({ op: "cabeceras", value }, host, send) as string[];
          }
          const [verb, ...rules] = arg.split(/[\s,]+/).filter(Boolean);
          if (verb === "sesiones" || verb === "proyecto" || verb === "todos") return this.scopeSessions(host?.engine.sessionId);
          const { store, label } = this.scopeFor(request, host);
          if (verb === "reglas") {
            const [, clase, ...palabras] = arg.split(/\s+/);
            const tipo = ({ exclusion: "exclusiones", honesto: "honestos", atacante: "posicionAtacante" } as const)[clase as "exclusion" | "honesto" | "atacante"];
            if (tipo) store.agregarRegla(tipo, palabras.join(" "), "operador: /alcance reglas");
            else if (clase) throw new Error("Uso: /alcance reglas [exclusion|honesto|atacante] <cita textual>");
            return [...(label ? [label] : []), ...scopeView(store.current())];
          }
          if (verb === "add" || verb === "agregar") store.edit({ include: rules });
          else if (verb === "excluir") store.edit({ exclude: rules });
          else if (verb === "quitar") store.edit({ remove: rules });
          else if (verb === "referencia" || verb === "reference") store.edit({ reference: rules });
          else if (verb === "limpiar") store.clear();
          else if (verb === "recuperar") {
            const rev = Number(rules[0]);
            if (!Number.isInteger(rev) || rev <= 0) throw new Error(t("Uso: /scope recuperar <rev> (la revisión la muestra /scope sesiones)", "Usage: /scope recuperar <rev> (/scope sesiones shows the revision)"));
            store.adopt(rev);
          } else if (verb) throw new Error("Uso: /scope [add|excluir|quitar|referencia <reglas>] | limpiar | recuperar <rev> | sesiones (referencia: documentación o código público que el agente sólo lee, nunca prueba)");
          return [...(label ? [label] : []), ...scopeView(store.current()), ...lineasCabeceras(new CabecerasPrograma(this.db).listar())];
        }
        if (request.name === "jobs") return jobsView(this.db, this.view.ledger, (id) => sessionState(this.db, id, this.liveState(id)));
        if (request.name === "sesiones") return sessionsView(sessionRows(this.db, this.view.ledger, (id) => this.liveState(id), host?.engine.sessionId));
        throw new Error(`Vista desconocida: ${request.name}`);
      }
      case "h1":
        return this.hackerone(request, host);
      case "account":
        return this.account(request);
      case "mail_account":
        return this.mailAccount(request);
      case "chatgpt": {
        const lines = await chatgptOp(request);
        for (const live of this.hosts.values()) live.broadcast({ ev: "status", status: live.status() });
        return lines;
      }
      case "platform_account":
        return this.platformAccount(request, send);
      case "confirm": {
        const { engine } = need();
        const decision = request.decision === "siempre" ? "siempre" : request.ok ? "si" : "no";
        if (!engine.resolveShell(Number(request.permiso ?? request.id), decision)) return ["Ese permiso ya no está esperando."];
        return decision === "no" ? ["Rechazado."] : [decision === "siempre" ? "Permitido y recordado para este proyecto." : "Permitido."];
      }
      case "permisos": {
        const { engine } = need();
        const value = String(request.value ?? "").trim();
        if (!value) return [...engine.shellPerms.view(), "", "Uso: /permisos todo · /permisos normal · /permisos permitir «prefijo» · /permisos quitar «prefijo» · /permisos limpiar"];
        const [accion, ...resto] = value.split(/\s+/);
        const prefix = resto.join(" ").trim();
        if (accion === "todo") { engine.shellPerms.setAuto(true); return ["Autoaprobar todo: encendido en todos los proyectos. Los comandos corren sin preguntar; sólo preguntan sudo, formatear o escribir discos, apagar la máquina y borrar la raíz, el home o carpetas del sistema. /permisos normal lo apaga."]; }
        if (accion === "normal") { engine.shellPerms.setAuto(false); return ["Autoaprobar todo: apagado. Vuelve a preguntar lo que escribe, sale a la red o es riesgoso.", ...engine.shellPerms.view()]; }
        if (accion === "limpiar") { engine.shellPerms.clear(); return ["Permisos de shell borrados: todo vuelve a preguntar."]; }
        if (accion === "quitar") {
          if (!prefix) throw new Error("Decí el prefijo: /permisos quitar «git push»");
          return [engine.shellPerms.revoke(prefix) ? `Quitado «${prefix}».` : `No estaba permitido «${prefix}».`];
        }
        if (accion === "permitir") {
          if (!prefix) throw new Error("Decí el prefijo: /permisos permitir «git push»");
          engine.shellPerms.allow(prefix);
          return [`Permitido siempre «${prefix}» (lo riesgoso igual pregunta).`, ...engine.shellPerms.view()];
        }
        return [...engine.shellPerms.view(), "", "Uso: /permisos todo · /permisos normal · /permisos permitir «prefijo» · /permisos quitar «prefijo» · /permisos limpiar"];
      }
      case "identity": {
        const { engine } = need();
        const text = String(request.value ?? "").trim();
        if (!text) {
          const pending = engine.http.proposedIdentities();
          return [
            `Identidades activas: ${engine.http.identityNames().join(", ") || "ninguna"}`,
            ...pending.map((item) => `Pendiente: ${item.name} · ${item.headers.join(", ")}${item.origin ? ` · ${item.origin}` : ""}`),
            "Aprobar una propuesta: /identity aprobar <nombre>. Los valores no se muestran.",
          ];
        }
        const approval = /^aprobar\s+(\S+)$/.exec(text);
        if (approval) {
          engine.http.approveIdentity(approval[1]!);
          return [`Identidad «${approval[1]}» aprobada para esta sesión del daemon.`];
        }
        const match = /^(\S+)\s+([^:]+):\s*(.+)$/s.exec(text);
        if (!match) throw new Error("Uso: /identity <nombre> <cabecera>: <valor>   (p. ej. /identity comprador Cookie: session=…)");
        const existing = engine.http.identityNames().includes(match[1]!);
        engine.http.setIdentity({ name: match[1]!, headers: { [match[2]!.trim().toLowerCase()]: match[3]!.trim() } });
        return [`Identidad «${match[1]}» ${existing ? "reemplazada" : "configurada"} con la cabecera ${match[2]!.trim()}. Vive sólo en esta sesión del daemon; el modelo no ve el valor.`];
      }
      case "toolbox":
        return toolboxView();
      case "toolbox_install": {
        const tools = Array.isArray(request.tools) ? request.tools.filter((tool: unknown) => typeof tool === "string") as string[] : [];
        if (!tools.length) throw new Error("Pasá las herramientas a instalar con /toolbox_install { tools: [...] }. Cada plan es fijo: no hay comandos del modelo ni texto del objetivo.");
        const lines: string[] = [];
        for (const tool of tools) {
          lines.push(`
=== ${tool}
${await installTool(tool, this.options.cwd)}`);
        }
        return lines;
      }
      case "extension":
        return extensionGuide(fileURLToPath(new URL("../extension", import.meta.url)));
      case "navegador": {
        // Navegador del operador: autorización por proyecto (la da sólo el operador, desde su interfaz) y estado de la extensión.
        const value = String(request.value ?? "").trim().toLowerCase();
        const engine = host?.engine;
        const access = engine?.browserAccess ?? new BrowserAccess(this.view.db);
        let done: string | undefined;
        if (/^(si|sí|on|yes)$/.test(value)) {
          const already = !!access.grant();
          if (engine) engine.allowBrowser("/navegador si", "comando");
          else if (access.allow("/navegador si", "comando").nueva) logEvent(this.db, null, "navegador.autorizado", { via: "comando", pedido: "/navegador si" });
          done = already ? t("Ya estaba autorizado.", "It was already allowed.") : t("Autorizado: el agente puede usar tu navegador en este proyecto (todas sus sesiones). La extensión se conecta sola en unos segundos.", "Allowed: the agent can use your browser in this project (all its sessions). The extension connects by itself in a few seconds.");
        } else if (/^(no|off)$/.test(value)) {
          const previous = engine ? engine.revokeBrowser("comando") : access.revoke();
          if (!engine) logEvent(this.db, null, "navegador.revocado", { via: "comando", pedido: "/navegador no" });
          done = previous ? t("Revocado: el agente no toca tu navegador en este proyecto hasta que lo autorices de nuevo.", "Revoked: the agent does not touch your browser in this project until you allow it again.") : t("No estaba autorizado.", "It was not allowed.");
        } else if (value) throw new Error(t("Uso: /navegador si | no", "Usage: /navegador si | no"));
        const info = engine ? engine.browserState() : (() => {
          const grant = access.grant();
          const bridge = chromeBridge(false);
          const seen = Math.max(access.seen(), bridge?.machineSeen() ?? readSeenMarker());
          return { grant, state: bridge?.state(access.seen()) ?? (seen ? "dormido" as const : "sin-emparejar" as const), seen, listening: !!bridge?.listening };
        })();
        const lines = browserLines({ ...info, cmd: extCmd() });
        return done ? [lines[0]!, done, ...lines.slice(1)] : lines;
      }
      case "inicio": {
        // Marca del inicio guiado, por máquina (configuración del usuario), no por proyecto.
        const action = String(request.action ?? "status");
        if (action === "done") markInicio({ skipped: request.skipped === true });
        else if (action === "reset") resetInicio();
        const done = inicioDone();
        return [inicioPending() ? "pendiente" : "hecho", done ? `${done.at} v${done.version}${done.skipped ? " omitido" : ""}` : ""];
      }
      case "sesiones": {
        // Menú de sesiones de la TUI: lista (tabulada), detalle, renombrar y ramificar. La TUI retoma con attach.
        const action = String(request.action ?? "list");
        // «id» numera los pedidos del protocolo: la sesión viaja en «session».
        const id = request.session ? findSession(this.db, String(request.session)) : undefined;
        if (action === "list") return request.todos ? allProjectsRows() : encodeRows(sessionRows(this.db, this.view.ledger, (s) => this.liveState(s), host?.engine.sessionId));
        if (!id) throw new Error(`No existe la sesión ${String(request.session ?? "")}`);
        if (action === "detalle") return sessionDetail(this.db, this.view.ledger, id, sessionState(this.db, id, this.liveState(id)));
        if (action === "rename") {
          renameSession(this.db, id, String(request.title ?? ""));
          for (const h of this.hosts.values()) if (h.engine.sessionId === id) h.broadcast({ ev: "status", status: h.status() });
          return [`Sesión ${id.slice(0, 8)} renombrada.`];
        }
        if (action === "fork") return [forkSession(this.db, id)];
        throw new Error(`Acción desconocida: ${action}`);
      }
      case "orquesta": {
        const { engine } = need();
        const action = String(request.action ?? "list");
        const id = String(request.run ?? "");
        if (action === "ver") return engine.orquesta.summary(engine.orquesta.need(id), 4000).split("\n");
        if (action === "parar") return [`#${engine.orquesta.stop(id).id} detenido.`];
        if (action === "limpiar") return await engine.orquesta.removeWorktree(engine.orquesta.need(id), request.rama === true);
        if (action === "harnesses") return harnessStatus();
        if (action === "ultra") {
          // /ultra <tarea> [--objetivo] [--partes N] [--con claude,codex]: el mensaje que la TUI le manda al agente.
          let text = String(request.tarea ?? "").trim();
          const mode = /--objetivo\b/.test(text) ? "objetivo" : "repo";
          const parts = Number(/--partes\s+(\d+)/.exec(text)?.[1]) || undefined;
          const con = /--con\s+([a-z,]+)/.exec(text)?.[1]?.split(",").filter((h): h is HarnessId => h in HARNESSES);
          text = text.replace(/--objetivo\b|--partes\s+\d+|--con\s+[a-z,]+/g, "").replace(/\s+/g, " ").trim();
          if (!text) throw new Error("Uso: /ultra <tarea> [--objetivo] [--partes N] [--con claude,codex,pi,opencode,cyber]");
          return [ultraPrompt(text, { mode, parts, harnesses: con?.length ? con : undefined })];
        }
        return engine.orquesta.view();
      }
      case "shutdown":
        if (this.busy() && !request.force) throw new Error("Hay un turno en curso; detenelo antes o usá force");
        setImmediate(() => this.close());
        return ["Daemon detenido."];
      default:
        throw new Error(`Operación desconocida: ${request.op}`);
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.idleTimer);
    const closing = [...this.hosts.values()].map((host) => host.engine.close());
    for (const socket of this.sockets) socket.destroy();
    this.server?.close();
    this.unlock?.();
    for (const file of [this.path, join(runtimeDir(this.options.cwd), "daemon.pid")]) {
      try {
        unlinkSync(file);
      } catch {}
    }
    await Promise.allSettled(closing);
    this.db.close();
    this.options.onClose?.();
  }
}

/** «sin» quita el límite a pedido (Infinity); vacío deja el valor por defecto; un número lo fija. */
function amount(value?: string): number | undefined {
  if (!value) return undefined;
  if (value === "sin") return Infinity;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`Valor inválido: «${value}». Usar un número mayor que cero o «sin».`);
  return parsed;
}
