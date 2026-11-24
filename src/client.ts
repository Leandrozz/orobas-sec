// Cliente del daemon: lo usan la TUI y el CLI. Si no hay daemon en el proyecto, lo levanta.
import { spawn } from "node:child_process";
import { openSync, readFileSync, rmSync } from "node:fs";
import { connect as netConnect, type Socket } from "node:net";
import { join } from "node:path";
import type { AgentEvent } from "./agent.ts";
import { buildId, type ServerEvent, type Snapshot, socketPath, type Status } from "./daemon.ts";
import { runtimeDir } from "./datos.ts";
import { compartido, otrasVentanas } from "./compartido.ts";
import { t } from "./idioma.ts";

export type ClientEvent = AgentEvent | { type: "confirm"; id: number; command: string; cwd: string; kind: string; risky: boolean; reasons: string[]; prefix: string } | { type: "recall"; ids: string[] } | { type: "notice"; text: string } | { type: "answer"; text: string } | { type: "status" } | { type: "disconnected" };

const CONTAINER_SIGNALS = ["SIGTERM", "SIGHUP"] as const;

export class Client {
  status: Status = { running: false, interrupted: false, usage: "", cost: "", notes: 0, needsKey: false };
  hello!: Extract<ServerEvent, { ev: "hello" }>;
  private socket: Socket;
  private listeners: Array<(event: ClientEvent) => void> = [];
  private replies = new Map<number, { resolve: (lines: string[]) => void; reject: (error: Error) => void }>();
  private attaching: { resolve: (snapshot: Snapshot) => void; reject: (error: Error) => void } | undefined;
  private nextId = 1;

  private constructor(socket: Socket) {
    this.socket = socket;
  }

  static open(path: string): Promise<Client> {
    return new Promise((resolve, reject) => {
      const socket = netConnect(path);
      const client = new Client(socket);
      let pending = "";
      socket.setEncoding("utf8");
      socket.once("error", reject);
      socket.on("error", () => {});
      socket.on("data", (chunk: string) => {
        pending += chunk;
        let newline: number;
        while ((newline = pending.indexOf("\n")) >= 0) {
          const event = JSON.parse(pending.slice(0, newline)) as ServerEvent;
          pending = pending.slice(newline + 1);
          if (event.ev === "hello") {
            client.hello = event;
            if (inContainer()) client.leaveOnSignal();
            resolve(client);
          } else client.receive(event);
        }
      });
      socket.on("close", () => {
        const error = new Error("Se perdió la conexión con el daemon");
        for (const reply of client.replies.values()) reply.reject(error);
        client.attaching?.reject(error);
        client.emit({ type: "disconnected" });
      });
    });
  }

  private receive(event: ServerEvent): void {
    if (event.ev === "attached") {
      this.status = event.snapshot.status;
      this.attaching?.resolve(event.snapshot);
      this.attaching = undefined;
    } else if (event.ev === "reply") {
      const reply = this.replies.get(event.id);
      this.replies.delete(event.id);
      if (event.error) (this.attaching ?? reply)?.reject(new Error(event.error));
      else reply?.resolve(event.lines ?? []);
      if (event.error) this.attaching = undefined;
    } else if (event.ev === "status") {
      this.status = event.status;
      this.emit({ type: "status" });
    } else if (event.ev === "agent") this.emit(event.event);
    else if (event.ev === "recall") this.emit({ type: "recall", ids: event.ids });
    else if (event.ev === "notice") this.emit({ type: "notice", text: event.text });
    else if (event.ev === "answer") this.emit({ type: "answer", text: event.text });
    else if (event.ev === "confirm") this.emit({ type: "confirm", id: event.id, command: event.command, cwd: event.cwd, kind: event.kind, risky: event.risky, reasons: event.reasons, prefix: event.prefix });
  }

  private emit(event: ClientEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  on(listener: (event: ClientEvent) => void): void {
    this.listeners.push(listener);
  }

  private write(request: object): void {
    this.socket.write(`${JSON.stringify(request)}\n`);
  }

  /** Operación con respuesta. */
  ask(op: string, payload: object = {}): Promise<string[]> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.replies.set(id, { resolve, reject });
      // El id del pedido va último: ninguna clave del payload lo pisa (si no, la respuesta nunca llega).
      this.write({ op, ...payload, id });
    });
  }

  attach(options: { session?: string; model?: string; budget?: string; requests?: string; rate?: string; agent?: string; cabeceras?: string[] } = {}): Promise<Snapshot> {
    return new Promise((resolve, reject) => {
      this.attaching = { resolve, reject };
      this.write({ op: "attach", id: this.nextId++, ...options });
    });
  }

  send(text: string): void {
    this.write({ op: "send", text });
  }

  /** Corta el turno en curso y manda ya el texto (después de lo que haya en cola); sin texto, manda la cola. */
  interrupt(text = ""): void {
    this.write({ op: "send", text, interrupt: true });
  }

  resume(): void {
    this.write({ op: "resume" });
  }

  abort(): void {
    this.write({ op: "abort" });
  }

  /** Vista del daemon. Sin sesión adjunta, `session` elige de qué sesión (alcance, hallazgos, informe). */
  view(name: string, arg = "", session?: string): Promise<string[]> {
    return this.ask("view", { name, arg, ...(session && { session }) });
  }

  /** Espera a que termine el turno en curso. */
  idle(): Promise<void> {
    return new Promise((resolve) => this.on((event) => (event.type === "idle" || event.type === "disconnected") && resolve()));
  }

  /** La conexión sigue abierta (mantiene vivo al daemon) pero no retiene al proceso. */
  sinRetener(): void {
    this.socket.unref();
  }

  close(): void {
    for (const signal of CONTAINER_SIGNALS) process.off(signal, this.onSignal);
    this.socket.destroy();
  }

  /** Cerrar la ventana o `docker stop` mandan SIGHUP/SIGTERM al cliente (pid 1): sin esto el daemon quedaría con el candado hasta 30 s. */
  private onSignal = (signal: NodeJS.Signals): void => void Promise.race([this.leave(), wait(3000)]).finally(() => process.exit(signal === "SIGTERM" ? 143 : 129));

  private leaveOnSignal(): void {
    for (const signal of CONTAINER_SIGNALS) process.on(signal, this.onSignal);
  }

  /** Dentro del contenedor el daemon muere con él sin soltar el candado (30 s): se apaga antes de salir. Fuera, solo se desconecta. */
  async leave(otras: () => number = otrasVentanas): Promise<void> {
    if (compartido() ? otras() === 0 : inContainer()) {
      const gone = new Promise<void>((resolve) => this.on((event) => event.type === "disconnected" && resolve()));
      // En modo compartido sin `force`: si hay un turno en curso el daemon se niega y sigue hasta quedar ocioso.
      const aceptado = await this.ask("shutdown", compartido() ? {} : { force: true }).then(() => true, () => false);
      if (aceptado) await Promise.race([gone, wait(2000)]); // el daemon suelta el candado antes de cortar el socket
    }
    this.close();
  }
}

/** Los lanzadores ponen CYBER_PROYECTO_HOST en cada contenedor; con pid 1 fallaría si hubiera un init o un script delante. */
export const inContainer = () => !!process.env.CYBER_PROYECTO_HOST;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Conecta con el daemon del proyecto y lo arranca (o lo renueva si quedó con código viejo). */
export async function connectDaemon(cwd: string, options: { spawn?: boolean } = {}): Promise<Client> {
  const path = socketPath(cwd);
  const tryOpen = () => Client.open(path).catch(() => undefined);
  let client = await tryOpen();
  if (client && client.hello.build !== buildId()) {
    // Un cambio de versión no corta un turno en curso ni a las otras ventanas conectadas (antes el daemon se apagaba
    // igual y todas perdían la conexión); tampoco desde una conexión extra que no puede levantar otro (spawn: false).
    // Con el código del harness editándose mientras corre, eso reiniciaba el daemon varias veces por día.
    if (client.hello.busy || client.hello.clients || options.spawn === false) return client;
    await client.ask("shutdown").catch(() => undefined);
    client.close();
    client = undefined;
    await wait(150);
  }
  if (client) return client;
  if (options.spawn === false) throw new Error("No hay un daemon de Cyber en este proyecto");
  if (compartido()) return esperarMotor(cwd, tryOpen);
  const root = runtimeDir(cwd);
  const log = openSync(join(root, "daemon.log"), "a");
  rmSync(join(root, "arranque.err"), { force: true });
  const child = spawn(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "cli.ts"), "daemon", "-C", cwd], {
    detached: true,
    stdio: ["ignore", log, log],
  });
  child.unref();
  // El daemon migra y respalda antes de escuchar (puede tardar minutos con un .cyber grande): se espera mientras viva el proceso.
  let exitedAt = 0;
  child.once("exit", () => (exitedAt = Date.now()));
  const started = Date.now();
  let warned = false;
  // Si el hijo salió (por ejemplo porque otro daemon ya estaba arrancando) se dan unos segundos más para conectarse a ese.
  while (exitedAt ? Date.now() - exitedAt < 6000 : Date.now() - started < 600_000) {
    await wait(100);
    client = await tryOpen();
    if (client) return client;
    try {
      throw new Error(readFileSync(join(root, "arranque.err"), "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (!warned && !exitedAt && Date.now() - started > 3000) {
      warned = true;
      process.stderr.write(`${t("Mudando datos del proyecto…", "Moving project data…")}\n`);
    }
  }
  let tail = "";
  try {
    tail = readFileSync(join(root, "daemon.log"), "utf8").trim().split("\n").slice(-5).join("\n");
  } catch {}
  const logPath = join(root, "daemon.log");
  // En Docker el log vive en el /tmp del contenedor, que el host no ve.
  const where = process.env.CYBER_DATOS_HOST
    ? t(`Log dentro del contenedor, en ${logPath} (no está en tu carpeta del host).`, `Log inside the container, at ${logPath} (not in your host folder).`)
    : `Ver ${logPath}`;
  throw new Error(`El daemon no arrancó. ${where}${tail ? `\n${tail}` : ""}`);
}

/** En modo compartido el motor lo arranca el contenedor: acá solo se espera a que escuche. */
async function esperarMotor(cwd: string, tryOpen: () => Promise<Client | undefined>): Promise<Client> {
  const started = Date.now();
  let warned = false;
  while (Date.now() - started < 600_000) {
    await wait(100);
    const client = await tryOpen();
    if (client) return client;
    try {
      throw new Error(readFileSync(join(runtimeDir(cwd), "arranque.err"), "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (!warned && Date.now() - started > 3000) {
      warned = true;
      process.stderr.write(`${t("Esperando al motor del proyecto…", "Waiting for the project engine…")}\n`);
    }
  }
  throw new Error("El motor del proyecto no respondió");
}
