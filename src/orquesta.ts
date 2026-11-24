// Orquestación de harnesses: el agente lanza otros agentes de código (Claude Code, Codex, pi, OpenCode
// u otro Orobas) sobre worktrees del repositorio del proyecto, varios a la vez, cada uno en su rama.
// Cada corrida es un trabajo con su registro en disco; al terminar quedan la salida y el diff como
// artefacto. El operador aprueba cada lanzamiento viendo la línea exacta (mismo aviso que la shell) y
// puede abrir cada corrida en una terminal propia. Nada de esto toca el objetivo: es trabajo sobre código.
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { exec, which } from "./exec.ts";
import type { ShellConfirmInfo, ShellPermissions } from "./shell.ts";

export type HarnessId = "claude" | "codex" | "pi" | "opencode" | "cyber";
export type RunState = "esperando" | "corriendo" | "terminado" | "fallido" | "detenido" | "vencido" | "rechazado";

export interface HarnessSpec {
  id: HarnessId;
  label: string;
  bin: string;
  /** Variable que apunta a otro binario (pruebas, instalaciones raras). */
  env: string;
  /** Línea no interactiva: una tarea, una salida, y termina. */
  argv: (task: string, options: { model?: string; cwd: string }) => string[];
  note: string;
}

export const HARNESSES: Record<HarnessId, HarnessSpec> = {
  claude: { id: "claude", label: "Claude Code", bin: "claude", env: "CYBER_HARNESS_CLAUDE", note: "edita con permiso automático dentro del worktree (acceptEdits)",
    argv: (task, o) => ["-p", "--output-format", "text", "--permission-mode", "acceptEdits", ...(o.model ? ["--model", o.model] : []), task] },
  codex: { id: "codex", label: "Codex", bin: "codex", env: "CYBER_HARNESS_CODEX", note: "exec con sandbox de escritura en el worktree",
    argv: (task, o) => ["exec", "-s", "workspace-write", "-C", o.cwd, ...(o.model ? ["-m", o.model] : []), task] },
  pi: { id: "pi", label: "pi", bin: "pi", env: "CYBER_HARNESS_PI", note: "modo --print",
    argv: (task, o) => ["-p", ...(o.model ? ["--model", o.model] : []), task] },
  opencode: { id: "opencode", label: "OpenCode", bin: "opencode", env: "CYBER_HARNESS_OPENCODE", note: "opencode run",
    argv: (task, o) => ["run", ...(o.model ? ["--model", o.model] : []), task] },
  cyber: { id: "cyber", label: "Orobas (otra instancia)", bin: "cyber", env: "CYBER_HARNESS_CYBER", note: "un turno sin TUI (-p) con su propio daemon en el worktree",
    argv: (task, o) => ["-C", o.cwd, ...(o.model ? ["-m", o.model] : []), "-p", task] },
};

export const harnessBinary = (spec: HarnessSpec): string | undefined => {
  const configured = process.env[spec.env];
  if (configured) return existsSync(configured) ? configured : which(configured);
  return which(spec.bin);
};

/** Qué harnesses hay en esta máquina, para la vista de herramientas y para el agente. */
export function harnessStatus(): string[] {
  return Object.values(HARNESSES).map((spec) => {
    const bin = harnessBinary(spec);
    return `${spec.id.padEnd(9)}${bin ? `✓ ${bin}` : "✗ no instalado"} · ${spec.label}`;
  });
}

export interface Run {
  id: string;
  harness: HarnessId;
  task: string;
  state: RunState;
  cwd: string;
  worktree?: string;
  branch?: string;
  model?: string;
  command: string;
  log: string;
  startedAt: number;
  endedAt?: number;
  exitCode?: number | null;
  signal?: string | null;
  /** Hash del artefacto con la salida completa y el diff, cuando terminó. */
  artifact?: string;
  diff?: string;
  /** Últimos bytes de la salida, para mostrar sin leer el archivo. */
  tail: string;
  sessionId: string;
}

export interface OrquestaContext {
  cwd: string;
  /** Carpeta del proyecto en la base de datos: los worktrees y registros van ahí (fuera del repo). */
  root: string;
  db: DatabaseSync;
  artifacts: Artifacts;
  permissions: ShellPermissions;
  confirm?: (info: ShellConfirmInfo) => Promise<"si" | "siempre" | "no">;
  sessionId: () => string;
  onEvent?: (type: string, payload: Record<string, unknown>) => void;
  notice?: (text: string) => void;
}

const TAIL_BYTES = 8_000;
const MAX_CONCURRENT = 6;
const DEFAULT_TIMEOUT_MIN = 30;

const slug = (text: string) => text.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 24) || "tarea";
const quote = (arg: string) => (/^[\w./:=@%+-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, "'\\''")}'`);

/** Lo que el operador ve y aprueba: el comando tal como se va a correr, con la tarea recortada. */
export function commandLine(bin: string, argv: string[]): string {
  return [bin, ...argv].map((a) => quote(a.length > 160 ? `${a.slice(0, 157)}…` : a)).join(" ");
}

export class Orquesta {
  readonly runs = new Map<string, Run>();
  private readonly procs = new Map<string, ChildProcess>();
  private readonly waiters = new Map<string, Array<() => void>>();

  private readonly ctx: OrquestaContext;

  constructor(ctx: OrquestaContext) {
    this.ctx = ctx;
    ctx.db.exec(`create table if not exists harness_runs(
      id text primary key, session_id text not null, harness text not null, task text not null, state text not null,
      worktree text, branch text, model text, command text not null, log text not null,
      started_at text not null, ended_at text, exit_code integer, artifact text)`);
  }

  private persist(run: Run): void {
    try { this.persistNow(run); } catch { /* la base ya se cerró (sesión terminada): queda el registro en disco */ }
  }

  private persistNow(run: Run): void {
    this.ctx.db.prepare(`insert or replace into harness_runs(id,session_id,harness,task,state,worktree,branch,model,command,log,started_at,ended_at,exit_code,artifact)
      values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(run.id, run.sessionId, run.harness, run.task, run.state, run.worktree ?? null, run.branch ?? null, run.model ?? null, run.command, run.log,
      new Date(run.startedAt).toISOString(), run.endedAt ? new Date(run.endedAt).toISOString() : null, run.exitCode ?? null, run.artifact ?? null);
  }

  /** Corridas guardadas de sesiones anteriores (sólo lectura: sus procesos ya no existen). */
  saved(limit = 20): Array<Pick<Run, "id" | "harness" | "task" | "state" | "branch" | "startedAt" | "artifact">> {
    const rows = this.ctx.db.prepare("select id, harness, task, state, branch, started_at, artifact from harness_runs order by started_at desc limit ?").all(limit) as Array<{ id: string; harness: HarnessId; task: string; state: RunState; branch: string | null; started_at: string; artifact: string | null }>;
    return rows.map((r) => ({ id: r.id, harness: r.harness, task: r.task, state: this.runs.get(r.id)?.state ?? (r.state === "corriendo" || r.state === "esperando" ? "detenido" : r.state), branch: r.branch ?? undefined, startedAt: Date.parse(r.started_at), artifact: r.artifact ?? undefined }));
  }

  active(): Run[] {
    return [...this.runs.values()].filter((r) => r.state === "corriendo" || r.state === "esperando");
  }

  private async git(args: string[], cwd: string): Promise<string> {
    const result = await exec({ argv: ["git", ...args], cwd, timeoutMs: 60_000, maxOutputBytes: 2_000_000 });
    if (result.exitCode !== 0) throw new Error(`git ${args[0]}: ${(result.stderr || result.stdout).trim().slice(0, 300)}`);
    return result.stdout;
  }

  /** Raíz del repositorio del proyecto, o nada si no es un repo. */
  async repoRoot(): Promise<string | undefined> {
    try { return (await this.git(["rev-parse", "--show-toplevel"], this.ctx.cwd)).trim() || undefined; } catch { return undefined; }
  }

  /** Un worktree nuevo en la carpeta de datos del proyecto, en una rama propia a partir de `base`. */
  async createWorktree(id: string, name: string, base = "HEAD"): Promise<{ dir: string; branch: string }> {
    const root = await this.repoRoot();
    if (!root) throw new Error("El proyecto no es un repositorio git: no se pueden armar worktrees. Lanzá sin worktree (worktree: false) para trabajar sobre la carpeta misma.");
    const dir = join(this.ctx.root, "worktrees", id);
    const branch = `orobas/${slug(name)}-${id}`;
    mkdirSync(join(this.ctx.root, "worktrees"), { recursive: true });
    await this.git(["worktree", "add", "-b", branch, dir, base], root);
    return { dir, branch };
  }

  async removeWorktree(run: Run, deleteBranch: boolean): Promise<string[]> {
    const root = await this.repoRoot();
    const out: string[] = [];
    if (run.worktree && root) {
      await this.git(["worktree", "remove", "--force", run.worktree], root);
      out.push(`worktree ${run.worktree} quitado`);
      if (deleteBranch && run.branch) { await this.git(["branch", "-D", run.branch], root); out.push(`rama ${run.branch} borrada`); }
      else if (run.branch) out.push(`la rama ${run.branch} queda: integrala o borrala con git branch -D`);
    }
    run.worktree = undefined;
    this.persist(run);
    return out;
  }

  /** Lanza una corrida. Pide permiso al operador como la shell: ve la línea exacta. */
  async start(options: { harness: HarnessId; task: string; worktree?: boolean; base?: string; model?: string; timeoutMin?: number; terminal?: boolean }): Promise<Run> {
    const spec = HARNESSES[options.harness];
    if (!spec) throw new Error(`Harness desconocido «${options.harness}». Hay: ${Object.keys(HARNESSES).join(", ")}`);
    const bin = harnessBinary(spec);
    if (!bin) throw new Error(`${spec.label} no está instalado en esta máquina (${spec.bin}). Hay: ${harnessStatus().filter((l) => l.includes("✓")).map((l) => l.split(/\s+/)[0]).join(", ") || "ninguno"}.`);
    if (this.active().length >= MAX_CONCURRENT) throw new Error(`Ya hay ${MAX_CONCURRENT} corridas en curso: esperá alguna con harness_wait.`);
    const task = options.task.trim();
    if (!task) throw new Error("La tarea está vacía.");
    const id = randomBytes(3).toString("hex");
    const useWorktree = options.worktree !== false;
    const where = useWorktree ? await this.createWorktree(id, task, options.base ?? "HEAD") : undefined;
    const cwd = where?.dir ?? this.ctx.cwd;
    const argv = spec.argv(task, { model: options.model, cwd });
    const command = commandLine(bin, argv);
    const dir = join(this.ctx.root, "orquesta");
    mkdirSync(dir, { recursive: true });
    const run: Run = { id, harness: spec.id, task, state: "esperando", cwd, worktree: where?.dir, branch: where?.branch, model: options.model, command, log: join(dir, `${id}.log`), startedAt: Date.now(), tail: "", sessionId: this.ctx.sessionId() };
    this.runs.set(id, run);
    this.persist(run);
    // Permiso: lanzar un agente que escribe código es «escritura»; «siempre» guarda el prefijo (el binario) para el proyecto.
    const prefix = `${basename(bin)} ${argv[0] ?? ""}`.trim();
    if (!this.ctx.permissions.allows(prefix) && !this.ctx.permissions.auto()) {
      const decision = this.ctx.confirm ? await this.ctx.confirm({ command, cwd, kind: "escritura", risky: false, reasons: [`lanza ${spec.label}, que puede modificar archivos en ${where ? "el worktree" : "la carpeta del proyecto"}`], prefix }) : "no";
      if (decision === "siempre") this.ctx.permissions.allow(prefix);
      if (decision === "no") {
        run.state = "rechazado"; run.endedAt = Date.now(); this.persist(run);
        if (where) await this.removeWorktree(run, true).catch(() => {});
        throw new Error(`El operador no autorizó lanzar ${spec.label}.`);
      }
    }
    writeFileSync(run.log, `# ${new Date(run.startedAt).toISOString()} · ${spec.label} · ${cwd}\n# ${command}\n\n`);
    const env = { ...process.env, CYBER_ORQUESTA_RUN: id, CYBER_ORQUESTA_PARENT: run.sessionId } as Record<string, string>;
    const child = spawn(bin, argv, { cwd, env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    this.procs.set(id, child);
    run.state = "corriendo";
    this.persist(run);
    this.ctx.onEvent?.("orquesta.lanzado", { id, harness: spec.id, worktree: where?.dir, branch: where?.branch, tarea: task.slice(0, 200) });
    const onChunk = (chunk: Buffer) => {
      const text = chunk.toString();
      appendFileSync(run.log, text);
      run.tail = (run.tail + text).slice(-TAIL_BYTES);
    };
    child.stdout?.on("data", onChunk);
    child.stderr?.on("data", onChunk);
    const timeoutMs = Math.min(180, Math.max(1, options.timeoutMin ?? DEFAULT_TIMEOUT_MIN)) * 60_000;
    const timer = setTimeout(() => { if (run.state === "corriendo") { run.state = "vencido"; this.kill(id); } }, timeoutMs);
    timer.unref();
    child.on("error", (error) => { appendFileSync(run.log, `\n# error al lanzar: ${error.message}\n`); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      this.procs.delete(id);
      void this.finish(run, code, signal);
    });
    if (options.terminal) this.openTerminal(run);
    return run;
  }

  private async finish(run: Run, code: number | null, signal: NodeJS.Signals | null): Promise<void> {
    run.exitCode = code; run.signal = signal; run.endedAt = Date.now();
    if (run.state === "corriendo") run.state = code === 0 ? "terminado" : "fallido";
    if (run.worktree) {
      try {
        const stat = (await this.git(["diff", "--stat", "HEAD"], run.worktree)).trim();
        const status = (await this.git(["status", "--short"], run.worktree)).trim();
        run.diff = [stat, status && `sin seguimiento o sin stage:\n${status}`].filter(Boolean).join("\n") || "sin cambios";
      } catch (error) { run.diff = `no se pudo leer el diff: ${(error as Error).message}`; }
    }
    try {
      const output = readFileSync(run.log, "utf8");
      if (run.state === "detenido" && !this.runs.has(run.id)) return;
      run.artifact = this.ctx.artifacts.put(JSON.stringify({ id: run.id, harness: run.harness, task: run.task, command: run.command, worktree: run.worktree, branch: run.branch, state: run.state, exitCode: code, signal, ms: run.endedAt - run.startedAt, diff: run.diff, output }, null, 1), "application/json", "orquesta").hash;
    } catch { /* sin artefacto: queda el registro en disco */ }
    this.persist(run);
    this.ctx.onEvent?.("orquesta.terminado", { id: run.id, harness: run.harness, estado: run.state, salida: code, ms: run.endedAt - run.startedAt, artefacto: run.artifact });
    this.ctx.notice?.(`${HARNESSES[run.harness].label} #${run.id} ${run.state} (${Math.round((run.endedAt - run.startedAt) / 1000)} s)${run.diff && run.diff !== "sin cambios" ? " · con cambios en su worktree" : ""}.`);
    for (const wake of this.waiters.get(run.id) ?? []) wake();
    this.waiters.delete(run.id);
  }

  private kill(id: string): void {
    const child = this.procs.get(id);
    if (!child?.pid) return;
    try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill("SIGTERM"); }
    setTimeout(() => { try { process.kill(-child.pid!, "SIGKILL"); } catch { /* ya terminó */ } }, 5_000).unref();
  }

  stop(id: string): Run {
    const run = this.need(id);
    if (run.state !== "corriendo" && run.state !== "esperando") throw new Error(`#${id} ya no corre (${run.state}).`);
    run.state = "detenido";
    this.kill(id);
    return run;
  }

  need(id: string): Run {
    const run = this.runs.get(id);
    if (!run) throw new Error(`No hay una corrida #${id} en esta sesión. Las guardadas se ven con harness_status.`);
    return run;
  }

  /** Espera a que terminen (todas las activas si no se nombran), con tope. */
  async wait(ids: string[] | undefined, timeoutMs: number, signal?: AbortSignal): Promise<Run[]> {
    const targets = (ids?.length ? ids.map((id) => this.need(id)) : this.active());
    const deadline = Date.now() + timeoutMs;
    await Promise.all(targets.map((run) => new Promise<void>((resolve) => {
      if (run.state !== "corriendo" && run.state !== "esperando") return resolve();
      const timer = setTimeout(resolve, Math.max(0, deadline - Date.now()));
      const done = () => { clearTimeout(timer); resolve(); };
      signal?.addEventListener("abort", done, { once: true });
      (this.waiters.get(run.id) ?? this.waiters.set(run.id, []).get(run.id)!).push(done);
    })));
    return targets;
  }

  /** Una terminal propia que sigue el registro de la corrida (sólo con escritorio; en Docker no hay). */
  openTerminal(run: Run): boolean {
    if (!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) return false;
    const terminal = process.env.CYBER_TERMINAL || process.env.TERMINAL || ["kitty", "alacritty", "foot", "gnome-terminal", "xterm"].find((t) => which(t));
    if (!terminal) return false;
    const title = `Orobas · ${HARNESSES[run.harness].label} #${run.id}`;
    const follow = ["tail", "-n", "+1", "-f", run.log];
    const argv = /gnome-terminal$/.test(terminal) ? ["--title", title, "--", ...follow] : /kitty$/.test(terminal) ? ["--title", title, "-e", ...follow] : ["-T", title, "-e", ...follow];
    try { spawn(terminal, argv, { detached: true, stdio: "ignore" }).unref(); return true; } catch { return false; }
  }

  /** Resumen de una corrida para el agente: estado, rama, diff y la cola de la salida. */
  summary(run: Run, tailChars = 2500): string {
    const seconds = Math.round(((run.endedAt ?? Date.now()) - run.startedAt) / 1000);
    const lines = [
      `#${run.id} · ${HARNESSES[run.harness].label} · ${run.state} · ${seconds} s${run.exitCode !== undefined && run.exitCode !== null ? ` · salida ${run.exitCode}` : ""}`,
      `tarea: ${run.task.slice(0, 200)}`,
      run.worktree ? `worktree: ${run.worktree} · rama ${run.branch}` : `carpeta: ${run.cwd}`,
      run.diff ? `cambios:\n${run.diff.slice(0, 1200)}` : "",
      run.artifact ? `artefacto: ${run.artifact}` : `registro: ${run.log}`,
      run.tail ? `salida (final):\n${run.tail.slice(-tailChars)}` : "(sin salida todavía)",
    ];
    return lines.filter(Boolean).join("\n");
  }

  /** Vista para la TUI. */
  view(): string[] {
    const live = [...this.runs.values()].sort((a, b) => b.startedAt - a.startedAt);
    const old = this.saved(12).filter((r) => !this.runs.has(r.id));
    if (!live.length && !old.length) return ["Sin corridas de otros harnesses. El agente las lanza con harness_run; vos con /ultra o pidiéndoselo.", "", ...harnessStatus()];
    const row = (r: { id: string; harness: HarnessId; state: string; startedAt: number; branch?: string; task: string }) =>
      `#${r.id}  ${r.harness.padEnd(8)} ${r.state.padEnd(10)} ${new Date(r.startedAt).toISOString().slice(5, 16).replace("T", " ")}  ${(r.branch ?? "sin worktree").slice(0, 34).padEnd(34)} ${r.task.slice(0, 40)}`;
    return ["ORQUESTA · corridas de harnesses", ...live.map(row), ...(old.length ? ["", "anteriores:", ...old.map(row)] : []), "", "/orquesta ver <id> · /orquesta parar <id> · /orquesta limpiar <id>"];
  }
}

const str = (extra: object = {}) => ({ type: "string", ...extra });

export function createOrquestaTools(orquesta: Orquesta): Tool[] {
  const ok = (text: string, details: Record<string, unknown> = {}): ToolResult => ({ text, details });
  return [
    {
      name: "harness_run",
      label: "Lanzar harness",
      description:
        "Lanza otro agente de código (claude, codex, pi, opencode o cyber: otro Orobas) sobre el repositorio del proyecto para que haga UNA tarea de código, sin esperar a que termine. " +
        "Por defecto trabaja en un worktree propio (rama orobas/<tarea>-<id> a partir de HEAD), así varios pueden correr a la vez sin pisarse; worktree=false lo corre sobre la carpeta misma. " +
        "El operador aprueba la línea exacta. Devuelve el id; seguí con harness_wait y harness_result. Es trabajo sobre código, nunca sobre el objetivo.",
      parameters: {
        type: "object",
        properties: {
          harness: str({ enum: Object.keys(HARNESSES), description: "claude, codex, pi, opencode o cyber" }),
          task: str({ description: "La tarea completa y autosuficiente: contexto, qué cambiar, cómo verificar (tests), qué no tocar. El otro agente no ve esta conversación.", maxLength: 12000 }),
          worktree: { type: "boolean", description: "true (por defecto): worktree y rama propios; false: sobre la carpeta del proyecto" },
          base: str({ description: "Commit o rama de partida del worktree; por defecto HEAD" }),
          model: str({ description: "Modelo para ese harness, con el nombre que ese harness entiende" }),
          timeoutMin: { type: "integer", minimum: 1, maximum: 180, description: "Tope en minutos; por defecto 30" },
          terminal: { type: "boolean", description: "Abrir una terminal del escritorio siguiendo la corrida (si hay escritorio)" },
        },
        required: ["harness", "task"],
      },
      execute: async (params): Promise<ToolResult> => {
        const run = await orquesta.start({ harness: String(params.harness) as HarnessId, task: String(params.task ?? ""), worktree: params.worktree !== false, base: params.base ? String(params.base) : undefined, model: params.model ? String(params.model) : undefined, timeoutMin: params.timeoutMin ? Number(params.timeoutMin) : undefined, terminal: params.terminal === true });
        return ok(`Lanzado #${run.id} (${HARNESSES[run.harness].label})${run.worktree ? ` en ${run.worktree}, rama ${run.branch}` : " sobre la carpeta del proyecto"}. Registro: ${run.log}. Seguí con harness_wait(ids:["${run.id}"]) y después harness_result.`, { id: run.id, harness: run.harness, worktree: run.worktree, branch: run.branch });
      },
    },
    {
      name: "harness_wait",
      label: "Esperar harnesses",
      description: "Espera a que terminen las corridas indicadas (o todas las activas), hasta un tope. Devuelve el estado de cada una; las que no terminaron siguen corriendo.",
      parameters: { type: "object", properties: { ids: { type: "array", items: str(), description: "Ids; vacío = todas las activas" }, timeoutSec: { type: "integer", minimum: 5, maximum: 3600, description: "Por defecto 600" } } },
      execute: async (params, signal): Promise<ToolResult> => {
        const ids = Array.isArray(params.ids) ? params.ids.map(String) : undefined;
        const runs = await orquesta.wait(ids, Math.min(3600, Math.max(5, Number(params.timeoutSec) || 600)) * 1000, signal);
        if (!runs.length) return ok("No hay corridas activas.");
        return ok(runs.map((run) => orquesta.summary(run, 600)).join("\n\n"), { estados: Object.fromEntries(runs.map((r) => [r.id, r.state])) });
      },
    },
    {
      name: "harness_status",
      label: "Estado de harnesses",
      description: "Consultalo para ubicar una corrida por tarea o rama y ver su estado y los harnesses instalados.",
      parameters: { type: "object", properties: {} },
      execute: async (): Promise<ToolResult> => ok(orquesta.view().join("\n")),
    },
    {
      name: "harness_result",
      label: "Resultado de harness",
      description: "Para revisar el trabajo de una corrida, devuelve su estado, los cambios del worktree y el final de la salida. La salida completa queda en el artefacto.",
      parameters: { type: "object", properties: { id: str(), tailChars: { type: "integer", minimum: 200, maximum: 20000, description: "Cuánta salida final traer; por defecto 2500" } }, required: ["id"] },
      execute: async (params): Promise<ToolResult> => {
        const run = orquesta.need(String(params.id));
        return ok(orquesta.summary(run, Number(params.tailChars) || 2500), { id: run.id, estado: run.state, artefacto: run.artifact });
      },
    },
    {
      name: "harness_stop",
      label: "Detener harness",
      description: "Detiene una corrida en curso (termina el grupo de procesos). Lo hecho hasta ahí queda en el worktree.",
      parameters: { type: "object", properties: { id: str() }, required: ["id"] },
      execute: async (params): Promise<ToolResult> => { const run = orquesta.stop(String(params.id)); return ok(`#${run.id} detenido.`); },
    },
    {
      name: "harness_cleanup",
      label: "Limpiar worktree",
      description: "Quita el worktree de una corrida terminada; con deleteBranch también su rama. Antes de limpiar, integrá lo que sirva (merge o cherry-pick desde la rama orobas/…).",
      parameters: { type: "object", properties: { id: str(), deleteBranch: { type: "boolean" } }, required: ["id"] },
      execute: async (params): Promise<ToolResult> => {
        const run = orquesta.need(String(params.id));
        if (run.state === "corriendo" || run.state === "esperando") throw new Error(`#${run.id} sigue corriendo: detenela primero.`);
        return ok((await orquesta.removeWorktree(run, params.deleteBranch === true)).join("\n") || "No había worktree.");
      },
    },
  ];
}

/** Mensaje que arma /ultra: el agente reparte la tarea entre harnesses en paralelo. */
export function ultraPrompt(task: string, options: { harnesses?: HarnessId[]; parts?: number; mode?: "repo" | "objetivo" } = {}): string {
  const available = options.harnesses?.length ? options.harnesses : (Object.values(HARNESSES).filter((s) => harnessBinary(s)).map((s) => s.id));
  const parts = Math.min(6, Math.max(2, options.parts ?? Math.min(4, Math.max(2, available.length))));
  if (options.mode === "objetivo") {
    return `Modo ultra sobre el objetivo: ${task}\n\nRepartí la evaluación en ${parts} frentes independientes (por host o ruta del alcance, o por clase de prueba) y lanzalos en paralelo con delegate (hasta 3 a la vez) y, si hace falta más, con harness_run harness=cyber (otra instancia de Orobas en un worktree, con la misma carpeta de datos). Cada frente con su encargo autosuficiente y su límite de gasto. Esperá con harness_wait, juntá los informes, deduplicá hallazgos y cerrá con un resumen por frente: qué se cubrió, qué quedó pendiente, qué hallazgos hay (con ids).`;
  }
  return `Modo ultra sobre el repositorio: ${task}\n\nHarnesses disponibles: ${available.join(", ") || "ninguno instalado (usá delegate)"}. Pasos: (1) leé el repositorio lo justo para partir la tarea en ${parts} partes independientes que no toquen los mismos archivos; (2) lanzá cada parte con harness_run en su propio worktree (repartí entre los harnesses disponibles; a cada uno un encargo autosuficiente: contexto, archivos, criterio de listo, cómo correr los tests, qué no tocar); (3) harness_wait; (4) leé cada harness_result y su diff; (5) integrá en orden las ramas orobas/… que sirvan (con shell: git merge --no-ff o cherry-pick desde la raíz del repo), corré los tests, y descartá o relanzá lo que no pasó; (6) harness_cleanup de cada worktree integrado o descartado; (7) cerrá con qué se integró, qué no y por qué, y los tests corridos.`;
}
