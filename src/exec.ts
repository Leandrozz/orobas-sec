// Ejecutor de procesos: argv sin shell, grupo de procesos propio, timeout duro, límites de
// salida y cancelación. Los binarios se resuelven contra una lista fija, nunca desde el modelo.
import { type ChildProcess, spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";

export interface ExecOptions {
  /** Binario (nombre o ruta) y argumentos; no se interpreta ningún shell. */
  argv: string[];
  cwd?: string;
  /** Variables de entorno permitidas; el resto no se hereda (no viajan claves de API al proceso hijo). */
  env?: Record<string, string>;
  timeoutMs?: number;
  /** Bytes máximos conservados de stdout y stderr; el resto se descarta y se marca truncado. */
  maxOutputBytes?: number;
  stdin?: string | Buffer;
  signal?: AbortSignal;
  onOutput?: (chunk: string, stream: "stdout" | "stderr") => void;
}

export interface ExecResult {
  argv: string[];
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
  cancelled: boolean;
  durationMs: number;
}

/** Rutas donde se buscan binarios: las del sistema más ~/go/bin, ~/.local/bin y Homebrew (Apple Silicon: /opt/homebrew; Intel: /usr/local). */
export const SEARCH_PATH = [join(homedir(), "go", "bin"), join(homedir(), ".local", "bin"), "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/bin", "/bin"].join(delimiter);

export function which(name: string): string | undefined {
  if (name.includes("/")) {
    try {
      accessSync(name, constants.X_OK);
      return name;
    } catch {
      return undefined;
    }
  }
  for (const dir of SEARCH_PATH.split(delimiter)) {
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {}
  }
  return undefined;
}

function collect(max: number, onOutput?: (chunk: string) => void) {
  const chunks: Buffer[] = [];
  let size = 0;
  let truncated = false;
  return {
    push(chunk: Buffer) {
      onOutput?.(chunk.toString("utf8"));
      if (size >= max) {
        truncated = true;
        return;
      }
      const room = max - size;
      chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
      size += Math.min(chunk.length, room);
      if (chunk.length > room) truncated = true;
    },
    text: () => Buffer.concat(chunks).toString("utf8"),
    get truncated() {
      return truncated;
    },
  };
}

/** Mata el grupo de procesos entero: primero TERM, y KILL si no se va. */
function killGroup(child: ChildProcess): void {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {}
  setTimeout(() => {
    try {
      process.kill(-child.pid!, "SIGKILL");
    } catch {}
  }, 2000).unref();
}

export async function exec(options: ExecOptions): Promise<ExecResult> {
  const [name, ...args] = options.argv;
  if (!name) throw new Error("argv vacío");
  const binary = which(name);
  if (!binary) throw new Error(`No encuentro el binario «${name}». Instalalo o revisá ${SEARCH_PATH}`);
  const started = Date.now();
  const max = options.maxOutputBytes ?? 4 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    let timedOut = false;
    let cancelled = false;
    const child = spawn(binary, args, {
      cwd: options.cwd,
      env: { PATH: SEARCH_PATH, HOME: homedir(), LANG: "C.UTF-8", TERM: "dumb", ...options.env },
      stdio: [options.stdin !== undefined ? "pipe" : "ignore", "pipe", "pipe"],
      detached: true, // grupo de procesos propio, para poder matar también a los hijos
    });
    const out = collect(max, options.onOutput && ((chunk) => options.onOutput!(chunk, "stdout")));
    const err = collect(max, options.onOutput && ((chunk) => options.onOutput!(chunk, "stderr")));
    child.stdout!.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr!.on("data", (chunk: Buffer) => err.push(chunk));
    if (options.stdin !== undefined) {
      // Un hijo que sale sin leer toda la entrada (un PoC que crashea) no tumba al harness con EPIPE.
      child.stdin!.on("error", () => {});
      child.stdin!.end(options.stdin);
    }
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup(child);
    }, options.timeoutMs ?? 300_000);
    const onAbort = () => {
      cancelled = true;
      killGroup(child);
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    child.on("error", (error) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      reject(error);
    });
    child.on("close", (exitCode, signal) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      resolve({
        argv: [binary, ...args],
        exitCode,
        signal,
        stdout: out.text(),
        stderr: err.text(),
        truncated: out.truncated || err.truncated,
        timedOut,
        cancelled,
        durationMs: Date.now() - started,
      });
    });
  });
}
