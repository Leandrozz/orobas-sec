// Lectura de código del proyecto: listar, buscar y leer archivos (por ejemplo un repositorio clonado
// con platform_cli) para revisar el código y después probar en vivo lo que sugiera. Nunca sale de la
// carpeta del proyecto ni entra en .cyber.
//
// Procedencia (src/secretos-sesion.ts, decisión de Lean del 22/11): la carpeta del proyecto es una por programa,
// donde el operador deja lo del objetivo (su repositorio clonado, el APK decompilado, un bundle bajado). Lo que se
// lee ahí es material del objetivo: el modelo lo ve tal cual, claves filtradas incluidas (son hallazgos), y las
// trazas lo tapan. Si la carpeta del proyecto es la máquina del operador (su carpeta personal, la raíz del disco o
// una que contiene su home: carpetaDelOperador), lo que se lee es suyo: se tapa por formato antes de mostrarse y
// el resultado sale con procedencia «local» (el registro tapa además lo que reconozca).
import { spawn } from "node:child_process";
import { closeSync, openSync, readFileSync, readSync, realpathSync, statSync } from "node:fs";
import { opendir, readFile, stat } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { StringDecoder } from "node:string_decoder";
import type { Tool, ToolResult } from "./agent.ts";
import { pacer } from "./ceder.ts";
import { carpetaDelOperador } from "./datos.ts";
import { redactSecrets } from "./plataformas.ts";
import { exec, SEARCH_PATH, which } from "./exec.ts";

const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });

// Nunca se recorren (ni con ocultos): control de versiones, evidencia del harness, cachés y dependencias o salidas de compilación.
const SKIP = new Set([".git", ".cyber", ".cache", "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__", ".terraform", "target", ".gradle", ".idea", "coverage"]);
const MAX_FILE = 1_000_000;
/** Una subcarpeta con más entradas que esto (caché, dataset, volcado) no se recorre: se avisa en la salida. */
const BIG_DIR = 5_000;
const MAX_FILES = 20_000;
/** Tope de bytes leídos por el recorrido propio (sin ripgrep). */
const MAX_BYTES = 200 * 1024 * 1024;
const SEARCH_TIMEOUT_MS = 60_000;

/** Ruta pedida, resuelta dentro del proyecto (también a través de enlaces simbólicos) y fuera de .cyber. */
export function insideProject(root: string, path = "."): string {
  const base = realpathSync(resolve(root));
  const target = resolve(base, path);
  let real = target;
  try {
    real = realpathSync(target);
  } catch {
    throw new Error(`No existe: ${path}`);
  }
  const rel = relative(base, real);
  if (rel.startsWith("..") || isAbsolute(rel)) throw new Error(`«${path}» está fuera de la carpeta del proyecto.`);
  if (rel.split(sep).includes(".cyber")) throw new Error("«.cyber» guarda credenciales y evidencia del harness: no se lee como código.");
  return real;
}

function binary(path: string): boolean {
  const fd = openSync(path, "r");
  try {
    const buffer = Buffer.alloc(4096);
    const read = readSync(fd, buffer, 0, buffer.length, 0);
    return buffer.subarray(0, read).includes(0);
  } finally {
    closeSync(fd);
  }
}

/** Carpeta que no se recorre: las de SKIP siempre, las ocultas salvo que se pidan. */
const skipDir = (name: string, hidden: boolean) => SKIP.has(name) || (!hidden && name.startsWith("."));

/** Entradas de una carpeta sin bloquear; `big` si pasa el tope (no se leen más). */
async function entriesOf(dir: string, limit: number): Promise<{ entries: Dirent[]; big: boolean }> {
  const entries: Dirent[] = [];
  try {
    for await (const entry of await opendir(dir, { bufferSize: 128 })) {
      if (entries.length >= limit) return { entries, big: true };
      entries.push(entry);
    }
  } catch {}
  return { entries, big: false };
}

interface WalkState {
  hidden: boolean;
  files: number;
  big: string[];
  deadline: number;
  signal?: AbortSignal;
}

/** Recorrido propio, asincrónico y ordenado (respaldo sin ripgrep): sin enlaces simbólicos, carpetas de SKIP, ocultas ni enormes. */
async function* walk(dir: string, state: WalkState, level = 0): AsyncGenerator<string> {
  const { entries, big } = await entriesOf(dir, level ? BIG_DIR : MAX_FILES);
  if (big && level) {
    state.big.push(dir);
    return;
  }
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    state.signal?.throwIfAborted();
    if (state.files >= MAX_FILES || Date.now() > state.deadline) return;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!skipDir(entry.name, state.hidden)) yield* walk(path, state, level + 1);
    } else if (entry.isFile()) {
      state.files++;
      yield path;
    }
  }
}

/**
 * Archivos de una carpeta del proyecto con el mismo recorrido que code_search sin ripgrep (sin .git,
 * node_modules, .cyber, ocultas ni carpetas enormes, con topes). Un archivo suelto se devuelve solo.
 */
export async function projectFiles(cwd: string, path = ".", options: { hidden?: boolean; timeoutMs?: number; signal?: AbortSignal } = {}): Promise<{ root: string; target: string; files: string[]; big: string[]; cut?: "tiempo" | "archivos" }> {
  const root = realpathSync(resolve(cwd));
  const target = insideProject(cwd, path);
  if ((await stat(target)).isFile()) return { root, target, files: [target], big: [] };
  const state: WalkState = { hidden: options.hidden === true, files: 0, big: [], deadline: Date.now() + (options.timeoutMs ?? SEARCH_TIMEOUT_MS), signal: options.signal };
  const files: string[] = [];
  for await (const file of walk(target, state)) files.push(file);
  const cut = state.files >= MAX_FILES ? "archivos" : Date.now() > state.deadline ? "tiempo" : undefined;
  return { root, target, files, big: state.big, ...(cut ? { cut } : {}) };
}

interface SearchOutcome {
  hits: string[];
  files: number;
  /** Por qué se cortó antes de terminar, si se cortó. */
  cut?: "tiempo" | "archivos" | "bytes";
  big: string[];
}

/** Línea de resultado: mismo formato con y sin ripgrep. `tapar`: en la máquina del operador, redactSecrets. */
const hitLine = (rel: string, line: number, text: string, tapar: (texto: string) => string) => `${rel}:${line}: ${tapar(text.trim()).slice(0, 240)}`;
const tal = (texto: string) => texto;

/** Globs que ripgrep entiende igual (o más amplio) que el filtro propio; con otros caracteres filtra sólo el propio. */
const rgGlob = (pattern: string) => /^[\w.*?/-]+$/.test(pattern) && !pattern.startsWith("/");

/**
 * Búsqueda con ripgrep en un subproceso: respeta .gitignore, sin carpetas ocultas (salvo que se pidan) ni las de SKIP,
 * archivos de hasta 1 MB, sin binarios ni enlaces. Se corta al llegar al tope, al vencer el tiempo o al abortar el turno.
 * Devuelve undefined si ripgrep no está o no entiende la expresión (el recorrido propio usa la sintaxis de JavaScript).
 */
async function ripgrep(options: { root: string; target: string; pattern: string; regex: boolean; glob?: string; filter?: RegExp; max: number; hidden: boolean; timeoutMs: number; signal?: AbortSignal; tapar?: (texto: string) => string }): Promise<SearchOutcome | undefined> {
  const rg = which("rg");
  if (!rg) return undefined;
  const target = relative(options.root, options.target) || ".";
  const argv = ["--no-config", "--line-number", "--with-filename", "--null", "--no-heading", "--color", "never", "--sort", "path", "--crlf", "--ignore-case", "--max-filesize", String(MAX_FILE), "--max-columns", "4000", "--max-columns-preview", "--stats", "--hidden"];
  if (!options.regex) argv.push("--fixed-strings");
  if (options.glob && rgGlob(options.glob)) argv.push("--iglob", options.glob);
  // Las exclusiones van después del glob pedido: en ripgrep gana la última que coincide.
  if (!options.hidden) argv.push("--glob", "!.*/");
  for (const name of SKIP) argv.push("--glob", `!${name}/`);
  argv.push("--regexp", options.pattern, "--", target);
  return new Promise<SearchOutcome | undefined>((done, fail) => {
    const child = spawn(rg, argv, { cwd: options.root, env: { PATH: SEARCH_PATH, HOME: homedir(), LANG: "C.UTF-8" }, stdio: ["ignore", "pipe", "pipe"], detached: true });
    const hits: string[] = [];
    const withHits = new Set<string>();
    let stats = "";
    let stderr = "";
    let pending = "";
    let cut: SearchOutcome["cut"];
    let finished = false;
    const decoder = new StringDecoder("utf8");
    const kill = () => {
      try { process.kill(-child.pid!, "SIGKILL"); } catch {}
    };
    const take = (line: string) => {
      const nul = line.indexOf("\0");
      if (nul < 0) {
        stats += `${line}\n`; // con --stats el resumen sale al final, sin NUL
        return;
      }
      if (hits.length >= options.max) return;
      const rel = line.slice(0, nul).replace(/^\.\//, "");
      const rest = line.slice(nul + 1);
      const colon = rest.indexOf(":");
      if (colon < 0) return;
      if (options.filter && !options.filter.test(rel.split(sep).join("/"))) return;
      hits.push(hitLine(rel, Number(rest.slice(0, colon)), rest.slice(colon + 1), options.tapar ?? tal));
      withHits.add(rel);
      if (hits.length >= options.max) kill();
    };
    child.stdout!.on("data", (chunk: Buffer) => {
      pending += decoder.write(chunk);
      let newline: number;
      while ((newline = pending.indexOf("\n")) >= 0) {
        take(pending.slice(0, newline));
        pending = pending.slice(newline + 1);
      }
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      if (stderr.length < 8192) stderr += chunk.toString("utf8");
    });
    const timer = setTimeout(() => {
      cut = "tiempo";
      kill();
    }, options.timeoutMs);
    const onAbort = () => kill();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const end = (result?: SearchOutcome, error?: Error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      if (error) fail(error);
      else done(result);
    };
    child.on("error", () => end(undefined)); // no arrancó: queda el recorrido propio
    child.on("close", (code) => {
      if (pending) take(pending + decoder.end());
      if (options.signal?.aborted) return end(undefined, options.signal.reason instanceof Error ? options.signal.reason : new Error("Búsqueda cancelada"));
      // Código 2 con salida es un error parcial (carpetas sin permiso); sin salida y con la expresión rechazada, va el recorrido propio.
      if (code === 2 && !hits.length && /regex parse error|error parsing|look-around|backreferences/i.test(stderr)) return end(undefined);
      const searched = Number(/^(\d+) files searched$/m.exec(stats)?.[1] ?? withHits.size);
      end({ hits, files: searched, cut, big: [] });
    });
    if (options.signal?.aborted) onAbort();
  });
}

/** Respaldo sin ripgrep (o con una expresión que ripgrep no entiende): recorrido propio, asincrónico y con topes. */
async function walkSearch(options: { root: string; target: string; single: boolean; matcher: RegExp; filter?: RegExp; max: number; hidden: boolean; timeoutMs: number; signal?: AbortSignal; tapar?: (texto: string) => string }): Promise<SearchOutcome> {
  const pause = pacer(options.signal);
  const state: WalkState = { hidden: options.hidden, files: 0, big: [], deadline: Date.now() + options.timeoutMs, signal: options.signal };
  const hits: string[] = [];
  let files = 0;
  let bytes = 0;
  let cut: SearchOutcome["cut"];
  const candidates: AsyncIterable<string> | string[] = options.single ? [options.target] : walk(options.target, state);
  for await (const file of candidates) {
    await pause();
    if (Date.now() > state.deadline) {
      cut = "tiempo";
      break;
    }
    const rel = relative(options.root, file) || ".";
    if (options.filter && !options.filter.test(rel.split(sep).join("/"))) continue;
    let content: Buffer;
    try {
      if ((await stat(file)).size > MAX_FILE) continue;
      content = await readFile(file);
    } catch {
      continue;
    }
    if (content.subarray(0, 4096).includes(0)) continue;
    files++;
    bytes += content.length;
    const lines = content.toString("utf8").split(/\r?\n/);
    for (let index = 0; index < lines.length && hits.length < options.max; index++) {
      if (options.matcher.test(lines[index]!)) hits.push(hitLine(rel, index + 1, lines[index]!, options.tapar ?? tal));
    }
    if (hits.length >= options.max) break;
    if (bytes >= MAX_BYTES) {
      cut = "bytes";
      break;
    }
  }
  if (!cut && state.files >= MAX_FILES) cut = "archivos";
  if (!cut && Date.now() > state.deadline) cut = "tiempo";
  return { hits, files, cut, big: state.big };
}

// Por partes: reemplazar en cadena convertía el «*» y el «?» del «(?:.*/)?» ya puesto y **/*.ts nunca coincidía.
const GLOB_PARTS: Record<string, string> = { "**/": "(?:.*/)?", "**": ".*", "*": "[^/]*", "?": "[^/]" };
const glob = (pattern: string) => new RegExp(`^${pattern.split(/(\*\*\/|\*\*|\*|\?)/).map((part) => GLOB_PARTS[part] ?? part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("")}$`, "i");

/** Pie común: lo que no se recorrió o por qué se cortó, para que el agente sepa qué afinar. */
function notes(outcome: { cut?: SearchOutcome["cut"]; big: string[]; hidden?: string[] }, show: (path: string) => string, timeoutMs: number): string[] {
  const lines: string[] = [];
  if (outcome.cut === "tiempo") lines.push(`… (búsqueda cortada a los ${Math.round(timeoutMs / 1000)} s: el resultado es parcial; acotá con path o glob)`);
  if (outcome.cut === "archivos") lines.push(`… (se revisaron ${MAX_FILES} archivos y se cortó: acotá con path o glob)`);
  if (outcome.cut === "bytes") lines.push("… (se leyeron 200 MB y se cortó: acotá con path o glob)");
  if (outcome.big.length) lines.push(`… (sin recorrer, más de ${BIG_DIR} entradas: ${outcome.big.slice(0, 5).map(show).join(", ")}${outcome.big.length > 5 ? ", …" : ""}; pasala como path si hace falta)`);
  if (outcome.hidden?.length) lines.push(`… (carpetas ocultas sin listar: ${outcome.hidden.slice(0, 8).join(", ")}${outcome.hidden.length > 8 ? ", …" : ""}; ocultos: true para incluirlas)`);
  return lines;
}

/** `ripgrep: false` fuerza el recorrido propio (pruebas). */
export function createCodeTools(context: { cwd: string; ripgrep?: boolean; delOperador?: (cwd: string) => boolean }): Tool[] {
  const root = () => realpathSync(resolve(context.cwd));
  const show = (path: string) => relative(root(), path) || ".";
  /** Procedencia de lo que se lee y cómo se muestra: tal cual (del objetivo) o tapado por formato (del operador). */
  const lectura = (): { procedencia: "objetivo" | "local"; tapar: (texto: string) => string } =>
    (context.delOperador ?? carpetaDelOperador)(context.cwd) ? { procedencia: "local", tapar: (texto) => redactSecrets(texto) } : { procedencia: "objetivo", tapar: tal };

  const list: Tool = {
    name: "code_list",
    label: "Listar código",
    description: "Lista carpetas y archivos dentro de la carpeta del proyecto (por ejemplo un repositorio clonado), con tamaño, sin .git, node_modules, .cache, .cyber ni carpetas ocultas (.github, .vscode…: con ocultos: true). Una carpeta enorme se nombra sin abrirla. Para orientarse antes de buscar o leer.",
    parameters: { type: "object", properties: { path: { type: "string", description: "Carpeta relativa al proyecto; por defecto la raíz" }, depth: { type: "integer", minimum: 1, maximum: 6 }, ocultos: { type: "boolean", description: "Incluir carpetas ocultas (.github, .vscode…); .git, .cyber y .cache nunca" } }, required: [] },
    parallel: true,
    replay: "safe",
    execute: async (params, signal): Promise<ToolResult> => {
      const start = insideProject(context.cwd, params.path ?? ".");
      const depth = params.depth ?? 2;
      const hidden = params.ocultos === true;
      const pause = pacer(signal);
      const lines: string[] = [];
      const big: string[] = [];
      const hiddenDirs = new Set<string>();
      const visit = async (dir: string, level: number) => {
        if (lines.length >= 400) return;
        const read = await entriesOf(dir, level ? BIG_DIR : MAX_FILES);
        const indent = "  ".repeat(level);
        if (read.big && level) {
          big.push(dir);
          lines.push(`${indent}… (más de ${BIG_DIR} entradas: no se abre)`);
          return;
        }
        for (const entry of read.entries.sort((a, b) => Number(b.isDirectory()) - Number(a.isDirectory()) || a.name.localeCompare(b.name))) {
          await pause();
          if (lines.length >= 400) return;
          if (SKIP.has(entry.name)) continue;
          const path = join(dir, entry.name);
          if (entry.isDirectory()) {
            if (skipDir(entry.name, hidden)) {
              hiddenDirs.add(entry.name);
              continue;
            }
            lines.push(`${indent}${entry.name}/`);
            if (level + 1 < depth) await visit(path, level + 1);
          } else if (entry.isFile()) {
            let size = "?";
            try { size = String((await stat(path)).size); } catch {}
            lines.push(`${indent}${entry.name}  ${size} B`);
          }
        }
      };
      await visit(start, 0);
      const tail = notes({ big, hidden: [...hiddenDirs] }, show, 0);
      return { text: `${show(start)}/\n${lines.join("\n")}${lines.length >= 400 ? "\n… (recortado: bajá la profundidad o elegí una subcarpeta)" : ""}${tail.length ? `\n${tail.join("\n")}` : ""}`, details: { entradas: lines.length }, procedencia: lectura().procedencia };
    },
  };

  const search: Tool = {
    name: "code_search",
    label: "Buscar en el código",
    description:
      "Busca un texto o una expresión regular en los archivos de texto del proyecto (o de una subcarpeta, con filtro glob como **/*.ts). Devuelve archivo:línea y la línea tal cual: una clave filtrada en el código del objetivo se ve entera (es un hallazgo); si el proyecto es la carpeta personal del operador, sus secretos van tapados. Para encontrar rutas, controles de acceso, consultas SQL, deserialización, secretos y configuraciones. " +
      "Respeta .gitignore y no entra en .git, node_modules, .cache, carpetas ocultas (salvo ocultos: true) ni carpetas enormes; archivos de hasta 1 MB y corte a los 60 s con resultado parcial.",
    parameters: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        regex: { type: "boolean", description: "Interpretar pattern como expresión regular (por defecto texto literal, sin distinguir mayúsculas)" },
        path: { type: "string" },
        glob: { type: "string" },
        max: { type: "integer", minimum: 1, maximum: 300 },
        ocultos: { type: "boolean", description: "Incluir carpetas ocultas (.github, .vscode…); .git, .cyber y .cache nunca" },
      },
      required: ["pattern"],
    },
    parallel: true,
    replay: "safe",
    execute: async (params, signal): Promise<ToolResult> => {
      const base = root();
      const start = insideProject(context.cwd, params.path ?? ".");
      const pattern = String(params.pattern);
      // La expresión se valida con la sintaxis de JavaScript aunque busque ripgrep: el error es el mismo de siempre.
      const matcher = params.regex ? new RegExp(pattern, "i") : new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      const filter = params.glob ? glob(params.glob) : undefined;
      const max = params.max ?? 120;
      const hidden = params.ocultos === true;
      const single = (await stat(start)).isFile();
      const { procedencia, tapar } = lectura();
      const common = { root: base, target: start, filter, max, hidden, timeoutMs: SEARCH_TIMEOUT_MS, signal, tapar };
      const outcome =
        (!single && context.ripgrep !== false ? await ripgrep({ ...common, pattern, regex: params.regex === true, glob: params.glob }) : undefined) ??
        (await walkSearch({ ...common, single, matcher }));
      const { hits, files } = outcome;
      const tail = notes(outcome, show, SEARCH_TIMEOUT_MS);
      const body = hits.length ? `${hits.join("\n")}${hits.length >= max ? `\n… (tope de ${max}; afiná la búsqueda)` : ""}` : `Sin coincidencias en ${files} archivos.`;
      return { text: `${body}${tail.length ? `\n${tail.join("\n")}` : ""}`, details: { coincidencias: hits.length, archivos: files }, procedencia };
    },
  };

  const read: Tool = {
    name: "code_read",
    label: "Leer código",
    description: "Lee un archivo de texto del proyecto con números de línea (por defecto 200 líneas desde «desde»). Lo que hay en la carpeta del proyecto es del objetivo y se ve tal cual, claves filtradas incluidas; si el proyecto es la carpeta personal del operador, sus secretos van tapados.",
    parameters: { type: "object", properties: { path: { type: "string" }, desde: { type: "integer", minimum: 1 }, lineas: { type: "integer", minimum: 1, maximum: 800 } }, required: ["path"] },
    parallel: true,
    replay: "safe",
    execute: (params): ToolResult => {
      const file = insideProject(context.cwd, params.path);
      const stat = statSync(file);
      if (!stat.isFile()) throw new Error(`«${params.path}» no es un archivo: usá code_list.`);
      if (stat.size > 5 * MAX_FILE) throw new Error("Archivo demasiado grande para leer entero: buscá con code_search.");
      if (binary(file)) throw new Error("Es un archivo binario.");
      const lines = readFileSync(file, "utf8").split(/\r?\n/);
      const from = Math.max(1, params.desde ?? 1);
      const count = params.lineas ?? 200;
      const window = lines.slice(from - 1, from - 1 + count);
      const width = String(from + window.length).length;
      const body = window.map((line, index) => `${String(from + index).padStart(width)}  ${line}`).join("\n");
      const { procedencia, tapar } = lectura();
      return { text: `${show(file)} · líneas ${from}-${from + window.length - 1} de ${lines.length}\n${tapar(body)}`, details: { total: lines.length }, procedencia };
    },
  };

  /** Análisis estático con herramientas de la caja, sobre la carpeta del proyecto: sólo lectura, sin red. */
  const semgrep: Tool = {
    name: "code_semgrep",
    label: "Semgrep sobre el código",
    description:
      "Corre semgrep sobre una carpeta del proyecto con un patrón propio (sintaxis de semgrep y lenguaje) o un archivo de reglas YAML local; nunca baja reglas de la red. Muestra archivo, línea y un extracto corto (para que un secreto no viaje entero al chat). " +
      "Un resultado es una pista: confirmá leyendo el código con code_read antes de registrar candidato con evidencia.",
    parameters: { type: "object", properties: { path: { type: "string", description: "Carpeta relativa al proyecto con el código; por defecto la raíz" }, pattern: { type: "string", description: "Patrón de semgrep (usar con lang)" }, lang: { type: "string", description: "Lenguaje: js, ts, python, go, java…" }, config: { type: "string", description: "Archivo YAML de reglas local, en vez de pattern" }, timeoutSec: { type: "integer", minimum: 10, maximum: 600 } }, required: [] },
    execute: async (params, signal): Promise<ToolResult> => {
      const root = realpathSync(resolve(context.cwd));
      const target = insideProject(context.cwd, params.path ?? ".");
      if (!which("semgrep")) throw new Error("semgrep no está instalado. Instalarlo: pip install semgrep (o uvx semgrep).");
      const argv = [which("semgrep")!, "--json", "--quiet", "--metrics=off"];
      if (params.config) argv.push("--config", insideProject(context.cwd, params.config));
      else {
        if (!params.pattern) throw new Error("Pasale pattern (con lang) o config (archivo YAML local)");
        if (!/^[A-Za-z0-9_-]+$/.test(String(params.lang ?? "js"))) throw new Error("lang inválido");
        argv.push("--lang", String(params.lang ?? "js"), "--pattern", String(params.pattern));
      }
      argv.push(target);
      const result = await exec({ argv, cwd: root, timeoutMs: Math.min(600, params.timeoutSec ?? 300) * 1000, maxOutputBytes: 4_000_000, signal });
      let rows: Array<{ file?: string; line?: number; rule?: string; extract?: string }> = [];
      try { rows = (JSON.parse(result.stdout).results ?? []).slice(0, 30); } catch { /* sin salida JSON */ }
      const shown = rows.map((item) => `${String(item.file ?? "?").replace(`${root}/`, "")}:${item.line ?? "?"} · ${item.rule ?? "?"} · ${String(item.extract ?? "").slice(0, 60)}`);
      const text = rows.length ? `Semgrep: ${rows.length} resultado(s):\n${shown.join("\n")}\nSon pistas: confirmá cada una leyendo el código con code_read antes de registrar candidato.` : `Semgrep: sin resultados con esa regla en ${target}. Revisá el patrón o probá code_search.`;
      return { text, details: { hallazgos: rows.length }, procedencia: lectura().procedencia };
    },
  };

  const gitleaks: Tool = {
    name: "code_gitleaks",
    label: "Gitleaks sobre el código",
    description:
      "Busca secretos (claves, tokens, credenciales) en la carpeta del proyecto con gitleaks --no-git: sólo lectura. Muestra archivo, línea, regla y el valor: una clave filtrada en el código del objetivo es un hallazgo y se ve entera. Si el proyecto es la carpeta personal del operador, sin el valor. " +
      "La exposición real del objetivo se confirma con otras herramientas, dentro del alcance.",
    parameters: obj({ path: { type: "string", description: "Carpeta relativa al proyecto; por defecto la raíz" }, timeoutSec: { type: "integer", minimum: 10, maximum: 600 } }, []),
    execute: async (params, signal): Promise<ToolResult> => {
      const root = realpathSync(resolve(context.cwd));
      const target = insideProject(context.cwd, params.path ?? ".");
      if (!which("gitleaks")) throw new Error("gitleaks no está instalado. Instalarlo: pacman -S gitleaks (o brew install gitleaks).");
      const { procedencia } = lectura();
      const argv = [which("gitleaks")!, "detect", "--source", target, "--no-git", "--no-banner", ...(procedencia === "local" ? ["--redact"] : []), "--report-format", "json", "--report-path", "-", "--exit-code", "0"];
      const result = await exec({ argv, cwd: root, timeoutMs: Math.min(600, params.timeoutSec ?? 300) * 1000, maxOutputBytes: 2_000_000, signal });
      // El informe JSON de gitleaks 8 usa File, StartLine, RuleID y Secret; se aceptan también en minúsculas.
      let rows: Array<Record<string, unknown>> = [];
      try { rows = JSON.parse(result.stdout); } catch { /* sin salida JSON */ }
      if (!Array.isArray(rows)) rows = [];
      const campo = (item: Record<string, unknown>, ...nombres: string[]) => nombres.map((nombre) => item[nombre]).find((valor) => valor !== undefined && valor !== "");
      const shown = rows.slice(0, 30).map((item) => {
        const secreto = procedencia === "objetivo" ? campo(item, "Secret", "secret", "Match", "match") : undefined;
        return `${String(campo(item, "File", "file") ?? "?").replace(`${root}/`, "")}:${String(campo(item, "StartLine", "line") ?? "?")} · ${String(campo(item, "RuleID", "rule") ?? "?")}${secreto === undefined ? "" : ` · ${String(secreto).slice(0, 400)}`}`;
      });
      const text = rows.length ? `Gitleaks: ${rows.length} secreto(s) en el código (mostrando ${shown.length}):\n${shown.join("\n")}` : `Gitleaks: sin secretos detectados en ${target}.`;
      return { text, details: { secretos: rows.length }, procedencia };
    },
  };

  return [list, search, read, semgrep, gitleaks];
}
