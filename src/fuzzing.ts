// Harness y fuzzing, el método de Provos: una hipótesis estática no vale hasta que un ejecutable dispara el bug.
// Sólo dentro de la caja de Orobas (el contenedor del proyecto): la imagen trae clang 16 de Debian con
// compiler-rt (libFuzzer, ASan, UBSan, MSan) y llvm-symbolizer. En la máquina del operador nada de esto se
// ofrece ni se ejecuta, igual que REA.
//
// Herramientas del catálogo, por demanda (grupo «harness y fuzzing», habilidad harness-fuzzing):
//   harness_build  compila un harness (LLVMFuzzerTestOneInput) o un PoC (main) contra el código del objetivo.
//   fuzz_run       corre el fuzzer acotado; junta, reproduce, minimiza y deduplica los crashes.
//   poc_run        corre un PoC o harness sobre un input N veces y dice si reproduce de forma determinista.
//
// API interna (la usan la verificación por ejecución y /investigar, sin pasar por el modelo):
//   fuzzEntorno(base, opciones)              → FuzzEntorno, o undefined fuera de la caja
//   compilarHarness(entorno, pedido, signal) → Compilacion
//   correrFuzzer(entorno, pedido, signal)    → CorridaFuzz
//   reproducirPoc(entorno, pedido, signal)   → Reproduccion (también con { command, cwd })
//   runPoc(entorno, { command, cwd, runs, timeoutMs, signal }) → Reproduccion, que incluye { exitCode, reproduce, corridas, salida }
//   pocRunner(entorno)                       → runPoc atado al entorno, para inyectar (EngineOptions.investigacion.poc)
//   clasificarReporte(salida)                → ReporteSanitizer | undefined (cualquier salida de un sanitizer)
//   crashesConocidos(entorno, harness)       → lo que ya encontró fuzz_run para ese harness
// Los artefactos de las tres herramientas traen `command`, el comando exacto de reproducción que poc_run (y runPoc)
// vuelve a aceptar; los details de poc_run, `reproduce`, `corridas` y `exitCode`.
//
// Todo lo que lee o escribe queda dentro de la carpeta del proyecto (lo propio, en harness/out/<nombre>/). Los
// procesos corren sin shell, con entorno mínimo (sin claves ni proxies), con tope de tiempo, memoria y procesos,
// con prioridad baja (nice) y sin red: cada binario lleva enlazado distro/fuzz/sin-red.c.
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { cpus } from "node:os";
import { basename, dirname, extname, isAbsolute, join, relative, resolve } from "node:path";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { insideProject } from "./codigo.ts";
import { exec, SEARCH_PATH, type ExecOptions, type ExecResult } from "./exec.ts";
import { t } from "./idioma.ts";
import { enCaja } from "./instalar-herramientas.ts";

/** Dónde deja la imagen cada cosa (distro/Dockerfile: enlaces a /usr/lib/llvm-16/bin). */
export const FUZZ = {
  llvm: "16",
  clang: "/usr/local/bin/clang",
  clangxx: "/usr/local/bin/clang++",
  symbolizer: "/usr/local/bin/llvm-symbolizer",
  pkgConfig: "/usr/bin/pkg-config",
  nice: "/usr/bin/nice",
  /** Carpeta del proyecto donde quedan binarios, corpus, corridas y crashes, una por harness. */
  salida: "harness/out",
  /** El corte de red que se enlaza en cada binario; la imagen lo compila y lo prueba al construirse. */
  sinRed: join(import.meta.dirname, "..", "distro", "fuzz", "sin-red.c"),
} as const;

/** Las herramientas de este módulo (las del grupo del catálogo) y su habilidad. */
export const HERRAMIENTAS_FUZZ = ["harness_build", "fuzz_run", "poc_run"];
export const HABILIDAD_FUZZ = "harness-fuzzing";

export interface BinariosFuzz { clang: string; clangxx: string; symbolizer: string; pkgConfig: string; nice: string }

/** Topes. Los «Max» son el techo de lo que puede pedir el modelo; los otros, lo que se usa si no pide nada. */
export interface LimitesFuzz {
  compilarSeg: number;
  fuzzSeg: number;
  fuzzSegMax: number;
  memoriaMb: number;
  memoriaMbMax: number;
  /** Tope por entrada (el -timeout de libFuzzer); pasarlo es un timeout. */
  entradaSeg: number;
  entradaSegMax: number;
  procesos: number;
  procesosMax: number;
  pocVeces: number;
  pocVecesMax: number;
  minimizarSeg: number;
  /** Crashes nuevos que se minimizan por corrida (cada uno tarda hasta minimizarSeg). */
  minimizarMax: number;
  /** Crashes que se procesan por corrida (los demás quedan en la carpeta de la corrida). */
  crashesMax: number;
  /** Prioridad de los procesos (nice); 0 la deja como está. */
  nice: number;
}

export const LIMITES_FUZZ: LimitesFuzz = {
  compilarSeg: 600,
  fuzzSeg: 120,
  fuzzSegMax: 1800,
  memoriaMb: 2048,
  memoriaMbMax: 8192,
  entradaSeg: 10,
  entradaSegMax: 120,
  procesos: 1,
  procesosMax: Math.max(1, Math.min(4, cpus().length - 1)),
  pocVeces: 5,
  pocVecesMax: 50,
  minimizarSeg: 60,
  minimizarMax: 3,
  crashesMax: 10,
  nice: 10,
};

/**
 * Topes efectivos: los de fábrica, los del operador por entorno (CYBER_FUZZ_SEG, CYBER_FUZZ_SEG_MAX,
 * CYBER_FUZZ_MB, CYBER_FUZZ_MB_MAX, CYBER_FUZZ_PROCESOS_MAX) y los que fija el código (pruebas), en ese orden.
 */
export function limitesFuzz(base: Partial<LimitesFuzz> = {}, env: NodeJS.ProcessEnv = process.env): LimitesFuzz {
  const num = (name: string) => {
    const value = Number(env[name]);
    return env[name] && Number.isFinite(value) && value > 0 ? Math.floor(value) : undefined;
  };
  const delEntorno: Partial<LimitesFuzz> = {};
  for (const [variable, clave] of [["CYBER_FUZZ_SEG", "fuzzSeg"], ["CYBER_FUZZ_SEG_MAX", "fuzzSegMax"], ["CYBER_FUZZ_MB", "memoriaMb"], ["CYBER_FUZZ_MB_MAX", "memoriaMbMax"], ["CYBER_FUZZ_PROCESOS_MAX", "procesosMax"]] as const) {
    const value = num(variable);
    if (value !== undefined) delEntorno[clave] = value;
  }
  const out = { ...LIMITES_FUZZ, ...delEntorno, ...base };
  out.fuzzSeg = Math.min(out.fuzzSeg, out.fuzzSegMax);
  out.memoriaMb = Math.min(out.memoriaMb, out.memoriaMbMax);
  out.entradaSeg = Math.min(out.entradaSeg, out.entradaSegMax);
  out.procesos = Math.min(out.procesos, out.procesosMax);
  out.pocVeces = Math.min(out.pocVeces, out.pocVecesMax);
  return out;
}

export interface FuzzEntorno {
  /** Carpeta del proyecto, real. */
  cwd: string;
  artifacts: Artifacts;
  binarios: BinariosFuzz;
  limites: LimitesFuzz;
  event?: (type: string, payload: Record<string, unknown>) => void;
  /** Ejecutor de procesos; por defecto exec (argv sin shell, grupo propio, tope duro, cancelable). */
  ejecutar?: (options: ExecOptions) => Promise<ExecResult>;
}

export interface FuzzOpciones {
  /** Por defecto, enCaja(). Las pruebas lo fijan. */
  enCaja?: boolean;
  /** Compilador, symbolizer y demás; por defecto los de la imagen. Las pruebas pasan dobles. */
  binarios?: Partial<BinariosFuzz>;
  limites?: Partial<LimitesFuzz>;
}

/** ¿Trae esta imagen el compilador? */
export const fuzzInstalado = (clang: string = FUZZ.clang) => existsSync(clang);

/** Harness y fuzzing usables: dentro de la caja y con la imagen que los trae. */
export const fuzzDisponible = (inside: boolean = enCaja(), clang?: string) => inside && fuzzInstalado(clang);

/** El entorno de las herramientas, o nada fuera de la caja (o en una caja vieja sin clang: /herramientas lo dice). */
export function fuzzEntorno(base: { cwd: string; artifacts: Artifacts; event?: FuzzEntorno["event"] }, opciones: FuzzOpciones = {}): FuzzEntorno | undefined {
  const binarios: BinariosFuzz = { clang: FUZZ.clang, clangxx: FUZZ.clangxx, symbolizer: FUZZ.symbolizer, pkgConfig: FUZZ.pkgConfig, nice: FUZZ.nice, ...opciones.binarios };
  if (!fuzzDisponible(opciones.enCaja ?? enCaja(), binarios.clang)) return undefined;
  return { cwd: realpathSync(resolve(base.cwd)), artifacts: base.artifacts, event: base.event, binarios, limites: limitesFuzz(opciones.limites) };
}

/** Para /herramientas: versión adentro de la caja, «sólo en la caja» afuera. Líneas cortas (entran en 80 columnas). */
export function fuzzStatus(options: { enCaja?: boolean; instalado?: boolean } = {}): string[] {
  const inside = options.enCaja ?? enCaja();
  if (!inside) return [`clang      · ${t("sólo en la caja (el contenedor de Orobas); acá no se ofrece", "box only (the Orobas container); not offered here")}`];
  if (!(options.instalado ?? fuzzInstalado())) return [`clang      ✗ ${t("falta en esta imagen · cyber --actualizar", "missing from this image · cyber --actualizar")}`];
  return [
    `clang      ✓ LLVM ${FUZZ.llvm} · libFuzzer, ASan, UBSan, MSan`,
    `             harness_build, fuzz_run, poc_run · ${t("sin red", "no network")}`,
  ];
}

// ───────────────────────────── rutas ─────────────────────────────

const NOMBRE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const C_EXT = /\.c$/;
const CXX_EXT = /\.(cc|cpp|cxx|C)$/;
const LINK_EXT = /\.(o|a|so(\.\d+)*)$/;
const MAX_FUENTE = 8 * 1024 * 1024;
const MAX_BINARIO = 1024 * 1024 * 1024;

/** Una ruta que existe y queda dentro del proyecto (mismo chequeo que apk_analyze y code_read: enlaces resueltos, sin .cyber). */
function enProyecto(entorno: FuzzEntorno, value: unknown, campo: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${campo}: falta la ruta.`);
  const path = value.trim();
  if (path.startsWith("~") || path.includes("\0")) throw new Error(`${campo}: «${path}» está fuera de la carpeta del proyecto.`);
  try {
    return insideProject(entorno.cwd, path);
  } catch (error) {
    throw new Error(`${campo}: ${(error as Error).message}`);
  }
}

function archivoEnProyecto(entorno: FuzzEntorno, value: unknown, campo: string): string {
  const real = enProyecto(entorno, value, campo);
  if (!statSync(real).isFile()) throw new Error(`${campo}: «${String(value)}» no es un archivo.`);
  return real;
}

function carpetaEnProyecto(entorno: FuzzEntorno, value: unknown, campo: string): string {
  const real = enProyecto(entorno, value, campo);
  if (!statSync(real).isDirectory()) throw new Error(`${campo}: «${String(value)}» no es una carpeta.`);
  return real;
}

/** Crea (si hace falta) una carpeta propia dentro del proyecto, paso a paso: un enlace que salga del proyecto no se sigue. */
function carpeta(entorno: FuzzEntorno, ...partes: string[]): string {
  let actual = entorno.cwd;
  for (const parte of partes.flatMap((item) => item.split("/")).filter(Boolean)) {
    if (parte === "." || parte === "..") throw new Error(`Ruta inválida: ${partes.join("/")}`);
    const siguiente = join(actual, parte);
    let existe = true;
    try { lstatSync(siguiente); } catch { existe = false; }
    if (existe) {
      actual = insideProject(entorno.cwd, siguiente);
      if (!statSync(actual).isDirectory()) throw new Error(`${relative(entorno.cwd, siguiente)} no es una carpeta.`);
    } else {
      mkdirSync(siguiente);
      actual = siguiente;
    }
  }
  return actual;
}

const rel = (entorno: FuzzEntorno, path: string) => relative(entorno.cwd, path) || ".";
const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");
const sha256Archivo = (path: string) => sha256(readFileSync(path));

/** Una línea de shell legible (y copiable) para un argv: sólo comillas donde hacen falta. */
export function lineaShell(argv: string[]): string {
  return argv.map((arg) => (/^[\w@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`)).join(" ");
}

function lista(value: unknown, campo: string, max: number): string[] {
  if (value === undefined || value === null) return [];
  const items = Array.isArray(value) ? value : [value];
  if (items.length > max) throw new Error(`${campo}: hasta ${max}.`);
  return items.map((item, index) => {
    if (typeof item !== "string" || !item.trim()) throw new Error(`${campo}[${index}]: tiene que ser texto.`);
    return item.trim();
  });
}

function entero(value: unknown, campo: string, def: number, min: number, max: number): number {
  if (value === undefined || value === null || value === "") return def;
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(`${campo}: tiene que ser un número.`);
  return Math.max(min, Math.min(max, Math.floor(number)));
}

// ───────────────────────────── compilar ─────────────────────────────

export type Sanitizer = "address" | "undefined" | "memory" | "integer" | "leak";
export const SANITIZERS: Sanitizer[] = ["address", "undefined", "memory", "integer", "leak"];
export type TipoBinario = "fuzzer" | "poc";

/** -fsanitize y compañía. UBSan e integer no se recuperan: el primer error corta, como un crash. */
export function banderasSanitizer(sanitizers: Sanitizer[], conFuzzer: boolean): string[] {
  const set = new Set(sanitizers);
  for (const item of set) if (!SANITIZERS.includes(item)) throw new Error(`sanitizers: «${item}» no; elegí entre ${SANITIZERS.join(", ")}.`);
  if (!set.size) throw new Error("sanitizers: pedí al menos uno (por defecto address y undefined).");
  if (set.has("memory") && (set.has("address") || set.has("leak"))) throw new Error("MSan (memory) no se combina con ASan ni LSan: compilá otro binario con memory (y undefined si querés), con todo el objetivo instrumentado con MSan.");
  const out = [`-fsanitize=${[...(conFuzzer ? ["fuzzer"] : []), ...set].join(",")}`];
  const sinRecuperar = [...set].filter((item) => item === "undefined" || item === "integer");
  if (sinRecuperar.length) out.push(`-fno-sanitize-recover=${sinRecuperar.join(",")}`);
  if (set.has("memory")) out.push("-fsanitize-memory-track-origins");
  return out;
}

/**
 * Banderas del compilador que se aceptan del modelo: lenguaje, optimización, depuración, advertencias y -f/-m sin
 * rutas. Nada que pase opciones al enlazador o al ensamblador, cargue plugins o escriba fuera (-Wl, -fplugin,
 * -fprofile=…, -o, @archivo, -B…); los sanitizers van por su parámetro e includes y librerías, por los suyos.
 */
const BANDERA_OK = /^-(?:std=[\w+]+|O[0-3sgz]?|g[\w-]*|W(?![lap],)[\w=+-]*|w|pedantic|ansi|pthread|f(?!plugin|sanitize|no-sanitize|profile|crash-diagnostics|save-optimization|record-command-line|debug-prefix-map|macro-prefix-map|file-prefix-map|coverage-prefix-map|use-ld|ld-path|lto|modules-cache-path|diagnostics-color|color-diagnostics)[\w=+.,-]+|m(?!llvm)[\w=+.-]+|D[A-Za-z_]\w*(?:=[^\s'"\\`$]*)?|U[A-Za-z_]\w*)$/;
const BANDERAS_EXACTAS = new Set(["-fprofile-instr-generate", "-fcoverage-mapping"]);

export function revisarBanderas(flags: string[]): string[] {
  for (const flag of flags) {
    if (BANDERAS_EXACTAS.has(flag)) continue;
    if (/[/\\]/.test(flag) || !BANDERA_OK.test(flag)) throw new Error(`flags: «${flag}» no se acepta. Van lenguaje, -O, -g, -W, -f y -m sin rutas; includes por include_dirs, librerías por link, lib_dirs y libs, macros por defines y sanitizers por su parámetro.`);
  }
  return flags;
}

const DEFINE_OK = /^[A-Za-z_]\w*(?:=[^\s'"\\`$]*)?$/;
const LIB_OK = /^[A-Za-z0-9_+.-]+$/;

export interface PedidoCompilacion {
  /** El harness (y fuentes extra del objetivo), dentro del proyecto: .c, .cc, .cpp, .cxx. */
  sources: string[];
  /** Nombre del binario y de su carpeta harness/out/<name>/; por defecto, el del primer fuente. */
  name?: string;
  /** fuzzer (libFuzzer, LLVMFuzzerTestOneInput) o poc (main propio); por defecto lo deduce de los fuentes. */
  kind?: TipoBinario;
  /** Por defecto address y undefined. */
  sanitizers?: Sanitizer[];
  include_dirs?: string[];
  defines?: string[];
  flags?: string[];
  /** Objetos y librerías del objetivo ya compilados (con los mismos sanitizers): .o, .a, .so, dentro del proyecto. */
  link?: string[];
  lib_dirs?: string[];
  /** Librerías del sistema por nombre (-l): z, m, pthread… */
  libs?: string[];
  /** Paquetes de pkg-config del sistema (zlib, libxml-2.0…): suma sus -I, -L y -l. */
  pkg_config?: string[];
  /** Forzar C++ (por defecto, si algún fuente es C++). */
  cxx?: boolean;
  timeout_sec?: number;
}

/** Lo que harness_build deja en harness/out/<nombre>/build.json: fuzz_run y poc_run sólo corren binarios así (o con sanitizers). */
export interface Manifiesto {
  nombre: string;
  tipo: TipoBinario;
  sanitizers: Sanitizer[];
  /** Relativo al proyecto. */
  binario: string;
  sha256: string;
  comando: string;
  argv: string[];
  fuentes: Array<{ ruta: string; sha256: string }>;
  llvm: string;
  fecha: string;
  artefacto: string;
}

export interface Compilacion {
  ok: boolean;
  nombre: string;
  tipo: TipoBinario;
  sanitizers: Sanitizer[];
  /** Ruta absoluta del binario, si compiló. */
  binario?: string;
  /** El comando exacto (rutas absolutas). */
  comando: string;
  argv: string[];
  exitCode: number | null;
  /** Errores del compilador y del enlazador, compactos (archivo:línea:columna: mensaje). */
  errores: string[];
  /** Símbolos que el enlazador no encontró. */
  indefinidos: string[];
  advertencias: number;
  /** Artefacto con el comando y la salida completa. */
  artefacto: string;
  duracionMs: number;
  cancelado: boolean;
  manifiesto?: Manifiesto;
}

/** Errores del compilador y del enlazador en pocas líneas, con las rutas del proyecto relativas. */
export function compactarErrores(salida: string, cwd?: string): { errores: string[]; indefinidos: string[]; advertencias: number } {
  const errores = new Set<string>();
  const indefinidos = new Set<string>();
  let advertencias = 0;
  const limpiar = (text: string) => (cwd ? text.split(`${cwd}/`).join("") : text).trim();
  for (const raw of salida.split(/\r?\n/)) {
    const line = limpiar(raw);
    let match: RegExpExecArray | null;
    if ((match = /^(.+?):(\d+):(\d+): (?:fatal )?error: (.+)$/.exec(line))) errores.add(`${match[1]}:${match[2]}:${match[3]}: ${match[4]}`);
    else if (/^.+?:\d+:\d+: warning: /.test(line)) advertencias++;
    else if ((match = /undefined reference to [`'‘]([^`'’]+)[`'’]/.exec(line))) indefinidos.add(match[1]!);
    else if ((match = /(?:ld(?:\.lld)?: )?error: undefined symbol: (.+)$/.exec(line))) indefinidos.add(match[1]!.trim());
    else if ((match = /cannot find (-l\S+|\S+): /.exec(line)) || (match = /cannot find (-l\S+)/.exec(line))) errores.add(`el enlazador no encuentra ${match[1]}`);
    else if ((match = /^clang(?:\+\+)?(?:-\d+)?: (?:fatal )?error: (.+)$/.exec(line))) {
      if (!/linker command failed/.test(match[1]!) || (!indefinidos.size && !errores.size)) errores.add(match[1]!);
    }
  }
  return { errores: [...errores].slice(0, 12), indefinidos: [...indefinidos].slice(0, 20), advertencias };
}

async function pkgConfig(entorno: FuzzEntorno, paquetes: string[], signal?: AbortSignal): Promise<string[]> {
  for (const name of paquetes) if (!LIB_OK.test(name)) throw new Error(`pkg_config: «${name}» no es un nombre de paquete.`);
  if (!paquetes.length) return [];
  if (!existsSync(entorno.binarios.pkgConfig)) throw new Error("pkg-config no está en esta caja.");
  const run = entorno.ejecutar ?? exec;
  const result = await run({ argv: [entorno.binarios.pkgConfig, "--cflags", "--libs", ...paquetes], env: { PATH: SEARCH_PATH, LANG: "C" }, timeoutMs: 30_000, maxOutputBytes: 64_000, signal });
  if (result.exitCode !== 0) throw new Error(`pkg_config: ${(result.stderr || result.stdout).trim().split("\n")[0]?.slice(0, 200) ?? "falló"}. Instalá el -dev en la caja con la shell o pasá includes y libs a mano.`);
  return result.stdout.trim().split(/\s+/).filter((token) => token.startsWith("-"));
}

const fuenteHarness = (texto: string) => /\bLLVMFuzzerTestOneInput\s*\(/.test(texto);

/** Compila el harness o el PoC; si falla, devuelve los errores compactos (no tira) y no deja binario viejo. */
export async function compilarHarness(entorno: FuzzEntorno, pedido: PedidoCompilacion, signal?: AbortSignal): Promise<Compilacion> {
  const fuentes = lista(pedido.sources, "sources", 64).map((item, index) => archivoEnProyecto(entorno, item, `sources[${index}]`));
  if (!fuentes.length) throw new Error("sources: pasá al menos el harness (p. ej. harness/xml.c).");
  for (const fuente of fuentes) {
    if (!C_EXT.test(fuente) && !CXX_EXT.test(fuente)) throw new Error(`sources: «${rel(entorno, fuente)}» no es C ni C++ (.c, .cc, .cpp, .cxx).`);
    if (statSync(fuente).size > MAX_FUENTE) throw new Error(`sources: «${rel(entorno, fuente)}» pesa más de 8 MB.`);
  }
  const textos = fuentes.map((fuente) => readFileSync(fuente, "utf8"));
  const tipo: TipoBinario = pedido.kind ?? (textos.some(fuenteHarness) ? "fuzzer" : "poc");
  if (tipo !== "fuzzer" && tipo !== "poc") throw new Error("kind: fuzzer o poc.");
  const nombre = (pedido.name?.trim() || basename(fuentes[0]!, extname(fuentes[0]!))).replace(/[^A-Za-z0-9._-]/g, "-");
  if (!NOMBRE.test(nombre)) throw new Error(`name: «${nombre}» no sirve (letras, números, punto, guion; hasta 64).`);
  const sanitizers = (pedido.sanitizers === undefined ? ["address", "undefined"] : lista(pedido.sanitizers, "sanitizers", SANITIZERS.length)) as Sanitizer[];
  const san = banderasSanitizer(sanitizers, tipo === "fuzzer");
  const sanCorte = banderasSanitizer(sanitizers, false);
  const includes = lista(pedido.include_dirs, "include_dirs", 64).map((item, index) => carpetaEnProyecto(entorno, item, `include_dirs[${index}]`));
  const libDirs = lista(pedido.lib_dirs, "lib_dirs", 32).map((item, index) => carpetaEnProyecto(entorno, item, `lib_dirs[${index}]`));
  const link = lista(pedido.link, "link", 128).map((item, index) => {
    const real = archivoEnProyecto(entorno, item, `link[${index}]`);
    if (!LINK_EXT.test(real)) throw new Error(`link[${index}]: «${item}» no es un objeto ni una librería (.o, .a, .so).`);
    return real;
  });
  const defines = lista(pedido.defines, "defines", 64).map((item) => item.replace(/^-D/, ""));
  for (const define of defines) if (!DEFINE_OK.test(define)) throw new Error(`defines: «${define}» no (NOMBRE o NOMBRE=valor, sin espacios ni comillas).`);
  const flags = revisarBanderas(lista(pedido.flags, "flags", 64));
  const libs = lista(pedido.libs, "libs", 64).map((item) => item.replace(/^-l/, ""));
  for (const lib of libs) if (!LIB_OK.test(lib)) throw new Error(`libs: «${lib}» no es un nombre de librería.`);
  const pkg = await pkgConfig(entorno, lista(pedido.pkg_config, "pkg_config", 16), signal);
  const cxx = pedido.cxx ?? fuentes.some((fuente) => CXX_EXT.test(fuente));
  const timeoutSeg = entero(pedido.timeout_sec, "timeout_sec", entorno.limites.compilarSeg, 10, entorno.limites.compilarSeg);

  const dir = carpeta(entorno, FUZZ.salida, nombre);
  const binario = join(dir, nombre);
  const manifiestoPath = join(dir, "build.json");
  // Un intento que falla no deja corriendo la versión anterior como si fuera ésta.
  rmSync(binario, { force: true });
  rmSync(manifiestoPath, { force: true });
  const corteC = join(dir, "sin-red.c");
  const corteO = join(dir, "sin-red.o");
  writeFileSync(corteC, readFileSync(FUZZ.sinRed));
  const rpaths = [...new Set([...libDirs, ...link.filter((item) => /\.so(\.\d+)*$/.test(item)).map((item) => dirname(item))])].map((item) => `-Wl,-rpath,${item}`);
  const argvCorte = [entorno.binarios.clang, "-c", "-g", "-O1", ...sanCorte, corteC, "-o", corteO];
  const argv = [
    cxx ? entorno.binarios.clangxx : entorno.binarios.clang,
    "-g", "-O1", "-fno-omit-frame-pointer", "-fdiagnostics-color=never", "-ferror-limit=20",
    ...san, ...flags, ...defines.map((item) => `-D${item}`), ...includes.map((item) => `-I${item}`),
    ...fuentes, ...link, corteO,
    // El socket() sin red también tiene que ganarles a las .so del objetivo.
    "-Wl,--export-dynamic-symbol=socket",
    ...libDirs.map((item) => `-L${item}`), ...rpaths, ...pkg, ...libs.map((item) => `-l${item}`),
    "-o", binario,
  ];
  const env = { PATH: SEARCH_PATH, LANG: "C", TERM: "dumb", HOME: dir, TMPDIR: carpeta(entorno, FUZZ.salida, nombre, "tmp") };
  const run = entorno.ejecutar ?? exec;
  const inicio = Date.now();
  const log: string[] = [];
  let ultimo: ExecResult | undefined;
  for (const [paso, comando] of [["corte de red", argvCorte], ["harness", argv]] as const) {
    ultimo = await run({ argv: comando, cwd: entorno.cwd, env, timeoutMs: timeoutSeg * 1000, maxOutputBytes: 2_000_000, signal });
    log.push(`$ ${lineaShell(comando)}`, ultimo.stdout, ultimo.stderr, `[${paso}: ${ultimo.cancelled ? "cancelado" : ultimo.timedOut ? `cortado a los ${timeoutSeg} s` : `salida ${ultimo.exitCode}`}]`);
    if (ultimo.exitCode !== 0) break;
  }
  const salida = log.filter(Boolean).join("\n");
  writeFileSync(join(dir, "build.log"), salida);
  const ok = !!ultimo && ultimo.exitCode === 0 && existsSync(binario);
  const comando = lineaShell(argv);
  // command: el comando exacto que reproduce esta compilación; run_command, cómo correr un PoC (main propio) ya compilado.
  const correrPoc = tipo === "poc" ? comandoReproducir(entorno, [binario], entornoSanitizers(entorno, dir, { leaks: true, rssMb: entorno.limites.memoriaMb })) : undefined;
  const artefacto = entorno.artifacts.put(JSON.stringify({ harness: nombre, tipo, sanitizers, ok, command: comando, comando, argv, ...(correrPoc ? { run_command: correrPoc } : {}), salida }, null, 1), "application/json", `harness_build:${nombre}`).hash;
  const compacto = compactarErrores(salida, entorno.cwd);
  let manifiesto: Manifiesto | undefined;
  if (ok) {
    manifiesto = {
      nombre, tipo, sanitizers, binario: rel(entorno, binario), sha256: sha256Archivo(binario), comando, argv,
      fuentes: fuentes.map((fuente, index) => ({ ruta: rel(entorno, fuente), sha256: sha256(textos[index]!) })),
      llvm: FUZZ.llvm, fecha: new Date().toISOString(), artefacto,
    };
    writeFileSync(manifiestoPath, JSON.stringify(manifiesto, null, 1));
  } else if (ultimo && ultimo.exitCode === 0 && !existsSync(binario)) {
    compacto.errores.unshift("el compilador terminó bien pero no dejó el binario");
  }
  entorno.event?.("fuzz.compilar", { harness: nombre, tipo, ok, artefacto, errores: compacto.errores.length + compacto.indefinidos.length });
  return {
    ok, nombre, tipo, sanitizers, ...(ok ? { binario } : {}), comando, argv, exitCode: ultimo?.exitCode ?? null,
    errores: compacto.errores, indefinidos: compacto.indefinidos, advertencias: compacto.advertencias,
    artefacto, duracionMs: Date.now() - inicio, cancelado: !!ultimo?.cancelled, ...(manifiesto ? { manifiesto } : {}),
  };
}

// ───────────────────────────── reportes de los sanitizers ─────────────────────────────

export type ClaseCrash = "memoria" | "ub" | "leak" | "timeout" | "oom" | "señal" | "harness" | "entorno";

export interface Frame { n: number; funcion?: string; archivo?: string; linea?: number; modulo?: string }

export interface ReporteSanitizer {
  /** AddressSanitizer, UndefinedBehaviorSanitizer, MemorySanitizer, LeakSanitizer, libFuzzer o «proceso». */
  sanitizer: string;
  /** heap-buffer-overflow, heap-use-after-free, double-free, SEGV, signed-integer-overflow, leak, timeout, oom-rss… */
  tipo: string;
  clase: ClaseCrash;
  acceso?: { op: "READ" | "WRITE"; bytes?: number };
  /** La línea SUMMARY, o la del error. */
  resumen: string;
  /** La primera pila, entera. */
  frames: Frame[];
  /** La misma sin el runtime de los sanitizers, libc ni libFuzzer: de dónde viene el crash. */
  propios: Frame[];
  /** Para deduplicar: tipo y las tres funciones propias de arriba (12 hex). */
  firma: string;
  /** El crash está en el harness (LLVMFuzzerTestOneInput o un fuente de harness/), no en el objetivo. */
  enHarness: boolean;
  /** Lo que ASan estima con print_scariness. */
  scariness?: string;
  /** Qué sugiere como primitiva o impacto, en una línea. */
  impacto: string;
  /** El reporte desde la línea del error (recortado). */
  texto: string;
}

const FRAME = /^\s*#(\d+)\s+0x[0-9a-fA-F]+\s*(.*)$/;
const UBICACION_MODULO = /^\((.+)\+(0x[0-9a-fA-F]+)\)$/;
const UBICACION_ARCHIVO = /^([^\s()]+?):(\d+)(?::\d+)?$/;
const UBICACION_SOLO = /^[^\s()]+\.(?:c|cc|cpp|cxx|h|hh|hpp|inc|C)$/;

/** Un frame de una pila de sanitizer: «#3 0x55 in f /src/x.c:12:3», «#4 0x7f in g (/lib/libz.so+0x12) (BuildId: …)» o «#5 0x55 (/bin/x+0x9)». */
export function parsearFrame(linea: string): Frame | undefined {
  const match = FRAME.exec(linea);
  if (!match) return undefined;
  const frame: Frame = { n: Number(match[1]) };
  let resto = match[2]!.replace(/\s+\(BuildId: [0-9a-fA-F]+\)\s*$/, "").trim();
  const ubicar = (token: string): boolean => {
    let found: RegExpExecArray | null;
    if ((found = UBICACION_MODULO.exec(token))) { frame.modulo = `${basename(found[1]!)}+${found[2]}`; return true; }
    if ((found = UBICACION_ARCHIVO.exec(token))) { frame.archivo = found[1]!; frame.linea = Number(found[2]); return true; }
    if (UBICACION_SOLO.test(token)) { frame.archivo = token; return true; }
    return false;
  };
  if (!resto.startsWith("in ")) { ubicar(resto); return frame; }
  resto = resto.slice(3).trim();
  const corte = resto.lastIndexOf(" ");
  if (corte > 0 && ubicar(resto.slice(corte + 1))) frame.funcion = resto.slice(0, corte).trim();
  else frame.funcion = resto;
  return frame;
}

const RUNTIME_FUNCION = /^(?:__asan|__lsan|__msan|__ubsan|__hwasan|__sanitizer|__interceptor|___interceptor|__interception|__libc_|__GI_|__cxa_|__gxx_|__tsan|__dfsan|fuzzer::|LLVMFuzzerRunDriver|_start$|_dl_|std::|operator new|operator delete|(?:malloc|calloc|realloc|reallocarray|free|posix_memalign|aligned_alloc|valloc|memalign|strdup|strndup|memcpy|memmove|memset|memcmp|bcmp|memchr|memrchr|strlen|strnlen|strcmp|strncmp|strcasecmp|strncasecmp|strcpy|strncpy|strcat|strncat|strchr|strrchr|strstr|sprintf|snprintf|vsprintf|vsnprintf|printf|fprintf|raise|abort|gsignal|__assert_fail|__assert_rtn|__stack_chk_fail|__fortify_fail|__chk_fail)\b)/;
const RUNTIME_RUTA = /(?:compiler-rt\/|llvm-project\/|sysdeps\/|csu\/|(?:^|\/)libc[.-]|(?:^|\/)libm[.-]|libstdc\+\+|(?:^|\/)libgcc|ld-linux|libpthread|(?:^|\/)libc\+\+)/;

const esRuntime = (frame: Frame) =>
  (!!frame.funcion && RUNTIME_FUNCION.test(frame.funcion)) || (!!frame.archivo && RUNTIME_RUTA.test(frame.archivo)) || (!!frame.modulo && RUNTIME_RUTA.test(frame.modulo));

/** Cómo se nombra un frame en la firma y en los resúmenes. */
export function nombreFrame(frame: Frame, conLinea = false): string {
  const donde = frame.archivo ? `${basename(frame.archivo)}${frame.linea ? `:${frame.linea}` : ""}` : frame.modulo ?? "?";
  if (!frame.funcion) return donde;
  return conLinea && frame.archivo ? `${frame.funcion.replace(/\(.*$/, "")} ${donde}` : frame.funcion.replace(/\(.*$/, "");
}

function pilaDesde(lineas: string[], desde: number, buscar = 8): Frame[] {
  const frames: Frame[] = [];
  let i = desde;
  // Antes de la pila puede haber una o más líneas (READ of size…, la de LeakSanitizer).
  while (i < lineas.length && i < desde + buscar && !FRAME.test(lineas[i]!)) i++;
  for (; i < lineas.length; i++) {
    const frame = parsearFrame(lineas[i]!);
    if (!frame) break;
    frames.push(frame);
    if (frames.length >= 64) break;
  }
  return frames;
}

const UB: Array<[RegExp, string]> = [
  [/^(?:signed integer overflow|negation of .* cannot be represented)/, "signed-integer-overflow"],
  [/^unsigned integer overflow/, "unsigned-integer-overflow"],
  [/^(?:left shift|shift exponent)/, "shift"],
  [/^(?:division by zero|integer divide by zero)/, "division-by-zero"],
  [/^implicit conversion/, "implicit-conversion"],
  [/^index -?\d+ out of bounds/, "array-bounds"],
  [/null pointer passed as argument|null pointer returned from function declared to never return null/, "nonnull"],
  [/applying (?:non-)?zero offset|pointer index expression|^(?:addition|subtraction) of unsigned offset/, "pointer-overflow"],
  [/null pointer|^(?:load|store) of null/, "null"],
  [/misaligned address/, "misaligned"],
  [/not a valid value for type/, "invalid-value"],
  [/unreachable program point/, "unreachable"],
  [/variable length array bound/, "vla-bound"],
  [/pointer to incorrect function type/, "function-type"],
  [/outside the range of representable values/, "float-cast-overflow"],
  [/end of a value-returning function/, "missing-return"],
];

function tipoAsan(resto: string): string {
  if (/^attempting double-free/.test(resto)) return "double-free";
  if (/^attempting free on address which was not malloc/.test(resto)) return "bad-free";
  if (/^requested allocation size .* exceeds maximum supported size/.test(resto)) return "allocation-size-too-big";
  if (/allocator is out of memory|^out of memory/.test(resto)) return "out-of-memory";
  if (/^hard rss limit exhausted/.test(resto)) return "oom-rss";
  if (/^calloc-parameters-overflow/.test(resto)) return "calloc-overflow";
  return /^([\w-]+)/.exec(resto)?.[1] ?? "unknown-crash";
}

const CLASE_ASAN: Record<string, ClaseCrash> = {
  "allocation-size-too-big": "oom", "out-of-memory": "oom", "oom-rss": "oom", "calloc-overflow": "oom",
  FPE: "señal", ILL: "señal", ABRT: "señal", "odr-violation": "harness", "initialization-order-fiasco": "harness",
};

function impactoDe(reporte: Pick<ReporteSanitizer, "tipo" | "clase" | "acceso" | "texto">): string {
  const { tipo, clase, acceso } = reporte;
  if (clase === "entorno") return "El sanitizer no pudo trabajar en este entorno: no dice nada del objetivo.";
  if (clase === "harness") return "Artefacto del harness (salió, escribió su input o el binario está mal armado): no es del objetivo.";
  if (clase === "timeout") return "Entrada que cuelga o tarda: DoS. Paga sólo si un atacante remoto la manda y el servicio no tiene tope.";
  if (clase === "oom") return "Consumo de memoria desmedido o tamaño de asignación controlado: DoS; si el tamaño sale de la entrada, mirá si en otra rama desborda en vez de fallar.";
  if (clase === "leak") return "Fuga de memoria: DoS lento; para casi ningún programa paga.";
  if (tipo === "stack-overflow") return "Recursión sin tope: DoS.";
  if (clase === "señal") return "El proceso murió por una señal (abort, assert, división por cero): DoS salvo que muestres otra cosa.";
  if (clase === "ub") {
    if (/integer-overflow|implicit-conversion/.test(tipo)) return "Overflow aritmético: importa si termina en un tamaño de asignación, un índice o un largo de copia; mostrá ese uso.";
    if (tipo === "array-bounds") return "Índice fuera de rango: mirá si se traduce en lectura o escritura real (con ASan aparece como overflow).";
    if (tipo === "null" || tipo === "nonnull") return "Puntero nulo: normalmente sólo DoS.";
    if (tipo === "pointer-overflow") return "Aritmética de punteros desbordada: mirá si el puntero se usa después para leer o escribir.";
    return "Comportamiento indefinido: sin un efecto demostrado no es hallazgo.";
  }
  if (tipo === "use-of-uninitialized-value") return "Uso de memoria no inicializada: posible fuga o decisión con basura; falta mostrar el efecto.";
  if (tipo === "SEGV" || tipo === "BUS") {
    if (/address points to the zero page|unknown address 0x0{0,10}[0-9a-f]{1,4}\b/i.test(reporte.texto)) return "Desreferencia de nulo o casi nulo: normalmente sólo DoS.";
    return acceso?.op === "WRITE" ? "Escritura en una dirección inválida: mirá de dónde sale el puntero; si la entrada lo controla, es una primitiva." : "Lectura de una dirección inválida: puntero corrupto o no inicializado; mirá de dónde sale.";
  }
  if (/double-free|bad-free|alloc-dealloc-mismatch|new-delete-type-mismatch/.test(tipo)) return "Liberación inválida: corrompe el heap; candidato a primitiva si se controla qué se reocupa.";
  if (acceso?.op === "WRITE") return "Escritura fuera de límites o sobre memoria liberada: candidato a primitiva de corrupción; falta mostrar control de qué, dónde y cuánto.";
  if (/use-after-free|use-after-return|use-after-scope/.test(tipo)) return "Lectura de memoria liberada: puede volverse escritura o fuga según quién reocupe el bloque; falta mostrarlo.";
  if (/overflow|underflow/.test(tipo)) return "Lectura fuera de límites: posible fuga de memoria; vale si los bytes leídos salen del proceso (respuesta, archivo, log).";
  return "Corrupción de memoria: falta mostrar qué controla la entrada.";
}

/**
 * Clasifica la salida de un sanitizer o de libFuzzer (la primera falla que aparece). Devuelve undefined si no hay
 * ninguna. Sirve para cualquier reporte: el de un fuzzer, el de un PoC o el log de un laboratorio (log_path).
 */
export function clasificarReporte(salida: string): ReporteSanitizer | undefined {
  const lineas = salida.split(/\r?\n/);
  type Candidato = { linea: number; sanitizer: string; tipo: string; clase: ClaseCrash; pila: () => Frame[] };
  const candidatos: Candidato[] = [];
  const pilaTras = (i: number) => () => pilaDesde(lineas, i + 1);
  for (const [i, line] of lineas.entries()) {
    let match: RegExpExecArray | null;
    if ((match = /==\d+==\s*ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|HWAddressSanitizer): (.+)$/.exec(line))) {
      const tipo = tipoAsan(match[2]!);
      candidatos.push({ linea: i, sanitizer: match[1]!, tipo, clase: CLASE_ASAN[tipo] ?? "memoria", pila: pilaTras(i) });
    } else if (/==\d+==\s*ERROR: LeakSanitizer: detected memory leaks/.test(line)) {
      const leak = lineas.findIndex((item, index) => index > i && /^(?:Direct|Indirect) leak of/.test(item));
      const directo = lineas.findIndex((item, index) => index > i && /^Direct leak of/.test(item));
      candidatos.push({ linea: i, sanitizer: "LeakSanitizer", tipo: "leak", clase: "leak", pila: () => pilaDesde(lineas, (directo >= 0 ? directo : leak) + 1) });
    } else if ((match = /==\d+==\s*WARNING: MemorySanitizer: ([\w-]+)/.exec(line))) {
      candidatos.push({ linea: i, sanitizer: "MemorySanitizer", tipo: match[1]!, clase: "memoria", pila: pilaTras(i) });
    } else if ((match = /^((?:\S+?):\d+:\d+|<unknown>): runtime error: (.+)$/.exec(line))) {
      const tipo = UB.find(([pattern]) => pattern.test(match![2]!))?.[1] ?? "undefined-behavior";
      candidatos.push({ linea: i, sanitizer: "UndefinedBehaviorSanitizer", tipo, clase: "ub", pila: pilaTras(i) });
    } else if ((match = /==\d+==\s*ERROR: libFuzzer: (.+)$/.exec(line))) {
      const texto = match[1]!;
      const [tipo, clase]: [string, ClaseCrash] = /^timeout/.test(texto) ? ["timeout", "timeout"]
        : /^out-of-memory \(malloc/.test(texto) ? ["oom-malloc", "oom"]
        : /^out-of-memory/.test(texto) ? ["oom-rss", "oom"]
        : /^deadly signal/.test(texto) ? ["deadly-signal", "señal"]
        : /^fuzz target exited/.test(texto) ? ["harness-exit", "harness"]
        : /overwrites its const input/.test(texto) ? ["harness-escribe-input", "harness"]
        : [texto.replace(/[^\w-]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "libfuzzer", "señal"];
      candidatos.push({ linea: i, sanitizer: "libFuzzer", tipo, clase, pila: pilaTras(i) });
    } else if (/LeakSanitizer has encountered a fatal error|LeakSanitizer does not work under ptrace/.test(line)) {
      candidatos.push({ linea: i, sanitizer: "LeakSanitizer", tipo: "lsan-no-corre", clase: "entorno", pila: () => [] });
    } else if (/Shadow memory range interleaves with an existing memory mapping|shadow was supposed to be located|Sanitizer: CHECK failed|Sanitizer: failed to (?:allocate|mmap|reserve)/.test(line)) {
      candidatos.push({ linea: i, sanitizer: /MemorySanitizer/.test(line) ? "MemorySanitizer" : "AddressSanitizer", tipo: "sanitizer-no-arranca", clase: "entorno", pila: () => [] });
    }
  }
  if (!candidatos.length) {
    // Una señal mortal tras otra sin reporte: el sanitizer no llegó a arrancar (por ejemplo vm.mmap_rnd_bits=32 con LLVM 16).
    const muertes = lineas.filter((line) => /Sanitizer:DEADLYSIGNAL/.test(line)).length;
    if (!muertes) return undefined;
    candidatos.push({ linea: lineas.findIndex((line) => /Sanitizer:DEADLYSIGNAL/.test(line)), sanitizer: "AddressSanitizer", tipo: "sanitizer-no-arranca", clase: "entorno", pila: () => [] });
  }
  const elegido = candidatos[0]!;
  const frames = elegido.pila();
  const propios = frames.filter((frame) => !esRuntime(frame));
  // Antes del error, el separador «=====» de ASan no aporta; desde la línea del error hasta el SUMMARY (o 120 líneas).
  const fin = lineas.findIndex((line, index) => index >= elegido.linea && /^SUMMARY: /.test(line));
  const hasta = fin >= 0 && fin - elegido.linea < 400 ? fin + 1 : elegido.linea + 120;
  const texto = lineas.slice(elegido.linea, hasta).join("\n").slice(0, 20_000);
  const tras = lineas.slice(elegido.linea, elegido.linea + 12).join("\n");
  const acceso = /\b(READ|WRITE) of size (\d+)/.exec(tras) ?? /caused by a (READ|WRITE) memory access/.exec(tras);
  const resumen = (fin >= 0 && fin - elegido.linea < 400 ? lineas[fin]!.replace(/^SUMMARY:\s*/, "") : lineas[elegido.linea]!.replace(/^==\d+==\s*/, "")).trim().slice(0, 300);
  const scariness = /SCARINESS: (\d+ \([^)]*\))/.exec(texto)?.[1];
  const arriba = propios[0];
  const enHarness = !!arriba && (arriba.funcion === "LLVMFuzzerTestOneInput" || /(?:^|\/)harness\//.test(arriba.archivo ?? ""));
  const clave = propios.slice(0, 3).map((frame) => nombreFrame(frame));
  const base = {
    sanitizer: elegido.sanitizer, tipo: elegido.tipo, clase: elegido.clase,
    ...(acceso ? { acceso: { op: acceso[1] as "READ" | "WRITE", ...(acceso[2] ? { bytes: Number(acceso[2]) } : {}) } } : {}),
    resumen, frames, propios, firma: createHash("sha1").update(`${elegido.tipo}|${clave.join("|")}`).digest("hex").slice(0, 12),
    enHarness, ...(scariness ? { scariness } : {}), texto,
  };
  return { ...base, impacto: impactoDe(base) };
}

/** Una línea para personas: tipo, acceso y de dónde viene. */
export function lineaReporte(reporte: ReporteSanitizer): string {
  const acceso = reporte.acceso ? ` (${reporte.acceso.op}${reporte.acceso.bytes ? ` de ${reporte.acceso.bytes}` : ""})` : "";
  const pila = reporte.propios.slice(0, 3).map((frame) => nombreFrame(frame, true)).join(" ← ");
  return `${reporte.tipo}${acceso}${pila ? ` en ${pila}` : ""}`;
}

// ───────────────────────────── qué binario se corre ─────────────────────────────

const MARCAS_SANITIZER = ["__asan_init", "__msan_init", "__ubsan_handle_", "__lsan_", "__sanitizer_"].map((item) => Buffer.from(item));

/** Un ELF compilado con algún sanitizer (lo que se puede correr sin que lo haya compilado harness_build). */
export function binarioInstrumentado(contenido: Buffer): boolean {
  return contenido.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) && MARCAS_SANITIZER.some((marca) => contenido.includes(marca));
}

export interface Objetivo {
  nombre: string;
  binario: string;
  /** harness/out/<nombre>, real. */
  dir: string;
  tipo: TipoBinario;
  manifiesto?: Manifiesto;
}

function leerManifiesto(dir: string): Manifiesto | undefined {
  try { return JSON.parse(readFileSync(join(dir, "build.json"), "utf8")) as Manifiesto; } catch { return undefined; }
}

/**
 * El binario a correr: el de un harness de harness_build (con su sha256 igual al del manifiesto) o un ELF del
 * proyecto compilado con sanitizers (el CLI del objetivo armado con ASan, para el nivel 2). Ningún otro: para eso
 * está la shell, con el permiso del operador.
 */
export function resolverObjetivo(entorno: FuzzEntorno, pedido: { harness?: string; binary?: string }): Objetivo {
  if (!!pedido.harness === !!pedido.binary) throw new Error("Pasá harness (el name de harness_build) o binary (un binario del proyecto compilado con sanitizers), uno solo.");
  if (pedido.harness) {
    const nombre = String(pedido.harness).trim();
    if (!NOMBRE.test(nombre)) throw new Error(`harness: «${nombre}» no es un nombre de harness.`);
    const logico = join(entorno.cwd, FUZZ.salida, nombre);
    if (!existsSync(join(logico, "build.json"))) throw new Error(`No hay un harness «${nombre}» compilado: harness_build primero.`);
    const dir = insideProject(entorno.cwd, logico);
    const manifiesto = leerManifiesto(dir);
    const binario = join(dir, nombre);
    if (!manifiesto || !existsSync(binario)) throw new Error(`El harness «${nombre}» está incompleto: volvé a compilarlo con harness_build.`);
    if (sha256Archivo(binario) !== manifiesto.sha256) throw new Error(`${rel(entorno, binario)} cambió desde que lo compiló harness_build: volvé a compilarlo.`);
    return { nombre, binario, dir, tipo: manifiesto.tipo, manifiesto };
  }
  const binario = archivoEnProyecto(entorno, pedido.binary, "binary");
  const manifiesto = leerManifiesto(dirname(binario));
  if (manifiesto && basename(binario) === manifiesto.nombre && sha256Archivo(binario) === manifiesto.sha256) return { nombre: manifiesto.nombre, binario, dir: dirname(binario), tipo: manifiesto.tipo, manifiesto };
  if (statSync(binario).size > MAX_BINARIO) throw new Error(`binary: «${pedido.binary}» pesa más de 1 GB.`);
  const contenido = readFileSync(binario);
  if (!binarioInstrumentado(contenido)) throw new Error(`binary: «${pedido.binary}» no lo compiló harness_build ni tiene sanitizers. fuzz_run y poc_run sólo corren binarios de prueba (instrumentados); otro programa, con la shell y el permiso del operador.`);
  const nombre = `ext-${basename(binario).replace(/[^A-Za-z0-9._-]/g, "-")}`.slice(0, 64);
  return { nombre, binario, dir: carpeta(entorno, FUZZ.salida, nombre), tipo: contenido.includes(Buffer.from("LLVMFuzzerTestOneInput")) ? "fuzzer" : "poc" };
}

// ───────────────────────────── correr ─────────────────────────────

/** El entorno de cada proceso: sin heredar nada del harness; sólo PATH, carpeta propia y las opciones de los sanitizers. */
export function entornoSanitizers(entorno: FuzzEntorno, dir: string, opciones: { leaks: boolean; rssMb?: number }): Record<string, string> {
  const sym = entorno.binarios.symbolizer;
  const comun = ["symbolize=1", `external_symbolizer_path=${sym}`, "handle_abort=1", "handle_segv=1", "handle_sigbus=1", "handle_sigfpe=1", "handle_sigill=1", "allocator_may_return_null=1", "print_summary=1", ...(opciones.rssMb ? [`hard_rss_limit_mb=${opciones.rssMb}`] : [])];
  return {
    PATH: SEARCH_PATH, HOME: dir, TMPDIR: carpetaTmp(entorno, dir), LANG: "C", TERM: "dumb",
    ASAN_OPTIONS: [...comun, `detect_leaks=${opciones.leaks ? 1 : 0}`, "print_scariness=1", "abort_on_error=0", "detect_odr_violation=0"].join(":"),
    UBSAN_OPTIONS: [...comun, "print_stacktrace=1", "halt_on_error=1", "report_error_type=1"].join(":"),
    MSAN_OPTIONS: [...comun, "halt_on_error=1"].join(":"),
    LSAN_OPTIONS: ["symbolize=1", `external_symbolizer_path=${sym}`, "print_suppressions=0"].join(":"),
  };
}

function carpetaTmp(entorno: FuzzEntorno, dir: string): string {
  const tmp = join(dir, "tmp");
  if (!existsSync(tmp)) mkdirSync(tmp, { recursive: true });
  return insideProject(entorno.cwd, tmp);
}

interface Proceso { stdout: string; stderr: string; exitCode: number | null; senal: string | null; timedOut: boolean; cancelled: boolean; ms: number }

async function correr(entorno: FuzzEntorno, argv: string[], opciones: { cwd: string; env: Record<string, string>; timeoutMs: number; signal?: AbortSignal; stdin?: Buffer; maxBytes?: number }): Promise<Proceso> {
  const conNice = entorno.limites.nice > 0 && existsSync(entorno.binarios.nice) ? [entorno.binarios.nice, "-n", String(entorno.limites.nice), ...argv] : argv;
  const result = await (entorno.ejecutar ?? exec)({ argv: conNice, cwd: opciones.cwd, env: opciones.env, timeoutMs: opciones.timeoutMs, maxOutputBytes: opciones.maxBytes ?? 4_000_000, signal: opciones.signal, ...(opciones.stdin ? { stdin: opciones.stdin } : {}) });
  return { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode, senal: result.signal, timedOut: result.timedOut, cancelled: result.cancelled, ms: result.durationMs };
}

/**
 * Argumentos de un PoC: «@@» es el archivo de entrada. Una ruta tiene que quedar dentro del proyecto (las relativas,
 * contra `base`, la carpeta donde corre el proceso). Lo mejor posible: puede venir sola, después de «=» (--salida=/x)
 * o pegada a una opción corta (-o/x); la de verdad la decide el programa, pero ninguna que se vea sale del proyecto.
 */
function argumentosPoc(entorno: FuzzEntorno, args: string[] | undefined, input: string | undefined, stdin: boolean, base: string = entorno.cwd): string[] {
  const lista_ = args ?? (stdin || input === undefined ? [] : ["@@"]);
  if (lista_.length > 64) throw new Error("args: hasta 64.");
  return lista_.map((original, index) => {
    if (typeof original !== "string" || original.includes("\0") || original.length > 4096) throw new Error(`args[${index}]: texto de hasta 4096.`);
    if (original.includes("@@") && input === undefined) throw new Error(`args[${index}]: «@@» necesita un input.`);
    const arg = input === undefined ? original : original.split("@@").join(input);
    for (const parte of [arg, arg.slice(arg.indexOf("=") + 1), arg.replace(/^-[A-Za-z]/, "")]) {
      if (parte.startsWith("~")) throw new Error(`args[${index}]: «${original}» sale de la carpeta del proyecto.`);
      if (/^(?:\/|\.\.(?:\/|$))/.test(parte) || parte.includes("/../")) {
        const dentro = relative(entorno.cwd, resolve(base, parte));
        if (dentro.startsWith("..") || isAbsolute(dentro)) throw new Error(`args[${index}]: «${original}» sale de la carpeta del proyecto.`);
      }
    }
    return arg;
  });
}

interface UnaEntrada { proceso: Proceso; reporte?: ReporteSanitizer; argv: string[]; env: Record<string, string>; cwd: string }

interface OpcionesEntrada {
  entradaSeg: number;
  memoriaMb: number;
  leaks: boolean;
  args?: string[];
  stdin?: boolean;
  signal?: AbortSignal;
  /** Carpeta donde corre el proceso: la de un `command` de poc_run. Por defecto, un PoC corre en la raíz del proyecto (sus argumentos relativos son del proyecto) y un fuzzer en su carpeta. */
  cwd?: string;
}

/** Corre el binario sobre una entrada (un PoC puede no tener archivo: sus argumentos lo dicen), una vez, y clasifica lo que pase. */
async function correrEntrada(entorno: FuzzEntorno, objetivo: Objetivo, input: string | undefined, opciones: OpcionesEntrada): Promise<UnaEntrada> {
  const fuzzer = objetivo.tipo === "fuzzer";
  if (fuzzer && input === undefined) throw new Error("Un fuzzer de libFuzzer necesita el archivo de entrada.");
  if (opciones.stdin && input === undefined) throw new Error("stdin necesita un input.");
  const cwd = opciones.cwd ?? (fuzzer ? objetivo.dir : entorno.cwd);
  const env = entornoSanitizers(entorno, objetivo.dir, { leaks: opciones.leaks, ...(fuzzer ? {} : { rssMb: opciones.memoriaMb }) });
  const argv = fuzzer
    ? [objetivo.binario, `-timeout=${opciones.entradaSeg}`, `-rss_limit_mb=${opciones.memoriaMb}`, `-malloc_limit_mb=${opciones.memoriaMb}`, ...(opciones.leaks ? [] : ["-detect_leaks=0"]), `-artifact_prefix=${env.TMPDIR}/`, input!]
    : [objetivo.binario, ...argumentosPoc(entorno, opciones.args, input, !!opciones.stdin, cwd)];
  const proceso = await correr(entorno, argv, { cwd, env, timeoutMs: (opciones.entradaSeg + (fuzzer ? 30 : 0)) * 1000, signal: opciones.signal, ...(opciones.stdin && !fuzzer ? { stdin: readFileSync(input!) } : {}) });
  let reporte = clasificarReporte(proceso.stderr) ?? clasificarReporte(proceso.stdout);
  if (!reporte && proceso.timedOut && !proceso.cancelled) reporte = sintetico("timeout", "timeout", `no terminó en ${opciones.entradaSeg} s`);
  else if (!reporte && proceso.senal && !proceso.cancelled && !proceso.timedOut) reporte = sintetico(proceso.senal, "señal", `murió con ${proceso.senal} sin reporte de sanitizer`);
  return { proceso, ...(reporte ? { reporte } : {}), argv, env, cwd };
}

function sintetico(tipo: string, clase: ClaseCrash, resumen: string): ReporteSanitizer {
  const base = { sanitizer: "proceso", tipo, clase, resumen, frames: [], propios: [], firma: createHash("sha1").update(`${tipo}|`).digest("hex").slice(0, 12), enHarness: false, texto: resumen };
  return { ...base, impacto: impactoDe(base) };
}

/**
 * El comando exacto para reproducir, con las opciones de los sanitizers y las rutas relativas a `desde` (por
 * defecto la raíz del proyecto). Es el `command` que poc_run vuelve a aceptar.
 */
function comandoReproducir(entorno: FuzzEntorno, argv: string[], env: Record<string, string>, stdinDe?: string, desde: string = entorno.cwd): string {
  const relativo = (arg: string) => arg.split(`${desde}/`).join("");
  const opciones = ["ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS"].map((key) => `${key}=${lineaShell([env[key] ?? ""])}`);
  return `${opciones.join(" ")} ${lineaShell(argv.map(relativo))}${stdinDe ? ` < ${lineaShell([relativo(stdinDe)])}` : ""}`;
}

// ───────────────────────────── crashes ─────────────────────────────

export interface CrashConocido {
  firma: string;
  tipo: string;
  clase: ClaseCrash;
  resumen: string;
  linea: string;
  impacto: string;
  /** Carpeta del crash, relativa al proyecto (input, input.min, reporte.txt, repro.sh, meta.json). */
  carpeta: string;
  /** El input con el que se reproduce (el minimizado si lo hay), relativo al proyecto. */
  input: string;
  reproducir: string;
  artefacto: string;
  vistas: number;
  primera: string;
  ultima: string;
  enHarness: boolean;
}

export interface CrashFuzz extends CrashConocido {
  nuevo: boolean;
  /** Se reprodujo al correr el binario sobre el input guardado. */
  reproduce: boolean;
  bytes: number;
  bytesOriginal: number;
  minimizado: boolean;
  reporte?: ReporteSanitizer;
}

const indicePath = (objetivo: Objetivo) => join(objetivo.dir, "crashes", "index.json");

function leerIndice(objetivo: Objetivo): Record<string, CrashConocido> {
  try { return JSON.parse(readFileSync(indicePath(objetivo), "utf8")) as Record<string, CrashConocido>; } catch { return {}; }
}

/** Lo que fuzz_run ya encontró para un harness (por nombre, el de harness_build o «ext-<binario>»). */
export function crashesConocidos(entorno: FuzzEntorno, harness: string): CrashConocido[] {
  if (!NOMBRE.test(harness)) return [];
  const dir = join(entorno.cwd, FUZZ.salida, harness);
  if (!existsSync(dir)) return [];
  return Object.values(leerIndice({ nombre: harness, binario: "", dir: insideProject(entorno.cwd, dir), tipo: "fuzzer" }));
}

/** Un crash del índice por prefijo de firma (6 a 12 hex). */
function buscarCrash(objetivo: Objetivo, prefijo: string): CrashConocido {
  if (!/^[0-9a-f]{6,12}$/.test(prefijo)) throw new Error("crash: la firma de fuzz_run (6 a 12 caracteres hexadecimales).");
  const hits = Object.values(leerIndice(objetivo)).filter((item) => item.firma.startsWith(prefijo));
  if (hits.length !== 1) throw new Error(hits.length ? `crash: «${prefijo}» es ambiguo.` : `crash: ${objetivo.nombre} no tiene un crash ${prefijo}. Los de fuzz_run quedan en ${FUZZ.salida}/${objetivo.nombre}/crashes/.`);
  return hits[0]!;
}

const PRIORIDAD: Record<ClaseCrash, number> = { memoria: 0, ub: 1, señal: 2, leak: 3, oom: 4, timeout: 5, harness: 6, entorno: 7 };

interface Candidato { input: string; reporte: ReporteSanitizer; reproduce: boolean; argv: string[]; env: Record<string, string>; stdin: boolean }

/** Guarda, deduplica (por firma, contra todo lo visto para este harness) y minimiza los crashes de una corrida. */
async function registrarCrashes(entorno: FuzzEntorno, objetivo: Objetivo, candidatos: Candidato[], opciones: { minimizar: boolean; entradaSeg: number; memoriaMb: number; leaks: boolean; signal?: AbortSignal }): Promise<{ crashes: CrashFuzz[]; omitidos: number }> {
  const indice = leerIndice(objetivo);
  const porFirma = new Map<string, Candidato>();
  for (const candidato of candidatos) {
    const previo = porFirma.get(candidato.reporte.firma);
    if (!previo || statSync(candidato.input).size < statSync(previo.input).size) porFirma.set(candidato.reporte.firma, candidato);
  }
  const ordenados = [...porFirma.values()].sort((a, b) => PRIORIDAD[a.reporte.clase] - PRIORIDAD[b.reporte.clase]);
  const salida: CrashFuzz[] = [];
  let minimizados = 0;
  let guardados = 0;
  let omitidos = 0;
  const ahora = new Date().toISOString();
  for (const candidato of ordenados) {
    const { reporte } = candidato;
    const conocido = indice[reporte.firma];
    const bytesOriginal = statSync(candidato.input).size;
    if (conocido) {
      conocido.vistas++;
      conocido.ultima = ahora;
      salida.push({ ...conocido, nuevo: false, reproduce: candidato.reproduce, bytes: bytesOriginal, bytesOriginal, minimizado: false, reporte });
      continue;
    }
    if (guardados >= entorno.limites.crashesMax) { omitidos++; continue; }
    guardados++;
    const dir = carpeta(entorno, FUZZ.salida, objetivo.nombre, "crashes", reporte.firma);
    const original = join(dir, "input");
    copyFileSync(candidato.input, original);
    let final = original;
    let finalReporte = reporte;
    let argv = candidato.argv.map((arg) => (arg === candidato.input ? original : arg.split(candidato.input).join(original)));
    let minimizado = false;
    const minimizable = objetivo.tipo === "fuzzer" && candidato.reproduce && ["memoria", "ub", "leak", "señal"].includes(reporte.clase);
    if (opciones.minimizar && minimizable && minimizados < entorno.limites.minimizarMax && !opciones.signal?.aborted) {
      minimizados++;
      const min = join(dir, "input.min");
      const segundos = entorno.limites.minimizarSeg;
      const env = entornoSanitizers(entorno, objetivo.dir, { leaks: opciones.leaks });
      await correr(entorno, [objetivo.binario, "-minimize_crash=1", `-max_total_time=${segundos}`, `-timeout=${opciones.entradaSeg}`, `-rss_limit_mb=${opciones.memoriaMb}`, ...(opciones.leaks ? [] : ["-detect_leaks=0"]), `-artifact_prefix=${env.TMPDIR}/`, `-exact_artifact_path=${min}`, original], { cwd: dir, env, timeoutMs: (segundos + 60) * 1000, signal: opciones.signal });
      if (existsSync(min) && statSync(min).size < bytesOriginal && !opciones.signal?.aborted) {
        const otra = await correrEntrada(entorno, objetivo, min, { entradaSeg: opciones.entradaSeg, memoriaMb: opciones.memoriaMb, leaks: opciones.leaks, signal: opciones.signal });
        // Vale si sigue siendo el mismo crash; si la minimización lo cambió, queda el original.
        if (otra.reporte?.firma === reporte.firma) {
          final = min;
          finalReporte = otra.reporte;
          argv = otra.argv;
          minimizado = true;
        } else rmSync(min, { force: true });
      }
    }
    const reproducir = comandoReproducir(entorno, argv, candidato.env, candidato.stdin ? final : undefined);
    writeFileSync(join(dir, "reporte.txt"), finalReporte.texto);
    const subir = relative(dir, entorno.cwd);
    writeFileSync(join(dir, "repro.sh"), `#!/bin/sh\n# Reproduce el crash ${reporte.firma} (${reporte.tipo}) de ${objetivo.nombre}. Lo generó fuzz_run de Orobas.\ncd "$(dirname "$0")/${subir}" || exit 1\n${reproducir}\n`);
    chmodSync(join(dir, "repro.sh"), 0o755);
    const bytes = statSync(final).size;
    const datos = readFileSync(final);
    const artefacto = entorno.artifacts.put(JSON.stringify({
      harness: objetivo.nombre, firma: reporte.firma, tipo: finalReporte.tipo, clase: finalReporte.clase, sanitizer: finalReporte.sanitizer,
      resumen: finalReporte.resumen, acceso: finalReporte.acceso, scariness: finalReporte.scariness, impacto: finalReporte.impacto, en_harness: finalReporte.enHarness,
      pila: finalReporte.propios.slice(0, 12), reporte: finalReporte.texto,
      input: { ruta: rel(entorno, final), bytes, minimizado, bytes_original: bytesOriginal, base64: bytes <= 262_144 ? datos.toString("base64") : undefined },
      command: reproducir, reproducir, carpeta: rel(entorno, dir),
    }, null, 1), "application/json", `fuzz_run:crash:${reporte.firma}`).hash;
    const meta: CrashConocido = {
      firma: reporte.firma, tipo: finalReporte.tipo, clase: finalReporte.clase, resumen: finalReporte.resumen, linea: lineaReporte(finalReporte), impacto: finalReporte.impacto,
      carpeta: rel(entorno, dir), input: rel(entorno, final), reproducir, artefacto, vistas: 1, primera: ahora, ultima: ahora, enHarness: finalReporte.enHarness,
    };
    writeFileSync(join(dir, "meta.json"), JSON.stringify(meta, null, 1));
    indice[reporte.firma] = meta;
    salida.push({ ...meta, nuevo: true, reproduce: candidato.reproduce, bytes, bytesOriginal, minimizado, reporte: finalReporte });
  }
  carpeta(entorno, FUZZ.salida, objetivo.nombre, "crashes");
  writeFileSync(indicePath(objetivo), JSON.stringify(indice, null, 1));
  return { crashes: salida.sort((a, b) => Number(b.nuevo) - Number(a.nuevo) || PRIORIDAD[a.clase] - PRIORIDAD[b.clase]), omitidos };
}

// ───────────────────────────── fuzz_run ─────────────────────────────

export interface PedidoFuzz {
  harness?: string;
  binary?: string;
  /** Duración total (por defecto 120 s). */
  seconds?: number;
  memory_mb?: number;
  /** Tope por entrada: pasarlo es un timeout (por defecto 10 s). */
  timeout_sec?: number;
  /** Procesos en paralelo (-fork de libFuzzer; con más de uno sigue después de cada crash). */
  workers?: number;
  /** Carpetas o archivos de semillas dentro del proyecto. El corpus propio queda en harness/out/<nombre>/corpus. */
  corpus?: string[];
  dict?: string;
  max_len?: number;
  /** Minimizar los crashes nuevos (-minimize_crash); por defecto sí. */
  minimize?: boolean;
  /** Detectar leaks (LeakSanitizer); por defecto sí. */
  leaks?: boolean;
  /** Sólo PoCs: argumentos («@@» es el archivo de entrada; por defecto sólo él) o la entrada por stdin. */
  args?: string[];
  stdin?: boolean;
}

export interface CorridaFuzz {
  nombre: string;
  tipo: TipoBinario;
  segundos: number;
  /** Cómo terminó: tiempo (sin crash), crash, cancelado, arranque (el binario no llegó a correr entradas) o error. */
  fin: "tiempo" | "crash" | "cancelado" | "arranque" | "error";
  ejecuciones?: number;
  porSegundo?: number;
  cobertura?: number;
  corpusNuevo?: number;
  crashes: CrashFuzz[];
  timeouts: number;
  ooms: number;
  /** Crashes que quedaron sin procesar por el tope por corrida. */
  sinProcesar: number;
  /** Corrida y corpus, relativos al proyecto. */
  carpeta: string;
  corpus: string;
  comando: string;
  /** Artefacto con el comando y el log completo. */
  log: string;
  /**
   * Artefacto con el resumen (JSON): `command` es el comando exacto para reproducir el crash principal (el primero
   * nuevo que no sea timeout ni oom) o, sin crashes, el de la corrida; `fuzz_command`, el de la corrida.
   */
  artefacto: string;
  /** Lo mismo que `command` del artefacto. */
  command: string;
  aviso?: string;
}

function estadisticas(salida: string): Pick<CorridaFuzz, "ejecuciones" | "porSegundo" | "cobertura" | "corpusNuevo"> {
  const stat = (name: string) => { const match = new RegExp(`stat::${name}:\\s*(\\d+)`).exec(salida); return match ? Number(match[1]) : undefined; };
  const covs = [...salida.matchAll(/\bcov: (\d+)/g)];
  const pulsos = [...salida.matchAll(/^#(\d+)[:\s]/gm)];
  const ejecuciones = stat("number_of_executed_units") ?? (pulsos.length ? Number(pulsos.at(-1)![1]) : undefined);
  const out: Pick<CorridaFuzz, "ejecuciones" | "porSegundo" | "cobertura" | "corpusNuevo"> = {};
  if (ejecuciones !== undefined) out.ejecuciones = ejecuciones;
  const porSegundo = stat("average_exec_per_sec");
  if (porSegundo !== undefined) out.porSegundo = porSegundo;
  if (covs.length) out.cobertura = Number(covs.at(-1)![1]);
  const nuevos = stat("new_units_added");
  if (nuevos !== undefined) out.corpusNuevo = nuevos;
  return out;
}

/** Semillas: las carpetas van tal cual a libFuzzer; los archivos sueltos se copian a una carpeta de la corrida. */
function semillas(rutas: string[], corrida: string): string[] {
  const carpetas: string[] = [];
  const sueltos: string[] = [];
  for (const real of rutas) (statSync(real).isDirectory() ? carpetas : sueltos).push(real);
  if (sueltos.length) {
    const dir = join(corrida, "semillas");
    mkdirSync(dir, { recursive: true });
    for (const archivo of sueltos) copyFileSync(archivo, join(dir, `${sha256Archivo(archivo).slice(0, 16)}-${basename(archivo)}`));
    carpetas.push(dir);
  }
  return carpetas;
}

function entradasDe(carpetas: string[], max: number): string[] {
  const out: string[] = [];
  for (const dir of carpetas) {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isFile()) out.push(join(dir, entry.name));
      if (out.length >= max) return out;
    }
  }
  return out;
}

/** Corre el fuzzer (o el PoC sobre el corpus) con sus topes y procesa lo que encuentre. */
export async function correrFuzzer(entorno: FuzzEntorno, pedido: PedidoFuzz, signal?: AbortSignal): Promise<CorridaFuzz> {
  const objetivo = resolverObjetivo(entorno, pedido);
  const { limites } = entorno;
  const segundos = entero(pedido.seconds, "seconds", limites.fuzzSeg, 5, limites.fuzzSegMax);
  const memoriaMb = entero(pedido.memory_mb, "memory_mb", limites.memoriaMb, 128, limites.memoriaMbMax);
  const entradaSeg = entero(pedido.timeout_sec, "timeout_sec", limites.entradaSeg, 1, limites.entradaSegMax);
  const workers = entero(pedido.workers, "workers", limites.procesos, 1, limites.procesosMax);
  const leaks = pedido.leaks !== false;
  const corpusPedido = lista(pedido.corpus, "corpus", 32).map((item, index) => enProyecto(entorno, item, `corpus[${index}]`));
  const dict = pedido.dict ? archivoEnProyecto(entorno, pedido.dict, "dict") : undefined;
  const maxLen = pedido.max_len === undefined ? undefined : entero(pedido.max_len, "max_len", 4096, 1, 16 * 1024 * 1024);
  if (objetivo.tipo === "poc" && (dict || maxLen || workers > 1)) throw new Error("dict, max_len y workers son de libFuzzer: este binario es un PoC (main propio).");
  if (objetivo.tipo === "fuzzer" && (pedido.args || pedido.stdin)) throw new Error("args y stdin son para PoCs con main: un fuzzer de libFuzzer toma cada entrada como archivo.");
  const id = `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(2).toString("hex")}`;
  const corrida = carpeta(entorno, FUZZ.salida, objetivo.nombre, "corridas", id);
  const trabajo = carpeta(entorno, FUZZ.salida, objetivo.nombre, "corpus");
  const seeds = semillas(corpusPedido, corrida);
  const base: Omit<CorridaFuzz, "fin" | "crashes" | "timeouts" | "ooms" | "sinProcesar" | "comando" | "log" | "artefacto" | "command"> = { nombre: objetivo.nombre, tipo: objetivo.tipo, segundos, carpeta: rel(entorno, corrida), corpus: rel(entorno, trabajo) };
  const candidatos: Candidato[] = [];
  let comando: string;
  let log: string;
  let fin: CorridaFuzz["fin"] = "tiempo";
  let stats: ReturnType<typeof estadisticas> = {};
  let sinProcesar = 0;
  let aviso: string | undefined;

  if (objetivo.tipo === "fuzzer") {
    const env = entornoSanitizers(entorno, objetivo.dir, { leaks });
    const argv = [
      objetivo.binario, `-max_total_time=${segundos}`, `-timeout=${entradaSeg}`, `-rss_limit_mb=${memoriaMb}`, `-malloc_limit_mb=${memoriaMb}`,
      `-artifact_prefix=${corrida}/`, "-print_final_stats=1", ...(leaks ? [] : ["-detect_leaks=0"]),
      ...(dict ? [`-dict=${dict}`] : []), ...(maxLen ? [`-max_len=${maxLen}`] : []),
      ...(workers > 1 ? [`-fork=${workers}`, "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1"] : []),
      trabajo, ...seeds,
    ];
    comando = lineaShell(argv);
    const proceso = await correr(entorno, argv, { cwd: corrida, env, timeoutMs: (segundos + 60) * 1000, signal, maxBytes: 8_000_000 });
    const salida = `${proceso.stderr}${proceso.stdout ? `\n[stdout]\n${proceso.stdout}` : ""}`;
    writeFileSync(join(corrida, "fuzz.log"), salida);
    log = entorno.artifacts.put(`$ ${comando}\n${salida}`, "text/plain", `fuzz_run:${objetivo.nombre}`).hash;
    stats = estadisticas(salida);
    const arranco = /INFO: Seed:|INFO: -fork=|Running: |INITED|#\d+\s/.test(salida);
    const archivos = readdirSync(corrida).filter((name) => /^(?:crash|leak|timeout|oom)-[0-9a-f]+$/.test(name)).map((name) => join(corrida, name)).sort((a, b) => statSync(a).mtimeMs - statSync(b).mtimeMs);
    if (proceso.cancelled) fin = "cancelado";
    else if (!arranco && proceso.exitCode !== 0) {
      fin = "arranque";
      const reporte = clasificarReporte(salida);
      aviso = `El binario no llegó a correr entradas${reporte ? ` (${reporte.tipo}: ${reporte.resumen.slice(0, 160)})` : ` (salida ${proceso.exitCode ?? proceso.senal})`}. ${reporte?.clase === "entorno" ? "Es el entorno, no el objetivo: con LLVM 16, ASan y MSan fallan si el kernel del host tiene vm.mmap_rnd_bits=32 (se arregla en el host con sysctl vm.mmap_rnd_bits=28)." : "Revisá LLVMFuzzerInitialize y los constructores globales del objetivo; el log completo está en el artefacto."}`;
    } else if (proceso.timedOut) aviso = `Cortado por tiempo a los ${segundos + 60} s (libFuzzer no terminó solo).`;
    if (archivos.length) fin = fin === "cancelado" ? fin : "crash";
    sinProcesar = Math.max(0, archivos.length - limites.crashesMax);
    for (const archivo of archivos.slice(0, limites.crashesMax)) {
      if (signal?.aborted) break;
      const prefijo = basename(archivo).replace(/-.*$/, "");
      const una = await correrEntrada(entorno, objetivo, archivo, { entradaSeg, memoriaMb, leaks, signal });
      // Si no reproduce solo (estado, tiempo), queda igual, con el tipo que dijo libFuzzer.
      const reporte = una.reporte ?? sintetico(prefijo === "crash" ? "crash-no-reproduce" : prefijo, prefijo === "timeout" ? "timeout" : prefijo === "oom" ? "oom" : prefijo === "leak" ? "leak" : "señal", `libFuzzer lo guardó como ${prefijo}, pero no se reprodujo al correrlo solo`);
      candidatos.push({ input: archivo, reporte, reproduce: !!una.reporte, argv: una.argv, env: una.env, stdin: false });
    }
    if (!archivos.length && fin !== "cancelado" && fin !== "arranque") {
      const reporte = proceso.exitCode !== 0 ? clasificarReporte(salida) : undefined;
      if (reporte) aviso = `libFuzzer terminó con ${reporte.tipo} sin guardar la entrada: ${reporte.resumen.slice(0, 200)}`;
    }
  } else {
    if (!seeds.length) throw new Error("Un PoC no muta entradas: pasá corpus con las entradas a probar, o compilá un harness con LLVMFuzzerTestOneInput para que libFuzzer las genere.");
    const entradas = entradasDe(seeds, 10_000);
    const hasta = Date.now() + segundos * 1000;
    const partes: string[] = [];
    let ejecuciones = 0;
    let primero: UnaEntrada | undefined;
    for (const input of entradas) {
      if (signal?.aborted) { fin = "cancelado"; break; }
      if (Date.now() >= hasta) { aviso = `Se acabó el tiempo con ${ejecuciones} de ${entradas.length} entradas.`; break; }
      const una = await correrEntrada(entorno, objetivo, input, { entradaSeg, memoriaMb, leaks, args: pedido.args, stdin: pedido.stdin, signal });
      primero ??= una;
      if (una.proceso.cancelled) { fin = "cancelado"; break; }
      ejecuciones++;
      if (una.reporte) {
        partes.push(`### ${rel(entorno, input)}\n${una.proceso.stderr.slice(-20_000)}`);
        candidatos.push({ input, reporte: una.reporte, reproduce: true, argv: una.argv, env: una.env, stdin: !!pedido.stdin });
      }
    }
    if (candidatos.length && fin !== "cancelado") fin = "crash";
    stats = { ejecuciones };
    comando = primero ? lineaShell(primero.argv).split(`${entorno.cwd}/`).join("") : lineaShell([objetivo.binario, ...(pedido.args ?? ["@@"])]);
    const salida = `PoC sobre ${entradas.length} entradas (${ejecuciones} corridas)\n${partes.join("\n\n")}`;
    writeFileSync(join(corrida, "fuzz.log"), salida);
    log = entorno.artifacts.put(`$ ${comando}\n${salida}`, "text/plain", `fuzz_run:${objetivo.nombre}`).hash;
  }

  // Lo que dice que el sanitizer no pudo trabajar no es un crash del objetivo: va como aviso.
  const delEntorno = candidatos.find((item) => item.reporte.clase === "entorno");
  if (delEntorno) aviso = [aviso, `${delEntorno.reporte.tipo === "lsan-no-corre" ? "LeakSanitizer no corre en este entorno: repetí con leaks: false." : "El sanitizer no pudo arrancar en este entorno (no es del objetivo)."} ${delEntorno.reporte.resumen.slice(0, 160)}`].filter(Boolean).join(" ");
  const registro = await registrarCrashes(entorno, objetivo, candidatos.filter((item) => item.reporte.clase !== "entorno"), { minimizar: pedido.minimize !== false, entradaSeg, memoriaMb, leaks, signal });
  const crashes = registro.crashes;
  sinProcesar += registro.omitidos;
  if (signal?.aborted) fin = "cancelado";
  else if (fin === "crash" && !crashes.length) fin = "tiempo";
  const principal = crashes.find((item) => item.nuevo && !["timeout", "oom"].includes(item.clase)) ?? crashes.find((item) => !["timeout", "oom"].includes(item.clase)) ?? crashes[0];
  const fuzzCommand = comando.split(`${entorno.cwd}/`).join("");
  const command = principal?.reproducir ?? fuzzCommand;
  const timeouts = crashes.filter((item) => item.clase === "timeout").length;
  const ooms = crashes.filter((item) => item.clase === "oom").length;
  const artefacto = entorno.artifacts.put(JSON.stringify({
    harness: objetivo.nombre, fin, command, fuzz_command: fuzzCommand, segundos, ...stats, timeouts, ooms, sin_procesar: sinProcesar, aviso, log,
    crashes: crashes.map((item) => ({ firma: item.firma, nuevo: item.nuevo, tipo: item.tipo, clase: item.clase, linea: item.linea, impacto: item.impacto, en_harness: item.enHarness, reproduce: item.reproduce, input: item.input, command: item.reproducir, artefacto: item.artefacto })),
  }, null, 1), "application/json", `fuzz_run:${objetivo.nombre}:resumen`).hash;
  const resultado: CorridaFuzz = {
    ...base, fin, ...stats, crashes, timeouts, ooms,
    sinProcesar, comando: fuzzCommand, log, artefacto, command, ...(aviso ? { aviso } : {}),
  };
  entorno.event?.("fuzz.corrida", { harness: objetivo.nombre, fin, segundos, ejecuciones: resultado.ejecuciones ?? 0, crashes: crashes.length, nuevos: crashes.filter((item) => item.nuevo).length, firmas: crashes.map((item) => item.firma), log });
  return resultado;
}

// ───────────────────────────── poc_run ─────────────────────────────

export interface PedidoPoc {
  harness?: string;
  binary?: string;
  /** Archivo de entrada dentro del proyecto. */
  input?: string;
  /** O la firma (o su prefijo) de un crash de fuzz_run: usa su input minimizado. */
  crash?: string;
  /**
   * O una línea de comando, como la que devuelven fuzz_run y poc_run en `command`: opciones de los sanitizers,
   * el binario (instrumentado, del proyecto), sus argumentos y a lo sumo «< archivo». Sin shell: nada de tuberías,
   * variables ni comodines. Excluye harness, binary, input y crash.
   */
  command?: string;
  /** Carpeta del proyecto desde donde se lee `command` (relativa o absoluta; por defecto la raíz). */
  cwd?: string;
  /** Veces (por defecto 5). */
  runs?: number;
  timeout_sec?: number;
  memory_mb?: number;
  leaks?: boolean;
  /** Sólo PoCs: argumentos («@@» es el archivo de entrada) o la entrada por stdin. */
  args?: string[];
  stdin?: boolean;
  /** Firma esperada: dice si cada corrida da ese mismo crash. */
  firma?: string;
}

export type Veredicto = "determinista" | "no determinista" | "no reproduce";

export interface CorridaPoc { n: number; crash: boolean; firma?: string; tipo?: string; exitCode: number | null; senal: string | null; ms: number }

export interface Reproduccion {
  nombre: string;
  /** El archivo de entrada, relativo al proyecto (un `command` puede no tener). */
  input?: string;
  veredicto: Veredicto;
  /** Al menos una corrida dio un crash (un reporte de sanitizer, una señal o un timeout). */
  reproduce: boolean;
  /** Corridas con crash. */
  veces: number;
  /** Corridas hechas. */
  corridas: number;
  /** El código de salida de la última corrida (null si murió por una señal). */
  exitCode: number | null;
  /** Cuántas veces salió cada firma. */
  firmas: Record<string, number>;
  /** El reporte de la firma más frecuente. */
  reporte?: ReporteSanitizer;
  /** El reporte del crash principal, o la salida de la última corrida si no hubo crash (recortada). */
  salida: string;
  esperada?: { firma: string; coincide: boolean };
  detalle: CorridaPoc[];
  /** El comando exacto para reproducir, relativo a `cwd`; poc_run lo vuelve a aceptar como `command`. */
  command: string;
  /** Desde dónde corre `command`, relativo al proyecto («.» es la raíz). */
  cwd: string;
  artefacto: string;
  cancelado: boolean;
  /** El sanitizer no pudo trabajar en este entorno (no cuenta como crash). */
  aviso?: string;
}

/**
 * Palabras de una línea de comando sin shell: comillas simples y dobles, barra invertida y a lo sumo un «< archivo»
 * al final. Lo que haría falta un shell para entender (tuberías, «;», «&», «>», variables, comodines) se rechaza.
 */
export function palabrasComando(linea: string): { palabras: string[]; stdin?: string } {
  const palabras: string[] = [];
  let actual = "";
  let hay = false;
  let redireccion = false;
  let stdin: string | undefined;
  const cerrar = () => {
    if (!hay) return;
    if (stdin !== undefined) throw new Error("command: «< archivo» va al final.");
    if (redireccion) stdin = actual;
    else palabras.push(actual);
    actual = "";
    hay = false;
  };
  for (let i = 0; i < linea.length; i++) {
    const c = linea[i]!;
    if (c === "'") {
      const fin = linea.indexOf("'", i + 1);
      if (fin < 0) throw new Error("command: comillas sin cerrar.");
      actual += linea.slice(i + 1, fin);
      hay = true;
      i = fin;
    } else if (c === '"') {
      let j = i + 1;
      for (; j < linea.length && linea[j] !== '"'; j++) {
        if (linea[j] === "\\" && j + 1 < linea.length && '"\\$`'.includes(linea[j + 1]!)) { actual += linea[++j]; continue; }
        if (linea[j] === "$" || linea[j] === "`") throw new Error(`command: «${linea[j]}» no se acepta (sin shell, sin variables).`);
        actual += linea[j];
      }
      if (j >= linea.length) throw new Error("command: comillas sin cerrar.");
      hay = true;
      i = j;
    } else if (c === "\\") {
      if (i + 1 >= linea.length) throw new Error("command: barra invertida al final.");
      actual += linea[++i];
      hay = true;
    } else if (/\s/.test(c)) cerrar();
    else if (c === "<") {
      cerrar();
      if (redireccion) throw new Error("command: un solo «< archivo».");
      redireccion = true;
    } else if ("|;&>`$(){}*?[]#\n".includes(c)) throw new Error(`command: «${c}» no se acepta. Sin shell: opciones de los sanitizers, el binario, sus argumentos y a lo sumo «< archivo».`);
    else { actual += c; hay = true; }
  }
  cerrar();
  if (redireccion && stdin === undefined) throw new Error("command: «<» sin archivo.");
  return { palabras, ...(stdin !== undefined ? { stdin } : {}) };
}

const OPCIONES_SAN = /^(?:ASAN|UBSAN|MSAN|LSAN)_OPTIONS$/;

/** Lo que dice un `command`: el binario, los argumentos (o el input de un fuzzer) y si apaga los leaks. */
interface ComandoPoc { objetivo: Objetivo; cwd: string; input?: string; args: string[]; stdin: boolean; leaks: boolean; entradaSeg?: number; memoriaMb?: number }

function leerComando(entorno: FuzzEntorno, command: string, cwdPedido: string | undefined): ComandoPoc {
  if (typeof command !== "string" || !command.trim() || command.length > 16_384) throw new Error("command: una línea de hasta 16384 caracteres.");
  const cwd = cwdPedido === undefined || cwdPedido === "" ? entorno.cwd : carpetaEnProyecto(entorno, cwdPedido, "cwd");
  const { palabras, stdin } = palabrasComando(command.trim());
  let leaks = true;
  let i = 0;
  for (; i < palabras.length; i++) {
    const asignacion = /^([A-Za-z_]\w*)=(.*)$/s.exec(palabras[i]!);
    if (!asignacion) break;
    if (!OPCIONES_SAN.test(asignacion[1]!)) throw new Error(`command: ${asignacion[1]} no; adelante del binario van sólo ASAN_OPTIONS, UBSAN_OPTIONS, MSAN_OPTIONS o LSAN_OPTIONS (el resto del entorno lo pone poc_run).`);
    if (/(?:^|:)detect_leaks=0(?::|$)/.test(asignacion[2]!)) leaks = false;
  }
  const binario = palabras[i];
  if (!binario) throw new Error("command: falta el binario.");
  const ruta = (value: string, campo: string) => archivoEnProyecto(entorno, resolve(cwd, value), campo);
  const objetivo = resolverObjetivo(entorno, { binary: ruta(binario, "command (binario)") });
  const resto = palabras.slice(i + 1);
  const entradaStdin = stdin === undefined ? undefined : ruta(stdin, "command (< archivo)");
  if (objetivo.tipo === "fuzzer") {
    if (entradaStdin) throw new Error("command: un fuzzer de libFuzzer toma el input como archivo, no por «<».");
    let entradaSeg: number | undefined;
    let memoriaMb: number | undefined;
    const sueltos: string[] = [];
    for (const palabra of resto) {
      let match: RegExpExecArray | null;
      if ((match = /^-timeout=(\d+)$/.exec(palabra))) entradaSeg = Number(match[1]);
      else if ((match = /^-rss_limit_mb=(\d+)$/.exec(palabra))) memoriaMb = Number(match[1]);
      else if (palabra === "-detect_leaks=0") leaks = false;
      // El resto de las banderas (prefijo de artefactos, malloc_limit…) las pone poc_run.
      else if (!palabra.startsWith("-")) sueltos.push(palabra);
    }
    if (sueltos.length !== 1) throw new Error(`command: un fuzzer de libFuzzer corre un archivo de entrada; acá hay ${sueltos.length}.`);
    return { objetivo, cwd, input: ruta(sueltos[0]!, "command (input)"), args: [], stdin: false, leaks, ...(entradaSeg ? { entradaSeg } : {}), ...(memoriaMb ? { memoriaMb } : {}) };
  }
  // Un PoC: sus argumentos tal cual (con las rutas revisadas); el input, el de «<» o el último argumento que sea un archivo del proyecto.
  const input = entradaStdin ?? [...resto].reverse().map((palabra) => {
    try { const real = resolve(cwd, palabra); return existsSync(real) && statSync(real).isFile() ? archivoEnProyecto(entorno, real, "command") : undefined; } catch { return undefined; }
  }).find(Boolean);
  return { objetivo, cwd, ...(input ? { input } : {}), args: resto, stdin: !!entradaStdin, leaks };
}

interface Repeticion { detalle: CorridaPoc[]; firmas: Record<string, number>; reportes: Map<string, ReporteSanitizer>; textos: string[]; primera?: UnaEntrada; ultima?: UnaEntrada; cancelado: boolean; aviso?: string }

/** Corre `una` hasta `veces` veces y junta qué crash dio cada corrida. */
async function repetir(veces: number, una: () => Promise<UnaEntrada>, signal?: AbortSignal): Promise<Repeticion> {
  const out: Repeticion = { detalle: [], firmas: {}, reportes: new Map(), textos: [], cancelado: false };
  for (let n = 1; n <= veces; n++) {
    if (signal?.aborted) { out.cancelado = true; break; }
    const corrida = await una();
    if (corrida.proceso.cancelled) { out.cancelado = true; break; }
    out.primera ??= corrida;
    out.ultima = corrida;
    // Que el sanitizer no pueda trabajar acá no es un crash del objetivo.
    const reporte = corrida.reporte?.clase === "entorno" ? undefined : corrida.reporte;
    if (corrida.reporte?.clase === "entorno") out.aviso ??= `${corrida.reporte.tipo === "lsan-no-corre" ? "LeakSanitizer no corre en este entorno: repetí con leaks: false." : "El sanitizer no pudo arrancar en este entorno (no es del objetivo)."} ${corrida.reporte.resumen.slice(0, 160)}`;
    out.detalle.push({ n, crash: !!reporte, ...(reporte ? { firma: reporte.firma, tipo: reporte.tipo } : {}), exitCode: corrida.proceso.exitCode, senal: corrida.proceso.senal, ms: corrida.proceso.ms });
    if (reporte) {
      out.firmas[reporte.firma] = (out.firmas[reporte.firma] ?? 0) + 1;
      if (!out.reportes.has(reporte.firma)) out.reportes.set(reporte.firma, reporte);
    }
    if (n <= 3 || reporte) out.textos.push(`### corrida ${n}: ${reporte ? `${reporte.tipo} (${reporte.firma})` : `sin crash (salida ${corrida.proceso.exitCode ?? corrida.proceso.senal})`}\n${(reporte?.texto ?? `${corrida.proceso.stderr}${corrida.proceso.stdout}`).slice(0, 8000)}`);
  }
  return out;
}

/** Arma el resultado (y su artefacto) de una serie de corridas. */
function reproduccion(entorno: FuzzEntorno, objetivo: Objetivo, r: Repeticion, extra: { input?: string; esperada?: string; stdin: boolean; productor: string; desde?: string }): Reproduccion {
  const corridas = r.detalle.length;
  const veces = r.detalle.filter((item) => item.crash).length;
  const distintas = Object.keys(r.firmas).length;
  const veredicto: Veredicto = !veces ? "no reproduce" : veces === corridas && distintas === 1 ? "determinista" : "no determinista";
  const principal = Object.entries(r.firmas).sort((a, b) => b[1] - a[1])[0]?.[0];
  const reporte = principal ? r.reportes.get(principal) : undefined;
  const coincide = !!extra.esperada && veredicto === "determinista" && !!principal && principal.startsWith(extra.esperada);
  // Las rutas del command, relativas a donde se lo leyó (el cwd de un command) o a la raíz del proyecto.
  const cwd = extra.desde ?? entorno.cwd;
  const command = r.primera ? comandoReproducir(entorno, r.primera.argv, r.primera.env, extra.stdin ? extra.input : undefined, cwd) : "";
  const ultima = r.ultima?.proceso;
  const salida = (reporte?.texto ?? (ultima ? `${ultima.stderr}${ultima.stdout ? `\n${ultima.stdout}` : ""}` : "")).slice(0, 20_000);
  const input = extra.input ? rel(entorno, extra.input) : undefined;
  const exitCode = ultima?.exitCode ?? null;
  const artefacto = entorno.artifacts.put(JSON.stringify({
    harness: objetivo.nombre, command, cwd: rel(entorno, cwd), input, veredicto, reproduce: veces > 0, veces, corridas, exitCode, firmas: r.firmas, esperada: extra.esperada,
    detalle: r.detalle, salida, reportes: r.textos.join("\n\n"),
  }, null, 1), "application/json", extra.productor).hash;
  entorno.event?.("fuzz.poc", { harness: objetivo.nombre, input, veredicto, veces, corridas, firmas: r.firmas, artefacto });
  return {
    nombre: objetivo.nombre, ...(input ? { input } : {}), veredicto, reproduce: veces > 0, veces, corridas, exitCode, firmas: r.firmas, ...(reporte ? { reporte } : {}), salida,
    ...(extra.esperada ? { esperada: { firma: extra.esperada, coincide } } : {}), detalle: r.detalle, command, cwd: rel(entorno, cwd), artefacto, cancelado: r.cancelado, ...(r.aviso ? { aviso: r.aviso } : {}),
  };
}

/** Corre el binario N veces sobre el mismo input y dice si el crash es determinista. Con `command`, ver runPoc. */
export async function reproducirPoc(entorno: FuzzEntorno, pedido: PedidoPoc, signal?: AbortSignal): Promise<Reproduccion> {
  const { limites } = entorno;
  const esperada = pedido.firma?.trim().toLowerCase();
  if (esperada && !/^[0-9a-f]{6,12}$/.test(esperada)) throw new Error("firma: 6 a 12 caracteres hexadecimales.");
  const veces = entero(pedido.runs, "runs", limites.pocVeces, 1, limites.pocVecesMax);
  const memoriaPedida = pedido.memory_mb;
  if (pedido.command !== undefined) {
    if (pedido.harness || pedido.binary || pedido.input || pedido.crash || pedido.args || pedido.stdin) throw new Error("command va solo: el binario, el input y los argumentos salen de la línea.");
    const comando = leerComando(entorno, pedido.command, pedido.cwd);
    const entradaSeg = entero(pedido.timeout_sec ?? comando.entradaSeg, "timeout_sec", comando.objetivo.tipo === "fuzzer" ? limites.entradaSeg : Math.max(limites.entradaSeg, 30), 1, limites.entradaSegMax);
    const memoriaMb = entero(memoriaPedida ?? comando.memoriaMb, "memory_mb", limites.memoriaMb, 128, limites.memoriaMbMax);
    const leaks = pedido.leaks === false ? false : comando.leaks;
    const r = await repetir(veces, () => correrEntrada(entorno, comando.objetivo, comando.input, { entradaSeg, memoriaMb, leaks, args: comando.args, stdin: comando.stdin, signal, cwd: comando.cwd }), signal);
    return reproduccion(entorno, comando.objetivo, r, { ...(comando.input ? { input: comando.input } : {}), ...(esperada ? { esperada } : {}), stdin: comando.stdin, productor: `poc_run:${comando.objetivo.nombre}`, desde: comando.cwd });
  }
  if (pedido.cwd !== undefined) throw new Error("cwd va con command.");
  const objetivo = resolverObjetivo(entorno, pedido);
  if (!!pedido.input === !!pedido.crash) throw new Error("Pasá input (un archivo del proyecto) o crash (la firma de fuzz_run), uno solo; o command con la línea entera.");
  if (objetivo.tipo === "fuzzer" && (pedido.args || pedido.stdin)) throw new Error("args y stdin son para PoCs con main: un fuzzer de libFuzzer toma el input como archivo.");
  const conocido = pedido.crash ? buscarCrash(objetivo, String(pedido.crash).trim().toLowerCase()) : undefined;
  const input = archivoEnProyecto(entorno, conocido ? conocido.input : pedido.input, conocido ? "crash" : "input");
  const entradaSeg = entero(pedido.timeout_sec, "timeout_sec", objetivo.tipo === "fuzzer" ? limites.entradaSeg : Math.max(limites.entradaSeg, 30), 1, limites.entradaSegMax);
  const memoriaMb = entero(memoriaPedida, "memory_mb", limites.memoriaMb, 128, limites.memoriaMbMax);
  const leaks = pedido.leaks !== false;
  const r = await repetir(veces, () => correrEntrada(entorno, objetivo, input, { entradaSeg, memoriaMb, leaks, args: pedido.args, stdin: pedido.stdin, signal }), signal);
  const firmaEsperada = esperada ?? conocido?.firma;
  return reproduccion(entorno, objetivo, r, { input, ...(firmaEsperada ? { esperada: firmaEsperada } : {}), stdin: !!pedido.stdin && objetivo.tipo === "poc", productor: `poc_run:${objetivo.nombre}` });
}

/** Lo que pide la verificación por ejecución (/investigar): una línea de comando y desde dónde. */
export interface PedidoRunPoc { command: string; cwd?: string; runs?: number; timeoutMs?: number; signal?: AbortSignal }

/**
 * La forma corta para la verificación por ejecución: corre `command` (la línea que devuelven fuzz_run y poc_run en
 * `command`) desde `cwd` las veces pedidas, con las mismas reglas que poc_run (binario instrumentado del proyecto,
 * sin shell, sin red, con topes). Devuelve, además de todo Reproduccion, `{ exitCode, reproduce, corridas, salida }`.
 */
export function runPoc(entorno: FuzzEntorno, pedido: PedidoRunPoc): Promise<Reproduccion> {
  const timeout = pedido.timeoutMs === undefined ? undefined : Math.max(1, Math.ceil(pedido.timeoutMs / 1000));
  return reproducirPoc(entorno, { command: pedido.command, ...(pedido.cwd !== undefined ? { cwd: pedido.cwd } : {}), ...(pedido.runs !== undefined ? { runs: pedido.runs } : {}), ...(timeout !== undefined ? { timeout_sec: timeout } : {}) }, pedido.signal);
}

/** runPoc atado a un entorno, para inyectarlo (por ejemplo en EngineOptions.investigacion.poc): `pocRunner(engine.fuzzing)`. */
export const pocRunner = (entorno: FuzzEntorno) => (pedido: PedidoRunPoc) => runPoc(entorno, pedido);

// ───────────────────────────── herramientas del agente ─────────────────────────────

const s = (description: string, extra: object = {}) => ({ type: "string", description, ...extra });
const n = (description: string, extra: object = {}) => ({ type: "integer", description, ...extra });
const b = (description: string) => ({ type: "boolean", description });
const ss = (description: string) => ({ type: "array", items: { type: "string" }, description });

const SIGUE_HABILIDAD = "Un crash no es un hallazgo: falta que sea determinista (poc_run), alcanzable desde una entrada real y con ganancia (primitiva o impacto). Ver la habilidad harness-fuzzing.";

export function textoCompilacion(entorno: FuzzEntorno, c: Compilacion): string {
  if (c.cancelado) return `Compilación de ${c.nombre} cancelada. Log en ${c.artefacto}.`;
  if (!c.ok) {
    return [
      `No compiló ${c.nombre} (salida ${c.exitCode ?? "?"}). Comando exacto y log completo en ${c.artefacto}.`,
      ...(c.errores.length ? ["Errores:", ...c.errores.map((item) => `- ${item}`)] : []),
      ...(c.indefinidos.length ? [`Símbolos sin definir (falta enlazar el objeto o la librería que los trae): ${c.indefinidos.join(", ")}`] : []),
    ].join("\n");
  }
  const binario = rel(entorno, c.binario!);
  const siguiente = c.tipo === "fuzzer"
    ? `fuzz_run { harness: "${c.nombre}" } (empezá con 60 a 120 s y mirá ejecuciones por segundo y cobertura).`
    : `poc_run { harness: "${c.nombre}", input: "<archivo>" }, o fuzz_run con corpus para correrlo sobre varias entradas.`;
  return [
    `Compilado ${binario}: ${c.tipo === "fuzzer" ? "fuzzer de libFuzzer" : "PoC"} con ${c.sanitizers.join(" + ")}, sin red${c.advertencias ? ` · ${c.advertencias} advertencias` : ""}. Comando y log en ${c.artefacto}.`,
    `Siguiente: ${siguiente}`,
  ].join("\n");
}

function lineaCrash(c: CrashFuzz): string[] {
  const estado = c.nuevo ? "nuevo" : `ya visto (${c.vistas} veces)`;
  const input = c.minimizado ? `${c.bytes} bytes (minimizado de ${c.bytesOriginal})` : `${c.bytes} bytes`;
  return [
    `- ${estado} · ${c.linea} · firma ${c.firma}${c.reproduce ? "" : " · no se reprodujo solo"}${c.enHarness ? " · está en el harness, no en el objetivo" : ""}`,
    `  ${c.impacto}`,
    `  input ${input} en ${c.carpeta}/ · artefacto ${c.artefacto}`,
    `  reproducir: ${c.reproducir.replace(/^(?:\w+_OPTIONS=\S+ )+/, "")}`,
  ];
}

export function textoCorrida(c: CorridaFuzz): string {
  const numeros = [
    c.ejecuciones !== undefined ? `${c.ejecuciones} ejecuciones${c.porSegundo !== undefined ? ` (${c.porSegundo}/s)` : ""}` : "",
    c.cobertura !== undefined ? `cobertura ${c.cobertura}` : "",
    c.corpusNuevo !== undefined ? `corpus +${c.corpusNuevo} en ${c.corpus}` : "",
  ].filter(Boolean).join(", ");
  const distintos = c.crashes.filter((item) => !["timeout", "oom"].includes(item.clase));
  const nuevos = distintos.filter((item) => item.nuevo).length;
  const encabezado = c.fin === "arranque"
    ? `${c.nombre} no arrancó.`
    : `${c.tipo === "fuzzer" ? "Fuzzing" : "PoC sobre el corpus"} de ${c.nombre}: ${c.segundos} s${numeros ? `, ${numeros}` : ""}${c.fin === "cancelado" ? " (cancelado)" : ""}.`;
  const cuenta = c.crashes.length
    ? `${distintos.length} crash${distintos.length === 1 ? "" : "es"} distinto${distintos.length === 1 ? "" : "s"} (${nuevos} nuevo${nuevos === 1 ? "" : "s"}) · ${c.timeouts} timeout${c.timeouts === 1 ? "" : "s"} · ${c.ooms} oom.`
    : c.fin === "arranque" ? "" : "Sin crashes.";
  const primero = c.crashes.find((item) => item.nuevo && !["timeout", "oom", "harness", "entorno"].includes(item.clase)) ?? c.crashes[0];
  return [
    encabezado,
    ...(c.aviso ? [c.aviso] : []),
    ...(cuenta ? [cuenta] : []),
    ...c.crashes.flatMap(lineaCrash),
    ...(c.sinProcesar ? [`${c.sinProcesar} crashes más quedaron sin procesar en ${c.carpeta}/ (tope por corrida).`] : []),
    `Resumen en ${c.artefacto} (command: el comando para reproducir); log completo en ${c.log}.`,
    ...(primero ? [`Siguiente: poc_run { harness: "${c.nombre}", crash: "${primero.firma}" } para ver si reproduce siempre. ${SIGUE_HABILIDAD}`] : c.fin === "tiempo" ? ["Sin crashes no prueba nada: si la cobertura dejó de crecer, mejorá semillas, diccionario o el harness antes de correr más tiempo."] : []),
  ].join("\n");
}

export function textoReproduccion(r: Reproduccion): string {
  const lista_ = Object.entries(r.firmas).map(([firma, count]) => `${firma}×${count}`);
  const sin = r.corridas - r.veces;
  const veredicto = r.veredicto === "determinista"
    ? `reproduce ${r.veces} de ${r.corridas}: determinista (firma ${Object.keys(r.firmas)[0]}${r.esperada ? r.esperada.coincide ? ", la esperada" : `, no la esperada ${r.esperada.firma}` : ""}).`
    : r.veredicto === "no reproduce" ? `no reproduce en ${r.corridas} corridas (la última sale con ${r.exitCode ?? r.detalle.at(-1)?.senal ?? "?"}).` : `reproduce ${r.veces} de ${r.corridas}: no determinista (${[...lista_, ...(sin ? [`sin crash×${sin}`] : [])].join(", ")}).`;
  return [
    `poc_run ${r.nombre}${r.input ? ` sobre ${r.input}` : ""}: ${veredicto}${r.cancelado ? " Cancelado antes de terminar." : ""}`,
    ...(r.aviso ? [r.aviso] : []),
    ...(r.reporte ? [lineaReporte(r.reporte), r.reporte.impacto, ...(r.reporte.enHarness ? ["El crash está en el harness, no en el objetivo: revisalo antes de creerle."] : [])] : []),
    ...(r.veredicto === "no determinista" ? ["Antes de reportarlo, buscá estado global, hilos, tiempo o aleatoriedad en el harness o el objetivo; un crash que no reproduce siempre se reporta con la tasa y el cómo."] : []),
    `Reporte y corridas en ${r.artefacto}. Reproducir${r.cwd !== "." ? ` (desde ${r.cwd})` : ""}: ${r.command}`,
  ].join("\n");
}

/** Las herramientas del agente. Sólo se crean con un entorno (dentro de la caja). */
export function createFuzzTools(entorno: FuzzEntorno): Tool[] {
  const { limites } = entorno;
  const build: Tool = {
    name: "harness_build",
    label: t("Compilar harness", "Build harness"),
    description:
      "Compila un harness que escribiste en el proyecto (p. ej. harness/<nombre>.c con LLVMFuzzerTestOneInput) o un PoC con main, contra el código del objetivo, con sanitizers (por defecto ASan + UBSan; MSan aparte). Sólo en la caja. " +
      "Fuentes, includes, objetos y librerías (.o/.a/.so del objetivo, compilados con los mismos sanitizers) tienen que estar dentro del proyecto. Deja el binario en harness/out/<nombre>/, guarda el comando exacto y el log como artefacto y devuelve los errores compactos. Cada binario lleva enlazado un corte de red (sólo sockets AF_UNIX).",
    parameters: {
      type: "object",
      properties: {
        sources: ss("Fuentes dentro del proyecto: el harness primero, después los del objetivo que quieras compilar con él (.c, .cc, .cpp, .cxx)"),
        name: s("Nombre del binario y de su carpeta (por defecto, el del primer fuente)"),
        kind: s("fuzzer (libFuzzer) o poc (main propio); por defecto lo deduce", { enum: ["fuzzer", "poc"] }),
        sanitizers: { type: "array", items: { type: "string", enum: SANITIZERS }, description: "Por defecto [address, undefined]. memory va solo (o con undefined); integer suma overflow sin signo (ruidoso)" },
        include_dirs: ss("Carpetas de includes del proyecto"),
        defines: ss("Macros: NOMBRE o NOMBRE=valor"),
        flags: ss("Banderas extra sin rutas: -std=…, -O2, -g, -W…, -f…, -m…"),
        link: ss("Objetos y librerías del objetivo ya compilados (.o, .a, .so) dentro del proyecto"),
        lib_dirs: ss("Carpetas del proyecto con librerías (-L, y rpath para las .so)"),
        libs: ss("Librerías del sistema por nombre (-l): z, m, pthread…"),
        pkg_config: ss("Paquetes de pkg-config del sistema (zlib, libxml-2.0…)"),
        cxx: b("Forzar C++ (por defecto, si algún fuente es C++)"),
        timeout_sec: n(`Tope de la compilación; por defecto y como máximo ${limites.compilarSeg}`, { minimum: 10, maximum: limites.compilarSeg }),
      },
      required: ["sources"],
    },
    replay: "never",
    execute: async (params, signal): Promise<ToolResult> => {
      const result = await compilarHarness(entorno, params as PedidoCompilacion, signal);
      return {
        text: textoCompilacion(entorno, result),
        isError: !result.ok,
        // La línea de la acción en la TUI («k v · k v») entra en 80 columnas.
        details: result.ok ? { harness: result.nombre, artefacto: result.artefacto } : { errores: result.errores.length + result.indefinidos.length, artefacto: result.artefacto },
      };
    },
  };
  const fuzz: Tool = {
    name: "fuzz_run",
    label: t("Correr fuzzer", "Run fuzzer"),
    description:
      "Corre un fuzzer de libFuzzer compilado con harness_build (o un PoC sobre las entradas de un corpus) con tiempo, memoria y procesos acotados y sin red; cancelable. " +
      "Junta los crashes, los reproduce uno por uno, minimiza los nuevos (-minimize_crash) y los deduplica por pila contra todo lo visto para ese harness. Devuelve cada uno clasificado (heap-buffer-overflow, use-after-free, double-free, SEGV, overflow de enteros de UBSan, leak, timeout, oom) con su impacto probable, y lo deja en harness/out/<nombre>/crashes/<firma>/ y como artefacto (input, reporte simbolizado y comando para reproducir). " +
      "binary sirve para un ELF del proyecto compilado con sanitizers (el CLI del objetivo armado con ASan).",
    parameters: {
      type: "object",
      properties: {
        harness: s("Nombre del harness (el name de harness_build)"),
        binary: s("O la ruta de un binario del proyecto compilado con sanitizers"),
        seconds: n(`Duración total; por defecto ${limites.fuzzSeg}, máximo ${limites.fuzzSegMax}`, { minimum: 5, maximum: limites.fuzzSegMax }),
        memory_mb: n(`Tope de memoria; por defecto ${limites.memoriaMb}, máximo ${limites.memoriaMbMax}`, { minimum: 128, maximum: limites.memoriaMbMax }),
        timeout_sec: n(`Tope por entrada (pasarlo es un timeout); por defecto ${limites.entradaSeg}`, { minimum: 1, maximum: limites.entradaSegMax }),
        workers: n(`Procesos en paralelo (con más de uno sigue después de cada crash); por defecto ${limites.procesos}, máximo ${limites.procesosMax}`, { minimum: 1, maximum: limites.procesosMax }),
        corpus: ss("Carpetas o archivos de semillas dentro del proyecto (los tests del objetivo son buenas semillas)"),
        dict: s("Diccionario de libFuzzer dentro del proyecto (tokens del formato)"),
        max_len: n("Largo máximo de cada entrada generada", { minimum: 1 }),
        minimize: b("Minimizar los crashes nuevos; por defecto sí"),
        leaks: b("Detectar leaks; por defecto sí"),
        args: ss("Sólo PoCs: argumentos; «@@» es el archivo de entrada (por defecto, sólo él)"),
        stdin: b("Sólo PoCs: la entrada por stdin en vez de como archivo"),
      },
      required: [],
    },
    replay: "never",
    execute: async (params, signal): Promise<ToolResult> => {
      const result = await correrFuzzer(entorno, params as PedidoFuzz, signal);
      const nuevos = result.crashes.filter((item) => item.nuevo).length;
      return {
        text: textoCorrida(result),
        isError: result.fin === "arranque",
        details: { crashes: result.crashes.length, ...(result.crashes.length ? { nuevos } : {}), artefacto: result.artefacto },
      };
    },
  };
  const poc: Tool = {
    name: "poc_run",
    // Corta a propósito: la línea de la acción lleva reproduce, corridas, exitCode y el artefacto en 80 columnas.
    label: "PoC",
    description:
      "Corre un PoC o harness ya compilado (harness_build, o un binario del proyecto con sanitizers) sobre un input concreto N veces, sin red y con topes, y dice si reproduce de forma determinista, con qué firma y qué reporte del sanitizer. " +
      "input es un archivo del proyecto; crash, la firma de un crash de fuzz_run (usa su input minimizado); o command, la línea «command» que devuelven fuzz_run y poc_run (sin shell: el binario instrumentado, sus argumentos y a lo sumo «< archivo»), con cwd. firma compara contra un crash esperado. Es la prueba de ejecución de una hipótesis.",
    parameters: {
      type: "object",
      properties: {
        harness: s("Nombre del harness (el name de harness_build)"),
        binary: s("O la ruta de un binario del proyecto compilado con sanitizers"),
        input: s("Archivo de entrada dentro del proyecto"),
        crash: s("O la firma (o un prefijo de 6+) de un crash de fuzz_run"),
        runs: n(`Veces; por defecto ${limites.pocVeces}, máximo ${limites.pocVecesMax}`, { minimum: 1, maximum: limites.pocVecesMax }),
        timeout_sec: n("Tope por corrida", { minimum: 1, maximum: limites.entradaSegMax }),
        memory_mb: n(`Tope de memoria; por defecto ${limites.memoriaMb}`, { minimum: 128, maximum: limites.memoriaMbMax }),
        leaks: b("Detectar leaks; por defecto sí"),
        args: ss("Sólo PoCs: argumentos; «@@» es el archivo de entrada (por defecto, sólo él)"),
        stdin: b("Sólo PoCs: la entrada por stdin"),
        firma: s("Firma esperada (6 a 12 hex): dice si reproduce ese mismo crash"),
        command: s("O la línea de comando entera (la de «command» de fuzz_run o poc_run); va sola"),
        cwd: s("Carpeta del proyecto desde donde se lee command; por defecto la raíz"),
      },
      required: [],
    },
    replay: "never",
    execute: async (params, signal): Promise<ToolResult> => {
      const result = await reproducirPoc(entorno, params as PedidoPoc, signal);
      return {
        text: textoReproduccion(result),
        // La verificación por ejecución lee reproduce, corridas y exitCode de acá; la TUI los muestra en ese orden.
        details: { reproduce: result.reproduce, corridas: result.corridas, exitCode: result.exitCode, artefacto: result.artefacto },
      };
    },
  };
  return [build, fuzz, poc];
}
