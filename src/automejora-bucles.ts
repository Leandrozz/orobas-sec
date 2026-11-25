// Señales deterministas por sesión. No cambia prompts ni bloquea herramientas.
import { createHash } from "node:crypto";

export const UMBRALES_BUCLE = {
  lecturas: 3, // cuarta lectura del mismo archivo o ventana
  llamadas: 2, // tercera llamada idéntica
  sinAvance: 8, // ocho herramientas seguidas sin hallazgo, cobertura ni nodo nuevo
} as const;

export interface SenalBucle { tipo: "archivo" | "rango" | "llamada" | "sin-avance"; detalle: string; paso: number; desde: number; veces: number }
export interface ProgresoBucle { hallazgos: number; cobertura: number; nodos: number }
/** resultado: el texto que devolvió la herramienta; pura: mismos argumentos, mismo resultado (Tool.pure). */
export interface ObservacionBucle { resultado?: string; pura?: boolean }

/** Esperas y sondeos: repetirlos con los mismos argumentos es su uso normal, no un bucle. */
const SONDEO = /^canary_list$|_(?:wait|status|poll)$/;
const NOTA = "\n[sistema][automejora]";
const huella = (texto: string) => createHash("sha256").update(texto).digest("base64url").slice(0, 22);

const objeto = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const numero = (value: unknown, fallback: number): number => typeof value === "number" && Number.isFinite(value) ? value : fallback;
const canon = (value: unknown): string => JSON.stringify(value && typeof value === "object" && !Array.isArray(value)
  ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, item && typeof item === "object" ? JSON.parse(canon(item)) : item]))
  : value);

/** Extrae sólo lecturas de una orden simple; no interpreta tuberías, variables ni sustituciones. */
export function lecturaShell(command: string): { archivo: string; rango: string } | undefined {
  const line = command.trim();
  const sed = /^sed\s+-n\s+['"]?(\d+),(\d+)p['"]?\s+([^\s;&|$`]+)$/.exec(line);
  if (sed) return { archivo: sed[3]!, rango: `${sed[1]}-${sed[2]}` };
  const awk = /^awk\s+['"]([^'"]+)['"]\s+([^\s;&|$`]+)$/.exec(line);
  if (awk) {
    const from = /\bNR\s*>=\s*(\d+)/.exec(awk[1]!)?.[1];
    const to = /\bNR\s*<=\s*(\d+)/.exec(awk[1]!)?.[1];
    if (from) return { archivo: awk[2]!, rango: `${from}-${to ?? "fin"}` };
  }
  const cat = /^cat\s+(?:--\s+)?([^\s;&|$`]+)$/.exec(line);
  return cat ? { archivo: cat[1]!, rango: "todo" } : undefined;
}

export function lectura(nombre: string, input: unknown): { archivo: string; rango: string } | undefined {
  const args = objeto(input);
  if (nombre === "code_read" && typeof args.path === "string") {
    const from = numero(args.desde, 1), lines = numero(args.lineas, 200);
    return { archivo: args.path, rango: `${from}-${from + lines - 1}` };
  }
  if (nombre === "artifact_read" && typeof args.hash === "string") {
    const range = args.at !== undefined ? `${numero(args.at, 0)}+${numero(args.chars, 2000)}` : args.offset !== undefined ? `líneas ${numero(args.offset, 0)}+${numero(args.limit, 200)}` : args.filter || args.filters || args.search ? canon({ filter: args.filter, filters: args.filters, search: args.search }) : "todo";
    return { archivo: `artefacto ${args.hash}`, rango: range };
  }
  if (nombre === "shell" && typeof args.command === "string") {
    const read = lecturaShell(args.command);
    return read && typeof args.cwd === "string" ? { ...read, archivo: `${args.cwd.replace(/\/$/, "")}/${read.archivo}` } : read;
  }
  return undefined;
}

/** Tramo leído: líneas, caracteres, un filtro (sólo solapa consigo) o el archivo entero (solapa con todo). */
interface Tramo { unidad: string; desde: number; hasta: number }
const TRAMOS_POR_ARCHIVO = 32;

function tramoDe(rango: string): Tramo {
  if (rango === "todo") return { unidad: "todo", desde: 0, hasta: Infinity };
  const lines = /^(?:líneas )?(\d+)(?:-(\d+|fin)|\+(\d+))$/.exec(rango);
  if (lines) {
    const desde = Number(lines[1]);
    const hasta = lines[2] === "fin" ? Infinity : lines[2] !== undefined ? Number(lines[2]) : desde + Number(lines[3]) - 1;
    return { unidad: rango.startsWith("líneas ") || lines[2] !== undefined ? "lineas" : "chars", desde, hasta };
  }
  return { unidad: `filtro ${rango}`, desde: 0, hasta: Infinity };
}

const solapan = (a: Tramo, b: Tramo) => a.unidad === "todo" || b.unidad === "todo" || (a.unidad === b.unidad && a.desde <= b.hasta && b.desde <= a.hasta);

/** Suma el tramo a los ya leídos, fundiendo los que se tocan, con un tope por archivo. */
function sumarTramo(tramos: Tramo[], nuevo: Tramo): Tramo[] {
  if (nuevo.unidad === "todo") return [nuevo];
  let merged = { ...nuevo };
  const rest = tramos.filter((tramo) => {
    if (tramo.unidad !== merged.unidad || tramo.desde > merged.hasta + 1 || merged.desde > tramo.hasta + 1) return true;
    merged = { unidad: merged.unidad, desde: Math.min(merged.desde, tramo.desde), hasta: Math.max(merged.hasta, tramo.hasta) };
    return false;
  });
  return [...rest, merged].slice(-TRAMOS_POR_ARCHIVO);
}

/** Tope de claves por mapa del detector: al pasarlo se olvida la usada hace más tiempo. */
export const TOPE_CLAVES_BUCLE = 512;

/** Mapa LRU simple: las claves son huellas cortas, nunca los argumentos ni las rutas. */
class Recientes<V> {
  private readonly mapa = new Map<string, V>();
  get size(): number { return this.mapa.size; }
  keys(): Iterable<string> { return this.mapa.keys(); }
  get(clave: string): V | undefined {
    const valor = this.mapa.get(clave);
    if (valor !== undefined) { this.mapa.delete(clave); this.mapa.set(clave, valor); }
    return valor;
  }
  set(clave: string, valor: V): void {
    this.mapa.delete(clave);
    this.mapa.set(clave, valor);
    if (this.mapa.size > TOPE_CLAVES_BUCLE) this.mapa.delete(this.mapa.keys().next().value!);
  }
}

export class DetectorBucles {
  private paso = 0;
  /** veces: la primera lectura más las que vuelven sobre líneas ya leídas; paginar no suma. */
  private readonly archivos = new Recientes<{ veces: number; desde: number; tramos: Tramo[] }>();
  private readonly rangos = new Recientes<{ veces: number; desde: number }>();
  private readonly llamadas = new Recientes<{ veces: number; desde: number }>();
  private readonly avisadas = new Recientes<true>();
  private anterior: ProgresoBucle = { hallazgos: 0, cobertura: 0, nodos: 0 };
  private quietos = 0;
  private desdeQuietos = 1;

  /** Tras reconstruir una sesión, conserva patrones y borra la racha cuyo progreso histórico no conocemos. */
  reiniciarRacha(progreso: ProgresoBucle): void {
    this.anterior = progreso;
    this.quietos = 0;
  }

  observar(nombre: string, args: unknown, progreso: ProgresoBucle, isError = false, extra: ObservacionBucle = {}): SenalBucle[] {
    const paso = ++this.paso;
    const signals: SenalBucle[] = [];
    const add = (key: string, tipo: SenalBucle["tipo"], detalle: string, desde: number, veces: number) => {
      if (this.avisadas.get(key)) return;
      this.avisadas.set(key, true);
      signals.push({ tipo, detalle, paso, desde, veces });
    };
    const seen = (map: Recientes<{ veces: number; desde: number }>, key: string) => {
      const previous = map.get(key) ?? { veces: 0, desde: paso };
      const current = { veces: previous.veces + 1, desde: previous.desde };
      map.set(key, current);
      return current;
    };
    if (!isError) {
      const read = lectura(nombre, args);
      if (read) {
        const tramo = tramoDe(read.rango);
        const fileKey = huella(read.archivo);
        const previous = this.archivos.get(fileKey);
        const file = previous
          ? { veces: previous.veces + (previous.tramos.some((item) => solapan(item, tramo)) ? 1 : 0), desde: previous.desde, tramos: sumarTramo(previous.tramos, tramo) }
          : { veces: 1, desde: paso, tramos: [tramo] };
        this.archivos.set(fileKey, file);
        if (file.veces > UMBRALES_BUCLE.lecturas) add(`archivo:${fileKey}`, "archivo", read.archivo, file.desde, file.veces);
        const rangeKey = huella(`${read.archivo}\n${read.rango}`);
        const range = seen(this.rangos, rangeKey);
        if (range.veces > UMBRALES_BUCLE.lecturas) add(`rango:${rangeKey}`, "rango", `${read.archivo} (${read.rango})`, range.desde, range.veces);
      }
    }
    if (!SONDEO.test(nombre)) {
      // Una orden no pura (shell, una petición) puede repetirse con razón: cuenta sólo si también repite el resultado.
      const salida = extra.pura ? "" : huella((extra.resultado ?? "").split(NOTA)[0]!);
      const key = huella(`${nombre}\n${canon(args)}\n${salida}`);
      const call = seen(this.llamadas, key);
      if (call.veces > UMBRALES_BUCLE.llamadas) add(`llamada:${key}`, "llamada", nombre, call.desde, call.veces);
    }
    const advanced = progreso.hallazgos > this.anterior.hallazgos || progreso.cobertura > this.anterior.cobertura || progreso.nodos > this.anterior.nodos;
    this.anterior = progreso;
    if (advanced) this.quietos = 0;
    else {
      if (!this.quietos) this.desdeQuietos = paso;
      this.quietos++;
      if (this.quietos >= UMBRALES_BUCLE.sinAvance) add(`sin-avance:${this.desdeQuietos}`, "sin-avance", "sin hallazgo, cobertura ni nodo nuevo", this.desdeQuietos, this.quietos);
    }
    return signals;
  }
}

export const notaBucle = (signal: SenalBucle): string => `[sistema][automejora] ${signal.tipo === "sin-avance" ? `${signal.veces} pasos sin progreso` : signal.tipo === "llamada" ? `${signal.detalle} con los mismos argumentos ${signal.veces} veces` : `${signal.detalle} leído ${signal.veces} veces`}. Cerrá la hipótesis con una prueba que muestre o refute el efecto, o descartala en la memoria con el motivo. Si estás siguiendo una grieta concreta, no la abandones: buscá el efecto con una prueba distinta en vez de repetir lo mismo.`;
