// Cuentas en USD para decidir sobre el contexto, con las tarifas del modelo (src/tarifas.ts las trae del servicio).
//
// Dieta: resumir las salidas viejas ahorra, en cada paso que sigue, leerlas desde caché; pero cambia mensajes del
// medio, y todo lo que viene después del primero cambiado se cobra una vez como entrada nueva. Conviene cuando
//   costo de reescribir × margen < ahorro por paso × pasos restantes,
// con los pasos restantes estimados a la baja y nunca más allá de la próxima compactación (ahí lo viejo se va igual).
// Si la caché del proveedor ya está fría (pausa larga, herramientas recién cargadas, modelo sin uso reciente),
// reescribir no cuesta nada extra: es el momento de resumir.
//
// Los parámetros salen de las trazas (scripts/simular-fase3.py, docs/costos-contexto.md): la mediana de caracteres
// por token va de 2,4 a 3,6 según el modelo (antes se suponía 4); el p25 de los pasos que le quedan a una sesión
// que ya hizo k ≥ 5 está entre 45 y 84; con margen 2 y un mínimo de 4.000 tokens la dieta deja de dispararse por
// ahorros chicos que no pagaban la reescritura.
import type { DatabaseSync } from "node:sqlite";
import type { AssistantMessage, Rates } from "./llm.ts";

/** Caracteres por token para estimar: la mediana del corpus está entre 2,4 y 3,6. */
export const CHARS_POR_TOKEN = 3;
/** El ahorro esperado tiene que superar esto por el costo de reescribir. */
export const MARGEN = 2;
/** Por debajo de esto (tokens que se dejan de enviar por paso) no se resume. */
export const MIN_TOKENS = 4000;
/** Tope de pasos restantes que se suponen. */
export const PASOS_MAX = 40;
/** Crecimiento por paso supuesto cuando no hay historia (tokens). */
export const CRECIMIENTO_DEFECTO = 600;
/** Más que esto sin pedidos a un modelo y su caché se da por vencida. */
export const CACHE_TTL_MS = 300_000;

/** Mediana de lo que creció el contexto por paso en los últimos 8 (sólo subidas). */
export function crecimientoPorPaso(tamanos: number[]): number {
  const ultimos = tamanos.slice(-9);
  const subidas = ultimos.slice(1).map((valor, i) => valor - ultimos[i]!).filter((delta) => delta > 0).sort((a, b) => a - b);
  if (!subidas.length) return CRECIMIENTO_DEFECTO;
  const medio = Math.floor(subidas.length / 2);
  return subidas.length % 2 ? subidas[medio]! : (subidas[medio - 1]! + subidas[medio]!) / 2;
}

/** Pasos que quedan, a la baja: la mitad de los hechos entre 4 y 40, y no más que hasta la próxima compactación. */
export function pasosRestantes(hechos: number, crecimiento: number, contexto: number, compactarEn: number): number {
  let pasos = Math.min(PASOS_MAX, Math.max(4, Math.floor(hechos / 2)));
  if (crecimiento > 0) pasos = Math.min(pasos, Math.max(1, Math.floor((compactarEn - contexto) / crecimiento)));
  return pasos;
}

export interface DecisionDieta {
  conviene: boolean;
  /** USD por paso que se dejan de leer desde caché. */
  ahorroPaso: number;
  /** USD extra de mandar como entrada nueva lo que sigue al primer mensaje resumido. */
  reescribir: number;
  pasos: number;
  frio: boolean;
}

export function convieneDieta(opciones: {
  /** Caracteres que se dejan de enviar por paso. */
  ahorroChars: number;
  /** Caracteres que quedan después del primer mensaje resumido (ya con el resumen). */
  despuesChars: number;
  tarifas: Rates;
  /** Pedidos principales hechos en la sesión. */
  hechos: number;
  /** Tamaños de los pedidos principales anteriores (tokens), el último al final. */
  tamanos: number[];
  /** Contexto del último pedido (tokens). */
  contexto: number;
  compactarEn: number;
  frio: boolean;
}): DecisionDieta {
  const { ahorroChars, despuesChars, tarifas, hechos, tamanos, contexto, compactarEn, frio } = opciones;
  const ahorroTokens = ahorroChars / CHARS_POR_TOKEN;
  const ahorroPaso = (ahorroTokens * tarifas.cacheRead) / 1e6;
  const reescribir = frio ? 0 : (Math.max(0, despuesChars / CHARS_POR_TOKEN) * Math.max(0, tarifas.input - tarifas.cacheRead)) / 1e6;
  const pasos = pasosRestantes(hechos, crecimientoPorPaso(tamanos), contexto - ahorroTokens, compactarEn);
  const conviene = ahorroTokens >= MIN_TOKENS && reescribir * MARGEN < ahorroPaso * pasos;
  return { conviene, ahorroPaso, reescribir, pasos, frio };
}

/**
 * Lo que la regla necesita saber de los pedidos principales anteriores: cuántos, de qué tamaño, cuándo se usó cada
 * modelo y con qué herramientas salió el último (si cambiaron, el prefijo se rompe igual).
 */
export class HistoriaDePedidos {
  pasos = 0;
  tamanos: number[] = [];
  private porModelo = new Map<string, number>();
  private ultimo?: { at: number; herramientas: string };

  /** Al retomar: cantidad y tamaños de lo ya hecho (los tiempos no: la caché se da por desconocida, no por fría). */
  static desde(db: DatabaseSync, sessionId: string): HistoriaDePedidos {
    const historia = new HistoriaDePedidos();
    const filas = db
      .prepare("select input+cache_read+cache_write n from requests where session_id=? and worker='principal' and input is not null and stop_reason not in ('error','aborted') order by rowid")
      .all(sessionId) as Array<{ n: number }>;
    historia.pasos = filas.length;
    historia.tamanos = filas.slice(-9).map((fila) => Number(fila.n));
    return historia;
  }

  anotar(mensaje: AssistantMessage, herramientas: string, ahora = Date.now()): void {
    if (!mensaje.usage || mensaje.stopReason === "error" || mensaje.stopReason === "aborted") return;
    const { input, cacheRead, cacheWrite } = mensaje.usage;
    this.pasos++;
    this.tamanos = [...this.tamanos.slice(-8), input + cacheRead + cacheWrite];
    this.porModelo.set(`${mensaje.provider}/${mensaje.model}`, ahora);
    this.ultimo = { at: ahora, herramientas };
  }

  /** La caché del próximo pedido está fría de todos modos: otras herramientas, o el modelo sin uso reciente. */
  fria(modelo: string, herramientas: string, ahora = Date.now()): boolean {
    if (!this.ultimo) return false;
    if (herramientas !== this.ultimo.herramientas) return true;
    const visto = this.porModelo.get(modelo);
    return visto === undefined || ahora - visto > CACHE_TTL_MS;
  }
}

/** Caracteres del hash con los que cada intercambio queda nombrado en el checkpoint: «sha256:» y 12 hexadecimales. */
export const PREFIJO_HASH = 19;

/**
 * La tabla de intercambios HTTP que va al final de cada checkpoint (los últimos 80). En las trazas era el 74 % del
 * texto de un checkpoint, y el checkpoint se relee en cada paso hasta la próxima compactación. El hash va por su
 * prefijo de 12 hexadecimales, que artifact_read y la evidencia de los hallazgos ya aceptan (Artifacts.resolve):
 * cada línea pasa de ~140 a ~88 caracteres sin perder a qué artefacto apunta.
 */
export function lineasIntercambios(log: ReadonlyArray<{ id: string; method: string; url: string; status?: number; hash: string }>): string[] {
  return log.slice(-80).map((entry) => `${entry.id} ${entry.method} ${entry.url.slice(0, 100)} → ${entry.status ?? "error"} · ${entry.hash.slice(0, PREFIJO_HASH)}`);
}
