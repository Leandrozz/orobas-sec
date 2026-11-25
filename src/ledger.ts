// Contabilidad de API: una fila por solicitud única (proveedor + cuenta + ID), con el uso
// reportado y la tarifa aplicada en ese momento. Todos los workers comparten esta instancia.
import type { DatabaseSync } from "node:sqlite";
import type { AssistantMessage, Model, Rates } from "./llm.ts";
import { ratePico, usd } from "./money.ts";
import { logEvent } from "./store.ts";

export const BUCKETS = ["input", "cacheRead", "cacheWrite", "output"] as const;
export type Bucket = (typeof BUCKETS)[number];

export interface Totals {
  requests: number;
  /** Solicitudes cuyo uso o precio no se conoce. Nunca cuentan como cero. */
  unknownRequests: number;
  tokens: Record<Bucket, number>;
  costs: Record<Bucket, bigint>;
  knownPico: bigint;
}

export interface RecordContext {
  sessionId: string;
  account: string;
  worker: string;
  model: Model;
}

/**
 * Tope de sesión guardado (evento «ajuste.presupuesto»): picoUSD, «sin» si se quitó, o undefined si la
 * sesión nunca guardó uno. Con esto el daemon reabre una sesión (reanudación automática incluida) con el
 * tope que tenía y no con el de fábrica.
 */
export function storedBudget(db: DatabaseSync, sessionId: string): bigint | "sin" | undefined {
  const row = db.prepare("select payload from events where session_id=? and type='ajuste.presupuesto' order by seq desc limit 1").get(sessionId) as { payload: string } | undefined;
  if (!row) return undefined;
  try {
    const { pico } = JSON.parse(row.payload) as { pico?: unknown };
    if (pico === "sin") return "sin";
    if (typeof pico === "string" && /^\d+$/.test(pico)) return BigInt(pico);
  } catch { /* ilegible: como si no hubiera */ }
  return undefined;
}

export class Ledger {
  readonly db: DatabaseSync;
  /** Reservas vivas por intención de solicitud (todos los workers del proceso). */
  private reservations = new Map<string, { sessionId: string; pico: bigint }>();
  private budget: bigint | undefined;
  /** Se llama cada vez que cambia el tope de la sesión (comando, ajuste del agente): el motor lo guarda. */
  onBudget?: (pico: bigint | undefined) => void;

  constructor(db: DatabaseSync, budgetPico?: bigint) {
    this.db = db;
    this.budget = budgetPico;
  }

  /** Tope por sesión en picoUSD; undefined = sin tope. */
  get budgetPico(): bigint | undefined {
    return this.budget;
  }

  set budgetPico(value: bigint | undefined) {
    this.budget = value;
    this.onBudget?.(value);
  }

  /**
   * Deja constancia de una solicitud que está por salir. Si el proceso muere antes de la
   * respuesta, la fila queda como gasto desconocido en vez de desaparecer.
   */
  begin(intent: string, ctx: RecordContext): void {
    this.db
      .prepare("insert or ignore into requests(provider,account,request_id,session_id,worker,model,at,stop_reason) values(?,?,?,?,?,?,?,'pendiente')")
      .run(ctx.model.provider, ctx.account, intent, ctx.sessionId, ctx.worker, ctx.model.id, new Date().toISOString());
  }

  /** Cierra una intención: la reemplaza el recibo real y libera su reserva. */
  settle(intent: string): void {
    this.db.prepare("delete from requests where request_id=? and stop_reason='pendiente'").run(intent);
    this.reservations.delete(intent);
  }

  /** Aparta el costo máximo estimado de una solicitud hasta que llegue su recibo. */
  reserve(intent: string, sessionId: string, pico: bigint): void {
    this.reservations.set(intent, { sessionId, pico });
  }

  reservedPico(sessionId: string): bigint {
    let sum = 0n;
    for (const reservation of this.reservations.values()) if (reservation.sessionId === sessionId) sum += reservation.pico;
    return sum;
  }

  /** Costo máximo estimado de una solicitud: entrada aproximada por tamaño + salida máxima del modelo. */
  static estimate(model: Model, inputChars: number): bigint {
    if (!model.cost) return 0n;
    const inputTokens = BigInt(Math.ceil(inputChars / 4));
    const outputTokens = BigInt(model.maxTokens ?? 4096);
    return inputTokens * ratePico(model.cost.input) + outputTokens * ratePico(model.cost.output);
  }

  /** Registra la respuesta final de una solicitud. Devuelve false si ya estaba registrada. */
  record(message: AssistantMessage, ctx: RecordContext): boolean {
    // Uso ausente = desconocido (p. ej. un turno cortado). Un rechazo previo al
    // procesamiento no consumió tokens y se registra con uso cero conocido.
    const u = message.usage ?? (message.rejected ? { input: 0, cacheRead: 0, cacheWrite: 0, output: 0 } : undefined);
    // El costo del plan es cero aunque el stream se corte antes de informar tokens.
    const plan = ctx.model.costSource === "plan de ChatGPT";
    const rates: Rates | undefined = (u || plan) ? ctx.model.cost : undefined;
    const cost = (tokens: number, rate: number) => String(BigInt(tokens) * ratePico(rate));
    const bucketCost = (tokens: number | undefined, rate: number) => tokens === undefined ? (plan ? "0" : null) : cost(tokens, rate);
    const result = this.db
      .prepare(
        `insert or ignore into requests(provider,account,request_id,session_id,worker,model,at,stop_reason,
           input,cache_read,cache_write,output,reasoning,price_json,
           cost_input,cost_cache_read,cost_cache_write,cost_output,provider_cost)
         values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,null)`,
      )
      .run(
        message.provider,
        ctx.account,
        message.requestId,
        ctx.sessionId,
        ctx.worker,
        message.model,
        new Date(message.at).toISOString(),
        message.stopReason,
        u?.input ?? null,
        u?.cacheRead ?? null,
        u?.cacheWrite ?? null,
        u?.output ?? null,
        u?.reasoning ?? null,
        rates ? JSON.stringify({ source: ctx.model.costSource ?? "configuración", model: ctx.model.id, usdPerMillion: rates }) : null,
        rates ? bucketCost(u?.input, rates.input) : null,
        rates ? bucketCost(u?.cacheRead, rates.cacheRead) : null,
        rates ? bucketCost(u?.cacheWrite, rates.cacheWrite) : null,
        rates ? bucketCost(u?.output, rates.output) : null,
      );
    const requestId = message.requestId;
    if (result.changes === 0) {
      logEvent(this.db, ctx.sessionId, "ledger.duplicate", { provider: message.provider, requestId });
      return false;
    }
    return true;
  }

  /** Totales de una sesión, o de todo el proyecto si no se indica sesión. */
  totals(sessionId?: string): Totals {
    const rows = this.db
      .prepare(`select * from requests ${sessionId ? "where session_id=?" : ""}`)
      .all(...(sessionId ? [sessionId] : [])) as Array<Record<string, any>>;
    const totals: Totals = {
      requests: rows.length,
      unknownRequests: 0,
      tokens: { input: 0, cacheRead: 0, cacheWrite: 0, output: 0 },
      costs: { input: 0n, cacheRead: 0n, cacheWrite: 0n, output: 0n },
      knownPico: 0n,
    };
    for (const row of rows) {
      if (row.input == null) {
        totals.unknownRequests++;
        continue;
      }
      totals.tokens.input += row.input;
      totals.tokens.cacheRead += row.cache_read;
      totals.tokens.cacheWrite += row.cache_write;
      totals.tokens.output += row.output;
      if (row.cost_input == null) {
        totals.unknownRequests++;
        continue;
      }
      totals.costs.input += BigInt(row.cost_input);
      totals.costs.cacheRead += BigInt(row.cost_cache_read);
      totals.costs.cacheWrite += BigInt(row.cost_cache_write);
      totals.costs.output += BigInt(row.cost_output);
    }
    totals.knownPico = BUCKETS.reduce((sum, bucket) => sum + totals.costs[bucket], 0n);
    return totals;
  }

  /** Tamaño del contexto según el uso reportado por la última respuesta del agente principal. */
  contextTokens(sessionId: string): number {
    const row = this.db
      .prepare("select input+cache_read+cache_write+output n from requests where session_id=? and worker='principal' and input is not null and stop_reason not in ('error','aborted') order by rowid desc limit 1")
      .get(sessionId) as { n: number } | undefined;
    return row?.n ?? 0;
  }

  /**
   * Corte efectivo, antes de enviar: lo gastado más lo reservado por solicitudes en vuelo más
   * la estimación de ésta no puede superar el tope. Devuelve el motivo si no entra.
   */
  overBudget(sessionId: string, estimatePico = 0n): string | undefined {
    if (this.budgetPico !== undefined) {
      const known = this.totals(sessionId).knownPico;
      const reserved = this.reservedPico(sessionId);
      if (known + reserved + estimatePico >= this.budgetPico) {
        const parts = [`gastado USD ${usd(known)}`, reserved ? `en vuelo USD ${usd(reserved)}` : "", estimatePico ? `estimado de esta solicitud USD ${usd(estimatePico)}` : ""].filter(Boolean);
        return `Presupuesto de sesión (USD ${usd(this.budgetPico, 2)}) no alcanza: ${parts.join(" + ")}. Ampliarlo con /presupuesto <USD>.`;
      }
    }
    return this.overProjectBudget(estimatePico);
  }

  /**
   * Sólo el tope del proyecto. El tope del proyecto suma todas las sesiones de la carpeta: sirve para
   * repartir un presupuesto por persona sin que abrir otra sesión lo esquive. Lo usa también el
   * verificador, que tiene su propio tope por candidato y no depende del de la sesión.
   */
  overProjectBudget(estimatePico = 0n): string | undefined {
    const cap = this.projectBudget();
    if (cap !== undefined) {
      const spent = this.knownPicoAll();
      if (spent + estimatePico >= cap) return `Tope del proyecto (USD ${usd(cap, 2)}) alcanzado: gastado USD ${usd(spent)} entre todas las sesiones de esta carpeta. Lo cambia el operador con «cyber tope <USD>» o lo quita con «cyber tope sin».`;
    }
    return undefined;
  }

  /**
   * Fracción del presupuesto que queda (0 a 1): del tope de la sesión si lo hay, si no del tope del
   * proyecto; undefined cuando nada acota el gasto.
   */
  budgetLeft(sessionId: string): number | undefined {
    if (this.budgetPico !== undefined && this.budgetPico > 0n) return Math.max(0, Number(this.budgetPico - this.totals(sessionId).knownPico) / Number(this.budgetPico));
    const cap = this.projectBudget();
    if (cap !== undefined && cap > 0n) return Math.max(0, Number(cap - this.knownPicoAll()) / Number(cap));
    return undefined;
  }

  /** Tope de gasto del proyecto, sumando todas sus sesiones. Lo fija el operador y queda en la base. */
  projectBudget(): bigint | undefined {
    const row = this.db.prepare("select value from meta where key='tope_proyecto'").get() as { value: string } | undefined;
    return row ? BigInt(row.value) : undefined;
  }

  setProjectBudget(pico: bigint | undefined): void {
    if (pico === undefined) this.db.prepare("delete from meta where key='tope_proyecto'").run();
    else this.db.prepare("insert or replace into meta(key,value) values('tope_proyecto',?)").run(String(pico));
  }

  /** Gasto conocido de todas las sesiones del proyecto. */
  knownPicoAll(): bigint {
    const row = this.db
      .prepare("select coalesce(sum(cast(cost_input as integer)+cast(cost_cache_read as integer)+cast(cost_cache_write as integer)+cast(cost_output as integer)),0) n from requests where cost_input is not null")
      .get() as { n: number | bigint };
    return BigInt(row.n);
  }
}
