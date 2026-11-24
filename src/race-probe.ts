// El control secuencial separa la repetición normal de los efectos de concurrencia.
import { isDeepStrictEqual } from "node:util";
import { sleep, type Tool } from "./agent.ts";
import type { HttpExchange, HttpRequestSpec } from "./http.ts";
import type { ProbeContext } from "./probes.ts";
import { diffResponses } from "./webtools.ts";

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const obj = (properties: Record<string, object>, required: string[] = []) => ({ type: "object", properties, required });
const headersSchema = { type: "object", additionalProperties: { type: "string" } };
const bodySchema = { description: "Objeto JSON o cuerpo ya codificado como cadena" };
const methods = ["POST", "PUT", "PATCH"];

function bounded(value: unknown, fallback: number, low: number, high: number, name: string): number {
  const result = value ?? fallback;
  if (typeof result !== "number" || !Number.isInteger(result) || result < low || result > high) throw new Error(`${name}: usá un entero entre ${low} y ${high}`);
  return result;
}

function writeSpec(input: any, timeoutMs: number): HttpRequestSpec {
  const method = input.method ?? "POST";
  if (!methods.includes(method)) throw new Error("La escritura debe usar POST, PUT o PATCH");
  if (typeof input.url !== "string") throw new Error("Falta la URL de escritura");
  new URL(input.url);
  const isJson = input.body !== undefined && typeof input.body !== "string";
  if (isJson && (input.body === null || typeof input.body !== "object")) throw new Error("body debe ser un objeto JSON o una cadena");
  const body = isJson ? JSON.stringify(input.body) : input.body;
  if (body && body.length > 10000) throw new Error("body: máximo 10000 caracteres");
  return { url: input.url, method, body, headers: { ...(isJson ? { "content-type": "application/json" } : {}), ...input.headers }, timeoutMs, maxBodyBytes: 128 * 1024 };
}

type State = { exchange: HttpExchange; available: boolean; value?: unknown };
type Phase = { name: string; writes: HttpExchange[]; reset?: HttpExchange; before?: State; after?: State };
const accepted = (exchange: HttpExchange) => !!exchange.response && exchange.response.status >= 200 && exchange.response.status < 300;
const preview = (value: unknown) => (JSON.stringify(value) ?? "sin dato").slice(0, 160);

function readState(exchange: HttpExchange, path?: string): State {
  if (!accepted(exchange) || exchange.response!.truncated) return { exchange, available: false };
  try {
    let value: unknown = JSON.parse(exchange.response!.body);
    for (const key of path?.split(".") ?? []) {
      if (!value || typeof value !== "object" || !Object.hasOwn(value, key)) return { exchange, available: false };
      value = (value as Record<string, unknown>)[key];
    }
    return { exchange, available: true, value };
  } catch {
    return { exchange, available: false };
  }
}

export function createRaceProbe(context: ProbeContext): Tool {
  const { http } = context;
  return {
    name: "race_probe",
    label: "Sonda de concurrencia",
    description:
      "Repite una escritura N veces en secuencia y luego N en paralelo (N=10, máximo 20). Compara aceptaciones HTTP, respuestas y estado final si pasás stateUrl, stateField y expected. " +
      "Si pasás reset, lo ejecuta antes de cada fase para partir del mismo estado; sin reset avisa que las fases acumulan efectos. Máximo 46 peticiones contando controles, lecturas y resets. " +
      "Confirmá las diferencias con una petición propia y registrá candidato con evidencia sólo si hay un efecto indebido.",
    parameters: obj({
      url: str(), method: str({ enum: methods }), body: bodySchema, headers: headersSchema, identity: str(),
      n: int({ minimum: 2, maximum: 20, default: 10 }),
      maxRequests: int({ minimum: 4, maximum: 46, default: 46, description: "Tope total, incluidos reset y lecturas de estado" }),
      delayMs: int({ minimum: 0, maximum: 1000, default: 100, description: "Pausa entre escrituras secuenciales y antes de la ráfaga paralela" }),
      timeoutMs: int({ minimum: 100, maximum: 10000, default: 5000 }),
      stateUrl: str({ description: "GET que permite observar el efecto antes y después de cada fase" }),
      stateField: str({ maxLength: 200, description: "Campo JSON con puntos; sin campo compara el JSON completo" }),
      expected: { description: "Valor final esperado de stateField (o del JSON completo) tras cada fase" },
      reset: obj({ url: str(), method: str({ enum: methods }), body: bodySchema, headers: headersSchema }, ["url"]),
    }, ["url"]),
    replay: "never",
    execute: async (params, signal) => {
      const n = bounded(params.n, 10, 2, 20, "n");
      const maxRequests = bounded(params.maxRequests, 46, 4, 46, "maxRequests");
      const delayMs = bounded(params.delayMs, 100, 0, 1000, "delayMs");
      const timeoutMs = bounded(params.timeoutMs, 5000, 100, 10000, "timeoutMs");
      const write = writeSpec(params, timeoutMs);
      const reset = params.reset ? writeSpec(params.reset, timeoutMs) : undefined;
      if ((params.stateField !== undefined || Object.hasOwn(params, "expected")) && !params.stateUrl) throw new Error("stateField y expected necesitan stateUrl");
      if (params.stateField !== undefined && (typeof params.stateField !== "string" || !params.stateField.length || params.stateField.length > 200)) throw new Error("stateField: pasá una ruta JSON de hasta 200 caracteres");
      if (params.stateUrl) new URL(params.stateUrl);
      const required = 2 * n + (reset ? 2 : 0) + (params.stateUrl ? 4 : 0);
      if (required > maxRequests) throw new Error(`La comparación necesita ${required} peticiones y maxRequests=${maxRequests}; bajá n o aumentá el tope hasta 46`);
      const startCount = http.count;
      const rows: string[] = [];
      const sequential: Phase = { name: "secuencial", writes: [] };
      const parallel: Phase = { name: "paralelo", writes: [] };
      const hasExpected = Object.hasOwn(params, "expected");
      let attempted = 0;
      const send = async (spec: HttpRequestSpec): Promise<HttpExchange | undefined> => {
        if (signal.aborted || attempted >= maxRequests || http.remaining() === 0) return undefined;
        attempted++;
        return http.send(spec, params.identity);
      };
      const state = async (): Promise<State | undefined> => {
        if (!params.stateUrl) return undefined;
        const exchange = await send({ url: params.stateUrl, headers: params.headers, timeoutMs, maxBodyBytes: 128 * 1024 });
        return exchange ? readState(exchange, params.stateField) : undefined;
      };
      const run = async (phase: Phase, concurrent: boolean): Promise<boolean> => {
        if (signal.aborted || http.remaining() === 0) return false;
        if (reset) {
          phase.reset = await send(reset);
          if (!phase.reset || !accepted(phase.reset)) {
            rows.push(`reset ${phase.name}: ${phase.reset?.id ?? "sin enviar"} ${phase.reset?.response?.status ?? phase.reset?.error ?? "cancelado o sin presupuesto"}; se detuvo la comparación.`);
            return false;
          }
        }
        phase.before = await state();
        if (concurrent) {
          await sleep(delayMs, signal);
          // Se reserva una cantidad local antes de lanzar la ráfaga para no exceder el saldo conocido.
          const count = Math.min(n, maxRequests - attempted, http.remaining() ?? n);
          const exchanges = await Promise.all(Array.from({ length: count }, () => send(write)));
          phase.writes.push(...exchanges.filter((exchange): exchange is HttpExchange => !!exchange));
        } else {
          for (let i = 0; i < n; i++) {
            if (i) await sleep(delayMs, signal);
            const exchange = await send(write);
            if (!exchange) break;
            phase.writes.push(exchange);
          }
        }
        phase.after = await state();
        return phase.writes.length === n;
      };
      if ((http.remaining() ?? required) < required) {
        rows.push(`La comparación necesita ${required} peticiones; quedan ${http.remaining()}. No se envió ninguna.`);
      } else if (await run(sequential, false)) {
        await run(parallel, true);
      }
      rows.push("fase        id     HTTP  bytes  ms    diferencia contra control secuencial");
      for (const phase of [sequential, parallel]) {
        for (const [index, exchange] of phase.writes.entries()) {
          const base = sequential.writes[phase === parallel ? index : 0];
          rows.push(`${phase.name.padEnd(11)} ${exchange.id.padEnd(6)} ${String(exchange.response?.status ?? "ERR").padEnd(5)} ${String(exchange.response?.bodyBytes ?? 0).padEnd(6)} ${String(exchange.durationMs).padEnd(5)} ${base ? `${base.id}: ${diffResponses(base, exchange)}` : exchange.error ?? "sin control"}`);
        }
        rows.push(`${phase.name}: ${phase.writes.filter(accepted).length}/${phase.writes.length} aceptadas HTTP (2xx).`);
        if (phase.reset && accepted(phase.reset)) rows.push(`reset ${phase.name}: ${phase.reset.id} HTTP ${phase.reset.response!.status}`);
        for (const [label, snapshot] of [["inicial", phase.before], ["final", phase.after]] as const) {
          if (snapshot) rows.push(`estado ${phase.name} ${label}: ${snapshot.exchange.id} ${snapshot.available ? preview(snapshot.value) : "no observable (respuesta sin JSON utilizable, incompleta o rechazada)"}`);
        }
        if (phase.after?.available && hasExpected) rows.push(`esperado ${phase.name}: ${preview(params.expected)} · ${isDeepStrictEqual(phase.after.value, params.expected) ? "coincide" : "NO coincide"}`);
      }
      const initialEqual = !!sequential.before?.available && !!parallel.before?.available && isDeepStrictEqual(sequential.before.value, parallel.before.value);
      const comparable = !!reset && !!sequential.reset && !!parallel.reset && accepted(sequential.reset) && accepted(parallel.reset) && initialEqual;
      if (!reset) rows.push("Sin reset: las fases acumulan efectos sobre el mismo recurso; no se aseguró la misma condición inicial.");
      else rows.push(comparable ? "Los resets respondieron 2xx y el estado inicial observado coincide en ambas fases." : "El reset no alcanza para asegurar equivalencia: el estado inicial no se pudo comparar o difiere.");
      if (sequential.writes.length !== n || parallel.writes.length !== n) rows.push("Comparación incompleta: cancelación, presupuesto insuficiente o reset rechazado.");
      if (!params.stateUrl) rows.push("Sin stateUrl: no se midió el efecto final. Un 2xx no demuestra que la operación se aplicó.");
      if (params.stateUrl && !hasExpected) rows.push("Sin expected: compará los estados observados con la regla de negocio.");
      rows.push("Confirmá cualquier diferencia con una petición propia; registrá candidato con evidencia si demuestra un efecto indebido.");
      rows.push(`peticiones HTTP: ${http.count} · esta llamada: ${http.count - startCount}/${maxRequests}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`);
      const summary = (phase: Phase) => ({ enviadas: phase.writes.length, aceptadas: phase.writes.filter(accepted).length, estadoInicial: phase.before?.available ? phase.before.value : undefined, estadoFinal: phase.after?.available ? phase.after.value : undefined, coincideEsperado: phase.after?.available && hasExpected ? isDeepStrictEqual(phase.after.value, params.expected) : undefined });
      return { text: rows.join("\n"), details: { secuencial: summary(sequential), paralelo: summary(parallel), comparables: comparable, peticiones: http.count - startCount } };
    },
  };
}
