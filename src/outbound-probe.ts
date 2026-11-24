import { setTimeout as delay } from "node:timers/promises";
import type { Tool } from "./agent.ts";
import type { HttpExchange } from "./http.ts";
import { startProbeListener, type ProbeListener } from "./listener.ts";
import type { ProbeContext } from "./probes.ts";
import { decide } from "./scope.ts";
import { diffResponses } from "./webtools.ts";

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const bounded = (value: unknown, fallback: number, min: number, max: number, name: string) => {
  const result = value ?? fallback;
  if (typeof result !== "number" || !Number.isInteger(result) || result < min || result > max) throw new Error(`${name}: usá un entero entre ${min} y ${max}`);
  return result;
};

export function createOutboundProbe(context: ProbeContext): Tool {
  const { http, artifacts } = context;
  return {
    name: "outbound_probe",
    label: "Sonda de petición saliente",
    description: "Compara un parámetro URL con un control. Si el operador declaró un oyente local alcanzable, comprueba callbacks con un camino aleatorio y guarda evidencia. Sin canal sólo compara tiempos y errores de las URLs que pases, dentro del alcance. Máximo 6 peticiones al objetivo. Confirmá las señales con una petición propia y registrá candidato con evidencia.",
    parameters: {
      type: "object",
      properties: {
        url: str(), param: str(),
        baseline: str({ description: "URL de control dentro del alcance, o cadena vacía para no indicar destino" }),
        method: str({ enum: ["GET", "POST", "PUT", "PATCH"] }),
        where: str({ enum: ["query", "body"] }),
        body: { type: "object", description: "Cuerpo JSON base si where=body" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        identity: str(),
        urls: { type: "array", items: str(), maxItems: 5, description: "URLs alternativas dentro del alcance; sólo se usan sin oyente" },
        maxRequests: int({ minimum: 2, maximum: 6, default: 6 }),
        delayMs: int({ minimum: 0, maximum: 1000, default: 100 }),
        waitMs: int({ minimum: 0, maximum: 5000, default: 1000 }),
        timeoutMs: int({ minimum: 100, maximum: 10000, default: 5000 }),
      },
      required: ["url", "param", "baseline"],
    },
    execute: async (params, signal) => {
      const maxRequests = bounded(params.maxRequests, 6, 2, 6, "maxRequests");
      const delayMs = bounded(params.delayMs, 100, 0, 1000, "delayMs");
      const waitMs = bounded(params.waitMs, 1000, 0, 5000, "waitMs");
      const timeoutMs = bounded(params.timeoutMs, 5000, 100, 10000, "timeoutMs");
      const method = params.method ?? "GET";
      const where = params.where ?? (method === "GET" ? "query" : "body");
      if (!["GET", "POST", "PUT", "PATCH"].includes(method)) throw new Error("Método no admitido para outbound_probe");
      if (!["query", "body"].includes(where) || (where === "body" && method === "GET")) throw new Error("Para probar el cuerpo usá un método de escritura");
      if (typeof params.param !== "string" || !params.param) throw new Error("Pasá el nombre del parámetro URL");
      if (typeof params.baseline !== "string") throw new Error("Pasá baseline como URL o cadena vacía");
      const validateDestination = (value: string) => {
        if (!value) return;
        const parsed = new URL(value);
        if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error("Los destinos deben ser HTTP(S) sin credenciales");
        const decision = decide(http.scope(), value);
        if (!decision.allowed) throw new Error(`Destino saliente fuera del alcance: ${decision.reason}`);
      };
      validateDestination(params.baseline);
      if (!Array.isArray(params.urls ?? []) || (params.urls?.length ?? 0) > 5) throw new Error("Pasá hasta cinco URLs alternativas");
      const alternatives: string[] = context.listener ? [] : (params.urls ?? []);
      for (const value of alternatives) {
        if (typeof value !== "string" || !value) throw new Error("Cada URL alternativa debe ser una cadena no vacía");
        validateDestination(value);
      }
      const before = http.count;
      const rows: string[] = [];
      const exchanges: HttpExchange[] = [];
      let listener: ProbeListener | undefined;
      let visits = 0;
      const counter = () => `peticiones HTTP: ${http.count} · esta llamada: ${http.count - before}/${maxRequests}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`;
      try {
        if (!signal.aborted && context.listener) listener = await startProbeListener(context.listener, artifacts);
        const variants = (listener ? [listener.url] : alternatives).slice(0, maxRequests - 1);
        if (!listener) rows.push("Sin canal declarado: sólo tiempos y errores; esto no comprueba una visita del servidor.");
        if (!variants.length) rows.push("No hay variantes para comparar. Pasá urls o pedile al operador que declare un canal alcanzable.");
        else {
          const values = [params.baseline, ...variants];
          for (const [index, value] of values.entries()) {
            if (signal.aborted || http.remaining() === 0) break;
            if (index) await delay(delayMs, undefined, { signal }).catch(() => {});
            if (signal.aborted) break;
            const url = new URL(params.url);
            if (where === "query") url.searchParams.set(params.param, value);
            const exchange = await http.send({
              url: url.toString(), method,
              headers: { ...(where === "body" ? { "content-type": "application/json" } : {}), ...(params.headers ?? {}) },
              body: where === "body" ? JSON.stringify({ ...(params.body ?? {}), [params.param]: value }) : undefined,
              timeoutMs,
            }, params.identity);
            exchanges.push(exchange);
            const base = exchanges[0]!;
            const delta = exchange.durationMs - base.durationMs;
            const preview = (exchange.error ?? exchange.response?.body ?? "").replace(/\s+/g, " ").slice(0, 120);
            rows.push(`${exchange.id}  ${index ? "variante" : "control"}  ${exchange.response?.status ?? "ERR"}  ${exchange.durationMs} ms (${delta >= 0 ? "+" : ""}${delta})  ${index ? diffResponses(base, exchange) : "referencia"}  ${preview}`);
          }
          if (listener && exchanges.length > 1) await listener.wait(waitMs, signal);
          if (listener) {
            visits = listener.hits.length;
            rows.push(visits ? `Callback recibido: ${visits} visita(s) al camino exclusivo.` : "Sin callback dentro de la ventana: no demuestra que el servidor no visite URLs.");
            for (const hit of listener.hits) rows.push(`  ${hit.method} desde ${hit.remoteAddress} · ${hit.at} · artefacto ${hit.artifact}`);
          }
          if (!listener && alternatives.length > variants.length) rows.push(`Se recortaron ${alternatives.length - variants.length} variantes por maxRequests.`);
        }
        if (signal.aborted) rows.push("Sonda cancelada; se conservó la evidencia obtenida.");
        rows.push("Las diferencias y callbacks son señales: confirmá con una petición propia y registrá candidato con evidencia.", counter());
        return { text: rows.join("\n"), details: { peticiones: http.count - before, visitas: visits, canal: !!listener, intercambios: exchanges.map((exchange) => exchange.id), callbacks: listener?.hits.map((hit) => hit.artifact) ?? [] } };
      } finally {
        await listener?.close();
      }
    },
  };
}
