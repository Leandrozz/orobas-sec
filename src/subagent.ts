// Subagentes: trabajos acotados que el agente principal delega. Cada uno tiene su propio
// transcript, un tope de pasos y un tope de gasto; comparte alcance, memoria, artefactos,
// hallazgos y el presupuesto de la sesión. Su gasto se imputa al worker en el ledger.
import { neutralizarMarcadores } from "./secretos-sesion.ts";
import { Agent, type Tool } from "./agent.ts";
import { conWorker } from "./grafo.ts";
import type { Engine } from "./engine.ts";
import type { Model } from "./llm.ts";
import type { Provider } from "./providers.ts";
import { Ledger } from "./ledger.ts";
import { usd, usdToPico } from "./money.ts";
import { scopeBrief } from "./scope.ts";
import { logEvent } from "./store.ts";

const SUB_PROMPT = `Sos un subagente de Orobas (orobas-sec): resolvés UNA tarea acotada que te delegó el agente principal y devolvés un informe breve en castellano rioplatense.
Trabajás dentro del alcance autorizado; lo que no esté ahí no se toca. No podés ampliar el alcance ni delegar a otros.
Usá las herramientas sólo para la tarea asignada. Guardá en memoria sólo lo que una sesión futura necesitaría. Registrá hallazgos con finding_record (pista o candidato con evidencia); verificar no te corresponde.
Terminá con un informe estructurado: RESULTADO (qué encontraste, con hashes de artefactos o ids), LÍMITES (qué no pudiste comprobar), SIGUIENTE (qué conviene hacer). Sin relleno.`;

const MAX_CONCURRENT = 3;

export interface SubagentRun {
  objective: string;
  context?: string;
  /** Worker con el que queda en requests («sub:3», «sub:4:fuerte»). */
  worker: string;
  /** Proveedor del subagente; sin esto, el del bucle. */
  provider?: Provider;
  /** Tope de gasto propio, en picoUSD. */
  budget: bigint;
  maxSteps?: number;
  signal: AbortSignal;
  /** Herramientas que no se le dan, además de delegate. */
  without?: string[];
  /** Sólo estas herramientas (las que tenga cargadas el agente): un contexto propio y chico para el router. */
  only?: string[];
  /** Prompt de sistema propio (los tramos del modo investigar); sin esto, el de los subagentes con el alcance. */
  system?: string;
  /** Herramientas exactas, ya envueltas (los tramos del modo investigar); sin esto, las del agente según without y only. */
  herramientas?: Tool[];
  /** Como el verificador: lo corta su tope y el del proyecto, no el de la sesión (el modo investigar tiene el suyo). */
  topeProyecto?: boolean;
  /** Cuando quiere cerrar: un texto lo manda como mensaje de sistema y sigue. Quien lo pasa limita cuántas veces. */
  beforeEnd?: () => string | undefined;
}

export interface SubagentResult { text: string; ok: boolean; reason?: string; requests: number; cost: bigint; transcript: string; model: Model }

/**
 * Corre un subagente con su propio transcript hasta que termina: lo usan delegate (a pedido del agente)
 * y el router (un tramo del fuerte o del medio sobre un traspaso). Su gasto queda en requests con su worker.
 */
export async function runSubagent(engine: Engine, run: SubagentRun): Promise<SubagentResult> {
  const { worker, provider, budget, signal } = run;
  const model = provider?.model ?? engine.agent.model;
  // Lo que escriba en el grafo de hechos lleva este worker como procedencia (src/grafo.ts).
  const tools = conWorker(worker, run.herramientas ?? engine.agent.tools.filter((tool) => tool.name !== "delegate" && !(run.without ?? []).includes(tool.name) && (!run.only || run.only.includes(tool.name))));
  const spent = () => {
    const row = engine.db
      .prepare("select coalesce(sum(cast(cost_input as integer)+cast(cost_cache_read as integer)+cast(cost_cache_write as integer)+cast(cost_output as integer)),0) n from requests where session_id=? and worker=? and cost_input is not null")
      .get(engine.sessionId, worker) as { n: number | bigint };
    return BigInt(row.n);
  };
  const system = run.system ?? `${SUB_PROMPT}\n\nAlcance: ${scopeBrief(engine.scope.current())}`;
  const child = new Agent({
    system,
    model,
    tools,
    transport: provider ? engine.transportFor(worker, () => provider) : engine.tagged(worker),
    maxSteps: run.maxSteps ?? 25,
    stallLimit: 2,
    prepare: () => {
      const estimate = Ledger.estimate(model, JSON.stringify(child.messages).length + SUB_PROMPT.length);
      if (spent() + estimate > budget) return `Tope del subagente (USD ${usd(budget, 2)}) alcanzado.`;
      return run.topeProyecto ? engine.ledger.overProjectBudget(estimate) : engine.ledger.overBudget(engine.sessionId, estimate);
    },
    ...(run.beforeEnd ? { beforeEnd: run.beforeEnd } : {}),
  });
  const ctx = () => ({ sessionId: engine.sessionId, account: (provider ?? engine.provider).account, worker, model: child.model });
  child.on((event) => {
    if (event.type === "text") engine.agent.relay({ ...event, worker });
    else if (event.type === "request_start") {
      engine.ledger.begin(event.intent, ctx());
      engine.ledger.reserve(event.intent, engine.sessionId, Ledger.estimate(child.model, JSON.stringify(child.messages).length));
    } else if (event.type === "request") {
      engine.ledger.settle(event.intent);
      engine.ledger.record(event.message, ctx());
    } else if (event.type === "tool_start" || event.type === "tool_end") engine.agent.relay({ ...event, id: `${worker}/${event.id}`, worker });
  });
  const onAbort = () => child.abort();
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    if (signal.aborted) throw new Error("Cancelado antes de empezar");
    await child.prompt(`${run.objective}${run.context ? `\n\nContexto:\n${run.context}` : ""}`);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  const last = child.messages.at(-1);
  const transcript = engine.artifacts.put(neutralizarMarcadores(JSON.stringify(child.messages, null, 1)), "application/json", `subagente:${worker}`).hash;
  const requests = child.messages.filter((m) => m.role === "assistant").length;
  const cost = spent();
  if (!last || last.role !== "assistant" || last.stopReason === "error" || last.stopReason === "aborted") {
    return { text: "", ok: false, reason: last?.role === "assistant" ? last.errorMessage ?? last.stopReason : "sin respuesta", requests, cost, transcript, model };
  }
  return { text: last.content, ok: true, requests, cost, transcript, model };
}

export function createDelegateTool(engine: Engine): Tool {
  let active = 0;
  const waiting: Array<() => void> = [];
  const acquire = () => new Promise<void>((resolve) => (active < MAX_CONCURRENT ? (active++, resolve()) : waiting.push(() => (active++, resolve()))));
  const release = () => {
    active--;
    waiting.shift()?.();
  };
  return {
    name: "delegate",
    label: "Delegar",
    description:
      "Delega una tarea acotada a un subagente con su propio contexto (ideal para trabajo largo o independiente: revisar un artefacto grande, explorar una hipótesis, buscar en memoria). " +
      "Varias delegaciones en el mismo paso corren en paralelo (hasta 3). Devuelve su informe final. Comparte alcance, memoria y presupuesto; no puede delegar a su vez. " +
      "Con strong, el subagente trabaja con el modelo fuerte (más capaz y mucho más caro): sólo para explotación o análisis que el modelo base no resuelve.",
    parameters: {
      type: "object",
      properties: {
        objective: { type: "string", description: "Qué tiene que lograr y cuándo terminar", maxLength: 1500 },
        context: { type: "string", description: "Datos que necesita: ids, hashes, rutas. No pegues artefactos enteros.", maxLength: 3000 },
        budgetUsd: { type: "number", description: "Tope de gasto propio en USD (por defecto 0.25; con strong, 1)", minimum: 0.01, maximum: 5 },
        strong: { type: "boolean", description: "true: el subagente usa el modelo fuerte en vez del base" },
      },
      required: ["objective"],
    },
    parallel: true,
    execute: async (params, signal) => {
      // Con strong, el modelo fuerte; el worker lo dice («sub:3:fuerte») para ver en requests qué fue al caro.
      const strong = params.strong === true;
      const worker = `sub:${engine.nextSubagent()}${strong ? ":fuerte" : ""}`;
      await acquire();
      let result: SubagentResult;
      try {
        // El que ya es fuerte no consulta al fuerte.
        // Comparte el grafo de hechos: una línea le dice que existe, para que no repita lo ya observado.
        const vista = engine.grafo?.ver();
        const grafo = vista?.nodos.size ? `Grafo de hechos de la sesión: ${vista.nodos.size} nodos (${vista.deTipo("ruta").length} rutas, ${vista.deTipo("objeto").length} objetos, ${vista.deTipo("hallazgo").length} hallazgos). Antes de pedir algo, mirá con grafo (faltantes o vecinos) si ya se observó.` : "";
        const context = [params.context ? String(params.context) : "", grafo].filter(Boolean).join("\n\n") || undefined;
        result = await runSubagent(engine, { objective: String(params.objective), context, worker, provider: strong ? engine.strong() : undefined, budget: usdToPico(String(params.budgetUsd ?? (strong ? 1 : 0.25))), signal, without: strong ? ["deep_reason"] : [] });
      } finally {
        release();
      }
      const { model, requests, cost, transcript } = result;
      if (strong) logEvent(engine.db, engine.sessionId, "modelo_fuerte.consulta", { herramienta: "delegate", worker, modelo: `${model.provider}/${model.id}`, solicitudes: requests, usd: usd(cost) });
      if (!result.ok) {
        return {
          text: `El subagente ${worker} no terminó: ${result.reason}. Transcripción completa en ${transcript}.`,
          details: { worker, estado: "incompleto", solicitudes: requests, usd: usd(cost), transcripcion: transcript },
        };
      }
      return {
        text: `${result.text}\n\n[${worker}: ${requests} solicitudes, USD ${usd(cost)}, transcripción ${transcript}]`,
        details: { worker, estado: "listo", solicitudes: requests, usd: usd(cost), transcripcion: transcript },
      };
    },
  };
}
