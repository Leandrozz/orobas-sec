// Capa de modelos propia. Un transporte recibe una solicitud y devuelve el mensaje final
import { cabecerasDePrivacidad, leerModo } from "./privacidad-trazas.ts";
import { readFileSync } from "node:fs";
import { join } from "node:path";
// del asistente con el uso reportado por el proveedor. Sin SDKs: fetch + SSE.
import { randomUUID } from "node:crypto";
import { apiKey, missingKeyMessage } from "./providers.ts";
import { accountGate } from "./cuenta.ts";
import { puntosDeCacheAnthropic } from "./prefijo.ts";

/** Categorías disjuntas. `reasoning` es un subconjunto de `output`. */
export interface Usage {
  input: number;
  cacheRead: number;
  cacheWrite: number;
  output: number;
  reasoning?: number;
}

/** USD por millón de tokens. */
export interface Rates {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
}

export interface Model {
  provider: string;
  id: string;
  baseUrl: string;
  /** Nombre de la variable de entorno con la clave; ausente = sin clave (servidor local). */
  apiKeyEnv?: string;
  /** Ausente = precio desconocido: el costo queda pendiente, nunca en cero. */
  cost?: Rates;
  /** De dónde salió la tarifa: la publicada por el servicio, o la configuración del harness. */
  costSource?: "servicio" | "configuración" | "plan de ChatGPT";
  contextWindow?: number;
  /** Máximo de tokens de salida que puede producir una respuesta; se usa para reservar presupuesto. Por defecto 4096. */
  maxTokens?: number;
  /** Corta la solicitud si el proveedor no envía nada durante este tiempo. Por defecto lo adapta idleTimeoutFor (45 s a 120 s). */
  idleTimeoutMs?: number;
  /** Tope absoluto por solicitud, con o sin latidos. Por defecto 15 minutos. */
  maxRequestMs?: number;
  /**
   * Razonamiento previo del modelo: true lo prende, false lo apaga, un nivel dice cuánto razona, ausente
   * deja el de cada modelo. Va como `reasoning: {enabled, effort}` (orobas, OpenRouter y compatibles); el
   * operador lo cambia en la sesión.
   */
  reasoning?: boolean | Effort;
  /** Niveles que este modelo acepta, según el servicio. Ausente: sólo se prende o se apaga. */
  reasoningEfforts?: Effort[];
  /** Si se puede apagar del todo; si no, «apagado» es su mínimo. Va junto con `reasoningEfforts`. */
  reasoningOff?: boolean;
}

/** Niveles de razonamiento, de menos a más. */
export const EFFORTS = ["low", "medium", "high", "max"] as const;
export type Effort = (typeof EFFORTS)[number];
export const isEffort = (value: unknown): value is Effort => typeof value === "string" && (EFFORTS as readonly string[]).includes(value);

export interface ToolCall {
  id: string;
  name: string;
  /** JSON tal como lo emitió el modelo. */
  arguments: string;
}

export interface UserMessage {
  role: "user";
  content: string;
  at: number;
}

export interface AssistantMessage {
  role: "assistant";
  content: string;
  toolCalls: ToolCall[];
  stopReason: "stop" | "toolUse" | "length" | "error" | "aborted";
  errorMessage?: string;
  /** El proveedor rechazó la solicitud antes de procesarla (HTTP 4xx): no consumió tokens. */
  rejected?: boolean;
  /** Falla transitoria (429, 5xx, red, silencio): conviene reintentar. */
  retryable?: boolean;
  /** Espera que pidió el servicio (Retry-After), en milisegundos. */
  retryAfterMs?: number;
  /** La respuesta llegó entera pero incoherente (restos de plantilla, «$MISSING», escrituras mezcladas): se descartó. */
  incoherent?: boolean;
  /** Sin saldo o con el plan inactivo (usage_limit y parecidos): reintentar o cambiar de modelo no lo arregla. */
  exhausted?: boolean;
  /** Silencio más largo de la solicitud, en milisegundos: desde el envío hasta la cabecera y entre trozos del stream. */
  silenceMs?: number;
  provider: string;
  model: string;
  requestId: string;
  /** Ausente = uso desconocido. */
  usage?: Usage;
  at: number;
}

export interface ToolMessage {
  role: "tool";
  toolCallId: string;
  name: string;
  content: string;
  isError: boolean;
  at: number;
}

/** Resumen que reemplaza la parte vieja de la conversación tras compactar. */
export interface CheckpointMessage {
  role: "checkpoint";
  content: string;
  /** Secuencia del primer mensaje conservado después del resumen. */
  keepFrom: number;
  at: number;
}

export type Message = UserMessage | AssistantMessage | ToolMessage | CheckpointMessage;

export interface ToolSpec {
  name: string;
  description: string;
  parameters: object;
}

export interface LlmRequest {
  model: Model;
  system: string;
  messages: Message[];
  tools: ToolSpec[];
  signal?: AbortSignal;
  onText?: (delta: string) => void;
  /** Razonamiento previo que va llegando: sólo su tamaño, para mostrar que el modelo está trabajando. */
  onReasoning?: (chars: number) => void;
  /** Etiquetas de uso (sesión, worker, proyecto): viajan como cabeceras x-cyber-* sólo al servicio propio. «trazas» sólo restringe el modo de ese pedido. */
  tags?: Record<string, string>;
}

export const CLIENT_VERSION = (() => {
  try {
    return String(JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8")).version ?? "0");
  } catch {
    return "0";
  }
})();

/** Cabeceras de trazabilidad. Un proveedor ajeno no las recibe: no hay por qué contarle nuestras sesiones. */
export function usageHeaders(model: Model, tags?: Record<string, string>): Record<string, string> {
  if (model.provider !== "orobas") return {};
  const headers: Record<string, string> = { "x-cyber-version": CLIENT_VERSION };
  for (const [key, value] of Object.entries(tags ?? {})) {
    if (key === "trazas") continue;
    const name = key.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    const clean = String(value).replace(/[^\x20-\x7e]/g, "").slice(0, 120);
    if (name && clean) headers[`x-cyber-${name}`] = clean;
  }
  // La etiqueta «trazas» sólo puede restringir el modo de este pedido (Engine.transportFor).
  return { ...headers, ...cabecerasDePrivacidad(leerModo(tags?.trazas)) };
}

export type Transport = (request: LlmRequest) => Promise<AssistantMessage>;

/**
 * Vigía de silencio. Cuenta como actividad todo lo que llega: la cabecera de la respuesta y cada trozo
 * del stream, también los comentarios SSE («: keep-alive»), el razonamiento y el uso. Con 120 s fijos,
 * cada caída del proveedor costaba dos minutos o más (sesiones de noviembre: ~75 min perdidos); con
 * 45 s el operador pierde menos de un minuto por falla. Un modelo que piensa callado más tiempo no se
 * corta para siempre: el silencio más largo que se le vio en una respuesta buena sube su margen (×1,5),
 * hasta 120 s. Un `idleTimeoutMs` del modelo (configuración o pruebas) manda sobre todo esto.
 */
export const IDLE_DEFAULT_MS = 45_000;
export const IDLE_MAX_MS = 120_000;
const silences = new Map<string, number>();
const modelKey = (model: Model) => `${model.provider}/${model.id}`;

/** Registra el silencio más largo de una respuesta que terminó bien. */
export function noteSilence(model: Model, ms: number): void {
  if (ms > (silences.get(modelKey(model)) ?? 0)) silences.set(modelKey(model), ms);
}

/** Cuánto silencio se le tolera a este modelo antes de cortar la solicitud. */
export function idleTimeoutFor(model: Model): number {
  if (model.idleTimeoutMs) return model.idleTimeoutMs;
  return Math.min(IDLE_MAX_MS, Math.max(IDLE_DEFAULT_MS, Math.round((silences.get(modelKey(model)) ?? 0) * 1.5)));
}

/** Olvida lo medido (pruebas). */
export const forgetSilences = () => silences.clear();

/** Arma el vigía de una solicitud: `alive` rearma el plazo y mide el hueco desde la última señal. */
export function watchdog(model: Model) {
  const idle = new AbortController();
  const idleMs = idleTimeoutFor(model);
  let last = Date.now();
  let longest = 0;
  let timer = setTimeout(() => idle.abort(), idleMs);
  return {
    idle,
    idleMs,
    alive: () => {
      const now = Date.now();
      longest = Math.max(longest, now - last);
      last = now;
      clearTimeout(timer);
      timer = setTimeout(() => idle.abort(), idleMs);
    },
    longest: () => longest,
    stop: () => clearTimeout(timer),
  };
}

const validJson = (text: string) => { try { JSON.parse(text); return text; } catch { return "{}"; } };

function toWire(system: string, messages: Message[]): object[] {
  const wire: object[] = [{ role: "system", content: system }];
  for (const message of messages) {
    if (message.role === "user") wire.push({ role: "user", content: message.content });
    else if (message.role === "checkpoint") {
      wire.push({ role: "user", content: `<checkpoint>\nResumen de la conversación anterior, ya compactada:\n${message.content}\n</checkpoint>` });
    }
    else if (message.role === "tool") wire.push({ role: "tool", tool_call_id: message.toolCallId, content: message.content });
    else if (message.content || message.toolCalls.length) {
      wire.push({
        role: "assistant",
        content: message.content || null,
        ...(message.toolCalls.length && {
          tool_calls: message.toolCalls.map((call) => ({
            id: call.id,
            type: "function",
            // Un JSON cortado (el modelo se quedó sin tokens a mitad de la llamada) haría rechazar cada turno siguiente: va «{}», como en anthropicMessages.
            function: { name: call.name, arguments: validJson(call.arguments) },
          })),
        }),
      });
    }
  }
  return wire;
}

/** Normaliza el uso de APIs compatibles con OpenAI a categorías disjuntas. */
export function normalizeUsage(raw: any): Usage | undefined {
  if (!raw || typeof raw.prompt_tokens !== "number") return undefined;
  // OpenAI/OpenRouter: prompt_tokens_details.cached_tokens; DeepSeek: prompt_cache_hit_tokens.
  const cacheRead = raw.prompt_tokens_details?.cached_tokens ?? raw.prompt_cache_hit_tokens ?? raw.cached_tokens ?? 0;
  const cacheWrite = raw.prompt_tokens_details?.cache_write_tokens ?? 0;
  const reasoning = raw.completion_tokens_details?.reasoning_tokens;
  return {
    input: Math.max(0, raw.prompt_tokens - cacheRead - cacheWrite),
    cacheRead,
    cacheWrite,
    output: raw.completion_tokens ?? 0,
    ...(typeof reasoning === "number" && { reasoning }),
  };
}

/** Chat Completions con streaming: OpenAI, DeepSeek, OpenRouter, Ollama, gateways compatibles. */
export const openAICompletions: Transport = async (request) => {
  const { model } = request;
  const message: AssistantMessage = {
    role: "assistant",
    content: "",
    toolCalls: [],
    stopReason: "stop",
    provider: model.provider,
    model: model.id,
    requestId: `local:${randomUUID()}`,
    at: Date.now(),
  };
  const fail = (reason: "error" | "aborted", detail: string): AssistantMessage => ({
    ...message,
    toolCalls: [],
    stopReason: reason,
    errorMessage: detail,
  });
  const key = model.apiKeyEnv ? apiKey(model.apiKeyEnv) : undefined;
  if (model.apiKeyEnv && !key) {
    return { ...fail("error", missingKeyMessage(model.apiKeyEnv)), rejected: true };
  }
  // Cuenta e identidad, sólo para los modelos de la suscripción (ver cuenta.ts).
  const denied = await accountGate(model);
  if (denied) return { ...fail("error", denied), rejected: true };
  // Vigía de silencio: se rearma con cada dato recibido (ver idleTimeoutFor).
  const { idle, idleMs, alive, longest, stop } = watchdog(model);
  // Tope absoluto: un proveedor que manda latidos sin terminar nunca la respuesta rearma el vigía
  // de silencio para siempre. Una corrida del benchmark quedó colgada 38 minutos así.
  const hard = new AbortController();
  const maxMs = model.maxRequestMs ?? 900_000;
  const deadline = setTimeout(() => hard.abort(), maxMs);
  const signal = AbortSignal.any([...(request.signal ? [request.signal] : []), idle.signal, hard.signal]);
  try {
    const response = await fetch(`${model.baseUrl.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      signal,
      headers: { "content-type": "application/json", ...usageHeaders(model, request.tags), ...(key && { authorization: `Bearer ${key}` }) },
      body: JSON.stringify({
        model: model.id,
        messages: toWire(request.system, request.messages),
        ...(request.tools.length && {
          tools: request.tools.map((tool) => ({ type: "function", function: tool })),
        }),
        stream: true,
        stream_options: { include_usage: true },
        ...(model.reasoning !== undefined && { reasoning: typeof model.reasoning === "string" ? { enabled: true, effort: model.reasoning } : { enabled: model.reasoning } }),
      }),
    });
    alive();
    message.requestId = response.headers.get("x-request-id") ?? message.requestId;
    if (!response.ok || !response.body) {
      const body = (await response.text()).slice(0, 400);
      // Sin saldo o con el plan inactivo no es una saturación pasajera: reintentar no lo arregla.
      const exhausted = /"code"\s*:\s*"(usage_limit|plan_inactive|insufficient_balance|insufficient_quota)"/.test(body);
      const retryable = !exhausted && (response.status === 429 || response.status === 408 || response.status >= 500);
      const rejected = response.status >= 400 && response.status < 500;
      // El servicio habla claro ({error:{message,code}}): al operador le llega ese mensaje, no el JSON crudo,
      // con el id del pedido (oro_req_…) para citarlo en soporte. Otro servidor: estado y cuerpo tal cual.
      let error: { message?: unknown; code?: unknown } | null = null;
      try { error = JSON.parse(body)?.error ?? null; } catch { /* no es JSON */ }
      const said = typeof error?.message === "string" && error.message ? `${error.message}${typeof error.code === "string" ? ` [${error.code}]` : ""}` : `HTTP ${response.status}: ${body}`;
      const support = message.requestId.startsWith("oro_req_") ? ` · pedido ${message.requestId}` : "";
      const retryAfterMs = Number(response.headers.get("retry-after")) * 1000 || undefined;
      return { ...fail("error", `${said}${support}`), ...(rejected && { rejected }), ...(retryable && { retryable, retryAfterMs }), ...(exhausted && { exhausted }) };
    }
    const calls: ToolCall[] = [];
    let finish: string | undefined;
    let done = false;
    let pending = "";
    const decoder = new TextDecoder();
    for await (const chunk of response.body) {
      alive();
      pending += decoder.decode(chunk, { stream: true });
      let newline: number;
      while ((newline = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, newline).trim();
        pending = pending.slice(newline + 1);
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (data === "[DONE]") { done = true; continue; }
        const event = JSON.parse(data);
        if (event.error) return fail("error", String(event.error.message ?? JSON.stringify(event.error)));
        if (event.id && message.requestId.startsWith("local:")) message.requestId = event.id;
        if (event.usage) message.usage = normalizeUsage(event.usage);
        const choice = event.choices?.[0];
        if (!choice) continue;
        if (choice.finish_reason) finish = choice.finish_reason;
        const delta = choice.delta ?? {};
        if (typeof delta.content === "string" && delta.content) {
          message.content += delta.content;
          request.onText?.(delta.content);
        }
        const thought = typeof delta.reasoning_content === "string" ? delta.reasoning_content : typeof delta.reasoning === "string" ? delta.reasoning : "";
        if (thought) request.onReasoning?.(thought.length);
        for (const part of delta.tool_calls ?? []) {
          const call = (calls[part.index ?? 0] ??= { id: "", name: "", arguments: "" });
          if (part.id) call.id = part.id;
          if (part.function?.name) call.name += part.function.name;
          if (part.function?.arguments) call.arguments += part.function.arguments;
        }
      }
    }
    // Un stream que se cierra sin finish_reason ni [DONE] no terminó: el proveedor cortó la conexión y un
    // intermediario la cerró limpio, así que no salta como error de red. Darlo por bueno deja una respuesta
    // por la mitad como si fuera el final del turno, o una llamada a herramienta con los argumentos truncados.
    if (!finish && !done) return { ...fail("error", "El proveedor cortó la respuesta a la mitad"), usage: undefined, retryable: true };
    message.toolCalls = calls.filter(Boolean).map((call) => ({ ...call, id: call.id || `call_${randomUUID().slice(0, 8)}` }));
    message.stopReason = message.toolCalls.length ? "toolUse" : finish === "length" ? "length" : "stop";
    message.silenceMs = longest();
    noteSilence(model, message.silenceMs);
    return message;
  } catch (error) {
    // Corte a mitad de respuesta: el texto recibido se conserva; el uso queda desconocido.
    if (request.signal?.aborted) return { ...fail("aborted", "Turno detenido"), usage: undefined };
    const detail = hard.signal.aborted
      ? `El proveedor no terminó la respuesta en ${Math.round(maxMs / 1000)} s`
      : idle.signal.aborted
        ? `El proveedor no respondió en ${Math.round(idleMs / 1000)} s`
        : `Red: ${(error as Error).message}`;
    return { ...fail("error", detail), usage: undefined, retryable: true };
  } finally {
    stop();
    clearTimeout(deadline);
  }
};

/** Mensajes al formato de Anthropic Messages: bloques tool_use / tool_result, roles alternados. */
function toAnthropic(messages: Message[]): object[] {
  const wire: Array<{ role: "user" | "assistant"; content: any[] }> = [];
  const push = (role: "user" | "assistant", block: object) => {
    const last = wire.at(-1);
    if (last && last.role === role) last.content.push(block);
    else wire.push({ role, content: [block] });
  };
  for (const message of messages) {
    if (message.role === "user") push("user", { type: "text", text: message.content });
    else if (message.role === "checkpoint") push("user", { type: "text", text: `<checkpoint>\nResumen de la conversación anterior, ya compactada:\n${message.content}\n</checkpoint>` });
    else if (message.role === "tool") push("user", { type: "tool_result", tool_use_id: message.toolCallId, content: message.content, is_error: message.isError });
    else {
      if (message.content) push("assistant", { type: "text", text: message.content });
      for (const call of message.toolCalls) {
        let input: unknown = {};
        try {
          input = JSON.parse(call.arguments || "{}");
        } catch {}
        push("assistant", { type: "tool_use", id: call.id, name: call.name, input });
      }
    }
  }
  // La API exige que el primer mensaje sea del usuario y que ningún bloque de texto esté vacío.
  return wire.filter((message) => message.content.length).map((message) => ({ ...message, content: message.content.filter((block) => block.type !== "text" || block.text) }));
}

/** Anthropic Messages con streaming. Lee uso de message_start (entrada y caché) y message_delta (salida). */
export const anthropicMessages: Transport = async (request) => {
  const { model } = request;
  const message: AssistantMessage = {
    role: "assistant",
    content: "",
    toolCalls: [],
    stopReason: "stop",
    provider: model.provider,
    model: model.id,
    requestId: `local:${randomUUID()}`,
    at: Date.now(),
  };
  const fail = (reason: "error" | "aborted", detail: string): AssistantMessage => ({ ...message, toolCalls: [], stopReason: reason, errorMessage: detail });
  const key = model.apiKeyEnv ? apiKey(model.apiKeyEnv) : undefined;
  if (model.apiKeyEnv && !key) return { ...fail("error", missingKeyMessage(model.apiKeyEnv)), rejected: true };
  const denied = await accountGate(model);
  if (denied) return { ...fail("error", denied), rejected: true };
  const { idle, idleMs, alive, longest, stop } = watchdog(model);
  // Tope absoluto: un proveedor que manda latidos sin terminar nunca la respuesta rearma el vigía
  // de silencio para siempre. Una corrida del benchmark quedó colgada 38 minutos así.
  const hard = new AbortController();
  const maxMs = model.maxRequestMs ?? 900_000;
  const deadline = setTimeout(() => hard.abort(), maxMs);
  const signal = AbortSignal.any([...(request.signal ? [request.signal] : []), idle.signal, hard.signal]);
  try {
    const response = await fetch(`${model.baseUrl.replace(/\/$/, "")}/messages`, {
      method: "POST",
      signal,
      headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", ...usageHeaders(model, request.tags), ...(key && { "x-api-key": key }) },
      body: JSON.stringify({
        model: model.id,
        max_tokens: model.maxTokens ?? 4096,
        // Puntos de caché explícitos (src/prefijo.ts): sin ellos Anthropic no cachea nada.
        ...puntosDeCacheAnthropic(request.system, toAnthropic(request.messages) as Parameters<typeof puntosDeCacheAnthropic>[1]),
        ...(request.tools.length && { tools: request.tools.map((tool) => ({ name: tool.name, description: tool.description, input_schema: tool.parameters })) }),
        stream: true,
      }),
    });
    alive();
    message.requestId = response.headers.get("request-id") ?? message.requestId;
    if (!response.ok || !response.body) {
      const body = (await response.text()).slice(0, 400);
      const retryable = response.status === 429 || response.status === 529 || response.status >= 500;
      const rejected = response.status >= 400 && response.status < 500 && response.status !== 429;
      return { ...fail("error", `HTTP ${response.status}: ${body}`), ...(rejected && { rejected }), ...(retryable && { retryable }) };
    }
    const blocks = new Map<number, { type: string; call?: ToolCall; json: string }>();
    let usage: Usage | undefined;
    let finish: string | undefined;
    let done = false;
    let pending = "";
    const decoder = new TextDecoder();
    for await (const chunk of response.body) {
      alive();
      pending += decoder.decode(chunk, { stream: true });
      let newline: number;
      while ((newline = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, newline).trim();
        pending = pending.slice(newline + 1);
        if (!line.startsWith("data:")) continue;
        const event = JSON.parse(line.slice(5).trim());
        if (event.type === "error") return fail("error", String(event.error?.message ?? JSON.stringify(event.error)));
        if (event.type === "message_start") {
          const raw = event.message?.usage ?? {};
          if (event.message?.id) message.requestId = event.message.id;
          usage = { input: raw.input_tokens ?? 0, cacheRead: raw.cache_read_input_tokens ?? 0, cacheWrite: raw.cache_creation_input_tokens ?? 0, output: raw.output_tokens ?? 0 };
        } else if (event.type === "content_block_start") {
          const block = event.content_block ?? {};
          blocks.set(event.index, { type: block.type, json: "", call: block.type === "tool_use" ? { id: block.id, name: block.name, arguments: "" } : undefined });
        } else if (event.type === "content_block_delta") {
          const block = blocks.get(event.index);
          const delta = event.delta ?? {};
          if (delta.type === "text_delta" && delta.text) {
            message.content += delta.text;
            request.onText?.(delta.text);
          } else if (delta.type === "input_json_delta" && block?.call) block.json += delta.partial_json ?? "";
        } else if (event.type === "content_block_stop") {
          const block = blocks.get(event.index);
          if (block?.call) message.toolCalls.push({ ...block.call, arguments: block.json || "{}" });
        } else if (event.type === "message_delta") {
          finish = event.delta?.stop_reason ?? finish;
          if (usage && typeof event.usage?.output_tokens === "number") usage.output = event.usage.output_tokens;
        } else if (event.type === "message_stop") done = true;
      }
    }
    // Igual que en Chat Completions: sin stop_reason ni message_stop, la respuesta quedó por la mitad.
    if (!finish && !done) return { ...fail("error", "El proveedor cortó la respuesta a la mitad"), usage: undefined, retryable: true };
    message.usage = usage;
    message.stopReason = message.toolCalls.length ? "toolUse" : finish === "max_tokens" ? "length" : "stop";
    message.silenceMs = longest();
    noteSilence(model, message.silenceMs);
    return message;
  } catch (error) {
    if (request.signal?.aborted) return { ...fail("aborted", "Turno detenido"), usage: undefined };
    const detail = hard.signal.aborted
      ? `El proveedor no terminó la respuesta en ${Math.round(maxMs / 1000)} s`
      : idle.signal.aborted
        ? `El proveedor no respondió en ${Math.round(idleMs / 1000)} s`
        : `Red: ${(error as Error).message}`;
    return { ...fail("error", detail), usage: undefined, retryable: true };
  } finally {
    stop();
    clearTimeout(deadline);
  }
};

/** Respuesta guionada para el transporte simulado. */
export interface Scripted {
  /** Simula una falla del proveedor en lugar de una respuesta. */
  fail?: { message: string; retryable?: boolean; rejected?: boolean; exhausted?: boolean };
  text?: string;
  toolCalls?: Array<{ name: string; arguments: object }>;
  requestId?: string;
}

/** Transporte simulado y determinista para pruebas y demos. Uso estimado: 1 token cada 4 caracteres. */
export interface Faux {
  transport: Transport;
  queue: Scripted[];
  calls: number;
}

export function fauxTransport(): Faux {
  const state: Faux = {
    queue: [],
    calls: 0,
    transport: async (request) => {
      const base = {
        role: "assistant" as const,
        content: "",
        toolCalls: [] as ToolCall[],
        provider: request.model.provider,
        model: request.model.id,
        requestId: `faux:${randomUUID()}`,
        at: Date.now(),
      };
      const next = state.queue.shift();
      if (!next) return { ...base, stopReason: "error", errorMessage: "Sin respuestas simuladas en cola", rejected: true };
      state.calls++;
      if (next.fail) return { ...base, stopReason: "error", errorMessage: next.fail.message, retryable: next.fail.retryable, rejected: next.fail.rejected, ...(next.fail.exhausted && { exhausted: true }) };
      const toolCalls = (next.toolCalls ?? []).map((call, index) => ({
        id: `call_${state.calls}_${index}`,
        name: call.name,
        arguments: JSON.stringify(call.arguments),
      }));
      for (const word of (next.text ?? "").split(/(?<=\s)/)) {
        if (request.signal?.aborted) return { ...base, stopReason: "aborted", errorMessage: "Turno detenido" };
        if (word) request.onText?.(word);
      }
      const size = (value: unknown) => Math.ceil(JSON.stringify(value).length / 4);
      return {
        ...base,
        content: next.text ?? "",
        toolCalls,
        stopReason: toolCalls.length ? "toolUse" : "stop",
        requestId: next.requestId ?? base.requestId,
        usage: { input: size([request.system, request.messages, request.tools]), cacheRead: 0, cacheWrite: 0, output: size([next.text, toolCalls]) },
      };
    },
  };
  return state;
}
