// Transporte Responses público para el permiso chatgpt.tokens.use.direct.
import { randomUUID } from "node:crypto";
import { chatgptAccessToken, chatgptBaseUrl, clearChatgptLimit, MANAGE_USAGE, markChatgptLimit } from "./chatgpt.ts";
import { type AssistantMessage, type Message, noteSilence, type ToolCall, type Transport, type Usage, watchdog } from "./llm.ts";

const validJson = (text: string) => { try { JSON.parse(text); return text; } catch { return "{}"; } };
const cleanCode = (raw: unknown) => typeof raw === "string" ? raw.replace(/[^a-z0-9_]/gi, "").slice(0, 80) : "";
/** Retry-After en segundos o como fecha HTTP; inválido o vencido, undefined. */
const retryAfterMs = (raw: string | null): number | undefined => {
  const value = raw?.trim();
  if (!value) return undefined;
  const ms = /^\d+$/.test(value) ? Number(value) * 1000 : Date.parse(value) - Date.now();
  return ms > 0 ? ms : undefined;
};
/** Si OpenAI rechazó `reasoning.summary` una vez, no se vuelve a pedir en este proceso. */
let summaryRejected = false;

/**
 * Esfuerzo que va a OpenAI. Los modelos con niveles (el catálogo marca los GPT que razonan) van en «alto» por defecto;
 * «apagado» es «low» porque no se apagan del todo; `max` es `xhigh`. Los demás sólo mandan algo si el operador lo prendió.
 */
export function chatgptEffort(model: { reasoning?: boolean | string; reasoningEfforts?: string[] }): string | undefined {
  const value = model.reasoning;
  if (model.reasoningEfforts) {
    if (value === undefined || value === true) return "high";
    if (value === false) return "low";
    return value === "max" ? "xhigh" : value;
  }
  if (!value) return undefined;
  return value === true ? "medium" : value === "max" ? "xhigh" : value;
}

const requestId = (raw: string | null | undefined, fallback: string) => raw && /^[A-Za-z0-9_-]{1,120}$/.test(raw) ? raw : fallback;

/** Cada pedido lleva todo el contexto; no usa previous_response_id ni almacenamiento remoto. */
export function toResponsesInput(messages: Message[]): object[] {
  const input: object[] = [];
  const user = (text: string) => input.push({ type: "message", role: "user", content: [{ type: "input_text", text }] });
  for (const message of messages) {
    if (message.role === "user") user(message.content);
    else if (message.role === "checkpoint") user("<checkpoint>\nResumen de la conversación anterior, ya compactada:\n" + message.content + "\n</checkpoint>");
    else if (message.role === "tool") input.push({ type: "function_call_output", call_id: message.toolCallId, output: message.content });
    else {
      if (message.content) input.push({ type: "message", role: "assistant", content: [{ type: "output_text", text: message.content }] });
      for (const call of message.toolCalls) input.push({ type: "function_call", call_id: call.id, name: "orobas." + call.name, arguments: validJson(call.arguments) });
    }
  }
  return input;
}

const usageOf = (raw: any): Usage | undefined => {
  if (typeof raw?.input_tokens !== "number") return undefined;
  const cacheRead = typeof raw.input_tokens_details?.cached_tokens === "number" ? raw.input_tokens_details.cached_tokens : 0;
  return { input: Math.max(0, raw.input_tokens - cacheRead), cacheRead, cacheWrite: 0, output: raw.output_tokens ?? 0, ...(typeof raw.output_tokens_details?.reasoning_tokens === "number" ? { reasoning: raw.output_tokens_details.reasoning_tokens } : {}) };
};

function failure(code: string, status?: number): { detail: string; retryable?: boolean; rejected?: boolean; limit?: boolean } {
  if (code === "subscription_sharing_usage_limit_exceeded") return { detail: "Llegaste al límite de uso del plan o de esta app. Manage usage: " + MANAGE_USAGE, rejected: true, limit: true };
  if (code === "subscription_sharing_user_not_eligible") return { detail: "Esta cuenta o espacio de trabajo no puede usar el plan de ChatGPT desde esta app.", rejected: true };
  if (code === "subscription_sharing_invalid_user") return { detail: "OpenAI no pudo validar esta sesión de ChatGPT. Revisá /chatgpt; si la sesión fue revocada, volvé a entrar.", rejected: true };
  if (code === "subscription_sharing_unsupported_capability") return { detail: "OpenAI rechazó una capacidad de este pedido (" + code + ").", rejected: true };
  if (code === "subscription_sharing_route_not_supported") return { detail: "La ruta de Responses no está habilitada para este cliente.", rejected: true };
  if (status === 503 || status === 408 || code === "subscription_sharing_usage_unavailable" || code === "subscription_sharing_user_unavailable") return { detail: "ChatGPT no está disponible ahora (" + (code || status) + ").", retryable: true };
  return { detail: "ChatGPT rechazó el pedido (" + (code || "HTTP " + (status ?? "?")) + ").", ...(status !== undefined && status >= 400 && status < 500 ? { rejected: true } : {}) };
}

/** Sólo response.completed confirma éxito, incluso cuando el servidor ya envió texto. */
export const chatgptResponses: Transport = async (request) => {
  const { model } = request;
  const message: AssistantMessage = { role: "assistant", content: "", toolCalls: [], stopReason: "stop", provider: model.provider, model: model.id, requestId: "local:" + randomUUID(), at: Date.now() };
  const fail = (detail: string, extra: Partial<AssistantMessage> = {}): AssistantMessage => ({ ...message, content: "", toolCalls: [], usage: undefined, stopReason: "error", errorMessage: detail, ...extra });
  let token: string;
  try { token = await chatgptAccessToken(); }
  catch (error) { return fail((error as Error).message, { rejected: true }); }
  const { idle, idleMs, alive, longest, stop } = watchdog(model);
  const hard = new AbortController();
  const maxMs = model.maxRequestMs ?? 900_000;
  const timer = setTimeout(() => hard.abort(), maxMs);
  const signal = AbortSignal.any([...(request.signal ? [request.signal] : []), idle.signal, hard.signal]);
  const effort = chatgptEffort(model);
  const body: Record<string, unknown> = {
    model: model.id,
    instructions: request.system,
    input: toResponsesInput(request.messages),
    ...(request.tools.length ? { tools: [{ type: "namespace", name: "orobas", description: "Herramientas locales de orobas-sec", tools: request.tools.map((tool) => ({ type: "function", name: tool.name, description: tool.description, parameters: tool.parameters, strict: false })) }], parallel_tool_calls: false } : {}),
    ...(effort ? { reasoning: { effort, ...(summaryRejected ? {} : { summary: "auto" }) } } : {}),
    store: false,
    stream: true,
  };
  try {
    const send = () => fetch(chatgptBaseUrl() + "/responses", {
      method: "POST", signal, headers: { authorization: "Bearer " + token, "content-type": "application/json", accept: "text/event-stream" }, body: JSON.stringify(body),
    });
    let response = await send();
    // El resumen del razonamiento es opcional: si esta vía no lo acepta, se repite una vez sin él y no se vuelve a pedir.
    if (response.status === 400 && (body.reasoning as { summary?: string } | undefined)?.summary) {
      const raw = await response.clone().text().catch(() => "");
      if (/summary/i.test(raw)) {
        summaryRejected = true;
        body.reasoning = { effort };
        response = await send();
      }
    }
    alive();
    message.requestId = requestId(response.headers.get("x-request-id"), message.requestId);
    if (!response.ok || !response.body) {
      const raw = await response.text();
      let parsed: any = {};
      try { parsed = JSON.parse(raw); } catch {}
      const code = cleanCode(parsed?.error?.code ?? parsed?.code);
      const result = failure(code, response.status);
      if (result.limit) await markChatgptLimit(retryAfterMs(response.headers.get("retry-after"))).catch(() => {});
      return fail(result.detail + " · HTTP " + response.status + " · pedido " + message.requestId, { rejected: result.rejected, retryable: result.retryable, retryAfterMs: result.retryable ? Number(response.headers.get("retry-after")) * 1000 || undefined : undefined });
    }
    const calls = new Map<string, ToolCall & { index: number }>();
    let completed = false;
    let pending = "";
    let streamed = false;
    let limited = false;
    const decoder = new TextDecoder();
    const eventOf = (data: string): AssistantMessage | undefined => {
      let event: any;
      try { event = JSON.parse(data); } catch { return undefined; }
      const type = String(event.type ?? "");
      if (type === "response.failed" || type === "error") {
        const code = cleanCode(event.response?.error?.code ?? event.error?.code ?? event.code);
        const result = failure(code);
        if (result.limit) limited = true;
        return fail(result.detail + " · pedido " + message.requestId, { rejected: result.rejected, retryable: result.retryable });
      }
      if (type === "response.incomplete") return fail("ChatGPT dejó la respuesta incompleta. Pedido " + message.requestId);
      if (type === "response.created") message.requestId = requestId(event.response?.id, message.requestId);
      if (type === "response.output_text.delta" && typeof event.delta === "string") {
        streamed = true;
        message.content += event.delta;
        request.onText?.(event.delta);
      }
      if ((type === "response.reasoning_summary_text.delta" || type === "response.reasoning_text.delta") && typeof event.delta === "string") request.onReasoning?.(event.delta.length);
      if (type === "response.output_item.added" && event.item?.type === "function_call") {
        calls.set(String(event.item.id ?? event.output_index), { id: String(event.item.call_id ?? ""), name: String(event.item.name ?? "").replace(/^orobas\./, ""), arguments: String(event.item.arguments ?? ""), index: Number(event.output_index) || calls.size });
      }
      if (type === "response.function_call_arguments.delta" && typeof event.delta === "string") {
        const call = calls.get(String(event.item_id ?? event.output_index));
        if (call) call.arguments += event.delta;
      }
      if (type === "response.output_item.done" && event.item?.type === "function_call") {
        const item = event.item;
        const key = String(item.id ?? event.output_index);
        const before = calls.get(key);
        calls.set(key, { id: String(item.call_id ?? before?.id ?? ""), name: String(item.name ?? before?.name ?? "").replace(/^orobas\./, ""), arguments: typeof item.arguments === "string" ? item.arguments : before?.arguments ?? "", index: before?.index ?? (Number(event.output_index) || calls.size) });
      }
      if (type === "response.output_item.done" && event.item?.type === "message" && !streamed) {
        const text = (event.item.content ?? []).filter((part: any) => part?.type === "output_text").map((part: any) => String(part.text ?? "")).join("");
        if (text) { message.content += text; request.onText?.(text); }
      }
      if (type === "response.completed") {
        completed = true;
        message.usage = usageOf(event.response?.usage);
        message.requestId = requestId(event.response?.id, message.requestId);
      }
      return undefined;
    };
    for await (const chunk of response.body) {
      alive();
      pending = (pending + decoder.decode(chunk, { stream: true })).replace(/\r\n/g, "\n");
      let boundary: number;
      while ((boundary = pending.indexOf("\n\n")) >= 0) {
        const frame = pending.slice(0, boundary).replace(/\r/g, "");
        pending = pending.slice(boundary + 2);
        const data = frame.split("\n").filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trim()).join("\n");
        if (data && data !== "[DONE]") {
          const error = eventOf(data);
          if (error) {
            if (limited) await markChatgptLimit().catch(() => {});
            return error;
          }
        }
      }
    }
    if (!completed) return fail("ChatGPT cortó el stream antes de response.completed.", { retryable: true });
    message.toolCalls = [...calls.values()].sort((a, b) => a.index - b.index).map((call) => ({ id: call.id || "call_" + randomUUID().slice(0, 8), name: call.name, arguments: validJson(call.arguments) }));
    message.stopReason = message.toolCalls.length ? "toolUse" : "stop";
    message.silenceMs = longest();
    noteSilence(model, message.silenceMs);
    await clearChatgptLimit().catch(() => {});
    return message;
  } catch {
    if (request.signal?.aborted) return { ...fail("Turno detenido."), stopReason: "aborted" };
    return fail(hard.signal.aborted ? "ChatGPT no terminó en " + Math.round(maxMs / 1000) + " s." : idle.signal.aborted ? "ChatGPT no respondió en " + Math.round(idleMs / 1000) + " s." : "No pude conectar con ChatGPT.", { retryable: true });
  } finally { stop(); clearTimeout(timer); }
};
