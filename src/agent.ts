// Bucle del agente, propio: solicitud → herramientas → solicitud, con reintentos,
// intervención del operador entre pasos, cancelación y reanudación tras una caída.
import { incoherenceMessage, readIncoherence } from "./coherencia.ts";
import type { AssistantMessage, Message, Model, ToolCall, ToolMessage, Transport } from "./llm.ts";

export interface ToolResult {
  text: string;
  isError?: boolean;
  /** Datos breves para la interfaz; no van al modelo. */
  details?: Record<string, unknown>;
  /**
   * De dónde viene el texto, si no es lo que dice el nombre de la herramienta (src/secretos-sesion.ts): una que
   * lee archivos dice «local» si leyó la máquina del operador y «objetivo» si leyó un artefacto del objetivo.
   */
  procedencia?: "objetivo" | "local";
}

export interface Tool {
  name: string;
  label: string;
  description: string;
  /** JSON Schema del objeto de argumentos. */
  parameters: object;
  /** Sólo lee: puede correr junto a otras llamadas del mismo paso. */
  parallel?: boolean;
  /** Mismo argumento ⇒ mismo resultado: una llamada repetida no se vuelve a ejecutar. */
  pure?: boolean;
  /** Qué hacer si el proceso murió durante la llamada. Por defecto no se repite. */
  replay?: "safe" | "never";
  execute(args: any, signal: AbortSignal): Promise<ToolResult> | ToolResult;
}

export type AgentEvent =
  /** `worker` identifica al subagente cuando el texto no es del agente principal. */
  | { type: "text"; delta: string; worker?: string }
  /** Llegó razonamiento previo del modelo: cuántos caracteres, acumulables. No se muestra, se cuenta. */
  | { type: "reasoning"; chars: number }
  /** Está por salir una solicitud al proveedor: se registra la intención antes de enviarla. */
  | { type: "request_start"; intent: string }
  /** Resultado de cada solicitud al proveedor, incluidos los intentos fallidos. Para contabilidad. */
  | { type: "request"; message: AssistantMessage; intent: string }
  | { type: "retry"; attempt: number; waitMs: number; reason: string }
  /** Los últimos pasos no aportaron nada nuevo. strikes acumulados y qué se detectó. */
  | { type: "stall"; strikes: number; reason: string }
  | { type: "message"; message: Message }
  /** `worker` identifica al subagente cuando la llamada no es del agente principal. */
  | { type: "tool_start"; id: string; name: string; label: string; worker?: string }
  | { type: "tool_end"; id: string; name: string; isError: boolean; text: string; details: Record<string, unknown>; worker?: string }
  | { type: "idle" };

/**
 * Campos de prosa: texto para personas (notas, resúmenes, motivos, títulos). Si se pasan del máximo
 * se recortan con «…» y se avisa en el resultado, en vez de rechazar la llamada entera. El criterio:
 * el nombre del campo está en esta lista, o su schema dice `truncate: true`; `truncate: false` lo
 * excluye aunque el nombre esté. Los campos con semántica (command, body, url, query, payloads, ids)
 * no están y siguen fallando: recortarlos cambiaría lo que se ejecuta.
 */
export const PROSE_FIELDS = new Set(["title", "titulo", "summary", "resumen", "note", "nota", "notes", "limits", "limites", "reason", "motivo", "causa", "description", "descripcion", "detail", "detalle", "comment", "comentario", "explanation", "explicacion"]);

export interface Trimmed {
  path: string;
  from: number;
  to: number;
}

const proseField = (key: string, schema: any) => schema?.type === "string" && typeof schema.maxLength === "number" && schema.truncate !== false && (schema.truncate === true || PROSE_FIELDS.has(key));

/** Recorta los campos de prosa que se pasan de su máximo. Devuelve los argumentos (copiados si cambió algo) y qué se recortó. */
export function fitProse(schema: any, value: unknown, path = "argumentos"): { value: unknown; trimmed: Trimmed[] } {
  const trimmed: Trimmed[] = [];
  const walk = (node: any, item: unknown, at: string): unknown => {
    if (node?.type === "object" && item && typeof item === "object" && !Array.isArray(item)) {
      let copy: Record<string, unknown> | undefined;
      for (const [key, child] of Object.entries(item)) {
        const property = node.properties?.[key];
        if (!property) continue;
        let next: unknown = child;
        if (proseField(key, property) && typeof child === "string" && child.length > property.maxLength) {
          next = `${child.slice(0, Math.max(0, property.maxLength - 1)).trimEnd()}…`;
          trimmed.push({ path: `${at}.${key}`, from: child.length, to: property.maxLength });
        } else next = walk(property, child, `${at}.${key}`);
        if (next !== child) (copy ??= { ...(item as Record<string, unknown>) })[key] = next;
      }
      return copy ?? item;
    }
    if (node?.type === "array" && Array.isArray(item) && node.items) {
      let changed = false;
      const items = item.map((child, index) => {
        const next = walk(node.items, child, `${at}[${index}]`);
        changed ||= next !== child;
        return next;
      });
      return changed ? items : item;
    }
    return item;
  };
  return { value: walk(schema, value, path), trimmed };
}

/** Aviso para el modelo cuando se recortó algo. */
export function trimNotice(trimmed: Trimmed[]): string {
  return `[aviso] Recorté ${trimmed.map((item) => `${item.path} a ${item.to} caracteres (tenía ${item.from})`).join(", ")}: quedó guardado con «…» al final. La próxima vez escribilo más corto; si lo que se cortó importa, resumilo y actualizalo.`;
}

/** Validación mínima de argumentos contra el subconjunto de JSON Schema que usan las herramientas. */
export function validate(schema: any, value: unknown, path = "argumentos"): string | undefined {
  const type = schema?.type;
  if (schema?.enum && !schema.enum.includes(value)) return `${path}: debe ser uno de ${schema.enum.join(", ")}`;
  if (type === "object") {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return `${path}: se esperaba un objeto`;
    for (const key of schema.required ?? []) if (!(key in value)) return `${path}: falta «${key}»`;
    for (const [key, item] of Object.entries(value)) {
      const error = schema.properties?.[key] && validate(schema.properties[key], item, `${path}.${key}`);
      if (error) return error;
    }
  } else if (type === "array") {
    if (!Array.isArray(value)) return `${path}: se esperaba una lista`;
    for (const [index, item] of value.entries()) {
      const error = schema.items && validate(schema.items, item, `${path}[${index}]`);
      if (error) return error;
    }
  } else if (type === "string") {
    if (typeof value !== "string") return `${path}: se esperaba texto`;
    if (schema.maxLength && value.length > schema.maxLength) return `${path}: máximo ${schema.maxLength} caracteres`;
  } else if (type === "integer" || type === "number") {
    if (typeof value !== "number" || (type === "integer" && !Number.isInteger(value))) return `${path}: se esperaba un número`;
    if (schema.minimum !== undefined && value < schema.minimum) return `${path}: mínimo ${schema.minimum}`;
    if (schema.maximum !== undefined && value > schema.maximum) return `${path}: máximo ${schema.maximum}`;
  } else if (type === "boolean" && typeof value !== "boolean") return `${path}: se esperaba verdadero o falso`;
  return undefined;
}

/** Espera que se corta al cancelar. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => (clearTimeout(timer), resolve()), { once: true });
  });
}

/**
 * El resultado de una herramienta, salvo que el turno se corte y ella no lo atienda: pasados `graceMs`
 * desde el corte, la llamada cierra con un resultado propio y lo que devuelva después se descarta.
 * Así un corte del operador nunca deja una llamada sin resultado ni el turno colgado.
 */
export function unlessAbandoned(work: Promise<ToolResult> | ToolResult, signal: AbortSignal, graceMs: number): Promise<ToolResult> {
  const pending = Promise.resolve(work);
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | undefined;
    const onAbort = () => {
      timer = setTimeout(() => resolve({ text: "Llamada cortada: el operador detuvo el turno y la herramienta no terminó a tiempo. Su efecto es desconocido: verificá el estado antes de repetirla.", isError: true, details: { cortada: true } }), graceMs);
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
    void pending.then(resolve, reject).finally(() => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
    });
  });
}

export interface AgentOptions {
  system: string;
  model: Model;
  tools: Tool[];
  transport: Transport;
  messages?: Message[];
  /** Antes de cada solicitud: presupuesto, compactación. Devolver un texto la bloquea con ese motivo. */
  prepare?: (signal: AbortSignal) => Promise<string | undefined> | string | undefined;
  /** Tope de solicitudes por mensaje del operador. */
  maxSteps?: number;
  /**
   * Al llegar al tope de pasos: devolver un texto sigue el turno con ese mensaje de sistema y otros
   * `maxSteps` pasos por delante; sin texto, el turno se corta como siempre. Quien lo implementa decide
   * si hubo avance y cuántas veces seguidas sigue.
   */
  onStepLimit?: (steps: number) => string | undefined;
  /**
   * Una herramienta que no atiende la cancelación no retiene el turno cortado: pasado este margen la
   * llamada cierra con un resultado propio («efecto desconocido»). Por defecto 3 s.
   */
  abortGraceMs?: number;
  /**
   * Un turno nunca termina en silencio: si se corta (tope de pasos, sin avance, error) o el modelo
   * termina sin escribirle al operador, se le pide un cierre de tres líneas; si tampoco puede, este
   * texto (lo arma el harness) queda como cierre.
   */
  closing?: (reason: string) => string;
  /** Reintentos ante fallas transitorias, con espera 1 s, 3 s, 9 s… */
  retries?: number;
  retryBaseMs?: number;
  /**
   * Plan B a la segunda falla transitoria seguida de una solicitud (sin respuesta, saturado, 5xx, corte,
   * salida incoherente): devuelve el modelo al que se pasó y el agente reintenta ya con ése; sin nada,
   * sigue reintentando con el mismo. Se usa una vez por solicitud.
   */
  fallback?: (reply: AssistantMessage) => Promise<string | undefined>;
  /** Pasos seguidos sin avance antes de cortar el turno. Al primero se avisa al modelo. Por defecto 3. */
  stallLimit?: number;
  /**
   * Cuando el modelo quiere terminar el turno (respuesta sin llamadas): devolver un texto lo manda
   * como mensaje de sistema y el turno sigue. Quien lo implementa limita cuántas veces objeta.
   */
  beforeEnd?: () => string | undefined;
  /**
   * Último paso de un resultado antes de entrar a la conversación (sólo de esta conversación: los subagentes
   * comparten las herramientas, no el historial). El motor lo usa para las relecturas idénticas.
   */
  alEntrar?: (nombre: string, resultado: ToolResult) => ToolResult;
}

/** Firma de un paso: qué se llamó y qué volvió. Dos pasos con la misma firma no aportan nada. */
function stepSignature(calls: ToolCall[], results: ToolMessage[]): { calls: string; outcome: string; allErrors: boolean; allRepeated: boolean } {
  const normalize = (call: ToolCall) => {
    try {
      return `${call.name}:${JSON.stringify(JSON.parse(call.arguments || "{}"), Object.keys(JSON.parse(call.arguments || "{}")).sort())}`;
    } catch {
      return `${call.name}:${call.arguments}`;
    }
  };
  return {
    calls: calls.map(normalize).sort().join("|"),
    // La nota de automejora acompaña al resultado para orientar al modelo, pero no cambia el resultado
    // de la herramienta a los ojos del detector de estancamiento ya existente.
    outcome: results.map((result) => `${result.isError ? "E" : "R"}:${result.content.split("\n[sistema][automejora]")[0]!.slice(0, 2000)}`).sort().join("|"),
    allErrors: results.length > 0 && results.every((result) => result.isError),
    allRepeated: results.length > 0 && results.every((result) => result.content.startsWith("Llamada idéntica")),
  };
}

export class Agent {
  readonly messages: Message[];
  readonly tools: Tool[];
  /** Prompt de sistema; el motor lo completa con el catálogo. */
  get system(): string {
    return this.options.system;
  }
  set system(value: string) {
    this.options.system = value;
  }
  model: Model;
  running = false;
  private options: AgentOptions;
  private listeners: Array<(event: AgentEvent) => void> = [];
  private steering: string[] = [];
  private controller: AbortController | undefined;
  /** Llamadas puras ya resueltas: nombre + argumentos. */
  private seen = new Set<string>();
  private recent: Array<ReturnType<typeof stepSignature>> = [];
  private strikes = 0;

  constructor(options: AgentOptions) {
    this.options = options;
    this.model = options.model;
    this.tools = options.tools;
    this.messages = options.messages ?? [];
  }

  on(listener: (event: AgentEvent) => void): void {
    this.listeners.push(listener);
  }

  private emit(event: AgentEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  /** Reenvía a los oyentes un evento de un subagente (con su `worker`). */
  relay(event: AgentEvent): void {
    this.emit(event);
  }

  private push(message: Message): void {
    this.messages.push(message);
    this.emit({ type: "message", message });
  }

  /** Mensaje del operador durante un turno: entra antes de la próxima solicitud. */
  steer(text: string): void {
    this.steering.push(text);
  }

  abort(): void {
    this.controller?.abort();
  }

  /** Olvida las llamadas puras ya vistas; hay que llamarlo cuando sus resultados salen del contexto. */
  forget(): void {
    this.seen.clear();
  }

  /** Llamadas del último mensaje del asistente que quedaron sin resultado. */
  private dangling(): ToolCall[] {
    const index = this.messages.findLastIndex((message) => message.role === "assistant");
    const last = this.messages[index];
    if (!last || last.role !== "assistant") return [];
    const answered = new Set(this.messages.slice(index + 1).flatMap((message) => (message.role === "tool" ? [message.toolCallId] : [])));
    return last.toolCalls.filter((call) => !answered.has(call.id));
  }

  /** Hay un turno a medio hacer: falta responder al operador o a una herramienta. */
  get unfinished(): boolean {
    const last = this.messages.at(-1);
    return !!last && (last.role === "user" || last.role === "tool" || this.dangling().length > 0);
  }

  prompt(text: string): Promise<void> {
    return this.turn(async () => this.push({ role: "user", content: text, at: Date.now() }));
  }

  /**
   * Retoma un turno interrumpido. Una herramienta sin resultado sólo se repite si es segura;
   * si no, queda como resultado desconocido y el modelo decide.
   */
  resume(): Promise<void> {
    return this.turn(async (signal) => {
      for (const call of this.dangling()) {
        const tool = this.tools.find((candidate) => candidate.name === call.name);
        if (tool?.replay === "safe") this.push(await this.run(call, signal));
        else {
          this.push({
            role: "tool",
            toolCallId: call.id,
            name: call.name,
            content: "Resultado desconocido: el proceso se interrumpió durante esta llamada y no se repitió automáticamente. Verificá el estado antes de repetirla.",
            isError: true,
            at: Date.now(),
          });
        }
      }
    });
  }

  private async turn(begin: (signal: AbortSignal) => Promise<void>): Promise<void> {
    if (this.running) throw new Error("El agente ya está trabajando; usar steer()");
    this.running = true;
    this.controller = new AbortController();
    const { signal } = this.controller;
    let ended = "";
    // Si el que falló fue el proveedor, pedirle el cierre al modelo fallaría igual: lo arma el harness.
    let providerFailed = false;
    try {
      await begin(signal);
      // Sin tope de pasos por defecto: cortan el presupuesto, la falta de avance y el operador (Esc).
      const maxSteps = this.options.maxSteps ?? Infinity;
      // Pasos del tramo en curso: una continuación automática arranca otro tramo de `maxSteps`.
      let from = 0;
      for (let step = 0; ; step++) {
        // Aviso cuando queda un cuarto de los pasos: que registre lo que tiene antes de que el turno se corte.
        if (Number.isFinite(maxSteps) && step - from === Math.floor(maxSteps * 0.75) && step > from) {
          this.push({ role: "user", content: `[sistema] Pasos: usaste ${step - from} de ${maxSteps} en este turno. Registrá ahora los candidatos y pistas que tengas (finding_record) y marcá la cobertura; después seguí si queda margen. Al llegar a ${maxSteps} el turno se corta.`, at: Date.now() });
        }
        if (step - from >= maxSteps) {
          const more = this.options.onStepLimit?.(step);
          if (more) {
            from = step;
            this.push({ role: "user", content: more, at: Date.now() });
          }
        }
        const blocked = step - from >= maxSteps ? "Límite de pasos por turno alcanzado." : await this.options.prepare?.(signal);
        // Lo que llegó mientras se preparaba la solicitud (el resultado de un encargo del router, un mensaje
        // del operador) entra ya, al final: el prefijo que el proveedor tiene en caché no cambia.
        if (!blocked) for (const queued of this.steering.splice(0)) this.push({ role: "user", content: queued, at: Date.now() });
        const reply = blocked ? this.refusal(blocked, step) : await this.request(signal);
        this.push(reply);
        if (reply.stopReason === "error" || reply.stopReason === "aborted") {
          ended = reply.errorMessage ?? "error del proveedor";
          providerFailed = !reply.requestId.startsWith("local:");
          break;
        }
        const results = await this.runAll(reply.toolCalls, signal);
        if (signal.aborted) break;
        const stalled = this.checkProgress(reply.toolCalls, results);
        if (stalled) {
          this.push(this.refusal(stalled, step));
          ended = stalled;
          break;
        }
        for (const queued of this.steering.splice(0)) this.push({ role: "user", content: queued, at: Date.now() });
        if (this.messages.at(-1)!.role === "assistant") {
          const objection = this.options.beforeEnd?.();
          if (!objection) break;
          this.push({ role: "user", content: objection, at: Date.now() });
        }
      }
      if (!signal.aborted && this.options.closing && this.silent()) await this.close(ended || "terminé sin escribirte", providerFailed, signal);
    } finally {
      this.steering.length = 0;
      this.recent = [];
      this.strikes = 0;
      this.running = false;
      this.emit({ type: "idle" });
    }
  }

  /** El turno no le dejó al operador un mensaje final con texto. */
  private silent(): boolean {
    const last = this.messages.findLast((message) => message.role === "assistant");
    return !last || last.role !== "assistant" || !last.content.trim() || last.toolCalls.length > 0 || last.stopReason === "error";
  }

  /** Cierre del turno: tres líneas del modelo o, si no puede, el texto que arma el harness. */
  private async close(reason: string, providerFailed: boolean, signal: AbortSignal): Promise<void> {
    // Sin presupuesto tampoco se gasta otra solicitud.
    if (!providerFailed && !/Presupuesto de sesión|Tope del proyecto/.test(reason)) {
      this.push({ role: "user", content: `[sistema] El turno terminó (${reason}). Escribile ahora al operador, en tres líneas como máximo y sin usar herramientas: qué hiciste, qué encontraste y qué sigue.`, at: Date.now() });
      const reply = await this.request(signal);
      if (reply.stopReason !== "error" && reply.stopReason !== "aborted" && reply.content.trim()) {
        this.push({ ...reply, toolCalls: [], stopReason: "stop" });
        return;
      }
    }
    const text = this.options.closing!(reason);
    this.push({ role: "assistant", content: text, toolCalls: [], stopReason: "stop", provider: "harness", model: "cierre", requestId: `local:cierre:${Date.now()}`, at: Date.now() });
  }

  /**
   * Detecta pasos que no aportan nada: mismas llamadas con el mismo resultado, sólo errores
   * repetidos o sólo llamadas ya hechas. Al primer strike avisa al modelo; al límite corta.
   */
  private checkProgress(calls: ToolCall[], results: ToolMessage[]): string | undefined {
    if (!calls.length) return undefined;
    const signature = stepSignature(calls, results);
    const previous = this.recent.at(-1);
    let reason: string | undefined;
    if (this.recent.some((old) => old.calls === signature.calls && old.outcome === signature.outcome)) reason = "las mismas llamadas devolvieron exactamente lo mismo que en un paso anterior";
    else if (signature.allRepeated) reason = "todas las llamadas del paso ya se habían hecho antes";
    else if (signature.allErrors && previous?.allErrors && previous.outcome === signature.outcome) reason = "se repite el mismo error sin cambiar nada";
    this.recent = [...this.recent.slice(-3), signature];
    if (!reason) {
      this.strikes = 0;
      return undefined;
    }
    this.strikes++;
    this.emit({ type: "stall", strikes: this.strikes, reason });
    const limit = this.options.stallLimit ?? 3;
    if (this.strikes >= limit) return `Turno cortado por falta de avance: ${reason} (${this.strikes} pasos seguidos).`;
    if (this.strikes === 1) {
      this.push({
        role: "user",
        content: `[sistema] Sin avance: ${reason}. No repitas la misma acción. Cambiá de enfoque, probá otra hipótesis o terminá el turno explicando qué te bloquea y qué haría falta.`,
        at: Date.now(),
      });
    }
    return undefined;
  }

  private refusal(reason: string, step: number): AssistantMessage {
    return { role: "assistant", content: "", toolCalls: [], stopReason: "error", errorMessage: reason, rejected: true, provider: this.model.provider, model: this.model.id, requestId: `local:bloqueada:${Date.now()}:${step}`, at: Date.now() };
  }

  /**
   * Una respuesta incoherente del modelo (restos de plantilla en los nombres, «$MISSING», escrituras
   * mezcladas) no entra al historial ni ejecuta nada: pasa a error reintentable, con el uso conservado
   * para la contabilidad. Si entrara, el modelo la releería en el turno siguiente y seguiría igual.
   */
  private screened(reply: AssistantMessage): AssistantMessage {
    if (reply.stopReason === "error" || reply.stopReason === "aborted") return reply;
    const reasons = readIncoherence(reply);
    if (!reasons.length) return reply;
    return { ...reply, content: "", toolCalls: [], stopReason: "error", errorMessage: incoherenceMessage(reasons), retryable: true, incoherent: true };
  }

  /** Una solicitud con reintentos. Cada intento se informa para la contabilidad. */
  private async request(signal: AbortSignal): Promise<AssistantMessage> {
    let switched = false;
    for (let attempt = 0; ; attempt++) {
      const intent = `pendiente:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`;
      this.emit({ type: "request_start", intent });
      const answered = await this.options.transport({
        model: this.model,
        system: this.options.system,
        messages: this.messages,
        tools: this.tools.map(({ name, description, parameters }) => ({ name, description, parameters })),
        signal,
        onText: (delta) => this.emit({ type: "text", delta }),
        onReasoning: (chars) => this.emit({ type: "reasoning", chars }),
      });
      const reply = this.screened(answered);
      this.emit({ type: "request", message: reply, intent });
      if (reply.stopReason !== "error" || !reply.retryable || attempt >= (this.options.retries ?? 3) || signal.aborted) return reply;
      // Si el servicio dijo cuánto esperar (Retry-After), se le hace caso, hasta 15 s; si no, 1 s · 3^intento.
      let waitMs = Math.min(reply.retryAfterMs ?? 0, 15_000) || (this.options.retryBaseMs ?? 1000) * 3 ** attempt;
      let reason = reply.errorMessage ?? "error";
      // A la segunda falla seguida no se insiste con el mismo modelo: otro, ya, si hay.
      if (attempt >= 1 && !switched && this.options.fallback) {
        const next = await this.options.fallback(reply);
        if (next) {
          switched = true;
          waitMs = 0;
          reason = `paso a ${next} · ${reason}`;
        }
      }
      this.emit({ type: "retry", attempt: attempt + 1, waitMs, reason });
      await sleep(waitMs, signal);
      if (signal.aborted) return { ...reply, stopReason: "aborted", errorMessage: "Turno detenido", requestId: `${reply.requestId}:corte` };
    }
  }

  /** Las llamadas de sólo lectura corren juntas; si alguna modifica estado, van en orden. */
  private async runAll(calls: ToolCall[], signal: AbortSignal): Promise<ToolMessage[]> {
    const together = calls.length > 1 && calls.every((call) => this.tools.find((tool) => tool.name === call.name)?.parallel);
    const results: ToolMessage[] = together ? await Promise.all(calls.map((call) => this.run(call, signal))) : [];
    if (together) for (const result of results) this.push(result);
    else {
      for (const call of calls) {
        const result = await this.run(call, signal);
        results.push(result);
        this.push(result);
      }
    }
    return results;
  }

  /** Cada llamada produce siempre un resultado, así el transcript queda válido tras un corte. */
  private async run(call: ToolCall, signal: AbortSignal): Promise<ToolMessage> {
    const tool = this.tools.find((candidate) => candidate.name === call.name);
    this.emit({ type: "tool_start", id: call.id, name: call.name, label: tool?.label ?? call.name });
    let result: ToolResult;
    let isError = false;
    let trimmed: Trimmed[] = [];
    try {
      if (signal.aborted) throw new Error("Cancelada antes de ejecutar");
      if (!tool) {
        let jsonError = "";
        try { JSON.parse(call.arguments || "{}"); } catch (error) { jsonError = (error as Error).message; }
        if (/[^\x21-\x7e]|\$/.test(call.name) || jsonError) {
          throw new Error(`La llamada salió malformada: nombre ${JSON.stringify(call.name)}. ${jsonError ? `Error al interpretar los argumentos JSON: ${jsonError}` : "El nombre contiene caracteres no permitidos; los argumentos JSON son válidos."}`);
        }
        throw new Error(`Herramienta desconocida: ${call.name}`);
      }
      // Un texto largo en un campo de prosa se recorta y se avisa; no tira la llamada.
      const fitted = fitProse(tool.parameters, JSON.parse(call.arguments || "{}"));
      trimmed = fitted.trimmed;
      const args = fitted.value as any;
      const invalid = validate(tool.parameters, args);
      if (invalid) throw new Error(invalid);
      const key = `${call.name}\n${JSON.stringify(args)}`;
      if (tool.pure && this.seen.has(key)) {
        result = { text: "Llamada idéntica a una anterior de esta conversación: el resultado ya está más arriba y no cambió. No la repitas.", details: { repetida: true } };
      } else {
        result = await unlessAbandoned(tool.execute(args, signal), signal, this.options.abortGraceMs ?? 3000);
        isError = result.isError === true;
        if (!isError && this.options.alEntrar) result = this.options.alEntrar(call.name, result);
        if (tool.pure) this.seen.add(key);
      }
    } catch (error) {
      isError = true;
      result = { text: (error as Error).message };
    }
    if (trimmed.length) result = { ...result, text: `${result.text}\n${trimNotice(trimmed)}`, details: { ...result.details, recortados: trimmed.map((item) => item.path) } };
    this.emit({ type: "tool_end", id: call.id, name: call.name, isError, text: result.text, details: result.details ?? {} });
    return { role: "tool", toolCallId: call.id, name: call.name, content: result.text, isError, at: Date.now() };
  }
}
