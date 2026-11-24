// Dieta de contexto. Cada paso del agente relee todo el historial, y lo que más pesa son las salidas de
// herramientas que ya cumplieron su función (artefactos leídos, shell, HTTP): en noviembre, el 70 % del
// gasto fue releer historial desde la caché. Cuando el contexto pasa un umbral, las salidas largas que no
// están entre las más recientes viajan al modelo resumidas: una línea de qué fue, el inicio del texto,
// los ids de evidencia que nombraba y el artefacto con el original, que el agente relee con
// artifact_read si lo necesita. Lo guardado no cambia: sólo lo que se envía.
//
// Caché de prompts: el proveedor cobra a precio de caché (~10 % de la entrada) el prefijo que ya vio, y
// completo todo lo que viene después del primer byte distinto. Si la frontera avanzara un mensaje por
// paso, cada paso cambiaría un mensaje del medio y se cobraría entero lo posterior. Por eso avanza por
// tandas: un checkpoint resume de una vez todo lo viejo, sólo si ahorra bastante, y la vista queda
// idéntica byte a byte hasta el próximo checkpoint (el texto resumido sale sólo del mensaje original y
// de su llamada, y el artefacto es por contenido, así que se rehace igual al retomar la sesión).
import type { Message, ToolCall, ToolMessage } from "./llm.ts";

/** Salidas de herramientas que siempre van literales: las más recientes. */
export const DIET_KEEP = 8;
/** Una salida más corta que esto no se resume: ahorraría poco. */
export const DIET_MIN_CHARS = 1500;
/** Un checkpoint tiene que ahorrar al menos esto (≈10k tokens); si no, romper la caché no paga. */
export const DIET_MIN_SAVING = 40_000;
/** Inicio del texto original que queda en el resumen. */
const HEAD_CHARS = 300;
/** Tamaño aproximado de un resumen, para estimar el ahorro sin escribir artefactos. */
const MASKED_ESTIMATE = HEAD_CHARS + 400;

/**
 * Herramientas cuya salida no se resume: instrucciones (habilidades, herramientas cargadas), síntesis
 * que no se recupera releyendo un artefacto (informes de subagentes, el modelo fuerte) y el estado de
 * hallazgos y cobertura que el agente y la verificación necesitan a la vista.
 */
const ALWAYS_LITERAL = new Set(["skill_load", "tools_load", "help_search", "delegate", "deep_reason", "finding_record", "finding_update", "finding_list", "coverage_view", "coverage_mark", "session_settings"]);

export const maskable = (message: Message): message is ToolMessage =>
  message.role === "tool" && message.content.length > DIET_MIN_CHARS && !ALWAYS_LITERAL.has(message.name) && !isMasked(message.content);

const MARK = "[resumido para ahorrar contexto]";
const isMasked = (text: string) => text.startsWith(MARK);

export interface DietPlan {
  /** Seq desde el que las salidas van literales. */
  boundary: number;
  /** Salidas que el checkpoint resume. */
  count: number;
  /** Caracteres que se dejan de enviar, estimados. */
  saved: number;
  /** Caracteres desde el primer mensaje resumido hasta el final, ya resumidos: lo que se reenvía sin caché. */
  after: number;
}

/** Caracteres de un mensaje como viaja (texto y argumentos de las llamadas). */
const sizeOf = (message: Message): number =>
  message.content.length + (message.role === "assistant" ? message.toolCalls.reduce((sum, call) => sum + call.name.length + call.arguments.length, 0) : 0);

export class ContextDiet {
  /** Las salidas largas con seq menor que esto viajan resumidas; -1 = ninguna. Sólo avanza. */
  boundary = -1;
  /** Texto resumido por seq: se arma una vez y queda igual. */
  private readonly texts = new Map<number, string>();
  /** Guarda el texto original como artefacto y devuelve su hash. */
  private readonly save: (text: string, tool: string) => string;
  /** Vista del modelo de un texto; `herramienta`: la que lo produjo (sin ella, lo escribió el modelo). */
  private readonly vista: (text: string, herramienta?: string) => string;
  private readonly keep: number;
  private readonly minSaving: number;

  constructor(save: (text: string, tool: string) => string, options: { keep?: number; minSaving?: number; vista?: (text: string, herramienta?: string) => string } = {}) {
    this.save = save;
    this.vista = options.vista ?? ((text) => text);
    this.keep = options.keep ?? DIET_KEEP;
    this.minSaving = options.minSaving ?? DIET_MIN_SAVING;
  }

  /**
   * ¿Conviene un checkpoint ahora? La frontera nueva deja literales las últimas `keep` salidas; el
   * checkpoint vale sólo si lo que resume suma al menos `minSaving` caracteres. Con tarifas conocidas el
   * motor pasa 0 y decide por economía (src/economia-contexto.ts).
   */
  plan(messages: Message[], seqs: number[], minSaving = this.minSaving): DietPlan | undefined {
    if (seqs.length !== messages.length) return undefined;
    const tools = messages.flatMap((message, index) => (message.role === "tool" ? [index] : []));
    if (tools.length <= this.keep) return undefined;
    const boundary = seqs[tools[tools.length - this.keep]!]!;
    if (boundary <= this.boundary) return undefined;
    let saved = 0;
    let count = 0;
    let first = -1;
    for (const index of tools) {
      const seq = seqs[index]!;
      if (seq >= boundary) break;
      const message = messages[index]!;
      if (seq < this.boundary || !maskable(message)) continue;
      saved += Math.max(0, message.content.length - MASKED_ESTIMATE);
      count++;
      if (first < 0) first = index;
    }
    if (!count || saved < minSaving) return undefined;
    let after = 0;
    for (let index = first; index < messages.length; index++) {
      const message = messages[index]!;
      const masked = seqs[index]! < boundary && seqs[index]! >= this.boundary && maskable(message);
      after += masked ? MASKED_ESTIMATE : sizeOf(message);
    }
    return { boundary, count, saved, after };
  }

  /** Fija la frontera de un checkpoint. Nunca retrocede: lo ya resumido sigue igual. */
  advance(boundary: number): void {
    if (boundary > this.boundary) this.boundary = boundary;
  }

  /** Lo que se envía al modelo: los mismos mensajes, con las salidas viejas y largas resumidas. */
  view(messages: Message[], seqs: number[]): Message[] {
    if (this.boundary < 0 || seqs.length !== messages.length) return messages;
    // La llamada de cada resultado está en el último mensaje del asistente antes de él (hay proveedores
    // que repiten ids como «call_0» en cada respuesta: un índice global los mezclaría).
    let calls: ToolCall[] = [];
    return messages.map((message, index) => {
      if (message.role === "assistant") calls = message.toolCalls;
      const seq = seqs[index]!;
      if (seq >= this.boundary || !maskable(message)) return message;
      let text = this.texts.get(seq);
      if (text === undefined) {
        text = this.mask(message, calls.find((call) => call.id === message.toolCallId));
        this.texts.set(seq, text);
      }
      return { ...message, content: text };
    });
  }

  /** Resumen determinista de una salida: qué fue, cómo empezaba, qué evidencia nombraba y dónde está entera. */
  private mask(message: ToolMessage, call: ToolCall | undefined): string {
    const original = message.content;
    // Una salida que la herramienta ya truncó nombra el artefacto con el original completo: ése es el bueno.
    const full = /Completa en (sha256:[0-9a-f]{64})/.exec(original)?.[1] ?? this.save(original, message.name);
    let args = "";
    if (call) {
      try { args = JSON.stringify(JSON.parse(call.arguments || "{}")); } catch { args = call.arguments; }
      args = this.vista(args);
      args = args === "{}" ? "" : ` ${args.length > 160 ? `${args.slice(0, 160)}…` : args}`;
    }
    const exchanges = [...new Set([...original.matchAll(/(?:^|\n)\s*(h\d+)\s/g)].map((match) => match[1]!))];
    const hashes = [...new Set(original.match(/sha256:[0-9a-f]{64}/g) ?? [])].filter((hash) => hash !== full);
    const evidence = [...exchanges.slice(0, 12), ...(exchanges.length > 12 ? [`… ${exchanges.length - 12} más`] : []), ...hashes.slice(0, 4)];
    const head = this.vista(original, message.name).slice(0, HEAD_CHARS).replace(/\s+/g, " ").trim();
    return [
      `${MARK} ${message.name}${args} → ${original.length} caracteres${message.isError ? ", error" : ""}.`,
      `Inicio: ${head}…`,
      ...(evidence.length ? [`Evidencia que nombraba: ${evidence.join(", ")}`] : []),
      `Completa en ${full}: releela con artifact_read (filter, search o at) sólo si la necesitás.`,
    ].join("\n");
  }
}
