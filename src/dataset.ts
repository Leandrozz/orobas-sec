// De trayectorias exportadas (una línea JSON por sesión, ver src/trayectorias.ts) a ejemplos de
// entrenamiento en formato chat con herramientas: un ejemplo por turno del operador, con el prompt
// del sistema, su pedido y los pasos del modelo (llamadas, resultados, cierre). Los filtros dejan
// afuera lo que no conviene imitar: turnos cortados, con errores, o corregidos por el operador.

export interface DatasetOptions {
  /** Sólo sesiones con al menos un hallazgo verificado. */
  onlyVerified?: boolean;
  /** Dejar afuera los turnos con algún error de herramienta o de modelo (por defecto, sí). */
  dropErrors?: boolean;
  /** Dejar afuera los turnos que el operador corrigió después (por defecto, sí). */
  dropCorrected?: boolean;
  /** Dejar afuera los turnos cortados por el harness o detenidos (por defecto, sí). */
  dropCut?: boolean;
  /** Turnos anteriores de la misma sesión que viajan como contexto (sólo operador y respuesta final). */
  context?: number;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_calls?: Array<{ id: string; type: "function"; function: { name: string; arguments: string } }>;
  tool_call_id?: string;
  name?: string;
}

export interface Example {
  messages: ChatMessage[];
  meta: { session: string; turn: number; harness: string; model: string; project: string; tools: string[]; labels: Record<string, unknown> };
}

export type Reason = "ok" | "sin verificados" | "con errores" | "corregido" | "cortado" | "sin pasos";

type Turn = { operator: string; messages: Array<Record<string, any>>; labels: Record<string, any> };
type Record_ = { harness: string; project: string; sesion: { id: string; model: string }; system?: string; labels: Record<string, any>; turns: Turn[] };

/** Último texto del modelo en un turno: lo que el operador leyó. */
const finalAnswer = (turn: Turn) => [...turn.messages].reverse().find((m) => m.role === "assistant" && m.content)?.content as string | undefined;

export function buildExamples(record: Record_, options: DatasetOptions = {}): Array<{ example?: Example; reason: Reason }> {
  const { onlyVerified = false, dropErrors = true, dropCorrected = true, dropCut = true, context = 2 } = options;
  if (onlyVerified && !(record.labels?.findings?.verificados > 0)) return record.turns.map(() => ({ reason: "sin verificados" as Reason }));
  return record.turns.map((turn, index) => {
    const labels = turn.labels ?? {};
    if (dropCut && labels.end !== "respuesta") return { reason: "cortado" };
    if (dropErrors && (labels.errors ?? 0) > 0) return { reason: "con errores" };
    if (dropCorrected && labels.follow_up === "corrección") return { reason: "corregido" };
    const steps = turn.messages.filter((m) => m.role === "assistant" && m.by === "modelo");
    if (!steps.length) return { reason: "sin pasos" };
    const messages: ChatMessage[] = [];
    if (record.system) messages.push({ role: "system", content: record.system });
    for (const previous of record.turns.slice(Math.max(0, index - context), index)) {
      messages.push({ role: "user", content: previous.operator });
      const answer = finalAnswer(previous);
      if (answer) messages.push({ role: "assistant", content: answer });
    }
    messages.push({ role: "user", content: turn.operator });
    const tools = new Set<string>();
    for (const m of turn.messages) {
      if (m.role === "assistant") {
        if (m.by !== "modelo") continue; // el cierre que escribe el harness no es del modelo
        const calls = (m.tool_calls ?? []) as Array<{ id: string; name: string; arguments: unknown }>;
        for (const call of calls) tools.add(call.name);
        messages.push({
          role: "assistant", content: m.content ?? "",
          ...(calls.length ? { tool_calls: calls.map((call) => ({ id: call.id, type: "function" as const, function: { name: call.name, arguments: typeof call.arguments === "string" ? call.arguments : JSON.stringify(call.arguments) } })) } : {}),
        });
      } else if (m.role === "tool") messages.push({ role: "tool", tool_call_id: m.tool_call_id, name: m.name, content: m.content ?? "" });
      else if (m.role === "system_note" || m.role === "checkpoint") messages.push({ role: "user", content: m.content ?? "" });
    }
    return { reason: "ok", example: { messages, meta: { session: record.sesion.id, turn: index + 1, harness: record.harness, model: record.sesion.model, project: record.project, tools: [...tools], labels } } };
  });
}

export function buildDataset(lines: string[], options: DatasetOptions = {}): { examples: Example[]; dropped: Record<Reason, number> } {
  const examples: Example[] = [];
  const dropped: Record<Reason, number> = { ok: 0, "sin verificados": 0, "con errores": 0, corregido: 0, cortado: 0, "sin pasos": 0 };
  for (const line of lines) {
    if (!line.trim()) continue;
    for (const item of buildExamples(JSON.parse(line) as Record_, options)) {
      dropped[item.reason]++;
      if (item.example) examples.push(item.example);
    }
  }
  return { examples, dropped };
}
