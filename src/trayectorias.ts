// Trayectorias: lo que hizo el agente en cada sesión, completo y tachado, para evaluar el harness y
// armar datos de entrenamiento. Sale de la base local del proyecto (mensajes con llamadas y resultados
// de herramientas, eventos, hallazgos con su veredicto final): una línea JSON por sesión, con sus turnos
// y etiquetas. Son parte de las trazas: en el modo «compartir» el motor sube la de cada sesión que usa
// la suscripción (anonimizada); en «local» la escribe en la carpeta de trazas; en «no», nada. Además la
// persona puede exportarlas a mano (cyber trayectorias) a la carpeta de informes.
import { cabecerasDePrivacidad, comparteConServicio } from "./privacidad-trazas.ts";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { Finding, Findings } from "./findings.ts";
import type { Ledger } from "./ledger.ts";
import { CLIENT_VERSION, type AssistantMessage, type Message, type ToolMessage } from "./llm.ts";
import { usd } from "./money.ts";
import { redactSecrets } from "./plataformas.ts";
import { ReportRedactor } from "./redact.ts";
import type { Scope } from "./scope.ts";

export interface TrajectoryOptions {
  /** Sesiones a exportar (ids o prefijos); vacío = todas. */
  sessions?: string[];
  /** Reemplaza los hosts del alcance por nombres neutros (host-1, host-2…) en todo el texto. */
  anonymize?: boolean;
  /**
   * Tachado adicional de la sesión viva (identidades y secretos, con la vista de trazas); se aplica antes del
   * tachado general. `de` dice quién escribió el texto: «operador», «modelo», «local» (el harness) o
   * «herramienta:<nombre>»; con eso la sesión sabe la procedencia de lo que aprende acá.
   */
  redact?: (text: string, de: string) => string;
  /** Largo máximo de cada resultado de herramienta. */
  maxToolChars?: number;
  /** El prompt del sistema vigente, para que la trayectoria se pueda reproducir. */
  system?: string;
}

export interface TrajectorySource {
  db: DatabaseSync;
  ledger: Ledger;
  findings: Findings;
  /** El alcance del proyecto entero (el de todas las sesiones junto): con él se anonimizan los hosts. */
  scope: Scope | undefined;
  /** El alcance de cada sesión, para su registro; sin esto va el del proyecto. */
  sessionScope?: (sessionId: string) => Scope | undefined;
}

/** Cómo siguió el operador después de un turno, inferido de su mensaje siguiente. */
export type FollowUp = "seguí" | "corrección" | "nuevo" | "fin";
export function followUp(next: string | undefined): FollowUp {
  if (next === undefined) return "fin";
  const text = next.trim().toLowerCase();
  if (/^(seg[uú][ií]|dale|continu[aá]|ok[,.]? seg|adelante|s[ií][,.]? seg)/u.test(text)) return "seguí";
  if (/^(no(?!\p{L})|mal(?!\p{L})|eso no|eso est[aá] mal|incorrecto|par[aá](?!\p{L})|fren[aá]|te equivoc|no es as[ií]|no era|est[aá]s equivocad)/u.test(text)) return "corrección";
  return "nuevo";
}

const SYSTEM_NOTE = /^\[sistema\]/;
const isOperator = (message: Message): message is Extract<Message, { role: "user" }> => message.role === "user" && !SYSTEM_NOTE.test(message.content);

function parseArgs(raw: string): unknown {
  try { return JSON.parse(raw); } catch { return raw; }
}

/**
 * Para los eventos de antes de msg_seq (columna NULL): el último mensaje de la sesión que ya existía a la hora
 * del evento, o undefined si el evento es anterior a todos. Cada mensaje lleva la hora en que entró a la
 * conversación, así que aproxima bien lo que hoy guarda msg_seq.
 */
function seqByTime(messages: Array<{ seq: number; message: Message }>): (at: number) => number | undefined {
  const points = messages
    .filter((row) => typeof row.message.at === "number")
    .map((row) => ({ at: row.message.at, seq: row.seq }))
    .sort((a, b) => a.at - b.at || a.seq - b.seq);
  // El seq más alto entre los mensajes que ya existían a cada hora, aunque las horas vengan desordenadas.
  const best: number[] = [];
  points.forEach((point, i) => best.push(i ? Math.max(best[i - 1]!, point.seq) : point.seq));
  return (at) => {
    if (Number.isNaN(at)) return undefined;
    let lo = 0, hi = points.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (points[mid]!.at <= at) lo = mid + 1;
      else hi = mid;
    }
    return lo ? best[lo - 1] : undefined;
  };
}

/**
 * Tacha cada texto por separado, no la línea entera ya serializada: un secreto aprendido puede empezar
 * dentro de un escape del JSON (`\"`), comerse la barra y dejar la línea sin parsear. Así la salida
 * siempre es JSON válido.
 */
function redactDeep<T>(value: T, redact: (text: string) => string): T {
  if (typeof value === "string") return redact(value) as T;
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, redact)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = redactDeep(item, redact);
    return out as T;
  }
  return value;
}

/** Las líneas JSONL (una por sesión), sin escribir nada. */
export function buildTrajectories(source: TrajectorySource, project: string, options: TrajectoryOptions = {}): { lines: string[]; sessions: number; turns: number } {
  const { db } = source;
  const maxTool = options.maxToolChars ?? 4000;
  const redactor = new ReportRedactor();
  const hosts = new Map<string, string>();
  if (options.anonymize) {
    const rules = [...(source.scope?.include ?? []), ...(source.scope?.exclude ?? [])];
    for (const rule of rules) {
      const host = rule.value.replace(/^https?:\/\//, "").replace(/^\*\./, "").split(/[/:]/)[0] ?? "";
      if (host && !/^\d+\.\d+\.\d+\.\d+/.test(host) && !hosts.has(host)) hosts.set(host, `host-${hosts.size + 1}`);
    }
  }
  const anon = (text: string) => {
    let out = text;
    for (const [host, alias] of [...hosts].sort((a, b) => b[0].length - a[0].length)) out = out.split(host).join(alias);
    return out;
  };
  const clean = (text: string, max = Infinity, de = "modelo") => {
    const once = redactor.text(options.redact ? options.redact(text, de) : text);
    const cut = once.length > max ? `${once.slice(0, max)}\n… [recortado: ${once.length - max} caracteres más]` : once;
    return anon(cut);
  };

  const sessions = (db.prepare("select id, started_at, model, title from sessions order by started_at").all() as Array<{ id: string; started_at: string; model: string; title: string | null }>)
    .filter((session) => !options.sessions?.length || options.sessions.some((wanted) => session.id.startsWith(wanted)));
  const allFindings = source.findings.list();
  const lines: string[] = [];
  let turnCount = 0;

  for (const session of sessions) {
    const messages = (db.prepare("select seq, json from messages where session_id=? order by seq").all(session.id) as Array<{ seq: number; json: string }>)
      .map((row) => ({ seq: row.seq, message: JSON.parse(row.json) as Message }));
    const seqAt = seqByTime(messages);
    const events = (db.prepare("select seq, type, at, payload, msg_seq from events where session_id=? order by seq").all(session.id) as Array<{ seq: number; type: string; at: string; payload: string; msg_seq: number | null }>)
      .map((event) => ({ ...event, msgSeq: event.msg_seq ?? seqAt(Date.parse(event.at)) }));
    const findings = allFindings.filter((item) => item.sessionId === session.id);
    const totals = source.ledger.totals(session.id);

    // Un turno empieza en cada mensaje del operador (los avisos [sistema] van en rol user, pero no abren turno).
    const starts = messages.map((row, index) => (isOperator(row.message) ? index : -1)).filter((index) => index >= 0);
    const turns = starts.map((start, i) => {
      const end = starts[i + 1] ?? messages.length;
      const slice = messages.slice(start, end);
      const operator = slice[0]!.message as Extract<Message, { role: "user" }>;
      const next = starts[i + 1] !== undefined ? (messages[starts[i + 1]!]!.message as Extract<Message, { role: "user" }>).content : undefined;
      type Item = Record<string, unknown> & { role: string; by?: string; is_error?: boolean; error?: string };
      const body: Item[] = slice.slice(1).map(({ message }): Item => {
        if (message.role === "assistant") {
          const m = message as AssistantMessage;
          return {
            role: "assistant", content: clean(m.content, Infinity, m.provider === "harness" ? "local" : "modelo"), tool_calls: m.toolCalls.map((call) => ({ id: call.id, name: call.name, arguments: parseArgs(clean(call.arguments)) })),
            stop_reason: m.stopReason, ...(m.errorMessage ? { error: clean(m.errorMessage, 300, "local") } : {}), by: m.provider === "harness" ? "harness" : "modelo", model: m.model,
            ...(m.usage ? { usage: m.usage } : {}), at: new Date(m.at).toISOString(),
          };
        }
        if (message.role === "tool") {
          const m = message as ToolMessage;
          return { role: "tool", tool_call_id: m.toolCallId, name: m.name, content: clean(String(m.content), maxTool, `herramienta:${m.name}`), is_error: m.isError, at: new Date(m.at).toISOString() };
        }
        if (message.role === "checkpoint") return { role: "checkpoint", content: clean(message.content), at: new Date(message.at).toISOString() };
        return { role: "system_note", content: clean(message.content, Infinity, "local"), at: new Date(message.at).toISOString() };
      });
      const steps = body.filter((item) => item.role === "assistant" && item.by === "modelo").length;
      const errors = body.filter((item) => (item.role === "tool" && item.is_error) || (item.role === "assistant" && "error" in item)).length;
      const last = [...body].reverse().find((item) => item.role === "assistant");
      const seqFrom = slice[0]!.seq, seqTo = slice.at(-1)!.seq;
      // msgSeq es un messages.seq de esta sesión; events.seq es de toda la base y no se compara con los mensajes.
      const inTurn = events.filter((event) => event.msgSeq !== undefined && event.msgSeq >= seqFrom && (end >= messages.length || event.msgSeq < messages[end]!.seq));
      const aborted = inTurn.some((event) => event.type === "turn.aborted");
      const changed = inTurn.filter((event) => event.type === "finding.changed").map((event) => { const p = JSON.parse(event.payload) as { id?: string; state?: string }; return { id: p.id, state: p.state }; });
      turnCount++;
      return {
        operator: clean(operator.content.replace(/\n\n<(memoria|alcance|verificacion|canarios|cves_nuevos|gasto)>[\s\S]*$/, ""), 4000, "operador"),
        at: new Date(operator.at).toISOString(),
        messages: body,
        labels: {
          steps, errors, end: aborted ? "detenido" : last?.by === "harness" ? "cierre-harness" : last ? "respuesta" : "sin respuesta",
          findings_changed: changed, follow_up: followUp(next), seq: [seqFrom, seqTo],
        },
      };
    });

    const verdicts = (states: Finding["state"][]) => findings.filter((item) => states.includes(item.state)).length;
    const record = {
      version: 1,
      harness: CLIENT_VERSION,
      exported_at: new Date().toISOString(),
      project: options.anonymize ? createHash("sha256").update(project).digest("hex").slice(0, 12) : project,
      // Ojo con los nombres de campo: el tachador final trata «session», «token» y parecidos como credenciales.
      sesion: { id: session.id, started_at: session.started_at, model: session.model, title: session.title ? clean(session.title, 200, "operador") : null },
      ...(options.system ? { system: options.system } : {}),
      scope: ((own) => (own ? { source: own.source, include: own.include.map((rule) => anon(rule.value)), exclude: own.exclude.map((rule) => anon(rule.value)) } : null))(source.sessionScope ? source.sessionScope(session.id) : source.scope),
      labels: {
        turns: turns.length,
        cut_by_harness: turns.filter((turn) => turn.labels.end === "cierre-harness").length,
        aborted: turns.filter((turn) => turn.labels.end === "detenido").length,
        findings: { verificados: verdicts(["verificado"]), descartados: verdicts(["descartado"]), candidatos: verdicts(["candidato"]), pistas: verdicts(["pista"]) },
        verifier: {
          confirmed: findings.filter((item) => item.decidedBy.startsWith("verificador") && item.state === "verificado").length,
          rejected: findings.filter((item) => item.decidedBy.startsWith("verificador") && item.state === "descartado").length,
        },
        requests: totals.requests,
        consumo: totals.tokens,
        cost_usd: usd(totals.knownPico, 6),
        cost_unknown_requests: totals.unknownRequests,
        http: Object.fromEntries(events.filter((event) => event.type === "http.turno").map((event, i) => [i, JSON.parse(event.payload) as unknown])),
      },
      findings: findings.map((item) => ({
        id: item.id, state: item.state, title: clean(item.title, 200), kind: item.kind, severity: item.severity, asset: clean(item.asset, 300),
        summary: clean(item.summary, 1500), decided_by: item.decidedBy, reason: clean(item.reason, 500), evidence: item.evidence.length,
      })),
      turns,
    };
    lines.push(JSON.stringify(redactDeep(record, (text) => redactSecrets(redactor.finish(text)))));
  }

  return { lines, sessions: sessions.length, turns: turnCount };
}

export function exportTrajectories(source: TrajectorySource, project: string, dir: string, options: TrajectoryOptions = {}): { path: string; sessions: number; turns: number; bytes: number } {
  const { lines, sessions, turns } = buildTrajectories(source, project, options);
  mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const path = join(dir, `trayectorias-${stamp}${options.anonymize ? "-anonimo" : ""}.jsonl`);
  const content = lines.length ? `${lines.join("\n")}\n` : "";
  writeFileSync(path, content);
  return { path, sessions, turns, bytes: Buffer.byteLength(content) };
}

/** Líneas para el operador. */
export function trajectoriesLines(result: ReturnType<typeof exportTrajectories>, anonymized: boolean): string[] {
  return [
    `TRAYECTORIAS · ${result.sessions} sesión${result.sessions === 1 ? "" : "es"} · ${result.turns} turno${result.turns === 1 ? "" : "s"} · ${(result.bytes / 1024).toFixed(1)} kB`,
    `Archivo: ${result.path}`,
    anonymized ? "Hosts del alcance reemplazados por host-1, host-2…; credenciales e identidades tachadas." : "Credenciales e identidades tachadas; los hosts quedan tal cual (anonimizar: /trayectorias anonimo).",
    "Una línea JSON por sesión: mensajes con llamadas y resultados de herramientas, hallazgos con veredicto final y etiquetas por turno. Este archivo no sale de tu máquina; lo que se comparte depende del modo de trazas (/datos).",
  ];
}

/* ---------- Compartir con el servicio ---------- */

export const SHARE_KIND = "trayectorias";
export const SHARE_SENTENCE = "Comparto con Elevate AI las trazas de este proyecto (pedidos y respuestas, turnos, trayectorias anonimizadas y la cita de los consentimientos), con las credenciales tachadas, para evaluar y entrenar el agente. Puedo cambiarlo cuando quiera con /datos.";

/**
 * Sube cada sesión exportada (una línea JSON) a POST /v1/trayectorias. Falla por sesión, no todo junto.
 * Sólo en «compartir»: en «local» o «no» no sale nada (el servicio igual las rechazaría).
 */
export async function shareTrajectories(lines: string[], options: { apiKey: string; consentHash?: string; base?: string; fetchImpl?: typeof fetch }): Promise<{ sent: number; failed: number; errors: string[] }> {
  if (!comparteConServicio()) return { sent: 0, failed: 0, errors: [] };
  const base = (options.base ?? process.env.OROBAS_BASE_URL ?? "https://cyber.elevateai.ar/api/v1").replace(/\/$/, "");
  const fetchImpl = options.fetchImpl ?? fetch;
  let sent = 0;
  const errors: string[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const record = JSON.parse(line) as { sesion?: { id?: string } };
    try {
      const response = await fetchImpl(`${base}/trayectorias`, {
        method: "POST",
        headers: { ...cabecerasDePrivacidad(), accept: "application/json", "content-type": "application/json", authorization: `Bearer ${options.apiKey}` },
        body: JSON.stringify({ session: record.sesion?.id ?? "", client: CLIENT_VERSION, ...(options.consentHash ? { consent: options.consentHash } : {}), record }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}${response.headers.get("x-request-id") ? ` · pedido ${response.headers.get("x-request-id")}` : ""}`);
      sent++;
    } catch (error) {
      errors.push(`${record.sesion?.id?.slice(0, 8) ?? "?"}: ${(error as Error).message.slice(0, 160)}`);
    }
  }
  return { sent, failed: errors.length, errors };
}

