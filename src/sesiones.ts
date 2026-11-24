// Sesiones del proyecto para la TUI y la CLI: lista con estado, detalle, renombrar y ramificar.
// Una sesión es la conversación con su gasto y sus hallazgos; retomarla la abre tal como quedó.
import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Ledger } from "./ledger.ts";
import { usd } from "./money.ts";
import { listSessions } from "./resumen.ts";
import { ScopeStore } from "./scope.ts";

export type SessionState = "en curso" | "interrumpida" | "abierta" | "guardada";

export interface SessionRow {
  id: string;
  title: string;
  startedAt: string;
  lastAt: string;
  messages: number;
  usd: string;
  requests: number;
  findings: number;
  state: SessionState;
  model: string;
  current: boolean;
}

/** «hace 5 min», «hace 3 h», «ayer», «hace 4 d», o la fecha. */
export function relative(iso: string, now = Date.now()): string {
  const ms = now - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return iso.slice(0, 16).replace("T", " ");
  const min = Math.round(ms / 60_000);
  if (min < 1) return "ahora";
  if (min < 60) return `hace ${min} min`;
  const h = Math.round(min / 60);
  if (h < 24) return `hace ${h} h`;
  const d = Math.round(h / 24);
  if (d === 1) return "ayer";
  if (d < 30) return `hace ${d} d`;
  return iso.slice(0, 10);
}

const firstText = (json: string | null): string => {
  if (!json) return "";
  try {
    const { content } = JSON.parse(json);
    return typeof content === "string" ? content : (content ?? []).find((part: { text?: string }) => part.text)?.text ?? "";
  } catch { return ""; }
};

const clean = (text: string, max: number) => text.replace(/\n\n<(memoria|alcance|canarios|cves_nuevos|gasto)>[\s\S]*$/, "").replace(/\s+/g, " ").trim().slice(0, max);

/** Estado de una sesión: la tiene abierta alguien, quedó un turno a medias, o está guardada. */
export function sessionState(db: DatabaseSync, id: string, live?: { running: boolean; interrupted: boolean }): SessionState {
  if (live?.running) return "en curso";
  if (live?.interrupted) return "interrumpida";
  if (live) return "abierta";
  const last = db.prepare("select type from events where session_id=? and type like 'turn.%' order by seq desc limit 1").get(id) as { type: string } | undefined;
  return last?.type === "turn.started" ? "interrumpida" : "guardada";
}

export function sessionRows(db: DatabaseSync, ledger: Ledger, live: (id: string) => { running: boolean; interrupted: boolean } | undefined, current?: string, limit = 40): SessionRow[] {
  db.exec("create table if not exists findings(id text primary key, json text not null)");
  const rows = db.prepare(`select s.id, s.started_at, s.model, s.title,
      (select count(*) from messages m where m.session_id=s.id and m.json like '%"role":"user"%' ) as users,
      (select count(*) from messages m where m.session_id=s.id) as n,
      (select json from messages m where m.session_id=s.id and m.json like '%"role":"user"%' order by seq limit 1) as first,
      (select max(at) from events e where e.session_id=s.id) as last_at,
      (select count(*) from findings f where f.json like '%"session":"' || s.id || '"%' or f.json like '%"sessionId":"' || s.id || '"%') as findings
    from sessions s order by coalesce((select max(at) from events e where e.session_id=s.id), s.started_at) desc limit ?`).all(limit) as Array<{ id: string; started_at: string; model: string; title: string | null; users: number; n: number; first: string | null; last_at: string | null; findings: number }>;
  return rows.map((r) => {
    const totals = ledger.totals(r.id);
    return {
      id: r.id, title: clean(r.title || firstText(r.first) || "", 80) || "(sin título)", startedAt: r.started_at, lastAt: r.last_at ?? r.started_at,
      messages: r.n, usd: usd(totals.knownPico), requests: totals.requests, findings: r.findings, state: sessionState(db, r.id, live(r.id)), model: r.model, current: r.id === current,
    };
  });
}

/** Una línea por sesión, con tabuladores: la TUI arma el menú con esto y la CLI lo muestra tal cual. */
export const encodeRows = (rows: SessionRow[]): string[] => rows.map((r) => [r.id, r.state, r.startedAt, r.lastAt, r.messages, r.usd, r.requests, r.findings, r.model, r.current ? "1" : "0", r.title].join("\t"));

export function decodeRows(lines: string[]): SessionRow[] {
  return lines.filter((l) => l.split("\t").length >= 11).map((l) => {
    const [id, state, startedAt, lastAt, messages, usd, requests, findings, model, current, ...title] = l.split("\t");
    return { id: id!, state: state as SessionState, startedAt: startedAt!, lastAt: lastAt!, messages: Number(messages), usd: usd!, requests: Number(requests), findings: Number(findings), model: model!, current: current === "1", title: title.join("\t") };
  });
}

/** Vista para la CLI (cyber sesiones). */
export function sessionsView(rows: SessionRow[]): string[] {
  if (!rows.length) return ["Todavía no hay sesiones en este proyecto."];
  return [
    "SESIONES · del proyecto, la más reciente primero",
    ...rows.map((r) => `${r.current ? "▶" : " "} ${r.id.slice(0, 8)}  ${r.state.padEnd(12)} ${relative(r.lastAt).padEnd(12)} ${String(r.messages).padStart(3)} msj  USD ${r.usd}  ${r.findings ? `${r.findings} hallazgo${r.findings === 1 ? "" : "s"}  ` : ""}${r.title.slice(0, 48)}`),
    "Retomar: cyber -s <id> · en la TUI: /sesiones",
  ];
}

/** Detalle de una sesión: lo que hace falta para decidir si retomarla. */
export function sessionDetail(db: DatabaseSync, ledger: Ledger, id: string, state: SessionState): string[] {
  const row = db.prepare("select id, started_at, model, title from sessions where id=?").get(id) as { id: string; started_at: string; model: string; title: string | null } | undefined;
  if (!row) throw new Error(`No existe la sesión ${id}`);
  const msgs = db.prepare("select json from messages where session_id=? order by seq").all(id) as Array<{ json: string }>;
  const parsed = msgs.map((m) => { try { return JSON.parse(m.json) as { role: string; content?: unknown }; } catch { return { role: "?" }; } });
  const text = (m: { content?: unknown } | undefined) => clean(typeof m?.content === "string" ? m.content : ((m?.content as Array<{ text?: string }> | undefined) ?? []).map((p) => p.text ?? "").join(" "), 300);
  const lastUser = parsed.findLast((m) => m.role === "user");
  const lastAssistant = parsed.findLast((m) => m.role === "assistant" && text(m));
  const totals = ledger.totals(id);
  const lastAt = (db.prepare("select max(at) at from events where session_id=?").get(id) as { at: string | null }).at ?? row.started_at;
  const findings = (db.prepare("select count(*) n from findings where json like ? or json like ?").get(`%"session":"${id}"%`, `%"sessionId":"${id}"%`) as { n: number }).n;
  // El alcance es de cada sesión: dice qué programa trabaja.
  const scope = new ScopeStore(db, id).current();
  return [
    `SESIÓN ${row.id.slice(0, 8)} · ${state}`,
    `${clean(row.title ?? "", 80) || "(sin título)"}`,
    `empezó ${row.started_at.slice(0, 16).replace("T", " ")} · última actividad ${relative(lastAt)} · modelo ${row.model.slice(row.model.indexOf("/") + 1)}`,
    `${parsed.length} mensajes · ${totals.requests} solicitudes · USD ${usd(totals.knownPico)}${findings ? ` · ${findings} hallazgo${findings === 1 ? "" : "s"}` : ""}`,
    `alcance: ${scope?.include.length ? `${scope.source} · ${scope.include.slice(0, 3).map((rule) => rule.value).join(", ")}${scope.include.length > 3 ? ", …" : ""}` : "sin definir"}`,
    ...(lastUser ? ["", `Vos: ${text(lastUser)}`] : []),
    ...(lastAssistant ? [`Orobas: ${text(lastAssistant)}`] : []),
  ];
}

export function renameSession(db: DatabaseSync, id: string, title: string): void {
  const value = clean(title, 80);
  if (!value) throw new Error("El título está vacío.");
  const result = db.prepare("update sessions set title=? where id=?").run(value, id);
  if (!result.changes) throw new Error(`No existe la sesión ${id}`);
}

/** Una sesión nueva que arranca con la conversación de otra (hasta ahora): para probar otro camino sin perder el original. */
export function forkSession(db: DatabaseSync, id: string): string {
  const source = db.prepare("select id, model, title from sessions where id=?").get(id) as { id: string; model: string; title: string | null } | undefined;
  if (!source) throw new Error(`No existe la sesión ${id}`);
  const fresh = randomUUID();
  const title = `↳ ${clean(source.title ?? "", 76) || source.id.slice(0, 8)}`;
  db.exec("begin");
  try {
    db.prepare("insert into sessions(id, started_at, model, title) values(?,?,?,?)").run(fresh, new Date().toISOString(), source.model, title);
    db.prepare("insert into messages(session_id, seq, json) select ?, seq, json from messages where session_id=? order by seq").run(fresh, id);
    db.exec("commit");
  } catch (error) { db.exec("rollback"); throw error; }
  // La rama sigue el mismo trabajo: hereda el alcance vigente de la sesión de la que sale (sólo ése).
  const parent = new ScopeStore(db, id);
  const scope = parent.current() ?? parent.recoverLegacy()?.recovered;
  if (scope) new ScopeStore(db, fresh).save(scope);
  return fresh;
}

/** Sesiones de todos los proyectos (para abrir otro proyecto desde acá). */
export const allProjectsRows = (): string[] => listSessions().map((s) => [s.projectId, s.ruta, s.nombre, s.session, s.fecha, s.estado, s.titulo].join("\t"));
