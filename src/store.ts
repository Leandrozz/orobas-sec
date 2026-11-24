// Base operativa local del proyecto: sesiones, mensajes, solicitudes de API, eventos,
// índice de memoria (reconstruible) y catálogo de artefactos.
import { mkdirSync } from "node:fs";
import { dataDir, hostPath, projectId } from "./datos.ts";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const SCHEMA = `
create table if not exists meta(key text primary key, value text not null);
create table if not exists sessions(
  id text primary key, started_at text not null, model text not null, title text);
create table if not exists messages(
  session_id text not null, seq integer not null, json text not null,
  primary key(session_id, seq));
create table if not exists requests(
  provider text not null, account text not null, request_id text not null,
  session_id text not null, worker text not null, model text not null, at text not null,
  stop_reason text not null,
  input integer, cache_read integer, cache_write integer, output integer, reasoning integer,
  price_json text, cost_input text, cost_cache_read text, cost_cache_write text, cost_output text,
  provider_cost text,
  primary key(provider, account, request_id));
create index if not exists requests_session on requests(session_id);
create table if not exists events(
  seq integer primary key autoincrement, session_id text, type text not null,
  at text not null, payload text not null, msg_seq integer);
create table if not exists memory(
  id text primary key, rev integer not null, type text not null, state text not null,
  title text not null, summary text not null, hash text not null, observed_at text not null);
create virtual table if not exists memory_fts using fts5(
  id unindexed, title, summary, body, tags, tokenize='unicode61 remove_diacritics 2');
create table if not exists memory_links(
  from_id text not null, to_id text not null, rel text not null, primary key(from_id, to_id, rel));
create table if not exists artifacts(
  hash text primary key, bytes integer not null, media_type text not null,
  producer text not null, created_at text not null);
`;

export interface Paths {
  root: string;
  db: string;
  records: string;
  notes: string;
  artifacts: string;
  /** Exportaciones (informes, uso): lo único que se escribe en la carpeta del proyecto. */
  exports: string;
  /** Trazas en modo «local»: el material de entrenamiento que no sale de la PC (trazas-locales.ts). */
  trazas: string;
}

export function projectPaths(cwd: string): Paths {
  const root = join(dataDir(), "proyectos", projectId(hostPath(cwd)));
  return {
    root,
    db: join(root, "cyber.db"),
    records: join(root, "memory", "records"),
    notes: join(root, "memory", "notes"),
    artifacts: join(root, "artifacts", "sha256"),
    exports: join(cwd, "cyber-informes"),
    trazas: join(root, "trazas"),
  };
}

export function openStore(paths: Paths): DatabaseSync {
  for (const dir of [paths.root, paths.records, paths.notes, paths.artifacts]) mkdirSync(dir, { recursive: true });
  const db = new DatabaseSync(paths.db);
  db.exec("pragma journal_mode=WAL; pragma synchronous=NORMAL; pragma busy_timeout=5000;");
  db.exec(SCHEMA);
  migrate(db);
  return db;
}

/**
 * events.seq es un autoincremental de toda la base y messages.seq va por sesión: no se pueden comparar.
 * msg_seq guarda el último messages.seq de la sesión al registrar el evento, para ubicarlo en su turno.
 * Las filas de antes quedan con msg_seq NULL (las trayectorias las ubican por hora).
 */
function migrate(db: DatabaseSync): void {
  const columns = db.prepare("pragma table_info(events)").all() as Array<{ name: string }>;
  if (columns.some((column) => column.name === "msg_seq")) return;
  try {
    db.exec("alter table events add column msg_seq integer");
  } catch (error) {
    if (!/duplicate column/i.test((error as Error).message)) throw error; // otra conexión la agregó recién
  }
}

/** Último mensaje guardado de la sesión (el parámetro es el session_id); NULL si no hay ninguno. */
export const LAST_MSG_SEQ = "(select max(seq) from messages where session_id=?)";

/**
 * msgSeq: el último messages.seq de la sesión cuando pasó el evento (null: todavía no hay mensajes).
 * Sin pasarlo, se toma de la base en el mismo insert: el motor guarda cada mensaje antes de seguir.
 */
export function logEvent(db: DatabaseSync, sessionId: string | null, type: string, payload: unknown, msgSeq?: number | null): void {
  const at = new Date().toISOString();
  const json = JSON.stringify(payload);
  if (msgSeq !== undefined) {
    db.prepare("insert into events(session_id,type,at,payload,msg_seq) values(?,?,?,?,?)").run(sessionId, type, at, json, msgSeq);
    return;
  }
  db.prepare(`insert into events(session_id,type,at,payload,msg_seq) values(?,?,?,?,${LAST_MSG_SEQ})`).run(sessionId, type, at, json, sessionId);
}
