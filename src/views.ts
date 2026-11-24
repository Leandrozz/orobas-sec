import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
// Vistas de texto compartidas por la TUI y el CLI. Sin llamadas al modelo.
import type { DatabaseSync } from "node:sqlite";
import type { Artifacts } from "./artifacts.ts";
import { encode } from "@toon-format/toon";
import { sameScope, type ScopeTag, scopeTagLabel } from "./scope.ts";
import type { MemoryHit, Vault } from "./vault.ts";
import { BUCKETS, type Bucket, type Ledger, type Totals } from "./ledger.ts";
import { kTokens, usd } from "./money.ts";
import { shown } from "./datos.ts";

/** Lo que necesitan las vistas de proyecto; un Engine lo cumple. */
export interface ProjectView {
  db: DatabaseSync;
  vault: Vault;
  artifacts: Artifacts;
}

const LABELS: Record<Bucket, string> = {
  input: "Entrada sin caché",
  cacheRead: "Lectura de caché",
  cacheWrite: "Escritura de caché",
  output: "Salida",
};

const pending = (totals: Totals) =>
  totals.unknownRequests ? ` +${totals.unknownRequests} pend.` : "";

export function costLine(ledger: Ledger, sessionId: string): string {
  const session = ledger.totals(sessionId);
  const project = ledger.totals();
  const budget = ledger.budgetPico === undefined ? "sin tope" : `tope ${usd(ledger.budgetPico, 2)}`;
  return `API est. USD ${usd(session.knownPico)}${pending(session)} / ${budget} · proyecto ${usd(project.knownPico)}${pending(project)}`;
}

export function usageLine(ledger: Ledger, sessionId: string): string {
  const { tokens, requests } = ledger.totals(sessionId);
  const used = BUCKETS.reduce((sum, bucket) => sum + tokens[bucket], 0);
  return `Contexto ${kTokens(ledger.contextTokens(sessionId))} · uso ${kTokens(used)} tokens · ${requests} solicitudes`;
}

export function costDetail(ledger: Ledger, sessionId: string, project: string): string[] {
  const session = ledger.totals(sessionId);
  const all = ledger.totals();
  const lines = [
    "COSTO API ESTIMADO · USD",
    `Sesión actual      USD ${usd(session.knownPico, 6)}   ${session.requests} solicitudes únicas`,
    `Proyecto ${project.slice(0, 9).padEnd(9)} USD ${usd(all.knownPico, 6)}   ${all.requests} solicitudes, incluye esta sesión`,
    ledger.budgetPico === undefined
      ? "Tope de sesión     sin tope"
      : `Tope de sesión     USD ${usd(ledger.budgetPico, 2)}       corta antes de la próxima solicitud`,
    "",
    "CATEGORÍA            TOKENS      SUBTOTAL USD",
    ...BUCKETS.map(
      (bucket) => `${LABELS[bucket].padEnd(21)}${String(session.tokens[bucket]).padEnd(12)}${usd(session.costs[bucket], 6)}`,
    ),
  ];
  if (session.unknownRequests) {
    lines.push("", `${session.unknownRequests} solicitudes con uso o precio sin determinar: no están incluidas ni cuentan como cero.`);
  }
  const models = ledger.db
    .prepare("select model, worker, count(*) n from requests where session_id=? group by model, worker")
    .all(sessionId) as Array<{ model: string; worker: string; n: number }>;
  if (models.length) lines.push("", `Modelos: ${models.map((row) => `${row.model} ×${row.n}${row.worker === "principal" ? "" : ` (${row.worker})`}`).join(", ")}`);
  lines.push(
    "Tarifa aplicada guardada por solicitud. Estimación sin impuestos;",
    "la facturación real se concilia con el proveedor.",
  );
  return lines;
}

/**
 * La memoria del proyecto para el operador: todas las notas, cada una con el programa donde nació. Con
 * la sesión adjunta (`current`), lo que no es de su programa va marcado «otro programa»: el agente no lo
 * recibe solo. Con el id exacto de una nota, la nota completa.
 */
export function memoryView(engine: Pick<ProjectView, "db" | "vault">, query: string, current?: ScopeTag): string[] {
  const exact = /^[a-z0-9][a-z0-9-]*$/.test(query.trim()) ? engine.vault.read(query.trim()) : undefined;
  if (exact) {
    const { record } = exact;
    const mark = current && !sameScope(record.scope, current) ? "otro programa · " : "";
    const { scope: _scope, ...rest } = record;
    return [`MEMORIA · ${record.id} · ${mark}${scopeTagLabel(record.scope)}`, ...encode(rest).split("\n")];
  }
  const hits: MemoryHit[] = query
    ? engine.vault.search(query, 8)
    : engine.vault.recent(8);
  if (!hits.length) return [query ? `Sin resultados para «${query}».` : "La memoria del proyecto está vacía."];
  const where = (hit: MemoryHit) => `${current && !sameScope(hit.scope, current) ? "otro programa · " : ""}${scopeTagLabel(hit.scope)}`;
  return [
    query ? `MEMORIA · «${query}»` : `MEMORIA · ${engine.vault.count()} notas · últimas`,
    ...hits.flatMap((hit) => [
      `${hit.id}  rev ${hit.rev} · ${hit.type}${hit.state === "vigente" ? "" : ` · ${hit.state}`} · ${where(hit)}`,
      `  ${hit.title}: ${hit.summary}`,
    ]),
  ];
}

export function evidenceView(engine: ProjectView, hash: string): string[] {
  if (!hash) {
    const rows = engine.db
      .prepare("select hash,bytes,producer,created_at from artifacts order by created_at desc limit 8")
      .all() as Array<{ hash: string; bytes: number; producer: string; created_at: string }>;
    if (!rows.length) return ["Todavía no hay artefactos guardados."];
    return ["EVIDENCIA · artefactos recientes", ...rows.map((row) => `${row.hash.slice(7, 19)}  ${String(row.bytes).padStart(7)} B  ${row.producer}`)];
  }
  const lines = engine.artifacts.read(hash).toString("utf8").split(/\r?\n/);
  return [`EVIDENCIA · ${engine.artifacts.resolve(hash)}`, ...lines.slice(0, 24), ...(lines.length > 24 ? [`… ${lines.length - 24} líneas más`] : [])];
}

/** Sesiones del proyecto como trabajos: estado, modelo y gasto. */
export function jobsView(db: DatabaseSync, ledger: Ledger, state: (sessionId: string) => string): string[] {
  const rows = db.prepare("select id,started_at,model,title from sessions order by started_at desc limit 12").all() as Array<{ id: string; started_at: string; model: string; title: string | null }>;
  if (!rows.length) return ["Todavía no hay sesiones en este proyecto."];
  return [
    "TRABAJOS · sesiones del proyecto",
    ...rows.map((row) => {
      const totals = ledger.totals(row.id);
      return `${row.id.slice(0, 8)}  ${state(row.id).padEnd(12)} ${row.started_at.slice(0, 16).replace("T", " ")}  USD ${usd(totals.knownPico)}${pending(totals)}  ${totals.requests} sol.  ${(row.title ?? "").slice(0, 26)}`;
    }),
    "Retomar una: cyber -s <id>",
  ];
}


/**
 * Todo el uso del proyecto, para mirar y para enviar: sesiones, cada solicitud al modelo con sus
 * tokens y costo, eventos del harness, hallazgos y artefactos. Sin contenido de mensajes ni secretos.
 * Escribe cyber-informes/uso-<fecha>.json y devuelve un resumen por sesión.
 */
export function usageExport(ledger: Ledger, project: string, cwd: string): string[] {
  const db = ledger.db;
  // Un proyecto sin hallazgos todavía no tiene la tabla: la crea Findings al primer uso.
  db.exec("create table if not exists findings(id text primary key, json text not null)");
  const sessions = db.prepare("select id, started_at, model, title from sessions order by started_at").all() as Array<{ id: string; started_at: string; model: string; title: string | null }>;
  const requests = db
    .prepare("select session_id, worker, model, at, stop_reason, input, cache_read, cache_write, output, reasoning, cost_input, cost_cache_read, cost_cache_write, cost_output, request_id from requests order by at")
    .all() as Array<Record<string, unknown>>;
  const events = db.prepare("select session_id, type, count(*) n from events group by session_id, type").all() as Array<{ session_id: string | null; type: string; n: number }>;
  const findings = db.prepare("select json from findings").all() as Array<{ json: string }>;
  const artifacts = db.prepare("select producer, count(*) n, sum(bytes) bytes from artifacts group by producer").all() as Array<{ producer: string; n: number; bytes: number }>;
  const porSesion = sessions.map((session) => {
    const totals = ledger.totals(session.id);
    const mine = requests.filter((row) => row.session_id === session.id);
    const last = mine.at(-1)?.at as string | undefined;
    return {
      id: session.id,
      inicio: session.started_at,
      fin: last ?? null,
      modelo: session.model,
      solicitudes: mine.length,
      tokens: totals.tokens,
      usd: usd(totals.knownPico, 6),
      sinPrecio: totals.unknownRequests,
      eventos: Object.fromEntries(events.filter((row) => row.session_id === session.id).map((row) => [row.type, row.n])),
    };
  });
  const total = ledger.totals();
  const exportado = {
    proyecto: project,
    exportadoEn: new Date().toISOString(),
    topeProyectoUsd: ledger.projectBudget() === undefined ? null : usd(ledger.projectBudget()!, 2),
    totalUsd: usd(total.knownPico, 6),
    sesiones: porSesion,
    solicitudes: requests,
    hallazgos: findings.map((row) => {
      const item = JSON.parse(row.json);
      return { id: item.id, estado: item.state, titulo: item.title, clase: item.kind, severidad: item.severity, activo: item.asset, decididoPor: item.decidedBy, creado: item.createdAt };
    }),
    artefactos: artifacts,
  };
  mkdirSync(join(cwd, "cyber-informes"), { recursive: true });
  const file = join(cwd, "cyber-informes", `uso-${exportado.exportadoEn.replace(/[:.]/g, "-")}.json`);
  writeFileSync(file, JSON.stringify(exportado, null, 1));
  const lines = [
    `USO DEL PROYECTO ${project} · USD ${exportado.totalUsd} · ${requests.length} solicitudes · ${sessions.length} sesiones`,
    "SESIÓN    INICIO               SOLIC.  TOKENS      USD        MODELO",
    ...porSesion.map((s) => `${s.id.slice(0, 8)}  ${s.inicio.slice(0, 19).replace("T", " ")}  ${String(s.solicitudes).padStart(6)}  ${String(s.tokens.input + s.tokens.cacheRead + s.tokens.cacheWrite + s.tokens.output).padStart(10)}  ${s.usd.padStart(9)}  ${s.modelo}`),
    `Hallazgos: ${exportado.hallazgos.length} · artefactos: ${artifacts.map((row) => `${row.producer} ${row.n}`).join(", ") || "ninguno"}`,
    `Exportado a ${shown(file, cwd)} (sin contenido de mensajes ni secretos): es lo que se envía.`,
  ];
  return lines;
}
