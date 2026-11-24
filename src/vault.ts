// Memoria del proyecto: un registro TOON por nota, con su detalle adentro, como fuente canónica.
// SQLite sólo guarda un índice de búsqueda (texto y enlaces) que se reconstruye desde los archivos.
// Antes el detalle largo iba en una nota Markdown aparte (.md): al reindexar, lo que quede de eso
// se pliega dentro del registro TOON y el .md se borra.
import { createHash, randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { decode, encode } from "@toon-format/toon";
import { projectScopeTags, sameScope, type ScopeTag } from "./scope.ts";

export const RECORD_TYPES = ["observacion", "inferencia", "decision", "hipotesis", "pendiente"] as const;
export type RecordType = (typeof RECORD_TYPES)[number];

export interface MemoryRecord {
  id: string;
  rev: number;
  type: RecordType;
  /** vigente | sustituido | refutado */
  state: string;
  title: string;
  summary: string;
  /** Detalle largo, texto plano. Vive dentro del registro: no hay archivo aparte. */
  body: string;
  tags: string[];
  /** IDs de evidencia, artefactos (sha256:…) o sesiones que respaldan el registro. */
  sources: string[];
  links: Array<{ to: string; rel: string }>;
  observedAt: string;
  /** Condición bajo la cual deja de valer; vacío si no se conoce. */
  validity: string;
  /**
   * Programa o alcance donde nació (ver ScopeTag). Sólo entra solo en una sesión del mismo programa.
   * Falta en los registros de antes: al reindexar se atribuyen si no hay duda (migrated) o quedan «?».
   */
  scope?: ScopeTag & { migrated?: boolean; attributionVersion?: number };
}

export interface MemoryHit {
  id: string;
  rev: number;
  type: string;
  state: string;
  title: string;
  summary: string;
  /** Por qué entró al paquete cuando no fue por la búsqueda: enlazado a otro resultado. */
  via?: string;
  /** Programa donde nació (del índice); no viaja al modelo. */
  scope?: ScopeTag;
}

export interface WriteInput {
  id?: string;
  type: RecordType;
  title: string;
  summary: string;
  body?: string;
  tags?: string[];
  sources?: string[];
  links?: Array<{ to: string; rel: string }>;
  validity?: string;
  supersedes?: string;
  expectedRev?: number;
  /** Programa de la sesión que escribe. Sin esto, el del registro anterior o «sin alcance». */
  scope?: ScopeTag;
}

export interface SearchOptions {
  /** Limitar a estos tipos. */
  types?: readonly RecordType[];
  /** Incluir también los sustituidos y refutados (por defecto quedan al final, marcados). */
  all?: boolean;
  /**
   * Sólo lo de este programa (ver sameScope). null: la sesión no tiene alcance, así que nada.
   * Sin la opción no se filtra: es la vista del operador.
   */
  scope?: ScopeTag | null;
}

/** Filtro por programa de una lista del índice; sin `scope` en las opciones, no filtra. */
const within = (options: { scope?: ScopeTag | null }) => (hit: MemoryHit) => options.scope === undefined || sameScope(hit.scope, options.scope ?? undefined);

function atomicWrite(path: string, content: string): void {
  const tmp = `${path}.${randomUUID()}.tmp`;
  writeFileSync(tmp, content, { flush: true });
  renameSync(tmp, path);
}

const slug = (text: string) =>
  text
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);

/** Palabras con las que se busca: tres letras o más, sin repetir, hasta 16. */
export const searchTerms = (query: string) => [...new Set(query.toLowerCase().match(/[\p{L}\p{N}]{3,}/gu) ?? [])].slice(0, 16);

export class Vault {
  readonly db: DatabaseSync;
  readonly records: string;
  /** Carpeta de las notas Markdown viejas; sólo se lee para migrarlas. */
  readonly notes: string;

  constructor(db: DatabaseSync, records: string, notes: string) {
    this.db = db;
    this.records = records;
    this.notes = notes;
    // Índice del programa de cada registro (reconstruible, como el resto): la fuente es el campo «scope» del TOON.
    db.exec("create table if not exists memory_scope(id text primary key, program text, domains text not null default '[]')");
  }

  private recordPath = (id: string) => join(this.records, `${id}.toon`);
  private legacyNotePath = (id: string) => join(this.notes, `${id}.md`);

  /** Lee un registro. Si quedó una nota Markdown vieja al lado, su texto vale como detalle. */
  read(id: string): { record: MemoryRecord; body: string } | undefined {
    if (!/^[a-z0-9][a-z0-9-]*$/.test(id) || !existsSync(this.recordPath(id))) return undefined;
    const raw = decode(readFileSync(this.recordPath(id), "utf8")) as unknown as Partial<MemoryRecord> & { id: string };
    const legacy = existsSync(this.legacyNotePath(id)) ? readFileSync(this.legacyNotePath(id), "utf8") : "";
    const body = typeof raw.body === "string" && raw.body ? raw.body : legacy;
    const record: MemoryRecord = {
      id: raw.id,
      rev: raw.rev ?? 1,
      type: (raw.type ?? "observacion") as RecordType,
      state: raw.state ?? "vigente",
      title: raw.title ?? "",
      summary: raw.summary ?? "",
      body,
      tags: raw.tags ?? [],
      sources: raw.sources ?? [],
      links: raw.links ?? [],
      observedAt: raw.observedAt ?? "",
      validity: raw.validity ?? "",
      ...(validTag(raw.scope) ? { scope: raw.scope } : {}),
    };
    return { record, body };
  }

  write(input: WriteInput): MemoryRecord {
    if (!RECORD_TYPES.includes(input.type)) throw new Error(`Tipo inválido. Usar: ${RECORD_TYPES.join(", ")}`);
    if (!input.title.trim() || !input.summary.trim()) throw new Error("Faltan título o resumen");
    const id = input.id ?? `${slug(input.title) || "nota"}-${randomUUID().slice(0, 4)}`;
    const previous = this.read(id);
    if (input.expectedRev !== undefined && (previous?.record.rev ?? 0) !== input.expectedRev) {
      throw new Error(`Revisión esperada ${input.expectedRev}, actual ${previous?.record.rev ?? 0}`);
    }
    const links = [...(input.links ?? [])];
    if (input.supersedes) {
      const old = this.read(input.supersedes);
      if (!old) throw new Error(`No existe el registro a sustituir: ${input.supersedes}`);
      links.push({ to: input.supersedes, rel: "sustituye" });
      this.save({ ...old.record, rev: old.record.rev + 1, state: "sustituido" });
    }
    const record: MemoryRecord = {
      id,
      rev: (previous?.record.rev ?? 0) + 1,
      type: input.type,
      state: "vigente",
      title: input.title.trim(),
      summary: input.summary.trim(),
      body: (input.body ?? previous?.body ?? "").trim(),
      tags: input.tags ?? [],
      sources: input.sources ?? [],
      links,
      observedAt: new Date().toISOString(),
      validity: input.validity ?? "",
      // Atada al programa de la sesión que la escribe; sin sesión (pruebas, vistas), la que ya tenía.
      scope: input.scope ? { program: input.scope.program, domains: [...input.scope.domains] } : previous?.record.scope ?? { program: "", domains: [] },
    };
    this.save(record);
    return record;
  }

  /** Escribe el registro completo en TOON, borra la nota Markdown vieja si la había y reindexa. */
  private save(record: MemoryRecord): void {
    atomicWrite(this.recordPath(record.id), `${encode(record)}\n`);
    if (existsSync(this.legacyNotePath(record.id))) rmSync(this.legacyNotePath(record.id), { force: true });
    this.index(record);
  }

  private index(record: MemoryRecord): void {
    const hash = createHash("sha256").update(encode(record)).digest("hex");
    this.db.prepare("delete from memory_fts where id=?").run(record.id);
    this.db.prepare("delete from memory_links where from_id=?").run(record.id);
    this.db
      .prepare("insert or replace into memory(id,rev,type,state,title,summary,hash,observed_at) values(?,?,?,?,?,?,?,?)")
      .run(record.id, record.rev, record.type, record.state, record.title, record.summary, hash, record.observedAt);
    this.db
      .prepare("insert into memory_fts(id,title,summary,body,tags) values(?,?,?,?,?)")
      .run(record.id, record.title, record.summary, record.body, record.tags.join(" "));
    const link = this.db.prepare("insert or ignore into memory_links(from_id,to_id,rel) values(?,?,?)");
    for (const item of record.links) if (item.to) link.run(record.id, item.to, item.rel || "relacionado");
    this.db.prepare("insert or replace into memory_scope(id,program,domains) values(?,?,?)").run(record.id, record.scope?.program ?? null, JSON.stringify(record.scope?.domains ?? []));
  }

  /**
   * Reconstruye el índice desde los archivos e incorpora ediciones externas. Las notas Markdown
   * viejas se pliegan en su registro TOON y se borran.
   */
  reindex(): { indexed: number; invalid: string[]; migrated: number } {
    this.db.exec("delete from memory; delete from memory_fts; delete from memory_links; delete from memory_scope;");
    const invalid: string[] = [];
    let indexed = 0;
    let migrated = 0;
    const found: MemoryRecord[] = [];
    for (const file of readdirSync(this.records)) {
      if (!file.endsWith(".toon")) continue;
      try {
        const id = file.slice(0, -5);
        const read = this.read(id);
        if (!read || read.record.id !== id) throw new Error("ID no coincide");
        found.push(read.record);
      } catch {
        invalid.push(file);
      }
    }
    // Los registros de antes no dicen de qué programa son: se atribuyen una vez y queda escrito en el archivo.
    const requiereAtribucion = ({ scope }: MemoryRecord) =>
      !scope || (scope.migrated === true && scope.program !== "?" && scope.attributionVersion === undefined);
    const attribute = found.some(requiereAtribucion) ? this.attribution() : undefined;
    for (const record of found) {
      try {
        if (attribute && requiereAtribucion(record)) {
          if (existsSync(this.legacyNotePath(record.id))) migrated++;
          record.scope = { ...attribute(record), migrated: true, attributionVersion: 2 };
          this.save(record);
        }
        else if (existsSync(this.legacyNotePath(record.id))) { this.save(record); migrated++; }
        else this.index(record);
        indexed++;
      } catch {
        invalid.push(`${record.id}.toon`);
      }
    }
    return { indexed, invalid, migrated };
  }

  /**
   * Programa de un registro de antes de que la memoria fuera por programa. Migración conservadora:
   * se atribuye sólo si no hay duda; si no, «?», que no entra solo en ninguna sesión.
   * - Lo escribió una sesión conocida (su memory_write quedó en la conversación): el programa de esa
   *   sesión, si tuvo uno solo. Las sesiones de antes del alcance por sesión no tienen filas propias:
   *   vale el alcance viejo del proyecto vigente cuando se escribió.
   * - Sin autor conocido: el del proyecto, si en toda su historia hubo un solo programa.
   */
  private attribution(): (record: MemoryRecord) => ScopeTag {
    const writers = new Map<string, Set<string>>();
    try {
      const rows = this.db.prepare(`select session_id, json from messages where json like '%"memory_write"%' and json like '%Guardado %'`).all() as Array<{ session_id: string; json: string }>;
      for (const row of rows) {
        try {
          const message = JSON.parse(row.json) as { role?: string; name?: string; content?: unknown; isError?: boolean };
          const saved = message.role === "tool" && message.name === "memory_write" && !message.isError && typeof message.content === "string" ? /^Guardado ([a-z0-9][a-z0-9-]*) rev \d+/.exec(message.content) : null;
          if (saved) writers.set(saved[1]!, (writers.get(saved[1]!) ?? new Set()).add(row.session_id));
        } catch { /* mensaje ilegible: no cuenta */ }
      }
    } catch { /* sin tabla de mensajes: sólo la historia del proyecto */ }
    const history = projectScopeTags(this.db);
    const unknown: ScopeTag = { program: "?", domains: [] };
    return (record) => {
      const sessions = writers.get(record.id);
      // Una atribución vieja sin recibos de autor no se recalcula con programas incorporados después.
      if (record.scope && !sessions) return record.scope;
      const pool = sessions
        ? [...sessions].flatMap((session) => {
            const own = history.filter((item) => item.session === session);
            if (own.length) return own.map((item) => item.tag);
            const legacy = history.filter((item) => !item.session && (!record.observedAt || item.at <= record.observedAt)).at(-1);
            // Un coautor sin ámbito conocido también cuenta para decidir si hubo unanimidad.
            return [legacy?.tag ?? unknown];
          })
        : history.map((item) => item.tag);
      const inferred = unanimous(pool) ?? unknown;
      if (!record.scope) return inferred;
      // Al revisar una atribución previa sólo se puede restringir su visibilidad.
      if (record.scope.program !== inferred.program) return unknown;
      const domains = record.scope.domains.filter(domain => inferred.domains.includes(domain));
      return inferred.program === "manual" && !domains.length ? unknown : { program: inferred.program, domains };
    };
  }

  count(): number {
    return (this.db.prepare("select count(*) n from memory").get() as { n: number }).n;
  }

  /**
   * Búsqueda por texto en dos pasadas: primero lo que tiene todas las palabras, después lo que tiene
   * alguna. Los vigentes van primero; a igual relevancia gana lo más reciente. Título y etiquetas
   * pesan más que el resumen; el detalle, menos.
   */
  search(query: string, limit = 5, options: SearchOptions = {}): MemoryHit[] {
    const terms = searchTerms(query);
    if (!terms.length) return [];
    const quoted = terms.map((term) => `"${term}"*`);
    const types = options.types?.length ? ` and m.type in (${options.types.map(() => "?").join(",")})` : "";
    const states = options.all ? "" : " and m.state <> 'refutado'";
    // Con filtro de programa se piden todos los candidatos (LIMIT -1) y se descarta lo de otros programas después:
    // con un tope fijo, una nota del programa correcto quedaba afuera si había muchas mejor ubicadas de otros.
    const filtered = options.scope !== undefined;
    const keep = within(options);
    const run = (match: string, cap: number) =>
      rowsToHits(this.db
        .prepare(
          `select m.id,m.rev,m.type,m.state,m.title,m.summary,s.program,s.domains from memory_fts f join memory m on m.id=f.id left join memory_scope s on s.id=m.id
           where memory_fts match ?${types}${states}
           order by (m.state='vigente') desc, bm25(memory_fts, 0, 5, 2, 1, 3), m.observed_at desc limit ?`,
        )
        .all(match, ...(options.types ?? []), filtered ? -1 : cap) as unknown as ScopeRow[]).filter(keep);
    const hits = terms.length > 1 ? run(quoted.join(" AND "), limit).slice(0, limit) : [];
    if (hits.length < limit) {
      const seen = new Set(hits.map((hit) => hit.id));
      for (const hit of run(quoted.join(" OR "), limit + hits.length)) if (!seen.has(hit.id) && hits.length < limit) { seen.add(hit.id); hits.push(hit); }
    }
    return hits;
  }

  /** Registros enlazados con los dados (en cualquier sentido), vigentes, que no estén ya en la lista. */
  related(ids: string[], limit = 3, options: { scope?: ScopeTag | null } = {}): MemoryHit[] {
    if (!ids.length || limit <= 0) return [];
    const marks = ids.map(() => "?").join(",");
    const rows = this.db
      .prepare(
        `select m.id,m.rev,m.type,m.state,m.title,m.summary,s.program,s.domains, l.rel, case when l.from_id in (${marks}) then l.from_id else l.to_id end as via
         from memory_links l join memory m on m.id = case when l.from_id in (${marks}) then l.to_id else l.from_id end left join memory_scope s on s.id=m.id
         where (l.from_id in (${marks}) or l.to_id in (${marks})) and m.state='vigente' and m.id not in (${marks})
         order by m.observed_at desc limit ?`,
      )
      .all(...ids, ...ids, ...ids, ...ids, ...ids, options.scope === undefined ? limit : -1) as unknown as Array<ScopeRow & { rel: string; via: string }>;
    return rows.map(({ rel, via, ...row }) => ({ ...rowToHit(row), via: `${rel} ${via}` })).filter(within(options)).slice(0, limit);
  }

  /** Las últimas notas, de cualquier programa: para la vista del operador. */
  recent(limit = 8): MemoryHit[] {
    return rowsToHits(this.db
      .prepare("select m.id,m.rev,m.type,m.state,m.title,m.summary,s.program,s.domains from memory m left join memory_scope s on s.id=m.id order by m.observed_at desc limit ?")
      .all(limit) as unknown as ScopeRow[]);
  }

  /** Decisiones vigentes: contexto obligatorio y acotado de cada sesión (de su programa, con `scope`). */
  decisions(limit = 8, options: { scope?: ScopeTag | null } = {}): MemoryHit[] {
    return this.byType("decision", limit, options);
  }

  /** Pendientes vigentes: lo que una sesión nueva tiene que saber que quedó abierto (de su programa, con `scope`). */
  pending(limit = 5, options: { scope?: ScopeTag | null } = {}): MemoryHit[] {
    return this.byType("pendiente", limit, options);
  }

  private byType(type: RecordType, limit: number, options: { scope?: ScopeTag | null }): MemoryHit[] {
    const rows = this.db
      .prepare("select m.id,m.rev,m.type,m.state,m.title,m.summary,s.program,s.domains from memory m left join memory_scope s on s.id=m.id where m.type=? and m.state='vigente' order by m.observed_at desc limit ?")
      .all(type, options.scope === undefined ? limit : -1) as unknown as ScopeRow[];
    return rowsToHits(rows).filter(within(options)).slice(0, limit);
  }

  /** Paquete TOON tabular para el modelo: sólo IDs, revisión y resumen (nunca de qué programa es). */
  static pack(hits: MemoryHit[]): string {
    return encode({ memoria: hits.map(({ via, scope: _scope, ...hit }) => (via ? { ...hit, via } : hit)) });
  }
}

type ScopeRow = Omit<MemoryHit, "scope" | "via"> & { program: string | null; domains: string | null };

function rowToHit({ program, domains, ...hit }: ScopeRow): MemoryHit {
  let list: string[] = [];
  try { list = JSON.parse(domains ?? "[]"); } catch { /* índice roto: sin dominios */ }
  return program === null ? hit : { ...hit, scope: { program, domains: list } };
}
const rowsToHits = (rows: ScopeRow[]) => rows.map(rowToHit);

function validTag(value: unknown): value is ScopeTag & { migrated?: boolean } {
  const tag = value as ScopeTag | undefined;
  return !!tag && typeof tag === "object" && typeof tag.program === "string" && Array.isArray(tag.domains) && tag.domains.every((domain) => typeof domain === "string");
}

/**
 * Un solo programa en toda la lista: ése (con sus dominios). Todos manuales y con un dominio en común:
 * ése, con los dominios comunes. Cualquier otra cosa (vacía, mezclada) es duda: undefined.
 */
function unanimous(tags: ScopeTag[]): ScopeTag | undefined {
  if (!tags.length) return undefined;
  const programs = new Set(tags.map((tag) => tag.program));
  if (programs.size !== 1) return undefined;
  const [program] = programs as unknown as [string];
  if (program !== "manual") return { program, domains: [...new Set(tags.flatMap((tag) => tag.domains))].sort() };
  const common = tags.slice(1).reduce((shared, tag) => shared.filter((domain) => tag.domains.includes(domain)), tags[0]!.domains);
  return common.length ? { program, domains: [...common].sort() } : undefined;
}
