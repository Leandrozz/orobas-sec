// Cosecha de identificadores de objetos en las respuestas, por identidad, para probar acceso cruzado
// (IDOR/BOLA). Cada respuesta exitosa (JSON, HTML, cabecera Location) deja los UUID v1-v8, los ObjectId
// y los ids numéricos de campos id/*_id/uuid que trae, con la identidad que la pidió, la ruta y el
// campo donde aparecieron. Un id que una identidad «descubrió» (le llegó sin pedirlo) y otra nunca vio
// es candidato: se pide con la otra identidad en su familia de ruta, con el dueño como control antes,
// y se comparan las respuestas. Todo pasa por HttpClient: alcance, ritmo, tope y guarda de borrado.
import type { DatabaseSync } from "node:sqlite";
import type { Tool, ToolResult } from "./agent.ts";
import { canonicalPath, ID_SEGMENT } from "./coverage.ts";
import { isDestructive, isStaticAsset, type HttpClient, type HttpExchange } from "./http.ts";
import { t } from "./idioma.ts";

export type IdKind = "uuid" | "objectid" | "numero";

/** Etiqueta de las peticiones sin credenciales (la misma que usa access_matrix). */
export const ANON = "(sin credenciales)";
/** Peticiones con cabeceras de autenticación propias, sin identidad con nombre: no se pueden repetir como dueño. */
export const UNNAMED = "(sin nombre)";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_TEXT = /(?<![0-9a-z-])[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-z-])/gi;
const OBJECT_ID = /^[0-9a-f]{24}$/i;
const NUMERIC = /^[1-9]\d{0,15}$/;
/** Palabras de un nombre de campo que no son un objeto de la aplicación: trazas, sesiones, terceros, secretos. */
const NOT_OBJECT = new Set(["request", "trace", "span", "correlation", "session", "csrf", "xsrf", "nonce", "idempotency", "client", "device", "install", "installation", "tracking", "anonymous", "visitor", "build", "commit", "ga", "gtm", "pixel", "stripe", "paypal", "google", "facebook", "apple", "token", "secret", "password", "passwd", "signature", "hash", "etag", "key", "apikey", "salt", "otp"]);
const ID_WORDS = new Set(["id", "uuid", "guid", "oid", "uid", "pk", "ids", "uuids", "uids"]);
const OWN_WORDS = new Set(["id", "uuid", "guid", "oid", "uid", "pk"]);
/** Recursos singulares de la propia cuenta: /me/{id} no es una ruta que exista. */
const SINGULAR = /^(me|self|profile|perfil|account|cuenta|current|whoami|session|sesion|settings|ajustes)$/i;
/** Envoltorios genéricos de una respuesta: «data.id» es el id del objeto, no de un recurso llamado «data». */
const WRAPPERS = /^(data|result|results|item|items|records|rows|list|payload|response|content|value|values|entries|objects|docs|hits|nodes|node|edges|script|\(raíz\))$/i;
/** Nombres de campo que suelen apuntar a usuarios aunque la ruta se llame distinto. */
const USER_ALIASES: Record<string, string[]> = { owner: ["users", "user", "accounts", "members"], author: ["users", "user"], creator: ["users", "user"], assignee: ["users", "user"], member: ["members", "users"], customer: ["customers", "users"] };
const MAX_PER_EXCHANGE = 300;
const MAX_ROWS = 10_000;
const READS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Palabras de un nombre de campo: snake_case, kebab-case y camelCase. */
function words(key: string): string[] {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

/** ¿El campo lleva un identificador (id, _id, uuid, owner_id, orderId, member_ids)? */
export function idField(key: string): boolean {
  if (key === "_id") return true;
  const parts = words(key);
  return !!parts.length && ID_WORDS.has(parts.at(-1)!);
}

/** Campos de traza, sesión, terceros o secretos: lo que traen no es un objeto que se pueda pedir. */
function excluded(key: string): boolean {
  return words(key).some((word) => NOT_OBJECT.has(word));
}

/** El id propio del objeto (id, _id, uuid), no una referencia a otro (owner_id). */
function ownIdLeaf(key: string): boolean {
  return key === "_id" || (words(key).length === 1 && OWN_WORDS.has(words(key)[0]!));
}

/** Un ObjectId real lleva un sello de tiempo de 2009 a 2040 en sus primeros cuatro bytes. */
function plausibleObjectId(text: string): boolean {
  const seconds = parseInt(text.slice(0, 8), 16);
  return seconds >= 0x495c0780 && seconds <= 0x83aa7e80 && !/^(.)\1+$/.test(text);
}

/** Tipo de identificador de un valor; los numéricos sólo cuando el contexto dice que es un id. */
export function idKind(text: string, numericOk: boolean): IdKind | undefined {
  if (UUID.test(text)) return "uuid";
  if (OBJECT_ID.test(text) && plausibleObjectId(text)) return "objectid";
  if (numericOk && NUMERIC.test(text) && Number(text) <= Number.MAX_SAFE_INTEGER) return "numero";
  return undefined;
}

function decodeSegment(segment: string): string {
  const plain = segment.split(";")[0]!;
  try { return decodeURIComponent(plain); } catch { return plain; }
}

/** Ids en los segmentos de una ruta: UUID y ObjectId en cualquier lugar; números después de un segmento que no es id. */
function pathIds(pathname: string): Array<{ value: string; kind: IdKind; index: number }> {
  const segments = pathname.split("/").filter(Boolean).map(decodeSegment);
  const out: Array<{ value: string; kind: IdKind; index: number }> = [];
  segments.forEach((segment, index) => {
    const previous = segments[index - 1];
    const kind = idKind(segment, index > 0 && !!previous && !idKind(previous, true));
    if (kind) out.push({ value: segment, kind, index });
  });
  return out;
}

/** Ids de objeto que lleva una URL: segmentos de la ruta y parámetros de consulta con nombre de id. */
export function urlIds(url: string): string[] {
  try {
    const parsed = new URL(url);
    const ids = pathIds(parsed.pathname).map((item) => item.value);
    for (const [key, value] of parsed.searchParams) if (idField(key) && !excluded(key) && idKind(value, true)) ids.push(value);
    return ids;
  } catch {
    return [];
  }
}

export interface HarvestedId {
  value: string;
  kind: IdKind;
  /** Dónde apareció: ruta JSON («[].owner_id»), «location», «html:enlace», «html:data-user-id»… */
  field: string;
  /** URL que lo lleva (Location, enlace, campo con URL): sirve tal cual para pedirlo con otra identidad. */
  link?: string;
}

/**
 * Identificadores de objetos en una respuesta: campos id/*_id/uuid del JSON (a cualquier profundidad,
 * también el JSON de <script type="application/json"> en el HTML), UUID y ObjectId en cualquier campo
 * que no sea un secreto o una traza, URLs con ids (Location, enlaces, campos href), atributos data-*id e
 * inputs con nombre de id. No mira respuestas binarias.
 */
export function extractIds(exchange: HttpExchange, max = MAX_PER_EXCHANGE): HarvestedId[] {
  const response = exchange.response;
  if (!response || response.bodyEncoding === "base64") return [];
  let base: URL;
  try { base = new URL(exchange.request.url); } catch { return []; }
  const found = new Map<string, HarvestedId>();
  const add = (value: string, kind: IdKind, field: string, link?: string) => {
    if (found.size >= max) return;
    const key = `${value.toLowerCase()}|${field}`;
    if (!found.has(key)) found.set(key, { value, kind, field: field.slice(0, 120), ...(link && { link }) });
  };
  const fromLink = (text: string, field: string) => {
    if (text.length > 2048) return;
    let url: URL;
    try { url = new URL(text.replace(/&amp;/g, "&"), base); } catch { return; }
    if (!/^https?:$/.test(url.protocol) || url.host !== base.host || isStaticAsset(url.pathname)) return;
    const link = `${url.origin}${url.pathname}${url.search}`;
    for (const { value, kind } of pathIds(url.pathname)) add(value, kind, field, link);
    for (const [key, value] of url.searchParams) {
      if (!idField(key) || excluded(key)) continue;
      const kind = idKind(value, true);
      if (kind) add(value, kind, `${field}?${key}`, link);
    }
  };
  for (const header of ["location", "content-location"]) {
    const value = response.headers[header];
    if (value) fromLink(value, header);
  }
  const walk = (node: unknown, path: string, leaf: string, depth: number): void => {
    if (depth > 8 || found.size >= max) return;
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 200)) walk(item, `${path}[]`, leaf, depth + 1);
      return;
    }
    if (node && typeof node === "object") {
      for (const [key, value] of Object.entries(node as Record<string, unknown>).slice(0, 300)) walk(value, path ? `${path}.${key}` : key, key, depth + 1);
      return;
    }
    if (typeof node !== "string" && typeof node !== "number") return;
    if (leaf && excluded(leaf)) return;
    const text = String(node);
    if (leaf && idField(leaf)) {
      const kind = idKind(text, typeof node === "number" ? Number.isInteger(node) : true);
      if (kind) add(text, kind, path || leaf);
      return;
    }
    if (typeof node !== "string") return;
    const kind = idKind(text, false);
    if (kind) return add(text, kind, path || "(raíz)");
    if (/^(https?:\/\/|\/)\S+$/.test(text)) fromLink(text, path || "(raíz)");
  };
  const type = response.headers["content-type"] ?? "";
  const body = response.body.slice(0, 1_000_000);
  if (/json/i.test(type) || /^\s*[[{]/.test(body.slice(0, 50))) {
    try { walk(JSON.parse(body), "", "", 0); } catch { /* no era JSON */ }
  }
  if (/html/i.test(type)) {
    for (const match of body.matchAll(/<script\b[^>]*type=["']application\/(?:ld\+)?json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
      try { walk(JSON.parse(match[1]!), "script", "", 0); } catch { /* bloque roto */ }
    }
    for (const match of body.matchAll(/\b(?:href|src|action|data-href|data-url)\s*=\s*["']([^"'#]+)["']/gi)) fromLink(match[1]!, "html:enlace");
    for (const match of body.matchAll(/\bdata-([\w-]+)\s*=\s*["']([^"']{1,64})["']/gi)) {
      const name = match[1]!;
      if (!idField(name) || excluded(name)) continue;
      const kind = idKind(match[2]!, true);
      if (kind) add(match[2]!, kind, `html:data-${name}`);
    }
    for (const match of body.matchAll(/<input\b[^>]*>/gi)) {
      const tag = match[0];
      const name = /\bname\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
      const value = /\bvalue\s*=\s*["']([^"']{1,64})["']/i.exec(tag)?.[1];
      if (!name || !value || /\btype\s*=\s*["']?password/i.test(tag) || !idField(name) || excluded(name)) continue;
      const kind = idKind(value, true);
      if (kind) add(value, kind, `html:input ${name}`);
    }
    // UUID sueltos en el texto visible; no en atributos ni scripts (ahí viven los tokens CSRF y de
    // sesión), ni ObjectId sueltos (se confunden con hashes de archivos).
    const known = new Set([...found.values()].map((item) => item.value.toLowerCase()));
    const visible = body.replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]*>/g, " ");
    for (const match of visible.matchAll(UUID_TEXT)) {
      if (known.has(match[0].toLowerCase())) continue;
      known.add(match[0].toLowerCase());
      add(match[0], "uuid", "html:texto");
    }
  }
  return [...found.values()];
}

/** Valores que lleva una petición (ruta, consulta y cuerpo), en minúsculas. */
function carriedValues(url: string, body?: string): Set<string> {
  const values = new Set<string>();
  const add = (text: string) => { for (const token of text.toLowerCase().match(/[0-9a-z_-]+/g) ?? []) values.add(token); };
  try {
    const parsed = new URL(url);
    for (const segment of parsed.pathname.split("/")) add(decodeSegment(segment));
    for (const value of parsed.searchParams.values()) add(value);
  } catch { add(url); }
  if (body) add(body.slice(0, 200_000));
  return values;
}

/** Familia de una URL para mostrar: ruta canónica con los ids como {n}. */
export function familyOfUrl(url: string): string {
  let path = url;
  try { path = new URL(url).pathname; } catch { /* queda como vino */ }
  return canonicalPath(path).split("/").map((segment) => (ID_SEGMENT.test(segment) ? "{n}" : segment)).join("/");
}

const pathOf = (url: string) => {
  try { return new URL(url).pathname; } catch { return url; }
};
const normal = (text: string) => text.toLowerCase().replace(/[^a-z0-9]/g, "");

/** Formas del nombre de un recurso para compararlo con un segmento de ruta (singular, plural, alias de usuario). */
function resourceForms(resource: string): Set<string> {
  const base = normal(resource);
  const forms = new Set([base, `${base}s`, `${base}es`, base.replace(/y$/, "ies"), base.replace(/s$/, "")]);
  for (const alias of USER_ALIASES[base] ?? []) forms.add(alias);
  return forms;
}

/** Recurso al que apunta un campo: «owner_id» → owner, «owner.id» → owner, «lines[].id» → lines; undefined si es el id propio del objeto listado. */
function resourceOf(field: string): string | undefined {
  const parts = field.replace(/\[\]/g, "").split(".").filter(Boolean);
  const leaf = parts.at(-1) ?? "";
  if (!ownIdLeaf(leaf)) {
    const pieces = words(leaf);
    return pieces.length > 1 ? pieces.slice(0, -1).join("") : undefined;
  }
  const parent = parts.at(-2);
  return parent && !WRAPPERS.test(parent) ? parent : undefined;
}

export interface HarvestRow {
  identity: string;
  value: string;
  kind: IdKind;
  method: string;
  /** Origen y ruta de la petición cuya respuesta lo trajo (sin consulta). */
  origin: string;
  field: string;
  link: string;
  /** Le llegó sin pedirlo (no estaba en la petición y la petición no llevó un id ajeno). Sólo esto hace «suyo» un id. */
  discovered: boolean;
  exchange: string;
  at: string;
}

export type CrossVerdict = "leido" | "publico" | "modificado" | "negado" | "redirigido" | "distinto" | "sin-efecto" | "error" | "ruta-no-sirve" | "omitida";

export interface CrossRow {
  value: string;
  owner: string;
  identity: string;
  method: string;
  url: string;
  ownerStatus?: number;
  status?: number;
  verdict: CrossVerdict;
  exchanges: string;
  at: string;
}

export interface Candidate {
  value: string;
  kind: IdKind;
  owner: string;
  /** Identidades que nunca lo vieron y con las que se puede pedir. */
  targets: string[];
  /** Identidades (no dueñas) que ya lo pidieron. */
  tested: Set<string>;
  rows: HarvestRow[];
}

export interface CrossTarget {
  url: string;
  how: "pedida" | "enlace" | "derivada" | "por campo";
}

export interface HarvestOptions {
  db: DatabaseSync;
  http: HttpClient;
  sessionId: string;
  event?: (type: string, payload: unknown) => void;
  notice?: (text: string) => void;
}

export class IdHarvest {
  readonly db: DatabaseSync;
  readonly http: HttpClient;
  readonly sessionId: string;
  event?: (type: string, payload: unknown) => void;
  notice?: (text: string) => void;
  /** Se llama una vez, cuando hay dos identidades del operador y una ya recibió ids propios: hay algo que cruzar. */
  onReady?: () => void;
  private ready = false;
  private readonly rows = new Map<string, HarvestRow>();
  /** Filas por valor (en minúsculas). */
  private readonly byValue = new Map<string, HarvestRow[]>();

  constructor(options: HarvestOptions) {
    this.db = options.db;
    this.http = options.http;
    this.sessionId = options.sessionId;
    this.event = options.event;
    this.notice = options.notice;
    this.db.exec(`create table if not exists ids_cosechados(session_id text not null, identidad text not null, valor text not null, tipo text not null, metodo text not null, origen text not null, campo text not null, enlace text not null default '', descubierto integer not null default 0, intercambio text not null, at text not null, primary key(session_id, identidad, valor, origen, campo));
      create table if not exists ids_cruces(session_id text not null, valor text not null, duenio text not null, identidad text not null, metodo text not null, url text not null, estado_duenio integer, estado integer, veredicto text not null, intercambios text not null, at text not null, primary key(session_id, valor, identidad, metodo, url));`);
    const stored = this.db.prepare("select identidad, valor, tipo, metodo, origen, campo, enlace, descubierto, intercambio, at from ids_cosechados where session_id=? order by at").all(this.sessionId) as Array<Record<string, string | number>>;
    for (const row of stored) this.remember({ identity: String(row.identidad), value: String(row.valor), kind: row.tipo as IdKind, method: String(row.metodo), origin: String(row.origen), field: String(row.campo), link: String(row.enlace), discovered: !!row.descubierto, exchange: String(row.intercambio), at: String(row.at) });
  }

  private key(row: Pick<HarvestRow, "identity" | "value" | "origin" | "field">): string {
    return `${row.identity}\n${row.value.toLowerCase()}\n${row.origin}\n${row.field}`;
  }

  private remember(row: HarvestRow): void {
    this.rows.set(this.key(row), row);
    const group = this.byValue.get(row.value.toLowerCase()) ?? [];
    group.push(row);
    this.byValue.set(row.value.toLowerCase(), group);
  }

  /** Cantidad de ids cosechados en la sesión. */
  get size(): number {
    return this.rows.size;
  }

  /** Quién pidió una entrada del registro HTTP: la identidad con nombre, o sin credenciales, o cabeceras propias. */
  requester(entry: { identity?: string; sentAuth?: boolean }): string {
    return entry.identity ?? (entry.sentAuth ? UNNAMED : ANON);
  }

  /** Identidades que descubrieron el valor (les llegó sin pedirlo). */
  owners(value: string): Set<string> {
    return new Set((this.byValue.get(value.toLowerCase()) ?? []).filter((row) => row.discovered).map((row) => row.identity));
  }

  /** ¿El valor es de otra identidad con nombre y ésta nunca lo descubrió? */
  private foreignTo(value: string, identity: string): boolean {
    const owners = this.owners(value);
    if (!owners.size || owners.has(identity) || owners.has(ANON)) return false;
    return [...owners].some((owner) => owner !== identity && owner !== UNNAMED);
  }

  /**
   * Registra los ids de una respuesta (lo llama HttpClient.onExchange). Una petición que llevó un id
   * ajeno es una prueba cruzada: lo que trae su respuesta no es de quien la pidió, así que no cuenta
   * como descubierto. Tampoco las respuestas con error, los señuelos ni las variantes artificiales.
   */
  observe(exchange: HttpExchange): void {
    if (!exchange.response || exchange.decoy || exchange.response.status >= 400 || this.rows.size >= MAX_ROWS) return;
    let entry: HttpClient["log"][number] | undefined;
    for (let i = this.http.log.length - 1; i >= 0; i--) if (this.http.log[i]!.id === exchange.id) { entry = this.http.log[i]; break; }
    if (!entry || entry.synthetic) return;
    // Un valor que es entero una credencial conocida no es un id de objeto (se compara el valor completo:
    // un trozo corto de cookie, «1», no puede tachar todos los ids que lo contengan).
    const found = extractIds(exchange).filter((item) => this.http.redact(item.value) !== "<credencial>" && !/^<identidad [^>]+>$/.test(this.http.redactIdentities(item.value)));
    if (!found.length) return;
    const identity = this.requester(entry);
    const carried = carriedValues(exchange.request.url, exchange.request.body);
    const crossing = [...carried].some((value) => this.foreignTo(value, identity));
    let origin: string;
    try { const url = new URL(exchange.request.url); origin = `${url.origin}${url.pathname}`; } catch { return; }
    const at = new Date().toISOString();
    const harvested: HarvestRow[] = [];
    const upsert = this.db.prepare("insert into ids_cosechados(session_id, identidad, valor, tipo, metodo, origen, campo, enlace, descubierto, intercambio, at) values(?,?,?,?,?,?,?,?,?,?,?) on conflict(session_id, identidad, valor, origen, campo) do update set descubierto=max(descubierto, excluded.descubierto)");
    for (const item of found) {
      if (this.rows.size >= MAX_ROWS) break;
      const discovered = !crossing && !carried.has(item.value.toLowerCase());
      const row: HarvestRow = { identity, value: item.value, kind: item.kind, method: exchange.request.method, origin, field: item.field, link: item.link ?? "", discovered, exchange: exchange.id, at };
      upsert.run(this.sessionId, identity, row.value, row.kind, row.method, origin, row.field, row.link, discovered ? 1 : 0, exchange.id, at);
      const previous = this.rows.get(this.key(row));
      if (previous) previous.discovered ||= discovered;
      else this.remember(row);
      harvested.push(row);
    }
    if (harvested.length) {
      try { this.onHarvest?.(harvested, exchange); } catch { /* el grafo nunca rompe una petición */ }
    }
    if (!this.ready && this.onReady) {
      const named = new Set(this.http.identityNames());
      const discoverers = new Set([...this.rows.values()].filter((row) => row.discovered && named.has(row.identity)).map((row) => row.identity));
      if (named.size >= 2 && discoverers.size >= 1) {
        this.ready = true;
        try { this.onReady(); } catch { /* cargar la herramienta nunca rompe una petición */ }
      }
    }
  }

  /** Pruebas cruzadas guardadas en la sesión. */
  crosses(): CrossRow[] {
    const rows = this.db.prepare("select valor, duenio, identidad, metodo, url, estado_duenio, estado, veredicto, intercambios, at from ids_cruces where session_id=? order by at").all(this.sessionId) as Array<Record<string, string | number | null>>;
    return rows.map((row) => ({ value: String(row.valor), owner: String(row.duenio), identity: String(row.identidad), method: String(row.metodo), url: String(row.url), ownerStatus: row.estado_duenio === null ? undefined : Number(row.estado_duenio), status: row.estado === null ? undefined : Number(row.estado), verdict: row.veredicto as CrossVerdict, exchanges: String(row.intercambios), at: String(row.at) }));
  }

  private saveCross(row: CrossRow): void {
    this.db.prepare("insert or replace into ids_cruces(session_id, valor, duenio, identidad, metodo, url, estado_duenio, estado, veredicto, intercambios, at) values(?,?,?,?,?,?,?,?,?,?,?)").run(this.sessionId, row.value, row.owner, row.identity, row.method, row.url, row.ownerStatus ?? null, row.status ?? null, row.verdict, row.exchanges, row.at);
    try { this.onCross?.(row); } catch { /* ídem */ }
  }

  /** Ids cosechados de una respuesta y pruebas cruzadas guardadas: el grafo de hechos los toma (src/grafo-alimentar.ts). */
  onHarvest?: (rows: HarvestRow[], exchange: HttpExchange) => void;
  onCross?: (row: CrossRow) => void;

  /** Por valor, quiénes (que no lo descubrieron) ya lo pidieron: el registro HTTP y las pruebas guardadas. */
  private testedIndex(): Map<string, Set<string>> {
    const tested = new Map<string, Set<string>>();
    const note = (value: string, identity: string) => {
      const group = tested.get(value) ?? new Set<string>();
      group.add(identity);
      tested.set(value, group);
    };
    for (const entry of this.http.log) {
      if (entry.synthetic || entry.status === undefined) continue;
      const identity = this.requester(entry);
      for (const value of carriedValues(entry.url)) if (this.byValue.has(value) && !this.owners(value).has(identity)) note(value, identity);
    }
    for (const row of this.crosses()) if (row.verdict !== "omitida" && row.verdict !== "ruta-no-sirve") note(row.value.toLowerCase(), row.identity);
    return tested;
  }

  /**
   * Ids de una identidad que otra nunca vio. Un id que descubrió alguien sin credenciales es público y
   * uno que descubrieron dos identidades es compartido: ninguno de los dos es candidato.
   */
  candidates(filter: { identities?: string[]; owner?: string; values?: string[] } = {}): Candidate[] {
    const named = this.http.identityNames();
    const wanted = filter.values?.length ? new Set(filter.values.map((value) => value.toLowerCase())) : undefined;
    const tested = this.testedIndex();
    const out: Candidate[] = [];
    for (const [value, rows] of this.byValue) {
      if (wanted && !wanted.has(value)) continue;
      const owners = this.owners(value);
      if (!owners.size || owners.has(ANON)) continue;
      const namedOwners = [...owners].filter((owner) => named.includes(owner));
      const owner = filter.owner ?? namedOwners[0];
      if (!owner || !namedOwners.includes(owner)) continue;
      const pool = filter.identities?.length ? filter.identities : named;
      const targets = pool.filter((name) => name !== owner && !owners.has(name) && (name === ANON || named.includes(name)));
      if (!targets.length) continue;
      const ownerRows = rows.filter((row) => row.identity === owner);
      out.push({ value: ownerRows[0]!.value, kind: ownerRows[0]!.kind, owner, targets, tested: tested.get(value) ?? new Set<string>(), rows: ownerRows });
    }
    const weight = (kind: IdKind) => (kind === "numero" ? 1 : 0);
    return out.sort((a, b) => weight(a.kind) - weight(b.kind) || a.rows[0]!.at.localeCompare(b.rows[0]!.at));
  }

  /** Plantillas de familia vistas (registro HTTP e importadas) cuyo último segmento es un id. */
  private templates(): Array<{ origin: string; segments: string[] }> {
    const seen = new Map<string, { origin: string; segments: string[] }>();
    for (const entry of this.http.log) {
      if (entry.synthetic) continue;
      try {
        const url = new URL(entry.url);
        const segments = url.pathname.split("/").filter(Boolean).map(decodeSegment);
        if (!segments.length || !ID_SEGMENT.test(segments.at(-1)!)) continue;
        const family = `${url.origin}${familyOfUrl(url.href)}`;
        if (!seen.has(family)) seen.set(family, { origin: url.origin, segments });
      } catch { /* URL rota */ }
    }
    for (const operation of this.http.observed) {
      try {
        const url = new URL(operation.url);
        const segments = url.pathname.split("/").filter(Boolean).map(decodeSegment);
        const holes = segments.filter((segment) => /^(\{[^}]+\}|:\w+)$/.test(segment)).length;
        if (holes !== 1 || !/^(\{[^}]+\}|:\w+)$/.test(segments.at(-1) ?? "")) continue;
        const family = `${url.origin}/${segments.slice(0, -1).join("/").toLowerCase()}/{n}`;
        if (!seen.has(family)) seen.set(family, { origin: url.origin, segments });
      } catch { /* operación sin URL válida */ }
    }
    return [...seen.values()];
  }

  /**
   * Dónde pedir un id ajeno: las URLs que el dueño ya pidió con él (y le respondieron), las que trajo
   * una respuesta (Location, enlaces), la colección donde apareció más el id, y las familias conocidas
   * cuyo nombre coincide con el del campo (owner_id → /users/{n}). Nunca una ruta que borra.
   */
  targetsOf(candidate: Candidate, limit = 3): CrossTarget[] {
    const out: CrossTarget[] = [];
    const seen = new Set<string>();
    const push = (url: string, how: CrossTarget["how"]) => {
      if (out.length >= limit || seen.has(url) || isDestructive("GET", url)) return;
      seen.add(url);
      out.push({ url, how });
    };
    const value = candidate.value.toLowerCase();
    for (const entry of this.http.log) {
      if (entry.synthetic || entry.identity !== candidate.owner || !READS.has(entry.method) || entry.status === undefined || entry.status >= 300) continue;
      if (carriedValues(entry.url).has(value)) push(entry.url.split("#")[0]!, "pedida");
    }
    for (const row of candidate.rows) if (row.link && carriedValues(row.link).has(value)) push(row.link, "enlace");
    const templates = this.templates();
    for (const row of candidate.rows) {
      if (!row.discovered) continue;
      const segments = pathOf(row.origin).split("/").filter(Boolean).map(decodeSegment);
      const last = segments.at(-1);
      const origin = (() => { try { return new URL(row.origin).origin; } catch { return ""; } })();
      const resource = resourceOf(row.field);
      if (!resource) {
        if (last && !ID_SEGMENT.test(last) && !SINGULAR.test(last) && ownIdLeaf(row.field.replace(/\[\]/g, "").split(".").at(-1) ?? "")) push(`${row.origin.replace(/\/+$/, "")}/${encodeURIComponent(candidate.value)}`, "derivada");
        continue;
      }
      const forms = resourceForms(resource);
      for (const template of templates) {
        if (template.origin !== origin && origin) continue;
        const name = template.segments.at(-2);
        if (name && forms.has(normal(name))) push(`${template.origin}/${[...template.segments.slice(0, -1).map((segment) => encodeURIComponent(segment)), encodeURIComponent(candidate.value)].join("/")}`, "por campo");
      }
      if (last && !ID_SEGMENT.test(last) && forms.has(normal(last))) push(`${row.origin.replace(/\/+$/, "")}/${encodeURIComponent(candidate.value)}`, "derivada");
    }
    return out;
  }

  /** ¿Se pidió alguna vez un id de una identidad con otra (por ids_harvest, access_matrix o a mano)? */
  crossTested(): boolean {
    if (this.crosses().some((row) => row.verdict !== "omitida" && row.verdict !== "ruta-no-sirve")) return true;
    return this.candidates().some((candidate) => candidate.tested.size > 0);
  }

  /**
   * Lo que la cobertura de control de acceso objeta: hay al menos dos identidades del operador, ids que
   * una descubrió y otra nunca vio, y ninguno se pidió cruzado. Una sola acción, con un ejemplo concreto.
   */
  pendingCross(): string | undefined {
    if (this.http.identityNames().length < 2) return undefined;
    const pending = this.candidates().filter((candidate) => candidate.targets.some((target) => target !== ANON));
    if (!pending.length || this.crossTested()) return undefined;
    const first = pending[0]!;
    const owned = pending.filter((candidate) => candidate.owner === first.owner);
    const target = first.targets.find((name) => name !== ANON)!;
    const row = first.rows.find((item) => item.discovered) ?? first.rows[0]!;
    return `la identidad «${first.owner}» vio ${owned.length} id${owned.length > 1 ? "s" : ""} de objetos que «${target}» nunca vio (p. ej. ${first.value} en «${row.field}» de ${row.method} ${pathOf(row.origin)}) y no se pidió ninguno con otra identidad: ids_harvest (tools_load si no la ves) con mode «probar» los pide con «${target}» en su familia de ruta (sólo lectura, con el dueño como control) y compara las respuestas`;
  }

  /**
   * ¿La identidad puede escribir sobre esta URL como recurso propio? Sí si la ruta no lleva id de objeto
   * (un alta, /me), si lleva un id creado en esta sesión, o si todos sus ids los descubrió esa identidad
   * y ninguna otra. Lo usa body_probe en los modos de asignación masiva.
   */
  ownedBy(identity: string | undefined, url: string): { ok: boolean; why: string } {
    return ownership(this.http, identity, url, (value) => this.owners(value));
  }

  /** Un id que descubrió otra identidad del operador (no ésta), del mismo tipo: para campos de dueño en la asignación masiva. */
  otherOperatorId(identity: string | undefined, kind: IdKind): string | undefined {
    const named = new Set(this.http.identityNames());
    for (const rows of this.byValue.values()) {
      const owners = new Set(rows.filter((row) => row.discovered).map((row) => row.identity));
      if (owners.size !== 1) continue;
      const [owner] = owners;
      if (owner === identity || !named.has(owner!)) continue;
      const row = rows.find((item) => item.discovered && item.kind === kind && ownIdLeaf(item.field.replace(/\[\]/g, "").split(".").at(-1) ?? "") && /\/(me|users?|accounts?|profiles?|perfil|cuenta|usuarios?)(\/|$)/i.test(pathOf(item.origin)));
      if (row) return row.value;
    }
    return undefined;
  }

  /** Pide cada id ajeno con otra identidad, con el dueño como control. Ver la descripción de ids_harvest. */
  async probe(params: ProbeParams, signal: AbortSignal): Promise<ToolResult> {
    const method = (params.method ?? "GET").toUpperCase();
    const write = !READS.has(method);
    if (write && !params.allowWrite) throw new Error(`${method} cambia datos de otra identidad: ids_harvest sólo pide con métodos de lectura (GET, HEAD) salvo que pases allowWrite: true a pedido explícito del operador. Primero probá la lectura.`);
    if (method === "DELETE") throw new Error("ids_harvest no borra: DELETE sobre un recurso ajeno pasa por la guarda de borrado y el consentimiento del operador (/consent borrar-ajeno), no por acá.");
    const max = Math.min(60, Math.max(1, params.maxRequests ?? 24));
    const start = this.http.count;
    const spent = () => this.http.count - start;
    const left = () => Math.min(max - spent(), this.http.remaining() ?? Infinity);
    const family = params.family ? params.family.toLowerCase() : undefined;
    const done = new Set(params.retest ? [] : this.crosses().filter((row) => row.verdict !== "omitida").map((row) => `${row.value.toLowerCase()}|${row.identity}|${row.method}|${row.url}`));
    // Un resultado concluyente (leyó, negado, público, otro contenido) cierra el id para esa identidad: no se prueban sus otras rutas.
    const conclusive = (verdict: CrossVerdict) => verdict !== "ruta-no-sirve" && verdict !== "error" && verdict !== "omitida";
    const concluded = new Set(params.retest ? [] : this.crosses().filter((row) => conclusive(row.verdict)).map((row) => `${row.value.toLowerCase()}|${row.identity}|${row.method}`));
    const controls = new Map<string, HttpExchange>();
    const rows: string[] = [];
    const tally = { probadas: 0, leidos: 0, publicos: 0, modificados: 0, negados: 0, distintos: 0, omitidas: 0 };
    const hits: Array<{ valor: string; duenio: string; identidad: string; url: string; veredicto: CrossVerdict }> = [];
    const send = async (url: string, as: string | undefined, verb = "GET", body?: string): Promise<HttpExchange | string> => {
      try {
        return await this.http.send({ url, method: verb, ...(body !== undefined && { body, headers: { "content-type": /^\s*[[{]/.test(body) ? "application/json" : "application/x-www-form-urlencoded" } }), systematic: true }, as === ANON ? undefined : as);
      } catch (error) {
        return (error as Error).message;
      }
    };
    const status = (exchange: HttpExchange | string) => (typeof exchange === "string" ? undefined : exchange.response?.status);
    const ok = (exchange: HttpExchange | string) => { const code = status(exchange); return code !== undefined && code >= 200 && code < 300; };
    const candidates = this.candidates({ identities: params.identities, owner: params.owner, values: params.values });
    let stopped = false;
    outer: for (const candidate of candidates) {
      if (candidate.owner === UNNAMED) continue;
      for (const target of this.targetsOf(candidate)) {
        if (family && !familyOfUrl(target.url).includes(family)) continue;
        for (const identity of candidate.targets) {
          if (signal.aborted) break outer;
          const key = `${candidate.value.toLowerCase()}|${identity}|${method}|${target.url}`;
          if (done.has(key) || concluded.has(`${candidate.value.toLowerCase()}|${identity}|${method}`)) continue;
          if (isDestructive(method, target.url)) {
            tally.omitidas++;
            rows.push(`omitida  ${method} ${target.url}: la ruta borra o vacía datos (guarda de borrado)`);
            continue;
          }
          const need = (controls.has(target.url) ? 1 : 2) + (write ? 1 : 0);
          if (left() < need) { stopped = true; break outer; }
          let control = controls.get(target.url);
          if (!control) {
            const sent = await send(target.url, candidate.owner);
            if (typeof sent === "string") { rows.push(`error  ${target.url}: ${sent}`); continue; }
            control = sent;
            controls.set(target.url, control);
          }
          const base: CrossRow = { value: candidate.value, owner: candidate.owner, identity, method, url: target.url, ownerStatus: status(control), verdict: "ruta-no-sirve", exchanges: control.id, at: new Date().toISOString() };
          const origin = `(id de ${candidate.owner} en ${candidate.rows[0]!.method} ${pathOf(candidate.rows[0]!.origin)} · ${candidate.rows[0]!.field}; ruta ${target.how})`;
          if (!ok(control)) {
            this.saveCross(base);
            rows.push(`${control.id} ${candidate.owner}→${status(control) ?? "ERR"}  la ruta no le sirve ni al dueño: no prueba nada  ${method} ${target.url}`);
            break;
          }
          tally.probadas++;
          const other = await send(target.url, identity, method, write ? params.body : undefined);
          if (typeof other === "string") {
            base.verdict = "error";
            this.saveCross(base);
            rows.push(`error  ${identity}: ${other}`);
            continue;
          }
          base.status = status(other);
          base.exchanges = `${control.id},${other.id}`;
          let verdict: CrossVerdict;
          let note = "";
          if (write) {
            if (!ok(other)) verdict = base.status !== undefined && [401, 403, 404, 405, 410].includes(base.status) ? "negado" : "error";
            else {
              const reread = await send(target.url, candidate.owner);
              base.exchanges += typeof reread === "string" ? "" : `,${reread.id}`;
              const changed = typeof reread !== "string" && ok(reread) && changedFields(control, reread, params.body);
              verdict = changed && changed.length ? "modificado" : "sin-efecto";
              note = changed && changed.length ? `el dueño relee ${typeof reread === "string" ? "" : reread.id} y cambió: ${changed.join(", ")}` : "el dueño relee y no cambió nada: 2xx sin efecto, no es hallazgo";
            }
          } else verdict = readVerdict(control, other, candidate.value);
          if (verdict === "leido" && identity !== ANON && params.anonymousCheck !== false && left() >= 1) {
            const anonymous = await send(target.url, ANON);
            if (typeof anonymous !== "string") {
              base.exchanges += `,${anonymous.id}`;
              if (readVerdict(control, anonymous, candidate.value) === "leido") {
                verdict = "publico";
                note = `${anonymous.id} sin credenciales también lo lee: es público o falta autenticación; no es IDOR entre cuentas`;
              }
            }
          }
          base.verdict = verdict;
          this.saveCross(base);
          if (conclusive(verdict)) concluded.add(`${candidate.value.toLowerCase()}|${identity}|${method}`);
          if (verdict === "leido") tally.leidos++;
          else if (verdict === "publico") tally.publicos++;
          else if (verdict === "modificado") tally.modificados++;
          else if (verdict === "negado" || verdict === "redirigido") tally.negados++;
          else if (verdict === "distinto" || verdict === "sin-efecto") tally.distintos++;
          if (verdict === "leido" || verdict === "modificado" || verdict === "publico") hits.push({ valor: candidate.value, duenio: candidate.owner, identidad: identity, url: target.url, veredicto: verdict });
          const label = { leido: "LEYÓ el objeto del dueño", publico: "lee, pero es público", modificado: "MODIFICÓ el objeto del dueño", negado: "negado", redirigido: "redirigido (¿login?)", distinto: "2xx con otro contenido: revisar, no es hallazgo", "sin-efecto": "2xx sin efecto", error: "error del servidor o de red", "ruta-no-sirve": "", omitida: "" }[verdict];
          rows.push(`${control.id} ${candidate.owner}→${status(control)} · ${other.id} ${identity}→${base.status ?? "ERR"}  ${label}  ${method} ${target.url}  ${origin}${note ? `\n    ${note}` : ""}`);
        }
      }
    }
    if (!candidates.length) rows.push("No hay ids ajenos para probar: hace falta que una identidad del operador vea ids de objetos (listados, altas, enlaces) que otra no vio. Pedí con cada identidad sus propios listados primero.");
    else if (!tally.probadas && !rows.length) rows.push("Ninguna ruta probable para esos ids (o ya se probaron todas: retest: true las repite). Mirá el listado con mode «listar».");
    if (stopped) rows.push(`Se cortó por el tope de esta llamada (${max} peticiones) o de la sesión: volvé a llamar para seguir con los que faltan.`);
    if (tally.leidos || tally.modificados) rows.push("Cada LEYÓ/MODIFICÓ es candidato a IDOR: registralo con finding_record (activo = la familia de la ruta; evidencia = el control del dueño y la respuesta de la otra identidad, por id). Un 2xx con otro contenido no es hallazgo hasta mirar qué devolvió.");
    rows.push(`peticiones HTTP: ${this.http.count}${this.http.remaining() !== undefined ? ` · quedan ${this.http.remaining()}` : ""}`);
    const details = { ...tally, peticiones: spent(), candidatos: candidates.length };
    if (tally.probadas) this.event?.("ids.cruce", { ...details, metodo: method, hallazgos: hits.slice(0, 10).map((hit) => ({ ...hit, url: this.http.redactIdentities(hit.url) })) });
    if (tally.leidos || tally.modificados) {
      const first = hits.find((hit) => hit.veredicto !== "publico")!;
      this.notice?.(t(`Acceso cruzado: «${first.identidad}» ${first.veredicto === "modificado" ? "modificó" : "leyó"} un objeto de «${first.duenio}» en ${familyOfUrl(first.url)}${tally.leidos + tally.modificados > 1 ? ` (y ${tally.leidos + tally.modificados - 1} más)` : ""}. Falta registrarlo como hallazgo.`, `Cross-account access: «${first.identidad}» ${first.veredicto === "modificado" ? "modified" : "read"} an object of «${first.duenio}» at ${familyOfUrl(first.url)}${tally.leidos + tally.modificados > 1 ? ` (and ${tally.leidos + tally.modificados - 1} more)` : ""}. It still has to be recorded as a finding.`));
    }
    return { text: rows.join("\n"), details };
  }

  /** Listado de ids ajenos por familia, sin peticiones. */
  list(params: ProbeParams): ToolResult {
    const candidates = this.candidates({ identities: params.identities, owner: params.owner, values: params.values });
    const family = params.family?.toLowerCase();
    const groups = new Map<string, string[]>();
    let shown = 0;
    for (const candidate of candidates) {
      const targets = this.targetsOf(candidate, 2);
      const where = candidate.rows.find((row) => row.discovered) ?? candidate.rows[0]!;
      const pending = candidate.targets.filter((name) => !candidate.tested.has(name));
      const line = `  ${candidate.value} (${candidate.kind}) de ${candidate.owner} · ${where.method} ${pathOf(where.origin)} «${where.field}» → ${pending.length ? `probar con ${pending.join(", ")}` : `ya pedido por ${[...candidate.tested].join(", ")}`}${targets.length ? `: ${targets.map((target) => `${target.url} [${target.how}]`).join(" · ")}` : ": sin ruta conocida (pedí una vez el recurso con el dueño o pasá la URL a http_request)"}`;
      const key = targets.length ? familyOfUrl(targets[0]!.url) : "(sin familia)";
      if (family && !key.includes(family)) continue;
      const group = groups.get(key) ?? [];
      if (group.length < 15) group.push(line);
      groups.set(key, group);
      shown++;
    }
    const crosses = this.crosses();
    const lines = [`Ids cosechados en la sesión: ${this.size} · identidades: ${this.http.identityNames().join(", ") || "ninguna"}`];
    if (!shown) lines.push("No hay ids ajenos candidatos: hacen falta dos identidades del operador y que cada una pida sus propios listados, altas o páginas (los ids que le llegan sin pedirlos son suyos).");
    for (const [key, group] of groups) lines.push(key, ...group);
    if (crosses.length) {
      const count = (verdict: CrossVerdict) => crosses.filter((row) => row.verdict === verdict).length;
      lines.push(`Pruebas cruzadas hechas: ${crosses.length} (leídos ${count("leido")}, públicos ${count("publico")}, modificados ${count("modificado")}, negados ${count("negado") + count("redirigido")}, otro contenido ${count("distinto")}, ruta sin dueño ${count("ruta-no-sirve")})`);
    }
    if (shown) lines.push("mode «probar» los pide con la otra identidad (GET, con el dueño como control; sólo lectura salvo allowWrite).");
    return { text: lines.join("\n"), details: { candidatos: shown, cosechados: this.size, cruces: crosses.length } };
  }
}

export interface ProbeParams {
  mode?: "listar" | "probar";
  identities?: string[];
  owner?: string;
  family?: string;
  values?: string[];
  method?: string;
  allowWrite?: boolean;
  body?: string;
  maxRequests?: number;
  retest?: boolean;
  anonymousCheck?: boolean;
}

/** Escalares de un JSON por ruta, sin los campos que cambian solos (fechas, contadores, nonces). */
function scalars(node: unknown, path = "", out = new Map<string, string>(), depth = 0): Map<string, string> {
  if (depth > 6 || out.size > 500) return out;
  if (Array.isArray(node)) node.slice(0, 50).forEach((item, index) => scalars(item, `${path}[${index}]`, out, depth + 1));
  else if (node && typeof node === "object") for (const [key, value] of Object.entries(node)) {
    if (/(^|_)(at|date|time|timestamp|updated|modified|seen|now|nonce|csrf|etag|version|rev)$|^(updatedAt|modifiedAt|lastSeen|views|viewCount|view_count|requestId|request_id)$/i.test(key)) continue;
    scalars(value, path ? `${path}.${key}` : key, out, depth + 1);
  }
  else if (node !== null && node !== undefined) out.set(path, String(node));
  return out;
}

const parse = (body: string) => { try { return JSON.parse(body) as unknown; } catch { return undefined; } };
const plain = (body: string) => body.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ");

/**
 * ¿La otra identidad recibió el mismo objeto que el dueño? Idéntico, o el mismo JSON (80 % de sus
 * valores, sin fechas ni contadores) con el id adentro, o la misma página (mismo texto, sin un
 * formulario de contraseña que el dueño no tenía). Un 2xx con otro contenido (su propio objeto, una
 * página de error con 200, un cascarón vacío) no cuenta.
 */
function sameObject(owner: HttpExchange, other: HttpExchange, value: string): boolean {
  const a = owner.response?.body ?? "";
  const b = other.response?.body ?? "";
  if (a === b) return a.length > 0;
  const lower = value.toLowerCase();
  if (a.toLowerCase().includes(lower) && !b.toLowerCase().includes(lower)) return false;
  const ja = parse(a);
  const jb = parse(b);
  if (ja !== undefined && jb !== undefined) {
    const sa = scalars(ja);
    const sb = scalars(jb);
    if (!sa.size) return false;
    let same = 0;
    for (const [path, text] of sa) if (sb.get(path) === text) same++;
    return same / sa.size >= 0.8;
  }
  if (/type\s*=\s*["']?password/i.test(b) && !/type\s*=\s*["']?password/i.test(a)) return false;
  const tokens = (text: string) => new Set(plain(text).toLowerCase().match(/[\p{L}\p{N}_-]{4,}/gu) ?? []);
  const ta = tokens(a);
  const tb = tokens(b);
  if (!ta.size) return false;
  let shared = 0;
  for (const token of ta) if (tb.has(token)) shared++;
  return shared / ta.size >= 0.8 && Math.abs(a.length - b.length) <= Math.max(200, a.length * 0.2);
}

function readVerdict(owner: HttpExchange, other: HttpExchange, value: string): CrossVerdict {
  const code = other.response?.status;
  if (code === undefined) return "error";
  if ([401, 403, 404, 410].includes(code)) return "negado";
  if (code >= 300 && code < 400) return "redirigido";
  if (code >= 500) return "error";
  if (code >= 400) return "negado";
  return sameObject(owner, other, value) ? "leido" : "distinto";
}

/** Campos que cambiaron entre dos lecturas del dueño; si se mandó un JSON, sólo los que quedaron con lo enviado. */
function changedFields(before: HttpExchange, after: HttpExchange, sent?: string): string[] {
  const a = parse(before.response?.body ?? "");
  const b = parse(after.response?.body ?? "");
  if (a === undefined || b === undefined) return (before.response?.body ?? "") === (after.response?.body ?? "") ? [] : ["(cuerpo distinto)"];
  const sa = scalars(a);
  const sb = scalars(b);
  const changed = [...new Set([...sa.keys(), ...sb.keys()])].filter((path) => sa.get(path) !== sb.get(path));
  const body = sent ? parse(sent) : undefined;
  if (!body || typeof body !== "object") return changed;
  const wanted = scalars(body);
  return changed.filter((path) => [...wanted].some(([key, value]) => (path === key || path.endsWith(`.${key}`)) && sb.get(path) === value));
}

/**
 * Propiedad de una URL para escribir sobre ella: sin id de objeto (alta, /me) vale; con un id creado en
 * la sesión, también; si no, todos sus ids tienen que haberle llegado a esa identidad, y a ninguna otra.
 */
export function ownership(http: HttpClient, identity: string | undefined, url: string, owners?: (value: string) => Set<string>): { ok: boolean; why: string } {
  const ids = urlIds(url);
  if (!ids.length) return { ok: true, why: "la ruta no lleva id de objeto (un alta o un recurso de la propia cuenta)" };
  if (http.owns(url)) return { ok: true, why: "lleva un id creado en esta sesión" };
  if (!identity) return { ok: false, why: `la ruta lleva el id ${ids[0]} y la petición no usa ninguna identidad del operador` };
  if (!owners) return { ok: false, why: `la ruta lleva el id ${ids[0]}, que no es de un recurso creado en esta sesión` };
  for (const id of ids) {
    if (http.created.has(id)) continue;
    const seen = owners(id);
    if (!seen.has(identity)) return { ok: false, why: `el id ${id} nunca le llegó a «${identity}» en una respuesta sin pedirlo (no se sabe si es suyo)` };
    const others = [...seen].filter((owner) => owner !== identity);
    if (others.length) return { ok: false, why: `el id ${id} también le llegó a ${others.map((owner) => `«${owner}»`).join(", ")}: no se sabe de quién es` };
  }
  return { ok: true, why: `«${identity}» recibió esos ids como suyos` };
}

const str = (extra: object = {}) => ({ type: "string", ...extra });

/** Herramienta del agente: listar los ids ajenos por familia y pedirlos con otra identidad. */
export function createHarvestTool(harvest: IdHarvest): Tool {
  return {
    name: "ids_harvest",
    label: "Ids cruzados",
    description:
      "IDOR/BOLA con ids reales: el harness cosecha de cada respuesta (JSON, HTML, Location) los UUID, ObjectId e ids numéricos de campos id/*_id/uuid, por identidad que los vio y con la ruta y el campo. " +
      "mode «listar» (por defecto, sin peticiones) muestra por familia de ruta los ids que una identidad del operador recibió y otra nunca vio, con las URLs donde pedirlos. " +
      "mode «probar» los pide con la otra identidad: primero el dueño como control (si a él no le responde 2xx, no se sigue), después la otra identidad, y compara (LEYÓ = mismo objeto; un 2xx con otro contenido no cuenta); si lee, repite sin credenciales para separar lo público. " +
      "Usala cuando tengas dos identidades y cada una ya pidió sus listados o altas. Sólo lectura (GET, HEAD) salvo allowWrite a pedido explícito del operador (PUT/PATCH/POST con body; el dueño relee para ver si cambió); nunca DELETE. Respeta alcance, ritmo, tope y la guarda de borrado. Cada celda cuenta peticiones (máx. 60 por llamada).",
    parameters: {
      type: "object",
      properties: {
        mode: str({ enum: ["listar", "probar"] }),
        identities: { type: "array", items: str(), description: `Identidades con las que pedir los ids ajenos; por defecto todas las del operador que no los vieron. «${ANON}» prueba sin credenciales.` },
        owner: str({ description: "Sólo los ids de esta identidad" }),
        family: str({ description: "Sólo las rutas cuya familia contenga este texto, p. ej. /api/orders" }),
        values: { type: "array", items: str(), description: "Sólo estos ids" },
        method: str({ enum: ["GET", "HEAD", "POST", "PUT", "PATCH"] }),
        allowWrite: { type: "boolean", description: "Permite PUT/PATCH/POST sobre el recurso ajeno; sólo a pedido explícito del operador" },
        body: str({ maxLength: 5000, description: "Cuerpo para las escrituras (JSON o formulario)" }),
        maxRequests: { type: "integer", minimum: 1, maximum: 60, default: 24 },
        retest: { type: "boolean", description: "Repetir pruebas ya hechas" },
        anonymousCheck: { type: "boolean", description: "Si otra identidad lee, repetir sin credenciales (por defecto sí)" },
      },
      required: [],
    },
    execute: async (params: ProbeParams, signal) => ((params.mode ?? "listar") === "probar" ? harvest.probe(params, signal) : harvest.list(params)),
  };
}
