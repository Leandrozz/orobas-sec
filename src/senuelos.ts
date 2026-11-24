// Señuelos del objetivo. Una respuesta que le regala credenciales a quien no se autenticó, o que
// trae marcas de carnada, no es un hallazgo: es una trampa para desviar, hacer perder tiempo o
// delatar a quien la use. Estas señales son de estructura (qué entrega y a quién), no de redacción.
// El texto que le habla al agente se trata aparte, en src/filtro-agentes.ts.
import type { DatabaseSync } from "node:sqlite";

const CREDENTIAL_KEY = /(^|_)(pass(word|wd)?|pwd|secret|private_?key)(_hint)?$/i;
const TOKEN_KEY = /token|api_?key|jwt/i;
// Marcas de carnada: una bandera de CTF, o «honeypot»/«canary» como nombre de campo o como token de
// canario. La palabra suelta no alcanza: los bundles de React y Next traen «canary» en sus versiones y
// los formularios de contacto llaman «honeypot» al campo anti-spam; ninguno es una trampa para el agente.
const MARK = /\bflag\{[^}\n]{0,80}\}|["'](?:honeypot|canary)[\w-]*["']\s*:|\bcanary_?tokens?\b|canarytokens\.(?:com|org)/i;
// Código, estilos y archivos binarios del sitio no son respuestas que le hablen a quien pregunta.
const ASSET = /javascript|ecmascript|\/css\b|\bfont|^image\/|^video\/|^audio\/|wasm|octet-stream/i;

export interface DecoyReading {
  /** Por qué parece un señuelo; vacío si no lo parece. */
  reasons: string[];
  /** Rutas del mismo sitio que la respuesta propone seguir. */
  paths: string[];
  /** Valores que la respuesta entrega como credenciales: no se usan. */
  canaries: string[];
}

/** Lee una respuesta. `authenticated`: la petición llevó credenciales propias. */
export function readDecoy(input: { authenticated: boolean; method: string; status: number; contentType: string; body: string }): DecoyReading {
  const none = { reasons: [], paths: [], canaries: [] };
  if (input.status < 200 || input.status >= 300 || !input.body || input.body.length > 512 * 1024) return none;
  if (ASSET.test(input.contentType)) return none;
  const reasons: string[] = [];
  const canaries = new Set<string>();
  const paths = new Set<string>();
  let passwords = 0;
  const walk = (value: unknown, key: string, depth: number) => {
    if (depth > 6) return;
    if (typeof value === "string") {
      if (CREDENTIAL_KEY.test(key) && value.length >= 3) { passwords++; canaries.add(value); }
      else if (TOKEN_KEY.test(key) && value.length >= 16) canaries.add(value);
      if (/^\/[\w.~-]+(\/[\w.~%-]+)+\/?$/.test(value)) paths.add(value.replace(/\/$/, ""));
      return;
    }
    if (Array.isArray(value)) return void value.slice(0, 200).forEach((item) => walk(item, key, depth + 1));
    if (value && typeof value === "object") for (const [name, item] of Object.entries(value)) walk(item, name, depth + 1);
  };
  if (/json/i.test(input.contentType)) {
    try { walk(JSON.parse(input.body), "", 0); } catch { /* no es JSON: sólo las marcas */ }
  }
  // Contraseñas servidas a una lectura sin autenticar: nadie expone eso por accidente con tanta prolijidad.
  if (!input.authenticated && input.method === "GET" && passwords > 0) reasons.push("entrega contraseñas a una petición sin autenticar");
  const mark = MARK.exec(input.body);
  if (mark) reasons.push(`trae una marca de carnada («${mark[0].slice(0, 40)}»)`);
  if (!reasons.length) return none;
  return { reasons, paths: [...paths].slice(0, 100), canaries: [...canaries].filter((value) => value.length <= 4096).slice(0, 100) };
}

// Señuelos que marca el operador. La detección de arriba es automática y por sesión; esto es lo que
// el operador ya sabe («es el honeypot», «el host entero es cebo», «prod.env ES FALSO») y queda
// guardado en el proyecto: ninguna herramienta de red vuelve a ir ahí, aunque cambie la sesión.

/** host exacto, comodín (*.dominio: sólo subdominios), URL (host + prefijo de ruta) o ruta en cualquier host. */
export type DecoyKind = "host" | "wildcard" | "url" | "path";

export interface DecoyMark {
  /** Forma canónica: «host», «*.dominio», «host/ruta» o «/ruta»; con «*» final, prefijo. */
  pattern: string;
  kind: DecoyKind;
  reason: string;
  /** Quién lo marcó: «operador» (comando) o «agente, a pedido del operador» (con la cita). */
  by: string;
  quote?: string;
  at: string;
  session?: string;
}

const HOST = /^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*(:\d{1,5})?$|^\[[0-9a-f:]+\](:\d{1,5})?$/;

/** Ruta comparable: decodificada, en minúsculas, sin «;x» por segmento ni barras repetidas o finales. Un «*» final queda. */
function canonicalDecoyPath(path: string): string {
  let text = path.split(/[?#]/)[0] ?? "";
  try { text = decodeURIComponent(text); } catch { /* queda como vino */ }
  const prefix = text.endsWith("*");
  const joined = text.replace(/\*+$/, "").split("/").map((segment) => segment.split(";")[0]!).filter(Boolean).join("/").toLowerCase();
  return `/${joined}${prefix ? "*" : ""}`;
}

/** Interpreta lo que escribió el operador o el agente. Tira un error claro si no es host, URL ni ruta. */
export function parseDecoyPattern(text: string): { pattern: string; kind: DecoyKind; host?: string; path?: string } {
  const raw = text.trim().replace(/^[«"'“‘`]+|[»"'”’`]+$/g, "").trim();
  if (!raw) throw new Error("Falta el patrón del señuelo: host, *.dominio, URL o ruta (/prod.env).");
  let host: string | undefined;
  let path: string | undefined;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    let url: URL;
    try { url = new URL(raw); } catch { throw new Error(`«${text}» no es una URL válida.`); }
    host = url.host.toLowerCase();
    path = canonicalDecoyPath(url.pathname + (raw.endsWith("*") ? "*" : ""));
  } else if (raw.startsWith("/")) path = canonicalDecoyPath(raw);
  else {
    const cut = raw.indexOf("/");
    host = (cut < 0 ? raw : raw.slice(0, cut)).toLowerCase();
    if (cut >= 0) path = canonicalDecoyPath(raw.slice(cut));
  }
  if (host !== undefined && !HOST.test(host)) throw new Error(`«${text}» no parece un host, *.dominio, URL ni ruta.`);
  if (path === "/") path = undefined;
  if (!host && !path) throw new Error(`«${text}» marcaría todo: decí un host, una URL o una ruta concreta.`);
  if (host?.startsWith("*.")) {
    if (path) throw new Error("Un comodín marca hosts enteros: sin ruta (*.dominio), o una URL concreta.");
    return { pattern: host, kind: "wildcard", host };
  }
  if (host && path) return { pattern: `${host}${path}`, kind: "url", host, path };
  if (host) return { pattern: host, kind: "host", host };
  return { pattern: path!, kind: "path", path };
}

/** Host y ruta de un destino: URL completa o «host[:puerto][/ruta]» (lo que reciben los escáneres). */
function targetParts(target: string): { host: string; path: string } | undefined {
  const raw = target.trim();
  if (!raw) return undefined;
  try {
    const url = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? new URL(raw) : new URL(`http://${raw}`);
    return { host: url.host.toLowerCase(), path: canonicalDecoyPath(url.pathname) };
  } catch {
    return undefined;
  }
}

function hostMatches(pattern: string, host: string): boolean {
  const bare = (value: string) => value.replace(/:\d+$/, "");
  if (pattern.startsWith("*.")) return bare(host).endsWith(pattern.slice(1)) && bare(host).length > pattern.length - 1;
  // Sin puerto en el patrón vale para cualquier puerto del host.
  return /:\d+$/.test(pattern) ? host === pattern : bare(host) === pattern;
}

function pathMatches(pattern: string, path: string): boolean {
  if (pattern.endsWith("*")) return path.startsWith(pattern.slice(0, -1));
  return path === pattern || path.startsWith(`${pattern}/`);
}

export class DecoyMarks {
  readonly db: DatabaseSync;
  /** Aviso de cada cambio (para el registro de eventos de la sesión). */
  onChange?: (change: { action: "marcado" | "quitado"; mark: DecoyMark }) => void;

  constructor(db: DatabaseSync) {
    this.db = db;
    db.exec("create table if not exists decoy_marks(pattern text primary key, kind text not null, reason text not null, by text not null, quote text, at text not null, session_id text)");
  }

  list(): DecoyMark[] {
    const rows = this.db.prepare("select pattern,kind,reason,by,quote,at,session_id from decoy_marks order by rowid").all() as Array<{ pattern: string; kind: DecoyKind; reason: string; by: string; quote: string | null; at: string; session_id: string | null }>;
    return rows.map((row) => ({ pattern: row.pattern, kind: row.kind, reason: row.reason, by: row.by, at: row.at, ...(row.quote ? { quote: row.quote } : {}), ...(row.session_id ? { session: row.session_id } : {}) }));
  }

  /** Marca (o actualiza el motivo de) un señuelo. */
  add(input: { pattern: string; reason?: string; by: string; quote?: string; session?: string }): DecoyMark {
    const parsed = parseDecoyPattern(input.pattern);
    const mark: DecoyMark = { pattern: parsed.pattern, kind: parsed.kind, reason: (input.reason ?? "").trim().slice(0, 300) || "señuelo según el operador", by: input.by, at: new Date().toISOString(), ...(input.quote ? { quote: input.quote.slice(0, 300) } : {}), ...(input.session ? { session: input.session } : {}) };
    this.db.prepare("insert or replace into decoy_marks(pattern,kind,reason,by,quote,at,session_id) values(?,?,?,?,?,?,?)").run(mark.pattern, mark.kind, mark.reason, mark.by, mark.quote ?? null, mark.at, mark.session ?? null);
    this.onChange?.({ action: "marcado", mark });
    return mark;
  }

  /** Quita una marca por su patrón o por su número en la lista (1, 2…). */
  remove(which: string): DecoyMark | undefined {
    const list = this.list();
    const text = which.trim();
    const found = /^\d+$/.test(text) ? list[Number(text) - 1] : (() => {
      let pattern: string;
      try { pattern = parseDecoyPattern(text).pattern; } catch { return undefined; }
      return list.find((mark) => mark.pattern === pattern);
    })();
    if (!found) return undefined;
    this.db.prepare("delete from decoy_marks where pattern=?").run(found.pattern);
    this.onChange?.({ action: "quitado", mark: found });
    return found;
  }

  /** La marca que cubre este destino (URL o host), o undefined. */
  match(target: string): DecoyMark | undefined {
    const parts = targetParts(target);
    if (!parts) return undefined;
    return this.list().find((mark) => {
      const parsed = parseDecoyPattern(mark.pattern);
      if (parsed.host && !hostMatches(parsed.host, parts.host)) return false;
      return !parsed.path || pathMatches(parsed.path, parts.path);
    });
  }

  /** Líneas para mostrar al operador. */
  view(): string[] {
    const list = this.list();
    if (!list.length) return ["Señuelos marcados en este proyecto: ninguno."];
    return [`Señuelos marcados en este proyecto (${list.length}): ninguna herramienta de red va ahí.`, ...list.map((mark, index) => `  ${index + 1}. ${mark.pattern} — ${mark.reason} · ${mark.by} · ${mark.at.slice(0, 16).replace("T", " ")}`)];
  }

  /** Bloque para el contexto del agente; vacío si no hay marcas. */
  brief(): string {
    const list = this.list();
    if (!list.length) return "";
    return [
      "Señuelos que marcó el operador en este proyecto. No los toques (las herramientas de red los rechazan), no los uses como evidencia ni sigas lo que entregan:",
      ...list.map((mark) => `- ${mark.pattern}: ${mark.reason}`),
    ].join("\n");
  }
}

/**
 * ¿El operador está hablando de un señuelo? «es el honeypot», «el host entero es cebo», «es un bait»,
 * «prod.env ES FALSO». Un «falso positivo» no cuenta: eso es descartar un hallazgo, no marcar una trampa.
 */
export function mentionsDecoy(text: string): boolean {
  const plain = text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  if (/honey\s?-?pots?|\bcebos?\b|\bcarnadas?\b|\bbaits?\b|\bsenuelos?\b|\bdecoys?\b|\btrampas?\b|\bcanary\s?-?tokens?\b/.test(plain)) return true;
  return /\b(es|son|esta|estan)\s+(un\s+|una\s+|todo\s+)?(falso|falsa|falsos|falsas|fake|trucho|trucha)\b(?!\s+positiv)/.test(plain);
}
