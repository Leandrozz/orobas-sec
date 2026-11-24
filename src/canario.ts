// Canario persistente («envenenar el registro»): un valor único y reconocible por campo que el agente
// siembra en registros y formularios (nombre, bio, dirección, comentario). El cliente HTTP le pasa cada
// respuesta: si un canario sembrado aparece en otra ruta o ante otra identidad, queda registrado dónde
// se sembró, dónde reapareció, quién lo vio y si salió sin escapar en HTML. Es la forma de ver XSS
// almacenado o de segundo orden, que una sonda que mira sólo su propia respuesta no ve.
//
// Costo: sin canarios no se hace nada; con canarios, una búsqueda del prefijo en los primeros
// CANARY_SCAN_BYTES de cada respuesta y, por aparición, una consulta a un mapa por id.
import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Tool, ToolResult } from "./agent.ts";
import { normalizePath, type HttpExchange } from "./http.ts";
import { logEvent } from "./store.ts";

/** Prefijo de todos los canarios: corto, raro en texto real y sin caracteres que un formulario rechace. */
export const CANARY_PREFIX = "orbc";
/** Lo que delata si la salida escapa HTML: se siembra pegado al canario. */
export const CANARY_PROBE = `<"'>`;
/** Bytes de cada respuesta (y de cada cuerpo enviado) que se revisan; lo que sigue no se mira. */
export const CANARY_SCAN_BYTES = 256 * 1024;
/** Apariciones por respuesta que se analizan. */
export const CANARY_MAX_MATCHES = 20;

const ID = /orbc([a-z0-9]{6})/gi;

/**
 * Cómo salió el sufijo de prueba pegado al canario: «sin escapar» (el < llegó literal), «parcial» (el <
 * escapado pero alguna comilla literal: peligroso dentro de un atributo), «escapado» (entidades HTML),
 * «codificado» (escapes de JavaScript/JSON o URL: depende de quién lo use) o «sin caracteres» (se sembró
 * la forma simple, o el servidor filtró o cortó los caracteres).
 */
export type EscapeState = "sin escapar" | "parcial" | "escapado" | "codificado" | "sin caracteres";

export interface CanarySowing {
  method: string;
  /** La petición llevaba el sufijo de prueba: sólo entonces se mide el escapado. */
  probe?: boolean;
  /** Ruta normalizada ({n} en los ids). */
  path: string;
  identity: string;
  /** Intercambio que lo llevó (h12). */
  exchange: string;
  at: string;
}

export interface Canary {
  id: string;
  token: string;
  field: string;
  /** Ruta donde el agente dijo que lo siembra (como la escribió) y normalizada. */
  route: string;
  routePath: string;
  sessionId: string;
  createdAt: string;
  /** Peticiones que lo llevaron: dónde se sembró de verdad y con qué identidad. */
  sown: CanarySowing[];
}

export interface CanaryHit {
  key: string;
  canary: string;
  token: string;
  field: string;
  /** Ruta declarada al crearlo y rutas e identidades donde se sembró de verdad. */
  route: string;
  sownPaths: string[];
  sownBy: string[];
  method: string;
  url: string;
  /** Ruta normalizada donde reapareció. */
  path: string;
  identity: string;
  exchange: string;
  artifact: string;
  escape: EscapeState;
  html: boolean;
  /** Sin escapar en una respuesta HTML: XSS almacenado probable. */
  unescapedHtml: boolean;
  otherRoute: boolean;
  otherIdentity: boolean;
  /** Unos caracteres alrededor, para ver el contexto sin abrir el artefacto. */
  snippet: string;
  sessionId: string;
  at: string;
}

const plain = (text: string) => text.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();

/** Nombre del campo como va en el canario: letras y números, hasta 20. */
export function fieldSlug(field: string): string {
  return plain(field).replace(/[^a-z0-9]+/g, "").slice(0, 20) || "campo";
}

/** Ruta de lo que el agente declaró («POST /api/perfil», una URL o una ruta), normalizada. */
export function routePath(route: string): string {
  const bare = route.trim().replace(/^[A-Z]+\s+/, "");
  return normalizePath(bare.startsWith("/") || /^[a-z][a-z0-9+.-]*:\/\//i.test(bare) ? bare : `/${bare}`) ?? "/";
}

const ESCAPES: Record<string, { entity: string[]; code: string[] }> = {
  "<": { entity: ["&lt;", "&#60;", "&#060;", "&#x3c;", "&#x003c;"], code: ["\\u003c", "\\x3c", "%3c", "\\074"] },
  '"': { entity: ["&quot;", "&#34;", "&#034;", "&#x22;", "&#x0022;"], code: ["\\u0022", '\\"', "\\x22", "%22"] },
  "'": { entity: ["&#39;", "&#039;", "&#x27;", "&#x0027;", "&apos;"], code: ["\\u0027", "\\'", "\\x27", "%27"] },
  ">": { entity: ["&gt;", "&#62;", "&#062;", "&#x3e;", "&#x003e;"], code: ["\\u003e", "\\x3e", "%3e", "\\076"] },
};

type Unit = "literal" | "entidad" | "codigo";

/** Forma en que aparece `char` al comienzo de `rest`, con su largo; undefined si no está. */
function unitAt(rest: string, char: string): { kind: Unit; length: number } | undefined {
  if (rest.startsWith(char)) return { kind: "literal", length: 1 };
  const entity = ESCAPES[char]!.entity.find((form) => rest.startsWith(form));
  if (entity) return { kind: "entidad", length: entity.length };
  const code = ESCAPES[char]!.code.find((form) => rest.startsWith(form));
  return code ? { kind: "codigo", length: code.length } : undefined;
}

/**
 * Lee el sufijo de prueba que sigue al canario en `text` desde `from` y dice cómo salió. Los caracteres
 * se buscan en orden y pueden faltar (un filtro que saca las comillas deja «<>»), pero hacen falta al
 * menos dos: un «<» suelto puede ser la etiqueta que sigue en el HTML («</li>»), no la prueba.
 */
export function classifyEscape(text: string, from: number): EscapeState {
  const order = [...CANARY_PROBE];
  const seen = new Map<string, Unit>();
  let at = from;
  for (let next = 0; next < order.length; ) {
    const rest = text.slice(at, at + 10).toLowerCase();
    let found: { index: number; unit: { kind: Unit; length: number } } | undefined;
    for (let index = next; index < order.length && !found; index++) {
      const unit = unitAt(rest, order[index]!);
      if (unit) found = { index, unit };
    }
    if (!found) break;
    seen.set(order[found.index]!, found.unit.kind);
    at += found.unit.length;
    next = found.index + 1;
  }
  if (seen.size < 2) return "sin caracteres";
  const lt = seen.get("<");
  const quotes = [seen.get('"'), seen.get("'")].filter(Boolean);
  if (lt === "literal") return "sin escapar";
  if (lt === "codigo") return "codificado";
  // Sin «<» literal no se abre una etiqueta, pero una comilla literal saca el valor de un atributo.
  if (quotes.includes("literal")) return "parcial";
  return !lt && quotes.length && quotes.every((kind) => kind === "codigo") ? "codificado" : "escapado";
}

/** ¿El texto enviado lleva el sufijo de prueba pegado al canario (crudo, en JSON, en URL o como entidad)? */
const PROBED = /^(<|\\u003c|%3c|&lt;)/i;

function finalUrl(exchange: HttpExchange): string {
  let url = exchange.request.url;
  for (const hop of exchange.redirects) {
    try { url = new URL(hop, url).href; } catch { /* salto ilegible: queda el anterior */ }
  }
  return url;
}

export class Canaries {
  readonly db: DatabaseSync;
  readonly sessionId: string;
  /** Canarios del proyecto por id: el segundo orden puede aparecer en otra sesión, mucho después. */
  private readonly active = new Map<string, Canary>();
  private readonly seenHits = new Set<string>();
  /** Reaparición nueva: el motor avisa al operador y al agente. */
  onHit?: (hit: CanaryHit) => void;

  constructor(db: DatabaseSync, sessionId: string) {
    this.db = db;
    this.sessionId = sessionId;
    db.exec("create table if not exists canaries(id text primary key, session_id text not null, created_at text not null, json text not null)");
    db.exec("create table if not exists canary_hits(key text primary key, canary_id text not null, session_id text not null, at text not null, json text not null)");
    for (const row of db.prepare("select json from canaries").all() as Array<{ json: string }>) {
      try {
        const canary = JSON.parse(row.json) as Canary;
        this.active.set(canary.id, canary);
      } catch { /* fila rota: no se vigila */ }
    }
    for (const row of db.prepare("select key from canary_hits").all() as Array<{ key: string }>) this.seenHits.add(row.key);
  }

  get size(): number {
    return this.active.size;
  }

  /** Canario nuevo para un campo, con la ruta donde se va a sembrar. */
  create(field: string, route: string): Canary {
    if (!field.trim()) throw new Error("Falta el campo: el nombre del campo donde lo vas a sembrar (nombre, bio, comentario).");
    if (!route.trim()) throw new Error("Falta la ruta donde lo vas a sembrar (p. ej. «POST /api/perfil»).");
    let id = "";
    do id = [...randomBytes(6)].map((byte) => "abcdefghijklmnopqrstuvwxyz0123456789"[byte % 36]).join("");
    while (this.active.has(id));
    const canary: Canary = { id, token: `${CANARY_PREFIX}${id}_${fieldSlug(field)}`, field: field.trim(), route: route.trim(), routePath: routePath(route), sessionId: this.sessionId, createdAt: new Date().toISOString(), sown: [] };
    this.active.set(id, canary);
    this.save(canary);
    logEvent(this.db, this.sessionId, "canario.creado", { id, token: canary.token, campo: canary.field, ruta: canary.route });
    return canary;
  }

  list(): Canary[] {
    return [...this.active.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  /** Reapariciones registradas; con `all`, las de todas las sesiones del proyecto. */
  hits(all = false): CanaryHit[] {
    const rows = (all ? this.db.prepare("select json from canary_hits order by at").all() : this.db.prepare("select json from canary_hits where session_id=? order by at").all(this.sessionId)) as Array<{ json: string }>;
    return rows.map((row) => JSON.parse(row.json) as CanaryHit);
  }

  private save(canary: Canary): void {
    this.db.prepare("insert or replace into canaries(id,session_id,created_at,json) values(?,?,?,?)").run(canary.id, canary.sessionId, canary.createdAt, JSON.stringify(canary));
  }

  /** Ids de canarios activos que aparecen en el texto (hasta el tope de apariciones). */
  private find(text: string): Array<{ canary: Canary; index: number; length: number }> {
    const found: Array<{ canary: Canary; index: number; length: number }> = [];
    ID.lastIndex = 0;
    for (let match = ID.exec(text); match && found.length < CANARY_MAX_MATCHES; match = ID.exec(text)) {
      const canary = this.active.get(match[1]!.toLowerCase());
      if (!canary) continue;
      // Si sigue el nombre del campo, el sufijo de prueba viene después de él.
      const suffix = canary.token.slice(CANARY_PREFIX.length + 6);
      const length = text.slice(match.index + match[0].length, match.index + match[0].length + suffix.length).toLowerCase() === suffix ? match[0].length + suffix.length : match[0].length;
      found.push({ canary, index: match.index, length });
    }
    return found;
  }

  /**
   * Revisa un intercambio terminado: si la petición lleva un canario, es una siembra; si la respuesta
   * trae uno que la petición no llevaba, en otra ruta o ante otra identidad que la de la siembra, es una
   * reaparición. Devuelve las reapariciones nuevas (cada combinación de canario, ruta, identidad y
   * escapado se registra una vez).
   */
  observe(exchange: HttpExchange, info: { identity: string; html: boolean }): CanaryHit[] {
    if (!this.active.size) return [];
    const request = exchange.request;
    const sent = [request.url, (request.body ?? "").slice(0, CANARY_SCAN_BYTES), ...Object.values(request.headers ?? {})].join("\n");
    const sentFound = this.find(sent);
    const carried = new Set(sentFound.map((item) => item.canary.id));
    const probed = new Set(sentFound.filter((item) => PROBED.test(sent.slice(item.index + item.length, item.index + item.length + 8))).map((item) => item.canary.id));
    const url = finalUrl(exchange);
    const path = normalizePath(url) ?? "/";
    const at = new Date().toISOString();
    for (const id of carried) {
      const canary = this.active.get(id)!;
      const previous = canary.sown.find((item) => item.path === normalizePath(request.url) && item.identity === info.identity && item.method === request.method);
      if (previous) {
        if (probed.has(id) && !previous.probe) {
          previous.probe = true;
          this.save(canary);
        }
        continue;
      }
      const sowing: CanarySowing = { method: request.method, path: normalizePath(request.url) ?? "/", identity: info.identity, exchange: exchange.id, at, ...(probed.has(id) ? { probe: true } : {}) };
      canary.sown.push(sowing);
      this.save(canary);
      logEvent(this.db, this.sessionId, "canario.sembrado", { id, token: canary.token, metodo: sowing.method, ruta: sowing.path, identidad: sowing.identity, intercambio: exchange.id });
    }
    const response = exchange.response;
    if (!response || response.bodyEncoding === "base64") return [];
    const body = response.body.length > CANARY_SCAN_BYTES ? response.body.slice(0, CANARY_SCAN_BYTES) : response.body;
    const text = `${Object.values(response.headers).join("\n")}\n${body}`;
    const hits: CanaryHit[] = [];
    for (const { canary, index, length } of this.find(text)) {
      // La misma petición lo llevaba: es un eco (reflejo), no algo guardado.
      if (carried.has(canary.id)) continue;
      const sownPaths = [...new Set([canary.routePath, ...canary.sown.map((item) => item.path)])];
      const sownBy = [...new Set(canary.sown.map((item) => item.identity))];
      const otherRoute = !sownPaths.includes(path);
      const otherIdentity = sownBy.length > 0 && !sownBy.includes(info.identity);
      if (!otherRoute && !otherIdentity) continue;
      // Si se sembró la forma simple, lo que sigue al canario es el documento, no la prueba.
      const escape = canary.sown.length && !canary.sown.some((item) => item.probe) ? "sin caracteres" : classifyEscape(text, index + length);
      const key = `${canary.id}|${request.method} ${path}|${info.identity}|${escape}`;
      if (this.seenHits.has(key)) continue;
      this.seenHits.add(key);
      const hit: CanaryHit = {
        key,
        canary: canary.id,
        token: canary.token,
        field: canary.field,
        route: canary.route,
        sownPaths,
        sownBy,
        method: request.method,
        url,
        path,
        identity: info.identity,
        exchange: exchange.id,
        artifact: exchange.artifact,
        escape,
        html: info.html,
        unescapedHtml: info.html && escape === "sin escapar",
        otherRoute,
        otherIdentity,
        snippet: text.slice(Math.max(0, index - 40), index + length + 40).replace(/\s+/g, " "),
        sessionId: this.sessionId,
        at,
      };
      this.db.prepare("insert or ignore into canary_hits(key,canary_id,session_id,at,json) values(?,?,?,?,?)").run(key, canary.id, this.sessionId, at, JSON.stringify(hit));
      logEvent(this.db, this.sessionId, "canario.reaparecido", {
        id: canary.id,
        token: canary.token,
        campo: canary.field,
        sembrado_en: canary.route,
        rutas_siembra: sownPaths,
        identidades_siembra: sownBy,
        reaparecio_en: `${request.method} ${path}`,
        identidad: info.identity,
        intercambio: exchange.id,
        artefacto: exchange.artifact,
        escape,
        html: info.html,
        sin_escapar_html: hit.unescapedHtml,
      });
      hits.push(hit);
      try { this.onHit?.(hit); } catch { /* un aviso que falla no rompe la petición */ }
    }
    return hits;
  }
}

/** Aviso para el agente sobre una reaparición: qué, dónde, quién y qué hacer. */
export function hitNotice(hit: CanaryHit): string {
  const where = `${hit.method} ${hit.path} (${hit.exchange}, identidad ${hit.identity})`;
  const sown = `sembrado en ${hit.route}${hit.sownBy.length ? ` por ${hit.sownBy.join(", ")}` : ""}`;
  const verdict = hit.unescapedHtml
    ? "SIN ESCAPAR en HTML: XSS almacenado probable. Confirmalo con una carga inofensiva en ese mismo campo (que se vea que el navegador la interpreta, sin robar nada) y registralo con finding_record con la siembra y esta respuesta como evidencia."
    : hit.escape === "sin escapar"
      ? "sin escapar, en una respuesta que no es HTML: mirá quién la muestra (una página que la inserte con innerHTML la vuelve XSS)."
      : hit.escape === "parcial"
        ? "con el < escapado pero comillas literales: si cae dentro de un atributo, se puede salir de él. Mirá el contexto en el artefacto."
        : hit.escape === "codificado"
          ? "codificado (escapes de JavaScript o URL): depende de quién lo decodifique. Mirá el contexto en el artefacto."
          : hit.escape === "escapado"
            ? "escapado: esa salida escapa HTML. Queda como evidencia de inyección probada en ese campo."
            : "sin los caracteres de prueba (se sembró la forma simple, o el servidor los filtró): sembrá el valor con < \" ' > para saber si escapa.";
  return `[sistema] Canario reapareció: «${hit.token}» (campo ${hit.field}, ${sown}) salió en ${where}${hit.otherIdentity ? ", otra identidad que la de la siembra" : ""}. ${verdict}`;
}

export function createCanaryTools(canaries: Canaries): Tool[] {
  const canaryNew: Tool = {
    name: "canary_new",
    label: "Crear canario",
    description:
      "Da un valor único y reconocible para sembrar en un campo que se guarda (nombre, bio, dirección, comentario, nombre de archivo) y deja anotado dónde se siembra. " +
      "Sembralo vos con http_request o el navegador; el harness revisa todas las respuestas: si el canario aparece en otra ruta o ante otra identidad, te avisa dónde, quién lo vio y si salió sin escapar en HTML (XSS almacenado o de segundo orden). Un canario por campo.",
    parameters: {
      type: "object",
      properties: {
        field: { type: "string", maxLength: 60, description: "Campo donde lo vas a sembrar" },
        route: { type: "string", maxLength: 300, description: "Dónde lo sembrás, p. ej. «POST /api/perfil» o la URL" },
      },
      required: ["field", "route"],
    },
    execute: (params): ToolResult => {
      const canary = canaries.create(String(params.field ?? ""), String(params.route ?? ""));
      const lines = [
        `Canario ${canary.id} para «${canary.field}» en ${canary.route}.`,
        `valor (con caracteres de prueba): ${canary.token}${CANARY_PROBE}`,
        `simple (si el campo rechaza < " ' >): ${canary.token}`,
        `email (campos de correo): ${canary.token}@example.com`,
        "Sembrá el valor con caracteres de prueba si el campo lo acepta: así se sabe si la salida escapa. Después recorré las vistas donde ese dato puede salir (listados, perfiles públicos, paneles de otra identidad, exportaciones, correos): el aviso llega solo.",
      ];
      return { text: lines.join("\n"), details: { canario: canary.id, token: canary.token } };
    },
  };
  const canaryList: Tool = {
    name: "canary_list",
    label: "Listar canarios",
    description: "Canarios del proyecto: dónde se declaró cada uno, dónde se sembró de verdad (peticiones que lo llevaron) y dónde reapareció, con identidad y escapado.",
    parameters: { type: "object", properties: {}, required: [] },
    parallel: true,
    replay: "safe",
    execute: (): ToolResult => {
      const list = canaries.list();
      if (!list.length) return { text: "No hay canarios. Pedí uno con canary_new.", details: { canarios: 0 } };
      const hits = canaries.hits(true);
      const lines = list.flatMap((canary) => {
        const own = hits.filter((hit) => hit.canary === canary.id);
        return [
          `${canary.id} ${canary.token} · campo ${canary.field} · declarado en ${canary.route}`,
          `  sembrado: ${canary.sown.length ? canary.sown.map((item) => `${item.method} ${item.path} (${item.identity}, ${item.exchange})`).join("; ") : "todavía ninguna petición lo llevó"}`,
          ...(own.length ? own.map((hit) => `  reapareció: ${hit.method} ${hit.path} (${hit.identity}, ${hit.exchange}) · ${hit.escape}${hit.html ? " en HTML" : ""}`) : ["  reapareció: en ninguna otra ruta ni identidad todavía"]),
        ];
      });
      return { text: lines.join("\n"), details: { canarios: list.length, reapariciones: hits.length } };
    },
  };
  return [canaryNew, canaryList];
}
