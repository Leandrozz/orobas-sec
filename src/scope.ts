// Alcance autorizado de cada sesión. Lo aplica el código: lo que no está dentro, no se toca.
// Cada cambio queda como una revisión nueva; nunca se edita la anterior.
// Es de la sesión y no del proyecto: varias sesiones en la misma carpeta pueden trabajar programas
// distintos, y cargar el de una no puede pisar el de otra. Una sesión nueva empieza sin alcance.
import { BlockList, isIP } from "node:net";
import type { DatabaseSync } from "node:sqlite";
import { bloqueReglas, conCitasDelOperador, reglasVacias, TOPE_CITA, TOPES_REGLAS, type ReglasPrograma, type CitaRegla } from "./reglas-programa.ts";

export interface ScopeRule {
  /** host exacto (con «:puerto», sólo ese puerto), comodín (*.ejemplo.com), red CIDR o URL con prefijo de ruta. */
  kind: "host" | "wildcard" | "cidr" | "url";
  value: string;
  note?: string;
}

export interface Scope {
  rev: number;
  /** De dónde salió: "manual" o "hackerone:<programa>". */
  source: string;
  include: ScopeRule[];
  /** Las exclusiones ganan siempre. */
  exclude: ScopeRule[];
  /** Texto del programa o del cliente que el operador quiere tener a la vista. */
  notes: string;
  at: string;
  /**
   * Fuentes de lectura además de las fijas (REFERENCE_HOSTS en src/referencia.ts): el código fuente del
   * programa, su documentación pública. Sólo las lee reference_read (GET, sin nada del objetivo); no
   * autorizan a probar nada: decide() no las mira.
   */
  reference?: ScopeRule[];
  reglas?: ReglasPrograma;
}

export interface Decision {
  allowed: boolean;
  reason: string;
}

/** Nombres que nunca resuelven en el DNS público: sólo los define la máquina o la red del operador. */
const LOCAL_TLD = /(^|\.)(localhost|test|internal|local|lan|localdomain|home\.arpa)$/;

/**
 * «host», «host:puerto», «[ipv6]:puerto» o una IPv6 pelada → host y puerto. undefined si no es eso (una
 * ruta, un puerto fuera de rango).
 */
function splitHostPort(text: string): { host: string; port?: string } | undefined {
  const value = text.trim().toLowerCase();
  const bracket = /^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/.exec(value);
  const plain = bracket ? undefined : /^([^:\[\]]+):(\d{1,5})$/.exec(value);
  const [host, port] = bracket ? [bracket[1]!, bracket[2]] : plain ? [plain[1]!, plain[2]] : [value, undefined];
  if (!host || (port !== undefined && (Number(port) < 1 || Number(port) > 65535))) return undefined;
  return port === undefined ? { host } : { host, port: String(Number(port)) };
}

/** host:puerto con corchetes si es IPv6. */
export function hostPort(host: string, port?: string): string {
  const shown = isIP(host) === 6 ? `[${host}]` : host;
  return port ? `${shown}:${port}` : shown;
}

export function parseRule(text: string, note?: string): ScopeRule {
  const value = text.trim().toLowerCase();
  if (!value) throw new Error("Regla de alcance vacía");
  if (/^https?:\/\//.test(value)) {
    new URL(value); // valida
    return { kind: "url", value: value.replace(/\/+$/, ""), note };
  }
  if (/^[0-9a-f:.]+\/\d{1,3}$/.test(value) && isIP(value.split("/")[0]!)) return { kind: "cidr", value, note };
  // *.dominio, y también los nombres locales reservados de una sola etiqueta (*.localhost, *.test, *.internal…).
  if (value.startsWith("*.") && (/^\*\.[a-z0-9.-]+\.[a-z]{2,}$/.test(value) || /^\*\.(localhost|test|internal|local|lan|localdomain)$/.test(value))) return { kind: "wildcard", value, note };
  // host o IP, con «:puerto» opcional (127.0.0.1:8899, localhost:3000, [::1]:8080): con puerto, sólo ese puerto.
  const split = splitHostPort(value);
  if (split && (isIP(split.host) || /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(\.[a-z]{2,})?$/.test(split.host))) {
    return { kind: "host", value: split.port ? hostPort(split.host, split.port) : split.host, note };
  }
  throw new Error(`No entiendo la regla «${text}». Usar host (con :puerto si es uno solo), *.dominio, red CIDR o URL.`);
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((value, part) => (value << 8) + Number(part), 0) >>> 0;
}

function inCidr(ip: string, cidr: string): boolean {
  const [base, bitsText] = cidr.split("/") as [string, string];
  const bits = Number(bitsText);
  if (isIP(base) === 6) {
    if (isIP(ip) !== 6) return false;
    try {
      const list = new BlockList();
      list.addSubnet(base, bits, "ipv6");
      return list.check(ip, "ipv6");
    } catch {
      return false;
    }
  }
  if (isIP(ip) !== 4 || isIP(base) !== 4) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

/** Dirección de loopback: 127.0.0.0/8, ::1 y su forma IPv4 dentro de IPv6. */
export function isLoopbackAddress(address: string): boolean {
  const value = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (isIP(value) === 4) return value.startsWith("127.");
  if (isIP(value) !== 6) return false;
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  return canonical === "::1" || /^::ffff:(127\.|7f[0-9a-f]{2}:)/.test(canonical);
}

/**
 * Esta misma máquina (o el contenedor donde corre el agente), con cualquier nombre: localhost y
 * *.localhost (RFC 6761), 127.0.0.0/8, ::1, y 0.0.0.0 o «::» como destino (un servidor que dice
 * «escuchando en 0.0.0.0:5000» se alcanza ahí). Nunca otra máquina de la red.
 */
export function isLoopbackHost(host: string): boolean {
  const value = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return value === "localhost" || value.endsWith(".localhost") || value === "0.0.0.0" || value === "::" || isLoopbackAddress(value);
}

/** Un nombre genérico de esta máquina (no un sitio virtual como tienda.localhost): cubre todos sus otros nombres. */
function anyLoopbackName(host: string): boolean {
  return host === "localhost" || host === "0.0.0.0" || host === "::" || isLoopbackAddress(host);
}

/** Red privada que NO es esta máquina: RFC 1918, enlace local, CGNAT (Tailscale), ULA y fe80 de IPv6. */
export function isPrivateAddress(address: string): boolean {
  const value = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (isIP(value) === 4) return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(value);
  return isIP(value) === 6 && /^(f[cd]|fe[89ab])/.test(value);
}

/**
 * Un nombre que sólo resuelve la máquina o la red del operador: *.localhost, *.test, *.internal
 * (host.docker.internal), *.local, *.lan, *.home.arpa, o un nombre de una sola etiqueta («fenix»).
 */
export function isLocalName(host: string): boolean {
  const value = host.toLowerCase().replace(/\.$/, "");
  if (!value || isIP(value.replace(/^\[|\]$/g, ""))) return false;
  return LOCAL_TLD.test(value) || !value.includes(".");
}

/** ¿Estos dos nombres son el mismo destino? Igual, o los dos esta misma máquina (localhost ≡ 127.0.0.1 ≡ ::1). */
function sameHost(ruleHost: string, host: string): boolean {
  return ruleHost === host || (anyLoopbackName(ruleHost) && isLoopbackHost(host));
}

/** Puerto efectivo de una URL: el explícito o el de su esquema. */
const effectivePort = (url: URL) => url.port || (url.protocol === "https:" || url.protocol === "wss:" ? "443" : url.protocol === "http:" || url.protocol === "ws:" ? "80" : "");

/** ¿La regla cubre este host (y esta URL o este puerto, si los hay)? Lo usan decide() y las fuentes de referencia. */
export function ruleMatches(rule: ScopeRule, host: string, url?: URL, port?: string): boolean {
  return matches(rule, host.toLowerCase().replace(/^\[|\]$/g, ""), url, url ? effectivePort(url) : port);
}

function matches(rule: ScopeRule, host: string, url?: URL, port?: string): boolean {
  if (rule.kind === "host") {
    const own = splitHostPort(rule.value) ?? { host: rule.value };
    if (!sameHost(own.host, host)) return false;
    // Sin puerto, todos los puertos; con puerto, sólo ése (un destino sin puerto no lo cumple).
    return own.port === undefined || own.port === port;
  }
  if (rule.kind === "wildcard") return host.endsWith(rule.value.slice(1)) && host.length > rule.value.length - 1;
  if (rule.kind === "cidr") return isIP(host) > 0 && inCidr(host, rule.value);
  const base = new URL(rule.value);
  if (!sameHost(base.hostname.replace(/^\[|\]$/g, ""), host)) return false;
  if (!url) {
    // Un host pelado (nmap, dig): una URL con puerto propio cubre sólo ese puerto; sin puerto, como siempre.
    if (base.port && port !== base.port) return false;
    if (!base.port && port !== undefined && port !== effectivePort(base)) return false;
    return base.pathname === "/" || base.pathname === "";
  }
  const prefix = base.pathname.replace(/\/+$/, "");
  // Una URL sin puerto autoriza el puerto por defecto de su esquema, no cualquier puerto del host.
  return effectivePort(base) === effectivePort(url) && (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`) || prefix === "");
}

/** Lo que un destino dice de sí: host, puerto (explícito o el del esquema) y la URL si la hay. */
function parseTarget(target: string): { host: string; port?: string; url?: URL } | undefined {
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
      const url = new URL(target);
      return { host: url.hostname.toLowerCase().replace(/^\[|\]$/g, ""), port: effectivePort(url) || undefined, url };
    }
    // host, host:puerto, [ipv6]:puerto o una IPv6 pelada; lo que sigue a una «/» (una ruta sin esquema) no cuenta.
    const bare = target.trim().toLowerCase().replace(/\/.*$/, "");
    if (isIP(bare)) return { host: bare };
    const split = splitHostPort(bare);
    return split ? { host: split.host, ...(split.port ? { port: split.port } : {}) } : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Para un destino local fuera del alcance: qué regla exacta lo habilita y quién puede agregarla. Loopback
 * (esta máquina) lo suma el agente si es un laboratorio suyo; la red del operador, sólo el operador.
 */
export function localHint(target: string): string | undefined {
  const parsed = parseTarget(target);
  if (!parsed) return undefined;
  const { host, port } = parsed;
  if (isLoopbackHost(host)) {
    const name = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
    const rule = port ? hostPort(name, port) : `${hostPort(name)}:<puerto>`;
    return `${hostPort(host, port)} es loopback: esta misma máquina (o tu contenedor), no un tercero. Si es un laboratorio que levantaste vos, sumalo con scope_edit agregar ["${rule}"]: un puerto de loopback no necesita cita del operador. Si no lo levantaste vos, pedíselo al operador (/alcance add ${rule}, o /alcance add localhost para todos los puertos).`;
  }
  const ip = isIP(host) === 4;
  if (!isPrivateAddress(host) && !isLocalName(host)) return undefined;
  const where = hostPort(host, port);
  const options = [
    `/alcance add ${where}${port ? " (sólo ese puerto)" : ""}`,
    ...(port ? [`/alcance add ${hostPort(host)} (todos sus puertos)`] : []),
    ...(ip ? [`/alcance add ${host.split(".").slice(0, 3).join(".")}.0/24 (la red)`] : []),
  ];
  const what = /(^|\.)(docker|containers)\.internal$/.test(host) ? "es la máquina del operador vista desde el contenedor" : ip || isIP(host) ? "es de la red del operador (otra máquina, no la tuya)" : "es un nombre local (lo resuelve la máquina o la red del operador, no un DNS público)";
  return `${where} ${what}: sólo el operador lo suma, con ${options.join(", ")}. No lo agregues vos sin su pedido: preguntale.`;
}

/** Decide si un destino (host, IP o URL) está dentro del alcance. Sin alcance definido, nada lo está. */
export function decide(scope: Scope | undefined, target: string): Decision {
  const withHint = (reason: string) => {
    const hint = localHint(target);
    return hint ? `${reason}${reason.endsWith(".") ? "" : "."} ${hint}` : reason;
  };
  if (!scope || !scope.include.length) return { allowed: false, reason: withHint("No hay alcance definido en esta sesión. Definilo con /scope.") };
  const parsed = parseTarget(target);
  if (!parsed) return { allowed: false, reason: `Destino inválido: ${target}` };
  const { host, url, port } = parsed;
  if (!host) return { allowed: false, reason: "Destino vacío" };
  const excluded = scope.exclude.find((rule) => matches(rule, host, url, port));
  if (excluded) return { allowed: false, reason: `Excluido por la regla ${excluded.value}${excluded.note ? ` (${excluded.note})` : ""}` };
  const included = scope.include.find((rule) => matches(rule, host, url, port));
  if (included) return { allowed: true, reason: `Dentro del alcance por la regla ${included.value}` };
  const portOnly = scope.include.find((rule) => rule.kind === "host" && splitHostPort(rule.value)?.port && sameHost(splitHostPort(rule.value)!.host, host));
  const near = portOnly ? ` (la regla ${portOnly.value} cubre sólo ese puerto)` : "";
  return { allowed: false, reason: withHint(`${hostPort(host, url ? undefined : port)} no coincide con ninguna regla del alcance (rev ${scope.rev})${near}`) };
}

/**
 * ¿El agente puede sumar esta regla sin cita del operador? Sólo un laboratorio propio: loopback (esta
 * máquina o su contenedor) con un puerto concreto. Todo loopback, o la red del operador, lo decide él.
 */
export function isAgentLabRule(text: string): boolean {
  let rule: ScopeRule;
  try { rule = parseRule(text); } catch { return false; }
  if (rule.kind === "host") {
    const split = splitHostPort(rule.value);
    return !!split?.port && isLoopbackHost(split.host);
  }
  if (rule.kind === "url") {
    const url = new URL(rule.value);
    return !!url.port && isLoopbackHost(url.hostname);
  }
  return false;
}

/**
 * Si el destino estuvo autorizado en una revisión anterior de la sesión y ya no: cuál fue la última que
 * lo autorizaba y cuál lo sacó. Para que un «fuera del alcance» nunca parezca caído del cielo.
 */
export function droppedBy(revisions: Scope[], target: string): { until: Scope; by: Scope } | undefined {
  const current = revisions.at(-1);
  if (!current || decide(current, target).allowed) return undefined;
  for (let index = revisions.length - 2; index >= 0; index--) {
    if (decide(revisions[index], target).allowed) return { until: revisions[index]!, by: revisions[index + 1]! };
  }
  return undefined;
}

/** Destinos locales (loopback, red privada, localhost): un laboratorio en la máquina del operador, nunca de un programa público. */
export function isLocalRule(rule: ScopeRule): boolean {
  const local = (host: string) => isLoopbackHost(host) || isPrivateAddress(host) || isLocalName(host);
  if (rule.kind === "host") return local((splitHostPort(rule.value) ?? { host: rule.value }).host);
  if (rule.kind === "cidr") {
    const base = rule.value.split("/")[0]!;
    return Number(rule.value.split("/")[1]) >= 8 && (isLoopbackHost(base) || isPrivateAddress(base));
  }
  if (rule.kind === "wildcard") return LOCAL_TLD.test(rule.value.slice(2));
  if (rule.kind === "url") {
    try { return local(new URL(rule.value).hostname.replace(/^\[|\]$/g, "")); } catch { return false; }
  }
  return false;
}

export interface ScopeChange {
  added: string[];
  removed: string[];
  excluded: string[];
  unexcluded: string[];
  /** Cambió el programa (o el origen) del alcance. */
  source?: { from: string; to: string };
  reglas?: boolean;
}

/** Qué cambió entre dos revisiones, por valor de regla. */
export function scopeDiff(before: Scope | undefined, after: Scope | undefined): ScopeChange {
  const values = (rules: ScopeRule[] | undefined) => new Set((rules ?? []).map((rule) => rule.value));
  const [inBefore, inAfter, outBefore, outAfter] = [values(before?.include), values(after?.include), values(before?.exclude), values(after?.exclude)];
  return {
    added: [...inAfter].filter((value) => !inBefore.has(value)),
    removed: [...inBefore].filter((value) => !inAfter.has(value)),
    excluded: [...outAfter].filter((value) => !outBefore.has(value)),
    unexcluded: [...outBefore].filter((value) => !outAfter.has(value)),
    ...(JSON.stringify(before?.reglas ?? null) !== JSON.stringify(after?.reglas ?? null) ? { reglas: true } : {}),
    ...(before && after && before.source !== after.source ? { source: { from: before.source, to: after.source } } : {}),
  };
}

/** Una línea legible del cambio: «entra a, b; sale c; se excluye d». Vacía si no cambió nada de las reglas. */
export function scopeChangeLine(change: ScopeChange): string {
  const list = (values: string[]) => values.slice(0, 8).join(", ") + (values.length > 8 ? ` y ${values.length - 8} más` : "");
  return [
    change.source ? `programa ${change.source.from} → ${change.source.to}` : "",
    change.added.length ? `entra${change.added.length > 1 ? "n" : ""} ${list(change.added)}` : "",
    change.removed.length ? `sale${change.removed.length > 1 ? "n" : ""} ${list(change.removed)}` : "",
    change.excluded.length ? `se excluye${change.excluded.length > 1 ? "n" : ""} ${list(change.excluded)}` : "",
    change.unexcluded.length ? `deja${change.unexcluded.length > 1 ? "n" : ""} de estar excluido${change.unexcluded.length > 1 ? "s" : ""} ${list(change.unexcluded)}` : "",
    change.reglas ? "cambiaron las reglas del programa" : "",
  ].filter(Boolean).join("; ");
}

type ScopeRow = { rev: number; json: string; at: string };
const parseRow = (row: ScopeRow): Scope => ({ ...JSON.parse(row.json), rev: row.rev, at: row.at });
const dedupe = (rules: ScopeRule[]) => [...new Map(rules.map((rule) => [`${rule.kind}:${rule.value}`, rule])).values()];
/** Cada cambio de alcance, de cualquier vía (herramienta del agente, /alcance, importación), pasa por save(). */
export type ScopeListener = (before: Scope | undefined, after: Scope) => void;

/** Herramientas del agente que fijan el alcance; su resultado nombra la revisión («rev N»). */
const SCOPE_TOOLS = new Set(["scope_edit", "h1_scope_load", "bb_scope_load"]);

/**
 * La tabla se creaba sin sesión: las filas de antes quedan sin dueña («alcance viejo del
 * proyecto») y no se heredan a ninguna sesión nueva. La fecha del cambio separa las sesiones
 * anteriores, las únicas que pueden recuperar lo suyo de esas filas (ver recoverLegacy).
 */
function migrate(db: DatabaseSync): void {
  db.exec("create table if not exists scope(rev integer primary key autoincrement, json text not null, at text not null, session_id text)");
  const columns = db.prepare("pragma table_info(scope)").all() as Array<{ name: string }>;
  if (!columns.some((column) => column.name === "session_id")) {
    try {
      db.exec("alter table scope add column session_id text");
    } catch (error) {
      if (!/duplicate column/i.test((error as Error).message)) throw error; // otra conexión la agregó recién
    }
  }
  db.exec("create index if not exists scope_session on scope(session_id, rev)");
  db.exec("create table if not exists meta(key text primary key, value text not null)");
  db.prepare("insert or ignore into meta(key,value) values('alcance_por_sesion',?)").run(new Date().toISOString());
}

/**
 * Rastro del alcance en la conversación de una sesión: la última revisión que fijó ella misma con
 * sus herramientas (o si lo último que hizo fue limpiarlo) y la última que vio en su bloque
 * <alcance>. Sólo sirve para las filas viejas, que no dicen de qué sesión son.
 */
export function scopeTrail(db: DatabaseSync, sessionId: string): { own?: number; cleared: boolean; seen?: number } {
  const rows = db
    .prepare("select json from messages where session_id=? and (json like '%\"role\":\"tool\"%' or json like '%<alcance>%') order by seq")
    .all(sessionId) as Array<{ json: string }>;
  const trail: { own?: number; cleared: boolean; seen?: number } = { cleared: false };
  for (const row of rows) {
    let message: { role?: string; name?: string; content?: unknown; isError?: boolean };
    try { message = JSON.parse(row.json); } catch { continue; }
    const content = typeof message.content === "string" ? message.content : "";
    if (message.role === "tool" && SCOPE_TOOLS.has(message.name ?? "") && !message.isError) {
      const rev = /ALCANCE · rev (\d+) ·|\(rev (\d+)\)/.exec(content);
      if (rev) Object.assign(trail, { own: Number(rev[1] ?? rev[2]), cleared: false });
      else if (content.startsWith("ALCANCE · sin definir")) Object.assign(trail, { own: undefined, cleared: true });
    } else if (message.role === "user") {
      for (const block of content.matchAll(/<alcance>\n(?:rev (\d+) \(|sin definir)/g)) trail.seen = block[1] ? Number(block[1]) : undefined;
    }
  }
  return trail;
}

/**
 * Revisiones del alcance. Con sesión, las de esa sesión: lo que el agente puede tocar. Sin sesión,
 * el alcance viejo del proyecto (filas de antes de que fuera por sesión): sólo lo usan las pruebas
 * y las herramientas sueltas. Para ver el proyecto entero está project(), que no sirve para autorizar.
 */
export class ScopeStore {
  readonly db: DatabaseSync;
  readonly sessionId: string | undefined;
  /** Lo avisa cada revisión nueva: un cambio de alcance nunca es silencioso (el motor se lo dice al operador). */
  onChange?: ScopeListener;
  /** Alcance sellado (src/ci/): ninguna vía lo cambia hasta que termine el proceso. Dice por qué. */
  private sello?: string;

  constructor(db: DatabaseSync, sessionId?: string) {
    this.db = db;
    this.sessionId = sessionId;
    migrate(db);
  }

  /**
   * Sella el alcance de esta sesión: desde acá, cualquier intento de cambiarlo (herramienta del agente, importación,
   * /alcance) falla con `motivo`. Lo usa la corrida de CI, donde el alcance lo autorizó quien versionó el archivo y
   * no hay operador que pueda ampliarlo.
   */
  sellar(motivo: string): void {
    this.sello = motivo;
  }

  /** El mismo almacén, mirando el alcance de otra sesión. */
  of(sessionId: string): ScopeStore {
    return new ScopeStore(this.db, sessionId);
  }

  current(): Scope | undefined {
    const row = (this.sessionId
      ? this.db.prepare("select rev,json,at from scope where session_id=? order by rev desc limit 1").get(this.sessionId)
      : this.db.prepare("select rev,json,at from scope where session_id is null order by rev desc limit 1").get()) as ScopeRow | undefined;
    return row ? parseRow(row) : undefined;
  }

  /** Todas las revisiones de esta sesión (o las viejas del proyecto), de la primera a la última. */
  revisions(): Scope[] {
    const rows = (this.sessionId
      ? this.db.prepare("select rev,json,at from scope where session_id=? order by rev").all(this.sessionId)
      : this.db.prepare("select rev,json,at from scope where session_id is null order by rev").all()) as ScopeRow[];
    return rows.map(parseRow);
  }

  /**
   * Todo el proyecto junto: el alcance vigente de cada sesión y el viejo sin sesión, unidos. Para el
   * informe del proyecto y para anonimizar trayectorias. Nunca para decidir si algo se puede tocar.
   */
  project(): Scope | undefined {
    const rows = this.db.prepare("select rev,json,at from scope where rev in (select max(rev) from scope group by session_id) order by rev").all() as ScopeRow[];
    const all = rows.map(parseRow);
    const defined = all.filter((scope) => scope.include.length || scope.exclude.length || scope.reglas && Object.values(scope.reglas).some((citas) => citas.length));
    if (defined.length <= 1) return defined[0] ?? all.at(-1);
    return {
      rev: Math.max(...defined.map((scope) => scope.rev)),
      at: defined.map((scope) => scope.at).sort().at(-1)!,
      source: [...new Set(defined.map((scope) => scope.source))].join(", "),
      include: dedupe(defined.flatMap((scope) => scope.include)),
      exclude: dedupe(defined.flatMap((scope) => scope.exclude)),
      notes: defined.map((scope) => scope.notes).filter(Boolean).join("\n\n"),
      reglas: { exclusiones: defined.flatMap((scope) => scope.reglas?.exclusiones ?? []), honestos: defined.flatMap((scope) => scope.reglas?.honestos ?? []), posicionAtacante: defined.flatMap((scope) => scope.reglas?.posicionAtacante ?? []) },
    };
  }

  /** Guarda una revisión nueva y la devuelve. */
  save(next: Pick<Scope, "source" | "include" | "exclude" | "notes" | "reference" | "reglas">): Scope {
    if (this.sello) throw new Error(`El alcance de esta sesión está sellado: ${this.sello}`);
    const before = this.onChange ? this.current() : undefined;
    const reference = dedupe(next.reference ?? []);
    const clean = { source: next.source, include: dedupe(next.include), exclude: dedupe(next.exclude), notes: next.notes, ...(reference.length ? { reference } : {}), ...(next.reglas ? { reglas: next.reglas } : {}) };
    const { lastInsertRowid } = this.db.prepare("insert into scope(json,at,session_id) values(?,?,?)").run(JSON.stringify(clean), new Date().toISOString(), this.sessionId ?? null);
    const saved = parseRow(this.db.prepare("select rev,json,at from scope where rev=?").get(lastInsertRowid) as ScopeRow);
    try { this.onChange?.(before, saved); } catch { /* avisar nunca impide guardar */ }
    return saved;
  }

  /**
   * El alcance de un programa (HackerOne, Bugcrowd, Intigriti) reemplaza al anterior, salvo los destinos
   * locales que el operador ya había autorizado en esta sesión (un laboratorio en 127.0.0.1): ningún
   * programa público los trae, y perderlos a mitad de sesión dejaba el laboratorio «fuera de alcance».
   * Tampoco se pierden las citas de reglas que agregó el operador. Devuelve lo conservado para decirlo.
   */
  saveProgram(next: Pick<Scope, "source" | "include" | "exclude" | "notes" | "reference" | "reglas">): { saved: Scope; kept: ScopeRule[] } {
    const previous = this.current();
    const kept = (previous?.include ?? []).filter((rule) => isLocalRule(rule) && !next.include.some((own) => own.value === rule.value) && !next.exclude.some((own) => own.value === rule.value));
    return { saved: this.save({ ...next, include: [...next.include, ...kept], reglas: conCitasDelOperador(previous?.reglas, next.reglas) }), kept };
  }

  /** Agrega o quita reglas partiendo de la revisión vigente. */
  edit(change: { include?: Array<string | ScopeRule>; exclude?: string[]; remove?: string[]; reference?: string[] }): Scope {
    const base = this.current() ?? { source: "manual", include: [], exclude: [], notes: "", reference: [], reglas: undefined };
    const gone = new Set((change.remove ?? []).map((value) => { try { return parseRule(value).value; } catch { return value.trim().toLowerCase().replace(/\/+$/, ""); } }));
    return this.save({
      source: base.source,
      notes: base.notes,
      reglas: base.reglas,
      include: [...base.include.filter((rule) => !gone.has(rule.value)), ...(change.include ?? []).map((item) => (typeof item === "string" ? parseRule(item) : item))],
      exclude: [...base.exclude.filter((rule) => !gone.has(rule.value)), ...(change.exclude ?? []).map((text) => parseRule(text))],
      reference: [...(base.reference ?? []).filter((rule) => !gone.has(rule.value)), ...(change.reference ?? []).map((text) => parseRule(text))],
    });
  }

  clear(): void {
    this.save({ source: "manual", include: [], exclude: [], notes: "" });
  }

  /** Agrega una cita textual del operador sin alterar destinos ni otras reglas. */
  agregarRegla(tipo: keyof ReglasPrograma, cita: string, fuente = "operador"): Scope {
    const base = this.current() ?? { source: "manual", include: [], exclude: [], notes: "", reference: [], reglas: undefined };
    const texto = cita.replace(/\s+/g, " ").trim();
    if (texto.length < 12 || texto.length > TOPE_CITA) throw new Error(`La cita de una regla debe tener entre 12 y ${TOPE_CITA} caracteres.`);
    const reglas = base.reglas ?? reglasVacias();
    const citas: CitaRegla[] = reglas[tipo];
    if (citas.length >= TOPES_REGLAS[tipo] && !citas.some((item) => item.cita === texto)) throw new Error(`Hay ${TOPES_REGLAS[tipo]} citas de este tipo: condensá las reglas antes de agregar otra.`);
    return this.save({ ...base, reglas: { ...reglas, [tipo]: citas.some((item) => item.cita === texto) ? citas : [...citas, { cita: texto, fuente }] } });
  }

  /** Copia una revisión cualquiera (de otra sesión o del alcance viejo) como revisión nueva de ésta. La pide el operador. */
  adopt(rev: number): Scope {
    const row = this.db.prepare("select rev,json,at from scope where rev=?").get(rev) as ScopeRow | undefined;
    if (!row) throw new Error(`No existe la revisión ${rev} del alcance.`);
    const { source, include, exclude, notes, reference, reglas } = parseRow(row);
    return this.save({ source, include, exclude, notes, reference, reglas });
  }

  /**
   * Una sesión anterior al alcance por sesión, sin alcance propio, recupera el que fijó ella misma
   * con sus herramientas: esa revisión vieja se copia a su nombre una vez. No se le da «el último del
   * proyecto»: ése pudo haberlo cargado otra sesión con otro programa, que es el error que esto
   * corrige. Si nunca lo fijó ella, queda vacía y vuelve como pista la última revisión que vio, para
   * que el operador decida (/alcance recuperar N). Las sesiones nuevas no pasan por acá.
   */
  recoverLegacy(): { recovered?: Scope; seen?: Scope } | undefined {
    const session = this.sessionId;
    if (!session || this.db.prepare("select 1 from scope where session_id=? limit 1").get(session)) return undefined;
    const started = this.db.prepare("select started_at from sessions where id=?").get(session) as { started_at: string } | undefined;
    const since = this.db.prepare("select value from meta where key='alcance_por_sesion'").get() as { value: string } | undefined;
    if (!started || !since || started.started_at >= since.value) return undefined;
    const legacy = (rev: number | undefined) => (rev === undefined ? undefined : (this.db.prepare("select rev,json,at from scope where rev=? and session_id is null").get(rev) as ScopeRow | undefined));
    const trail = scopeTrail(this.db, session);
    const own = legacy(trail.own);
    if (own) return { recovered: this.adopt(own.rev) };
    if (trail.cleared) return undefined;
    const seen = legacy(trail.seen);
    return seen ? { seen: parseRow(seen) } : undefined;
  }
}

/**
 * De qué programa es algo (la memoria, sobre todo): el programa de la plataforma («hackerone:matomo»)
 * o, si el alcance lo dictó el operador, «manual» con sus dominios. «» es «sin alcance» y «?» un
 * registro viejo cuyo programa no se pudo saber: ninguno de los dos coincide con nada.
 */
export interface ScopeTag {
  program: string;
  /** Dominio base de cada regla de inclusión (o la IP, el CIDR, o host:puerto de una URL a una IP). */
  domains: string[];
}

/** Sufijos de dos niveles (com.ar, co.uk…): el dominio base lleva una etiqueta más. */
const SECOND_LEVEL = /^(com|net|org|gov|gob|edu|co|ac|mil|nic|ne|or|go)\.[a-z]{2}$/;
/** Alojamientos compartidos: el dominio base no dice de quién es, así que vale el host entero. */
const SHARED = /(^|\.)(github\.io|vercel\.app|netlify\.app|herokuapp\.com|amazonaws\.com|cloudfront\.net|azurewebsites\.net|appspot\.com|firebaseapp\.com|web\.app|pages\.dev|workers\.dev|supabase\.co|googleapis\.com|windows\.net|onrender\.com|fly\.dev|ngrok\.io|ngrok-free\.app)$/;

function baseDomain(host: string): string {
  const clean = host.toLowerCase().replace(/\.$/, "");
  if (isIP(clean) || SHARED.test(clean)) return clean;
  const labels = clean.split(".");
  const keep = labels.length >= 3 && SECOND_LEVEL.test(labels.slice(-2).join(".")) ? 3 : 2;
  return labels.slice(-keep).join(".");
}

function ruleDomain(rule: ScopeRule): string {
  if (rule.kind === "cidr") return rule.value;
  if (rule.kind === "wildcard") return baseDomain(rule.value.slice(2));
  if (rule.kind === "host") {
    // Un laboratorio con puerto (127.0.0.1:8899, localhost:3000) se distingue por el puerto, como en una URL.
    const split = splitHostPort(rule.value) ?? { host: rule.value };
    if (isIP(split.host) || split.host === "localhost") return hostPort(split.host, split.port);
    return baseDomain(split.host);
  }
  try {
    const url = new URL(rule.value);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    // Un laboratorio en una IP o en localhost se distingue por el puerto: dos laboratorios locales no son el mismo.
    if (isIP(host) || host === "localhost") return url.port ? `${host}:${url.port}` : host;
    return baseDomain(host);
  } catch {
    return rule.value;
  }
}

/** La etiqueta del alcance vigente; undefined si no hay alcance (nada dentro ni fuentes del programa). */
export function scopeTag(scope: Pick<Scope, "source" | "include" | "reference"> | undefined): ScopeTag | undefined {
  // Un programa sólo de código (todo SOURCE_CODE) no tiene nada dentro, pero es un programa: su código se lee.
  const rules = [...(scope?.include ?? []), ...(scope?.reference ?? [])];
  if (!scope || !rules.length) return undefined;
  const source = (scope.source || "manual").trim().toLowerCase();
  return { program: source.startsWith("manual") ? "manual" : source, domains: [...new Set(rules.map(ruleDomain))].sort().slice(0, 50) };
}

/**
 * ¿Es el mismo programa? Dos programas de plataforma, sólo si son el mismo programa. Si alguno es
 * manual, si comparten un dominio. Sin alcance («») o desconocido («?») no coincide con nada.
 */
export function sameScope(a: ScopeTag | undefined, b: ScopeTag | undefined): boolean {
  if (!a?.program || !b?.program || a.program === "?" || b.program === "?") return false;
  if (a.program !== "manual" && b.program !== "manual") return a.program === b.program;
  const domains = new Set(a.domains);
  return b.domains.some((domain) => domains.has(domain));
}

/** Para el operador: «hackerone:matomo», «alcance manual (tienda.test, …)», «sin alcance», «programa desconocido». */
export function scopeTagLabel(tag: ScopeTag | undefined): string {
  if (!tag || tag.program === "?") return "programa desconocido (nota vieja)";
  if (!tag.program) return "sin alcance";
  if (tag.program === "manual") return `alcance manual (${tag.domains.slice(0, 3).join(", ")}${tag.domains.length > 3 ? ", …" : ""})`;
  return tag.program;
}

/**
 * Etiquetas de todas las revisiones del alcance del proyecto que tienen algo dentro, con su sesión (las
 * filas viejas, de antes de que el alcance fuera por sesión, van con sesión «»). Para atribuir las
 * notas viejas de la memoria a un programa; nunca para autorizar nada.
 */
export function projectScopeTags(db: DatabaseSync): Array<{ session: string; at: string; tag: ScopeTag }> {
  if (!db.prepare("select 1 from sqlite_master where type='table' and name='scope'").get()) return [];
  const columns = db.prepare("pragma table_info(scope)").all() as Array<{ name: string }>;
  const withSession = columns.some((column) => column.name === "session_id");
  const rows = db.prepare(`select json, at${withSession ? ", session_id" : ""} from scope order by rev`).all() as Array<{ json: string; at: string; session_id?: string | null }>;
  const tags: Array<{ session: string; at: string; tag: ScopeTag }> = [];
  for (const row of rows) {
    try {
      const tag = scopeTag(JSON.parse(row.json) as Scope);
      if (tag) tags.push({ session: row.session_id ?? "", at: row.at, tag });
    } catch { /* fila ilegible: no atribuye nada */ }
  }
  return tags;
}

export function scopeView(scope: Scope | undefined): string[] {
  if (!scope || (!scope.include.length && !scope.exclude.length)) {
    return ["ALCANCE · sin definir", "Sin alcance, ninguna herramienta puede tocar un destino. Es de cada sesión: una nueva empieza vacía (/scope sesiones muestra el de las demás).", "Agregar: /scope add <host | *.dominio | CIDR | URL>   ·   Excluir: /scope excluir <regla>", ...bloqueReglas(scope?.reglas).split("\n")];
  }
  const line = (rule: ScopeRule) => `  ${rule.value}${rule.note ? `  — ${rule.note}` : ""}`;
  return [
    `ALCANCE · rev ${scope.rev} · ${scope.source} · ${scope.at.slice(0, 16).replace("T", " ")}`,
    `Dentro (${scope.include.length})`,
    ...scope.include.slice(0, 40).map(line),
    ...(scope.include.length > 40 ? [`  … ${scope.include.length - 40} más`] : []),
    ...(scope.exclude.length ? [`Excluido (${scope.exclude.length})`, ...scope.exclude.slice(0, 20).map(line)] : []),
    `Lectura de referencia (sólo reference_read: GET, sin credenciales; no se prueba): github.com, api.github.com, raw.githubusercontent.com${scope.reference?.length ? ` y ${scope.reference.length} del programa` : ""}`,
    ...(scope.reference ?? []).slice(0, 12).map(line),
    ...((scope.reference?.length ?? 0) > 12 ? [`  … ${scope.reference!.length - 12} más`] : []),
    ...(scope.notes ? ["Notas", ...scope.notes.split("\n").slice(0, 8).map((text) => `  ${text}`)] : []),
    ...bloqueReglas(scope.reglas).split("\n"),
  ];
}

/** Resumen corto para el modelo. */
export function scopeBrief(scope: Scope | undefined, conReglas = true): string {
  const bloque = conReglas ? `\n${bloqueReglas(scope?.reglas)}` : "";
  if (!scope || !scope.include.length) return `sin definir: no hay destinos autorizados${bloque}`;
  const list = (rules: ScopeRule[]) => rules.slice(0, 25).map((rule) => rule.value).join(", ") + (rules.length > 25 ? ` y ${rules.length - 25} más` : "");
  const reference = scope.reference?.length ? ` Lectura de referencia con reference_read (GET, no se prueba): GitHub y ${list(scope.reference)}.` : " Lectura de referencia con reference_read (GET, no se prueba): GitHub.";
  return `rev ${scope.rev} (${scope.source}). Dentro: ${list(scope.include)}.${scope.exclude.length ? ` Excluido: ${list(scope.exclude)}.` : ""}${reference}${bloque}`;
}
