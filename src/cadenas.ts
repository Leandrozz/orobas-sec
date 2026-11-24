// Cadenas de hallazgos. Un hallazgo bajo o medio rara vez es el final: hay escaladas conocidas que lo
// vuelven alto (un open redirect que se lleva el código de OAuth, un XSS que lee una cookie de sesión
// sin HttpOnly, un CSRF que cambia el email y abre el reset de contraseña). CHAINS dice, por clase de
// hallazgo, cuál es la escalada, cuándo aplica en este sitio, qué acción concreta la prueba y qué
// tráfico cuenta como intento. La regla de cierre (src/cierre.ts) la usa para objetar el cierre con una
// sola acción por hallazgo; se cierra con un hallazgo vinculado, con el intento en el tráfico o
// marcando la escalada (intentada, limitada o no aplica) con una nota.
import { canonicalPath } from "./coverage.ts";
import type { Finding } from "./findings.ts";
import { LECTURA_ARISTA, limpio, type NodoVista, type Vista } from "./grafo.ts";
import { isAuthPath, type HttpClient } from "./http.ts";
import { decide, type Scope } from "./scope.ts";

export type LogEntry = HttpClient["log"][number];

/** Cookie que fijó el servidor, vista en el tráfico guardado. */
export interface SeenCookie {
  name: string;
  httpOnly: boolean;
  /** Intercambio que la fijó (h12) y su ruta. */
  exchange: string;
  path: string;
}

export interface ChainContext {
  /** Tráfico de la sesión (registro compacto del cliente HTTP). */
  log: readonly LogEntry[];
  scope: Scope | undefined;
  /** Cookies de sesión fijadas en respuestas de autenticación; se calcula sólo si hace falta. */
  cookies?: () => SeenCookie[];
  /**
   * Grafo de hechos (src/grafo.ts): lo observado también en sesiones anteriores del mismo programa y lo que el
   * tráfico no dice (contratos, código, enlaces). Con él, las acciones nombran nodos reales con su evidencia.
   */
  grafo?: Vista;
}

const corta = (evidencia: string) => (evidencia.startsWith("sha256:") ? evidencia.slice(0, 19) : evidencia.slice(0, 40));

/** Rutas del grafo dentro del alcance vigente que cumplen la condición, de las pedidas a las sólo vistas. */
function rutasDelGrafo(ctx: ChainContext, filtro: (nodo: NodoVista) => boolean, max = 2): NodoVista[] {
  if (!ctx.grafo) return [];
  return ctx.grafo.deTipo("ruta").filter((nodo) => ctx.grafo!.destinable(nodo) && filtro(nodo)).sort((a, b) => Number(a.estado === "inferido") - Number(b.estado === "inferido") || a.clave.localeCompare(b.clave)).slice(0, max);
}

const nombreRuta = (nodo: NodoVista) => `${nodo.etiqueta} (${nodo.estado === "inferido" ? `vista en ${String(nodo.atributos.via ?? "otra fuente")}, sin pedir` : `observada, ${corta(nodo.ultima.evidencia)}`})`;

/** Flujos OAuth del grafo: rutas de authorize/callback o que aceptan client_id, redirect_uri o response_type. */
function oauthDelGrafo(ctx: ChainContext): NodoVista[] {
  return rutasDelGrafo(ctx, (nodo) => !!nodo.atributos.oauth || (ctx.grafo!.salientes.get(nodo.clave) ?? []).some((arista) => arista.tipo === "acepta" && !!ctx.grafo!.nodos.get(arista.destino)?.atributos.oauth), 3);
}

export interface ChainRule {
  id: string;
  /** Hallazgo de partida, en palabras. */
  from: string;
  /** Escalada conocida, en palabras. */
  to: string;
  /** Reconoce el hallazgo de partida por clase y título (sin tildes, en minúsculas). */
  match: RegExp;
  /** Descarta los que ya son la escalada (un IDOR que ya es de escritura). */
  unless?: RegExp;
  /** ¿Aplica en este sitio? Sin esto, siempre. */
  applies?: (ctx: ChainContext, finding: Finding) => boolean;
  /** La acción concreta, una sola. */
  action: (ctx: ChainContext, finding: Finding) => string;
  /** ¿Estas peticiones son un intento de la escalada? Se mira lo pedido después de objetarla. */
  tried: (entries: readonly LogEntry[], finding: Finding, ctx: ChainContext) => boolean;
  /** El intento también vale si ya estaba en el tráfico antes de objetar (entonces no se objeta). */
  history?: boolean;
  /** La acción no se resuelve con tráfico (pedirle algo al operador): se objeta una sola vez. */
  once?: (ctx: ChainContext) => boolean;
}

/** Severidades que todavía pueden escalar. «alta» y «crítica» ya son el final de la cadena. */
export const ESCALABLE = new Set<Finding["severity"]>(["informativa", "baja", "media"]);

const plain = (text: string) => text.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url.split(/[?#]/)[0] ?? url;
  }
}

/** Un segmento que es un identificador de objeto: número, UUID u ObjectId. */
const ID_SEGMENT = /^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})$/i;

/** Familia de una ruta: canónica, con los ids como {n}; undefined si no tiene ningún id. */
export function idFamily(urlOrPath: string): string | undefined {
  const segments = canonicalPath(pathOf(urlOrPath)).split("/").filter(Boolean);
  if (!segments.some((segment) => ID_SEGMENT.test(segment))) return undefined;
  return `/${segments.map((segment) => (ID_SEGMENT.test(segment) ? "{n}" : segment)).join("/")}`;
}

const WRITES = new Set(["POST", "PUT", "PATCH", "DELETE"]);
export const OAUTH_PATH = /(^|\/)(oauth2?|authorize|authorization|openid|openid-configuration|sso|saml2?)(\/|$)/i;
export const OAUTH_PARAMS = /^(client_id|redirect_uri|response_type)$/i;
const EMAIL_FIELD = /e-?mail|correo/i;
const EMAIL_PATH = /(^|\/)(e-?mail|correo|account|cuenta|perfil|profile|settings|ajustes|me)(\/|$)/i;
const RESET_PATH = /forgot|olvid|reset|recuper|recover/i;
const SESSION_PATH = /(^|\/)(me|account|cuenta|perfil|profile|session|sesion|whoami)(\/|$)/i;
const SESSION_COOKIE = /sess|sid|auth|token|jwt|login|remember/i;
/** Destinos internos que un SSRF busca. Sólo se proponen si el alcance los nombra. */
export const INTERNAL_TARGETS = ["169.254.169.254", "metadata.google.internal", "127.0.0.1", "localhost"];
const INTERNAL_VALUE = /169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|(^|\D)10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/i;

const oauthEntries = (log: readonly LogEntry[]) => log.filter((entry) => OAUTH_PATH.test(pathOf(entry.url)) || Object.keys(entry.query).some((key) => OAUTH_PARAMS.test(key)));
const internalAllowed = (ctx: ChainContext) => INTERNAL_TARGETS.filter((target) => decide(ctx.scope, `http://${target}/`).allowed);

/**
 * Tabla de cadenas. Cada fila: de qué hallazgo bajo o medio se parte, a qué escala, cuándo aplica,
 * la acción concreta y qué tráfico cuenta como intento. Las acciones nunca amplían el alcance ni
 * tocan cuentas ajenas: si lo que falta es una decisión del operador, la acción es pedírsela.
 */
export const CHAINS: readonly ChainRule[] = [
  {
    id: "redirect-oauth",
    from: "open redirect",
    to: "robo del código o token de OAuth",
    match: /open[\s_-]?redirect|redireccion (abierta|no validada|sin validar)|redirect abierto|unvalidated redirect/,
    applies: (ctx) => oauthEntries(ctx.log).length > 0 || oauthDelGrafo(ctx).length > 0,
    action: (ctx, finding) => {
      const grafo = oauthDelGrafo(ctx);
      const flow = oauthEntries(ctx.log)[0];
      const donde = grafo.length ? grafo.map(nombreRuta).join(" y ") : `${flow!.method} ${pathOf(flow!.url)}`;
      const redirect = redirectDelGrafo(ctx, finding);
      return `${finding.asset} es un open redirect${redirect ? ` (${redirect})` : ""} y el sitio tiene un flujo OAuth (${donde}): con tu cuenta de prueba, armá el authorize con redirect_uri apuntando a la ruta del redirect dentro del dominio que el cliente acepta, sin seguir redirecciones, y mirá si el code o el token salen en el Location hacia el destino que controlás (outbound_probe lo confirma si hay canal declarado).`;
    },
    tried: (entries) => entries.some((entry) => OAUTH_PATH.test(pathOf(entry.url)) || "redirect_uri" in entry.query),
  },
  {
    id: "xss-sesion",
    from: "XSS (reflejado o almacenado)",
    to: "robo de la sesión: cookie sin HttpOnly o sesión que no rota",
    match: /\bxss\b|cross[\s_-]?site scripting|secuencia de comandos (en sitios )?cruzados|inyeccion (de )?(html|script|javascript)|html injection|script (almacenado|reflejado)/,
    action: (ctx, finding) => {
      const cookies = [...(ctx.cookies?.() ?? []), ...cookiesDelGrafo(ctx)].filter((cookie, i, all) => all.findIndex((other) => other.name === cookie.name) === i);
      const loose = cookies.filter((cookie) => !cookie.httpOnly);
      const seen = loose.length
        ? ` En el tráfico ya se ve: ${loose.slice(0, 3).map((cookie) => `«${cookie.name}» sin HttpOnly (${cookie.exchange}, ${cookie.path})`).join(", ")}.`
        : cookies.length ? ` Las cookies de sesión vistas tienen HttpOnly (${cookies.slice(0, 3).map((cookie) => `«${cookie.name}» en ${cookie.exchange}`).join(", ")}): mirá entonces si la sesión rota.` : "";
      return `${finding.asset} tiene un XSS: lo que lo vuelve alto es la sesión. Pedí el login (o /me) con http_request y leé el Set-Cookie: si la cookie de sesión no tiene HttpOnly, el script la lee; y compará el valor antes y después de iniciar sesión (si no cambia, fijación de sesión).${seen}`;
    },
    tried: (entries) => entries.some((entry) => isAuthPath(entry.url) || SESSION_PATH.test(pathOf(entry.url))),
  },
  {
    id: "csrf-email",
    from: "CSRF",
    to: "cambio de email y reset de contraseña: toma de la cuenta",
    match: /\bcsrf\b|\bxsrf\b|cross[\s_-]?site request forgery|falsificacion de (peticion|peticiones|solicitud|solicitudes) (en sitios cruzados|entre sitios)/,
    action: (ctx, finding) => {
      const email = rutasDelGrafo(ctx, (nodo) => WRITES.has(String(nodo.atributos.metodo)) && (EMAIL_PATH.test(String(nodo.atributos.familia ?? "")) || (ctx.grafo!.salientes.get(nodo.clave) ?? []).some((arista) => arista.tipo === "acepta" && EMAIL_FIELD.test(String(ctx.grafo!.nodos.get(arista.destino)?.atributos.nombre ?? "")))), 2);
      return `${finding.asset} acepta escrituras sin protección anti-CSRF: la escalada es el cambio de email de la cuenta. ${email.length ? `El grafo tiene la operación candidata: ${email.map(nombreRuta).join(", ")}; probala` : "Buscá la operación que cambia el email (perfil, cuenta, ajustes) y probala"} con csrf_check sobre tu cuenta de prueba; si también pasa sin token o desde un origen ajeno, el reset de contraseña al email nuevo es toma de cuenta. No dispares el reset sobre cuentas ajenas.`;
    },
    tried: (entries) => entries.some((entry) => (WRITES.has(entry.method) && (EMAIL_PATH.test(pathOf(entry.url)) || [...entry.bodyKeys, ...(entry.fields ?? []), ...Object.keys(entry.query)].some((key) => EMAIL_FIELD.test(key)))) || RESET_PATH.test(pathOf(entry.url))),
  },
  {
    id: "idor-escritura",
    from: "IDOR de lectura",
    to: "escritura sobre el recurso ajeno en la misma familia",
    match: /\bidor\b|\bbola\b|insecure direct object|referencia (directa )?(a objetos? )?insegura|control de acceso|acceso a (recursos|datos|objetos|registros) ajen|(recurso|objeto|dato|registro)s? ajen|broken (object level )?authorization|autorizacion (rota|ausente)/,
    unless: /escritura|escribir|modific|edita|borra|elimina|actualiza|\bwrite\b|\bupdate\b|\bdelete\b|\bmodify\b|\b(put|patch|post)\b|mass assignment|asignacion masiva/,
    applies: (_ctx, finding) => !!idFamily(finding.asset),
    action: (ctx, finding) => {
      const familia = idFamily(finding.asset);
      const escrituras = rutasDelGrafo(ctx, (nodo) => String(nodo.atributos.familia) === familia && /^(PUT|PATCH|POST)$/.test(String(nodo.atributos.metodo)), 3);
      return `${finding.asset} deja leer recursos ajenos: probá una escritura sobre el mismo id ajeno en ${familia} (PUT o PATCH con un cambio mínimo y reversible, o la operación que la API ofrezca sobre ese recurso: archivar, asignar, cambiar estado).${escrituras.length ? ` El grafo ya tiene esa familia con ${escrituras.map(nombreRuta).join(", ")}.` : ""} Nada de borrar: DELETE sólo sobre lo propio. Si la escritura pasa, el hallazgo sube.`;
    },
    tried: (entries, finding) => {
      const family = idFamily(finding.asset);
      return !!family && entries.some((entry) => WRITES.has(entry.method) && idFamily(entry.url) === family);
    },
    history: true,
  },
  {
    id: "ssrf-interno",
    from: "SSRF",
    to: "metadata de la nube o servicios internos",
    match: /\bssrf\b|server[\s_-]?side request forgery|falsificacion de (peticiones|solicitudes) del lado del servidor|(peticion|peticiones|solicitud|solicitudes) del lado del servidor/,
    action: (ctx, finding) => {
      const allowed = internalAllowed(ctx);
      if (allowed.length) return `${finding.asset} tiene un SSRF: vale por lo que alcanza adentro. El alcance incluye ${allowed.join(", ")}: probá esos destinos en el mismo parámetro (outbound_probe o http_request), sólo lectura, y registrá qué devuelve.`;
      return `${finding.asset} tiene un SSRF: la escalada es llegar a la metadata de la nube o a servicios internos, y el alcance no incluye ninguno de esos destinos (${INTERNAL_TARGETS.join(", ")}, redes privadas). No lo amplíes vos: pedile al operador en tu cierre que decida si lo autoriza, y marcá la escalada con finding_update (escalation «limitada», escalation_note «pedido al operador»).`;
    },
    tried: (entries, _finding, ctx) => internalAllowed(ctx).length > 0 && entries.some((entry) => Object.values(entry.query).some((value) => INTERNAL_VALUE.test(value)) || (entry.marks ?? []).some((mark) => mark.mark === "externo")),
    once: (ctx) => internalAllowed(ctx).length === 0,
  },
];

/** La fila de la tabla que corresponde a un hallazgo, por clase y título; undefined si no tiene escalada conocida. */
export function chainFor(finding: Pick<Finding, "kind" | "title">): ChainRule | undefined {
  const text = plain(`${finding.kind} ${finding.title}`);
  return CHAINS.find((rule) => rule.match.test(text) && !rule.unless?.test(text));
}

export interface PendingEscalation {
  /** Clave estable: cuenta las objeciones y va al evento. */
  key: string;
  finding: Finding;
  rule: ChainRule;
  text: string;
  /** Se objeta una sola vez (la acción es pedirle algo al operador). */
  once: boolean;
}

/**
 * Hallazgos bajos o medios de la sesión con una escalada conocida que aplica y nadie cerró: sin
 * vínculos con otro hallazgo (en ninguna dirección), sin escalada marcada y, si la fila lo admite, sin
 * el intento ya en el tráfico. `all` son los hallazgos del proyecto, para ver los vínculos.
 */
export function pendingEscalations(own: Finding[], all: Finding[], ctx: ChainContext): PendingEscalation[] {
  const linked = (finding: Finding) => (finding.related?.length ?? 0) > 0 || all.some((other) => other.id !== finding.id && (other.related ?? []).some((link) => link.id === finding.id));
  const pending: PendingEscalation[] = [];
  for (const finding of own) {
    if (finding.state === "descartado" || !ESCALABLE.has(finding.severity) || finding.escalation || linked(finding)) continue;
    const rule = chainFor(finding);
    if (!rule || rule.applies?.(ctx, finding) === false) continue;
    if (rule.history && rule.tried(ctx.log, finding, ctx)) continue;
    pending.push({ key: `escalada:${rule.id}:${finding.id.slice(0, 8)}`, finding, rule, text: rule.action(ctx, finding), once: rule.once?.(ctx) ?? false });
  }
  return pending;
}

/** Cookie de un Set-Cookie: nombre y si lleva HttpOnly. */
export function parseSetCookie(header: string): Array<{ name: string; httpOnly: boolean }> {
  return header
    .split(/\n|,(?=\s*[^;,=\s]+=)/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => ({ name: line.split("=")[0]!.trim(), httpOnly: /;\s*httponly\s*(;|$)/i.test(line) }))
    .filter((cookie) => cookie.name);
}

/**
 * Cookies de sesión fijadas en respuestas de autenticación de este tráfico (hasta `max` intercambios,
 * los más nuevos). Lee el artefacto de cada uno: se llama al objetar, no en cada petición.
 */
export function sessionCookies(log: readonly LogEntry[], read: (hash: string) => string | undefined, max = 20): SeenCookie[] {
  const cookies = new Map<string, SeenCookie>();
  const auth = log.filter((entry) => entry.status !== undefined && (isAuthPath(entry.url) || SESSION_PATH.test(pathOf(entry.url)))).slice(-max);
  for (const entry of auth) {
    let header = "";
    try {
      const exchange = JSON.parse(read(entry.hash) ?? "") as { response?: { headers?: Record<string, string> } };
      header = Object.entries(exchange.response?.headers ?? {}).find(([key]) => key.toLowerCase() === "set-cookie")?.[1] ?? "";
    } catch {
      continue;
    }
    for (const cookie of parseSetCookie(header)) {
      if (!SESSION_COOKIE.test(cookie.name)) continue;
      cookies.set(cookie.name, { ...cookie, exchange: entry.id, path: pathOf(entry.url) });
    }
  }
  return [...cookies.values()];
}

/** Cookies de sesión que el grafo vio fijar (por nombre y banderas, nunca el valor), con dónde. */
function cookiesDelGrafo(ctx: ChainContext): SeenCookie[] {
  if (!ctx.grafo) return [];
  const out: SeenCookie[] = [];
  for (const nodo of ctx.grafo.deTipo("credencial")) {
    if (nodo.atributos.clase !== "cookie" || !SESSION_COOKIE.test(String(nodo.atributos.nombre ?? "")) || !ctx.grafo.destinable(nodo)) continue;
    const ruta = (ctx.grafo.entrantes.get(nodo.clave) ?? []).map((arista) => ctx.grafo!.nodos.get(arista.origen)).find((otro) => otro?.tipo === "ruta");
    out.push({ name: String(nodo.atributos.nombre), httpOnly: nodo.atributos.httponly === true, exchange: corta(nodo.ultima.evidencia), path: ruta ? String(ruta.atributos.familia ?? ruta.etiqueta) : "" });
  }
  return out;
}

/** Cómo redirige la ruta de un hallazgo según el grafo: qué parámetro decide el destino y con qué evidencia. */
function redirectDelGrafo(ctx: ChainContext, finding: Finding): string | undefined {
  if (!ctx.grafo) return undefined;
  const familia = canonicalPath(pathOf(finding.asset.trim().split(/\s/)[0] ?? ""));
  const ruta = ctx.grafo.deTipo("ruta").find((nodo) => nodo.atributos.redirige && String(nodo.atributos.familia) === familia && ctx.grafo!.destinable(nodo));
  if (!ruta) return undefined;
  return `${ruta.etiqueta}${ruta.atributos.redireccion_por ? ` redirige según ?${String(ruta.atributos.redireccion_por)}` : " redirige"}, ${corta(ruta.ultima.evidencia)}`;
}

/**
 * Escaladas concretas para un hallazgo, con los nodos reales del grafo: la de su fila en CHAINS (aunque ya no sea
 * escalable, para el subgrafo) y los hallazgos que comparten ruta con él sin estar vinculados. Nunca nombra un
 * destino fuera del alcance vigente: el grafo los aparta al leer.
 */
export function propuestasDeEscalada(vista: Vista, finding: Finding | undefined, scope: Scope | undefined): string[] {
  if (!finding) return [];
  const out: string[] = [];
  const ctx: ChainContext = { log: [], scope, grafo: vista };
  const rule = chainFor(finding);
  if (rule && finding.state !== "descartado" && rule.applies?.(ctx, finding) !== false) {
    out.push(finding.escalation ? `${rule.from} → ${rule.to}: escalada ya marcada «${finding.escalation.state}» (${limpio(finding.escalation.note, 120)})` : rule.action(ctx, finding));
  }
  // Otros hallazgos observados en la misma ruta que no están vinculados: puede que uno habilite al otro.
  const clave = `hallazgo:${finding.id}`;
  const rutas = new Set((vista.salientes.get(clave) ?? []).filter((arista) => arista.tipo === "observado_en").map((arista) => arista.destino));
  const vinculados = new Set(vista.vecinas(clave).filter((arista) => arista.tipo === "habilita").flatMap((arista) => [arista.origen, arista.destino]));
  for (const ruta of rutas) {
    for (const arista of vista.entrantes.get(ruta) ?? []) {
      if (arista.tipo !== "observado_en" || arista.origen === clave || vinculados.has(arista.origen)) continue;
      const otro = vista.nodos.get(arista.origen);
      if (otro?.tipo !== "hallazgo" || otro.estado === "refutado") continue;
      out.push(`${String(otro.atributos.corto ?? otro.id.slice(0, 8))} «${limpio(otro.etiqueta, 60)}» también se observó en ${vista.nodos.get(ruta)?.etiqueta ?? "la misma ruta"}: si uno habilita al otro, vinculalos (finding_update con related y rol habilita o escala).`);
      if (out.length >= 4) return out;
    }
  }
  return out;
}

/**
 * La cadena de un hallazgo según el grafo: cada arista «habilita» con su estado y la evidencia de los dos eslabones,
 * y dónde se observó cada uno. Lo leen el verificador y el informe.
 */
export function cadenaConEvidencia(vista: Vista, findingId: string): string[] {
  const inicio = `hallazgo:${findingId}`;
  if (!vista.nodos.has(inicio)) return [];
  const visitados = new Set([inicio]);
  const cola = [inicio];
  const aristas = new Map<string, import("./grafo.ts").AristaVista>();
  while (cola.length && visitados.size < 20) {
    const actual = cola.shift()!;
    for (const arista of vista.vecinas(actual)) {
      if (arista.tipo !== "habilita") continue;
      aristas.set(arista.clave, arista);
      for (const extremo of [arista.origen, arista.destino]) if (!visitados.has(extremo)) { visitados.add(extremo); cola.push(extremo); }
    }
  }
  if (!aristas.size) return [];
  const nombre = (clave: string) => { const nodo = vista.nodos.get(clave); return nodo ? `${String(nodo.atributos.corto ?? nodo.id.slice(0, 8))} «${limpio(nodo.etiqueta, 60)}» (${String(nodo.atributos.estado_hallazgo ?? nodo.estado)})` : clave; };
  const donde = (clave: string) => (vista.salientes.get(clave) ?? []).filter((arista) => arista.tipo === "observado_en").slice(0, 2).map((arista) => `${vista.nodos.get(arista.destino)?.etiqueta ?? "?"} ${corta(arista.ultima.evidencia)}`).join(", ");
  return [...aristas.values()].sort((a, b) => a.procedencia.momento.localeCompare(b.procedencia.momento)).map((arista) => {
    const evidencias = Array.isArray(arista.atributos.evidencias) ? arista.atributos.evidencias.join(", ") : "";
    const a = donde(arista.origen);
    const b = donde(arista.destino);
    return `- ${nombre(arista.origen)} ${LECTURA_ARISTA.habilita} ${nombre(arista.destino)} · arista ${arista.estado}${evidencias ? ` · evidencia ${evidencias}` : ""}${a ? ` · el primero se observó en ${a}` : ""}${b ? ` · el segundo en ${b}` : ""}`;
  });
}
