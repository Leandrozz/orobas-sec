// Sondas propias de autenticación, parámetros, tokens y secretos. Todas con alcance, ritmo acotado
// y evidencia en artefactos. Las listas incorporadas son cortas a propósito: la fuerza bruta no es el
// objetivo; sí probar lo que un programa de bug bounty o un pentest autorizado espera que se pruebe.
import { createHash, createHmac, randomBytes } from "node:crypto";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { HttpClient, type HttpExchange } from "./http.ts";
import { createGraphqlProbe } from "./graphql-probe.ts";
import { createOutboundProbe } from "./outbound-probe.ts";
import { createRaceProbe } from "./race-probe.ts";
import { createCsrfCheck } from "./csrf-probe.ts";
import { createWsProbe } from "./ws-probe.ts";
import { massAssignment, type AssignMode, type BodyEncoding } from "./asignacion.ts";
import type { IdHarvest } from "./cosecha.ts";
import type { ListenerConfig } from "./listener.ts";
import { diffResponses } from "./webtools.ts";

export interface ProbeContext {
  artifacts: Artifacts;
  http: HttpClient;
  /** Dirección local que el operador declaró alcanzable desde el objetivo. */
  listener?: ListenerConfig;
  /** Ids cosechados por identidad: deciden qué recurso es propio en la asignación masiva (src/cosecha.ts). */
  harvest?: IdHarvest;
  /** Eventos de la sesión (asignacion.sondeo) y avisos al operador. */
  event?: (type: string, payload: unknown) => void;
  notice?: (text: string) => void;
}

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const list = (items: object) => ({ type: "array", items });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
const finish = (text: string, details: Record<string, unknown> = {}): ToolResult => ({ text, details });
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Contraseñas que aparecen en toda guía de hardening como las que hay que descartar primero. */
export const COMMON_PASSWORDS = ["admin", "admin123", "password", "123456", "12345678", "qwerty", "letmein", "welcome", "changeme", "test", "test123", "secret", "root", "toor", "pass", "password1", "Password1", "admin@123", "P@ssw0rd", "Admin123"];

/** Cargas por familia: cortas, para ver cómo reacciona el servidor, no para explotar. */
export const PAYLOADS: Record<string, string[]> = {
  traversal: ["../", "../../", "../../../etc/hostname", "..%2F..%2F", "....//....//", "%2e%2e/%2e%2e/"],
  html: ["<b>x</b>", "<svg/onload=1>", "\"><i>x</i>", "'\"><s>x</s>"],
  sql: ["'", "''", "' OR '1'='1", "1 OR 1=1", "1' AND '1'='2", "1;--", "\" OR \"\"=\""],
  ssti: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
  comando: ["; id", "| id", "`id`", "$(id)"],
  numerico: ["0", "-1", "1e9", "9999999999", "1.5", "NaN", "null", "true", "[]"],
  tipo: ["", " ", "null", "undefined", "[]", "{}", "%00", "ñ€𝄞"],
};

/** Decodifica un JWT sin verificarlo. */
export function decodeJwt(token: string): { header: any; payload: any; signature: string } | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const decode = (part: string) => JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return { header: decode(parts[0]!), payload: decode(parts[1]!), signature: parts[2]! };
  } catch {
    return undefined;
  }
}

/** También los usa apk_analyze (src/movil.ts) sobre lo que trae una app. */
export const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "clave de acceso AWS", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "token de GitHub", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: "clave privada", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: "JWT", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: "clave de Stripe", pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { name: "clave de Google", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "token de Slack", pattern: /\bxox[abpr]-[A-Za-z0-9-]{10,}\b/g },
  { name: "URL con credenciales", pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@"']+:[^\s/@"']+@[^\s"']+/gi },
  { name: "campo password/secret/token con valor", pattern: /"(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key|jwtSecret|client[_-]?secret)"\s*:\s*"[^"]{4,}"/gi },
  { name: "asignación password/secret", pattern: /\b(?:password|passwd|secret|api_key|apikey|token)\s*[=:]\s*['"]?[A-Za-z0-9_\-./+=]{6,}/gi },
];

export function createProbeTools(context: ProbeContext): Tool[] {
  const { http, artifacts } = context;
  const counter = () => `peticiones HTTP: ${http.count}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`;

  /** Intentos de autenticación con ritmo acotado y comparación de respuestas. */
  const authProbe: Tool = {
    name: "auth_probe",
    label: "Sonda de autenticación",
    description:
      "Prueba un formulario o endpoint de login con una lista corta de credenciales (las que pases, más las contraseñas comunes si pedís commonPasswords) a ritmo acotado, y devuelve una tabla: credencial, código, tamaño, mensaje. " +
      "Marca cuando el servidor responde distinto a un usuario inexistente que a una contraseña incorrecta (enumeración) y cuando una combinación entra. Máximo 30 intentos por llamada.",
    parameters: obj(
      {
        url: str(),
        method: str({ enum: ["POST", "PUT", "GET"] }),
        userField: str({ description: "Nombre del campo de usuario, p. ej. email" }),
        passwordField: str({ description: "Nombre del campo de contraseña" }),
        users: list(str()),
        passwords: list(str()),
        commonPasswords: { type: "boolean", description: "Sumar la lista corta de contraseñas comunes" },
        nonexistentUser: str({ description: "Un usuario que seguro no existe, para comparar mensajes; por defecto se inventa uno" }),
        extraFields: { type: "object", additionalProperties: {} },
        encoding: str({ enum: ["json", "form"] }),
        delayMs: int({ minimum: 0, maximum: 5000 }),
      },
      ["url", "userField", "passwordField", "users"],
    ),
    execute: async (params, signal) => {
      const passwords: string[] = [...new Set([...(params.passwords ?? []), ...(params.commonPasswords ? COMMON_PASSWORDS : [])])];
      if (!passwords.length) throw new Error("Sin contraseñas: pasá passwords o commonPasswords");
      const attempts: Array<{ user: string; password: string; tag: string }> = [];
      const ghost = params.nonexistentUser ?? `nadie-${Date.now().toString(36)}@inexistente.invalid`;
      attempts.push({ user: ghost, password: passwords[0]!, tag: "inexistente" });
      for (const user of params.users) for (const password of passwords) attempts.push({ user, password, tag: "" });
      const trimmed = attempts.length > 30 ? attempts.length - 30 : 0;
      if (trimmed) attempts.length = 30; // se recorta y se avisa, en vez de perder el paso
      const encode = (fields: Record<string, unknown>) =>
        (params.encoding ?? "json") === "json" ? { body: JSON.stringify(fields), type: "application/json" } : { body: new URLSearchParams(Object.entries(fields).map(([key, value]) => [key, String(value)])).toString(), type: "application/x-www-form-urlencoded" };
      const rows: string[] = [];
      const exchanges: Array<{ attempt: (typeof attempts)[number]; exchange: HttpExchange }> = [];
      for (const attempt of attempts) {
        if (signal.aborted) break;
        const { body, type } = encode({ ...(params.extraFields ?? {}), [params.userField]: attempt.user, [params.passwordField]: attempt.password });
        const exchange = await http.send({ url: params.url, method: params.method ?? "POST", headers: { "content-type": type }, body, systematic: true });
        exchanges.push({ attempt, exchange });
        await wait(params.delayMs ?? 250);
      }
      const message = (exchange: HttpExchange) => (exchange.response?.body ?? exchange.error ?? "").replace(/\s+/g, " ").slice(0, 70);
      const ghostExchange = exchanges[0]!.exchange;
      let entered = 0;
      let enumeration = false;
      for (const { attempt, exchange } of exchanges) {
        const response = exchange.response;
        const ok = response && response.status < 300 && /token|session|jwt|bearer|set-cookie|"user"|success/i.test(`${JSON.stringify(response.headers)} ${response.body}`);
        if (ok && attempt.tag !== "inexistente") entered++;
        const differs = attempt.tag !== "inexistente" && !ok && response && ghostExchange.response && (response.status !== ghostExchange.response.status || message(exchange) !== message(ghostExchange));
        if (differs) enumeration = true;
        rows.push(`${exchange.id}  ${attempt.tag ? `[${attempt.tag}] ` : ""}${attempt.user} / ${attempt.password}  ${response?.status ?? "ERR"}  ${response?.bodyBytes ?? 0} B  ${message(exchange)}${ok ? "  ← ENTRÓ" : differs ? "  ← distinto al inexistente" : ""}`);
      }
      const notes: string[] = [];
      if (entered) notes.push(`${entered} combinación(es) entraron: registrá candidato con los ids marcados.`);
      if (enumeration) notes.push("El servidor responde distinto a un usuario inexistente que a una contraseña incorrecta: enumeración de usuarios (comparar con el id [inexistente]).");
      if (!entered && !enumeration) notes.push("Ninguna entró y los mensajes no distinguen usuario inexistente de contraseña incorrecta.");
      if (trimmed) notes.push(`Se recortaron ${trimmed} intentos: el máximo por llamada es 30. Llamá de nuevo con el resto si hace falta.`);
      return finish([...rows, ...notes, counter()].join("\n"), { intentos: exchanges.length, entraron: entered, enumeracion: enumeration });
    },
  };

  /** Cargas por familia sobre un parámetro, con diferencia contra la petición de control. */
  const paramProbe: Tool = {
    name: "param_probe",
    label: "Sonda de parámetro",
    description:
      "Envía cargas cortas de una o varias familias (traversal, html, sql, ssti, comando, numerico, tipo) en un parámetro de consulta o campo del cuerpo, y por cada una muestra la diferencia contra la petición de control: " +
      "código, tamaño, si la carga se refleja literal, si aparece un error del servidor o un resultado de evaluación (49 para 7*7). Es para orientar: lo que marque, confirmalo con una petición propia.",
    parameters: obj(
      {
        url: str(),
        method: str({ enum: ["GET", "POST", "PUT", "PATCH"] }),
        param: str({ description: "Nombre del parámetro de consulta o del campo del cuerpo" }),
        where: str({ enum: ["query", "body"] }),
        families: list(str({ enum: Object.keys(PAYLOADS) })),
        baseline: str({ description: "Valor de control; por defecto 1" }),
        body: { type: "object", description: "Cuerpo JSON base cuando where=body" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        identity: str(),
      },
      ["url", "param"],
    ),
    execute: async (params) => {
      const families: string[] = params.families?.length ? params.families : ["traversal", "html", "sql", "numerico"];
      const payloads = families.flatMap((family) => (PAYLOADS[family] ?? []).map((value) => ({ family, value })));
      if (payloads.length > 40) throw new Error("Demasiadas cargas: elegí menos familias");
      const build = (value: string) => {
        const url = new URL(params.url);
        const where = params.where ?? (params.method && params.method !== "GET" ? "body" : "query");
        if (where === "query") {
          url.searchParams.set(params.param, value);
          return { url: url.toString(), body: undefined as string | undefined, headers: params.headers };
        }
        return { url: url.toString(), body: JSON.stringify({ ...(params.body ?? {}), [params.param]: value }), headers: { "content-type": "application/json", ...(params.headers ?? {}) } };
      };
      const control = build(params.baseline ?? "1");
      const base = await http.send({ ...control, method: params.method ?? "GET" }, params.identity);
      const rows: string[] = [`control ${base.id}: ${base.response?.status ?? base.error} · ${base.response?.bodyBytes ?? 0} B`];
      let flagged = 0;
      for (let i = 0; i < payloads.length; i += 4) {
        const batch = await Promise.all(payloads.slice(i, i + 4).map(async ({ family, value }) => ({ family, value, exchange: await http.send({ ...build(value), method: params.method ?? "GET", systematic: true }, params.identity) })));
        for (const { family, value, exchange } of batch) {
          const body = exchange.response?.body ?? "";
          const signals: string[] = [];
          if (value.length > 1 && body.includes(value)) signals.push("reflejada literal");
          const serverError = /syntax error|sqlite|mysql|postgres|pg_|ORA-\d|unterminated|unexpected token|traceback|exception|stack trace|warning: /i;
          if (serverError.test(body) && !serverError.test(base.response?.body ?? "")) signals.push("error del servidor");
          if (family === "ssti" && /\b49\b/.test(body) && !/\b49\b/.test(base.response?.body ?? "")) signals.push("evaluó 7*7");
          if (family === "traversal" && /root:|\[extensions\]|localhost/i.test(body) && !/root:/.test(base.response?.body ?? "")) signals.push("contenido de archivo");
          if (exchange.response && exchange.response.status >= 500) signals.push("5xx");
          if (signals.length) flagged++;
          rows.push(`${exchange.id}  ${family.padEnd(9)} ${JSON.stringify(value).slice(0, 28).padEnd(30)} ${diffResponses(base, exchange).slice(0, 50).padEnd(50)} ${signals.join(", ")}`);
        }
      }
      rows.push(counter());
      return finish(rows.join("\n"), { cargas: payloads.length, marcadas: flagged });
    },
  };

  /** Mutaciones con sentido de negocio sobre los campos de un cuerpo que ya funcionó. */
  const bodyProbe: Tool = {
    name: "body_probe",
    label: "Sonda de cuerpo",
    description:
      "Toma una petición de escritura que ya funcionó (por id de intercambio, o url+method+body) y la repite alterando un campo por vez con valores que el servidor no debería aceptar: " +
      "números a 0, negativos, enormes y decimales; booleanos invertidos; cadenas que parecen rol o estado a admin/aprobado; ids al vecino; cadenas vacías, largas, de otro tipo y con caracteres especiales. Máximo 41 peticiones. Muestra por cada mutación la diferencia contra el control y si el valor alterado volvió aceptado en la respuesta. " +
      "Es la prueba de lógica de negocio (precio, cantidad, descuento, estado, dueño) sin saber de antemano qué campo importa. " +
      "mode «agregar» es asignación masiva: suma, de a uno, campos que la escritura NO manda (role, roles, isAdmin/is_admin, admin, plan, tier, status, verified/email_verified, owner_id, user_id, tenant_id/org_id, price, balance, credits, y los que el objeto expone) con un valor del tipo que tiene el objeto; mode «hpp» repite una clave con un valor inocuo y otro privilegiado, en los dos órdenes (role=user&role=admin; en JSON la clave dos veces). " +
      "Los dos leen el objeto antes y después de cada intento (readUrl, o la misma ruta en PUT/PATCH, o lo que creó un alta): sólo cuenta APLICADO si la relectura muestra el valor enviado y antes tenía otro; reflejado en la respuesta no es hallazgo. Lo aplicado se restaura enseguida. " +
      "Usalos sobre una escritura propia que ya funcionó (perfil, /me, un alta, un recurso creado en la sesión o que esa identidad recibió como suyo), JSON o formulario (encoding); sobre un recurso ajeno se niegan (para eso, ids_harvest).",
    parameters: obj(
      {
        id: str({ description: "Id del intercambio de control (una escritura que respondió 2xx)" }),
        url: str(),
        method: str({ enum: ["POST", "PUT", "PATCH"] }),
        body: { type: "object", description: "Cuerpo JSON de control si no pasás id" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        identity: str(),
        fields: list(str({ description: "Limitar a estos campos; por defecto todos los de primer nivel (en agregar/hpp: los de privilegio)" })),
        maxRequests: int({ minimum: 1, maximum: 41, default: 41 }),
        mode: str({ enum: ["mutar", "agregar", "hpp"], description: "mutar (por defecto) altera los campos que vienen; agregar suma campos de privilegio ausentes; hpp duplica claves" }),
        encoding: str({ enum: ["json", "form"], description: "Cómo se manda el cuerpo en agregar/hpp; por defecto el del intercambio, o json" }),
        readUrl: str({ description: "Ruta GET que devuelve el objeto, para confirmar por relectura (agregar/hpp)" }),
        restore: { type: "boolean", description: "Restaurar cada campo aplicado apenas se confirma (por defecto sí)" },
      },
      [],
    ),
    execute: async (params, signal) => {
      const mode: "mutar" | AssignMode = params.mode ?? "mutar";
      let encoding: BodyEncoding | undefined = params.encoding;
      const maxRequests = params.maxRequests ?? 41;
      if (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 41) throw new Error("maxRequests debe estar entre 1 y 41");
      let url: string = params.url;
      let method: string = params.method ?? "POST";
      let body: Record<string, unknown> = params.body ?? {};
      let headers: Record<string, string> = params.headers ?? {};
      let identity: string | undefined = params.identity;
      if (params.id) {
        const hash = http.hashOf(params.id);
        if (!hash) throw new Error(`No existe el intercambio ${params.id}`);
        const stored = JSON.parse(context.artifacts.read(hash).toString("utf8")) as HttpExchange;
        url = stored.request.url;
        method = params.method ?? stored.request.method;
        try {
          body = stored.request.body ? JSON.parse(stored.request.body) : {};
        } catch {
          // Un formulario sirve para agregar y hpp; mutar sigue pidiendo JSON.
          if (mode === "mutar" || !stored.request.body) throw new Error("El cuerpo del intercambio no es JSON; pasá body");
          body = Object.fromEntries(new URLSearchParams(stored.request.body));
          encoding ??= "form";
        }
        identity ??= Object.values(stored.request.headers).map((value) => /^<identidad (.+)>$/.exec(String(value))?.[1]).find(Boolean);
        headers = { ...Object.fromEntries(Object.entries(stored.request.headers).filter(([key, value]) => !String(value).startsWith("<identidad") && key !== "user-agent")), ...headers };
      }
      if (!url) throw new Error("Pasá id o url");
      if (mode !== "mutar") {
        if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("El cuerpo de control tiene que ser un objeto (JSON) o un formulario");
        return massAssignment({ http, mode, url, method, body, encoding: encoding ?? "json", headers, identity, fields: params.fields, readUrl: params.readUrl, maxRequests, restore: params.restore !== false, harvest: context.harvest, event: context.event, notice: context.notice, signal });
      }
      const names = (params.fields?.length ? params.fields : Object.keys(body)) as string[];
      if (!names.length) throw new Error("El cuerpo no tiene campos de primer nivel para alterar");
      const mutations: Array<{ field: string; value: unknown; why: string }> = [];
      for (const field of names) {
        const current = body[field];
        const lower = field.toLowerCase();
        if (typeof current === "number") {
          mutations.push({ field, value: 0, why: "cero" }, { field, value: -1, why: "negativo" }, { field, value: 1e9, why: "enorme" });
          if (Number.isInteger(current)) mutations.push({ field, value: current + 0.5, why: "decimal" });
          if (/id$|_id|Id$/.test(field)) mutations.push({ field, value: current + 1, why: "id vecino" });
          if (/precio|price|monto|amount|total|descuento|discount/.test(lower)) mutations.push({ field, value: 1, why: "precio mínimo" });
        } else if (typeof current === "boolean") mutations.push({ field, value: !current, why: "invertido" });
        else if (typeof current === "string") {
          mutations.push({ field, value: "", why: "vacía" }, { field, value: "x".repeat(4096), why: "muy larga" }, { field, value: 0, why: "otro tipo" }, { field, value: "ñ€𝄞\"'<>\u0000", why: "caracteres especiales" });
          if (/rol|role|perfil|permiso|scope|tipo|type|estado|status/.test(lower)) mutations.push({ field, value: "admin", why: "rol admin" }, { field, value: "aprobado", why: "estado aprobado" });
          if (/^\d+$/.test(current)) mutations.push({ field, value: String(Number(current) + 1), why: "id vecino" }, { field, value: "0", why: "cero" });
          if (/email|mail/.test(lower)) mutations.push({ field, value: "admin@" + (current.split("@")[1] ?? "ejemplo.test"), why: "email de otro" });
        }
      }
      if (!mutations.length) throw new Error("Ningún campo admite mutaciones conocidas (números, booleanos, roles, estados, ids)");
      const trimmed = Math.max(0, mutations.length - (maxRequests - 1));
      mutations.length = Math.min(mutations.length, maxRequests - 1);
      const start = http.count;
      if (signal.aborted) return finish(`Cancelada. ${counter()}`, { peticiones: 0 });
      const send = (payload: Record<string, unknown>) => http.send({ url, method, headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(payload), systematic: true }, identity);
      const control = await send(body);
      const rows = [`control ${control.id}: ${control.response?.status ?? control.error} · ${control.response?.bodyBytes ?? 0} B`];
      let accepted = 0;
      let tested = 0;
      for (let i = 0; i < mutations.length; i += 4) {
        if (signal.aborted || http.remaining() === 0) break;
        const batch = await Promise.all(mutations.slice(i, i + 4).map(async (mutation) => ({ mutation, exchange: await send({ ...body, [mutation.field]: mutation.value }) })));
        for (const { mutation, exchange } of batch) {
          tested++;
          const response = exchange.response;
          const ok = response && response.status < 300;
          let echoed = false;
          try {
            // El valor alterado cuenta como devuelto sólo bajo el mismo nombre de campo, en cualquier nivel.
            const parsed = JSON.parse(response?.body ?? "");
            echoed = JSON.stringify(parsed).includes(`${JSON.stringify(mutation.field)}:${JSON.stringify(mutation.value)}`);
          } catch {}
          const flag = ok && echoed ? "ACEPTÓ y devolvió el valor alterado" : ok ? "aceptó (2xx)" : "";
          if (ok) accepted++;
          rows.push(`${exchange.id}  ${mutation.field}=${JSON.stringify(mutation.value).slice(0, 70)} (${mutation.why})`.padEnd(48) + ` ${diffResponses(control, exchange).slice(0, 48).padEnd(48)} ${flag}`);
        }
      }
      rows.push(accepted ? `${accepted} mutaciones aceptadas con 2xx: cada una es candidata si el valor alterado produce efecto (precio cobrado, rol cambiado, recurso ajeno).` : "Ninguna mutación fue aceptada.");
      if (trimmed) rows.push(`Se recortaron ${trimmed} variantes por maxRequests.`);
      rows.push("Confirmá el efecto con una petición propia y registrá candidato con evidencia.", counter());
      return finish(rows.join("\n"), { mutaciones: tested, aceptadas: accepted, peticiones: http.count - start });
    },
  };

  /** Inspección de tokens JWT: estructura, algoritmo, vencimiento y secretos triviales. */
  const jwtInspect: Tool = {
    name: "jwt_inspect",
    label: "Inspeccionar JWT",
    description:
      "Decodifica un JWT y señala lo que importa: algoritmo (none, HS* vs RS*), reclamos de identidad y rol, vencimiento ausente o muy largo, y si la firma HS256 se verifica con alguna palabra de una lista corta de secretos triviales (o las que pases). No envía nada por red.",
    parameters: obj({ token: str(), secrets: list(str()) }, ["token"]),
    parallel: true,
    pure: true,
    execute: (params) => {
      const decoded = decodeJwt(params.token.trim().replace(/^Bearer\s+/i, ""));
      if (!decoded) throw new Error("No parece un JWT (tres partes base64url separadas por punto)");
      const { header, payload } = decoded;
      const lines = [`header: ${JSON.stringify(header)}`, `payload: ${JSON.stringify(payload).slice(0, 800)}`];
      const notes: string[] = [];
      const alg = String(header.alg ?? "").toLowerCase();
      if (alg === "none" || !alg) notes.push("alg none o ausente: el servidor podría aceptar tokens sin firma; probá reenviar el payload modificado con alg none y firma vacía.");
      if (alg.startsWith("hs")) notes.push("firma simétrica: todo servicio que verifica también puede firmar; vale probar un secreto trivial.");
      if (header.kid) notes.push(`kid presente (${header.kid}): si se usa para buscar la clave, probá valores controlados.`);
      if (header.jku || header.x5u) notes.push("jku/x5u presente: la clave se obtiene de una URL; revisar si acepta una ajena.");
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp === undefined) notes.push("sin exp: el token no vence.");
      else if (payload.exp - (payload.iat ?? now) > 30 * 86400) notes.push(`vida de ${Math.round((payload.exp - (payload.iat ?? now)) / 86400)} días.`);
      else if (payload.exp < now) notes.push("vencido: si el servidor igual lo acepta, es hallazgo.");
      for (const claim of ["role", "roles", "admin", "isAdmin", "scope", "permissions", "groups", "sub", "user_id", "uid", "email"]) if (payload[claim] !== undefined) notes.push(`reclamo ${claim} = ${JSON.stringify(payload[claim])}: si el servidor confía en él sin verificar la firma o con firma débil, se puede alterar.`);
      let cracked: string | undefined;
      if (alg === "hs256" || alg === "hs384" || alg === "hs512") {
        const [h, p] = params.token.trim().replace(/^Bearer\s+/i, "").split(".");
        const candidates = [...new Set([...(params.secrets ?? []), "secret", "password", "123456", "changeme", "jwt_secret", "jwtsecret", "key", "private", "test", "dev", "development", "admin", "default", "your-256-bit-secret", "supersecret", "s3cr3t"])];
        for (const candidate of candidates) {
          const digest = createHmac(alg.replace("hs", "sha") as "sha256", candidate).update(`${h}.${p}`).digest("base64url");
          if (digest === decoded.signature) {
            cracked = candidate;
            break;
          }
        }
        notes.push(cracked ? `la firma se verifica con el secreto «${cracked}»: se pueden forjar tokens.` : `la firma no coincide con ${candidates.length} secretos triviales.`);
      }
      return finish([...lines, "", ...notes.map((note) => `- ${note}`)].join("\n"), { alg, secretoTrivial: cracked ?? null });
    },
  };

  /** Patrones de secretos en un artefacto o texto. */
  const secretsScan: Tool = {
    name: "secrets_scan",
    label: "Buscar secretos",
    description: "Busca patrones de credenciales (claves de nube, tokens, claves privadas, JWT, campos password/secret con valor, URLs con usuario y contraseña) en un artefacto guardado (hash o id de intercambio) o en un texto. Devuelve tipo, cuántas veces y un fragmento enmascarado.",
    parameters: obj({ artifact: str({ description: "Hash o id de intercambio (h12)" }), text: str({ maxLength: 50000 }) }, []),
    parallel: true,
    execute: (params) => {
      let text: string = params.text ?? "";
      if (params.artifact) {
        const hash = /^h\d+$/.test(params.artifact) ? http.hashOf(params.artifact) : params.artifact;
        if (!hash) throw new Error(`No existe el intercambio ${params.artifact}`);
        text = context.artifacts.read(hash).toString("utf8");
      }
      if (!text) throw new Error("Pasá artifact o text");
      const rows: string[] = [];
      let total = 0;
      for (const { name, pattern } of SECRET_PATTERNS) {
        const matches = [...text.matchAll(pattern)].map((match) => match[0]);
        if (!matches.length) continue;
        total += matches.length;
        const mask = (value: string) => (value.length <= 12 ? value.slice(0, 3) + "…" : `${value.slice(0, 8)}…${value.slice(-4)}`);
        rows.push(`${name}: ${matches.length} · ${[...new Set(matches)].slice(0, 3).map(mask).join("  ")}`);
      }
      return finish(rows.length ? rows.join("\n") : "Sin patrones de secretos.", { coincidencias: total });
    },
  };

  /** Tecnologías a partir de cabeceras, cookies y cuerpo de una respuesta ya obtenida. */
  const fingerprint: Tool = {
    name: "tech_fingerprint",
    label: "Huella tecnológica",
    description: "A partir de un intercambio (id) o de una URL nueva, infiere servidor, framework, lenguaje, CDN/WAF y versiones expuestas desde cabeceras, cookies y marcas del HTML. Devuelve cada inferencia con la pista que la sostiene.",
    parameters: obj({ id: str(), url: str() }, []),
    parallel: true,
    execute: async (params) => {
      let exchange: HttpExchange | undefined;
      if (params.id) {
        const hash = http.hashOf(params.id);
        if (!hash) throw new Error(`No existe el intercambio ${params.id}`);
        exchange = JSON.parse(context.artifacts.read(hash).toString("utf8"));
      } else if (params.url) exchange = await http.send({ url: params.url });
      else throw new Error("Pasá id o url");
      const response = exchange!.response;
      if (!response) throw new Error(exchange!.error ?? "sin respuesta");
      const headers = response.headers;
      const body = response.body.slice(0, 200_000);
      const hits: string[] = [];
      const say = (what: string, clue: string) => hits.push(`${what}  ← ${clue}`);
      for (const key of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime", "x-version", "via", "x-amz-cf-id", "cf-ray", "x-vercel-id", "x-served-by", "x-cache"]) if (headers[key]) say(key === "cf-ray" ? "Cloudflare" : key === "x-amz-cf-id" ? "CloudFront" : key === "x-vercel-id" ? "Vercel" : `${key}: ${headers[key]}`, `cabecera ${key}`);
      const cookies = headers["set-cookie"] ?? "";
      for (const [pattern, what] of [[/PHPSESSID/i, "PHP"], [/JSESSIONID/i, "Java (servlets)"], [/ASP\.NET_SessionId|\.AspNetCore/i, "ASP.NET"], [/connect\.sid/i, "Express (express-session)"], [/laravel_session|XSRF-TOKEN/i, "Laravel"], [/csrftoken|sessionid/i, "Django"], [/_rails|_session=/i, "Rails"], [/wordpress_/i, "WordPress"]] as Array<[RegExp, string]>) if (pattern.test(cookies)) say(what, "cookie de sesión");
      if (!/httponly/i.test(cookies) && cookies) say("cookie sin HttpOnly", "set-cookie");
      for (const [pattern, what] of [[/wp-content|wp-includes/i, "WordPress"], [/__NEXT_DATA__|_next\/static/i, "Next.js"], [/ng-version="([^"]+)"/i, "Angular"], [/data-reactroot|react-dom/i, "React"], [/__nuxt|_nuxt\//i, "Nuxt"], [/jquery[.-]?(\d[\d.]*)?/i, "jQuery"], [/bootstrap[.-]?(\d[\d.]*)?/i, "Bootstrap"], [/Drupal\.settings|\/sites\/default\/files/i, "Drupal"], [/Joomla!/i, "Joomla"], [/swagger-ui|redoc/i, "documentación de API expuesta"], [/<meta name="generator" content="([^"]+)"/i, "generator"]] as Array<[RegExp, string]>) {
        const match = pattern.exec(body);
        if (match) say(match[1] ? `${what} ${match[1]}` : what, "marca en el HTML");
      }
      if (/application\/json/.test(headers["content-type"] ?? "")) say("API JSON", "content-type");
      if (!headers["content-security-policy"]) say("sin Content-Security-Policy", "cabecera ausente");
      if (!headers["strict-transport-security"] && exchange!.request.url.startsWith("https")) say("sin HSTS", "cabecera ausente en HTTPS");
      return finish(hits.length ? hits.join("\n") : "Sin marcas reconocibles.", { pistas: hits.length });
    },
  };


  /**
   * Formas no canónicas de la misma ruta. Dos capas que normalizan distinto (un router y un
   * servidor de archivos, un middleware y su servlet) deciden la autorización sobre textos
   * distintos: la barra final, un punto y coma o una barra doble cambian quién decide.
   * No es traversal (eso es param_probe): la ruta apunta al mismo recurso.
   */
  const pathVariants: Tool = {
    name: "path_probe",
    label: "Formas de ruta",
    description:
      "Repite una petición cambiando sólo la forma de la ruta (barra final, barra doble, punto y coma de parámetro, /., mayúsculas) y marca las variantes cuyo código difiere del de la ruta original. " +
      "Usala cuando una operación responde 401, 403 o 404 y querés saber si el rechazo depende de la forma del texto y no del permiso. Cada variante cuenta como una petición.",
    parameters: obj(
      {
        url: str(),
        method: str({ enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] }),
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: str({ maxLength: 5000 }),
        identity: str({ description: "Nombre de identidad configurada" }),
      },
      ["url"],
    ),
    parallel: true,
    execute: async (params) => {
      const method: string = params.method ?? "GET";
      const target = new URL(params.url);
      const path = target.pathname;
      const segments = path.split("/").filter(Boolean);
      const last = segments.at(-1);
      const parent = segments.slice(0, -1).join("/");
      const forms = new Set<string>();
      forms.add(path.endsWith("/") ? path.replace(/\/+$/, "") || "/" : `${path}/`);
      forms.add(`${path.replace(/\/+$/, "")}/.`);
      forms.add(`${path.replace(/\/+$/, "")};x`);
      forms.add(`//${path.replace(/^\/+/, "")}`);
      if (last) {
        forms.add(`/${parent}${parent ? "/" : ""}${last};x/`);
        forms.add(`/${parent}${parent ? "/" : ""}${last.toUpperCase()}`);
      }
      // El punto y coma se inserta después de cada segmento: el límite donde dos capas dejan de
      // coincidir puede estar en cualquier parte de la ruta, no sólo al final.
      for (let i = 0; i < Math.min(segments.length, 6); i++) {
        forms.add("/" + segments.map((segment, index) => (index === i ? `${segment};x` : segment)).join("/"));
      }
      forms.delete(path);
      const send = (pathname: string) => {
        const url = new URL(target.href);
        url.pathname = pathname;
        return context.http.send({ url: url.href, method, headers: params.headers, body: method === "GET" || method === "HEAD" ? undefined : params.body, systematic: true, synthetic: pathname !== path }, params.identity);
      };
      const original = await send(path);
      const base = original.response?.status;
      const rows = [`${original.id}  original  ${path}  ${base ?? original.error}`];
      let distintas = 0;
      for (const form of forms) {
        const exchange = await send(form);
        const status = exchange.response?.status;
        const differs = status !== base;
        if (differs) distintas++;
        rows.push(`${exchange.id}  ${differs ? "DISTINTA" : "igual   "}  ${form}  ${status ?? exchange.error}  ${exchange.response?.bodyBytes ?? 0} B`);
      }
      const nota = distintas
        ? "Una variante que responde distinto que la ruta original significa que la autorización depende de la forma del texto: comprobá qué devuelve y registrá el efecto."
        : "Todas las formas responden igual que la original: el rechazo no depende de la forma de la ruta.";
      return finish([...rows, nota, ""].join("\n"), { variantes: forms.size + 1, distintas });
    },
  };

  return [authProbe, paramProbe, bodyProbe, pathVariants, jwtInspect, secretsScan, fingerprint, createGraphqlProbe(context), createOutboundProbe(context), createRaceProbe(context), createCsrfCheck(context), createWsProbe({ http, artifacts })];
}

/**
 * Cabecera de respuesta a un desafío HTTP Digest (RFC 7616, compatible con RFC 2069).
 * Es una capacidad de protocolo del cliente: sin ella no se puede siquiera intentar
 * una ruta protegida con digestAuth, ni comprobar si rechaza credenciales inválidas.
 */
export function digestHeader(challenge: string, method: string, url: string, username: string, password: string, ha1Override?: string): string {
  const field = (name: string) => new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|([^",\\s]+))`, "i").exec(challenge)?.slice(1).find((value) => value !== undefined) ?? "";
  const realm = field("realm");
  const nonce = field("nonce");
  const opaque = field("opaque");
  const qop = field("qop").split(/\s*,\s*/).filter(Boolean);
  const algorithm = (field("algorithm") || "MD5").toUpperCase();
  const hash = (value: string) => createHash(algorithm.startsWith("SHA-256") ? "sha256" : "md5").update(value).digest("hex");
  let uri = url;
  try {
    const parsed = new URL(url);
    uri = parsed.pathname + parsed.search;
  } catch {}
  const cnonce = randomBytes(8).toString("hex");
  const nc = "00000001";
  const useQop = qop.includes("auth") ? "auth" : qop[0];
  // Un archivo htdigest guarda HA1, no la contraseña: por eso se puede pasar HA1 directo.
  const ha1 = ha1Override ?? hash(`${username}:${realm}:${password}`);
  const ha2 = hash(`${method.toUpperCase()}:${uri}`);
  const response = useQop ? hash(`${ha1}:${nonce}:${nc}:${cnonce}:${useQop}:${ha2}`) : hash(`${ha1}:${nonce}:${ha2}`);
  const parts = [`username="${username}"`, `realm="${realm}"`, `nonce="${nonce}"`, `uri="${uri}"`, `response="${response}"`, `algorithm=${algorithm}`];
  if (useQop) parts.push(`qop=${useQop}`, `nc=${nc}`, `cnonce="${cnonce}"`);
  if (opaque) parts.push(`opaque="${opaque}"`);
  return `Digest ${parts.join(", ")}`;
}
