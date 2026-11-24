// Asignación masiva (mass assignment) y claves duplicadas (HPP) sobre una escritura propia, para
// body_probe. «agregar» suma campos de privilegio o propiedad que la escritura no manda (rol, admin,
// plan, verificado, dueño, saldo…) con valores del tipo que tiene el objeto; «hpp» repite una clave
// con un valor inocuo y otro privilegiado, en los dos órdenes. Un campo cuenta como aplicado sólo si
// una relectura del objeto lo muestra con el valor enviado y antes tenía otro: que la respuesta de la
// escritura lo repita no prueba nada (hay servidores que reflejan sin guardar).
import type { ToolResult } from "./agent.ts";
import { ownership, idKind, type IdHarvest, type IdKind } from "./cosecha.ts";
import { ID_SEGMENT } from "./coverage.ts";
import type { HttpClient, HttpExchange } from "./http.ts";
import { t } from "./idioma.ts";

export type AssignMode = "agregar" | "hpp";
export type BodyEncoding = "json" | "form";

interface Assignable {
  /** Nombre en snake_case y, si cambia, en camelCase. */
  names: [string, string?];
  /** Valor privilegiado por defecto; undefined en los campos de dueño (se elige un id). */
  value?: unknown;
  /** Valor inocuo para la clave duplicada cuando el objeto no trae uno. */
  benign?: unknown;
  owner?: boolean;
}

/** Campos típicos de privilegio y propiedad que un cliente no debería poder fijar. */
export const ASSIGNABLE: Assignable[] = [
  { names: ["role"], value: "admin", benign: "user" },
  { names: ["roles"], value: ["admin"], benign: ["user"] },
  { names: ["is_admin", "isAdmin"], value: true, benign: false },
  { names: ["admin"], value: true, benign: false },
  { names: ["plan"], value: "enterprise", benign: "free" },
  { names: ["tier"], value: "premium", benign: "free" },
  { names: ["status"], value: "approved", benign: "pending" },
  { names: ["verified"], value: true, benign: false },
  { names: ["email_verified", "emailVerified"], value: true, benign: false },
  { names: ["owner_id", "ownerId"], owner: true },
  { names: ["user_id", "userId"], owner: true },
  { names: ["tenant_id", "tenantId"], owner: true },
  { names: ["org_id", "orgId"], owner: true },
  { names: ["price"], value: 1, benign: 100 },
  { names: ["balance"], value: 999999, benign: 0 },
  { names: ["credits"], value: 999999, benign: 0 },
];

/** Campos que el objeto expone y suelen ser del servidor: si la relectura los trae y la escritura no los manda, también se prueban. */
const SERVER_FIELD = /^(is_?)?(admin|staff|superuser|super_?user|moderator|verified|approved|confirmed|banned|premium|vip)$|role|permission|scope|group|tier|plan|level|subscription|account_?type|credit|balance|price|discount|quota|owner|tenant|^org(anization)?_?id$|^user_?id$|verified/i;
const OWNER_FIELD = /owner|tenant|^org|user_?id|account_?id/i;
/** Valor alternativo cuando el objeto ya tiene el privilegiado (para que el cambio se vea). */
const ALTERNATIVE: Record<string, string> = { admin: "superadmin", enterprise: "business", premium: "enterprise", approved: "active" };
const WRAPPER = /^(data|user|item|result|account|profile|perfil|usuario|cuenta|object|resource|record|attributes)$/i;
/** Ids de prueba que no deberían existir: asignarle un objeto propio a una cuenta real de un tercero no es una prueba aceptable. */
const SENTINEL: Record<IdKind, string> = { numero: "2147483600", uuid: "00000000-0000-4000-8000-0000000000aa", objectid: "650000000000000000000aaa" };

const parse = (text: string | undefined): unknown => {
  try { return text ? JSON.parse(text) : undefined; } catch { return undefined; }
};
const jsonOf = (exchange: HttpExchange) => (exchange.response && exchange.response.bodyEncoding !== "base64" ? parse(exchange.response.body) : undefined);
const ok = (exchange: HttpExchange) => !!exchange.response && exchange.response.status >= 200 && exchange.response.status < 300;
const pathOf = (url: string) => {
  try { const parsed = new URL(url); return `${parsed.pathname}${parsed.search}`; } catch { return url; }
};
const show = (value: unknown) => JSON.stringify(value)?.slice(0, 60) ?? "undefined";

/** El objeto del recurso dentro de una respuesta: el primero de una lista, o el de un envoltorio («data», «user»). */
function resourceObject(node: unknown, depth = 0): Record<string, unknown> | undefined {
  if (depth > 3) return undefined;
  if (Array.isArray(node)) return resourceObject(node[0], depth + 1);
  if (!node || typeof node !== "object") return undefined;
  const record = node as Record<string, unknown>;
  const keys = Object.keys(record);
  const wrapper = keys.find((key) => WRAPPER.test(key) && record[key] && typeof record[key] === "object" && !Array.isArray(record[key]));
  if (wrapper && (keys.length === 1 || !("id" in record))) return resourceObject(record[wrapper], depth + 1);
  return record;
}

/** Busca un campo en una respuesta (en el objeto del recurso, o a lo ancho hasta cuatro niveles). */
function lookup(node: unknown, key: string): { found: boolean; value?: unknown } {
  const resource = resourceObject(node);
  if (resource && key in resource) return { found: true, value: resource[key] };
  const queue: Array<{ node: unknown; depth: number }> = [{ node, depth: 0 }];
  while (queue.length) {
    const { node: current, depth } = queue.shift()!;
    if (!current || typeof current !== "object" || depth > 4) continue;
    if (!Array.isArray(current) && key in (current as Record<string, unknown>)) return { found: true, value: (current as Record<string, unknown>)[key] };
    for (const child of Array.isArray(current) ? current.slice(0, 5) : Object.values(current)) queue.push({ node: child, depth: depth + 1 });
  }
  return { found: false };
}

const scalarSame = (a: unknown, b: unknown) => a === b || (a !== null && b !== null && a !== undefined && b !== undefined && typeof a !== "object" && typeof b !== "object" && String(a).toLowerCase() === String(b).toLowerCase());

/** ¿El valor leído es el enviado? Las listas (roles) cuentan si incluyen lo enviado, también como objetos {name}. */
function matches(sent: unknown, got: unknown): boolean {
  if (Array.isArray(sent)) {
    if (!Array.isArray(got)) return sent.length === 1 && scalarSame(sent[0], got);
    return sent.every((item) => got.some((value) => scalarSame(item, value) || (value && typeof value === "object" && Object.values(value).some((inner) => scalarSame(item, inner)))));
  }
  return scalarSame(sent, got);
}

function kindOf(value: unknown): IdKind {
  return typeof value === "string" ? idKind(value, true) ?? "numero" : "numero";
}

/**
 * Valor privilegiado coherente con el tipo que el objeto ya tiene: booleano invertido, número distinto,
 * texto privilegiado, lista con «admin»; en los campos de dueño, un id de otra identidad del operador
 * o uno que no existe. undefined si no hay un valor que se pueda distinguir del actual.
 */
function privilegedValue(spec: Assignable, field: string, current: unknown, otherId: (kind: IdKind) => string | undefined): unknown {
  if (spec.owner || (spec.value === undefined && OWNER_FIELD.test(field))) {
    const kind = current === undefined || current === null ? "numero" : kindOf(current);
    const id = otherId(kind) ?? SENTINEL[kind];
    if (scalarSame(id, current)) return undefined;
    return typeof current === "number" || (current === undefined && kind === "numero") ? Number(id) : id;
  }
  const wanted = spec.value;
  if (current === undefined || current === null) return wanted;
  if (typeof current === "boolean") return !current;
  if (typeof current === "number") {
    if (typeof wanted === "number") return wanted !== current ? wanted : current + 1;
    return current === 1 ? 2 : 1;
  }
  if (typeof current === "string") {
    if (typeof wanted === "string") return wanted.toLowerCase() !== current.toLowerCase() ? wanted : ALTERNATIVE[wanted] ?? `${wanted}2`;
    if (typeof wanted === "number") return String(Number(current) === wanted ? wanted + 1 : wanted);
    if (typeof wanted === "boolean") return current === "true" ? "false" : "true";
    return current === "admin" ? "superadmin" : "admin";
  }
  if (Array.isArray(current)) return current.some((item) => scalarSame(item, "admin")) ? [...current, "superadmin"] : [...current, "admin"];
  return undefined;
}

/** Serializa entradas en orden, admitiendo claves repetidas (que un objeto no puede tener). */
function encode(entries: Array<[string, unknown]>, encoding: BodyEncoding): string {
  if (encoding === "json") return `{${entries.map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value ?? null)}`).join(",")}}`;
  const parts: string[] = [];
  for (const [key, value] of entries) {
    if (Array.isArray(value)) for (const item of value) parts.push(`${encodeURIComponent(key)}[]=${encodeURIComponent(String(item))}`);
    else parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value === null || value === undefined ? "" : typeof value === "object" ? JSON.stringify(value) : String(value))}`);
  }
  return parts.join("&");
}

const hasId = (url: string) => {
  try { return new URL(url).pathname.split("/").some((segment) => ID_SEGMENT.test(segment)); } catch { return false; }
};

/** La lectura del objeto antes de escribir: la misma URL en PUT/PATCH; en un POST sobre /x/{id}/accion, /x/{id}. */
function inferRead(method: string, url: string): string | undefined {
  if (method === "PUT" || method === "PATCH") return url.split("#")[0];
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split("/");
    let last = -1;
    segments.forEach((segment, index) => { if (ID_SEGMENT.test(segment)) last = index; });
    if (last < 0) return undefined;
    return `${parsed.origin}${segments.slice(0, last + 1).join("/")}`;
  } catch {
    return undefined;
  }
}

/** URL del objeto que creó un alta: Location, o la colección más el id de la respuesta (con 201). */
function createdUrl(url: string, exchange: HttpExchange): string | undefined {
  const response = exchange.response;
  if (!response || !ok(exchange)) return undefined;
  const location = response.headers.location ?? response.headers["content-location"];
  if (location) {
    try { return new URL(location, url).href; } catch { /* Location rota */ }
  }
  if (response.status !== 201 || hasId(url)) return undefined;
  const resource = resourceObject(jsonOf(exchange));
  const id = resource?.id ?? resource?._id ?? resource?.uuid;
  if ((typeof id !== "string" && typeof id !== "number") || !/^[\w.-]{1,64}$/.test(String(id))) return undefined;
  return `${url.split(/[?#]/)[0]!.replace(/\/+$/, "")}/${encodeURIComponent(String(id))}`;
}

export interface AssignmentInput {
  http: HttpClient;
  mode: AssignMode;
  url: string;
  method: string;
  body: Record<string, unknown>;
  encoding: BodyEncoding;
  headers: Record<string, string>;
  identity?: string;
  fields?: string[];
  readUrl?: string;
  maxRequests: number;
  restore: boolean;
  harvest?: IdHarvest;
  event?: (type: string, payload: unknown) => void;
  notice?: (text: string) => void;
  signal: AbortSignal;
}

interface Attempt {
  field: string;
  value: unknown;
  /** Cómo se mandó: «agregar» o el orden de la clave duplicada. */
  label: string;
  /** Cuerpo crudo: con HPP lleva la clave dos veces. */
  payload: string;
}

type Outcome = "APLICADO" | "GUARDADO" | "reflejado, no aplicado" | "sin efecto" | "rechazado" | "sin relectura" | "ya tenía ese valor";

export async function massAssignment(input: AssignmentInput): Promise<ToolResult> {
  const { http, mode, url, encoding, identity, signal } = input;
  const method = input.method.toUpperCase();
  if (!["POST", "PUT", "PATCH"].includes(method)) throw new Error("La asignación masiva va sobre una escritura: POST, PUT o PATCH.");
  const owned = input.harvest ? input.harvest.ownedBy(identity, url) : ownership(http, identity, url);
  if (!owned.ok) throw new Error(`body_probe en modo «${mode}» sólo corre sobre recursos propios: ${owned.why}. Usalo sobre un alta (POST a la colección), un recurso que creaste en esta sesión o uno que la misma identidad recibió como suyo (/me, su propio listado). Para recursos de otra cuenta está ids_harvest, de sólo lectura.`);
  const start = http.count;
  const left = () => Math.min(input.maxRequests - (http.count - start), http.remaining() ?? Infinity);
  const contentType = encoding === "json" ? "application/json" : "application/x-www-form-urlencoded";
  const baseHeaders = Object.fromEntries(Object.entries(input.headers).filter(([key]) => !/^content-(type|length)$/i.test(key)));
  const write = (payload: string) => http.send({ url, method, headers: { ...baseHeaders, "content-type": contentType }, body: payload, systematic: true }, identity);
  const read = async (target: string): Promise<HttpExchange | undefined> => {
    try { return await http.send({ url: target, method: "GET", headers: baseHeaders }, identity); } catch { return undefined; }
  };
  const entries = Object.entries(input.body);
  const bodyKeys = new Set(Object.keys(input.body));
  const rows: string[] = [];
  const finishWith = (lines: string[], details: Record<string, unknown>): ToolResult => ({ text: [...lines, `peticiones HTTP: ${http.count}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`].join("\n"), details: { modo: mode, peticiones: http.count - start, ...details } });

  // Estado antes de escribir (en una actualización) y escritura de control con el cuerpo tal cual.
  let readUrl = input.readUrl ?? inferRead(method, url);
  let state: unknown;
  if (readUrl) {
    const before = await read(readUrl);
    state = before && ok(before) ? jsonOf(before) : undefined;
    if (before) rows.push(`estado antes ${before.id}: GET ${pathOf(readUrl)} → ${before.response?.status ?? before.error}${state === undefined ? " (no es JSON o no respondió 2xx: no sirve para confirmar)" : ""}`);
    if (state === undefined && !input.readUrl) readUrl = undefined;
  }
  if (signal.aborted) return finishWith(["Cancelada."], { intentos: 0 });
  const control = await write(encode(entries, encoding));
  rows.push(`control ${control.id}: ${method} ${pathOf(url)} → ${control.response?.status ?? control.error} · ${control.response?.bodyBytes ?? 0} B`);
  if (!ok(control)) return finishWith([...rows, "La escritura de control no respondió 2xx: conseguí primero una que funcione (js_endpoints da los campos) y repetí."], { intentos: 0, aplicados: 0 });
  const creationUrl = method === "POST" ? createdUrl(url, control) : undefined;
  const creation = !!creationUrl;
  if (creationUrl) {
    readUrl = creationUrl;
    const after = await read(creationUrl);
    state = after && ok(after) ? jsonOf(after) : undefined;
    if (after) rows.push(`alta: el control creó ${pathOf(creationUrl)}; relectura ${after.id} → ${after.response?.status ?? after.error}`);
  } else if (!readUrl && method === "POST") {
    // POST sin id ni alta (un perfil, una preferencia): la misma ruta con GET suele devolver el objeto.
    const probe = await read(url);
    if (probe && ok(probe) && jsonOf(probe) !== undefined) {
      readUrl = url;
      state = jsonOf(probe);
      rows.push(`relectura ${probe.id}: GET ${pathOf(url)} devuelve el objeto`);
    }
  }
  if (!readUrl || state === undefined) {
    return finishWith([...rows, "Sin una lectura JSON del objeto no se puede confirmar nada: una respuesta que repite el campo no prueba que se haya guardado. Pasá readUrl (la ruta GET que devuelve este objeto) y repetí."], { intentos: 0, aplicados: 0, sinRelectura: true });
  }

  // Campos a probar: los que el objeto expone y la escritura no manda, después la lista típica.
  const resource = resourceObject(state) ?? {};
  const camel = Object.keys(input.body).filter((key) => /[a-z][A-Z]/.test(key)).length > Object.keys(input.body).filter((key) => key.includes("_")).length;
  const otherId = (kind: IdKind) => input.harvest?.otherOperatorId(identity, kind);
  const specs: Array<{ field: string; spec: Assignable }> = [];
  const taken = new Set<string>();
  const push = (field: string, spec: Assignable) => {
    if (taken.has(field)) return;
    taken.add(field);
    specs.push({ field, spec });
  };
  const wanted = input.fields?.length ? new Set(input.fields) : undefined;
  for (const spec of ASSIGNABLE) {
    const present = spec.names.find((name) => name && (name in resource || bodyKeys.has(name)));
    if (present) push(present, spec);
  }
  for (const key of Object.keys(resource)) {
    if (/^(id|_id|uuid|guid)$/i.test(key) || !SERVER_FIELD.test(key)) continue;
    const value = resource[key];
    if (value !== null && typeof value === "object" && !Array.isArray(value)) continue;
    if (OWNER_FIELD.test(key)) push(key, { names: [key], owner: true });
    else push(key, { names: [key], value: typeof value === "string" ? (/plan|tier|level|subscription|account_?type/i.test(key) ? "enterprise" : "admin") : undefined });
  }
  for (const spec of ASSIGNABLE) push((camel && spec.names[1]) || spec.names[0], spec);
  for (const field of wanted ?? []) if (!taken.has(field)) push(field, { names: [field], value: OWNER_FIELD.test(field) ? undefined : "admin", owner: OWNER_FIELD.test(field) });
  const chosen = specs.filter(({ field }) => !wanted || wanted.has(field));

  const attempts: Attempt[] = [];
  const skipped: string[] = [];
  if (mode === "agregar") {
    for (const { field, spec } of chosen) {
      if (bodyKeys.has(field)) continue;
      const current = lookup(state, field);
      const value = privilegedValue(spec, field, current.value, otherId);
      if (value === undefined) { skipped.push(field); continue; }
      attempts.push({ field, value, label: "agregar", payload: encode([...entries, [field, value]], encoding) });
    }
  } else {
    // HPP: los campos de privilegio que la escritura o el objeto ya traen; si no hay, los tres primeros de la lista.
    const relevant = wanted ? chosen : chosen.filter(({ field }) => bodyKeys.has(field) || lookup(state, field).found);
    const pool = relevant.length ? relevant : chosen.filter(({ spec }) => !spec.owner).slice(0, 3);
    for (const { field, spec } of pool.slice(0, wanted ? 8 : 4)) {
      const current = bodyKeys.has(field) ? input.body[field] : lookup(state, field).value;
      let value = privilegedValue(spec, field, current, otherId);
      let benign = current ?? spec.benign;
      // Una lista no se duplica: la clave repetida lleva un valor suelto.
      if (Array.isArray(value)) value = value.at(-1);
      if (Array.isArray(benign)) benign = benign[0];
      if (value === undefined || benign === undefined || matches(value, benign)) { skipped.push(field); continue; }
      const rest = entries.filter(([key]) => key !== field);
      attempts.push({ field, value, label: `hpp: ${show(benign)} y después ${show(value)}`, payload: encode([...rest, [field, benign], [field, value]], encoding) });
      attempts.push({ field, value, label: `hpp: ${show(value)} y después ${show(benign)}`, payload: encode([...rest, [field, value], [field, benign]], encoding) });
    }
  }
  if (!attempts.length) return finishWith([...rows, `No quedó ningún campo para probar${skipped.length ? ` (sin un valor distinguible del actual: ${skipped.join(", ")})` : ""}.`], { intentos: 0, aplicados: 0 });

  const baseline = state;
  const outcomes: Array<{ field: string; value: unknown; outcome: Outcome; before: { found: boolean; value?: unknown }; label: string }> = [];
  let trimmed = 0;
  const restored: string[] = [];
  const unrestored: string[] = [];
  for (const attempt of attempts) {
    if (signal.aborted) break;
    // En un alta, cada intento crea un objeto nuevo y se compara contra el del control; en una
    // actualización, contra el estado que dejó el intento anterior.
    const before = lookup(creation ? baseline : state, attempt.field);
    // Si puede quedar aplicado (el campo existía), se reserva lo que cuesta restaurarlo.
    if (left() < (input.restore && !creation && before.found ? 4 : 2)) { trimmed++; continue; }
    if (before.found && matches(attempt.value, before.value)) {
      outcomes.push({ field: attempt.field, value: attempt.value, outcome: "ya tenía ese valor", before, label: attempt.label });
      rows.push(`—  ${attempt.field}=${show(attempt.value)} (${attempt.label}): el objeto ya tenía ese valor; no se puede distinguir`);
      continue;
    }
    const exchange = await write(attempt.payload);
    const echoed = ok(exchange) && matches(attempt.value, lookup(jsonOf(exchange), attempt.field).value) && lookup(jsonOf(exchange), attempt.field).found;
    if (!ok(exchange)) {
      outcomes.push({ field: attempt.field, value: attempt.value, outcome: "rechazado", before, label: attempt.label });
      rows.push(`${exchange.id}  ${attempt.field}=${show(attempt.value)} (${attempt.label})  ${exchange.response?.status ?? exchange.error}  rechazado`);
      continue;
    }
    const target = creation ? createdUrl(url, exchange) : readUrl;
    const after = target ? await read(target) : undefined;
    const afterState = after && ok(after) ? jsonOf(after) : undefined;
    let outcome: Outcome;
    if (afterState === undefined) outcome = "sin relectura";
    else {
      const now = lookup(afterState, attempt.field);
      if (now.found && matches(attempt.value, now.value)) outcome = before.found ? "APLICADO" : "GUARDADO";
      else outcome = echoed ? "reflejado, no aplicado" : "sin efecto";
      if (!creation) state = afterState;
    }
    outcomes.push({ field: attempt.field, value: attempt.value, outcome, before, label: attempt.label });
    const was = before.found ? `antes ${show(before.value)}` : "antes no existía";
    rows.push(`${exchange.id}  ${attempt.field}=${show(attempt.value)} (${attempt.label})  ${exchange.response!.status}${echoed ? " reflejado" : ""}  relectura ${after?.id ?? "—"}: ${outcome}${outcome === "APLICADO" || outcome === "GUARDADO" ? ` (${was})` : ""}`);
    // Restauración enseguida: el objeto propio vuelve a su valor anterior y el próximo intento (el
    // otro orden de la clave duplicada, otro campo) arranca del estado original.
    if (outcome === "APLICADO" && input.restore && !creation) {
      if (left() < 2 || signal.aborted) { unrestored.push(`${attempt.field} (quedó en ${show(attempt.value)}; antes ${show(before.value)})`); continue; }
      const back = await write(encode([...entries.filter(([key]) => key !== attempt.field), [attempt.field, before.value]], encoding));
      const reread = await read(readUrl);
      const now = reread && ok(reread) ? jsonOf(reread) : undefined;
      const done = now !== undefined && matches(before.value, lookup(now, attempt.field).value);
      if (now !== undefined) state = now;
      if (done) restored.push(attempt.field);
      else unrestored.push(`${attempt.field} (quedó en ${show(attempt.value)}; antes ${show(before.value)})`);
      rows.push(`restauración ${back.id}: ${attempt.field}=${show(before.value)} → relectura ${reread?.id ?? "—"}: ${done ? "restaurado" : "NO volvió; revisalo a mano"}`);
    }
  }
  if (unrestored.length) rows.push(`Sin restaurar: ${unrestored.join(", ")}. Devolvelo a mano antes de seguir.`);

  const fields = (outcome: Outcome) => [...new Set(outcomes.filter((item) => item.outcome === outcome).map((item) => item.field))];
  const aplicados = fields("APLICADO");
  const guardados = fields("GUARDADO");
  const reflejados = fields("reflejado, no aplicado");
  if (aplicados.length) rows.push(`APLICADO (la relectura lo muestra con el valor enviado y antes tenía otro): ${aplicados.join(", ")}. Cada uno es candidato a asignación masiva${mode === "hpp" ? " por clave duplicada" : ""}: registralo con finding_record con el control, la escritura y la relectura (ids) como evidencia.`);
  if (guardados.length) rows.push(`GUARDADO pero el objeto no tenía ese campo: ${guardados.join(", ")}. El servidor guarda campos arbitrarios; no es hallazgo hasta ver un efecto (permiso nuevo, precio cobrado, acceso a otra cuenta).`);
  if (reflejados.length) rows.push(`Reflejados en la respuesta pero no aplicados: ${reflejados.join(", ")}. No es hallazgo: la respuesta repite lo que mandaste.`);
  if (!aplicados.length && !guardados.length) rows.push("Ningún campo se aplicó: la relectura del objeto no cambió.");
  if (creation) rows.push("Cada intento creó un objeto (quedan en «Para limpiar» del informe).");
  if (trimmed) rows.push(`Se recortaron ${trimmed} intentos por maxRequests o el tope de la sesión.`);
  const details = { intentos: outcomes.length, aplicados: aplicados.length, guardados: guardados.length, reflejados: reflejados.length, campos: aplicados, restaurados: restored };
  input.event?.("asignacion.sondeo", { modo: mode, metodo: method, ruta: http.redactIdentities(pathOf(url)), identidad: identity ?? null, aplicados, guardados, reflejados, restaurados: restored, peticiones: http.count - start });
  if (aplicados.length) input.notice?.(t(`Asignación masiva confirmada por relectura en ${method} ${http.redactIdentities(pathOf(url))}: ${aplicados.join(", ")}. Falta registrarla como hallazgo.`, `Mass assignment confirmed by re-read on ${method} ${http.redactIdentities(pathOf(url))}: ${aplicados.join(", ")}. It still has to be recorded as a finding.`));
  return finishWith(rows, details);
}
