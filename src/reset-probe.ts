// Sonda de recuperación de contraseña. Sólo con correos del operador: la «víctima» y el «atacante»
// son dos direcciones creadas con mail_address en esta sesión (llegan a su casilla) y la sonda se
// niega a mandar un pedido que nombre cualquier otra dirección. Prueba:
//   · el correo duplicado o en lista (email=a&email=b, {"email":[a,b]}, separadores , espacio y salto):
//     ¿le llega al atacante un mail de reset de la cuenta víctima?
//   · el envenenamiento del enlace por Host, X-Forwarded-Host, X-Forwarded-Server, X-Host y Forwarded,
//     con un host marcador propio que nunca resuelve (*.orobas.invalid);
//   · el token: si el anterior sigue valiendo después de pedir otro, si se reusa, cuándo vence según el
//     mail y si es corto o predecible (sólo mirando los tokens recibidos, sin adivinar ninguno).
// Lo que llegó a cada dirección se lee con la misma regla de mail_wait: sólo mensajes dirigidos a
// direcciones de prueba propias.
import { createHash, randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Tool } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { aliasFor, digest, fetchFor, mailboxes, type Connector, type Mail, type Mailbox } from "./correo.ts";
import { isDestructive, type HttpClient, type HttpExchange } from "./http.ts";
import { recordResidue } from "./residuos.ts";

export interface ResetProbeContext {
  http: HttpClient;
  artifacts: Artifacts;
  db: DatabaseSync;
  sessionId: string;
  connector?: Connector;
  boxes?: () => Mailbox[];
  sleep?: (ms: number) => Promise<void>;
}

const EMAIL = /[^\s@"'<>,;:()[\]\\]+@[^\s@"'<>,;:()[\]\\]+\.[a-z]{2,}/gi;

/** Valores de un token y su enlace sacados de un mail de recuperación. */
export function resetToken(mail: Pick<Mail, "subject" | "text" | "html">): { link?: string; token?: string; code?: string } {
  const info = digest(mail);
  const link = info.links.find((url) => /reset|password|passwd|recover|recuper|forgot|olvid|token|clave|contrase|restablec/i.test(url)) ?? info.links[0];
  let token: string | undefined;
  if (link) {
    try {
      const url = new URL(link);
      const named = [...url.searchParams.entries()].find(([key, value]) => /^(token|reset_?token|code|key|hash|t|k|otp|sig(nature)?)$/i.test(key) && value.length >= 4);
      const longest = [...url.searchParams.values()].filter((value) => value.length >= 16).sort((a, b) => b.length - a.length)[0];
      const segment = url.pathname.split("/").filter(Boolean).at(-1) ?? "";
      token = named?.[1] ?? longest ?? (/^[\w.~-]{16,}$/.test(segment) ? segment : undefined);
    } catch {}
  }
  return { link, token, code: info.codes[0] };
}

const ALPHABETS: Array<{ name: string; test: RegExp; size: number }> = [
  { name: "dígitos", test: /^\d+$/, size: 10 },
  { name: "hexadecimal", test: /^[0-9a-f]+$/i, size: 16 },
  { name: "alfanumérico", test: /^[0-9a-z]+$/i, size: 62 },
  { name: "base64url", test: /^[\w-]+=*$/, size: 64 },
];

/** Observaciones sobre tokens recibidos: largo, alfabeto, bits aproximados y patrones predecibles. No adivina ninguno. */
export function analyzeTokens(tokens: string[], email: string, now = Date.now()): { lines: string[]; weak: string[] } {
  const lines: string[] = [];
  const weak: string[] = [];
  const unique = [...new Set(tokens.filter(Boolean))];
  for (const token of unique) {
    const alphabet = ALPHABETS.find((item) => item.test.test(token));
    const bits = Math.round(token.length * Math.log2(alphabet?.size ?? 90));
    const notes: string[] = [];
    if (/^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*$/.test(token)) {
      try {
        const payload = JSON.parse(Buffer.from(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
        const header = JSON.parse(Buffer.from(token.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
        notes.push(`JWT alg ${header.alg ?? "?"}${payload.exp ? `, vence ${new Date(Number(payload.exp) * 1000).toISOString()} (${Math.round((Number(payload.exp) * 1000 - now) / 60000)} min)` : ", sin exp"}`);
        if (String(header.alg).toLowerCase() === "none") weak.push("JWT con alg none");
      } catch {}
    } else if (bits < 64) {
      weak.push(`${alphabet?.name === "dígitos" && token.length <= 8 ? "código numérico corto" : "token corto"} (${token.length} caracteres, ~${bits} bits)`);
    }
    const lower = email.toLowerCase();
    for (const algorithm of ["md5", "sha1", "sha256"]) {
      if (createHash(algorithm).update(lower).digest("hex") === token.toLowerCase()) weak.push(`es el ${algorithm} del correo`);
    }
    if (/^\d{10,13}$/.test(token) && Math.abs(Number(token.length === 10 ? Number(token) * 1000 : Number(token)) - now) < 7 * 24 * 3600_000) weak.push("parece una marca de tiempo");
    try {
      const decoded = Buffer.from(token.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      if (decoded.toLowerCase().includes(lower)) weak.push("en base64 contiene el correo");
    } catch {}
    lines.push(`${token.slice(0, 6)}… ${token.length} caracteres, ${alphabet?.name ?? "mixto"}, ~${bits} bits${notes.length ? ` · ${notes.join(" · ")}` : ""}`);
  }
  if (unique.length < tokens.filter(Boolean).length) weak.push("el mismo token llegó en dos pedidos: no se renueva");
  const numeric = unique.filter((token) => /^\d{1,15}$/.test(token)).map(Number);
  for (let i = 1; i < numeric.length; i++) if (Math.abs(numeric[i]! - numeric[i - 1]!) < 1000) { weak.push("tokens numéricos casi consecutivos"); break; }
  for (let i = 1; i < unique.length; i++) {
    const [a, b] = [unique[i - 1]!, unique[i]!];
    let common = 0;
    while (common < Math.min(a.length, b.length) && a[common] === b[common]) common++;
    if (a.length >= 8 && common >= Math.floor(a.length / 2) && !a.startsWith("eyJ")) { weak.push(`dos tokens comparten ${common} caracteres iniciales`); break; }
  }
  return { lines, weak: [...new Set(weak)] };
}

/** Vencimiento que declara el mail («vence en 30 minutos», «expires in 1 hour»). */
export function declaredExpiry(mail: Pick<Mail, "subject" | "text" | "html">): string | undefined {
  const text = digest(mail).snippet + " " + mail.text;
  return /(vence|venc|expira|caduca|expires?|valid for|válid[oa] (por|durante))[^.\n]{0,40}?\d+\s*(min(uto)?s?|minutes?|h(ora)?s?|hours?|d[ií]as?|days?)/i.exec(text)?.[0];
}

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const bounded = (value: unknown, fallback: number, min: number, max: number, name: string) => {
  const result = value ?? fallback;
  if (typeof result !== "number" || !Number.isInteger(result) || result < min || result > max) throw new Error(`${name}: usá un entero entre ${min} y ${max}`);
  return result;
};
const fingerprint = (mail: Mail) => createHash("sha256").update(`${mail.date}|${mail.to}|${mail.subject}|${mail.text}|${mail.html}`).digest("hex").slice(0, 16);
const accepted = (exchange: HttpExchange) => !!exchange.response && exchange.response.status < 400;
const rejectedWords = /invalid|inválid|expired|expir|venc|caduc|error|denied|no v[aá]lido|not found/i;

export const RESET_TESTS = ["duplicado", "envenenamiento", "token"] as const;
const HEADER_VARIANTS = [
  { id: "Host", code: "h", headers: (marker: string) => ({ host: marker }) },
  { id: "X-Forwarded-Host", code: "xfh", headers: (marker: string) => ({ "x-forwarded-host": marker }) },
  { id: "X-Forwarded-Server", code: "xfs", headers: (marker: string) => ({ "x-forwarded-server": marker }) },
  { id: "X-Host", code: "xh", headers: (marker: string) => ({ "x-host": marker }) },
  { id: "Forwarded", code: "fwd", headers: (marker: string) => ({ forwarded: `host=${marker}` }) },
];

export function createResetProbe(context: ResetProbeContext): Tool {
  const { http, artifacts, db } = context;
  db.exec("create table if not exists mail_addresses(address text primary key, label text not null, mailbox text not null, created_at integer not null, session_id text)");
  const own = (address: string) => db.prepare("select address, mailbox from mail_addresses where lower(address)=lower(?) and session_id=?").get(address.trim(), context.sessionId) as { address: string; mailbox: string } | undefined;
  const sleep = context.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  return {
    name: "reset_probe",
    label: "Sonda de recuperación de contraseña",
    description:
      "Prueba el pedido de recuperación de contraseña con DOS direcciones tuyas creadas con mail_address en esta sesión (victim: la de la cuenta registrada; attacker: otra tuya) y lee qué llegó a cada una. " +
      "duplicado: email=a&email=b, {\"email\":[a,b]} y separadores (coma, espacio, salto); envenenamiento: Host, X-Forwarded-Host, X-Forwarded-Server, X-Host y Forwarded con un host marcador *.orobas.invalid, y mira si el enlace del mail lo usa; " +
      "token: si el anterior sigue valiendo después de pedir otro, reúso (con complete), vencimiento declarado y si es corto o predecible. Nunca manda un pedido con otra dirección. Máximo 24 peticiones; cada pedido manda un mail a tu casilla.",
    parameters: {
      type: "object",
      properties: {
        url: str({ description: "Endpoint que pide el reset (p. ej. /api/forgot-password)" }),
        method: str({ enum: ["POST", "PUT"] }),
        field: str({ description: "Campo del correo; por defecto «email»" }),
        encoding: str({ enum: ["json", "form"], description: "Codificación del pedido normal; por defecto json" }),
        victim: str({ description: "Dirección de la cuenta registrada en el objetivo (creada con mail_address en esta sesión)" }),
        attacker: str({ description: "Otra dirección tuya (mail_address en esta sesión) que hace de atacante" }),
        extraFields: { type: "object", additionalProperties: { type: "string" } },
        headers: { type: "object", additionalProperties: { type: "string" } },
        identity: str(),
        tests: { type: "array", items: str({ enum: [...RESET_TESTS] }), description: "Qué pruebas correr; por defecto todas" },
        complete: {
          type: "object",
          description: "Cómo se usa el token para fijar contraseña: habilita la prueba de reúso. Cambia la contraseña de TU cuenta de prueba (victim).",
          properties: {
            url: str(), method: str({ enum: ["POST", "PUT", "PATCH"] }), tokenField: str(), passwordField: str(), confirmField: str(),
            password: str({ description: "Contraseña nueva; si falta se genera una y se muestra" }),
            encoding: str({ enum: ["json", "form"] }), extraFields: { type: "object", additionalProperties: { type: "string" } },
          },
          required: ["url", "tokenField", "passwordField"],
        },
        waitSec: int({ minimum: 0, maximum: 180, default: 60, description: "Cuánto esperar los mails de cada tanda" }),
        maxRequests: int({ minimum: 1, maximum: 24, default: 20 }),
        delayMs: int({ minimum: 0, maximum: 10000, default: 1500 }),
      },
      required: ["url", "victim"],
    },
    execute: async (params, signal) => {
      const waitMs = bounded(params.waitSec, 60, 0, 180, "waitSec") * 1000;
      const maxRequests = bounded(params.maxRequests, 20, 1, 24, "maxRequests");
      const delayMs = bounded(params.delayMs, 1500, 0, 10000, "delayMs");
      const method = String(params.method ?? "POST").toUpperCase();
      if (!["POST", "PUT"].includes(method)) throw new Error("El pedido de reset va con POST o PUT");
      const field = String(params.field ?? "email");
      const encoding = params.encoding === "form" ? "form" : "json";
      const tests = new Set<string>(params.tests?.length ? params.tests : RESET_TESTS);
      for (const test of tests) if (!(RESET_TESTS as readonly string[]).includes(test)) throw new Error(`Prueba desconocida «${test}». Válidas: ${RESET_TESTS.join(", ")}`);

      // A quién puede apuntar: sólo direcciones de prueba propias de esta sesión.
      const victimRow = own(String(params.victim ?? ""));
      if (!victimRow) throw new Error("victim tiene que ser una dirección creada con mail_address en esta sesión: la sonda sólo pide resets para correos propios del operador.");
      const attackerRow = params.attacker ? own(String(params.attacker)) : undefined;
      if (params.attacker && !attackerRow) throw new Error("attacker tiene que ser otra dirección creada con mail_address en esta sesión: nunca una ajena.");
      if (tests.has("duplicado") && !attackerRow) throw new Error("La prueba de duplicado necesita attacker: otra dirección tuya creada con mail_address.");
      if (attackerRow && attackerRow.address.toLowerCase() === victimRow.address.toLowerCase()) throw new Error("victim y attacker tienen que ser dos direcciones distintas.");
      const boxes = (context.boxes ?? mailboxes)();
      const victimBox = boxes.find((box) => box.direccion === victimRow.mailbox);
      const attackerBox = attackerRow ? boxes.find((box) => box.direccion === attackerRow.mailbox) : undefined;
      if (!victimBox || (attackerRow && !attackerBox)) throw new Error("La casilla de esas direcciones ya no está vinculada: el operador la vincula con /correo.");
      // Ningún otro correo puede viajar en el pedido: ni en la URL, ni en campos extra, ni en cabeceras.
      const complete = params.complete as undefined | { url: string; method?: string; tokenField: string; passwordField: string; confirmField?: string; password?: string; encoding?: string; extraFields?: Record<string, string> };
      const loose = [String(params.url), ...Object.values(params.extraFields ?? {}), ...Object.values(params.headers ?? {}), ...(complete ? [complete.url, ...Object.values(complete.extraFields ?? {})] : [])].map((value) => {
        let text = String(value);
        try { text = decodeURIComponent(text.replace(/\+/g, " ")); } catch {}
        return text;
      });
      for (const value of loose) for (const match of value.matchAll(EMAIL)) {
        if (!own(match[0])) throw new Error(`El pedido nombra ${match[0]}, que no es una dirección de prueba de esta sesión: la sonda no manda resets a correos ajenos.`);
      }
      new URL(String(params.url));
      if (complete && isDestructive(complete.method ?? "POST", complete.url)) throw new Error(`complete.url (${complete.url}) parece una ruta que borra o vacía datos para la guarda de borrado (dice «reset» sin «password» ni «forgot»): no se usa. Si es el formulario de nueva contraseña, probalo a mano con http_request.`);

      const victim = victimRow.address;
      const tag = randomBytes(3).toString("hex");
      const before = http.count;
      const used = () => http.count - before;
      const counter = () => `peticiones HTTP: ${http.count} · esta llamada: ${used()}/${maxRequests}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`;
      let limited = false;
      const canSend = () => !signal.aborted && !limited && used() < maxRequests && http.remaining() !== 0;
      const rows: string[] = [];
      const signals: Array<{ prueba: string; variante: string; senal: string; ids: string[] }> = [];
      const exchanges: string[] = [];
      const evidence: Record<string, unknown> = { victim, attacker: attackerRow?.address, url: params.url, tag };
      const mailLog: Array<Record<string, unknown>> = [];

      const encode = (value: Record<string, unknown>, as: "json" | "form", extraFields: Record<string, string> = params.extraFields ?? {}) => as === "json"
        ? { body: JSON.stringify({ ...extraFields, ...value }), type: "application/json" }
        : { body: new URLSearchParams(Object.entries({ ...extraFields, ...value }).map(([key, item]) => [key, String(item)])).toString(), type: "application/x-www-form-urlencoded" };
      const send = async (body: string, type: string, extraHeaders: Record<string, string> = {}): Promise<HttpExchange | undefined> => {
        if (!canSend()) return undefined;
        if (exchanges.length && delayMs) await sleep(delayMs);
        if (signal.aborted) return undefined;
        try {
          const exchange = await http.send({ url: String(params.url), method, headers: { ...params.headers, "content-type": type, ...extraHeaders }, body, systematic: true, timeoutMs: 20_000 }, params.identity);
          exchanges.push(exchange.id);
          if (exchange.response?.status === 429) limited = true;
          return exchange;
        } catch (error) {
          rows.push(`  no se envió: ${(error as Error).message}`);
          return undefined;
        }
      };

      // Mails: sólo los dirigidos a las direcciones propias; cada uno se cuenta una vez.
      const seen = new Set<string>();
      const fetchNew = async (box: Mailbox, address: string, since: number) => {
        const mails = await fetchFor(box, address, since, context.connector);
        return mails.filter((mail) => !seen.has(fingerprint(mail)));
      };
      const take = (mail: Mail, why: string) => {
        seen.add(fingerprint(mail));
        const info = resetToken(mail);
        mailLog.push({ por: why, de: mail.from.slice(0, 120), para: mail.to.slice(0, 300), asunto: mail.subject.slice(0, 200), fecha: new Date(mail.date).toISOString(), enlaces: digest(mail).links, codigos: digest(mail).codes, token: info.token, vence: declaredExpiry(mail) });
        return info;
      };
      /** Espera hasta que llegue lo esperado o venza el plazo; después una última mirada corta por si llegan juntos. */
      const collect = async (since: number, expectVictim: number, attackerAddress?: string) => {
        const deadline = Date.now() + waitMs;
        let victimMails: Mail[] = [];
        let attackerMails: Mail[] = [];
        for (;;) {
          victimMails = await fetchNew(victimBox, victim, since);
          if (attackerAddress && attackerBox) attackerMails = await fetchNew(attackerBox, attackerAddress, since);
          if (victimMails.length >= expectVictim || Date.now() >= deadline || signal.aborted) break;
          await sleep(Math.min(5000, Math.max(250, deadline - Date.now())));
        }
        // El mail al atacante puede llegar un poco después que el de la víctima: una última mirada.
        if (attackerAddress && attackerBox && waitMs && !signal.aborted) {
          await sleep(Math.min(3000, waitMs));
          attackerMails = await fetchNew(attackerBox, attackerAddress, since);
        }
        return { victimMails: victimMails.sort((a, b) => a.date - b.date), attackerMails };
      };

      const scan = async () => {
        try {
          const start = Date.now() - 1000;
          // Lo que ya estaba en la casilla de antes no cuenta.
          for (const mail of await fetchFor(victimBox, victim, start - 120_000, context.connector)) seen.add(fingerprint(mail));

          // ---------- Control: un pedido normal tiene que mandar el mail a la víctima ----------
          const controlStart = Date.now() - 1000;
          const control = await send(encode({ [field]: victim }, encoding).body, encode({}, encoding).type);
          if (!control) { rows.push("Control: no se pudo enviar."); return; }
          rows.push(`Control  ${control.id}  ${control.response?.status ?? `ERROR ${control.error}`}`);
          if (!accepted(control)) { rows.push("El pedido normal no fue aceptado: revisá url, field y encoding antes de seguir."); return; }
          const first = await collect(controlStart, 1);
          if (!first.victimMails.length) { rows.push(`No llegó el mail de control a ${victim} en ${waitMs / 1000} s: sin eso no se puede concluir nada. ¿La cuenta está registrada con esa dirección? Probá de nuevo con más waitSec.`); return; }
          const baseline = take(first.victimMails[0]!, "control");
          for (const mail of first.victimMails.slice(1)) take(mail, "control (extra)");
          rows.push(`  mail a la víctima: «${first.victimMails[0]!.subject.slice(0, 80)}» · enlace: ${baseline.link ?? "ninguno"}${baseline.token ? ` · token ${baseline.token.slice(0, 6)}… (${baseline.token.length})` : baseline.code ? ` · código ${baseline.code}` : ""}`);
          const victimTokens = [baseline.token ?? baseline.code ?? ""];

          // ---------- Duplicado o en lista ----------
          if (tests.has("duplicado") && attackerRow && canSend()) {
            rows.push("", `Duplicado o en lista (atacante: un alias de ${attackerRow.address} por variante, en la misma casilla, para saber qué pedido mandó cada mail):`);
            const variants: Array<{ id: string; build: (attacker: string) => { body: string; type: string } }> = [
              { id: "form-duplicado", build: (attacker) => ({ body: new URLSearchParams([...Object.entries(params.extraFields ?? {}).map(([key, value]) => [key, String(value)] as [string, string]), [field, victim], [field, attacker]]).toString(), type: "application/x-www-form-urlencoded" }) },
              { id: "json-lista", build: (attacker) => encode({ [field]: [victim, attacker] }, "json") },
              { id: "separador-coma", build: (attacker) => encode({ [field]: `${victim},${attacker}` }, encoding) },
              { id: "separador-espacio", build: (attacker) => encode({ [field]: `${victim} ${attacker}` }, encoding) },
              { id: "separador-salto", build: (attacker) => encode({ [field]: `${victim}\n${attacker}` }, encoding) },
            ];
            const stageStart = Date.now() - 1000;
            const sent: Array<{ id: string; alias: string; exchange: HttpExchange }> = [];
            for (const variant of variants) {
              const alias = aliasFor(attackerRow.address, `${variant.id.slice(0, 10)}`);
              db.prepare("insert or ignore into mail_addresses(address,label,mailbox,created_at,session_id) values(?,?,?,?,?)").run(alias, `reset-${variant.id}`.slice(0, 24), attackerRow.mailbox, Date.now(), context.sessionId);
              const request = variant.build(alias);
              const exchange = await send(request.body, request.type);
              if (!exchange) { rows.push(`  ${variant.id.padEnd(18)} no se envió (tope, límite del objetivo o cancelación)`); continue; }
              sent.push({ id: variant.id, alias, exchange });
            }
            const acceptedCount = sent.filter((item) => accepted(item.exchange)).length;
            // Los alias comparten el comienzo del atacante: una sola búsqueda los trae a todos.
            const common = attackerRow.address.split("@")[0]!;
            const got = acceptedCount ? await collect(stageStart, acceptedCount, common) : { victimMails: [], attackerMails: [] };
            for (const mail of got.victimMails) victimTokens.push(take(mail, "duplicado (víctima)").token ?? "");
            const stageVictimTokens = new Set(got.victimMails.map((mail) => resetToken(mail).token).filter(Boolean));
            for (const item of sent) {
              const status = item.exchange.response?.status ?? `ERROR ${item.exchange.error}`;
              const mine = got.attackerMails.filter((mail) => mail.to.toLowerCase().includes(item.alias.toLowerCase()));
              if (!mine.length) { rows.push(`  ${item.exchange.id}  ${item.id.padEnd(18)} ${status}  ${accepted(item.exchange) ? "al atacante no le llegó nada" : "rechazado"}`); continue; }
              const info = take(mine[0]!, `duplicado (${item.id}, atacante)`);
              const both = mine[0]!.to.toLowerCase().includes(victim.toLowerCase());
              const sameToken = !!info.token && stageVictimTokens.has(info.token);
              const text = `al atacante le llegó un mail de recuperación pedido para la víctima${both ? " (el mismo mail, dirigido a las dos)" : sameToken ? " con el MISMO token que el de la víctima" : ""}: «${mine[0]!.subject.slice(0, 60)}»`;
              signals.push({ prueba: "duplicado", variante: item.id, senal: text, ids: [item.exchange.id] });
              rows.push(`  ${item.exchange.id}  ${item.id.padEnd(18)} ${status}  ← SEÑAL: ${text}`);
            }
          }

          // ---------- Envenenamiento del enlace ----------
          if (tests.has("envenenamiento") && canSend()) {
            rows.push("", "Envenenamiento del enlace (host marcador propio, *.orobas.invalid: no resuelve, nadie lo visita):");
            const stageStart = Date.now() - 1000;
            const sent: Array<{ id: string; marker: string; exchange: HttpExchange }> = [];
            for (const variant of HEADER_VARIANTS) {
              const marker = `${variant.code}-${tag}.orobas.invalid`;
              const request = encode({ [field]: victim }, encoding);
              const exchange = await send(request.body, request.type, variant.headers(marker));
              if (!exchange) { rows.push(`  ${variant.id.padEnd(18)} no se envió`); continue; }
              sent.push({ id: variant.id, marker, exchange });
            }
            const acceptedCount = sent.filter((item) => accepted(item.exchange)).length;
            const got = acceptedCount ? await collect(stageStart, acceptedCount) : { victimMails: [], attackerMails: [] };
            const infos = got.victimMails.map((mail) => ({ mail, info: take(mail, "envenenamiento") }));
            for (const { info } of infos) victimTokens.push(info.token ?? "");
            for (const item of sent) {
              const status = item.exchange.response?.status ?? `ERROR ${item.exchange.error}`;
              const poisoned = infos.find(({ mail }) => `${mail.html}\n${mail.text}`.toLowerCase().includes(item.marker));
              if (!poisoned) { rows.push(`  ${item.exchange.id}  ${item.id.padEnd(18)} ${status}  ${accepted(item.exchange) ? "el mail no usa el host inyectado" : "rechazado"}`); continue; }
              const link = digest(poisoned.mail).links.find((url) => url.toLowerCase().includes(item.marker)) ?? `${poisoned.mail.html}\n${poisoned.mail.text}`.match(new RegExp(`\\S*${item.marker.replace(/\./g, "\\.")}\\S*`, "i"))?.[0];
              const text = `el enlace del mail apunta al host inyectado por ${item.id}: ${link?.slice(0, 200) ?? item.marker}`;
              signals.push({ prueba: "envenenamiento", variante: item.id, senal: text, ids: [item.exchange.id] });
              rows.push(`  ${item.exchange.id}  ${item.id.padEnd(18)} ${status}  ← SEÑAL: ${text}`);
            }
            if (got.victimMails.length < acceptedCount) rows.push(`  Llegaron ${got.victimMails.length} de ${acceptedCount} mails esperados en la ventana: un mail tardío no se miró.`);
          }

          // ---------- Token ----------
          if (tests.has("token") && canSend()) {
            rows.push("", "Token:");
            // Lo que llegó tarde de las tandas anteriores no es de esta: se aparta antes de pedir.
            for (const mail of await fetchNew(victimBox, victim, start)) take(mail, "tardío");
            const plain = (mail: Mail) => !`${mail.html}\n${mail.text}`.includes(".orobas.invalid");
            const request = encode({ [field]: victim }, encoding);
            const firstStart = Date.now() - 1000;
            const r1 = await send(request.body, request.type);
            const a = r1 && accepted(r1) ? (await collect(firstStart, 1)).victimMails.find(plain) : undefined;
            const tokenA = a ? take(a, "token (primero)") : undefined;
            const secondStart = Date.now() - 1000;
            const r2 = a ? await send(request.body, request.type) : undefined;
            const b = r2 && accepted(r2) ? (await collect(secondStart, 1)).victimMails.find(plain) : undefined;
            const tokenB = b ? take(b, "token (segundo)") : undefined;
            if (tokenA) victimTokens.push(tokenA.token ?? tokenA.code ?? "");
            if (tokenB) victimTokens.push(tokenB.token ?? tokenB.code ?? "");
            if (!tokenA?.link || !tokenB?.link) rows.push(`  No llegaron dos mails con enlace (${r1?.id ?? "-"}, ${r2?.id ?? "-"}): la vigencia no se pudo comparar.`);
            else {
              const expiry = declaredExpiry(b!) ?? declaredExpiry(a!);
              rows.push(`  ${r1!.id} → token A ${tokenA.token?.slice(0, 6) ?? "?"}…, ${r2!.id} → token B ${tokenB.token?.slice(0, 6) ?? "?"}…${expiry ? ` · el mail dice: «${expiry}»` : " · el mail no declara vencimiento"}`);
              // ¿Sigue valiendo A después de pedir B? Se compara contra B (válido) y contra un token inventado (inválido).
              const bogus = tokenB.token ? tokenB.link.replace(tokenB.token, randomBytes(Math.ceil(tokenB.token.length / 2)).toString("hex").slice(0, tokenB.token.length)) : undefined;
              const open = async (link: string) => {
                if (!canSend()) return undefined;
                try {
                  const exchange = await http.send({ url: link, method: "GET", timeoutMs: 20_000, systematic: true }, params.identity);
                  exchanges.push(exchange.id);
                  return exchange;
                } catch (error) { rows.push(`  no se abrió ${link.slice(0, 80)}: ${(error as Error).message}`); return undefined; }
              };
              const [linkA, linkB, linkBogus] = [await open(tokenA.link), await open(tokenB.link), bogus ? await open(bogus) : undefined];
              const looks = (x?: HttpExchange, y?: HttpExchange) => !!x?.response && !!y?.response && x.response.status === y.response.status && Math.abs(x.response.bodyBytes - y.response.bodyBytes) <= Math.max(40, y.response.bodyBytes * 0.05);
              if (!linkA?.response || !linkB?.response) rows.push(`  No se pudo abrir el enlace (¿fuera del alcance?): ${linkA?.error ?? linkB?.error ?? "sin respuesta"}`);
              else if (linkBogus?.response && looks(linkBogus, linkB)) rows.push(`  ${linkA.id}/${linkB.id}/${linkBogus.id}: la página responde igual a un token inventado; la vigencia se ve recién al usarlo (pasá complete).`);
              else if (looks(linkA, linkB) && !looks(linkA, linkBogus)) {
                const text = "el token anterior sigue valiendo después de pedir uno nuevo";
                signals.push({ prueba: "token", variante: "vigencia", senal: text, ids: [linkA.id, linkB.id, ...(linkBogus ? [linkBogus.id] : [])] });
                rows.push(`  ${linkA.id} (A) responde como ${linkB.id} (B)${linkBogus ? ` y distinto de ${linkBogus.id} (inventado)` : ""}  ← SEÑAL: ${text}`);
              } else rows.push(`  ${linkA.id} (A) responde distinto de ${linkB.id} (B): el anterior parece invalidado.`);
              // Reúso: usar B, usarlo otra vez, y probar A después de usar B. Cambia la contraseña de la cuenta propia.
              if (complete && tokenB.token) {
                const password = complete.password ?? `Orobas-${randomBytes(6).toString("hex")}!9`;
                const use = async (token: string) => {
                  if (!canSend()) return undefined;
                  const fields: Record<string, string> = { [complete.tokenField]: token, [complete.passwordField]: password, ...(complete.confirmField ? { [complete.confirmField]: password } : {}) };
                  const body = encode(fields, complete.encoding === "form" ? "form" : "json", complete.extraFields ?? {});
                  try {
                    const exchange = await http.send({ url: complete.url, method: (complete.method ?? "POST").toUpperCase(), headers: { "content-type": body.type }, body: body.body, systematic: true, timeoutMs: 20_000 }, params.identity);
                    exchanges.push(exchange.id);
                    return exchange;
                  } catch (error) { rows.push(`  no se usó el token: ${(error as Error).message}`); return undefined; }
                };
                const ok = (exchange?: HttpExchange) => !!exchange?.response && exchange.response.status < 300 && !rejectedWords.test(exchange.response.body.slice(0, 2000));
                const used1 = await use(tokenB.token);
                if (!ok(used1)) rows.push(`  ${used1?.id ?? "-"}: usar el token B no funcionó (${used1?.response?.status ?? used1?.error ?? "sin enviar"}); revisá complete.`);
                else {
                  recordResidue(db, context.sessionId, { tool: "reset_probe", kind: "cuenta", target: victim, detail: `contraseña de la cuenta de prueba cambiada con el token (${used1!.id})` });
                  rows.push(`  ${used1!.id}: token B usado; la contraseña de ${victim} ahora es ${password}`);
                  const used2 = await use(tokenB.token);
                  if (ok(used2)) { const text = "el token se puede usar más de una vez"; signals.push({ prueba: "token", variante: "reuso", senal: text, ids: [used1!.id, used2!.id] }); rows.push(`  ${used2!.id}: B otra vez → ${used2!.response!.status}  ← SEÑAL: ${text}`); }
                  else if (used2) rows.push(`  ${used2.id}: B otra vez → ${used2.response?.status ?? used2.error}: rechazado (bien)`);
                  if (tokenA.token && tokenA.token !== tokenB.token) {
                    const usedA = await use(tokenA.token);
                    if (ok(usedA)) { const text = "el token anterior sirve aun después de usar el nuevo"; signals.push({ prueba: "token", variante: "anterior", senal: text, ids: [usedA!.id] }); rows.push(`  ${usedA!.id}: A después de usar B → ${usedA!.response!.status}  ← SEÑAL: ${text}`); }
                    else if (usedA) rows.push(`  ${usedA.id}: A después de usar B → ${usedA.response?.status ?? usedA.error}: rechazado (bien)`);
                  }
                }
              } else if (!complete) rows.push("  Reúso sin probar: pasá complete (url, tokenField, passwordField) para usar el token sobre tu cuenta.");
            }
          }

          // Observación sobre los tokens recibidos: nada se adivina.
          const analysis = analyzeTokens(victimTokens.filter(Boolean), victim);
          if (analysis.lines.length) {
            rows.push("", `Tokens recibidos (${analysis.lines.length}):`, ...analysis.lines.slice(0, 6).map((line) => `  ${line}`));
            for (const weak of analysis.weak) {
              signals.push({ prueba: "token", variante: "predecible", senal: weak, ids: [] });
              rows.push(`  ← SEÑAL: ${weak}`);
            }
            evidence.tokens = analysis;
          }
        } catch (error) {
          rows.push(`No se pudo leer la casilla: ${(error as Error).message}`);
        }
      };
      await scan();
      if (limited) rows.push("El objetivo respondió 429: limita los pedidos de reset. Se cortó; no insistas.");
      evidence.mails = mailLog;
      evidence.senales = signals;
      evidence.intercambios = exchanges;
      const artifact = artifacts.put(JSON.stringify(evidence, null, 1), "application/json", "reset_probe");
      rows.push("", signals.length ? `Señales: ${signals.length}. Son observaciones: confirmalas (abrí el mail con mail_wait, repetí el pedido) y registrá candidato con los ids y el artefacto ${artifact.hash}.` : `Sin señales. Mails y enlaces en el artefacto ${artifact.hash}.`, counter());
      return { text: rows.join("\n"), details: { peticiones: used(), senales: signals, intercambios: exchanges, mails: mailLog.length, artefacto: artifact.hash } };
    },
  };
}
