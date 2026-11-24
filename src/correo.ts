// Correo de prueba. Para crear cuentas de prueba en un objetivo hace falta recibir el mail de
// verificación. El operador vincula una o más casillas propias por IMAP (con contraseña de
// aplicación, cifrada en su carpeta de credenciales) y el agente genera direcciones con «+etiqueta»
// —todas llegan a esa casilla— y pide el código o el enlace que llegó a UNA de esas direcciones.
// Nunca ve la bandeja: la herramienta sólo busca mensajes dirigidos a direcciones que ella generó.
import { randomBytes } from "node:crypto";
import { resolveMx } from "node:dns/promises";
import type { Socket } from "node:net";
import type { DatabaseSync } from "node:sqlite";
import { connect as tlsConnect } from "node:tls";
import type { Tool, ToolResult } from "./agent.ts";
import { deleteSecret, readSecret, writeSecret } from "./secretos.ts";

export interface Mailbox {
  /** Dirección de la casilla (y usuario de IMAP, salvo que se indique otro). */
  direccion: string;
  usuario?: string;
  clave: string;
  host: string;
  puerto: number;
  /** Dirección que reenvía a esta casilla y que conviene usar al registrarse (p. ej. usuario@wearehackerone.com). */
  alias?: string;
}

const HOSTS: Record<string, string> = {
  "gmail.com": "imap.gmail.com", "googlemail.com": "imap.gmail.com", "icloud.com": "imap.mail.me.com", "me.com": "imap.mail.me.com",
  "fastmail.com": "imap.fastmail.com", "yahoo.com": "imap.mail.yahoo.com", "outlook.com": "outlook.office365.com", "hotmail.com": "outlook.office365.com",
  "live.com": "outlook.office365.com", "zoho.com": "imap.zoho.com", "gmx.com": "imap.gmx.com",
};
/** Servidor IMAP habitual de un dominio; un dominio propio suele estar en Google Workspace. */
export const guessHost = (address: string) => HOSTS[address.split("@")[1]?.toLowerCase() ?? ""] ?? "imap.gmail.com";

/** Servidor IMAP según el MX del dominio: un dominio propio puede estar en Hostinger, Workspace, Microsoft 365… */
const MX_HOSTS: Array<[RegExp, string]> = [
  [/(^|\.)google(mail)?\.com$/, "imap.gmail.com"],
  [/(^|\.)hostinger\.com$/, "imap.hostinger.com"],
  [/(^|\.)(protection\.)?outlook\.com$/, "outlook.office365.com"],
  [/(^|\.)zoho\.com$/, "imap.zoho.com"],
  [/(^|\.)zoho\.eu$/, "imap.zoho.eu"],
  [/(^|\.)titan\.email$/, "imap.titan.email"],
  [/(^|\.)secureserver\.net$/, "imap.secureserver.net"],
  [/(^|\.)(ionos|kundenserver)\.[a-z.]+$/, "imap.ionos.com"],
  [/(^|\.)messagingengine\.com$/, "imap.fastmail.com"],
  [/(^|\.)icloud\.com$/, "imap.mail.me.com"],
];
export function hostFromMx(exchanges: string[]): string | undefined {
  for (const raw of exchanges) {
    const mx = raw.toLowerCase().replace(/\.$/, "");
    const hit = MX_HOSTS.find(([pattern]) => pattern.test(mx));
    if (hit) return hit[1];
  }
  return undefined;
}
/** Dominios conocidos por nombre; los propios, por su MX; si no se reconoce, Google (lo más común). */
export async function detectHost(address: string, resolve: (domain: string) => Promise<Array<{ exchange: string; priority: number }>> = resolveMx): Promise<string> {
  const domain = address.split("@")[1]?.toLowerCase() ?? "";
  if (HOSTS[domain]) return HOSTS[domain];
  try {
    const records = await resolve(domain);
    const found = hostFromMx([...records].sort((a, b) => a.priority - b.priority).map((record) => record.exchange));
    if (found) return found;
  } catch { /* sin DNS: se queda con la suposición */ }
  return guessHost(address);
}

export function mailboxes(): Mailbox[] {
  try {
    const saved = JSON.parse(readSecret("correo") ?? "{}") as { cuentas?: Mailbox[] };
    return Array.isArray(saved.cuentas) ? saved.cuentas.filter((item) => item?.direccion && item.clave && item.host) : [];
  } catch { return []; }
}
export function saveMailboxes(list: Mailbox[]): void {
  if (list.length) writeSecret("correo", JSON.stringify({ cuentas: list }));
  else deleteSecret("correo");
}

// ---------- IMAP mínimo: LOGIN, LIST, SELECT, UID SEARCH, UID FETCH. Sin dependencias. ----------

type Part = string | Buffer;
export type Connector = (box: Mailbox) => Socket;
const defaultConnector: Connector = (box) => tlsConnect({ host: box.host, port: box.puerto, servername: box.host });

class Imap {
  private buffer = Buffer.alloc(0);
  private waiters: Array<() => void> = [];
  private failure?: Error;
  private tag = 0;
  private readonly socket: Socket;
  constructor(socket: Socket) {
    this.socket = socket;
    socket.on("data", (chunk: Buffer) => { this.buffer = Buffer.concat([this.buffer, chunk]); this.wake(); });
    socket.on("error", (error: Error) => { this.failure = error; this.wake(); });
    socket.on("close", () => { this.failure ??= new Error("El servidor de correo cerró la conexión"); this.wake(); });
    socket.setTimeout(20_000, () => { this.failure = new Error("El servidor de correo no respondió a tiempo"); socket.destroy(); this.wake(); });
  }
  private wake() { for (const waiter of this.waiters.splice(0)) waiter(); }
  private async need(test: () => boolean): Promise<void> {
    while (!test()) {
      if (this.failure) throw this.failure;
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
  }
  /** Una respuesta completa: su texto y los literales {n} que traiga en el medio. */
  private async unit(): Promise<Part[]> {
    const parts: Part[] = [];
    for (;;) {
      await this.need(() => this.buffer.includes("\r\n"));
      const end = this.buffer.indexOf("\r\n");
      const line = this.buffer.subarray(0, end).toString("latin1");
      this.buffer = this.buffer.subarray(end + 2);
      parts.push(line);
      const literal = /\{(\d+)\}$/.exec(line);
      if (!literal) return parts;
      const size = Number(literal[1]);
      if (size > 8 * 1024 * 1024) throw new Error("Mensaje demasiado grande");
      await this.need(() => this.buffer.length >= size);
      parts.push(Buffer.from(this.buffer.subarray(0, size)));
      this.buffer = this.buffer.subarray(size);
    }
  }
  greeting() { return this.unit(); }
  async command(text: string): Promise<Part[][]> {
    const tag = `o${++this.tag}`;
    this.socket.write(`${tag} ${text}\r\n`);
    const units: Part[][] = [];
    for (;;) {
      const unit = await this.unit();
      const head = String(unit[0]);
      if (head.startsWith(`${tag} `)) {
        if (!/^\S+ OK/i.test(head)) throw new Error(head.slice(tag.length + 1).replace(/^(NO|BAD)\s*/i, "").slice(0, 200) || "El servidor de correo rechazó el pedido");
        return units;
      }
      units.push(unit);
    }
  }
  close() { try { this.socket.write(`o${++this.tag} LOGOUT\r\n`); } catch {} this.socket.destroy(); }
}

const quote = (value: string) => `"${value.replace(/[\\"]/g, "\\$&")}"`;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

async function open(box: Mailbox, connector: Connector): Promise<Imap> {
  const imap = new Imap(connector(box));
  try {
    await imap.greeting();
    // Google muestra la contraseña de aplicación con espacios; no forman parte de ella.
    const password = /gmail|google/.test(box.host) ? box.clave.replace(/\s+/g, "") : box.clave;
    await imap.command(`LOGIN ${quote(box.usuario || box.direccion)} ${quote(password)}`);
    return imap;
  } catch (error) {
    imap.close();
    const message = (error as Error).message;
    throw new Error(/AUTHENTICATIONFAILED|Invalid credentials|LOGIN failed|authentication/i.test(message)
      ? `La casilla ${box.direccion} rechazó el usuario o la contraseña. Tiene que ser una contraseña de aplicación (no la de la cuenta), con IMAP habilitado.`
      : `No pude entrar a la casilla ${box.direccion} (${box.host}): ${message}`);
  }
}

/** Comprueba que la casilla abre. Devuelve cuántos mensajes tiene la bandeja. */
export async function testMailbox(box: Mailbox, connector: Connector = defaultConnector): Promise<number> {
  const imap = await open(box, connector);
  try {
    const units = await imap.command("SELECT INBOX");
    return Number(units.map((unit) => /^\* (\d+) EXISTS/i.exec(String(unit[0]))?.[1]).find(Boolean) ?? 0);
  } finally { imap.close(); }
}

export interface Mail { from: string; to: string; subject: string; date: number; text: string; html: string; folder: string }

/** Mensajes dirigidos a una dirección, desde un momento dado. Mira la bandeja y la carpeta de spam. */
export async function fetchFor(box: Mailbox, address: string, sinceMs: number, connector: Connector = defaultConnector): Promise<Mail[]> {
  const imap = await open(box, connector);
  try {
    const folders = ["INBOX"];
    for (const unit of await imap.command('LIST "" "*"')) {
      const match = /^\* LIST \(([^)]*)\) (?:"[^"]*"|NIL) (?:"((?:[^"\\]|\\.)*)"|(\S+))/i.exec(String(unit[0]));
      if (match && /\\Junk/i.test(match[1]!)) folders.push((match[2] ?? match[3])!.replace(/\\(.)/g, "$1"));
    }
    const since = new Date(sinceMs - 24 * 3600_000);
    const day = `${since.getUTCDate()}-${MONTHS[since.getUTCMonth()]}-${since.getUTCFullYear()}`;
    const found: Mail[] = [];
    for (const folder of folders) {
      try { await imap.command(`SELECT ${quote(folder)}`); } catch { continue; }
      const search = await imap.command(`UID SEARCH SINCE ${day} TO ${quote(address)}`);
      const uids = search.flatMap((unit) => /^\* SEARCH(.*)$/i.exec(String(unit[0]))?.[1]?.trim().split(/\s+/).filter(Boolean) ?? []).slice(-10);
      if (!uids.length) continue;
      for (const unit of await imap.command(`UID FETCH ${uids.join(",")} (BODY.PEEK[]<0.300000>)`)) {
        const raw = unit.find((part): part is Buffer => Buffer.isBuffer(part));
        if (!raw) continue;
        const mail = { ...parseMail(raw), folder };
        // El filtro del servidor es por día y por texto: se vuelve a comprobar destinatario y hora.
        if (mail.to.toLowerCase().includes(address.toLowerCase()) && mail.date >= sinceMs - 120_000) found.push(mail);
      }
    }
    return found.sort((a, b) => b.date - a.date);
  } finally { imap.close(); }
}

// ---------- Lectura del mensaje ----------

function decodeBytes(bytes: Buffer, charset?: string): string {
  try { return new TextDecoder((charset || "utf-8").toLowerCase().replace(/^(us-)?ascii$/, "utf-8")).decode(bytes); } catch { return bytes.toString("latin1"); }
}
const fromQuoted = (text: string) => Buffer.from(text.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_all, hex: string) => String.fromCharCode(parseInt(hex, 16))), "latin1");
/** «=?utf-8?B?…?=» de los encabezados. */
const decodeWords = (value: string) => value.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=(\s+(?==\?))?/g, (_all, charset: string, kind: string, data: string) =>
  decodeBytes(kind.toLowerCase() === "b" ? Buffer.from(data, "base64") : fromQuoted(data.replace(/_/g, " ")), charset));

function splitHeaders(raw: Buffer): { headers: Map<string, string>; body: Buffer } {
  let cut = raw.indexOf("\r\n\r\n");
  let gap = 4;
  if (cut < 0) { cut = raw.indexOf("\n\n"); gap = 2; }
  const head = (cut < 0 ? raw : raw.subarray(0, cut)).toString("latin1").replace(/\r?\n[ \t]+/g, " ");
  const headers = new Map<string, string>();
  for (const line of head.split(/\r?\n/)) {
    const at = line.indexOf(":");
    if (at > 0) headers.set(line.slice(0, at).trim().toLowerCase(), `${headers.has(line.slice(0, at).trim().toLowerCase()) ? `${headers.get(line.slice(0, at).trim().toLowerCase())}, ` : ""}${line.slice(at + 1).trim()}`);
  }
  return { headers, body: cut < 0 ? Buffer.alloc(0) : raw.subarray(cut + gap) };
}

function collect(raw: Buffer, out: { text: string; html: string }, depth = 0): void {
  const { headers, body } = splitHeaders(raw);
  const type = headers.get("content-type") ?? "text/plain";
  const boundary = /boundary="?([^";]+)"?/i.exec(type)?.[1];
  if (/^multipart\//i.test(type) && boundary && depth < 6) {
    const text = body.toString("latin1");
    for (const piece of text.split(`--${boundary}`).slice(1)) {
      if (piece.startsWith("--")) break;
      collect(Buffer.from(piece.replace(/^\r?\n/, ""), "latin1"), out, depth + 1);
    }
    return;
  }
  if (!/^text\//i.test(type) || /attachment/i.test(headers.get("content-disposition") ?? "")) return;
  const encoding = (headers.get("content-transfer-encoding") ?? "").toLowerCase();
  const bytes = encoding === "base64" ? Buffer.from(body.toString("latin1").replace(/\s+/g, ""), "base64") : encoding === "quoted-printable" ? fromQuoted(body.toString("latin1")) : body;
  const content = decodeBytes(bytes, /charset="?([^";\s]+)"?/i.exec(type)?.[1]);
  if (/^text\/html/i.test(type)) out.html += content;
  else out.text += content;
}

export function parseMail(raw: Buffer): Omit<Mail, "folder"> {
  const { headers } = splitHeaders(raw);
  const out = { text: "", html: "" };
  collect(raw, out);
  const header = (name: string) => decodeWords(headers.get(name) ?? "");
  return { from: header("from"), to: [header("to"), header("delivered-to"), header("x-original-to")].filter(Boolean).join(", "), subject: header("subject"), date: Date.parse(headers.get("date") ?? "") || Date.now(), text: out.text, html: out.html };
}

const entities = (text: string) => text.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&nbsp;/g, " ");
const plain = (html: string) => entities(html.replace(/<(style|script)[\s\S]*?<\/\1>/gi, " ").replace(/<br\s*\/?>|<\/(p|div|tr|h\d|li)>/gi, "\n").replace(/<[^>]+>/g, " ")).replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();

/** Lo que sirve de un mail de verificación: códigos y enlaces, y un tramo corto del texto. */
export function digest(mail: Pick<Mail, "subject" | "text" | "html">): { codes: string[]; links: string[]; snippet: string } {
  const text = (mail.text.trim() || plain(mail.html)).replace(/\r/g, "");
  const links = new Set<string>();
  for (const match of mail.html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) links.add(entities(match[1]!));
  for (const match of text.matchAll(/https?:\/\/[^\s<>"')\]]+/g)) links.add(match[0].replace(/[.,;]+$/, ""));
  const useful = /verif|confirm|activ|valid|token|magic|sign-?up|register|registr|reset|invit|auth|callback|otp|code=|welcome|bienvenid/i;
  const ranked = [...links].filter((url) => /^https?:\/\//.test(url) && !/unsubscribe|preferences|\.(png|jpe?g|gif|css)(\?|$)/i.test(url)).sort((a, b) => Number(useful.test(b)) - Number(useful.test(a)));
  const codes = new Set<string>();
  const hint = /c[oó]digo|code|otp|pin\b|one[- ]time|verific|clave de un solo uso/i;
  for (const source of [mail.subject, text]) {
    for (const match of source.matchAll(/(?<![\w/.-])(\d{4,8}|[A-Z0-9]{3,5}-[A-Z0-9]{3,5})(?![\w/-])/g)) {
      const around = source.slice(Math.max(0, match.index - 90), match.index + match[0].length + 40);
      if (hint.test(around) && !/^(19|20)\d{2}$/.test(match[1]!)) codes.add(match[1]!);
    }
  }
  return { codes: [...codes].slice(0, 5), links: ranked.slice(0, 6).map((url) => url.slice(0, 600)), snippet: text.replace(/\s+/g, " ").slice(0, 400) };
}

// ---------- Direcciones de prueba y herramientas ----------

/** usuario+etiqueta@dominio: llega a la misma casilla y el objetivo la ve como una cuenta distinta. */
export function aliasFor(base: string, label: string): string {
  const [local, domain] = base.split("@") as [string, string];
  const tag = `${label.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 16) || "prueba"}-${randomBytes(3).toString("hex").slice(0, 5)}`;
  return `${local}${local.includes("+") ? "-" : "+"}${tag}@${domain}`;
}

interface MailContext { db: DatabaseSync; sessionId: string; connector?: Connector; boxes?: () => Mailbox[]; sleep?: (ms: number) => Promise<void> }

export function createMailTools(context: MailContext): Tool[] {
  const { db } = context;
  db.exec("create table if not exists mail_addresses(address text primary key, label text not null, mailbox text not null, created_at integer not null, session_id text)");
  const boxes = () => (context.boxes ?? mailboxes)();
  const none = "No hay ninguna casilla de correo vinculada. La vincula el operador una vez, con /correo (o «orobas-sec correo»): la dirección y una contraseña de aplicación. Pedíselo; la contraseña no pasa por el chat.";
  const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });

  const address: Tool = {
    name: "mail_address",
    label: "Direcciones de correo de prueba",
    description:
      "Genera direcciones de correo de prueba (una por cuenta que vayas a crear en el objetivo): todas llegan a la casilla del operador, y el objetivo las ve como personas distintas. " +
      "Usalas para registrar cuentas propias: dos cuentas del mismo rol permiten probar control de acceso sin tocar datos ajenos. Después leé el código o el enlace de verificación con mail_wait. Sin argumentos, lista las ya creadas.",
    parameters: obj({
      etiquetas: { type: "array", items: { type: "string", maxLength: 24 }, maxItems: 10, description: "Un nombre corto por cuenta: «comprador-a», «comprador-b», «admin»" },
      casilla: { type: "string", description: "Casilla a usar, si hay más de una vinculada" },
    }, []),
    execute: (params): ToolResult => {
      const list = boxes();
      if (!list.length) throw new Error(none);
      const created: string[] = [];
      for (const label of (params.etiquetas ?? []) as string[]) {
        const box = params.casilla ? list.find((item) => item.direccion === params.casilla) : list[0];
        if (!box) throw new Error(`No hay una casilla «${params.casilla}». Vinculadas: ${list.map((item) => item.direccion).join(", ")}`);
        const fresh = aliasFor(box.alias || box.direccion, label);
        db.prepare("insert into mail_addresses(address,label,mailbox,created_at,session_id) values(?,?,?,?,?)").run(fresh, label, box.direccion, Date.now(), context.sessionId);
        created.push(`${label}: ${fresh}`);
      }
      const all = db.prepare("select address, label, created_at from mail_addresses order by created_at desc limit 40").all() as Array<{ address: string; label: string; created_at: number }>;
      const lines = created.length ? ["Direcciones nuevas:", ...created.map((line) => `  ${line}`), "", "Registrá cada cuenta con su dirección y después pedí el mail con mail_wait."] : all.length ? ["Direcciones de prueba de este proyecto:", ...all.map((row) => `  ${row.label}: ${row.address}`)] : ["Todavía no hay direcciones de prueba. Pasá etiquetas para crear."];
      return { text: lines.join("\n"), details: { creadas: created.length, total: all.length + 0 } };
    },
  };

  const wait: Tool = {
    name: "mail_wait",
    label: "Esperar el mail de verificación",
    description:
      "Espera el mail que le llegó a una dirección creada con mail_address y devuelve remitente, asunto, códigos y enlaces de verificación (no el mensaje entero ni el resto de la bandeja). " +
      "Llamala después de enviar el formulario de registro. El enlace se abre con http_request o con el navegador si está dentro del alcance; si apunta a otro host, decíselo al operador.",
    parameters: obj({
      direccion: { type: "string", description: "Una dirección creada con mail_address" },
      esperaSeg: { type: "integer", minimum: 0, maximum: 180, description: "Cuánto esperar a que llegue; por defecto 60" },
      desdeMin: { type: "integer", minimum: 1, maximum: 1440, description: "Mirar mensajes de los últimos N minutos; por defecto, desde que se creó la dirección" },
    }, ["direccion"]),
    execute: async (params, signal): Promise<ToolResult> => {
      const row = db.prepare("select address, mailbox, created_at from mail_addresses where lower(address)=lower(?)").get(String(params.direccion).trim()) as { address: string; mailbox: string; created_at: number } | undefined;
      if (!row) throw new Error("Esa dirección no la creó mail_address en este proyecto: sólo se leen mensajes dirigidos a direcciones de prueba propias.");
      const box = boxes().find((item) => item.direccion === row.mailbox);
      if (!box) throw new Error(`La casilla ${row.mailbox} ya no está vinculada. ${none}`);
      const since = params.desdeMin ? Date.now() - params.desdeMin * 60_000 : row.created_at;
      const deadline = Date.now() + (params.esperaSeg ?? 60) * 1000;
      const sleep = context.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
      for (;;) {
        const mails = await fetchFor(box, row.address, since, context.connector);
        if (mails.length) {
          const lines = mails.slice(0, 3).flatMap((mail, index) => {
            const info = digest(mail);
            return [
              `${index ? "\n" : ""}De: ${mail.from.slice(0, 120)}`,
              `Asunto: ${mail.subject.slice(0, 200)}${mail.folder === "INBOX" ? "" : `  (estaba en ${mail.folder})`}`,
              `Códigos: ${info.codes.join(", ") || "ninguno a la vista"}`,
              ...(info.links.length ? ["Enlaces:", ...info.links.map((url) => `  ${url}`)] : ["Enlaces: ninguno"]),
              `Texto: ${info.snippet}`,
            ];
          });
          return { text: lines.join("\n"), details: { mensajes: mails.length } };
        }
        if (Date.now() >= deadline || signal?.aborted) return { text: `Todavía no llegó ningún mail a ${row.address}. Puede tardar, o el objetivo no lo envió: revisá la respuesta del registro y volvé a llamar con más espera.`, details: { mensajes: 0 } };
        await sleep(Math.min(8000, Math.max(1000, deadline - Date.now())));
      }
    },
  };
  return [address, wait];
}
