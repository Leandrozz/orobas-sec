// Sonda de subida de archivos: sube variantes chicas con nombre y contenido marcados y mira dónde
// quedan, con qué Content-Type y Content-Disposition se sirven, si el nombre se respetó y si el
// contenido se interpreta. Nada ejecutable de verdad: los archivos «peligrosos» son marcadores de
// texto (doble extensión, ../ en el nombre, HTML declarado imagen). Las variantes activas (SVG con un
// script que sólo pone un atributo, XML con entidad externa hacia /etc/hostname y el oyente del
// operador) piden perfil con upload vivo (pentest en adelante) o el consentimiento «subida-activa».
// Cada archivo aceptado queda en «Para limpiar» del informe y su nombre cuenta como recurso propio
// para la guarda de borrado (se puede borrar con allowDestructive).
import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import type { Tool } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { createdIdentifiers, type HttpClient, type HttpExchange } from "./http.ts";
import { startProbeListener, type ListenerConfig, type ProbeListener } from "./listener.ts";
import { xxeDoctype, xxeExpansion, xxeReference } from "./payloads.ts";
import type { ProfileGrants } from "./perfil.ts";
import { recordResidue } from "./residuos.ts";

export interface UploadProbeContext {
  http: HttpClient;
  artifacts: Artifacts;
  db: DatabaseSync;
  sessionId: string;
  grants: () => ProfileGrants;
  /** Oyente que declaró el operador (CYBER_LISTENER_HOST): para la XXE fuera de banda. */
  listener?: ListenerConfig;
}

// ---------- ZIP mínimo (sin compresión) para DOCX y XLSX, sin dependencias ----------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Buffer): number {
  let c = 0xffffffff;
  for (const byte of data) c = CRC_TABLE[(c ^ byte) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** ZIP con las entradas guardadas tal cual (método 0): alcanza para un DOCX o XLSX que un parser abra. */
export function zipStored(files: Array<{ name: string; content: string | Buffer }>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name, "utf8");
    const data = Buffer.isBuffer(file.content) ? file.content : Buffer.from(file.content, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0x21, 12); // 1980-01-01
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x21, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    centrals.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/** Lee las entradas de un ZIP guardado sin compresión (el que arma zipStored). Para las pruebas y para revisar lo subido. */
export function unzipStored(zip: Buffer): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  let at = 0;
  while (at + 30 <= zip.length && zip.readUInt32LE(at) === 0x04034b50) {
    const size = zip.readUInt32LE(at + 18);
    const nameLength = zip.readUInt16LE(at + 26);
    const extra = zip.readUInt16LE(at + 28);
    const name = zip.subarray(at + 30, at + 30 + nameLength).toString("utf8");
    const start = at + 30 + nameLength + extra;
    out.set(name, zip.subarray(start, start + size));
    at = start + size;
  }
  return out;
}

const XML = '<?xml version="1.0" encoding="UTF-8"?>';
const OOXML_RELS = "http://schemas.openxmlformats.org/package/2006/relationships";
const OOXML_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/** DOCX mínimo con la entidad externa en word/document.xml. */
export function docxWithXxe(marker: string, listenerUrl?: string): Buffer {
  return zipStored([
    { name: "[Content_Types].xml", content: `${XML}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>` },
    { name: "_rels/.rels", content: `${XML}<Relationships xmlns="${OOXML_RELS}"><Relationship Id="rId1" Type="${OOXML_DOC}/officeDocument" Target="word/document.xml"/></Relationships>` },
    { name: "word/document.xml", content: `${XML}\n${xxeDoctype("w:document", listenerUrl)}\n<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${xxeReference(marker)}</w:t></w:r></w:p></w:body></w:document>` },
  ]);
}

/** XLSX mínimo con la entidad externa en xl/sharedStrings.xml (la celda A1 la usa). */
export function xlsxWithXxe(marker: string, listenerUrl?: string): Buffer {
  const main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
  const type = (kind: string) => `application/vnd.openxmlformats-officedocument.spreadsheetml.${kind}+xml`;
  return zipStored([
    { name: "[Content_Types].xml", content: `${XML}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="${type("sheet.main")}"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="${type("worksheet")}"/><Override PartName="/xl/sharedStrings.xml" ContentType="${type("sharedStrings")}"/></Types>` },
    { name: "_rels/.rels", content: `${XML}<Relationships xmlns="${OOXML_RELS}"><Relationship Id="rId1" Type="${OOXML_DOC}/officeDocument" Target="xl/workbook.xml"/></Relationships>` },
    { name: "xl/workbook.xml", content: `${XML}<workbook xmlns="${main}" xmlns:r="${OOXML_DOC}"><sheets><sheet name="orobas" sheetId="1" r:id="rId1"/></sheets></workbook>` },
    { name: "xl/_rels/workbook.xml.rels", content: `${XML}<Relationships xmlns="${OOXML_RELS}"><Relationship Id="rId1" Type="${OOXML_DOC}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="${OOXML_DOC}/sharedStrings" Target="sharedStrings.xml"/></Relationships>` },
    { name: "xl/worksheets/sheet1.xml", content: `${XML}<worksheet xmlns="${main}"><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>` },
    { name: "xl/sharedStrings.xml", content: `${XML}\n${xxeDoctype("sst", listenerUrl)}\n<sst xmlns="${main}" count="1" uniqueCount="1"><si><t>${xxeReference(marker)}</t></si></sst>` },
  ]);
}

// ---------- Variantes ----------

type Kind = "control" | "doble-ext" | "traversal" | "mime" | "svg-script" | "xxe";
interface Variant {
  id: string;
  kind: Kind;
  /** Contenido activo (script o entidades externas): pide perfil con upload vivo o consentimiento subida-activa. */
  active: boolean;
  /** Código corto que distingue el archivo y su marcador. */
  code: string;
  extension: string;
  contentType: string;
  label: string;
  build: (marker: string, listenerUrl?: string) => Buffer;
}

const textMarker = (marker: string, note: string) => Buffer.from(`orobas-upload ${marker}\n${note}\n`, "utf8");

export const UPLOAD_VARIANTS: Variant[] = [
  { id: "control", kind: "control", active: false, code: "c", extension: ".txt", contentType: "text/plain", label: "texto plano (control)", build: (marker) => textMarker(marker, "archivo de control de la sonda") },
  { id: "doble-ext-php-jpg", kind: "doble-ext", active: false, code: "d1", extension: ".php.jpg", contentType: "image/jpeg", label: "doble extensión .php.jpg (texto, sin código)", build: (marker) => textMarker(marker, "marcador de texto: no es una imagen ni contiene código") },
  { id: "doble-ext-jpg-php", kind: "doble-ext", active: false, code: "d2", extension: ".jpg.php", contentType: "image/jpeg", label: "doble extensión .jpg.php (texto, sin código)", build: (marker) => textMarker(marker, "marcador de texto: no es una imagen ni contiene código") },
  { id: "traversal", kind: "traversal", active: false, code: "t", extension: ".txt", contentType: "text/plain", label: "«../» en el nombre", build: (marker) => textMarker(marker, "si este archivo quedó fuera de la carpeta de subidas, el nombre no se saneó") },
  { id: "mime-html", kind: "mime", active: false, code: "m", extension: ".png", contentType: "image/png", label: "HTML sin script declarado como image/png", build: (marker) => Buffer.from(`<!doctype html><title>orobas</title><p id="orobas">${marker}</p>\n`, "utf8") },
  { id: "svg-script", kind: "svg-script", active: true, code: "s", extension: ".svg", contentType: "image/svg+xml", label: "SVG con script marcador (sólo pone un atributo)", build: (marker) => Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="240" height="24"><text x="0" y="16">${marker}</text><script>document.documentElement.setAttribute("data-orobas","${marker}")</script></svg>\n`, "utf8") },
  { id: "svg-xxe", kind: "xxe", active: true, code: "x", extension: ".svg", contentType: "image/svg+xml", label: "SVG con entidad externa", build: (marker, listenerUrl) => Buffer.from(`${XML}\n${xxeDoctype("svg", listenerUrl)}\n<svg xmlns="http://www.w3.org/2000/svg" width="400" height="24"><text x="0" y="16">${xxeReference(marker)}</text></svg>\n`, "utf8") },
  { id: "docx-xxe", kind: "xxe", active: true, code: "w", extension: ".docx", contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", label: "DOCX con entidad externa en document.xml", build: (marker, listenerUrl) => docxWithXxe(marker, listenerUrl) },
  { id: "xlsx-xxe", kind: "xxe", active: true, code: "e", extension: ".xlsx", contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", label: "XLSX con entidad externa en sharedStrings.xml", build: (marker, listenerUrl) => xlsxWithXxe(marker, listenerUrl) },
];

// ---------- Dónde quedó el archivo ----------

const LOCATION_KEY = /^(url|uri|href|link|path|location|src|file(_?(url|path|name))?|filename|download(_?url)?|public(_?url)?|key|name)$/i;

/** Lugares donde la respuesta de la subida dice que quedó el archivo: Location, campos JSON y rutas en el texto que nombran el archivo. */
export function locateUpload(exchange: HttpExchange, stem: string): string[] {
  const found: string[] = [];
  const response = exchange.response;
  if (!response) return found;
  const add = (value: string) => {
    const text = value.trim();
    if (text && !found.includes(text)) found.push(text);
  };
  if (response.headers.location) add(response.headers.location);
  const walk = (value: unknown, depth: number) => {
    if (depth > 4 || !value || typeof value !== "object") return;
    if (Array.isArray(value)) return void value.slice(0, 20).forEach((item) => walk(item, depth + 1));
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (typeof item === "string" && LOCATION_KEY.test(key) && (item.includes("/") || item.includes(stem)) && item.length < 2000) add(item);
      else walk(item, depth + 1);
    }
  };
  if (response.bodyEncoding !== "base64") {
    try { walk(JSON.parse(response.body), 0); } catch {
      const escaped = stem.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      for (const match of response.body.matchAll(new RegExp(`(?:https?://[^\\s"'<>]+?|/[^\\s"'<>]*?)${escaped}[^\\s"'<>]*`, "g"))) add(match[0]);
    }
  }
  // Las que nombran este archivo primero: un «url» genérico puede ser otra cosa.
  return found.sort((a, b) => Number(b.includes(stem)) - Number(a.includes(stem)));
}

interface Served {
  exchange: HttpExchange;
  url: string;
  status?: number;
  type: string;
  disposition: string;
  nosniff: boolean;
  csp: string;
  marker: boolean;
}

const servedView = (exchange: HttpExchange, marker: string): Served => {
  const headers = exchange.response?.headers ?? {};
  return {
    exchange,
    url: exchange.request.url,
    status: exchange.response?.status,
    type: (headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase(),
    disposition: headers["content-disposition"] ?? "",
    nosniff: /nosniff/i.test(headers["x-content-type-options"] ?? ""),
    csp: headers["content-security-policy"] ?? "",
    marker: !!exchange.response && exchange.response.status < 300 && exchange.response.body.includes(marker),
  };
};

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const bounded = (value: unknown, fallback: number, min: number, max: number, name: string) => {
  const result = value ?? fallback;
  if (typeof result !== "number" || !Number.isInteger(result) || result < min || result > max) throw new Error(`${name}: usá un entero entre ${min} y ${max}`);
  return result;
};

export function createUploadProbe(context: UploadProbeContext): Tool {
  const { http, artifacts } = context;
  return {
    name: "upload_probe",
    label: "Sonda de subida de archivos",
    description:
      "Sube variantes chicas a un endpoint de subida (multipart) y mira cómo se sirve cada archivo después: URL devuelta, Content-Type, Content-Disposition, si el nombre se respetó y si el contenido se interpreta. " +
      "Variantes inertes (siempre): control .txt, doble extensión (.php.jpg, .jpg.php) con texto, «../» en el nombre, HTML sin script declarado image/png. Activas (perfil pentest o superior, o /consent subida-activa): SVG con script marcador, SVG/DOCX/XLSX con entidad externa hacia /etc/hostname y, si el operador declaró un oyente, hacia el oyente. " +
      "Nada ejecutable de verdad: no hay código PHP ni webshells, sólo marcadores. Cada archivo aceptado queda en «Para limpiar» y se puede borrar con allowDestructive. Máximo 30 peticiones. Confirmá las señales (p. ej. abrir el SVG con el navegador) y registrá candidato con evidencia.",
    parameters: {
      type: "object",
      properties: {
        url: str({ description: "Endpoint que recibe la subida" }),
        method: str({ enum: ["POST", "PUT", "PATCH"] }),
        field: str({ description: "Nombre del campo de archivo; por defecto «file»" }),
        extraFields: { type: "object", additionalProperties: { type: "string" }, description: "Otros campos de texto del formulario (p. ej. un token CSRF)" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        identity: str(),
        variants: { type: "array", items: str({ enum: UPLOAD_VARIANTS.map((variant) => variant.id) }), maxItems: UPLOAD_VARIANTS.length, description: "Qué variantes subir; por defecto todas las permitidas" },
        servedAt: str({ description: "Plantilla de la URL donde se sirve lo subido si la respuesta no la dice, con {name} (nombre enviado) o {id} (id devuelto). P. ej. https://app/uploads/{name}" }),
        maxRequests: int({ minimum: 1, maximum: 30, default: 20 }),
        delayMs: int({ minimum: 0, maximum: 2000, default: 200 }),
        waitMs: int({ minimum: 0, maximum: 5000, default: 2000, description: "Espera final por visitas al oyente (XXE fuera de banda)" }),
        timeoutMs: int({ minimum: 500, maximum: 30000, default: 15000 }),
      },
      required: ["url"],
    },
    execute: async (params, signal) => {
      const maxRequests = bounded(params.maxRequests, 20, 1, 30, "maxRequests");
      const delayMs = bounded(params.delayMs, 200, 0, 2000, "delayMs");
      const waitMs = bounded(params.waitMs, 2000, 0, 5000, "waitMs");
      const timeoutMs = bounded(params.timeoutMs, 15000, 500, 30000, "timeoutMs");
      const method = String(params.method ?? "POST").toUpperCase();
      if (!["POST", "PUT", "PATCH"].includes(method)) throw new Error("La subida va con POST, PUT o PATCH");
      const target = new URL(String(params.url));
      const field = String(params.field ?? "file");
      const extra = Object.entries((params.extraFields ?? {}) as Record<string, unknown>).map(([name, value]) => ({ name, value: String(value) }));
      if (params.servedAt !== undefined && !/\{(name|id)\}/.test(String(params.servedAt))) throw new Error("servedAt necesita {name} o {id}");
      const wanted: string[] = params.variants?.length ? params.variants : UPLOAD_VARIANTS.map((variant) => variant.id);
      const unknown = wanted.filter((id) => !UPLOAD_VARIANTS.some((variant) => variant.id === id));
      if (unknown.length) throw new Error(`Variantes desconocidas: ${unknown.join(", ")}. Válidas: ${UPLOAD_VARIANTS.map((variant) => variant.id).join(", ")}`);
      // Contenido activo: el perfil (pentest en adelante) o el consentimiento del operador con cita.
      const live = context.grants().uploadLive || !!http.consent?.()?.has("subida-activa");
      const selected = UPLOAD_VARIANTS.filter((variant) => wanted.includes(variant.id));
      const blocked = selected.filter((variant) => variant.active && !live);
      const variants = selected.filter((variant) => !blocked.includes(variant));
      if (!variants.length) throw new Error(`Las variantes pedidas tienen contenido activo (${blocked.map((variant) => variant.id).join(", ")}) y este proyecto no lo habilita: hace falta perfil pentest o superior (/perfil) o que el operador dé /consent subida-activa si «cita de la política del programa». Las inertes no lo piden.`);

      const tag = randomBytes(4).toString("hex");
      const before = http.count;
      const used = () => http.count - before;
      const counter = () => `peticiones HTTP: ${http.count} · esta llamada: ${used()}/${maxRequests}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`;
      const canSend = () => !signal.aborted && used() < maxRequests && http.remaining() !== 0;
      const rows: string[] = [];
      const signals: Array<{ variante: string; senal: string; ids: string[] }> = [];
      const exchanges: string[] = [];
      const markers = new Map<string, string>();
      let uploads = 0;
      let listener: ProbeListener | undefined;
      try {
        if (context.listener && variants.some((variant) => variant.kind === "xxe") && !signal.aborted) listener = await startProbeListener(context.listener, artifacts);
        for (const [index, variant] of variants.entries()) {
          if (!canSend()) { rows.push(`${variant.id}: no se subió (tope de peticiones o cancelación).`); continue; }
          if (index && delayMs) await delay(delayMs, undefined, { signal }).catch(() => {});
          if (signal.aborted) break;
          const stem = `orobas-${tag}-${variant.code}`;
          const marker = stem;
          markers.set(variant.id, marker);
          const filename = `${variant.kind === "traversal" ? "../" : ""}${stem}${variant.extension}`;
          const content = variant.build(marker, listener ? `${listener.url}?v=${variant.id}` : undefined);
          const upload = await http.send({
            url: target.toString(), method, timeoutMs, systematic: true, headers: params.headers,
            multipart: [...extra, { name: field, filename, contentType: variant.contentType, base64: content.toString("base64") }],
          }, params.identity);
          exchanges.push(upload.id);
          const status = upload.response?.status;
          const accepted = status !== undefined && status < 400;
          const notes: string[] = [];
          const flag = (text: string) => { notes.push(`← ${text}`); signals.push({ variante: variant.id, senal: text, ids: [upload.id] }); };
          const ids = createdIdentifiers(method, upload.request.url, upload.response);
          if (!accepted) {
            rows.push(`${upload.id}  ${variant.id.padEnd(18)} ${filename}  ${status ?? `ERROR ${upload.error}`}  rechazado${upload.response ? `: ${upload.response.body.replace(/\s+/g, " ").slice(0, 100)}` : ""}`);
            continue;
          }
          uploads++;
          // Dónde quedó: lo que diga la respuesta, o la plantilla del operador.
          const locations = locateUpload(upload, stem).map((value) => { try { return new URL(value, target).toString(); } catch { return undefined; } }).filter((value): value is string => !!value);
          // Con «../» en el nombre, la plantilla resuelta sin sanear apunta a la carpeta de arriba: se mira primero ahí.
          let escaped: string | undefined;
          if (params.servedAt) {
            const fill = (name: string) => String(params.servedAt).replace(/\{name\}/g, name).replace(/\{id\}/g, encodeURIComponent(ids[0] ?? ""));
            if (!/\{id\}/.test(params.servedAt) || ids.length) {
              try { locations.push(new URL(fill(encodeURIComponent(`${stem}${variant.extension}`)), target).toString()); } catch {}
              if (variant.kind === "traversal" && /\{name\}/.test(params.servedAt)) try { escaped = new URL(fill(filename), target).toString(); } catch {}
            }
          }
          const unique = [...new Set([...(escaped ? [escaped] : []), ...locations])];
          const rawLocation = locateUpload(upload, stem).find((value) => value.includes(stem));
          if (variant.kind === "traversal" && rawLocation && /\.\.(\/|%2f|\\)/i.test(rawLocation)) flag("la respuesta devuelve el nombre con «../» sin sanear");
          const expandedAtUpload = variant.kind === "xxe" && upload.response ? xxeExpansion(upload.response.body, marker) : undefined;
          if (expandedAtUpload) flag(`XXE in-band: la respuesta de la subida trae /etc/hostname resuelto («${expandedAtUpload.slice(0, 60)}»)`);
          // Lo subido es residuo propio: va a «Para limpiar» y su nombre habilita borrarlo con allowDestructive.
          for (const value of [`${stem}${variant.extension}`, ...unique.map((value) => decodeURIComponent(new URL(value).pathname.split("/").filter(Boolean).at(-1) ?? ""))]) if (value.includes(stem)) http.created.add(value);
          // Probar dónde quedó: hasta dos lugares por variante, sólo dentro del alcance.
          const served: Served[] = [];
          const outside: string[] = [];
          for (const location of unique.slice(0, variant.kind === "traversal" ? 2 : 1)) {
            if (!http.inScope(location)) { outside.push(location); continue; }
            if (!canSend()) break;
            const fetched = await http.send({ url: location, method: "GET", timeoutMs, maxBodyBytes: 256 * 1024 }, params.identity);
            exchanges.push(fetched.id);
            served.push(servedView(fetched, marker));
          }
          const hit = served.find((item) => item.marker);
          recordResidue(context.db, context.sessionId, { tool: "upload_probe", kind: "archivo", target: hit?.url ?? unique[0] ?? `${method} ${target}`, detail: `${filename} (${variant.id}, subida ${upload.id})${ids.length ? ` · ids: ${ids.join(", ")}` : ""}` });
          if (hit) {
            const inline = !/attachment/i.test(hit.disposition);
            const sameOrigin = new URL(hit.url).origin === target.origin;
            const where = `${hit.exchange.id} ${hit.status} ${hit.type || "sin Content-Type"}${hit.disposition ? ` · ${hit.disposition.slice(0, 60)}` : " · inline"}${hit.nosniff ? " · nosniff" : ""}${sameOrigin ? "" : ` · otro origen (${new URL(hit.url).host})`}`;
            notes.unshift(`servido en ${hit.url} → ${where}`);
            const scriptable = /html|svg|xml/.test(hit.type) && inline && !/sandbox/i.test(hit.csp);
            if (variant.kind === "doble-ext" && /\.php$/i.test(decodeURIComponent(new URL(hit.url).pathname))) flag(`se guardó y se sirve con extensión .php (${hit.type || "sin tipo"}): si esa carpeta ejecuta PHP, un archivo con código correría (no se probó con código)`);
            if (variant.kind === "traversal" && escaped && hit.url === escaped && unique.length > 1) flag("el archivo quedó en la carpeta de arriba: «../» del nombre no se sanea");
            if (variant.kind === "mime" && (/html/.test(hit.type) || (!hit.type && !hit.nosniff)) && inline) flag(`HTML declarado imagen se sirve como ${hit.type || "tipo adivinable (sin Content-Type ni nosniff)"} inline${sameOrigin ? " en el mismo origen" : ""}: con script sería XSS almacenado`);
            if (variant.kind === "svg-script" && scriptable && hit.exchange.response!.body.includes("<script")) flag(`SVG con script servido inline como ${hit.type}${sameOrigin ? " en el mismo origen" : ""}: al abrirlo directo el script corre (confirmalo con el navegador: data-orobas en el documento)`);
            if (variant.kind === "xxe") {
              const expanded = xxeExpansion(hit.exchange.response!.body, marker);
              if (expanded) flag(`XXE in-band: lo servido trae /etc/hostname resuelto («${expanded.slice(0, 60)}»)`);
            }
          } else if (served.length) notes.unshift(`no se encontró el archivo en ${served.map((item) => `${item.url} (${item.exchange.id} ${item.status ?? "ERR"})`).join(", ")}`);
          else if (outside.length) notes.unshift(`se sirve fuera del alcance (${outside[0]}): no se pidió`);
          else notes.unshift("la respuesta no dice dónde quedó: pasá servedAt con {name} o {id} para que lo busque");
          rows.push(`${upload.id}  ${variant.id.padEnd(18)} ${filename}  ${status}  ${notes.join(" · ")}`);
        }
        if (listener) {
          await listener.wait(waitMs, signal);
          if (listener.hits.length) {
            for (const item of listener.hits) {
              let from = "";
              try { from = new URL(String(JSON.parse(artifacts.read(item.artifact).toString("utf8")).request?.url ?? ""), "http://x").searchParams.get("v") ?? ""; } catch {}
              const text = `XXE fuera de banda: el servidor pidió el oyente (${item.method} desde ${item.remoteAddress}, artefacto ${item.artifact})`;
              signals.push({ variante: from || "?", senal: text, ids: [item.artifact] });
              rows.push(`${from || "variante ?"}  ← ${text}`);
            }
          } else rows.push("Oyente: sin visitas en la ventana; no descarta un procesamiento diferido.");
        } else if (variants.some((variant) => variant.kind === "xxe")) rows.push("Sin oyente declarado: la XXE se probó sólo in-band (/etc/hostname). El operador lo declara con CYBER_LISTENER_HOST.");
      } finally {
        await listener?.close();
      }
      if (blocked.length) rows.push(`Omitidas por contenido activo (${blocked.map((variant) => variant.id).join(", ")}): hace falta perfil pentest o superior o /consent subida-activa.`);
      if (uploads) rows.push(`${uploads} archivo(s) aceptado(s): quedaron en «Para limpiar» del informe. Para borrarlos, DELETE sobre su URL con allowDestructive.`);
      rows.push(signals.length ? "Las señales son observaciones: confirmá con una petición propia (el SVG, con el navegador) y registrá candidato con evidencia." : "Sin señales en lo que se pudo observar.", counter());
      return { text: rows.join("\n"), details: { peticiones: used(), subidas: uploads, senales: signals, omitidas: blocked.map((variant) => variant.id), intercambios: exchanges, marcadores: Object.fromEntries(markers) } };
    },
  };
}
