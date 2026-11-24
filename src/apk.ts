// Formatos de una app Android leídos sin herramientas externas: zip (con zip64 y descriptores de
// datos), XML binario de Android (AXML), la tabla de cadenas de un dex y la de resources.arsc. Todo
// con topes: un APK puede venir armado para romper analizadores (tamaños falsos, bombas de
// compresión, índices fuera de rango, cabeceras raras), y acá lo raro se saltea en vez de tirar abajo
// el análisis. Lo que no se puede leer queda afuera y el llamador lo cuenta.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, sep } from "node:path";
import { inflateRawSync } from "node:zlib";

export interface ZipEntry {
  name: string;
  /** 0 guardado, 8 deflate; otro método no se abre. */
  method: number;
  compressed: number;
  size: number;
  /** Posición de la cabecera local. */
  offset: number;
}

const EOCD = 0x06054b50;
const CEN = 0x02014b50;
const LOC = 0x04034b50;
const EOCD64 = 0x06064b50;
const LOC64 = 0x07064b50;

/** El fin del directorio central está en los últimos 22 bytes más el comentario (hasta 64 KB). */
function findEocd(buf: Buffer): number {
  const stop = Math.max(0, buf.length - 22 - 0xffff);
  for (let at = buf.length - 22; at >= stop; at--) if (buf.readUInt32LE(at) === EOCD) return at;
  return -1;
}

/** ¿Empieza como un zip? (cabecera local «PK\x03\x04»). */
export const looksLikeZip = (buf: Buffer) => buf.length >= 4 && buf.readUInt32LE(0) === LOC;

/**
 * Entradas del directorio central. Android lee los tamaños de ahí (no de la cabecera local, que con el
 * bit 3 viene en cero), ignora la marca de cifrado y tolera basura entre las entradas y el directorio
 * (el bloque de firma v2/v3 va justo ahí): lo mismo hace este lector.
 */
export function zipEntries(buf: Buffer, limit = 100_000): ZipEntry[] {
  const eocd = findEocd(buf);
  if (eocd < 0) throw new Error("no es un zip: no encuentro el directorio central");
  let count = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  if ((count === 0xffff || offset === 0xffffffff) && eocd >= 20 && buf.readUInt32LE(eocd - 20) === LOC64) {
    const at = Number(buf.readBigUInt64LE(eocd - 20 + 8));
    if (at >= 0 && at + 56 <= buf.length && buf.readUInt32LE(at) === EOCD64) {
      count = Number(buf.readBigUInt64LE(at + 32));
      offset = Number(buf.readBigUInt64LE(at + 48));
    }
  }
  const entries: ZipEntry[] = [];
  let p = offset;
  while (p >= 0 && p + 46 <= buf.length && entries.length < limit && buf.readUInt32LE(p) === CEN) {
    const method = buf.readUInt16LE(p + 10);
    let compressed = buf.readUInt32LE(p + 20);
    let size = buf.readUInt32LE(p + 24);
    const nameLength = buf.readUInt16LE(p + 28);
    const extraLength = buf.readUInt16LE(p + 30);
    const commentLength = buf.readUInt16LE(p + 32);
    let local = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, Math.min(buf.length, p + 46 + nameLength));
    // Campo extra zip64 (id 1): trae, en ese orden, sólo los valores que en la entrada valen 0xffffffff.
    const extraEnd = Math.min(buf.length, p + 46 + nameLength + extraLength);
    for (let e = p + 46 + nameLength; e + 4 <= extraEnd; ) {
      const id = buf.readUInt16LE(e);
      const length = buf.readUInt16LE(e + 2);
      if (id === 1) {
        let q = e + 4;
        const end = Math.min(extraEnd, q + length);
        const next = (value: number) => {
          if (value !== 0xffffffff || q + 8 > end) return value;
          const read = Number(buf.readBigUInt64LE(q));
          q += 8;
          return read;
        };
        size = next(size);
        compressed = next(compressed);
        local = next(local);
      }
      e += 4 + length;
    }
    entries.push({ name, method, compressed, size, offset: local });
    p += 46 + nameLength + extraLength + commentLength;
  }
  if (!entries.length && count) throw new Error("el directorio central del zip está dañado");
  return entries;
}

/**
 * Contenido de una entrada, descomprimido hasta `max` bytes. Si se pasa del tope (o los datos están
 * dañados, o el método no es guardado ni deflate) devuelve undefined: no se lee a medias.
 */
export function zipRead(buf: Buffer, entry: ZipEntry, max: number): Buffer | undefined {
  if (entry.offset < 0 || entry.offset + 30 > buf.length || buf.readUInt32LE(entry.offset) !== LOC) return undefined;
  const start = entry.offset + 30 + buf.readUInt16LE(entry.offset + 26) + buf.readUInt16LE(entry.offset + 28);
  if (start > buf.length) return undefined;
  const data = buf.subarray(start, Math.min(buf.length, start + entry.compressed));
  if (entry.method === 0) return data.length > max ? undefined : data;
  if (entry.method !== 8) return undefined;
  try {
    return inflateRawSync(data, { maxOutputLength: Math.max(1, max) });
  } catch {
    return undefined;
  }
}

/**
 * Abre un zip en una carpeta. Sólo para archivos ya verificados por sha256 (el instalador): una entrada
 * con ruta absoluta o con «..» corta todo, igual que pasarse del tope de bytes o de entradas.
 */
export function zipExtract(buf: Buffer, dir: string, limits = { bytes: 800 * 1024 * 1024, entries: 20_000 }): number {
  let total = 0;
  let files = 0;
  for (const entry of zipEntries(buf, limits.entries + 1)) {
    if (files > limits.entries) throw new Error("el zip tiene demasiadas entradas");
    const relative = normalize(entry.name.replace(/\\/g, "/"));
    if (!entry.name || isAbsolute(relative) || relative.split(sep).includes("..")) throw new Error(`entrada con ruta insegura: ${entry.name}`);
    const target = join(dir, relative);
    if (entry.name.endsWith("/")) {
      mkdirSync(target, { recursive: true });
      continue;
    }
    const data = zipRead(buf, entry, limits.bytes - total);
    if (!data) throw new Error(`no se pudo abrir ${entry.name} (método ${entry.method}, o pasa el tope de ${limits.bytes} bytes)`);
    total += data.length;
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, data);
    files++;
  }
  return files;
}

/** Tabla de cadenas de un recurso (ResStringPool): UTF-8 o UTF-16, con largos de 1 o 2 unidades. */
export function stringPool(buf: Buffer, at: number, limit = 1_000_000): string[] {
  const out: string[] = [];
  if (at < 0 || at + 28 > buf.length) return out;
  const header = buf.readUInt16LE(at + 2);
  const end = Math.min(buf.length, at + buf.readUInt32LE(at + 4));
  const count = Math.min(buf.readUInt32LE(at + 8), limit);
  const utf8 = (buf.readUInt32LE(at + 16) & 0x100) !== 0;
  const base = at + buf.readUInt32LE(at + 20);
  for (let i = 0; i < count; i++) {
    const slot = at + header + i * 4;
    if (slot + 4 > end) break;
    let p = base + buf.readUInt32LE(slot);
    let text = "";
    if (p + 2 <= end) {
      if (utf8) {
        // Largo en caracteres (se saltea) y después en bytes; cada uno en 1 byte, o 2 si el primero tiene el bit alto.
        p += buf[p]! & 0x80 ? 2 : 1;
        let bytes = buf[p] ?? 0;
        if (bytes & 0x80) {
          bytes = ((bytes & 0x7f) << 8) | (buf[p + 1] ?? 0);
          p += 2;
        } else p += 1;
        if (p + bytes <= end) text = buf.toString("utf8", p, p + bytes);
      } else {
        let units = buf.readUInt16LE(p);
        p += 2;
        if (units & 0x8000 && p + 2 <= end) {
          units = ((units & 0x7fff) << 16) | buf.readUInt16LE(p);
          p += 2;
        }
        if (p + units * 2 <= end) text = buf.toString("utf16le", p, p + units * 2);
      }
    }
    out.push(text);
  }
  return out;
}

export interface XmlNode {
  name: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  /** Texto dentro del elemento (p. ej. el dominio en <domain>…</domain>). */
  text?: string;
}

/**
 * Atributos de Android por id de recurso. Los ofuscadores suelen vaciar o cambiar el nombre del
 * atributo en la tabla de cadenas; Android se guía por el id, y acá también.
 */
const ANDROID_ATTRS: Record<number, string> = {
  0x01010003: "name",
  0x01010006: "permission",
  0x01010007: "readPermission",
  0x01010008: "writePermission",
  0x01010009: "protectionLevel",
  0x0101000e: "enabled",
  0x0101000f: "debuggable",
  0x01010010: "exported",
  0x01010018: "authorities",
  0x0101001b: "grantUriPermissions",
  0x01010024: "value",
  0x01010027: "scheme",
  0x01010028: "host",
  0x01010029: "port",
  0x0101002a: "path",
  0x0101002b: "pathPrefix",
  0x0101002c: "pathPattern",
  0x0101020c: "minSdkVersion",
  0x0101021b: "versionCode",
  0x0101021c: "versionName",
  0x01010270: "targetSdkVersion",
  0x01010280: "allowBackup",
  0x010104ec: "usesCleartextTraffic",
  0x010104ee: "autoVerify",
  0x01010527: "networkSecurityConfig",
};

/** Valor tipado de un atributo (Res_value) como texto. */
function typedValue(buf: Buffer, at: number, strings: string[]): string {
  const type = buf[at + 7]!;
  const data = buf.readUInt32LE(at + 8);
  switch (type) {
    case 0x03: return strings[data] ?? "";
    case 0x12: return data !== 0 ? "true" : "false";
    case 0x10: return String(data | 0);
    case 0x01: return `@0x${data.toString(16).padStart(8, "0")}`;
    case 0x02: return `?0x${data.toString(16).padStart(8, "0")}`;
    case 0x04: return String(buf.readFloatLE(at + 8));
    default: return `0x${data.toString(16)}`;
  }
}

/** XML binario de Android (AndroidManifest.xml, res/xml/*.xml) a un árbol simple. undefined si no lo es. */
export function decodeAxml(buf: Buffer, maxNodes = 200_000): XmlNode | undefined {
  if (buf.length < 8 || buf.readUInt16LE(0) !== 0x0003) return undefined;
  let strings: string[] = [];
  let ids: number[] = [];
  const document: XmlNode = { name: "#documento", attrs: {}, children: [] };
  const stack = [document];
  let nodes = 0;
  let p = Math.max(8, buf.readUInt16LE(2));
  try {
    while (p + 8 <= buf.length) {
      const type = buf.readUInt16LE(p);
      const header = buf.readUInt16LE(p + 2);
      const size = buf.readUInt32LE(p + 4);
      if (size < 8 || header < 8 || p + size > buf.length) break;
      if (type === 0x0001) strings = stringPool(buf, p);
      else if (type === 0x0180) {
        ids = [];
        for (let q = p + header; q + 4 <= p + size && ids.length < 100_000; q += 4) ids.push(buf.readUInt32LE(q));
      } else if (type === 0x0102) {
        if (++nodes > maxNodes) break;
        const ext = p + header;
        const node: XmlNode = { name: strings[buf.readUInt32LE(ext + 4)] ?? "", attrs: {}, children: [] };
        const start = buf.readUInt16LE(ext + 8);
        const stride = Math.max(20, buf.readUInt16LE(ext + 10));
        const count = buf.readUInt16LE(ext + 12);
        for (let i = 0; i < count; i++) {
          const a = ext + start + i * stride;
          if (a + 20 > p + size) break;
          const ns = strings[buf.readUInt32LE(a)] ?? "";
          const nameIndex = buf.readUInt32LE(a + 4);
          const known = ANDROID_ATTRS[ids[nameIndex] ?? -1];
          const plain = strings[nameIndex] ?? "";
          const key = known ? `android:${known}` : plain ? (/android/.test(ns) ? `android:${plain}` : plain) : `attr#${(ids[nameIndex] ?? nameIndex).toString(16)}`;
          const raw = buf.readUInt32LE(a + 8);
          node.attrs[key] = raw !== 0xffffffff && strings[raw] !== undefined ? strings[raw]! : typedValue(buf, a + 8, strings);
        }
        stack.at(-1)!.children.push(node);
        if (stack.length < 512) stack.push(node);
      } else if (type === 0x0103 && stack.length > 1) stack.pop();
      else if (type === 0x0104 && p + header + 4 <= p + size) {
        const node = stack.at(-1)!;
        node.text = `${node.text ?? ""}${strings[buf.readUInt32LE(p + header)] ?? ""}`.slice(0, 4096);
      }
      p += size;
    }
  } catch {
    // Lo leído hasta acá vale; el resto estaba roto.
  }
  return document.children[0];
}

/** Las cadenas de la tabla de un XML binario (para buscar URLs y claves en metadatos, sin armar el árbol). */
export function axmlStrings(buf: Buffer): string[] {
  if (buf.length < 16 || buf.readUInt16LE(0) !== 0x0003) return [];
  const at = Math.max(8, buf.readUInt16LE(2));
  return at + 8 <= buf.length && buf.readUInt16LE(at) === 0x0001 ? stringPool(buf, at) : [];
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const unescapeXml = (text: string) => text.replace(/&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-f]+);/gi, (all, name: string) => name[0] === "#" ? String.fromCodePoint(name[1]!.toLowerCase() === "x" ? parseInt(name.slice(2), 16) : Number(name.slice(1))) : ENTITIES[name.toLowerCase()] ?? all);

/**
 * XML de texto (lo que escriben jadx y apktool al decodificar) al mismo árbol. Recorrido lineal a mano,
 * sin expresiones con retroceso: el texto viene del APK y puede estar armado para trabar un parser.
 */
export function parseTextXml(text: string, maxNodes = 200_000): XmlNode | undefined {
  const document: XmlNode = { name: "#documento", attrs: {}, children: [] };
  const stack = [document];
  let nodes = 0;
  let i = 0;
  const skipTo = (marker: string) => {
    const at = text.indexOf(marker, i);
    i = at < 0 ? text.length : at + marker.length;
  };
  const space = (c: string | undefined) => c === " " || c === "\n" || c === "\t" || c === "\r";
  while (i < text.length && nodes < maxNodes) {
    const open = text.indexOf("<", i);
    if (open < 0) break;
    const between = text.slice(i, Math.min(open, i + 4096)).trim();
    if (between && stack.length > 1) {
      const node = stack.at(-1)!;
      node.text = `${node.text ?? ""}${unescapeXml(between)}`.slice(0, 4096);
    }
    i = open + 1;
    if (text.startsWith("!--", i)) { skipTo("-->"); continue; }
    if (text.startsWith("![CDATA[", i)) { skipTo("]]>"); continue; }
    if (text[i] === "?" || text[i] === "!") { skipTo(">"); continue; }
    const closing = text[i] === "/";
    if (closing) i++;
    let start = i;
    while (i < text.length && !space(text[i]) && text[i] !== ">" && text[i] !== "/") i++;
    const name = text.slice(start, i);
    if (closing) {
      skipTo(">");
      if (stack.length > 1) stack.pop();
      continue;
    }
    const node: XmlNode = { name, attrs: {}, children: [] };
    let selfClosing = false;
    while (i < text.length) {
      while (space(text[i])) i++;
      if (text[i] === ">") { i++; break; }
      if (text[i] === "/") { selfClosing = true; i++; continue; }
      start = i;
      while (i < text.length && !space(text[i]) && text[i] !== "=" && text[i] !== ">" && text[i] !== "/") i++;
      const key = text.slice(start, i);
      while (space(text[i])) i++;
      if (text[i] !== "=") { if (key) node.attrs[key] = ""; if (i === start) i++; continue; }
      i++;
      while (space(text[i])) i++;
      const quote = text[i];
      if (quote === '"' || quote === "'") {
        const end = text.indexOf(quote, i + 1);
        const stop = end < 0 ? text.length : end;
        node.attrs[key] = unescapeXml(text.slice(i + 1, stop));
        i = stop + 1;
      } else {
        start = i;
        while (i < text.length && !space(text[i]) && text[i] !== ">") i++;
        node.attrs[key] = unescapeXml(text.slice(start, i));
      }
    }
    nodes++;
    stack.at(-1)!.children.push(node);
    if (!selfClosing && stack.length < 512) stack.push(node);
  }
  return document.children[0];
}

/**
 * Cadenas de un dex desde su tabla (string_ids): cada una es un literal del código, un nombre de clase o
 * de método. Mucho más limpio que buscar texto imprimible. undefined si no es un dex.
 */
export function dexStrings(buf: Buffer, limit = 2_000_000): string[] | undefined {
  if (buf.length < 0x70 || buf.toString("latin1", 0, 4) !== "dex\n") return undefined;
  const count = Math.min(buf.readUInt32LE(0x38), limit);
  const table = buf.readUInt32LE(0x3c);
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const slot = table + i * 4;
    if (slot + 4 > buf.length) break;
    let p = buf.readUInt32LE(slot);
    if (p >= buf.length) continue;
    // ULEB128 con el largo en unidades UTF-16: no hace falta, la cadena termina en un byte cero.
    for (let k = 0; k < 5 && p < buf.length; k++) if (!(buf[p++]! & 0x80)) break;
    let end = p;
    const stop = Math.min(buf.length, p + 8192);
    while (end < stop && buf[end] !== 0) end++;
    out.push(buf.toString("utf8", p, end));
  }
  return out;
}

/** Cadenas globales de resources.arsc: ahí quedan los valores de strings.xml (google_api_key, firebase_database_url…). */
export function arscStrings(buf: Buffer): string[] | undefined {
  if (buf.length < 12 || buf.readUInt16LE(0) !== 0x0002) return undefined;
  const at = buf.readUInt16LE(2);
  return at + 8 <= buf.length && buf.readUInt16LE(at) === 0x0001 ? stringPool(buf, at) : undefined;
}

/** Corridas de texto imprimible (como `strings`), para binarios sin estructura conocida. */
export function printableStrings(buf: Buffer, min = 6, limit = 400_000): string[] {
  const out: string[] = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i]! : 0;
    if ((c >= 0x20 && c < 0x7f) || c === 0x09) {
      if (start < 0) start = i;
      continue;
    }
    if (start >= 0 && i - start >= min) {
      out.push(buf.toString("latin1", start, Math.min(i, start + 4096)));
      if (out.length >= limit) break;
    }
    start = -1;
  }
  return out;
}
