// Un HAR describe tráfico del cliente; importarlo no equivale a autorizar su repetición.
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import type { Tool, ToolResult } from "../agent.ts";
import type { Artifacts } from "../artifacts.ts";
import { normalizePath, type HttpClient } from "../http.ts";
import { reaDisponible } from "../rea.ts";
import { decide } from "../scope.ts";

interface HarContext {
  artifacts: Artifacts;
  http: HttpClient;
  cwd?: string;
  /** ¿Hay REA en esta sesión (dentro de la caja)? Entonces sugiere leer el HAR entero y armar un AgentEnv. Por defecto, reaDisponible(). */
  rea?: () => boolean;
}
interface Pair { name: string; value: string }
interface HarEntry {
  request: { url: string; method: string; headers: Pair[]; cookies?: Pair[]; queryString?: Pair[]; postData?: { mimeType?: string; text?: string; params?: Array<{ name: string; value?: string }> } };
}
const MAX_BYTES = 20 * 1024 * 1024;
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

function pairs(value: unknown): value is Pair[] {
  return Array.isArray(value) && value.every((item) => object(item) && typeof item.name === "string" && typeof item.value === "string");
}

function entriesFrom(value: unknown): HarEntry[] {
  if (!object(value) || !object(value.log) || !/^1\.[12]$/.test(String(value.log.version)) || !Array.isArray(value.log.entries)) throw new Error("HAR inválido: se espera log.version (1.1 o 1.2) y log.entries.");
  if (value.log.entries.length > 10000) throw new Error("HAR demasiado grande: máximo 10000 entradas.");
  for (const [index, entry] of value.log.entries.entries()) {
    const request = object(entry) ? entry.request : undefined;
    let valid = object(request) && typeof request.url === "string" && typeof request.method === "string" && /^[A-Za-z]+$/.test(request.method) && pairs(request.headers);
    if (valid && object(request)) {
      try { valid = /^https?:$/.test(new URL(String(request.url)).protocol); } catch { valid = false; }
      if (request.cookies !== undefined && !pairs(request.cookies)) valid = false;
      if (request.queryString !== undefined && !pairs(request.queryString)) valid = false;
      if (request.postData !== undefined) {
        const data = request.postData;
        if (!object(data) || (data.text !== undefined && typeof data.text !== "string") || (data.params !== undefined && (!Array.isArray(data.params) || !data.params.every((param) => object(param) && typeof param.name === "string" && (param.value === undefined || typeof param.value === "string"))))) valid = false;
      }
    }
    // El error no repite contenido del archivo: podría contener una credencial.
    if (!valid) throw new Error(`HAR inválido en la entrada ${index + 1}: revisá URL, método, cabeceras y cuerpo.`);
  }
  return value.log.entries as unknown as HarEntry[];
}

function bodyKeys(entry: HarEntry): string[] {
  const data = entry.request.postData;
  const keys = new Set(data?.params?.map((param) => param.name));
  if (data?.text) {
    try {
      const parsed: unknown = JSON.parse(data.text);
      if (object(parsed)) for (const key of Object.keys(parsed)) keys.add(key);
    } catch {
      if (data.mimeType?.includes("application/x-www-form-urlencoded")) for (const key of new URLSearchParams(data.text).keys()) keys.add(key);
    }
  }
  return [...keys];
}

export function importHar(value: unknown, http: HttpClient): ToolResult {
  // Validar todo antes de tocar la sesión evita una importación parcial silenciosa.
  const entries = entriesFrom(value);
  // Una credencial puede aparecer antes en una ruta y recién después en Authorization.
  const identities = new Map<HarEntry, string>();
  for (const entry of entries) {
    const request = entry.request;
    const url = new URL(request.url);
    const credentials: Record<string, string> = {};
    for (const { name, value } of request.headers) {
      if (/^authorization$/i.test(name) && value.trim()) credentials.authorization = value;
      if (/^cookie$/i.test(name) && value.trim()) credentials.cookie = credentials.cookie ? `${credentials.cookie}; ${value}` : value;
    }
    if (!credentials.cookie && request.cookies?.length) credentials.cookie = request.cookies.map(({ name, value }) => `${name}=${value}`).join("; ");
    if (Object.keys(credentials).length) {
      const name = http.proposeIdentity({ name: `har-${url.hostname.replace(/[^a-z0-9-]/gi, "-")}`, headers: credentials }, url.origin);
      identities.set(entry, name);
    }
  }
  const hosts = new Map<string, { paths: Set<string>; writes: Set<string>; identities: Set<string>; outside: number }>();
  for (const entry of entries) {
    const request = entry.request;
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const row = hosts.get(url.host) ?? { paths: new Set<string>(), writes: new Set<string>(), identities: new Set<string>(), outside: 0 };
    const path = normalizePath(url.href)!;
    row.paths.add(path);
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) row.writes.add(`${method} ${path}`);
    if (!decide(http.scope(), url.href).allowed) row.outside++;
    const identity = identities.get(entry);
    if (identity) row.identities.add(identity);
    http.observe({ url: request.url, method, params: request.queryString?.map((param) => param.name), bodyKeys: bodyKeys(entry) });
    hosts.set(url.host, row);
  }
  const rows = ["Host | Rutas | Escritura | Identidades | Fuera de alcance"];
  for (const [host, row] of hosts) rows.push(`${host} | ${row.paths.size} | ${[...row.writes].join(", ") || "—"} | ${[...row.identities].join(", ") || "—"} | ${row.outside ? `${row.outside} entradas` : "no"}`);
  rows.push(`${entries.length} entradas vistas; no se enviaron peticiones. Las identidades detectadas requieren aprobación del operador con /identity aprobar <nombre>.`);
  return { text: http.redactIdentities(rows.join("\n")), details: { entradas: entries.length, hosts: hosts.size, identidades: [...new Set([...hosts.values()].flatMap((row) => [...row.identities]))].length, fueraDeAlcance: [...hosts.values()].reduce((sum, row) => sum + row.outside, 0) } };
}

export function createHarTools(context: HarContext): Tool[] {
  return [{
    name: "har_import",
    label: "Importar HAR",
    description: "Cuando ya tenés una captura HAR, importala desde el archivo o artefacto para registrar la superficie vista sin reenviar tráfico. Resume hosts, rutas, escrituras y alcance; propone identidades sin mostrar sus credenciales. El operador las aprueba con /identity.",
    parameters: { type: "object", properties: { path: { type: "string", description: "Ruta del HAR, relativa al proyecto o absoluta" }, artifact: { type: "string", description: "Hash del artefacto que contiene el HAR" } }, required: [] },
    replay: "safe",
    execute: (params) => {
      if (Boolean(params.path) === Boolean(params.artifact)) throw new Error("Pasá path o artifact, sólo uno.");
      let bytes: Buffer;
      if (params.path) {
        const path = resolve(context.cwd ?? process.cwd(), params.path);
        const stat = statSync(path);
        if (!stat.isFile()) throw new Error("El HAR debe ser un archivo regular.");
        if (stat.size > MAX_BYTES) throw new Error("HAR demasiado grande: máximo 20 MiB.");
        bytes = readFileSync(path);
      } else bytes = context.artifacts.read(params.artifact);
      if (bytes.length > MAX_BYTES) throw new Error("HAR demasiado grande: máximo 20 MiB.");
      let parsed: unknown;
      try { parsed = JSON.parse(bytes.toString("utf8").replace(/^\uFEFF/, "")); } catch { throw new Error("HAR inválido: el contenido no es JSON."); }
      const result = importHar(parsed, context.http);
      // El mismo HAR alimenta a REA (en la caja): lo lee entero y puede armar un AgentEnv de la aplicación.
      if (params.path && (context.rea ?? reaDisponible)()) result.text += `\nCon REA en la caja: rea.inspect_web_network_capture con capture_path «${params.path}» lo lee entero, y rea.export_environment_bundle con esa evidencia arma un AgentEnv (habilidad ingenieria-inversa).`;
      return result;
    },
  }];
}
