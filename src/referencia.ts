// Lectura de material de referencia: el código fuente de un programa de código abierto, su
// documentación pública, la página del programa. Leer no es probar: estas fuentes no son objetivos y
// nunca entran en decide(). Se leen con una herramienta aparte, con fetch propio (como el recon pasivo),
// y nada de lo que la hace útil para atacar existe acá: sólo GET, sin cuerpo, sin cabeceras propias,
// sin identidades ni cookies del objetivo, sin consultas libres ni caracteres de payload, a un ritmo
// fijo y con tope por sesión. Hace falta un alcance cargado, y sus exclusiones ganan siempre.
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { type Decision, isLoopbackHost, isPrivateAddress, ruleMatches, type Scope } from "./scope.ts";

/** Fuentes fijas: donde vive el código público de casi todos los programas de código abierto. */
export const REFERENCE_HOSTS = ["github.com", "api.github.com", "raw.githubusercontent.com"] as const;
/** Una lectura por segundo como mucho, y un tope por sesión: es para leer, no para barrer. */
export const REFERENCE_INTERVAL_MS = 1000;
export const REFERENCE_CAP = 200;
export const REFERENCE_MAX_BYTES = 1_000_000;
/** Lo único que puede ir en la consulta: lo que usan las APIs de lectura de GitHub. */
const QUERY_KEYS = new Set(["ref", "page", "per_page", "recursive", "plain", "path", "sha", "state", "sort", "direction"]);
/** Caracteres de una ruta de código: nada de comillas, < >, ;, %xx (salvo el espacio), ni nada que arme un payload. */
const SAFE_PATH = /^(?:[A-Za-z0-9._~\-/+@]|%20)*$/;
const SAFE_VALUE = /^[A-Za-z0-9._\-/]{0,120}$/;
const PRIVATE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|::1$|f[cd]|fe80)/i;
const TEXTUAL = /^(text\/|application\/(?:[\w.+-]*json|[\w.+-]*xml|javascript|x-javascript|x-sh|x-httpd-php|x-yaml|yaml|toml|x-python|vnd\.github[\w.+-]*))/i;

/** La página del programa cargado en HackerOne (verificadas: la del programa, su alcance y su CSV). */
function programPage(scope: Scope, url: URL): string | undefined {
  const handle = /^hackerone:([a-z0-9_-]+)$/i.exec(scope.source)?.[1]?.toLowerCase();
  if (!handle || url.hostname !== "hackerone.com") return undefined;
  const path = url.pathname.replace(/\/+$/, "").toLowerCase();
  return [`/${handle}`, `/${handle}/policy_scopes`, `/teams/${handle}/assets/download_csv.csv`].includes(path) ? `página del programa ${handle}` : undefined;
}

/**
 * ¿Se puede leer esta URL como referencia? Hace falta un alcance cargado; la URL tiene que ser https,
 * sin credenciales ni puerto, de una fuente de referencia (las fijas, las del alcance o la página del
 * programa) y no excluida; la ruta y la consulta, sin nada que parezca un payload.
 */
export function referenceDecision(scope: Scope | undefined, target: string): Decision {
  const no = (reason: string): Decision => ({ allowed: false, reason });
  // Un programa sólo de código no tiene nada dentro, pero sus fuentes sí se leen.
  if (!scope?.include.length && !scope?.reference?.length) return no("Sin alcance cargado no hay fuentes de referencia: primero el alcance del programa.");
  if (target.length > 600) return no("URL demasiado larga para una lectura de referencia.");
  // Sobre lo escrito, antes de que el parser normalice («%2e%2e» se vuelve «..» y se resuelve): ahí se ve el intento.
  if (/(^|\/)\.\.?(\/|$|\?)|%(?!20)[0-9a-f]{2}|['"<>;\\\s{}|^`]/i.test(target.replace(/^https?:\/\/[^/?#]*/i, ""))) return no("La ruta tiene caracteres que no van en una lectura de código (comillas, < >, ;, %xx, ..): reference_read no sirve para mandar payloads.");
  let url: URL;
  try { url = new URL(target); } catch { return no(`URL inválida: ${target}`); }
  if (url.protocol !== "https:") return no("Las fuentes de referencia se leen sólo por https.");
  if (url.username || url.password) return no("Una URL de referencia no lleva credenciales.");
  if (url.port) return no("Una fuente de referencia no se lee en otro puerto.");
  const host = url.hostname.toLowerCase();
  // Un laboratorio o la red del operador nunca son referencia: ésta se lee de internet. Aunque el alcance
  // tenga 127.0.0.1 o una regla de referencia lo nombre, reference_read no sale a loopback ni a una IP
  // privada (un nombre que resuelve adentro lo frena la resolución, al leer).
  const bare = host.replace(/^\[|\]$/g, "");
  if (isLoopbackHost(bare) || isPrivateAddress(bare) || PRIVATE.test(bare)) return no(`${host} es un destino local (loopback o la red del operador): reference_read lee referencia pública en internet. Un laboratorio se prueba con http_request dentro del alcance.`);
  const fixed = (REFERENCE_HOSTS as readonly string[]).includes(host);
  const own = scope.reference?.find((rule) => ruleMatches(rule, host, url));
  const page = programPage(scope, url);
  if (!fixed && !own && !page) {
    return no(`${host} no es una fuente de referencia (fijas: ${REFERENCE_HOSTS.join(", ")}${scope.reference?.length ? `; del programa: ${scope.reference.slice(0, 5).map((rule) => rule.value).join(", ")}` : ""}). Para probar un objetivo del alcance usá http_request; una documentación pública la suma el operador con /alcance referencia <host>.`);
  }
  const excluded = scope.exclude.find((rule) => ruleMatches(rule, host, url));
  if (excluded) return no(`Excluido por la regla ${excluded.value}${excluded.note ? ` (${excluded.note})` : ""}: las exclusiones del programa ganan también para leer.`);
  if (!SAFE_PATH.test(url.pathname) || /\/\.{1,2}(\/|$)|\/\//.test(url.pathname)) return no("La ruta tiene caracteres que no van en una lectura de código (comillas, < >, ;, %xx, ..): reference_read no sirve para mandar payloads.");
  for (const [key, value] of url.searchParams) {
    if (!QUERY_KEYS.has(key)) return no(`La consulta sólo admite ${[...QUERY_KEYS].join(", ")}: «${key}» no.`);
    if (!SAFE_VALUE.test(value)) return no(`El valor de «${key}» tiene caracteres que no van en una lectura (sólo letras, números, . _ - /).`);
  }
  return { allowed: true, reason: fixed ? `fuente fija ${host}` : own ? `fuente del alcance ${own.value}` : page! };
}

export interface ReferenceContext {
  scope: () => Scope | undefined;
  artifacts: Artifacts;
  /** Pruebas: transporte, resolución DNS y espera simulados. */
  fetch?: typeof fetch;
  lookup?: (host: string) => Promise<string[]>;
  sleep?: (ms: number) => Promise<void>;
  event?: (type: string, payload: unknown) => void;
}

export function createReferenceTool(context: ReferenceContext): Tool {
  const fetchImpl = context.fetch ?? fetch;
  const resolve = context.lookup ?? (async (host: string) => (await dnsLookup(host, { all: true })).map((entry) => entry.address));
  const sleep = context.sleep ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
  let count = 0;
  /** Lo más temprano que puede salir la próxima lectura. */
  let next = 0;

  /** Un GET, con el ritmo y el tope de la sesión. Devuelve la respuesta sin seguir redirecciones. */
  const get = async (url: URL, signal?: AbortSignal): Promise<Response> => {
    if (count >= REFERENCE_CAP) throw new Error(`Llegaste al tope de ${REFERENCE_CAP} lecturas de referencia de esta sesión: trabajá con lo que ya bajaste (artifact_read) o clonalo con platform_cli (gh repo clone).`);
    const host = url.hostname;
    const addresses = isIP(host) ? [host] : await resolve(host);
    const inner = addresses.find((address) => PRIVATE.test(address));
    if (inner) throw new Error(`${host} resuelve a la dirección privada ${inner}: una fuente de referencia es pública; no se lee.`);
    const now = Date.now();
    const at = Math.max(now, next);
    next = at + REFERENCE_INTERVAL_MS;
    count++;
    if (at > now) await sleep(at - now);
    return fetchImpl(url, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": "ElevateAICyber/0.1 (lectura de referencia)", accept: "text/plain, application/json, application/vnd.github.raw, text/html;q=0.5" },
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000),
    });
  };

  return {
    name: "reference_read",
    label: "Leer referencia",
    description:
      "Lee material de referencia público, NO un objetivo: el código fuente del programa (github.com, api.github.com, raw.githubusercontent.com: un archivo crudo, el README, /repos/<dueño>/<repo>/contents/<ruta>?ref=<rama>), su documentación pública si el operador la sumó al alcance, o la página del programa en HackerOne. " +
      "Sólo GET, sin cuerpo, sin cabeceras ni identidades, una lectura por segundo y " + REFERENCE_CAP + " por sesión; la ruta no admite payloads. Para probar el objetivo, http_request dentro del alcance.",
    parameters: { type: "object", properties: { url: { type: "string" }, chars: { type: "integer", minimum: 200, maximum: 20000, description: "Caracteres del cuerpo en la respuesta (por defecto 6000; completo en el artefacto)" } }, required: ["url"] },
    parallel: false,
    replay: "safe",
    execute: async (params, signal): Promise<ToolResult> => {
      // Sólo url y chars: un método, un cuerpo o cabeceras no se aceptan aunque el modelo los mande.
      const extra = Object.keys(params).filter((key) => key !== "url" && key !== "chars");
      if (extra.length) throw new Error(`reference_read sólo lee: no acepta ${extra.join(", ")}. Para mandar algo a un objetivo del alcance, http_request.`);
      let url = new URL(String(params.url ?? "").replace(/#.*$/, ""));
      const chain: string[] = [];
      for (let hop = 0; ; hop++) {
        const decision = referenceDecision(context.scope(), url.href);
        if (!decision.allowed) {
          if (!hop) throw new Error(decision.reason);
          return { text: `${chain.join(" → ")} redirige a ${url.href}, que no es una fuente de referencia (${decision.reason}): no se siguió.`, details: { url: chain[0], redireccion: url.href } };
        }
        chain.push(url.href);
        const response = await get(url, signal);
        const location = response.headers.get("location");
        if (response.status >= 300 && response.status < 400 && location) {
          await response.body?.cancel();
          if (hop >= 3) return { text: `${chain.join(" → ")}: demasiadas redirecciones; no se siguió a ${location}.`, details: { url: chain[0] } };
          url = new URL(location, url);
          continue;
        }
        const type = response.headers.get("content-type") ?? "";
        if (type && !TEXTUAL.test(type)) {
          await response.body?.cancel();
          return { text: `${url.href} · HTTP ${response.status} · ${type.split(";")[0]}: es binario y no se baja como referencia (para un repositorio entero, platform_cli con gh repo clone).`, details: { url: url.href, status: response.status } };
        }
        const bytes = new Uint8Array(await response.arrayBuffer());
        const truncated = bytes.length > REFERENCE_MAX_BYTES;
        const body = Buffer.from(bytes.subarray(0, REFERENCE_MAX_BYTES)).toString("utf8");
        const artifact = context.artifacts.put(JSON.stringify({ url: url.href, redirecciones: chain.slice(0, -1), status: response.status, contentType: type, body }, null, 1), "application/json", "referencia").hash;
        context.event?.("referencia.lectura", { url: url.href, status: response.status, bytes: bytes.length });
        const chars = Math.min(20000, Math.max(200, Number(params.chars) || 6000));
        const view = body.length > chars ? `${body.slice(0, chars)}\n… (${body.length} caracteres${truncated ? `, cortado en ${REFERENCE_MAX_BYTES} bytes` : ""}; completo en el artefacto)` : body;
        return {
          text: `GET ${url.href} · HTTP ${response.status} · ${bytes.length} B · ${type.split(";")[0] || "sin tipo"} · artefacto ${artifact} · lectura ${count}/${REFERENCE_CAP}${chain.length > 1 ? `\nredirecciones: ${chain.join(" → ")}` : ""}\n${view}`,
          details: { url: url.href, status: response.status, artefacto: artifact },
        };
      }
    },
  };
}
