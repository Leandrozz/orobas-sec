// REA («Reverse Engineer Anything», paquete npm rea-agents de morluto, MIT) como servidor MCP incorporado.
// Sólo dentro de la caja de Orobas (el contenedor del proyecto): ahí la imagen lo trae con versión fija y
// npm ci verifica el sha512 de cada paquete; en la máquina del operador no se ofrece ni se arranca. Sirve
// para lo compilado o empaquetado (el build de una app JavaScript, un APK, un binario, una captura HAR) y
// para grabar una web de caja negra. También analiza el JS de una web que bajó web_source_pull y el fuente JS/TS
// del programa (grafo de módulos y rutas); para buscar texto puntual siguen code_search y code_read.
// Cada llamada pasa por una política: sólo las herramientas ofrecidas acá, rutas dentro del proyecto, URLs
// dentro del alcance de la sesión, y la salida completa queda en un artefacto (al modelo le llega un extracto).
import { existsSync, lstatSync, realpathSync } from "node:fs";
import { createServer, request as httpRequest, type Server } from "node:http";
import { connect, type Socket } from "node:net";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { insideProject } from "./codigo.ts";
import { carpetaDelOperador } from "./datos.ts";
import type { HttpClient } from "./http.ts";
import { t } from "./idioma.ts";
import { enCaja } from "./instalar-herramientas.ts";
import type { McpIncorporado, McpOferta, McpServerConfig } from "./mcp.ts";
import { redactSecrets } from "./plataformas.ts";
import { decide, type Scope } from "./scope.ts";
import { origenDeHerramienta } from "./secretos-sesion.ts";

/**
 * Versión fija, publicada hace más de dos semanas al fijarla (6.8.0: 25/10/2026). La misma que
 * distro/rea/package-lock.json, cuyo sha512 (y el de cada dependencia) verifica npm ci al construir la imagen.
 * Para subir de versión: regenerar ese lock (npm install --package-lock-only --ignore-scripts, sólo lee
 * metadatos del registro) y cambiar acá versión e integridad con lo que publica `npm view rea-agents@X dist`.
 */
export const REA = {
  paquete: "rea-agents",
  version: "6.8.0",
  integridad: "sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==",
  /** Dónde lo deja distro/Dockerfile. */
  raiz: "/opt/rea",
  entrada: "/opt/rea/node_modules/rea-agents/scripts/rea.mjs",
  /** Chromium de la caja con las banderas del contenedor: REA no acepta argumentos de lanzamiento. */
  chromium: "/usr/local/bin/chromium-rea",
  /** apktool de la caja (el mismo de apk_analyze): REA lo usa para decode_android_resources. */
  apktool: "/usr/local/bin/apktool",
} as const;

/** Qué hace cada herramienta ofrecida con lo que recibe: lee archivos del proyecto, toca una web viva o sólo evidencia ya retenida. */
type Clase = "archivo" | "web" | "evidencia";
interface Entrada { name: string; es: string; en: string; clase: Clase; description: string; parameters?: Record<string, object> }

const s = (description: string, extra: object = {}) => ({ type: "string", description, ...extra });
const DETAIL = s("summary para resultados grandes (el completo queda retenido en REA); complete para todo en línea", { enum: ["summary", "complete"] });
const RUTA = (what: string) => s(`${what}, dentro de la carpeta del proyecto (relativa o absoluta)`);

/** Lo que Orobas expone de REA. Lo demás (depuradores, Frida, adb, ejecución de procesos, CDP, comandos de rizin) no se ofrece. */
const ENTRADAS: Entrada[] = [
  { name: "analyze_javascript_application", es: "REA · app JavaScript", en: "REA · JavaScript app", clase: "archivo", description: "Reconstruye sin ejecutarla una app JavaScript del proyecto: compilada o empaquetada (el .output/ de Nuxt/Nitro, un .next/ o dist/, un ASAR de Electron), el código de una web que bajó web_source_pull (su carpeta web/ o fuentes/) o el fuente JS/TS del programa: módulos, rutas, relaciones, cobertura y desconocidos. Con apps grandes pedí detail summary y seguí con inspect_analysis_view. Para un texto puntual del fuente, code_search; para claves, firmas y validaciones, code_crypto.", parameters: { input_path: RUTA("Carpeta o .asar de la app"), source_paths: { type: "array", items: { type: "string" }, description: "Archivos exactos del inventario (relativos a la app) para analizar sólo esos" }, detail: DETAIL } },
  { name: "trace_javascript_semantics", es: "REA · seguir en el JS", en: "REA · trace in JS", clase: "evidencia", description: "Sigue una consulta (función, ruta, llamada, valor) dentro de la evidencia de analyze_javascript_application.", parameters: { application: { type: "object" }, query: { type: "object" } } },
  { name: "trace_application_feature", es: "REA · seguir una función", en: "REA · trace a feature", clase: "evidencia", description: "Rastrea una función de la app desde una semilla (texto, ruta o módulo) sobre la evidencia retenida.", parameters: { application: { type: "object" }, seed: { type: "object" }, direction: s("Dirección") } },
  { name: "inspect_web_network_capture", es: "REA · captura HAR", en: "REA · HAR capture", clase: "archivo", description: "Lee una captura del proyecto (HAR, SAZ de Fiddler, mitmproxy o qlog) sin reenviar nada: registros, hosts, rutas y forma de los cuerpos. format «har» para un HAR. Su evidencia alimenta export_environment_bundle.", parameters: { capture_path: RUTA("Archivo de la captura"), format: s("har, saz, mitmproxy o qlog"), detail: DETAIL } },
  { name: "export_environment_bundle", es: "REA · AgentEnv", en: "REA · AgentEnv", clase: "archivo", description: "Arma un AgentEnv (una carpeta con un servidor MCP que responde como la web grabada) desde la evidencia de inspect_web_network_capture o capture_browser_scenario. output_directory: carpeta nueva dentro del proyecto. Lleva respuestas grabadas: no lo publiques ni lo compartas vos.", parameters: { source: { type: "object", description: "{kind: retained-evidence, evidence_id}" }, output_directory: RUTA("Carpeta nueva del bundle"), name: s("Nombre kebab-case"), dry_run: { type: "boolean" } } },
  { name: "capture_browser_scenario", es: "REA · grabar la web", en: "REA · record the web", clase: "web", description: "Graba una sesión de navegador sobre una web del alcance con el Chromium de la caja: start_url y acciones declaradas (goto, click, fill, press, wait_for, request GET). Toda URL tiene que estar en el alcance y el navegador sale por un proxy de alcance (lo de terceros no carga); las peticiones directas sólo GET o HEAD; sin secretos de entorno (para sesiones con login: chrome_session o las identidades). Clics y formularios pasan de verdad en el objetivo: sólo en instancias propias o que el operador dijo descartables. Su evidencia alimenta export_environment_bundle.", parameters: { start_url: { type: "object", description: "{url}" }, actions: { type: "array", items: { type: "object" } }, capture: { type: "object" } } },
  { name: "open_binary", es: "REA · abrir objetivo", en: "REA · open target", clase: "archivo", description: "Abre un archivo del proyecto como objetivo activo de REA: APK, IPA, ZIP, ASAR, ELF, PE o Mach-O. Después inspect_artifact (inventario) o binary_overview.", parameters: { path: RUTA("Archivo") } },
  { name: "inspect_artifact", es: "REA · inventario", en: "REA · inventory", clase: "evidencia", description: "Inventario del paquete abierto con open_binary: miembros, hashes, capas anidadas e integridad. Con contenedores grandes, detail summary.", parameters: { detail: DETAIL } },
  { name: "binary_overview", es: "REA · resumen del binario", en: "REA · binary overview", clase: "evidencia", description: "Resumen del objetivo abierto (formato, arquitectura, secciones) cuando hay motor para eso." },
  { name: "binary_session", es: "REA · estado", en: "REA · status", clase: "evidencia", description: "Estado de la sesión de REA: objetivo abierto y qué herramientas tienen motor en la caja (y por qué no las demás)." },
  { name: "close_binary", es: "REA · cerrar objetivo", en: "REA · close target", clase: "archivo", description: "Cierra el objetivo abierto con open_binary." },
  { name: "inspect_apk_signature", es: "REA · firma del APK", en: "REA · APK signature", clase: "archivo", description: "Firmas de un APK del proyecto: esquemas v1 a v3.1, huella de cada certificado, rotación de claves y si los digests coinciden con los bytes. Es identidad e integridad, no un veredicto de confianza.", parameters: { path: RUTA("APK"), detail: DETAIL } },
  { name: "decode_android_resources", es: "REA · recursos del APK", en: "REA · APK resources", clase: "archivo", description: "Decodifica los recursos de un APK del proyecto con el apktool de la caja (sin smali): AndroidManifest.xml legible, versión, SDK y strings por idioma.", parameters: { path: RUTA("APK"), include_strings: { type: "boolean" }, locale: s("Idioma de las strings") } },
  { name: "identify_flutter_build", es: "REA · build de Flutter", en: "REA · Flutter build", clase: "archivo", description: "Si la app es Flutter: hashes del snapshot de Dart por ABI, build-id del motor y versión de Dart.", parameters: { path: RUTA("APK o carpeta") } },
  { name: "inspect_dart_aot", es: "REA · Dart AOT", en: "REA · Dart AOT", clase: "archivo", description: "Lee el snapshot AOT de Dart (libapp.so) de una app Flutter del proyecto.", parameters: { path: RUTA("libapp.so o APK"), detail: DETAIL } },
  { name: "inspect_electron_fuses", es: "REA · fusibles Electron", en: "REA · Electron fuses", clase: "archivo", description: "Fusibles de una app Electron del proyecto (si acepta --inspect, integridad del ASAR y demás).", parameters: { path: RUTA("Ejecutable de Electron") } },
  { name: "open_bundle_resources", es: "REA · recursos Apple", en: "REA · Apple resources", clase: "archivo", description: "Recursos de una app Apple (.app de un IPA ya extraído en el proyecto): plist, Interface Builder y catálogos de assets.", parameters: { path: RUTA(".app") } },
  { name: "inspect_native_exports", es: "REA · exports nativos", en: "REA · native exports", clase: "archivo", description: "Exports de un PE o símbolos dinámicos de un ELF del proyecto (una .so de un APK, por ejemplo).", parameters: { path: RUTA("Binario") } },
  { name: "inspect_elf_notes", es: "REA · notas ELF", en: "REA · ELF notes", clase: "archivo", description: "Notas de un ELF del proyecto (build-id GNU, ABI).", parameters: { path: RUTA("ELF") } },
  { name: "inspect_pe_imports", es: "REA · imports PE", en: "REA · PE imports", clase: "archivo", description: "Imports (y delay-load) de un PE del proyecto.", parameters: { path: RUTA("PE") } },
  { name: "inspect_pe_certificates", es: "REA · certificados PE", en: "REA · PE certificates", clase: "archivo", description: "Certificados Authenticode de un PE del proyecto (no los valida).", parameters: { path: RUTA("PE") } },
  { name: "inspect_go_binary", es: "REA · binario Go", en: "REA · Go binary", clase: "archivo", description: "Versión de Go, módulos y ajustes de build embebidos en un binario Go del proyecto.", parameters: { path: RUTA("Binario") } },
  { name: "inspect_rust_binary", es: "REA · binario Rust", en: "REA · Rust binary", clase: "archivo", description: "Dependencias cargo-auditable de un binario Rust del proyecto.", parameters: { path: RUTA("Binario") } },
  { name: "inspect_byte_entropy", es: "REA · entropía", en: "REA · entropy", clase: "archivo", description: "Entropía por bloques de un archivo del proyecto (zonas cifradas o comprimidas).", parameters: { path: RUTA("Archivo") } },
  { name: "inspect_sqlite_database", es: "REA · base SQLite", en: "REA · SQLite database", clase: "archivo", description: "Esquema y filas de muestra de una base SQLite del proyecto (la de una app, por ejemplo).", parameters: { path: RUTA("Base"), table: s("Tabla") } },
  { name: "inspect_python_pyc", es: "REA · .pyc", en: "REA · .pyc", clase: "archivo", description: "Encabezado y objetos de código de un .pyc del proyecto (no decompila).", parameters: { path: RUTA(".pyc") } },
  { name: "inspect_analysis_view", es: "REA · ver evidencia", en: "REA · view evidence", clase: "evidencia", description: "Página una evidencia retenida de REA ({kind: retained-evidence, evidence_id}) por vista: resumen, módulo, rutas o colección. Es como se leen resultados grandes sin repetir el análisis.", parameters: { source: { type: "object" }, view: { type: "object" } } },
  { name: "get_evidence_bundle", es: "REA · evidencia retenida", en: "REA · retained evidence", clase: "evidencia", description: "Lista la evidencia retenida en esta conexión (detail summary y filtros) para recuperar sus ids.", parameters: { detail: s("summary o records"), filters: { type: "object" } } },
  { name: "list_unknowns", es: "REA · desconocidos", en: "REA · unknowns", clase: "evidencia", description: "Desconocidos registrados en la investigación de REA." },
  { name: "export_evidence_bundle", es: "REA · exportar evidencia", en: "REA · export evidence", clase: "archivo", description: "Escribe toda la evidencia de esta conexión de REA en un archivo nuevo del proyecto, para retomarla en otra sesión.", parameters: { path: RUTA("Archivo nuevo") } },
  { name: "import_evidence_bundle", es: "REA · importar evidencia", en: "REA · import evidence", clase: "archivo", description: "Recupera evidencia exportada antes (archivo del proyecto).", parameters: { path: RUTA("Archivo") } },
  { name: "inspect_analysis_settings", es: "REA · límites", en: "REA · limits", clase: "evidencia", description: "Límites de análisis de REA y sus valores." },
  { name: "update_analysis_settings", es: "REA · cambiar límites", en: "REA · change limits", clase: "evidencia", description: "Cambia un límite de REA cuando un error lo nombra (por ejemplo asar.max_header_bytes).", parameters: { changes: { type: "array", items: { type: "object" } } } },
];
const POR_NOMBRE = new Map(ENTRADAS.map((entry) => [entry.name, entry]));

/** La oferta de REA: nombre, etiqueta bilingüe (para la TUI), descripción para el modelo y esquema provisorio. */
export function ofertaRea(): McpOferta[] {
  return ENTRADAS.map((entry) => ({
    name: entry.name,
    label: t(entry.es, entry.en),
    description: `${entry.description} (Arranca REA al primer uso.)`,
    parameters: { type: "object", properties: entry.parameters ?? {}, additionalProperties: true },
  }));
}

const AVISO = "REA en la caja: rutas sólo dentro del proyecto, URLs sólo del alcance; la salida completa queda en un artefacto y acá llega un extracto.";

export interface ReaContexto {
  cwd: string;
  scope: () => Scope | undefined;
  artifacts: Artifacts;
  /** Señuelos marcados y tope de peticiones de la sesión, para la web viva. */
  http?: Pick<HttpClient, "refuseDecoy" | "remaining">;
  event?: (type: string, payload: Record<string, unknown>) => void;
  /** Chromium para capture_browser_scenario; por defecto el envoltorio de la caja. */
  chromium?: string;
}

export interface ReaOpciones {
  /** Por defecto, enCaja(). Las pruebas lo fijan. */
  enCaja?: boolean;
  /** Servidor a arrancar; por defecto el de la imagen (node rea.mjs mcp), si está. Las pruebas pasan uno falso. */
  server?: McpServerConfig;
}

const record = (value: unknown): value is Record<string, any> => !!value && typeof value === "object" && !Array.isArray(value);

/** Una ruta que REA va a leer o escribir: absoluta, real y dentro del proyecto (mismo chequeo que apk_analyze y code_read). */
export function rutaEnProyecto(cwd: string, value: string, campo: string): string {
  let path = value.trim();
  if (/^file:\/\//i.test(path)) path = fileURLToPath(path);
  if (!path || path.startsWith("~")) throw new Error(`${campo}: «${value}» está fuera de la carpeta del proyecto. REA sólo lee y escribe adentro de ella.`);
  const base = realpathSync(resolve(cwd));
  const target = resolve(base, path);
  let exists = true;
  try { lstatSync(target); } catch { exists = false; }
  // Lo que existe (un enlace incluido) se resuelve y se compara; un enlace roto no pasa.
  if (exists) return insideProject(base, target);
  // Una salida que todavía no existe: la carpeta que la va a contener tiene que estar en el proyecto.
  const parent = insideProject(base, dirname(target));
  const name = basename(target);
  if (name === ".cyber") throw new Error("«.cyber» guarda credenciales y evidencia del harness: REA no escribe ahí.");
  return join(parent, name);
}

/** Claves de nivel superior que REA usa como archivo o carpeta. */
const RUTAS = new Set(["path", "input_path", "capture_path", "output_directory", "snapshot_path", "package_tarball", "binary_path", "additional_paths", "mapping_path", "save_path"]);
/** Parecen rutas pero no son del disco: archivos dentro de la app analizada o una expectativa que REA compara. */
const NO_RUTAS = new Set(["source_paths", "expected_server_path"]);
const esRuta = (key: string) => RUTAS.has(key) || (/(^|_)(path|paths|directory|tarball)$/.test(key) && !NO_RUTAS.has(key));

function rutas(cwd: string, value: unknown, campo: string): unknown {
  if (typeof value === "string") return rutaEnProyecto(cwd, value, campo);
  if (Array.isArray(value)) return value.map((item, index) => (typeof item === "string" ? rutaEnProyecto(cwd, item, `${campo}[${index}]`) : item));
  return value;
}

const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/** Una URL de la web viva: http(s) o ws(s), dentro del alcance y no marcada como señuelo. */
function urlEnAlcance(context: ReaContexto, value: string, campo: string): void {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`${campo}: «${value.slice(0, 120)}» no es una URL válida.`); }
  if (!/^(https?|wss?):$/.test(url.protocol)) throw new Error(`${campo}: sólo URLs http(s) o ws(s) del alcance; «${url.protocol}» no.`);
  const decision = decide(context.scope(), url.href);
  if (!decision.allowed) throw new Error(`Fuera del alcance de esta sesión: ${url.href}. ${decision.reason}. REA no la abre; si el programa la cubre, que el operador la agregue.`);
  context.http?.refuseDecoy(url.href);
}

/** Recorre todo el pedido de la web viva: cada URL, en el alcance. */
function urlsEnAlcance(context: ReaContexto, value: unknown, campo: string): void {
  if (typeof value === "string") {
    if (URL_RE.test(value.trim())) urlEnAlcance(context, value.trim(), campo);
    else if (/(^|\.)(url|destination)$/.test(campo) && /^(javascript|data|file|blob|chrome|about):/i.test(value.trim()) && value.trim() !== "about:blank") throw new Error(`${campo}: «${value.slice(0, 40)}» no es una URL del alcance.`);
    return;
  }
  if (Array.isArray(value)) value.forEach((item, index) => urlsEnAlcance(context, item, `${campo}[${index}]`));
  else if (record(value)) for (const [key, item] of Object.entries(value)) urlsEnAlcance(context, item, campo ? `${campo}.${key}` : key);
}

const LECTURAS = new Set(["GET", "HEAD"]);

/** capture_browser_scenario: el Chromium de la caja, sin secretos del entorno, sólo lecturas directas y todo en el alcance. */
function revisarWeb(context: ReaContexto, args: Record<string, any>): void {
  if (args.browser !== undefined && (!record(args.browser) || (args.browser.mode !== undefined && args.browser.mode !== "launch"))) throw new Error("REA no se conecta a otro navegador (CDP): graba con el Chromium de la caja. Para tu navegador con sesión están las herramientas chrome_*.");
  args.browser = { mode: "launch", executable_path: context.chromium ?? REA.chromium, headless: true };
  if (Array.isArray(args.secrets) && args.secrets.length) throw new Error("REA corre sin las variables de entorno del operador: no hay secretos que referenciar. Para sesiones con login usá chrome_session o una identidad aprobada.");
  delete args.secrets;
  const start = record(args.start_url) ? args.start_url.url : typeof args.start_url === "string" ? args.start_url : undefined;
  if (typeof start !== "string" || !/^https?:\/\//i.test(start.trim())) throw new Error("start_url.url tiene que ser una URL http(s) del alcance.");
  if (typeof args.start_url === "string") args.start_url = { url: args.start_url };
  for (const [index, action] of (Array.isArray(args.actions) ? args.actions : []).entries()) {
    if (record(action) && action.action === "request" && !LECTURAS.has(String(action.method ?? "GET").toUpperCase())) throw new Error(`actions[${index}]: una petición ${String(action.method)} desde REA esquiva los controles de escritura. Las escrituras van por http_request o body_probe; acá sólo GET o HEAD.`);
  }
  urlsEnAlcance(context, args, "");
  if (context.http?.remaining() === 0) throw new Error("Tope de peticiones de la sesión alcanzado: REA no graba la web.");
}

/** Revisa (y completa) los argumentos antes de mandarlos a REA; si algo no pasa, tira y no se manda nada. */
export function reaRevisar(context: ReaContexto, tool: string, args: Record<string, unknown>): Record<string, unknown> {
  const entry = POR_NOMBRE.get(tool);
  if (!entry) throw new Error(`rea.${tool} no está habilitada en Orobas (depuradores, ejecución de procesos, Frida y adb no se ofrecen).`);
  const out: Record<string, any> = structuredClone(args ?? {});
  for (const key of Object.keys(out)) if (esRuta(key)) out[key] = rutas(context.cwd, out[key], key);
  // Las anidadas que también son del disco: un archivo de evidencia y un descriptor de protobuf.
  if (record(out.source) && typeof out.source.path === "string") out.source.path = rutaEnProyecto(context.cwd, out.source.path, "source.path");
  if (record(out.protobuf) && record(out.protobuf.schema) && typeof out.protobuf.schema.descriptor_set_path === "string") out.protobuf.schema.descriptor_set_path = rutaEnProyecto(context.cwd, out.protobuf.schema.descriptor_set_path, "protobuf.schema.descriptor_set_path");
  if (tool === "inspect_web_network_capture" && out.format === undefined && typeof out.capture_path === "string" && /\.har$/i.test(out.capture_path)) out.format = "har";
  if (entry.clase === "web") revisarWeb(context, out);
  return out;
}

/** Ids de evidencia que devolvió REA, para seguir con inspect_analysis_view o pasarlos a export_environment_bundle. */
function evidencias(value: unknown, found = new Set<string>(), budget = { nodes: 20_000 }): Set<string> {
  if (found.size >= 6 || --budget.nodes < 0) return found;
  if (Array.isArray(value)) for (const item of value) evidencias(item, found, budget);
  else if (record(value)) for (const [key, item] of Object.entries(value)) {
    if (/(^|_)evidence_id$/.test(key) && typeof item === "string" && item.length <= 120) found.add(item);
    else evidencias(item, found, budget);
  }
  return found;
}

/** Código y mensaje de un error de REA, si vino uno. */
function errorDe(value: unknown): string | undefined {
  if (!record(value)) return undefined;
  const error = record(value.error) ? value.error : undefined;
  if (!error) return undefined;
  const remediation = record(error.remediation) ? error.remediation.action : record(value.remediation) ? value.remediation.action : undefined;
  return [error.code, error.message].filter((part) => typeof part === "string").join(": ").slice(0, 400) + (typeof remediation === "string" ? ` · Remedio: ${remediation.slice(0, 200)}` : "");
}

/** Lo que el modelo ve de un resultado: estado, ids de evidencia, artefacto y un extracto. Nunca el volcado entero. */
export const EXTRACTO = 3000;

/**
 * Procedencia de lo que devuelve una herramienta de REA (src/secretos-sesion.ts). Del objetivo: grabar una web del
 * alcance y analizar sus artefactos (binarios, APK, apps JS) puestos en una carpeta por programa; ahí una clave
 * filtrada es un hallazgo y el modelo la ve. Del operador: la captura HAR (su navegación), las vistas de evidencia
 * (pueden venir de esa captura), exportar e importar evidencia, y cualquier archivo si la carpeta del proyecto es
 * su carpeta personal (carpetaDelOperador).
 */
export function procedenciaRea(context: Pick<ReaContexto, "cwd">, tool: string): "objetivo" | "local" {
  if (origenDeHerramienta(tool) !== "objetivo") return "local";
  return POR_NOMBRE.get(tool)?.clase === "web" || !carpetaDelOperador(context.cwd) ? "objetivo" : "local";
}

export function reaSalida(context: ReaContexto, tool: string, result: unknown): ToolResult {
  const raw = JSON.stringify(result, null, 1) ?? "null";
  const procedencia = procedenciaRea(context, tool);
  // Lo del objetivo va tal cual (las trazas lo tapan); lo del operador, tapado por formato antes de mostrarse.
  const tapar = procedencia === "objetivo" ? (texto: string) => texto : (texto: string) => redactSecrets(texto);
  const isError = record(result) && result.isError === true;
  const texts = record(result) && Array.isArray(result.content) ? result.content.filter((item: unknown) => record(item) && item.type === "text" && typeof item.text === "string").map((item: { text: string }) => item.text) : [];
  const body = texts.join("\n") || (record(result) && result.structuredContent !== undefined ? JSON.stringify(result.structuredContent, null, 1) : raw);
  let parsed: unknown = record(result) ? result.structuredContent : undefined;
  if (parsed === undefined) try { parsed = JSON.parse(texts[0] ?? ""); } catch { parsed = undefined; }
  // Del operador: el artefacto que puede leer el modelo va con los secretos tapados; el crudo, aparte, para él.
  const clean = tapar(raw);
  const artifact = context.artifacts.put(clean, "application/json", `rea:${tool}`);
  const operator = clean !== raw ? context.artifacts.put(raw, "application/json", `rea:${tool}:operador`) : undefined;
  const ids = [...evidencias(parsed ?? result)];
  const failure = isError ? errorDe(parsed) : undefined;
  const preview = tapar(body);
  // La primera línea es la que muestra la TUI si falla: la causa va adelante.
  const lines = [
    ...(isError ? [`Falló: ${failure ?? (tapar(texts[0] ?? "").replace(/\s+/g, " ").trim().slice(0, 300) || "sin detalle (está en el artefacto)")}`] : []),
    `REA ${tool}: ${isError ? "error" : "listo"}${ids.length ? ` · evidencia ${ids.join(", ")}` : ""} · completo en ${artifact.hash} (${raw.length} caracteres).`,
    ...(operator ? ["Había valores con forma de secreto: van tapados; los completos quedan en un artefacto aparte para el operador."] : []),
    preview.length > EXTRACTO ? `Extracto (${EXTRACTO} de ${preview.length} caracteres; el resto con artifact_read y filter, o inspect_analysis_view con el id de evidencia):\n${preview.slice(0, EXTRACTO)}…` : preview,
    ...(isError ? [] : ["Para planificar con esto: deep_reason con artifacts [ese hash] y una pregunta concreta."]),
  ];
  context.event?.("rea.llamada", { herramienta: tool, error: isError, artefacto: artifact.hash, evidencia: ids });
  return {
    text: lines.join("\n"),
    isError,
    // Para la TUI: la línea de la acción muestra esto, en este orden; entra en 80 columnas (los secretos, al final).
    details: { ...(ids.length ? { evidencia: ids.length } : {}), artefacto: artifact.hash, ...(operator ? { secretos: operator.hash } : {}) },
    procedencia,
  };
}

/**
 * Proxy local por el que sale el Chromium de REA (el envoltorio de la caja no arranca sin él). El navegador
 * propio de Orobas intercepta cada pedido; el de REA no, así que acá se corta por host: CONNECT (HTTPS y
 * WebSocket) y URLs absolutas (HTTP) sólo hacia el alcance, sin señuelos marcados y con cupo de peticiones.
 * Lo de terceros que cargue la página (analítica, CDNs) no sale. No abre TLS: no ve rutas ni cuerpos.
 */
export class ProxyAlcance {
  private server?: Server;
  private ready?: Promise<string>;
  private readonly sockets = new Set<Socket>();
  /** Hosts cortados desde la última vez que se preguntó, con cuántas veces. */
  private readonly cortados = new Map<string, number>();
  /** Devuelve el motivo para no dejar pasar esa URL, o undefined si pasa. */
  private readonly motivo: (url: string) => string | undefined;

  constructor(motivo: (url: string) => string | undefined) { this.motivo = motivo; }

  private cortar(host: string): void { this.cortados.set(host, (this.cortados.get(host) ?? 0) + 1); }

  /** Lo cortado desde la última consulta (y lo olvida). */
  vaciar(): Array<[string, number]> {
    const items = [...this.cortados.entries()];
    this.cortados.clear();
    return items;
  }

  /** Arranca (una sola vez) y devuelve la URL del proxy. */
  url(): Promise<string> {
    this.ready ??= new Promise((done, fail) => {
      const server = createServer((req, res) => {
        // HTTP plano: el navegador manda la URL absoluta.
        let target: URL;
        try { target = new URL(req.url ?? ""); } catch { res.writeHead(400).end(); return; }
        if (target.protocol !== "http:" || this.motivo(target.href)) { this.cortar(target.host); res.writeHead(403, { "content-type": "text/plain" }).end("fuera del alcance de la sesión\n"); return; }
        const headers = { ...req.headers };
        delete headers["proxy-connection"];
        delete headers["proxy-authorization"];
        const upstream = httpRequest({ host: target.hostname, port: target.port || 80, method: req.method, path: `${target.pathname}${target.search}`, headers }, (answer) => {
          res.writeHead(answer.statusCode ?? 502, answer.headers);
          answer.pipe(res);
        });
        upstream.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end(); });
        req.pipe(upstream);
      });
      server.on("connect", (req, client: Socket, head: Buffer) => {
        this.sockets.add(client);
        client.on("close", () => this.sockets.delete(client));
        client.on("error", () => client.destroy());
        const match = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(req.url ?? "");
        const host = match?.[1];
        const port = Number(match?.[2]);
        if (!host || !(port > 0 && port < 65536) || this.motivo(`https://${host.includes(":") ? `[${host}]` : host}:${port}/`)) {
          if (host) this.cortar(host);
          client.end("HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\n\r\nfuera del alcance de la sesión\n");
          return;
        }
        const upstream = connect(port, host, () => {
          client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          if (head.length) upstream.write(head);
          upstream.pipe(client);
          client.pipe(upstream);
        });
        this.sockets.add(upstream);
        upstream.on("close", () => { this.sockets.delete(upstream); client.destroy(); });
        upstream.on("error", () => { if (!client.destroyed) client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); });
      });
      server.on("error", fail);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        done(`http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`);
      });
      server.unref();
      this.server = server;
    });
    return this.ready;
  }

  close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    const server = this.server;
    return new Promise((done) => (server ? server.close(() => done()) : done()));
  }
}

/** El motivo para no dejar salir al navegador de REA hacia esa URL, con las mismas reglas que la web viva. */
function motivoWeb(context: ReaContexto, url: string): string | undefined {
  try {
    urlEnAlcance(context, url, "proxy");
    if (context.http?.remaining() === 0) return "tope de peticiones";
    return undefined;
  } catch (error) {
    return (error as Error).message;
  }
}

/** ¿Está REA en esta imagen? */
export const reaInstalado = (entrada: string = REA.entrada) => existsSync(entrada);

/** REA usable en esta sesión: dentro de la caja y con la imagen que lo trae. */
export const reaDisponible = (inside: boolean = enCaja()) => inside && reaInstalado();

/** El servidor incorporado, o nada fuera de la caja (o en una caja vieja sin REA: /toolbox lo dice). */
export function reaIncorporado(context: ReaContexto, opciones: ReaOpciones = {}): McpIncorporado | undefined {
  if (!(opciones.enCaja ?? enCaja())) return undefined;
  const server = opciones.server ?? (reaInstalado() ? { command: process.execPath, args: [REA.entrada, "mcp"], env: existsSync(REA.apktool) ? { REA_APKTOOL_COMMAND: REA.apktool } : {} } : undefined);
  if (!server) return undefined;
  // Las variables REA_* del contenedor (límites, un jadx-headless-mcp que agregue el operador) sí pasan.
  const propias = Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => /^REA_/.test(entry[0]) && typeof entry[1] === "string"));
  // Corre en la carpeta del proyecto y sin heredar el entorno: ni claves de plataformas ni variables del operador.
  const config: McpServerConfig = { ...server, env: { ...propias, ...server.env }, cwd: context.cwd, entornoMinimo: true };
  const proxy = new ProxyAlcance((url) => motivoWeb(context, url));
  return {
    config,
    resumen: t(`REA ${REA.version} · incorporado en la caja · arranca al primer uso`, `REA ${REA.version} · built into the box · starts on first use`),
    oferta: ofertaRea(),
    aviso: AVISO,
    revisar: (tool, args) => reaRevisar(context, tool, args),
    salida: (tool, result) => {
      const out = reaSalida(context, tool, result);
      const cortados = proxy.vaciar();
      if (!cortados.length) return out;
      const lista = cortados.slice(0, 8).map(([host, n]) => `${host} (${n})`).join(", ");
      context.event?.("rea.proxy", { herramienta: tool, cortados: Object.fromEntries(cortados) });
      return { ...out, text: `${out.text}\nEl proxy de alcance cortó conexiones del navegador de REA a hosts fuera del alcance: ${lista}${cortados.length > 8 ? ", …" : ""}. No salieron; si alguno es del programa, que el operador lo agregue.` };
    },
    // El Chromium de REA sale por el proxy de alcance: el envoltorio de la caja lo toma de esta variable.
    preparar: async () => { config.env = { ...config.env, CYBER_REA_PROXY: await proxy.url() }; },
    cerrar: () => proxy.close(),
  };
}

/** REA se ejecuta sólo en la caja y sólo como el incorporado (con su política): una entrada del operador que lo arranque no corre. */
export function reaBloqueo(name: string, config: McpServerConfig, inside: boolean = enCaja()): string | undefined {
  const line = [config.command, ...(config.args ?? [])].join(" ");
  const isRea = name.toLowerCase() === "rea" || /\brea-agents\b/i.test(line) || /(^|[/\\])rea(\.mjs)?(\s|$)/.test(line);
  if (!isRea) return undefined;
  return inside
    ? t("En la caja, REA corre sólo como el incorporado «rea» (con la política de rutas y alcance): no se registra aparte.", "In the box, REA only runs as the built-in “rea” (with the path and scope policy): it is not registered separately.")
    : t("REA corre sólo dentro de la caja de Orobas (el contenedor del proyecto): en esta máquina no se ejecuta.", "REA only runs inside the Orobas box (the project container): it does not run on this machine.");
}

/** Para /toolbox: con versión adentro de la caja, «sólo en la caja» afuera. Líneas cortas (entran en 80 columnas). */
export function reaStatus(options: { enCaja?: boolean; instalado?: boolean } = {}): string[] {
  const inside = options.enCaja ?? enCaja();
  if (!inside) return [`rea        · ${t("sólo en la caja (el contenedor de Orobas); acá no se ofrece", "box only (the Orobas container); not offered here")}`];
  if (!(options.instalado ?? reaInstalado())) return [`rea        ✗ ${t("falta en esta imagen · cyber --actualizar", "missing from this image · cyber --actualizar")}`];
  return [
    `rea        ✓ ${REA.paquete} ${REA.version} · ${t("arranca al primer uso", "starts on first use")}`,
    `             ${t("JS (compilado, fuente o bajado), APK, binarios, HAR y web", "JS (built, source or pulled), APKs, binaries, HAR and web")}`,
  ];
}
