// Caja de herramientas de red: binarios conocidos envueltos con argumentos tipados, sin shell,
// alcance validado en cada destino, salida cruda como artefacto y resumen para el modelo.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { encode } from "@toon-format/toon";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { exec, which } from "./exec.ts";
import { CATEGORIES, type Coverage } from "./coverage.ts";
import { HttpClient, summarize, type HttpExchange, isDestructive } from "./http.ts";
import { digestHeader } from "./probes.ts";
import { decide, type Scope } from "./scope.ts";
import { movilStatus } from "./instalar-herramientas.ts";

export interface NetContext {
  artifacts: Artifacts;
  scope: () => Scope | undefined;
  http: HttpClient;
  /** Cobertura de la evaluación (lista de verificación y mapa de superficie). */
  coverage?: Coverage;
  protegerTexto?: (texto: string) => string;
  sessionId?: string;
  /** Con el grafo de hechos: la línea de lo que falta probar que se agrega al final de coverage_view. */
  superficie?: () => string[];
}

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const list = (items: object) => ({ type: "array", items });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });

/** Todos los destinos deben estar dentro del alcance y ninguno puede ser un señuelo marcado; con uno así, no se ejecuta nada. */
function authorizeAll(scope: Scope | undefined, targets: string[], http?: HttpClient): void {
  if (!targets.length) throw new Error("Sin destinos");
  for (const target of targets) {
    const decision = decide(scope, target);
    if (!decision.allowed) throw new Error(`Fuera del alcance: ${target}. ${decision.reason}`);
    http?.refuseDecoy(target);
  }
}

/** Un valor que va como argumento no puede empezar con «-»: evita inyectar opciones. */
function plain(value: string, what: string): string {
  if (!value || value.startsWith("-") || /[\s\0]/.test(value)) throw new Error(`${what} inválido: «${value}»`);
  return value;
}

/**
 * Cabecera «Nombre: valor» para el -H de un escáner. Va como un argumento propio (sin shell): puede llevar
 * espacios («Authorization: Bearer …», «Cookie: a=1; b=2»), pero no saltos de línea ni un nombre que empiece con «-».
 */
function header(value: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9!#$%&'*+.^_`|~][A-Za-z0-9!#$%&'*+.^_`|~-]*:[^\r\n\0]*$/.test(value)) throw new Error(`header inválido: «${String(value).slice(0, 80)}». Va «Nombre: valor», uno por elemento.`);
  return value;
}

/** Cabeceras del escáner: cada una como -H (las credenciales que el modelo ve o un marcador, que se repone si los destinos están en el alcance). */
const headerArgs = (headers: unknown): string[] => (Array.isArray(headers) ? headers : []).flatMap((value) => ["-H", header(value)]);
/** Siempre después de las cabeceras de la herramienta: las fijas del operador ganan. */
const fixedHeaderArgs = (http: HttpClient): string[] => Object.entries(http.cabecerasPrograma?.() ?? {}).flatMap(([name, value]) => ["-H", header(`${name}: ${value}`)]);
/** Con cabeceras fijas, un escáner no sigue redirecciones ni rastrea fuera del origen: no las lleva a otro host. */
const hayFijas = (http: HttpClient): boolean => Object.keys(http.cabecerasPrograma?.() ?? {}).length > 0;
const scannerHeaderArgs = (http: HttpClient, headers: unknown): string[] => {
  const fijas = new Set(Object.keys(http.cabecerasPrograma?.() ?? {}).map((name) => name.toLowerCase()));
  return headerArgs((Array.isArray(headers) ? headers : []).filter((linea) => !fijas.has(String(linea).split(":", 1)[0]!.trim().toLowerCase())));
};
const HEADERS = list(str({ description: "Cabeceras «Nombre: valor» (Cookie, Authorization…) para ir autenticado; una por elemento" }));

interface Runner {
  binary: string;
  install: string;
  /** Argumentos para comprobar que arranca (que exista el archivo no alcanza). */
  check: string[];
}

const pkg = (name: string) => `${process.platform === "darwin" ? "brew install" : "sudo pacman -S"} ${name}`;
export const BINARIES: Record<string, Runner> = {
  nmap: { binary: "nmap", get install() { return pkg("nmap"); }, check: ["--version"] },
  ffuf: { binary: "ffuf", get install() { return pkg("ffuf"); }, check: ["-V"] },
  sqlmap: { binary: "sqlmap", get install() { return pkg("sqlmap"); }, check: ["--version"] },
  httpx: { binary: "httpx", install: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", check: ["-version"] },
  nuclei: { binary: "nuclei", install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", check: ["-version"] },
  subfinder: { binary: "subfinder", install: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", check: ["-version"] },
  katana: { binary: "katana", install: "go install github.com/projectdiscovery/katana/cmd/katana@latest", check: ["-version"] },
  dnsx: { binary: "dnsx", install: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", check: ["-version"] },
};

/**
 * ¿Arranca? Un binario instalado puede estar roto (una biblioteca que falta después de una
 * actualización a medias). Devuelve el motivo si no arranca. Se comprueba una vez por proceso.
 */
const health = new Map<string, string | undefined>();
export function broken(name: string): string | undefined {
  const runner = BINARIES[name];
  const path = runner && which(runner.binary);
  if (!runner || !path) return undefined;
  if (health.has(path)) return health.get(path);
  const run = spawnSync(path, runner.check, { encoding: "utf8", timeout: 15_000, stdio: ["ignore", "pipe", "pipe"] });
  const output = `${run.stderr ?? ""}\n${run.stdout ?? ""}`;
  const library = /error while loading shared libraries: (\S+?):/.exec(output)?.[1];
  let reason: string | undefined;
  if (library) reason = `falta la biblioteca ${library} (el sistema quedó actualizado a medias; se arregla actualizándolo completo: ${process.platform === "darwin" ? "brew upgrade" : "sudo pacman -Syu"})`;
  else if (run.error) reason = `no se pudo ejecutar (${(run.error as NodeJS.ErrnoException).code ?? run.error.message})`;
  else if (run.status === 127 || run.status === 126 || run.signal) reason = `termina con ${run.signal ?? `código ${run.status}`}: ${output.trim().split("\n")[0]?.slice(0, 120) ?? ""}`;
  health.set(path, reason);
  return reason;
}

export function toolboxStatus(): string[] {
  return [
    ...Object.entries(BINARIES).map(([name, runner]) => {
      const path = which(runner.binary);
      const failure = path ? broken(name) : undefined;
      return `${name.padEnd(10)} ${!path ? `✗ no instalado · ${runner.install}` : failure ? `✗ instalado pero no arranca: ${failure}` : `✓ ${path}`}`;
    }),
    // Apps móviles (apk_analyze): sólo en la caja; en el host no cuentan como faltantes.
    ...movilStatus(),
  ];
}

function need(name: keyof typeof BINARIES): string {
  const runner = BINARIES[name]!;
  if (!which(runner.binary)) throw new Error(`${name} no está instalado. Instalarlo: ${runner.install}`);
  const failure = broken(name);
  if (failure) throw new Error(`${name} está instalado pero no arranca en esta máquina: ${failure}. Es un problema de la herramienta, no del objetivo: no saques conclusiones del objetivo por esto, avisale al operador y seguí con otra herramienta.`);
  return runner.binary;
}

/**
 * Conducta para un escáner externo: no corre si el programa no lo habilitó o si ya no queda cupo de peticiones,
 * y hereda el ritmo y el User-Agent de la sesión. Sus peticiones no se pueden contar una por una (salvo ffuf).
 */
function conductFor(context: NetContext, name: string, ownRate = 20): { rate: number; agent: string } {
  const conduct = context.http.conduct();
  if (!conduct.scanners) throw new Error(`${name} está apagado: el alcance viene del programa ${conduct.program} y muchos programas prohíben escáneres automáticos. Si su política los permite, el operador los habilita con /escaneres si.`);
  if (context.http.remaining() === 0) throw new Error(`Tope de peticiones alcanzado (${conduct.limit}). ${name} no corre.`);
  return { rate: Math.max(1, Math.floor(Math.min(ownRate, conduct.rate ?? ownRate))), agent: conduct.userAgent };
}

/** Ejecuta, guarda stdout/stderr completos como artefacto y devuelve lo necesario para resumir. */
async function run(context: NetContext, label: string, argv: string[], signal: AbortSignal, timeoutMs: number, stdin?: string) {
  const result = await exec({ argv, signal, timeoutMs, stdin });
  const artifact = context.artifacts.put(JSON.stringify({ argv: result.argv, exitCode: result.exitCode, timedOut: result.timedOut, stdout: result.stdout, stderr: result.stderr }, null, 1), "application/json", label);
  const status = result.cancelled ? "cancelado" : result.timedOut ? `cortado por tiempo (${Math.round(timeoutMs / 1000)} s)` : `salida ${result.exitCode}`;
  return { ...result, artifact: artifact.hash, status };
}

/**
 * Parser mínimo del XML de nmap: host (dirección), nombre, y los puertos abiertos con servicio, producto y versión.
 * Lo usan nmap_scan y el grafo de hechos (src/grafo-alimentar.ts), que lo lee del artefacto.
 */
export function parseNmapXml(xml: string): Array<{ host: string; nombre?: string; puertos: Array<{ puerto: string; proto: string; servicio: string; producto: string; version: string }> }> {
  const hosts: Array<{ host: string; nombre?: string; puertos: Array<{ puerto: string; proto: string; servicio: string; producto: string; version: string }> }> = [];
  for (const block of xml.split("<host ").slice(1)) {
    const address = /<address addr="([^"]+)"/.exec(block)?.[1] ?? "?";
    const name = /<hostname name="([^"]+)"/.exec(block)?.[1];
    // Cada puerto por separado: un solo patrón con el servicio opcional después de un tramo perezoso lo salteaba
    // siempre (servicio y versión salían vacíos).
    const puertos = [...block.matchAll(/<port protocol="(\w+)" portid="(\d+)"[^>]*>([\s\S]*?)<\/port>/g)].filter((match) => /<state state="open"/.test(match[3]!)).map((match) => {
      const servicio = /<service\b[^>]*>/.exec(match[3]!)?.[0] ?? "";
      const atributo = (nombre: string) => new RegExp(`\\b${nombre}="([^"]*)"`).exec(servicio)?.[1] ?? "";
      return { puerto: match[2]!, proto: match[1]!, servicio: atributo("name"), producto: atributo("product"), version: atributo("version") };
    });
    hosts.push({ host: address, ...(name ? { nombre: name } : {}), puertos });
  }
  return hosts;
}

export const jsonLines = (text: string): any[] =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("{"))
    .flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });

function finish(text: string, details: Record<string, unknown>): ToolResult {
  return { text, details };
}

/** Tope por defecto de un escáner externo. Mientras corre, el agente no atiende al operador: que sea corto. */
export const SCAN_SECONDS = 300;

export function createNetTools(context: NetContext): Tool[] {
  const scope = context.scope;

  const httpRequest: Tool = {
    name: "http_request",
    label: "HTTP",
    description:
      "Envía una petición HTTP a un destino dentro del alcance. Guarda request y response completos como artefacto y devuelve un resumen. " +
      "Usá identity para enviar como una identidad de prueba configurada por el operador (sus credenciales no se muestran). Las redirecciones no se siguen salvo followRedirects.",
    parameters: obj(
      {
        url: str(),
        method: str({ enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] }),
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: str({ maxLength: 20000 }),
        multipart: {
          type: "array", maxItems: 20,
          description: "Cuerpo multipart/form-data en vez de body: campos de texto y archivos (filename, contentType y el contenido en value o, si es binario, en base64). El nombre del archivo se envía tal cual. Para probar subidas completas está upload_probe.",
          items: obj({ name: str(), filename: str({ maxLength: 300 }), contentType: str({ maxLength: 200 }), value: str({ maxLength: 20000 }), base64: str({ maxLength: 2_000_000 }) }, ["name"]),
        },
        identity: str({ description: "Nombre de identidad configurada" }),
        followRedirects: { type: "boolean" },
        timeoutSec: int({ minimum: 1, maximum: 120, description: "Cuánto esperar la respuesta; por defecto 30. Subilo para un backend lento." }),
        digest: { ...obj({ username: str(), password: str(), ha1: str({ description: "HA1 ya calculado. Un archivo htdigest guarda HA1, no la contraseña: con ha1 vacío se prueba el secreto vacío." }) }, ["username"]), description: "Responde un desafío HTTP Digest: envía la petición, lee el desafío del 401 y la repite firmada. Cuenta dos peticiones. Pasá password, o ha1 si querés fijar el secreto guardado." },
        allowDestructive: { type: "boolean", description: "Permitir una operación que borra o vacía datos (DELETE, rutas delete/clear/reset). La URL tiene que llevar un id que haya devuelto una creación tuya, salvo que el operador haya dado consentimiento de borrado ajeno (/consent borrar-ajeno)." },
        bodyChars: int({ minimum: 0, maximum: 8000, description: "Caracteres del cuerpo en el resumen (por defecto 1500)" }),
      },
      ["url"],
    ),
    parallel: true,
    execute: async (params) => {
      if (params.timeoutSec) params = { ...params, timeoutMs: params.timeoutSec * 1000 };
      // La guarda de borrado vive en el cliente HTTP (HttpClient.guardDestructive): ninguna vía la esquiva.
      let exchange = await context.http.send(params, params.identity);
      if (params.digest) {
        const challenge = exchange.response?.headers["www-authenticate"];
        if (!/^digest/i.test(challenge ?? "")) {
          return finish(`${summarize(exchange, params.bodyChars, context.protegerTexto)}\nSin desafío Digest en la respuesta: no se repitió la petición.\n${counter()}`, { id: exchange.id, status: exchange.response?.status ?? exchange.error, artefacto: exchange.artifact });
        }
        const header = digestHeader(challenge!, params.method ?? "GET", params.url, params.digest.username, params.digest.password ?? "", params.digest.ha1);
        exchange = await context.http.send({ ...params, headers: { ...params.headers, authorization: header } }, params.identity);
      }
      return finish(`${summarize(exchange, params.bodyChars, context.protegerTexto)}\n${counter()}`, { id: exchange.id, status: exchange.response?.status ?? exchange.error, artefacto: exchange.artifact });
    },
  };

  const counter = () => {
    const remaining = context.http.remaining();
    return `peticiones HTTP: ${context.http.count}${remaining !== undefined ? ` · quedan ${remaining}` : ""}`;
  };

  const probeLine = (exchange: HttpExchange) => {
    const response = exchange.response;
    if (!response) return `${exchange.id}  ${exchange.request.method.padEnd(7)} ${exchange.request.url}  ERROR ${exchange.error}`;
    const type = (response.headers["content-type"] ?? "").split(";")[0];
    const extra = response.headers.location ? `  → ${response.headers.location.slice(0, 80)}` : response.headers.allow ? `  allow: ${response.headers.allow}` : "";
    // Un cuerpo corto que no es HTML va en la misma línea: ahorra un artifact_read por petición.
    const body = response.bodyEncoding !== "base64" && !/html/i.test(type ?? "") ? response.body.replace(/\s+/g, " ").trim() : "";
    const inline = body && body.length <= 240 ? `  «${body}»` : body ? `  «${body.slice(0, 160)}…»` : "";
    return `${exchange.id}  ${exchange.request.method.padEnd(7)} ${exchange.request.url}  ${response.status}  ${response.bodyBytes} B  ${type}${extra}${exchange.decoy ? `  ⚠ SEÑUELO PROBABLE (${exchange.decoy.join("; ")}): no sigas sus rutas ni uses lo que entrega` : inline}`;
  };

  const httpProbe: Tool = {
    name: "http_probe",
    label: "Sondeo HTTP",
    description:
      "Sondea muchas URLs o varios métodos en una sola llamada y devuelve una tabla compacta (id, método, URL, código, tamaño, tipo, location y el arranque del cuerpo si no es HTML). " +
      "Sirve para mapear rutas, probar rutas habituales no enlazadas y para saber qué métodos de escritura acepta un recurso antes de darlo por sólo lectura. " +
      "Cada combinación URL × método cuenta como una petición; los cuerpos quedan en artefactos (ampliá con artifact_read).",
    parameters: obj(
      {
        urls: list(str()),
        methods: list(str({ enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] })),
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: str({ maxLength: 5000, description: "Cuerpo para los métodos con cuerpo" }),
        identity: str({ description: "Nombre de identidad configurada" }),
        timeoutSec: int({ minimum: 1, maximum: 120, description: "Cuánto esperar cada respuesta; por defecto 30" }),
        allowLogout: { type: "boolean", description: "Permitir rutas de cierre de sesión con credenciales" },
        allowDestructive: { type: "boolean", description: "Incluir operaciones que borran o vacían datos (DELETE, rutas delete/clear/reset). Sólo se envían sobre recursos creados en esta sesión o, con consentimiento de borrado ajeno, sobre cualquier destino del alcance; las demás se omiten." },
      },
      ["urls"],
    ),
    parallel: true,
    execute: async (params) => {
      const methods: string[] = params.methods?.length ? params.methods : ["GET"];
      const combos: Array<{ url: string; method: string }> = params.urls.flatMap((url: string) => methods.map((method) => ({ url, method })));
      if (!combos.length) throw new Error("Sin URLs");
      if (combos.length > 60) throw new Error(`Son ${combos.length} peticiones; el máximo por llamada es 60`);
      // Con credenciales, una ruta de cierre de sesión en la lista invalida el token y arruina el resto de la evaluación.
      const hasAuth = !!params.identity || Object.keys(params.headers ?? {}).some((key) => /^(authorization|cookie)$/i.test(key));
      const risky = combos.filter((combo) => /\/(logout|salir|signout|sign-out|cerrar[-_]?sesion|desconectar)(\/|\?|$)/i.test(combo.url));
      if (hasAuth && risky.length && !params.allowLogout) {
        throw new Error(`La lista incluye rutas que cierran la sesión (${risky.map((combo) => combo.url).join(", ")}) y va con credenciales: sondealas sin credenciales o aparte con allowLogout.`);
      }
      // Lo que borra o vacía datos no se sondea a ciegas: sólo sobre recursos creados en esta sesión y
      // con allowDestructive; el resto se omite y se dice, en vez de frenar toda la lista.
      // Con consentimiento de borrado ajeno vigente, lo destructivo deja de exigir que el recurso sea
      // propio: el alcance y el consent ya lo autorizaron.
      const anyOwner = !!params.allowDestructive && !!context.http.consent?.()?.has("borrar-ajeno");
      const skipped = combos.filter((combo) => isDestructive(combo.method, combo.url) && !(params.allowDestructive && (anyOwner || context.http.owns(combo.url))));
      const allowed = combos.filter((combo) => !skipped.includes(combo));
      if (!allowed.length) throw new Error(`La lista sólo tiene rutas que borran o vacían datos (${skipped.slice(0, 5).map((combo) => `${combo.method} ${combo.url}`).join(", ")}) sobre recursos que no creaste en esta sesión: no se sondean. Creá un recurso propio y probá sobre ése con allowDestructive, o pedile al operador consentimiento de borrado ajeno.`);
      const exchanges: HttpExchange[] = [];
      // De a cuatro: suficiente para ir rápido sin golpear al objetivo.
      for (let i = 0; i < allowed.length; i += 4) {
        exchanges.push(...(await Promise.all(allowed.slice(i, i + 4).map((combo) => context.http.send({ url: combo.url, method: combo.method, headers: params.headers, body: combo.method === "GET" || combo.method === "HEAD" ? undefined : params.body, allowDestructive: params.allowDestructive, ...(params.timeoutSec && { timeoutMs: params.timeoutSec * 1000 }) }, params.identity)))));
      }
      const ok = exchanges.filter((exchange) => exchange.response && exchange.response.status < 400).length;
      const note = skipped.length ? [`omitidas ${skipped.length} combinaciones que borran o vacían datos sobre recursos que no creaste (${skipped.slice(0, 4).map((combo) => `${combo.method} ${combo.url}`).join(", ")}${skipped.length > 4 ? ", …" : ""}): creá el recurso y probá sobre el tuyo`] : [];
      return finish([...exchanges.map(probeLine), ...note, counter()].join("\n"), { peticiones: exchanges.length, respondieron: ok, omitidas: skipped.length });
    },
  };

  const coverageMark: Tool = {
    name: "coverage_mark",
    label: "Marcar cobertura",
    description: `Marca una categoría de la evaluación como cubierta (diciendo qué probaste), limitada (probaste hasta donde se pudo: decí qué faltó y por qué) o no aplica (diciendo por qué). Categorías: ${Object.keys(CATEGORIES).join(", ")}.`,
    parameters: obj({ category: str(), state: str({ enum: ["cubierta", "limitada", "no aplica", "pendiente"] }), note: str({ maxLength: 600 }) }, ["category", "state", "note"]),
    execute: (params) => {
      if (!context.coverage || !context.sessionId) throw new Error("Sin cobertura en esta sesión");
      const mark = context.coverage.mark(context.sessionId, params.category, params.state, params.note);
      return finish(`${mark.category}: ${mark.state}. Pendientes: ${context.coverage.pending(context.sessionId).join(", ") || "ninguna"}.`, { categoria: mark.category, estado: mark.state });
    },
  };

  const coverageView: Tool = {
    name: "coverage_view",
    label: "Ver cobertura",
    description: "Lista de verificación por categoría, peticiones usadas y mapa de superficie (rutas vistas con métodos probados y códigos). Consultalo antes de resumir.",
    parameters: obj({}, []),
    parallel: true,
    replay: "safe",
    execute: () => {
      if (!context.coverage || !context.sessionId) throw new Error("Sin cobertura en esta sesión");
      // Con el grafo, una línea al final dice cuántas pruebas concretas faltan y dónde verlas. El listado de rutas
      // se queda: reemplazarlo por un resumen ahorraba contexto pero le sacaba al agente lo que no está en el grafo
      // como pendiente (la ruta de login con sus campos, por ejemplo); ver bench/RESULTADOS.md, grafo de hechos.
      const texto = [...context.coverage.view(context.sessionId), ...(context.superficie?.() ?? [])];
      return finish(texto.join("\n"), { pendientes: context.coverage.pending(context.sessionId).length });
    },
  };

  const identities: Tool = {
    name: "http_identities",
    label: "Identidades",
    description: "Lista las identidades de prueba disponibles para http_request (las configura el operador con /identity).",
    parameters: obj({}, []),
    parallel: true,
    replay: "safe",
    execute: () => {
      const names = context.http.identityNames();
      return finish(names.length ? names.join(", ") : "No hay identidades configuradas. El operador las agrega con /identity <nombre> <cabecera>: <valor>.", { identidades: names.length });
    },
  };

  const nmap: Tool = {
    name: "nmap_scan",
    label: "nmap",
    description: "Escaneo de puertos y servicios con nmap sobre hosts dentro del alcance. Por defecto los 1000 puertos más comunes con detección de versión (-sV), ritmo moderado (-T3).",
    parameters: obj(
      {
        targets: list(str()),
        ports: str({ description: "p. ej. 80,443 o 1-1024; vacío = top 1000" }),
        versionDetection: { type: "boolean" },
        scripts: str({ description: "Scripts NSE por categoría, p. ej. default o vuln; vacío = ninguno" }),
        timeoutSec: int({ minimum: 10, maximum: 3600 }),
      },
      ["targets"],
    ),
    execute: async (params, signal) => {
      authorizeAll(scope(), params.targets, context.http);
      if (Object.keys(context.http.cabecerasPrograma?.() ?? {}).length && (params.versionDetection !== false || params.scripts))
        throw new Error("nmap no puede garantizar cabeceras fijas en sus sondas de versión ni en scripts NSE. Avisale al operador; usá nmap sólo para puertos con versionDetection:false y sin scripts, u otra herramienta HTTP.");
      const conduct = conductFor(context, "nmap", 1000);
      const argv = [need("nmap"), "-T3", "-Pn", "--open", "-oX", "-"];
      if (context.http.conduct().rate) argv.push("--max-rate", String(conduct.rate));
      if (params.scripts) argv.push("--script-args", `http.useragent=${conduct.agent}`);
      if (params.versionDetection !== false) argv.push("-sV");
      if (params.ports) argv.push("-p", plain(params.ports, "ports"));
      if (params.scripts) argv.push("--script", plain(params.scripts, "scripts"));
      argv.push(...params.targets.map((target: string) => plain(target, "target")));
      const result = await run(context, "nmap", argv, signal, (params.timeoutSec ?? SCAN_SECONDS) * 1000);
      const hosts = parseNmapXml(result.stdout).map(({ host, nombre, puertos }) => ({ host: nombre ? `${nombre} (${host})` : host, puertos: puertos.map(({ puerto, proto, servicio, producto, version }) => ({ puerto, proto, servicio, version: [producto, version].filter(Boolean).join(" ") })) }));
      const text = hosts.length ? encode({ hosts }) : `Sin hosts con puertos abiertos. ${result.stderr.slice(0, 300)}`;
      return finish(`${text}\n${result.status} · artefacto ${result.artifact}`, { hosts: hosts.length, puertos: hosts.reduce((sum, host) => sum + host.puertos.length, 0), artefacto: result.artifact });
    },
  };

  const ffuf: Tool = {
    name: "ffuf_fuzz",
    label: "ffuf",
    description: "Descubre rutas o parámetros con ffuf. La URL lleva la palabra FUZZ donde va cada entrada de la lista. Ritmo acotado (por defecto 20 req/s). Filtra por códigos de estado.",
    parameters: obj(
      {
        url: str({ description: "URL con FUZZ, dentro del alcance" }),
        wordlist: str({ description: "Ruta a la lista de palabras" }),
        words: list(str({ description: "Lista inline, alternativa a wordlist (máx. 2000)" })),
        matchCodes: str({ description: "p. ej. 200,204,301,302,307,401,403" }),
        rate: int({ minimum: 1, maximum: 100 }),
        extensions: str({ description: "p. ej. .php,.bak" }),
        headers: HEADERS,
        timeoutSec: int({ minimum: 10, maximum: 3600 }),
      },
      ["url"],
    ),
    execute: async (params, signal) => {
      if (!params.url.includes("FUZZ")) throw new Error("La URL debe contener FUZZ");
      authorizeAll(scope(), [params.url.replace("FUZZ", "fuzz")], context.http);
      const argv = [need("ffuf"), "-u", plain(params.url, "url"), "-of", "json", "-o", "/dev/stdout", "-s", "-rate", String(conductFor(context, "ffuf", params.rate ?? 20).rate), "-H", `User-Agent: ${context.http.conduct().userAgent}`, "-mc", plain(params.matchCodes ?? "200,204,301,302,307,401,403", "matchCodes")];
      let stdin: string | undefined;
      if (params.words?.length) {
        if (params.words.length > 2000) throw new Error("Máximo 2000 palabras inline");
        argv.push("-w", "-");
        stdin = params.words.join("\n");
      } else if (params.wordlist) argv.push("-w", plain(params.wordlist, "wordlist"));
      else throw new Error("Falta wordlist o words");
      if (params.extensions) argv.push("-e", plain(params.extensions, "extensions"));
      argv.push(...scannerHeaderArgs(context.http, params.headers), ...fixedHeaderArgs(context.http));
      const result = await run(context, "ffuf", argv, signal, (params.timeoutSec ?? SCAN_SECONDS) * 1000, stdin);
      // Cada palabra es una petición al objetivo: cuenta contra el tope como las propias.
      let sent = params.words?.length ?? 0;
      if (!sent && params.wordlist) {
        try {
          sent = readFileSync(params.wordlist, "utf8").split(/\r?\n/).filter(Boolean).length;
        } catch {}
      }
      if (params.extensions) sent *= 1 + String(params.extensions).split(",").filter(Boolean).length;
      context.http.count += sent;
      let hits: any[] = [];
      try {
        hits = JSON.parse(result.stdout.slice(result.stdout.indexOf("{"))).results ?? [];
      } catch {}
      const rows = hits.slice(0, 200).map((hit) => ({ url: hit.url, status: hit.status, bytes: hit.length, palabras: hit.words }));
      return finish(`${rows.length ? encode({ resultados: rows }) : "Sin coincidencias."}${hits.length > 200 ? `\n… ${hits.length - 200} más en el artefacto` : ""}\n${result.status} · artefacto ${result.artifact} · peticiones HTTP: ${context.http.count}${context.http.remaining() !== undefined ? ` · quedan ${context.http.remaining()}` : ""}`, { coincidencias: hits.length, artefacto: result.artifact });
    },
  };

  const sqlmap: Tool = {
    name: "sqlmap_scan",
    label: "sqlmap",
    description:
      "Comprueba inyección SQL en los parámetros de una URL o de un cuerpo con sqlmap en modo no interactivo, nivel y riesgo bajos (1/1), sin volcado de datos, ritmo acotado. " +
      "Devuelve qué parámetros marcó como inyectables y la técnica. Antes de llamarlo, confirmá con param_probe que hay un indicio; un resultado de sqlmap es candidato hasta verificarlo con una petición propia.",
    parameters: obj(
      {
        url: str({ description: "URL con los parámetros a probar, dentro del alcance" }),
        data: str({ description: "Cuerpo POST (form o JSON) cuando los parámetros van en el cuerpo", maxLength: 5000 }),
        params: str({ description: "Parámetros a probar, separados por coma; vacío = todos" }),
        headers: list(str({ description: "Cabeceras «Nombre: valor», p. ej. Authorization" })),
        level: int({ minimum: 1, maximum: 3 }),
        risk: int({ minimum: 1, maximum: 2 }),
        timeoutSec: int({ minimum: 30, maximum: 3600 }),
      },
      ["url"],
    ),
    execute: async (params, signal) => {
      authorizeAll(scope(), [params.url], context.http);
      const sqlmapConduct = conductFor(context, "sqlmap");
      const argv = [need("sqlmap"), "-u", plain(params.url, "url"), "--batch", "--disable-coloring", ...(hayFijas(context.http) ? ["--ignore-redirects"] : []), "--level", String(params.level ?? 1), "--risk", String(params.risk ?? 1), "--delay", String(Math.max(0.1, 1 / sqlmapConduct.rate)), "--threads", context.http.conduct().rate ? "1" : "2", "--user-agent", sqlmapConduct.agent, "--technique", "BEUST", "--flush-session", "--output-dir", "/tmp/elevate-sqlmap"];
      if (params.data) argv.push("--data", plain(params.data, "data"));
      if (params.params) argv.push("-p", plain(params.params, "params"));
      argv.push(...scannerHeaderArgs(context.http, params.headers), ...fixedHeaderArgs(context.http));
      const result = await run(context, "sqlmap", argv, signal, (params.timeoutSec ?? SCAN_SECONDS) * 1000);
      const out = result.stdout;
      const injectable = [...out.matchAll(/Parameter: ([^\n]+)\n[\s\S]*?Type: ([^\n]+)\n\s*Title: ([^\n]+)/g)].map((match) => `${match[1]!.trim()} · ${match[2]!.trim()} · ${match[3]!.trim()}`);
      const dbms = /back-end DBMS: ([^\n]+)/.exec(out)?.[1]?.trim();
      const notInjectable = /all tested parameters do not appear to be injectable/i.test(out);
      const lines = injectable.length ? [`Parámetros inyectables (${injectable.length}):`, ...injectable.map((item) => `  ${item}`), dbms ? `DBMS: ${dbms}` : ""] : [notInjectable ? "sqlmap no encontró inyección con este nivel y riesgo." : "Sin conclusión; mirá el artefacto."];
      return finish(`${lines.filter(Boolean).join("\n")}\n${result.status} · artefacto ${result.artifact}`, { inyectables: injectable.length, artefacto: result.artifact });
    },
  };

  const httpx: Tool = {
    name: "httpx_probe",
    label: "httpx",
    description: "Comprueba qué hosts responden HTTP/HTTPS y con qué título, estado, servidor y tecnologías (httpx de ProjectDiscovery).",
    parameters: obj({ targets: list(str()), headers: HEADERS, timeoutSec: int({ minimum: 10, maximum: 1800 }) }, ["targets"]),
    execute: async (params, signal) => {
      authorizeAll(scope(), params.targets, context.http);
      const argv = [need("httpx"), "-silent", "-json", "-title", "-status-code", "-tech-detect", "-server", "-rate-limit", String(conductFor(context, "httpx").rate), "-H", `User-Agent: ${context.http.conduct().userAgent}`, ...scannerHeaderArgs(context.http, params.headers), ...fixedHeaderArgs(context.http)];
      const result = await run(context, "httpx", argv, signal, (params.timeoutSec ?? SCAN_SECONDS) * 1000, params.targets.map((target: string) => plain(target, "target")).join("\n"));
      const rows = jsonLines(result.stdout).map((row) => ({ url: row.url, status: row.status_code, titulo: (row.title ?? "").slice(0, 60), servidor: row.webserver ?? "", tech: (row.tech ?? []).join("+") }));
      return finish(`${rows.length ? encode({ vivos: rows }) : "Ningún host respondió."}\n${result.status} · artefacto ${result.artifact}`, { vivos: rows.length, artefacto: result.artifact });
    },
  };

  const nuclei: Tool = {
    name: "nuclei_scan",
    label: "nuclei",
    description: "Corre plantillas de nuclei contra destinos dentro del alcance. Por defecto severidades media, alta y crítica y ritmo acotado. Un resultado de nuclei es un candidato, no un hallazgo verificado.",
    parameters: obj(
      {
        targets: list(str()),
        severity: str({ description: "p. ej. medium,high,critical" }),
        tags: str({ description: "Etiquetas de plantillas, acotadas a la tecnología que detectaste (p. ej. supabase,exposure). «cve» sola o tecnologías que no viste son miles de plantillas: no entran en el tiempo." }),
        templates: str({ description: "Ruta o id de plantillas" }),
        headers: HEADERS,
        timeoutSec: int({ minimum: 30, maximum: 3600, description: "Por defecto 300. Mientras corre no podés hacer otra cosa: subilo sólo si hace falta" }),
      },
      ["targets"],
    ),
    execute: async (params, signal) => {
      authorizeAll(scope(), params.targets, context.http);
      const argv = [need("nuclei"), "-silent", "-jsonl", ...(hayFijas(context.http) ? ["-disable-redirects"] : []), "-disable-update-check", "-rate-limit", String(conductFor(context, "nuclei").rate), "-H", `User-Agent: ${context.http.conduct().userAgent}`, "-severity", plain(params.severity ?? "medium,high,critical", "severity")];
      if (params.tags) argv.push("-tags", plain(params.tags, "tags"));
      if (params.templates) argv.push("-t", plain(params.templates, "templates"));
      argv.push(...scannerHeaderArgs(context.http, params.headers), ...fixedHeaderArgs(context.http));
      const result = await run(context, "nuclei", argv, signal, (params.timeoutSec ?? SCAN_SECONDS) * 1000, params.targets.map((target: string) => plain(target, "target")).join("\n"));
      const rows = jsonLines(result.stdout).map((row) => ({ plantilla: row["template-id"], severidad: row.info?.severity, url: row["matched-at"], nombre: (row.info?.name ?? "").slice(0, 60) }));
      return finish(`${rows.length ? encode({ candidatos: rows.slice(0, 100) }) : "Sin coincidencias."}\n${result.status} · artefacto ${result.artifact}`, { candidatos: rows.length, artefacto: result.artifact });
    },
  };

  const subfinder: Tool = {
    name: "subfinder_enum",
    label: "subfinder",
    description: "Enumera subdominios de un dominio por fuentes pasivas (subfinder). Devuelve sólo los que caen dentro del alcance; el resto se cuenta aparte.",
    parameters: obj({ domain: str(), timeoutSec: int({ minimum: 10, maximum: 1800 }) }, ["domain"]),
    execute: async (params, signal) => {
      authorizeAll(scope(), [params.domain], context.http);
      const result = await run(context, "subfinder", [need("subfinder"), "-silent", "-d", plain(params.domain, "domain")], signal, (params.timeoutSec ?? SCAN_SECONDS) * 1000);
      const all = result.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
      const inside = all.filter((host) => decide(scope(), host).allowed);
      return finish(`${inside.length ? inside.slice(0, 300).join("\n") : "Ninguno dentro del alcance."}${all.length > inside.length ? `\n(${all.length - inside.length} subdominios fuera del alcance omitidos; están en el artefacto)` : ""}\n${result.status} · artefacto ${result.artifact}`, { dentro: inside.length, total: all.length, artefacto: result.artifact });
    },
  };

  const katana: Tool = {
    name: "katana_crawl",
    label: "katana",
    description: "Rastrea un sitio dentro del alcance y lista rutas y endpoints descubiertos (katana). Profundidad acotada.",
    parameters: obj({ url: str(), depth: int({ minimum: 1, maximum: 5 }), headers: HEADERS, timeoutSec: int({ minimum: 10, maximum: 1800 }) }, ["url"]),
    execute: async (params, signal) => {
      authorizeAll(scope(), [params.url], context.http);
      const origen = new URL(params.url).origin;
      const patronOrigen = `^${origen.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:/|$)`;
      const argv = [need("katana"), "-silent", "-jsonl", "-u", plain(params.url, "url"), "-d", String(params.depth ?? 2), "-rate-limit", String(conductFor(context, "katana").rate), "-H", `User-Agent: ${context.http.conduct().userAgent}`, ...scannerHeaderArgs(context.http, params.headers), ...fixedHeaderArgs(context.http), "-field-scope", "fqdn", ...(hayFijas(context.http) ? ["-crawl-scope", patronOrigen, "-disable-redirects"] : [])];
      const result = await run(context, "katana", argv, signal, (params.timeoutSec ?? SCAN_SECONDS) * 1000);
      const urls = [...new Set(jsonLines(result.stdout).map((row) => row.request?.endpoint ?? row.endpoint).filter(Boolean))];
      const inside = urls.filter((url) => decide(scope(), url).allowed);
      // Lo descubierto entra al mapa de superficie como enlace visto: la cobertura sabe qué falta visitar.
      for (const url of inside) {
        try {
          const parsed = new URL(url);
          context.http.linked.add(parsed.pathname + parsed.search);
        } catch {}
      }
      return finish(`${inside.length ? inside.slice(0, 300).join("\n") : "Nada descubierto dentro del alcance."}${urls.length > 300 ? `\n… ${urls.length - 300} más en el artefacto` : ""}\n${result.status} · artefacto ${result.artifact}`, { urls: inside.length, artefacto: result.artifact });
    },
  };

  const dnsx: Tool = {
    name: "dns_resolve",
    label: "dnsx",
    description: "Resuelve hosts y devuelve A, AAAA y CNAME (dnsx).",
    parameters: obj({ hosts: list(str()) }, ["hosts"]),
    parallel: true,
    execute: async (params, signal) => {
      authorizeAll(scope(), params.hosts, context.http);
      const result = await run(context, "dnsx", [need("dnsx"), "-silent", "-json", "-a", "-aaaa", "-cname"], signal, 120_000, params.hosts.map((host: string) => plain(host, "host")).join("\n"));
      const rows = jsonLines(result.stdout).map((row) => ({ host: row.host, a: (row.a ?? []).join(" "), aaaa: (row.aaaa ?? []).join(" "), cname: (row.cname ?? []).join(" ") }));
      return finish(`${rows.length ? encode({ dns: rows }) : "Sin respuestas."}\n${result.status} · artefacto ${result.artifact}`, { resueltos: rows.length, artefacto: result.artifact });
    },
  };

  return [httpRequest, httpProbe, identities, ...(context.coverage ? [coverageMark, coverageView] : []), nmap, ffuf, sqlmap, httpx, nuclei, subfinder, katana, dnsx];
}
