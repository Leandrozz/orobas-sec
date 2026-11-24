// El informe usa evidencia guardada: generarlo no vuelve a tocar el objetivo.
// Sale en castellano o en inglés (`lang`): cambian los textos fijos, los nombres de estado y severidad
// y los marcadores de redacción; lo que escribió el agente (títulos, resúmenes, motivos, límites,
// clase, activos, alcance) queda tal cual.
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { Vista } from "./grafo.ts";
import type { ArtifactRef, Artifacts } from "./artifacts.ts";
import { calcularCvss } from "./cvss.ts";
import { pacer } from "./ceder.ts";
import { SEVERITIES, STATES, type Finding, type Findings } from "./findings.ts";
import { createdIdentifiers, isAuthPath, type HttpExchange } from "./http.ts";
import { listResidues } from "./residuos.ts";
import type { Ledger } from "./ledger.ts";
import { usd } from "./money.ts";
import { ReportRedactor } from "./redact.ts";
import { decide, type ScopeStore } from "./scope.ts";
import type { Paths } from "./store.ts";
import { shown } from "./datos.ts";

export type ReportLang = "es" | "en";

export interface ReportContext {
  paths: Paths;
  db: DatabaseSync;
  artifacts: Artifacts;
  findings: Findings;
  scope: ScopeStore;
  ledger: Ledger;
  /** Corta la generación (turno abortado): no se escribe nada. */
  signal?: AbortSignal;
  redact?: (text: string) => string;
  now?: Date;
  /** Idioma de los textos fijos del informe; por defecto castellano. */
  lang?: ReportLang;
  /**
   * Sólo esta sesión: sus hallazgos, su alcance, su gasto y el tráfico a su alcance. Sin sesión, el
   * proyecto entero (todas las sesiones de la carpeta), que es lo que pide el operador para verlo todo.
   */
  sessionId?: string;
  /** Grafo de hechos de la sesión (src/grafo.ts): las cadenas muestran sus aristas «habilita» con la evidencia. */
  grafo?: Vista;
}

/** Interpreta el argumento de `/informe`, `cyber informe` y `report_generate`: vacío o «es» es castellano, «en» inglés. */
export function parseReportLang(value: unknown): ReportLang {
  const text = String(value ?? "").trim().toLowerCase();
  if (!text || text === "es" || text === "castellano" || text === "español") return "es";
  if (text === "en" || text === "ingles" || text === "inglés" || text === "english") return "en";
  throw new Error("Uso: /informe [en] [proyecto] · «en» genera el informe con los textos fijos en inglés (para HackerOne o un cliente que no lee castellano); «proyecto», el de todas las sesiones de la carpeta en vez del de esta sesión.");
}

/** Líneas para el operador tras generar el informe; siempre en castellano, el idioma es el del archivo. */
export function reportSavedLines(report: { path: string; artifact: ArtifactRef; lang: ReportLang }): string[] {
  return [`Informe${report.lang === "en" ? " en inglés" : ""} guardado en ${shown(report.path)}`, `Artefacto: ${report.artifact.hash}`];
}

const STRINGS = {
  es: {
    artifactMissing: "Artefacto no disponible; no se derivaron pasos de reproducción.",
    artifactOpaque: "Artefacto sin intercambio HTTP interpretable; revisión manual necesaria. No se inventaron pasos.",
    title: "# Informe de evaluación de seguridad",
    generated: "Generado",
    summary: "## Resumen ejecutivo",
    counts: (active: number, appendix: number) => `Hallazgos para revisión: ${active}. Registros en el anexo: ${appendix}.`,
    stateColumn: "Estado",
    total: "Total",
    period: (first: string | undefined, last: string | undefined) => `Período registrado: ${first ?? "sin actividad registrada"}${last ? ` a ${last}` : ""}.`,
    cost: (amount: string, requests: number, session = false) => `Costo de API conocido ${session ? "de la sesión" : "del proyecto"}: USD ${amount} (${requests} solicitudes, incluidos subagentes y verificadores).`,
    pendingCost: (requests: number) => `Costo pendiente de determinar: ${requests} solicitudes; no se computaron como costo cero.`,
    noPendingCost: "No hay solicitudes con costo pendiente.",
    scope: "### Alcance",
    scopeCurrent: (rev: number, at: string, source: string) => `Alcance autorizado vigente: revisión ${rev}, ${at}. Fuente: ${source}.`,
    included: "Incluido",
    excluded: "Excluido",
    scopeNotes: "Notas del alcance",
    noScope: "No hay alcance autorizado registrado.",
    assets: (list: string, session = false) => `Activos con respuestas HTTP guardadas en ${session ? "la sesión" : "el proyecto"}: ${list}.`,
    none: "ninguno",
    coverageCaveat: "Las respuestas guardadas no demuestran cobertura completa del alcance. El alcance vigente puede diferir del autorizado al obtener cada artefacto.",
    findings: "## Hallazgos verificados",
    noFindings: "No hay hallazgos verificados con severidad superior a informativa.",
    candidates: "## Candidatos sin verificar",
    candidatesIntro: "Todavía no los reprodujo el verificador ni el operador: no se envían como hallazgo sin verificarlos.",
    summaryVerified: (count: number) => `Verificados: ${count}.`,
    summaryCandidates: (count: number) => `Candidatos sin verificar: ${count} (sección aparte; no se envían sin verificar).`,
    cvss: (severity: string, range: string) => `CVSS 3.1: ${range} para severidad ${severity}. El vector no se calculó.`,
    versions: (list: string) => `Versiones observadas en la evidencia: ${list}.`,
    impact: "#### Impacto",
    impactMissing: "No declarado por separado. Antes de enviar, escribí el efecto concreto: qué datos o acciones de quién, con qué alcance. La interpretación registrada está arriba.",
    remediation: "#### Remediación sugerida",
    remediationGeneric: (text: string) => `${text} (Sugerencia genérica para la clase: ajustala al caso.)`,
    remediationNone: (kind: string) => `Sin sugerencia genérica para la clase «${kind}»: escribila a mano antes de enviar.`,
    curl: "Con curl (cada identidad va en una variable de entorno con el valor completo de su cabecera):",
    stateLine: (state: string, severity: string, kind: string) => `Estado: ${state}. Severidad: ${severity}. Clase: ${kind}.`,
    asset: "Activo",
    decided: (by: string, at: string) => `Decidido por: ${by}. Fecha de decisión: ${at}.`,
    recorded: (created: string, updated: string) => `Registrado: ${created}. Última actualización: ${updated}.`,
    reason: (reason: string) => `Motivo de la decisión: ${reason || "no declarado"}.`,
    observed: "#### Observado en la evidencia",
    noResponse: "sin respuesta HTTP registrada",
    artifact: "Artefacto",
    interpretation: "#### Interpretación registrada",
    steps: "#### Pasos para reproducir",
    identitiesNote: "Usá las identidades de prueba nombradas; los valores de autenticación se omitieron.",
    sendStep: (step: number, hash: string) => `${step}. Enviá la petición guardada en ${hash}.`,
    noBody: "(sin cuerpo)",
    responseRecorded: "Respuesta registrada:",
    truncated: "Fragmento de respuesta recortado; consultá el artefacto original en el proyecto.",
    noResponseError: (error: string) => `Sin respuesta: ${error || "no registrada"}.`,
    noSteps: "No se pudieron derivar pasos HTTP de la evidencia disponible.",
    limits: (limits: string) => `Límites declarados: ${limits || "no declarados; no equivale a ausencia de límites"}.`,
    chainLine: (links: string) => `Cadena: ${links}.`,
    roles: { escala: "es la escalada de", habilita: "habilita a", relacionado: "relacionado con" } as Record<string, string>,
    chains: "## Cadenas",
    chainsIntro: "Hallazgos vinculados: el primero habilita al siguiente. La severidad de una cadena es la de su eslabón más alto y sólo vale si todos sus eslabones están verificados.",
    chainSeverity: (level: string, missing: string) => missing ? `Severidad de la cadena: ${level}, pendiente de verificar ${missing}.` : `Severidad de la cadena: ${level}, con todos sus eslabones verificados.`,
    chainLink: (from: string, to: string, edge: string, evidence: string, where: string) => `  - ${from} habilita a ${to} (arista del grafo de hechos: ${edge})${evidence ? `; evidencia de los eslabones: ${evidence}` : ""}${where ? `; ${where}` : ""}.`,
    chainWhere: (id: string, routes: string) => `${id} se observó en ${routes}`,
    edgeStates: { inferido: "declarada, sin verificar", observado: "observada", verificado: "verificada", refutado: "refutada" } as Record<string, string>,
    cleanup: "## Para limpiar",
    nothingToClean: "Ninguna escritura de la evaluación devolvió un identificador y no se generaron direcciones de correo: no consta nada creado en el objetivo.",
    cleanupIntro: "Escrituras de la evaluación que devolvieron un identificador: son los recursos que el agente pudo haber creado en el objetivo (cuentas, registros, archivos). Revisá cuáles siguen existiendo y borralos, o pedile al cliente que lo haga. No incluye inicios de sesión ni emisión de tokens.",
    cleanupHeader: "| Fecha | Petición | Identificadores | HTTP |",
    cleanupMore: (count: number) => `| … | ${count} escrituras más en la evidencia del proyecto | | |`,
    mailAddresses: (list: string) => `Direcciones de correo de prueba generadas (las cuentas registradas con ellas también son residuo): ${list}.`,
    probeResidues: "Lo que dejaron las sondas sin un identificador de por medio (archivos subidos, contraseñas cambiadas en cuentas de prueba): borralo o restablecelo, o pedile al cliente que lo haga.",
    probeResiduesHeader: "| Fecha | Sonda | Dónde | Detalle |",
    detection: "## Detección (purple)",
    detectionNone: "Sin señales de detección registradas en esta evaluación (el modo purple se abre con perfil «laboratorio» o «defensa» y señales declaradas con detection_expect).",
    detectionIntro: "Acciones ofensivas contra infra propia con la señal que debería haber disparado y si llegó por el canal declarado. Cada «sin detectar» es un gap de detección: un ataque exitoso que nadie vio es la falla del lado de la defensa, con la misma evidencia que cualquier hallazgo.",
    detectionHeader: "| Señal esperada | Acción | Resultado |",
    detectionTotal: (detected: number, expected: number) => `Total: ${detected}/${expected} señales detectadas.`,
    detectionGap: "sin detectar (gap)",
    detectionHit: "detectada",
    appendix: "## Anexo: pistas, descartados e informativos",
    appendixHeader: "| ID | Estado | Severidad | Título y activo | Decisión y límites |",
    noReason: "Sin motivo declarado",
    appendixLimits: (limits: string) => `Límites: ${limits || "no declarados"}.`,
    noRecords: "| — | — | — | Sin registros | — |",
    informationalNote: "Los registros informativos describen condiciones observadas sin una falla explotable demostrada. La confirmación del hecho no cambia su severidad.",
    states: { pista: "pista", candidato: "candidato", verificado: "verificado", descartado: "descartado" } as Record<string, string>,
    severities: { informativa: "informativa", baja: "baja", media: "media", alta: "alta", critica: "crítica" } as Record<string, string>,
    deciders: { operador: "operador", agente: "agente", verificador: "verificador" } as Record<string, string>,
  },
  en: {
    artifactMissing: "Artifact not available; no reproduction steps were derived.",
    artifactOpaque: "Artifact has no interpretable HTTP exchange; manual review needed. No steps were invented.",
    title: "# Security assessment report",
    generated: "Generated",
    summary: "## Executive summary",
    counts: (active: number, appendix: number) => `Findings for review: ${active}. Records in the appendix: ${appendix}.`,
    stateColumn: "State",
    total: "Total",
    period: (first: string | undefined, last: string | undefined) => `Recorded period: ${first ?? "no recorded activity"}${last ? ` to ${last}` : ""}.`,
    // Nada de «session: …» en los textos fijos: el redactor toma «session» como clave sensible y tapa lo que sigue.
    cost: (amount: string, requests: number, session = false) => `Known API cost (${session ? "this session" : "whole project"}): USD ${amount} (${requests} requests, including subagents and verifiers).`,
    pendingCost: (requests: number) => `Cost still to be determined: ${requests} requests; they were not counted as zero cost.`,
    noPendingCost: "No requests with pending cost.",
    scope: "### Scope",
    scopeCurrent: (rev: number, at: string, source: string) => `Authorized scope in force: revision ${rev}, ${at}. Source: ${source}.`,
    included: "Included",
    excluded: "Excluded",
    scopeNotes: "Scope notes",
    noScope: "No authorized scope recorded.",
    assets: (list: string, session = false) => `Assets with HTTP responses saved (${session ? "this session" : "whole project"}): ${list}.`,
    none: "none",
    coverageCaveat: "Saved responses do not demonstrate full coverage of the scope. The scope in force may differ from the one authorized when each artifact was obtained.",
    findings: "## Verified findings",
    noFindings: "No verified findings with severity above informational.",
    candidates: "## Unverified candidates",
    candidatesIntro: "Not yet reproduced by the verifier or the operator: do not submit them as findings until they are verified.",
    summaryVerified: (count: number) => `Verified: ${count}.`,
    summaryCandidates: (count: number) => `Unverified candidates: ${count} (separate section; do not submit before verifying).`,
    cvss: (severity: string, range: string) => `CVSS 3.1: ${range} for ${severity} severity. The vector was not computed.`,
    versions: (list: string) => `Versions observed in the evidence: ${list}.`,
    impact: "#### Impact",
    impactMissing: "Not stated separately. Before submitting, write the concrete effect: whose data or actions, and how far it reaches. The recorded interpretation is above.",
    remediation: "#### Suggested remediation",
    remediationGeneric: (text: string) => `${text} (Generic suggestion for the class: adapt it to the case.)`,
    remediationNone: (kind: string) => `No generic suggestion for the class “${kind}”: write it by hand before submitting.`,
    curl: "With curl (each identity goes in an environment variable holding its full header value):",
    stateLine: (state: string, severity: string, kind: string) => `State: ${state}. Severity: ${severity}. Class: ${kind}.`,
    asset: "Asset",
    decided: (by: string, at: string) => `Decided by: ${by}. Decision date: ${at}.`,
    recorded: (created: string, updated: string) => `Recorded: ${created}. Last update: ${updated}.`,
    reason: (reason: string) => `Reason for the decision: ${reason || "not stated"}.`,
    observed: "#### Observed in the evidence",
    noResponse: "no HTTP response recorded",
    artifact: "Artifact",
    interpretation: "#### Recorded interpretation",
    steps: "#### Steps to reproduce",
    identitiesNote: "Use the named test identities; authentication values were omitted.",
    sendStep: (step: number, hash: string) => `${step}. Send the request saved in ${hash}.`,
    noBody: "(no body)",
    responseRecorded: "Recorded response:",
    truncated: "Response excerpt truncated; see the original artifact in the project.",
    noResponseError: (error: string) => `No response: ${error || "not recorded"}.`,
    noSteps: "No HTTP steps could be derived from the available evidence.",
    limits: (limits: string) => `Stated limits: ${limits || "not stated; this does not mean there are no limits"}.`,
    chainLine: (links: string) => `Chain: ${links}.`,
    roles: { escala: "escalates", habilita: "enables", relacionado: "related to" } as Record<string, string>,
    chains: "## Chains",
    chainsIntro: "Linked findings: each one enables the next. A chain's severity is that of its highest link and only holds if every link is verified.",
    chainSeverity: (level: string, missing: string) => missing ? `Chain severity: ${level}, pending verification of ${missing}.` : `Chain severity: ${level}, with every link verified.`,
    chainLink: (from: string, to: string, edge: string, evidence: string, where: string) => `  - ${from} enables ${to} (fact-graph edge: ${edge})${evidence ? `; evidence of the links: ${evidence}` : ""}${where ? `; ${where}` : ""}.`,
    chainWhere: (id: string, routes: string) => `${id} was observed at ${routes}`,
    edgeStates: { inferido: "declared, not verified", observado: "observed", verificado: "verified", refutado: "refuted" } as Record<string, string>,
    cleanup: "## Cleanup",
    nothingToClean: "No write during the assessment returned an identifier and no email addresses were generated: nothing is on record as created on the target.",
    cleanupIntro: "Writes during the assessment that returned an identifier: these are the resources the agent may have created on the target (accounts, records, files). Check which ones still exist and delete them, or ask the client to do so. Logins and token issuance are not included.",
    cleanupHeader: "| Date | Request | Identifiers | HTTP |",
    cleanupMore: (count: number) => `| … | ${count} more writes in the project evidence | | |`,
    mailAddresses: (list: string) => `Test email addresses generated (accounts registered with them are residue too): ${list}.`,
    probeResidues: "What the probes left without an identifier in between (uploaded files, passwords changed on test accounts): delete or restore it, or ask the client to do so.",
    probeResiduesHeader: "| Date | Probe | Where | Detail |",
    detection: "## Detection (purple)",
    detectionNone: "No detection signals recorded in this assessment (purple mode opens with profile «laboratorio» or «defensa» and signals declared with detection_expect).",
    detectionIntro: "Offensive actions against owned infrastructure with the signal they should have triggered and whether it arrived on the declared channel. Each «undetected» is a detection gap: a successful attack nobody saw is a failure on the defense side, with the same evidence as any finding.",
    detectionHeader: "| Expected signal | Action | Result |",
    detectionTotal: (detected: number, expected: number) => `Total: ${detected}/${expected} signals detected.`,
    detectionGap: "undetected (gap)",
    detectionHit: "detected",
    appendix: "## Appendix: leads, discarded and informational",
    appendixHeader: "| ID | State | Severity | Title and asset | Decision and limits |",
    noReason: "No reason stated",
    appendixLimits: (limits: string) => `Limits: ${limits || "not stated"}.`,
    noRecords: "| — | — | — | No records | — |",
    informationalNote: "Informational records describe observed conditions without a demonstrated exploitable flaw. Confirming the fact does not change their severity.",
    states: { pista: "lead", candidato: "candidate", verificado: "verified", descartado: "discarded" } as Record<string, string>,
    severities: { informativa: "informational", baja: "low", media: "medium", alta: "high", critica: "critical" } as Record<string, string>,
    deciders: { operador: "operator", agente: "agent", verificador: "verifier" } as Record<string, string>,
  },
};

type Strings = (typeof STRINGS)["es"];

interface Evidence {
  hash: string;
  exchange?: HttpExchange;
  note?: string;
  /** Cuerpos ya redactados: se recorren una sola vez, al aprender los secretos. */
  requestBody?: string;
  responseBody?: string;
}

const inline = (text: string) => text.replace(/[\r\n]+/g, " ").replace(/[|<>*_`\[\]\\]/g, "\\$&");
/** Texto libre que va dentro de una oración del informe: sin el punto final, que lo pone la oración. */
const sentence = (text: string) => text.trim().replace(/\.+$/, "");
const block = (text: string, language = "text") => {
  const fence = "`".repeat(Math.max(3, ...[...text.matchAll(/`+/g)].map((match) => match[0].length + 1)));
  return `${fence}${language}\n${text}\n${fence}`;
};

/** Sólo el comienzo de cada intercambio HTTP del proyecto que el informe no cita: pedido, estado y cabeceras. */
const HEAD_BYTES = 16 * 1024;

const stringRecord = (value: unknown): value is Record<string, string> => !!value && typeof value === "object" && !Array.isArray(value) && Object.values(value).every((item) => typeof item === "string");
const validRequest = (request: any): request is HttpExchange["request"] => typeof request?.method === "string" && typeof request?.url === "string" && stringRecord(request.headers) && (request.body === undefined || typeof request.body === "string");

/** Intercambio HTTP interpretable de un artefacto, o undefined. */
function parseExchange(text: string): HttpExchange | undefined {
  try {
    const data = JSON.parse(text);
    if (!validRequest(data?.request)) return undefined;
    const response = data.response;
    if (response && (typeof response.status !== "number" || typeof response.body !== "string" || !response.headers || Object.values(response.headers).some((value) => typeof value !== "string"))) return undefined;
    return data as HttpExchange;
  } catch {
    return undefined;
  }
}

async function readEvidence(artifacts: Artifacts, hash: string, s: Strings): Promise<Evidence> {
  let text: string;
  try {
    text = (await readFile(artifacts.file(artifacts.resolve(hash)))).toString("utf8");
  } catch {
    return { hash, note: s.artifactMissing };
  }
  const exchange = parseExchange(text);
  return exchange ? { hash, exchange } : { hash, note: s.artifactOpaque };
}

interface Head {
  request: HttpExchange["request"];
  /** Estado y cabeceras, sin el cuerpo; sin respuesta, undefined. */
  response?: { status: number; headers: Record<string, string> };
}

const RESPONSE_KEY = '\n "response": {';

/**
 * Pedido, estado y cabeceras de un intercambio guardado por HttpClient (JSON con sangría de un espacio) sin leer
 * el cuerpo: cada clave de primer nivel empieza en «\n "» y un salto de línea real nunca cae dentro de un texto
 * JSON. Undefined si el formato es otro o lo leído no alcanza: entonces se lee entero.
 */
function parseHead(text: string): Head | undefined {
  if (!text.startsWith('{\n "id": ')) return undefined;
  try {
    const requestAt = text.indexOf('\n "request": ');
    const requestEnd = requestAt < 0 ? -1 : text.indexOf('\n "resolved": ', requestAt);
    if (requestEnd < 0) return undefined;
    const request = JSON.parse(text.slice(requestAt + '\n "request": '.length, requestEnd).replace(/,$/, ""));
    if (!validRequest(request)) return undefined;
    // «artifact» es la última clave fija; si la respuesta viene después, la clave que sigue lo dice.
    const artifactAt = text.indexOf('\n "artifact": ', requestEnd);
    const after = artifactAt < 0 ? -1 : text.indexOf("\n", artifactAt + 1);
    if (after < 0 || text.slice(requestEnd, artifactAt).includes(RESPONSE_KEY)) return undefined;
    const next = text.slice(after, after + RESPONSE_KEY.length);
    if (next.length < RESPONSE_KEY.length && RESPONSE_KEY.startsWith(next)) return undefined;
    if (next !== RESPONSE_KEY) return { request };
    const status = /^\n "response": \{\n  "status": (\d+),\n  "headers": /.exec(text.slice(after, after + 80));
    const headersAt = status ? after + status[0].length : -1;
    const headersEnd = headersAt < 0 ? -1 : text.indexOf('\n  "body": ', headersAt);
    if (headersEnd < 0) return undefined;
    const headers = JSON.parse(text.slice(headersAt, headersEnd).replace(/,$/, ""));
    return stringRecord(headers) ? { request, response: { status: Number(status![1]), headers } } : undefined;
  } catch {
    return undefined;
  }
}

/** Comienzo del archivo (o el archivo entero si es chico). Undefined si no se puede leer. */
async function readHead(path: string, bytes: number): Promise<{ text: string; whole: boolean } | undefined> {
  try {
    if (bytes <= HEAD_BYTES) return { text: (await readFile(path)).toString("utf8"), whole: true };
    const handle = await open(path, "r");
    try {
      const buffer = Buffer.alloc(HEAD_BYTES);
      const { bytesRead } = await handle.read(buffer, 0, HEAD_BYTES, 0);
      return { text: buffer.subarray(0, bytesRead).toString("utf8"), whole: bytesRead < HEAD_BYTES };
    } finally {
      await handle.close();
    }
  } catch {
    return undefined;
  }
}

const header = (headers: Record<string, string>, name: string) => Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1] ?? "";

/**
 * Hace falta el cuerpo de un intercambio no citado si puede aportar al informe: una escritura que devolvió algo
 * («Para limpiar»), una respuesta de autenticación o una JSON (tokens que el agente pudo copiar en un hallazgo).
 * El resto (HTML, JS, imágenes: casi todo el peso) aporta pedido y cabeceras, que ya salen del comienzo.
 */
function needsBody(head: Head): boolean {
  if (!head.response) return false;
  if (isAuthPath(head.request.url)) return true;
  if (["POST", "PUT", "PATCH"].includes(head.request.method.toUpperCase()) && head.response.status < 300) return true;
  return /json/i.test(header(head.response.headers, "content-type"));
}

/** Fecha de la decisión vigente: la del hallazgo o, en registros viejos, la del último cambio que la dejó así. */
function decidedAt(changes: () => Array<{ at: string; change: Record<string, unknown> }>, finding: Finding): string {
  if (finding.decidedAt) return finding.decidedAt;
  let at = finding.updatedAt;
  for (const { at: when, change } of changes()) {
    if (change.id !== finding.id) continue;
    if (change.state !== finding.state || change.by !== finding.decidedBy) break;
    at = when;
  }
  return at;
}

/** Quién decidió, en el idioma del informe: «verificador:1» queda «verifier:1». */
function decider(by: string, s: Strings): string {
  const [head, ...rest] = by.split(":");
  const translated = s.deciders[head ?? ""];
  return translated ? [translated, ...rest].join(":") : by;
}

/** Rango CVSS 3.1 de cada severidad (la escala cualitativa de FIRST). */
const CVSS_RANGE: Record<string, string> = { informativa: "0.0", baja: "0.1–3.9", media: "4.0–6.9", alta: "7.0–8.9", critica: "9.0–10.0" };

/** Remediación genérica por clase, en los dos idiomas. Va rotulada como genérica: no reemplaza la del caso. */
const REMEDIATIONS: Array<{ match: RegExp; es: string; en: string }> = [
  { match: /control de acceso|idor|bola|autoriz|access control|authori[sz]ation|permis/, es: "Comprobar en el servidor, en cada operación, que el recurso pertenece al usuario de la sesión (o que puede verlo), sin confiar en ids que manda el cliente; denegar por defecto.", en: "Check on the server, for every operation, that the resource belongs to (or is visible to) the session's user, without trusting client-supplied ids; deny by default." },
  { match: /xss|cross.?site scripting/, es: "Codificar la salida según el contexto (HTML, atributo, JavaScript, URL), usar plantillas con escapado automático y una CSP restrictiva.", en: "Encode output for its context (HTML, attribute, JavaScript, URL), use auto-escaping templates and a restrictive CSP." },
  { match: /sqli|sql/, es: "Consultas parametrizadas en todo acceso a la base; nunca concatenar entrada del usuario.", en: "Use parameterized queries for every database access; never concatenate user input." },
  { match: /ssrf/, es: "Lista de destinos permitidos del lado del servidor; resolver y validar la IP final (sin redes internas ni metadatos) y no seguir redirecciones a otros hosts.", en: "Allow-list destinations server-side; resolve and validate the final IP (no internal networks or metadata) and do not follow redirects to other hosts." },
  { match: /csrf/, es: "Token anti-CSRF por sesión en cada escritura y cookies SameSite=Lax o Strict.", en: "Per-session anti-CSRF token on every write and SameSite=Lax or Strict cookies." },
  { match: /cors/, es: "No reflejar el Origin con credenciales: lista fija de orígenes permitidos.", en: "Do not reflect Origin with credentials: use a fixed allow-list of origins." },
  { match: /redirect|redirecci/, es: "Validar el destino contra una lista de rutas o dominios propios.", en: "Validate the destination against an allow-list of own paths or domains." },
  { match: /jwt/, es: "Fijar el algoritmo esperado, verificar siempre firma y expiración, y usar secretos fuertes fuera del código.", en: "Pin the expected algorithm, always verify signature and expiry, and keep strong secrets out of the code." },
  { match: /cripto|crypto|hash|deriv|aleatori|random|cifrado|encrypt/, es: "Contraseñas con un KDF (Argon2id, scrypt o PBKDF2 con iteraciones altas), tokens con un generador criptográfico, firmas con HMAC comparadas en tiempo constante, cifrado autenticado (AES-GCM con nonce único) y claves fuera del código.", en: "Hash passwords with a KDF (Argon2id, scrypt or high-iteration PBKDF2), generate tokens with a CSPRNG, sign with HMAC compared in constant time, use authenticated encryption (AES-GCM with unique nonces) and keep keys out of the code." },
  { match: /secret|credencial|credential|exposici|exposure|leak|filtraci/, es: "Rotar el secreto expuesto, sacarlo del código o de la respuesta y revisar su uso en los registros.", en: "Rotate the exposed secret, remove it from the code or response and review its use in the logs." },
  { match: /subida|upload/, es: "Validar el tipo por contenido, renombrar, guardar fuera de la raíz web y servir con Content-Disposition: attachment.", en: "Validate type by content, rename, store outside the web root and serve with Content-Disposition: attachment." },
  { match: /traversal|recorrido de ruta|lfi|inclusi[oó]n de archivo/, es: "Normalizar la ruta y verificar que quede dentro de la carpeta permitida; no usar nombres que vengan del cliente.", en: "Normalize the path and check it stays inside the allowed folder; do not use client-supplied names." },
  { match: /ssti|plantilla|template/, es: "No renderizar entrada del usuario como plantilla; motor en modo sandbox.", en: "Never render user input as a template; run the engine sandboxed." },
  { match: /xxe/, es: "Desactivar entidades externas y DTD en el parser XML.", en: "Disable external entities and DTDs in the XML parser." },
  { match: /race|carrera/, es: "Hacer la operación atómica en el servidor (transacción, restricción única o bloqueo).", en: "Make the operation atomic on the server (transaction, unique constraint or lock)." },
  { match: /fuerza bruta|brute|rate.?limit|l[ií]mite de intentos/, es: "Limitar intentos por cuenta e IP con demora progresiva.", en: "Limit attempts per account and IP with progressive delay." },
  { match: /deserializ/, es: "No deserializar datos del cliente con formatos que instancian clases; usar JSON con esquema.", en: "Do not deserialize client data with class-instantiating formats; use schema-validated JSON." },
  { match: /monto|precio|price|amount|pago|payment/, es: "Recalcular montos y precios en el servidor e ignorar los que manda el cliente.", en: "Recompute amounts and prices on the server and ignore client-supplied ones." },
  { match: /inyecci[oó]n|injection|comando|command/, es: "No pasar entrada del usuario a un intérprete (shell, SQL, LDAP, plantillas); APIs parametrizadas y listas de valores permitidos.", en: "Do not pass user input to an interpreter (shell, SQL, LDAP, templates); use parameterized APIs and allow-lists." },
];

function remediationFor(finding: Finding, lang: ReportLang): string | undefined {
  const text = `${finding.kind} ${finding.title}`.toLowerCase();
  return REMEDIATIONS.find((item) => item.match.test(text))?.[lang];
}

/** Productos y versiones que dicen las respuestas de la evidencia (Server, X-Powered-By, generator): no se inventa ninguna. */
function observedVersions(exchanges: HttpExchange[]): string[] {
  const found = new Set<string>();
  for (const exchange of exchanges) {
    const response = exchange.response;
    if (!response) continue;
    for (const name of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-jenkins"]) {
      const value = header(response.headers, name).trim();
      if (value && value.length <= 80) found.add(name === "x-aspnet-version" ? `ASP.NET ${value}` : name === "x-jenkins" ? `Jenkins ${value}` : name === "x-drupal-cache" ? "Drupal" : value);
    }
    const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,80})["']/i.exec(response.body.slice(0, 20_000))?.[1];
    if (generator) found.add(generator);
  }
  return [...found].slice(0, 8);
}

/** Cabeceras de transporte que no dicen nada del hallazgo. */
const HOP = new Set(["connection", "keep-alive", "transfer-encoding"]);

/** Una petición guardada como curl copiable. Las identidades (ya reemplazadas por «<identidad x>») van como variables. */
export function curlOf(request: { method: string; url: string; headers: Record<string, string>; body?: string }, lang: ReportLang): string {
  const quote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;
  const variable = (name: string) => `${lang === "en" ? "IDENTITY" : "IDENTIDAD"}_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`;
  const headerArg = (key: string, value: string) => {
    const identity = /^<identidad ([^>]+)>$/.exec(value.trim());
    return identity ? `-H "${key}: \${${variable(identity[1]!)}}"` : `-H ${quote(`${key}: ${value}`)}`;
  };
  const parts = [`curl -i${request.method === "GET" ? "" : ` -X ${request.method}`} ${quote(request.url)}`, ...Object.entries(request.headers).filter(([key]) => key.toLowerCase() !== "content-length").map(([key, value]) => headerArg(key, value))];
  if (request.body !== undefined && request.body !== "") parts.push(`--data-binary ${quote(request.body)}`);
  return parts.join(" \\\n  ");
}

/** Los marcadores que dejan el redactor y el cliente HTTP son castellano fijo; en inglés se traducen al final. */
function translateMarkers(markdown: string, lang: ReportLang): string {
  if (lang !== "en") return markdown;
  return markdown.replace(/<identidad ([^>]+)>/g, "<identity $1>").replaceAll("[credencial omitida]", "[credential redacted]");
}

/**
 * Genera el informe sin congelar el daemon: lee con fs/promises y cede el event loop entre artefactos. Lee entera
 * la evidencia de los hallazgos; del resto de los intercambios HTTP del proyecto sólo el comienzo (pedido, estado y
 * cabeceras: activos probados y secretos de cabeceras), salvo los que pueden aportar cuerpo (needsBody).
 */
export async function generateReport(context: ReportContext): Promise<{ path: string; artifact: ArtifactRef; markdown: string; lang: ReportLang }> {
  const { paths, db, artifacts, findings, scope, ledger, signal, sessionId } = context;
  const lang: ReportLang = context.lang ?? "es";
  const s: Strings = STRINGS[lang];
  const state = (value: string) => s.states[value] ?? value;
  const severity = (value: string) => s.severities[value] ?? value;
  const now = context.now ?? new Date();
  const pause = pacer(signal);
  const all = findings.list({ sessionId });
  // Los artefactos no dicen de qué sesión son: con sesión, cuenta el tráfico a su alcance (en cualquiera
  // de sus revisiones) y la evidencia de sus hallazgos. El redactor igual aprende de todo el proyecto.
  const own = sessionId ? scope.of(sessionId) : undefined;
  const revisions = own?.revisions() ?? [];
  const evidenceHashes = new Set(all.flatMap((finding) => finding.evidence));
  const mine = (hash: string, url: string) => !own || evidenceHashes.has(hash) || revisions.some((revision) => decide(revision, url).allowed);
  const mineDates: string[] = [];
  const redactor = new ReportRedactor();
  const clean = (text: string) => redactor.text(context.redact?.(text) ?? text);
  // Se recorren todos los cuerpos antes de recortar, para ocultar también secretos reflejados en otros campos.
  const learn = (exchange: HttpExchange) => {
    redactor.url(exchange.request.url);
    redactor.headers(exchange.request.headers);
    const requestBody = clean(exchange.request.body ?? "");
    if (!exchange.response) return { requestBody };
    redactor.headers(exchange.response.headers);
    return { requestBody, responseBody: clean(exchange.response.body) };
  };
  const httpArtifacts = db.prepare("select hash,created_at,bytes from artifacts where producer='http'").all() as Array<{ hash: string; created_at: string; bytes: number }>;
  const createdAt = new Map(httpArtifacts.map((item) => [item.hash, item.created_at]));
  // Lo que el informe usa del resto: orígenes con respuesta (activos) y escrituras que devolvieron ids (para limpiar).
  const origins = new Set<string>();
  const residues: Array<{ at: string; method: string; url: string; status: number; ids: string[] }> = [];
  const account = (hash: string, exchange: HttpExchange) => {
    if (!mine(hash, exchange.request.url)) return;
    mineDates.push(createdAt.get(hash) ?? "");
    const response = exchange.response;
    if (!response) return;
    try { origins.add(new URL(exchange.request.url).origin); } catch {}
    if (isAuthPath(exchange.request.url)) return;
    const ids = createdIdentifiers(exchange.request.method, exchange.request.url, response);
    if (ids.length) residues.push({ at: createdAt.get(hash) ?? "", method: exchange.request.method, url: exchange.request.url, status: response.status, ids });
  };

  const evidence = new Map<string, Evidence>();
  for (const finding of all) for (const hash of finding.evidence) {
    if (evidence.has(hash)) continue;
    await pause();
    const item = await readEvidence(artifacts, hash, s);
    if (item.exchange) {
      Object.assign(item, learn(item.exchange));
      account(hash, item.exchange);
    }
    evidence.set(hash, item);
  }
  const rest = httpArtifacts.filter((item) => !evidence.has(item.hash));
  for (let index = 0; index < rest.length; index += 16) {
    const batch = rest.slice(index, index + 16);
    const heads = await Promise.all(batch.map((item) => readHead(artifacts.file(item.hash), item.bytes)));
    for (const [position, item] of batch.entries()) {
      await pause();
      const read = heads[position];
      if (!read) continue;
      let exchange = read.whole ? parseExchange(read.text) : undefined;
      if (!read.whole) {
        const head = parseHead(read.text);
        if (head) {
          redactor.url(head.request.url);
          redactor.headers(head.request.headers);
          clean(head.request.body ?? "");
          if (mine(item.hash, head.request.url)) mineDates.push(item.created_at);
          if (head.response) {
            redactor.headers(head.response.headers);
            if (mine(item.hash, head.request.url)) try { origins.add(new URL(head.request.url).origin); } catch {}
          }
        }
        if (!head || needsBody(head)) {
          try { exchange = parseExchange((await readFile(artifacts.file(item.hash))).toString("utf8")); } catch {}
        }
      }
      if (!exchange) continue;
      learn(exchange);
      account(item.hash, exchange);
    }
  }
  for (const finding of all) clean(JSON.stringify(finding));
  // Con sesión, su alcance; sin sesión, el vigente de cada sesión del proyecto, juntos.
  const currentScope = own ? own.current() : scope.project();
  if (currentScope) clean(JSON.stringify(currentScope));
  await pause();
  let changes: Array<{ at: string; change: Record<string, unknown> }> | undefined;
  const findingChanges = () => (changes ??= (db.prepare("select at,payload from events where type='finding.changed' order by seq desc").all() as Array<{ at: string; payload: string }>).flatMap((event) => {
    try { return [{ at: event.at, change: JSON.parse(event.payload) as Record<string, unknown> }]; } catch { return []; }
  }));

  const totals = ledger.totals(sessionId);
  const dates = [
    ...all.flatMap((finding) => [finding.createdAt, finding.updatedAt]),
    ...(sessionId
      ? (db.prepare("select started_at at from sessions where id=? union all select at from requests where session_id=?").all(sessionId, sessionId) as Array<{ at: string }>)
      : (db.prepare("select started_at at from sessions union all select at from requests").all() as Array<{ at: string }>)).map((row) => row.at),
    ...(sessionId ? mineDates : httpArtifacts.map((item) => item.created_at)),
  ].filter(Boolean).sort();
  // Verificados primero y en su sección; los candidatos aparte: un informe para enviar no los mezcla. Dentro, de mayor a menor severidad.
  const bySeverity = (a: Finding, b: Finding) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || a.createdAt.localeCompare(b.createdAt);
  const verified = all.filter((finding) => finding.state === "verificado" && finding.severity !== "informativa").sort(bySeverity);
  const candidates = all.filter((finding) => finding.state === "candidato" && finding.severity !== "informativa").sort(bySeverity);
  const active = [...verified, ...candidates];
  const appendix = all.filter((finding) => !active.includes(finding));
  const evaluated = [...origins].sort();
  const lines = [
    s.title, "", `${s.generated}: ${now.toISOString()}`, "",
    s.summary, "",
    s.counts(active.length, appendix.length), "",
    s.summaryVerified(verified.length),
    ...verified.map((finding) => `- ${finding.id.slice(0, 8)} — ${inline(clean(finding.title))} (${severity(finding.severity)})`),
    ...(candidates.length ? [s.summaryCandidates(candidates.length)] : []), "",
    `| ${s.stateColumn} | ${SEVERITIES.map(severity).join(" | ")} | ${s.total} |`, "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...STATES.map((value) => `| ${state(value)} | ${SEVERITIES.map((level) => all.filter((finding) => finding.state === value && finding.severity === level).length).join(" | ")} | ${all.filter((finding) => finding.state === value).length} |`), "",
    s.period(dates[0], dates.length ? dates.at(-1) : undefined),
    s.cost(usd(totals.knownPico, 6), totals.requests, !!sessionId),
    totals.unknownRequests ? s.pendingCost(totals.unknownRequests) : s.noPendingCost, "",
    s.scope, "",
    ...(currentScope ? [
      s.scopeCurrent(currentScope.rev, currentScope.at, inline(clean(currentScope.source))), "",
      ...currentScope.include.map((rule) => `- ${s.included}: ${inline(clean(rule.value))}${rule.note ? ` — ${inline(clean(rule.note))}` : ""}`),
      ...currentScope.exclude.map((rule) => `- ${s.excluded}: ${inline(clean(rule.value))}${rule.note ? ` — ${inline(clean(rule.note))}` : ""}`),
      ...(currentScope.notes ? ["", `${s.scopeNotes}: ${clean(currentScope.notes)}`] : []),
    ] : [s.noScope]), "",
    s.assets(evaluated.length ? evaluated.map((asset) => inline(clean(asset))).join(", ") : s.none, !!sessionId),
    s.coverageCaveat, "",
  ];
  // Cadenas: los vínculos se ven en el proyecto entero (un eslabón puede ser de otra sesión), pero el
  // informe sólo nombra hallazgos que lista.
  const project = findings.list();
  const listed = new Set(all.map((finding) => finding.id));
  const describe = (finding: Finding) => `${finding.id.slice(0, 8)} «${inline(clean(finding.title))}» (${severity(finding.severity)}, ${state(finding.state)})`;
  const chainLine = (finding: Finding): string[] => {
    const links = findings.linksOf(finding.id, project).filter(({ finding: other }) => listed.has(other.id));
    return links.length ? [s.chainLine(links.map(({ finding: other, role }) => `${s.roles[role] ?? role} ${describe(other)}`).join("; "))] : [];
  };
  const lineaCvss = (vector: string) => {
    const { puntaje, grupo } = calcularCvss(vector);
    const etiqueta = lang === "en" && grupo === "ambiental" ? "environmental" : grupo;
    return `CVSS 3.1 (${etiqueta}) · ${puntaje.toFixed(1)} · \`${vector}\``;
  };
  for (const finding of active) {
    await pause();
    if (finding === verified[0] || (!verified.length && finding === active[0])) lines.push(s.findings, "", ...(verified.length ? [] : [s.noFindings, ""]));
    if (finding === candidates[0]) lines.push(s.candidates, "", s.candidatesIntro, "");
    const items = finding.evidence.map((hash) => evidence.get(hash)!);
    const versions = observedVersions(items.flatMap((item) => (item.exchange ? [item.exchange] : [])));
    lines.push(
      `### ${finding.id.slice(0, 8)} — ${inline(clean(finding.title))}`, "",
      s.stateLine(state(finding.state), severity(finding.severity), inline(clean(finding.kind))),
      finding.cvss ? lineaCvss(finding.cvss) : s.cvss(severity(finding.severity), CVSS_RANGE[finding.severity] ?? "?"),
      `${s.asset}: ${inline(clean(finding.asset))}.`,
      ...(versions.length ? [s.versions(versions.map((version) => inline(clean(version))).join(", "))] : []),
      ...chainLine(finding),
      s.decided(inline(clean(decider(finding.decidedBy, s))), decidedAt(findingChanges, finding)),
      s.recorded(finding.createdAt, finding.updatedAt),
      s.reason(sentence(clean(finding.reason))), "",
      s.observed, "",
    );
    for (const item of items) {
      const exchange = item.exchange;
      lines.push(exchange ? `- ${inline(exchange.request.method)} ${inline(clean(redactor.url(exchange.request.url)))}: ${exchange.response ? `HTTP ${exchange.response.status}` : s.noResponse}. ${s.artifact}: ${item.hash}.` : `- ${item.hash}: ${item.note}`);
    }
    lines.push("", s.interpretation, "", clean(finding.summary), "", s.steps, "", s.identitiesNote, "");
    let step = 0;
    for (const item of items) {
      if (!item.exchange) continue;
      const exchange = item.exchange;
      const headers = redactor.headers(exchange.request.headers);
      const shown = { method: exchange.request.method, url: clean(redactor.url(exchange.request.url)), headers: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, clean(value)])), body: exchange.request.body === undefined ? undefined : item.requestBody ?? clean(exchange.request.body) };
      lines.push(s.sendStep(++step, item.hash), "", block([
        `${shown.method} ${shown.url}`,
        ...Object.entries(shown.headers).map(([key, value]) => `${key}: ${value}`),
        "", shown.body === undefined ? clean(s.noBody) : shown.body,
      ].join("\n"), "http"), "", s.curl, "", block(curlOf(shown, lang), "sh"), "");
      if (exchange.response) {
        const response = exchange.response;
        const body = item.responseBody ?? clean(response.body);
        lines.push(s.responseRecorded, "", block([
          `HTTP ${response.status}`,
          ...Object.entries(redactor.headers(response.headers)).filter(([key]) => !HOP.has(key.toLowerCase())).map(([key, value]) => `${key}: ${clean(value)}`),
          "", body.slice(0, 2000),
        ].join("\n"), "http"), "");
        if (body.length > 2000 || response.truncated) lines.push(s.truncated, "");
      } else lines.push(s.noResponseError(clean(exchange.error ?? "")), "");
    }
    if (!step) lines.push(s.noSteps, "");
    const remedy = remediationFor(finding, lang);
    lines.push(s.impact, "", s.impactMissing, "", s.remediation, "", remedy ? s.remediationGeneric(remedy) : s.remediationNone(inline(clean(finding.kind))), "");
    lines.push(s.limits(sentence(clean(finding.limits))), "");
  }
  if (!active.length) lines.push(s.findings, "", s.noFindings, "");
  const chains: Finding[][] = [];
  const chained = new Set<string>();
  for (const finding of all) {
    if (chained.has(finding.id)) continue;
    const chain = findings.chainOf(finding.id, project).filter((link) => listed.has(link.id));
    for (const link of chain) chained.add(link.id);
    if (chain.length > 1) chains.push(chain);
  }
  if (chains.length) {
    lines.push(s.chains, "", s.chainsIntro, "");
    for (const chain of chains) {
      const live = chain.filter((link) => link.state !== "descartado");
      const top = SEVERITIES[Math.max(0, ...live.map((link) => SEVERITIES.indexOf(link.severity)))]!;
      const missing = live.filter((link) => link.state !== "verificado").map((link) => `${link.id.slice(0, 8)} (${state(link.state)})`).join(", ");
      lines.push(`- ${chain.map(describe).join(" → ")}. ${s.chainSeverity(severity(top), missing)}`);
      // Con el grafo: cada eslabón con su arista, la evidencia de los dos hallazgos y la ruta donde se observó cada uno.
      const vista = context.grafo;
      if (vista) for (let i = 0; i + 1 < chain.length; i++) {
        const [a, b] = [chain[i]!, chain[i + 1]!];
        const arista = vista.aristas.get(`hallazgo:${a.id}\nhabilita\nhallazgo:${b.id}`) ?? vista.aristas.get(`hallazgo:${b.id}\nhabilita\nhallazgo:${a.id}`);
        if (!arista) continue;
        const [desde, hacia] = arista.origen === `hallazgo:${a.id}` ? [a, b] : [b, a];
        const evidencias = Array.isArray(arista.atributos.evidencias) ? arista.atributos.evidencias.map(String).join(", ") : "";
        const rutas = (finding: Finding) => (vista.salientes.get(`hallazgo:${finding.id}`) ?? []).filter((item) => item.tipo === "observado_en").slice(0, 2).map((item) => `${vista.nodos.get(item.destino)?.etiqueta ?? "?"} (${item.ultima.evidencia.slice(0, 19)})`).join(", ");
        const donde = [desde, hacia].map((finding) => (rutas(finding) ? s.chainWhere(finding.id.slice(0, 8), rutas(finding)) : "")).filter(Boolean).join("; ");
        lines.push(s.chainLink(desde.id.slice(0, 8), hacia.id.slice(0, 8), s.edgeStates[arista.estado] ?? arista.estado, inline(clean(evidencias)), inline(clean(donde))));
      }
    }
    lines.push("");
  }
  // Para limpiar: lo que el agente pudo haber dejado en el objetivo. Sale de la evidencia guardada,
  // con la misma regla que usa la guarda de borrado para reconocer una creación propia.
  residues.sort((a, b) => a.at.localeCompare(b.at));
  let mailAddresses: Array<{ address: string; label: string }> = [];
  try {
    mailAddresses = (sessionId
      ? db.prepare("select address,label from mail_addresses where session_id=? order by created_at").all(sessionId)
      : db.prepare("select address,label from mail_addresses order by created_at").all()) as Array<{ address: string; label: string }>;
  } catch {}
  const probeResidues = listResidues(db, sessionId);
  lines.push(s.cleanup, "");
  if (!residues.length && !mailAddresses.length && !probeResidues.length) {
    lines.push(s.nothingToClean, "");
  } else {
    lines.push(s.cleanupIntro, "");
    if (residues.length) {
      const LIMIT = 200;
      lines.push(s.cleanupHeader, "| --- | --- | --- | ---: |");
      for (const item of residues.slice(0, LIMIT)) {
        lines.push(`| ${inline(item.at)} | ${inline(clean(`${item.method} ${item.url}`))} | ${inline(clean(item.ids.join(", ")))} | ${item.status} |`);
      }
      if (residues.length > LIMIT) lines.push(s.cleanupMore(residues.length - LIMIT));
      lines.push("");
    }
    if (mailAddresses.length) {
      lines.push(s.mailAddresses(mailAddresses.map((row) => inline(clean(`${row.address} (${row.label})`))).join(", ")), "");
    }
    if (probeResidues.length) {
      lines.push(s.probeResidues, "", s.probeResiduesHeader, "| --- | --- | --- | --- |");
      for (const item of probeResidues.slice(0, 200)) lines.push(`| ${inline(item.at)} | ${inline(`${item.tool} · ${item.kind}`)} | ${inline(clean(item.target))} | ${inline(clean(item.detail))} |`);
      if (probeResidues.length > 200) lines.push(s.cleanupMore(probeResidues.length - 200));
      lines.push("");
    }
  }
  // Detección purple: sólo si hubo señales registradas (la tabla existe desde la primera corrida purple).
  let detection: Array<{ esperada: string; accion: string; detectada: number }> = [];
  try {
    detection = db.prepare("select esperada, accion, detectada from detection order by at").all() as Array<{ esperada: string; accion: string; detectada: number }>;
  } catch {}
  lines.push(s.detection, "");
  if (!detection.length) {
    lines.push(s.detectionNone, "");
  } else {
    const detected = detection.filter((row) => row.detectada).length;
    lines.push(s.detectionIntro, "", s.detectionHeader, "| --- | --- | --- |");
    for (const row of detection) lines.push(`| ${inline(clean(row.esperada))} | ${inline(clean(row.accion))} | ${row.detectada ? s.detectionHit : s.detectionGap} |`);
    lines.push("", s.detectionTotal(detected, detection.length), "");
  }
  lines.push(s.appendix, "", s.appendixHeader, "| --- | --- | --- | --- | --- |");
  for (const finding of appendix) lines.push(`| ${finding.id.slice(0, 8)} | ${state(finding.state)} | ${severity(finding.severity)}${finding.cvss ? ` · ${lineaCvss(finding.cvss)}` : ""} | ${inline(clean(finding.title))} — ${inline(clean(finding.asset))} | ${inline(clean(decider(finding.decidedBy, s)))}, ${decidedAt(findingChanges, finding)}. ${inline(sentence(clean(finding.reason)) || s.noReason)}. ${inline(s.appendixLimits(sentence(clean(finding.limits))))} |`);
  if (!appendix.length) lines.push(s.noRecords);
  lines.push("", s.informationalNote, "");
  await pause();
  const markdown = translateMarkers(redactor.finish(context.redact?.(lines.join("\n")) ?? lines.join("\n")), lang);
  signal?.throwIfAborted();
  const dir = paths.exports;
  await mkdir(dir, { recursive: true });
  const stem = `${now.toISOString().replace(/[:.]/g, "-")}${lang === "en" ? "-en" : ""}`;
  let path = join(dir, `${stem}.md`);
  for (let suffix = 0; ; suffix++) {
    path = join(dir, `${stem}${suffix ? `-${suffix}` : ""}.md`);
    try {
      await writeFile(path, markdown, { encoding: "utf8", flag: "wx", mode: 0o600 });
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
  const artifact = artifacts.put(markdown, "text/markdown", "informe");
  return { path, artifact, markdown, lang };
}
