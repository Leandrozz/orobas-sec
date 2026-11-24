// Comprobaciones del verificador que van en cada veredicto, visibles (reporte de Nico, 22/11: «que valide que
// está en el scope asignado por HackerOne, que tenga sentido, que si hay open source no esté ya arreglado, y
// con el historial de bug bounties»). El alcance del programa se resuelve acá, con el código y sin modelo;
// coherencia, código abierto y duplicados los completa el verificador con lo que leyó. Lo que no se pudo
// comprobar dice «no comprobado»: nunca cuenta como aprobado.
import type { Finding } from "./findings.ts";
import { decide, ruleMatches, type Scope, type ScopeRule } from "./scope.ts";

export type CheckResult = "ok" | "falla" | "excluido" | "fuera" | "posible fuera de alcance" | "posible duplicado" | "arreglado" | "no aplica" | "no comprobado";
export interface Check { resultado: CheckResult; detalle: string; fuente?: string }
export interface Checks { alcance: Check; politica: Check; coherencia: Check; codigoAbierto: Check; duplicados: Check }

export const CHECK_NAMES: Record<keyof Checks, string> = { alcance: "alcance del programa", politica: "política del programa", coherencia: "coherencia", codigoAbierto: "código abierto", duplicados: "duplicados" };
const MODEL_RESULTS = new Set<CheckResult>(["ok", "falla", "posible duplicado", "arreglado", "no aplica", "no comprobado"]);
const OUT_MARKERS = /fuera de(l)? alcance|out[- ]of[- ]scope|not eligible|no elegible|excluded|excluid|no se aceptan|no aceptamos|we do not accept|not accepted|will not be accepted|won'?t be rewarded|ineligible|non-qualifying|no califica/i;
const STOP = new Set(["para", "with", "from", "that", "this", "como", "sobre", "entre", "desde", "otro", "otra", "the", "and", "una", "uno", "los", "las", "del"]);

/** Lo que el hallazgo nombra como destino: una URL, un host o una IP; una ruta suelta no alcanza. */
function targetOf(asset: string): string | undefined {
  const value = asset.trim();
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) || /^\[?[0-9a-f:.]+\]?(:\d+)?(\/|$)/i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/|$)/i.test(value) || /^localhost(:\d+)?(\/|$)/i.test(value) ? value : undefined;
}

const quoteRule = (rule: ScopeRule) => `«${rule.value}»${rule.note ? ` — «${rule.note}»` : ""}`;

/**
 * El alcance según la fuente del programa: el activo, en qué regla entra (y si esa regla dice recompensa), si
 * una exclusión del programa lo deja afuera (citada textual), y si la política cargada en las notas nombra la
 * clase del hallazgo como fuera de alcance (citada textual).
 */
export function programChecks(scope: Scope | undefined, finding: Pick<Finding, "asset" | "kind" | "title">): Pick<Checks, "alcance" | "politica"> {
  const source = scope?.source ? (scope.source.startsWith("hackerone:") ? `${scope.source} (alcance del programa en HackerOne)` : scope.source) : undefined;
  if (!scope || !scope.include.length) return { alcance: { resultado: "no comprobado", detalle: "la sesión no tiene alcance cargado" }, politica: { resultado: "no comprobado", detalle: "sin alcance ni política cargados" } };
  const target = targetOf(finding.asset);
  let alcance: Check;
  if (!target) alcance = { resultado: "no comprobado", detalle: `el activo «${finding.asset.slice(0, 80)}» no nombra un host (es una ruta o un texto): no se puede cruzar con el alcance`, fuente: source };
  else {
    let url: URL | undefined;
    try { url = /^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? new URL(target) : undefined; } catch { url = undefined; }
    const host = (url?.hostname ?? target.replace(/[/:].*$/, "")).toLowerCase().replace(/^\[|\]$/g, "");
    const excluded = scope.exclude.find((rule) => ruleMatches(rule, host, url));
    // La regla más específica manda (un host exacto antes que un comodín): es la que dice la recompensa de ese activo.
    const rank = (rule: ScopeRule) => (rule.kind === "url" ? 0 : rule.kind === "host" ? 1 : rule.kind === "wildcard" ? 2 : 3) * 1000 - rule.value.length;
    const included = scope.include.filter((rule) => ruleMatches(rule, host, url)).sort((a, b) => rank(a) - rank(b))[0];
    if (excluded) alcance = { resultado: "excluido", detalle: `el programa lo excluye: ${quoteRule(excluded)}`, fuente: source };
    else if (!decide(scope, target).allowed || !included) alcance = { resultado: "fuera", detalle: `ninguna regla del programa cubre ${target.slice(0, 80)}`, fuente: source };
    else {
      const note = included.note ?? "";
      const bounty = /sin recompensa/i.test(note) ? "elegible para reportar, sin recompensa" : /con recompensa/i.test(note) ? "elegible para reportar y con recompensa" : "elegible para reportar; la recompensa no la dice la fuente (no comprobado)";
      alcance = { resultado: "ok", detalle: `dentro por la regla ${quoteRule(included)}: ${bounty}`, fuente: source };
    }
  }
  // Política: una línea de las notas del programa que diga «fuera de alcance» y nombre la clase del hallazgo.
  const notes = scope.notes ?? "";
  let politica: Check;
  if (!notes.trim() || /^Programa HackerOne «[^»]+»\. Leé la política completa/.test(notes.trim())) {
    politica = { resultado: "no comprobado", detalle: "la política del programa (tipos de falla fuera de alcance) no está cargada en el alcance; leela en la página del programa", fuente: source };
  } else {
    const words = [...new Set(`${finding.kind} ${finding.title}`.toLowerCase().normalize("NFKD").replace(/\p{M}/gu, "").split(/[^a-z0-9-]+/).filter((word) => word.length >= 4 && !STOP.has(word)))];
    const sentences = notes.split(/(?<=[.;])\s+|\n+/).map((sentence) => sentence.trim()).filter(Boolean);
    const plain = (text: string) => text.toLowerCase().normalize("NFKD").replace(/\p{M}/gu, "");
    const hit = sentences.find((sentence) => OUT_MARKERS.test(sentence) && words.some((word) => plain(sentence).includes(word)));
    politica = hit ? { resultado: "posible fuera de alcance", detalle: `la política dice: «${hit.slice(0, 240)}»`, fuente: source } : { resultado: "ok", detalle: "la política cargada no nombra esta clase como fuera de alcance", fuente: source };
  }
  return { alcance, politica };
}

/** Completa lo que dictó el verificador: lo que falta o no es un resultado válido queda «no comprobado». */
export function modelChecks(raw: unknown): Pick<Checks, "coherencia" | "codigoAbierto" | "duplicados"> {
  const value = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const one = (key: string, aliases: string[] = []): Check => {
    const item = [key, ...aliases].map((name) => value[name]).find((entry) => entry && typeof entry === "object") as Record<string, unknown> | undefined;
    const resultado = String(item?.resultado ?? "").trim().toLowerCase() as CheckResult;
    const detalle = String(item?.detalle ?? "").trim().slice(0, 300);
    const fuente = String(item?.fuente ?? "").trim().slice(0, 300);
    if (!item || !MODEL_RESULTS.has(resultado)) return { resultado: "no comprobado", detalle: detalle || "el verificador no lo informó" };
    if (resultado !== "no comprobado" && resultado !== "no aplica" && !detalle) return { resultado: "no comprobado", detalle: "sin detalle de qué se miró" };
    return { resultado, detalle, ...(fuente ? { fuente } : {}) };
  };
  return { coherencia: one("coherencia"), codigoAbierto: one("codigo_abierto", ["codigoAbierto"]), duplicados: one("duplicados") };
}

/** Una línea por comprobación, para el motivo del veredicto (lo ven /verificar, /hallazgos y el informe). */
export function checksLines(checks: Checks): string[] {
  return (Object.keys(CHECK_NAMES) as Array<keyof Checks>).map((key) => {
    const check = checks[key];
    return `${CHECK_NAMES[key]}: ${check.resultado} — ${check.detalle}${check.fuente ? ` [${check.fuente}]` : ""}`;
  });
}

/** ¿Algo impide dar el hallazgo por verificado? (activo excluido o fuera del programa, o evidencia que no demuestra el impacto). */
export function blocksVerified(checks: Checks): string | undefined {
  if (checks.alcance.resultado === "excluido" || checks.alcance.resultado === "fuera") return `No se verifica algo fuera del alcance del programa (${checks.alcance.detalle}). Dictá «descartado» con ese motivo.`;
  if (checks.coherencia.resultado === "falla") return "Dijiste que la evidencia no demuestra el impacto afirmado: eso no es «verificado». Dictá «candidato» (qué falta demostrar) o «descartado».";
  return undefined;
}
