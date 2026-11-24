// Regla de cierre honesta (punto 93 de bench/MEJORAS-AGENTE.md; A1 del plan del FLASH).
// El modelo quiere terminar el turno con más de la mitad del presupuesto sin gastar y el tráfico
// guardado muestra una grieta concreta: el harness no acepta el cierre y la nombra. No pide
// «seguir probando»: dice qué recurso, qué respondió y qué falta hacer. Una grieta se cierra con un
// hallazgo que la nombre (candidato, pista o descartado con motivo) o probando lo que falta. Se
// objeta una grieta por vez; la misma, pocas veces y nunca otra vez si el agente ya la intentó
// (pidió algo de esa ruta después de la objeción). Si queda abierta al cerrar, el operador se entera.
// Además, un hallazgo bajo o medio con una escalada conocida sin intentar (src/cadenas.ts) se objeta
// igual: una acción, sin repetirse si ya se intentó, y «limitada» con nota la cierra.
import { pendingEscalations, sessionCookies, type ChainContext } from "./cadenas.ts";
import { canonicalPath, ID_SEGMENT } from "./coverage.ts";
import type { Findings } from "./findings.ts";
import { calcularFaltantes } from "./grafo-consultas.ts";
import type { Vista } from "./grafo.ts";
import type { HttpClient } from "./http.ts";

export interface Crack {
  /** Clave estable: cuenta las objeciones y va al evento. */
  key: string;
  /** Familia o ruta canónica a la que se refiere; se cruza con el activo de los hallazgos. */
  path: string;
  /** Qué se vio y qué falta, para el modelo. */
  text: string;
  /** Escalada de un hallazgo (src/cadenas.ts): cuenta como intento lo que diga su fila, no la ruta. */
  tried?: (entries: HttpClient["log"]) => boolean;
  /** Veces que se objeta; por defecto maxPerCrack. */
  max?: number;
  /** Se resuelve al documentar el informe, independientemente del tráfico posterior. */
  soloInforme?: boolean;
}

export interface ClosingGateOptions {
  http: HttpClient;
  findings: Findings;
  /** Sesión del tráfico: sólo sus hallazgos cierran grietas (otra sesión puede ser otro programa con las mismas rutas). */
  sessionId?: string;
  /** Fracción del presupuesto que queda (0 a 1), o undefined si nada acota la sesión: entonces no se objeta. */
  budgetLeft: () => number | undefined;
  /** Con esta fracción o menos, el cierre se acepta aunque haya grietas. Por defecto 0.5. */
  fraction?: number;
  /** Veces que se objeta la misma grieta en la sesión. Por defecto 2. */
  maxPerCrack?: number;
  /** Grafo de hechos: las escaladas nombran sus nodos reales (src/cadenas.ts). */
  grafo?: () => Vista;
  grafoConsultado?: () => boolean;
}

const READS = new Set(["GET", "HEAD", "OPTIONS"]);
const WRITES = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const denied = (status: number | undefined) => status === 401 || status === 403;
const served = (status: number | undefined) => status !== undefined && status >= 200 && status < 300;

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

/**
 * Familia de una ruta: canónica y con los ids (números, UUID, ObjectId) como {n}, igual que la
 * cobertura, sin pasar por `URL`, que codificaría las llaves de una familia ya normalizada.
 */
function familyOf(path: string): string {
  return canonicalPath(path).split("/").map((segment) => (ID_SEGMENT.test(segment) ? "{n}" : segment)).join("/");
}

const idsOf = (path: string) => canonicalPath(path).split("/").filter((segment) => ID_SEGMENT.test(segment));

export class ClosingGate {
  private readonly http: HttpClient;
  private readonly findings: Findings;
  private readonly sessionId: string | undefined;
  private readonly budgetLeft: () => number | undefined;
  private readonly grafo?: () => Vista;
  private readonly grafoConsultado?: () => boolean;
  readonly fraction: number;
  readonly maxPerCrack: number;
  private readonly objected = new Map<string, number>();
  /** Largo del registro HTTP cuando se objetó cada grieta: lo posterior es lo que el agente intentó. */
  private readonly objectedAt = new Map<string, number>();

  constructor(options: ClosingGateOptions) {
    this.http = options.http;
    this.findings = options.findings;
    this.sessionId = options.sessionId;
    this.budgetLeft = options.budgetLeft;
    this.grafo = options.grafo;
    this.grafoConsultado = options.grafoConsultado;
    this.fraction = options.fraction ?? 0.5;
    this.maxPerCrack = options.maxPerCrack ?? 2;
  }

  private get log() {
    return this.http.log.filter((entry) => !entry.synthetic && entry.status !== undefined);
  }

  /**
   * Un id negado en su familia (401/403 donde otro id respondió) que otra operación sirvió: un
   * sub-recurso que lo entrega (/items/{n}/attachments) o una escritura que lo aceptó (PUT /items/{n}).
   * Es el «recurso ajeno que respondió distinto» y la «operación que aceptó de más» del punto 93.
   */
  foreignServed(): Crack[] {
    const families = new Map<string, { ok: Set<string>; denied: Map<string, number> }>();
    for (const entry of this.log) {
      if (!READS.has(entry.method)) continue;
      const path = pathOf(entry.url);
      const family = familyOf(path);
      if (!family.includes("{n}")) continue;
      const id = idsOf(path).join("/");
      const group = families.get(family) ?? { ok: new Set<string>(), denied: new Map<string, number>() };
      if (served(entry.status)) group.ok.add(id);
      else if (denied(entry.status)) group.denied.set(id, entry.status!);
      families.set(family, group);
    }
    const cracks = new Map<string, Crack>();
    for (const [family, group] of families) {
      if (!group.ok.size) continue;
      for (const [id, status] of group.denied) {
        if (group.ok.has(id)) continue;
        const numbers = new Set(id.split("/"));
        for (const entry of this.log) {
          if (!served(entry.status)) continue;
          const path = pathOf(entry.url);
          const other = familyOf(path);
          if (!idsOf(path).some((number) => numbers.has(number))) continue;
          const write = WRITES.has(entry.method);
          const child = other !== family && other.startsWith(`${family}/`);
          if (write && (other === family || child)) {
            const key = `escritura-con-id-ajeno:${entry.method} ${other}`;
            if (!cracks.has(key)) cracks.set(key, { key, path: other, text: `${entry.method} ${other} aceptó el id ${id} con HTTP ${entry.status}, y ese id te lo negaron al leerlo en ${family} (HTTP ${status}): una escritura sobre un recurso que no es tuyo. Es un candidato: registralo con finding_record con las dos respuestas como evidencia, o un descartado con el motivo si la escritura no cambió nada.` });
          } else if (!write && child) {
            const key = `sub-recurso-ajeno-servido:${other}`;
            if (!cracks.has(key)) cracks.set(key, { key, path: other, text: `${other} sirvió el id ${id} con HTTP ${entry.status}, y ese id te lo negaron en ${family} (HTTP ${status}): el sub-recurso no comprueba al dueño. Registralo con finding_record (candidato si el contenido es del otro usuario; descartado con motivo si está vacío o es público).` });
          }
        }
      }
    }
    return [...cracks.values()];
  }

  /**
   * Un recurso negado al leerlo (401/403) que aceptó una escritura con la misma autenticación.
   * `except` son las escrituras («MÉTODO familia») que otra regla ya reportó, para no repetirlas.
   */
  writesOnDenied(except = new Set<string>()): Crack[] {
    const deniedReads = new Map<string, number>();
    const okReads = new Set<string>();
    for (const entry of this.log) {
      if (!READS.has(entry.method)) continue;
      const key = `${canonicalPath(pathOf(entry.url))}|${entry.sentAuth ? "auth" : "anon"}`;
      if (denied(entry.status)) deniedReads.set(key, entry.status!);
      else if (served(entry.status)) okReads.add(key);
    }
    const cracks = new Map<string, Crack>();
    for (const entry of this.log) {
      if (!WRITES.has(entry.method) || !served(entry.status)) continue;
      const path = canonicalPath(pathOf(entry.url));
      if (except.has(`${entry.method} ${familyOf(path)}`)) continue;
      const key = `${path}|${entry.sentAuth ? "auth" : "anon"}`;
      const status = deniedReads.get(key);
      if (status === undefined || okReads.has(key)) continue;
      const crack = `escritura-sobre-negado:${entry.method} ${path}`;
      if (!cracks.has(crack)) cracks.set(crack, { key: crack, path, text: `${path} te negó la lectura (HTTP ${status}) pero aceptó ${entry.method} con HTTP ${entry.status}, con la misma autenticación: la escritura no pasa por el control que sí tiene la lectura. Registralo con finding_record (candidato), o descartado con motivo si el 2xx no persistió nada.` });
    }
    return [...cracks.values()];
  }

  /**
   * Dos formas del mismo texto de ruta (barra final, punto y coma, mayúsculas) con respuestas
   * opuestas y la misma autenticación: una capa autoriza y otra sirve.
   */
  variantServed(): Crack[] {
    const groups = new Map<string, Map<string, { denied?: number; served?: number }>>();
    for (const entry of this.log) {
      if (!READS.has(entry.method)) continue;
      const raw = pathOf(entry.url);
      const key = `${canonicalPath(raw)}|${entry.sentAuth ? "auth" : "anon"}`;
      const forms = groups.get(key) ?? new Map<string, { denied?: number; served?: number }>();
      const form = forms.get(raw) ?? {};
      if (denied(entry.status)) form.denied = entry.status;
      else if (served(entry.status)) form.served = entry.status;
      forms.set(raw, form);
      groups.set(key, forms);
    }
    const cracks: Crack[] = [];
    for (const [key, forms] of groups) {
      if (forms.size < 2) continue;
      const refused = [...forms].find(([, form]) => form.denied !== undefined && form.served === undefined);
      const open = [...forms].find(([, form]) => form.served !== undefined && form.denied === undefined);
      if (!refused || !open) continue;
      const path = key.split("|")[0]!;
      cracks.push({ key: `forma-de-ruta-servida:${path}`, path, text: `GET ${refused[0]} respondió HTTP ${refused[1].denied} y GET ${open[0]}, otra forma del mismo texto, respondió HTTP ${open[1].served} con la misma autenticación: la capa que autoriza y la que sirve leen la ruta distinto. Registralo con finding_record (candidato con las dos respuestas), o descartado con motivo si las dos devuelven lo mismo.` });
    }
    return cracks;
  }

  /**
   * Familias de recursos de API que respondieron 2xx y donde nunca se intentó una escritura (el mismo
   * criterio que `Coverage.readOnlyPaths`), más las rutas vistas con un método de escritura sin probar.
   */
  untestedWrites(): Crack[] {
    const paths = new Set<string>();
    for (const row of this.http.surface()) {
      if (!row.methods.length || !row.statuses.some((status) => status < 300)) continue;
      if (row.methods.every((method) => READS.has(method)) && /\/api\/|\{n\}/.test(row.path)) paths.add(row.path);
      if (row.seenMethods.some((method) => WRITES.has(method) && !row.methods.includes(method))) paths.add(row.path);
    }
    return [...paths].map((path) => ({ key: `familia-sin-escritura:${path}`, path, text: `${path} respondió 2xx y no se probó POST, PUT, PATCH ni DELETE sobre esa ruta: una llamada a http_probe con methods dice qué acepta. Hasta ahí, «sólo lectura» es una suposición.` }));
  }

  /** Contexto para la tabla de cadenas: el tráfico, el alcance y las cookies de sesión vistas. */
  private chainContext(): ChainContext {
    let cookies: ReturnType<typeof sessionCookies> | undefined;
    const read = (hash: string) => {
      try { return this.http.artifacts.read(hash).toString("utf8"); } catch { return undefined; }
    };
    let grafo: Vista | undefined;
    try { grafo = this.grafo?.(); } catch { /* sin grafo, las acciones salen del tráfico como antes */ }
    return { log: this.log, scope: this.http.scope(), cookies: () => (cookies ??= sessionCookies(this.log, read)), ...(grafo ? { grafo } : {}) };
  }

  /**
   * Hallazgos bajos o medios de la sesión con una escalada conocida sin intentar ni vincular (tabla en
   * src/cadenas.ts). Lo que cuenta como intento lo dice cada fila.
   */
  escalations(ctx = this.chainContext()): Crack[] {
    return pendingEscalations(this.findings.list({ sessionId: this.sessionId }), this.findings.list(), ctx).map((item) => ({
      key: item.key,
      path: item.finding.asset,
      text: `${item.finding.id.slice(0, 8)} («${item.finding.title}», ${item.finding.severity}) es un ${item.rule.from} y su escalada conocida es ${item.rule.to}, sin intentar. ${item.text}`,
      tried: (entries) => item.rule.tried(entries, item.finding, ctx),
      ...(item.once ? { max: 1 } : {}),
    }));
  }

  /** Observaciones para el informe que se resuelven con la evidencia ya guardada. */
  pendientesDeInforme(vista?: Vista): Crack[] {
    // Cada objeción es un turno más del modelo releyendo todo el contexto: los vectores pendientes van juntos
    // en una sola, y cada observación de informe se hace una vez.
    const pendientes: Crack[] = [];
    const sinVector = this.findings.list({ sessionId: this.sessionId })
      .filter((item) => item.state === "candidato" && !item.cvss && ["media", "alta", "critica"].includes(item.severity));
    if (sinVector.length) {
      const lista = sinVector.slice(0, 8).map((item) => `${item.id.slice(0, 8)} (${item.severity})`).join(", ");
      pendientes.push({
        key: "informe:cvss", path: sinVector[0]!.asset, soloInforme: true, max: 1,
        text: `${sinVector.length === 1 ? "El candidato" : "Los candidatos"} ${lista}${sinVector.length > 8 ? ` y ${sinVector.length - 8} más` : ""} tienen severidad estimada sin vector. Usá finding_update con cvss donde la evidencia guardada respalde las ocho métricas; si falta evidencia, indicá qué métrica quedó pendiente en el informe.`,
      });
    }
    if (vista && this.grafoConsultado?.() === false) {
      const cantidad = calcularFaltantes(vista, { identidades: this.http.identityNames() }).length;
      if (cantidad) pendientes.push({
        key: "informe:grafo", path: "", soloInforme: true, max: 1,
        text: `El grafo registra ${cantidad} pendientes y quedó sin consultar en esta sesión. Indicá la cobertura parcial en el resumen al operador.`,
      });
    }
    return pendientes;
  }

  /** Todas las grietas que el tráfico muestra hoy, sin cruzar con hallazgos ni contar objeciones. */
  cracks(): Crack[] {
    const foreign = this.foreignServed();
    const reportedWrites = new Set(foreign.filter((crack) => crack.key.startsWith("escritura-con-id-ajeno:")).map((crack) => crack.key.slice("escritura-con-id-ajeno:".length)));
    const seen = new Set<string>();
    return [...foreign, ...this.writesOnDenied(reportedWrites), ...this.variantServed(), ...this.untestedWrites()].filter((crack) => !seen.has(crack.key) && seen.add(crack.key));
  }

  /** Un hallazgo de cualquier estado cuyo activo sea la ruta, su familia, un padre o un hijo cierra la grieta. */
  private covered(crack: Crack): boolean {
    const target = familyOf(crack.path);
    return this.findings.list({ sessionId: this.sessionId }).some((finding) => {
      const asset = familyOf(pathOf(finding.asset));
      if (asset === "/" ) return false;
      return asset === target || target.startsWith(`${asset}/`) || asset.startsWith(`${target}/`);
    });
  }

  /** Grietas sin hallazgo que las nombre. Para el aviso al operador y para el evento de cierre. */
  open(): Crack[] {
    return this.cracks().filter((crack) => !this.covered(crack));
  }

  /**
   * ¿El agente pidió algo de la ruta de la grieta (o de su familia, un padre o un hijo) después de que
   * se la objetaron? Entonces ya la intentó: si sigue abierta, se la dice al operador, no otra vez a él.
   */
  private attempted(crack: Crack): boolean {
    const from = this.objectedAt.get(crack.key);
    if (from === undefined || crack.soloInforme) return false;
    if (crack.tried) return crack.tried(this.http.log.slice(from));
    const target = familyOf(crack.path);
    return this.http.log.slice(from).some((entry) => {
      const family = familyOf(pathOf(entry.url));
      return family === target || family.startsWith(`${target}/`) || target.startsWith(`${family}/`);
    });
  }

  /**
   * Grietas abiertas y escaladas pendientes que todavía se pueden objetar. Primero lo que el tráfico ya
   * muestra roto, después las escaladas de hallazgos registrados y al final las familias sin escritura.
   */
  objectionable(): Crack[] {
    const open = this.open();
    const weak = (crack: Crack) => crack.key.startsWith("familia-sin-escritura:");
    const ctx = this.chainContext();
    return [...open.filter((crack) => !weak(crack)), ...this.escalations(ctx), ...open.filter(weak), ...this.pendientesDeInforme(ctx.grafo)].filter((crack) => (this.objected.get(crack.key) ?? 0) < (crack.max ?? this.maxPerCrack) && !this.attempted(crack));
  }

  /**
   * Qué objetar al cierre, o undefined si se acepta. Sólo con tráfico en el turno, con presupuesto
   * acotado del que quede más de la fracción, y con una grieta abierta que no se haya objetado ya.
   * Nombra una sola grieta: una acción concreta, no una lista.
   */
  objection(requestsThisTurn: number): { text: string; cracks: Crack[] } | undefined {
    if (requestsThisTurn === 0) return undefined;
    const remainingRequests = this.http.remaining();
    if (remainingRequests !== undefined && remainingRequests < 3) return undefined;
    const left = this.budgetLeft();
    if (left === undefined || left <= this.fraction) return undefined;
    const open = this.objectionable();
    const crack = open[0];
    if (!crack) return undefined;
    this.objected.set(crack.key, (this.objected.get(crack.key) ?? 0) + 1);
    this.objectedAt.set(crack.key, this.http.log.length);
    const more = open.length > 1 ? ` Hay ${open.length - 1} más; si no llegás, el operador las ve al cerrar.` : "";
    if (crack.soloInforme) {
      return { text: `[sistema] Antes de presentar el informe. ${crack.text}`, cracks: [crack] };
    }
    const text = crack.key.startsWith("escalada:")
      ? [
          `[sistema] Antes de cerrar: queda el ${Math.round(left * 100)}% del presupuesto y un hallazgo tiene una escalada conocida sin intentar:`,
          `- ${crack.text}`,
          `Una sola acción: probala y registrá el resultado vinculado (finding_record con related al hallazgo, o finding_update con escalation «intentada» y una nota). Si no se puede, finding_update con escalation «limitada» (o «no aplica») y escalation_note diciendo qué faltó: se acepta siempre. Resumí después.${more}`,
        ].join("\n")
      : [
          `[sistema] Antes de cerrar: queda el ${Math.round(left * 100)}% del presupuesto y el tráfico muestra una grieta concreta sin resolver:`,
          `- ${crack.text}`,
          `Una sola acción: probala y registrá el resultado con finding_record (un descartado con motivo también la cierra). Resumí después.${more}`,
        ].join("\n");
    return { text, cracks: [crack] };
  }
}
