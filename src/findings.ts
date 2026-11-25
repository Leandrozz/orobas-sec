// Hallazgos como datos. El agente registra pistas y candidatos con su evidencia;
// «verificado» sólo lo pone un verificador o el operador, nunca el modelo.
import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { calcularCvss } from "./cvss.ts";
import { LAST_MSG_SEQ } from "./store.ts";

/** Un id copiado del chat puede venir con comillas, «», #, o un punto o una coma al final. */
export const cleanRef = (ref: string): string => ref.trim().replace(/^[«"'`#(\[]+|[»"'`)\].,;:!?]+$/g, "").trim();

export const STATES = ["pista", "candidato", "verificado", "descartado"] as const;
export type FindingState = (typeof STATES)[number];
export const SEVERITIES = ["informativa", "baja", "media", "alta", "critica"] as const;

/**
 * Rol de un vínculo entre hallazgos, desde el que lo declara: «escala» (éste es la escalada del
 * vinculado: el open redirect que se lleva el token escala al open redirect), «habilita» (éste es el
 * eslabón previo que hace posible al vinculado) o «relacionado» (misma causa, misma familia).
 */
export const LINK_ROLES = ["escala", "habilita", "relacionado"] as const;
export type LinkRole = (typeof LINK_ROLES)[number];
export interface FindingLink {
  id: string;
  role: LinkRole;
}
const INVERSE: Record<LinkRole, LinkRole> = { escala: "habilita", habilita: "escala", relacionado: "relacionado" };

/**
 * Qué pasó con la escalada conocida de un hallazgo bajo o medio (src/cadenas.ts): «intentada» (se probó
 * y la nota dice qué dio), «limitada» (no se pudo: qué faltó y por qué) o «no aplica». Cualquiera la
 * cierra ante la regla de cierre.
 */
export const ESCALATION_STATES = ["intentada", "limitada", "no aplica"] as const;
export type EscalationState = (typeof ESCALATION_STATES)[number];
export interface Escalation {
  state: EscalationState;
  note: string;
  at: string;
}

// Reproducir una observación no demuestra que sea explotable. Los patrones son
// acotados para no bajar CORS permisivo ni listados que exponen datos sensibles.
const INFORMATIONAL_PATTERNS = [
  /(?:cabeceras?(?: de seguridad)?|(?:security )?headers?)\s+(?:ausentes?|faltantes?|missing|absent)/,
  /(?:ausencia de|falta de|sin|missing|absent)\s+(?:cabeceras?(?: de seguridad)?|(?:security )?headers?|csp|hsts|x-frame-options|x-content-type-options|content-security-policy|strict-transport-security)\b/,
  /(?:csp|hsts|x-frame-options|x-content-type-options|content-security-policy|strict-transport-security).{0,40}(?:ausente|faltante|missing|absent)/,
  /(?:cors.{0,25}(?:ausente|faltante|missing|absent)|(?:sin|ausencia de|missing|absent) cors)/,
  /(?:version(?:es)?|versions?).{0,40}(?:expuest|expos|revelad|disclosure)/,
  /(?:exposicion|divulgacion|disclosure).{0,30}(?:version|versions)/,
  /(?:listado|directory listing).{0,70}(?:sin (?:datos|informacion|archivos) sensibles|without sensitive (?:data|files)|no sensitive data)/,
] as const;

const plain = (text: string) => text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();

export function effectiveSeverity(finding: Pick<Finding, "kind" | "title" | "severity" | "cvss">): Finding["severity"] {
  // Una observación informativa (cabeceras ausentes, versión expuesta) sigue informativa aunque traiga un vector:
  // el vector no puede saltear este piso.
  const text = plain(`${finding.kind} ${finding.title}`);
  if (INFORMATIONAL_PATTERNS.some((pattern) => pattern.test(text))) return "informativa";
  return finding.cvss ? calcularCvss(finding.cvss).severidad : finding.severity;
}

// Un hallazgo habla de lo que hizo el servidor. Lo que describe al cliente o a las herramientas del
// agente (punto 86 de MEJORAS-AGENTE) llegaba al informe como si fuera una falla de la aplicación.
const TOOLING_PATTERNS = [
  /no se pud[oe] (leer|extraer|parsear|interpretar|decodificar|obtener el cuerpo)/,
  /herramienta (lee|leyo|interpreta|interpreto|no pud[oe]|no puede|devuelve|devolvio|corta|corto|trunca|trunco)/,
  /formato del artefacto/,
  /campo indefinido|\bundefined\b|\[object object\]/,
  /extraccion .{0,40}bloqueada/,
  /artefacto .{0,30}(truncad|ilegible|no se pud)/,
] as const;

/** Verdadero si el texto describe un fallo del cliente o de la herramienta y no del servidor. */
export function describesTooling(title: string, summary: string): boolean {
  const text = plain(`${title} ${summary}`);
  return TOOLING_PATTERNS.some((pattern) => pattern.test(text));
}

export interface Finding {
  id: string;
  rev: number;
  state: FindingState;
  title: string;
  /** Clase de problema, p. ej. "control de acceso". */
  kind: string;
  severity: (typeof SEVERITIES)[number];
  cvss?: string;
  /** Activo afectado: host, URL o ruta. */
  asset: string;
  summary: string;
  /** Hashes de artefactos que respaldan la afirmación. */
  evidence: string[];
  /** Qué falta comprobar o qué límites tiene la prueba. */
  limits: string;
  /** Quién fijó el estado actual: "agente", "operador" o "verificador:<id>". */
  decidedBy: string;
  /** Las correcciones de texto no cambian la fecha del veredicto. */
  decidedAt?: string;
  reason: string;
  sessionId: string;
  createdAt: string;
  updatedAt: string;
  /** Hallazgos vinculados (cadenas), con el rol desde éste. El vínculo inverso se calcula al leer (linksOf). */
  related?: FindingLink[];
  /** La escalada conocida de este hallazgo ya se intentó, quedó limitada o no aplica (src/cadenas.ts). */
  escalation?: Escalation;
  /** Revisión de elegibilidad antes de invertir en el candidato. */
  exclusionCercana?: string;
  porQueNoAplica?: string;
  /** Una pista fuera del modelo de confianza cierra la grieta correspondiente ante el control de cierre. */
  fueraModeloConfianza?: string;
}

/** Un vínculo como lo manda el agente: el id (o prefijo) solo, o con su rol; «quitar» lo borra. */
export type LinkInput = string | { id: string; role?: string };

export interface FindingInput {
  title: string;
  kind: string;
  severity?: string;
  cvss?: string;
  asset: string;
  summary: string;
  evidence?: string[];
  limits?: string;
  state?: string;
  /** Vínculos con otros hallazgos del proyecto (cadenas). */
  related?: LinkInput[];
  exclusionCercana?: string;
  porQueNoAplica?: string;
  fueraModeloConfianza?: string;
}

export class Findings {
  readonly db: DatabaseSync;
  private hasArtifact: (hash: string) => string | undefined;
  private readArtifact?: (hash: string) => Buffer | undefined;

  constructor(db: DatabaseSync, resolveArtifact: (hash: string) => string | undefined, readArtifact?: (hash: string) => Buffer | undefined) {
    this.db = db;
    this.hasArtifact = resolveArtifact;
    this.readArtifact = readArtifact;
    db.exec("create table if not exists findings(id text primary key, json text not null)");
  }

  /** Qué es un artefacto de evidencia: un intercambio con respuesta, uno sin respuesta (error del cliente) u otra cosa. */
  private kindOf(hash: string): "respuesta" | "sin-respuesta" | "otro" {
    try {
      const data = JSON.parse(this.readArtifact?.(hash)?.toString("utf8") ?? "") as { request?: unknown; response?: unknown };
      if (data && typeof data === "object" && "request" in data) return data.response ? "respuesta" : "sin-respuesta";
    } catch {}
    return "otro";
  }

  /** Un candidato tiene que hablar del servidor y apoyarse en al menos una respuesta suya. */
  private rejectToolingClaim(title: string, summary: string, evidence: string[]): void {
    if (describesTooling(title, summary)) throw new Error("Eso describe un fallo de la herramienta o del cliente, no de la aplicación: no se registra como candidato. Si la respuesta del servidor muestra una falla, registrá eso, con ese intercambio como evidencia.");
    if (this.readArtifact && evidence.length && evidence.every((hash) => this.kindOf(hash) === "sin-respuesta")) {
      throw new Error("Toda la evidencia son peticiones sin respuesta del servidor (error del cliente): eso es un fallo de la herramienta, no de la aplicación. Dejalo como pista si querés constancia.");
    }
  }

  /** Un hallazgo por id completo o por un prefijo que no se confunde con otro. Ambiguo o inexistente: undefined. */
  get(idOrPrefix: string): Finding | undefined {
    const found = this.matching(idOrPrefix);
    return found.length === 1 ? found[0] : undefined;
  }

  /**
   * Lo que pidió el operador (o el agente) por id: exactamente ese registro. Acepta el id completo o su
   * prefijo (el corto que muestran las herramientas), aunque venga copiado con comillas o un punto al final.
   * Si no existe o el prefijo es de más de uno, el error lo dice y lista los ids que sí sirven: nunca se
   * elige otro registro en su lugar. Antes era un LIKE con «limit 1» sin orden: con un prefijo corto o
   * ambiguo devolvía cualquiera.
   */
  resolve(ref: string, options: { sessionId?: string; state?: FindingState } = {}): Finding {
    const clean = cleanRef(ref);
    const found = this.matching(clean);
    if (found.length === 1) return found[0]!;
    const show = (item: Finding) => `${item.id.slice(0, 8)} (${item.state}, «${item.title.slice(0, 50)}»${options.sessionId && item.sessionId !== options.sessionId ? ", de otra sesión" : ""})`;
    if (found.length > 1) throw new Error(`«${clean}» corresponde a ${found.length} hallazgos: ${found.slice(0, 8).map(show).join("; ")}. Pasá más caracteres del id.`);
    const valid = this.list().filter((item) => !options.state || item.state === options.state);
    // Los de la sesión primero: son los que el operador acaba de ver en el chat.
    const ordered = [...valid.filter((item) => item.sessionId === options.sessionId), ...valid.filter((item) => item.sessionId !== options.sessionId)];
    const what = options.state ? `${options.state}s` : "hallazgos";
    throw new Error(`No hay un hallazgo «${clean}» en este proyecto. ${ordered.length ? `Ids de ${what} que sí existen: ${ordered.slice(0, 10).map(show).join("; ")}${ordered.length > 10 ? ` y ${ordered.length - 10} más (/hallazgos)` : ""}.` : `No hay ${what} en este proyecto.`}`);
  }

  private matching(ref: string): Finding[] {
    const clean = cleanRef(ref).toLowerCase();
    if (!clean) return [];
    const parse = (row: { json: string }) => {
      const finding = JSON.parse(row.json) as Finding;
      return { ...finding, severity: effectiveSeverity(finding) };
    };
    const exact = this.db.prepare("select json from findings where lower(id) = ?").get(clean) as { json: string } | undefined;
    if (exact) return [parse(exact)];
    // Prefijo literal (substr, no LIKE: un «_» o un «%» del texto no son comodines).
    return (this.db.prepare("select json from findings where lower(substr(id, 1, ?)) = ?").all(clean.length, clean) as Array<{ json: string }>).map(parse);
  }

  /** Hallazgos del proyecto, o sólo los de una sesión: cada sesión trabaja su programa. */
  list(filter: { sessionId?: string } = {}): Finding[] {
    return (this.db.prepare("select json from findings").all() as Array<{ json: string }>)
      .map((row) => {
        const finding = JSON.parse(row.json) as Finding;
        return { ...finding, severity: effectiveSeverity(finding) };
      })
      .filter((finding) => !filter.sessionId || finding.sessionId === filter.sessionId)
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  private put(finding: Finding): Finding {
    if (!SEVERITIES.includes(finding.severity)) throw new Error(`Severidad inválida. Usar: ${SEVERITIES.join(", ")}`);
    finding.severity = effectiveSeverity(finding);
    this.db.prepare("insert or replace into findings(id,json) values(?,?)").run(finding.id, JSON.stringify(finding));
    this.db
      .prepare(`insert into events(session_id,type,at,payload,msg_seq) values(?,?,?,?,${LAST_MSG_SEQ})`)
      .run(finding.sessionId, "finding.changed", finding.updatedAt, JSON.stringify({ id: finding.id, rev: finding.rev, state: finding.state, by: finding.decidedBy }), finding.sessionId);
    try { this.onChange?.(finding); } catch { /* el grafo de hechos nunca rompe un registro */ }
    return finding;
  }

  /** Cada alta o cambio de un hallazgo (el grafo de hechos lo toma: src/grafo-alimentar.ts). */
  onChange?: (finding: Finding) => void;

  private evidence(hashes: string[] | undefined): string[] {
    return (hashes ?? []).map((hash) => {
      const full = this.hasArtifact(hash);
      if (!full) throw new Error(`La evidencia ${hash} no es un artefacto guardado de este proyecto`);
      return full;
    });
  }

  /** Alta por el agente: pista (sin evidencia) o candidato (con evidencia). */
  record(input: FindingInput, sessionId: string): Finding {
    const state = (input.state ?? "candidato") as FindingState;
    if (state !== "pista" && state !== "candidato") throw new Error("Sólo se puede registrar como pista o candidato. Verificar le corresponde a un verificador o al operador.");
    const evidence = this.evidence(input.evidence);
    if (state === "candidato" && !evidence.length) throw new Error("Un candidato necesita al menos un artefacto de evidencia. Sin evidencia, registralo como pista.");
    if (state === "candidato") this.rejectToolingClaim(input.title, input.summary, evidence);
    if (state === "candidato" && input.fueraModeloConfianza?.trim()) throw new Error("Una hipótesis fuera del modelo de confianza se registra como pista, no como candidato.");
    const severity = (input.severity ?? "media") as Finding["severity"];
    if (!SEVERITIES.includes(severity)) throw new Error(`Severidad inválida. Usar: ${SEVERITIES.join(", ")}`);
    const same = this.list().find((item) => item.state !== "descartado" && item.asset === input.asset.trim() && item.kind === input.kind.trim().toLowerCase());
    if (same) throw new Error(`Ya existe ${same.id.slice(0, 8)} («${same.title}») para ese activo y clase${same.sessionId !== sessionId ? ", registrado en otra sesión de este proyecto" : ""}. Actualizalo con finding_update.`);
    const now = new Date().toISOString();
    const id = randomUUID();
    const related = this.links([], input.related, id);
    return this.put({
      id,
      rev: 1,
      state,
      title: input.title.trim(),
      kind: input.kind.trim().toLowerCase(),
      severity,
      cvss: input.cvss?.trim() || undefined,
      asset: input.asset.trim(),
      summary: input.summary.trim(),
      evidence,
      limits: input.limits?.trim() ?? "",
      exclusionCercana: input.exclusionCercana?.trim() || undefined,
      porQueNoAplica: input.porQueNoAplica?.trim() || undefined,
      fueraModeloConfianza: input.fueraModeloConfianza?.trim() || undefined,
      decidedBy: "agente",
      decidedAt: now,
      reason: "",
      sessionId,
      createdAt: now,
      updatedAt: now,
      ...(related.length ? { related } : {}),
    });
  }

  /**
   * Vínculos nuevos sobre los que ya hay: cada id tiene que ser un hallazgo del proyecto distinto de éste;
   * el mismo id con otro rol reemplaza al anterior y el rol «quitar» lo borra.
   */
  private links(current: FindingLink[], input: LinkInput[] | undefined, self: string): FindingLink[] {
    const result = new Map(current.map((link) => [link.id, link]));
    for (const item of input ?? []) {
      const raw = typeof item === "string" ? { id: item } : item;
      const ref = String(raw?.id ?? "").trim();
      if (!ref) continue;
      const role = String(raw.role ?? "relacionado").trim().toLowerCase();
      const target = this.get(ref);
      if (role === "quitar") {
        if (target) result.delete(target.id);
        continue;
      }
      if (!(LINK_ROLES as readonly string[]).includes(role)) throw new Error(`Rol de vínculo inválido «${role}». Usar: ${LINK_ROLES.join(", ")} (o «quitar»).`);
      if (!target) throw new Error(`No existe el hallazgo ${ref} para vincular. Mirá los ids con finding_list.`);
      if (target.id === self) throw new Error("Un hallazgo no se vincula consigo mismo.");
      result.set(target.id, { id: target.id, role: role as LinkRole });
    }
    return [...result.values()];
  }

  /**
   * Vínculos de un hallazgo en las dos direcciones: los que declara y los que otros declaran hacia él,
   * con el rol visto desde éste («habilita» del otro lado es «escala» de este lado).
   */
  linksOf(id: string, all: Finding[] = this.list()): Array<{ finding: Finding; role: LinkRole }> {
    const self = all.find((item) => item.id === id) ?? this.get(id);
    if (!self) return [];
    const result = new Map<string, { finding: Finding; role: LinkRole }>();
    for (const link of self.related ?? []) {
      const other = all.find((item) => item.id === link.id);
      if (other) result.set(other.id, { finding: other, role: link.role });
    }
    for (const other of all) {
      if (other.id === self.id || result.has(other.id)) continue;
      const link = (other.related ?? []).find((item) => item.id === self.id);
      if (link) result.set(other.id, { finding: other, role: INVERSE[link.role] });
    }
    return [...result.values()];
  }

  /**
   * La cadena de un hallazgo: él y todos los alcanzables por vínculos, con el primer eslabón primero
   * (el que habilita antes que el que escala; a igualdad, el más viejo). Sin vínculos, sólo él.
   */
  chainOf(id: string, all: Finding[] = this.list()): Finding[] {
    const start = all.find((item) => item.id === id) ?? this.get(id);
    if (!start) return [];
    const members = new Map<string, Finding>([[start.id, start]]);
    const queue = [start];
    while (queue.length) {
      const current = queue.shift()!;
      for (const { finding } of this.linksOf(current.id, all)) {
        if (members.has(finding.id)) continue;
        members.set(finding.id, finding);
        queue.push(finding);
      }
    }
    // Orden: arista habilitador → escalada; lo demás, por fecha.
    const before = new Map<string, Set<string>>([...members.keys()].map((key) => [key, new Set<string>()]));
    for (const member of members.values()) {
      for (const link of member.related ?? []) {
        if (!members.has(link.id) || link.role === "relacionado") continue;
        if (link.role === "habilita") before.get(link.id)!.add(member.id);
        else before.get(member.id)!.add(link.id);
      }
    }
    const ordered: Finding[] = [];
    const pending = [...members.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    while (pending.length) {
      const index = pending.findIndex((item) => [...before.get(item.id)!].every((need) => ordered.some((done) => done.id === need)));
      ordered.push(...pending.splice(index < 0 ? 0 : index, 1));
    }
    return ordered;
  }

  /** Cambios del agente: sumar evidencia, corregir texto, pasar de pista a candidato o descartar con motivo. */
  update(id: string, change: Partial<FindingInput> & { reason?: string; escalation?: string; escalationNote?: string }, sessionId: string): Finding {
    const current = this.get(id);
    if (!current) throw new Error(`No existe el hallazgo ${id}`);
    const state = (change.state ?? current.state) as FindingState;
    if (state === "verificado" && current.state !== "verificado") throw new Error("El agente no puede marcar un hallazgo como verificado.");
    if (current.state === "verificado" && state !== "verificado") throw new Error("Un hallazgo verificado sólo lo puede cambiar el operador.");
    if (!STATES.includes(state)) throw new Error(`Estado inválido. Usar: pista, candidato o descartado`);
    if (state === "descartado" && !change.reason?.trim()) throw new Error("Para descartar hace falta el motivo.");
    const evidence = [...new Set([...current.evidence, ...this.evidence(change.evidence)])];
    if (state === "candidato" && !evidence.length) throw new Error("Un candidato necesita al menos un artefacto de evidencia.");
    if (state === "candidato") this.rejectToolingClaim(change.title?.trim() || current.title, change.summary?.trim() || current.summary, evidence);
    if (state === "candidato" && (change.fueraModeloConfianza ?? current.fueraModeloConfianza)?.trim()) throw new Error("Una hipótesis fuera del modelo de confianza se registra como pista, no como candidato.");
    const related = this.links(current.related ?? [], change.related, current.id);
    let escalation = current.escalation;
    if (change.escalation !== undefined && String(change.escalation).trim()) {
      const wanted = String(change.escalation).trim().toLowerCase();
      if (!(ESCALATION_STATES as readonly string[]).includes(wanted)) throw new Error(`Escalada inválida «${wanted}». Usar: ${ESCALATION_STATES.join(", ")}.`);
      const note = String(change.escalationNote ?? "").trim();
      if (!note) throw new Error("Para marcar la escalada hace falta escalation_note: qué probaste, o qué faltó y por qué.");
      escalation = { state: wanted as EscalationState, note, at: new Date().toISOString() };
    }
    return this.put({
      ...current,
      rev: current.rev + 1,
      state,
      title: change.title?.trim() || current.title,
      cvss: change.cvss === undefined ? current.cvss : change.cvss.trim() || undefined,
      severity: (change.severity as Finding["severity"]) ?? current.severity,
      summary: change.summary?.trim() || current.summary,
      limits: change.limits?.trim() ?? current.limits,
      exclusionCercana: change.exclusionCercana?.trim() || current.exclusionCercana,
      porQueNoAplica: change.porQueNoAplica?.trim() || current.porQueNoAplica,
      fueraModeloConfianza: change.fueraModeloConfianza === undefined ? current.fueraModeloConfianza : change.fueraModeloConfianza.trim() || undefined,
      evidence,
      decidedBy: state === current.state ? current.decidedBy : "agente",
      decidedAt: state === current.state ? (current.decidedAt ?? current.updatedAt) : new Date().toISOString(),
      reason: change.reason?.trim() ?? current.reason,
      sessionId,
      updatedAt: new Date().toISOString(),
      related: related.length ? related : undefined,
      escalation,
    });
  }

  /** Veredicto de un verificador independiente. Un candidato ya verificado o descartado por él sólo lo cambia el operador. */
  verdict(id: string, state: FindingState, reason: string, evidence: string[], by: string, correction: { title?: string } = {}): Finding {
    const current = this.get(id);
    if (!current) throw new Error(`No existe el hallazgo ${id}`);
    if (!by.startsWith("verificador")) throw new Error("El veredicto lo dicta un verificador");
    if (!["verificado", "descartado", "candidato"].includes(state)) throw new Error("Veredicto inválido: verificado, descartado o candidato");
    const merged = [...new Set([...current.evidence, ...evidence.filter((hash) => this.hasArtifact(hash))])];
    if (state === "verificado" && !merged.length) throw new Error("No se puede verificar un hallazgo sin evidencia guardada.");
    const now = new Date().toISOString();
    // El verificador puede corregir el título cuando demostró una causa distinta de la afirmada.
    const title = correction.title?.trim() || current.title;
    return this.put({ ...current, rev: current.rev + 1, state, title, evidence: merged, decidedBy: by, decidedAt: now, reason: reason.trim(), updatedAt: now });
  }

  /** Decisión del operador desde la interfaz. Queda registrado que fue una revisión humana. */
  decide(id: string, state: FindingState, reason: string): Finding {
    const current = this.get(id);
    if (!current) throw new Error(`No existe el hallazgo ${id}`);
    if (!STATES.includes(state)) throw new Error(`Estado inválido. Usar: ${STATES.join(", ")}`);
    if (state === "verificado" && !current.evidence.length) throw new Error("No se puede verificar un hallazgo sin evidencia guardada.");
    const now = new Date().toISOString();
    return this.put({ ...current, rev: current.rev + 1, state, decidedBy: "operador", decidedAt: now, reason: reason.trim(), updatedAt: now });
  }
}

const MARK: Record<FindingState, string> = { pista: "·", candidato: "?", verificado: "✓", descartado: "✗" };
/** Cómo se lee un vínculo desde el hallazgo que se muestra. */
const ROLE_TEXT: Record<LinkRole, string> = { escala: "es la escalada de", habilita: "habilita a", relacionado: "relacionado con" };

/**
 * Vista de hallazgos para el operador. Con `sessionId`, la lista es la de esa sesión y avisa cuántos
 * hay en el resto del proyecto; «todos» como argumento (o sin sesión) muestra el proyecto entero.
 * El detalle y el cambio de estado por id valen para cualquier hallazgo del proyecto.
 */
export function findingsView(findings: Findings, arg: string, sessionId?: string): string[] {
  const words = arg.split(/\s+/).filter(Boolean);
  const everything = /^(todos|todo|proyecto|all)$/i.test(words[0] ?? "");
  if (everything) words.shift();
  const [first, ...rest] = words;
  if (first && (STATES as readonly string[]).includes(rest[0] ?? "")) {
    const changed = findings.decide(first, rest[0] as FindingState, rest.slice(1).join(" ") || "revisión del operador");
    return [`${changed.id.slice(0, 8)} pasó a ${changed.state} (revisión del operador).`];
  }
  if (first) {
    const item = findings.get(first);
    if (!item) return [`No existe el hallazgo ${first}.`];
    const all = findings.list();
    const links = findings.linksOf(item.id, all);
    const chain = links.length ? findings.chainOf(item.id, all) : [];
    return [
      `HALLAZGO ${item.id.slice(0, 8)} · ${item.state} · ${item.severity} · rev ${item.rev}`,
      item.title,
      `Clase: ${item.kind} · Activo: ${item.asset}`,
      item.summary,
      ...(item.cvss ? [`CVSS 3.1 · ${calcularCvss(item.cvss).puntaje.toFixed(1)} · ${item.cvss}`] : []),
      `Evidencia: ${item.evidence.length ? item.evidence.map((hash) => hash.slice(7, 19)).join(", ") : "ninguna"}`,
      ...(item.limits ? [`Falta comprobar: ${item.limits}`] : []),
      `Estado fijado por: ${item.decidedBy}${item.reason ? ` — ${item.reason}` : ""}`,
      ...links.map(({ finding, role }) => `Vínculo: ${ROLE_TEXT[role]} ${finding.id.slice(0, 8)} «${finding.title.slice(0, 60)}» (${finding.state}, ${finding.severity})`),
      ...(chain.length > 1 ? [`Cadena: ${chain.map((link) => `${link.id.slice(0, 8)} ${link.severity}`).join(" → ")}`] : []),
      ...(item.escalation ? [`Escalada: ${item.escalation.state} — ${item.escalation.note}`] : []),
      `Cambiar: /findings ${item.id.slice(0, 8)} <verificado|descartado|candidato> [motivo]`,
    ];
  }
  const own = !everything && sessionId ? sessionId : undefined;
  const all = findings.list({ sessionId: own });
  const others = own ? findings.list().length - all.length : 0;
  const where = own ? " · esta sesión" : sessionId ? " · todo el proyecto" : "";
  const elsewhere = others ? [`En otras sesiones de este proyecto hay ${others} más: /findings todos`] : [];
  if (!all.length) return [`HALLAZGOS${where} · ninguno registrado`, ...elsewhere];
  const count = (state: FindingState) => all.filter((item) => item.state === state).length;
  const project = findings.list();
  const chained = (item: Finding) => {
    const ids = findings.linksOf(item.id, project).map(({ finding }) => finding.id.slice(0, 8));
    return ids.length ? `  ⛓ ${ids.join(",")}` : "";
  };
  return [
    `HALLAZGOS${where} · ${count("verificado")} verificados · ${count("candidato")} candidatos · ${count("pista")} pistas · ${count("descartado")} descartados`,
    ...all.map((item) => `${MARK[item.state]} ${item.id.slice(0, 8)}  ${item.state.padEnd(10)} ${item.severity.padEnd(11)} ${item.title.slice(0, 60)}${chained(item)}`),
    "Detalle: /findings <id>",
    ...elsewhere,
  ];
}
