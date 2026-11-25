// Herramientas del agente. Los resultados completos se guardan como artefactos;
// al modelo vuelve una vista acotada con IDs para ampliar bajo demanda.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Tool } from "./agent.ts";
import { encode } from "@toon-format/toon";
import type { Artifacts } from "./artifacts.ts";
import { ESCALATION_STATES, type Findings, LINK_ROLES, SEVERITIES } from "./findings.ts";
import { decide, sameScope, type ScopeStore, scopeTag, scopeTagLabel } from "./scope.ts";
import { RECORD_TYPES, Vault } from "./vault.ts";

export interface ToolContext {
  vault: Vault;
  artifacts: Artifacts;
  scope: ScopeStore;
  findings: Findings;
  sessionId: string;
  /** Vista del modelo del contenido de un artefacto (`hash`: el artefacto, cuya procedencia decide qué se tapa). */
  vistaArtefacto?: (texto: string, hash: string) => string;
  /** Resuelve una referencia corta de evidencia (p. ej. el id h12 de un intercambio HTTP) a un hash de artefacto. */
  evidenceRef?: (ref: string) => string | undefined;
}

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const text = (value: string) => ({ text: value });
// Constructores mínimos de JSON Schema.
const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const list = (items: object) => ({ type: "array", items });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
/** Vínculos con otros hallazgos (cadenas): id corto y rol desde el que se registra o actualiza. */
const related = (extra = "") => ({
  type: "array",
  items: {
    type: "object",
    properties: {
      id: str({ description: "Id (8 caracteres) del otro hallazgo" }),
      role: str({ enum: [...LINK_ROLES, "quitar"], description: "Desde este hallazgo: escala (éste es la escalada del otro), habilita (éste hace posible al otro) o relacionado; quitar borra el vínculo" }),
    },
    required: ["id"],
  },
  description: `Cadena: hallazgos vinculados a éste.${extra}`,
});

interface FixtureEntry {
  identity: string;
  method: string;
  route: string;
  status: number;
  bytes: number;
}

/** Ejecutor determinista: compara el acceso por identidad contra la política de roles del fixture. */
export function runFixture(name: string, artifacts: Artifacts) {
  if (!/^[a-z0-9-]+$/.test(name) || !existsSync(join(FIXTURES, `${name}.json`))) {
    const known = readdirSync(FIXTURES).map((file) => file.replace(/\.json$/, ""));
    throw new Error(`Fixture desconocido. Disponibles: ${known.join(", ")}`);
  }
  const raw = readFileSync(join(FIXTURES, `${name}.json`));
  const fixture = JSON.parse(raw.toString()) as {
    identities: Array<{ id: string }>;
    rolePolicy: Record<string, string[]>;
    entries: FixtureEntry[];
  };
  const input = artifacts.put(raw, "application/json", `fixture:${name}`);
  const byRoute = new Map<string, FixtureEntry[]>();
  for (const entry of fixture.entries) byRoute.set(entry.route, [...(byRoute.get(entry.route) ?? []), entry]);
  const matrix = [...byRoute].map(([route, entries]) => {
    const prefix = Object.keys(fixture.rolePolicy).find((candidate) => route.startsWith(candidate));
    const allowed = prefix ? fixture.rolePolicy[prefix]! : fixture.identities.map((identity) => identity.id);
    const unexpected = entries.filter((entry) => entry.status < 400 && !allowed.includes(entry.identity));
    return {
      route,
      method: entries[0]!.method,
      status: Object.fromEntries(entries.map((entry) => [entry.identity, entry.status])),
      allowed,
      unexpected: unexpected.map((entry) => entry.identity),
    };
  });
  const output = artifacts.put(JSON.stringify({ fixture: name, input: input.hash, matrix }, null, 1), "application/json", `ejecutor-fixture:${name}`);
  const candidates = matrix
    .filter((row) => row.unexpected.length)
    .map((row) => ({ ruta: row.route, metodo: row.method, identidad: row.unexpected.join("+"), status: row.status[row.unexpected[0]!]! }));
  // Vista tabular completa y compacta: evita que el modelo relea el artefacto para conocer la matriz.
  const table = matrix.map((row) => ({ ruta: row.route, metodo: row.method, ...row.status, permitido: row.allowed.join("+") }));
  return { input, output, routes: matrix.length, identities: fixture.identities.length, candidates, table };
}

export function createTools({ vault, artifacts, scope, findings, sessionId, evidenceRef, vistaArtefacto }: ToolContext): Tool[] {
  const resolveEvidence = (refs?: string[]) => refs?.map((ref) => evidenceRef?.(ref.trim()) ?? ref);
  // La memoria es del programa: lo que nació con el alcance de otro programa (o de uno desconocido) no se
  // le da al agente, ni buscando ni leyendo, ni se pisa. El operador sí lo ve, marcado, con /memoria.
  const current = () => scopeTag(scope.current());
  const foreignNote = (count: number) => (count ? `\n(${count} recuerdo${count === 1 ? "" : "s"} de otro programa, sin alcance o de origen desconocido coincide${count === 1 ? "" : "n"}; no se muestra${count === 1 ? "" : "n"}: no ${count === 1 ? "es" : "son"} del alcance de esta sesión. El operador los ve con /memoria.)` : "");
  const memorySearch: Tool = {
    name: "memory_search",
    label: "Buscar en memoria",
    description: "Busca en la memoria persistente del programa de esta sesión (título, resumen, etiquetas y detalle). Devuelve una tabla TOON con id, revisión y resumen; con «tipo» limita a una clase de registro. Lo guardado con otro programa no aparece.",
    parameters: obj({ query: str({ description: "Términos de búsqueda" }), limit: int({ minimum: 1, maximum: 20 }), tipo: str({ enum: [...RECORD_TYPES] }) }, ["query"]),
    parallel: true,
    replay: "safe",
    execute: (params) => {
      const tag = current();
      const limit = params.limit ?? 5;
      const types = params.tipo ? { types: [params.tipo] } : {};
      const hits = vault.search(params.query, limit, { ...types, scope: tag ?? null });
      const others = vault.search(params.query, limit, types).filter((hit) => !sameScope(hit.scope, tag)).length;
      const empty = tag ? "Sin resultados." : "Sin resultados: esta sesión no tiene alcance todavía y la memoria se lee por programa; cargá el alcance primero.";
      return { ...text((hits.length ? Vault.pack(hits) : empty) + foreignNote(others)), details: { resultados: hits.length, otros: others } };
    },
  };
  const memoryRead: Tool = {
    name: "memory_read",
    label: "Leer nota",
    description: "Cuando ya tenés el id de una nota, lee el registro completo del programa de esta sesión en TOON.",
    parameters: obj({ id: str() }, ["id"]),
    parallel: true,
    replay: "safe",
    execute: (params) => {
      const found = vault.read(params.id);
      if (!found) throw new Error(`No existe el registro ${params.id}`);
      const tag = current();
      if (!sameScope(found.record.scope, tag)) throw new Error(`El registro ${params.id} es de otro programa (${scopeTagLabel(found.record.scope)}), no del alcance de esta sesión (${scopeTagLabel(tag)}): no se lee desde acá. Si el operador lo quiere, lo mira con /memoria ${params.id} y te dice lo que haga falta.`);
      const { scope: _scope, ...record } = found.record;
      return { ...text(encode(record)), details: { id: params.id } };
    },
  };
  const memoryWrite: Tool = {
    name: "memory_write",
    label: "Guardar en memoria",
    description:
      "Guarda o actualiza un registro duradero del proyecto. Separar observaciones, inferencias y decisiones. " +
      "Usar supersedes cuando reemplaza a otro registro. No guardar secretos.",
    parameters: obj({
      type: str({ enum: [...RECORD_TYPES] }),
      title: str({ maxLength: 120 }),
      summary: str({ description: "Una o dos oraciones autosuficientes", maxLength: 400 }),
      body: str({ description: "Detalle largo, opcional: texto plano con lo que no entra en el resumen (pasos, evidencia, contexto). Queda dentro del registro TOON" }),
      tags: list(str()),
      sources: list(str({ description: "Hash de artefacto o ID de evidencia" })),
      validity: str({ description: "Condición bajo la cual deja de valer" }),
      id: str({ description: "ID existente para actualizar" }),
      supersedes: str({ description: "ID del registro que este reemplaza" }),
    }, ["type", "title", "summary"]),
    execute: (params) => {
      const tag = current();
      // Actualizar o sustituir sólo lo del mismo programa: una nota de otro no se pisa desde acá.
      for (const id of [params.id, params.supersedes].filter(Boolean) as string[]) {
        const existing = vault.read(id);
        if (existing && !sameScope(existing.record.scope, tag)) throw new Error(`El registro ${id} es de otro programa (${scopeTagLabel(existing.record.scope)}), no del alcance de esta sesión: no se actualiza ni se sustituye desde acá. Guardá uno nuevo sin «id».`);
      }
      const record = vault.write({ ...params, scope: tag ?? { program: "", domains: [] } });
      // El formato «Guardado <id> rev N» lo lee la migración de la memoria (vault.attribution): no cambiarlo.
      return { ...text(`Guardado ${record.id} rev ${record.rev}${tag ? "" : " (sin alcance: no va a volver sola en ninguna sesión; lo del programa guardalo después de cargar su alcance)"}`), details: { id: record.id, rev: record.rev } };
    },
  };
  const fixtureRun: Tool = {
    name: "fixture_run",
    label: "Ejecutar fixture",
    description:
      "Ejecuta una comparación determinista de permisos por identidad sobre tráfico SINTÉTICO de laboratorio " +
      "(fixture disponible: atlas-permisos). Devuelve los candidatos y la matriz completa de status por identidad; el artefacto guarda lo mismo como respaldo y no hace falta leerlo.",
    parameters: obj({ name: str() }, ["name"]),
    parallel: true,
    pure: true,
    replay: "safe",
    execute: (params) => {
      const result = runFixture(params.name, artifacts);
      const view = encode({
        sintetico: true,
        rutas: result.routes,
        identidades: result.identities,
        artefacto: result.output.hash,
        candidatos: result.candidates,
        matriz: result.table,
      });
      return { ...text(view), details: { artefacto: result.output.hash, candidatos: result.candidates.length } };
    },
  };
  const artifactRead: Tool = {
    name: "artifact_read",
    label: "Leer artefacto",
    description: "Lee un artefacto guardado. Por líneas (filter o filters para quedarte con las que contienen un texto), por búsqueda (search: expresión regular, devuelve cada coincidencia con su contexto; sirve en archivos de una sola línea como JavaScript minificado) o por posición (at + chars). Pedí varias cosas en una sola llamada con filters o con alternativas en search (a|b|c) en vez de leer el mismo artefacto varias veces.",
    parameters: obj({
      hash: str({ description: "sha256:… o prefijo de 8+ caracteres, o el id de un intercambio HTTP (h12)" }),
      filter: str(),
      filters: { type: "array", items: str(), maxItems: 12, description: "Líneas que contienen cualquiera de estos textos" },
      search: str({ description: "Expresión regular (sin distinguir mayúsculas); devuelve coincidencias con contexto" }),
      context: int({ minimum: 0, maximum: 600, description: "Caracteres de contexto a cada lado de una coincidencia; por defecto 120" }),
      at: int({ minimum: 0, description: "Posición en caracteres desde donde leer" }),
      chars: int({ minimum: 1, maximum: 6000, description: "Cuántos caracteres leer desde «at»; por defecto 2000" }),
      offset: int({ minimum: 0 }),
      limit: int({ minimum: 1, maximum: 200 }),
    }, ["hash"]),
    parallel: true,
    pure: true,
    replay: "safe",
    execute: (params) => {
      const ref = String(params.hash).trim();
      const hash = /^h\d+$/.test(ref) ? evidenceRef?.(ref) : ref;
      if (!hash) throw new Error(`No existe el intercambio ${ref}`);
      const original = artifacts.read(hash).toString("utf8");
      // Los filtros, posiciones y longitudes corresponden a la vista ya protegida.
      const content = vistaArtefacto ? vistaArtefacto(original, hash) : original;
      if (params.search) {
        let pattern: RegExp;
        try { pattern = new RegExp(params.search, "gi"); } catch (error) { throw new Error(`search no es una expresión regular válida: ${(error as Error).message}`); }
        const around = params.context ?? 120;
        const max = params.limit ?? 20;
        const hits: string[] = [];
        let total = 0;
        for (const match of content.matchAll(pattern)) {
          total++;
          if (hits.length >= max) continue;
          const from = Math.max(0, match.index - around);
          const to = Math.min(content.length, match.index + match[0].length + around);
          hits.push(`@${match.index}: ${from > 0 ? "…" : ""}${content.slice(from, to).replace(/\s+/g, " ")}${to < content.length ? "…" : ""}`);
          if (!match[0].length) pattern.lastIndex++;
        }
        return { ...text(total ? `${hits.join("\n")}${total > hits.length ? `\n… ${total - hits.length} coincidencias más (subí limit o afiná search)` : ""}` : `Sin coincidencias para /${params.search}/ en ${content.length} caracteres.`), details: { coincidencias: total } };
      }
      if (params.at !== undefined) {
        const size = params.chars ?? 2000;
        const slice = content.slice(params.at, params.at + size);
        const rest = content.length - params.at - slice.length;
        return { ...text(`${slice}${rest > 0 ? `\n… ${rest} caracteres más (at ${params.at + slice.length})` : ""}`), details: { caracteres: slice.length, total: content.length } };
      }
      let lines = content.split(/\r?\n/);
      const wanted: string[] = [...(params.filter ? [params.filter] : []), ...(params.filters ?? [])];
      if (wanted.length) lines = lines.filter((line) => wanted.some((term) => line.includes(term)));
      const offset = params.offset ?? 0;
      // Una línea enorme (JavaScript minificado, JSON en una línea) se corta: para eso está search.
      const window = lines.slice(offset, offset + (params.limit ?? 60)).map((line) => (line.length > 2000 ? `${line.slice(0, 2000)}… (línea de ${line.length} caracteres: usá search o at)` : line));
      const rest = lines.length - offset - window.length;
      return {
        ...text(`${window.join("\n")}${rest > 0 ? `\n… ${rest} líneas más (offset ${offset + window.length})` : ""}`),
        details: { líneas: window.length, total: lines.length },
      };
    },
  };
  const scopeCheck: Tool = {
    name: "scope_check",
    label: "Consultar alcance",
    description: "Dice si un host, IP o URL está dentro del alcance autorizado de esta sesión y por qué regla. Consultalo ante la duda; lo que esté fuera no se toca.",
    parameters: obj({ target: str({ description: "Host, IP o URL" }) }, ["target"]),
    parallel: true,
    replay: "safe",
    execute: (params) => {
      const decision = decide(scope.current(), params.target);
      return { ...text(`${decision.allowed ? "DENTRO" : "FUERA"} del alcance. ${decision.reason}`), details: { dentro: decision.allowed } };
    },
  };
  const cvss = str({ description: "Vector CVSS:3.1 respaldado por la evidencia. Si está, determina la severidad." });
  const revisarExclusion = (estado: string, cercana?: string, motivo?: string) => {
    if (estado !== "candidato") return;
    const citas = scope.current()?.reglas?.exclusiones ?? [];
    if (!citas.length) return;
    if (!cercana?.trim()) throw new Error("Antes de registrar un candidato falta exclusion_cercana: citá una exclusión textual de /alcance.");
    if (!citas.some((item) => item.cita === cercana.trim())) throw new Error("exclusion_cercana debe ser una cita exacta de las reglas del programa en /alcance.");
    if (!motivo?.trim()) throw new Error("Antes de registrar un candidato falta por_que_no_aplica: explicá por qué esa exclusión no cubre este caso.");
  };
  const revisarConfianza = (cita?: string) => {
    if (!cita?.trim()) return;
    const reglas = scope.current()?.reglas;
    if (![...(reglas?.honestos ?? []), ...(reglas?.posicionAtacante ?? [])].some((item) => item.cita === cita.trim())) throw new Error("fuera_modelo_confianza debe citar exactamente una parte honesta o la posición del atacante en /alcance.");
  };
  const findingRecord: Tool = {
    name: "finding_record",
    label: "Registrar hallazgo",
    description:
      "Registra una pista (sospecha sin evidencia) o un candidato (con artefactos de evidencia). No existe el estado verificado para el agente: " +
      "eso lo decide un verificador o el operador. El activo debe estar dentro del alcance. Un fallo de la herramienta (cuerpo ilegible, artefacto truncado, cookie no guardada) no es un hallazgo sobre la aplicación.",
    parameters: obj({
      state: str({ enum: ["pista", "candidato"] }),
      title: str({ maxLength: 120 }),
      kind: str({ description: "Clase de problema, p. ej. control de acceso", maxLength: 60 }),
      cvss,
      severity: str({ enum: [...SEVERITIES], description: "Estimación; no la infles" }),
      asset: str({ description: "Host, URL o ruta afectada" }),
      summary: str({ description: "Qué se observó, separado de lo que se infiere", maxLength: 1200 }),
      evidence: list(str({ description: "Hash de artefacto o id de intercambio HTTP (h12)" })),
      limits: str({ description: "Qué falta comprobar", maxLength: 300 }),
      exclusion_cercana: str({ description: "Cita exacta de una exclusión en /alcance; obligatoria para candidato si hay reglas" }),
      por_que_no_aplica: str({ description: "Por qué la exclusión cercana no cubre este caso" }),
      fuera_modelo_confianza: str({ description: "Para una pista fuera del modelo: cita exacta de una parte honesta o de la posición del atacante en /alcance" }),
      related: related(" Si este hallazgo es la escalada de uno bajo (o al revés), vinculalos: el informe los muestra como cadena."),
    }, ["state", "title", "kind", "asset", "summary"]),
    execute: (params) => {
      revisarExclusion(params.state, params.exclusion_cercana, params.por_que_no_aplica);
      revisarConfianza(params.fuera_modelo_confianza);
      const host = /^[a-z][a-z0-9+.-]*:\/\//i.test(params.asset) || /^[a-z0-9.-]+\.[a-z]{2,}/i.test(params.asset) ? params.asset : undefined;
      if (host) {
        const decision = decide(scope.current(), host);
        if (!decision.allowed) throw new Error(`No se registra: ${decision.reason}`);
      }
      const item = findings.record({ ...params, exclusionCercana: params.exclusion_cercana, porQueNoAplica: params.por_que_no_aplica, fueraModeloConfianza: params.fuera_modelo_confianza, evidence: resolveEvidence(params.evidence) }, sessionId);
      return { ...text(`Registrado ${item.id.slice(0, 8)} como ${item.state}.`), details: { id: item.id.slice(0, 8), estado: item.state } };
    },
  };
  const findingUpdate: Tool = {
    name: "finding_update",
    label: "Actualizar hallazgo",
    description: "Suma evidencia, corrige el texto, pasa una pista a candidato o descarta con motivo. Vincula hallazgos en cadena (related) y marca qué pasó con la escalada conocida de uno bajo o medio (escalation con escalation_note). No puede verificar.",
    parameters: obj({
      id: str(),
      state: str({ enum: ["pista", "candidato", "descartado"] }),
      title: str({ maxLength: 120 }),
      cvss,
      severity: str({ enum: [...SEVERITIES] }),
      summary: str({ maxLength: 1200 }),
      evidence: list(str()),
      limits: str({ maxLength: 300 }),
      exclusion_cercana: str({ description: "Cita exacta de una exclusión en /alcance, al pasar a candidato" }),
      por_que_no_aplica: str({ description: "Por qué la exclusión cercana no cubre este caso" }),
      fuera_modelo_confianza: str({ description: "Marcá una pista fuera del modelo; vacío para quitar la marca" }),
      reason: str({ description: "Obligatorio al descartar", maxLength: 300 }),
      related: related(),
      escalation: str({ enum: [...ESCALATION_STATES], description: "La escalada conocida de este hallazgo: intentada (decí qué dio), limitada (qué faltó y por qué) o no aplica" }),
      escalation_note: str({ description: "Obligatoria con escalation", maxLength: 300 }),
    }, ["id"]),
    execute: (params) => {
      // Sólo al pasar a candidato: uno de antes de cargar las reglas (o de otra sesión) sigue aceptando escalation,
      // cvss y correcciones sin exclusion_cercana, como promete y pide src/cierre.ts.
      const previo = findings.get(params.id);
      if (params.state === "candidato" && previo?.state !== "candidato") revisarExclusion("candidato", params.exclusion_cercana ?? previo?.exclusionCercana, params.por_que_no_aplica ?? previo?.porQueNoAplica);
      revisarConfianza(params.fuera_modelo_confianza);
      const item = findings.update(params.id, { ...params, exclusionCercana: params.exclusion_cercana, porQueNoAplica: params.por_que_no_aplica, fueraModeloConfianza: params.fuera_modelo_confianza, evidence: resolveEvidence(params.evidence), escalationNote: params.escalation_note }, sessionId);
      return { ...text(`${item.id.slice(0, 8)} quedó como ${item.state}, rev ${item.rev}.`), details: { id: item.id.slice(0, 8), estado: item.state } };
    },
  };
  const findingList: Tool = {
    name: "finding_list",
    label: "Listar hallazgos",
    description: "Hallazgos registrados en esta sesión con su estado. Consultalo antes de registrar uno para no duplicar. Con todos, también los de otras sesiones del proyecto (otros programas): sólo si el operador los pide.",
    parameters: obj({ todos: { type: "boolean", description: "Incluir los de otras sesiones del proyecto" } }, []),
    parallel: true,
    replay: "safe",
    execute: (params) => {
      const project = findings.list();
      const links = (id: string) => findings.linksOf(id, project).map(({ finding, role }) => `${role} ${finding.id.slice(0, 8)}`).join("; ");
      const all = findings.list(params?.todos ? {} : { sessionId }).map((item) => ({ id: item.id.slice(0, 8), estado: item.state, severidad: item.severity, cvss: item.cvss ?? "", clase: item.kind, activo: item.asset, titulo: item.title, cadena: links(item.id) }));
      return { ...text(all.length ? encode({ hallazgos: all }) : "Sin hallazgos registrados."), details: { hallazgos: all.length } };
    },
  };
  return [memorySearch, memoryRead, memoryWrite, fixtureRun, artifactRead, scopeCheck, findingRecord, findingUpdate, findingList];
}
