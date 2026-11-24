// Verificador independiente: un agente con contexto limpio que toma un candidato, lee su evidencia,
// reproduce la afirmación con peticiones propias, hace un control negativo y dicta veredicto.
// Es lo que convierte «candidato» en «verificado» sin que el mismo agente que lo encontró se
// califique solo. Su gasto se imputa al worker «verificador:n» en el ledger.
import { neutralizarMarcadores } from "./secretos-sesion.ts";
import { Agent, type Tool } from "./agent.ts";
import { cadenaConEvidencia } from "./cadenas.ts";
import { conWorker } from "./grafo.ts";
import type { Engine } from "./engine.ts";
import type { Finding, FindingState } from "./findings.ts";
import { Ledger } from "./ledger.ts";
import type { Model } from "./llm.ts";
import { usd, usdToPico } from "./money.ts";
import { blocksVerified, type Checks, checksLines, modelChecks, programChecks } from "./comprobaciones.ts";
import { decide, scopeBrief } from "./scope.ts";
import { logEvent } from "./store.ts";
import { findingPrint } from "./verificacion.ts";
import { type Poc, pocDe, reproducir } from "./investigar/ejecucion.ts";

const VERIFIER_PROMPT = `Sos el verificador de Orobas (orobas-sec). Otro agente registró un candidato; tu trabajo es comprobarlo de forma independiente y dictar veredicto. No buscás fallas nuevas.
Método, en este orden:
0. Mirá de qué habla la afirmación. Si describe la conducta del cliente o de las herramientas del agente y no la del servidor (un cuerpo que no se pudo leer, el formato de un artefacto, una cookie que el cliente no guardó, una respuesta HTML leída como JSON, un campo indefinido), es «descartado: fallo de herramienta, no de la aplicación», sin gastar peticiones. Si describe que una función no funciona (un login que no persiste, un 401 a credenciales válidas, un 500 en el flujo normal), es una falla de funcionamiento y no de seguridad: «descartado», salvo que ese fallo abra un acceso o un dato que no corresponde.
1. Leé la evidencia registrada con artifact_read, usando los hashes de «Evidencia registrada» (el id del candidato no es un artefacto, y un id hN que nombre la afirmación puede ser de otra corrida: la evidencia es la de los hashes), y entendé exactamente qué se afirma y qué causa le atribuye.
2. Reproducí la afirmación con una petición propia (http_request, http_replay, access_matrix o http_probe). No alcanza con que la evidencia vieja exista: tiene que volver a pasar ahora. Esa petición es la prueba.
3. Hacé un control que cambie una sola cosa: la condición que el candidato afirma como causa (sin credenciales, con la identidad dueña del recurso, con el valor normal del parámetro). Si el control da lo mismo que la prueba, la causa no está demostrada. Si la causa afirmada tiene una alternativa plausible, hacé también la petición que las separa: si el candidato dice que una cuenta concreta tiene el secreto vacío, probá otra cuenta inventada con el mismo secreto; si también entra, la causa no es esa cuenta sino cómo se tratan las cuentas inexistentes. Un efecto real con la causa mal atribuida llega mal al informe: verificalo con la causa que tu control demostró y corregí el título.
4. Si la afirmación depende del significado de un rol, un permiso, un estado o una bandera (por ejemplo «permiso 1 es sólo lectura», «este rol no debería poder X»), comprobá ese significado en una fuente del producto: su documentación, su OpenAPI o lo que muestra su propia interfaz. Si no podés mostrar de dónde sale, el veredicto es «candidato» con ese motivo, aunque la petición se reproduzca: reproducir no es lo mismo que demostrar que el permiso estaba mal.
5. Pesá el valor antes de confirmar: una respuesta 500 ante una entrada inválida, un parámetro ignorado, una cabecera ausente o un mensaje distinto son ciertos pero no son, por sí solos, una falla con efecto. Si no hay efecto sobre datos, acceso o integridad, «descartado» con ese motivo, o «verificado» con severidad informativa si el operador necesita el dato.
6. Dictá veredicto con verdict: «verificado» sólo si la reproducción pasó y el control la distingue; pasá en prueba y control los ids de esas dos peticiones y en causa qué cambió el control. «descartado» si la afirmación es falsa o el comportamiento es correcto (p. ej. un 403 bien puesto, CORS ausente, 404); «candidato» si no pudiste reproducir por falta de acceso o de datos. Si la causa demostrada no es la que afirma el candidato, mandá titulo con el enunciado corregido. Explicá el motivo en una línea.
7. Si el candidato trae una «Cadena» (hallazgos vinculados), verificás este eslabón: el efecto que él afirma, con tu prueba y tu control. Un eslabón previo que no está verificado no se da por bueno: si el efecto de éste depende de él, reproducilo también dentro de esta verificación o dejá «candidato» diciendo qué eslabón falta. La severidad que reclama una cadena sólo vale con todos sus eslabones demostrados; si el candidato la infla por la cadena y el eslabón previo no se sostiene, decilo en el motivo.
8. Antes de dictar, las comprobaciones que van en el veredicto (comprobaciones), cada una con resultado, detalle y fuente (la URL o el archivo que leíste). El alcance del programa y su política ya los resolvió el harness (te llegan con el candidato): no los repitas, pero si dicen «excluido» o «fuera», no es «verificado». Vos completás:
   - coherencia: ¿la evidencia guardada (lo que leíste y lo que reprodujiste) demuestra el impacto que afirma el título y la severidad? «ok», o «falla» si afirma más de lo que muestra (entonces no es verificado).
   - codigo_abierto: si el programa tiene código público (te llega como lectura de referencia) o el repositorio está en la carpeta, mirá con reference_read (commits?path=…&sha=<rama>, releases/latest, compare/<versión>...<rama>, pulls?state=closed) o code_search si la falla sigue en la rama principal y en la última versión publicada, y si un commit o PR ya la arregla: «ok» (sigue presente, con dónde), «arreglado» (citá el commit o PR) o «no aplica» si no es código abierto.
   - duplicados: buscá en lo público de sólo lectura: avisos de seguridad del repositorio (api.github.com/repos/<dueño>/<repo>/security-advisories), CVE del producto en el banco local (cve_search) y lo que el operador sumó como referencia. «ok» si no hay nada parecido (decí dónde miraste) o «posible duplicado» con el enlace o el CVE. No inventes direcciones: si no hay fuente, «no comprobado».
   Lo que no pudiste mirar es «no comprobado», nunca «ok». Leer estas fuentes no toca el objetivo; igual, que sean pocas lecturas.
Trabajás dentro del alcance autorizado; lo que no esté ahí no se toca. Sé breve: cada petición cuesta.`;

export interface Verdict {
  finding: Finding;
  state: FindingState;
  reason: string;
  evidence: string[];
  requests: number;
  costUsd: string;
  transcript: string;
  /** Verificación por ejecución: en cuántas de las corridas en limpio disparó el PoC. */
  ejecucion?: { disparos: number; corridas: number };
  /** Alcance y política del programa (del harness), coherencia, código abierto y duplicados (del verificador). */
  comprobaciones?: Checks;
}

/** Lo que importa de un intercambio para comparar prueba y control. */
export interface Outcome {
  id: string;
  status?: number;
  body?: string;
  error?: string;
}

/**
 * Un control sirve si es otra petición y no dio lo mismo que la prueba: distinto estado o distinto
 * cuerpo. Si dieron igual, la condición que se quitó no era la causa (punto 83 de MEJORAS-AGENTE):
 * el efecto puede ser real, pero la explicación que llegaría al informe no está demostrada.
 */
export function contrast(prueba: Outcome, control: Outcome): { ok: true } | { ok: false; reason: string } {
  if (prueba.id === control.id) return { ok: false, reason: "Prueba y control son la misma petición. El control es otra petición, igual a la prueba salvo en la causa que afirmás." };
  if (prueba.status === undefined) return { ok: false, reason: `La prueba ${prueba.id} no tiene respuesta del servidor${prueba.error ? ` (${prueba.error})` : ""}: un error del cliente no demuestra nada.` };
  if (control.status === undefined) return { ok: false, reason: `El control ${control.id} no tiene respuesta del servidor${control.error ? ` (${control.error})` : ""}: sin respuesta no hay comparación.` };
  const flat = (text?: string) => (text ?? "").replace(/\s+/g, "");
  if (prueba.status === control.status && flat(prueba.body) === flat(control.body)) {
    return {
      ok: false,
      reason: `El control ${control.id} dio lo mismo que la prueba ${prueba.id} (${prueba.status} y el mismo cuerpo): no distingue la causa que afirmás. Cambiá sólo la condición que creés que causa la falla y compará de nuevo; si sigue dando igual, el veredicto es descartado o candidato.`,
    };
  }
  return { ok: true };
}

/** Herramientas que el verificador puede usar: leer, pedir, comparar. Nada de memoria ni de registrar hallazgos nuevos. */
const ALLOWED = new Set(["artifact_read", "http_request", "http_probe", "http_replay", "access_matrix", "param_probe", "body_probe", "auth_probe", "http_identities", "scope_check", "reference_read", "cve_search", "cve_detail", "code_list", "code_search", "code_read"]);

/** El motivo del veredicto con sus comprobaciones, una por línea: lo que ven /verificar, /hallazgos y el informe. */
const withChecks = (reason: string, checks: Checks) => `${reason.trim()}\nComprobaciones: ${checksLines(checks).join("; ")}.`;

/** Tope de gasto por candidato. Con USD 0,15 la mitad de las verificaciones se cortaba antes del veredicto. */
export const VERIFIER_BUDGET_USD = 0.5;
/** Solicitudes al modelo por candidato: leer, reproducir, controlar, a veces buscar el significado de un permiso, y dictar. */
export const VERIFIER_MAX_STEPS = 24;

export interface VerifierOptions {
  /** Tope de gasto por candidato, en USD. Por defecto VERIFIER_BUDGET_USD. */
  budgetUsd?: number;
  /** Solicitudes al modelo por candidato. Por defecto VERIFIER_MAX_STEPS. */
  maxSteps?: number;
  /**
   * Modelo del verificador. Acá se conecta el «modelo base» (el barato) cuando exista ese ajuste;
   * si devuelve undefined, o no está, usa el modelo de la sesión. Tiene que poder hablar por el
   * transporte del proveedor de la sesión.
   */
  model?: () => Model | undefined;
}

/** El proveedor dice que no hay saldo o que el plan no alcanza (o insiste con 429): seguir sólo gasta intentos. */
export function exhaustedError(message: string): boolean {
  return /\b(usage_limit|plan_inactive|insufficient_balance|insufficient_quota)\b|\bHTTP 429\b|\b429 Too Many Requests\b|sin saldo|saldo agotado/i.test(message);
}

/** El verificador no terminó. `exhausted`: fue por falta de saldo y no tiene sentido seguir con la tanda. */
export class VerifierFailure extends Error {
  readonly exhausted: boolean;
  constructor(message: string, exhausted: boolean) {
    super(message);
    this.exhausted = exhausted;
  }
}

/**
 * Resultado de un candidato en una tanda: el veredicto, o por qué no terminó. `skipped`: no se lanzó (fuera del
 * alcance o tope de la sesión), sin modelo ni gasto; no cuenta como intento fallido.
 */
export type VerifyResult = Verdict | { finding: Finding; error: string; exhausted?: boolean; skipped?: boolean };

export class Verifier {
  readonly engine: Engine;
  readonly options: VerifierOptions;
  private count = 0;

  constructor(engine: Engine, options: VerifierOptions = {}) {
    this.engine = engine;
    this.options = options;
  }

  /** Verifica un hallazgo y aplica el veredicto. Devuelve el veredicto o lanza VerifierFailure si el verificador no terminó. */
  async verify(findingId: string, options: { budgetUsd?: number; signal?: AbortSignal } = {}): Promise<Verdict> {
    const { engine } = this;
    // Exactamente el registro pedido: si no existe o es ambiguo, el error lista los que sí; nunca se toma otro.
    const finding = engine.findings.resolve(findingId, { sessionId: engine.sessionId, state: "candidato" });
    if (finding.state !== "candidato") throw new Error(`Sólo se verifican candidatos; ${finding.id.slice(0, 8)} está como ${finding.state}`);
    const before = findingPrint(finding);
    const done = (verdict: Verdict): Verdict => {
      // Lo que vio (antes) y cómo quedó (después): con cualquiera de las dos huellas no se vuelve a verificar solo.
      logEvent(engine.db, engine.sessionId, "verification.verdict", { id: verdict.finding.id, state: verdict.state, usd: verdict.costUsd, requests: verdict.requests, huella: findingPrint(verdict.finding), huellaAntes: before, ...(verdict.comprobaciones ? { comprobaciones: verdict.comprobaciones } : {}) });
      return verdict;
    };
    // Con un PoC o harness ejecutable no se discute: se corre de nuevo en limpio (src/investigar/ejecucion.ts).
    const poc = pocDe(engine.artifacts, finding);
    if (poc) return done(await this.byExecution(finding, poc, options.signal));
    // En el modo investigar, un candidato de código sin evidencia ejecutable no pasa a verificado.
    if (engine.investigar?.exigeEjecucion(finding)) return done(this.withoutExecutable(finding));
    // Fuera del alcance no hay nada que reproducir: se dice sin gastar un paso del modelo.
    const outside = this.outOfScope(finding);
    if (outside) throw new VerifierFailure(outside, false);
    const worker = `verificador:${++this.count}`;
    const budget = usdToPico(String(options.budgetUsd ?? this.options.budgetUsd ?? VERIFIER_BUDGET_USD));
    const maxSteps = this.options.maxSteps ?? VERIFIER_MAX_STEPS;
    const model = this.options.model?.() ?? engine.agent.model;
    const startCount = engine.http.log.length;
    let verdict: { state: FindingState; reason: string; evidence: string[]; title?: string; checks: Checks } | undefined;
    // Alcance y política del programa: con el código, antes de lanzar el modelo (el resto lo completa el verificador).
    const program = programChecks(engine.scope.current(), finding);

    const verdictTool: Tool = {
      name: "verdict",
      label: "Veredicto",
      description: "Dicta el veredicto sobre el candidato que estás verificando. Para «verificado» hacen falta prueba y control: los ids de tu petición que reproduce el efecto y de la que quita sólo la causa afirmada.",
      parameters: {
        type: "object",
        properties: {
          state: { type: "string", enum: ["verificado", "descartado", "candidato"] },
          reason: { type: "string", maxLength: 400, description: "Qué reprodujiste, qué dio el control y por qué decidís así" },
          prueba: { type: "string", description: "Id (h12) de tu petición que reproduce el efecto" },
          control: { type: "string", description: "Id (h12) de tu petición igual a la prueba salvo en la causa afirmada" },
          causa: { type: "string", maxLength: 200, description: "Qué cambió el control respecto de la prueba y por qué eso es la causa" },
          titulo: { type: "string", maxLength: 120, description: "Sólo si la causa demostrada no es la que afirma el candidato: el título corregido" },
          evidence: { type: "array", items: { type: "string" }, description: "Otros ids (h12) o hashes de tus peticiones" },
          comprobaciones: {
            type: "object",
            description: "coherencia, codigo_abierto y duplicados: cada una {resultado, detalle, fuente}. Lo que no miraste, resultado «no comprobado».",
            properties: Object.fromEntries(["coherencia", "codigo_abierto", "duplicados"].map((name) => [name, { type: "object", properties: { resultado: { type: "string", enum: ["ok", "falla", "arreglado", "posible duplicado", "no aplica", "no comprobado"] }, detalle: { type: "string", maxLength: 300 }, fuente: { type: "string", maxLength: 300 } }, required: ["resultado"] }])),
          },
        },
        // comprobaciones no es obligatoria en el esquema: si falta, todo lo del verificador queda «no comprobado» (y se ve).
        required: ["state", "reason"],
      },
      execute: (params) => {
        const own = engine.http.log.slice(startCount);
        let evidence: string[] = (params.evidence ?? []).map((ref: string) => (/^h\d+$/.test(ref) ? engine.http.hashOf(ref) : ref)).filter((hash: string | undefined): hash is string => !!hash && !!engine.artifacts.find(hash));
        const checks: Checks = { ...program, ...modelChecks(params.comprobaciones) };
        if (params.state === "verificado") {
          const blocked = blocksVerified(checks);
          if (blocked) throw new Error(blocked);
          if (!own.length) throw new Error("No se verifica sin reproducir: hacé al menos una petición propia antes del veredicto.");
          const prueba = own.find((entry) => entry.id === params.prueba);
          const control = own.find((entry) => entry.id === params.control);
          if (!prueba || !control) throw new Error("Para verificar hacen falta prueba y control: los ids (h12) de dos peticiones tuyas de esta verificación, la que reproduce el efecto y la que quita sólo la causa que afirma el candidato.");
          const check = contrast(this.outcome(prueba.id, prueba.hash), this.outcome(control.id, control.hash));
          if (!check.ok) throw new Error(check.reason);
          if (!String(params.causa ?? "").trim()) throw new Error("Decí en causa qué cambió el control respecto de la prueba.");
          evidence = [...new Set([prueba.hash, control.hash, ...evidence])];
        }
        verdict = { state: params.state, reason: String(params.reason).trim(), evidence, title: params.titulo ? String(params.titulo).trim() : undefined, checks };
        return { text: `Veredicto registrado: ${params.state}.\nComprobaciones: ${checksLines(checks).join("; ")}.`, details: { estado: params.state } };
      },
    };

    // Las de lectura (reference_read, cve_search, code_*) pueden no estar cargadas en el agente principal: se toman del
    // catálogo. Toda herramienta pasa por bounded (#39: secretos aprendidos, marcadores repuestos, salida tapada); las
    // del agente ya vienen envueltas y ganan sobre las del catálogo, que se envuelven acá.
    const pool = new Map([...[...engine.catalog.available.values()].map((tool) => engine.bounded(tool)), ...engine.agent.tools].map((tool) => [tool.name, tool]));
    // Lo que reproduzca queda en el grafo de hechos con el verificador como procedencia.
    const tools = conWorker(worker, [...[...pool.values()].filter((tool) => ALLOWED.has(tool.name)), engine.bounded(verdictTool)]);
    const spent = () => {
      const row = engine.db
        .prepare("select coalesce(sum(cast(cost_input as integer)+cast(cost_cache_read as integer)+cast(cost_cache_write as integer)+cast(cost_output as integer)),0) n from requests where session_id=? and worker=? and cost_input is not null")
        .get(engine.sessionId, worker) as { n: number | bigint };
      return BigInt(row.n);
    };
    const steps = () => child.messages.filter((message) => message.role === "assistant").length;
    const system = `${VERIFIER_PROMPT}\n\nAlcance: ${scopeBrief(engine.scope.current())}\nIdentidades disponibles: ${engine.http.identityNames().join(", ") || "ninguna"}`;
    const child = new Agent({
      system,
      model,
      tools,
      transport: engine.tagged(worker),
      // El tope de pasos lo lleva el verificador (prepare): el aviso genérico del agente principal
      // le pediría registrar hallazgos con herramientas que no tiene.
      stallLimit: 2,
      prepare: () => {
        if (steps() >= maxSteps) return `Límite de pasos del verificador (${maxSteps}) alcanzado.`;
        const estimate = Ledger.estimate(model, JSON.stringify(child.messages).length + system.length);
        if (spent() + estimate > budget) return `Tope del verificador (USD ${usd(budget, 2)}) alcanzado.`;
        // No depende del tope de la sesión (USD 2 por defecto, también en las reanudaciones
        // automáticas): tiene el suyo por candidato. El tope del proyecto, que fija el operador, sí corta.
        return engine.ledger.overProjectBudget(estimate);
      },
      // Si quiere cerrar sin veredicto, se le exige uno (una vez).
      beforeEnd: () => (verdict ? undefined : "[sistema] Falta el veredicto: llamá a verdict con verificado, descartado o candidato y el motivo."),
    });
    const ctx = () => ({ sessionId: engine.sessionId, account: engine.provider.account, worker, model: child.model });
    let warned = false;
    child.on((event) => {
      if (event.type === "request_start") {
        engine.ledger.begin(event.intent, ctx());
        engine.ledger.reserve(event.intent, engine.sessionId, Ledger.estimate(child.model, JSON.stringify(child.messages).length));
      } else if (event.type === "request") {
        engine.ledger.settle(event.intent);
        engine.ledger.record(event.message, ctx());
        // A tres pasos del tope (o con la mayor parte del tope de gasto usada), que dicte con lo que tiene.
        const late = steps() >= maxSteps - 3 || spent() * 4n >= budget * 3n;
        if (late && !verdict && !warned && event.message.stopReason === "toolUse") {
          warned = true;
          child.steer("[sistema] Te queda poco margen (pasos o gasto). Dictá el veredicto ahora con verdict: si no llegaste a reproducir con prueba y control, «candidato» con lo que falta.");
        }
      } else if (event.type === "tool_start" || event.type === "tool_end") engine.agent.relay({ ...event, id: `${worker}/${event.id}`, worker });
    });
    const onAbort = () => child.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    // La cadena viaja con el candidato: qué eslabones tiene, en qué estado y con qué evidencia.
    const chain = engine.findings.linksOf(finding.id).map(({ finding: other, role }) => `- ${role === "escala" ? "es la escalada de" : role === "habilita" ? "habilita a" : "relacionado con"} ${other.id.slice(0, 8)} · ${other.state} · ${other.severity} · ${other.kind}: ${other.title} (activo ${other.asset}; evidencia ${other.evidence.join(", ") || "ninguna"})`);
    try {
      await child.prompt(
        [
          `CANDIDATO ${finding.id.slice(0, 8)} (id completo ${finding.id}) · ${finding.severity} · ${finding.kind}. Verificás este y ningún otro.`,
          finding.title,
          `Activo: ${finding.asset}`,
          `Afirmación: ${finding.summary}`,
          finding.limits ? `Límites declarados: ${finding.limits}` : "",
          `Evidencia registrada (leela con artifact_read y estos hashes): ${finding.evidence.join(", ") || "ninguna"}`,
          chain.length ? `Cadena:\n${chain.join("\n")}` : "",
          // Con el grafo: cada eslabón con el estado de su arista «habilita» y dónde se observó cada uno.
          ...(() => { const lineas = engine.grafo ? cadenaConEvidencia(engine.grafo.ver(), finding.id) : []; return lineas.length ? [`Cadena según el grafo de hechos (evidencia de cada eslabón):\n${lineas.join("\n")}`] : []; })(),
          `Comprobaciones del harness: alcance del programa: ${program.alcance.resultado} — ${program.alcance.detalle}; política: ${program.politica.resultado} — ${program.politica.detalle}.`,
          (engine.scope.current()?.reference ?? []).length ? `Código del programa (lectura de referencia): ${(engine.scope.current()?.reference ?? []).slice(0, 6).map((rule) => rule.value).join(", ")}` : "Código del programa: no hay lectura de referencia cargada (si no es código abierto, codigo_abierto «no aplica»).",
        ]
          .filter(Boolean)
          .join("\n"),
      );
    } finally {
      options.signal?.removeEventListener("abort", onAbort);
    }
    const transcript = engine.artifacts.put(neutralizarMarcadores(JSON.stringify(child.messages, null, 1)), "application/json", worker).hash;
    const requests = child.messages.filter((m) => m.role === "assistant").length;
    const costUsd = usd(spent());
    if (!verdict) {
      const last = child.messages.findLast((message) => message.role === "assistant");
      const reason = last?.role === "assistant" ? last.errorMessage ?? last.stopReason ?? "sin veredicto" : "sin veredicto";
      throw new VerifierFailure(`El verificador no dictó veredicto (${reason}). Transcripción ${transcript}.`, exhaustedError(reason));
    }
    const reason = withChecks(verdict.reason, verdict.checks);
    const updated = engine.findings.verdict(finding.id, verdict.state, reason, verdict.evidence, worker, { title: verdict.title });
    return done({ finding: updated, state: verdict.state, reason, evidence: verdict.evidence, requests, costUsd, transcript, comprobaciones: verdict.checks });
  }

  /**
   * Por qué este candidato no se puede verificar en esta sesión sin gastar: su activo está fuera del alcance
   * vigente. Un activo que es sólo una ruta («/api/x») no se juzga acá.
   */
  outOfScope(finding: Finding): string | undefined {
    const asset = finding.asset.trim();
    const target = /^[a-z][a-z0-9+.-]*:\/\//i.test(asset) || /^\[?[0-9a-f:.]+\]?(:\d+)?(\/|$)/i.test(asset) || /^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/|$)/i.test(asset) || /^localhost(:\d+)?(\/|$)/i.test(asset) ? asset : undefined;
    // Sin alcance cargado no se juzga acá (el verificador lo ve en su prompt): esto es para el que quedó afuera de uno vigente.
    const scope = this.engine.scope.current();
    if (!target || !scope?.include.length) return undefined;
    const decision = decide(scope, target);
    return decision.allowed ? undefined : `${finding.id.slice(0, 8)} no se verifica: su activo está fuera del alcance de esta sesión (${decision.reason.split(". ")[0]}). No se gastó nada; si el operador lo vuelve a sumar, /verificar ${finding.id.slice(0, 8)}.`;
  }

  /** Huellas que ya pasaron por el verificador en esta sesión (antes y después de cada veredicto), y los ids con veredicto registrado con huella. */
  private seen(): { prints: Set<string>; ids: Set<string> } {
    const prints = new Set<string>();
    const ids = new Set<string>();
    const rows = this.engine.db.prepare("select payload from events where session_id=? and type='verification.verdict'").all(this.engine.sessionId) as Array<{ payload: string }>;
    for (const row of rows) {
      try {
        const payload = JSON.parse(row.payload) as { id?: string; huella?: string; huellaAntes?: string };
        if (payload.huella) prints.add(payload.huella);
        if (payload.huellaAntes) prints.add(payload.huellaAntes);
        if (payload.id && payload.huella) ids.add(payload.id);
      } catch { /* evento ilegible */ }
    }
    return { prints, ids };
  }

  /**
   * Verificación por ejecución: el PoC se corre en limpio (poc_run) dos veces. Si dispara las dos, verificado
   * con el PoC y la salida como evidencia; si no, sigue candidato con el motivo. Sin modelo ni peticiones.
   */
  private async byExecution(finding: Finding, poc: { hash: string; poc: Poc }, signal?: AbortSignal): Promise<Verdict> {
    const { engine } = this;
    const worker = `verificador:${++this.count}`;
    const ejecutar = engine.ejecutorPoc();
    if (!ejecutar) {
      const reason = "Trae un PoC ejecutable, pero en este entorno no hay poc_run para correrlo en limpio (está en la caja): queda candidato hasta correrlo ahí.";
      const updated = engine.findings.verdict(finding.id, "candidato", reason, [poc.hash], worker);
      return { finding: updated, state: "candidato", reason, evidence: [poc.hash], requests: 0, costUsd: usd(0n), transcript: poc.hash };
    }
    const rep = await reproducir(ejecutar, poc.poc, signal);
    if (signal?.aborted && rep.corridas.length < 2) throw new VerifierFailure("Verificación por ejecución cortada antes de terminar las corridas.", false);
    const log = engine.artifacts.put(JSON.stringify({ poc: poc.hash, comando: poc.poc.comando, senal: poc.poc.senal ?? null, corridas: rep.corridas.map((corrida) => ({ ...corrida, salida: corrida.salida.slice(0, 20_000) })) }, null, 1), "application/json", "verificador:ejecucion").hash;
    const checks: Checks = { ...programChecks(engine.scope.current(), finding), ...modelChecks({}) };
    const blocked = rep.reproduce ? blocksVerified(checks) : undefined;
    const state: FindingState = rep.reproduce && !blocked ? "verificado" : blocked ? "descartado" : "candidato";
    const evidence = [poc.hash, log];
    const reason = withChecks(blocked ? `${rep.motivo} ${blocked}` : rep.motivo, checks);
    const updated = engine.findings.verdict(finding.id, state, reason, evidence, worker);
    return { finding: updated, state, reason, evidence, requests: 0, costUsd: usd(0n), transcript: log, ejecucion: { disparos: rep.disparos, corridas: rep.corridas.length }, comprobaciones: checks };
  }

  /** En el modo investigar, un candidato de código sin PoC queda candidato: lo estático no se verifica con un modelo. */
  private withoutExecutable(finding: Finding): Verdict {
    const worker = `verificador:${++this.count}`;
    const reason = "Es de código y no trae evidencia ejecutable: en el modo investigar sólo se verifica con un PoC o harness que se reproduzca en limpio (poc_run). Queda candidato.";
    const updated = this.engine.findings.verdict(finding.id, "candidato", reason, [], worker);
    return { finding: updated, state: "candidato", reason, evidence: [], requests: 0, costUsd: usd(0n), transcript: "" };
  }

  /** Estado y cuerpo de un intercambio guardado, para comparar prueba y control. */
  private outcome(id: string, hash: string): Outcome {
    try {
      const exchange = JSON.parse(this.engine.artifacts.read(hash).toString("utf8")) as { response?: { status: number; body: string }; error?: string };
      return { id, status: exchange.response?.status, body: exchange.response?.body, error: exchange.error };
    } catch {
      return { id };
    }
  }

  /**
   * Candidatos de esta sesión que esperan verificador. Los de otras sesiones del proyecto son de otro
   * programa: los verifica su sesión, o el operador a mano por id. `retries` deja afuera los que ya
   * fallaron esa cantidad de veces sin cambiar (misma revisión): reintentarlos en cada turno sólo gasta.
   */
  pending(retries = Infinity): Finding[] {
    const { engine } = this;
    const { prints, ids } = this.seen();
    return engine.findings.list({ sessionId: engine.sessionId }).filter((item) => {
      if (item.state !== "candidato") return false;
      // Ya lo vio con esta misma evidencia (o vio otro candidato con la misma): no se repite solo.
      if (prints.has(findingPrint(item))) return false;
      // Veredictos de antes de la huella: como siempre, el que ya dictó el verificador no se repite.
      if (item.decidedBy.startsWith("verificador") && !ids.has(item.id)) return false;
      return this.failures(item) < retries;
    });
  }

  /** Veces que el verificador no terminó con este candidato tal como está ahora (sin contar la falta de saldo). */
  failures(finding: Finding): number {
    const rows = this.engine.db.prepare("select payload from events where type='verification.failed' and payload like ?").all(`%${finding.id}%`) as Array<{ payload: string }>;
    return rows.filter((row) => {
      try {
        const payload = JSON.parse(row.payload) as { id?: string; rev?: number; huella?: string };
        // Con la misma evidencia (huella); los eventos viejos, sin huella, por revisión.
        return payload.id === finding.id && (payload.huella ? payload.huella === findingPrint(finding) : payload.rev === finding.rev);
      } catch {
        return false;
      }
    }).length;
  }

  /**
   * Verifica los candidatos pendientes de esta sesión, de a uno. Devuelve los veredictos; los fallos
   * quedan como candidatos. Si el proveedor dice que no hay saldo, corta la tanda ahí: el resultado
   * de ese candidato lleva `exhausted` y los demás no se intentan.
   */
  async verifyAll(options: { signal?: AbortSignal; retries?: number; onVerdict?: (verdict: VerifyResult) => void; findings?: Finding[]; stop?: () => string | undefined } = {}): Promise<VerifyResult[]> {
    const results: VerifyResult[] = [];
    for (const finding of options.findings ?? this.pending(options.retries)) {
      if (options.signal?.aborted) break;
      // Fuera del alcance: se dice sin lanzar el modelo (antes gastaba pasos consultando el alcance).
      const outside = this.outOfScope(finding);
      if (outside) {
        const skipped = { finding, error: outside, skipped: true };
        results.push(skipped);
        options.onVerdict?.(skipped);
        continue;
      }
      // Tope de gasto de la sesión (ajuste del operador): los que quedan esperan /verificar.
      const stop = options.stop?.();
      if (stop) {
        const skipped = { finding, error: stop, skipped: true };
        results.push(skipped);
        options.onVerdict?.(skipped);
        continue;
      }
      try {
        const verdict = await this.verify(finding.id, { signal: options.signal });
        results.push(verdict);
        options.onVerdict?.(verdict);
      } catch (error) {
        const exhausted = error instanceof VerifierFailure ? error.exhausted : exhaustedError((error as Error).message);
        const failed = { finding, error: (error as Error).message, ...(exhausted && { exhausted }) };
        results.push(failed);
        options.onVerdict?.(failed);
        if (exhausted) break;
      }
    }
    return results;
  }
}
