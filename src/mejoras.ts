// Diagnóstico local y determinista. Sólo consume trazas locales y la base operativa del proyecto.
import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { AssistantMessage, Message } from "./llm.ts";
import { DetectorBucles, lectura } from "./automejora-bucles.ts";
import { redactSecrets } from "./plataformas.ts";
import { modoTrazas } from "./privacidad-trazas.ts";
import { apiKey, DEFAULT_STRONG_MODEL, defaultStrongModel, resolveProvider, type Provider } from "./providers.ts";
import { secretosDelAlmacen, secretosDelEntorno } from "./secretos-sesion.ts";
import { projectPaths } from "./store.ts";

export interface PatronMejora {
  tipo: string;
  sesion: string;
  pasos: [number, number];
  /** Texto para el informe local (puede citar errores, motivos o rutas): nunca sale hacia un modelo. */
  evidencia: string;
  /** Lo único que, junto con tipo, sesión y pasos, puede salir con --modelo. */
  datos: { herramienta?: string; conteo?: number };
  cambio: string;
  hipotesis: string;
  cve: boolean;
}
export interface InformeMejoras { modo: string; sesiones: number; trazas: number; patrones: PatronMejora[]; lineas: string[] }

const tabla = (db: DatabaseSync, name: string): boolean => !!db.prepare("select 1 from sqlite_master where type='table' and name=?").get(name);
const json = (text: string): any => { try { return JSON.parse(text); } catch { return {}; } };
const idCorto = (id: string) => id.slice(0, 12);
const safe = (value: unknown, n = 100): string => String(value ?? "").replace(/[\r\n\t]+/g, " ").slice(0, n);
const totalTrazas = (dir: string, ids: Set<string>) => {
  const turnos = new Map<string, number>(), llamadas = new Map<string, number>();
  const errores = new Map<string, Map<string, number>>();
  const rechazos = new Map<string, number>();
  let cantidad = 0;
  for (const [file, target] of [["turnos.jsonl", turnos], ["llamadas.jsonl", llamadas]] as const) {
    const path = join(dir, file);
    if (!existsSync(path)) continue;
    try {
      for (const raw of readFileSync(path, "utf8").split("\n")) {
        if (!raw) continue;
        const item = json(raw), id = item.sesion;
        if (typeof id !== "string" || !ids.has(id)) continue;
        target.set(id, (target.get(id) ?? 0) + 1); cantidad++;
        if (file === "turnos.jsonl") for (const error of item.turn?.errors ?? []) {
          const byTool = errores.get(id) ?? new Map<string, number>();
          const tool = safe(error.tool, 60);
          byTool.set(tool, (byTool.get(tool) ?? 0) + 1);
          errores.set(id, byTool);
        }
        if (file === "llamadas.jsonl" && /rechaz|refus|policy/i.test(String(item.respuesta?.error ?? ""))) rechazos.set(id, (rechazos.get(id) ?? 0) + 1);
      }
    } catch { /* un archivo truncado no impide leer la base */ }
  }
  return { cantidad, turnos, llamadas, errores, rechazos };
};

const CAMBIOS: Record<string, { cambio: string; hipotesis: string; cve: boolean }> = {
  archivo: { cambio: "Agregar una guarda que avise al volver a leer un archivo ya leído tres veces.", hipotesis: "Bajan al menos 20 % las relecturas por sesión sin bajar los hallazgos verificados.", cve: false },
  rango: { cambio: "Revisar la descripción de code_read para pedir code_search antes de repetir una ventana, y la de artifact_read para agrupar filtros.", hipotesis: "Bajan al menos 20 % las ventanas repetidas sin bajar los hallazgos verificados.", cve: false },
  llamada: { cambio: "Agregar una guarda de argumentos idénticos en la herramienta afectada.", hipotesis: "Bajan al menos 20 % las llamadas repetidas sin bajar los hallazgos verificados.", cve: false },
  "sin-avance": { cambio: "Ajustar el umbral de estancamiento o la nota de cierre de hipótesis en el motor.", hipotesis: "Bajan al menos 20 % los pasos sin progreso sin bajar los hallazgos verificados.", cve: false },
  errores: { cambio: "Aclarar el esquema y los errores de la herramienta indicada, con un ejemplo válido.", hipotesis: "Bajan al menos 20 % los errores de esa herramienta sin bajar los hallazgos verificados.", cve: false },
  malformada: { cambio: "Aclarar el esquema de argumentos de la herramienta y mostrar un ejemplo JSON válido.", hipotesis: "Bajan al menos 20 % las llamadas malformadas sin bajar los hallazgos verificados.", cve: false },
  rechazo: { cambio: "Ajustar el criterio de selección del modelo para ese tipo de decisión.", hipotesis: "Bajan al menos 20 % los rechazos sin bajar los hallazgos verificados.", cve: true },
  hipotesis: { cambio: "Agregar una guarda de cierre para hipótesis inferidas antes de terminar el turno.", hipotesis: "Bajan al menos 20 % las hipótesis abiertas sin bajar los hallazgos verificados.", cve: false },
  fuerte: { cambio: "Hacer explícita la próxima acción del traspaso del modelo fuerte en la nota al ejecutor.", hipotesis: "Bajan al menos 20 % las decisiones sin acción observable sin bajar los hallazgos verificados.", cve: true },
  descartado: { cambio: "Precisar en finding_record la evidencia mínima de un candidato y el límite de su afirmación.", hipotesis: "Bajan al menos 20 % los candidatos descartados sin bajar los hallazgos verificados.", cve: true },
  contexto: { cambio: "Reducir la ventana de lectura por defecto y pedir búsquedas puntuales antes de releer.", hipotesis: "Bajan al menos 20 % los caracteres redundantes y el costo de entrada sin bajar los hallazgos verificados.", cve: false },
};

function experimento(cve: boolean): string[] {
  const base = "node bench/run.ts --target fenix --task bench/tasks/fenix.md --runs 3 --presupuesto 0.50";
  const rows = [
    "En el checkout de main: " + base + " --label mejora-base",
    "En el checkout de la propuesta: " + base + " --label mejora-rama",
    "6 corridas Fénix (3 por variante); gasto máximo configurado: USD 3.00. Comparar hallazgos verificados, relecturas, errores, tiempo y costo por hallazgo. Mismo modelo y runner.",
  ];
  if (cve) rows.push(
    "En main: node bench/run.ts --target cve --caso todos --version afectada --runs 2 --presupuesto 0.50 --label mejora-cve-base",
    "En la propuesta: node bench/run.ts --target cve --caso todos --version afectada --runs 2 --presupuesto 0.50 --label mejora-cve-rama",
    "En main: node bench/run.ts --target cve --caso todos --version corregida --runs 2 --presupuesto 0.50 --label mejora-cve-fp-base",
    "En la propuesta: node bench/run.ts --target cve --caso todos --version corregida --runs 2 --presupuesto 0.50 --label mejora-cve-fp-rama",
    "8 corridas por caso CVE (2 por variante y versión); tope USD 4.00 por caso. El gasto real puede ser menor; los casos disponibles los decide el runner.",
  );
  return rows;
}

export function diagnosticarMejoras(db: DatabaseSync, cwd: string, n = 10, modo = modoTrazas()): InformeMejoras {
  if (modo === "no") return { modo, sesiones: 0, trazas: 0, patrones: [], lineas: ["MEJORAS", "Trazas en «no»: no leí trazas ni cyber.db. Cambiá el modo con /datos local si querés un diagnóstico local."] };
  if (!Number.isInteger(n) || n < 1 || n > 100) throw new Error("Uso: cyber mejoras [1..100]");
  const sessions = db.prepare("select id, model from sessions order by started_at desc limit ?").all(n) as Array<{ id: string; model: string }>;
  const ids = new Set(sessions.map((item) => item.id));
  const dir = projectPaths(cwd).trazas;
  const traces = modo === "local" ? totalTrazas(dir, ids) : { cantidad: 0, turnos: new Map<string, number>(), llamadas: new Map<string, number>(), errores: new Map<string, Map<string, number>>(), rechazos: new Map<string, number>() };
  const patrones: PatronMejora[] = [];
  const errorTotals = new Map<string, { count: number; sesion: string; rango: [number, number]; sesiones: Set<string> }>();
  const findingsRows = tabla(db, "findings") ? (db.prepare("select json from findings").all() as Array<{ json: string }>).map((row) => json(row.json)) : [];
  const put = (tipo: string, sesion: string, pasos: [number, number], evidencia: string, datos: PatronMejora["datos"]) => {
    const spec = CAMBIOS[tipo]!;
    patrones.push({ tipo, sesion, pasos, evidencia: safe(evidencia, 240), datos, cambio: spec.cambio, hipotesis: spec.hipotesis, cve: spec.cve });
  };
  for (const { id } of sessions) {
    const rows = db.prepare("select seq,json from messages where session_id=? order by seq").all(id) as Array<{ seq: number; json: string }>;
    const events = db.prepare("select type,payload,msg_seq from events where session_id=? order by seq").all(id) as Array<{ type: string; payload: string; msg_seq: number | null }>;
    const detector = new DetectorBucles();
    const errors = new Map<string, { count: number; from: number; to: number }>();
    let step = 0, duplicateChars = 0;
    let toolStep = 0;
    const toolToModelStep = new Map<number, number>();
    const readSeen = new Set<string>();
    const calls = new Map<string, { name: string; args: any; step: number }>();
    const stepsBySeq = new Map<number, number>();
    for (const row of rows) {
      const m = json(row.json) as Message;
      if (m.role === "assistant" && m.provider !== "harness") {
        step++;
        for (const call of m.toolCalls ?? []) calls.set(call.id, { name: call.name, args: json(call.arguments), step });
        if (m.rejected || m.stopReason === "error" && /rechaz|refus|policy/i.test(m.errorMessage ?? "")) put("rechazo", id, [step, step], `Respuesta del modelo: ${safe(m.errorMessage ?? m.stopReason, 80)}`, { conteo: 1 });
      }
      stepsBySeq.set(row.seq, step);
      if (m.role !== "tool") continue;
      const call = calls.get(m.toolCallId);
      if (call) {
        toolToModelStep.set(++toolStep, call.step);
        const signals = detector.observar(call.name, call.args, { hallazgos: 0, cobertura: 0, nodos: 0 }, m.isError, { resultado: m.content }).filter((signal) => signal.tipo !== "sin-avance");
        for (const signal of signals) put(signal.tipo, id, [toolToModelStep.get(signal.desde) ?? call.step, call.step], signal.detalle, { herramienta: call.name, conteo: signal.veces });
        const read = lectura(call.name, call.args);
        if (read && !m.isError) {
          const key = `${read.archivo}\n${read.rango}`;
          if (readSeen.has(key)) duplicateChars += m.content.length;
          readSeen.add(key);
        }
      }
      if (m.isError) {
        const prev = errors.get(m.name) ?? { count: 0, from: call?.step ?? step, to: step };
        prev.count++; prev.to = call?.step ?? step; errors.set(m.name, prev);
        if (/malformada|argumentos.*(json|falta|esperaba|máximo)|nombre.*no permitido/i.test(m.content)) put("malformada", id, [call?.step ?? step, call?.step ?? step], `${m.name}: ${safe(m.content, 100)}`, { herramienta: m.name, conteo: 1 });
      }
    }
    const acumularError = (name: string, count: number, rango: [number, number]) => {
      const current = errorTotals.get(name) ?? { count: 0, sesion: id, rango, sesiones: new Set<string>() };
      current.count += count;
      current.sesiones.add(id);
      errorTotals.set(name, current);
    };
    for (const [name, count] of errors) acumularError(name, count.count, [count.from, count.to]);
    for (const [name, count] of traces.errores.get(id) ?? []) if (!errors.has(name)) acumularError(name, count, [1, Math.max(1, step)]);
    if (traces.rechazos.get(id) && !events.some((event) => event.type === "router.rechazo")) put("rechazo", id, [1, Math.max(1, step)], `${traces.rechazos.get(id)} rechazo(s) en llamadas.jsonl`, { conteo: traces.rechazos.get(id) });
    for (const event of events) {
      const item = json(event.payload);
      const at = event.msg_seq ? (stepsBySeq.get(event.msg_seq) ?? step) : step;
      if (event.type === "automejora.loop" && item.tipo === "sin-avance") put("sin-avance", id, [toolToModelStep.get(Number(item.desde)) ?? at, toolToModelStep.get(Number(item.paso)) ?? at], `${item.veces} herramientas sin progreso`, { conteo: Number(item.veces) });
      if (event.type === "router.rechazo") put("rechazo", id, [at, at], `Router: ${safe(item.modelo, 60)} rechazó ${safe(item.clase, 60)}`, { conteo: 1 });
      if (event.type === "router.decision" && item.rol === "fuerte" && item.estado === "listo") {
        const after = rows.filter((row) => row.seq > (event.msg_seq ?? Infinity)).map((row) => json(row.json) as Message).filter((m) => m.role === "assistant" && m.provider !== "harness").slice(0, 3) as AssistantMessage[];
        if (after.length >= 2 && after.every((m) => !(m.toolCalls ?? []).length)) put("fuerte", id, [at, at + after.length], `Decisión del fuerte sin llamada de herramienta en los ${after.length} pasos siguientes (inferencia)`, { conteo: after.length });
      }
    }
    if (tabla(db, "grafo_nodos")) {
      const pending = db.prepare("select count(*) n from grafo_nodos where sesion=? and tipo='hipotesis' and estado='inferido'").get(id) as { n: number };
      if (pending.n) put("hipotesis", id, [1, Math.max(1, step)], `${pending.n} hipótesis del grafo siguen inferidas`, { conteo: pending.n });
    }
    if (findingsRows.length) {
      for (const f of findingsRows) {
        if (f.sessionId === id && f.state === "descartado" && String(f.decidedBy ?? "").startsWith("verificador")) put("descartado", id, [1, Math.max(1, step)], `Candidato ${safe(f.id, 16)} descartado por el verificador: ${safe(f.reason, 90)}`, { conteo: 1 });
      }
    }
    if (duplicateChars >= 2000) {
      const requests = db.prepare("select sum(input) input, sum(cast(cost_input as real)) cost from requests where session_id=?").get(id) as { input: number | null; cost: number | null };
      const estimatedTokens = Math.round(duplicateChars / 4);
      const estimatedPico = requests.input && requests.cost ? Math.round(estimatedTokens * requests.cost / requests.input) : undefined;
      put("contexto", id, [1, Math.max(1, step)], `${duplicateChars} caracteres de ventanas repetidas (~${estimatedTokens} tokens); costo de entrada atribuible sólo como estimación${estimatedPico ? `: ~USD ${(estimatedPico / 1e12).toFixed(6)}` : " (sin tarifa medida)"}`, { conteo: duplicateChars });
    }
  }
  for (const [name, count] of [...errorTotals].sort((a, b) => b[1].count - a[1].count).slice(0, 3)) if (count.count >= 2) put("errores", count.sesion, count.rango, `${name}: ${count.count} errores en ${count.sesiones.size} sesión(es), entre las herramientas con más errores`, { herramienta: name, conteo: count.count });
  const lines = ["MEJORAS", `Modo: ${modo} · sesiones: ${sessions.length}/${n} · registros locales: ${traces.cantidad} · patrones: ${patrones.length}`];
  if (modo === "local" && !traces.cantidad) lines.push("No hay turnos ni llamadas locales para las sesiones elegidas; el diagnóstico usa sólo cyber.db.");
  if (modo === "compartir") lines.push("Sin carpeta de trazas locales en este modo; el diagnóstico usa la base operativa local.");
  if (!patrones.length) lines.push("Sin patrones con evidencia suficiente en estas sesiones.");
  for (const [i, p] of patrones.entries()) lines.push("", `${i + 1}. ${p.tipo} · sesión ${idCorto(p.sesion)} · pasos ${p.pasos[0]}–${p.pasos[1]}`, `Evidencia: ${p.evidencia}`, `Propuesta: ${p.cambio}`, `Hipótesis: ${p.hipotesis}`, `Experimento: Fénix${p.cve ? " y CVE" : ""}; comandos y costo debajo.`);
  if (patrones.length) lines.push("", "COMANDOS DEL EXPERIMENTO", ...experimento(patrones.some((p) => p.cve)));
  lines.push("", "Las propuestas son hipótesis para comparar con el bench; ninguna cambia el harness por sí sola. El costo es un tope presupuestado, no gasto observado.");
  return { modo, sesiones: sessions.length, trazas: traces.cantidad, patrones, lineas: lines };
}

/**
 * Lo único que sale hacia el modelo: tipo, sesión corta, rango de pasos, conteo y nombre de herramienta, con los
 * textos fijos de propuesta e hipótesis. La evidencia en texto (errores de herramientas, motivos, rutas) se queda
 * en el informe local; el nombre de herramienta y la sesión pasan igual por el tapado de secretos.
 */
function evidenciaParaModelo(report: InformeMejoras): Array<Record<string, unknown>> {
  const conocidos = [...secretosDelEntorno(), ...secretosDelAlmacen()].map((fuente) => fuente.valor);
  const tapar = (texto: string) => redactSecrets(texto, conocidos);
  return report.patrones.flatMap((p, i) => {
    const spec = CAMBIOS[p.tipo];
    if (!spec) return [];
    const nombre = p.datos?.herramienta;
    const herramienta = typeof nombre === "string" && /^[\w.:-]{1,80}$/.test(nombre) ? tapar(nombre) : undefined;
    const conteo = typeof p.datos?.conteo === "number" && Number.isFinite(p.datos.conteo) ? p.datos.conteo : undefined;
    return [{ id: i + 1, tipo: p.tipo, sesion: tapar(idCorto(p.sesion)), pasos: p.pasos.map(Number), ...(herramienta ? { herramienta } : {}), ...(conteo !== undefined ? { conteo } : {}), propuesta: spec.cambio, hipotesis: spec.hipotesis }];
  });
}

/** Optativo y explícito: sólo datos estructurados (evidenciaParaModelo), nunca la conversación, la evidencia en texto ni archivos de trazas. */
export async function redactarConModelo(report: InformeMejoras, cwd: string, modelSpec?: string, deps: { fetch?: typeof fetch; resolve?: (model: string) => Provider; key?: string } = {}): Promise<string> {
  if (report.modo === "no") return "";
  const configured = defaultStrongModel({ provider: "orobas", id: "auto" });
  const model = modelSpec ?? (configured.startsWith("orobas/") ? configured : DEFAULT_STRONG_MODEL);
  if (!model.startsWith("orobas/")) throw new Error("Para /mejoras modelo usá el modelo fuerte del gateway de Elevate.");
  const provider = deps.resolve?.(model) ?? resolveProvider(model);
  const key = deps.key ?? apiKey("OROBAS_API_KEY");
  if (!key) throw new Error("Falta la clave del gateway para /mejoras modelo: usá /orobas.");
  const catalog = await (deps.fetch ?? fetch)(`${provider.model.baseUrl.replace(/\/$/, "")}/models`, { headers: { authorization: `Bearer ${key}`, "x-cyber-session": "mejoras-local", "x-cyber-project": basename(cwd), "x-cyber-trazas": "no" }, signal: AbortSignal.timeout(8000) });
  if (!catalog.ok) throw new Error(`No pude consultar los modelos de tu cuenta (HTTP ${catalog.status}).`);
  const available = ((await catalog.json()) as { data?: Array<{ id?: string }> }).data ?? [];
  if (!available.some((item) => item.id === provider.model.id)) throw new Error(`El modelo fuerte ${provider.model.id} no figura entre los modelos disponibles para esta cuenta.`);
  const evidence = evidenciaParaModelo(report);
  const reply = await provider.transport({ model: provider.model, system: "Redactá en castellano propuestas de mejora concretas desde la evidencia estructurada: cada patrón trae tipo, sesión, pasos, conteo (veces, pasos o caracteres según el tipo) y a veces la herramienta. No inventes hechos ni afirmes que se corrió el bench. No propongas cambios automáticos.", messages: [{ role: "user", content: JSON.stringify(evidence), at: Date.now() }], tools: [], signal: AbortSignal.timeout(90_000), tags: { session: "mejoras-local", project: basename(cwd), trazas: "no" } });
  if (reply.stopReason === "error" || reply.rejected || !reply.content.trim()) throw new Error(`El modelo no redactó propuestas: ${safe(reply.errorMessage ?? reply.stopReason, 150)}`);
  return reply.content.trim();
}
