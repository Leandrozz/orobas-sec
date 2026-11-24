// Modo investigar: `/investigar <objetivo> [usd]`, pedido citado en lenguaje natural o apertura
// automática habilitada por el operador en /config. Sin abrir una investigación, no corren tramos.
//
// Abierta una investigación, corre en segundo plano, aparte del chat:
// - un DIARIO append-only en la carpeta de datos del proyecto (src/investigar/diario.ts) es lo único que
//   recuerda: en qué estado va, qué hipótesis hay, a qué nivel llegó cada una y con qué evidencia;
// - un ORQUESTADOR elige el próximo estado e hipótesis mirando sólo el resumen del diario (nunca el código
//   ni los artefactos): las movidas posibles salen de la máquina de estados en datos (src/investigar/estados.ts)
//   y, si hay más de una, decide el modelo del bucle (barato) con una consulta corta;
// - cada estado corre como un TRAMO con contexto limpio (runSubagent, como los tramos del router, con su
//   elección de modelo por rol blue/red): el contexto se arma del diario y de los artefactos citados;
// - una hipótesis sube de nivel (función → componentes → punta a punta) sólo si el PoC del harness se
//   reproduce en limpio (poc_run) de forma determinista: el hallazgo se verifica por ejecución.
// Costo en tokens y USD por estado y total; tope de USD por investigación.
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import type { Tool, ToolResult } from "../agent.ts";
import { readRefusal } from "../coherencia.ts";
import type { Engine } from "../engine.ts";
import type { Finding } from "../findings.ts";
import { t } from "../idioma.ts";
import { Ledger } from "../ledger.ts";
import { usd, usdToPico } from "../money.ts";
import { operatorQuote } from "../operador.ts";
import { scopeBrief } from "../scope.ts";
import { logEvent } from "../store.ts";
import { runSubagent } from "../subagent.ts";
import { exhaustedError } from "../verifier.ts";
import { type Asiento, clave, Diario, diariosDe, type HipotesisPlegada, type Plegado, plegar, porPrioridad, type Prioridad, resumenDiario } from "./diario.ts";
import { guardarPoc, reproducir } from "./ejecucion.ts";
import { cumple, type DefinicionEstado, type Entrada, ESTADO_INICIAL, ESTADOS, type EstadoId, type Salida } from "./estados.ts";

/** Tope por investigación si el operador no da uno, en USD. Referencia del método: ~10M tokens por investigación. */
export const PRESUPUESTO_DEFECTO = "10";
/** Por debajo de esto no arranca otro tramo: no alcanza ni para leer el contexto. */
const MINIMO_TRAMO = usdToPico("0.02");
/** Opciones que ve el orquestador como máximo: las primeras por prioridad. */
const MAX_OPCIONES = 6;
/** Investigaciones corriendo en este proceso (un proyecto puede tener varias sesiones abiertas en el daemon). */
const CORRIENDO = new Set<string>();

const SISTEMA_TRAMO = `Sos un tramo de una investigación de Orobas (orobas-sec): hacés sólo la tarea de UN estado de la máquina y devolvés su salida con investigation_output. Respondé en castellano rioplatense, breve.
No ves la conversación del operador ni los otros tramos: lo que sabés está en el contexto que sigue y en los artefactos que cita (artifact_read). No adivines lo que no está ahí: leelo.
Una hipótesis estática no es un hallazgo: sólo cuenta lo que un harness ejecutable dispara. No inventes comandos ni señales: el harness vuelve a correr tu comando en limpio y, si no dispara las dos veces, no cuenta.
Trabajás dentro del alcance autorizado; lo que no esté ahí no se toca. No borres ni cambies nada fuera de la carpeta de trabajo del harness.`;

const SISTEMA_ORQUESTADOR = `Sos el orquestador de una investigación de Orobas (orobas-sec). No leés código ni artefactos: decidís sólo con el resumen del diario. Elegí de la lista la próxima movida que más acerque a evidencia ejecutable con el presupuesto que queda: profundizar una hipótesis que ya disparó vale más que abrir otra; una que falló dos veces, menos; el reporte, cuando no queda nada prometedor o el presupuesto no alcanza.
Respondé exactamente dos líneas: «MOVIDA: <número>» y «MOTIVO: <una oración>».`;

export interface InvestigacionOpciones {
  /** Ejecutor de PoC en limpio (pruebas, o la API interna de la caja); sin esto, la herramienta poc_run. */
  poc?: import("./ejecucion.ts").EjecutarPoc;
}

interface Movida { estado: EstadoId; hipotesis?: string }
interface Costo { tramos: number; pasos: number; tokens: number; pico: bigint }
/** Lo que devuelve un tramo con investigation_output, ya validado. */
type SalidaTramo =
  | { tipo: "mapa"; mapa: string; puntos: string[]; resumen: string }
  | { tipo: "hipotesis"; hipotesis: Array<{ titulo: string; clase: string; activo: string; porque: string; evidencia: string; prioridad: Prioridad }>; resumen: string }
  | { tipo: "evidencia"; dispara: boolean; comando?: string; cwd?: string; senal?: string; artefactos: string[]; resumen: string }
  | { tipo: "reporte"; titulo: string; informe: string; resumen: string };

const str = (extra: object = {}) => ({ type: "string", ...extra });
const plata = (pico: bigint) => usd(pico, 2).replace(".", t(",", "."));
const ktok = (n: number) => (n < 1000 ? String(n) : `${(n / 1000).toFixed(1).replace(".", t(",", "."))}k`);
const nombreEstado = (estado: EstadoId) => t(ESTADOS[estado].nombre.es, ESTADOS[estado].nombre.en);
const corto8 = (hash: string) => hash.replace(/^sha256:/, "").slice(0, 8);

/**
 * Esquema y lectura de investigation_output por clase de salida. Lo que el estado tiene que devolver está en
 * su definición (`salida`); acá sólo cómo se pide y cómo se valida.
 */
const SALIDAS: Record<Salida, { descripcion: string; parametros: object; leer: (args: any) => SalidaTramo }> = {
  mapa: {
    descripcion: "Entregá el mapa del objetivo (markdown) y la lista de puntos de entrada, con archivo:línea.",
    parametros: { type: "object", properties: { mapa: str({ maxLength: 30000 }), puntos_entrada: { type: "array", items: str() }, resumen: str({ maxLength: 400 }) }, required: ["mapa", "puntos_entrada", "resumen"] },
    leer: (args) => ({ tipo: "mapa", mapa: String(args.mapa ?? "").trim(), puntos: (args.puntos_entrada ?? []).map(String).filter(Boolean), resumen: String(args.resumen ?? "").trim() }),
  },
  hipotesis: {
    descripcion: "Entregá la lista priorizada de hipótesis (de 3 a 8), cada una con su por qué y su evidencia estática.",
    parametros: {
      type: "object",
      properties: {
        hipotesis: { type: "array", items: { type: "object", properties: { titulo: str({ maxLength: 120 }), clase: str({ description: "Clase de falla: desborde de buffer, uso después de liberar, inyección…" }), activo: str({ description: "Archivo:función o componente" }), porque: str({ maxLength: 400 }), evidencia: str({ maxLength: 400, description: "Evidencia estática: archivo:línea y la condición que falta" }), prioridad: { type: "string", enum: ["alta", "media", "baja"] } }, required: ["titulo", "clase", "activo", "porque", "evidencia", "prioridad"] } },
        resumen: str({ maxLength: 400 }),
      },
      required: ["hipotesis", "resumen"],
    },
    leer: (args) => ({ tipo: "hipotesis", hipotesis: (args.hipotesis ?? []).map((h: any) => ({ titulo: String(h.titulo).trim(), clase: String(h.clase).trim().toLowerCase(), activo: String(h.activo).trim(), porque: String(h.porque).trim(), evidencia: String(h.evidencia).trim(), prioridad: (["alta", "media", "baja"].includes(h.prioridad) ? h.prioridad : "media") as Prioridad })).filter((h: { titulo: string }) => h.titulo), resumen: String(args.resumen ?? "").trim() }),
  },
  evidencia: {
    descripcion: "Entregá el resultado del harness: si disparó, el comando de reproducción (corre en limpio desde la carpeta indicada) y la señal que lo prueba. El harness lo vuelve a correr dos veces: si no dispara las dos, no cuenta.",
    parametros: {
      type: "object",
      properties: {
        dispara: { type: "boolean" },
        comando: str({ maxLength: 2000, description: "Comando de reproducción, autosuficiente" }),
        cwd: str({ description: "Carpeta donde correrlo" }),
        senal: str({ maxLength: 300, description: "Texto (o /regex/) que aparece en la salida cuando dispara; sin señal, cuenta salir con error" }),
        artefactos: { type: "array", items: str(), description: "Hashes de los artefactos del harness (fuente, binario, entrada)" },
        resumen: str({ maxLength: 600 }),
      },
      required: ["dispara", "resumen"],
    },
    leer: (args) => ({ tipo: "evidencia", dispara: args.dispara === true, ...(args.comando ? { comando: String(args.comando).trim() } : {}), ...(args.cwd ? { cwd: String(args.cwd).trim() } : {}), ...(args.senal ? { senal: String(args.senal) } : {}), artefactos: (args.artefactos ?? []).map(String), resumen: String(args.resumen ?? "").trim() }),
  },
  reporte: {
    descripcion: "Entregá el informe de la investigación (markdown), sólo con la evidencia ejecutable.",
    parametros: { type: "object", properties: { titulo: str({ maxLength: 120 }), informe: str({ maxLength: 40000 }), resumen: str({ maxLength: 400 }) }, required: ["titulo", "informe", "resumen"] },
    leer: (args) => ({ tipo: "reporte", titulo: String(args.titulo ?? "").trim(), informe: String(args.informe ?? "").trim(), resumen: String(args.resumen ?? "").trim() }),
  },
};

/** Cuántos elementos trae una salida, para el criterio de avance (las hipótesis cuentan las nuevas, no las repetidas). */
const elementos = (salida: SalidaTramo, nuevas?: number): number => (salida.tipo === "mapa" ? (salida.mapa ? Math.max(1, salida.puntos.length) : 0) : salida.tipo === "hipotesis" ? nuevas ?? salida.hipotesis.length : salida.tipo === "evidencia" ? 1 : salida.informe ? 1 : 0);

/** Movidas posibles, de la máquina de estados en datos y del diario; retomar un tramo cortado va primero y solo. */
export function movidasPosibles(p: Plegado): Movida[] {
  const corte = p.abierto ?? p.pendiente;
  if (corte) return [{ estado: corte.estado, ...(corte.hipotesis ? { hipotesis: corte.hipotesis } : {}) }];
  if (!p.ultimo) return [{ estado: ESTADO_INICIAL }];
  const ultimo = p.ultimo;
  const def = ESTADOS[ultimo.estado];
  const out: Movida[] = [];
  const agregar = (movida: Movida) => { if (!out.some((item) => item.estado === movida.estado && item.hipotesis === movida.hipotesis)) out.push(movida); };
  for (const siguiente of ultimo.resultado === "cumplido" ? def.siguiente.cumplido : def.siguiente.fallido) {
    const destino = ESTADOS[siguiente.estado];
    if (destino.porHipotesis) {
      const candidatas = siguiente.hipotesis === "misma" ? p.hipotesis.filter((h) => h.id === ultimo.hipotesis) : porPrioridad(p.hipotesis).filter((h) => h.id !== ultimo.hipotesis);
      for (const h of candidatas) if (elegible(destino, h, p)) agregar({ estado: destino.id, hipotesis: h.id });
    } else if ((p.intentos[destino.id] ?? 0) < destino.tope.intentos && !(destino.salida === "reporte" && p.reporte)) agregar({ estado: destino.id });
  }
  // Las de hipótesis se recortan a las primeras por prioridad; las demás (otra tanda de hipótesis, el reporte) quedan siempre.
  const fijas = out.filter((movida) => !movida.hipotesis);
  const conHipotesis = out.filter((movida) => movida.hipotesis).slice(0, Math.max(1, MAX_OPCIONES - fijas.length));
  return out.filter((movida) => !movida.hipotesis || conHipotesis.includes(movida));
}

export class Investigaciones {
  readonly engine: Engine;
  /** Carpeta de las investigaciones del proyecto (una subcarpeta con su diario por investigación). */
  readonly base: string;
  /** Algo cambió (estado, fase, costo): el pie de la TUI se actualiza. */
  onCambio?: () => void;
  private corriendo?: { id: string; control: AbortController; promesa: Promise<void> };
  private readonly track: (work: Promise<void>) => Promise<void>;

  constructor(engine: Engine, base: string, track: (work: Promise<void>) => Promise<void>) {
    this.engine = engine;
    this.base = base;
    this.track = track;
  }

  /* ---------- Lectura ---------- */

  /** Último plegado de cada diario, por su tamaño: el pie lo pide seguido y un diario no cambia sin crecer. */
  private memo = new Map<string, { tamano: number; p: Plegado | undefined }>();

  /** Las investigaciones del proyecto, de la más nueva a la más vieja. */
  todas(): Array<{ diario: Diario; p: Plegado }> {
    return diariosDe(this.base).flatMap((diario) => {
      const tamano = diario.tamano();
      let visto = this.memo.get(diario.dir);
      if (visto?.tamano !== tamano) this.memo.set(diario.dir, (visto = { tamano, p: plegar(diario.leer()) }));
      return visto.p ? [{ diario, p: visto.p }] : [];
    }).sort((a, b) => b.p.inicio.localeCompare(a.p.inicio));
  }

  /** La investigación abierta del proyecto (la última sin cerrar), con su diario y su estado plegado. */
  activa(): { diario: Diario; p: Plegado } | undefined {
    return this.todas().find((item) => item.p.fase !== "cerrada");
  }

  /** La última investigación del proyecto, abierta o cerrada. */
  private ultima(): { diario: Diario; p: Plegado } | undefined {
    return this.todas()[0];
  }

  /** ¿Corre ahora en este proceso? Una «corriendo» en el diario sin proceso que la mueva quedó interrumpida. */
  viva(id: string): boolean {
    return this.corriendo?.id === id;
  }

  /** Gasto de una investigación, por estado y total, desde el ledger (todas las sesiones del proyecto). */
  costos(id: string): { porEstado: Map<string, Costo>; total: Costo } {
    const rows = this.engine.db
      .prepare("select worker, input, cache_read, cache_write, output, cast(cost_input as integer)+cast(cost_cache_read as integer)+cast(cost_cache_write as integer)+cast(cost_output as integer) as pico from requests where worker like ? and input is not null")
      .all(`inv:${id.slice(0, 8)}:%`) as Array<{ worker: string; input: number; cache_read: number; cache_write: number; output: number; pico: number | bigint | null }>;
    const porEstado = new Map<string, Costo>();
    const total: Costo = { tramos: 0, pasos: 0, tokens: 0, pico: 0n };
    const tramos = new Map<string, Set<string>>();
    for (const row of rows) {
      const [, , estado = "?", ...resto] = row.worker.split(":");
      const fila = porEstado.get(estado) ?? { tramos: 0, pasos: 0, tokens: 0, pico: 0n };
      const tokens = row.input + row.cache_read + row.cache_write + row.output;
      const pico = row.pico === null ? 0n : BigInt(row.pico);
      fila.pasos++;
      fila.tokens += tokens;
      fila.pico += pico;
      const vistos = tramos.get(estado) ?? new Set<string>();
      vistos.add(resto.join(":"));
      tramos.set(estado, vistos);
      fila.tramos = vistos.size;
      porEstado.set(estado, fila);
      total.pasos++;
      total.tokens += tokens;
      total.pico += pico;
    }
    total.tramos = [...tramos.entries()].filter(([estado]) => estado !== "orquestador").reduce((sum, [, vistos]) => sum + vistos.size, 0);
    return { porEstado, total };
  }

  /* ---------- Comandos del operador ---------- */

  /** /investigar <objetivo> [usd] | estado | pausa | seguir [usd] | cerrar. Devuelve las líneas del panel o de la respuesta. */
  async comando(texto: string): Promise<string[]> {
    const limpio = texto.trim();
    const [verbo = "", ...resto] = limpio.split(/\s+/);
    if (!limpio || /^(estado|status|ver)$/i.test(limpio)) return this.estadoLineas();
    if (/^(pausa|pausar|pause)$/i.test(limpio)) return this.pausar();
    if (/^(seguir|continuar|retomar|resume)$/i.test(verbo)) return this.seguir(resto.join(" "));
    if (/^(cerrar|terminar|close)$/i.test(limpio)) return this.cerrar();
    const { objetivo, presupuesto } = leerPedido(limpio);
    return this.iniciar(objetivo, presupuesto, "operador");
  }

  iniciar(objetivo: string, presupuesto: string | undefined, por: "operador" | "agente", pedido?: string): string[] {
    if (objetivo.trim().length < 3) throw new Error(t("Decí qué investigar: /investigar <objetivo> [usd], por ejemplo /investigar libfoo/src/parser.c 10", "Say what to investigate: /investigar <target> [usd], e.g. /investigar libfoo/src/parser.c 10"));
    const abierta = this.activa();
    if (abierta) throw new Error(t(`Ya hay una investigación abierta en este proyecto (${abierta.p.id.slice(0, 8)}, «${abierta.p.objetivo.slice(0, 60)}»). /investigar estado la muestra; /investigar cerrar la cierra.`, `There is already an open investigation in this project (${abierta.p.id.slice(0, 8)}, «${abierta.p.objetivo.slice(0, 60)}»). /investigar estado shows it; /investigar cerrar closes it.`));
    const tope = presupuesto ?? PRESUPUESTO_DEFECTO;
    usdToPico(tope);
    const id = randomUUID();
    const diario = new Diario(join(this.base, id));
    diario.anotar({ tipo: "inicio", id, objetivo: objetivo.trim(), presupuesto: tope, sesion: this.engine.sessionId, por, ...(pedido ? { pedido } : {}) });
    logEvent(this.engine.db, this.engine.sessionId, "investigacion.inicio", { id, objetivo: objetivo.trim(), presupuesto: tope, por });
    this.arrancar(diario, id);
    const sinPoc = !this.engine.ejecutorPoc();
    return [
      t(`Investigación ${id.slice(0, 8)} abierta: «${objetivo.trim()}», tope USD ${plata(usdToPico(tope))}.`, `Investigation ${id.slice(0, 8)} open: «${objetivo.trim()}», cap USD ${plata(usdToPico(tope))}.`),
      t("Corre en segundo plano, un estado por vez y con contexto limpio: analista → hipótesis → harness 1, 2 y 3 → reporte. El chat sigue libre; el pie muestra dónde va.", "It runs in the background, one state at a time with a clean context: analyst → hypotheses → harness 1, 2 and 3 → report. The chat stays free; the footer shows where it is."),
      ...(sinPoc ? [t("Ojo: en este entorno no hay poc_run (lo trae la caja). Sin correr los PoC en limpio, ninguna hipótesis sube de nivel.", "Note: there is no poc_run here (the box has it). Without running the PoCs clean, no hypothesis levels up.")] : []),
      t(`Diario: ${diario.vista}`, `Journal: ${diario.vista}`),
      t("Uso: /investigar estado · pausa · seguir [usd] · cerrar", "Usage: /investigar estado · pausa · seguir [usd] · cerrar"),
    ];
  }

  pausar(): string[] {
    const abierta = this.activa();
    if (!abierta) throw new Error(t("No hay una investigación abierta. /investigar <objetivo> [usd] abre una.", "No open investigation. /investigar <target> [usd] opens one."));
    if (abierta.p.fase !== "corriendo") return [t(`La investigación ${abierta.p.id.slice(0, 8)} ya está ${faseNombre(abierta.p.fase)}. /investigar seguir la retoma.`, `Investigation ${abierta.p.id.slice(0, 8)} is already ${faseNombre(abierta.p.fase)}. /investigar seguir resumes it.`)];
    abierta.diario.anotar({ tipo: "control", accion: "pausa", motivo: t("el operador la pausó", "the operator paused it") });
    logEvent(this.engine.db, this.engine.sessionId, "investigacion.pausa", { id: abierta.p.id });
    this.detener();
    this.cambio();
    return [t(`Pausé la investigación ${abierta.p.id.slice(0, 8)}: el tramo en curso se corta y se retoma igual desde el diario.`, `Paused investigation ${abierta.p.id.slice(0, 8)}: the running stretch stops and resumes from the journal.`), t("Uso: /investigar seguir [usd] · estado · cerrar", "Usage: /investigar seguir [usd] · estado · cerrar")];
  }

  seguir(arg = ""): string[] {
    const abierta = this.activa();
    if (!abierta) throw new Error(t("No hay una investigación abierta para seguir. /investigar <objetivo> [usd] abre una.", "No open investigation to resume. /investigar <target> [usd] opens one."));
    const { p, diario } = abierta;
    if (this.viva(p.id)) return [t(`La investigación ${p.id.slice(0, 8)} ya está corriendo.`, `Investigation ${p.id.slice(0, 8)} is already running.`)];
    if (CORRIENDO.has(p.id)) throw new Error(t("La investigación corre en otra sesión de este proyecto: pausala desde ahí.", "The investigation runs in another session of this project: pause it from there."));
    const nuevo = arg.trim() ? leerMonto(arg.trim()) : undefined;
    if (arg.trim() && !nuevo) throw new Error(t("Uso: /investigar seguir [usd]", "Usage: /investigar seguir [usd]"));
    const tope = usdToPico(nuevo ?? p.presupuesto);
    const gastado = this.costos(p.id).total.pico;
    if (gastado + MINIMO_TRAMO >= tope || (p.fase === "tope" && !nuevo)) throw new Error(t(`El tope de USD ${plata(tope)} ya se gastó (USD ${plata(gastado)}): /investigar seguir <usd> con uno mayor.`, `The USD ${plata(tope)} cap is spent (USD ${plata(gastado)}): /investigar seguir <usd> with a higher one.`));
    diario.anotar({ tipo: "control", accion: "seguir", sesion: this.engine.sessionId, ...(nuevo ? { presupuesto: nuevo } : {}) });
    logEvent(this.engine.db, this.engine.sessionId, "investigacion.seguir", { id: p.id, ...(nuevo ? { presupuesto: nuevo } : {}) });
    this.arrancar(diario, p.id);
    const retoma = p.abierto ?? p.elegido;
    return [t(`Sigo la investigación ${p.id.slice(0, 8)} desde el diario${retoma ? `: ${nombreEstado(retoma.estado)}${retoma.hipotesis ? ` ${retoma.hipotesis}` : ""}` : ""}. Tope USD ${plata(tope)}, gastado ${plata(gastado)}.`, `Resuming investigation ${p.id.slice(0, 8)} from the journal${retoma ? `: ${nombreEstado(retoma.estado)}${retoma.hipotesis ? ` ${retoma.hipotesis}` : ""}` : ""}. Cap USD ${plata(tope)}, spent ${plata(gastado)}.`)];
  }

  cerrar(): string[] {
    const abierta = this.activa();
    if (!abierta) throw new Error(t("No hay una investigación abierta.", "No open investigation."));
    abierta.diario.anotar({ tipo: "control", accion: "cierre", motivo: t("la cerró el operador", "closed by the operator") });
    logEvent(this.engine.db, this.engine.sessionId, "investigacion.cierre", { id: abierta.p.id });
    this.detener();
    this.cambio();
    const p = plegar(abierta.diario.leer())!;
    return [t(`Cerré la investigación ${p.id.slice(0, 8)}. El diario queda en ${abierta.diario.vista}.`, `Closed investigation ${p.id.slice(0, 8)}. The journal stays at ${abierta.diario.vista}.`), ...this.balance(p)];
  }

  /** Termina cuando termina la vuelta en curso (fin, tope, pausa o corte); sin una corriendo, ya. */
  esperar(): Promise<void> {
    return this.corriendo?.promesa ?? Promise.resolve();
  }

  /** Corta el tramo en curso sin anotar nada: lo usa el motor al cerrarse (la investigación queda para retomar). */
  detener(): void {
    this.corriendo?.control.abort();
  }

  /** Aviso al abrir: una investigación que corría cuando se cortó el proceso. */
  aviso(): string | undefined {
    const abierta = this.activa();
    if (!abierta || abierta.p.fase !== "corriendo" || CORRIENDO.has(abierta.p.id)) return undefined;
    const donde = abierta.p.abierto ?? abierta.p.elegido;
    return t(`La investigación ${abierta.p.id.slice(0, 8)} («${abierta.p.objetivo.slice(0, 60)}») quedó a medio${donde ? ` en ${nombreEstado(donde.estado)}${donde.hipotesis ? ` ${donde.hipotesis}` : ""}` : ""}: /investigar seguir la retoma desde el diario.`, `Investigation ${abierta.p.id.slice(0, 8)} («${abierta.p.objetivo.slice(0, 60)}») was cut${donde ? ` at ${nombreEstado(donde.estado)}${donde.hipotesis ? ` ${donde.hipotesis}` : ""}` : ""}: /investigar seguir resumes it from the journal.`);
  }

  private arrancar(diario: Diario, id: string): void {
    if (this.corriendo || CORRIENDO.has(id)) return;
    const control = new AbortController();
    CORRIENDO.add(id);
    const promesa = this.track(
      this.correr(diario, control.signal)
        .catch((error: Error) => {
          logEvent(this.engine.db, this.engine.sessionId, "investigacion.error", { id, error: error.message.slice(0, 300) });
          this.engine.onNotice?.(t(`La investigación ${id.slice(0, 8)} se detuvo por un error: ${error.message.slice(0, 200)}. /investigar seguir la retoma.`, `Investigation ${id.slice(0, 8)} stopped on an error: ${error.message.slice(0, 200)}. /investigar seguir resumes it.`));
        })
        .finally(() => {
          CORRIENDO.delete(id);
          if (this.corriendo?.control === control) this.corriendo = undefined;
          this.cambio();
        }),
    );
    this.corriendo = { id, control, promesa };
    this.cambio();
  }

  private cambio(): void {
    this.onCambio?.();
  }

  /* ---------- El bucle: orquestador → tramo, hasta el reporte, el tope o una pausa ---------- */

  private async correr(diario: Diario, signal: AbortSignal): Promise<void> {
    for (let vuelta = 0; vuelta < 200 && !signal.aborted; vuelta++) {
      const p = plegar(diario.leer())!;
      if (p.fase !== "corriendo") return;
      const gastado = this.costos(p.id).total.pico;
      const tope = usdToPico(p.presupuesto);
      if (gastado + MINIMO_TRAMO >= tope) return this.alTope(diario, p, gastado, tope);
      const movida = await this.orquestar(diario, p, gastado, signal);
      if (signal.aborted) return;
      if (!movida) {
        diario.anotar({ tipo: "control", accion: "fin", motivo: p.reporte ? "reporte listo" : "no quedan movidas" });
        const final = plegar(diario.leer())!;
        logEvent(this.engine.db, this.engine.sessionId, "investigacion.fin", { id: p.id, hipotesis: final.hipotesis.length, ejecutables: final.hipotesis.filter((h) => h.nivel > 0).length, usd: usd(gastado) });
        this.engine.onNotice?.([t(`La investigación ${p.id.slice(0, 8)} terminó.`, `Investigation ${p.id.slice(0, 8)} finished.`), ...this.balance(final)].join(" "));
        return;
      }
      const fin = await this.tramo(diario, p, movida, tope - gastado, signal);
      this.cambio();
      if (fin === "tope") return this.alTope(diario, p, this.costos(p.id).total.pico, tope);
      if (fin === "sin-saldo") {
        diario.anotar({ tipo: "control", accion: "pausa", motivo: "el proveedor dice que no hay saldo" });
        this.engine.onNotice?.(t(`La investigación ${p.id.slice(0, 8)} se pausó: el proveedor dice que no hay saldo. Cuando vuelva, /investigar seguir la retoma donde quedó.`, `Investigation ${p.id.slice(0, 8)} paused: the provider says there is no balance. When it is back, /investigar seguir resumes it where it was.`));
        return;
      }
    }
  }

  /** Lo que queda no alcanza para otro tramo: la investigación se pausa en su tope y el operador decide. */
  private alTope(diario: Diario, p: Plegado, gastado: bigint, tope: bigint): void {
    diario.anotar({ tipo: "control", accion: "tope", motivo: `gastado USD ${usd(gastado, 2)} de ${p.presupuesto}` });
    logEvent(this.engine.db, this.engine.sessionId, "investigacion.tope", { id: p.id, usd: usd(gastado) });
    this.engine.onNotice?.(t(`La investigación ${p.id.slice(0, 8)} llegó a su tope (USD ${plata(gastado)} de ${plata(tope)}: lo que queda no alcanza para otro tramo) y se pausó. /investigar seguir <usd> la sigue con más.`, `Investigation ${p.id.slice(0, 8)} hit its cap (USD ${plata(gastado)} of ${plata(tope)}: what is left does not cover another stretch) and paused. /investigar seguir <usd> resumes it with more.`));
  }

  /** Balance corto: hipótesis, cuántas dispararon y hasta qué nivel, informe y gasto. */
  private balance(p: Plegado): string[] {
    const ejecutables = p.hipotesis.filter((h) => h.nivel > 0);
    const gasto = this.costos(p.id).total;
    return [t(`${p.hipotesis.length} hipótesis, ${ejecutables.length} con evidencia ejecutable${ejecutables.length ? ` (nivel máximo ${Math.max(...ejecutables.map((h) => h.nivel))})` : ""}${p.reporte ? `; informe ${p.reporte.slice(0, 19)}` : ""}. Gasto USD ${plata(gasto.pico)}, ${ktok(gasto.tokens)} tokens.`, `${p.hipotesis.length} hypotheses, ${ejecutables.length} with executable evidence${ejecutables.length ? ` (max level ${Math.max(...ejecutables.map((h) => h.nivel))})` : ""}${p.reporte ? `; report ${p.reporte.slice(0, 19)}` : ""}. Spent USD ${plata(gasto.pico)}, ${ktok(gasto.tokens)} tokens.`)];
  }

  /**
   * El orquestador: con una sola movida posible, va ésa; con varias, decide el modelo del bucle (barato)
   * mirando SÓLO el resumen del diario. Si no elige una opción válida, va la primera (la de la regla).
   */
  private async orquestar(diario: Diario, p: Plegado, gastado: bigint, signal: AbortSignal): Promise<Movida | undefined> {
    const opciones = movidasPosibles(p);
    if (!opciones.length) return undefined;
    const etiqueta = (movida: Movida) => `${movida.estado}${movida.hipotesis ? ` ${movida.hipotesis}` : ""}`;
    const anotar = (movida: Movida, por: "modelo" | "regla", motivo: string) => diario.anotar({ tipo: "orquestador", estado: movida.estado, ...(movida.hipotesis ? { hipotesis: movida.hipotesis } : {}), opciones: opciones.map(etiqueta), por, motivo });
    const corte = p.abierto ?? p.pendiente;
    if (opciones.length === 1) {
      anotar(opciones[0]!, "regla", corte ? "retoma el tramo que se cortó" : p.ultimo ? "única movida posible" : "empieza por el analista");
      return opciones[0];
    }
    const lista = opciones.map((movida, index) => {
      const h = movida.hipotesis ? p.hipotesis.find((item) => item.id === movida.hipotesis) : undefined;
      return `${index + 1}. ${nombreEstado(movida.estado)}${h ? ` sobre ${h.id} (nivel ${h.nivel}, ${h.prioridad}) «${h.titulo.slice(0, 80)}»` : ""}`;
    });
    const prompt = `${resumenDiario(p, usd(gastado, 2))}\n\nMOVIDAS POSIBLES:\n${lista.join("\n")}`;
    const worker = `inv:${p.id.slice(0, 8)}:orquestador`;
    const model = this.engine.agent.model;
    const ctx = { sessionId: this.engine.sessionId, account: this.engine.provider.account, worker, model };
    const intent = `pendiente:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`;
    this.engine.ledger.begin(intent, ctx);
    this.engine.ledger.reserve(intent, this.engine.sessionId, Ledger.estimate(model, prompt.length + SISTEMA_ORQUESTADOR.length));
    const reply = await this.engine.tagged(worker)({ model, system: SISTEMA_ORQUESTADOR, messages: [{ role: "user", content: prompt, at: Date.now() }], tools: [], signal });
    this.engine.ledger.settle(intent);
    this.engine.ledger.record(reply, ctx);
    const elegida = Number(/MOVIDA:\s*(\d+)/i.exec(reply.content)?.[1] ?? /\b(\d+)\b/.exec(reply.content)?.[1]);
    const movida = Number.isInteger(elegida) && elegida >= 1 && elegida <= opciones.length ? opciones[elegida - 1]! : undefined;
    if (!movida) {
      anotar(opciones[0]!, "regla", "el orquestador no eligió una opción válida: va la primera");
      return opciones[0];
    }
    anotar(movida, "modelo", (/MOTIVO:\s*(.+)/i.exec(reply.content)?.[1] ?? "sin motivo").trim().slice(0, 240));
    return movida;
  }

  /** Herramientas del tramo: las de su estado que existan (cargadas o en el catálogo), sin tocar las del bucle. */
  private herramientasDe(def: DefinicionEstado): Tool[] {
    const out: Tool[] = [];
    for (const name of def.herramientas) {
      const cargada = this.engine.agent.tools.find((tool) => tool.name === name);
      const catalogo = this.engine.catalog.available.get(name);
      if (cargada) out.push(cargada);
      else if (catalogo) out.push(this.engine.bounded(catalogo));
    }
    return out;
  }

  /**
   * Contexto limpio de un tramo: sólo lo que la ENTRADA del estado pide del diario y de los artefactos
   * citados. Nada de la conversación del operador ni de otros tramos.
   */
  contexto(def: DefinicionEstado, p: Plegado, movida: Movida): string {
    const h = movida.hipotesis ? p.hipotesis.find((item) => item.id === movida.hipotesis) : undefined;
    const leer = (hash: string, max: number) => {
      try {
        const texto = this.engine.artifacts.read(hash).toString("utf8");
        return texto.length > max ? `${texto.slice(0, max)}\n… (sigue en ${hash}; artifact_read para el resto)` : texto;
      } catch {
        return `(no pude leer ${hash})`;
      }
    };
    const bloques: Record<Entrada, () => string | undefined> = {
      objetivo: () => `OBJETIVO: ${p.objetivo}\nEl código está en la carpeta del proyecto: code_list, code_search y code_read lo leen.`,
      mapa: () => (p.mapa ? `MAPA (${p.mapa}):\n${leer(p.mapa, 12_000)}` : undefined),
      hipotesis: () => (p.hipotesis.length ? `HIPÓTESIS YA PROPUESTAS (no las repitas; podés proponer otras):\n${porPrioridad(p.hipotesis).map((item) => `- ${item.id} [${item.prioridad}] nivel ${item.nivel}: ${item.titulo} — ${item.activo}`).join("\n")}` : undefined),
      "hipotesis-elegida": () => (h ? `HIPÓTESIS ${h.id} [${h.prioridad}] · nivel ejecutable actual ${h.nivel}\nTítulo: ${h.titulo}\nClase: ${h.clase}\nActivo: ${h.activo}\nPor qué: ${h.porque}\nEvidencia estática: ${h.evidencia}` : undefined),
      "evidencia-previa": () => {
        if (!h || !h.nivel) return undefined;
        const nivel = h.nivel as 1 | 2 | 3;
        const corrida = [...p.ejecuciones].reverse().find((item) => item.hipotesis === h.id && item.nivel === nivel && item.dispara);
        return `EVIDENCIA DEL NIVEL ${nivel} (ejecutable, reproducida en limpio):\nPoC: ${h.pocs[nivel]}\nComando: ${h.comandos[nivel] ?? "(ver el PoC)"}\n${corrida ? `Corrida: ${corrida.motivo}${corrida.salida ? `\nSalida (${corrida.salida}):\n${leer(corrida.salida, 3000)}` : ""}` : ""}`;
      },
      evidencias: () => {
        const filas = porPrioridad(p.hipotesis).map((item) => {
          const niveles = ([1, 2, 3] as const).filter((nivel) => item.pocs[nivel]).map((nivel) => `  nivel ${nivel}: PoC ${item.pocs[nivel]} · comando ${item.comandos[nivel] ?? "(en el PoC)"}`);
          const fallas = Object.entries(p.fallas).filter(([k]) => k.endsWith(`:${item.id}`)).map(([k, motivos]) => `  ${k.split(":")[0]} falló: ${motivos.at(-1)!.slice(0, 200)}`);
          return [`- ${item.id} [${item.prioridad}] nivel ${item.nivel}${item.hallazgo ? ` · hallazgo ${item.hallazgo.slice(0, 8)}` : ""}: ${item.titulo} — ${item.activo}`, ...niveles, ...fallas].join("\n");
        });
        return `EVIDENCIA POR HIPÓTESIS (sólo lo ejecutable cuenta):\n${filas.join("\n") || "ninguna hipótesis"}${p.mapa ? `\nMapa: ${p.mapa}` : ""}`;
      },
      intentos: () => {
        const fallas = p.fallas[clave(def.id, movida.hipotesis)] ?? [];
        return fallas.length ? `INTENTOS ANTERIORES DE ESTE ESTADO (fallaron; no repitas lo mismo):\n${fallas.map((motivo) => `- ${motivo.slice(0, 300)}`).join("\n")}` : undefined;
      },
    };
    return def.entrada.map((entrada) => bloques[entrada]()).filter(Boolean).join("\n\n");
  }

  /**
   * Un estado, como tramo con contexto limpio. Anota inicio, artefactos, ejecuciones y fin en el diario.
   * Devuelve «tope» si lo que queda de la investigación no alcanza para hacerlo (o lo cortó sin avanzar).
   */
  private async tramo(diario: Diario, p: Plegado, movida: Movida, restante: bigint, signal: AbortSignal): Promise<"tope" | "sin-saldo" | undefined> {
    const def = ESTADOS[movida.estado];
    const n = p.tramos + 1;
    const intento = (p.intentos[clave(def.id, movida.hipotesis)] ?? 0) + 1;
    const elegido = this.engine.modeloTramo(def.rol, def.nivel);
    const worker = `inv:${p.id.slice(0, 8)}:${def.id}:${movida.hipotesis ? `${movida.hipotesis}:` : ""}${n}`;
    const tope = usdToPico(def.tope.usd);
    const budget = restante < tope ? restante : tope;
    const contexto = this.contexto(def, p, movida);
    // Ni el primer paso entra en lo que queda (con la misma cuenta que hace el subagente antes de cada paso):
    // no se arranca un tramo que se cortaría sin hacer nada.
    if (budget < Ledger.estimate(elegido.provider.model, contexto.length + def.tarea.length + 1200)) return "tope";
    diario.anotar({ tipo: "estado.inicio", tramo: n, estado: def.id, ...(movida.hipotesis ? { hipotesis: movida.hipotesis } : {}), intento, modelo: elegido.spec, worker });
    this.cambio();
    let salida: SalidaTramo | undefined;
    const forma = SALIDAS[def.salida];
    const salidaTool: Tool = {
      name: "investigation_output",
      label: t("Salida del estado", "State output"),
      description: `${forma.descripcion} Llamala una vez, al terminar; sin esta llamada el estado no cuenta.`,
      parameters: forma.parametros,
      execute: (args): ToolResult => {
        // La primera entrega vale: el estado se evalúa con ella; una segunda no la pisa.
        if (salida) return { text: "La salida de este estado ya está registrada: terminá con una línea de resumen.", isError: true };
        salida = forma.leer(args);
        return { text: "Salida registrada. Terminá con una línea de resumen.", details: { estado: def.id } };
      },
    };
    const tools = [...this.herramientasDe(def), this.engine.bounded(salidaTool)];
    let insistio = false;
    const correrCon = (provider: typeof elegido.provider, w: string) => runSubagent(this.engine, {
      objective: `ESTADO: ${nombreEstado(def.id)}${movida.hipotesis ? ` · hipótesis ${movida.hipotesis}` : ""} · intento ${intento}\nTAREA: ${def.tarea}`,
      context: `${contexto}\n\nSALIDA: ${forma.descripcion} Con investigation_output.\nTOPE DEL TRAMO: ${def.tope.pasos} pasos, USD ${usd(budget, 2)}.`,
      worker: w,
      provider,
      budget,
      maxSteps: def.tope.pasos,
      signal,
      system: `${SISTEMA_TRAMO}\n\nAlcance: ${scopeBrief(this.engine.scope.current())}`,
      herramientas: tools,
      topeProyecto: true,
      beforeEnd: () => (salida || insistio ? undefined : ((insistio = true), "[sistema] Falta la salida del estado: llamá a investigation_output con lo que tengas (si el harness no disparó, dispara: false y por qué).")),
    });
    let resultado = await correrCon(elegido.provider, worker);
    let modelo = elegido.spec;
    // Un estándar que se niega: el mismo tramo con el del nivel red, como en el router.
    if (!salida && resultado.ok && elegido.alternativa && !signal.aborted && readRefusal({ content: resultado.text, toolCalls: [], stopReason: "stop" })) {
      this.engine.rechazos.anotar(elegido.spec, def.nivel, def.id, true);
      modelo = elegido.alternativa.spec;
      resultado = await correrCon(elegido.alternativa.provider, `${worker}b`);
    }
    const pasos = resultado.requests;
    const gasto = usd(resultado.cost);
    if (signal.aborted && !salida) {
      diario.anotar({ tipo: "estado.fin", tramo: n, estado: def.id, ...(movida.hipotesis ? { hipotesis: movida.hipotesis } : {}), resultado: "cortado", motivo: "pausa o corte del proceso", pasos, usd: gasto });
      return undefined;
    }
    // Sin saldo en el proveedor: no gasta un intento; la investigación se pausa hasta que vuelva.
    if (!salida && !resultado.ok && exhaustedError(resultado.reason ?? "")) {
      diario.anotar({ tipo: "estado.fin", tramo: n, estado: def.id, ...(movida.hipotesis ? { hipotesis: movida.hipotesis } : {}), resultado: "cortado", motivo: "el proveedor dice que no hay saldo", pasos, usd: gasto });
      return "sin-saldo";
    }
    // Lo cortó el resto del presupuesto de la investigación (no el tope propio del estado): no gasta un intento.
    if (!salida && budget < tope && /Tope del subagente/.test(resultado.reason ?? "")) {
      diario.anotar({ tipo: "estado.fin", tramo: n, estado: def.id, ...(movida.hipotesis ? { hipotesis: movida.hipotesis } : {}), resultado: "cortado", motivo: "lo cortó el tope de la investigación", pasos, usd: gasto });
      return resultado.cost > 0n ? undefined : "tope";
    }
    diario.anotar({ tipo: "artefacto", tramo: n, estado: def.id, clase: "transcripcion", hash: resultado.transcript, nota: modelo });
    const { reproduce, motivo, nuevas } = salida ? await this.procesar(diario, p, def, movida, n, salida, signal) : { reproduce: false, motivo: resultado.ok ? "terminó sin investigation_output" : `el tramo no terminó: ${resultado.reason ?? "sin respuesta"}`, nuevas: undefined };
    const ok = cumple(def, salida ? { tipo: salida.tipo, elementos: elementos(salida, nuevas) } : undefined, reproduce);
    diario.anotar({ tipo: "estado.fin", tramo: n, estado: def.id, ...(movida.hipotesis ? { hipotesis: movida.hipotesis } : {}), resultado: ok ? "cumplido" : "fallido", motivo, ...(salida ? { salida: salida.tipo } : {}), pasos, usd: gasto });
    return undefined;
  }

  /** Guarda lo que devolvió el tramo según su clase de salida. Para la evidencia: PoC, hallazgo y verificación por ejecución. */
  private async procesar(diario: Diario, p: Plegado, def: DefinicionEstado, movida: Movida, n: number, salida: SalidaTramo, signal: AbortSignal): Promise<{ reproduce?: boolean; motivo: string; nuevas?: number }> {
    const { artifacts } = this.engine;
    switch (salida.tipo) {
      case "mapa": {
        if (!salida.mapa) return { motivo: "mapa vacío" };
        const hash = artifacts.put(`# Mapa: ${p.objetivo}\n\n${salida.mapa}\n\n## Puntos de entrada\n${salida.puntos.map((punto) => `- ${punto}`).join("\n")}\n`, "text/markdown", "investigacion:mapa").hash;
        diario.anotar({ tipo: "artefacto", tramo: n, estado: def.id, clase: "mapa", hash, nota: `${salida.puntos.length} puntos de entrada` });
        return { motivo: `mapa con ${salida.puntos.length} puntos de entrada` };
      }
      case "hipotesis": {
        let siguiente = p.hipotesis.length;
        const vistas = new Set(p.hipotesis.map((h) => h.titulo.toLowerCase()));
        let nuevas = 0;
        for (const h of salida.hipotesis.slice(0, 8)) {
          if (vistas.has(h.titulo.toLowerCase())) continue;
          vistas.add(h.titulo.toLowerCase());
          diario.anotar({ tipo: "hipotesis", tramo: n, id: `h${++siguiente}`, ...h });
          nuevas++;
        }
        return { motivo: nuevas ? `${nuevas} hipótesis nuevas` : "ninguna hipótesis nueva", nuevas };
      }
      case "reporte": {
        if (!salida.informe) return { motivo: "informe vacío" };
        const hash = artifacts.put(`# ${salida.titulo || p.objetivo}\n\n${salida.informe}\n`, "text/markdown", "investigacion:reporte").hash;
        diario.anotar({ tipo: "artefacto", tramo: n, estado: def.id, clase: "reporte", hash, nota: salida.titulo });
        return { motivo: `informe ${hash.slice(0, 19)}` };
      }
      case "evidencia":
        return this.evidencia(diario, p, def, movida, n, salida, signal);
    }
  }

  /**
   * Un harness dijo que disparó: se guarda su PoC, se registra (o actualiza) el hallazgo de la hipótesis y
   * se verifica por ejecución. Sólo si se reproduce en limpio la hipótesis sube de nivel.
   */
  private async evidencia(diario: Diario, p: Plegado, def: DefinicionEstado, movida: Movida, n: number, salida: Extract<SalidaTramo, { tipo: "evidencia" }>, signal: AbortSignal): Promise<{ reproduce: boolean; motivo: string }> {
    const h = p.hipotesis.find((item) => item.id === movida.hipotesis);
    const nivel = def.harness!.nivel;
    const anotar = (dispara: boolean, motivo: string, extra: { poc?: string; comando?: string; corridas?: string; salida?: string; hallazgo?: string } = {}) => {
      diario.anotar({ tipo: "ejecucion", tramo: n, hipotesis: movida.hipotesis ?? "?", nivel, dispara, corridas: extra.corridas ?? "0/0", motivo, ...(extra.poc ? { poc: extra.poc } : {}), ...(extra.comando ? { comando: extra.comando } : {}), ...(extra.salida ? { salida: extra.salida } : {}), ...(extra.hallazgo ? { hallazgo: extra.hallazgo } : {}) });
      return { reproduce: dispara, motivo };
    };
    if (!h) return anotar(false, "la hipótesis no está en el diario");
    if (!salida.dispara || !salida.comando) return anotar(false, `el harness no disparó: ${salida.resumen.slice(0, 200) || "sin resumen"}`);
    const artefactos = salida.artefactos.map((hash) => this.engine.artifacts.find(hash)).filter((hash): hash is string => !!hash);
    const poc = guardarPoc(this.engine.artifacts, { comando: salida.comando, ...(salida.cwd ? { cwd: salida.cwd } : {}), ...(salida.senal ? { senal: salida.senal } : {}), ...(artefactos.length ? { artefactos } : {}), investigacion: p.id, hipotesis: h.id, nivel });
    diario.anotar({ tipo: "artefacto", tramo: n, estado: def.id, clase: "poc", hash: poc, nota: `${h.id} nivel ${nivel}` });
    const ejecutar = this.engine.ejecutorPoc();
    if (!ejecutar) return anotar(false, "no hay poc_run en este entorno para correr el PoC en limpio (está en la caja)", { poc, comando: salida.comando });
    const previo = h.hallazgo ? this.engine.findings.get(h.hallazgo) : undefined;
    // Ya verificado en un nivel anterior: la corrida en limpio de este nivel suma su evidencia al hallazgo.
    if (previo?.state === "verificado") {
      const rep = await reproducir(ejecutar, { formato: "orobas.poc/1", comando: salida.comando, ...(salida.cwd ? { cwd: salida.cwd } : {}), ...(salida.senal ? { senal: salida.senal } : {}) }, signal);
      const log = this.engine.artifacts.put(JSON.stringify({ poc, comando: salida.comando, corridas: rep.corridas.map((c) => ({ ...c, salida: c.salida.slice(0, 20_000) })) }, null, 1), "application/json", "investigacion:corrida").hash;
      if (rep.reproduce) this.engine.findings.update(previo.id, { evidence: [poc, log], limits: limites(nivel) }, this.engine.sessionId);
      return anotar(rep.reproduce, rep.motivo, { poc, comando: salida.comando, corridas: `${rep.disparos}/${rep.corridas.length}`, salida: log, hallazgo: previo.id });
    }
    let hallazgo: Finding;
    try {
      const mismo = previo ?? this.engine.findings.list().find((item) => item.state !== "descartado" && item.asset === h.activo && item.kind === h.clase);
      const resumen = `${h.porque}\nNivel ${nivel} (${nombreNivel(nivel)}): ${salida.resumen}\nReproducción: ${salida.comando}${salida.senal ? `\nSeñal: ${salida.senal}` : ""}`;
      hallazgo = mismo
        ? this.engine.findings.update(mismo.id, { evidence: [poc], summary: resumen, limits: limites(nivel), ...(mismo.state === "pista" ? { state: "candidato" } : {}) }, this.engine.sessionId)
        : this.engine.findings.record({ title: h.titulo, kind: h.clase, severity: "media", asset: h.activo, summary: resumen, evidence: [poc], limits: limites(nivel), state: "candidato" }, this.engine.sessionId);
    } catch (error) {
      return anotar(false, `no pude registrar el hallazgo: ${(error as Error).message.slice(0, 200)}`, { poc, comando: salida.comando });
    }
    try {
      const veredicto = await this.engine.verifier.verify(hallazgo.id, { signal });
      logEvent(this.engine.db, this.engine.sessionId, "verification.verdict", { id: hallazgo.id, state: veredicto.state, usd: veredicto.costUsd, requests: veredicto.requests, por: "investigacion" });
      const corridas = veredicto.ejecucion ? `${veredicto.ejecucion.disparos}/${veredicto.ejecucion.corridas}` : "—";
      return anotar(veredicto.state === "verificado", veredicto.reason, { poc, comando: salida.comando, corridas, salida: veredicto.transcript, hallazgo: hallazgo.id });
    } catch (error) {
      // La verificación automática del chat pudo ganarle de mano con el mismo PoC: lo que vale es el veredicto guardado.
      const ahora = this.engine.findings.get(hallazgo.id);
      if (ahora?.state === "verificado" && ahora.evidence.includes(poc)) return anotar(true, ahora.reason, { poc, comando: salida.comando, corridas: "—", hallazgo: hallazgo.id });
      return anotar(false, `no se pudo verificar por ejecución: ${(error as Error).message.slice(0, 200)}`, { poc, comando: salida.comando, hallazgo: hallazgo.id });
    }
  }

  /* ---------- Verificación: en el modo, lo de código necesita evidencia ejecutable ---------- */

  /**
   * ¿Este candidato tiene que verificarse por ejecución? Sí, si es de una investigación del proyecto (su
   * hipótesis lo registró) o si es de código (no web) y se registró con una investigación abierta. Los
   * hallazgos web siguen con el verificador de siempre.
   */
  exigeEjecucion(finding: Finding): boolean {
    const asset = finding.asset.trim();
    const hosts = (this.engine.scope.current()?.include ?? []).map((rule) => rule.value.replace(/^https?:\/\//, "").split(/[/:]/)[0]!.replace(/^\*\./, "").toLowerCase());
    const host = asset.replace(/^https?:\/\//, "").split(/[/:]/)[0]!.toLowerCase();
    if (/^(https?|wss?):\/\//i.test(asset) || hosts.some((item) => item && (host === item || host.endsWith(`.${item}`)))) return false;
    for (const { p } of this.todas()) if (p.hipotesis.some((h) => h.hallazgo === finding.id) || p.ejecuciones.some((item) => item.hallazgo === finding.id)) return true;
    const abierta = this.activa();
    return !!abierta && finding.createdAt >= abierta.p.inicio;
  }

  /* ---------- Lenguaje natural ---------- */

  /** El operador nombra el modo con todas las letras: el agente sabe que se abre con investigation_start. */
  contextoOperador(texto: string): string {
    if (!/\bmodo (de )?investiga(r|ci[oó]n)\b|\/investigar\b/i.test(texto) || this.activa()) return "";
    return "\n\n[sistema] El operador nombra el modo investigar: se abre con investigation_start (cargala con tools_load), con el objetivo y, si lo dio, el tope en USD, citando su mensaje en «pedido». Si no queda claro que lo quiere abrir, preguntale.";
  }

  /** investigation_start: cita del operador, salvo que haya habilitado la apertura automática en /config. */
  herramienta(): Tool {
    return {
      name: "investigation_start",
      label: t("Abrir una investigación", "Open an investigation"),
      description: "Modo investigar: investigación de código con harnesses ejecutables. Proponela al cierre si una hipótesis de código necesita ejecución. Abrila sólo con cita del operador o con investigación automática activa en /config; en ese caso el tope es el menor entre USD 2 y la mitad del presupuesto restante.",
      parameters: { type: "object", properties: { objetivo: str({ maxLength: 400, description: "Qué investigar: repo, componente, archivo o función" }), presupuesto_usd: { type: "number", minimum: 0.5, maximum: 500, description: `Tope pedido por el operador en USD; por defecto ${PRESUPUESTO_DEFECTO}` }, pedido: str({ description: "Cita textual del mensaje del operador que lo pide; omitible sólo si /config habilitó la apertura automática" }) }, required: ["objetivo"] },
      execute: (params) => {
        const tienePedido = typeof params.pedido === "string" && params.pedido.trim().length > 0;
        const pedido = tienePedido ? operatorQuote(this.engine.operatorTexts(), params.pedido, "abrir una investigación") : undefined;
        if (!pedido && !this.engine.investigationAuto) throw new Error("Para abrir una investigación hace falta la cita del operador o activar investigación automática en /config.");
        let monto = typeof params.presupuesto_usd === "number" ? String(params.presupuesto_usd) : undefined;
        if (!pedido) {
          const ledger = this.engine.ledger;
          if (ledger.totals(this.engine.sessionId).unknownRequests) throw new Error("Hay gasto sin contabilizar: no puedo calcular el tope automático.");
          const sesion = ledger.budgetPico === undefined ? undefined : ledger.budgetPico - ledger.totals(this.engine.sessionId).knownPico - ledger.reservedPico(this.engine.sessionId);
          const proyecto = ledger.projectBudget();
          const global = proyecto === undefined ? undefined : proyecto - ledger.totals().knownPico;
          const restante = sesion === undefined ? global : global === undefined ? sesion : sesion < global ? sesion : global;
          if (restante === undefined || restante <= 0n) throw new Error("La apertura automática necesita un presupuesto restante positivo.");
          const mitad = restante / 2n;
          const tope = usdToPico("2");
          const cap = mitad < tope ? mitad : tope;
          if (cap < usdToPico("0.02")) throw new Error("El presupuesto restante no alcanza para un tramo de investigación.");
          monto = usd(cap);
        }
        const lines = this.iniciar(String(params.objetivo ?? ""), monto, "agente", pedido);
        if (!pedido) this.engine.onNotice?.(`Abrí una investigación automática: ${String(params.objetivo ?? "").slice(0, 100)}. Tope USD ${monto}; /investigar estado muestra el avance.`);
        return { text: `${lines.join("\n")}\nNo hace falta que la sigas vos: corre aparte y el operador la ve con /investigar estado.`, details: { investigacion: this.activa()?.p.id } };
      },
    };
  }

  /* ---------- Pie y panel ---------- */

  /** Indicador del pie mientras hay una investigación abierta: «inv: harness-1 · h3/7 · USD 1,20». */
  pie(): { label: string; short: string; activa: boolean } | undefined {
    const abierta = this.activa();
    if (!abierta) return undefined;
    const { p } = abierta;
    const viva = this.viva(p.id);
    const donde = p.abierto ?? p.elegido;
    const gasto = `USD ${plata(this.costos(p.id).total.pico)}`;
    const fase = viva ? "" : `${faseNombre(p.fase === "corriendo" ? "interrumpida" : p.fase)} · `;
    const estado = donde ? donde.estado : ESTADO_INICIAL;
    const h = donde?.hipotesis && p.hipotesis.length ? ` · ${donde.hipotesis}/${p.hipotesis.length}` : p.hipotesis.length ? ` · ${p.hipotesis.length} ${t("hip.", "hyp.")}` : "";
    return { label: `inv: ${fase}${estado}${h} · ${gasto}`, short: `inv: ${viva ? estado : faseNombre(p.fase === "corriendo" ? "interrumpida" : p.fase)} · ${gasto}`, activa: viva };
  }

  /** /investigar estado: estado actual, hipótesis con su nivel, evidencia y costo por estado. */
  estadoLineas(): string[] {
    const elegida = this.activa() ?? this.ultima();
    const uso = t("Uso: /investigar <objetivo> [usd] · estado · pausa · seguir [usd] · cerrar", "Usage: /investigar <target> [usd] · estado · pausa · seguir [usd] · cerrar");
    if (!elegida) return [t("No hay investigaciones en este proyecto. Una investigación arma el mapa del objetivo, hipótesis priorizadas y harnesses ejecutables en tres niveles (función, componentes, punta a punta), con su diario y su tope de USD.", "No investigations in this project. An investigation builds the target map, prioritized hypotheses and executable harnesses on three levels (function, components, end to end), with its journal and USD cap."), uso];
    const { p, diario } = elegida;
    const col = (label: string) => label.padEnd(12);
    const sangria = " ".repeat(12);
    const ajustar = (texto: string, ancho: number) => (texto.length > ancho ? `${texto.slice(0, ancho - 1)}…` : texto.padEnd(ancho));
    const costos = this.costos(p.id);
    const tope = usdToPico(p.presupuesto);
    const viva = this.viva(p.id);
    const fase = viva ? t("corriendo", "running") : faseNombre(p.fase === "corriendo" ? "interrumpida" : p.fase);
    const donde = p.abierto ?? p.elegido;
    const lineas = [
      t("INVESTIGACIÓN", "INVESTIGATION"),
      `${col(t("Objetivo", "Target"))}${ajustar(p.objetivo, 60).trimEnd()}`,
      `${col(t("Estado", "State"))}${donde && p.fase !== "cerrada" ? `${nombreEstado(donde.estado)}${donde.hipotesis ? ` · ${donde.hipotesis}` : ""} · ` : ""}${fase} · ${p.id.slice(0, 8)}`,
      `${col(t("Tope", "Cap"))}USD ${plata(costos.total.pico)} ${t("de", "of")} ${plata(tope)} (${tope > 0n ? Math.round(Number((costos.total.pico * 1000n) / tope) / 10) : 0} %) · ${ktok(costos.total.tokens)} tokens`,
    ];
    const fila = (a: string, b: string, c: string, d: string, e: string) => `${ajustar(a, 24)}${b.padStart(6)} ${c.padStart(6)} ${d.padStart(9)} ${e.padStart(7)}`;
    lineas.push(`${col(t("Por estado", "By state"))}${fila(t("estado", "state"), t("tramos", "runs"), t("pasos", "steps"), "tokens", "USD")}`);
    const orden = [...Object.keys(ESTADOS), "orquestador"];
    for (const estado of orden) {
      const c = costos.porEstado.get(estado);
      if (!c) continue;
      const nombre = estado === "orquestador" ? t("orquestador", "orchestrator") : nombreEstado(estado as EstadoId);
      lineas.push(`${sangria}${fila(nombre, estado === "orquestador" ? "—" : String(c.tramos), String(c.pasos), ktok(c.tokens), plata(c.pico))}`);
    }
    if (!costos.porEstado.size) lineas.push(`${sangria}${t("todavía no hubo pasos", "no steps yet")}`);
    lineas.push(`${sangria}${fila(t("total", "total"), String(costos.total.tramos), String(costos.total.pasos), ktok(costos.total.tokens), plata(costos.total.pico))}`);
    const barra = (nivel: number) => `${"■".repeat(nivel)}${"□".repeat(3 - nivel)}`;
    if (p.hipotesis.length) {
      lineas.push(`${col(t("Hipótesis", "Hypotheses"))}${t("id   nivel    prior.  título", "id   level    prio.   title")}`);
      for (const h of porPrioridad(p.hipotesis)) lineas.push(`${sangria}${ajustar(h.id, 5)}${barra(h.nivel)} ${h.nivel}/3  ${ajustar(t(h.prioridad, { alta: "high", media: "medium", baja: "low" }[h.prioridad]), 7)} ${ajustar(h.titulo, 36).trimEnd()}`);
    } else lineas.push(`${col(t("Hipótesis", "Hypotheses"))}${t("todavía ninguna", "none yet")}`);
    const evidencia = porPrioridad(p.hipotesis).flatMap((h) => ([1, 2, 3] as const).filter((nivel) => h.pocs[nivel]).map((nivel) => {
      const finding = h.hallazgo ? this.engine.findings.get(h.hallazgo) : undefined;
      return `${h.id} n${nivel} PoC ${corto8(h.pocs[nivel]!)}${finding ? ` · ${t("hallazgo", "finding")} ${finding.id.slice(0, 8)} ${finding.state}` : ""}`;
    }));
    const sinDisparar = p.ejecuciones.filter((item) => !item.dispara).length;
    if (evidencia.length) evidencia.forEach((linea, index) => lineas.push(`${index ? sangria : col(t("Evidencia", "Evidence"))}${ajustar(linea, 60).trimEnd()}`));
    else lineas.push(`${col(t("Evidencia", "Evidence"))}${t("ninguna ejecutable todavía", "no executable evidence yet")}${sinDisparar ? t(` · ${sinDisparar} corrida(s) sin disparar`, ` · ${sinDisparar} run(s) did not trigger`) : ""}`);
    if (p.reporte) lineas.push(`${col(t("Informe", "Report"))}${p.reporte.slice(0, 19)}… (/evidencia ${corto8(p.reporte)})`);
    lineas.push(`${col(t("Diario", "Journal"))}${diario.vista}`);
    lineas.push(uso);
    return lineas;
  }
}

/** Una hipótesis puede ir a un harness si ya tiene el nivel que pide y no agotó sus intentos ahí. */
function elegible(def: DefinicionEstado, h: HipotesisPlegada, p: Plegado): boolean {
  if (!def.harness) return false;
  return h.nivel === def.harness.requiere && (p.intentos[clave(def.id, h.id)] ?? 0) < def.tope.intentos;
}

const nombreNivel = (nivel: 1 | 2 | 3) => ({ 1: "función", 2: "componentes", 3: "punta a punta" })[nivel];
const limites = (nivel: 1 | 2 | 3) => (nivel === 3 ? "Demostrado punta a punta en el laboratorio." : `Demostrado hasta el nivel ${nivel} (${nombreNivel(nivel)}); falta ${nivel === 1 ? "mostrar que se alcanza desde el componente y punta a punta" : "reproducirlo punta a punta"}.`);

function faseNombre(fase: Plegado["fase"] | "interrumpida"): string {
  return { corriendo: t("corriendo", "running"), pausada: t("pausada", "paused"), tope: t("en su tope", "at its cap"), cerrada: t("cerrada", "closed"), interrumpida: t("interrumpida", "interrupted") }[fase];
}

/** «12», «12.5», «12,5», «usd 12», «$12», «12usd» → «12.5»; otra cosa, nada. */
export function leerMonto(texto: string): string | undefined {
  const match = /^(?:usd\s*|\$\s*)?(\d+(?:[.,]\d{1,2})?)\s*(?:usd)?$/i.exec(texto.trim());
  if (!match) return undefined;
  const valor = match[1]!.replace(",", ".");
  return Number(valor) > 0 ? valor : undefined;
}

/** «<objetivo> [usd]»: el último término es el tope si es un monto. */
export function leerPedido(texto: string): { objetivo: string; presupuesto?: string } {
  const palabras = texto.trim().split(/\s+/);
  for (const corte of [2, 1]) {
    if (palabras.length <= corte) continue;
    const monto = leerMonto(palabras.slice(-corte).join(" "));
    if (monto) return { objetivo: palabras.slice(0, -corte).join(" "), presupuesto: monto };
  }
  return { objetivo: texto.trim() };
}

export type { Asiento };
