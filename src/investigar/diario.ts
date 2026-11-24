// Diario de una investigación: append-only, en la carpeta de datos del proyecto. Cada asiento es una línea
// JSON en diario.jsonl (la fuente de verdad) y una línea legible en diario.md (para el operador). Nada se
// reescribe: el estado de la investigación (en qué estado va, qué hipótesis hay y a qué nivel llegó cada
// una, qué evidencia la respalda, qué intentos fallaron) se reconstruye plegando los asientos. Por eso es
// retomable: si el proceso se corta, el próximo arranque lee el diario y sigue desde ahí.
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { EstadoId, Salida } from "./estados.ts";
import { ESTADOS } from "./estados.ts";

export type Prioridad = "alta" | "media" | "baja";
export type Resultado = "cumplido" | "fallido" | "cortado";
export type Fase = "corriendo" | "pausada" | "tope" | "cerrada";

/** Un asiento del diario. `n` y `at` los pone el diario al anotarlo. */
export type Asiento = { n: number; at: string } & (
  | { tipo: "inicio"; id: string; objetivo: string; presupuesto: string; sesion: string; por: "operador" | "agente"; pedido?: string }
  /** Cambios de fase: pausa, seguir (con presupuesto nuevo, si lo dio), cierre del operador, tope de USD, fin (no hay más movidas). */
  | { tipo: "control"; accion: "pausa" | "seguir" | "cierre" | "tope" | "fin"; motivo?: string; presupuesto?: string; sesion?: string }
  | { tipo: "orquestador"; estado: EstadoId; hipotesis?: string; opciones: string[]; por: "modelo" | "regla"; motivo: string }
  | { tipo: "estado.inicio"; tramo: number; estado: EstadoId; hipotesis?: string; intento: number; modelo: string; worker: string }
  | { tipo: "artefacto"; tramo: number; estado: EstadoId; clase: "mapa" | "reporte" | "poc" | "corrida" | "transcripcion"; hash: string; nota?: string }
  | { tipo: "hipotesis"; tramo: number; id: string; titulo: string; clase: string; activo: string; porque: string; evidencia: string; prioridad: Prioridad }
  /** Una corrida en limpio del PoC de un harness: si disparó de forma determinista, la hipótesis sube a `nivel`. */
  | { tipo: "ejecucion"; tramo: number; hipotesis: string; nivel: 1 | 2 | 3; dispara: boolean; poc?: string; comando?: string; corridas: string; motivo: string; salida?: string; hallazgo?: string }
  | { tipo: "estado.fin"; tramo: number; estado: EstadoId; hipotesis?: string; resultado: Resultado; motivo: string; salida?: Salida; pasos: number; usd: string }
);

/** Lo que se le pasa a `anotar`: un asiento sin `n` ni `at`. */
export type NuevoAsiento = Asiento extends infer A ? (A extends Asiento ? Omit<A, "n" | "at"> : never) : never;

export class Diario {
  readonly dir: string;
  readonly archivo: string;
  readonly vista: string;
  /** Último número anotado; se lee del archivo recién al anotar (listar diarios no los lee). */
  private n?: number;

  constructor(dir: string) {
    this.dir = dir;
    this.archivo = join(dir, "diario.jsonl");
    this.vista = join(dir, "diario.md");
  }

  /** Tamaño del archivo: cambia con cada asiento (sirve de firma para no releer lo que no cambió). */
  tamano(): number {
    try { return statSync(this.archivo).size; } catch { return 0; }
  }

  /** Asientos en orden. Una última línea a medio escribir (el proceso murió escribiéndola) se ignora. */
  leer(): Asiento[] {
    if (!existsSync(this.archivo)) return [];
    const out: Asiento[] = [];
    for (const line of readFileSync(this.archivo, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try { out.push(JSON.parse(line) as Asiento); } catch { /* línea cortada por una caída: no cuenta */ }
    }
    return out;
  }

  anotar(nuevo: NuevoAsiento): Asiento {
    mkdirSync(this.dir, { recursive: true });
    this.n ??= this.leer().reduce((max, asiento) => Math.max(max, asiento.n), 0);
    const asiento = { n: ++this.n, at: new Date().toISOString(), ...nuevo } as Asiento;
    appendFileSync(this.archivo, `${JSON.stringify(asiento)}\n`);
    if (asiento.tipo === "inicio") appendFileSync(this.vista, `# Investigación ${asiento.id.slice(0, 8)}\n\n`);
    appendFileSync(this.vista, `${legible(asiento)}\n`);
    return asiento;
  }
}

/** Investigaciones guardadas del proyecto: una carpeta por investigación, con su diario. */
export function diariosDe(base: string): Diario[] {
  if (!existsSync(base)) return [];
  return readdirSync(base, { withFileTypes: true }).filter((entry) => entry.isDirectory() && existsSync(join(base, entry.name, "diario.jsonl"))).map((entry) => new Diario(join(base, entry.name)));
}

const hora = (at: string) => new Date(at).toTimeString().slice(0, 5);
const nombre = (estado: EstadoId) => ESTADOS[estado].nombre.es;

/** Una línea del diario para leer: hora, estado y qué pasó. */
export function legible(a: Asiento): string {
  const h = (id?: string) => (id ? ` ${id}` : "");
  switch (a.tipo) {
    case "inicio": return `- ${hora(a.at)} · empieza: «${a.objetivo}» · tope USD ${a.presupuesto} · sesión ${a.sesion.slice(0, 8)} · pedida por ${a.por}${a.pedido ? ` («${a.pedido}»)` : ""}`;
    case "control": return `- ${hora(a.at)} · ${a.accion}${a.presupuesto ? ` · tope USD ${a.presupuesto}` : ""}${a.motivo ? `: ${a.motivo}` : ""}`;
    case "orquestador": return `- ${hora(a.at)} · orquestador (${a.por}) → ${nombre(a.estado)}${h(a.hipotesis)}: ${a.motivo}`;
    case "estado.inicio": return `- ${hora(a.at)} · ${nombre(a.estado)}${h(a.hipotesis)} · tramo ${a.tramo}, intento ${a.intento}, ${a.modelo}`;
    case "artefacto": return `- ${hora(a.at)} · ${nombre(a.estado)} · ${a.clase} ${a.hash}${a.nota ? ` (${a.nota})` : ""}`;
    case "hipotesis": return `- ${hora(a.at)} · hipótesis ${a.id} [${a.prioridad}] ${a.titulo} — ${a.activo} · ${a.porque} (evidencia: ${a.evidencia})`;
    case "ejecucion": return `- ${hora(a.at)} · ${a.hipotesis} nivel ${a.nivel}: ${a.dispara ? "dispara" : "no dispara"} (${a.corridas}) · ${a.motivo}${a.poc ? ` · PoC ${a.poc}` : ""}${a.hallazgo ? ` · hallazgo ${a.hallazgo.slice(0, 8)}` : ""}`;
    case "estado.fin": return `- ${hora(a.at)} · ${nombre(a.estado)}${h(a.hipotesis)} · ${a.resultado}: ${a.motivo} · ${a.pasos} pasos, USD ${a.usd}`;
  }
}

/* ---------- Plegado: el estado de la investigación, sólo desde el diario ---------- */

export interface HipotesisPlegada {
  id: string;
  titulo: string;
  clase: string;
  activo: string;
  porque: string;
  evidencia: string;
  prioridad: Prioridad;
  /** Nivel alcanzado con evidencia ejecutable reproducida en limpio: 0 = sólo estática. */
  nivel: 0 | 1 | 2 | 3;
  /** PoC (hash del artefacto) que respalda cada nivel alcanzado. */
  pocs: Partial<Record<1 | 2 | 3, string>>;
  comandos: Partial<Record<1 | 2 | 3, string>>;
  hallazgo?: string;
}

export interface Plegado {
  id: string;
  objetivo: string;
  presupuesto: string;
  sesion: string;
  inicio: string;
  fase: Fase;
  mapa?: string;
  reporte?: string;
  hipotesis: HipotesisPlegada[];
  /** Intentos terminados (cumplidos o fallidos) por estado y, si corresponde, hipótesis: «harness-1:h3». */
  intentos: Record<string, number>;
  /** Motivos de los intentos fallidos, por la misma clave: el próximo tramo los ve. */
  fallas: Record<string, string[]>;
  /** El último tramo terminado. */
  ultimo?: { estado: EstadoId; hipotesis?: string; resultado: Resultado; motivo: string; tramo: number };
  /** Un tramo empezado y sin fin: el proceso murió en el medio; se retoma. */
  abierto?: { estado: EstadoId; hipotesis?: string; tramo: number; intento: number };
  /** Un tramo cortado (pausa o cierre del motor): se retoma antes que cualquier otra movida. */
  pendiente?: { estado: EstadoId; hipotesis?: string };
  /** Lo que el orquestador eligió último (lo que está corriendo o va a correr). */
  elegido?: { estado: EstadoId; hipotesis?: string };
  tramos: number;
  ejecuciones: Array<Extract<Asiento, { tipo: "ejecucion" }>>;
}

export const clave = (estado: EstadoId, hipotesis?: string) => (hipotesis ? `${estado}:${hipotesis}` : estado);

/** El estado de la investigación a partir de sus asientos. Sin asiento de inicio no hay investigación. */
export function plegar(asientos: Asiento[]): Plegado | undefined {
  const inicio = asientos.find((a): a is Extract<Asiento, { tipo: "inicio" }> => a.tipo === "inicio");
  if (!inicio) return undefined;
  const p: Plegado = { id: inicio.id, objetivo: inicio.objetivo, presupuesto: inicio.presupuesto, sesion: inicio.sesion, inicio: inicio.at, fase: "corriendo", hipotesis: [], intentos: {}, fallas: {}, tramos: 0, ejecuciones: [] };
  for (const a of asientos) {
    switch (a.tipo) {
      case "control":
        if (a.presupuesto) p.presupuesto = a.presupuesto;
        if (a.sesion) p.sesion = a.sesion;
        p.fase = a.accion === "pausa" ? "pausada" : a.accion === "tope" ? "tope" : a.accion === "cierre" || a.accion === "fin" ? "cerrada" : "corriendo";
        break;
      case "orquestador":
        p.elegido = { estado: a.estado, ...(a.hipotesis ? { hipotesis: a.hipotesis } : {}) };
        break;
      case "estado.inicio":
        p.tramos = Math.max(p.tramos, a.tramo);
        p.abierto = { estado: a.estado, ...(a.hipotesis ? { hipotesis: a.hipotesis } : {}), tramo: a.tramo, intento: a.intento };
        break;
      case "artefacto":
        if (a.clase === "mapa") p.mapa = a.hash;
        if (a.clase === "reporte") p.reporte = a.hash;
        break;
      case "hipotesis":
        if (!p.hipotesis.some((h) => h.id === a.id)) p.hipotesis.push({ id: a.id, titulo: a.titulo, clase: a.clase, activo: a.activo, porque: a.porque, evidencia: a.evidencia, prioridad: a.prioridad, nivel: 0, pocs: {}, comandos: {} });
        break;
      case "ejecucion": {
        p.ejecuciones.push(a);
        const h = p.hipotesis.find((item) => item.id === a.hipotesis);
        if (h && a.hallazgo) h.hallazgo = a.hallazgo;
        // Sube de nivel sólo con evidencia ejecutable del nivel anterior (o ninguna, para el primero).
        if (h && a.dispara && a.poc && a.nivel === h.nivel + 1) {
          h.nivel = a.nivel;
          h.pocs[a.nivel] = a.poc;
          if (a.comando) h.comandos[a.nivel] = a.comando;
        }
        break;
      }
      case "estado.fin": {
        if (p.abierto?.tramo === a.tramo) p.abierto = undefined;
        if (a.resultado === "cortado") {
          p.pendiente = { estado: a.estado, ...(a.hipotesis ? { hipotesis: a.hipotesis } : {}) };
          break;
        }
        p.pendiente = undefined;
        const k = clave(a.estado, a.hipotesis);
        p.intentos[k] = (p.intentos[k] ?? 0) + 1;
        if (a.resultado === "fallido") (p.fallas[k] ??= []).push(a.motivo);
        p.ultimo = { estado: a.estado, ...(a.hipotesis ? { hipotesis: a.hipotesis } : {}), resultado: a.resultado, motivo: a.motivo, tramo: a.tramo };
        break;
      }
    }
  }
  return p;
}

const ORDEN_PRIORIDAD: Record<Prioridad, number> = { alta: 0, media: 1, baja: 2 };
/** Hipótesis por prioridad y, a igual prioridad, en el orden en que se propusieron. */
export const porPrioridad = (hipotesis: HipotesisPlegada[]) => [...hipotesis].sort((a, b) => ORDEN_PRIORIDAD[a.prioridad] - ORDEN_PRIORIDAD[b.prioridad] || hipotesis.indexOf(a) - hipotesis.indexOf(b));

/**
 * Resumen para el orquestador: SÓLO lo estructurado del diario (estados, intentos, niveles, ids de
 * evidencia, costo). Ni el mapa, ni el texto de los tramos, ni código del repositorio: el orquestador
 * decide sin leer el objetivo.
 */
export function resumenDiario(p: Plegado, gastado: string): string {
  const hechos = Object.entries(p.intentos).map(([k, n]) => `${k} ×${n}${p.fallas[k]?.length ? ` (fallas: ${p.fallas[k]!.length})` : ""}`);
  const hipotesis = porPrioridad(p.hipotesis).map((h) => {
    const k = `harness-${Math.min(3, h.nivel + 1)}:${h.id}`;
    return `${h.id} · ${h.prioridad} · nivel ${h.nivel}${h.nivel ? ` (PoC ${Object.values(h.pocs).map((hash) => hash!.slice(0, 15)).join(", ")})` : ""}${p.intentos[k] ? ` · ${p.intentos[k]} intento(s) en ${k.split(":")[0]}` : ""} · «${h.titulo.slice(0, 80)}»`;
  });
  return [
    `OBJETIVO: ${p.objetivo.slice(0, 300)}`,
    `PRESUPUESTO: gastado USD ${gastado} de ${p.presupuesto}`,
    `MAPA: ${p.mapa ? p.mapa.slice(0, 15) : "todavía no"} · REPORTE: ${p.reporte ? p.reporte.slice(0, 15) : "todavía no"}`,
    `ESTADOS HECHOS: ${hechos.join("; ") || "ninguno"}`,
    `HIPÓTESIS (id · prioridad · nivel ejecutable): ${hipotesis.length ? `\n${hipotesis.join("\n")}` : "ninguna todavía"}`,
    `ÚLTIMO: ${p.ultimo ? `${p.ultimo.estado}${p.ultimo.hipotesis ? ` ${p.ultimo.hipotesis}` : ""} → ${p.ultimo.resultado}` : "nada todavía"}`,
  ].join("\n");
}
