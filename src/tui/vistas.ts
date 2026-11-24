// Pestañas de vista del proyecto: qué pide cada una al daemon y cómo se parten sus líneas en filas elegibles.
import { t } from "../idioma.ts";
import { coverageLines } from "./comandos.ts";
import type { Vista } from "./pestanas.ts";
import { badgeWarn, dim, segment, segmentDim } from "./text.ts";

/** `id` es el que se pasa a view() para pedir el detalle. */
export interface Fila { id: string; texto: string }

const filasPor = (re: RegExp) => (lineas: string[]): Fila[] => lineas.flatMap((texto) => { const id = re.exec(texto)?.[1]; return id ? [{ id, texto }] : []; });

export const VISTAS: Record<Vista, { comando: string; titulo: () => string; filas?: (lineas: string[]) => Fila[]; lineas?: (lineas: string[]) => string[] }> = {
  // `${MARK} ${id8}  ${estado} ${severidad} ${título}` (findingsView)
  hallazgos: { comando: "findings", titulo: () => t("hallazgos", "findings"), filas: filasPor(/^\S ([0-9a-f]{8}) {2}\S/) },
  // `${hash12}  ${bytes} B  ${productor}` (evidenceView)
  artefactos: { comando: "evidencia", titulo: () => t("artefactos", "artifacts"), filas: filasPor(/^([0-9a-f]{12}) {2}\s*\d+ B /) },
  cobertura: { comando: "cobertura", titulo: () => t("cobertura", "coverage"), lineas: coverageLines },
  costos: { comando: "costos", titulo: () => t("costos", "costs") },
  trabajos: { comando: "jobs", titulo: () => t("trabajos", "jobs") },
};

export const filasDe = (vista: Vista, lineas: string[]): Fila[] => VISTAS[vista].filas?.(lineas) ?? [];

// Línea de findingsView: `${MARK} ${id8}  ${estado.padEnd(10)} ${severidad.padEnd(11)} ${título}`.
const LINEA_HALLAZGO = /^(\S) ([0-9a-f]{8}) {2}(\S+)\s+(informativa|baja|media|alta|critica)(.*)$/;
const SEVERIDAD = {
  critica: { forma: "◆", palabra: () => t("CRÍTICA", "CRITICAL"), estilo: badgeWarn },
  alta: { forma: "▲", palabra: () => t("ALTA", "HIGH"), estilo: badgeWarn },
  media: { forma: "■", palabra: () => t("MEDIA", "MEDIUM"), estilo: segment },
  baja: { forma: "●", palabra: () => t("BAJA", "LOW"), estilo: segmentDim },
  informativa: { forma: "○", palabra: () => "INFO", estilo: dim },
} as const;

/** Reemplaza la severidad en texto por una etiqueta con forma y palabra, del mismo ancho en ambos idiomas; otras líneas vuelven iguales. */
export function etiquetarHallazgo(linea: string): string {
  const m = LINEA_HALLAZGO.exec(linea);
  if (!m) return linea;
  const sev = SEVERIDAD[m[4] as keyof typeof SEVERIDAD];
  // El daemon rellena la severidad a 11 y deja un espacio; lo que siga es el título tal cual.
  const titulo = m[5]!.replace(new RegExp(`^ {0,${12 - m[4]!.length}}`), "");
  return `${sev.estilo(` ${sev.forma} ${sev.palabra().padEnd(8)} `)} ${m[1]} ${m[2]}  ${m[3]!.padEnd(10)} ${titulo}`;
}
