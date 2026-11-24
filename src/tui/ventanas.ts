// Geometría de las ventanas en paralelo y el arreglo que se recuerda: funciones puras, sin terminal.
import { chat, validarPestanas, type Pestana } from "./pestanas.ts";

export type Forma = "una" | "lado" | "lateral" | "tres" | "cuatro";
export const FORMAS: readonly Forma[] = ["una", "lado", "lateral", "tres", "cuatro"];
const CANTIDAD: Record<Forma, number> = { una: 1, lado: 2, lateral: 2, tres: 3, cuatro: 4 };
export const cantidad = (forma: Forma): number => CANTIDAD[forma];

export interface Rect { x: number; y: number; ancho: number; alto: number }
export interface Divisores { x?: number; y?: number }

export const MIN_ANCHO = 40;
export const MIN_ALTO = 8;
export const ANCHO_LISTA = 24;

const POR_DEFECTO: Record<Forma, { x: number; y: number }> = {
  una: { x: 0.5, y: 0.5 }, lado: { x: 0.5, y: 0.5 }, lateral: { x: 0.67, y: 0.5 }, tres: { x: 0.5, y: 0.5 }, cuatro: { x: 0.5, y: 0.5 },
};
/** A qué forma baja cuando no entra. */
const MENOR: Record<Forma, Forma> = { una: "una", lado: "una", lateral: "una", tres: "lado", cuatro: "lado" };

const entra = (forma: Forma, ancho: number, alto: number) =>
  ancho >= MIN_ANCHO && (forma === "una" || (ancho >= 2 * MIN_ANCHO && (forma === "lado" || forma === "lateral" || alto >= 2 * MIN_ALTO)));

const acotar = (valor: number, minimo: number, maximo: number) => Math.max(minimo, Math.min(maximo, valor));

/** Reparte el área entre las ventanas (sin superponerse, cubriéndola toda). Las que no entran quedan en undefined. */
export function repartir(forma: Forma, area: Rect, divisores: Divisores, lista: boolean, activa: number): { lista?: Rect; ventanas: Array<Rect | undefined>; ocultas: number; forma: Forma } {
  const total = cantidad(forma);
  // Primero se esconde la lista; después se degrada la forma hasta que entra.
  const conLista = lista && entra(forma, area.ancho - ANCHO_LISTA, area.alto);
  const resto: Rect = conLista ? { ...area, x: area.x + ANCHO_LISTA, ancho: area.ancho - ANCHO_LISTA } : area;
  let usada = forma;
  while (usada !== "una" && !entra(usada, resto.ancho, resto.alto)) usada = MENOR[usada];

  const ventanas: Array<Rect | undefined> = Array.from({ length: total });
  let primeras = [0, 1, 2, 3].slice(0, total);
  if (usada !== forma) primeras = usada === "una" ? [activa] : [...new Set([activa, (activa + 1) % total])].sort((a, b) => a - b);
  const por = POR_DEFECTO[usada];
  const izq = usada === "una" ? resto.ancho : acotar(Math.round(resto.ancho * (divisores.x ?? por.x)), MIN_ANCHO, resto.ancho - MIN_ANCHO);
  const arriba = acotar(Math.round(resto.alto * (divisores.y ?? por.y)), MIN_ALTO, resto.alto - MIN_ALTO);
  const col = (x: number, ancho: number, y = resto.y, alto = resto.alto): Rect => ({ x, y, ancho, alto });
  const xd = resto.x + izq;
  const anchoD = resto.ancho - izq;
  let rects: Rect[];
  if (usada === "una") rects = [col(resto.x, resto.ancho)];
  else if (usada === "lado" || usada === "lateral") rects = [col(resto.x, izq), col(xd, anchoD)];
  else if (usada === "tres") rects = [col(resto.x, izq), col(xd, anchoD, resto.y, arriba), col(xd, anchoD, resto.y + arriba, resto.alto - arriba)];
  else rects = [col(resto.x, izq, resto.y, arriba), col(xd, anchoD, resto.y, arriba), col(resto.x, izq, resto.y + arriba, resto.alto - arriba), col(xd, anchoD, resto.y + arriba, resto.alto - arriba)];
  primeras.forEach((indice, k) => { ventanas[indice] = rects[k]; });
  return { ...(conLista ? { lista: { ...area, ancho: ANCHO_LISTA } } : {}), ventanas, ocultas: total - primeras.length, forma: usada };
}

/** Lo que se recuerda (para todos los proyectos): forma, pestañas de cada ventana, divisores y si se ve la lista. */
export interface Arreglo { forma: Forma; pestanas: Pestana[][]; divisores: Divisores; lista: boolean }

const divisor = (v: unknown): number | undefined => (typeof v === "number" && v > 0.1 && v < 0.9 ? v : undefined);

/** Arreglo válido: descarta lo inválido; sin valor, las pestañas previas son la única ventana. */
export function validarArreglo(valor: unknown, previas: Pestana[]): Arreglo {
  if (!valor || typeof valor !== "object" || Array.isArray(valor)) return { forma: "una", pestanas: [previas], divisores: {}, lista: false };
  const v = valor as Record<string, unknown>;
  const forma = FORMAS.find((f) => f === v.forma) ?? "una";
  const listas = Array.isArray(v.pestanas) ? v.pestanas : [];
  const pestanas = Array.from({ length: cantidad(forma) }, (_, i) => (listas[i] === undefined ? [chat()] : validarPestanas(listas[i])));
  const d = v.divisores && typeof v.divisores === "object" ? (v.divisores as Record<string, unknown>) : {};
  const [x, y] = [divisor(d.x), divisor(d.y)];
  return { forma, pestanas, divisores: { ...(x !== undefined ? { x } : {}), ...(y !== undefined ? { y } : {}) }, lista: v.lista === true };
}
