import { ADORNO_ABRE, ADORNO_CIERRA, CORTE_ESPACIO, CORTE_PEGADO, cellWidth, graphemes } from "./text.ts";
// Selección con el mouse: de filas ya dibujadas al texto a copiar, y resaltado de columnas.
export interface Punto { fila: number; col: number }
interface Celda { g: string; col: number; ancho: number; adorno: boolean; i: number; f: number }

const ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/y;

/** Un recorrido por fila: celdas con su columna e índices en el texto, y la marca de corte (antes del primer contenido). */
function recorrer(fila: string): { celdas: Celda[]; corte?: string } {
  const celdas: Celda[] = [];
  let corte: string | undefined;
  let adorno = false;
  let col = 0;
  for (let i = 0; i < fila.length; ) {
    ANSI.lastIndex = i;
    const m = ANSI.exec(fila);
    if (m) {
      if (m[0] === ADORNO_ABRE) adorno = true;
      else if (m[0] === ADORNO_CIERRA) adorno = false;
      else if ((m[0] === CORTE_ESPACIO || m[0] === CORTE_PEGADO) && !corte && !celdas.some((c) => !c.adorno && c.g !== " ")) corte = m[0];
      i += m[0].length;
      continue;
    }
    const g = graphemes(fila.slice(i, i + 16))[0]!;
    const ancho = cellWidth(g);
    if (ancho > 0) celdas.push({ g, col, ancho, adorno, i, f: i + g.length });
    col += ancho;
    i += g.length;
  }
  return { celdas, corte };
}

const enRango = (c: Celda, desde: number, hasta: number): boolean => c.col + c.ancho - 1 >= desde && c.col <= hasta;

/** `enteras`: filas completas (triple clic), siempre con las reglas de varias filas. */
export function textoSeleccionado(filas: readonly string[], a: Punto, b: Punto, enteras = false): string {
  const [p, q] = a.fila < b.fila || (a.fila === b.fila && a.col <= b.col) ? [a, b] : [b, a];
  if (p.fila === q.fila && !enteras) return recorrer(filas[p.fila] ?? "").celdas.filter((c) => enRango(c, p.col, q.col)).map((c) => c.g).join("").trimEnd();
  const lineas: { t: string; ind: number }[] = [];
  for (let n = p.fila; n <= q.fila; n++) {
    const { celdas, corte } = recorrer(filas[n] ?? "");
    const sel = celdas.filter((c) => enRango(c, n === p.fila ? p.col : 0, n === q.fila ? q.col : Infinity));
    const util = sel.filter((c) => c.g !== " ");
    // Fila en blanco dentro de un panel (sólo sus dos bordes «│»): queda como línea vacía; el resto de los adornos se omite.
    if (util.length && util.every((c) => c.adorno)) {
      if (util.length >= 2 && util.every((c) => c.g === "│")) lineas.push({ t: "", ind: Infinity });
      continue;
    }
    // La sangría se mide sobre la fila entera: un arrastre que empieza a mitad de fila no cambia el margen común.
    const ind = celdas.filter((c) => !c.adorno).findIndex((c) => c.g !== " ");
    const texto = sel.filter((c) => !c.adorno).map((c) => c.g).join("").trimEnd();
    const prev = lineas[lineas.length - 1];
    if (corte && prev) {
      prev.t += (corte === CORTE_ESPACIO ? " " : "") + texto.trimStart();
      prev.ind = Math.min(prev.ind, ind < 0 ? Infinity : ind);
      continue;
    }
    lineas.push({ t: texto, ind: texto && ind >= 0 ? ind : Infinity });
  }
  while (lineas.length && !lineas[0]!.t) lineas.shift();
  while (lineas.length && !lineas[lineas.length - 1]!.t) lineas.pop();
  const sangria = Math.min(...lineas.map((l) => l.ind));
  return lineas.map((l) => l.t.slice(Math.min(sangria, l.t.length - l.t.trimStart().length))).join("\n");
}

const util = (cs: Celda[]) => cs.filter((c) => !c.adorno && c.g !== " ");

/** Palabra bajo `col` en la fila `n`; si está partida con CORTE_PEGADO se extiende a las filas vecinas. */
export function palabraEn(filas: readonly string[], n: number, col: number): [Punto, Punto] | undefined {
  const { celdas } = recorrer(filas[n]!);
  let k = celdas.findIndex((c) => enRango(c, col, col));
  if (k < 0 || celdas[k]!.g === " ") return undefined;
  let i = k;
  while (i > 0 && celdas[i - 1]!.g !== " ") i--;
  while (k < celdas.length - 1 && celdas[k + 1]!.g !== " ") k++;
  let [f0, z] = [n, n];
  let cs = celdas;
  let [i0, k0] = [i, k];
  while (f0 > 0 && recorrer(filas[f0]!).corte === CORTE_PEGADO && util(cs)[0] === cs[i0]) {
    const prev = recorrer(filas[f0 - 1]!).celdas;
    const u = util(prev);
    if (!u.length) break;
    let j = prev.indexOf(u[u.length - 1]!);
    while (j > 0 && prev[j - 1]!.g !== " ") j--;
    [f0, cs, i0] = [f0 - 1, prev, j];
  }
  const ini = { fila: f0, col: cs[i0]!.col };
  cs = celdas;
  while (z + 1 < filas.length && recorrer(filas[z + 1]!).corte === CORTE_PEGADO && util(cs).at(-1) === cs[k0]) {
    const sig = recorrer(filas[z + 1]!).celdas;
    const u = util(sig);
    if (!u.length) break;
    let e = sig.indexOf(u[0]!);
    while (e + 1 < sig.length && sig[e + 1]!.g !== " ") e++;
    [z, cs, k0] = [z + 1, sig, e];
  }
  return [ini, { fila: z, col: cs[k0]!.col + cs[k0]!.ancho - 1 }];
}

export function lineaLogica(filas: readonly string[], i: number): [primera: number, ultima: number] {
  let a = i;
  let z = i;
  while (a > 0 && recorrer(filas[a]!).corte) a--;
  while (z + 1 < filas.length && recorrer(filas[z + 1]!).corte) z++;
  return [a, z];
}

export function resaltar(fila: string, desde: number, hasta: number): string {
  const dentro = recorrer(fila).celdas.filter((c) => enRango(c, desde, hasta));
  if (!dentro.length) return fila;
  const ini = dentro[0]!.i;
  const fin = dentro[dentro.length - 1]!.f;
  // Un reset dentro del rango apagaría la inversa: se repone tras cada SGR que lo contenga.
  const medio = fila.slice(ini, fin).replace(/\x1b\[([0-9;]*)m/g, (sgr, p: string) => (p.split(";").some((x) => x === "" || x === "0" || x === "27") ? sgr + "\x1b[7m" : sgr));
  return fila.slice(0, ini) + "\x1b[7m" + medio + "\x1b[27m" + fila.slice(fin);
}
