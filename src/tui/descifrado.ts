// Efecto descifrado: las letras recién llegadas se ven como glifos un instante. Reemplaza letra→letra y dígito→dígito (ancho 1) para no tocar el formato.
import { descifradoGuardado } from "./ajustes.ts";
import { cellWidth } from "./text.ts";
import type { Intensidad } from "./temas.ts";

export const DURACION: Record<Intensidad, number> = { no: 0, suave: 150, fuerte: 500 };

/** Sólo con la preferencia activa y fuera de conhost y de terminales mudas. */
export const descifradoActivo = (): boolean => descifradoGuardado() && process.env.CYBER_CONSOLE !== "conhost" && process.env.TERM !== "dumb";

/** `llegadas` son pares [desde (índice UTF-16), ms]: cada trozo tiene su reloj y nada tarda más que `DURACION` desde que llegó. */
export function descifrar(markdown: string, llegadas: ReadonlyArray<readonly [number, number]>, ahora: number, intensidad: Intensidad, glifos: string, azar: () => number = Math.random): { texto: string; animando: boolean } {
  const dur = DURACION[intensidad];
  const letras = Array.from(glifos);
  if (!dur || !letras.length || !llegadas.length) return { texto: markdown, animando: false };
  let animando = false;
  let k = 0; // trozo del carácter actual
  let salida = "";
  let pos = 0;
  for (const c of markdown) {
    while (k + 1 < llegadas.length && llegadas[k + 1]![0] <= pos) k++;
    const [desde, ms] = llegadas[k]!;
    if (pos >= desde) {
      const fin = k + 1 < llegadas.length ? llegadas[k + 1]![0] : markdown.length;
      const largo = Math.max(1, fin - desde);
      if (ahora < ms + dur * (0.4 + (0.6 * (pos - desde)) / largo)) {
        animando = true;
        if (/\p{L}/u.test(c) && cellWidth(c) === 1) { salida += letras[Math.floor(azar() * letras.length)]!; pos += c.length; continue; }
        if (/\p{N}/u.test(c) && cellWidth(c) === 1) { salida += String(Math.floor(azar() * 10)); pos += c.length; continue; }
      }
    }
    salida += c;
    pos += c.length;
  }
  return { texto: salida, animando };
}
