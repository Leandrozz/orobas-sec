// Recorte al entrar. Lo que una herramienta devuelve viaja al modelo en cada paso hasta la próxima compactación,
// desde la caché del proveedor: lo que nunca entra no se relee nunca. Una salida que pasa el tope de su
// herramienta entra como cabeza + cola + los tramos del medio que coinciden con lo que se buscó (o con señales
// como errores, credenciales y códigos HTTP), y el original queda entero en un artefacto que el modelo relee
// con artifact_read. Es determinista y ocurre antes de que el mensaje exista: no toca el prefijo cacheado.
//
// Los topes salen de las trazas (scripts/simular-fase3.py y docs/costos-contexto.md): por herramienta, lo que
// se dejaba de releer contra las citas posteriores que quedaban fuera de vista. scripts/repeticion_contexto.py
// replica este algoritmo; test/fixtures/recorte-casos.json ata las dos implementaciones.

/** Tope en caracteres por herramienta. Las que no están entran enteras (hasta el corte general de 8.000). */
export const TOPES_POR_HERRAMIENTA: Readonly<Record<string, number>> = {
  shell: 3000,
  artifact_read: 3000,
  code_read: 3000,
  http_probe: 1500,
  memory_search: 1500,
};

/** Las líneas largas (JavaScript minificado, JSON de una línea) se parten en trozos de este tamaño. */
const TROZO = 400;
/** Señales que valen la pena aunque no se hayan buscado. */
const RELEVANTE = new RegExp(
  "error|exception|traceback|denied|forbidden|unauthori[sz]ed|invalid|fail|warn|secret|passw|token|api[_-]?key|" +
    "bearer|cookie|session|admin|root:|flag\\{|sha256:[0-9a-f]{8}|\\bh\\d+\\b|HTTP/\\d|location:|vuln|cve-\\d|inject|" +
    "\\b(?:200|201|204|301|302|400|401|403|404|405|409|422|500|502|503)\\b",
  "i",
);
const PALABRA = /[A-Za-z0-9_][A-Za-z0-9_.\-/]{3,}/g;
const VACIAS = new Set(["http", "https", "true", "false", "null", "none", "curl", "grep", "echo", "head", "tail", "with", "from", "this", "that", "para", "como", "desde", "json", "text", "html", "www.", "-sS", "--silent"]);

/** Palabras de los argumentos de la llamada (patrones, rutas, parámetros): eligen qué líneas del medio quedan. */
export function terminos(argumentos: unknown): string[] {
  const cadenas: string[] = [];
  const juntar = (valor: unknown): void => {
    if (typeof valor === "string") cadenas.push(valor);
    else if (Array.isArray(valor)) valor.forEach(juntar);
    else if (valor && typeof valor === "object") Object.values(valor).forEach(juntar);
  };
  juntar(argumentos);
  const salida: string[] = [];
  for (const cadena of cadenas) {
    for (const match of cadena.matchAll(PALABRA)) {
      const palabra = match[0].replace(/^[./-]+|[./-]+$/g, "").toLowerCase();
      if (palabra.length >= 4 && !VACIAS.has(palabra) && !salida.includes(palabra)) salida.push(palabra);
      if (salida.length >= 12) return salida;
    }
  }
  return salida;
}

/** [posición, texto, ¿empieza a mitad de línea?, ¿termina a mitad de línea?] */
type Trozo = [number, string, boolean, boolean];

function trozos(texto: string): Trozo[] {
  const salida: Trozo[] = [];
  let pos = 0;
  for (const linea of texto.split("\n")) {
    if (linea.length <= TROZO) salida.push([pos, linea, false, false]);
    else for (let k = 0; k < linea.length; k += TROZO) salida.push([pos + k, linea.slice(k, k + TROZO), k > 0, k + TROZO < linea.length]);
    pos += linea.length + 1;
  }
  return salida;
}

/** Opciones del recorte. */
export interface OpcionesRecorte {
  /**
   * Cada corte a mitad de línea lleva «…» (fin de un trozo, comienzo del siguiente, tramo del medio cortado a 240).
   * Lo usa el motor con secretos (#39): los recortes del harness terminan en «…» y así las trazas reconocen y tapan
   * un secreto del objetivo que quedó partido. Sin esto, el formato es el que replica el simulador.
   */
  marcarCortes?: boolean;
}

/**
 * Cabeza (la mitad del tope) + tramos del medio con coincidencias (un 30 %, cada uno con su posición «@n» para
 * releerlo con artifact_read at) + cola (un 20 %) + el puntero al original. Undefined si el texto entra entero.
 */
export function recortarSalida(texto: string, tope: number, palabras: string[], puntero: string, opciones: OpcionesRecorte = {}): string | undefined {
  if (texto.length <= tope) return undefined;
  const partes = trozos(texto);
  const cab = Math.floor((tope * 5) / 10);
  const col = Math.floor((tope * 2) / 10);
  const med = tope - cab - col;
  let i = 0;
  let usado = 0;
  while (i < partes.length && usado + partes[i]![1].length + 1 <= cab) {
    usado += partes[i]![1].length + 1;
    i++;
  }
  let j = partes.length;
  usado = 0;
  while (j - 1 >= i && usado + partes[j - 1]![1].length + 1 <= col) {
    j--;
    usado += partes[j]![1].length + 1;
  }
  const marcar = opciones.marcarCortes === true;
  // Las marcas no cuentan para los topes: así eligen lo mismo que sin ellas (el simulador no las tiene).
  const entero = ([, linea, empieza, termina]: Trozo) => (marcar ? `${empieza ? "…" : ""}${linea}${termina ? "…" : ""}` : linea);
  const elegidos: string[] = [];
  usado = 0;
  for (const [pos, linea, empieza, termina] of partes.slice(i, j)) {
    const bajo = linea.toLowerCase();
    if (RELEVANTE.test(linea) || palabras.some((palabra) => bajo.includes(palabra))) {
      const renglon = `@${pos}: ${linea.slice(0, 240).trim()}`;
      if (usado + renglon.length + 1 > med) break;
      elegidos.push(marcar ? `@${pos}: ${empieza ? "…" : ""}${linea.slice(0, 240).trim()}${linea.length > 240 || termina ? "…" : ""}` : renglon);
      usado += renglon.length + 1;
    }
  }
  const desde = i < partes.length ? partes[i]![0] : texto.length;
  const hasta = j < partes.length ? partes[j]![0] : texto.length;
  return [
    ...partes.slice(0, i).map(entero),
    `[… ${hasta - desde} caracteres fuera de vista (@${desde} a @${hasta}); abajo, ${elegidos.length} tramos con coincidencias …]`,
    ...elegidos,
    ...(elegidos.length ? ["[…]"] : []),
    ...partes.slice(j).map(entero),
    `[Recortado al entrar: ${texto.length} caracteres en total. Completa en ${puntero}: el resto con artifact_read usando search, filter, o at con chars de 2000 o menos.]`,
  ].join("\n");
}

/** Recorte apagado con CYBER_RECORTE=no (para comparar en vivo con la conducta anterior). */
export const recorteApagado = (): boolean => /^(no|0|false|off)$/i.test(process.env.CYBER_RECORTE ?? "");

/**
 * El resultado de una herramienta, recortado si pasa su tope: el original va a `guardar` (un artefacto) y el
 * modelo recibe la vista recortada con el puntero. Undefined si no hay que recortar. `vista` transforma el texto
 * antes de cortarlo (para tapar secretos enteros antes de que un corte los parta); por defecto, ninguna. Con
 * vista, además, los cortes a mitad de línea llevan «…» (ver OpcionesRecorte.marcarCortes).
 */
export function recortarAlEntrar(
  herramienta: string,
  argumentos: unknown,
  resultado: { text: string; isError?: boolean; details?: Record<string, unknown> },
  guardar: (texto: string) => string,
  vista?: (texto: string) => string,
): { text: string; isError?: boolean; details?: Record<string, unknown> } | undefined {
  const tope = TOPES_POR_HERRAMIENTA[herramienta];
  if (tope === undefined || recorteApagado() || resultado.text.length <= tope) return undefined;
  // Una salida que la dieta ya resumió no se vuelve a recortar.
  if (resultado.text.startsWith("[resumido para ahorrar contexto]")) return undefined;
  const visible = vista ? vista(resultado.text) : resultado.text;
  if (visible.length <= tope) return undefined;
  const puntero = guardar(resultado.text);
  const texto = recortarSalida(visible, tope, terminos(argumentos), puntero, { marcarCortes: vista !== undefined })!;
  return { ...resultado, text: texto, details: { ...resultado.details, recortado: puntero, caracteres: resultado.text.length } };
}
