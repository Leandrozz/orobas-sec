// Las instrucciones del operador no se resumen. La compactación reemplaza lo viejo por un resumen que escribe el
// modelo y conserva literales sólo los 6 mensajes más recientes: en un turno con muchas herramientas, el pedido en
// curso queda afuera a los dos o tres pasos. En las trazas locales, 62 de 79 compactaciones resumieron el pedido
// en curso, las 79 resumieron el encargo inicial, y de 1.285 mensajes del operador compactados sólo 111
// sobrevivían textuales en el checkpoint (el «pierde el hilo» que reportó Nico el 22/11). La dieta no los toca
// (sólo resume salidas de herramientas).
//
// El checkpoint lleva al final, textuales y en orden, todos los mensajes del operador anteriores a lo que se
// conserva: se leen de la base, así una segunda compactación no resume lo que guardó la primera. Un pegado largo
// queda con su comienzo y el puntero al texto entero; si todo no entra, quedan el encargo inicial y los últimos,
// y los del medio, enteros en un artefacto.
import type { DatabaseSync } from "node:sqlite";

/** Más largo que esto (un pegado), el mensaje queda con su comienzo y un puntero al texto entero. */
export const TOPE_MENSAJE = 2000;
/** Tope de la sección entera: ~4.000 tokens que se releen en cada paso hasta la próxima compactación. */
export const TOPE_TOTAL = 12_000;

/** Bloques que el harness agrega al mensaje del operador (alcance, memoria, señuelos, veredictos, CVEs, gasto, avisos). */
const AGREGADO = /\n\n(?=<(?:alcance|senuelos|verificacion|canarios|cves_nuevos|memoria|gasto)>|\[sistema\])/;

/** Lo que escribió el operador en un mensaje de usuario guardado; undefined si el mensaje es del harness. */
export function textoDelOperador(content: string): string | undefined {
  if (content.startsWith("[sistema]")) return undefined;
  const texto = content.split(AGREGADO)[0]!.trim();
  return texto || undefined;
}

/** La sección del checkpoint con los mensajes del operador, textuales y en orden. Vacía si no hay ninguno. */
export function instruccionesDelOperador(textos: string[], guardar: (texto: string) => string): string {
  if (!textos.length) return "";
  const items = textos.map((texto) => (texto.length <= TOPE_MENSAJE ? texto : `${texto.slice(0, TOPE_MENSAJE - 200)}… [${texto.length} caracteres; completo en ${guardar(texto)}]`));
  // El encargo inicial siempre; después, desde el último hacia atrás, lo que entre.
  let usado = items[0]!.length;
  let desde = items.length;
  while (desde > 1 && usado + items[desde - 1]!.length + 8 <= TOPE_TOTAL) usado += items[--desde]!.length + 8;
  const omitidos = textos.slice(1, desde);
  const lineas = [
    `[1] ${items[0]}`,
    ...(omitidos.length ? [`[… ${omitidos.length} mensajes intermedios del operador, completos en ${guardar(omitidos.map((texto, i) => `[${i + 2}] ${texto}`).join("\n\n"))}]`] : []),
    ...items.slice(desde).map((item, i) => `[${desde + i + 1}] ${item}`),
  ];
  return `MENSAJES DEL OPERADOR (textuales y en orden, no resumidos; mandan sobre el resumen de arriba, y el último es el pedido más reciente antes de lo que sigue):\n${lineas.join("\n")}`;
}

/** Los mensajes del operador guardados en la sesión antes de `hasta` (seq), para el checkpoint. */
export function seccionDelOperador(db: DatabaseSync, sessionId: string, hasta: number, guardar: (texto: string) => string): string {
  const filas = db.prepare("select json from messages where session_id=? and seq<? order by seq").all(sessionId, hasta) as Array<{ json: string }>;
  const textos: string[] = [];
  for (const { json } of filas) {
    try {
      const mensaje = JSON.parse(json) as { role?: string; content?: unknown };
      const texto = mensaje.role === "user" && typeof mensaje.content === "string" ? textoDelOperador(mensaje.content) : undefined;
      if (texto) textos.push(texto);
    } catch { /* fila ilegible: se saltea */ }
  }
  return instruccionesDelOperador(textos, guardar);
}
