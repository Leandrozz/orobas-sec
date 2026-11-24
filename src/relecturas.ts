// Relecturas idénticas. Si una herramienta devuelve exactamente lo mismo que una salida suya que sigue a la vista
// (no compactada ni resumida por la dieta), la segunda copia no entra: viaja una referencia corta, con el
// artefacto del texto por si la primera sale del contexto más adelante. En las trazas fueron 64 casos
// (scripts/simular-fase3.py): poco dinero, pero cero pérdida, porque el texto sigue más arriba.
//
// No se toca lo que el detector de falta de avance compara (src/agent.ts mira los últimos cuatro pasos): una
// repetición dentro de esa ventana entra entera, para que la repetición se siga viendo como tal.
import type { Message } from "./llm.ts";

/** Una salida más corta que esto no se deduplica: la referencia ocuparía casi lo mismo. */
export const RELECTURA_MIN = 400;
/** Pasos hacia atrás que mira el detector de falta de avance: ahí no se deduplica. */
export const VENTANA_SIN_AVANCE = 4;

export function referenciaRelectura(nombre: string, hace: number, puntero: string): string {
  const cuando = hace <= 0 ? "en este mismo paso" : `hace ${hace} paso${hace !== 1 ? "s" : ""}`;
  return `[Sin cambios: ${nombre} devolvió exactamente lo mismo que ${cuando}, y esa salida sigue más arriba. Completa en ${puntero}.]`;
}

/**
 * Referencia en lugar de `texto` si `mensajes` (lo que se envía: la vista con la dieta aplicada) ya tiene una salida
 * idéntica de la misma herramienta, fuera de la ventana del detector de falta de avance. Undefined si no.
 */
export function relecturaIgual(mensajes: Message[], nombre: string, texto: string, guardar: (texto: string) => string): string | undefined {
  if (texto.length <= RELECTURA_MIN) return undefined;
  let pasos = 0;
  for (let i = mensajes.length - 1; i >= 0; i--) {
    const mensaje = mensajes[i]!;
    if (mensaje.role === "assistant") pasos++;
    else if (mensaje.role === "tool" && mensaje.name === nombre && mensaje.content === texto) {
      return pasos > VENTANA_SIN_AVANCE ? referenciaRelectura(nombre, pasos, guardar(texto)) : undefined;
    }
  }
  return undefined;
}
