// Prefijo estable y puntos de caché. Los proveedores cobran a precio de caché el prefijo que ya vieron y entero
// todo lo que viene después del primer byte distinto. Medido en las trazas (scripts/simular-fase3.py): el sistema
// y las descripciones de herramientas no cambian durante una sesión; lo que rompe el prefijo del lado del harness
// es cargar herramientas a mitad de sesión (el catálogo va antes que los mensajes), la dieta y la compactación.
//
// Chat Completions (orobas y compatibles) cachea solo por prefijo, sin marcas. Anthropic Messages, en cambio, no
// cachea nada si el pedido no marca dónde: sin esto, cada paso con un modelo de Anthropic pagaba entero.

type Bloque = { type: string; text?: string; cache_control?: { type: "ephemeral" } };
type MensajeAnthropic = { role: "user" | "assistant"; content: Bloque[] };

const EFIMERO = { type: "ephemeral" } as const;

/**
 * Dos puntos de caché para Anthropic: al final del sistema (cubre herramientas y sistema, que no cambian) y en el
 * último bloque del último mensaje (cada paso relee desde caché lo que escribió el anterior). El límite es 4.
 */
export function puntosDeCacheAnthropic(system: string, mensajes: MensajeAnthropic[]): { system?: Bloque[]; messages: MensajeAnthropic[] } {
  const messages = mensajes.map((mensaje, i) => {
    if (i !== mensajes.length - 1 || !mensaje.content.length) return mensaje;
    const content = mensaje.content.map((bloque, j) => (j === mensaje.content.length - 1 ? { ...bloque, cache_control: EFIMERO } : bloque));
    return { ...mensaje, content };
  });
  return { ...(system ? { system: [{ type: "text", text: system, cache_control: EFIMERO }] } : {}), messages };
}
