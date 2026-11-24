// Todas las sesiones de una carpeta comparten un daemon de un solo hilo: un trabajo largo (recorrer carpetas,
// leer y redactar evidencia) cede el event loop cada tanto para que las demás sigan respondiendo, y se corta
// con la señal del turno.

/** Pausa que cede el event loop si pasaron más de `ms` desde la anterior; antes y después mira la señal. */
export function pacer(signal?: AbortSignal, ms = 20): () => Promise<void> {
  let last = performance.now();
  return async () => {
    signal?.throwIfAborted();
    if (performance.now() - last < ms) return;
    await new Promise((done) => setImmediate(done));
    last = performance.now();
    signal?.throwIfAborted();
  };
}
