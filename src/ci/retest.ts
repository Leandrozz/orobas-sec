// Retest: vuelve a probar hallazgos verificados de una corrida anterior y dice cuáles quedaron arreglados. Por cada
// uno: repite la petición que lo demostró (con el host del entorno actual, por el destino de su huella, y con la
// identidad de prueba por nombre), la guarda como evidencia, y lo vuelve a pasar por el verificador independiente,
// que hace su propia prueba y su control. Verificado: persiste. Descartado: arreglado, con la prueba que ahora da
// como el control. Cualquier otra cosa: sin confirmar (nunca se da por arreglado lo que no se pudo probar).
import type { Engine } from "../engine.ts";
import type { HttpRequestSpec } from "../http.ts";
import { VerifierFailure, exhaustedError } from "../verifier.ts";
import { paso } from "./recolectar.ts";
import type { HallazgoCi, Paso, RetestCi } from "./resultado.ts";
import type { Tapador } from "./tapado.ts";

export interface DestinoActual {
  clave: string;
  /** Origen (esquema://host[:puerto]) del destino en este entorno, si es una URL. */
  origen?: string;
}

export interface Retesteado {
  retest: RetestCi;
  /** Id del candidato que se creó en esta sesión para el retest (no se lista como hallazgo nuevo). */
  id?: string;
  /** El verificador no pudo por falta de saldo o el proveedor falló. */
  proveedor?: boolean;
  /** Se cortó por presupuesto o tiempo. */
  corte?: boolean;
}

const enmascarado = (texto: string) => /\[credencial omitida\]|‹SECRETO_\d+›|‹secreto›/.test(texto);

/** La URL del paso anterior en el entorno actual: mismo camino y consulta, el origen del destino de ahora. */
export function remapear(url: string, destino: string, destinos: DestinoActual[]): string {
  const actual = destinos.find((d) => d.clave === destino)?.origen;
  if (!actual) return url;
  try {
    const vieja = new URL(url);
    const nueva = new URL(actual);
    return `${nueva.origin}${vieja.pathname}${vieja.search}`;
  } catch {
    return url;
  }
}

/** Repite un paso guardado. Devuelve el hash del intercambio nuevo, o por qué no se pudo. */
async function repetir(engine: Engine, anterior: Paso, url: string): Promise<{ hash?: string; nota?: string }> {
  if (anterior.cuerpo && enmascarado(anterior.cuerpo)) return { nota: "el cuerpo de la petición original tenía secretos tapados: no se repite tal cual (el verificador hace la suya)" };
  const identidad = anterior.identidad && engine.http.identityNames().includes(anterior.identidad) ? anterior.identidad : undefined;
  if (anterior.identidad && !identidad) return { nota: `la identidad «${anterior.identidad}» no está cargada en esta corrida: no se repite` };
  const cabeceras = Object.fromEntries(Object.entries(anterior.cabeceras).filter(([k, v]) => !/^(host|content-length|user-agent)$/i.test(k) && !/^<identidad [^>]+>$/.test(v) && !enmascarado(v)));
  const spec: HttpRequestSpec = { method: anterior.metodo, url, headers: cabeceras, ...(anterior.cuerpo !== undefined ? { body: anterior.cuerpo } : {}) };
  try {
    const ex = await engine.http.send(spec, identidad);
    return { hash: ex.artifact };
  } catch (error) {
    return { nota: `no se repitió: ${(error as Error).message.slice(0, 300)}` };
  }
}

export async function retestear(opciones: {
  engine: Engine;
  tapador: Tapador;
  conocidos: HallazgoCi[];
  destinos: DestinoActual[];
  signal?: AbortSignal;
  /** Por qué no seguir (presupuesto o tiempo); undefined para seguir. */
  parar: () => string | undefined;
  alVeredicto?: (r: Retesteado) => void;
}): Promise<Retesteado[]> {
  const { engine, tapador } = opciones;
  const salida: Retesteado[] = [];
  const base = (h: HallazgoCi, resultado: RetestCi["resultado"], motivo: string, extra: Partial<RetestCi> = {}): RetestCi => ({ huella: h.huella, titulo: h.titulo, severidad: h.severidad, clase: h.clase, resultado, motivo, bloqueante: false, ...extra });
  for (const h of opciones.conocidos) {
    const corte = opciones.parar();
    if (corte || opciones.signal?.aborted) {
      const r = { retest: base(h, "sin-confirmar", `no se retesteó: ${corte ?? "se cortó la corrida"}`), corte: true };
      salida.push(r);
      opciones.alVeredicto?.(r);
      continue;
    }
    const original = h.verificacion?.prueba ?? h.reproduccion.find((p) => p.respuesta) ?? h.reproduccion[0];
    const url = original ? remapear(original.url, h.destino, opciones.destinos) : remapear(h.activo, h.destino, opciones.destinos);
    const repeticion = original ? await repetir(engine, original, url) : { nota: "la corrida anterior no guardó la petición" };
    // La evidencia del candidato del retest: la repetición (si salió) y lo que dijo la corrida anterior.
    const anterior = engine.artifacts.put(JSON.stringify({ retest: h.huella, titulo: h.titulo, activo: h.activo, resumen: h.resumen, reproduccion: h.reproduccion.slice(0, 3), verificacion: h.verificacion ?? null }, null, 1), "application/json", "ci:retest").hash;
    let id: string;
    try {
      id = engine.findings.record({
        title: h.titulo,
        kind: h.clase_declarada || h.clase.nombre,
        severity: h.severidad,
        asset: url,
        summary: `Retest de un hallazgo verificado en una corrida anterior (huella ${h.huella}). ${h.resumen}`,
        evidence: [...(repeticion.hash ? [repeticion.hash] : []), anterior],
        limits: [h.limites, repeticion.nota].filter(Boolean).join(" "),
      }, engine.sessionId).id;
    } catch (error) {
      const r = { retest: base(h, "sin-confirmar", `no se pudo preparar el retest: ${(error as Error).message.slice(0, 300)}`, repeticion.hash ? { repeticion: paso(engine, tapador, repeticion.hash) } : {}) };
      salida.push(r);
      opciones.alVeredicto?.(r);
      continue;
    }
    const repetida = repeticion.hash ? paso(engine, tapador, repeticion.hash) : undefined;
    try {
      const v = await engine.verifier.verify(id, { signal: opciones.signal });
      const [prueba, control] = v.evidence.slice(0, 2).map((hash) => paso(engine, tapador, hash));
      const resultado: RetestCi["resultado"] = v.state === "verificado" ? "persiste" : v.state === "descartado" ? "arreglado" : "sin-confirmar";
      const motivo = tapador.texto(v.reason.split("\nComprobaciones:")[0]!.trim());
      const r = { id, retest: base(h, resultado, motivo, { ...(repetida ? { repeticion: repetida } : {}), ...(prueba ? { prueba } : {}), ...(control ? { control } : {}) }) };
      salida.push(r);
      opciones.alVeredicto?.(r);
    } catch (error) {
      const mensaje = (error as Error).message;
      const proveedor = error instanceof VerifierFailure ? error.exhausted : exhaustedError(mensaje);
      const r = { id, proveedor, retest: base(h, "sin-confirmar", `el verificador no terminó: ${tapador.texto(mensaje).slice(0, 300)}`, repetida ? { repeticion: repetida } : {}) };
      salida.push(r);
      opciones.alVeredicto?.(r);
    }
  }
  return salida;
}
