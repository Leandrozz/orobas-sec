// Línea de base: supresiones versionadas (por huella, con motivo, autor y vencimiento) y la comparación con la
// corrida anterior (nuevos, persisten, resueltos). Una supresión vencida deja de valer sola: el hallazgo vuelve a
// bloquear y la salida lo dice.
import { ErrorConfig, leerFuente, parsearDocumento, type Problema } from "./config.ts";
import { FORMATO, type HallazgoCi, type ResultadoCi } from "./resultado.ts";

export interface Supresion {
  huella: string;
  motivo: string;
  autor: string;
  /** AAAA-MM-DD: vale hasta ese día inclusive. */
  vence: string;
  linea?: number;
}

export interface Supresiones {
  archivo: string;
  existe: boolean;
  vigentes: Map<string, Supresion>;
  vencidas: Supresion[];
  /** Vencimientos a más de un año: valen, pero se avisa. */
  avisos: string[];
}

const HUELLA = /^orobas:v1:[0-9a-f]{24}$/;
const FECHA = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Hoy en UTC como AAAA-MM-DD. */
export const hoy = (ahora = new Date()) => ahora.toISOString().slice(0, 10);

/** Lee y valida el archivo de supresiones. Sin archivo, ninguna. Un archivo mal formado es un error de configuración. */
export function leerSupresiones(cwd: string, archivo: string, ref: string | undefined, ahora = new Date()): Supresiones {
  const fuente = leerFuente(cwd, archivo, ref);
  const vacio: Supresiones = { archivo, existe: false, vigentes: new Map(), vencidas: [], avisos: [] };
  if (fuente === undefined) return vacio;
  const { valor, posiciones } = parsearDocumento(archivo, fuente);
  const problemas: Problema[] = [];
  const error = (ruta: string, mensaje: string): false => {
    const pos = posiciones.get(ruta) ?? posiciones.get(ruta.replace(/\.[^.]+$/, ""));
    problemas.push({ ruta, mensaje: `«${ruta}» ${mensaje}`, linea: pos?.linea, columna: pos?.columna });
    return false;
  };
  if (valor === null || valor === undefined) return { ...vacio, existe: true };
  if (typeof valor !== "object" || Array.isArray(valor)) throw new ErrorConfig(archivo, [{ ruta: "", mensaje: "tiene que ser un mapa con «version: 1» y «supresiones: [...]»", linea: 1, columna: 1 }]);
  const raiz = valor as Record<string, unknown>;
  for (const clave of Object.keys(raiz)) if (!["version", "supresiones"].includes(clave)) error(clave, "no es una clave conocida. Válidas: version, supresiones");
  if (raiz.version !== 1) error("version", "tiene que ser 1");
  const lista = raiz.supresiones ?? [];
  if (!Array.isArray(lista)) {
    error("supresiones", "tiene que ser una lista");
    throw new ErrorConfig(archivo, problemas);
  }
  const salida: Supresiones = { ...vacio, existe: true };
  const limite = new Date(ahora.getTime() + 366 * 86_400_000).toISOString().slice(0, 10);
  for (const [k, item] of lista.entries()) {
    const ruta = `supresiones[${k}]`;
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      error(ruta, "tiene que ser un mapa con huella, motivo, autor y vence");
      continue;
    }
    const s = item as Record<string, unknown>;
    for (const clave of Object.keys(s)) if (!["huella", "motivo", "autor", "vence"].includes(clave)) error(`${ruta}.${clave}`, "no es una clave conocida. Válidas: huella, motivo, autor, vence");
    const huella = typeof s.huella === "string" ? s.huella.trim() : "";
    const motivo = typeof s.motivo === "string" ? s.motivo.trim() : "";
    const autor = typeof s.autor === "string" ? s.autor.trim() : "";
    const vence = typeof s.vence === "string" ? s.vence.trim() : "";
    let bien = true;
    if (!HUELLA.test(huella)) bien = error(`${ruta}.huella`, "tiene que ser la huella de un hallazgo (orobas:v1:…, la que muestran el comentario del PR, el JSON y el SARIF)");
    if (motivo.length < 10) bien = error(`${ruta}.motivo`, "falta o es muy corto: decí por qué se acepta el riesgo (10 caracteres o más)");
    if (!autor) bien = error(`${ruta}.autor`, "falta: quién lo decidió");
    const f = FECHA.exec(vence);
    const valida = f && !Number.isNaN(Date.parse(`${vence}T00:00:00Z`)) && new Date(`${vence}T00:00:00Z`).toISOString().slice(0, 10) === vence;
    if (!valida) bien = error(`${ruta}.vence`, "falta o no es una fecha AAAA-MM-DD válida: toda supresión vence");
    if (!bien) continue;
    if (salida.vigentes.has(huella)) {
      error(`${ruta}.huella`, "está repetida");
      continue;
    }
    const supresion: Supresion = { huella, motivo, autor, vence, linea: posiciones.get(ruta)?.linea };
    if (vence < hoy(ahora)) salida.vencidas.push(supresion);
    else {
      salida.vigentes.set(huella, supresion);
      if (vence > limite) salida.avisos.push(`La supresión de ${huella} vence el ${vence}, a más de un año: conviene revisarla antes.`);
    }
  }
  if (problemas.length) throw new ErrorConfig(archivo, problemas);
  return salida;
}

/** Lee el resultado de la corrida anterior; undefined (con el motivo) si no hay o no es de este formato. */
export function leerAnterior(texto: string | undefined): { anterior?: ResultadoCi; aviso?: string } {
  if (texto === undefined) return {};
  try {
    const anterior = JSON.parse(texto) as ResultadoCi;
    if (anterior?.formato !== FORMATO || !Array.isArray(anterior.hallazgos)) return { aviso: `La corrida anterior no es del formato ${FORMATO}: no la comparo.` };
    return { anterior };
  } catch (error) {
    return { aviso: `No pude leer la corrida anterior (${(error as Error).message}): no la comparo.` };
  }
}

export interface Comparacion {
  anterior: { sesion: string; fin: string; commit?: string } | null;
  nuevos: string[];
  persisten: string[];
  /** Verificados en la anterior que no reaparecieron y el retest confirmó arreglados. */
  resueltos: string[];
  /** Verificados en la anterior que no reaparecieron y no se pudo confirmar que estén arreglados. */
  sinConfirmar: string[];
}

/**
 * Clasifica los hallazgos de esta corrida contra la anterior. Sólo cuentan los verificados: un candidato de la
 * anterior que no reaparece no dice nada. Un ausente pasa a «resuelto» sólo si el retest lo confirmó; si no, queda
 * «sin confirmar» (una evaluación con un modelo no recorre siempre lo mismo: no volver a verlo no es prueba de nada).
 */
export function comparar(actuales: HallazgoCi[], anterior: ResultadoCi | undefined, retest: Map<string, "arreglado" | "persiste" | "sin-confirmar">): Comparacion {
  const verificadosAntes = new Set((anterior?.hallazgos ?? []).filter((h) => h.estado === "verificado").map((h) => h.huella));
  const actualesVerificados = actuales.filter((h) => h.estado === "verificado");
  const ahora = new Set(actualesVerificados.map((h) => h.huella));
  const reverificados = [...retest].filter(([, r]) => r === "persiste").map(([h]) => h);
  const nuevos = actualesVerificados.filter((h) => !verificadosAntes.has(h.huella)).map((h) => h.huella);
  const persisten = [...new Set([...actualesVerificados.filter((h) => verificadosAntes.has(h.huella)).map((h) => h.huella), ...reverificados.filter((h) => verificadosAntes.has(h))])];
  const ausentes = [...verificadosAntes].filter((h) => !ahora.has(h) && !reverificados.includes(h));
  return {
    anterior: anterior ? { sesion: anterior.corrida.sesion, fin: anterior.corrida.fin, ...(anterior.corrida.commit ? { commit: anterior.corrida.commit } : {}) } : null,
    nuevos,
    persisten,
    resueltos: ausentes.filter((h) => retest.get(h) === "arreglado"),
    sinConfirmar: ausentes.filter((h) => retest.get(h) !== "arreglado"),
  };
}
