// Verificación por ejecución. Un hallazgo que trae un PoC o harness ejecutable (un artefacto con el comando
// de reproducción) no se discute: se corre de nuevo en limpio con poc_run, dos veces. Si dispara las dos
// veces, está verificado con esa evidencia; si no, queda candidato con el motivo. Lo usan el verificador
// (src/verifier.ts) y la subida de nivel de las hipótesis del modo investigar.
//
// poc_run es una herramienta de la caja (la provee otro módulo): acá se la usa por nombre y por su interfaz
// mínima (comando y carpeta → salida y código de salida). En pruebas, o cuando la caja exporte su API
// interna, se inyecta un `EjecutarPoc` directo.
import type { Tool } from "../agent.ts";
import type { Artifacts } from "../artifacts.ts";
import type { Finding } from "../findings.ts";

export const FORMATO_POC = "orobas.poc/1";
/** Productor con el que se guardan los PoC: sólo este código los escribe, así un artefacto cualquiera no pasa por PoC. */
export const PRODUCTOR_POC = "poc:investigacion";
/** Corridas en limpio para decir «reproduce de forma determinista». */
export const CORRIDAS = 2;

/** Un PoC ejecutable: el comando de reproducción y la señal que prueba que disparó. */
export interface Poc {
  formato: typeof FORMATO_POC;
  comando: string;
  /** Carpeta donde correrlo (relativa al proyecto o de la caja). */
  cwd?: string;
  /** Lo que tiene que aparecer en la salida (texto, o /regex/). Sin señal: dispara si sale con código distinto de 0. */
  senal?: string;
  /** Artefactos del harness (fuente, binario, entrada) que el comando necesita. */
  artefactos?: string[];
  investigacion?: string;
  hipotesis?: string;
  nivel?: 1 | 2 | 3;
}

export interface CorridaPoc { codigo: number | null; salida: string; error?: string }
/** Corre un comando de reproducción en limpio y devuelve su salida. */
export type EjecutarPoc = (pedido: { comando: string; cwd?: string; signal?: AbortSignal }) => Promise<CorridaPoc>;

export function guardarPoc(artifacts: Artifacts, poc: Omit<Poc, "formato">): string {
  return artifacts.put(JSON.stringify({ formato: FORMATO_POC, ...poc }, null, 1), "application/json", PRODUCTOR_POC).hash;
}

/** El PoC de un artefacto, si es uno: formato propio, o el artefacto de una herramienta de la caja con su comando. */
export function leerPoc(artifacts: Artifacts, hash: string): Poc | undefined {
  const row = artifacts.db.prepare("select producer from artifacts where hash=?").get(hash) as { producer: string } | undefined;
  if (!row) return undefined;
  const caja = /^(poc_run|harness_build|fuzz_run)\b/.test(row.producer);
  if (row.producer !== PRODUCTOR_POC && !caja) return undefined;
  try {
    const data = JSON.parse(artifacts.read(hash).toString("utf8")) as Record<string, unknown>;
    // En harness_build, `command` es la compilación: el PoC es `run_command` (sólo los PoC con main lo traen).
    const comando = row.producer.startsWith("harness_build")
      ? (typeof data.run_command === "string" ? data.run_command : undefined)
      : typeof data.comando === "string" ? data.comando : typeof data.command === "string" ? data.command : undefined;
    if (!comando?.trim()) return undefined;
    if (row.producer === PRODUCTOR_POC && data.formato !== FORMATO_POC) return undefined;
    const senal = typeof data.senal === "string" ? data.senal : typeof data.signal === "string" ? data.signal : undefined;
    const cwd = typeof data.cwd === "string" ? data.cwd : undefined;
    return { formato: FORMATO_POC, comando, ...(cwd ? { cwd } : {}), ...(senal ? { senal } : {}) };
  } catch {
    return undefined;
  }
}

/** El primer PoC ejecutable entre la evidencia de un hallazgo. */
export function pocDe(artifacts: Artifacts, finding: Pick<Finding, "evidence">): { hash: string; poc: Poc } | undefined {
  for (const hash of finding.evidence) {
    const poc = leerPoc(artifacts, hash);
    if (poc) return { hash, poc };
  }
  return undefined;
}

/** ¿Esta corrida muestra la señal? Con señal, que aparezca en la salida; sin señal, que salga con error. */
export function disparo(poc: Pick<Poc, "senal">, corrida: CorridaPoc): boolean {
  if (corrida.error && corrida.codigo === null) return false;
  if (poc.senal) {
    const regex = /^\/(.+)\/([a-z]*)$/.exec(poc.senal);
    if (regex) {
      try { return new RegExp(regex[1]!, regex[2]).test(corrida.salida); } catch { return false; }
    }
    return corrida.salida.includes(poc.senal);
  }
  return corrida.codigo !== null && corrida.codigo !== 0;
}

export interface Reproduccion { reproduce: boolean; corridas: CorridaPoc[]; disparos: number; motivo: string }

/** Corre el PoC `veces` veces en limpio: reproduce sólo si dispara en todas (determinista). */
export async function reproducir(ejecutar: EjecutarPoc, poc: Poc, signal?: AbortSignal, veces = CORRIDAS): Promise<Reproduccion> {
  const corridas: CorridaPoc[] = [];
  for (let i = 0; i < veces && !signal?.aborted; i++) {
    try {
      corridas.push(await ejecutar({ comando: poc.comando, ...(poc.cwd ? { cwd: poc.cwd } : {}), signal }));
    } catch (error) {
      corridas.push({ codigo: null, salida: "", error: (error as Error).message });
    }
  }
  const disparos = corridas.filter((corrida) => disparo(poc, corrida)).length;
  const senal = poc.senal ? `la señal «${poc.senal.slice(0, 80)}»` : "una salida con error";
  if (signal?.aborted && corridas.length < veces) return { reproduce: false, corridas, disparos, motivo: "corte antes de terminar las corridas" };
  const fallida = corridas.find((corrida) => corrida.error);
  if (disparos === veces) return { reproduce: true, corridas, disparos, motivo: `reproduce de forma determinista: ${senal} en ${disparos} de ${veces} corridas en limpio` };
  if (fallida && !disparos) return { reproduce: false, corridas, disparos, motivo: `no se pudo correr el PoC en limpio: ${fallida.error!.slice(0, 160)}` };
  if (disparos) return { reproduce: false, corridas, disparos, motivo: `no reproduce de forma determinista: ${senal} en ${disparos} de ${veces} corridas` };
  return { reproduce: false, corridas, disparos, motivo: `no reproduce: ${senal} no apareció en ${veces} corridas en limpio${corridas[0] ? ` (código ${corridas[0].codigo ?? "—"})` : ""}` };
}

/**
 * Adaptador a la herramienta poc_run de la caja: le pasa el comando y la carpeta, y lee el código de salida
 * de sus detalles (exitCode, exit_code, codigo o code) y la salida de su texto. Si la herramienta marca el
 * resultado como error sin código, cuenta como código 1.
 */
export function ejecutorDesdeHerramienta(tool: Tool): EjecutarPoc {
  return async ({ comando, cwd, signal }) => {
    const result = await tool.execute({ command: comando, ...(cwd ? { cwd } : {}) }, signal ?? new AbortController().signal);
    const details = (result.details ?? {}) as Record<string, unknown>;
    const raw = details.exitCode ?? details.exit_code ?? details.codigo ?? details.code;
    const codigo = typeof raw === "number" ? raw : result.isError ? 1 : 0;
    return { codigo, salida: result.text };
  };
}
