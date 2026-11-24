// «$ comando» en la TUI: corre el comando en el shell del usuario y arma el bloque que viaja al agente.
import { SEARCH_PATH, exec } from "../exec.ts";

export const MAX_AGENTE = 16 * 1024;

export interface Corrida {
  comando: string;
  /** stdout y stderr juntos, en orden de llegada. */
  salida: string;
  codigo: number | null;
  cortado: boolean;
}

/** El comando sin el prefijo «$ », o undefined si el texto no es un comando. */
export function comandoDolar(texto: string): string | undefined {
  if (!texto.startsWith("$ ")) return undefined;
  return texto.slice(2).trim() || undefined;
}

export async function correrComando(comando: string, opciones: { cwd: string; signal?: AbortSignal; onOutput?: (chunk: string) => void }): Promise<Corrida> {
  let salida = "";
  try {
    // Entorno filtrado a propósito: las claves de API no llegan al comando; del entorno pasa solo el PATH del usuario (sbin, nvm, pyenv).
    const r = await exec({
      argv: [process.env.SHELL || "sh", "-c", comando],
      cwd: opciones.cwd,
      env: { PATH: process.env.PATH ?? SEARCH_PATH },
      signal: opciones.signal,
      timeoutMs: 300_000,
      onOutput: (chunk) => {
        // Acotada: una salida enorme no crece sin límite; el +1 deja a bloqueTerminal saber que se recortó.
        salida = (salida + chunk).slice(-MAX_AGENTE - 1);
        opciones.onOutput?.(chunk);
      },
    });
    return { comando, salida, codigo: r.exitCode, cortado: r.timedOut || r.cancelled };
  } catch (error) {
    // exec tira si no encuentra el shell; no se propaga: queda como una corrida fallida.
    return { comando, salida: error instanceof Error ? error.message : String(error), codigo: null, cortado: false };
  }
}

/** Bloque para anexar al mensaje del usuario; "" si no hubo corridas. */
export function bloqueTerminal(corridas: Corrida[]): string {
  if (corridas.length === 0) return "";
  let bloque = "\n\n<terminal>\n";
  for (const c of corridas) {
    const recortada = c.salida.length > MAX_AGENTE;
    const salida = recortada ? `[salida recortada: últimos 16 KB]\n${c.salida.slice(-MAX_AGENTE)}` : c.salida;
    bloque += `$ ${c.comando}\n${salida}\n[${c.cortado ? "cortado" : `código ${c.codigo}`}]\n`;
  }
  return `${bloque}</terminal>`;
}
