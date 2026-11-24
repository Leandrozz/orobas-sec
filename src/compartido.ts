import { readdirSync, readFileSync } from "node:fs";

/** Varias ventanas comparten un contenedor (y un daemon) por proyecto; lo pone el lanzador. */
export const compartido = (): boolean => process.env.CYBER_COMPARTIDO === "1";

const leer = (ruta: string): string[] | undefined => {
  try {
    return readFileSync(ruta, "utf8").split("\0");
  } catch {
    return undefined; // proceso que murió o directorio ilegible
  }
};
const pids = (procDir: string): string[] => {
  try {
    return readdirSync(procDir).filter((n) => /^\d+$/.test(n));
  } catch {
    return [];
  }
};

/** Cuántos otros TUI de Cyber (no el daemon ni `despedir-ventana`) corren en este contenedor. */
export function otrasVentanas(procDir = "/proc", propio = process.pid): number {
  let cuenta = 0;
  for (const pid of pids(procDir)) {
    if (Number(pid) === propio) continue;
    const args = leer(`${procDir}/${pid}/cmdline`);
    if (args?.some((a) => a.endsWith("/src/cli.ts")) && !args.includes("daemon") && !args.includes("despedir-ventana")) cuenta++;
  }
  return cuenta;
}

const estaVivo = (pid: number): boolean => {
  try {
    return process.kill(pid, 0);
  } catch {
    return false;
  }
};

/** Manda SIGHUP a los procesos de la ventana `id` (los que llevan CYBER_VENTANA=<id>), SIGKILL a los que sigan vivos tras `espera` ms; devuelve cuántos. */
export async function despedirVentana(id: string, procDir = "/proc", matar: (pid: number, senal: NodeJS.Signals) => unknown = process.kill, vivo: (pid: number) => boolean = estaVivo, espera = 3000): Promise<number> {
  const enviados: number[] = [];
  for (const pid of pids(procDir)) {
    if (!leer(`${procDir}/${pid}/environ`)?.includes(`CYBER_VENTANA=${id}`)) continue;
    try {
      matar(Number(pid), "SIGHUP");
      enviados.push(Number(pid));
    } catch {}
  }
  if (enviados.length) await new Promise((fin) => setTimeout(fin, espera));
  for (const pid of enviados) {
    try {
      if (vivo(pid)) matar(pid, "SIGKILL");
    } catch {}
  }
  return enviados.length;
}
