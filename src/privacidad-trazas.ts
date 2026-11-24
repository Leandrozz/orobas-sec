// Trazas: todo el material de entrenamiento que puede dejar una sesión. Son la traza del gateway (cada
// pedido al modelo y su respuesta), el registro de cada turno (/traces), la trayectoria de cada sesión
// (/trayectorias) y la cita de los consentimientos (/consent). Un solo modo, el mismo que en la web
// (decisión de Lean, 22/11/2026):
//   · compartir (por defecto): todo se manda al servicio, con los secretos ya tapados.
//   · local: nada de contenido sale hacia el servicio; el material completo, tapado igual que si saliera,
//     queda en la PC de la persona (trazas-locales.ts).
//   · no: nada de contenido sale y no se arma material de entrenamiento; queda sólo lo que la sesión
//     necesita para funcionar y retomarse.
// El modo local sale de CYBER_TRAZAS, si no de «trazas» en la configuración, si no «compartir». Si el
// servicio informa el modo de la cuenta (GET /cuenta) y es más restrictivo, gana ése. Lo que no se
// entiende restringe. En todos los modos el pedido igual viaja al proveedor del modelo: eso no cambia.
// La preferencia se consulta en cada envío, también si cambia durante la sesión.
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { t } from "./idioma.ts";

export const MODOS_TRAZAS = ["compartir", "local", "no"] as const;
export type ModoTrazas = (typeof MODOS_TRAZAS)[number];
const RANGO: Record<ModoTrazas, number> = { compartir: 0, local: 1, no: 2 };

/** Interpreta un valor. Acepta los de antes (no/0/false/off/cantidades, y sí/1/on/completa). Vacío: nada; otro: «no». */
export function leerModo(valor: unknown): ModoTrazas | undefined {
  if (typeof valor !== "string" || !valor.trim()) return undefined;
  const v = valor.trim().toLowerCase();
  if (/^(compartir|si|sí|1|true|on|completa)$/.test(v)) return "compartir";
  if (v === "local") return "local";
  return "no";
}

/** El más restrictivo de los dos; sin el segundo, el primero. */
export const masRestrictivo = (a: ModoTrazas, b: ModoTrazas | undefined): ModoTrazas => (b !== undefined && RANGO[b] > RANGO[a] ? b : a);

// Igual que providers.configPath; se repite para no cargar los proveedores desde acá (llm.ts nos importa).
const rutaConfig = () => process.env.CYBER_CONFIG || join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "elevate-cyber", "config.json");

let leido: { ruta: string; mtime: number; modo: ModoTrazas | undefined } | undefined;
/** «trazas» de la configuración. Un archivo que existe y no se entiende cuenta como «no». */
function modoDeConfig(): ModoTrazas | undefined {
  const ruta = rutaConfig();
  let mtime: number;
  try { mtime = statSync(ruta).mtimeMs; } catch { return undefined; }
  if (leido?.ruta === ruta && leido.mtime === mtime) return leido.modo;
  let modo: ModoTrazas | undefined;
  try {
    const config = JSON.parse(readFileSync(ruta, "utf8").replace(/^\uFEFF/, "")) as { trazas?: unknown };
    modo = leerModo(config?.trazas);
  } catch { modo = "no"; }
  leido = { ruta, mtime, modo };
  return modo;
}

export type Origen = "variable" | "configuración" | "defecto";
/** El modo que eligió esta máquina, y de dónde sale. */
export function modoLocal(): { modo: ModoTrazas; origen: Origen } {
  const variable = leerModo(process.env.CYBER_TRAZAS);
  if (variable) return { modo: variable, origen: "variable" };
  const config = modoDeConfig();
  if (config) return { modo: config, origen: "configuración" };
  return { modo: "compartir", origen: "defecto" };
}

let cuenta: ModoTrazas | undefined;
/** Lo que informó el servicio sobre la cuenta (cuenta.ts lo anota al leer GET /cuenta). */
export function anotarModoCuenta(modo: ModoTrazas | undefined): void { cuenta = modo; }
export const modoCuenta = () => cuenta;

/** El modo que rige: el más restrictivo entre el de esta máquina y el de la cuenta. */
export const modoTrazas = (): ModoTrazas => masRestrictivo(modoLocal().modo, cuenta);
/** ¿Sale contenido hacia el servicio? Sólo en «compartir». */
export const comparteConServicio = () => modoTrazas() === "compartir";
/** ¿Se guarda el material en la PC? Sólo en «local». */
export const guardaLocal = () => modoTrazas() === "local";
/** Compatibilidad: «apagadas» es que nada de contenido va al servicio («local» o «no»). */
export const trazasApagadas = () => !comparteConServicio();

/**
 * Va en todos los pedidos al servicio: el modo que rige. El servicio aplica el más restrictivo con el de la cuenta.
 * `pedido`: un modo más restrictivo para este pedido solo (un pedido al modelo que trae material del objetivo a la
 * vista sale con «no», para que el gateway no guarde su contenido); nunca amplía.
 */
export function cabecerasDePrivacidad(pedido?: ModoTrazas): Record<string, string> {
  return { "x-cyber-trazas": masRestrictivo(modoTrazas(), pedido) };
}

/** Guarda «trazas» en la configuración sin tocar el resto. Devuelve un aviso si no pudo, o si la variable manda. */
export function guardarModoTrazas(modo: ModoTrazas): string | undefined {
  const ruta = rutaConfig();
  let config: Record<string, unknown> = {};
  if (existsSync(ruta)) {
    try { config = JSON.parse(readFileSync(ruta, "utf8").replace(/^\uFEFF/, "")) as Record<string, unknown>; }
    catch (error) { return `No guardé en ${ruta}: no es un JSON válido (${(error as Error).message}). Arreglalo a mano.`; }
  }
  config.trazas = modo;
  try {
    mkdirSync(dirname(ruta), { recursive: true });
    writeFileSync(ruta, `${JSON.stringify(config, null, 2)}\n`);
  } catch (error) {
    return `No pude guardar en ${ruta}: ${(error as Error).message}.`;
  }
  const variable = leerModo(process.env.CYBER_TRAZAS);
  if (variable && variable !== modo) return `Quedó guardado, pero la variable CYBER_TRAZAS=${process.env.CYBER_TRAZAS} manda en este proceso: rige «${variable}» hasta que la saques.`;
  return undefined;
}

/**
 * Antes de los tres modos, «/datos revocar» dejaba en la base del proyecto un consentimiento «trayectorias-no». Esa
 * revocación sigue valiendo (decisión de Lean del 22/11: compartir viene activado, pero quien lo había apagado lo
 * sigue teniendo apagado). Si esta máquina no eligió un modo (ni CYBER_TRAZAS ni «trazas» en la configuración) y el
 * último registro del proyecto es esa revocación, queda «no» en la configuración, una sola vez, y devuelve el aviso.
 * Un permiso posterior («trayectorias», que deja /datos compartir) la deja sin efecto. Un modo ya elegido manda.
 */
export function respetarRevocacionAnterior(consentimientos: { get(kind: string): { at: string } | undefined }): string | undefined {
  if (modoLocal().origen !== "defecto") return undefined;
  const revoco = consentimientos.get("trayectorias-no")?.at;
  const permiso = consentimientos.get("trayectorias")?.at;
  if (!revoco || (permiso && Date.parse(permiso) >= Date.parse(revoco))) return undefined;
  const problema = guardarModoTrazas("no");
  return t(
    `Habías revocado con /datos el permiso de compartir datos de este proyecto: las trazas quedan en «no» (guardado en la configuración, vale para toda la máquina).${problema ? ` ${problema}` : ""} Para compartir: /datos compartir.`,
    `You had revoked data sharing for this project with /datos: traces stay at “no” (saved in the settings, for the whole machine).${problema ? ` ${problema}` : ""} To share: /datos compartir.`,
  );
}
