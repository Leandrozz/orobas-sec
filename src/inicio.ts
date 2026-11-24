// Estado del inicio guiado (onboarding): una marca en la configuración del usuario, no del proyecto.
// Se corre la primera vez que la TUI arranca en una máquina y se vuelve a correr con /inicio.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { configPath } from "./providers.ts";
import { t } from "./idioma.ts";

export const INICIO_VERSION = 1;

/** Con `strict`, un archivo que existe y no se puede leer tira error: quien escribe nunca lo pisa. */
function readConfig(strict = false): Record<string, unknown> {
  const path = configPath();
  if (!existsSync(path)) return {};
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    throw new Error("se esperaba un objeto");
  } catch (error) {
    if (strict) throw new Error(t(`No toqué ${path}: no es un JSON válido (${(error as Error).message}). Arreglalo a mano.`, `Left ${path} untouched: it is not valid JSON (${(error as Error).message}). Fix it by hand.`));
    return {};
  }
}

/** Cuándo se completó (o se descartó) el inicio en esta máquina; nada si nunca. */
export function inicioDone(): { at: string; version: number; skipped: boolean } | undefined {
  const inicio = readConfig().inicio as { at?: string; version?: number; skipped?: boolean } | undefined;
  if (!inicio?.at) return undefined;
  return { at: inicio.at, version: inicio.version ?? 0, skipped: Boolean(inicio.skipped) };
}

/** ¿Hay que mostrarlo? Nunca se hizo, o se hizo con una versión anterior y no fue descartado para siempre. */
export function inicioPending(): boolean {
  const done = inicioDone();
  if (!done) return true;
  return done.version < INICIO_VERSION && !done.skipped;
}

export function markInicio(options: { skipped?: boolean } = {}): void {
  const path = configPath();
  const config = readConfig(true);
  config.inicio = { at: new Date().toISOString(), version: INICIO_VERSION, ...(options.skipped ? { skipped: true } : {}) };
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`);
  } catch (error) {
    throw new Error(`No puedo guardar la configuración en ${path}: ${(error as Error).message}`);
  }
}

/** Vuelve a pedir el inicio la próxima vez (por ejemplo, para probarlo). */
export function resetInicio(): void {
  const path = configPath();
  const config = readConfig(true);
  delete config.inicio;
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`);
  } catch (error) {
    throw new Error(`No puedo guardar la configuración en ${path}: ${(error as Error).message}`);
  }
}
