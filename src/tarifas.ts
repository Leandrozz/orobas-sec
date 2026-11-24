// Tarifas y contexto de los modelos de la suscripción, tal como los publica el servicio (/v1/models).
// Se guardan junto a la configuración: así el costo que muestra la TUI es el que cobra orobas, también
// para un modelo que el harness no conocía, y sin servicio se usa la última lectura.
import { cabecerasDePrivacidad } from "./privacidad-trazas.ts";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { isEffort, type Effort, type Rates } from "./llm.ts";
import { configPath } from "./providers.ts";

export interface CatalogModel {
  cost?: Rates;
  contextWindow?: number;
  name?: string;
  kind?: string;
  status?: string;
  /** Niveles de razonamiento que acepta y si se puede apagar; ausentes si el servicio no lo dice. */
  reasoningEfforts?: Effort[];
  reasoningOff?: boolean;
}

export interface CatalogItem { id?: string; name?: string; kind?: string; context_length?: number; status?: string; pricing?: { input?: number; cached_input?: number; output?: number }; reasoning?: { efforts?: unknown; off?: unknown } }

interface CatalogFile { at: string; baseUrl: string; models: Record<string, CatalogModel> }

/** Más viejo que esto, se vuelve a pedir al arrancar. */
export const CATALOG_TTL_MS = 60 * 60 * 1000;

export const catalogPath = () => join(dirname(configPath()), "orobas-modelos.json");

/** Lo que dice el servicio, en la forma del harness. Un modelo sin precio queda sin tarifa (costo pendiente, nunca cero). */
export function parseCatalog(items: CatalogItem[]): Record<string, CatalogModel> {
  const models: Record<string, CatalogModel> = {};
  for (const item of items) {
    if (!item.id) continue;
    const p = item.pricing;
    const priced = p && typeof p.input === "number" && typeof p.output === "number";
    models[item.id] = {
      ...(priced ? { cost: { input: p.input!, output: p.output!, cacheRead: typeof p.cached_input === "number" ? p.cached_input : p.input!, cacheWrite: 0 } } : {}),
      ...(item.context_length ? { contextWindow: item.context_length } : {}),
      ...(item.name ? { name: item.name } : {}),
      ...(item.kind ? { kind: item.kind } : {}),
      ...(item.status ? { status: item.status } : {}),
      ...(item.reasoning && typeof item.reasoning === "object" ? { reasoningEfforts: Array.isArray(item.reasoning.efforts) ? item.reasoning.efforts.filter(isEffort) : [], reasoningOff: item.reasoning.off === true } : {}),
    };
  }
  return models;
}

export function readCatalog(): CatalogFile | undefined {
  const path = catalogPath();
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as CatalogFile;
    return parsed && typeof parsed === "object" && parsed.models && typeof parsed.models === "object" ? parsed : undefined;
  } catch { return undefined; }
}

/** Modelos guardados; vacío si nunca se leyó el servicio. */
export const cachedModels = (): Record<string, CatalogModel> => readCatalog()?.models ?? {};

export const catalogStale = (): boolean => {
  const saved = readCatalog();
  return !saved || Date.now() - Date.parse(saved.at) > CATALOG_TTL_MS;
};

export function saveCatalog(baseUrl: string, models: Record<string, CatalogModel>): void {
  const path = catalogPath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify({ at: new Date().toISOString(), baseUrl, models } satisfies CatalogFile, null, 2)}\n`);
}

/** Pide la lista al servicio y la guarda. Lanza si el servicio no responde o responde vacío. */
export async function fetchCatalog(baseUrl: string, key: string | undefined, fetchImpl: typeof fetch = fetch): Promise<{ items: Array<CatalogItem & { id: string }>; models: Record<string, CatalogModel> }> {
  const response = await fetchImpl(`${baseUrl.replace(/\/$/, "")}/models`, { headers: { ...cabecerasDePrivacidad(), ...(key && { authorization: `Bearer ${key}` }) }, signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const items = (((await response.json()) as { data?: CatalogItem[] }).data ?? []).filter((item): item is CatalogItem & { id: string } => !!item.id);
  if (!items.length) throw new Error("lista vacía");
  const models = parseCatalog(items);
  // Sin clave el servicio lista sólo los abiertos: no se pisa una lectura completa con una parcial.
  const previous = readCatalog();
  const merged = key || !previous || previous.baseUrl !== baseUrl ? models : { ...previous.models, ...models };
  saveCatalog(baseUrl, merged);
  return { items, models: merged };
}
