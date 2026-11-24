// Proveedores intercambiables, configurados en un archivo propio. Las claves nunca se
// guardan: el archivo sólo nombra la variable de entorno que las contiene.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { t } from "./idioma.ts";
import { readSecret, secretState } from "./secretos.ts";
import { anthropicMessages, type Faux, fauxTransport, type Model, openAICompletions, type Rates, type Transport } from "./llm.ts";
import { cachedModels } from "./tarifas.ts";
import { OROBAS_ALIASES } from "./alias-orobas.ts";

interface ProviderConfig {
  baseUrl: string;
  /** Protocolo: Chat Completions compatible con OpenAI (por defecto) o Anthropic Messages. */
  api?: "openai" | "anthropic";
  apiKeyEnv?: string;
  /** Tarifas y límites por modelo. Un modelo sin entrada funciona, con costo pendiente. */
  models?: Record<string, { cost?: Rates; contextWindow?: number; maxTokens?: number; reasoning?: boolean }>;
}

interface Config {
  defaultModel?: string;
  /** Modelo fuerte (deep_reason y delegate con strong), «proveedor/modelo». */
  strongModel?: string;
  /** Modelo medio del router (leer y razonar sobre código, sobre un traspaso), «proveedor/modelo». Opcional. */
  mediumModel?: string;
  providers?: Record<string, ProviderConfig>;
}

const OROBAS_MODEL = { contextWindow: 1048576 };
/**
 * Modelos de la suscripción, con nombres propios (el proveedor que los sirve no se nombra).
 * DeepSeek y su versión estándar están abiertos a todas las cuentas; auto, GLM y Qwen, a las que el
 * servicio habilita. «auto» usa DeepSeek y, si el proveedor falla, pasa a GLM, Qwen o DeepSeek por
 * otro proveedor: su contexto es el del más chico de esa cadena.
 */
const OROBAS_MODELS = {
  auto: { contextWindow: 524288 },
  "deepseek-v4.1-flash": OROBAS_MODEL,
  "deepseek-v4.1-flash-estandar": OROBAS_MODEL,
  "glm-5.3-flash": OROBAS_MODEL,
  "qwen3.8-27b": { contextWindow: 524288 },
};
/** Modelo base cuando el operador todavía no eligió uno. */
export const DEFAULT_BASE_MODEL = "orobas/glm-5.3-flash";
/** Modelo fuerte de fábrica: el que razona a pedido del base (deep_reason, delegate con strong). */
export const DEFAULT_STRONG_MODEL = "orobas/cyber-ultra-1.0";

/** Dirección del servicio de orobas (cuentas, modelos y medición). OROBAS_BASE_URL la cambia para desarrollo. */
export const orobasBaseUrl = () => process.env.OROBAS_BASE_URL || "https://cyber.elevateai.ar/api/v1";

/** Nombres anteriores de los modelos de la suscripción (ver alias-orobas.ts): se traducen al nombre propio. */
let aliases: Record<string, string> = OROBAS_ALIASES;
/** Sustituye la tabla de nombres anteriores (pruebas); sin argumento vuelve a la de fábrica. */
export function configureAliases(map: Record<string, string> = OROBAS_ALIASES): void {
  aliases = map;
}

/** Endpoints conocidos. Las tarifas vienen del catálogo del servicio o de la configuración local. */
const PRESETS: Record<string, ProviderConfig> = {
  // La suscripción: cada persona usa su propia clave (cyber.elevateai.ar/cuenta) y el servicio mide y limita su uso.
  orobas: {
    baseUrl: orobasBaseUrl(),
    apiKeyEnv: "OROBAS_API_KEY",
    models: OROBAS_MODELS,
  },
  openai: { baseUrl: "https://api.openai.com/v1", apiKeyEnv: "OPENAI_API_KEY" },
  anthropic: { baseUrl: "https://api.anthropic.com/v1", apiKeyEnv: "ANTHROPIC_API_KEY", api: "anthropic" },
  deepseek: { baseUrl: "https://api.deepseek.com/v1", apiKeyEnv: "DEEPSEEK_API_KEY" },
  openrouter: { baseUrl: "https://openrouter.ai/api/v1", apiKeyEnv: "OPENROUTER_API_KEY" },
  // En el contenedor 127.0.0.1 es el propio contenedor: Ollama corre en el host.
  get ollama(): ProviderConfig {
    return { baseUrl: `http://${process.env.CYBER_PROYECTO_HOST ? "host.docker.internal" : "127.0.0.1"}:11434/v1` };
  },
};

/** La configuración del operador: la que se lee y la que se escribe (inicio, ajustes, tarifas guardadas). */
export const configPath = () =>
  process.env.CYBER_CONFIG || join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "elevate-cyber", "config.json");

function readJson(path: string): Config {
  try {
    return JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
  } catch (error) {
    throw new Error(`Configuración inválida en ${path}: ${(error as Error).message}`);
  }
}

/** La base de la imagen (CYBER_CONFIG_BASE, de solo lectura) queda debajo de la del usuario: gana el usuario, por proveedor y por modelo. */
function loadConfig(): Config {
  const path = configPath();
  const base = process.env.CYBER_CONFIG_BASE;
  const user = existsSync(path) ? readJson(path) : {};
  if (!base || !existsSync(base)) return user;
  const under = readJson(base);
  const providers: Record<string, ProviderConfig> = { ...under.providers };
  for (const [id, own] of Object.entries(user.providers ?? {})) {
    const below = providers[id];
    providers[id] = below ? { ...below, ...own, ...(below.models || own.models ? { models: { ...below.models, ...own.models } } : {}) } : own;
  }
  return { ...under, ...user, providers };
}

export interface Provider {
  model: Model;
  transport: Transport;
  /** Etiqueta de cuenta para deduplicar solicitudes; no contiene secretos. */
  account: string;
  /** Sólo en modo simulado: cola de respuestas guionadas. */
  faux?: Faux;
}

/** Entorno primero; la clave de orobas también vive en el almacén cifrado. */
export function apiKey(envName: string): string | undefined {
  return process.env[envName] || (envName === "OROBAS_API_KEY" ? readSecret("orobas") : undefined);
}

export const missingKeyMessage = (envName: string) =>
  envName === "OROBAS_API_KEY" && secretState("orobas") === "locked"
    ? t("Tu clave de orobas está cifrada y no tengo la llave del llavero: desbloquealo o borrá la cuenta con /orobas → Revocar", "Your orobas key is encrypted and I do not have the keyring key: unlock it or delete the account with /orobas → Revoke")
    : envName === "OROBAS_API_KEY" ? t("Falta la clave de orobas: usá /orobas", "Missing the orobas key: use /orobas") : `Falta la variable de entorno ${envName}`;

export function resolveProvider(spec?: string): Provider {
  const config = loadConfig();
  // Sin elección del operador, el base de fábrica: barato para el bucle, y el fuerte razona a pedido.
  const chosen = spec || process.env.CYBER_MODEL || config.defaultModel || DEFAULT_BASE_MODEL;
  if (chosen === "faux") {
    const faux = fauxTransport();
    faux.queue.push({ text: "Respuesta simulada." });
    return { model: { provider: "faux", id: "faux", baseUrl: "" }, transport: faux.transport, account: "faux", faux };
  }
  const slash = chosen.indexOf("/");
  if (slash < 1) throw new Error(`Modelo inválido «${chosen}». Formato: proveedor/modelo`);
  const providerId = chosen.slice(0, slash);
  const asked = chosen.slice(slash + 1);
  const modelId = providerId === "orobas" ? (aliases[asked] ?? asked) : asked;
  const declared = config.providers?.[providerId];
  const preset = PRESETS[providerId];
  const served = providerId === "orobas" ? cachedModels() : {};
  // Las tarifas explícitas del operador tienen prioridad sobre las del catálogo.
  const configured = { ...declared?.models };
  if (providerId === "orobas") {
    for (const [alias, id] of Object.entries(aliases)) {
      if (configured[alias]) configured[id] = { ...configured[alias], ...configured[id] };
    }
  }
  const layers = [preset?.models ?? {}, served, configured];
  const ids = [...new Set(layers.flatMap(Object.keys))];
  const known = ids.length ? Object.fromEntries(ids.map((id) => [id, Object.assign({}, ...layers.map((layer) => layer[id] ?? {}))])) : undefined;
  const provider = declared && known ? { ...declared, models: known } : declared ?? (preset && known ? { ...preset, models: known } : preset);
  if (!provider) {
    // Sólo lo que se puede usar ahora: la suscripción y los que el operador configuró (los de fábrica sin clave no valen).
    const usable = [...new Set(["orobas", ...readyProviders()])].map((id) => (id === "orobas" ? "orobas (la suscripción)" : id)).join(", ");
    throw new Error(`Proveedor desconocido «${providerId}». Valen: ${usable}. Para la suscripción escribí orobas/<modelo> (por ejemplo ${DEFAULT_BASE_MODEL}) o sólo el nombre del modelo; otro proveedor se declara, con la variable de su clave, en ${configPath()}.`);
  }
  const info = provider.models?.[modelId];
  const { name: _name, kind: _kind, status: _status, ...fields } = (info ?? {}) as Record<string, unknown>;
  return {
    model: { provider: providerId, id: modelId, baseUrl: provider.baseUrl, apiKeyEnv: provider.apiKeyEnv, ...fields, ...(info?.cost ? { costSource: served[modelId]?.cost === info.cost ? "servicio" : "configuración" } : {}) } as Model,
    transport: provider.api === "anthropic" ? anthropicMessages : openAICompletions,
    account: provider.apiKeyEnv ?? "sin-clave",
  };
}

/**
 * Modelo fuerte cuando el operador no eligió uno en la sesión: $CYBER_STRONG_MODEL, «strongModel» de la
 * configuración o, con la suscripción, el de fábrica. Con otro proveedor, el mismo modelo del bucle
 * (deep_reason sigue sirviendo como consulta con el contexto limpio).
 */
export function defaultStrongModel(main: { provider: string; id: string }): string {
  let configured: string | undefined;
  try { configured = loadConfig().strongModel; } catch { /* configuración ilegible: la de fábrica */ }
  const chosen = process.env.CYBER_STRONG_MODEL || configured;
  if (chosen) return chosen;
  return main.provider === "orobas" ? DEFAULT_STRONG_MODEL : `${main.provider}/${main.id}`;
}

/** Modelo medio del router, si el operador lo configuró ($CYBER_MEDIUM_MODEL o «mediumModel»); sin esto no hay rol medio. */
export function defaultMediumModel(): string | undefined {
  let configured: string | undefined;
  try { configured = loadConfig().mediumModel; } catch { /* configuración ilegible: sin medio */ }
  return process.env.CYBER_MEDIUM_MODEL || configured || undefined;
}

/** Línea de MODELO de la vista de herramientas: ✓ o ✗ según haya clave en alguna parte. */
export function modelLine(spec?: string): string {
  try {
    const { model } = resolveProvider(spec);
    const name = `${model.provider}/${model.id}`;
    const env = model.apiKeyEnv;
    if (!env) return `✓ ${name}`;
    if (process.env[env]) return `✓ ${name} · ${t(`clave en $${env} presente`, `key in $${env} present`)}`;
    if (apiKey(env)) return `✓ ${name} · ${t("clave guardada", "key stored")}`;
    return `✗ ${name} · ${missingKeyMessage(env)}`;
  } catch (error) {
    return `✗ ${(error as Error).message}`;
  }
}

/** Modelos conocidos de un proveedor: los del preset y los declarados en la configuración. */
export function providerModels(providerId: string): string[] {
  const declared = loadConfig().providers?.[providerId]?.models ?? {};
  const preset = PRESETS[providerId]?.models ?? {};
  const served = providerId === "orobas" ? cachedModels() : {};
  const names = [...Object.keys(preset), ...Object.keys(served), ...Object.keys(declared)].map((id) => (providerId === "orobas" ? (aliases[id] ?? id) : id));
  return [...new Set(names)];
}

/** Los de fábrica que no piden clave (un servidor local, como Ollama): se pueden elegir sin declararlos. */
export function keylessPresets(): string[] {
  return Object.keys(PRESETS).filter((id) => !PRESETS[id]!.apiKeyEnv);
}

/** Proveedores que se pueden usar ahora: declarados o conocidos, con su clave presente si la necesitan. */
export function readyProviders(): string[] {
  const declared = loadConfig().providers ?? {};
  return [...new Set([...Object.keys(PRESETS), ...Object.keys(declared)])].filter((id) => {
    const provider = declared[id] ?? PRESETS[id]!;
    // Uno sin clave (un servidor local) cuenta sólo si el operador lo declaró.
    return provider.apiKeyEnv ? !!apiKey(provider.apiKeyEnv) : id in declared;
  });
}
