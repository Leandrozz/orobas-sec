// Qué pide cada modelo (decisión de Lean, 22/11/2026, que reemplaza la tabla de niveles del 15/11):
//   · los de la suscripción (proveedor orobas): cuenta de orobas con la identidad verificada (Didit, nivel
//     «basica» o más). El servicio lo exige en cada pedido (403 identity_required); acá se avisa antes, claro;
//   · todo lo que no es nuestro (modelos locales y cualquier API con clave propia): nada. Ni cuenta ni
//     verificación: la clave es de quien la usa y el modelo corre donde él quiera.
// El nivel lo dice el servicio (GET /api/v1/cuenta) y se recuerda un rato. Si no se puede consultar, el pedido
// sigue y decide el servicio, que es quien manda: la consulta sólo sirve para dar un mensaje claro.
import { anotarModoCuenta, cabecerasDePrivacidad, leerModo, type ModoTrazas } from "./privacidad-trazas.ts";
import { t } from "./idioma.ts";
import { apiKey, orobasBaseUrl } from "./providers.ts";

export const LEVELS = ["ninguna", "basica", "completa"] as const;
export type Level = (typeof LEVELS)[number];
export const atLeast = (level: Level, target: Level) => LEVELS.indexOf(level) >= LEVELS.indexOf(target);

/** ¿El modelo es de la suscripción de orobas? Son los únicos que piden cuenta. */
export const isSubscription = (model: { provider: string }) => model.provider === "orobas";

/**
 * Nivel que pide un modelo. `null`: no pide cuenta ni verificación (modelos locales, claves propias de
 * cualquier proveedor y el modo simulado).
 */
export function requiredLevel(model: { provider: string; baseUrl: string }): Level | null {
  return isSubscription(model) ? "basica" : null;
}

export interface AccountInfo {
  name: string;
  verification: Level;
  plan: string | null;
  tier_usd: number;
  /** El modo de trazas de la cuenta, si el servicio lo informa: rige el más restrictivo con el local. */
  trazas?: ModoTrazas;
}

const TTL_MS = 10 * 60_000;
const ERROR_TTL_MS = 30_000;
let cache: { key: string; at: number; result: AccountInfo | { error: string } } | undefined;
let fetcher: typeof fetch = fetch;

/** Sustituye el fetch (pruebas) y olvida lo recordado. */
export function configureAccount(options: { fetch?: typeof fetch } = {}): void {
  fetcher = options.fetch ?? fetch;
  cache = undefined;
  anotarModoCuenta(undefined);
}
export const forgetAccount = () => { cache = undefined; anotarModoCuenta(undefined); };
/** Olvida el nivel recordado, no el modo de trazas que informó la cuenta: ése sigue rigiendo hasta la próxima consulta. */
const olvidarNivel = () => { cache = undefined; };

/** La cuenta detrás de la clave de orobas, según el servicio. Recordada 10 minutos; un fallo, 30 segundos. */
export async function fetchAccount(key: string): Promise<AccountInfo | { error: string }> {
  const now = Date.now();
  if (cache && cache.key === key && now - cache.at < ("error" in cache.result ? ERROR_TTL_MS : TTL_MS)) return cache.result;
  let result: AccountInfo | { error: string };
  try {
    const response = await fetcher(`${orobasBaseUrl().replace(/\/$/, "")}/cuenta`, { headers: { ...cabecerasDePrivacidad(), authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(8000) });
    const body = (await response.json().catch(() => ({}))) as Partial<AccountInfo> & { error?: { message?: string } };
    if (!response.ok) result = { error: body.error?.message ?? `el servicio respondió ${response.status}` };
    else if (!LEVELS.includes(body.verification as Level)) result = { error: "respuesta del servicio sin nivel de verificación" };
    else {
      result = { name: String(body.name ?? ""), verification: body.verification as Level, plan: body.plan ?? null, tier_usd: Number(body.tier_usd ?? 0), ...(leerModo(body.trazas) ? { trazas: leerModo(body.trazas) } : {}) };
      anotarModoCuenta(result.trazas);
    }
  } catch (error) {
    result = { error: (error as Error).name === "TimeoutError" ? "no respondió a tiempo" : "no se pudo conectar" };
  }
  cache = { key, at: now, result };
  return result;
}

/**
 * Relee la cuenta (recordada 10 minutos) para saber su modo de trazas. Sin clave o sin servicio no hace
 * nada: rige el modo local. Nunca tira.
 */
export async function refrescarModoCuenta(): Promise<ModoTrazas | undefined> {
  const key = apiKey("OROBAS_API_KEY");
  if (!key) return undefined;
  const account = await fetchAccount(key).catch(() => undefined);
  return account && !("error" in account) ? account.trazas : undefined;
}

const PORTAL = "cyber.elevateai.ar/cuenta";

/**
 * Puerta de cuenta antes de cada solicitud a un modelo: devuelve el motivo del rechazo, o nada si puede seguir.
 * Es la misma para el agente, los subagentes y el verificador, porque todos pasan por los transportes.
 */
export async function accountGate(model: { provider: string; baseUrl: string }): Promise<string | undefined> {
  const need = requiredLevel(model);
  if (need === null) return undefined;
  const key = apiKey("OROBAS_API_KEY");
  if (!key) {
    return t(`Los modelos de la suscripción (orobas/…) piden tu cuenta: usá /orobas con tu clave de ${PORTAL}. Los modelos locales y tus propias claves funcionan sin cuenta.`,
      `Subscription models (orobas/…) need your account: use /orobas with your key from ${PORTAL}. Local models and your own keys work without an account.`);
  }
  const account = await fetchAccount(key);
  // Sin respuesta del servicio, el pedido sigue: el servicio exige la identidad en cada pedido y contesta él.
  if ("error" in account) return undefined;
  if (atLeast(account.verification, need)) return undefined;
  // Rechazado: no recordar el nivel, así apenas la persona verifica, el próximo pedido ya pasa. El modo de trazas
  // de la cuenta (#39) se conserva: si pidió «no», el registro del turno no tiene que salir mientras tanto.
  olvidarNivel();
  return t(`Los modelos de la suscripción (orobas/…) piden la identidad verificada, y tu cuenta todavía está sin verificar. Verificala en ${PORTAL} (se habilita con el pago del plan) y volvé a mandar el mensaje. Mientras tanto podés usar un modelo local o tus propias claves (/modelo), que no la piden.`,
    `Subscription models (orobas/…) require a verified identity, and your account is not verified yet. Verify it at ${PORTAL} (it unlocks once the plan is paid) and send the message again. Meanwhile you can use a local model or your own keys (/model), which do not require it.`);
}
