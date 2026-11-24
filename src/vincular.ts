// Vincular el agente a la cuenta entrando al sitio, sin pegar claves: el servicio da un código corto,
// la persona lo aprueba en cyber.elevateai.ar/vincular con su llave, y el agente recibe una clave
// nueva una sola vez (flujo de dispositivo, como «gh auth login»). La clave queda cifrada en la
// carpeta de credenciales, como si se hubiera pegado.
import { cabecerasDePrivacidad } from "./privacidad-trazas.ts";
import { orobasBaseUrl } from "./providers.ts";

export interface DeviceStart {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export type DeviceOutcome =
  | { state: "listo"; key: string; name?: string | null; verification?: string | null }
  | { state: "denegado" | "vencido" | "sin_cupo" | "cancelado"; detail: string };

const base = () => orobasBaseUrl().replace(/\/$/, "");

export async function startDeviceLink(client: string, fetchImpl: typeof fetch = fetch): Promise<DeviceStart> {
  const response = await fetchImpl(`${base()}/dispositivo`, {
    method: "POST", headers: { ...cabecerasDePrivacidad(), "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ client }), signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`El servicio no pudo dar un código (HTTP ${response.status}). Probá de nuevo en un momento, o pegá una clave de cyber.elevateai.ar/cuenta.`);
  const data = (await response.json()) as Partial<DeviceStart>;
  if (!data.device_code || !data.user_code || !data.verification_uri) throw new Error("El servicio devolvió una respuesta incompleta para la vinculación.");
  return { device_code: data.device_code, user_code: data.user_code, verification_uri: data.verification_uri, verification_uri_complete: data.verification_uri_complete ?? data.verification_uri, expires_in: data.expires_in ?? 900, interval: data.interval ?? 5 };
}

/** Pregunta cada `interval` segundos hasta que la persona aprueba, rechaza, el código vence o se cancela. */
export async function waitDeviceKey(start: DeviceStart, options: { fetchImpl?: typeof fetch; signal?: AbortSignal; sleep?: (ms: number) => Promise<void> } = {}): Promise<DeviceOutcome> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const deadline = Date.now() + start.expires_in * 1000;
  let interval = Math.max(1, start.interval) * 1000;
  while (Date.now() < deadline) {
    if (options.signal?.aborted) return { state: "cancelado", detail: "Cancelado." };
    await sleep(interval);
    if (options.signal?.aborted) return { state: "cancelado", detail: "Cancelado." };
    let response: Response;
    try {
      response = await fetchImpl(`${base()}/dispositivo/clave`, {
        method: "POST", headers: { ...cabecerasDePrivacidad(), "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ device_code: start.device_code }), signal: AbortSignal.timeout(15_000),
      });
    } catch { continue; } // sin red un rato: se sigue esperando
    if (response.status === 428) continue;
    if (response.status === 429) { interval += 2000; continue; }
    if (response.status === 410) return { state: "vencido", detail: "El código venció sin aprobarse. Pedí otro." };
    if (response.status === 409) return { state: "sin_cupo", detail: "Tu cuenta ya tiene el máximo de claves activas: revocá una en cyber.elevateai.ar/cuenta y volvé a vincular." };
    if (response.status === 403) return { state: "denegado", detail: "El código fue rechazado o ya se usó." };
    if (!response.ok) continue;
    const data = (await response.json()) as { api_key?: string; name?: string | null; verification?: string | null };
    if (!data.api_key) return { state: "denegado", detail: "El servicio no devolvió la clave." };
    return { state: "listo", key: data.api_key, name: data.name, verification: data.verification };
  }
  return { state: "vencido", detail: "El código venció sin aprobarse. Pedí otro." };
}
