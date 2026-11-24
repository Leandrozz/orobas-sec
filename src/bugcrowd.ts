// Bugcrowd e Intigriti: alcance de programas por API. Bugcrowd usa la Disclosure API (token por
// cabecera); Intigriti, client credentials de investigador (OAuth client_credentials). Las
// credenciales viven en variables de entorno (CI) o en el almacén cifrado del usuario, nunca en el
// chat. Lo que importa acá es lo mismo que en HackerOne: activos elegibles dentro, no elegibles
// fuera, y el aviso de que la lista de activos no reemplaza la lectura de la política del programa.
import { avisoDeCabeceras, textoDePolitica } from "./politica-cabeceras.ts";
import { readSecret } from "./secretos.ts";
import { parseRule, scopeView, type ScopeRule, type ScopeStore } from "./scope.ts";

export interface BBProgram {
  handle: string;
  name: string;
  estado: string;
  paga: boolean;
}

export interface BBScope {
  include: ScopeRule[];
  exclude: ScopeRule[];
  saltados: string[];
  avisoCabeceras?: string;
}

/** Token de Bugcrowd: env primero, después el almacén cifrado. */
export function bugcrowdToken(): string | undefined {
  return process.env.BGC_API_TOKEN ?? readSecret("bugcrowd");
}

/** Credenciales de Intigriti: env primero, después el almacén cifrado («clientId:clientSecret»). */
export function intigritiCredentials(): { clientId: string; clientSecret: string } | undefined {
  if (process.env.INTIGRITI_CLIENT_ID && process.env.INTIGRITI_CLIENT_SECRET) return { clientId: process.env.INTIGRITI_CLIENT_ID, clientSecret: process.env.INTIGRITI_CLIENT_SECRET };
  const saved = readSecret("intigriti");
  if (!saved || !saved.includes(":")) return undefined;
  const [clientId, clientSecret] = saved.split(":", 2);
  return clientId && clientSecret ? { clientId, clientSecret } : undefined;
}

async function json(url: string, headers: Record<string, string>, fetchImpl: typeof fetch, signal?: AbortSignal): Promise<any> {
  const response = await fetchImpl(url, { headers: { accept: "application/json", ...headers }, signal });
  if (!response.ok) throw new Error(`La API respondió HTTP ${response.status} para ${url.replace("https://api.", "")}`);
  return response.json();
}

/** Un activo del programa: string o objeto con nombre, elegibilidad y nota. */
function assetRule(target: any): { value: string; dentro: boolean; nota?: string } | undefined {
  const identifier = String(typeof target === "string" ? target : (target?.name ?? target?.target ?? target?.identifier ?? "")).trim();
  if (!identifier) return undefined;
  const dentro = target?.in_scope === false || target?.eligible === false ? false : true;
  const descripcion = textoDePolitica(target?.description);
  const detalle = [target?.category, descripcion].filter(Boolean).join(" · ").replace(/\s+/g, " ").slice(0, 120);
  const note = [avisoDeCabeceras(descripcion), detalle].filter(Boolean).join(" · ") || undefined;
  return { value: identifier, dentro, nota: note };
}

/** Programas de Bugcrowd visibles con el token (Disclosure API). */
export async function bugcrowdPrograms(token: string, fetchImpl: typeof fetch = fetch, signal?: AbortSignal): Promise<BBProgram[]> {
  const body = await json("https://api.bugcrowd.com/disclosures/programs", { authorization: `Token ${token}` }, fetchImpl, signal);
  const items = Array.isArray(body) ? body : (body?.programs ?? body?.data ?? []);
  return (items as any[]).slice(0, 200).map((program) => ({
    handle: String(program?.handle ?? program?.id ?? ""),
    name: String(program?.name ?? program?.title ?? "").slice(0, 60),
    estado: String(program?.status ?? ""),
    paga: !!program?.rewards?.length || !!program?.bounty,
  }));
}

/** Alcance de un programa de Bugcrowd. Estructura tolerante: los activos aparecen bajo claves distintas según la versión de la API. */
export async function bugcrowdScope(token: string, handle: string, fetchImpl: typeof fetch = fetch, signal?: AbortSignal): Promise<BBScope> {
  if (!/^[a-z0-9._-]+$/i.test(handle)) throw new Error("Identificador de programa inválido");
  const body = await json(`https://api.bugcrowd.com/disclosures/programs/${encodeURIComponent(handle)}`, { authorization: `Token ${token}` }, fetchImpl, signal);
  const brief = body?.data ?? body;
  const targets = brief?.targets ?? brief?.in_scope ?? brief?.assets ?? [];
  const include: ScopeRule[] = [];
  const exclude: ScopeRule[] = [];
  const saltados: string[] = [];
  for (const raw of Array.isArray(targets) ? targets : []) {
    const asset = assetRule(raw);
    if (!asset) continue;
    try {
      (asset.dentro ? include : exclude).push(parseRule(asset.value, asset.dentro ? asset.nota : `no elegible${asset.nota ? ` · ${asset.nota}` : ""}`));
    } catch { saltados.push(asset.value.slice(0, 60)); }
  }
  const avisoCabeceras = avisoDeCabeceras(brief?.policy, brief?.description);
  return { include, exclude, saltados, ...(avisoCabeceras ? { avisoCabeceras } : {}) };
}

/** Token de acceso de Intigriti (client_credentials: es una credencial de máquina, no un usuario). */
export async function intigritiToken(credentials: { clientId: string; clientSecret: string }, fetchImpl: typeof fetch = fetch, signal?: AbortSignal): Promise<string> {
  const response = await fetchImpl("https://api.intigriti.com/external/authentication/v1/token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ client_id: credentials.clientId, client_secret: credentials.clientSecret, grant_type: "client_credentials", scope: "external_api" }),
    signal,
  });
  if (!response.ok) throw new Error(`Intigriti rechazó las credenciales (HTTP ${response.status}).`);
  const body = await response.json() as { access_token?: string; token?: string };
  const token = body.access_token ?? body.token;
  if (!token) throw new Error("Intigriti no devolvió token");
  return token;
}

/** Programas de Intigriti accesibles por el investigador. */
export async function intigritiPrograms(token: string, fetchImpl: typeof fetch = fetch, signal?: AbortSignal): Promise<BBProgram[]> {
  const body = await json("https://api.intigriti.com/external/researcher/v1/programs", { authorization: `Bearer ${token}` }, fetchImpl, signal);
  return (Array.isArray(body) ? body : (body?.records ?? [])).map((program: any) => ({
    handle: String(program?.id ?? program?.handle ?? ""),
    name: String(program?.name ?? "").slice(0, 60),
    estado: String(program?.status ?? ""),
    paga: program?.maxBounty !== undefined || program?.minBounty !== undefined,
  })).slice(0, 200);
}

/** Alcance de un programa de Intigriti: los activos llegan como `endpoints` con su tipo y severidad máxima. */
export async function intigritiScope(token: string, handle: string, fetchImpl: typeof fetch = fetch, signal?: AbortSignal): Promise<BBScope> {
  const body = await json(`https://api.intigriti.com/external/researcher/v1/programs/${encodeURIComponent(handle)}`, { authorization: `Bearer ${token}` }, fetchImpl, signal);
  const program = Array.isArray(body) ? body.at(-1) : body;
  const include: ScopeRule[] = [];
  const exclude: ScopeRule[] = [];
  const saltados: string[] = [];
  for (const endpoint of program?.endpoints ?? []) {
    const value = String(endpoint?.uri ?? endpoint?.name ?? "").trim();
    if (!value) continue;
    const dentro = endpoint?.type === undefined || /inscope|in_scope/i.test(String(endpoint?.type ?? ""));
    const detalle = [endpoint?.type, textoDePolitica(endpoint?.weblogic)].filter(Boolean).join(" · ").slice(0, 120);
    const note = [avisoDeCabeceras(endpoint?.description, endpoint?.weblogic), detalle].filter(Boolean).join(" · ") || undefined;
    try {
      (dentro ? include : exclude).push(parseRule(value, note));
    } catch { saltados.push(value.slice(0, 60)); }
  }
  const avisoCabeceras = avisoDeCabeceras(program?.policy, program?.rulesOfEngagement, program?.description);
  return { include, exclude, saltados, ...(avisoCabeceras ? { avisoCabeceras } : {}) };
}

/** Líneas de vista de programas, mismo formato que programLines de HackerOne. */
export function programLines(programs: BBProgram[], plataforma: string): string[] {
  if (!programs.length) return [`${plataforma}: tu cuenta no devuelve programas por la API (o no hay credenciales cargadas).`];
  return [
    `${plataforma.toUpperCase()} · ${programs.length} programas`,
    ...programs.slice(0, 60).map((program: BBProgram) => `${program.handle.padEnd(28)} ${(program.paga ? "paga" : "sin pago").padEnd(9)} ${program.estado.padEnd(10)} ${program.name.slice(0, 44)}`),
  ];
}

/** Importa el alcance de una plataforma distinta de HackerOne como revisión nueva del alcance. */
export async function importBBScope(platform: "bugcrowd" | "intigriti", scope: BBScope, store: ScopeStore, handle: string): Promise<string[]> {
  if (!scope.include.length) throw new Error(`El programa ${handle} no tiene activos de red elegibles en su alcance.`);
  const notes = [
    `Programa ${platform} «${handle}». Leé la política completa del programa antes de probar: esta lista es sólo la de activos.`,
    scope.avisoCabeceras,
  ].filter(Boolean).join("\n");
  const { saved, kept } = store.saveProgram({
    source: `${platform}:${handle}`, include: scope.include, exclude: scope.exclude, notes,
  });
  return [
    `Alcance importado de ${platform} «${handle}»: ${scope.include.length} dentro, ${scope.exclude.length} excluidos (rev ${saved.rev}).`,
    ...(kept.length ? [`Conservé del alcance anterior los destinos locales (laboratorio): ${kept.map((rule) => rule.value).join(", ")}. Si ya no van: /alcance quitar <regla>.`] : []),
    ...(scope.saltados.length ? [`No importados (${scope.saltados.length}): ${scope.saltados.slice(0, 6).join(" · ")}`] : []),
    "",
    ...scopeView(saved),
  ];
}