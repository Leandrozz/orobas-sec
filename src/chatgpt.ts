// Sign in with ChatGPT para clientes locales de código abierto.
// Las credenciales y el identificador del cliente viven sólo en el almacén cifrado.
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { credentialsDir, readSecret, secretState, writeSecret } from "./secretos.ts";

export const MANAGE_USAGE = "https://chatgpt.com/settings/usage";
export const CHATGPT_SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const RESOURCE = "https://api.openai.com/v1";
const SECRET = "chatgpt";
const MARGIN = 5 * 60_000;
/** Pausa tras un tope de uso si OpenAI no manda Retry-After, y techo para un Retry-After desmedido. */
const LIMIT_PAUSE = 15 * 60_000;
const LIMIT_MAX = 7 * 24 * 3600_000;
const TERMINAL_REFRESH = new Set(["invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused"]);

const localEndpoint = (name: string, official: string) => {
  const override = process.env[name];
  if (!override) return official;
  const url = new URL(override);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port || url.username || url.password) throw new Error(name + " sólo admite un servidor de prueba en 127.0.0.1.");
  return override.replace(/\/$/, "");
};
export const chatgptIssuer = () => localEndpoint("CHATGPT_AUTH_URL", "https://auth.openai.com");
export const chatgptBaseUrl = () => localEndpoint("CHATGPT_BASE_URL", RESOURCE);

interface Tokens {
  access: string;
  refresh: string;
  id: string;
  scopes: string[];
  expiresAt: number;
}
interface Account {
  clientId: string;
  subject: string;
  email?: string;
  tokens?: Tokens;
  models?: Array<{ slug: string; name: string }>;
  modelsAt?: number;
  /** Hasta cuándo (ms) no se mandan pedidos tras un tope de uso; vencido, el pedido sale. */
  limitUntil?: number;
}
interface Stored {
  v: 1;
  hostId: string;
  noticeAccepted?: boolean;
  welcomeShown?: boolean;
  active?: string;
  accounts: Account[];
}
interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  revocation_endpoint: string;
  jwks_uri: string;
}
const empty = (): Stored => ({ v: 1, hostId: "urn:uuid:" + randomUUID(), accounts: [] });
function readStored(): Stored | undefined {
  const raw = readSecret(SECRET);
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw) as Stored;
    return parsed.v === 1 && typeof parsed.hostId === "string" && Array.isArray(parsed.accounts) ? parsed : undefined;
  } catch { return undefined; }
}
function save(value: Stored): void {
  writeSecret(SECRET, JSON.stringify(value), { requireEncryption: true });
}
function stored(): Stored {
  const value = readStored();
  if (value) return value;
  if (secretState(SECRET) === "locked") throw new Error("El llavero de ChatGPT está bloqueado.");
  const fresh = empty();
  save(fresh);
  return fresh;
}
const active = (value: Stored): Account | undefined => value.accounts.find((account) => account.clientId === value.active);
const usable = (account?: Account): boolean => !!account?.tokens?.scopes.includes("chatgpt.tokens.use.direct");
const safeCode = (raw: unknown): string => typeof raw === "string" ? raw.replace(/[^a-z0-9_]/gi, "").slice(0, 64) : "";
const errorCode = (body: any): string => safeCode(typeof body?.error === "string" ? body.error : body?.error?.code ?? body?.code);
const json = async (response: Response): Promise<any> => response.json().catch(() => ({}));
const limitedUntil = (account?: Account): number | undefined => account?.limitUntil !== undefined && account.limitUntil > Date.now() ? account.limitUntil : undefined;
const when = (ms: number): string => {
  const date = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  const time = pad(date.getHours()) + ":" + pad(date.getMinutes());
  return ms - Date.now() > 12 * 3600_000 ? "el " + pad(date.getDate()) + "/" + pad(date.getMonth() + 1) + " a las " + time : "las " + time;
};

export function chatgptState(): { linked: boolean; locked: boolean; email?: string; clientId?: string; scopeDisabled?: boolean; limitReached?: boolean; limitUntil?: number; accounts: Array<{ clientId: string; email?: string; linked: boolean; active: boolean }> } {
  const locked = secretState(SECRET) === "locked";
  const value = locked ? undefined : readStored();
  const account = value && active(value);
  const until = limitedUntil(account);
  return {
    linked: usable(account), locked,
    ...(account?.email ? { email: account.email } : {}),
    ...(account ? { clientId: account.clientId, scopeDisabled: !!account.tokens && !usable(account), limitReached: !!until, ...(until ? { limitUntil: until } : {}) } : {}),
    accounts: (value?.accounts ?? []).map((item) => ({ clientId: item.clientId, ...(item.email ? { email: item.email } : {}), linked: usable(item), active: item.clientId === value?.active })),
  };
}
export const chatgptLinked = () => chatgptState().linked;
export const chatgptCatalog = () => active(readStored() ?? empty())?.models ?? [];
export const noticePending = () => !readStored()?.noticeAccepted;
export async function acceptNotice(): Promise<void> {
  await update((value) => { value.noticeAccepted = true; });
}
export const noticeLines = () => [
  "Continue with ChatGPT usa el flujo oficial de OpenAI. Los pedidos elegibles a la API Responses usarán tu plan de ChatGPT.",
  "Se aplican los términos de OpenAI: https://openai.com/policies/terms-of-use/. Podés revisar y administrar el uso en " + MANAGE_USAGE + ".",
];

async function discovery(fetcher: typeof fetch): Promise<Discovery> {
  const response = await fetcher(chatgptIssuer() + "/.well-known/openid-configuration", { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error("No pude consultar la configuración OAuth de OpenAI.");
  const body = await json(response) as Discovery;
  if (body.issuer !== chatgptIssuer() || !["authorization_endpoint", "token_endpoint", "revocation_endpoint", "jwks_uri"].every((key) => {
    const url = body[key as keyof Discovery];
    return typeof url === "string" && new URL(url).origin === new URL(body.issuer).origin;
  })) throw new Error("La configuración OAuth no corresponde al emisor esperado.");
  return body;
}

function idClaims(token: string, keys: any, issuer: string, clientId: string, nonce?: string): { sub: string; email?: string } {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("ID token inválido.");
  let header: any;
  let payload: any;
  try {
    header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
  } catch { throw new Error("ID token inválido."); }
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("Firma del ID token no admitida.");
  const jwk = keys?.keys?.find((item: any) => item.kid === header.kid && item.kty === "RSA" && (!item.use || item.use === "sig"));
  if (!jwk || !verify("RSA-SHA256", Buffer.from(parts[0] + "." + parts[1]), createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(parts[2]!, "base64url"))) throw new Error("Firma del ID token inválida.");
  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== issuer || !(payload.aud === clientId || Array.isArray(payload.aud) && payload.aud.includes(clientId)) || Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== clientId || typeof payload.exp !== "number" || payload.exp <= now || typeof payload.sub !== "string" || !payload.sub || (nonce !== undefined && payload.nonce !== nonce)) throw new Error("Identidad del ID token inválida.");
  return { sub: payload.sub, ...(typeof payload.email === "string" ? { email: payload.email } : {}) };
}

async function verifiedIdentity(token: string, endpoints: Discovery, clientId: string, nonce: string | undefined, fetcher: typeof fetch) {
  const response = await fetcher(endpoints.jwks_uri, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error("No pude verificar la firma de OpenAI.");
  return idClaims(token, await json(response), endpoints.issuer, clientId, nonce);
}

interface Pending {
  url: string;
  wait: Promise<string[]>;
  settled: boolean;
  cancel: () => void;
}
let pending: Pending | undefined;
let bridgeCallback: ((request: IncomingMessage, response: ServerResponse) => void) | undefined;
/** Una URL malformada (p. ej. «http://[::1/…») no debe tirar una excepción sin capturar en el servidor. */
const requestUrl = (request: IncomingMessage): URL | undefined => {
  try { return new URL(request.url ?? "/", "http://127.0.0.1"); } catch { return undefined; }
};

/** El puente del navegador comparte su puerto publicado con el callback OAuth dentro del contenedor. */
export function handleChatgptCallback(request: IncomingMessage, response: ServerResponse): boolean {
  if (!bridgeCallback || requestUrl(request)?.pathname !== "/auth/callback") return false;
  bridgeCallback(request, response);
  return true;
}

/** Inicia el listener antes de construir el enlace; no escribe ni muestra tokens. */
export async function beginChatgptLogin(options: { fetch?: typeof fetch; newAccount?: boolean; openBrowser?: (url: string) => void } = {}): Promise<string[]> {
  if (noticePending()) throw new Error("Leé el aviso sobre los términos de OpenAI antes de continuar.");
  // Un ingreso nuevo reemplaza al pendiente: un enlace abandonado no bloquea el siguiente.
  if (pending && !pending.settled) pending.cancel();
  pending = undefined;
  const value = readStored() ?? await withLock(async () => stored());
  const selected = options.newAccount ? undefined : active(value);
  const fetcher = options.fetch ?? fetch;
  const endpoints = await discovery(fetcher);
  const state = randomBytes(32).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  let finish!: (result: { query?: URLSearchParams; error?: string }) => void;
  const callback = new Promise<{ query?: URLSearchParams; error?: string }>((resolve) => { finish = resolve; });
  const handleCallback = (request: IncomingMessage, response: ServerResponse) => {
    const url = requestUrl(request);
    if (!url) { response.writeHead(400, { "content-type": "text/plain" }).end("Pedido inválido."); return; }
    if (request.method !== "GET" || url.pathname !== "/auth/callback") { response.writeHead(404).end(); return; }
    // Un state ajeno o ausente se rechaza sin cortar el ingreso: sólo el callback válido lo termina.
    if (url.searchParams.get("state") !== state) {
      response.writeHead(400, { "content-type": "text/plain" }).end("Estado OAuth inválido.");
      return;
    }
    response.writeHead(200, { "content-type": "text/plain" }).end("Podés volver a orobas-sec.");
    finish({ query: url.searchParams });
  };
  const inContainer = !!process.env.CYBER_PROYECTO_HOST;
  const published = Number(process.env.CYBER_PUERTO_HOST);
  if (inContainer && (!Number.isInteger(published) || published < 1 || published > 65535)) throw new Error("Falta el puerto local del navegador: actualizá el lanzador de cyber.");
  const server = inContainer ? undefined : createServer(handleCallback);
  let port = published;
  if (inContainer) {
    const { chromeBridge } = await import("./chrome.ts");
    await chromeBridge().start();
    bridgeCallback = handleCallback;
  } else {
    try {
      await new Promise<void>((resolve, reject) => {
        server!.once("error", reject);
        server!.listen(0, "127.0.0.1", () => { server!.off("error", reject); resolve(); });
      });
    } catch (error) { server!.close(); throw error; }
    const address = server!.address();
    if (!address || typeof address === "string") throw new Error("No pude abrir el callback local.");
    port = address.port;
  }
  const redirect = "http://127.0.0.1:" + port + "/auth/callback";
  const url = new URL(endpoints.authorization_endpoint);
  url.search = new URLSearchParams({
    client_id: selected?.clientId ?? "dynamic_agent_client",
    ext_agent_host_id: value.hostId,
    response_type: "code",
    redirect_uri: redirect,
    scope: CHATGPT_SCOPES,
    resource: RESOURCE,
    state, nonce,
    code_challenge_method: "S256",
    code_challenge: challenge,
    ...(selected ? { login_hint: selected.email ?? "" } : { agent_name_hint: "orobas-sec" }),
    ...(selected?.tokens && !usable(selected) ? { prompt: "consent" } : {}),
  }).toString();
  const timer = setTimeout(() => finish({ error: "Terminó la espera del ingreso a ChatGPT." }), 180_000);
  let entry: Pending | undefined;
  const wait = (async () => {
    try {
      const result = await callback;
      if (result.error) throw new Error(result.error);
      const query = result.query!;
      if (query.has("error")) throw new Error("OpenAI rechazó el permiso: " + safeCode(query.get("error")));
      const clientId = selected?.clientId ?? query.get("client_id") ?? "";
      if (!/^oaiapp_[A-Za-z0-9_-]+$/.test(clientId) || selected && query.has("client_id") && query.get("client_id") !== selected.clientId) throw new Error("El registro devolvió otro cliente OAuth.");
      const code = query.get("code");
      if (!code) throw new Error("El callback no trajo un código.");
      const response = await fetcher(endpoints.token_endpoint, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: redirect, resource: RESOURCE }),
        signal: AbortSignal.timeout(20_000),
      });
      const body = await json(response);
      if (!response.ok) throw new Error("OpenAI rechazó el intercambio OAuth: " + (errorCode(body) || String(response.status)));
      if (typeof body.access_token !== "string" || !body.access_token || typeof body.refresh_token !== "string" || !body.refresh_token || typeof body.id_token !== "string" || !body.id_token || typeof body.scope !== "string" || !(Number(body.expires_in) > 0) || String(body.token_type).toLowerCase() !== "bearer") throw new Error("La respuesta OAuth está incompleta.");
      const identity = await verifiedIdentity(body.id_token, endpoints, clientId, nonce, fetcher);
      if (selected && identity.sub !== selected.subject) throw new Error("Ingresaste con otra cuenta; la sesión anterior sigue intacta.");
      // El guardado del ingreso también toma el candado: no pisa una renovación en curso.
      return await withLock(async () => {
        const next = stored();
        const current = next.accounts.find((item) => item.clientId === clientId);
        if (current && current.subject !== identity.sub) throw new Error("El cliente OAuth ya pertenece a otra identidad.");
        const account: Account = {
          ...current, clientId, subject: identity.sub,
          ...(identity.email ? { email: identity.email } : {}),
          tokens: { access: body.access_token, refresh: body.refresh_token, id: body.id_token, scopes: body.scope.split(/\s+/).filter(Boolean), expiresAt: Date.now() + Number(body.expires_in) * 1000 },
        };
        delete account.limitUntil;
        next.accounts = [...next.accounts.filter((item) => item.clientId !== clientId), account];
        next.active = clientId;
        const welcome = usable(account) && !next.welcomeShown;
        if (welcome) next.welcomeShown = true;
        save(next);
        return usable(account)
          ? [welcome ? "Conectado con ChatGPT. Estás usando tu plan de ChatGPT para los pedidos elegibles." : "Conectado con ChatGPT" + (account.email ? " (" + account.email + ")" : "") + ".", "Usá chatgpt/<modelo> para elegir un modelo.", "Manage usage: " + MANAGE_USAGE]
          : ["Conectado, pero falta el permiso para usar tu plan. Volvé a entrar y habilitá el uso del plan.", "Manage usage: " + MANAGE_USAGE];
      });
    } finally {
      clearTimeout(timer);
      server?.close();
      if (bridgeCallback === handleCallback) bridgeCallback = undefined;
      if (entry) entry.settled = true;
    }
  })();
  // La promesa puede resolverse antes de que /chatgpt pida esperar; nunca queda sin handler.
  void wait.catch(() => {});
  entry = { url: url.toString(), wait, settled: false, cancel: () => finish({ error: "Se reemplazó por un ingreso nuevo a ChatGPT." }) };
  pending = entry;
  if (options.openBrowser) options.openBrowser(url.toString());
  else if (process.platform === "win32" || process.platform === "darwin" || process.env.DISPLAY || process.env.WAYLAND_DISPLAY) {
    const child = spawn(process.platform === "win32" ? "explorer.exe" : process.platform === "darwin" ? "open" : "xdg-open", [url.toString()], { detached: true, stdio: "ignore" });
    child.on("error", () => {});
    child.unref();
  }
  return ["Continue with ChatGPT: " + url.toString(), "Esperando la autorización en el navegador. Si no abrió, copiá el enlace."];
}
export async function waitChatgptLogin(): Promise<string[]> {
  if (!pending) throw new Error("No hay un ingreso a ChatGPT pendiente.");
  const current = pending;
  try { return await current.wait; }
  finally { if (pending === current) pending = undefined; }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const path = join(credentialsDir(), "chatgpt.lock");
  const until = Date.now() + 60_000;
  for (;;) {
    try { writeFileSync(path, String(process.pid), { flag: "wx", mode: 0o600 }); break; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const age = Date.now() - statSync(path).mtimeMs;
        if (age > 120_000) unlinkSync(path);
      } catch {}
      if (Date.now() > until) throw new Error("Otra instancia está renovando ChatGPT; reintentá en un momento.");
      await sleep(100);
    }
  }
  try { return await fn(); }
  finally { try { unlinkSync(path); } catch {} }
}
/** Todo escritor toma el candado y relee adentro: ningún save pisa lo que guardó otro proceso. */
async function update<T>(change: (value: Stored) => T): Promise<T> {
  return withLock(async () => {
    const value = stored();
    const result = change(value);
    save(value);
    return result;
  });
}

/** Relee el secreto dentro del candado: el refresh token rota en cada uso. */
export async function chatgptAccessToken(options: { fetch?: typeof fetch } = {}): Promise<string> {
  const value = readStored();
  const account = value && active(value);
  if (!usable(account)) throw new Error("Entrá con ChatGPT y habilitá el uso del plan desde /chatgpt.");
  const until = limitedUntil(account);
  if (until) throw new Error("Tope de uso de ChatGPT alcanzado hasta " + when(until) + ". Manage usage: " + MANAGE_USAGE);
  if (account!.tokens!.expiresAt - Date.now() > MARGIN) return account!.tokens!.access;
  return withLock(async () => {
    const latest = stored();
    const selected = active(latest);
    if (!usable(selected)) throw new Error("La sesión de ChatGPT se desconectó. Volvé a entrar con /chatgpt.");
    if (selected!.tokens!.expiresAt - Date.now() > MARGIN) return selected!.tokens!.access;
    const { clientId, subject } = selected!;
    const used = selected!.tokens!;
    const endpoints = await discovery(options.fetch ?? fetch);
    const response = await (options.fetch ?? fetch)(endpoints.token_endpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: used.refresh, resource: RESOURCE }),
      signal: AbortSignal.timeout(20_000),
    });
    const body = await json(response);
    // Tras la espera de red se relee justo antes de guardar y sólo cambian los tokens de esta cuenta,
    // y sólo si siguen siendo los que se usaron: no se pisa un ingreso, un cambio de cuenta ni una marca de tope.
    const keep = (change: (account: Account) => void) => {
      const now = readStored();
      const account = now?.accounts.find((item) => item.clientId === clientId && item.subject === subject);
      if (!now || !account || account.tokens?.refresh !== used.refresh) return;
      change(account);
      save(now);
    };
    if (!response.ok) {
      const code = errorCode(body);
      if (TERMINAL_REFRESH.has(code)) {
        keep((account) => { delete account.tokens; });
        throw new Error("La sesión de ChatGPT se desconectó (" + code + "). Volvé a entrar con /chatgpt.");
      }
      throw new Error("No pude renovar ChatGPT (" + (code || response.status) + ").");
    }
    if (typeof body.access_token !== "string" || !body.access_token || typeof body.refresh_token !== "string" || !body.refresh_token || !(Number(body.expires_in) > 0) || String(body.token_type).toLowerCase() !== "bearer") throw new Error("La renovación OAuth está incompleta.");
    if (typeof body.id_token === "string") {
      const identity = await verifiedIdentity(body.id_token, endpoints, clientId, undefined, options.fetch ?? fetch);
      if (identity.sub !== subject) throw new Error("La renovación devolvió otra identidad.");
    }
    const tokens: Tokens = {
      access: body.access_token, refresh: body.refresh_token,
      id: typeof body.id_token === "string" ? body.id_token : used.id,
      scopes: typeof body.scope === "string" ? body.scope.split(/\s+/).filter(Boolean) : used.scopes,
      expiresAt: Date.now() + Number(body.expires_in) * 1000,
    };
    keep((account) => { account.tokens = tokens; });
    if (!tokens.scopes.includes("chatgpt.tokens.use.direct")) throw new Error("Falta el permiso de usar el plan de ChatGPT.");
    return tokens.access;
  });
}

/** El tope dura lo que pida Retry-After o, si no viene, una pausa corta; después el pedido vuelve a salir. */
export async function markChatgptLimit(retryAfterMs?: number): Promise<void> {
  const pause = retryAfterMs !== undefined && retryAfterMs > 0 ? Math.min(retryAfterMs, LIMIT_MAX) : LIMIT_PAUSE;
  await update((value) => {
    const account = active(value);
    if (account) account.limitUntil = Date.now() + pause;
  });
}
/** La primera respuesta exitosa borra la marca de tope. */
export async function clearChatgptLimit(): Promise<void> {
  const value = readStored();
  if (!value || active(value)?.limitUntil === undefined) return;
  await update((latest) => {
    const account = active(latest);
    if (account) delete account.limitUntil;
  });
}
/** /v1/models público devuelve { data: [{ id }] }; el formato del backend de Codex ({ models: [{ slug, visibility }] }) queda de respaldo. */
const catalogOf = (body: any): Array<{ slug: string; name: string }> => Array.isArray(body?.data)
  ? body.data.filter((item: any) => typeof item?.id === "string" && item.id).map((item: any) => ({ slug: item.id, name: item.id }))
  : (Array.isArray(body?.models) ? body.models : []).filter((item: any) => item?.visibility === "list" && typeof item.slug === "string").map((item: any) => ({ slug: item.slug, name: typeof item.display_name === "string" ? item.display_name : item.slug }));
export async function chatgptModels(options: { fetch?: typeof fetch } = {}): Promise<Array<{ slug: string; name: string }>> {
  const value = readStored();
  const account = value && active(value);
  if (!usable(account)) return [];
  if (account!.modelsAt && Date.now() - account!.modelsAt < 3600_000) return account!.models ?? [];
  const { clientId } = account!;
  try {
    const token = await chatgptAccessToken(options);
    const response = await (options.fetch ?? fetch)(chatgptBaseUrl() + "/models", { headers: { authorization: "Bearer " + token }, signal: AbortSignal.timeout(10_000) });
    if (!response.ok) throw new Error("Catálogo no disponible.");
    const models = catalogOf(await json(response));
    // chatgptAccessToken pudo rotar el refresh token: se relee dentro del candado y sólo cambia el catálogo.
    await update((latest) => {
      const current = latest.accounts.find((item) => item.clientId === clientId);
      if (current) { current.models = models; current.modelsAt = Date.now(); }
    });
    return models;
  } catch { return account!.models ?? []; }
}
export async function logoutChatgpt(options: { fetch?: typeof fetch } = {}): Promise<string[]> {
  return withLock(async () => {
    const value = readStored();
    const account = value && active(value);
    if (!account?.tokens) return ["ChatGPT ya está desconectado."];
    let revoked = false;
    try {
      const endpoints = await discovery(options.fetch ?? fetch);
      for (const delay of [0, 250, 1000]) {
        if (delay) await sleep(delay);
        try {
          const response = await (options.fetch ?? fetch)(endpoints.revocation_endpoint, {
            method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ token: account.tokens.refresh, token_type_hint: "refresh_token", client_id: account.clientId }),
            signal: AbortSignal.timeout(10_000),
          });
          if (response.ok) { revoked = true; break; }
          if (response.status < 500) break;
        } catch {}
      }
    } catch {}
    delete account.tokens;
    delete account.limitUntil;
    save(value!);
    return [revoked ? "Sesión de ChatGPT revocada y borrada de esta máquina." : "Sesión local borrada. No pude confirmar la revocación remota; podés desconectar la app en ChatGPT Settings."];
  });
}
export async function switchChatgpt(clientId: string): Promise<string[]> {
  await update((value) => {
    if (!value.accounts.some((item) => item.clientId === clientId)) throw new Error("Cuenta de ChatGPT desconocida.");
    value.active = clientId;
  });
  return statusLines();
}
export function statusLines(): string[] {
  const state = chatgptState();
  return [
    state.locked ? "ChatGPT: llavero bloqueado." : state.linked ? "Using ChatGPT plan" + (state.email ? " · " + state.email : "") : state.scopeDisabled ? "ChatGPT conectado sin permiso para usar el plan." : "ChatGPT sin conectar. Continue with ChatGPT para entrar.",
    "Uso del plan: revisalo en ChatGPT Settings; orobas-sec no recibe un porcentaje confiable.",
    ...(state.limitUntil ? ["Tope de uso alcanzado hasta " + when(state.limitUntil) + ". Revisá el límite de este plan o de la app."] : []),
    "Manage usage: " + MANAGE_USAGE,
    ...state.accounts.map((item) => (item.active ? "● " : "  ") + (item.email ?? item.clientId) + (item.linked ? " · conectado" : " · requiere ingreso")),
  ];
}
export async function chatgptOp(request: { action?: string; clientId?: string; fetch?: typeof fetch; openBrowser?: (url: string) => void } = {}): Promise<string[]> {
  switch (request.action) {
    case "notice": return noticePending() ? ["pendiente", ...noticeLines()] : ["aceptado"];
    case "accept_notice": await acceptNotice(); return ["Aviso guardado."];
    case "start": return beginChatgptLogin({ fetch: request.fetch, openBrowser: request.openBrowser });
    case "add": return beginChatgptLogin({ fetch: request.fetch, newAccount: true, openBrowser: request.openBrowser });
    case "wait": return waitChatgptLogin();
    case "logout": return logoutChatgpt({ fetch: request.fetch });
    case "switch": return switchChatgpt(request.clientId ?? "");
    case "state": return [JSON.stringify(chatgptState())];
    default: return statusLines();
  }
}
