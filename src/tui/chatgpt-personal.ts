import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { createRemoteJWKSet, jwtVerify } from "jose";
import lockfile from "proper-lockfile";
import { isEffort, type Effort } from "./effort-personal.ts";
import OpenAI from "openai";
import { credentialsDir, readSecret, writeSecret } from "../secretos.ts";

const issuer = "https://auth.openai.com";
const resource = "https://api.openai.com/v1";
const jwks = createRemoteJWKSet(new URL(issuer + "/.well-known/jwks.json"));
const scope = "chatgpt.tokens.use.direct";
type Profile = { client: string; subject: string; access: string; refresh: string; expires: number };

async function locked<T>(name: string, fn: () => Promise<T>) {
  const unlock = await lockfile.lock(join(credentialsDir(), name), { realpath: false, retries: { retries: 8, minTimeout: 100, maxTimeout: 600 } });
  try { return await fn(); } finally { await unlock(); }
}

async function exchange(fields: Record<string, string>) {
  const request = await fetch(issuer + "/api/accounts/oauth/token", { method: "POST", body: new URLSearchParams({ ...fields, resource }), redirect: "error", signal: AbortSignal.timeout(20000) });
  if (!request.ok) throw new Error("ChatGPT OAuth · HTTP " + request.status);
  const data = await request.json();
  if (typeof data.access_token !== "string" || typeof data.refresh_token !== "string" || !(data.expires_in > 0)) throw new Error("Respuesta OAuth incompleta.");
  return data;
}

export async function connectChatGPT(show: (url: string) => void) {
  const host = await locked("chatgpt-host", async () => {
    const saved = readSecret("chatgpt-host");
    if (saved) return saved;
    const value = "urn:uuid:" + randomUUID();
    writeSecret("chatgpt-host", value);
    return value;
  });
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") { server.close(); throw new Error("OAuth loopback"); }
  const redirect = `http://127.0.0.1:${address.port}/auth/callback`;
  const verifier = randomBytes(48).toString("base64url");
  const state = randomUUID(), nonce = randomUUID();
  try {
    const url = new URL(issuer + "/api/accounts/authorize");
    url.search = new URLSearchParams({
      client_id: "dynamic_agent_client", agent_name_hint: "Orobas", ext_agent_host_id: host,
      response_type: "code", redirect_uri: redirect, resource, state, nonce,
      scope: "openid email profile offline_access resource.invoke " + scope,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256",
    }).toString();
    const callback = await new Promise<URLSearchParams>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("El login de ChatGPT venció.")), 180000);
      server.once("close", () => clearTimeout(timer));
      server.on("request", (req, res) => {
        const incoming = new URL(req.url ?? "/", redirect);
        if (req.method !== "GET" || incoming.origin + incoming.pathname !== redirect || incoming.searchParams.get("state") !== state) { res.writeHead(400).end(); return; }
        res.writeHead(200, { "Cache-Control": "no-store" }).end("Volvé a Orobas.");
        resolve(incoming.searchParams);
      });
      show(url.href);
      execFile(process.platform === "darwin" ? "open" : "xdg-open", [url.href], () => {});
    });
    const client = callback.get("client_id"), code = callback.get("code");
    if (!client || client === "dynamic_agent_client" || !code || callback.has("error")) throw new Error("ChatGPT no autorizó la conexión.");
    const data = await exchange({ grant_type: "authorization_code", client_id: client, code, code_verifier: verifier, redirect_uri: redirect });
    const { payload } = await jwtVerify(data.id_token, jwks, { issuer, audience: client, requiredClaims: ["exp", "sub", "nonce"] });
    if (payload.nonce !== nonce || !payload.sub || !String(data.scope).split(" ").includes(scope)) throw new Error("ChatGPT no concedió el uso del plan.");
    const profile = "chatgpt-" + createHash("sha256").update(JSON.stringify([client, payload.sub])).digest("hex");
    writeSecret(profile, JSON.stringify({ client, subject: payload.sub, access: data.access_token, refresh: data.refresh_token, expires: Date.now() + data.expires_in * 1000 }));
    return profile;
  } finally { server.close(); }
}

async function access(profile: string) {
  if (!/^chatgpt-[a-f0-9]{64}$/.test(profile)) throw new Error("Perfil de ChatGPT inválido.");
  return locked(profile, async () => {
    const p: Profile = JSON.parse(readSecret(profile) ?? "null");
    if (!p) throw new Error("Volvé a conectar tu cuenta de ChatGPT.");
    if (p.expires > Date.now() + 30000) return p.access;
    const data = await exchange({ grant_type: "refresh_token", client_id: p.client, refresh_token: p.refresh });
    writeSecret(profile, JSON.stringify({ ...p, access: data.access_token, refresh: data.refresh_token, expires: Date.now() + data.expires_in * 1000 }));
    return data.access_token as string;
  });
}

export async function chatGPTModels(profile: string, caps?: Map<string, Effort[]>): Promise<string[]> {
  const r = await fetch(resource + "/models", { headers: { Authorization: "Bearer " + await access(profile) }, redirect: "error", signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error("Catálogo ChatGPT · HTTP " + r.status);
  const data = await r.json();
  for (const m of data.models ?? []) {
    if (Array.isArray(m.supported_reasoning_levels)) caps?.set(m.slug, m.supported_reasoning_levels.map((v: string | {effort: string}) => typeof v === "string" ? v : v.effort).filter(isEffort));
  }
  return (data.models ?? []).filter((m: {visibility: string}) => m.visibility === "list").map((m: {slug: string}) => m.slug);
}

export async function chatGPTReply(profile: string, model: string, input: Array<{role: "user" | "assistant"; content: string}>, effort?: "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max") {
  const client = new OpenAI({ apiKey: await access(profile), baseURL: resource, maxRetries: 0, timeout: 120000 });
  const stream = await client.responses.create({ model, input, store: false, stream: true, ...(effort ? { reasoning: { effort } } : {}) });
  let content = "";
  for await (const e of stream) {
    if (e.type === "response.output_text.delta") content += e.delta;
    if (e.type === "response.completed" && content.trim()) return { content, usage: e.response.usage };
    if (e.type === "response.failed" || e.type === "response.incomplete") throw new Error("ChatGPT no completó la respuesta.");
  }
  throw new Error("ChatGPT terminó sin una respuesta completa.");
}
