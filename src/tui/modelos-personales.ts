import { createHash, randomUUID } from "node:crypto";
import { readdirSync } from "node:fs";
import { stripVTControlCharacters } from "node:util";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { credentialsDir, readSecret, writeSecret } from "../secretos.ts";
import { t } from "../idioma.ts";
import type { CommandIO } from "./comandos.ts";

import { levels, isEffort, personalFields, supported, type Effort } from "./effort-personal.ts";
import { connectChatGPT, chatGPTModels, chatGPTReply } from "./chatgpt-personal.ts";
import { personalModelName } from "./nombres-modelos.ts";
import { nativeClaudeModels, clientPath, personalEnv, subscriptionReply } from "./clientes-personales.ts";
import { geminiToken, type GeminiGrant } from "./gemini-oauth.ts";

const providers = {
  OpenAI: "https://api.openai.com/v1",
  Claude: "https://api.anthropic.com/v1",
  Gemini: "https://generativelanguage.googleapis.com/v1beta/openai",
  "Gemini (Vertex AI · Google OAuth)": "",
  "OpenCode Zen": "https://opencode.ai/inference/openai/v1",
  Ollama: "http://localhost:11434/v1",
  "Self-hosted": "",
  "OpenCode Go": "https://opencode.ai/inference/go/openai/v1",
  "Z.ai": "https://api.z.ai/api/paas/v4",
  "Kimi (Moonshot AI)": "https://api.moonshot.ai/v1",
  "Otra API compatible con OpenAI": "",
};
const vertex = "Gemini (Vertex AI · Google OAuth)";
export type Connection = { provider: keyof typeof providers; model: string; base: string; key?: string; oauth?: GeminiGrant; chatgptProfile?: string; nativeClaude?: boolean; variants?: Record<string, string>; effort?: Effort; availableEfforts?: Effort[]; subscription?: "agy" | "kimi" };

export function personalModels(): Connection[] {
  return readdirSync(credentialsDir()).filter(name => /^chat-personal-[a-f0-9]{64}\.secreto$/.test(name)).map(name => {
    return JSON.parse(readSecret(name.slice(0, -8))!) as Connection;
  });
}

async function catalog(c: Connection, caps = new Map<string, Effort[]>()): Promise<string[]> {
  if (c.chatgptProfile) return chatGPTModels(c.chatgptProfile, caps);
  if (c.subscription) {
    const exe = clientPath(c.subscription);
    if (!exe) return [];
    const { stdout } = await promisify(execFile)(exe, c.subscription === "agy" ? ["models"] : ["provider", "list", "--json"], { env: personalEnv(), timeout: 10000 });
    if (c.subscription === "agy") return stdout.split(/\r?\n/).filter(line => line.includes("\t")).map(line => line.split("\t")[0]!.trim());
    const models = JSON.parse(stdout).models ?? {};
    const ids = Object.keys(models).filter(id => /kimi/i.test(id) || /kimi/i.test(String(models[id]?.provider)));
    for (const alias of ids) {
      const id = models[alias]?.model;
      if (typeof id === "string") caps.set(alias, supported({ ...c, model: id, availableEfforts: undefined }));
    }
    return ids;
  }
  const key = c.provider === vertex ? await googleToken() : c.oauth ? await geminiToken(c.oauth) : c.key;
  if (c.provider === "Gemini" && c.key) {
    const models: string[] = [];
    const seen = new Set<string>();
    let token = "";
    do {
      const url = new URL("https://generativelanguage.googleapis.com/v1beta/models");
      url.searchParams.set("pageSize", "1000");
      if (token) url.searchParams.set("pageToken", token);
      const r = await fetch(url, { headers: { "x-goog-api-key": c.key }, redirect: "error", signal: AbortSignal.timeout(8000) });
      if (!r.ok) throw new Error("Gemini · HTTP " + r.status);
      const page = await r.json();
      for (const m of page.models ?? []) {
        if (m.supportedGenerationMethods?.includes("generateContent")) models.push(m.name.replace(/^models\//, ""));
      }
      token = page.nextPageToken ?? "";
      if (token && seen.has(token)) throw new Error("Paginación inválida de Gemini.");
      seen.add(token);
    } while (token);
    return models;
  }
  if (c.provider === "Claude" && key) {
    const models: string[] = [];
    let after = "";
    for (;;) {
      const url = new URL("https://api.anthropic.com/v1/models");
      url.searchParams.set("limit", "100");
      if (after) url.searchParams.set("after_id", after);
      const r = await fetch(url, { headers: { "x-api-key": key, "anthropic-version": "2023-06-01" }, redirect: "error", signal: AbortSignal.timeout(8000) });
      if (!r.ok) throw new Error("Claude · HTTP " + r.status);
      const page = await r.json();
      for (const entry of page.data) {
        models.push(entry.id);
        const info = entry.capabilities?.effort;
        if (info) caps.set(entry.id, info.supported === false ? [] : Object.keys(info).filter(isEffort).filter(key => info[key]?.supported === true));
      }
      if (!page.has_more) return models;
      if (!page.last_id || page.last_id === after) throw new Error("Paginación inválida de Claude.");
      after = page.last_id;
    }
  }
  const response = await fetch(c.base + "/models", { headers: { ...(key ? { Authorization: "Bearer " + key } : {}), ...(c.oauth ? { "x-goog-user-project": c.oauth.project } : {}) }, redirect: "error", signal: AbortSignal.timeout(4500) });
  if (!response.ok) return [];
  const data = await response.json();
  for (const entry of Array.isArray(data.data) ? data.data : []) {
    const values = entry.supported_reasoning_levels ?? entry.supported_reasoning_efforts;
    if (typeof entry.id === "string" && Array.isArray(values)) caps.set(entry.id, values.map(v => typeof v === "string" ? v : v?.effort).filter(isEffort));
  }
  return Array.isArray(data.data) ? data.data.map((row: {id: string}) => row.id).filter((id: unknown) => typeof id === "string") : [];
}

export function personalRow(c: Connection) {
  const hint = c.nativeClaude ? "Claude · Claude Code" : c.subscription === "agy" ? "Gemini · Antigravity" : c.chatgptProfile ? "OpenAI · ChatGPT" : c.subscription === "kimi" ? "Kimi · Kimi Code" : c.provider;
  return { label: personalModelName(c.model), hint };
}

export function catalogEntries(c: Connection, ids: string[], caps = new Map<string, Effort[]>()) {
  const entries = new Map<string, Connection>();
  for (const id of ids) {
    const variant = c.subscription === "agy" ? /^(.*)-(low|medium|high|xhigh|max)$/.exec(id) : undefined;
    const model = variant?.[1] ?? id;
    let entry = entries.get(model);
    if (!entry) {
      entry = { ...c, model, availableEfforts: caps.get(id) ?? (model === c.model ? c.availableEfforts : undefined) };
      delete entry.variants;
      if (model !== c.model) delete entry.effort;
      if (c.subscription === "agy") entry.availableEfforts = [];
      entries.set(model, entry);
    }
    if (variant && isEffort(variant[2])) {
      (entry.variants ??= {})[variant[2]] = id;
      entry.availableEfforts!.push(variant[2]);
    }
  }
  for (const entry of entries.values()) {
    if (entry.variants) entry.availableEfforts = levels.filter(level => Object.hasOwn(entry.variants!, level));
  }
  return [...entries.values()];
}

async function pickPersonal(io: Pick<CommandIO, "pick">, entries: Connection[]) {
  const at = await io.pick(t("Elegir modelo", "Choose model"), entries.map(personalRow), { search: true });
  return at === undefined ? undefined : entries[at];
}

async function claudeEntries(): Promise<Connection[]> {
  return (await nativeClaudeModels()).map(model => ({ provider: "Claude", base: "", nativeClaude: true, model }));
}

export async function selectablePersonal(includeClaude = false) {
  const groups = new Map<string, Connection[]>();
  for (const c of personalModels()) {
    const id = JSON.stringify([c.provider, c.base, c.subscription, c.chatgptProfile, c.key, c.oauth?.refreshToken]);
    const group = groups.get(id) ?? [];
    group.push(c);
    groups.set(id, group);
  }
  const groupsPending = [...groups.values()].map(async group => {
    const c = group[0]!;
    const caps = new Map<string, Effort[]>();
    const fetched = await catalog(c, caps).catch(() => []);
    const ids = new Set(fetched.length ? fetched : group.map(entry => entry.model));
    return catalogEntries(c, [...ids], caps);
  });
  if (includeClaude) groupsPending.push(claudeEntries().catch(() => []));
  return (await Promise.all(groupsPending)).flat();
}

export async function connectPersonal(io: Pick<CommandIO, "pick" | "input" | "notice" | "loginCLI">): Promise<Connection | undefined> {
  const names = Object.keys(providers) as Array<keyof typeof providers>;
  const menu = names.filter(name => name !== "OpenCode Go");
  const rows = menu.map(name => {
    if (name === "OpenCode Zen") return { label: "OpenCode", hint: "Zen / Go" };
    if (["OpenAI", "Claude", "Gemini", "Kimi (Moonshot AI)"].includes(name)) return { label: name, hint: "Login · API key" };
    return name;
  });
  const selected = await io.pick(t("Conectar modelo", "Connect model"), rows);
  if (selected === undefined) return;
  let provider: keyof typeof providers = menu[selected]!;
  if (provider === "OpenCode Zen") {
    const plan = await io.pick("OpenCode", ["Zen · pago por uso", "Go · suscripción"]);
    if (plan === undefined) return;
    provider = plan === 0 ? "OpenCode Zen" : "OpenCode Go";
    const method = await io.pick(provider, ["Usar API key", "Entrar a OpenCode Console y crear una clave"]);
    if (method === undefined) return;
    if (method === 1) {
      const url = "https://opencode.ai/auth";
      execFile(process.platform === "darwin" ? "open" : "xdg-open", [url], () => {});
      io.notice?.({ title: "OpenCode Console", lines: [url, "Elegí tu workspace, creá una clave y pegala acá."] });
    }
  }
  const subscription = ({
    OpenAI: { client: "codex", label: "ChatGPT" },
    Claude: { client: "claude", label: "Claude.ai · Claude Code" },
    Gemini: { client: "agy", label: "Google · Antigravity" },
    "Kimi (Moonshot AI)": { client: "kimi", label: "Kimi Code" },
  } as const)[provider as "OpenAI" | "Claude" | "Gemini" | "Kimi (Moonshot AI)"];
  if (subscription) {
    const method = await io.pick(provider, [
      { label: t("Iniciar sesión con ", "Sign in with ") + subscription.label, hint: t("Suscripción · cliente oficial", "Subscription · official client") },
      { label: "API key", hint: t("API del proveedor", "Provider API") },
    ]);
    if (method === undefined) return;
    if (method === 0) {
      if (provider === "OpenAI") {
        const profile = await connectChatGPT(url => io.notice?.({ title: "ChatGPT", lines: [t("Autorizá el uso del plan en el navegador.", "Authorize plan usage in your browser."), url] }));
        const caps = new Map<string, Effort[]>();
        const models = await chatGPTModels(profile, caps);
        if (!models.length) throw new Error("ChatGPT no devolvió modelos disponibles para esta cuenta.");
        const connection: Connection = { provider, base: providers.OpenAI, model: models[0]!, chatgptProfile: profile };
        const id = createHash("sha256").update(profile).digest("hex");
        writeSecret("chat-personal-" + id, JSON.stringify(connection));
        return pickPersonal(io, catalogEntries(connection, models, caps));
      }
      if (!io.loginCLI) throw new Error(t("Abrí Orobas completo para iniciar sesión.", "Open the full Orobas TUI to sign in."));
      if (!await io.loginCLI(subscription.client)) return;
      if (subscription.client === "agy" || subscription.client === "kimi") {
        const connection = { provider, model: subscription.label, base: "", subscription: subscription.client };
        const id = createHash("sha256").update("subscription:" + provider).digest("hex");
        writeSecret("chat-personal-" + id, JSON.stringify(connection));
        const caps = new Map<string, Effort[]>();
        const available = await catalog(connection, caps).catch(() => []);
        if (available.length) {
          return pickPersonal(io, catalogEntries(connection, available, caps));
        }
        return connection;
      }
      const entries = await claudeEntries();
      if (!entries.length) throw new Error(t("Claude Code no devolvió modelos para la sesión.", "Claude Code returned no models for the session."));
      return pickPersonal(io, entries);
    }
  }
  let base = providers[provider];
  const custom = provider === "Ollama" || provider === "Self-hosted" || provider === "Otra API compatible con OpenAI";
  if (custom) {
    const url = await io.input(t("URL base con /v1", "Base URL including /v1") + (base ? " [" + base + "]" : ""));
    if (url === undefined) return;
    const parsed = new URL(url.trim() || base);
    if (!["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("URL inválida");
    base = parsed.href.replace(/\/+$/, "");
  } else if (provider === vertex) {
    const project = (await io.input(t("Proyecto de Google Cloud (requiere gcloud auth application-default login)", "Google Cloud project (requires gcloud auth application-default login)")))?.trim();
    if (!project) return;
    if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project)) throw new Error("ID de proyecto inválido");
    base = "https://aiplatform.googleapis.com/v1beta1/projects/" + project + "/locations/global/endpoints/openapi";
  }
  let key: string | undefined;
  if (provider !== vertex) {
    key = (await io.input(custom ? t("API key (opcional)", "API key (optional)") : "API key", { hidden: true }))?.trim();
    if (key === undefined || (!custom && !key)) return;
  } else if (provider === vertex) {
    await googleToken();
  }
  const caps = new Map<string, Effort[]>();
  const available = await catalog({ provider, base, key, model: "" }, caps);
  if (!available.length) throw new Error(t("La cuenta no devolvió un catálogo. Revisá el acceso y reintentá.", "The account did not return a catalog. Check access and retry."));
  const connection = await pickPersonal(io, catalogEntries({ provider, base, key, model: "" }, available, caps));
  if (!connection) return;
  const id = createHash("sha256").update(JSON.stringify([provider, base, connection.model])).digest("hex");
  writeSecret("chat-personal-" + id, JSON.stringify(connection));
  return connection;
}

async function googleToken() {
  try {
    return (await promisify(execFile)("gcloud", ["auth", "application-default", "print-access-token"], { timeout: 15000 })).stdout.trim();
  } catch {
    throw new Error(t("Se necesita gcloud con credenciales de aplicación en el entorno del TUI.", "The TUI environment needs gcloud with application default credentials."));
  }
}

export function openPersonalChat(connection: Connection) {
  const messages: Array<{ role: "user" | "assistant"; content: string }> = [];
  const goSession = connection.provider === "OpenCode Go" ? "ses_" + randomUUID() : undefined;
  const row = personalRow(connection);
  const title = row.label + " · " + row.hint;
  return { title, connection, async reply(prompt: string, progress?: (stage: string) => void) {
    const turn = [...messages, { role: "user" as const, content: prompt }];
    let content: string;
    let usage: { total_tokens?: number; prompt_tokens?: number; input_tokens?: number; output_tokens?: number; completion_tokens?: number } | undefined;
    if (connection.chatgptProfile) {
      const reply = await chatGPTReply(connection.chatgptProfile, connection.model, turn, connection.effort === "on" || connection.effort === "off" ? undefined : connection.effort);
      content = reply.content;
      usage = reply.usage ?? undefined;
    } else if (connection.subscription) {
      ({ content, usage } = await subscriptionReply(connection.subscription, turn, connection.variants ? (connection.variants[connection.effort ?? ""] ?? Object.values(connection.variants)[0]!) : connection.model, progress, connection.variants ? undefined : connection.effort));
    } else if (connection.provider === "Ollama" && connection.effort) {
      const effort = connection.effort;
      const response = await fetch(connection.base.replace(/\/v1$/, "") + "/api/chat", {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(120000),
        headers: { "content-type": "application/json", ...(connection.key ? { Authorization: "Bearer " + connection.key } : {}) },
        body: JSON.stringify({ model: connection.model, messages: turn, stream: false, think: effort === "on" ? true : effort === "off" ? false : effort }),
      });
      if (!response.ok) throw new Error(title + " · HTTP " + response.status);
      const data = await response.json();
      content = data.message?.content;
      if (!content?.trim()) throw new Error("Ollama devolvió una respuesta sin texto.");
      if (Number.isFinite(data.prompt_eval_count) && Number.isFinite(data.eval_count))
        usage = { input_tokens: data.prompt_eval_count, output_tokens: data.eval_count, total_tokens: data.prompt_eval_count + data.eval_count };
    } else if (connection.provider === "Claude" && connection.effort) {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(120000),
        headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": connection.key! },
        body: JSON.stringify({ model: connection.model, max_tokens: 4096, messages: turn, output_config: { effort: connection.effort } }),
      });
      if (!response.ok) throw new Error(title + " · HTTP " + response.status);
      const data = await response.json();
      content = data.content.filter((block: {type: string}) => block.type === "text").map((block: {text: string}) => block.text).join("");
      if (!content.trim()) throw new Error("Claude devolvió una respuesta sin texto.");
      if (data.usage) usage = { ...data.usage, total_tokens: data.usage.input_tokens + data.usage.output_tokens + (data.usage.cache_read_input_tokens ?? 0) + (data.usage.cache_creation_input_tokens ?? 0) };
    } else {
      const key = connection.provider === vertex ? await googleToken() : connection.oauth ? await geminiToken(connection.oauth) : connection.key;
      const response = await fetch(connection.base + "/chat/completions", {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(120000),
        headers: { "Content-Type": "application/json", ...(goSession ? { "x-opencode-session": goSession } : {}), ...(connection.oauth ? { "x-goog-user-project": connection.oauth.project } : {}), ...(key ? { Authorization: "Bearer " + key } : {}) },
        body: JSON.stringify({ model: connection.model, messages: turn, ...personalFields(connection) }),
      });
      if (!response.ok) throw new Error(title + " · HTTP " + response.status);
      const data = await response.json();
      content = data.choices?.[0]?.message?.content;
      usage = data.usage;
      if (typeof content !== "string" || !content.trim()) throw new Error(t("Respuesta sin texto", "Empty text response"));
    }
    messages.push({ role: "user", content: prompt }, { role: "assistant", content });
    return { usage, text: stripVTControlCharacters(content).replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, "") };
  } };
}

export async function personalChat(io: Pick<CommandIO, "input" | "notice">, connection: Connection) {
  const chat = openPersonalChat(connection);
  for (;;) {
    const prompt = (await io.input(chat.title))?.trim();
    if (!prompt) return;
    io.notice?.({ title: chat.title, lines: (await chat.reply(prompt)).text.split("\n") });
  }
}
