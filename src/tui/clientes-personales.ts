import { execFile, spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { accessSync, constants, mkdirSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { promisify } from "node:util";
import { credentialsDir } from "../secretos.ts";

export type ClientName = "agy" | "kimi" | "codex" | "claude";
const packages = { kimi: "@moonshot-ai/kimi-code", codex: "@openai/codex", claude: "@anthropic-ai/claude-code" };
const local = join(homedir(), ".local");
export function clientPath(name: ClientName) {
  for (const dir of [...(process.env.PATH ?? "").split(delimiter), join(local, "bin")]) {
    if (!dir) continue;
    const file = join(dir, name);
    try { accessSync(file, constants.X_OK); return file; } catch {}
  }
  return undefined;
}

export function installClient(name: ClientName) {
  if (name === "agy") {
    const script = spawnSync("curl", ["--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https", "https://antigravity.google/cli/install.sh"], { encoding: "utf8", timeout: 60000 });
    if (script.error || script.status !== 0 || !script.stdout.startsWith("#!/bin/bash")) throw new Error("No se pudo descargar el instalador oficial de Google.");
    const result = spawnSync("bash", ["-s", "--", "--dir", join(local, "bin")], { input: script.stdout, stdio: ["pipe", "inherit", "inherit"] });
    if (result.error || result.status !== 0) throw new Error("Falló la instalación de Antigravity.");
  } else {
    const result = spawnSync("npm", ["install", "--global", "--prefix", local, packages[name]], { stdio: "inherit" });
    if (result.error || result.status !== 0) throw new Error("Falló la instalación de " + name);
  }
}

export function personalEnv() {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (/^(GOOGLE_|GCLOUD_|CLOUDSDK_|GEMINI_|AGY_|ANTHROPIC_|OPENAI_|MOONSHOT_|KIMI_API_KEY)/.test(name)) delete env[name];
  }
  return env;
}

export async function subscriptionReply(client: "agy" | "kimi", messages: Array<{ role: string; content: string }>, model: string, progress?: (stage: string) => void, effort?: string) {
  const executable = clientPath(client);
  if (!executable) throw new Error("Volvé a conectar la suscripción para instalar " + client);
  const cwd = join(credentialsDir(), "chat-personal", client);
  const dir = join(cwd, ".agents", "agents");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const name = "orobas-chat";
  const profile = join(dir, name + ".md");
  writeFileSync(profile, "---\nname: orobas-chat\ndescription: Chat de texto de Orobas\nmainAgent: true\ntools: []\nsubagents: []\n---\nRespondé al último mensaje del usuario.\n", { mode: 0o600 });
  const prompt = JSON.stringify(messages);
  const args = client === "agy"
    ? ["--agent", name, "--disable-slash-commands", "--output-format", "stream-json", "--print", prompt]
    : ["--agent-file", profile, "--prompt", prompt];
  if (client === "agy" && effort) {
    const variant = /^(.*)-(low|medium|high|xhigh|max)$/.exec(model);
    if (variant) model = variant[1] + "-" + effort;
    else args.unshift("--effort", effort);
  }
  if (model !== "Google · Antigravity" && model !== "Kimi Code") args.unshift("--model", model);
  try {
    if (client === "agy") {
      const child = spawn(executable, args, { cwd, env: personalEnv(), stdio: ["ignore", "pipe", "ignore"], timeout: 120000 });
      let result: { response?: string; status?: string; usage?: { total_tokens?: number; input_tokens?: number } } | undefined;
      let previous = "";
      const lines = createInterface({ input: child.stdout });
      lines.on("line", line => {
        let event;
        try { event = JSON.parse(line); } catch { return; }
        if (event.event === "result") result = event.result;
        const step = event.step_update;
        const stage = event.event === "init" ? "Conectado" : step?.step_type === "agent_response" ? "Escribiendo respuesta" : step?.step_type === "thinking" ? "Procesando" : undefined;
        if (stage && stage !== previous) { previous = stage; progress?.(stage); }
      });
      await new Promise<void>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", code => code === 0 ? resolve() : reject(new Error("Antigravity")));
      });
      if (result?.response?.trim() && result.status !== "ERROR") return { content: result.response, usage: result.usage };
    } else {
      const env = personalEnv();
      if (effort) env.KIMI_MODEL_THINKING_EFFORT = effort;
      const { stdout } = await promisify(execFile)(executable, args, { cwd, env, timeout: 120000, maxBuffer: 4 * 1024 * 1024 });
      if (stdout.trim()) return { content: stdout.trim(), usage: undefined };
    }
  } catch {
    throw new Error("El cliente " + client + " no pudo responder. Revisá la sesión y la cuota de tu cuenta.");
  }
  throw new Error("El cliente devolvió una respuesta vacía.");
}

// La inicialización de Claude Code devuelve su catálogo sin enviar un prompt de inferencia.
export async function nativeClaudeModels(): Promise<string[]> {
  const bin = clientPath("claude");
  if (!bin) return [];
  const opts = { cwd: tmpdir(), env: personalEnv(), timeout: 10000, maxBuffer: 4 * 1024 * 1024 };
  const status = JSON.parse((await promisify(execFile)(bin, ["auth", "status", "--json"], opts)).stdout);
  if (!status.loggedIn || status.authMethod !== "claude.ai") return [];
  const child = execFile(bin, ["--print", "--verbose", "--input-format", "stream-json", "--output-format", "stream-json", "--tools", "", "--no-session-persistence"], opts);
  const response = new Promise<string>((resolve, reject) => {
    let output = "";
    child.stdout!.on("data", chunk => { output += chunk; });
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve(output) : reject(new Error("Claude Code no pudo listar los modelos.")));
  });
  child.stdin!.on("error", () => {});
  child.stdin!.end(JSON.stringify({ type: "control_request", request_id: "catalog", request: { subtype: "initialize" } }) + "\n");
  for (const line of (await response).split("\n").filter(Boolean)) {
    const r = JSON.parse(line);
    if (r.type !== "control_response" || r.response?.request_id !== "catalog") continue;
    const ids = new Set<string>();
    for (const m of r.response.response?.models ?? []) {
      const id = m.resolvedModel || m.value;
      if (typeof id === "string" && id) ids.add(id);
    }
    return [...ids];
  }
  return [];
}
