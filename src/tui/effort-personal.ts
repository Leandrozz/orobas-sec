// Catálogo de capacidades por identificador exacto de models.dev (2026-11-24).
// El catálogo de la cuenta decide qué modelos existen; esta tabla sólo informa controles.
import catalog from "./niveles-modelos.json" with { type: "json" };
import type { Connection } from "./modelos-personales.ts";

export const levels = ["none", "minimal", "low", "medium", "high", "xhigh", "max", "on", "off"] as const;
export type Effort = typeof levels[number];
export const isEffort = (s: unknown): s is Effort => levels.some(level => level === s);
const providers: Record<string, keyof typeof catalog> = {
  OpenAI: "openai", Claude: "anthropic", "OpenCode Zen": "opencode", "OpenCode Go": "opencode-go",
  "Kimi (Moonshot AI)": "moonshotai", "Z.ai": "zai", Gemini: "google", "Gemini (Vertex AI · Google OAuth)": "google",
};

export function supported(c: Connection): Effort[] {
  if (c.availableEfforts !== undefined) return c.availableEfforts;
  const provider = c.subscription === "kimi" ? "kimi-code-plan-global" : providers[c.provider];
  if (!provider) return [];
  const id = c.model.replace(/^models\//, "");
  const model = c.subscription === "kimi" ? id.split("/").at(-1)! : id;
  const entries: Record<string, string[]> = catalog[provider];
  return (entries[model] ?? []).filter(isEffort);
}

export async function loadPersonalReasoning(connection: Connection, value?: string) {
  if (connection.provider === "Ollama" && connection.availableEfforts === undefined) {
    const r = await fetch(connection.base.replace(/\/v1$/, "") + "/api/show", {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(8000),
      headers: { "Content-Type": "application/json", ...(connection.key ? { Authorization: "Bearer " + connection.key } : {}) },
      body: JSON.stringify({ model: connection.model }),
    });
    if (!r.ok) throw new Error("Ollama · HTTP " + r.status);
    const values = (await r.json()).thinking?.values;
    const mapped = Array.isArray(values) ? values.map(v => v === true ? "on" : v === false ? "off" : v).filter(isEffort) : [];
    connection.availableEfforts = mapped.length === 1 && mapped[0] === "off" ? [] : mapped;
  }
  return personalReasoning(connection, value);
}

const aliases: Record<string, string> = { bajo: "low", medio: "medium", alto: "high", mínimo: "minimal", minimo: "minimal", si: "on", sí: "on", no: "off", defecto: "default" };
export function personalReasoning(connection: Connection, value?: string) {
  const options = supported(connection);
  if (value) {
    let selected = aliases[value.toLowerCase()] ?? value.toLowerCase();
    if (selected === "off" && !options.includes("off") && options.includes("none")) selected = "none";
    if (selected === "default") delete connection.effort;
    else if (isEffort(selected) && options.includes(selected)) connection.effort = selected;
    else throw new Error(`Nivel no disponible para ${connection.model}. Opciones: ${["default", ...options].join(", ")}.`);
  }
  return [`Razonamiento: ${connection.effort ?? "default"} · ${connection.model}`, "Opciones personales: " + options.join(",")];
}

export function personalFields(c: Connection): Record<string, unknown> {
  const effort = c.effort;
  if (!effort || !supported(c).includes(effort)) return {};
  if (effort === "on" || effort === "off") return { thinking: { type: effort === "on" ? "enabled" : "disabled" } };
  return { reasoning_effort: effort };
}
