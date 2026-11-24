// Habilidades nativas: guías cortas en Markdown (skills/<nombre>/SKILL.md en el repo, y las del
// operador en la carpeta de configuración) que le dicen al agente cuándo y cómo encarar una tarea con
// las herramientas que ya tiene. El prompt lleva sólo nombre y descripción; el cuerpo se lee a pedido
// con skill_load, que además carga las herramientas que la habilidad declara. Mismo patrón de
// divulgación progresiva que el catálogo: lo que no se usa no ocupa contexto.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Tool, ToolResult } from "./agent.ts";

export interface Skill {
  name: string;
  description: string;
  /** Herramientas del catálogo que la habilidad usa; skill_load las carga. */
  tools: string[];
  body: string;
  path: string;
}

/** Frontmatter mínimo (name, description, tools) y cuerpo. Sin dependencias de YAML: tres claves. */
export function parseSkill(text: string, path: string): Skill | undefined {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (!match) return undefined;
  const meta: Record<string, string> = {};
  for (const line of match[1]!.split(/\r?\n/)) {
    const pair = /^([\w-]+):\s*(.*)$/.exec(line);
    if (pair) meta[pair[1]!.toLowerCase()] = pair[2]!.trim();
  }
  const name = meta.name?.replace(/^["']|["']$/g, "");
  if (!name || !/^[a-z0-9][a-z0-9-]*$/i.test(name)) return undefined;
  const tools = (meta.tools ?? "").replace(/^\[|\]$/g, "").split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
  return { name, description: (meta.description ?? "").replace(/^["']|["']$/g, ""), tools, body: match[2]!.trim(), path };
}

/** Lee skills/<nombre>/SKILL.md de cada carpeta; la última carpeta gana ante nombres repetidos. */
export function loadSkills(dirs: string[]): Skill[] {
  const skills = new Map<string, Skill>();
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const path = join(dir, entry.name, "SKILL.md");
      if (!existsSync(path)) continue;
      const skill = parseSkill(readFileSync(path, "utf8"), path);
      if (skill) skills.set(skill.name, skill);
    }
  }
  return [...skills.values()];
}

/** Lo que pasó al cargar las herramientas de una habilidad; `note` explica las que faltan (REA fuera de la caja, por ejemplo). */
export interface SkillLoad { ok: string[]; missing: string[]; note?: string; errors?: string[] }

export function skillsSummary(skills: Skill[]): string {
  return skills.map((skill) => `${skill.name} — ${skill.description}`).join("\n");
}

export function createSkillTool(skills: () => Skill[], loadTools: (names: string[], signal?: AbortSignal) => SkillLoad | Promise<SkillLoad>): Tool {
  return {
    name: "skill_load",
    label: "Leer una habilidad",
    description: "Lee una habilidad del harness (guía corta de cuándo y cómo encarar una tarea con las herramientas que ya tenés) y carga las herramientas que declara. Las habilidades disponibles están listadas en el prompt; sin nombre, las lista.",
    parameters: { type: "object", properties: { name: { type: "string", description: "Nombre de la habilidad" } }, required: [] },
    parallel: true,
    replay: "safe",
    execute: async (params, signal): Promise<ToolResult> => {
      const all = skills();
      const name = String(params.name ?? "").trim().toLowerCase();
      if (!name) return { text: all.length ? `Habilidades:\n${skillsSummary(all)}` : "No hay habilidades instaladas.", details: { habilidades: all.length } };
      const skill = all.find((item) => item.name.toLowerCase() === name);
      if (!skill) throw new Error(`No existe la habilidad «${name}». Disponibles: ${all.map((item) => item.name).join(", ") || "ninguna"}.`);
      const loaded = await loadTools(skill.tools, signal);
      const notes = [
        loaded.ok.length ? `Herramientas cargadas: ${loaded.ok.join(", ")}.` : "",
        loaded.missing.length ? `No están en el catálogo: ${loaded.missing.join(", ")}.${loaded.note ? ` ${loaded.note}` : ""}` : "",
        ...(loaded.errors ?? []),
      ].filter(Boolean);
      return { text: [`# Habilidad ${skill.name}`, skill.body, ...notes].join("\n\n"), details: { habilidad: skill.name, cargadas: loaded.ok } };
    },
  };
}
