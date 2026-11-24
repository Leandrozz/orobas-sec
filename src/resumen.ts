// cyber --resumen: últimas sesiones de todos los proyectos del usuario y apertura de la elegida.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { dataDir, hostPath, projectId } from "./datos.ts";
import { t } from "./idioma.ts";
import { pickInTerminal } from "./menu.ts";

export type SessionSummary = { projectId: string; ruta: string; nombre: string; session: string; titulo: string; fecha: string; estado: string };

const firstText = (json: string): string => {
  try {
    const { content } = JSON.parse(json);
    return typeof content === "string" ? content : (content ?? []).find((part: { text?: string }) => part.text)?.text ?? "";
  } catch {
    return "";
  }
};

export function listSessions(): SessionSummary[] {
  let projects: Record<string, { ruta: string; nombre: string }> = {};
  try {
    projects = JSON.parse(readFileSync(join(dataDir(), "proyectos.json"), "utf8"));
  } catch {}
  const all: SessionSummary[] = [];
  for (const [id, project] of Object.entries(projects)) {
    const file = join(dataDir(), "proyectos", id, "cyber.db");
    if (!existsSync(file)) continue;
    try {
      const db = new DatabaseSync(file, { readOnly: true });
      try {
        const rows = db.prepare("select id, started_at, title, (select count(*) from messages where session_id = sessions.id) as n, (select json from messages where session_id = sessions.id and json like '%\"role\":\"user\"%' order by seq limit 1) as first from sessions order by started_at desc limit 50").all() as { id: string; started_at: string; title: string | null; n: number; first: string | null }[];
        for (const row of rows) {
          const titulo = (row.title || firstText(row.first ?? "") || "—").replace(/\s+/g, " ").slice(0, 60);
          all.push({ projectId: id, ruta: project.ruta, nombre: project.nombre, session: row.id, titulo, fecha: row.started_at, estado: t(`${row.n} mensajes`, `${row.n} messages`) });
        }
      } finally {
        db.close();
      }
    } catch {} // base corrupta o ilegible: se saltea
  }
  return all.sort((a, b) => b.fecha.localeCompare(a.fecha)).slice(0, 50);
}

/** Devuelve la sesión a abrir en este proyecto, o undefined si no hay nada que abrir aquí (salió, o se reabrió en otro proyecto). */
export async function chooseSession(cwd: string): Promise<string | undefined> {
  const sessions = listSessions();
  if (!sessions.length) {
    console.log(t("No hay sesiones guardadas.", "No saved sessions."));
    return;
  }
  const index = await pickInTerminal(t("Sesiones recientes", "Recent sessions"), sessions.map((s) => `${s.fecha.slice(0, 16).replace("T", " ")}  ${s.nombre}  ${s.titulo}  (${s.estado})`));
  if (index === undefined) return;
  const chosen = sessions[index]!;
  if (chosen.projectId === projectId(hostPath(cwd))) return chosen.session;
  if (process.env.CYBER_PROYECTO_HOST) {
    // El lanzador del host no lee la salida del contenedor (sería una tubería sobre la TUI): lee este archivo.
    if (/[\t\r\n]/.test(chosen.ruta + chosen.session)) return void console.error(t("La ruta o la sesión tiene tabulaciones o saltos de línea: no se puede reabrir.", "The path or session contains tabs or line breaks: cannot reopen."));
    const file = join(dataDir(), "reabrir.txt");
    writeFileSync(`${file}.tmp`, `${chosen.ruta}\t${chosen.session}\n`, { mode: 0o600 });
    renameSync(`${file}.tmp`, file);
    console.log(`CYBER_REABRIR\t${chosen.ruta}\t${chosen.session}`);
    process.exitCode = 75;
  } else {
    process.exitCode = spawnSync(process.execPath, [...process.execArgv, process.argv[1]!, "-C", chosen.ruta, "-s", chosen.session], { stdio: "inherit" }).status ?? 1;
  }
}
