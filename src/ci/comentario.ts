// El comentario del PR (GitHub) o del MR (GitLab): uno solo por configuración, que se edita en cada corrida. Se
// reconoce por el marcador oculto del principio («<!-- orobas-sec:ci:nombre -->»). Si no se puede editar (lo escribió
// otra cuenta, o lo borraron), se crea uno nuevo. Nunca se escribe el token en la salida.
import { existsSync, readFileSync } from "node:fs";

export interface Publicado {
  accion: "creado" | "editado";
  url?: string;
  id: number;
}

interface Opciones {
  cuerpo: string;
  marcador: string;
  env: NodeJS.ProcessEnv;
  fetch?: typeof fetch;
  pr?: number;
}

/** El número del PR, del evento de GitHub. */
export function prDeGithub(env: NodeJS.ProcessEnv): number | undefined {
  try {
    if (!env.GITHUB_EVENT_PATH || !existsSync(env.GITHUB_EVENT_PATH)) return undefined;
    const evento = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")) as { pull_request?: { number?: number }; number?: number };
    return evento.pull_request?.number ?? undefined;
  } catch {
    return undefined;
  }
}

async function pedir(f: typeof fetch, url: string, init: RequestInit): Promise<{ estado: number; cuerpo: unknown }> {
  const respuesta = await f(url, { ...init, signal: AbortSignal.timeout(30_000) });
  const texto = await respuesta.text();
  let cuerpo: unknown = texto;
  try { cuerpo = JSON.parse(texto); } catch { /* texto */ }
  return { estado: respuesta.status, cuerpo };
}

const mensajeDe = (cuerpo: unknown) => (cuerpo && typeof cuerpo === "object" && "message" in cuerpo ? String((cuerpo as { message: unknown }).message).slice(0, 200) : String(cuerpo).slice(0, 200));

/** Crea o edita el comentario en el PR de GitHub. Lanza con un mensaje claro si no se puede. */
export async function comentarGithub({ cuerpo, marcador, env, fetch: f = fetch, pr }: Opciones): Promise<Publicado> {
  const token = env.GITHUB_TOKEN || env.GH_TOKEN;
  const repo = env.GITHUB_REPOSITORY;
  const numero = pr ?? prDeGithub(env);
  if (!token) throw new Error("Falta GITHUB_TOKEN (con permiso pull-requests: write) para comentar en el PR.");
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error("Falta GITHUB_REPOSITORY (dueño/repositorio).");
  if (!numero) throw new Error("No es un PR: no hay dónde comentar (el resumen queda en el job).");
  const api = (env.GITHUB_API_URL || "https://api.github.com").replace(/\/$/, "");
  const cabeceras = { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "content-type": "application/json", "user-agent": "orobas-sec-ci" };
  let existente: number | undefined;
  for (let pagina = 1; pagina <= 30 && existente === undefined; pagina++) {
    const r = await pedir(f, `${api}/repos/${repo}/issues/${numero}/comments?per_page=100&page=${pagina}`, { headers: cabeceras });
    if (r.estado !== 200 || !Array.isArray(r.cuerpo)) throw new Error(`GitHub respondió ${r.estado} al listar los comentarios del PR #${numero}: ${mensajeDe(r.cuerpo)}`);
    const lista = r.cuerpo as Array<{ id: number; body?: string; user?: { type?: string } }>;
    existente = lista.find((c) => (c.body ?? "").startsWith(marcador) && c.user?.type === "Bot")?.id ?? lista.find((c) => (c.body ?? "").startsWith(marcador))?.id;
    if (lista.length < 100) break;
  }
  if (existente !== undefined) {
    const r = await pedir(f, `${api}/repos/${repo}/issues/comments/${existente}`, { method: "PATCH", headers: cabeceras, body: JSON.stringify({ body: cuerpo }) });
    if (r.estado === 200) return { accion: "editado", id: existente, url: (r.cuerpo as { html_url?: string }).html_url };
    if (r.estado !== 403 && r.estado !== 404) throw new Error(`GitHub respondió ${r.estado} al editar el comentario: ${mensajeDe(r.cuerpo)}`);
  }
  const r = await pedir(f, `${api}/repos/${repo}/issues/${numero}/comments`, { method: "POST", headers: cabeceras, body: JSON.stringify({ body: cuerpo }) });
  if (r.estado !== 201) throw new Error(`GitHub respondió ${r.estado} al crear el comentario: ${mensajeDe(r.cuerpo)}${r.estado === 403 ? " (¿falta pull-requests: write, o es un PR de un fork?)" : ""}`);
  const creado = r.cuerpo as { id: number; html_url?: string };
  return { accion: "creado", id: creado.id, url: creado.html_url };
}

/** Lo mismo en un MR de GitLab. Necesita un token con permiso de API (OROBAS_CI_GITLAB_TOKEN): el del job no alcanza. */
export async function comentarGitlab({ cuerpo, marcador, env, fetch: f = fetch, pr }: Opciones): Promise<Publicado> {
  const token = env.OROBAS_CI_GITLAB_TOKEN;
  const proyecto = env.CI_PROJECT_ID;
  const mr = pr ?? (env.CI_MERGE_REQUEST_IID ? Number(env.CI_MERGE_REQUEST_IID) : undefined);
  if (!token) throw new Error("Falta OROBAS_CI_GITLAB_TOKEN (un token de proyecto con permiso api) para comentar en el MR.");
  if (!proyecto) throw new Error("Falta CI_PROJECT_ID.");
  if (!mr) throw new Error("No es un merge request: no hay dónde comentar.");
  const api = (env.CI_API_V4_URL || "https://gitlab.com/api/v4").replace(/\/$/, "");
  const cabeceras = { "private-token": token, "content-type": "application/json", "user-agent": "orobas-sec-ci" };
  const base = `${api}/projects/${encodeURIComponent(proyecto)}/merge_requests/${mr}/notes`;
  let existente: number | undefined;
  for (let pagina = 1; pagina <= 30 && existente === undefined; pagina++) {
    const r = await pedir(f, `${base}?per_page=100&page=${pagina}&sort=asc`, { headers: cabeceras });
    if (r.estado !== 200 || !Array.isArray(r.cuerpo)) throw new Error(`GitLab respondió ${r.estado} al listar las notas del MR !${mr}: ${mensajeDe(r.cuerpo)}`);
    const lista = r.cuerpo as Array<{ id: number; body?: string }>;
    existente = lista.find((c) => (c.body ?? "").startsWith(marcador))?.id;
    if (lista.length < 100) break;
  }
  if (existente !== undefined) {
    const r = await pedir(f, `${base}/${existente}`, { method: "PUT", headers: cabeceras, body: JSON.stringify({ body: cuerpo }) });
    if (r.estado === 200) return { accion: "editado", id: existente };
    if (r.estado !== 403 && r.estado !== 404) throw new Error(`GitLab respondió ${r.estado} al editar la nota: ${mensajeDe(r.cuerpo)}`);
  }
  const r = await pedir(f, base, { method: "POST", headers: cabeceras, body: JSON.stringify({ body: cuerpo }) });
  if (r.estado !== 201) throw new Error(`GitLab respondió ${r.estado} al crear la nota: ${mensajeDe(r.cuerpo)}`);
  return { accion: "creado", id: (r.cuerpo as { id: number }).id };
}
