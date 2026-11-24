// HackerOne: programas del usuario y su alcance. La API para hackers no ofrece OAuth;
// usa un token personal por HTTP Basic. El token vive cifrado en la carpeta de credenciales del usuario.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { t } from "./idioma.ts";
import { deleteSecret, readSecret, writeSecret } from "./secretos.ts";
import { avisoDeCabeceras, textoDePolitica } from "./politica-cabeceras.ts";
import { parseRule, scopeView, type ScopeRule, type ScopeStore } from "./scope.ts";

const API = "https://api.hackerone.com/v1/hackers";
const KEYRING = ["service", "elevate-cyber", "account", "hackerone"];
/** Si no hay llavero (sin servicio Secret Service), archivo sólo legible por el usuario. */
const FILE = join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "elevate-cyber", "hackerone.json");

export interface Credentials {
  username: string;
  token: string;
}

/** Entorno primero (CI); después el almacén cifrado; por compatibilidad, el llavero y el archivo viejos. */
export function loadCredentials(): Credentials | undefined {
  if (process.env.H1_USERNAME && process.env.H1_API_TOKEN) return { username: process.env.H1_USERNAME, token: process.env.H1_API_TOKEN };
  try {
    const own = JSON.parse(readSecret("hackerone") ?? "null");
    if (own?.username && own?.token) return { username: own.username, token: own.token };
  } catch {}
  // Llavero y archivo viejos: sólo lectura, por compatibilidad.
  try {
    const stored = (process.platform === "darwin"
      ? execFileSync("security", ["find-generic-password", "-s", "elevate-cyber", "-a", "hackerone", "-w"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })
      : execFileSync("secret-tool", ["lookup", ...KEYRING], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })).trim();
    const split = stored.indexOf(":");
    if (split > 0) return { username: stored.slice(0, split), token: stored.slice(split + 1) };
  } catch {}
  try {
    if (existsSync(FILE)) return JSON.parse(readFileSync(FILE, "utf8"));
  } catch {}
  return undefined;
}

/** Devuelve dónde quedó guardado. */
export function saveCredentials(credentials: Credentials): string {
  const { encrypted, path } = writeSecret("hackerone", JSON.stringify(credentials));
  return encrypted
    ? t("cifrado en tu carpeta de credenciales", "encrypted in your credentials folder")
    : `${path} ${t("(sin cifrar: no hay llave; el archivo es legible sólo por tu usuario)", "(unencrypted: no key available; the file is readable only by your user)")}`;
}

export function clearCredentials(): void {
  deleteSecret("hackerone");
  if (process.platform === "darwin") spawnSync("security", ["delete-generic-password", "-s", "elevate-cyber", "-a", "hackerone"], { stdio: "ignore" });
  else spawnSync("secret-tool", ["clear", ...KEYRING], { stdio: "ignore" });
  try {
    unlinkSync(FILE);
  } catch {}
}

type Fetch = typeof fetch;

export class HackerOne {
  private credentials: Credentials;
  private fetch: Fetch;

  constructor(credentials: Credentials, fetchImpl: Fetch = fetch) {
    this.credentials = credentials;
    this.fetch = fetchImpl;
  }

  private async get(path: string): Promise<any> {
    const { username, token } = this.credentials;
    const response = await this.fetch(`${API}${path}`, {
      headers: { accept: "application/json", authorization: `Basic ${Buffer.from(`${username}:${token}`).toString("base64")}` },
    });
    if (response.status === 401) throw new Error("HackerOne rechazó las credenciales. Volvé a cargarlas con: cyber login hackerone");
    if (response.status === 404) throw new Error("HackerOne no encontró ese programa (o tu cuenta no tiene acceso).");
    if (!response.ok) throw new Error(`HackerOne respondió HTTP ${response.status}`);
    return response.json();
  }

  private async pages(path: string, max = 20): Promise<any[]> {
    const items: any[] = [];
    for (let page = 1; page <= max; page++) {
      const body = await this.get(`${path}${path.includes("?") ? "&" : "?"}page%5Bsize%5D=100&page%5Bnumber%5D=${page}`);
      items.push(...(body.data ?? []));
      if (!body.links?.next || !(body.data ?? []).length) break;
    }
    return items;
  }

  /** Programas a los que la cuenta tiene acceso. */
  async programs(): Promise<Array<{ handle: string; name: string; state: string; bounties: boolean; submission: string }>> {
    return (await this.pages("/programs")).map((item) => ({
      handle: item.attributes?.handle ?? "",
      name: item.attributes?.name ?? "",
      state: item.attributes?.state ?? "",
      bounties: !!item.attributes?.offers_bounties,
      submission: item.attributes?.submission_state ?? "",
    }));
  }

  /** Alcance estructurado de un programa, traducido a reglas. Lo que no es un destino de red queda como nota. */
  async scope(handle: string): Promise<ImportedScope> {
    if (!/^[a-z0-9_-]+$/i.test(handle)) throw new Error("Identificador de programa inválido");
    const assets = await this.pages(`/programs/${handle}/structured_scopes`);
    return translateAssets(assets.map((asset) => {
      const { asset_type: type, asset_identifier: identifier, eligible_for_submission: eligible, eligible_for_bounty: bounty, instruction, max_severity: severity } = asset.attributes ?? {};
      return { type: String(type ?? ""), identifier: String(identifier ?? ""), eligible: !!eligible, ...(typeof bounty === "boolean" ? { bounty } : {}), instruction, severity };
    }), handle);
  }
}

export interface ImportedScope {
  include: ScopeRule[];
  exclude: ScopeRule[];
  /** Código fuente del programa (SOURCE_CODE, o una URL de GitHub/GitLab/Bitbucket): se lee con reference_read, no se prueba. */
  reference: ScopeRule[];
  skipped: string[];
  notes: string;
}

/** Un activo del alcance, venga de la API con token o del CSV público. */
export interface Asset {
  type: string;
  identifier: string;
  eligible: boolean;
  /** Elegible para recompensa (eligible_for_bounty), si la fuente lo dice. */
  bounty?: boolean;
  instruction?: unknown;
  severity?: unknown;
}

const NETWORK_TYPES = new Set(["URL", "WILDCARD", "DOMAIN", "CIDR", "IP_ADDRESS", "API"]);
/** Donde vive código: una URL ahí es para leer el código del programa, no un servidor a probar. */
const CODE_HOSTS = /^(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)$/i;

/**
 * Traduce los activos de un programa a reglas: los elegibles adentro, los no elegibles excluidos, el
 * código fuente a lectura de referencia y el resto (apps móviles, «OTHER») como no importado, para que
 * el operador lo vea. «https://*.dominio/» es un comodín.
 */
export function translateAssets(assets: Asset[], handle: string): ImportedScope {
  const include: ScopeRule[] = [];
  const exclude: ScopeRule[] = [];
  const reference: ScopeRule[] = [];
  const skipped: string[] = [];
  for (const asset of assets) {
    const { type, identifier, eligible } = asset;
    if (!identifier.trim()) continue;
    const instrucciones = textoDePolitica(asset.instruction);
    const note = [
      avisoDeCabeceras(instrucciones),
      asset.bounty === true ? "con recompensa" : asset.bounty === false ? "sin recompensa" : "",
      asset.severity && `severidad máx. ${asset.severity}`,
      instrucciones.replace(/\s+/g, " ").slice(0, 120),
    ].filter(Boolean).join(" · ") || undefined;
    // Un identificador puede traer varios destinos separados por coma.
    for (const raw of identifier.split(",")) {
      const part = raw.trim().replace(/^(https?:\/\/)(\*\.[^/]+)\/?$/i, "$2");
      if (!part) continue;
      let host = "";
      let path = "";
      try { ({ hostname: host, pathname: path } = new URL(/^[a-z]+:\/\//i.test(part) ? part : `https://${part}`)); } catch { /* no es una URL */ }
      // Un repositorio o una organización (github.com/org/…) es código para leer. El host pelado es la
      // plataforma misma: en el programa de GitHub, GitLab o Bitbucket es un objetivo y se prueba.
      const repository = CODE_HOSTS.test(host) && path.replace(/\/+$/, "") !== "";
      if (type === "SOURCE_CODE" || (NETWORK_TYPES.has(type) && repository)) {
        if (!eligible) continue;
        try { reference.push(parseRule(/^[a-z]+:\/\//i.test(part) ? part : `https://${part}`, note)); } catch { skipped.push(`${type}: ${part}`); }
        continue;
      }
      if (!NETWORK_TYPES.has(type)) {
        skipped.push(`${type}: ${part}`);
        continue;
      }
      try {
        (eligible ? include : exclude).push(parseRule(part, eligible ? note : `no elegible${note ? ` · ${note}` : ""}`));
      } catch {
        skipped.push(`${type}: ${part}`);
      }
    }
  }
  return { include, exclude, reference, skipped, notes: `Programa HackerOne «${handle}». Leé la política completa del programa antes de probar: este alcance es sólo la lista de activos.` };
}

/** CSV (RFC 4180): comillas dobles, «""» como comilla y saltos de línea dentro de un campo. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  const input = text.replace(/^\uFEFF/, "");
  for (let index = 0; index < input.length; index++) {
    const char = input[index]!;
    if (quoted) {
      if (char === '"' && input[index + 1] === '"') { field += '"'; index++; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"' && field === "") quoted = true;
    else if (char === ",") { row.push(field); field = ""; }
    else if (char === "\n" || char === "\r") {
      if (char === "\r" && input[index + 1] === "\n") index++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += char;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows;
}

/** El handle de un programa, escrito tal cual o como URL de su página en HackerOne (…/policy_scopes). */
export function programHandle(text: string): string {
  const value = text.trim();
  if (/^https?:\/\//i.test(value)) {
    const url = new URL(value);
    if (!/^(www\.)?hackerone\.com$/i.test(url.hostname)) throw new Error(`${url.hostname} no es HackerOne: pasá el handle del programa o la URL de su página en hackerone.com.`);
    const [first, second] = url.pathname.split("/").filter(Boolean);
    const handle = first === "teams" ? second : first;
    if (!handle) throw new Error("La URL no nombra un programa de HackerOne.");
    return handle.toLowerCase();
  }
  return value.replace(/^@/, "").toLowerCase();
}

/**
 * Alcance público de un programa de HackerOne sin token: el CSV que publica su página de alcance
 * (policy_scopes → «Download CSV»). Un GET de sólo lectura a hackerone.com, sin credenciales ni
 * cookies; los programas privados no lo publican (responden una página, no un CSV).
 */
export async function publicScope(handle: string, fetchImpl: typeof fetch = fetch): Promise<ImportedScope> {
  if (!/^[a-z0-9_-]+$/i.test(handle)) throw new Error("Identificador de programa inválido");
  const response = await fetchImpl(`https://hackerone.com/teams/${handle}/assets/download_csv.csv`, { method: "GET", redirect: "manual", headers: { accept: "text/csv", "user-agent": "ElevateAICyber/0.1" }, signal: AbortSignal.timeout(30_000) });
  const type = response.headers.get("content-type") ?? "";
  if (response.status !== 200 || !/csv/i.test(type)) throw new Error(`HackerOne no publica el alcance de «${handle}» (HTTP ${response.status}${type ? `, ${type.split(";")[0]}` : ""}): el programa no es público, no existe o el handle está mal. Si es privado, cargá el token con /hackerone y volvé a pedirlo.`);
  const [header, ...rows] = parseCsv(await response.text());
  const column = (name: string) => header?.indexOf(name) ?? -1;
  const at = { identifier: column("identifier"), type: column("asset_type"), eligible: column("eligible_for_submission"), bounty: column("eligible_for_bounty"), instruction: column("instruction"), severity: column("max_severity") };
  if (at.identifier < 0 || at.type < 0 || at.eligible < 0) throw new Error(`El CSV de «${handle}» no tiene la forma esperada (identifier, asset_type, eligible_for_submission): no lo cargo a ciegas.`);
  return translateAssets(rows.filter((row) => row.length > 1).map((row) => ({ type: row[at.type] ?? "", identifier: row[at.identifier] ?? "", eligible: row[at.eligible] === "true", ...(at.bounty >= 0 && /^(true|false)$/.test(row[at.bounty] ?? "") ? { bounty: row[at.bounty] === "true" } : {}), instruction: row[at.instruction] || undefined, severity: row[at.severity] || undefined })), handle);
}

export type Program = Awaited<ReturnType<HackerOne["programs"]>>[number];

/** Lista de programas para mostrar: abiertos por defecto, «todos», o los que coinciden con «buscar». */
export function programLines(all: Program[], action?: string, search?: string): string[] {
  if (!all.length) return ["Tu cuenta de HackerOne no tiene programas accesibles por la API."];
  const query = (action === "buscar" ? search ?? "" : "").toLowerCase();
  const everything = action === "todos";
  const programs = all
    .filter((program) => (everything || program.submission === "open") && (!query || `${program.handle} ${program.name}`.toLowerCase().includes(query)))
    .sort((a, b) => Number(b.bounties) - Number(a.bounties) || a.handle.localeCompare(b.handle));
  const shown = programs.slice(0, everything || query ? 200 : 60);
  return [
    `HACKERONE · ${programs.length} programas${query ? ` con «${query}»` : everything ? "" : " abiertos"} de ${all.length} accesibles${shown.length < programs.length ? ` · se muestran ${shown.length}` : ""}`,
    ...shown.map((program) => `${program.handle.padEnd(28)} ${(program.bounties ? "paga" : "sin pago").padEnd(9)} ${program.submission.padEnd(8)} ${program.name.slice(0, 40)}`),
  ];
}

/**
 * Importa el alcance de un programa como revisión nueva del alcance de la sesión. Con token, por la
 * API (también los privados); sin token, el CSV público del programa. Los destinos locales que ya
 * estaban (un laboratorio) se conservan y se dice.
 */
export async function importScope(api: HackerOne | undefined, store: ScopeStore, handle: string, fetchImpl?: typeof fetch): Promise<string[]> {
  const imported = api ? await api.scope(handle) : await publicScope(handle, fetchImpl);
  if (!imported.include.length && !imported.reference.length) throw new Error(`El programa ${handle} no tiene activos de red elegibles en su alcance (ni código fuente).`);
  const { saved, kept } = store.saveProgram({ source: `hackerone:${handle}`, include: imported.include, exclude: imported.exclude, notes: imported.notes, reference: imported.reference });
  return [
    `Alcance importado de HackerOne «${handle}»: ${imported.include.length} dentro, ${imported.exclude.length} excluidos${imported.reference.length ? `, ${imported.reference.length} de código fuente para leer con reference_read` : ""} (rev ${saved.rev}). Fuente: ${api ? "la API, con tu token" : "el CSV público del programa, sin token"}.`,
    ...(imported.reference.length ? ["Es de código abierto: antes de probar, leé lo reciente del repositorio (commits y PRs mergeados, CHANGELOG, roadmap, documentación) buscando regresiones, arreglos incompletos y funciones nuevas sin endurecer; la habilidad ingenieria-inversa dice cómo."] : []),
    ...(kept.length ? [`Conservé del alcance anterior los destinos locales (laboratorio): ${kept.map((rule) => rule.value).join(", ")}. Si ya no van: /alcance quitar <regla>.`] : []),
    ...(imported.skipped.length ? [`No importados (${imported.skipped.length}; no son destinos de red): ${imported.skipped.slice(0, 8).join(" · ")}. Revisalos y agregá a mano lo que corresponda.`] : []),
    "",
    ...scopeView(saved),
  ];
}

/**
 * Borrador de submission para la API de HackerOne (POST /reports), construido desde un hallazgo
 * verificado del proyecto. Sólo la forma del payload: nada se envía en esta tanda; el envío
 * (con confirmación explícita del operador y redacción previa) queda para la siguiente.
 */
export interface H1ReportDraft {
  /** Título corto: clase + activo, sin adjetivos. */
  title: string;
  vulnerability_information: string;
  severity_rating?: "none" | "low" | "medium" | "high" | "critical";
  disclosure_requested?: boolean;
}

export function draftReport(finding: {
  title: string;
  summary: string;
  motive?: string;
  limits?: string;
  steps?: string[];
  asset: string;
  severity: string;
}, lang: "es" | "en" = "en"): H1ReportDraft {
  const severityMap: Record<string, NonNullable<H1ReportDraft["severity_rating"]>> = { informativa: "none", baja: "low", media: "medium", alta: "high", critica: "critical" };
  const rating = severityMap[finding.severity];
  if (!rating) throw new Error(`Severidad desconocida «${finding.severity}»`);
  const body = [finding.summary, finding.motive ? `Motivo: ${finding.motive}` : undefined, finding.steps?.length ? `Pasos:\n${finding.steps.map((step, index) => `${index + 1}. ${step}`).join("\n")}` : undefined, finding.limits ? `Límites: ${finding.limits}` : undefined].filter(Boolean).join("\n\n");
  return { title: `${finding.title} — ${finding.asset}`, vulnerability_information: body, severity_rating: rating };
}
/** Envia un borrador como reporte a un programa de HackerOne. multipart/form-data, como la API espera. */
export async function submitDraft(api: HackerOne, draft: H1ReportDraft, handle: string, options: { fetch?: typeof fetch; confirmar?: (resumen: string) => Promise<boolean> } = {}): Promise<{ id: string; url: string }> {
  if (!/^[a-z0-9_-]+$/i.test(handle)) throw new Error("Identificador de programa inválido");
  const payload = {
    data: {
      type: "report",
      attributes: { title: draft.title, vulnerability_information: draft.vulnerability_information, severity_rating: draft.severity_rating ?? undefined, disclosure_requested: !!draft.disclosure_requested },
    },
  };
  if (options.confirmar && !(await options.confirmar(JSON.stringify(payload, null, 1)))) throw new Error("El operador no confirmó el envío: no se envió nada.");
  const form = new FormData();
  form.append("data", JSON.stringify(payload));
  const request = await (options.fetch ?? fetch)(`${API}/reports`, {
    method: "POST",
    headers: { accept: "application/json", authorization: `Basic ${Buffer.from(`${(api as any).credentials.username}:${(api as any).credentials.token}`).toString("base64")}` },
    body: form,
  });
  const body = await request.json().catch(() => ({}));
  if (!request.ok) throw new Error(`HackerOne rechazó la submission (HTTP ${request.status}). ${JSON.stringify(body?.errors?.[0] ?? body).slice(0, 200)}`);
  const id = String(body?.data?.id ?? "");
  if (!id) throw new Error("HackerOne respondió sin id de reporte; el envío pudo quedar a medias: revisá tu bandeja antes de reintentar.");
  return { id, url: `https://hackerone.com/reports/${id}` };
}
