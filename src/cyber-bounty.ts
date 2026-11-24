import { calcularCvss } from "./cvss.ts";
import { cabecerasDePrivacidad } from "./privacidad-trazas.ts";
import { createHash } from "node:crypto";
import { orobasBaseUrl } from "./providers.ts";
import { readSecret, writeSecret, deleteSecret } from "./secretos.ts";
import { parseRule, type ScopeRule } from "./scope.ts";
import { avisoDeCabeceras, textoDePolitica } from "./politica-cabeceras.ts";
import { ReportRedactor } from "./redact.ts";
import type { Finding } from "./findings.ts";

export const loadBountyKey = () => process.env.CYBER_BOUNTY_KEY || readSecret("cyber-bounty");
export const saveBountyKey = (key: string) => writeSecret("cyber-bounty", key);
export const clearBountyKey = () => deleteSecret("cyber-bounty");
export const hashPayload = (body: unknown) => createHash("sha256").update(JSON.stringify(body)).digest("hex");
export interface BountyProgram {
  id: string; name: string; scope_revision: number; accepting_reports: boolean; status: string;
  policy?: string; authorization?: { by: string; role: string; at: string } | null;
  conduct: { max_requests_per_second: number; destructive_actions: boolean; agent_header: string; test_window: string; response_days?: number };
  scope: { include: Array<{ kind: string; value: string }>; exclude: Array<{ kind: string; value: string }> };
}

export class CyberBounty {
  readonly redactor = new ReportRedactor();
  private key: string;
  private fetchImpl: typeof fetch;
  constructor(key: string, fetchImpl: typeof fetch = fetch) {
    this.key = key;
    this.fetchImpl = fetchImpl;
    if (!/^bb_[A-Za-z0-9_-]+$/.test(key)) throw new Error("Cyber Bounty necesita una clave de agente bb_, no la clave oro_. Cargala con cyber login cyber-bounty.");
    this.redactor.headers({ authorization: `Bearer ${key}` });
  }
  private slug(value: string) {
    if (!/^[a-z0-9][a-z0-9_-]{0,99}$/.test(value)) throw new Error("Identificador de programa inválido.");
    return value;
  }
  private async request(path: string, init: RequestInit = {}): Promise<{ body?: any; etag?: string; unchanged?: boolean }> {
    const response = await this.fetchImpl(`${orobasBaseUrl().replace(/\/$/, "")}/bounty${path}`, {
      ...init, headers: { accept: "application/json", authorization: `Bearer ${this.key}`, ...init.headers, ...cabecerasDePrivacidad() }, signal: AbortSignal.timeout(30_000), redirect: "error",
    });
    if (response.status === 304) return { unchanged: true };
    const body = await response.json();
    if (!response.ok) throw new Error(`Cyber Bounty: ${this.redactor.finish(String(body.error?.message ?? `HTTP ${response.status}`))}`);
    return { body, etag: response.headers.get("etag") ?? undefined };
  }
  async programs(): Promise<BountyProgram[]> { return (await this.request("/programs")).body.data; }
  async program(slug: string, etag?: string) { return this.request(`/programs/${this.slug(slug)}`, { headers: etag ? { "If-None-Match": etag } : {} }); }
  async submit(slug: string, body: unknown, idempotencyKey: string) {
    return (await this.request(`/programs/${this.slug(slug)}/reports`, { method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, body: JSON.stringify(body) })).body;
  }
  async report(id: string) { return (await this.request(`/reports/${encodeURIComponent(id)}`)).body; }
  display(value: unknown) { return this.redactor.finish(JSON.stringify(value, null, 2)); }
}

export function bountyScope(program: BountyProgram) {
  const skipped: string[] = [];
  const convert = (items: BountyProgram["scope"]["include"]): ScopeRule[] => items.flatMap((item) => {
    try {
      if (!["host", "wildcard", "cidr", "url"].includes(item.kind)) throw new Error();
      const rule = parseRule(item.kind === "url" ? `https://${item.value}` : item.value);
      if (rule.kind !== item.kind) throw new Error();
      return [rule];
    } catch { skipped.push(`${item.kind}: ${item.value}`); return []; }
  });
  const include = convert(program.scope.include), exclude = convert(program.scope.exclude);
  if (skipped.length && program.scope.exclude.some((item) => skipped.includes(`${item.kind}: ${item.value}`))) throw new Error(`Hay exclusiones que no se pueden importar: ${skipped.join(" · ")}. No se amplía el alcance.`);
  const c = program.conduct;
  const aviso = avisoDeCabeceras(program.policy, c.agent_header);
  const notes = [
    `Cyber «${program.id}». scope_revision: ${program.scope_revision}.`,
    aviso,
    `Política: ${textoDePolitica(program.policy).slice(0, 8000)}`,
    `Autorización: ${JSON.stringify(program.authorization ?? null).slice(0, 2000)}`,
    `Conducta: máximo ${c.max_requests_per_second} peticiones/s; acciones destructivas: ${c.destructive_actions ? "permitidas" : "prohibidas"}; cabecera del agente: ${textoDePolitica(c.agent_header)}; ventana: ${c.test_window}. Aplicá estas restricciones también en herramientas externas; no reemplazan límites más estrictos del operador.`,
  ].filter(Boolean).join("\n");
  return { include, exclude, skipped, notes };
}

export function bountyDraft(finding: Omit<Finding, "cvss"> & { cwe?: string; cvss?: string | number }, read: (hash: string) => Buffer, redactor: ReportRedactor) {
  if (finding.state !== "verificado") throw new Error("Sólo se envían hallazgos verificados.");
  if (finding.severity === "informativa") throw new Error("No se envían hallazgos de severidad informativa.");
  if (finding.evidence.length > 20) throw new Error("El reporte admite hasta 20 artefactos.");
  const evidence = finding.evidence.map((ref) => {
    const bytes = read(ref);
    return { name: ref, sha256: createHash("sha256").update(bytes).digest("hex"), text: bytes.toString("utf8") };
  });
  const poc = redactor.text(evidence.map((e) => {
    try {
      const data = JSON.parse(e.text);
      if (data.request?.method && data.request?.url) {
        const u = new URL(data.request.url);
        return `${data.request.method} ${u.pathname}${u.search} HTTP/1.1\nHost: ${u.host}\n${Object.entries(data.request.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join("\n")}\n\n${data.request.body ?? ""}\n${e.text}`;
      }
    } catch {}
    return e.text;
  }).join("\n\n")).slice(0, 20_000);
  if (!/^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP\/[\d.]+\s*$/im.test(poc) && !/\bcurl\s+[^\n]*https?:\/\//i.test(poc)) throw new Error("La evidencia no trae un pedido HTTP ni curl reproducible. Agregá el intercambio antes de pedir aprobación.");
  const cvss = typeof finding.cvss === "string" ? calcularCvss(finding.cvss).puntaje : finding.cvss;
  const body = { title: redactor.text(finding.title).slice(0, 160), asset: redactor.url(finding.asset), severity: finding.severity, ...(finding.cwe ? { cwe: finding.cwe } : {}), ...(cvss !== undefined ? { cvss } : {}), summary: redactor.text(finding.summary).slice(0, 4000), steps: redactor.text(`${finding.summary}\nLímites: ${finding.limits}`).slice(0, 8000), poc, evidence: evidence.map(({ name, sha256 }) => ({ name, sha256 })) };
  for (const field of ["title", "asset", "summary", "steps", "poc"] as const) body[field] = redactor.finish(body[field]);
  if (body.title.length < 8) throw new Error("El título necesita al menos 8 caracteres.");
  if (Buffer.byteLength(JSON.stringify(body)) > 256 * 1024) throw new Error("El reporte supera los 256 KB.");
  return body;
}
