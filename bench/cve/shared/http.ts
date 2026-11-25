import { lookup } from "node:dns/promises";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Artifacts } from "../../../src/artifacts.ts";
import { HttpClient } from "../../../src/http.ts";
import { parseRule, type Scope } from "../../../src/scope.ts";

/** La preparación también deja evidencia y sólo puede hablar con su objetivo. */
export async function createLabHttp(base: string, evidenceDir: string) {
  const origin = new URL(base).origin;
  const target = new URL(origin);
  // Las reglas URL del harness no distinguen puertos predeterminados; estos labs usan puertos explícitos.
  if (!target.port) throw new Error("El laboratorio debe usar un puerto distinto de 80/443");
  const addresses = await lookup(target.hostname.replace(/^\[|\]$/g, ""), { all: true });
  const resolved = addresses.map(({ address }) => {
    const url = new URL(origin);
    url.hostname = address.includes(":") ? `[${address}]` : address;
    return parseRule(`${url.origin}/`);
  });
  mkdirSync(evidenceDir, { recursive: true });
  const db = new DatabaseSync(join(evidenceDir, "http.sqlite"));
  db.exec("CREATE TABLE IF NOT EXISTS artifacts (hash TEXT PRIMARY KEY, bytes INTEGER, media_type TEXT, producer TEXT, created_at TEXT)");
  const scope: Scope = {
    rev: 1, source: "manual", at: new Date().toISOString(), notes: "Preparación del laboratorio",
    include: [parseRule(`${origin}/`), ...resolved], exclude: [],
  };
  const http = new HttpClient(new Artifacts(db, join(evidenceDir, "artifacts")), () => scope);
  return { http, close: () => db.close() };
}

export async function requestJson(http: HttpClient, base: string, path: string, options: {
  method?: string; body?: unknown; headers?: Record<string, string>; expected?: number[];
} = {}): Promise<any> {
  const exchange = await http.send({
    url: new URL(path, base).toString(), method: options.method ?? "GET",
    headers: { accept: "application/json", ...(options.body === undefined ? {} : { "content-type": "application/json" }), ...options.headers },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const response = exchange.response;
  if (!response || (options.expected ? !options.expected.includes(response.status) : response.status < 200 || response.status >= 300)) {
    throw new Error(`${options.method ?? "GET"} ${path}: ${response?.status ?? exchange.error}; artefacto ${exchange.artifact}`);
  }
  return response.body ? JSON.parse(response.body) : undefined;
}
