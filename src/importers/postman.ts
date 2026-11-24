// Las colecciones describen superficie; importarlas no autoriza ejecutarlas.
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import type { Tool } from "../agent.ts";
import type { Artifacts } from "../artifacts.ts";
import type { HttpClient, ObservedOperation } from "../http.ts";
import { decide } from "../scope.ts";

export interface ImportContext { artifacts: Artifacts; http: HttpClient; cwd?: string }
export interface LocalSource { path?: string; artifact?: string }

/** El error no cita el documento: podría contener credenciales. */
export function readLocalJson(context: Pick<ImportContext, "artifacts" | "cwd">, source: LocalSource): any {
  if (Number(!!source.path) + Number(!!source.artifact) !== 1) throw new Error("Pasá path o artifact, sólo uno.");
  let bytes: Buffer;
  if (source.path) {
    const path = resolve(context.cwd ?? process.cwd(), source.path);
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > 20 * 1024 * 1024) throw new Error("El archivo debe ser regular y de hasta 20 MiB.");
    bytes = readFileSync(path);
  } else bytes = context.artifacts.read(source.artifact!);
  if (bytes.length > 20 * 1024 * 1024) throw new Error("El documento supera 20 MiB.");
  try { return JSON.parse(bytes.toString("utf8").replace(/^\uFEFF/, "")); }
  catch { throw new Error("El documento debe ser JSON válido; YAML no está soportado."); }
}

const sensitive = /password|passwd|contrase[ñn]a|secret|token|authorization|cookie|api[_-]?key|credential|session/i;

/** Conserva los ejemplos útiles sin convertir un secreto en parte de la superficie. */
export function safeExample(body: unknown, secrets: string[] = []): string | undefined {
  if (body === undefined) return undefined;
  let value = body;
  let form = false;
  if (typeof body === "string") {
    try { value = JSON.parse(body); }
    catch {
      // Un cuerpo opaco puede ser un token completo: sólo conservamos ejemplos estructurados.
      if (!/^[A-Za-z0-9_%.[\]-]+=/.test(body)) return "<cuerpo omitido>";
      value = [...new URLSearchParams(body)];
      form = true;
    }
  }
  const known = new Set(secrets.filter((secret) => secret && secret !== "<credencial>"));
  const remember = (item: unknown): void => {
    if (typeof item === "string" && item && item !== "<credencial>") {
      known.add(item);
      try { known.add(encodeURIComponent(item)); } catch {}
    } else if (Array.isArray(item)) item.forEach(remember);
    else if (item && typeof item === "object") Object.values(item).forEach(remember);
  };
  const collect = (item: unknown, key = ""): void => {
    if (sensitive.test(key)) remember(item);
    if (Array.isArray(item)) item.forEach((child) => collect(child));
    else if (item && typeof item === "object") for (const [name, child] of Object.entries(item)) collect(child, name);
    else if (typeof item === "string") for (const match of item.matchAll(/\bBearer\s+([^\s"']+)/gi)) remember(match[1]);
  };
  if (form) for (const [key, item] of value as string[][]) collect(item, key);
  else collect(value);
  const escaped = [...known].sort((a, b) => b.length - a.length).map((secret) => secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = escaped.length ? new RegExp(`<credencial>|${escaped.join("|")}`, "g") : undefined;
  const text = (item: string) => pattern ? item.replace(pattern, "<credencial>") : item;
  const mask = (item: unknown, key = ""): unknown => {
    if (sensitive.test(key)) return "<credencial>";
    if (Array.isArray(item)) return item.map((child) => mask(child));
    if (item && typeof item === "object") return Object.fromEntries(Object.entries(item).map(([name, child]) => [text(name), mask(child, name)]));
    return typeof item === "string" ? text(item) : item;
  };
  if (form) return new URLSearchParams((value as string[][]).map(([key, item]) => [text(key!), String(mask(item, key))])).toString();
  return JSON.stringify(mask(value));
}

function secretValues(value: any): string[] {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap(secretValues);
  const auth = value.auth && typeof value.auth === "object" ? Object.values(value.auth).flatMap((items) => Array.isArray(items) ? items.filter((item) => item && typeof item.value === "string").map((item) => item.value as string) : []) : [];
  const direct = (sensitive.test(String(value.key ?? "")) || value.type === "secret") && value.value != null ? [String(value.value)] : [];
  return [...auth, ...direct, ...Object.entries(value).flatMap(([key, item]) => sensitive.test(key) && typeof item === "string" ? [item] : secretValues(item))];
}

function variables(items: any, into: Map<string, string>): void {
  if (items === undefined) return;
  if (!Array.isArray(items)) throw new Error("Lista de variables inválida.");
  for (const item of items) {
    if (!item || typeof item.key !== "string") throw new Error("Variable sin nombre.");
    if (item.disabled || item.enabled === false) continue;
    into.set(item.key, String(item.value ?? ""));
  }
}

function expand(value: string, vars: Map<string, string>): string {
  let text = value;
  for (let pass = 0; pass < 10; pass++) {
    const next = text.replace(/\{\{([^{}]+)\}\}/g, (_, key: string) => vars.get(key) ?? `{{${key}}}`);
    if (next === text) break;
    text = next;
  }
  if (/\{\{[^{}]+\}\}/.test(text)) throw new Error("Hay variables sin resolver o cíclicas; completá el entorno.");
  return text;
}

export function createPostmanTools(context: ImportContext): Tool[] {
  return [{
    name: "postman_import",
    label: "Importar Postman",
    description: "Cuando el proyecto trae una colección Postman v2.1, importala desde path o artifact, con environmentPath o environmentArtifact opcional. Agrega operaciones vistas y cuerpos de ejemplo al mapa sin enviar peticiones ni ejecutar scripts. El entorno prevalece sobre las variables de la colección.",
    parameters: { type: "object", properties: {
      path: { type: "string" }, artifact: { type: "string" },
      environmentPath: { type: "string" }, environmentArtifact: { type: "string" },
    }, required: [] },
    replay: "safe",
    execute: (params) => {
      const collection = readLocalJson(context, params);
      if (!collection || !/\/collection\/v2\.1\.0\/collection\.json$/.test(collection.info?.schema ?? "") || !Array.isArray(collection.item)) throw new Error("Se espera una colección Postman v2.1 con info.schema e item.");
      const env = new Map<string, string>();
      const knownSecrets = secretValues(collection);
      if (params.environmentPath || params.environmentArtifact) {
        const environment = readLocalJson(context, { path: params.environmentPath, artifact: params.environmentArtifact });
        if (!environment || !Array.isArray(environment.values)) throw new Error("El entorno Postman debe tener values.");
        variables(environment.values, env);
        knownSecrets.push(...secretValues(environment));
      }
      const operations: ObservedOperation[] = [];
      let skippedScripts = collection.event?.length ?? 0;
      const visit = (items: any[], inherited: Map<string, string>, depth: number): void => {
        if (depth > 30) throw new Error("La colección supera 30 niveles de carpetas.");
        for (const item of items) {
          if (!item || typeof item !== "object") throw new Error("Elemento de colección inválido.");
          const vars = new Map(inherited);
          variables(item.variable, vars);
          for (const [key, value] of env) vars.set(key, value);
          if (item.event?.length) skippedScripts += item.event.length;
          if (Array.isArray(item.item)) { visit(item.item, vars, depth + 1); continue; }
          const request = item.request;
          if (!request || typeof request !== "object" || typeof request.method !== "string" || !/^[A-Za-z]+$/.test(request.method)) throw new Error("Petición Postman sin método o URL válidos.");
          const spec = request.url;
          const urlVars = new Map(vars);
          if (spec && typeof spec === "object") variables(spec.variable, urlVars);
          let raw: string;
          if (typeof spec === "string") raw = spec;
          else if (typeof spec?.raw === "string") raw = spec.raw;
          else if (spec && spec.host) {
            const host = Array.isArray(spec.host) ? spec.host.join(".") : spec.host;
            const path = Array.isArray(spec.path) ? spec.path.join("/") : spec.path ?? "";
            raw = `${spec.protocol ?? "https"}://${host}${spec.port ? `:${spec.port}` : ""}/${path}`;
          } else throw new Error("Petición Postman sin URL válida.");
          const pathParams = [...raw.matchAll(/:([A-Za-z_][\w]*)(?=\/|\?|#|$)/g)].map((match) => match[1]!);
          raw = expand(raw, urlVars).replace(/:([A-Za-z_][\w]*)(?=\/|\?|#|$)/g, (whole, key: string) => urlVars.has(key) ? encodeURIComponent(expand(urlVars.get(key)!, urlVars)) : whole);
          let url: URL;
          try { url = new URL(raw); } catch { throw new Error("Una URL de la colección no es absoluta o válida."); }
          if (!/^https?:$/.test(url.protocol)) throw new Error("Sólo se importan operaciones HTTP o HTTPS.");
          if (Array.isArray(spec?.query)) for (const field of spec.query) {
            if (typeof field.key !== "string") throw new Error("Parámetro de consulta inválido.");
            if (field.disabled) url.searchParams.delete(expand(field.key, urlVars));
            else url.searchParams.set(expand(field.key, urlVars), expand(String(field.value ?? ""), urlVars));
          }
          // El secreto puede llegar por una variable de nombre neutro o una cadena de referencias.
          const secrets = [...knownSecrets.flatMap((value) => {
            try { return [expand(value, urlVars)]; } catch { return []; }
          }), ...[...urlVars].filter(([key]) => sensitive.test(key)).map(([, value]) => expand(value, urlVars)), url.username, url.password].filter(Boolean);
          if (Array.isArray(request.header)) for (const header of request.header) if (sensitive.test(header.key ?? "") && typeof header.value === "string") {
            const value = expand(header.value, urlVars);
            secrets.push(value, value.replace(/^(?:Bearer|Basic)\s+/i, ""));
            if (/cookie/i.test(header.key)) secrets.push(...value.split(";").map((part) => part.slice(part.indexOf("=") + 1).trim()));
          }
          if (request.body?.mode === "raw") {
            try { secrets.push(...secretValues(JSON.parse(expand(String(request.body.raw ?? ""), urlVars)))); } catch {}
          }
          const variants = [...new Set(secrets.filter(Boolean).flatMap((secret) => [secret, encodeURIComponent(secret)]))].sort((a, b) => b.length - a.length);
          const pattern = variants.length ? new RegExp(variants.map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g") : undefined;
          const redact = (text: string) => pattern ? text.replace(pattern, "<credencial>") : text;
          if (redact(url.host) !== url.host) throw new Error("Una credencial forma parte del host; corregí la URL antes de importar.");
          url.pathname = redact(url.pathname);
          let body: string | undefined;
          let bodyKeys: string[] = [];
          if (request.body?.mode === "raw") body = safeExample(expand(String(request.body.raw ?? ""), urlVars), secrets);
          else if (["urlencoded", "formdata"].includes(request.body?.mode)) {
            const fields = request.body[request.body.mode];
            if (!Array.isArray(fields)) throw new Error("Cuerpo Postman inválido.");
            const pairs: Array<[string, string]> = fields.filter((field: any) => !field.disabled).map((field: any) => {
              if (typeof field.key !== "string") throw new Error("Campo del cuerpo sin nombre.");
              return [expand(field.key, urlVars), field.type === "file" ? "<archivo>" : expand(String(field.value ?? ""), urlVars)];
            });
            bodyKeys = pairs.map(([key]) => key);
            body = safeExample(new URLSearchParams(pairs).toString(), secrets);
          } else if (request.body?.mode) body = "<cuerpo omitido>";
          if (body) try { bodyKeys = Object.keys(JSON.parse(body)); } catch {}
          operations.push({ url: url.toString(), method: request.method.toUpperCase(), params: [...new Set(url.searchParams.keys())].map(redact), pathParams: pathParams.map(redact), bodyKeys: bodyKeys.map(redact), body });
          if (operations.length > 10000) throw new Error("La colección supera 10000 operaciones.");
        }
      };
      const initial = new Map<string, string>();
      variables(collection.variable, initial);
      visit(collection.item, initial, 0);
      const rows = ["Método  Host  Ruta  Alcance  Parámetros / cuerpo"];
      const outside = new Set<string>();
      for (const operation of operations) {
        const url = new URL(operation.url);
        const allowed = decide(context.http.scope(), operation.url).allowed;
        if (!allowed) outside.add(url.host);
        context.http.observe(operation);
        rows.push(`${operation.method.padEnd(7)} ${url.host} ${url.pathname} ${allowed ? "dentro" : "fuera"} ${operation.params?.map((name) => `?${name}`).join(" ") ?? ""}${operation.bodyKeys?.length ? ` cuerpo: ${operation.bodyKeys.join(", ")}` : ""}`.trim());
      }
      rows.push(`${operations.length} operaciones vistas; 0 peticiones enviadas. Scripts no ejecutados${skippedScripts ? `: ${skippedScripts}` : "."}`);
      if (outside.size) rows.push(`Hosts fuera del alcance: ${[...outside].join(", ")}`);
      return { text: rows.join("\n"), details: { operaciones: operations.length, fueraDeAlcance: [...outside] } };
    },
  }];
}
