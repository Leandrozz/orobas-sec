// Herramientas de análisis web propias, sobre nuestro cliente HTTP: alcance validado en cada
// petición, request y response completos como artefacto, y tablas compactas para el modelo.
// Son las que CyberStrike y compañía resuelven con bash y curl; acá son datos, no texto.
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { HttpClient, type HttpExchange, type ObservedOperation } from "./http.ts";
import { readLocalJson, safeExample } from "./importers/postman.ts";
import { decide } from "./scope.ts";

export interface WebContext {
  artifacts: Artifacts;
  http: HttpClient;
  cwd?: string;
}

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const list = (items: object) => ({ type: "array", items });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
const finish = (text: string, details: Record<string, unknown> = {}): ToolResult => ({ text, details });

const line = (exchange: HttpExchange, label?: string) => {
  const response = exchange.response;
  const head = `${exchange.id}  ${(label ?? exchange.request.method).padEnd(10)} ${exchange.request.url}`;
  if (!response) return `${head}  ERROR ${exchange.error}`;
  return `${head}  ${response.status}  ${response.bodyBytes} B${response.headers.location ? `  → ${response.headers.location.slice(0, 80)}` : ""}`;
};

/** Claves de primer nivel de un JSON, o undefined si no es JSON. */
function jsonKeys(body: string): string[] | undefined {
  try {
    const parsed = JSON.parse(body);
    if (Array.isArray(parsed)) return parsed.length && typeof parsed[0] === "object" ? Object.keys(parsed[0]).map((key) => `[].${key}`) : ["[]"];
    return parsed && typeof parsed === "object" ? Object.keys(parsed) : undefined;
  } catch {
    return undefined;
  }
}

/** Diferencia entre dos respuestas: estado, tamaño, claves que aparecen o desaparecen. */
export function diffResponses(base: HttpExchange, other: HttpExchange): string {
  const a = base.response;
  const b = other.response;
  if (!a || !b) return `sin respuesta (${base.error ?? other.error})`;
  const parts: string[] = [];
  if (a.status !== b.status) parts.push(`estado ${a.status} → ${b.status}`);
  const delta = b.bodyBytes - a.bodyBytes;
  if (Math.abs(delta) > Math.max(20, a.bodyBytes * 0.05)) parts.push(`tamaño ${a.bodyBytes} → ${b.bodyBytes} B`);
  const ka = jsonKeys(a.body);
  const kb = jsonKeys(b.body);
  if (ka && kb) {
    const gone = ka.filter((key) => !kb.includes(key));
    const added = kb.filter((key) => !ka.includes(key));
    if (gone.length) parts.push(`claves que faltan: ${gone.join(", ")}`);
    if (added.length) parts.push(`claves nuevas: ${added.join(", ")}`);
  }
  if (!parts.length) return a.body === b.body ? "idéntica" : "mismo estado y tamaño; cuerpo distinto";
  return parts.join(" · ");
}

export function createWebTools(context: WebContext): Tool[] {
  const { http } = context;

  /** Misma petición con cada identidad: la base del control de acceso. */
  const accessMatrix: Tool = {
    name: "access_matrix",
    label: "Matriz de acceso",
    description:
      "Envía las mismas peticiones sin credenciales y con cada identidad configurada (o las que nombres) y devuelve una tabla código × identidad con la diferencia contra la primera. " +
      "Es la prueba de control de acceso: un recurso de un usuario que responde 200 a otro, o a nadie, salta a la vista. Cada celda cuenta una petición.",
    parameters: obj(
      {
        urls: list(str()),
        method: str({ enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] }),
        body: str({ maxLength: 5000 }),
        identities: list(str({ description: "Identidades a comparar; por defecto todas las configuradas" })),
        headersByIdentity: { type: "object", additionalProperties: { type: "object", additionalProperties: { type: "string" } }, description: "Cabeceras ad hoc por nombre (p. ej. {\"alicia\": {\"Authorization\": \"Bearer …\"}}) cuando no hay identidades configuradas" },
      },
      ["urls"],
    ),
    parallel: true,
    execute: async (params) => {
      const adHoc: Record<string, Record<string, string>> = params.headersByIdentity ?? {};
      const names: string[] = ["(sin credenciales)", ...(params.identities?.length ? params.identities : http.identityNames()), ...Object.keys(adHoc)];
      if (names.length < 2) throw new Error("Hace falta al menos una identidad (configurada con /identity o pasada en headersByIdentity) para comparar");
      if (params.urls.length * names.length > 60) throw new Error("Demasiadas celdas: máximo 60 (URLs × identidades)");
      const rows: string[] = [`${"URL".padEnd(50)} ${names.map((name) => name.padEnd(19)).join("")}`];
      let suspicious = 0;
      for (const url of params.urls) {
        const cells = await Promise.all(
          names.map((name) => {
            const spec = { url, method: params.method ?? "GET", body: params.body, headers: adHoc[name] };
            return name === "(sin credenciales)" || adHoc[name] ? http.send(spec) : http.send(spec, name);
          }),
        );
        const base = cells[1]!;
        const text = cells.map((cell, index) => {
          const status = cell.response?.status ?? "ERR";
          if (index <= 1) return String(status).padEnd(19);
          return `${status} ${diffResponses(base, cell)}`.slice(0, 18).padEnd(19);
        });
        // Sin credenciales con 2xx sobre algo que pide identidad, o dos identidades con la misma respuesta 2xx, merece mirarse.
        const open = cells[0]!.response && cells[0]!.response.status < 300 && cells.slice(1).some((cell) => cell.response && cell.response.status < 300);
        const same = cells.length > 2 && cells.slice(1).every((cell) => cell.response?.status === base.response?.status && base.response!.status < 300 && cell.response?.body === base.response?.body);
        if (open || same) suspicious++;
        rows.push(`${url.slice(0, 50).padEnd(50)} ${text.join("")}${open ? "  ← responde igual sin credenciales" : same ? "  ← todas las identidades ven lo mismo" : ""}`);
        rows.push(`  ids: ${cells.map((cell) => cell.id).join(" ")}`);
      }
      rows.push(`peticiones HTTP: ${http.count}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`);
      return finish(rows.join("\n"), { filas: params.urls.length, sospechosas: suspicious });
    },
  };

  /** Repetir un intercambio con cambios y ver qué cambió en la respuesta. */
  const httpReplay: Tool = {
    name: "http_replay",
    label: "Repetir con cambios",
    description:
      "Repite un intercambio anterior (por id, p. ej. h12) aplicando cambios: otro método, cabeceras, parámetros de consulta, campos del cuerpo JSON o identidad; " +
      "devuelve la diferencia contra el original (estado, tamaño, claves). Sirve para probar un valor indebido sin reescribir toda la petición.",
    parameters: obj(
      {
        id: str({ description: "Id del intercambio original" }),
        method: str({ enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] }),
        setHeaders: { type: "object", additionalProperties: { type: "string" } },
        setQuery: { type: "object", additionalProperties: { type: "string" } },
        setBody: { type: "object", description: "Campos a fijar en el cuerpo JSON (los demás se conservan)" },
        body: str({ maxLength: 5000, description: "Cuerpo completo, si no es JSON" }),
        identity: str(),
        path: str({ description: "Ruta nueva (misma base), p. ej. /api/usuarios/2" }),
        bodyChars: int({ minimum: 0, maximum: 4000 }),
      },
      ["id"],
    ),
    execute: async (params) => {
      const original = http.log.find((entry) => entry.id === params.id);
      if (!original) throw new Error(`No existe el intercambio ${params.id}`);
      const stored = JSON.parse(context.artifacts.read(original.hash).toString("utf8")) as HttpExchange;
      const url = new URL(stored.request.url);
      if (params.path) url.pathname = params.path.split("?")[0]!;
      for (const [key, value] of Object.entries(params.setQuery ?? {})) url.searchParams.set(key, String(value));
      let body = params.body ?? stored.request.body;
      if (params.setBody) {
        let parsed: Record<string, unknown> = {};
        try {
          parsed = body ? JSON.parse(body) : {};
        } catch {}
        body = JSON.stringify({ ...parsed, ...params.setBody });
      }
      // Las cabeceras de identidad quedaron enmascaradas en el artefacto: se vuelve a aplicar la misma identidad salvo que se pida otra.
      const masked = Object.values(stored.request.headers).map((value) => /^<identidad (.+)>$/.exec(String(value))?.[1]).find(Boolean);
      const headers = { ...Object.fromEntries(Object.entries(stored.request.headers).filter(([, value]) => !String(value).startsWith("<identidad"))), ...(params.setHeaders ?? {}) };
      delete headers["user-agent"];
      // Un multipart se repite con sus partes exactas (la vista en texto no lleva los bytes binarios), salvo que se pase otro cuerpo.
      const multipart = stored.request.multipart && params.body === undefined && !params.setBody ? stored.request.multipart : undefined;
      if (multipart) delete headers["content-type"];
      const exchange = await http.send({ url: url.toString(), method: params.method ?? stored.request.method, headers, ...(multipart ? { multipart } : { body }) }, params.identity ?? masked);
      const preview = exchange.response ? exchange.response.body.replace(/\s+/g, " ").slice(0, params.bodyChars ?? 600) : "";
      return finish([line(exchange), `diferencia contra ${params.id}: ${diffResponses(stored, exchange)}`, preview, `peticiones HTTP: ${http.count}`].filter(Boolean).join("\n"), { id: exchange.id, status: exchange.response?.status });
    },
  };

  /** Rastreo liviano del mismo origen: enlaces, formularios con sus campos y scripts con rutas de API. */
  const siteMap: Tool = {
    name: "site_map",
    label: "Mapa del sitio",
    description:
      "Rastrea el sitio desde una URL (mismo origen, hasta la profundidad indicada, 25 páginas por defecto y 40 como máximo) y devuelve rutas encontradas, formularios con método y campos, y rutas de API mencionadas en los scripts. " +
      "Lo que encuentra queda como enlace visto para la cobertura. Úsalo al empezar, antes de adivinar rutas.",
    parameters: obj({ url: str(), depth: int({ minimum: 0, maximum: 3 }), maxPages: int({ minimum: 1, maximum: 40 }), identity: str() }, ["url"]),
    execute: async (params) => {
      const origin = new URL(params.url).origin;
      const queue: Array<{ url: string; depth: number }> = [{ url: params.url, depth: 0 }];
      const visited = new Set<string>();
      const forms: string[] = [];
      const apiPaths = new Set<string>();
      const pages: string[] = [];
      while (queue.length && visited.size < (params.maxPages ?? 25)) {
        const next = queue.shift()!;
        const key = next.url.split("#")[0]!;
        if (visited.has(key)) continue;
        visited.add(key);
        const exchange = await http.send({ url: key }, params.identity);
        const response = exchange.response;
        pages.push(line(exchange));
        if (!response || response.status >= 400) continue;
        const type = response.headers["content-type"] ?? "";
        const body = response.body;
        if (/javascript|json/.test(type) || /\.js(\?|$)/.test(key)) {
          for (const match of body.matchAll(/["'`](\/(?:api|v\d|graphql|rest)[^"'`\s?#]*)/g)) apiPaths.add(match[1]!);
          continue;
        }
        if (!/html/.test(type)) continue;
        for (const match of body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
          const attrs = match[1]!;
          const action = /action=["']([^"']*)["']/i.exec(attrs)?.[1] ?? key;
          const method = (/method=["']([^"']*)["']/i.exec(attrs)?.[1] ?? "GET").toUpperCase();
          const fields = [...match[2]!.matchAll(/<(?:input|select|textarea)\b[^>]*name=["']([^"']+)["'][^>]*>/gi)].map((field) => field[1]);
          forms.push(`${method} ${new URL(action, key).pathname}  campos: ${fields.join(", ") || "(ninguno)"}`);
        }
        for (const match of body.matchAll(/["'`](\/(?:api|v\d|graphql|rest)[^"'`\s?#]*)/g)) apiPaths.add(match[1]!);
        if (next.depth < (params.depth ?? 2)) {
          for (const match of body.matchAll(/(?:href|src|action)=["']([^"'#]+)["']/gi)) {
            try {
              const link = new URL(match[1]!, key);
              if (link.origin === origin && !/\.(png|jpe?g|gif|svg|ico|woff2?|css)(\?|$)/i.test(link.pathname)) queue.push({ url: link.toString(), depth: next.depth + 1 });
            } catch {}
          }
        }
      }
      const out = [`Páginas (${pages.length})`, ...pages];
      if (forms.length) out.push(`Formularios (${forms.length})`, ...forms.map((form) => `  ${form}`));
      if (apiPaths.size) out.push(`Rutas de API en scripts (${apiPaths.size})`, ...[...apiPaths].sort().map((path) => `  ${path}`));
      const pending = http.unvisitedLinks();
      if (pending.length) out.push(`Enlazadas sin visitar (${pending.length}): ${pending.slice(0, 20).join(", ")}`);
      out.push(`peticiones HTTP: ${http.count}`);
      return finish(out.join("\n"), { paginas: pages.length, formularios: forms.length, api: apiPaths.size });
    },
  };

  /** Las operaciones declaradas quedan vistas; sólo la descarga consume peticiones. */
  const openapiImport: Tool = {
    name: "openapi_import",
    label: "Importar OpenAPI",
    description:
      "Importa OpenAPI o Swagger JSON desde path, artifact o url. Con una URL base busca la especificación. " +
      "Agrega operaciones vistas con método, parámetros y cuerpo de ejemplo sin ejecutarlas. Para un archivo sin servidor absoluto, pasá baseUrl. No carga referencias externas ni YAML.",
    parameters: obj({ url: str(), path: str(), artifact: str(), baseUrl: str({ description: "Base HTTP cuando el archivo no declara un servidor absoluto" }) }, []),
    execute: async (params) => {
      if ([params.url, params.path, params.artifact].filter(Boolean).length !== 1) throw new Error("Pasá url, path o artifact, sólo uno.");
      let spec: any;
      let from = "archivo local";
      let sourceUrl: URL | undefined;
      if (params.path || params.artifact) spec = readLocalJson(context, params);
      else {
        const base = new URL(params.url);
        const candidates = /\.(json|ya?ml)$/.test(base.pathname) || /docs|swagger|openapi/.test(base.pathname) ? [params.url] : ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json", "/api/openapi.json", "/api/swagger.json"].map((path) => new URL(path, base.origin).toString());
        for (const candidate of candidates) {
          const exchange = await http.send({ url: candidate });
          if (!exchange.response || exchange.response.status !== 200) continue;
          try {
            const parsed = JSON.parse(exchange.response.body);
            if (parsed.paths && (parsed.openapi || parsed.swagger)) {
              spec = parsed;
              sourceUrl = new URL(candidate);
              from = sourceUrl.origin + sourceUrl.pathname;
              break;
            }
          } catch {}
        }
        if (!spec) return finish(`No encontré una especificación JSON en ${candidates.length} ubicaciones.`, { operaciones: 0 });
      }
      if (!spec || !(typeof spec.openapi === "string" || spec.swagger === "2.0") || !spec.paths || typeof spec.paths !== "object" || Array.isArray(spec.paths)) throw new Error("Se espera una especificación OpenAPI o Swagger JSON con paths.");
      let externalRefs = 0;
      const deref = (value: any, seen = new Set<string>()): any => {
        if (!value?.$ref) return value;
        const ref = String(value.$ref);
        if (!ref.startsWith("#/")) { externalRefs++; return undefined; }
        if (seen.has(ref)) return undefined;
        seen.add(ref);
        const target = ref.slice(2).split("/").map((key) => key.replace(/~1/g, "/").replace(/~0/g, "~")).reduce((obj, key) => obj?.[key], spec);
        return deref(target, seen);
      };
      const formatSecrets = (rawSchema: any, value: any, depth = 0): string[] => {
        if (depth > 30) return [];
        const schema = deref(rawSchema);
        if (!schema) return [];
        if (schema.format === "password") return typeof value === "string" ? [value] : [];
        if (Array.isArray(value)) return value.flatMap((item) => formatSecrets(schema.items, item, depth + 1));
        if (!value || typeof value !== "object") return [];
        return Object.entries<any>(schema.properties ?? {}).flatMap(([key, property]) => formatSecrets(property, value[key], depth + 1));
      };
      const base = params.baseUrl ? new URL(params.baseUrl) : sourceUrl;
      const serverUrls = (item: any, op: any): URL[] => {
        const servers = op.servers ?? item.servers ?? spec.servers;
        const values: string[] = Array.isArray(servers) && servers.length ? servers.map((server: any) => {
          if (typeof server.url !== "string") throw new Error("Servidor OpenAPI sin URL.");
          return server.url.replace(/\{([^}]+)\}/g, (_: string, key: string) => {
            const value = server.variables?.[key]?.default;
            if (value === undefined) throw new Error("Servidor OpenAPI con una variable sin valor por defecto.");
            return String(value);
          });
        }) : spec.host ? [`${spec.schemes?.[0] ?? base?.protocol.replace(":", "") ?? "https"}://${spec.host}${spec.basePath ?? ""}`] : [base ? (params.baseUrl ? base.toString() : base.origin) : ""];
        return values.map((value) => {
          let url: URL;
          try { url = new URL(value, base); } catch { throw new Error("La especificación local necesita un servidor absoluto o baseUrl."); }
          if (!/^https?:$/.test(url.protocol)) throw new Error("Los servidores deben ser HTTP o HTTPS.");
          url.username = ""; url.password = ""; url.search = ""; url.hash = "";
          return url;
        });
      };
      const rows: string[] = [`Especificación en ${from}`];
      const operations: ObservedOperation[] = [];
      const outside = new Set<string>();
      let count = 0;
      for (const [path, value] of Object.entries<any>(spec.paths)) {
        if (!path.startsWith("/")) throw new Error("Ruta OpenAPI inválida.");
        const item = deref(value);
        if (!item) continue;
        for (const [method, rawOp] of Object.entries<any>(item)) {
          if (!["get", "post", "put", "patch", "delete", "head", "options", "trace"].includes(method)) continue;
          const op = deref(rawOp);
          if (!op || typeof op !== "object") throw new Error("Operación OpenAPI inválida.");
          count++;
          const parameters = [...(item.parameters ?? []), ...(op.parameters ?? [])].map((p) => deref(p)).filter(Boolean);
          const paramsList = [...new Set<string>(parameters.filter((p) => typeof p.name === "string").map((p) => p.in === "path" ? `{${p.name}}` : p.in === "query" ? `?${p.name}` : `${p.in}:${p.name}`))];
          const requestBody = deref(op.requestBody);
          const media = requestBody?.content?.["application/json"] ?? Object.values<any>(requestBody?.content ?? {})[0];
          const schema = deref(media?.schema ?? parameters.find((p) => p.in === "body")?.schema);
          const fields = [...new Set([...Object.keys(schema?.properties ?? {}), ...parameters.filter((p) => p.in === "formData").map((p) => String(p.name))])];
          const example = media?.example ?? Object.values<any>(media?.examples ?? {}).map((entry) => deref(entry)?.value).find((entry) => entry !== undefined) ?? schema?.example;
          const exampleBody = example ?? (schema?.properties ? Object.fromEntries(Object.entries<any>(schema.properties).map(([key, raw]) => {
            const prop = deref(raw);
            return [key, prop?.example ?? prop?.default ?? prop?.enum?.[0] ?? (prop?.type === "integer" || prop?.type === "number" ? 1 : prop?.type === "boolean" ? false : "ejemplo")];
          })) : undefined);
          const body = safeExample(exampleBody, formatSecrets(schema, exampleBody));
          const security = op.security ?? spec.security;
          rows.push(`${method.toUpperCase().padEnd(7)} ${path}  ${security?.length ? "auth" : "pública"}${paramsList.length ? `  params: ${paramsList.join(" ")}` : ""}${fields.length ? `  cuerpo: ${fields.join(", ")}` : ""}`);
          for (const server of serverUrls(item, op)) {
            const url = new URL(server);
            url.pathname = server.pathname.replace(/\/$/, "") + path.replace(/\{[^}]+\}/g, "1");
            const allowed = decide(http.scope(), url.toString()).allowed;
            if (!allowed) outside.add(url.host);
            operations.push({ url: url.toString(), method: method.toUpperCase(), params: parameters.filter((p) => p.in === "query").map((p) => p.name), pathParams: parameters.filter((p) => p.in === "path").map((p) => p.name), bodyKeys: fields, body });
            if (operations.length > 10000) throw new Error("La especificación supera 10000 operaciones y servidores.");
          }
        }
      }
      for (const operation of operations) {
        http.observe(operation);
        // Los enlaces históricos alimentan sugerencias; no implican una petición probada.
        http.linked.add(operation.url);
      }
      rows.push(`${count} operaciones vistas`);
      if (outside.size) rows.push(`Hosts fuera del alcance: ${[...outside].join(", ")}`);
      if (externalRefs) rows.push(`Referencias externas omitidas: ${externalRefs}. Importá un documento autocontenido.`);
      return finish(rows.join("\n"), { operaciones: count, fueraDeAlcance: [...outside], referenciasExternas: externalRefs });
    },
  };

  return [accessMatrix, httpReplay, siteMap, openapiImport];
}
