import { setTimeout as wait } from "node:timers/promises";
import type { Tool } from "./agent.ts";
import type { HttpExchange, HttpRequestSpec } from "./http.ts";
import type { ProbeContext } from "./probes.ts";
import { diffResponses } from "./webtools.ts";

const str = (extra: object = {}) => ({ type: "string", ...extra });
const tokenName = /csrf|xsrf|requestverificationtoken|authenticity_token/i;

export function createCsrfCheck({ http, artifacts }: ProbeContext): Tool {
  return {
    name: "csrf_check",
    label: "Comprobar CSRF",
    description: "Repite una escritura autenticada por cookie: control, sin Origin/Referer, origen ajeno y sin token anti-CSRF. Máximo 5 peticiones. Con bearer no envía nada. Muestra aceptación HTTP y diferencias; confirmá el efecto con una petición propia y registrá candidato con evidencia.",
    parameters: {
      type: "object", required: [], properties: {
        id: str({ description: "Intercambio de una escritura que funcionó" }), url: str(),
        method: str({ enum: ["POST", "PUT", "PATCH", "DELETE"] }),
        body: { description: "Cuerpo JSON o cadena (p. ej. formulario)", anyOf: [{ type: "object" }, { type: "string" }] },
        headers: { type: "object", additionalProperties: str() }, identity: str(),
        tokenFields: { type: "array", items: str(), maxItems: 20, description: "Campos JSON/formulario/query; por defecto reconoce csrf/xsrf" },
        tokenHeaders: { type: "array", items: str(), maxItems: 20 },
        maxRequests: { type: "integer", minimum: 1, maximum: 5, default: 5 },
        delayMs: { type: "integer", minimum: 0, maximum: 1000, default: 100 },
      },
    },
    execute: async (params, signal) => {
      const max = params.maxRequests ?? 5;
      const delay = params.delayMs ?? 100;
      if (!Number.isInteger(max) || max < 1 || max > 5) throw new Error("maxRequests debe estar entre 1 y 5");
      if (!Number.isInteger(delay) || delay < 0 || delay > 1000) throw new Error("delayMs debe estar entre 0 y 1000");
      let stored: HttpExchange | undefined;
      if (params.id) {
        const hash = http.hashOf(params.id);
        if (!hash) throw new Error(`No existe el intercambio ${params.id}`);
        stored = JSON.parse(artifacts.read(hash).toString("utf8"));
      }
      const identity = params.identity ?? Object.values(stored?.request.headers ?? {}).map((value) => /^<identidad (.+)>$/.exec(value)?.[1]).find(Boolean);
      const headers: Record<string, string> = Object.fromEntries(Object.entries({
        ...Object.fromEntries(Object.entries(stored?.request.headers ?? {}).filter(([, value]) => !value.startsWith("<identidad "))),
        ...params.headers,
      }).map(([key, value]) => [key.toLowerCase(), String(value)]));
      // La longitud cambia al quitar campos; el transporte la recalcula.
      delete headers["content-length"];
      const auth = http.authentication(identity, headers);
      const counter = () => `peticiones HTTP: ${http.count}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`;
      if (auth.bearer || !auth.cookie) return { text: `No aplica: ${auth.bearer ? "la escritura usa bearer" : "no hay autenticación por cookie"}. 0 peticiones en esta llamada.\n${counter()}`, details: { aplica: false, peticiones: 0 } };
      const url = params.url ?? stored?.request.url;
      if (!url) throw new Error("Pasá id o url");
      const method = (params.method ?? stored?.request.method ?? "POST").toUpperCase();
      if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) throw new Error("CSRF requiere una escritura POST, PUT, PATCH o DELETE");
      let body = params.body ?? stored?.request.body;
      if (body !== undefined && typeof body !== "string") {
        body = JSON.stringify(body);
        headers["content-type"] ??= "application/json";
      }
      const base: HttpRequestSpec = { url, method, headers, body, timeoutMs: 5000, followRedirects: false };
      const foreign = "https://csrf.invalid";
      const variants: Array<{ label: string; spec: HttpRequestSpec }> = [
        { label: "control", spec: base },
        { label: "sin Origin/Referer", spec: { ...base, omitHeaders: ["origin", "referer"] } },
        { label: "origen ajeno", spec: { ...base, headers: { ...headers, origin: foreign, referer: `${foreign}/` } } },
      ];
      const removeHeaders = [...new Set([...auth.headerNames.filter((key) => tokenName.test(key)), ...(params.tokenHeaders ?? []).map((key: string) => key.toLowerCase())])];
      if (removeHeaders.some((key) => ["cookie", "authorization"].includes(key))) throw new Error("tokenHeaders no puede quitar la autenticación de control");
      const fields: string[] = params.tokenFields ?? [];
      const isToken = (key: string) => tokenName.test(key) || fields.includes(key);
      const tokenUrl = new URL(url);
      let removed = removeHeaders.filter((key) => auth.headerNames.includes(key)).length;
      for (const key of [...tokenUrl.searchParams.keys()]) if (isToken(key)) { tokenUrl.searchParams.delete(key); removed++; }
      let strippedBody = body;
      if (body) {
        try {
          const parsed = JSON.parse(body);
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            for (const key of Object.keys(parsed)) if (isToken(key)) { delete parsed[key]; removed++; }
            strippedBody = JSON.stringify(parsed);
          }
        } catch {
          if (/application\/x-www-form-urlencoded/i.test(headers["content-type"] ?? "")) {
            const form = new URLSearchParams(body);
            for (const key of [...form.keys()]) if (isToken(key)) { form.delete(key); removed++; }
            strippedBody = form.toString();
          }
        }
      }
      if (removed) {
        const spec = { ...base, url: tokenUrl.toString(), body: strippedBody, omitHeaders: removeHeaders };
        variants.push({ label: "sin token", spec }, { label: "origen ajeno sin token", spec: { ...spec, headers: { ...headers, origin: foreign, referer: `${foreign}/` } } });
      }
      const start = http.count;
      const rows: string[] = [];
      const outcomes: Array<{ variante: string; id: string; aceptada: boolean; status?: number }> = [];
      let control: HttpExchange | undefined;
      for (const { label, spec } of variants.slice(0, max)) {
        if (signal.aborted || http.remaining() === 0) break;
        if (rows.length && delay) { try { await wait(delay, undefined, { signal }); } catch { break; } }
        const exchange = await http.send(spec, identity);
        control ??= exchange;
        const status = exchange.response?.status;
        const accepted = status !== undefined && status >= 200 && status < 300;
        rows.push(`${exchange.id}  ${label.padEnd(24)} ${status ?? "ERR"}  ${accepted ? "aceptada (2xx)" : "sin aceptación 2xx"}  ${diffResponses(control, exchange)}`);
        outcomes.push({ variante: label, id: exchange.id, aceptada: accepted, status });
      }
      if (!removed) rows.push("No se detectó token anti-CSRF; indicá tokenFields/tokenHeaders si usa otro nombre.");
      if (outcomes.length < variants.length) rows.push("Prueba parcial por tope de peticiones o cancelación.");
      if (!outcomes[0]?.aceptada) rows.push("El control no fue aceptado: estas variantes no permiten concluir sobre la protección.");
      rows.push("2xx no prueba el efecto ni la viabilidad desde un navegador (SameSite, CORS y formato importan). Confirmá con una petición propia y registrá candidato con evidencia.", `peticiones de esta llamada: ${http.count - start}`, counter());
      return { text: rows.join("\n"), details: { aplica: true, variantes: outcomes, peticiones: http.count - start } };
    },
  };
}
