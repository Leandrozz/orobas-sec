import { setTimeout as delay } from "node:timers/promises";
import type { Tool } from "./agent.ts";
import type { HttpExchange } from "./http.ts";
import type { ProbeContext } from "./probes.ts";
import { diffResponses } from "./webtools.ts";

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });

interface TypeRef { kind?: string; name?: string; ofType?: TypeRef }
interface InputValue { name: string; type: TypeRef; defaultValue?: string | null }
interface Field { name: string; type: TypeRef; args?: InputValue[] }
interface SchemaType { kind: string; name: string; fields?: Field[] | null }
interface Schema { queryType?: { name: string }; mutationType?: { name: string } | null; types: SchemaType[] }
interface Operation { query: string; variables?: Record<string, unknown>; operationName?: string; label?: string }
interface GraphqlBody { data?: Record<string, unknown> | null; errors?: Array<{ message?: string }> }

// La profundidad alcanza listas y no-nulos anidados sin traer descripciones enormes.
const TYPE_REF = "kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }";
const INTROSPECTION = `query SondaEsquema { __schema { queryType { name } mutationType { name } types { kind name fields(includeDeprecated: true) { name args { name defaultValue type { ${TYPE_REF} } } type { ${TYPE_REF} } } } } }`;

function parse(exchange: HttpExchange): GraphqlBody | undefined {
  try {
    const body = JSON.parse(exchange.response?.body ?? "");
    return body && typeof body === "object" && !Array.isArray(body) ? body : undefined;
  } catch { return undefined; }
}

function typeName(type?: TypeRef): string {
  if (!type) return "?";
  if (type.kind === "NON_NULL") return `${typeName(type.ofType)}!`;
  if (type.kind === "LIST") return `[${typeName(type.ofType)}]`;
  return type.name ?? "?";
}

function errors(body?: GraphqlBody): string {
  return Array.isArray(body?.errors) ? body.errors.map((error) => error?.message ?? "error GraphQL").join("; ").replace(/\s+/g, " ").slice(0, 180) : "";
}

function accepted(exchange: HttpExchange): boolean {
  const body = parse(exchange);
  return !!exchange.response && exchange.response.status >= 200 && exchange.response.status < 300 && !!body?.data && typeof body.data === "object" && !Array.isArray(body.data) && Object.values(body.data).some((value) => value !== null) && !(body.errors?.length);
}

function resultLine(exchange: HttpExchange, label: string, control?: HttpExchange): string {
  const body = parse(exchange);
  return `${exchange.id}  ${label}  ${exchange.response?.status ?? "ERR"}  ${exchange.response?.bodyBytes ?? 0} B  ${control ? diffResponses(control, exchange) : exchange.request.url}${errors(body) ? ` · ${errors(body)}` : exchange.error ? ` · ${exchange.error}` : ""}`;
}

export function createGraphqlProbe({ http }: ProbeContext): Tool {
  return {
    name: "graphql_probe",
    label: "Sonda GraphQL",
    description: "Busca el endpoint GraphQL y pide introspección: tipos, consultas, mutaciones y argumentos. Señala campos para revisar propiedad. Prueba sólo las operaciones que pases, con tus credenciales como control y después sin cabeceras ni identidad; las mutaciones se ejecutan dos veces. Si la introspección está apagada, usa esas operaciones. Máximo 30 peticiones por llamada, secuenciales. Confirmá las señales con una petición propia y registrá candidato con evidencia.",
    parameters: obj({
      url: str({ description: "Base del sitio para descubrir rutas habituales, o URL exacta del endpoint" }),
      identity: str(),
      headers: { type: "object", additionalProperties: str() },
      operations: { type: "array", maxItems: 10, items: obj({ query: str({ maxLength: 8000 }), variables: { type: "object" }, operationName: str(), label: str({ maxLength: 80 }) }, ["query"]) },
      maxRequests: int({ minimum: 2, maximum: 30, default: 16, description: "Incluye descubrimiento, introspección y controles" }),
      delayMs: int({ minimum: 0, maximum: 1000, default: 100 }),
    }, ["url"]),
    replay: "never",
    execute: async (params, signal) => {
      const startCount = http.count;
      const maxRequests: number = params.maxRequests ?? 16;
      const delayMs: number = params.delayMs ?? 100;
      if (!Number.isInteger(maxRequests) || maxRequests < 2 || maxRequests > 30) throw new Error("maxRequests debe estar entre 2 y 30");
      if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > 1000) throw new Error("delayMs debe estar entre 0 y 1000");
      const operations: Operation[] = params.operations ?? [];
      if (!Array.isArray(operations) || operations.length > 10 || operations.some((operation) => !operation || typeof operation.query !== "string" || !operation.query.trim() || operation.query.length > 8000)) throw new Error("Pasá hasta 10 operaciones con query de 1 a 8000 caracteres");
      const base = new URL(params.url);
      const exact = base.pathname !== "/" || !!base.search;
      const candidates = exact ? [base.toString()] : ["/graphql", "/api/graphql", "/query", "/v1/graphql"].map((path) => new URL(path, base).toString());
      const rows: string[] = [];
      let requests = 0;
      let completed = 0;
      let signals = 0;
      let endpoint: string | undefined;
      let detectionControl: HttpExchange | undefined;
      let introspection = "sin probar";
      const send = async (url: string, operation: Operation, anonymous = false): Promise<HttpExchange | undefined> => {
        if (signal.aborted || requests >= maxRequests || http.remaining() === 0) return undefined;
        if (requests && delayMs) await delay(delayMs, undefined, { signal }).catch(() => {});
        if (signal.aborted) return undefined;
        requests++;
        // Quitar todas las cabeceras aportadas evita arrastrar claves con nombres propios.
        return http.send({ url, method: "POST", headers: { ...(anonymous ? {} : params.headers ?? {}), "content-type": "application/json" }, body: JSON.stringify({ query: operation.query, variables: operation.variables, operationName: operation.operationName }), timeoutMs: 10_000 }, anonymous ? undefined : params.identity);
      };
      const finish = () => {
        if (signal.aborted) rows.push("Cancelada: resultados parciales.");
        else if (requests >= maxRequests || http.remaining() === 0) rows.push("Tope alcanzado: puede haber operaciones pendientes.");
        rows.push("Las señales orientan; confirmá con una petición propia y registrá candidato con evidencia. Un 2xx no demuestra un cambio de estado.");
        rows.push(`peticiones de la sonda: ${http.count - startCount} · peticiones HTTP: ${http.count}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`);
        return { text: rows.join("\n"), details: { endpoint, introspeccion: introspection, operaciones: completed, senales: signals, peticiones: http.count - startCount, intentos: requests } };
      };
      for (const candidate of candidates) {
        const control = await send(candidate, { query: "query SondaControl { __typename }" });
        if (!control) break;
        rows.push(resultLine(control, "control __typename"));
        const body = parse(control);
        if (typeof body?.data?.__typename === "string" || /graphql|query|field|introspect|syntax/i.test(errors(body))) {
          endpoint = candidate;
          detectionControl = control;
          break;
        }
        if (exact) {
          endpoint = candidate;
          detectionControl = control;
          rows.push("Endpoint indicado sin confirmar con __typename; se prueba introspección y las operaciones aportadas.");
        }
      }
      if (!endpoint) {
        rows.push("No se detectó GraphQL en las rutas consultadas; pasá la URL exacta si la conocés.");
        return finish();
      }
      const schemaExchange = await send(endpoint, { query: INTROSPECTION });
      if (schemaExchange) {
        rows.push(resultLine(schemaExchange, "introspección", detectionControl));
        const body = parse(schemaExchange);
        const schema = body?.data?.__schema as Schema | undefined;
        if (schema && Array.isArray(schema.types)) {
          introspection = "habilitada";
          rows.push(`Introspección habilitada (${schemaExchange.id}); esquema completo en su artefacto.`);
          const types = schema.types.filter((type) => type && typeof type.name === "string" && !type.name.startsWith("__"));
          rows.push(`Tipos (${types.length}): ${types.slice(0, 100).map((type) => `${type.name}:${type.kind}`).join(", ")}${types.length > 100 ? " · lista recortada; ampliá con artifact_read" : ""}`);
          let displayed = 0;
          let omitted = 0;
          // Primero las operaciones; después los campos que sugieren acceso a otras cuentas.
          const ordered = [...types.filter((type) => [schema.queryType?.name, schema.mutationType?.name].includes(type.name)), ...types.filter((type) => ![schema.queryType?.name, schema.mutationType?.name].includes(type.name))];
          for (const type of ordered) {
            const root = type.name === schema.queryType?.name ? "consulta" : type.name === schema.mutationType?.name ? "mutación" : "campo";
            for (const field of Array.isArray(type.fields) ? type.fields : []) {
              if (!field || typeof field.name !== "string") continue;
              const access = /user|usuario|account|cuenta|member|miembro|owner|perfil|profile/i.test(`${field.name} ${typeName(field.type)}`);
              if (root === "campo" && !access) continue;
              const args = (Array.isArray(field.args) ? field.args : []).filter((arg) => arg && typeof arg.name === "string").map((arg) => `${arg.name}:${typeName(arg.type)}${arg.defaultValue != null ? `=${arg.defaultValue}` : ""}`).join(", ");
              if (displayed++ >= 150) { omitted++; continue; }
              rows.push(`${root}  ${type.name}.${field.name}(${args}) → ${typeName(field.type)}${access ? " · revisar acceso a otras cuentas (pista por nombre)" : ""}`);
            }
          }
          if (omitted) rows.push(`${omitted} filas más en el esquema: ampliá ${schemaExchange.id} con artifact_read.`);
          rows.push("El esquema no demuestra controles de acceso. Para medir mutaciones sin autenticación, pasá operations con una escritura de prueba.");
        } else {
          introspection = /introspection|introspecci[oó]n|__schema|__type/i.test(errors(body)) ? "deshabilitada o restringida" : "no disponible";
          rows.push(`Introspección ${introspection}; ${operations.length ? "se prueban las operaciones aportadas" : "pasá operations para probar operaciones conocidas"}.`);
        }
      }
      for (const [index, operation] of operations.entries()) {
        if (maxRequests - requests < 2 || (http.remaining() ?? Infinity) < 2) {
          rows.push("No alcanza el presupuesto para otro par control/sin credenciales.");
          break;
        }
        const control = await send(endpoint, operation);
        if (!control) break;
        const label = (operation.label ?? operation.operationName ?? `operación ${index + 1}`).replace(/\s+/g, " ").slice(0, 80);
        rows.push(resultLine(control, `${label} control`));
        const anonymous = await send(endpoint, operation, true);
        if (!anonymous) break;
        rows.push(resultLine(anonymous, `${label} sin credenciales`, control));
        completed++;
        if (accepted(anonymous)) {
          signals++;
          const mutation = /\bmutation\b/.test(operation.query.replace(/#[^\n]*/g, ""));
          rows.push(`${anonymous.id}  ${mutation ? "Operación con mutación" : "Operación"} devolvió datos sin autenticación y sin errores GraphQL; revisá si debía exigirla.`);
        }
      }
      return finish();
    },
  };
}
