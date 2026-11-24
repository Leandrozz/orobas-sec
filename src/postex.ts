// Post-explotación de laboratorio: persistencia simulada, usuario de prueba, exfiltración acotada
// de datos propios, borrado simulado de evidencia propia. Sólo con perfil «laboratorio» o
// «defensa» y contra hosts que el alcance confirma; nunca credenciales de terceros. Todo lo que
// queda en el objetivo entra en createdIdentifiers («Para limpiar», A3): nada desaparece
// silenciosamente. Ninguna acción destruye datos de otros usuarios.
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { HttpClient } from "./http.ts";
import { decide } from "./scope.ts";
import { postexAnyHost, type ProfileGrants } from "./perfil.ts";

export interface PostexContext {
  artifacts: Artifacts;
  http: HttpClient;
  scope: () => import("./scope.ts").Scope | undefined;
  grants: () => ProfileGrants;
  /** Perfil actual (para full-blast, que levanta la guarda de host de laboratorio). */
  perfil?: () => import("./perfil.ts").CapabilityProfile;
}

const str = (extra: object = {}) => ({ type: "string", ...extra });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
const finish = (text: string, details: Record<string, unknown> = {}): ToolResult => ({ text, details });

/** Guarda de post-explotación: perfil con permiso, host dentro del alcance, identidad legítima. */
function postexGuard(context: PostexContext, url: string, identity?: string): { reason?: string } {
  const grants = context.grants();
  if (!grants.postexLab) return { reason: `La post-explotación requiere perfil «laboratorio» o «defensa» (el operador lo cambia con /perfil); el actual no la habilita.` };
  const decision = decide(context.scope(), url);
  if (!decision.allowed) return { reason: `Fuera del alcance: ${url}. ${decision.reason}` };
  const lab = /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(url);
  if (!lab && !(context.perfil && postexAnyHost(context.perfil()))) return { reason: `${url} no es un host de laboratorio (localhost o red privada). La post-explotación de esta tanda sólo corre contra laboratorios o infra propia, salvo en perfil full-blast (donde el alcance ya autorizó el destino).` };
  if (identity && !context.http.identityNames().includes(identity)) return { reason: `La identidad «${identity}» no está configurada. La post-explotación usa identidades legítimas del operador, nunca credenciales de terceros.` };
  return {};
}

/** Cada acción es una petición legítima más su registro de evidencia local, nunca más. */
export function createPostexTools(context: PostexContext): Tool[] {
  const { artifacts, http } = context;
  const counter = () => `peticiones HTTP: ${http.count}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`;
  const createdIds = (id: string) => (http as any).log?.find((e: any) => e.id === id)?.created ?? [];

  /** Persistencia simulada: crear un recurso que «quede» (una cuenta, un token, un archivo propio) por identidad legítima. */
  const postexPersist: Tool = {
    name: "postex_persist",
    label: "Persistencia simulada (lab)",
    description:
      "Crea en el laboratorio un recurso que quede («persistencia» simulada: una clave de API propia, un token, un archivo con marca propia) usando una identidad legítima del operador, y lo registra todo para el «Para limpiar». " +
      "Sólo con perfil que habilite post-explotación: laboratorio, defensa o full-blast, que además acepta cualquier host del alcance. No es persistencia real de sistema: es un recurso creado y anotado con hash, reversible y listado.",
    parameters: obj({ url: str({ description: "Endpoint de creación del laboratorio" }), body: str({ maxLength: 4000, description: "Cuerpo de la creación; llevá tu marca de operador en el nombre" }), identity: str({ description: "Identidad legítima con la que crear" }) }, ["url", "body", "identity"]),
    execute: async (params, signal) => {
      const guard = postexGuard(context, params.url, params.identity);
      if (guard.reason) throw new Error(guard.reason);
      const exchange = await http.send({ url: params.url, method: "POST", body: params.body, headers: { "content-type": "application/json" } }, params.identity); // sin signal: send acepta 2 args
      const ok = exchange.response && exchange.response.status < 300;
      const artifact = artifacts.put(JSON.stringify({ accion: "persistencia-simulada", url: params.url, identity: params.identity, status: exchange.response?.status, created: createdIds(exchange.id) }, null, 1), "application/json", "postex_persist");
      return finish(
        ok ? `Persistencia simulada creada: ${exchange.request.method} ${params.url} → ${exchange.response?.status}, identidad ${params.identity}. Quedó en createdIdentifiers («Para limpiar» la lista). Artefacto: ${artifact.hash}\n${counter()}` : `No se creó: ${params.url} → ${exchange.response?.status ?? `ERROR ${exchange.error}`}. Revisá el cuerpo y la identidad. ${counter()}`,
        { url: params.url, status: exchange.response?.status, artefacto: artifact.hash },
      );
    },
  };

  /** Exfiltración acotada: pedir recursos propios del laboratorio y guardarlos localmente con hash. */
  const postexExfil: Tool = {
    name: "postex_exfil",
    label: "Exfiltración simulada (lab)",
    description:
      "Lee recursos propios del laboratorio (por identidad legítima, hosts de lab, dentro del alcance) y guarda el resultado en evidencia local con hash verificado: eso «exfiltrado» es la copia local, no una copia a ningún tercero. " +
      "Nunca usa credenciales de terceros ni hosts fuera del alcance. Sólo perfil laboratorio/defensa.",
    parameters: obj({ url: str({ description: "Recurso propio del laboratorio a leer" }), identity: str({ description: "Identidad legítima" }) }, ["url", "identity"]),
    execute: async (params, signal) => {
      const guard = postexGuard(context, params.url, params.identity);
      if (guard.reason) throw new Error(guard.reason);
      const exchange = await http.send({ url: params.url, method: "GET" }, params.identity); // sin signal: send acepta 2 args
      if (!exchange.response || exchange.response.status >= 300) return finish(`No se leyó: ${params.url} → ${exchange.response?.status ?? `ERROR ${exchange.error}`}. ${counter()}`, { url: params.url });
      const artifact = artifacts.put(JSON.stringify({ accion: "exfiltracion-simulada", url: params.url, identity: params.identity, status: exchange.response.status, bytes: exchange.response.bodyBytes, guardadoEn: ".cyber/evidencia/postex/" }, null, 1), "application/json", "postex_exfil");
      return finish(`Leído y guardado local: ${params.url} → ${exchange.response.status}, ${exchange.response.bodyBytes} B, identidad ${params.identity}. Copia en evidencia con hash ${artifact.hash} (nunca a ningún tercero). ${counter()}`, { url: params.url, bytes: exchange.response.bodyBytes, artefacto: artifact.hash });
    },
  };

  /** Borrado simulado de evidencia propia: destruir un recurso que esta sesión creó (guarda de borrado intacta). */
  const postexCleanup: Tool = {
    name: "postex_cleanup",
    label: "Borrado simulado de lo propio (lab)",
    description:
      "Destruye un recurso que esta sesión creó (guarda de borrado intacta: con allowDestructive, y sobre lo ajeno sólo si el operador dio consentimiento de borrado ajeno) y anota qué «evidencia» desapareció, para ejercitar detección de limpieza. Sólo perfiles con post-explotación; nunca datos de otros usuarios sin consentimiento.",
    parameters: obj({ url: str({ description: "Recurso propio a borrar (creado esta sesión)" }), identity: str({ description: "Identidad legítima" }) }, ["url", "identity"]),
    execute: async (params, signal) => {
      const guard = postexGuard(context, params.url, params.identity);
      if (guard.reason) throw new Error(guard.reason);
      const exchange = await http.send({ url: params.url, method: "DELETE", allowDestructive: true }, params.identity); // sin signal: send acepta 2 args
      const ok = exchange.response && exchange.response.status < 300;
      return finish(
        ok ? `Borrado simulado: ${params.url} → ${exchange.response?.status}. Recurso propio, lista de «Para limpiar» actualizada. ${counter()}` : `No se borró: ${params.url} → ${exchange.response?.status ?? `ERROR ${exchange.error}`} (sólo recursos creados esta sesión). ${counter()}`,
        { url: params.url, status: exchange.response?.status },
      );
    },
  };

  return [postexPersist, postexExfil, postexCleanup];
}