// Lo que el operador pega en el chat y es una credencial (un token, una cabecera de autenticación,
// una cookie o un HAR) se carga como identidad antes de que lo vea el modelo: el modelo recibe sólo
// el nombre de la identidad. Así «te creé un token: dp.pt.…» funciona sin comandos y el secreto no
// viaja al proveedor del modelo ni queda en la conversación.
import type { HttpClient } from "./http.ts";
import { importHar } from "./importers/har.ts";

export interface Absorbed {
  /** El mensaje con cada credencial reemplazada por el nombre de su identidad. */
  text: string;
  /** Identidades cargadas. */
  loaded: string[];
}

const TOKEN = "[A-Za-z0-9._~+/=-]";
// Cabeceras de autenticación escritas tal cual, una por línea.
const HEADER = /^[ \t]*(authorization|cookie|x-api-key|x-auth-token|x-access-token|api-key)[ \t]*:[ \t]*(\S[^\n]*)$/gim;
const BEARER = new RegExp(`\\bbearer\\s+(${TOKEN}{16,})`, "gi");
// Tokens de API con prefijo conocido (Doppler, GitHub, GitLab, Slack, Shopify, Atlassian) y JWT.
const PREFIXED = new RegExp(`\\b((?:dp\\.(?:pt|st|ct|sa|scim)\\.|ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|xox[bpas]-|shpat_|ATATT)${TOKEN}{16,})`, "g");
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
// «token: xxxx», «api key = xxxx»: un valor largo que el operador presenta como credencial.
const LABELED = new RegExp(`\\b(?:token|api[ _-]?key|access[ _-]?token|clave de (?:la )?api)\\b[ \\t]*[:=]?[ \\t]*(${TOKEN}{20,})`, "gi");

/** Base para nombrar identidades: la marca del primer destino del alcance («doppler»), o «operador». */
export function identityBase(host?: string): string {
  if (!host || /^[\d.]+$|:/.test(host)) return "operador";
  const labels = host.toLowerCase().replace(/^\*\./, "").split(".").filter(Boolean);
  const brand = labels.length >= 2 ? labels[labels.length - 2]! : labels[0] ?? "operador";
  return brand.replace(/[^a-z0-9-]/g, "") || "operador";
}

/** Reconoce los formatos que acepta el chat, también para la pantalla pública. */
export function reemplazarTokensConPrefijo(texto: string, reemplazo: (token: string) => string): string {
  return texto.replace(PREFIXED, reemplazo);
}

export function absorbCredentials(text: string, http: HttpClient, base = "operador"): Absorbed {
  const loaded: string[] = [];
  const fresh = () => {
    const taken = new Set([...http.identityNames(), ...http.proposedIdentities().map((item) => item.name)]);
    let n = 1;
    while (taken.has(`${base}-${n}`)) n++;
    return `${base}-${n}`;
  };
  const load = (headers: Record<string, string>) => {
    const name = fresh();
    http.setIdentity({ name, headers });
    loaded.push(name);
    return `«credencial cargada como identidad ${name}»`;
  };

  // Un HAR pegado entero: se importa como lo haría har_import y sus credenciales quedan aprobadas,
  // porque las pegó el operador.
  const whole = text.trim();
  if (/^\{\s*"log"\s*:/.test(whole)) {
    try {
      const before = new Set(http.proposedIdentities().map((item) => item.name));
      const summary = importHar(JSON.parse(whole), http);
      for (const item of http.proposedIdentities()) {
        if (before.has(item.name)) continue;
        http.approveIdentity(item.name);
        loaded.push(item.name);
      }
      const outcome = loaded.length ? `Identidades cargadas: ${loaded.join(", ")} (aprobadas: las pegó el operador).` : "El HAR no trae ninguna credencial: ni Authorization ni cookies en las peticiones.";
      return { text: `[El operador pegó un HAR en el chat. Importación:]\n${summary.text.replace(/\n?[^\n]*requieren aprobación del operador[^\n]*$/, "")}\n${outcome}`, loaded };
    } catch {
      // No era un HAR válido: sigue como texto común.
    }
  }

  let result = text.replace(HEADER, (_line, name: string, value: string) => `${name}: ${load({ [name.toLowerCase()]: value.trim() })}`);
  result = result.replace(BEARER, (_match, token: string) => `Bearer ${load({ authorization: `Bearer ${token}` })}`);
  result = reemplazarTokensConPrefijo(result, (token: string) => load({ authorization: `Bearer ${token}` }));
  result = result.replace(JWT, (token: string) => load({ authorization: `Bearer ${token}` }));
  result = result.replace(LABELED, (match: string, token: string) => match.replace(token, load({ authorization: `Bearer ${token}` })));
  return { text: result, loaded };
}
