// Secretos de la sesión: qué ve el modelo y qué queda en las trazas (decisión de Lean del 22/11/2026).
//
// Cada secreto conocido tiene una clase, que sale de su PROCEDENCIA (quién trajo el valor a la sesión y de
// dónde), nunca de su formato:
// - Del operador: lo que el operador carga o escribe (identidades, cookies de su sesión, contraseñas del chat),
//   las claves del servicio y de los proveedores (variables de entorno, almacén cifrado) y lo que sale de su
//   máquina (shell local, CLIs de plataformas, archivos propios, el sistema, herramientas sin declarar). El
//   modelo nunca lo lee: recibe un marcador (‹SECRETO_n›). Cuando pide ejecutar una herramienta con el
//   marcador, el valor real vuelve sólo en esos argumentos, en cualquier herramienta que actúe contra el alcance
//   (el cliente HTTP y lo que va por él, el navegador, las sondas, la shell y los escáneres externos), con una
//   sola condición: que los destinos que nombra la llamada estén en el alcance vigente. Sin flags ni envoltorios
//   por herramienta (decisión de Lean del 22/11, 15:25): si el objetivo redirige afuera, un escáner o la shell
//   pueden seguirlo; el cliente HTTP controla cada salto. Las claves del servicio y de los proveedores (entorno,
//   almacén) no se reponen hacia ningún objetivo, y una identidad propuesta (HAR, Chrome) espera a que el
//   operador la apruebe.
// - Del objetivo: lo que devuelve un sistema bajo prueba (respuestas HTTP, código y artefactos del objetivo,
//   tokens que emite, claves filtradas) y las credenciales de las cuentas de prueba que crea el propio agente
//   (lo que el modelo escribe en los argumentos de una herramienta: procedencia «agente»). El modelo lo ve tal
//   cual y lo puede usar en cualquier herramienta y destino: el alcance sigue siendo el único límite. Un token
//   que el objetivo emite después de un login hecho con la sesión del operador es del objetivo; la contraseña o
//   la cookie original sigue siendo del operador.
// - Sin clase: lo que escribió otro modelo de la sesión (un subagente, un resumen). Lo derivó de lo que ya ve,
//   así que queda a la vista del modelo hasta que aparezca en una fuente conocida, que le da su clase.
// La forma de un valor decide si es una credencial (formatos conocidos y campos con nombre de credencial); un id
// opaco sin etiqueta (nanoid, id de GraphQL) no lo es: taparlo dejaba ciegas las pruebas de IDOR.
// Las fuentes que carga el operador (identidades, cookies, entorno, almacén) mandan: si su valor ya se había
// visto como material del objetivo, pasa a ser del operador. Lo demás no cambia la clase de un valor ya
// conocido: la primera procedencia gana (un eco del objetivo no destapa una credencial del operador, y un eco
// local no tapa lo que el modelo ya vio del objetivo).
//
// Dos vistas del mismo registro, con los mismos números:
// - «modelo»: lo que viaja al proveedor del modelo (en los dos transportes, por Engine.transportFor). Tapa lo
//   del operador.
// - «trazas»: lo que se guarda o se envía como material de entrenamiento (turnos, trayectorias, citas, llamadas
//   en modo local). Tapa todo, de las dos clases.
// Con el proveedor orobas el pedido al modelo pasa por el gateway propio, que en «compartir» guarda el pedido
// entero: si la vista del modelo trae material del objetivo a la vista, ese pedido sale pidiendo que no se
// guarde su contenido (Engine.transportFor).
//
// Reglas que ya costaron (no aflojarlas):
// - Se trabaja sobre cada texto por separado, antes de serializar el pedido: un secreto puede quedar partido
//   por los escapes de JSON de la línea serializada (PR #33).
// - Un valor corto o sin letras ni dígitos no es un secreto: taparlo rompe el texto (PR #32).
// - Los objetivos (dominios, rutas, IPs del alcance) no se tapan: el modelo los necesita para trabajar.
// - El mismo secreto recibe siempre el mismo marcador, numerado en el orden en que apareció, también al
//   retomar la sesión (se guarda una huella, nunca el valor). Un marcador que cambia entre turnos rompe la
//   caché de prefijo del proveedor, y la caché es el 75 % del costo de una sesión.
import { tokenConPrefijo } from "./formatos-credencial.ts";
import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { LlmRequest, Message, Transport } from "./llm.ts";
import type { Scope } from "./scope.ts";
import { readSecret } from "./secretos.ts";

export const marcador = (n: number) => `‹SECRETO_${n}›`;
const MARCA = /‹SECRETO_(\d+)›/g;
/** Lo que queda de un marcador en un texto que se guarda para que lo lea un modelo después (memoria, hallazgos). */
export const SECRETO_GUARDADO = "‹secreto›";
export const neutralizarMarcadores = (texto: string): string => texto.replace(MARCA, SECRETO_GUARDADO);

/**
 * De dónde viene un valor o el texto donde apareció. Define su clase (claseDe):
 * - identidad, propuesta, cookie, entorno, almacén: fuentes que cargó el operador o que son de su máquina. Mandan.
 *   Una propuesta es una identidad importada (HAR, Chrome) que el operador todavía no aprobó.
 * - operador: lo que escribe el operador (el chat, sus respuestas, la cita de un consentimiento).
 * - local: la máquina del operador y el harness (shell, CLIs de plataformas, archivos propios, el sistema, la
 *   memoria, herramientas no declaradas como del objetivo).
 * - objetivo: lo que devuelve un sistema bajo prueba o un artefacto suyo.
 * - agente: lo que el modelo principal escribe en los argumentos de una herramienta (la contraseña que inventa
 *   para una cuenta de prueba, un token que copia). Ya lo sabe: es material del objetivo.
 * - modelo: lo que escribe otro modelo de la sesión (subagentes, deep_reason, checkpoints).
 */
export type Origen = "identidad" | "propuesta" | "cookie" | "entorno" | "almacén" | "operador" | "local" | "objetivo" | "agente" | "modelo";
/** Del operador: tapado en las dos vistas. Del objetivo: a la vista del modelo, tapado en trazas. */
export type Clase = "operador" | "objetivo";
/** modelo: lo que viaja al proveedor; trazas: lo que se guarda o se envía como material de entrenamiento. */
export type Vista = "modelo" | "trazas";
export interface Fuente { valor: string; origen: Origen; sitio?: string }

/** La clase que da una procedencia; lo que escribió otro modelo no tiene (undefined). */
export const claseDe = (origen: Origen): Clase | undefined => origen === "objetivo" || origen === "agente" ? "objetivo" : origen === "modelo" ? undefined : "operador";
/** Fuentes que cargó el operador: su clase pisa la que el valor tuviera. */
const MANDAN = new Set<Origen>(["identidad", "propuesta", "cookie", "entorno", "almacén"]);

/**
 * Hasta dónde se repone el marcador de un secreto del operador: «alcance», en cualquier herramienta que ejecute
 * contra el alcance; «pendiente», todavía no (una identidad propuesta sin aprobar); «nunca», hacia ningún objetivo
 * (las claves del servicio y de los proveedores). Gana el más restrictivo de lo que se sabe del valor, salvo que
 * una aprobación (la identidad cargada) saca a una propuesta de «pendiente».
 */
export type Uso = "alcance" | "pendiente" | "nunca";
const USO: Partial<Record<Origen, Uso>> = { identidad: "alcance", cookie: "alcance", operador: "alcance", local: "alcance", propuesta: "pendiente", entorno: "nunca", almacén: "nunca" };
const usoCon = (actual: Uso | undefined, origen: Origen): Uso | undefined => {
  const nuevo = USO[origen];
  if (!nuevo || actual === "nunca") return actual ?? nuevo;
  if (nuevo === "nunca" || !actual) return nuevo;
  return actual === "alcance" || nuevo === "alcance" ? "alcance" : "pendiente";
};

/**
 * Herramientas que ejecutan contra el alcance y lo hacen cumplir ellas mismas: las que salen por el cliente HTTP
 * (controla el alcance en cada salto, también en las redirecciones, y la cabecera Host), el navegador (va por el
 * mismo cliente), las de REA que graban una web del alcance y jwt_inspect (no sale a la red). Un marcador del
 * operador se repone en ellas; adónde va lo decide el alcance vigente. La shell y los escáneres externos también,
 * si los destinos que nombra la llamada están en el alcance (destinosDeShell, DESTINOS_DE_ESCANER).
 */
export const EJECUTAN_EN_EL_ALCANCE: ReadonlySet<string> = new Set([
  "http_request", "http_probe", "http_replay", "access_matrix", "auth_probe", "param_probe", "body_probe", "path_probe",
  "tech_fingerprint", "graphql_probe", "outbound_probe", "race_probe", "csrf_check", "ws_probe", "reset_probe", "upload_probe",
  "ids_harvest", "takeover_check", "js_endpoints", "sourcemap_recover", "postex_persist", "postex_exfil", "postex_cleanup",
  "browser_open", "browser_act", "browser_read", "capture_browser_scenario", "jwt_inspect",
  // #41: baja el código de una web del alcance por el cliente HTTP (alcance, ritmo y tope en cada pedido).
  "web_source_pull",
]);

/**
 * Escáneres externos (src/toolbox.ts): binarios propios que van al objetivo con lo que reciben en argv. Reciben
 * una credencial del operador igual que la shell: con los destinos de la llamada en el alcance. No se les agrega
 * ningún flag (decisión de Lean): si el objetivo redirige fuera del alcance, el escáner puede seguirlo.
 */
export const DESTINOS_DE_ESCANER: Readonly<Record<string, (args: any) => unknown[]>> = {
  nmap_scan: (args) => Array.isArray(args?.targets) ? args.targets : [args?.targets],
  httpx_probe: (args) => Array.isArray(args?.targets) ? args.targets : [args?.targets],
  nuclei_scan: (args) => Array.isArray(args?.targets) ? args.targets : [args?.targets],
  // ffuf lleva FUZZ donde va cada palabra: el control del alcance (como authorizeAll) lo lee como «fuzz».
  ffuf_fuzz: (args) => [typeof args?.url === "string" ? args.url.replaceAll("FUZZ", "fuzz") : args?.url],
  sqlmap_scan: (args) => [args?.url],
  katana_crawl: (args) => [args?.url],
};

/** El servidor MCP incorporado de REA nombra sus herramientas «rea.<nombre>»; la procedencia va por el nombre. */
export const nombreBase = (herramienta: string) => herramienta.startsWith("rea.") ? herramienta.slice(4) : herramienta;

/** Host de un destino (URL, host, IP o rango), sin esquema, usuario, ruta ni puerto. */
const hostDe = (destino: string) => {
  const sinEsquema = destino.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/)[0]!;
  return sinEsquema.slice(sinEsquema.lastIndexOf("@") + 1);
};

/** Lo que una línea de shell no deja leer: el destino se arma al correr, o el tráfico va por otro camino. */
const SHELL_OPACO = /\$\(|`|\beval\b|\bbase64\s+(?:-d|--decode)\b|\bxxd\s+-r\b|(?:^|\s)(?:-x|--proxy|--preproxy|--socks\S*|--resolve|--connect-to)(?=\s|=)/;

/**
 * Destinos que nombra una línea de shell (URLs y usuario@host), o undefined si la línea arma el destino de una
 * forma que no se puede leer, o si un marcador queda dentro de un nombre de host (iría por DNS).
 */
export function destinosDeShell(comando: string): string[] | undefined {
  if (SHELL_OPACO.test(comando) || /‹SECRETO_\d+›\.|[.@]‹SECRETO_\d+›/.test(comando)) return undefined;
  const destinos: string[] = [];
  const resto = comando.replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s'"<>|;&)]+/gi, (url) => { destinos.push(url); return " "; });
  for (const [, host] of resto.matchAll(/(?<![\w.%+-])[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})\b/gi)) destinos.push(host!);
  return destinos;
}
/** Procedencias de texto: lo que se aprende de ellas tiene que parecer una credencial (pareceSecreto). */
const DE_TEXTO = new Set<Origen>(["operador", "local", "objetivo", "agente", "modelo"]);
/** Qué tapa cada vista: la del modelo, sólo lo del operador; la de trazas, todo. */
const tapa = (clase: Clase | undefined, vista: Vista) => vista === "trazas" || clase === "operador";

/**
 * Herramientas cuya salida es material del objetivo: la traen de un sistema bajo prueba (red, navegador,
 * escáneres, el correo de las cuentas de prueba) o de un artefacto del objetivo puesto en el proyecto (su código,
 * su APK, sus binarios). Cualquier otra (shell, CLIs de plataformas, importadores de archivos del operador como
 * HAR o Postman, memoria, MCP sin declarar, herramientas nuevas) es del operador hasta que se la declare acá.
 * Una herramienta que lee archivos de la máquina puede decir otra procedencia en su resultado (ToolResult.procedencia):
 * las de código y REA leen la carpeta del proyecto, que es del operador si es su carpeta personal (codigo.ts).
 */
export const SALIDA_DEL_OBJETIVO: ReadonlySet<string> = new Set([
  // HTTP y navegador sobre el alcance.
  "http_request", "http_probe", "http_replay", "access_matrix", "site_map",
  "browser_open", "browser_act", "browser_read", "browser_tabs", "browser_capture",
  "auth_probe", "param_probe", "body_probe", "path_probe", "tech_fingerprint", "graphql_probe", "outbound_probe",
  "race_probe", "csrf_check", "ws_probe", "reset_probe", "upload_probe", "ids_harvest", "jwt_inspect",
  // Reconocimiento y escáneres.
  "nmap_scan", "ffuf_fuzz", "sqlmap_scan", "httpx_probe", "nuclei_scan", "subfinder_enum", "katana_crawl", "dns_resolve",
  "wayback_cdx", "crt_sh", "github_search", "takeover_check", "js_endpoints", "sourcemap_recover", "js_wayback_diff",
  // Código, apps y binarios del objetivo (REA incluido, salvo la captura HAR, que es la navegación del operador).
  "code_list", "code_search", "code_read", "code_semgrep", "code_gitleaks", "apk_analyze",
  "analyze_javascript_application", "trace_javascript_semantics", "trace_application_feature", "capture_browser_scenario",
  "open_binary", "inspect_artifact", "binary_overview", "inspect_apk_signature", "decode_android_resources",
  "identify_flutter_build", "inspect_dart_aot", "inspect_electron_fuses", "open_bundle_resources", "inspect_native_exports",
  "inspect_elf_notes", "inspect_pe_imports", "inspect_pe_certificates", "inspect_go_binary", "inspect_rust_binary",
  "inspect_byte_entropy", "inspect_sqlite_database", "inspect_python_pyc", "harness_build", "fuzz_run", "poc_run",
  // Post-explotación, y códigos y enlaces que el objetivo manda a las casillas de prueba.
  "postex_persist", "postex_exfil", "postex_cleanup", "mail_wait",
  // #41: el código de la web del objetivo (web_source_pull), lo que se lee de fuentes públicas de referencia (GitHub,
  // la página del programa: una clave filtrada ahí es un hallazgo), la cripto del código del proyecto (code_crypto,
  // que como code_read dice «local» en la carpeta del operador) y lo que confirma hash_crack sobre valores observados.
  "web_source_pull", "reference_read", "code_crypto", "hash_crack",
  // El grafo de hechos (src/grafo.ts) devuelve lo observado del objetivo: rutas, parámetros, ids, tecnologías.
  "grafo",
]);
/** Herramientas cuya salida escribe otro modelo de la sesión: sin clase. */
const SALIDA_DE_UN_MODELO: ReadonlySet<string> = new Set(["delegate", "deep_reason"]);
/** Productores de artefactos que no son nombres de herramienta: intercambios HTTP, escáneres y el oyente de callbacks. */
const PRODUCTORES_DEL_OBJETIVO: ReadonlySet<string> = new Set(["http", "nmap", "ffuf", "sqlmap", "httpx", "nuclei", "subfinder", "katana", "dnsx", "outbound_listener", "referencia"]);

/** Procedencia de lo que devuelve una herramienta, por su nombre (las de REA, «rea.x», por el de adentro). */
export const origenDeHerramienta = (nombre: string): Origen => {
  const base = nombreBase(nombre);
  return SALIDA_DEL_OBJETIVO.has(base) ? "objetivo" : SALIDA_DE_UN_MODELO.has(base) ? "modelo" : "local";
};

/** Procedencia de un texto de una trayectoria según quién lo escribió («operador», «local», «herramienta:x»; si no, un modelo). */
export const origenDeTraza = (de: string | undefined): Origen =>
  de?.startsWith("herramienta:") ? origenDeHerramienta(de.slice("herramienta:".length)) : de === "operador" || de === "local" ? de : "modelo";

/** Procedencia de un artefacto por su productor («http», «herramienta:shell», «rea:open_binary», «apk_analyze:secretos:x»…). */
export function origenDeProductor(productor: string | undefined): Origen {
  // La copia sin redactar que REA guarda para el operador queda como la marcó él: suya.
  if (!productor || /:operador$/.test(productor)) return "local";
  const nombre = productor.replace(/^(?:herramienta|contexto|rea):/, "").split(":")[0]!;
  return PRODUCTORES_DEL_OBJETIVO.has(nombre) ? "objetivo" : origenDeHerramienta(nombre);
}

/**
 * Herramientas cuyos argumentos son texto que se guarda para que lo lea un modelo más adelante, quizás en
 * otra sesión: ahí no se repone el valor (no es algo que se ejecuta) ni queda el número, que en otra sesión
 * sería otro secreto. Queda «‹secreto›».
 */
const GUARDAN_TEXTO = new Set(["memory_write", "finding_record", "finding_update", "investigation_output", "verdict", "grafo_anotar"]);
/** Herramientas cuyos argumentos son un pedido a otro modelo de esta misma sesión: el marcador viaja tal cual y ahí sigue valiendo. */
const HABLAN_CON_MODELOS = new Set(["delegate", "deep_reason"]);

/** PR #32: un valor de menos de 6 caracteres o sin letras ni dígitos no se trata como secreto. */
export const aprendible = (valor: string) => valor.length >= 6 && /[a-z0-9]/i.test(valor);

/** Marcas que ya dejaron otros tachadores: no son secretos. */
const YA_TACHADO = /‹SECRETO_|‹secreto›|<identidad |\[credencial omitida\]|<credencial>|\[secreto omitido/;

// Direcciones: una URL, una ruta de dos tramos o más, una IP, o un host en minúsculas con un TLD corto. Estrictas a
// propósito: un token base64 puede empezar con «/» o tener puntos, y ése sí es un secreto.
const URL = /^[a-z][a-z0-9+.-]*:\/\//i;
const RUTA = /^(?:\.{1,2}\/|~\/|\/[a-z0-9._~%-]*(?:\/[a-z0-9._~%-]*)+$)/i;
const HOST = /^(?:\*\.)?(?:[a-z0-9-]{1,30}\.)+[a-z]{2,6}(?::\d{1,5})?$/;
const IP = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2}|:\d{1,5})?$|^\[?[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\]?$/i;
const pareceDireccion = (valor: string) => URL.test(valor) || RUTA.test(valor) || HOST.test(valor) || IP.test(valor);
const FECHA = /^\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/;
/** Una referencia en código (process.env.X, config.secret, this.token, ${VAR}, getToken()) no es el secreto. */
const REFERENCIA = /^(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+|\$\{.*|\$[A-Za-z_]\w*)$|[()]/;

/**
 * Formatos de credencial conocidos (los mismos que tachan el informe, plataformas.ts y credenciales.ts). Lo
 * que coincide se aprende siempre: no puede ser un objetivo ni una palabra común.
 */
const FORMATOS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{16,16384}?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  tokenConPrefijo,
];
const FORMATOS_ENTEROS = FORMATOS.map((patron) => new RegExp(`^(?:${patron.source})$`));
const esFormato = (valor: string) => FORMATOS_ENTEROS.some((patron) => patron.test(valor));

/** Claves cuyo valor es una credencial (password, token, session, csrf…), como en el redactor del informe. */
const SENSIBLE = /passw|passphrase|^pass$|^pwd$|secret|token|cookie|authori[sz]ation|credential|signature|api[-_]?key|access[-_]?key|private[-_]?key|session|sessid|^sid$|csrf|xsrf|^(?:jwt|auth|clave|contrase[ñn]a)$/i;
/** …salvo las que describen a la credencial y no la contienen: token_type («Bearer»), expires_in, session_url… */
const DESCRIBE = /(?:type|types|url|uri|urls|endpoint|expires|expiry|expiresin|expiresat|expiration|ttl|timeout|maxage|lifetime|name|names|length|len|count|method|algorithm|alg|format|header|hint|policy|scope|scopes|required|enabled|disabled|path|domain|version|status|state|kind|label|description|location|field|param|parameter)$/;
export const claveSensible = (clave: string) => SENSIBLE.test(clave) && !DESCRIBE.test(clave.toLowerCase().replace(/[^a-z0-9]/g, ""));

/**
 * Un valor aprendido de un texto (no declarado por el operador) tiene que parecer una credencial: largo,
 * sin espacios, con letras y dígitos (o largo y con mayúsculas y minúsculas), y no una fecha. Así «invalid»
 * en un error de validación o «Bearer» en token_type no tapan cada aparición de esa palabra.
 */
export function pareceSecreto(valor: string): boolean {
  if (valor.length < 8 || /\s/.test(valor) || FECHA.test(valor) || REFERENCIA.test(valor) || pareceDireccion(valor)) return false;
  const letra = /[a-z]/i.test(valor);
  return (letra && /\d/.test(valor)) || (valor.length >= 16 && /[a-z]/.test(valor) && /[A-Z]/.test(valor));
}

/** Atributos de Set-Cookie: no son valores. */
const ATRIBUTO_COOKIE = /^(?:path|domain|expires|max-age|samesite|secure|httponly|priority|partitioned)$/i;

/** Valores de una cabecera Cookie o Set-Cookie (sin los atributos). */
export function piezasDeCookie(valor: string): string[] {
  const out: string[] = [];
  for (const parte of valor.split(/;\s*|\n|,\s*(?=[^;,=\s]+=)/)) {
    const at = parte.indexOf("=");
    if (at <= 0 || ATRIBUTO_COOKIE.test(parte.slice(0, at).trim())) continue;
    const pieza = parte.slice(at + 1).trim().replace(/^"|"$/g, "");
    if (pieza) out.push(pieza);
  }
  return out;
}

/** Credencial de una cabecera Authorization: sin el esquema; con Basic, también la contraseña decodificada. */
export function piezasDeAutorizacion(valor: string): string[] {
  const match = /^(\S+)\s+(\S+)$/.exec(valor.trim());
  if (!match) return [valor.trim()];
  const out = [match[2]!];
  if (/^basic$/i.test(match[1]!)) {
    try {
      const plano = Buffer.from(match[2]!, "base64").toString("utf8");
      const at = plano.indexOf(":");
      if (at >= 0 && /^[\x20-\x7e]+$/.test(plano)) out.push(plano.slice(at + 1));
    } catch {}
  }
  return out;
}

/** Lo que se tapa de un campo con clave sensible: piezas de cookie, la credencial de un Authorization, o el valor. */
function piezasDeCampo(clave: string, valor: string): string[] {
  if (/cookie/i.test(clave)) return piezasDeCookie(valor);
  if (/authori[sz]ation/i.test(clave)) return piezasDeAutorizacion(valor);
  return [valor];
}

/**
 * Las formas en que un secreto aparece en un texto: tal cual, escapado en JSON (una y dos veces), en una URL o en
 * HTML, y con los espacios colapsados (una clave PEM en una vista que junta las líneas, como el resumen de una
 * respuesta HTTP o una búsqueda en un artefacto).
 */
function formasDe(valor: string): string[] {
  const una = JSON.stringify(valor).slice(1, -1);
  const out = new Set([valor, una, JSON.stringify(una).slice(1, -1)]);
  if (/\s/.test(valor)) out.add(valor.replace(/\s+/g, " ").trim());
  try {
    const url = encodeURIComponent(valor);
    out.add(url);
    out.add(url.replace(/%20/g, "+"));
  } catch {}
  out.add(valor.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"));
  return [...out];
}

/** Hosts del alcance (sin esquema, ruta, puerto ni comodín): nunca se tratan como secretos. */
export function hostsDelAlcance(scope: Scope | undefined): string[] {
  const out = new Set<string>();
  for (const rule of [...(scope?.include ?? []), ...(scope?.exclude ?? [])]) {
    const host = rule.value.toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/^\*\./, "").split(/[/?#]/)[0]!.replace(/:\d+$/, "").replace(/\/\d+$/, "");
    if (host) out.add(host);
  }
  return [...out];
}

/** Variables de entorno con nombre de credencial (OROBAS_API_KEY, H1_API_TOKEN, AWS_SECRET_ACCESS_KEY…), en orden fijo. */
const CLAVE_ENTORNO = /(?:^|_)(?:TOKEN|SECRET|SECRETS|PASSWORD|PASSWD|APIKEY|CREDENTIALS?)(?:_|$)|(?:^|_)(?:API|ACCESS|PRIVATE|SECRET|SECRETS|AUTH|SIGNING|ENCRYPTION|MASTER)_KEY(?:_|$)/i;
export function secretosDelEntorno(env: NodeJS.ProcessEnv = process.env): Fuente[] {
  return Object.keys(env).filter((key) => CLAVE_ENTORNO.test(key)).sort().map((key) => ({ valor: env[key] ?? "", origen: "entorno" as const })).filter((item) => item.valor);
}

/** Lo que guarda el almacén cifrado: claves de orobas y de las plataformas, credenciales de correo. */
const DEL_ALMACEN = ["orobas", "hackerone", "bugcrowd", "intigriti", "correo"];
export function secretosDelAlmacen(read: (name: string) => string | undefined = readSecret): Fuente[] {
  const out: Fuente[] = [];
  const hojas = (value: unknown, clave = ""): void => {
    if (typeof value === "string") { if (claveSensible(clave)) out.push({ valor: value, origen: "almacén" }); }
    else if (Array.isArray(value)) value.forEach((item) => hojas(item, clave));
    else if (value && typeof value === "object") for (const [key, item] of Object.entries(value)) hojas(item, key);
  };
  for (const name of DEL_ALMACEN) {
    let raw: string | undefined;
    try { raw = read(name); } catch { continue; }
    if (!raw) continue;
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { parsed = undefined; }
    if (parsed && typeof parsed === "object") hojas(parsed);
    else {
      out.push({ valor: raw, origen: "almacén" });
      // «clientId:clientSecret» (Intigriti): el secreto es lo que va después de los dos puntos.
      const at = raw.indexOf(":");
      if (at > 0) out.push({ valor: raw.slice(at + 1), origen: "almacén" });
    }
  }
  return out;
}

/* ---------- Persistencia de los números: huellas, nunca valores ---------- */

export function marcadoresGuardados(db: DatabaseSync, sessionId: string): Map<string, number> {
  db.exec("create table if not exists secret_markers(session_id text not null, n integer not null, fingerprint text not null, primary key(session_id, n))");
  const rows = db.prepare("select n, fingerprint from secret_markers where session_id=? order by n").all(sessionId) as Array<{ n: number; fingerprint: string }>;
  return new Map(rows.map((row) => [row.fingerprint, Number(row.n)]));
}

export function origenesGuardados(db: DatabaseSync, sessionId: string): Map<number, string> {
  db.exec("create table if not exists secret_marker_origins(session_id text not null, n integer not null, origin_hash text not null, primary key(session_id, n))");
  const filas = db.prepare("select n, origin_hash from secret_marker_origins where session_id=?").all(sessionId);
  return new Map(filas.map((fila) => [Number(fila.n), String(fila.origin_hash)]));
}

/**
 * Clase de cada número guardado: «operador», «objetivo» o «sin-clase». Un número sin fila es de antes de las
 * clases y se sigue tratando como del operador (el registro lo decide; acá sólo se lee).
 */
export function clasesGuardadas(db: DatabaseSync, sessionId: string): Map<number, Clase | null> {
  db.exec("create table if not exists secret_marker_classes(session_id text not null, n integer not null, class text not null, primary key(session_id, n))");
  const filas = db.prepare("select n, class from secret_marker_classes where session_id=?").all(sessionId);
  return new Map(filas.map((fila) => [Number(fila.n), fila.class === "operador" || fila.class === "objetivo" ? fila.class : null]));
}

/** Guarda la huella y el origen de un número nuevo (una sola vez) y su clase (cada vez que cambia). */
export function guardarMarcador(db: DatabaseSync, sessionId: string, n: number, huella: string, sitio?: string, clase?: Clase | null): void {
  db.prepare("insert or ignore into secret_markers(session_id, n, fingerprint) values(?,?,?)").run(sessionId, n, huella);
  if (sitio) db.prepare("insert or ignore into secret_marker_origins(session_id,n,origin_hash) values(?,?,?)").run(sessionId, n, sitio);
  if (clase !== undefined) {
    db.exec("create table if not exists secret_marker_classes(session_id text not null, n integer not null, class text not null, primary key(session_id, n))");
    db.prepare("insert or replace into secret_marker_classes(session_id,n,class) values(?,?,?)").run(sessionId, n, clase ?? "sin-clase");
  }
}

/* ---------- El registro ---------- */

interface Entrada { n: number; valor: string; origen: Origen; clase: Clase | undefined; uso: Uso | undefined; sitio?: string }
interface Forma { texto: string; entrada: Entrada; corta: boolean }

export interface Opciones {
  /** Sal de las huellas (el id de la sesión): la misma contraseña en dos sesiones no da la misma huella. */
  sal: string;
  /** Huella → número, de lo que ya se marcó en esta sesión (al retomarla). */
  previas?: Map<string, number>;
  /** Guarda la huella de un número nuevo, y su clase cada vez que cambia (null: sin clase). */
  guardar?: (n: number, huella: string, sitio?: string, clase?: Clase | null) => void;
  origenesPrevios?: Map<number, string>;
  /** Clase guardada de cada número (null: sin clase). Un número previo sin clase guardada es del operador. */
  clasesPrevias?: Map<number, Clase | null>;
  /** ¿El destino (URL, host o IP) está en el alcance vigente? Lo usa la reposición en la shell. */
  enAlcance?: (destino: string) => boolean;
  /** Se consultan antes de cada pedido, siempre en el mismo orden: identidades, cookies, entorno. */
  fuentes?: Array<() => Iterable<Fuente>>;
  /** Hosts del alcance: un valor que es o contiene uno no se tapa. */
  objetivos?: () => string[];
}

const PALABRA = /[A-Za-z0-9_-]/;
/** Clave numérica de los primeros (o últimos) cuatro caracteres de un texto desde `at`. */
const clave4 = (text: string, at: number) => ((text.charCodeAt(at) * 31 + text.charCodeAt(at + 1)) * 31 + text.charCodeAt(at + 2)) * 31 + text.charCodeAt(at + 3);
/** Un tramo cortado más corto que esto no es un secreto usable: no se busca. */
const PARCIAL_MIN = 8;
/** Hasta dónde se busca hacia atrás desde un corte el comienzo de un secreto partido. */
const VENTANA_MAX = 4096;
/** Tope de caracteres en las memorias de textos ya vistos; al pasarlo se vacían (sólo cuesta recalcular). */
const MEMORIA_MAX = 32 * 1024 * 1024;

/** Orden fijo de las procedencias: cada texto recuerda con cuáles ya se aprendió (un bit por procedencia). */
const ORIGENES: readonly Origen[] = ["identidad", "cookie", "entorno", "almacén", "operador", "local", "objetivo", "modelo", "agente", "propuesta"];

/** Dos vistas del mismo mensaje: ¿dicen lo mismo? */
function mismoMensaje(a: Message, b: Message): boolean {
  if (a === b) return true;
  if (a.content !== b.content) return false;
  if (a.role !== "assistant" || b.role !== "assistant") return true;
  return a.toolCalls.every((call, index) => call.arguments === b.toolCalls[index]?.arguments);
}

export class SecretosSesion {
  private readonly porValor = new Map<string, Entrada>();
  private readonly porNumero = new Map<number, Entrada>();
  private readonly porForma = new Map<string, Entrada>();
  private readonly porCabeza = new Map<number, Forma[]>();
  private readonly porCola = new Map<number, Forma[]>();
  /** Entradas en orden de registro. */
  private readonly entradas: Entrada[] = [];
  /** Sube con cada alta y con cada cambio de clase: lo que se tapó con una versión anterior se recalcula. */
  private version = 0;
  private largoMax = 0;
  private ultimo = 0;
  private readonly previas: Map<string, number>;
  private objetivosVistos: string[] = [];
  /** Textos ya aprendidos (con qué procedencias) y textos ya tapados en cada vista (con la versión con que se taparon). */
  private aprendidos = new Map<string, number>();
  private tapados: Record<Vista, Map<string, { version: number; texto: string }>> = { modelo: new Map(), trazas: new Map() };
  private memoria = 0;
  private readonly opciones: Opciones;

  constructor(opciones: Opciones) {
    this.opciones = opciones;
    this.previas = new Map(opciones.previas ?? []);
    for (const n of this.previas.values()) this.ultimo = Math.max(this.ultimo, n);
  }

  /** Cuántos secretos conoce la sesión. */
  get size(): number {
    return this.entradas.length;
  }

  /** Números, procedencia y clase de cada secreto, para mostrarle al operador qué se tapa (nunca el valor). */
  resumen(): Array<{ marcador: string; origen: Origen; clase: Clase | "sin clase"; largo: number }> {
    return this.entradas.map((entrada) => ({ marcador: marcador(entrada.n), origen: entrada.origen, clase: entrada.clase ?? "sin clase", largo: entrada.valor.length }));
  }

  /** Clase de un valor conocido (null: sin clase; undefined: no es un secreto de la sesión). */
  claseDelValor(valor: string): Clase | null | undefined {
    const entrada = this.porValor.get(valor) ?? this.porForma.get(valor);
    return entrada ? entrada.clase ?? null : undefined;
  }

  private huella(valor: string): string {
    return createHash("sha256").update(`${this.opciones.sal}\0${valor}`).digest("hex").slice(0, 32);
  }

  /** Un valor que contiene un host del alcance es un objetivo (o lo nombra): el modelo lo necesita a la vista. */
  private nombraObjetivo(valor: string): boolean {
    const lower = valor.toLowerCase();
    return this.objetivosVistos.some((host) => host.length >= 4 && lower.includes(host));
  }

  private admisible(valor: string, origen: Origen, deTexto: boolean, formato: boolean): boolean {
    if (!aprendible(valor) || YA_TACHADO.test(valor)) return false;
    if (formato) return true;
    if (this.nombraObjetivo(valor)) return false;
    // Lo que se aprende de un texto o de una cookie tiene que parecer una credencial (y no una dirección); lo que
    // declaró el operador (la cabecera de una identidad, una variable de entorno, el almacén, «mi contraseña es…»)
    // vale con la regla de #32.
    return deTexto || origen === "cookie" ? pareceSecreto(valor) : true;
  }

  /**
   * Registra un secreto con su procedencia; devuelve su marcador, o nada si el valor no se trata como secreto. Lo
   * que llega de una procedencia de texto (operador, local, objetivo, modelo) tiene que parecer una credencial.
   * `sitio`: el origen HTTP donde apareció (ata el marcador de un secreto del operador a ese destino).
   */
  registrar(valor: string, origen: Origen, sitio?: string): string | undefined {
    return this.alta(valor, origen, sitio, DE_TEXTO.has(origen));
  }

  private alta(valor: string, origen: Origen, sitio: string | undefined, deTexto: boolean): string | undefined {
    if (typeof valor !== "string" || !valor) return undefined;
    const ya = this.porValor.get(valor) ?? this.porForma.get(valor);
    if (ya) {
      this.reclasificar(ya, origen);
      return marcador(ya.n);
    }
    if (!this.admisible(valor, origen, deTexto, esFormato(valor))) return undefined;
    const huella = this.huella(valor);
    const previa = this.previas.get(huella);
    const n = previa ?? ++this.ultimo;
    // De dónde vino (el origen HTTP de la respuesta, como huella): una huella anterior conserva el primero. Es
    // procedencia, no permiso: adónde se repone lo decide el alcance.
    const sitioHash = previa !== undefined ? this.opciones.origenesPrevios?.get(n) : sitio ? this.huella("origen:" + sitio) : undefined;
    // Al retomar, la clase guardada. Un número de antes de las clases sigue del operador: así se veía, y así el
    // prefijo que ya salió no cambia ni se destapa nada que estaba tapado.
    const guardadas = this.opciones.clasesPrevias;
    const clase = previa === undefined ? claseDe(origen) : guardadas?.has(n) ? guardadas.get(n) ?? undefined : "operador";
    const entrada: Entrada = { n, valor, origen, clase, uso: undefined, sitio: sitioHash };
    this.porValor.set(valor, entrada);
    this.porNumero.set(n, entrada);
    this.entradas.push(entrada);
    for (const texto of formasDe(valor)) {
      if (this.porForma.has(texto)) continue;
      this.porForma.set(texto, entrada);
      const forma: Forma = { texto, entrada, corta: texto.length < 10 };
      for (const [indice, key] of [[this.porCabeza, clave4(texto, 0)], [this.porCola, clave4(texto, texto.length - 4)]] as const) {
        const lista = indice.get(key) ?? [];
        lista.push(forma);
        lista.sort((a, b) => b.texto.length - a.texto.length);
        indice.set(key, lista);
      }
      this.largoMax = Math.max(this.largoMax, texto.length);
    }
    this.version++;
    if (previa === undefined) {
      this.previas.set(huella, n);
      this.opciones.guardar?.(n, huella, sitioHash, clase ?? null);
    }
    this.reclasificar(entrada, origen);
    return marcador(n);
  }

  /**
   * Una fuente que carga el operador (identidad, propuesta, cookie, entorno, almacén) pasa el valor al operador; un
   * valor sin clase toma la de la primera procedencia conocida. Ninguna otra procedencia cambia una clase ya puesta.
   * Cada procedencia suma a hasta dónde se puede reponer (usoCon).
   */
  private reclasificar(entrada: Entrada, origen: Origen): void {
    entrada.uso = usoCon(entrada.uso, origen);
    const nueva = MANDAN.has(origen) ? "operador" : entrada.clase ?? claseDe(origen);
    if (nueva === entrada.clase) return;
    entrada.clase = nueva;
    this.version++;
    this.opciones.guardar?.(entrada.n, this.huella(entrada.valor), entrada.sitio, nueva ?? null);
  }

  /** Consulta las fuentes (identidades, cookies del navegador, entorno) y el alcance vigente. */
  sincronizar(): void {
    this.objetivosVistos = (this.opciones.objetivos?.() ?? []).map((host) => host.toLowerCase());
    for (const fuente of this.opciones.fuentes ?? []) {
      for (const { valor, origen, sitio } of fuente()) this.registrar(valor, origen, sitio);
    }
  }

  /**
   * Aprende de un texto lo que tiene forma de credencial: formatos conocidos, Bearer y Basic, cabeceras
   * Cookie/Set-Cookie/Authorization, campos JSON y «clave=valor» con clave sensible, inputs de formulario, URLs
   * con usuario y contraseña y «mi contraseña es …». La forma decide QUÉ es un secreto;
   * la clase la decide `origen`, la procedencia del texto. `sitio`: el origen HTTP de una respuesta.
   */
  aprender(texto: string, origen: Origen, sitio?: string): void {
    if (!texto) return;
    const bit = 1 << ORIGENES.indexOf(origen);
    const visto = this.aprendidos.get(texto) ?? 0;
    if (visto & bit) return;
    if (!visto) this.recordar(texto.length);
    this.aprendidos.set(texto, visto | bit);
    for (const literal of texto.matchAll(/\b(?:mi (?:clave|contrase[ñn]a|token)|my (?:password|token)) (?:es|is)\s+(?:"([^"\n]+)"|'([^'\n]+)'|([^\s,;!?]+))/gi)) {
      const valor = literal[1] ?? literal[2] ?? literal[3]!.replace(/[.]$/, "");
      this.alta(valor, origen, undefined, false);
    }
    // Un id opaco sin etiqueta (nanoid, id de GraphQL) no se aprende: no es una credencial, y taparlo dejaba ciegas
    // las pruebas de IDOR. Sólo cuentan los formatos conocidos y los campos con nombre de credencial.
    for (const candidato of candidatos(texto)) this.alta(candidato, origen, sitio, true);
    // Un JSON dentro de una cadena JSON (un artefacto leído con artifact_read) llega escapado: se mira también desescapado una vez.
    if (texto.includes('\\"')) for (const candidato of candidatos(texto.replace(/\\\\/g, "\u0000").replace(/\\"/g, '"').replace(/\u0000/g, "\\"))) this.alta(candidato, origen, sitio, true);
  }

  private recordar(chars: number): void {
    this.memoria += chars;
    if (this.memoria <= MEMORIA_MAX) return;
    this.aprendidos = new Map();
    this.tapados = { modelo: new Map(), trazas: new Map() };
    this.memoria = chars;
  }

  /**
   * Reemplaza por su marcador cada secreto conocido que la vista tapa: la del modelo, los del operador; la de
   * trazas, todos. Determinista: el mismo texto, la misma salida.
   */
  ocultar(texto: string, vista: Vista): string {
    if (!texto || !this.entradas.length) return texto;
    const memo = this.tapados[vista];
    const previo = memo.get(texto);
    if (previo?.version === this.version) return previo.texto;
    if (!previo) this.recordar(texto.length);
    const salida = this.reemplazar(texto, vista);
    memo.set(texto, { version: this.version, texto: salida });
    return salida;
  }

  private reemplazar(texto: string, vista: Vista): string {
    const partes: string[] = [];
    let copiado = 0;
    for (let at = 0; at + 4 <= texto.length; ) {
      const forma = this.porCabeza.get(clave4(texto, at))?.find((item) => tapa(item.entrada.clase, vista) && texto.startsWith(item.texto, at) && (!item.corta || (!PALABRA.test(texto[at - 1] ?? "") && !PALABRA.test(texto[at + item.texto.length] ?? ""))));
      if (!forma) { at++; continue; }
      partes.push(texto.slice(copiado, at), marcador(forma.entrada.n));
      at = copiado = at + forma.texto.length;
    }
    const entero = copiado ? partes.join("") + texto.slice(copiado) : texto;
    return this.cortados(entero, vista);
  }

  /**
   * Un texto recortado (la salida de una herramienta truncada, una ventana de artifact_read) puede dejar un
   * secreto por la mitad: el comienzo antes de «…» o del final, o el final al principio del texto o después de un
   * «…». Esos pedazos también se tapan, desde PARCIAL_MIN caracteres.
   */
  private cortados(texto: string, vista: Vista): string {
    const ventana = Math.min(this.largoMax, VENTANA_MAX);
    if (!ventana) return texto;
    // Los recortes del harness terminan en «…» (summarize, bounded, la dieta); el texto entero también puede cortar.
    const elipsis: number[] = [];
    for (let at = texto.indexOf("…"); at >= 0; at = texto.indexOf("…", at + 1)) elipsis.push(at);
    const tramos: Array<[number, number, number]> = [];
    for (let corte of new Set([...elipsis, texto.length])) {
      while (corte > 0 && /\s/.test(texto[corte - 1]!)) corte--;
      for (let desde = Math.max(0, corte - ventana + 1); desde <= corte - PARCIAL_MIN; desde++) {
        const lista = this.porCabeza.get(clave4(texto, desde));
        if (!lista || (desde > 0 && PALABRA.test(texto[desde - 1]!))) continue;
        const pedazo = texto.slice(desde, corte);
        const forma = lista.find((item) => tapa(item.entrada.clase, vista) && item.texto.length > pedazo.length && item.texto.startsWith(pedazo));
        if (forma) { tramos.push([desde, corte, forma.entrada.n]); break; }
      }
    }
    // El final de un secreto al comienzo del texto o justo después de un «…» (una ventana que empieza a mitad).
    for (let inicio of new Set([0, ...elipsis.map((at) => at + 1)])) {
      while (inicio < texto.length && /\s/.test(texto[inicio]!)) inicio++;
      for (let hasta = Math.min(texto.length, inicio + ventana - 1); hasta >= inicio + PARCIAL_MIN; hasta--) {
        const lista = this.porCola.get(clave4(texto, hasta - 4));
        if (!lista || (hasta < texto.length && PALABRA.test(texto[hasta]!))) continue;
        const pedazo = texto.slice(inicio, hasta);
        const forma = lista.find((item) => tapa(item.entrada.clase, vista) && item.texto.length > pedazo.length && item.texto.endsWith(pedazo));
        if (forma) { tramos.push([inicio, hasta, forma.entrada.n]); break; }
      }
    }
    if (!tramos.length) return texto;
    tramos.sort((a, b) => a[0] - b[0]);
    const partes: string[] = [];
    let copiado = 0;
    for (const [desde, hasta, n] of tramos) {
      if (desde < copiado) continue;
      partes.push(texto.slice(copiado, desde), marcador(n));
      copiado = hasta;
    }
    return partes.join("") + texto.slice(copiado);
  }

  /** Tapa los secretos de cada cadena de un valor (los argumentos JSON de una llamada), una por una. */
  private ocultarHondo(value: unknown, vista: Vista): unknown {
    if (typeof value === "string") return this.ocultar(value, vista);
    if (Array.isArray(value)) return value.map((item) => this.ocultarHondo(item, vista));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [this.ocultar(key, vista), this.ocultarHondo(item, vista)]));
    return value;
  }

  /** Los argumentos de una llamada del asistente: cada cadena por separado, y se reserializa sólo si algo cambió. */
  private ocultarArgumentos(argumentos: string, vista: Vista): string {
    if (!argumentos) return argumentos;
    let parsed: unknown;
    try { parsed = JSON.parse(argumentos); } catch { return this.ocultar(argumentos, vista); }
    const tapado = this.ocultarHondo(parsed, vista);
    const salida = JSON.stringify(tapado);
    return salida === JSON.stringify(parsed) ? argumentos : salida;
  }

  private ocultarMensaje(message: Message, vista: Vista): Message {
    if (message.role === "assistant") {
      const content = this.ocultar(message.content, vista);
      const toolCalls = message.toolCalls.map((call) => {
        const argumentos = this.ocultarArgumentos(call.arguments, vista);
        return argumentos === call.arguments ? call : { ...call, arguments: argumentos };
      });
      const igual = content === message.content && toolCalls.every((call, index) => call === message.toolCalls[index]);
      return igual ? message : { ...message, content, toolCalls };
    }
    const content = this.ocultar(message.content, vista);
    return content === message.content ? message : { ...message, content };
  }

  /**
   * Aprende de lo que entra a un pedido, cada texto con su procedencia: el sistema y las herramientas son del
   * harness; un mensaje del usuario, del operador; un resultado, de la herramienta que lo produjo; un checkpoint,
   * del modelo que lo escribió; los argumentos de una llamada del asistente, del agente (la contraseña que inventó
   * para una cuenta de prueba: la ve, y en trazas va tapada). Del texto libre del asistente no aprende.
   */
  private aprenderPedido(request: LlmRequest): void {
    this.sincronizar();
    this.aprender(request.system, "local");
    for (const tool of request.tools) {
      this.aprender(tool.description, "local");
      this.aprender(JSON.stringify(tool.parameters), "local");
    }
    for (const message of request.messages) this.aprenderMensaje(message);
  }

  /** Aprende de un mensaje de la conversación con la procedencia que le toca (ver aprenderPedido). */
  aprenderMensaje(message: Message, origenDeResultado: (nombre: string) => Origen = origenDeHerramienta): void {
    if (message.role === "user") this.aprender(message.content, "operador");
    else if (message.role === "tool") this.aprender(message.content, origenDeResultado(message.name));
    else if (message.role === "checkpoint") this.aprender(message.content, "modelo");
    else if (message.role === "assistant") for (const call of message.toolCalls) this.aprenderArgumentos(call.arguments);
  }

  /**
   * Lo que el modelo escribió en los argumentos de una llamada (procedencia «agente», material del objetivo): el
   * JSON entero (campos con nombre de credencial) y cada cadena por separado (un cuerpo JSON dentro de «body», una
   * línea de shell con password=…, una cabecera Authorization), que escapada dentro del JSON no se reconoce.
   */
  aprenderArgumentos(argumentos: unknown): void {
    let valor = argumentos;
    if (typeof argumentos === "string") {
      this.aprender(argumentos, "agente");
      try { valor = JSON.parse(argumentos); } catch { return; }
    } else {
      try { this.aprender(JSON.stringify(argumentos ?? null), "agente"); } catch { return; }
    }
    let presupuesto = 2_000;
    const hojas = (item: unknown): void => {
      if (--presupuesto < 0) return;
      if (typeof item === "string") this.aprender(item, "agente");
      else if (Array.isArray(item)) item.forEach(hojas);
      else if (item && typeof item === "object") Object.values(item).forEach(hojas);
    };
    hojas(valor);
  }

  private vistaDelPedido(request: LlmRequest, vista: Vista): LlmRequest {
    const messages = request.messages.map((message) => this.ocultarMensaje(message, vista));
    const tools = request.tools.map((tool) => ({ ...tool, description: this.ocultar(tool.description, vista), parameters: this.ocultarHondo(tool.parameters, vista) as object }));
    return { ...request, system: this.ocultar(request.system, vista), messages, tools };
  }

  /**
   * El pedido tal como viaja al proveedor del modelo: aprende de lo que entra y tapa lo del operador. No toca los
   * mensajes originales (la sesión guarda lo que pasó; lo que viaja es otra vista).
   */
  pedido(request: LlmRequest): LlmRequest {
    this.aprenderPedido(request);
    return this.vistaDelPedido(request, "modelo");
  }

  /**
   * Las dos vistas de un mismo pedido, con los mismos números: la que viaja al proveedor y la que se guarda como
   * traza (todo tapado). `conMaterial`: la del modelo deja a la vista algo que las trazas tapan.
   */
  vistas(request: LlmRequest): { modelo: LlmRequest; trazas: LlmRequest; conMaterial: boolean } {
    this.aprenderPedido(request);
    const modelo = this.vistaDelPedido(request, "modelo");
    const trazas = this.vistaDelPedido(request, "trazas");
    const igual = modelo.system === trazas.system &&
      modelo.tools.every((tool, index) => tool.description === trazas.tools[index]!.description && JSON.stringify(tool.parameters) === JSON.stringify(trazas.tools[index]!.parameters)) &&
      modelo.messages.every((message, index) => mismoMensaje(message, trazas.messages[index]!));
    return { modelo, trazas, conMaterial: !igual };
  }

  /**
   * La respuesta de un modelo trae algo que las trazas tapan: la contraseña que el agente acaba de inventar para una
   * cuenta de prueba, o material del objetivo que el pedido no tenía. Aprende de los argumentos de sus llamadas como
   * lo haría el próximo pedido (procedencia «agente») y compara la respuesta con su vista de trazas. El motor lo usa
   * para pedir que el gateway descarte la traza de ese pedido: salió sin material, pero la respuesta que el gateway
   * pudo guardar lo tiene en claro.
   */
  respuestaConMaterial(reply: Message): boolean {
    if (reply.role !== "assistant") return false;
    this.sincronizar();
    this.aprenderMensaje(reply);
    return this.ocultarMensaje(reply, "trazas") !== reply;
  }

  /** Un texto para el modelo: aprende de él con su procedencia y tapa lo del operador (antes de recortarlo). */
  vistaModelo(texto: string, origen: Origen, sitio?: string): string {
    this.sincronizar();
    this.aprender(texto, origen, sitio);
    return this.ocultar(texto, "modelo");
  }

  /** Un texto para las trazas (lo que se guarda o se envía como material de entrenamiento): aprende y tapa todo. */
  vistaTrazas(texto: string, origen: Origen): string {
    this.sincronizar();
    this.aprender(texto, origen);
    return this.ocultar(texto, "trazas");
  }

  /** Un transporte que sólo deja salir pedidos con la vista del modelo. */
  transporte(transport: Transport): Transport {
    return (request) => transport(this.pedido(request));
  }

  /**
   * Por qué una herramienta no puede recibir el valor de un secreto del operador (undefined: puede). Las que
   * ejecutan contra el alcance y lo hacen cumplir, sí: el alcance decide adónde va. La shell y los escáneres
   * externos, si todos los destinos que nombra la llamada están en el alcance y nombra al menos uno (la misma
   * condición para los dos, sin flags propios de cada escáner). Las demás no ejecutan contra el objetivo.
   */
  private sinPermiso(herramienta: string, args: unknown): string | undefined {
    const nombre = nombreBase(herramienta);
    if (EJECUTAN_EN_EL_ALCANCE.has(nombre)) return undefined;
    if (nombre === "shell") {
      const comando = String((args as { command?: unknown })?.command ?? "");
      const destinos = destinosDeShell(comando);
      if (!destinos) return "En la shell, una credencial del operador sólo va en una línea que nombra sus destinos: sin $( ), comillas invertidas, eval, decodificaciones, proxies ni el marcador dentro de un nombre de host.";
      if (!destinos.length) return "En la shell, una credencial del operador sólo va hacia un destino del alcance que la línea nombre (una URL https://… o usuario@host); esta línea no nombra ninguno.";
      return this.fueraDelAlcance(destinos);
    }
    const escaner = DESTINOS_DE_ESCANER[nombre];
    if (escaner) {
      const destinos = escaner(args);
      if (!destinos.length || destinos.some((destino) => typeof destino !== "string" || !destino.trim())) return `${nombre}: una credencial del operador va sólo hacia destinos del alcance que la llamada nombre, y esta llamada no nombra ninguno válido.`;
      const conMarcador = (destinos as string[]).filter((destino) => /‹SECRETO_\d+›/.test(hostDe(destino)));
      if (conMarcador.length) return `${nombre}: el marcador quedó dentro de un nombre de host (${conMarcador.slice(0, 2).join(", ")}); iría por DNS a quien resuelva ese nombre.`;
      return this.fueraDelAlcance(destinos as string[]);
    }
    return `${herramienta} no ejecuta contra el alcance: una credencial del operador se repone sólo en las herramientas que van al objetivo (http_request, el navegador, las sondas, la shell y los escáneres externos con destinos del alcance).`;
  }

  private fueraDelAlcance(destinos: string[]): string | undefined {
    const fuera = destinos.filter((destino) => !this.opciones.enAlcance?.(destino));
    return fuera.length ? `Fuera del alcance: ${fuera.slice(0, 3).join(", ")}. Una credencial del operador no sale del alcance.` : undefined;
  }

  /**
   * Repone los marcadores de un texto que se va a ejecutar. Si el texto es un JSON (el cuerpo de una petición
   * escrito por el modelo) y el marcador está dentro de una cadena, el valor va escapado como lo pondría él.
   * Lo del objetivo (o sin clase) no tiene más límite que el alcance, que controla la herramienta. Lo del operador
   * se repone si su uso lo permite y la herramienta ejecuta contra el alcance (`permiso`, que se calcula una vez).
   */
  private reponerTexto(texto: string, desconocidos: Set<string>, permiso: () => string | undefined): string {
    if (!texto.includes("‹SECRETO_")) return texto;
    const con = (escapar: boolean) => texto.replace(MARCA, (todo, n: string) => {
      const entrada = this.porNumero.get(Number(n));
      if (!entrada) { desconocidos.add(todo); return todo; }
      if (entrada.clase === "operador") {
        if (entrada.uso === "nunca") throw new Error(`${todo} es una clave del servicio o de un proveedor (variable de entorno o almacén): no se manda a ningún objetivo.`);
        if (entrada.uso === "pendiente") throw new Error(`${todo} es de una identidad importada que el operador todavía no aprobó: pedile que la apruebe con /identity.`);
        // «alcance», o sin uso conocido (un número guardado antes de las clases que ninguna fuente reclama: las de
        // entorno, almacén y propuestas se consultan antes de cada pedido y le darían «nunca» o «pendiente»).
        const motivo = permiso();
        if (motivo) throw new Error(`No repongo ${todo}. ${motivo}`);
      }
      return escapar ? JSON.stringify(entrada.valor).slice(1, -1) : entrada.valor;
    });
    const plano = con(false);
    if (/^\s*[[{]/.test(texto)) {
      try {
        JSON.parse(texto);
        const escapado = con(true);
        JSON.parse(escapado);
        return escapado;
      } catch { /* no era JSON, o el marcador no estaba dentro de una cadena */ }
    }
    return plano;
  }

  private reponerHondo(value: unknown, desconocidos: Set<string>, permiso: () => string | undefined): unknown {
    if (typeof value === "string") return this.reponerTexto(value, desconocidos, permiso);
    if (Array.isArray(value)) return value.map((item) => this.reponerHondo(item, desconocidos, permiso));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.reponerHondo(item, desconocidos, permiso)]));
    return value;
  }

  /**
   * Argumentos de una herramienta a punto de ejecutarse: los marcadores vuelven a ser valores sólo acá. En lo
   * que se guarda para que lo lea un modelo (memoria, hallazgos) queda «‹secreto›», y en un pedido a otro
   * modelo de la sesión (delegate, deep_reason), el marcador tal cual. `desconocidos`: marcadores que no son de
   * esta sesión; con alguno, la herramienta no se ejecuta. Un secreto del operador que no puede ir adonde va la
   * herramienta corta la llamada con el motivo.
   */
  reponer<T>(herramienta: string, args: T): { args: T; desconocidos: string[] } {
    if (HABLAN_CON_MODELOS.has(herramienta)) return { args, desconocidos: [] };
    if (GUARDAN_TEXTO.has(herramienta)) {
      const generico = (value: unknown): unknown => typeof value === "string" ? neutralizarMarcadores(value)
        : Array.isArray(value) ? value.map(generico)
        : value && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([key, item]) => [neutralizarMarcadores(key), generico(item)]))
        : value;
      return { args: generico(args) as T, desconocidos: [] };
    }
    const desconocidos = new Set<string>();
    let calculado: { motivo: string | undefined } | undefined;
    const permiso = () => (calculado ??= { motivo: this.sinPermiso(herramienta, args) }).motivo;
    const repuesto = this.reponerHondo(args, desconocidos, permiso) as T;
    return { args: repuesto, desconocidos: [...desconocidos] };
  }
}

/* ---------- Aprendizaje por patrones ---------- */

const CABECERA_COOKIE = /^[ \t]*(set-cookie|cookie)[ \t]*:[ \t]*([^\r\n]+)$/gim;
const CABECERA_CREDENCIAL = /^[ \t]*(authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token|api-key|x-csrf-token|x-xsrf-token)[ \t]*:[ \t]*([^\r\n]+)$/gim;
const BEARER = /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/gi;
const BASIC = /\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})/gi;
const CAMPO_JSON = /"([A-Za-z0-9_$.\- ]{1,64})"\s*:\s*"((?:\\.|[^"\\]){1,16384})"/g;
const URL_CON_CLAVE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@"'<>]+:([^\s/@"'<>]+)@/gi;
const INPUT = /<(?:input|meta)\b[^>]{0,800}>/gi;

/** Valores con forma de credencial en un texto, en orden de patrón y de aparición (determinista). */
export function candidatos(texto: string): string[] {
  const out: string[] = [];
  for (const patron of FORMATOS) for (const match of texto.matchAll(patron)) out.push(match[0]);
  for (const match of texto.matchAll(BEARER)) out.push(match[1]!);
  for (const match of texto.matchAll(BASIC)) out.push(...piezasDeAutorizacion(`Basic ${match[1]}`));
  for (const match of texto.matchAll(CABECERA_COOKIE)) out.push(...piezasDeCookie(match[2]!));
  for (const match of texto.matchAll(CABECERA_CREDENCIAL)) out.push(...piezasDeAutorizacion(match[2]!));
  for (const match of texto.matchAll(CAMPO_JSON)) {
    if (!claveSensible(match[1]!)) continue;
    let valor = match[2]!;
    try { valor = JSON.parse(`"${valor}"`) as string; } catch {}
    out.push(...piezasDeCampo(match[1]!, valor));
  }
  out.push(...clavesValor(texto));
  for (const match of texto.matchAll(URL_CON_CLAVE)) {
    try { out.push(decodeURIComponent(match[1]!)); } catch { out.push(match[1]!); }
  }
  for (const match of texto.matchAll(INPUT)) {
    const tag = match[0];
    const nombre = /\b(?:name|id|property)\s*=\s*["']?([^"'\s>]+)/i.exec(tag)?.[1] ?? "";
    if (!claveSensible(nombre) && !/\btype\s*=\s*["']?password\b/i.test(tag)) continue;
    const valor = /\b(?:value|content)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    const encontrado = valor?.[1] ?? valor?.[2] ?? valor?.[3];
    if (encontrado) out.push(encontrado);
  }
  return out;
}

/**
 * «clave=valor» y «clave: valor» con clave sensible (un .env leído con la shell, un formulario, YAML). La
 * clave se toma entera desde su comienzo y sin retroceso, como en el redactor del informe: con [\w-]* delante
 * el patrón era cuadrático en una corrida larga de letras.
 */
function clavesValor(texto: string): string[] {
  const clave = /(?<![\w-])(?=([\w-]+))\1(?=[ \t]*[=:])/g;
  const valor = /([ \t]*[=:][ \t]*)("(?:\\.|[^"\\\n])*"|'[^'\n]*'|[^\s&;,<>"'}\[\]]+)/y;
  const out: string[] = [];
  for (let match: RegExpExecArray | null; (match = clave.exec(texto)); ) {
    const nombre = match[1]!;
    if (!claveSensible(nombre)) continue;
    valor.lastIndex = clave.lastIndex;
    const found = valor.exec(texto);
    if (!found) continue;
    clave.lastIndex = valor.lastIndex;
    let crudo = found[2]!;
    if (/^["']/.test(crudo)) crudo = crudo.slice(1, -1);
    out.push(...piezasDeCampo(nombre, crudo));
  }
  return out;
}
