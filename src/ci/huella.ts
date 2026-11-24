// Huella estable de un hallazgo entre corridas y entre entornos. El agente escribe el título y la clase con sus
// palabras, que cambian de una corrida a otra, y el id es nuevo cada vez: la huella no depende de ninguno de los
// dos. Sale de cuatro cosas que se repiten si la falla es la misma:
//   · el destino: el nombre de la regla del alcance que cubre el activo (o la regla tal como está escrita en el
//     archivo, con sus variables sin expandir), así un entorno efímero por PR no cambia la huella;
//   · la clase canónica (control de acceso, XSS, inyección SQL…), por palabras clave sobre la clase y el título;
//   · el método HTTP de la evidencia;
//   · la ruta normalizada (ids, uuids y tokens como marcadores) y los nombres de los parámetros de consulta.
import { createHash } from "node:crypto";
import { decide, type Scope, type ScopeRule } from "../scope.ts";

export const VERSION_HUELLA = "v1";

export interface Clase {
  id: string;
  nombre: string;
  cwe?: number;
}

/** Del más específico al más general: el primero que coincide gana. */
const CLASES: Array<{ id: string; nombre: string; cwe?: number; patron: RegExp }> = [
  { id: "asignacion-masiva", nombre: "Asignación masiva", cwe: 915, patron: /asignaci[oó]n masiva|mass[- ]assign/ },
  { id: "xss", nombre: "Cross-site scripting (XSS)", cwe: 79, patron: /\bxss\b|cross[- ]?site scripting/ },
  { id: "inyeccion-sql", nombre: "Inyección SQL", cwe: 89, patron: /\bsqli\b|inyecci[oó]n sql|sql injection|\bsql\b/ },
  { id: "ssti", nombre: "Inyección de plantillas (SSTI)", cwe: 1336, patron: /\bssti\b|template injection|inyecci[oó]n de plantilla/ },
  { id: "inyeccion-comandos", nombre: "Inyección de comandos", cwe: 78, patron: /inyecci[oó]n de comandos|command injection|\brce\b|ejecuci[oó]n remota|remote code/ },
  { id: "xxe", nombre: "Entidades externas XML (XXE)", cwe: 611, patron: /\bxxe\b|entidad(es)? externa|external entit/ },
  { id: "ssrf", nombre: "Falsificación de peticiones del servidor (SSRF)", cwe: 918, patron: /\bssrf\b|server[- ]side request/ },
  { id: "csrf", nombre: "Falsificación de peticiones (CSRF)", cwe: 352, patron: /\bcsrf\b|xsrf|cross[- ]site request/ },
  { id: "redireccion-abierta", nombre: "Redirección abierta", cwe: 601, patron: /redirecci[oó]n abierta|open redirect|redirect/ },
  { id: "recorrido-de-ruta", nombre: "Recorrido de ruta", cwe: 22, patron: /traversal|recorrido de ruta|\blfi\b|inclusi[oó]n de archivo/ },
  { id: "deserializacion", nombre: "Deserialización insegura", cwe: 502, patron: /deserializ/ },
  { id: "subida-de-archivos", nombre: "Subida de archivos", cwe: 434, patron: /subida de archivo|\bupload\b/ },
  { id: "control-de-acceso", nombre: "Control de acceso", cwe: 284, patron: /control de acceso|\bidor\b|\bbola\b|\bbfla\b|autorizaci[oó]n|authori[sz]ation|access control|permis|privileg|escalad|escalation/ },
  { id: "autenticacion", nombre: "Autenticación", cwe: 287, patron: /autenticaci|authenticat|\blogin\b|credencial|credential|contrase[nñ]a|password|\bjwt\b|sesi[oó]n|session|fuerza bruta|brute/ },
  { id: "logica-de-negocio", nombre: "Lógica de negocio", cwe: 840, patron: /l[oó]gica de negocio|business logic|precio|price|monto|amount|carrera|race condition/ },
  { id: "inyeccion", nombre: "Inyección", cwe: 74, patron: /inyecci[oó]n|injection/ },
  { id: "criptografia", nombre: "Criptografía", cwe: 327, patron: /criptogr|crypto|cifrado|encrypt|hash d[eé]bil|weak hash/ },
  { id: "exposicion-de-datos", nombre: "Exposición de datos", cwe: 200, patron: /exposici[oó]n|exposure|filtraci[oó]n|leak|divulgaci[oó]n|disclosure|datos sensibles|sensitive data|secreto expuesto/ },
  { id: "configuracion", nombre: "Configuración insegura", cwe: 16, patron: /configuraci[oó]n|misconfig|\bdebug\b|cabecera|header|\bcors\b|listado de directorio|directory listing/ },
];

const plano = (texto: string) => texto.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
const slug = (texto: string) => plano(texto).replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "otra";

/** La clase canónica de un hallazgo: primero por su clase, si no dice nada conocido, por su título. */
export function claseCanonica(kind: string, title: string): Clase {
  const buscar = (texto: string) => CLASES.find((c) => c.patron.test(plano(texto)) || c.patron.test(texto.toLowerCase()));
  // La clase manda; si dice algo genérico («inyección») o nada conocido, el título precisa («XSS reflejado»).
  const porClase = buscar(kind);
  const clase = porClase && porClase.id !== "inyeccion" ? porClase : buscar(`${kind} ${title}`) ?? porClase;
  return clase ? { id: clase.id, nombre: clase.nombre, ...(clase.cwe ? { cwe: clase.cwe } : {}) } : { id: slug(kind), nombre: kind.trim() || "Otra" };
}

/** Las clases conocidas, para las reglas del SARIF. */
export const clasesConocidas = (): Clase[] => CLASES.map(({ id, nombre, cwe }) => ({ id, nombre, ...(cwe ? { cwe } : {}) }));

/**
 * Un segmento de ruta que es un identificador (número, uuid, hexadecimal, correo, fecha o token opaco) queda como
 * «{id}», sea cual sea: así «/usuarios/2» y «/usuarios/{id}» (como lo escriba el agente esa vez) dan la misma huella.
 */
function segmento(texto: string): string {
  let s = texto;
  try { s = decodeURIComponent(texto); } catch { /* queda como vino */ }
  s = s.toLowerCase();
  if (/^\d+$/.test(s)) return "{id}";
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) return "{id}";
  if (/^[0-9a-f]{16,}$/.test(s)) return "{id}";
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/.test(s)) return "{id}";
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return "{id}";
  if (/^[{:<\[][a-z_][\w-]*[}>\]]?$/.test(s)) return "{id}";
  // Un token o un id opaco: largo, con letras y dígitos, y no un texto con palabras separadas por guiones.
  if (s.length >= 20 && /\d/.test(s) && /[a-z]/.test(s) && (s.match(/[-_.]/g)?.length ?? 0) <= 2) return "{id}";
  return s;
}

/** Ruta normalizada y nombres de los parámetros de consulta de una URL (o de una ruta suelta). */
export function normalizarRuta(objetivo: string): { ruta: string; consulta: string[] } {
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(objetivo) ? objetivo : `http://x${objetivo.startsWith("/") ? "" : "/"}${objetivo}`);
  } catch {
    return { ruta: objetivo.trim().toLowerCase(), consulta: [] };
  }
  const partes = url.pathname.split("/").filter(Boolean).map((p) => segmento(p.split(";")[0]!));
  return { ruta: `/${partes.join("/")}`, consulta: [...new Set([...url.searchParams.keys()].map((k) => k.toLowerCase()))].sort() };
}

/** Lo mínimo de una regla expandida que necesita la huella: cómo se llama el destino y qué reglas del harness lo forman. */
export interface DestinoHuella {
  clave: string;
  reglas: ScopeRule[];
}

/** El destino (nombre o regla del archivo) que cubre un activo; «?» si ninguno. */
export function destinoDe(destinos: DestinoHuella[], objetivo: string): string {
  for (const destino of destinos) {
    const scope: Scope = { rev: 0, source: "ci", include: destino.reglas, exclude: [], notes: "", at: "" };
    try {
      if (decide(scope, objetivo).allowed) return destino.clave;
    } catch { /* destino ilegible: sigue */ }
  }
  return "?";
}

export interface DatosHuella {
  destino: string;
  clase: string;
  metodo: string;
  ruta: string;
  consulta: string[];
}

export function huella(datos: DatosHuella): string {
  const texto = [VERSION_HUELLA, datos.destino, datos.clase, datos.metodo.toUpperCase(), datos.ruta, datos.consulta.join(",")].join("|");
  return `orobas:${VERSION_HUELLA}:${createHash("sha256").update(texto).digest("hex").slice(0, 24)}`;
}
