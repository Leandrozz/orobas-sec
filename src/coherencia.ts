// Salida incoherente del modelo. Un modelo que se desarma (contexto largo, cuantización floja, plantilla
// de herramientas mal cerrada en el servidor de inferencia) devuelve nombres de herramienta con restos de
// su plantilla, el relleno «$MISSING» del parser, ráfagas de escrituras ajenas al idioma de la sesión,
// caracteres invisibles o bloques de dibujo. Nada de eso lo mandó el objetivo: es el proveedor. Si entra
// al historial, el modelo lo relee en el turno siguiente y sigue en ese patrón, así que se descarta entero
// y se reintenta. Visto el 19/11/2026 con GLM 5.3 a 110 k tokens de contexto: siete llamadas
// «http_request $MISSING</arg_value>» seguidas y dos respuestas largas hechas de pedazos de prompts ajenos.
// Las señales de las respuestas HTTP (señuelos, texto que le habla al agente) van en src/senuelos.ts y
// src/filtro-agentes.ts; acá se mira sólo lo que el modelo produjo.

/** Nombre de herramienta como lo define cualquier API de herramientas: identificador, sin espacios ni etiquetas. */
const TOOL_NAME = /^[A-Za-z_][\w.-]{0,127}$/;
/** Restos de plantillas de chat o de herramientas, y el relleno del parser cuando falta un argumento. */
const TEMPLATE = /\$MISSING|<\/?(?:tool_call|arg_key|arg_value|tool_response)>|<\|(?:im_start|im_end|observation|assistant|user|system|eot_id|start_header_id|tool_calls?_begin|tool_calls?_end)\|>/i;
/** Caracteres de ancho cero y controles bidireccionales, además del guion suave. */
const INVISIBLE = /[​-‏‪-‮⁠-⁤﻿­]/gu;
/** Elementos de bloque (█▄▀▓): no el dibujo de cajas, que se usa para tablas legítimas. */
const BLOCKS = /[▀-▟]/gu;
/** Escrituras que no son la de la sesión: una sola puede ser una cita del objetivo; dos o más, no. */
const SCRIPTS: Array<[string, RegExp]> = [
  ["han", /\p{Script=Han}/gu],
  ["cirílico", /\p{Script=Cyrillic}/gu],
  ["árabe", /\p{Script=Arabic}/gu],
  ["birmano", /\p{Script=Myanmar}/gu],
  ["tailandés", /\p{Script=Thai}/gu],
  ["devanagari", /\p{Script=Devanagari}/gu],
  ["hebreo", /\p{Script=Hebrew}/gu],
  ["griego", /\p{Script=Greek}/gu],
  ["hangul", /\p{Script=Hangul}/gu],
  ["japonés", /[\p{Script=Hiragana}\p{Script=Katakana}]/gu],
  ["georgiano", /\p{Script=Georgian}/gu],
  ["armenio", /\p{Script=Armenian}/gu],
  ["etíope", /\p{Script=Ethiopic}/gu],
  ["bengalí", /\p{Script=Bengali}/gu],
  ["tamil", /\p{Script=Tamil}/gu],
  ["jemer", /\p{Script=Khmer}/gu],
];
const LATIN = /\p{Script=Latin}/gu;

const count = (text: string, pattern: RegExp): number => text.match(pattern)?.length ?? 0;

export interface ReplyToScreen {
  content: string;
  toolCalls: Array<{ name: string; arguments: string }>;
}

/**
 * Por qué la respuesta del modelo parece incoherente; vacío si no lo parece. Las razones describen la
 * señal sin copiar el texto: lo que se descarta no tiene que volver a aparecer en la pantalla ni en el
 * historial por la vía del mensaje de error.
 */
export function readIncoherence(reply: ReplyToScreen): string[] {
  const reasons: string[] = [];
  const badNames = reply.toolCalls.filter((call) => !TOOL_NAME.test(call.name));
  if (badNames.length) reasons.push(`${badNames.length === 1 ? "una llamada a herramienta trae" : `${badNames.length} llamadas a herramienta traen`} restos de plantilla en el nombre`);
  if (reply.toolCalls.some((call) => /\$MISSING/.test(call.arguments))) reasons.push("argumentos con el relleno «$MISSING» del parser");
  const text = reply.content;
  if (TEMPLATE.test(text)) reasons.push("etiquetas de plantilla de chat en el texto");
  const invisible = count(text, INVISIBLE);
  if (invisible >= 8) reasons.push(`${invisible} caracteres invisibles`);
  const blocks = count(text, BLOCKS);
  if (blocks >= 20) reasons.push(`${blocks} caracteres de bloque`);
  const latin = count(text, LATIN);
  const foreign = SCRIPTS.map(([name, pattern]) => [name, count(text, pattern)] as const).filter(([, n]) => n >= 2);
  const foreignTotal = foreign.reduce((sum, [, n]) => sum + n, 0);
  // Texto en nuestra escritura con pedazos de dos o más ajenas: una cita del objetivo trae una sola.
  if (foreign.length >= 2 && latin >= foreignTotal) reasons.push(`mezcla de escrituras (${foreign.map(([name]) => name).join(", ")})`);
  return reasons;
}

/** Mensaje de error con el que se descarta la respuesta: lo ve el operador y queda en los eventos. */
export function incoherenceMessage(reasons: string[]): string {
  return `El modelo devolvió una respuesta incoherente (${reasons.join("; ")}): se descarta sin ejecutar nada y se reintenta`;
}

/**
 * Negativa de un modelo con barandas (los «estándar» del catálogo): una frase de rechazo al empezar,
 * una respuesta vacía que no se cortó por largo, o un texto corto que sólo explica por qué no lo hace.
 * La usa el router para reintentar ese paso con un modelo sin barandas y llevar la tasa por modelo; no
 * cambia el prompt para «evitar» negativas. Devuelve el motivo, o nada si la respuesta hizo lo pedido.
 */
const NEGATIVA = /^[\s"'«*_>#-]*(lo siento|lamento|perd[oó]n|disculp|no puedo|no voy a|no me es posible|no estoy en condiciones|no (es|ser[ií]a) (apropiado|[ée]tico|correcto)|i['’]?m sorry|i am sorry|sorry,|i can['’]?t|i cannot|i won['’]?t|i will not|i['’]?m (not able|unable)|as an ai|como (modelo|asistente|ia)\b)/i;
const DESVIO = /no (puedo|voy a|debo) (ayudar|asistir|colaborar|participar|proporcionar|dar|generar|escribir)|actividad(es)? (ilegal|maliciosa|da[ñn]ina)|hacking (no autorizado|malicioso)|contra (mis|las) (pol[ií]ticas|directrices|normas)|can['’]?t (help|assist) with|against (my|the) (policy|policies|guidelines)|not (able|allowed) to (help|assist)/i;

export function readRefusal(reply: ReplyToScreen & { stopReason: string }): string | undefined {
  if (reply.toolCalls.length || reply.stopReason === "length" || reply.stopReason === "error" || reply.stopReason === "aborted") return undefined;
  const text = reply.content.trim();
  if (!text) return "respuesta vacía";
  if (NEGATIVA.test(text.slice(0, 300))) return "negativa al empezar";
  if (text.length < 700 && DESVIO.test(text)) return "explica por qué no lo hace en vez de hacerlo";
  return undefined;
}
