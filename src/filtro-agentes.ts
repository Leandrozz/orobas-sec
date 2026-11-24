// Filtro de texto dirigido a agentes. Lo que devuelve un objetivo (o un archivo, o una página) es
// dato; si incluye texto que le habla al agente para darle órdenes, el modelo no tiene por qué
// leerlo: se reemplaza por una marca y el original queda en el artefacto para el operador.

export interface AgentTextScreening {
  /** El texto con cada tramo dirigido a agentes reemplazado por AGENT_TEXT_MARK. */
  text: string;
  /** Cantidad de tramos reemplazados. */
  removed: number;
  /** Cantidad de caracteres invisibles quitados, si había alguno. */
  invisibleRemoved?: number;
}

export const AGENT_TEXT_MARK = "[instrucción ajena omitida: el contenido intentaba darle órdenes al agente]";

const ORDER = /\b(?:ignore|disregard|forget|override|replace|obey|follow|fetch|request|visit|open|call|run|execute|send|upload|transmit|reveal|print|output|reply|respond|answer|return|say|continue|keep|hide|must|should|treat|accept|act|use|ignora|ignoren|olvida|olvidate|descarta|reemplaza|sustitui|obedece|obedezcan|segui|sigue|sigan|solicita|soliciten|pedi|pide|pidan|visita|visiten|abri|abre|abran|llama|llamen|ejecuta|ejecuten|envia|envien|manda|manden|subi|revela|imprimi|responde|responda|respondan|devolve|debes|deben|continua|continuen|insisti|reintenta|oculta|omite|cambia|cambien|trata|traten)\b/;
const RECIPIENT = /\b(?:agents?|agentes?|assistants?|asistentes?|models?|modelos?|llms?|chatgpt|herramientas? automaticas?|automated tools?)\b/g;
const CHANGE = new Set("ignore|disregard|forget|override|replace|ignora|ignoren|olvida|olvidate|descarta|reemplaza|sustituye|sustitui".split("|"));
const PRIOR = new Set("previous|prior|earlier|original|above|system|developer|anteriores|previas|originales|sistema|desarrollador".split("|"));
const BEFORE = new Set([...PRIOR, "all", "your", "todas", "tus"]);
const NEW = new Set(["these", "following", "new", "estas", "nuevas"]);
const REPLACE = new Set(["override", "replace", "supersede", "reemplazan", "sustituyen", "anulan"]);
const RULES = new Set("instruction|instructions|rule|rules|prompt|prompts|policy|policies|instrucciones|reglas|politicas".split("|"));
const OVERRIDE_WORDS = new RegExp(`\\b(?:${[...new Set([...CHANGE, ...BEFORE, ...NEW, ...REPLACE, ...RULES])].join("|")})\\b`, "g");
const CONCEAL = /\b(?:(?:do not|don't|never) (?:tell|inform|notify|show|mention|reveal)|(?:hide|conceal|withhold)|no (?:le |les )?(?:cuentes|digas|informes|avises|muestres|reveles)|(?:oculta|ocultale|esconde|escondele))\b.{0,96}\b(?:operator|user|operador|usuario)\b/;
const PERSIST = /\b(?:do not stop|don't stop|never stop|no te detengas|no se detengan|no pares|no paren|sin detenerte|sin parar)\b.{0,96}\b(?:until|hasta|requests|requesting|calling|urls?|peticiones|solicitudes|tarea)\b/;
const ENDLESS = /\b(?:keep (?:requesting|fetching|calling|retrying)|segui (?:pidiendo|solicitando|reintentando))\b.{0,120}\b(?:forever|indefinitely|sin limite|siempre|operator|operador|next url|proxima url)\b/;
const APPROVAL = /\b(?:operator|operador|developer|desarrollador) (?:has already |already |has |ya )?(?:approved|authorized|aprobado|aprobo|autorizado|autorizo)\b/;
const ROLE = /^(?:#{1,6} )?(?:\[(?:system|developer|operator)\]|(?:system|developer|operator|sistema|desarrollador|operador)(?: message| instructions?| override| prompt)?(?::|$)|(?:nuevo )?(?:mensaje|instrucciones) (?:del? )?(?:sistema|desarrollador|operador):|<\|im_start\|> ?(?:system|developer)|<\|start_header_id\|> ?(?:system|developer))/;
const SEND = /\b(?:send|upload|transmit|post|forward|email|envia|manda|subi|transmiti|reenvia)\b/;
const PRIVATE_DATA = /\b(?:conversation|transcript|system prompt|secrets|findings|session (?:data|tokens)|(?:all|collected|internal) (?:credentials|tokens)|historial|conversacion|secretos|hallazgos|datos de la sesion|(?:todas las|internas|recolectadas) credenciales)\b/;
const DESTINATION = /https?:\/\/|\b(?:external|another|third.party|externo|externa|otro destino|otra direccion)\b/;
const PROMPT_KEY = /^(?:system[_-]?prompt|developer[_-]?prompt|prompt[_-]?template|chatbot[_-]?prompt|prompt[_-]?sistema)$/i;
const RULE_WORD = /\b(?:instructions?|rules?|prompts?|polic(?:y|ies)|instrucciones|reglas|politicas)\b/;
const HUMAN = /\b(?:operator|operador|developer|desarrollador|user|usuario)\b/;
const STOP = /\b(?:stop|detengas|detengan|pares|paren|detenerte|parar|requesting|fetching|calling|retrying|pidiendo|solicitando|reintentando)\b/;
const SPACED = new RegExp(`\\b(?:${["ignor", "forge", "disre", "asist", "assist", "agen", "llm", "model", "syste", "devel", "donot", "send", "envia", "olvid", "ocul", "reemp", "repla", "keep", "nole"].map((word) => [...word].join("[ \\t\\r\\n]+")).join("|")})\\b`);
const ORDER_HINT = new RegExp(ORDER.source.slice(2, -2));
const TRIGGER_HINT = new RegExp(`${ORDER_HINT.source}|stop|tell|inform|notify|show|mention|conceal|withhold|cuentes|digas|informes|avises|muestres|reveles|ocultale|esconde|approved|authorized|aprobado|aprobo|autorizado|autorizo|detengas|detengan|pares|paren|detenerte|parar`, "i");
const ADDRESSEE_HINT = /agent|asistent|assistant|model|llm|chatgpt|herramienta|automated tool|instruction|instruccion|rule|regla|prompt|polic|system|sistema|developer|desarrollador|operator|operador/;
const BLOCK_TAG = "(?:html|head|body|p|div|section|article|header|footer|li|ul|ol|h[1-6]|br|hr|pre|script|style|title|system|developer|operator)";
const IS_BLOCK = new RegExp(`^${BLOCK_TAG}$`);

/** Este descarte barato evita ejecutar el clasificador por cada celda de una tabla enorme. */
function possible(value: string): boolean {
  return (ADDRESSEE_HINT.test(value) && ORDER_HINT.test(value))
    || (HUMAN.test(value) && /\b(?:tell|inform|notify|show|mention|reveal|hide|conceal|withhold|cuentes|digas|informes|avises|muestres|reveles|oculta|ocultale|esconde|escondele|approved|authorized|aprobado|aprobo|autorizado|autorizo)\b/.test(value))
    || STOP.test(value) || (PRIVATE_DATA.test(value) && SEND.test(value)) || SPACED.test(value);
}

/** Sólo se normaliza la copia de comparación: la evidencia conserva sus bytes. */
function normalize(text: string, spaces = true): string {
  let value = text;
  if (value.includes("\\u")) value = value.replace(/(?:\\u[\da-fA-F]{4})+/g, (run) => JSON.parse(`"${run}"`) as string);
  if (value.includes("&")) value = value.replace(/&(?:#(x[\da-f]{1,6}|\d{1,7})|(?:amp|lt|gt|quot|apos|nbsp));/gi, (entity: string, code?: string) => {
    if (!code) return ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'", "&nbsp;": " " } as Record<string, string>)[entity.toLowerCase()]!;
    const point = code[0]!.toLowerCase() === "x" ? parseInt(code.slice(1), 16) : parseInt(code, 10);
    return point <= 0x10ffff ? String.fromCodePoint(point) : entity;
  });
  if (/[^\x00-\x7f]/.test(value)) value = value.normalize("NFKD").replace(/[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, "");
  value = value.toLowerCase();
  // Vocabulario de HTTP que no es prosa (medido sobre 2.888 resultados reales: 40 falsos positivos):
  // la cabecera User-Agent no nombra a un agente, y una línea «POST https://…/secrets» no es una
  // orden de enviar secretos. La URL se conserva como destino, sin las palabras de su ruta.
  if (value.includes("user-agent")) value = value.replace(/\buser-agents?\b/g, "cabecera-ua");
  if (value.includes("://")) {
    value = value
      .replace(/\b(?:get|post|put|patch|delete|head|options)(\s+)(?=https?:\/\/)/g, (_all, gap: string) => " ".repeat(_all.length - gap.length) + gap)
      .replace(/(https?:\/\/)([^\s"'<>\\]*)/g, (_all, scheme: string, rest: string) => scheme + "x".repeat(rest.length));
  }
  return spaces ? value.replace(/\s{2,}|[^\S ]/g, " ").trim() : value;
}

function addressed(value: string, match: { index: number; 0: string }): boolean {
  const before = value.slice(Math.max(0, match.index - 90), match.index);
  // Una mención descriptiva («el modelo...») no alcanza para convertir documentación en una orden.
  const salutation = /(?:^|\b(?:for|to|dear|attention|attn|para|atencion|a los|a las|you are|you as|si sos|si eres) |[:,] )(?:(?:an?|un|una|all|todos|todas|los|las|automated|automaticos?|automaticas?|security|seguridad|ai|ia|language|large|lenguaje|autonomous|autonomos?) ){0,6}$/.test(before);
  const vocative = /^ *[:!,]/.test(value.slice(match.index + match[0].length));
  return salutation || vocative;
}

/** Guardar posiciones evita buscar «instrucciones» otra vez por cada «ignorá» de una entrada hostil larga. */
function overrides(value: string): boolean {
  let change = -Infinity, qualified = -Infinity, rule = -Infinity, ruleChange = -Infinity, fresh = -Infinity, freshRule = -Infinity;
  for (const match of value.matchAll(OVERRIDE_WORDS)) {
    const word = match[0], at = match.index;
    if (REPLACE.has(word) && at - freshRule <= 64) return true;
    if (CHANGE.has(word)) change = at;
    if (BEFORE.has(word)) {
      if (PRIOR.has(word) && at - rule <= 64 && Number.isFinite(ruleChange)) return true;
      if (at - change <= 112) qualified = change;
    }
    if (NEW.has(word)) fresh = at;
    if (RULES.has(word)) {
      if (at - qualified <= 176) return true;
      rule = at;
      ruleChange = at - change <= 112 ? change : -Infinity;
      if (at - fresh <= 40) freshRule = at;
    }
  }
  return false;
}

function hostile(value: string, config = false, directed = false): boolean {
  if (!value) return false;
  if ((RULE_WORD.test(value) && overrides(value)) || (HUMAN.test(value) && CONCEAL.test(value)) || (STOP.test(value) && (PERSIST.test(value) || ENDLESS.test(value)))) return true;
  const approval = APPROVAL.exec(value);
  if (approval) {
    const after = value.slice(approval.index + approval[0].length, approval.index + approval[0].length + 180);
    if (ORDER.test(after) || /\b(?:que|this action|everything|todo|scope|alcance|instructions|instrucciones)\b/.test(after)) return true;
  }
  if (SEND.test(value) && PRIVATE_DATA.test(value) && DESTINATION.test(value)) return true;
  if (config) return false;
  if ((directed || ROLE.test(value)) && ORDER.test(value)) return true;
  if (!ORDER.test(value)) return false;
  for (const recipient of value.matchAll(RECIPIENT)) {
    if (addressed(value, recipient) && ORDER.test(value.slice(recipient.index + recipient[0].length, recipient.index + recipient[0].length + 400))) return true;
  }
  return false;
}

function inspect(text: string, config = false, directed = false, knownSpaced?: boolean): { bad: boolean; heading: boolean } {
  const raw = normalize(text, false);
  const spaced = knownSpaced ?? SPACED.test(raw);
  // Un espacio une letras; dos o más conservan el límite de palabra.
  const joined = spaced ? raw.replace(/\b(?:[a-z][ \t])+[a-z]\b/g, (run) => run.replace(/\t/g, " ").split(" ").join("")) : raw;
  // Cada corrida de espacios se consume una vez, incluso si nunca aparece la puntuación esperada.
  const letters = spaced ? joined.replace(/ +/g, (spaces, at: number) => joined[at - 1] === ":" || joined[at - 1] === "/" || joined[at + spaces.length] === ":" || joined[at + spaces.length] === "/" ? "" : spaces) : joined;
  const value = letters.replace(/\s{2,}|[^\S ]/g, " ").trim();
  const heading = !config && ((value.endsWith(":") && [...value.matchAll(RECIPIENT)].some((match) => addressed(value, match))) || ROLE.test(value));
  if (!directed && !heading && !spaced && !possible(value)) return { bad: false, heading: false };
  let bad = hostile(value, config, directed);
  // Letras separadas incluso sin doble espacio entre palabras: sólo firmas inequívocas compactadas.
  if (!bad && spaced) {
    const compact = value.split(" ").join("");
    bad = /(?:ignore|disregard|forget)(?:all|the|your)?(?:previous|prior|system)(?:instructions|rules|prompt)|(?:ignora|olvida)(?:todaslas|las|tus)?(?:instrucciones|reglas)(?:anteriores|previas)|(?:aiassistant|aiagent|asistentedeia|agentedeia)(?:s|:|,)*(?:follow|fetch|visit|send|ignore|segui|visita|envia)|donotstop|donottelltheoperator|nolecuentesaloperador/.test(compact);
  }
  return { bad, heading };
}

interface Edit { start: number; end: number; replacement?: string }
interface JsonFrame { kind: string; name: string; key: string; message: boolean; role: string; pending: Edit[]; depth: number }

/**
 * Un valor que es a su vez JSON serializado (el cuerpo de una respuesta guardado dentro de un
 * artefacto) no es prosa: juntar palabras de campos distintos da falsos positivos. Se mira cada
 * cadena de adentro por separado; el valor entero se marca sólo si alguna lo amerita.
 */
function valueBad(value: string, config: boolean, depth = 0): boolean {
  const first = value.trimStart()[0];
  if (depth < 4 && (first === "{" || first === "[") && value.length <= 2 * 1024 * 1024) {
    let parsed: unknown;
    try { parsed = JSON.parse(value); } catch { return inspect(value, config).bad; }
    const pending: unknown[] = [parsed];
    for (let seen = 0; pending.length && seen < 200_000; seen++) {
      const item = pending.pop();
      if (typeof item === "string") { if (item.length > 8 && valueBad(item, config, depth + 1)) return true; }
      else if (Array.isArray(item)) pending.push(...item);
      else if (item && typeof item === "object") pending.push(...Object.values(item));
    }
    return false;
  }
  return inspect(value, config).bad;
}

/** ¿La línea es un trozo de JSON serializado? Tres pares «"clave":» o más, con o sin escape. */
function serializedLine(line: string): boolean {
  let pairs = 0;
  for (let at = line.indexOf('":'); at >= 0 && pairs < 3; at = line.indexOf('":', at + 2)) pairs++;
  return pairs >= 3;
}

/** Las cadenas de una línea serializada, una por una (cortando en comillas, escapadas o no). */
function serializedParts(line: string): string[] {
  return line.split(/\\*"/).filter((part) => part.length > 8 && !/^[\s:,{}\[\]]*$/.test(part));
}

/** El cursor consume también entradas malformadas; nunca vuelve a buscar un cierre desde cada apertura. */
function containerEnd(text: string, start: number): number {
  let depth = 0;
  let quoted = false;
  for (let i = start; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === "\\") i++;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === "{" || char === "[") depth++;
    else if ((char === "}" || char === "]") && --depth === 0) return i + 1;
  }
  return text.length;
}

function quoteEnd(text: string, start: number, limit: number): number {
  const quote = text[start];
  for (let i = start + 1; i < limit; i++) {
    if (text[i] === "\\") i++;
    else if (text[i] === quote) return i + 1;
  }
  return limit;
}

export function screenAgentText(text: string): AgentTextScreening {
  let invisibleRemoved = 0;
  // Los separadores de control pasan a espacio: borrarlos uniría palabras y escondería la orden.
  const clean = text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u{e0000}-\u{e007f}]/gu, (char) => {
    invisibleRemoved++;
    return /[\u000b\u000c\u001c-\u001f\u0085]/.test(char) ? " " : "";
  });
  const result = screenInstructions(clean);
  return invisibleRemoved ? { ...result, invisibleRemoved } : result;
}

function screenInstructions(text: string): AgentTextScreening {
  const normalized = normalize(text, false);
  if (!possible(normalized)) return { text, removed: 0 };
  const edits: Edit[] = [];
  const add = (start: number, end: number, replacement = AGENT_TEXT_MARK) => edits.push({ start, end, replacement });
  let heading: Edit | undefined;
  let role = false;
  const prose = (start: number, end: number) => {
    if (start === end || (!heading && !role && end - start < 4)) return;
    const part = text.slice(start, end);
    const entire = start === 0 && end === text.length;
    const comparison = entire ? normalized : normalize(part, false);
    if (!entire && !heading && !role && !part.trimEnd().endsWith(":") && !possible(comparison)) return;
    // En texto espaciado el punto de una URL también lleva espacios: la unidad segura es la línea.
    const spaced = SPACED.test(comparison);
    const boundary = spaced ? /[\r\n]/g : /[\r\n]|[.!?](?:<\/[\w-]{1,40}>){0,8}(?=\s|$)/g;
    let from = 0;
    const sentence = (to: number) => {
      const raw = part.slice(from, to);
      const offset = from;
      from = to;
      if (!heading && !role && raw.length < 7 && !/llm:/i.test(raw)) return;
      const clean = raw.trim();
      const left = start + offset + raw.length - raw.trimStart().length;
      const right = left + clean.length;
      if (!clean) { heading = undefined; return; }
      const reading = inspect(clean.replace(/<[^<>]{0,512}>/g, ""), false, role || !!heading, spaced || undefined);
      // Una línea que es un trozo de JSON serializado (muchos «clave: valor») no es una oración:
      // se marca sólo si alguna de sus cadenas, por separado, lo amerita.
      if (reading.bad && !reading.heading && !role && !heading && serializedLine(clean) && !serializedParts(clean).some((part) => inspect(part).bad)) return;
      if (reading.bad) {
        if (heading) { heading.replacement = AGENT_TEXT_MARK; heading = undefined; }
        add(left, right);
      } else {
        heading = reading.heading ? { start: left, end: right } : undefined;
        // Reservar la posición evita reordenar ediciones cuando hay atributos entre encabezado y orden.
        if (heading) edits.push(heading);
      }
    };
    for (const match of part.matchAll(boundary)) sentence(match.index + match[0].length);
    if (from < part.length) sentence(part.length);
  };
  const json = (start: number, end: number): boolean => {
    const raw = text.slice(start, end);
    if (!TRIGGER_HINT.test(raw) && !/[&]|\\u|[^\x00-\x7f]/.test(raw) && !SPACED.test(raw.toLowerCase())) return true;
    const editStart = edits.length;
    const stack: JsonFrame[] = [];
    // Se valida sin construir un árbol: una respuesta puede anidar miles de arrays.
    // 0 valor, 1 array vacío/valor, 2 coma/cierre array, 3 valor tras coma;
    // 4 objeto vacío/clave, 5 dos puntos, 6 valor del objeto, 7 coma/cierre objeto, 8 clave tras coma.
    const states: number[] = [];
    const scalar = /(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/y;
    let rootDone = false;
    const invalid = () => { edits.length = editStart; return false; };
    const consumed = (parent: JsonFrame | undefined) => {
      if (parent) { states[states.length - 1] = parent.kind === "[" ? 2 : 7; parent.key = ""; }
      else rootDone = true;
    };
    for (let i = start; i < end; i++) {
      const char = text[i]!;
      if (char === " " || char === "\t" || char === "\r" || char === "\n") continue;
      const parent = stack.at(-1);
      const state = states.at(-1) ?? (rootDone ? -1 : 0);
      const expectsValue = state === 0 || state === 1 || state === 3 || state === 6;
      if (char === "{" || char === "[") {
        if (!expectsValue) return invalid();
        // Arrays que sólo abren otro array comparten contexto. Un millón de niveles no requiere un millón de objetos.
        if (char === "[" && state === 1 && parent?.name !== "messages") { parent!.depth++; continue; }
        const frame = { kind: char, name: parent?.key ?? "", key: "", message: char === "{" && parent?.kind === "[" && parent.name === "messages", role: "", pending: [], depth: 1 };
        consumed(parent);
        stack.push(frame);
        states.push(char === "[" ? 1 : 4);
        continue;
      } else if (char === "}" || char === "]") {
        if (char === "}" ? state !== 4 && state !== 7 : state !== 1 && state !== 2) return invalid();
        if (char === "]" && parent!.depth > 1) {
          let closes = 1;
          while (closes < parent!.depth - 1 && text[i + closes] === "]") closes++;
          parent!.depth -= closes;
          states[states.length - 1] = 2;
          i += closes - 1;
          continue;
        }
        const frame = stack.pop()!;
        states.pop();
        // role puede venir después de content. Las posiciones reservadas conservan el orden original.
        if (!/^(?:system|developer)$/.test(frame.role)) for (const edit of frame.pending) edit.replacement = JSON.stringify(AGENT_TEXT_MARK);
        continue;
      }
      if (char === ":" && state === 5) { states[states.length - 1] = 6; continue; }
      if (char === "," && (state === 2 || state === 7)) { states[states.length - 1] = state === 2 ? 3 : 8; continue; }
      if (char !== '"') {
        if (!expectsValue) return invalid();
        scalar.lastIndex = i;
        const token = scalar.exec(text);
        if (!token || scalar.lastIndex > end) return invalid();
        consumed(parent);
        i = scalar.lastIndex - 1;
        continue;
      }
      if (!expectsValue && state !== 4 && state !== 8) return invalid();
      const until = quoteEnd(text, i, end);
      let value: string;
      try { value = JSON.parse(text.slice(i, until)) as string; } catch { return invalid(); }
      if ((state === 4 || state === 8) && parent) { parent.key = value; states[states.length - 1] = 5; }
      else {
        if (parent?.key === "role") parent.role = value;
        if (valueBad(value, PROMPT_KEY.test(parent?.key ?? ""))) {
          if (parent?.message && parent.key === "content" && !inspect(value, true).bad) {
            const edit = { start: i, end: until };
            edits.push(edit);
            parent.pending.push(edit);
          } else add(i, until, JSON.stringify(AGENT_TEXT_MARK));
        }
        consumed(parent);
      }
      i = until - 1;
    }
    if (!rootDone || stack.length) return invalid();
    heading = undefined;
    return true;
  };

  const trimmed = text.trim();
  if (trimmed.startsWith('"') && json(text.indexOf('"'), text.trimEnd().length)) {
    // Una cadena también es un documento JSON, aunque no tenga objeto contenedor.
  } else {
    const assignment = `\\b${PROMPT_KEY.source.slice(1, -1)}["']?\\s*[=:]\\s*["'\x60]`;
    const structure = new RegExp(`^\\[sistema\\]|${assignment}|<!--|<\\/?${BLOCK_TAG}\\b|<[a-z][\\w-]*\\s|[{\\[](?=\\s*["{\\[\\]}\\d\\-tfn])`, "gim");
    let start = 0;
    let invalidJsonUntil = 0;
    let match: RegExpExecArray | null;
    while ((match = structure.exec(text))) {
      const at = match.index;
      if (text.startsWith("[sistema]", at) && (at === 0 || /[\r\n]/.test(text[at - 1]!))) {
        prose(start, at);
        let end = at;
        while (end < text.length && text[end] !== "\r" && text[end] !== "\n") end++;
        start = structure.lastIndex = end;
        heading = undefined;
        continue;
      }
      if (text[at] !== "<" && text[at] !== "{" && text[at] !== "[") {
        prose(start, at);
        const quoteAt = at + match[0].length - 1;
        const delimiter = text[quoteAt]!;
        const triple = text.startsWith(delimiter.repeat(3), quoteAt);
        const valueAt = quoteAt + (triple ? 3 : 1);
        const close = triple ? text.indexOf(delimiter.repeat(3), valueAt) : quoteEnd(text, quoteAt, text.length) - 1;
        const until = close < 0 ? text.length : close;
        if (inspect(text.slice(valueAt, until), true).bad) add(valueAt, until);
        start = structure.lastIndex = Math.min(text.length, until + (triple ? 3 : 1));
        heading = undefined;
        continue;
      }
      if (text[at] === "{" || text[at] === "[") {
        if (at < invalidJsonUntil) continue;
        let next = at + 1;
        while (next < text.length && /\s/.test(text[next]!)) next++;
        if (!/["{\[\]}\d\-tfn]/.test(text[next] ?? "")) continue;
        const end = containerEnd(text, at);
        prose(start, at);
        if (json(at, end)) start = structure.lastIndex = end;
        else {
          // Puede ser código con claves sin comillas. Se recorre el interior sin volver a intentar JSON.
          invalidJsonUntil = end;
          start = at;
          structure.lastIndex = at + 1;
        }
        continue;
      }
      if (text.startsWith("<!--", at)) {
        prose(start, at);
        const close = text.indexOf("-->", at + 4);
        const end = close < 0 ? text.length : close;
        prose(at + 4, end);
        start = structure.lastIndex = close < 0 ? end : end + 3;
        continue;
      }
      const name = /^<\/?([a-z][\w-]*)\b/i.exec(text.slice(at, at + 80))?.[1]?.toLowerCase();
      if (!name) continue;
      let end = at + 1;
      let quote = "";
      for (; end < text.length; end++) {
        const char = text[end]!;
        if (quote) { if (char === quote) quote = ""; }
        else if (char === '"' || char === "'") quote = char;
        else if (char === ">") break;
      }
      if (end === text.length) { structure.lastIndex = end; break; }
      end++;
      const tag = text.slice(at, end);
      const attrs: Edit[] = [];
      for (const attr of tag.matchAll(/\b(?:alt|title|aria-label)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
        const value = attr[1] ?? attr[2] ?? attr[3]!;
        if (!inspect(value).bad) continue;
        const offset = attr.index + attr[0].indexOf("=") + 1;
        const leading = /^\s*/.exec(tag.slice(offset))![0].length;
        const quoted = tag[offset + leading] === '"' || tag[offset + leading] === "'";
        const left = at + offset + leading + (quoted ? 1 : 0);
        attrs.push({ start: left, end: left + value.length, replacement: quoted ? AGENT_TEXT_MARK : JSON.stringify(AGENT_TEXT_MARK) });
      }
      // Los tags de bloque separan evidencia; los de énfasis no cortan una orden por la mitad.
      const block = IS_BLOCK.test(name);
      if (block || attrs.length) {
        prose(start, at);
        for (const attr of attrs) edits.push(attr);
        start = end;
        if (/^(?:system|developer|operator)$/.test(name)) role = text[at + 1] !== "/";
      }
      structure.lastIndex = end;
    }
    prose(start, text.length);
  }
  if (!edits.length) return { text, removed: 0 };
  const parts: string[] = [];
  let from = 0;
  let removed = 0;
  for (const edit of edits) {
    if (edit.replacement === undefined) continue;
    parts.push(text.slice(from, edit.start), edit.replacement);
    from = edit.end;
    removed++;
  }
  if (!removed) return { text, removed: 0 };
  parts.push(text.slice(from));
  return { text: parts.join(""), removed };
}
