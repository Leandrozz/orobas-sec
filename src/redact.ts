import { tokenConPrefijo } from "./formatos-credencial.ts";

// Una credencial puede reaparecer fuera de su campo: primero se aprende, después se redacta.
const HIDDEN = "[credencial omitida]";
const sensitive = (key: string) => /password|passwd|passphrase|secret|token|cookie|authorization|credential|signature|api[-_]?key|access[-_]?key|private[-_]?key|session|csrf|xsrf|^(?:pwd|clave|jwt|auth|key)$/i.test(key);
const sensitiveQuery = (key: string) => sensitive(key) || /^code$/i.test(key);
/** Palabras que hacen sensible a la clave de un «clave=valor» en texto libre. */
const SENSITIVE_KEY = /password|passwd|secret|token|api[-_]?key|session|csrf|xsrf|credential|private[-_]?key/i;
const marker = (value: string) => /^(?:<identidad [^>]+>|\[credencial omitida\])$/.test(value);

/** Aplica `change` sólo a text[0, end): lo que sigue no puede formar parte de una coincidencia. */
const upTo = (text: string, end: number, change: (head: string) => string) => (end > 0 ? change(text.slice(0, end)) + text.slice(end) : text);

const SCHEME = /[a-z0-9+.-]/i;
const WORD = /\w/;
const LETTER = /[a-z]/i;
const URL_END = /[\s<>'"`]/;

/**
 * Lo mismo que text.replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s<>'"`]+/gi, replace), en tiempo lineal: el patrón
 * probaba cada límite de palabra de una corrida larga con puntos o guiones (a-b-c-…) hasta su final, y una sola
 * respuesta así (puesta por el objetivo) trababa el informe. Se parte de cada «://» y se busca el esquema hacia atrás.
 */
function replaceUrls(text: string, replace: (url: string) => string): string {
  const parts: string[] = [];
  let copied = 0;
  for (let from = 0, at: number; (at = text.indexOf("://", from)) >= 0; ) {
    from = at + 1;
    if (at + 3 >= text.length || URL_END.test(text[at + 3]!)) continue;
    let start = at;
    while (start > copied && SCHEME.test(text[start - 1]!)) start--;
    // El primer comienzo posible del esquema: una letra en un límite de palabra.
    while (start < at && !(LETTER.test(text[start]!) && (start === 0 || !WORD.test(text[start - 1]!)))) start++;
    if (start === at) continue;
    let end = at + 3;
    while (end < text.length && !URL_END.test(text[end]!)) end++;
    parts.push(text.slice(copied, start), replace(text.slice(start, end)));
    copied = from = end;
  }
  return copied ? parts.join("") + text.slice(copied) : text;
}

const HEADER_NAMES = "(?:Cookie|Set-Cookie|Authorization|Proxy-Authorization|X-Api-Key)";
const HEADER_LINE = new RegExp(`^([^\\S\\r\\n]*${HEADER_NAMES}\\s*):\\s*(.+)$`, "gim");
const HEADER_INLINE = new RegExp(`\\b(${HEADER_NAMES})[ \\t]*:[ \\t]*([^\\n]+)`, "gi");

export class ReportRedactor {
  private readonly pantalla: boolean;
  constructor(opciones: { pantalla?: boolean } = {}) { this.pantalla = !!opciones.pantalla; }
  private readonly secrets = new Set<string>();

  /** Permite invalidar vistas ya tachadas cuando se aprende otra credencial. */
  get cantidadConocida(): number { return this.secrets.size; }

  /**
   * Un valor demasiado corto o sin letras ni dígitos (`{`, `#`, `|`, `ok`) no es una credencial, y taparlo
   * en todo el informe rompe el texto: en las trayectorias dejaba el JSON ilegible y la exportación fallaba.
   */
  private learnable(value: string): boolean {
    return this.pantalla ? !!value.trim() : value.length >= 6 && /[a-z0-9]/i.test(value);
  }

  private remember(value: unknown): void {
    if (this.pantalla && typeof value === "number") value = String(value);
    if (typeof value === "string" && value && !marker(value) && this.learnable(value)) {
      const variants = new Set([value]);
      try { variants.add(decodeURIComponent(value.replace(/\+/g, " "))); } catch {}
      for (const variant of variants) {
        if (marker(variant) || !this.learnable(variant)) continue;
        this.secrets.add(variant);
        try { this.secrets.add(encodeURIComponent(variant)); } catch {}
        this.secrets.add(JSON.stringify(variant).slice(1, -1));
      }
    } else if (Array.isArray(value)) value.forEach((item) => this.remember(item));
    else if (value && typeof value === "object") Object.values(value).forEach((item) => this.remember(item));
  }

  private fields(value: unknown): unknown {
    if (Array.isArray(value)) return value.map((item) => this.fields(item));
    if (typeof value === "string" && /^[\s]*[\[{]/.test(value)) return this.text(value);
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(Object.entries(value).map(([key, item]) => {
      if (!sensitive(key)) return [key, this.fields(item)];
      if (this.pantalla && typeof item === "string") this.headers({ [key]: item });
      else this.remember(item);
      return [key, typeof item === "string" && marker(item) ? item : HIDDEN];
    }));
  }

  url(text: string): string {
    try {
      const url = new URL(text);
      if (url.username || url.password) {
        for (const value of [url.username, url.password]) {
          this.remember(value);
          try { this.remember(decodeURIComponent(value)); } catch {}
        }
        url.username = "";
        url.password = "";
      }
      for (const [key, value] of [...url.searchParams]) if (sensitiveQuery(key)) {
        this.remember(value);
        url.searchParams.set(key, HIDDEN);
      }
      if (url.hash) {
        this.remember(url.hash.slice(1));
        url.hash = "";
      }
      return url.toString();
    } catch {
      return this.text(text);
    }
  }

  headers(headers: Record<string, string>): Record<string, string> {
    return Object.fromEntries(Object.entries(headers).map(([key, value]) => {
      if (!sensitive(key)) return [key, this.text(value)];
      if (marker(value)) return [key, value];
      this.remember(value);
      if (/cookie/i.test(key)) for (const cookie of value.split(/[;,]/)) {
        const at = cookie.indexOf("=");
        if (at >= 0 && !/^(?:path|domain|expires|max-age|samesite)\s*=/i.test(cookie.trim())) this.remember(cookie.slice(at + 1).trim());
      }
      if (/authorization/i.test(key)) this.remember(value.replace(/^\S+\s+/, ""));
      return [key, HIDDEN];
    }));
  }

  text(text: string): string {
    let result = text.replace(/\bbb_[A-Za-z0-9_-]+\b/g, HIDDEN);
    try {
      result = JSON.stringify(this.fields(JSON.parse(result)), null, 2);
    } catch {}
    const urls: string[] = [];
    result = replaceUrls(result, (value) => {
      try {
        const url = new URL(value);
        const cleaned = url.username || url.password || url.hash || [...url.searchParams.keys()].some(sensitiveQuery) ? this.url(value) : value;
        return `\u0000url${urls.push(cleaned) - 1}\u0000`;
      } catch { return value; }
    });
    result = result.replace(/("(?:\\.|[^"\\])*"\s*:\s*)("(?:\\.|[^"\\])*")/g, (all, prefix: string, value: string) => {
      const key = prefix.slice(0, prefix.lastIndexOf(":")).trim().slice(1, -1);
      if (!sensitive(key)) return all;
      let decoded = value.slice(1, -1);
      try { decoded = JSON.parse(value) as string; } catch {}
      if (this.pantalla) this.headers({ [key]: decoded });
      else this.remember(decoded);
      return `${prefix}${JSON.stringify(marker(decoded) ? decoded : HIDDEN)}`;
    });
    // Sólo hasta el último «>»: un <input sin cierre después recorría el resto del texto por cada aparición.
    result = upTo(result, result.lastIndexOf(">") + 1, (head) => head.replace(/<(input|meta)\b[^>]*>/gi, (tag) => {
      const names = [...tag.matchAll(/\b(?:name|type)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)].map((match) => match[1] ?? match[2] ?? match[3]!);
      if (!names.some(sensitive)) return tag;
      return tag.replace(/(\b(?:value|content)\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi, (_all: string, prefix: string, double: string, single: string, bare: string) => {
        const value = double ?? single ?? bare;
        this.remember(value);
        return `${prefix}"${HIDDEN}"`;
      });
    }));
    result = result.replace(/(Content-Disposition:[^\r\n]*\bname="([^"]+)"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)([\s\S]*?)(?=\r?\n--|$)/gi, (all, prefix: string, key: string, value: string) => {
      if (!sensitive(key)) return all;
      this.remember(value);
      return `${prefix}${HIDDEN}`;
    });
    // Espacio horizontal al comienzo de la línea: con \s* cada línea vacía recorría todas las vacías siguientes.
    result = result.replace(this.pantalla ? HEADER_INLINE : HEADER_LINE, (_all, key: string, value: string) => `${key}: ${this.headers({ [key.trim()]: value })[key.trim()]}`);
    result = result.replace(/<([\w:-]+)>([^<>]+)<\/\1>/g, (all, key: string, value: string) => {
      if (!sensitive(key)) return all;
      this.remember(value);
      return `<${key}>${HIDDEN}</${key}>`;
    });
    // Los cuerpos de formularios, cabeceras crudas y textos del hallazgo también pueden contener secretos.
    result = result.replace(/\b(Bearer|Basic)\s+([A-Za-z0-9_.~+/=-]+)/gi, (_all, scheme: string, value: string) => {
      this.remember(value);
      return `${scheme} ${HIDDEN}`;
    });
    result = this.keyValues(result);
    // Sólo hasta el último END: un BEGIN sin cierre después recorría el resto del texto por cada aparición.
    const ends = [...result.matchAll(/-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g)].at(-1);
    result = upTo(result, ends ? ends.index + ends[0].length : 0, (head) => head.replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, (value) => {
      this.remember(value);
      return HIDDEN;
    }));
    const ocultarToken = (value: string) => {
      this.remember(value);
      return HIDDEN;
    };
    result = result.replace(/\u0000url(\d+)\u0000/g, (_all, index: string) => urls[Number(index)]!);
    return result.replace(tokenConPrefijo, ocultarToken).replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g, ocultarToken);
  }

  /**
   * «clave=valor» con una clave sensible (password, token, session…, o que termine en pwd o clave). La clave se toma
   * entera desde su comienzo y sin retroceso: el patrón anterior, con [\w-]* delante, era cuadrático en una corrida
   * larga de letras (JS minificado, base64url) y congelaba el informe minutos con una sola respuesta grande.
   */
  private keyValues(text: string): string {
    const key = /(?<![\w-])(?=([\w-]+))\1(?=\s*[=:])/g;
    const value = /(\s*[=:]\s*)("(?:\\.|[^"\\])*"|'[^']*'|[^\s&;,<>"'}\[\]]+)/y;
    const parts: string[] = [];
    let copied = 0;
    for (let match: RegExpExecArray | null; (match = key.exec(text)); ) {
      const name = match[1]!;
      if (!SENSITIVE_KEY.test(name) && !/(?:pwd|clave)$/i.test(name) && !(this.pantalla && sensitive(name))) continue;
      value.lastIndex = key.lastIndex;
      const found = value.exec(text);
      if (!found) continue;
      this.remember(found[2]!.replace(/^["']|["']$/g, ""));
      parts.push(text.slice(copied, key.lastIndex), found[1]!, HIDDEN);
      copied = key.lastIndex = value.lastIndex;
    }
    return copied ? parts.join("") + text.slice(copied) : text;
  }

  /**
   * Redacción final del informe: el texto entero otra vez y después cada secreto aprendido, en una sola pasada.
   * Antes era un split/join por secreto sobre todo el informe (secretos × tamaño): con miles de cookies aprendidas,
   * minutos. Ahora se indexan por sus primeros cuatro caracteres y cada tramo tapado por uno o más secretos que se
   * pisan sale como un único marcador.
   */
  finish(text: string): string {
    let result = this.text(text);
    const byHead = new Map<string, string[]>();
    const short: string[] = [];
    for (const secret of this.secrets) {
      if (!secret) continue;
      if (secret.length < 4) short.push(secret);
      else {
        const head = secret.slice(0, 4);
        const list = byHead.get(head);
        if (list) list.push(secret);
        else byHead.set(head, [secret]);
      }
    }
    if (byHead.size) {
      for (const list of byHead.values()) list.sort((a, b) => b.length - a.length);
      // Tramos tapados [desde, hasta): un secreto que empieza dentro de un tramo (o justo al final) lo alarga.
      const spans: Array<[number, number]> = [];
      for (let at = 0; at + 4 <= result.length; at++) {
        const secret = byHead.get(result.slice(at, at + 4))?.find((candidate) => result.startsWith(candidate, at));
        if (!secret) continue;
        const last = spans.at(-1);
        if (last && at <= last[1]) last[1] = Math.max(last[1], at + secret.length);
        else spans.push([at, at + secret.length]);
      }
      if (spans.length) {
        const parts: string[] = [];
        let copied = 0;
        for (const [from, to] of spans) {
          parts.push(result.slice(copied, from), HIDDEN);
          copied = to;
        }
        parts.push(result.slice(copied));
        result = parts.join("");
      }
    }
    if (short.length) {
      const alternatives = short.sort((a, b) => b.length - a.length).map((secret) => secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      result = result.replace(new RegExp(`(?<![\\w])(?:${alternatives.join("|")})(?![\\w])`, "g"), HIDDEN);
    }
    return result;
  }
}
