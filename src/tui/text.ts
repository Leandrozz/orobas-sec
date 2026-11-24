import { FONDO_REFERENCIA, temaActivo } from "./temas.ts";
// Medición y ajuste de texto para la terminal: ancho por celda, estilos y envoltura.
const segmenter = new Intl.Segmenter("es", { granularity: "grapheme" });
const ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;

export const graphemes = (text: string): string[] => Array.from(segmenter.segment(text), (part) => part.segment);
/** Hiperenlace OSC 8 (clicable); en conhost y terminales "dumb", que no lo soportan, devuelve el texto plano. */
export const link = (url: string, text = url): string =>
  process.env.CYBER_CONSOLE === "conhost" || process.env.TERM === "dumb" ? text : `\x1b]8;;${url}\x1b\\${text}\x1b]8;;\x1b\\`;
/** Vuelve clicables las URL https que hay dentro de un texto. */
export const linkify = (text: string): string => text.replace(/https?:\/\/[^\s"')]*[^\s"')\.,;:!?]/g, (url) => link(url));
export const stripAnsi = (text: string): string => text.replace(ANSI, "");

// Marcas de ancho cero (SGR sin efecto) para reconstruir el texto al copiar: continuación de fila y glifos de la TUI.
export const CORTE_ESPACIO = "\x1b[28;29m";
export const CORTE_PEGADO = "\x1b[29;28m";
export const ADORNO_ABRE = "\x1b[28;28m";
export const ADORNO_CIERRA = "\x1b[29;29m";
export const adornoTUI = (s: string): string => (s ? ADORNO_ABRE + s + ADORNO_CIERRA : "");
export const sinMarcas = (fila: string): string => fila.replaceAll(CORTE_ESPACIO, "").replaceAll(CORTE_PEGADO, "").replaceAll(ADORNO_ABRE, "").replaceAll(ADORNO_CIERRA, "");

function wide(code: number): boolean {
  return (
    (code >= 0x1100 && code <= 0x115f) ||
    (code >= 0x2e80 && code <= 0xa4cf) ||
    (code >= 0xac00 && code <= 0xd7a3) ||
    (code >= 0xf900 && code <= 0xfaff) ||
    (code >= 0xfe30 && code <= 0xfe6f) ||
    (code >= 0xff00 && code <= 0xff60) ||
    (code >= 0xffe0 && code <= 0xffe6) ||
    (code >= 0x1f300 && code <= 0x1faff) ||
    (code >= 0x20000 && code <= 0x3fffd)
  );
}

/** Celdas que ocupa un grafema. */
export function cellWidth(grapheme: string): number {
  const code = grapheme.codePointAt(0)!;
  if (code < 0x20 || (code >= 0x7f && code < 0xa0)) return 0;
  if (/^\p{M}+$/u.test(grapheme) || code === 0x200b || code === 0x200d) return 0;
  // Un selector de presentación emoji (U+FE0F) vuelve ancho al símbolo, p. ej. ☀️.
  if (grapheme.includes("\uFE0F") || wide(code)) return 2;
  return 1;
}

export function visibleWidth(text: string): number {
  let width = 0;
  for (const grapheme of graphemes(stripAnsi(text))) width += cellWidth(grapheme);
  return width;
}

/** Corta una línea (con o sin estilos) a un ancho máximo y cierra los estilos abiertos. */
export function truncate(line: string, width: number): string {
  if (visibleWidth(line) <= width) return line;
  let out = "";
  let used = 0;
  let index = 0;
  let linked = false;
  const pattern = new RegExp(ANSI.source, "y");
  while (index < line.length) {
    pattern.lastIndex = index;
    const escape = pattern.exec(line);
    if (escape) {
      out += escape[0];
      const osc = /^\x1b\]8;[^;]*;(.*?)(?:\x07|\x1b\\)$/.exec(escape[0]);
      if (osc) linked = osc[1] !== "";
      index += escape[0].length;
      continue;
    }
    const grapheme = graphemes(line.slice(index, index + 16))[0]!;
    const cells = cellWidth(grapheme);
    if (used + cells > width - 1) break;
    out += grapheme;
    used += cells;
    index += grapheme.length;
  }
  return `${out}…${linked ? "\x1b]8;;\x1b\\" : ""}\x1b[0m`;
}

export type Style = (text: string) => string;
export interface Span {
  text: string;
  style?: Style;
}

/** Envuelve tramos con estilo por palabras; las palabras más anchas que la línea se parten. */
export function wrapSpans(spans: Span[], width: number, firstIndent = "", restIndent = firstIndent): string[] {
  const lines: string[] = [];
  let line = firstIndent;
  let used = visibleWidth(firstIndent);
  let pendingSpace = "";
  let empty = true;
  const breakLine = (corte: string) => {
    lines.push(line);
    line = corte + restIndent;
    used = visibleWidth(restIndent);
    pendingSpace = "";
    empty = true;
  };
  const pattern = new RegExp(ANSI.source, "y");
  for (const span of spans) {
    const paint = span.style ?? ((text: string) => text);
    for (const piece of span.text.split(/( +)/)) {
      if (!piece) continue;
      if (piece.trim() === "") {
        pendingSpace = piece;
        continue;
      }
      let word = piece;
      let cells = visibleWidth(word);
      if (!empty && used + pendingSpace.length + cells > width) breakLine(pendingSpace ? CORTE_ESPACIO : CORTE_PEGADO);
      if (!empty && pendingSpace) {
        line += pendingSpace;
        used += pendingSpace.length;
      }
      pendingSpace = "";
      while (cells > width - used && width - used > 0) {
        let head = "";
        let headCells = 0;
        let opener = ""; // enlace OSC 8 abierto en el corte: se cierra al final de la cabeza y se reabre en el resto
        for (let at = 0; at < word.length; ) {
          pattern.lastIndex = at;
          const escape = pattern.exec(word); // las secuencias son atómicas y de ancho cero
          if (escape) {
            const osc = /^\x1b\]8;[^;]*;(.*?)(?:\x07|\x1b\\)$/.exec(escape[0]);
            if (osc) opener = osc[1] !== "" ? escape[0] : "";
            head += escape[0];
            at += escape[0].length;
            continue;
          }
          const grapheme = graphemes(word.slice(at, at + 16))[0]!;
          if (headCells + cellWidth(grapheme) > width - used) break;
          head += grapheme;
          headCells += cellWidth(grapheme);
          at += grapheme.length;
        }
        if (!headCells) break;
        line += paint(opener ? `${head}\x1b]8;;\x1b\\` : head);
        word = opener + word.slice(head.length);
        cells -= headCells;
        breakLine(CORTE_PEGADO);
      }
      line += paint(word);
      used += cells;
      empty = false;
    }
  }
  lines.push(line);
  return lines;
}

/** Envuelve texto plano conservando sus saltos de línea. */
export function wrapText(text: string, width: number, indent = "", style?: Style): string[] {
  return text.split("\n").flatMap((line) => wrapSpans([{ text: line, style }], width, indent));
}

const color = !process.env.NO_COLOR;
const sgr = (open: () => string): Style => (text) => (color && text ? `\x1b[${open()}m${text}\x1b[0m` : text);
export const rgb = (hex: string): string => `${parseInt(hex.slice(1, 3), 16)};${parseInt(hex.slice(3, 5), 16)};${parseInt(hex.slice(5, 7), 16)}`;
const fg = (hex: string) => `38;2;${rgb(hex)}`;
const bg = (hex: string) => `48;2;${rgb(hex)}`;
export const accent = sgr(() => { const t = temaActivo(); return (t.acentoNegrita ? "1;" : "") + fg(t.acento); });
export const dim = sgr(() => fg(temaActivo().apagado));
export const warn = sgr(() => fg(temaActivo().aviso));
export const bold = sgr(() => "1");
// Adorno del tema (el ❦ de Filete); sin adorno no se usa.
export const adorno = sgr(() => fg(temaActivo().adorno?.color ?? temaActivo().acento));
// Aviso de una línea: negrita; en temas con avisoInverso, texto del color del fondo sobre el aviso.
export const avisoLinea = sgr(() => {
  const t = temaActivo();
  return t.avisoInverso ? `1;${fg(t.fondo ?? FONDO_REFERENCIA)};${bg(t.aviso)}` : `1;${fg(t.aviso)}`;
});
// Segmentos de la barra de estado: fondo de color, sin glifos de Nerd Font.
export const badge = sgr(() => { const [a, b] = temaActivo().insignia; return `1;${fg(a)};${bg(b)}`; });
export const badgeWarn = sgr(() => { const t = temaActivo(); return `1;${fg(t.fondo ?? FONDO_REFERENCIA)};${bg(t.aviso)}`; });
export const segment = sgr(() => { const [a, b] = temaActivo().segmento; return `${fg(a)};${bg(b)}`; });
export const segmentDim = sgr(() => { const [a, b] = temaActivo().segmentoApagado; return `${fg(a)};${bg(b)}`; });
export const italic = sgr(() => "3");
