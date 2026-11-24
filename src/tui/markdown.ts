// Markdown línea por línea, para poder mostrar la respuesta a medida que llega.
import { accent, adornoTUI, bold, dim, italic, type Span, type Style, truncate, visibleWidth, wrapSpans } from "./text.ts";

/** Énfasis, código y enlaces dentro de una línea. `base` se aplica a todo el tramo. */
export function inline(text: string, base?: Style): Span[] {
  const spans: Span[] = [];
  const over = (style: Style): Style => (base ? (value) => base(style(value)) : style);
  // El código va primero: un asterisco dentro de `código` no abre ni cierra énfasis.
  const pattern = /`([^`]+)`|\*\*(?=\S)((?:`[^`]*`|[^`])+?)(?<=\S)\*\*|(?<![\p{L}\p{N}*])\*(?=\S)([^*`]+?)(?<=\S)\*(?![\p{L}\p{N}])|\[([^\]]+)\]\(([^)\s]+)\)/gu;
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    if (match.index > last) spans.push({ text: text.slice(last, match.index), style: base });
    if (match[1] !== undefined) spans.push({ text: match[1], style: over(accent) });
    else if (match[2] !== undefined) spans.push(...inline(match[2], over(bold)));
    else if (match[3] !== undefined) spans.push({ text: match[3], style: over(italic) });
    else spans.push({ text: match[4]!, style: over(accent) }, { text: ` (${match[5]})`, style: dim });
    last = match.index + match[0].length;
  }
  if (last < text.length) spans.push({ text: text.slice(last), style: base });
  return spans;
}

const styled = (spans: Span[]) => spans.map((span) => (span.style ? span.style(span.text) : span.text)).join("");
const isTableRow = (source: string) => /^\s*\|.*\|\s*$/.test(source);

/** Tabla alineada por columnas; si no entra, se achican las columnas más anchas. */
function renderTable(rows: string[], width: number, indent: string): string[] {
  const cells = rows
    .map((row) => row.trim().slice(1, -1).split("|").map((cell) => cell.trim()))
    .filter((row) => !row.every((cell) => /^:?-+:?$/.test(cell)));
  if (!cells.length) return [];
  const columns = Math.max(...cells.map((row) => row.length));
  const text = (row: string[], column: number, head: boolean) => styled(inline(row[column] ?? "", head ? bold : undefined));
  const widths = Array.from({ length: columns }, (_, column) => Math.max(...cells.map((row) => visibleWidth(text(row, column, false)))));
  const room = width - visibleWidth(indent) - 2 * (columns - 1);
  while (widths.reduce((sum, value) => sum + value, 0) > room && Math.max(...widths) > 4) {
    widths[widths.indexOf(Math.max(...widths))]!--;
  }
  const line = (row: string[], head: boolean) =>
    indent +
    widths
      .map((size, column) => {
        const cell = truncate(text(row, column, head), size);
        return cell + " ".repeat(Math.max(0, size - visibleWidth(cell)));
      })
      .join("  ")
      .trimEnd();
  const out = [line(cells[0]!, true), indent + dim(widths.map((size) => "─".repeat(size)).join("  "))];
  for (const row of cells.slice(1)) out.push(line(row, false));
  return out;
}

export class MarkdownStream {
  private fenced = false;
  private table: string[] = [];

  /** Cierra lo que quedó acumulado (una tabla) al terminar el mensaje. */
  flush(width: number, indent = "  "): string[] {
    return renderTable(this.table.splice(0), width, indent);
  }

  /** Convierte una línea de origen en filas de terminal ya envueltas y con sangría. */
  line(source: string, width: number, indent = "  "): string[] {
    // Las filas de una tabla se acumulan para poder alinear las columnas.
    if (!this.fenced && isTableRow(source)) {
      this.table.push(source);
      return [];
    }
    return [...this.flush(width, indent), ...this.block(source, width, indent)];
  }

  private block(source: string, width: number, indent: string): string[] {
    if (/^\s*```/.test(source)) {
      this.fenced = !this.fenced;
      return [];
    }
    if (this.fenced) return [truncate(`${indent}${adornoTUI(`${dim("│")} `)}${source}`, width)];
    const heading = /^(#{1,6})\s+(.*)$/.exec(source);
    if (heading) return wrapSpans([{ text: heading[2]!.replace(/\*\*/g, ""), style: bold }], width, indent);
    if (/^\s*([-*_])\s*(\1\s*){2,}$/.test(source)) return [indent + dim("─".repeat(Math.max(3, Math.min(40, width - indent.length))))];
    const item = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(source);
    if (item) {
      const marker = /\d/.test(item[2]!) ? item[2]! : "·";
      const lead = indent + item[1];
      return wrapSpans(inline(item[3]!), width, `${lead}${accent(marker)} `, `${lead}${" ".repeat(marker.length + 1)}`);
    }
    const quote = /^>\s?(.*)$/.exec(source);
    if (quote) return wrapSpans([{ text: quote[1]!, style: dim }], width, `${indent}${dim("│")} `);
    return wrapSpans(inline(source), width, indent);
  }
}

export function renderMarkdown(text: string, width: number, indent = "  "): string[] {
  const stream = new MarkdownStream();
  return [...text.split("\n").flatMap((line) => stream.line(line, width, indent)), ...stream.flush(width, indent)];
}
