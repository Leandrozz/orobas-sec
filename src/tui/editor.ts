// Editor multilínea: búfer, cursor, historial y presentación envuelta por ancho de celda.
import type { Key } from "./keys.ts";
import { cellWidth, graphemes, visibleWidth } from "./text.ts";

export interface EditorView {
  lines: string[];
  cursorRow: number;
  cursorCol: number;
}

export class Editor {
  text = "";
  /** Posición del cursor en unidades UTF-16, siempre en un límite de grafema. */
  cursor = 0;
  private history: string[] = [];
  private historyIndex = -1;
  private draft = "";

  set(text: string): void {
    this.text = text;
    this.cursor = text.length;
  }

  remember(text: string): void {
    if (text && this.history.at(-1) !== text) this.history.push(text);
    this.historyIndex = -1;
  }

  private insert(text: string): void {
    this.text = this.text.slice(0, this.cursor) + text + this.text.slice(this.cursor);
    this.cursor += text.length;
  }

  private step(direction: -1 | 1): number {
    if (direction < 0) return this.cursor - (graphemes(this.text.slice(0, this.cursor)).at(-1)?.length ?? 0);
    return this.cursor + (graphemes(this.text.slice(this.cursor))[0]?.length ?? 0);
  }

  private word(direction: -1 | 1): number {
    let position = this.cursor;
    const at = () => (direction < 0 ? this.text[position - 1] : this.text[position]);
    while (at() !== undefined && /\s/.test(at()!)) position += direction;
    while (at() !== undefined && !/\s/.test(at()!)) position += direction;
    return position;
  }

  private lineStart = () => this.text.lastIndexOf("\n", this.cursor - 1) + 1;
  private lineEnd = () => {
    const end = this.text.indexOf("\n", this.cursor);
    return end < 0 ? this.text.length : end;
  };

  private remove(from: number, to: number): void {
    this.text = this.text.slice(0, from) + this.text.slice(to);
    this.cursor = from;
  }

  private vertical(direction: -1 | 1): boolean {
    const start = this.lineStart();
    const column = this.cursor - start;
    if (direction < 0) {
      if (start === 0) return false;
      const previousStart = this.text.lastIndexOf("\n", start - 2) + 1;
      this.cursor = Math.min(previousStart + column, start - 1);
    } else {
      const end = this.lineEnd();
      if (end === this.text.length) return false;
      const nextEnd = this.text.indexOf("\n", end + 1);
      this.cursor = Math.min(end + 1 + column, nextEnd < 0 ? this.text.length : nextEnd);
    }
    return true;
  }

  private recall(direction: -1 | 1): void {
    if (!this.history.length) return;
    if (this.historyIndex < 0) {
      if (direction > 0) return;
      this.draft = this.text;
      this.historyIndex = this.history.length;
    }
    this.historyIndex += direction;
    if (this.historyIndex >= this.history.length) {
      this.historyIndex = -1;
      this.set(this.draft);
    } else {
      this.historyIndex = Math.max(0, this.historyIndex);
      this.set(this.history[this.historyIndex]!);
    }
  }

  /** Aplica una tecla de edición. Devuelve false si la tecla no es del editor. */
  handle(key: Key): boolean {
    switch (key.name) {
      case "text":
      case "paste":
        this.insert(key.text ?? "");
        break;
      case "newline":
        this.insert("\n");
        break;
      case "backspace":
        if (this.cursor > 0) this.remove(this.step(-1), this.cursor);
        break;
      case "delete":
        if (this.cursor < this.text.length) this.remove(this.cursor, this.step(1));
        break;
      case "left":
        this.cursor = Math.max(0, this.step(-1));
        break;
      case "right":
        this.cursor = Math.min(this.text.length, this.step(1));
        break;
      case "wordLeft":
        this.cursor = this.word(-1);
        break;
      case "wordRight":
        this.cursor = this.word(1);
        break;
      case "home":
        this.cursor = this.lineStart();
        break;
      case "end":
        this.cursor = this.lineEnd();
        break;
      case "up":
        if (!this.vertical(-1)) this.recall(-1);
        break;
      case "down":
        if (!this.vertical(1)) this.recall(1);
        break;
      case "killToEnd":
        this.remove(this.cursor, this.lineEnd());
        break;
      case "killToStart":
        this.remove(this.lineStart(), this.cursor);
        break;
      case "killWord":
        this.remove(this.word(-1), this.cursor);
        break;
      default:
        return false;
    }
    return true;
  }

  /** Filas visibles con el indicador «› », envueltas por ancho; desplaza para seguir al cursor. */
  view(width: number, maxRows: number, prompt = "› ", indent = "  "): EditorView {
    // En celdas, no en unidades UTF-16: el prompt puede llevar caracteres de ancho doble.
    const anchoPrompt = visibleWidth(prompt), anchoIndent = visibleWidth(indent);
    const room = Math.max(4, width - anchoIndent - anchoPrompt);
    const rows: string[] = [];
    let cursorRow = 0;
    let cursorCol = 0;
    let offset = 0;
    for (const [index, logical] of this.text.split("\n").entries()) {
      let row = "";
      let cells = 0;
      let position = offset;
      const locate = () => {
        if (position === this.cursor) {
          cursorRow = rows.length;
          cursorCol = anchoIndent + anchoPrompt + cells;
        }
      };
      const lead = () => indent + (index === 0 && position === offset ? prompt : " ".repeat(anchoPrompt));
      let head = lead();
      for (const grapheme of graphemes(logical)) {
        if (cells + cellWidth(grapheme) > room) {
          rows.push(head + row);
          row = "";
          cells = 0;
          head = indent + " ".repeat(anchoPrompt);
        }
        locate();
        row += grapheme;
        cells += cellWidth(grapheme);
        position += grapheme.length;
      }
      locate();
      rows.push(head + row);
      offset += logical.length + 1;
    }
    const first = Math.max(0, Math.min(cursorRow - Math.floor(maxRows / 2), rows.length - maxRows));
    return { lines: rows.slice(first, first + maxRows), cursorRow: cursorRow - first, cursorCol };
  }
}
