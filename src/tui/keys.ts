// Decodifica la entrada cruda de la terminal en teclas con nombre.
export interface Key {
  name: string;
  /** Texto a insertar, para `text` y `paste`. */
  text?: string;
  /** Posición (0-based) de los eventos del mouse. */
  fila?: number;
  col?: number;
}

const SEQUENCES: Record<string, string> = {
  "\x1b[A": "up",
  "\x1b[B": "down",
  "\x1b[C": "right",
  "\x1b[D": "left",
  "\x1bOA": "up",
  "\x1bOB": "down",
  "\x1bOC": "right",
  "\x1bOD": "left",
  "\x1b[H": "home",
  "\x1b[F": "end",
  "\x1bOH": "home",
  "\x1bOF": "end",
  "\x1b[1~": "home",
  "\x1b[7~": "home",
  "\x1b[4~": "end",
  "\x1b[8~": "end",
  "\x1b[3~": "delete",
  "\x1b[1;5C": "wordRight",
  "\x1b[1;5D": "wordLeft",
  "\x1b[1;6C": "ctrl+shift+right", // mover la pestaña a otra ventana
  "\x1b[1;6D": "ctrl+shift+left",
  "\x1b[1;7C": "ctrl+alt+right", // correr el divisor
  "\x1b[1;7D": "ctrl+alt+left",
  "\x1b[17~": "f6",
  "\x1b[17;2~": "shift+f6",
  "\x1bOQ": "f2",
  "\x1b[12~": "f2",
  "\x1b[1;3C": "alt+right",
  "\x1b[1;3D": "alt+left",
  "\x1b[1;3A": "alt+up",
  "\x1b[1;3B": "alt+down",
  "\x1b[5~": "pageUp",
  "\x1b[6~": "pageDown",
  "\x1b[5;5~": "ctrl+pageUp", // Ctrl+PgUp/PgDn: pestaña sin Alt (Windows Terminal, xterm)
  "\x1b[6;5~": "ctrl+pageDown",
  "\x1b[1;5H": "ctrl+home",
  "\x1b[1;5F": "ctrl+end",
  "\x1bf": "wordRight",
  "\x1bb": "wordLeft",
  "\x1b\r": "newline", // Alt+Enter
  "\x1b\n": "newline",
  "\x1b[13;2u": "newline", // Shift+Enter (protocolo kitty)
  "\x1b[27;2;13~": "newline",
  "\x1b[27;5;13~": "ctrl+enter", // Ctrl+Enter con modifyOtherKeys (xterm); en modo clásico llega como Enter
  "\x1b\x7f": "killWord", // Alt+Backspace
  "\x1b[Z": "shiftTab",
};

const CONTROL: Record<string, string> = {
  "\r": "enter",
  "\n": "newline", // Ctrl+J
  "\t": "tab",
  "\x7f": "backspace",
  "\b": "backspace",
  "\x01": "home",
  "\x05": "end",
  "\x03": "ctrl+c",
  "\x04": "ctrl+d",
  "\x0b": "killToEnd",
  "\x15": "killToStart",
  "\x17": "killWord",
  "\x0c": "ctrl+l",
  "\x0e": "ctrl+n", // pestaña siguiente: llega igual en cualquier terminal, sin Alt ni Fn
  "\x10": "ctrl+p",
  "\x19": "ctrl+y", // «ya»: corta el turno y manda el mensaje. Byte 0x19 del modo clásico (kitty 0.50 lo manda así)
};

/** conhost no tiene pegado entre corchetes: un solo chunk con texto, salto y más texto es un pegado.
 * shortcut: un pegado partido en varias lecturas manda la cola como Enter, y tipeo rápido que llega junto en una lectura («ls\rnext») se toma por pegado; si molesta, medir tiempos entre lecturas. */
export const esPegadoConhost = (data: string) =>
  process.env.CYBER_CONSOLE === "conhost" && !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(data) && /\S[\r\n]+\s*\S/.test(data);

const PASTE_START = "\x1b[200~";
const PASTE_END = "\x1b[201~";

/** F8 en xterm y CSI-u. Los bloqueos del teclado no cambian la tecla. */
function secuenciaF8(texto: string) {
  const m = /^\x1b\[(19|57371)(?:;(\d+)(?::(\d+))?)?([~u])/.exec(texto);
  if (!m || m[4] !== (m[1] === "19" ? "~" : "u")) return;
  const modificadores = Number(m[2] ?? 1) - 1;
  return { longitud: m[0].length, pulsada: (modificadores & ~(64 | 128)) === 0 && (!m[3] || m[3] === "1") };
}

export class KeyParser {
  private paste: string | undefined;
  private pending = "";

  parse(data: string): Key[] {
    // Las teclas de salida no pueden quedar atrapadas detrás de un pegado o CSI incompleto.
    const directa = secuenciaF8(data);
    if (/^[\x03\x04]+$/.test(data) || (directa?.pulsada && directa.longitud === data.length)) {
      this.paste = undefined;
      this.pending = "";
    }
    data = this.pending + data;
    this.pending = "";
    const keys: Key[] = [];
    let index = 0;
    while (index < data.length) {
      if (this.paste !== undefined) {
        const end = data.indexOf(PASTE_END, index);
        const interrupt = data.slice(index).search(/[\x03\x04]/);
        if (interrupt >= 0 && (end < 0 || index + interrupt < end)) {
          this.paste = undefined;
          index += interrupt;
          continue;
        }
        if (end < 0) {
          const rest = data.slice(index);
          let keep = Math.min(PASTE_END.length - 1, rest.length);
          while (keep > 0 && !PASTE_END.startsWith(rest.slice(-keep))) keep--;
          this.paste += rest.slice(0, rest.length - keep);
          this.pending = keep ? rest.slice(-keep) : "";
          break;
        }
        keys.push({ name: "paste", text: (this.paste + data.slice(index, end)).replace(/\r\n?/g, "\n") });
        this.paste = undefined;
        index = end + PASTE_END.length;
        continue;
      }
      if (data.startsWith(PASTE_START, index)) {
        this.paste = "";
        index += PASTE_START.length;
        continue;
      }
      const char = data[index]!;
      if (char === "\x1b") {
        const rest = data.slice(index);
        if (rest.length > 1 && ((rest.length < PASTE_START.length && PASTE_START.startsWith(rest)) || Object.keys(SEQUENCES).some((sequence) => rest.length < sequence.length && sequence.startsWith(rest)))) {
          this.pending = rest;
          break;
        }
        const panico = secuenciaF8(rest);
        if (panico) {
          if (panico.pulsada) keys.push({ name: "f8" });
          index += panico.longitud;
          continue;
        }
        // Kitty/CSI-u: aceptar teclas de control aunque el shell haya dejado ese protocolo activo.
        const enhanced = /^\x1b\[(\d+)(?::[\d:]*)?(?:;(\d+)(?::(\d+))?)?(?:;([\d:]+))?u/.exec(rest);
        if (enhanced) {
          const code = Number(enhanced[1]), mods = Number(enhanced[2] ?? 1) - 1;
          index += enhanced[0].length;
          if (enhanced[3] === "3") continue; // key-up no es otra pulsación
          if (code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) continue;
          if (code === 13 && mods & 4) keys.push({ name: "ctrl+enter" });
          else if (mods & 4) {
            const control = code >= 97 && code <= 122 ? String.fromCharCode(code - 96) : code >= 65 && code <= 90 ? String.fromCharCode(code - 64) : "";
            if (CONTROL[control]) keys.push({ name: CONTROL[control] });
          } else if (code === 13 && mods & 3) keys.push({ name: "newline" });
          else if (code === 27) keys.push({ name: "escape" });
          else if (CONTROL[String.fromCodePoint(code)]) keys.push({ name: CONTROL[String.fromCodePoint(code)]! });
          else if (!(mods & (2 | 8 | 16 | 32)) && !(code >= 57344 && code <= 63743)) {
            const points = enhanced[4]?.split(":").map(Number) ?? [code];
            if (!enhanced[4] && mods & 1 && code >= 97 && code <= 122) points[0] = code - 32;
            if (points.every((point) => point >= 32 && point <= 0x10ffff && !(point >= 0xd800 && point <= 0xdfff))) keys.push({ name: "text", text: String.fromCodePoint(...points) });
          }
          continue;
        }
        if (/^\x1b\[[\d;:]+$/.test(rest) || /^\x1b\[<[\d;]*$/.test(rest)) { this.pending = rest; break; }
        // Mouse SGR: rueda y botón izquierdo (clic, arrastre, soltar) emiten tecla; el resto se consume.
        const mouse = /^\x1b\[<(\d+);(\d+);(\d+)([Mm])/.exec(rest);
        if (mouse) {
          index += mouse[0].length;
          if (mouse[1] === "64" || mouse[1] === "65") keys.push({ name: mouse[1] === "64" ? "wheelUp" : "wheelDown", col: Number(mouse[2]) - 1, fila: Number(mouse[3]) - 1 });
          else if (mouse[1] === "0" || mouse[1] === "32") {
            const name = mouse[4] === "m" ? "mouseUp" : mouse[1] === "0" ? "mouseDown" : "mouseDrag";
            keys.push({ name, col: Number(mouse[2]) - 1, fila: Number(mouse[3]) - 1 });
          }
          continue;
        }
        if (/^\x1b[1-9]/.test(rest)) {
          keys.push({ name: `alt+${rest[1]}` });
          index += 2;
          continue;
        }
        const known = Object.keys(SEQUENCES).find((sequence) => rest.startsWith(sequence));
        if (known) {
          keys.push({ name: SEQUENCES[known]! });
          index += known.length;
          continue;
        }
        // Secuencia CSI/SS3 desconocida: se descarta entera. Un ESC suelto es la tecla Escape.
        const unknown = /^\x1b(?:\[[0-9;?<>=]*[ -\/]*[@-~]|O.)/.exec(rest);
        if (unknown) index += unknown[0].length;
        else {
          keys.push({ name: "escape" });
          index += 1;
        }
        continue;
      }
      if (CONTROL[char]) {
        keys.push({ name: CONTROL[char] });
        index += 1;
        continue;
      }
      if (char < " ") {
        index += 1;
        continue;
      }
      let end = index;
      while (end < data.length && data[end]! >= " " && data[end] !== "\x7f") end++;
      keys.push({ name: "text", text: data.slice(index, end) });
      index = end;
    }
    return keys;
  }
}
