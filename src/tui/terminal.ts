// Capacidades de la terminal, independientes del sistema operativo o del shell.
import { randomInt } from "node:crypto";

export type ImageProtocol = "kitty" | "sixel" | "iterm2" | "braille" | "ascii";
export interface ImageTerminal {
  graphics: boolean;
  protocol?: ImageProtocol;
  cellWidth: number;
  cellHeight: number;
  cellSizeKnown?: boolean;
  columns?: number;
  rows?: number;
  color?: boolean;
  allowImages?: boolean;
  forced?: boolean;
}

export const imageProtocol = (terminal: ImageTerminal): ImageProtocol => terminal.protocol ?? (terminal.graphics ? "kitty" : "braille");
const isImage = (protocol: ImageProtocol) => protocol === "kitty" || protocol === "sixel" || protocol === "iterm2";
const featureCodes = (value: string): string[] => (value.match(/^[A-Za-z0-9]*/)?.[0] ?? "").match(/[A-Z][a-z]*\d*/g) ?? [];

export function detectTerminal(env: NodeJS.ProcessEnv): ImageTerminal {
  const requested = env.CYBER_GRAPHICS;
  const modes: ImageProtocol[] = ["kitty", "sixel", "iterm2", "braille", "ascii"];
  const forced = modes.includes(requested as ImageProtocol);
  // La consola clásica de Windows no tiene Braille en su fuente: texto ASCII.
  const conhost = env.CYBER_CONSOLE === "conhost";
  const blocked = conhost || !!env.NO_COLOR || requested === "off" || !!env.TMUX || !!env.STY || env.TERM === "dumb";
  const features = featureCodes(env.TERM_FEATURES ?? "");
  let protocol: ImageProtocol = env.TERM === "dumb" ? "ascii" : "braille";
  if (!blocked) {
    if (forced) protocol = requested as ImageProtocol;
    else if (env.TERM === "xterm-kitty" || env.KITTY_WINDOW_ID || env.TERM_PROGRAM === "ghostty") protocol = "kitty";
    else if (env.TERM_PROGRAM === "iTerm.app" || env.TERM_PROGRAM === "WezTerm" || features.includes("F")) protocol = "iterm2";
    else if (features.includes("Sx")) protocol = "sixel";
  } else if (requested === "ascii" || conhost) protocol = "ascii";
  const cell = /^(\d{1,3})x(\d{1,3})$/.exec(env.CYBER_CELL_SIZE ?? "");
  const known = !!cell && Number(cell[1]) > 0 && Number(cell[2]) > 0;
  return { protocol, graphics: isImage(protocol), cellWidth: known ? Number(cell![1]) : 10, cellHeight: known ? Number(cell![2]) : 20, cellSizeKnown: known,
    color: !env.NO_COLOR, allowImages: !blocked && (!forced || isImage(protocol)), forced: blocked || forced };
}

/** Respuestas separadas de las teclas: ninguna consulta puede acabar en el prompt. */
export class ImageReplies {
  readonly queryId = randomInt(0x80000000, 0xffffffff);
  private pending = "";
  private sixel = false;
  private kittyConfirmed = false;
  private readonly prefixes = ["\x1b_G", "\x1b[6;", "\x1b[4;", "\x1b[?", "\x1b]1337;"];

  /** ESC también es una tecla: esperar brevemente a distinguirla de una respuesta partida. */
  get flushDelay(): number | undefined {
    if (!this.pending) return undefined;
    return this.prefixes.some((prefix) => prefix.startsWith(this.pending) && this.pending.length < prefix.length) ? 25 : 250;
  }

  flush(): string {
    const input = this.flushDelay === 25 ? this.pending : "";
    this.pending = "";
    return input;
  }

  query(): string {
    return `\x1b_Ga=q,i=${this.queryId},t=d,f=24,s=1,v=1;AAAA\x1b\\\x1b[16t\x1b[14t\x1b[c\x1b]1337;Capabilities\x1b\\`;
  }

  consume(data: string, terminal: ImageTerminal): { input: string; changed: boolean } {
    let source = this.pending + data;
    this.pending = "";
    let input = "";
    let changed = false;
    const select = (protocol: ImageProtocol) => {
      if (terminal.forced || terminal.allowImages === false) return;
      changed ||= imageProtocol(terminal) !== protocol;
      terminal.protocol = protocol;
      terminal.graphics = isImage(protocol);
    };
    while (source) {
      if (this.prefixes.some((prefix) => source.length < prefix.length && prefix.startsWith(source))) {
        this.pending = source;
        break;
      }
      if (source.startsWith("\x1b_G")) {
        const end = source.indexOf("\x1b\\");
        if (end < 0) { this.pending = source; break; }
        const reply = source.slice(3, end);
        if (new RegExp(`(?:^|,)i=${this.queryId}(?:,|;)`).test(reply)) {
          if (reply.endsWith(";OK")) { this.kittyConfirmed = true; select("kitty"); }
          else if (imageProtocol(terminal) === "kitty") select(this.sixel ? "sixel" : "braille");
        }
        source = source.slice(end + 2);
      } else if (source.startsWith("\x1b[6;") || source.startsWith("\x1b[4;")) {
        const reply = /^\x1b\[(6|4);(\d+);(\d+)t/.exec(source);
        if (!reply && /^\x1b\[(6|4);[\d;]*$/.test(source)) { this.pending = source; break; }
        if (reply) {
          const direct = reply[1] === "6";
          const height = direct ? Number(reply[2]) : Math.floor(Number(reply[2]) / (terminal.rows || Infinity));
          const width = direct ? Number(reply[3]) : Math.floor(Number(reply[3]) / (terminal.columns || Infinity));
          if (height > 0 && width > 0 && height <= 1024 && width <= 1024) {
            if (direct || !terminal.cellSizeKnown) {
              changed ||= !terminal.cellSizeKnown || terminal.cellWidth !== width || terminal.cellHeight !== height;
              terminal.cellWidth = width;
              terminal.cellHeight = height;
              terminal.cellSizeKnown = true;
            }
          }
          source = source.slice(reply[0].length);
        } else { input += source[0]; source = source.slice(1); }
      } else if (source.startsWith("\x1b[?")) {
        const reply = /^\x1b\[\?([\d;]*)c/.exec(source);
        if (!reply && /^\x1b\[\?[\d;]*$/.test(source)) { this.pending = source; break; }
        if (reply) {
          // DA1: el atributo 4 anuncia Sixel, también en Windows Terminal y WSL.
          this.sixel = reply[1]!.split(";").slice(1).includes("4");
          if (!this.kittyConfirmed && imageProtocol(terminal) !== "iterm2") select(this.sixel ? "sixel" : "braille");
          source = source.slice(reply[0].length);
        } else { input += source[0]; source = source.slice(1); }
      } else if (source.startsWith("\x1b]1337;")) {
        const end = /\x07|\x1b\\/.exec(source);
        if (!end) { this.pending = source; break; }
        const reply = source.slice(7, end.index);
        if (reply.startsWith("Capabilities=")) {
          const features = featureCodes(reply.slice("Capabilities=".length));
          if (features.includes("F") && !this.kittyConfirmed) select("iterm2");
          else if (features.includes("Sx") && !this.kittyConfirmed && imageProtocol(terminal) !== "iterm2") select("sixel");
        }
        source = source.slice(end.index + end[0].length);
      } else {
        const next = source.slice(1).indexOf("\x1b");
        const end = next < 0 ? source.length : next + 1;
        input += source.slice(0, end);
        source = source.slice(end);
      }
    }
    if (this.pending.length > 4096) this.pending = "";
    return { input, changed };
  }
}
