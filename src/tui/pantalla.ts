// Renderer de pantalla completa: dibuja en la pantalla alternativa y repinta sólo las filas que cambian.
import type { Output } from "./screen.ts";
import type { TerminalImage } from "./kitty.ts";
import { TerminalImages } from "./images.ts";
import { rgb, sinMarcas, truncate } from "./text.ts";
import { temaActivo, type Tema } from "./temas.ts";

export interface Cuadro {
  lineas: string[];
  cursor?: { row: number; col: number };
  imagen?: TerminalImage;
}

const MOUSE_ON = "\x1b[?1000h\x1b[?1002h\x1b[?1006h";
const MOUSE_OFF = "\x1b[?1006l\x1b[?1002l\x1b[?1000l";
// conhost no soporta la secuencia 2026 (mismo criterio que screen.ts).
const sincro = (on: boolean) => (process.env.CYBER_CONSOLE === "conhost" ? "" : `\x1b[?2026${on ? "h" : "l"}`);

export type ModoColor = "24bit" | "256";

/** CYBER_COLOR manda; si no, COLORTERM; Terminal.app de macOS sólo tiene 256; el resto, 24 bits como hoy. */
export function modoColor(env: NodeJS.ProcessEnv = process.env): ModoColor {
  if (env.CYBER_COLOR === "256" || env.CYBER_COLOR === "24bit") return env.CYBER_COLOR;
  if (env.COLORTERM === "truecolor" || env.COLORTERM === "24bit") return "24bit";
  return env.TERM_PROGRAM === "Apple_Terminal" ? "256" : "24bit";
}

const NIVELES = [0, 95, 135, 175, 215, 255];
/** Índice de la paleta de 256 más cercano (cubo 6x6x6 o rampa de grises) por distancia euclídea. */
function indice256(r: number, g: number, b: number): number {
  let mejor = 16;
  let dmin = Infinity;
  const prueba = (n: number, pr: number, pg: number, pb: number) => {
    const d = (r - pr) ** 2 + (g - pg) ** 2 + (b - pb) ** 2;
    if (d < dmin) [dmin, mejor] = [d, n];
  };
  NIVELES.forEach((nr, i) => NIVELES.forEach((ng, j) => NIVELES.forEach((nb, k) => prueba(16 + 36 * i + 6 * j + k, nr, ng, nb))));
  for (let k = 0; k < 24; k++) prueba(232 + k, 8 + 10 * k, 8 + 10 * k, 8 + 10 * k);
  return mejor;
}

/** Convierte cada 38;2;r;g;b / 48;2;r;g;b de la línea a 38;5;n / 48;5;n. */
export function a256(linea: string): string {
  return linea.replace(/\x1b\[[0-9;]*m/g, (sgr) => sgr.replace(/([34]8);2;(\d+);(\d+);(\d+)/g, (_, c, r, g, b) => `${c};5;${indice256(+r, +g, +b)}`));
}

/** Línea lista para escribir tras posicionar el cursor: con fondo y texto del tema que sobreviven a los resets de la línea. */
export function conFondo(linea: string, tema: Tema): string {
  if (process.env.NO_COLOR) return "\x1b[2K" + linea;
  // Sin fondo propio hay que borrar el estilo que dejó el tema anterior.
  if (!tema.fondo || !tema.texto) return "\x1b[0m\x1b[2K" + linea;
  const fg = `\x1b[38;2;${rgb(tema.texto)}m`;
  const bg = `\x1b[48;2;${rgb(tema.fondo)}m`;
  const resets = linea.replace(/\x1b\[0?m/g, (r) => `${r}${fg}${bg}`).replace(/\x1b\[39m/g, `\x1b[39m${fg}`).replace(/\x1b\[49m/g, `\x1b[49m${bg}`);
  return `${fg}${bg}\x1b[2K${resets}`;
}

/** Secuencia de salida sin estado: sirve para process.on("exit") ante Ctrl+C o errores. */
export function restaurarTerminal(out: Output): void {
  out.write(`${MOUSE_OFF}\x1b[?2026l\x1b[?1049l\x1b[?25h\x1b[0m`);
}

/** Pantallas que siguen adentro de la alternativa: en una salida normal ya restauraron y no hay que repetirlo. */
let adentro = 0;
export function restaurarSiDentro(out: Output): void {
  if (adentro > 0) restaurarTerminal(out);
}

export class Pantalla {
  private out: Output;
  private mouseOn: boolean;
  private dentro = false;
  private images = new TerminalImages();
  private dibujado: string[] = [];
  private tam = "";
  private clave = "";
  private temaId = "";

  constructor(out: Output, opciones: { mouse: boolean }) {
    this.out = out;
    this.mouseOn = opciones.mouse;
  }

  get width(): number {
    return Math.max(20, this.out.columns || 80);
  }

  get height(): number {
    return Math.max(8, this.out.rows || 24);
  }

  entrar(): void {
    if (!this.dentro) adentro++;
    this.dentro = true;
    this.dibujado = [];
    this.tam = this.clave = this.temaId = "";
    this.out.write(`\x1b[?1049h\x1b[2J\x1b[H${this.mouseOn ? MOUSE_ON : ""}`);
  }

  salir(): void {
    if (!this.dentro) return;
    this.dentro = false;
    this.out.write(this.images.close());
    restaurarTerminal(this.out);
    adentro--; // después de restaurar: si algo falla antes, restaurarSiDentro todavía lo cubre
  }

  /** Suelta de la terminal las imágenes ya enviadas (los cuadros del arranque); el próximo cuadro repinta y coloca la imagen de nuevo. */
  liberarImagenes(): void {
    this.out.write(this.images.close());
    this.clave = "\0";
  }

  limpiar(): void {
    this.tam = "";
    this.out.write(this.images.close() + "\x1b[0m\x1b[?25l\x1b[2J\x1b[H");
  }

  mouse(prendido: boolean): void {
    this.mouseOn = prendido;
    if (this.dentro) this.out.write(prendido ? MOUSE_ON : MOUSE_OFF);
  }

  dibujar(cuadro: Cuadro): void {
    const { width, height } = this;
    const lineas = Array.from({ length: height }, (_, i) => truncate(sinMarcas(cuadro.lineas[i] ?? ""), width));
    const tam = `${width}x${height}`;
    const img = cuadro.imagen;
    const clave = img ? `${img.key}@${img.row},${img.col}` : "";
    const tema = temaActivo();
    // Cambiar de tema repinta todo (también las filas vacías, que sólo difieren en el fondo), sin 2J para no parpadear.
    const todo = tam !== this.tam || clave !== this.clave || tema.id !== this.temaId;
    let f = `${sincro(true)}\x1b[?25l`;
    if (todo) f += this.images.hide() + (tam !== this.tam ? "\x1b[2J" : "");
    lineas.forEach((l, i) => {
      if (todo || l !== this.dibujado[i]) f += `\x1b[${i + 1};1H${modoColor() === "256" ? a256(conFondo(l, tema)) : conFondo(l, tema)}`;
    });
    if (img && todo) f += `\x1b[${img.row + 1};${img.col + 1}H${this.images.place(img)}`;
    const c = cuadro.cursor;
    if (c) f += `\x1b[${Math.min(c.row, height - 1) + 1};${Math.min(c.col, width - 1) + 1}H\x1b[?25h`;
    this.out.write(f + sincro(false));
    this.dibujado = lineas;
    this.tam = tam;
    this.clave = clave;
    this.temaId = tema.id;
  }
}
