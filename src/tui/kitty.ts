// Transporte PNG de Kitty. No ejecuta kittens ni requiere dependencias externas.
import { randomInt } from "node:crypto";
export { ImageReplies, type ImageTerminal } from "./terminal.ts";

export interface TerminalImage {
  key: string;
  png: Buffer;
  row: number;
  col: number;
  columns: number;
  rows: number;
  protocol?: "kitty" | "sixel" | "iterm2";
  pixelWidth?: number;
  pixelHeight?: number;
  sixel?: string;
}

const graphics = (control: string, data = "") => `\x1b_G${control}${data ? `;${data}` : ""}\x1b\\`;

/** Cada pantalla posee sus IDs: nunca borra imágenes de otros programas. */
export class KittyImages {
  private nextId = randomInt(1, 0x7fffffff - 100);
  private images = new Map<string, number>();
  private visible: number | undefined;

  hide(): string {
    if (this.visible === undefined) return "";
    const command = graphics(`a=d,d=i,i=${this.visible},q=2`);
    this.visible = undefined;
    return command;
  }

  place(image: TerminalImage): string {
    let id = this.images.get(image.key);
    let output = "";
    if (id === undefined) {
      id = this.nextId++;
      this.images.set(image.key, id);
      const data = image.png.toString("base64");
      // Los trozos son múltiplos de cuatro y no superan los 4096 bytes del protocolo.
      for (let offset = 0; offset < data.length; offset += 4000) {
        const more = offset + 4000 < data.length ? 1 : 0;
        output += graphics(offset === 0 ? `a=t,t=d,f=100,i=${id},q=2,m=${more}` : `m=${more},q=2`, data.slice(offset, offset + 4000));
      }
    }
    // Sólo se fija el ancho: Kitty calcula la altura y conserva la proporción exacta.
    output += graphics(`a=p,i=${id},p=1,c=${image.columns},C=1,q=2`);
    this.visible = id;
    return output;
  }

  close(): string {
    const commands = [...this.images.values()].map((id) => graphics(`a=d,d=I,i=${id},q=2`)).join("");
    this.images.clear();
    this.visible = undefined;
    return commands;
  }
}

