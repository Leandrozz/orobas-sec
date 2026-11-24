import { KittyImages, type TerminalImage } from "./kitty.ts";

/** El renderer reserva la región antes de dibujar; ED borra Sixel/inline junto al texto. */
export class TerminalImages {
  private kitty = new KittyImages();

  hide(): string { return this.kitty.hide(); }
  close(): string { return this.kitty.close(); }

  place(image: TerminalImage): string {
    if (image.protocol === "sixel") return image.sixel ?? "";
    if (image.protocol === "iterm2") {
      return `\x1b]1337;File=inline=1;size=${image.png.length};width=${image.columns};height=${image.rows};preserveAspectRatio=1:${image.png.toString("base64")}\x07`;
    }
    return this.kitty.place(image);
  }
}
