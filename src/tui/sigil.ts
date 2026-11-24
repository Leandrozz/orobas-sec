// El sello aprobado: cuadros PNG del demo, sin redibujar ni simplificar el Braille.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ImageTerminal, TerminalImage } from "./kitty.ts";
import { imageProtocol } from "./terminal.ts";
import { decodeAsset, encodeSixel, type Raster, textRaster } from "./raster.ts";
import { accent, bold, visibleWidth } from "./text.ts";

const ROOT = join(import.meta.dirname, "assets", "orobas");
const manifest = JSON.parse(readFileSync(join(ROOT, "animation.json"), "utf8")) as {
  size_px: [number, number];
  frames: Array<{ file: string; duration_ms: number }>;
};
const pngs = new Map<number, Buffer>();
const rasters = new Map<number, Raster>();
const center = (line: string, width: number) => " ".repeat(Math.max(0, Math.floor((width - visibleWidth(line)) / 2))) + line;

export class Sigil {
  frame = manifest.frames.length - 1;
  booting: boolean;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private rendered = new Map<string, string[] | string>();

  private raster(png: Buffer): Raster {
    let raster = rasters.get(this.frame);
    if (!raster) {
      raster = decodeAsset(png);
      if (rasters.size >= 2) rasters.delete(rasters.keys().next().value!);
      rasters.set(this.frame, raster);
    }
    return raster;
  }

  private cache(key: string, render: () => string[] | string): string[] | string {
    if (this.rendered.has(key)) return this.rendered.get(key)!;
    const value = render();
    if (this.rendered.size >= 24) this.rendered.delete(this.rendered.keys().next().value!);
    this.rendered.set(key, value);
    return value;
  }

  constructor(animate: boolean) {
    this.booting = animate;
    if (animate) this.frame = 0;
  }

  start(redraw: () => void, finish: () => void): void {
    if (!this.booting) return;
    const next = () => {
      this.timer = setTimeout(() => {
        if (this.frame < manifest.frames.length - 1) {
          this.frame++;
          redraw();
          next();
        } else finish();
      }, manifest.frames[this.frame]!.duration_ms);
    };
    next();
  }

  settle(): void {
    clearTimeout(this.timer);
    this.booting = false;
    this.frame = manifest.frames.length - 1;
  }

  view(width: number, height: number, terminal: ImageTerminal, title = true): { lines: string[]; image?: TerminalImage } {
    height = Math.max(0, height);
    const lines: string[] = [];
    let image: TerminalImage | undefined;
    const titleRows = title ? (height >= 7 ? 3 : height >= 1 ? 1 : 0) : 0;
    const availableRows = Math.max(0, height - titleRows);
    if (width >= 12 && availableRows >= 3) {
      const [pixelsWide, pixelsHigh] = manifest.size_px;
      const columns = Math.max(1, Math.floor(Math.min(width - 4, availableRows * terminal.cellHeight * pixelsWide / pixelsHigh / terminal.cellWidth)));
      const rows = Math.max(1, Math.min(availableRows, Math.ceil(columns * terminal.cellWidth * pixelsHigh / pixelsWide / terminal.cellHeight)));
      const row = Math.floor((height - rows - titleRows) / 2);
      lines.push(...Array.from({ length: row + rows }, () => ""));
      let png = pngs.get(this.frame);
      if (!png) {
        png = readFileSync(join(ROOT, manifest.frames[this.frame]!.file));
        pngs.set(this.frame, png);
      }
      const detected = imageProtocol(terminal);
      // Sixel usa píxeles, no celdas: sin geometría confirmada no se puede reservar su altura.
      const protocol = detected === "sixel" && terminal.cellSizeKnown === false ? "braille" : detected;
      const pixelWidth = Math.round(columns * terminal.cellWidth);
      const pixelHeight = Math.round(pixelWidth * pixelsHigh / pixelsWide);
      if (protocol === "braille" || protocol === "ascii") {
        const key = `${this.frame}:${columns}:${rows}:${protocol}:${terminal.color !== false}`;
        const text = this.cache(key, () => textRaster(this.raster(png), columns, rows, terminal.color !== false, protocol === "ascii")) as string[];
        for (const [index, line] of text.entries()) lines[row + index] = center(line, width);
      } else {
        const sixel = protocol === "sixel" ? this.cache(`${this.frame}:${pixelWidth}:${pixelHeight}:sixel`, () => encodeSixel(this.raster(png), pixelWidth, pixelHeight)) as string : undefined;
        image = { key: `orobas-${this.frame}`, png, row, col: Math.floor((width - columns) / 2), columns, rows, protocol, pixelWidth, pixelHeight, ...(sixel ? { sixel } : {}) };
      }
    }
    if (titleRows === 3) lines.push(center(bold("OROBAS"), width), center(accent("by ELEVATE AI"), width), "");
    else if (titleRows === 1) lines.push(center(bold("OROBAS"), width));
    while (lines.length < height) lines.push("");
    return { lines, ...(image ? { image } : {}) };
  }
}
