// Decodificador acotado a nuestros recursos RGBA de 8 bits, no a archivos del usuario.
// PNG: https://www.w3.org/TR/png/#9Filtering
import { inflateSync } from "node:zlib";

export interface Raster { width: number; height: number; data: Buffer }

const paeth = (a: number, b: number, c: number) => {
  const p = a + b - c, x = Math.abs(p - a), y = Math.abs(p - b), z = Math.abs(p - c);
  return x <= y && x <= z ? a : y <= z ? b : c;
};

export function decodeAsset(png: Buffer): Raster {
  if (!png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) throw new Error("Recurso Orobas: firma PNG inválida");
  let width = 0, height = 0;
  const parts: Buffer[] = [];
  for (let offset = 8; offset + 12 <= png.length;) {
    const length = png.readUInt32BE(offset), type = png.toString("ascii", offset + 4, offset + 8);
    if (offset + length + 12 > png.length) throw new Error("Recurso Orobas: PNG truncado");
    if (type === "IHDR") {
      width = png.readUInt32BE(offset + 8); height = png.readUInt32BE(offset + 12);
      if (length !== 13 || png[offset + 16] !== 8 || png[offset + 17] !== 6 || png[offset + 18] !== 0 || png[offset + 19] !== 0 || png[offset + 20] !== 0) throw new Error("Recurso Orobas: se requiere RGBA8 sin entrelazado");
    } else if (type === "IDAT") parts.push(png.subarray(offset + 8, offset + 8 + length));
    offset += length + 12;
  }
  if (width !== 820 || height !== 700) throw new Error("Recurso Orobas: tamaño PNG inesperado");
  const stride = width * 4;
  const raw = inflateSync(Buffer.concat(parts), { maxOutputLength: (stride + 1) * height });
  if (raw.length !== (stride + 1) * height) throw new Error("Recurso Orobas: datos PNG incompletos");
  const data = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)]!;
    if (filter > 4) throw new Error("Recurso Orobas: filtro PNG inválido");
    for (let x = 0; x < stride; x++) {
      const i = y * stride + x;
      const a = x >= 4 ? data[i - 4]! : 0, b = y ? data[i - stride]! : 0, c = y && x >= 4 ? data[i - stride - 4]! : 0;
      const prediction = filter === 0 ? 0 : filter === 1 ? a : filter === 2 ? b : filter === 3 ? Math.floor((a + b) / 2) : paeth(a, b, c);
      data[i] = (raw[y * (stride + 1) + 1 + x]! + prediction) & 255;
    }
  }
  return { width, height, data };
}

/** Promedio de área con alpha; conserva líneas finas al bajar la resolución. */
export function resizeRaster(source: Raster, width: number, height: number): Raster {
  const data = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y++) {
    const y0 = Math.floor(y * source.height / height), y1 = Math.max(y0 + 1, Math.ceil((y + 1) * source.height / height));
    for (let x = 0; x < width; x++) {
      const x0 = Math.floor(x * source.width / width), x1 = Math.max(x0 + 1, Math.ceil((x + 1) * source.width / width));
      let r = 0, g = 0, b = 0, alpha = 0;
      for (let sy = y0; sy < y1; sy++) for (let sx = x0; sx < x1; sx++) {
        const i = (sy * source.width + sx) * 4, a = source.data[i + 3]!;
        alpha += a;
        r += source.data[i]! * a; g += source.data[i + 1]! * a; b += source.data[i + 2]! * a;
      }
      const i = (y * width + x) * 4;
      if (alpha) {
        data[i] = Math.round(r / alpha); data[i + 1] = Math.round(g / alpha); data[i + 2] = Math.round(b / alpha);
        data[i + 3] = Math.round(alpha / ((x1 - x0) * (y1 - y0)));
      }
    }
  }
  return { width, height, data };
}

export function textRaster(source: Raster, columns: number, rows: number, color: boolean, ascii = false): string[] {
  const scaleX = ascii ? 1 : 2, scaleY = ascii ? 1 : 4;
  const raster = resizeRaster(source, columns * scaleX, rows * scaleY);
  const dots = [[0,0,0],[0,1,1],[0,2,2],[1,0,3],[1,1,4],[1,2,5],[0,3,6],[1,3,7]] as const;
  const lines: string[] = [];
  for (let row = 0; row < rows; row++) {
    let line = "";
    for (let col = 0; col < columns; col++) {
      let bits = 0, r = 0, g = 0, b = 0, count = 0, density = 0;
      for (const [dx,dy,bit] of ascii ? [[0,0,0] as const] : dots) {
        const i = ((row * scaleY + dy) * raster.width + col * scaleX + dx) * 4;
        const alpha = raster.data[i + 3]!, peak = Math.max(raster.data[i]!, raster.data[i + 1]!, raster.data[i + 2]!);
        if (alpha > 2 && peak > 20) {
          bits |= 1 << bit; r += raster.data[i]!; g += raster.data[i + 1]!; b += raster.data[i + 2]!; count++;
          density += alpha / 255;
        }
      }
      const char = !bits ? " " : ascii ? " .:-=+*#%@"[Math.max(1, Math.min(9, Math.ceil(density * 18)))]! : String.fromCharCode(0x2800 + bits);
      line += color && count ? `\x1b[38;2;${Math.round(r/count)};${Math.round(g/count)};${Math.round(b/count)}m${char}\x1b[0m` : char;
    }
    lines.push(line);
  }
  return lines;
}

const palette = Array.from({ length: 96 }, (_, index) => {
  const base = [[212,226,238],[102,186,249],[249,180,42]][Math.floor(index / 32)]!;
  return base.map((channel) => Math.round(channel * (index % 32) / 31));
});

/** Sixel estándar: 96 colores, fondo transparente y compresión por repeticiones. */
export function encodeSixel(source: Raster, width: number, height: number): string {
  const raster = resizeRaster(source, width, height);
  const bands: string[] = [], used = new Set<number>();
  for (let y = 0; y < height; y += 6) {
    const layers = new Map<number, Uint8Array>();
    for (let dy = 0; dy < 6 && y + dy < height; dy++) for (let x = 0; x < width; x++) {
      const i = ((y + dy) * width + x) * 4, alpha = raster.data[i + 3]!;
      if (alpha < 8) continue;
      const r = raster.data[i]!, g = raster.data[i + 1]!, b = raster.data[i + 2]!;
      const hue = r > b * 1.3 ? 2 : b > r * 1.25 ? 1 : 0;
      const peak = Math.max(r,g,b), basePeak = hue === 0 ? 238 : 249;
      const level = Math.max(1, Math.min(31, Math.round(peak * alpha / 255 * 31 / basePeak)));
      const index = hue * 32 + level;
      if (!layers.has(index)) layers.set(index, new Uint8Array(width));
      const layer = layers.get(index)!;
      layer[x] = layer[x]! | (1 << dy);
      used.add(index);
    }
    const pieces: string[] = [];
    for (const [index, masks] of layers) {
      let last = width - 1;
      while (last >= 0 && masks[last] === 0) last--;
      let encoded = `#${index}`;
      for (let x = 0; x <= last;) {
        let end = x + 1;
        while (end <= last && masks[end] === masks[x]) end++;
        const length = end - x, char = String.fromCharCode(63 + masks[x]!);
        encoded += length >= 4 ? `!${length}${char}` : char.repeat(length);
        x = end;
      }
      pieces.push(encoded);
    }
    bands.push(pieces.join("$"));
  }
  const colors = [...used].map((index) => `#${index};2;${palette[index]!.map((value) => Math.round(value * 100 / 255)).join(";")}`).join("");
  return `\x1bP0;1;0q"1;1;${width};${height}${colors}${bands.join("-")}\x1b\\`;
}
