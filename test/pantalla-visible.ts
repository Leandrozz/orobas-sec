import { stripAnsi } from "../src/tui/text.ts";

/** Reconstruye lo que se ve en la pantalla alternativa a partir de lo escrito: posiciona, borra filas y apila texto. */
export function pantallaVisible(written: string, width: number, height: number): string[] {
  void width;
  const filas: string[] = Array.from({ length: height }, () => "");
  let fila = 0;
  for (const parte of written.split(/(\x1b\[\d+;\d+H|\x1b\[2K|\x1b\[2J)/)) {
    const pos = /^\x1b\[(\d+);\d+H$/.exec(parte);
    if (pos) fila = Math.min(height - 1, Number(pos[1]) - 1);
    else if (parte === "\x1b[2K") filas[fila] = "";
    else if (parte === "\x1b[2J") filas.fill("");
    else filas[fila] += stripAnsi(parte);
  }
  return filas;
}
