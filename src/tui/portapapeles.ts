// Copiar al portapapeles del terminal con OSC 52 (funciona también por SSH). En tmux la secuencia va envuelta.
import { t } from "../idioma.ts";
import { graphemes } from "./text.ts";

export const TOPE_COPIA = 50_000;

export function osc52(texto: string, env: NodeJS.ProcessEnv = process.env): string {
  const seq = `\x1b]52;c;${Buffer.from(texto, "utf8").toString("base64")}\x07`;
  const tmux = env.TMUX !== undefined || /^(screen|tmux)/.test(env.TERM ?? "");
  return tmux ? `\x1bPtmux;${seq.replaceAll("\x1b", "\x1b\x1b")}\x1b\\` : seq;
}

export function copiar(texto: string, escribir: (s: string) => void, env: NodeJS.ProcessEnv = process.env): { aviso: string; ok: boolean } {
  const n = graphemes(texto).length;
  if (n > TOPE_COPIA) return { aviso: t(`Demasiado para copiar (${n} caracteres, máximo 50 000)`, `Too much to copy (${n} characters, max 50,000)`), ok: false };
  escribir(osc52(texto, env));
  return { aviso: t(`✓ ${n} caracteres copiados al portapapeles`, `✓ ${n} characters copied to clipboard`), ok: true };
}
