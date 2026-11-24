// Escribe las salidas de una corrida en su carpeta: resultado.json, resultado.sarif, resumen.md, registro.jsonl y,
// si se pide, junit.xml (y las trazas locales, si el modo de trazas es «local»). Cada archivo pasa por la última
// pasada del tapado antes de escribirse.
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { ConfigCi } from "./config.ts";
import { armarJunit } from "./junit.ts";
import { armarMarkdown } from "./markdown.ts";
import type { ResultadoCi } from "./resultado.ts";
import { armarSarif } from "./sarif.ts";
import { Tapador } from "./tapado.ts";

export const ARCHIVOS = { json: "resultado.json", sarif: "resultado.sarif", markdown: "resumen.md", junit: "junit.xml", registro: "registro.jsonl", trazas: "trazas" } as const;

/** Líneas de cada destino del alcance en el archivo de configuración, para las ubicaciones del SARIF. */
export function lineasDeDestinos(config: ConfigCi | undefined): { lineas: Record<string, number>; lineaAlcance: number } {
  const lineas: Record<string, number> = {};
  if (!config) return { lineas, lineaAlcance: 1 };
  for (const [k, r] of config.alcance.entries()) {
    const linea = config.posiciones.get(`objetivo.alcance[${k}]`)?.linea;
    if (linea) lineas[r.nombre ?? r.literal] = linea;
  }
  return { lineas, lineaAlcance: config.posiciones.get("objetivo.alcance")?.linea ?? config.posiciones.get("objetivo")?.linea ?? 1 };
}

export interface Escritas {
  carpeta: string;
  json: string;
  sarif: string;
  markdown: string;
  registro: string;
  junit?: string;
  trazas?: string;
}

export function escribirSalidas(opciones: { carpeta: string; cwd: string; resultado: ResultadoCi; registro: Array<Record<string, unknown>>; config?: ConfigCi; junit: boolean; sarifCandidatos: boolean; tapador?: Tapador; trazas?: string }): Escritas {
  const carpeta = resolve(opciones.cwd, opciones.carpeta);
  mkdirSync(carpeta, { recursive: true });
  const tapador = opciones.tapador ?? new Tapador();
  const escribir = (nombre: string, texto: string) => {
    const ruta = join(carpeta, nombre);
    writeFileSync(ruta, tapador.final(texto), { mode: 0o644 });
    return ruta;
  };
  const r = opciones.resultado;
  const { lineas, lineaAlcance } = lineasDeDestinos(opciones.config);
  const salida: Escritas = {
    carpeta,
    json: escribir(ARCHIVOS.json, `${JSON.stringify(r, null, 2)}\n`),
    sarif: escribir(ARCHIVOS.sarif, `${JSON.stringify(armarSarif(r, { archivoConfig: opciones.config?.archivo.replace(/^\.\//, "") ?? ".orobas/ci.yml", lineas, lineaAlcance, candidatos: opciones.sarifCandidatos }), null, 2)}\n`),
    markdown: escribir(ARCHIVOS.markdown, armarMarkdown(r)),
    registro: escribir(ARCHIVOS.registro, opciones.registro.map((l) => JSON.stringify(l)).join("\n") + (opciones.registro.length ? "\n" : "")),
  };
  if (opciones.junit) salida.junit = escribir(ARCHIVOS.junit, armarJunit(r));
  else rmSync(join(carpeta, ARCHIVOS.junit), { force: true });
  if (opciones.trazas) {
    const destino = join(carpeta, ARCHIVOS.trazas);
    rmSync(destino, { recursive: true, force: true });
    cpSync(opciones.trazas, destino, { recursive: true });
    rmSync(opciones.trazas, { recursive: true, force: true });
    salida.trazas = destino;
  }
  return salida;
}
