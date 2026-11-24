// Modo «local» de las trazas: el material de entrenamiento queda en la PC de la persona, en la carpeta de
// datos del proyecto (…/elevate-cyber/proyectos/<id>/trazas), con los secretos tapados igual que si
// saliera. Es JSONL: una línea JSON por registro, para leerlo con cualquier cosa (jq, pandas, otro harness).
// El formato está en LEEME.md, que se escribe junto a los archivos la primera vez.
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const VERSION_TRAZAS = 1;

export const LEEME = `# Trazas locales de orobas-sec

Las escribe el agente cuando el modo de trazas es «local» (CYBER_TRAZAS=local, «trazas»: "local" en
config.json, /datos local, o «Guardarlas sólo en mi PC» en cyber.elevateai.ar/cuenta/trazas). Es el mismo
material que en el modo «compartir» se manda a Elevate AI, pero no sale de esta máquina. Los secretos que
el agente reconoce (credenciales, cookies, tokens, valores de la sesión) ya están tapados, igual que si
salieran. Un dato sensible sin forma reconocible puede no estarlo: tratá esta carpeta como confidencial.

Todos los archivos son JSONL (UTF-8, una línea JSON por registro). Cada registro lleva «v» (versión del
formato, hoy ${VERSION_TRAZAS}), «at» (fecha ISO 8601), «sesion» y «proyecto».

- llamadas.jsonl: cada pedido a un modelo y su respuesta, de cualquier proveedor (el bucle, subagentes,
  verificador, compactador, router). Campos: worker, modelo ("proveedor/id"), pedido { system, tools,
  messages }, respuesta { content, tool_calls, stop_reason, usage, request_id, error }, ms. «system» y
  «tools» se repiten en casi todos los pedidos: van como "sha256:<hash>" y el contenido está una sola vez
  en piezas/<hash>.json. «messages» usa el formato interno del harness (role user | assistant | tool |
  checkpoint, con toolCalls en los del asistente).
- turnos.jsonl: el registro de cada turno, el mismo que en «compartir» va a /v1/traces: mensajes del
  operador, respuestas del agente, herramientas usadas con su cantidad, errores, pasos, cómo terminó.
- trayectorias/<sesion>.jsonl: la sesión entera en una línea, el mismo formato que exporta /trayectorias
  (mensajes con llamadas y resultados de herramientas, hallazgos con veredicto y etiquetas por turno). Se
  reescribe a medida que la sesión avanza. Los hosts del alcance quedan como están (no se anonimizan).
- consentimientos.jsonl: cada consentimiento con su tipo, fecha, huella y la cita tapada.
- piezas/<hash>.json: el prompt del sistema o la lista de herramientas que referencian las llamadas.

Para juntar todas las trayectorias: cat trayectorias/*.jsonl > todas.jsonl
`;

/** Crea la carpeta (privada) y su LEEME.md si faltan. */
export function prepararCarpeta(dir: string): void {
  mkdirSync(join(dir, "trayectorias"), { recursive: true, mode: 0o700 });
  mkdirSync(join(dir, "piezas"), { recursive: true, mode: 0o700 });
  const leeme = join(dir, "LEEME.md");
  if (!existsSync(leeme)) writeFileSync(leeme, LEEME, { mode: 0o600 });
}

const base = (registro: Record<string, unknown>) => ({ v: VERSION_TRAZAS, at: new Date().toISOString(), ...registro });

/** Agrega un registro a uno de los JSONL de la carpeta. */
export function anotar(dir: string, archivo: "llamadas.jsonl" | "turnos.jsonl" | "consentimientos.jsonl", registro: Record<string, unknown>): void {
  prepararCarpeta(dir);
  appendFileSync(join(dir, archivo), `${JSON.stringify(base(registro))}\n`, { mode: 0o600 });
}

/** Guarda una pieza grande que se repite (prompt, herramientas) una sola vez y devuelve su referencia. */
export function pieza(dir: string, valor: unknown): string {
  const texto = JSON.stringify(valor);
  const hash = createHash("sha256").update(texto).digest("hex");
  prepararCarpeta(dir);
  const ruta = join(dir, "piezas", `${hash}.json`);
  if (!existsSync(ruta)) writeFileSync(ruta, texto, { mode: 0o600 });
  return `sha256:${hash}`;
}

/** Reescribe la trayectoria de una sesión (una línea JSON). */
export function guardarTrayectoria(dir: string, sesion: string, linea: string): string {
  prepararCarpeta(dir);
  const ruta = join(dir, "trayectorias", `${sesion.replace(/[^A-Za-z0-9_-]/g, "_")}.jsonl`);
  writeFileSync(ruta, linea.endsWith("\n") ? linea : `${linea}\n`, { mode: 0o600 });
  return ruta;
}

/** Para /datos: qué hay en la carpeta. */
export function resumenCarpeta(dir: string): { existe: boolean; archivos: number; bytes: number } {
  if (!existsSync(dir)) return { existe: false, archivos: 0, bytes: 0 };
  let archivos = 0, bytes = 0;
  const recorrer = (d: string) => {
    for (const nombre of readdirSync(d)) {
      const ruta = join(d, nombre), info = statSync(ruta);
      if (info.isDirectory()) recorrer(ruta);
      else if (nombre !== "LEEME.md") { archivos++; bytes += info.size; }
    }
  };
  recorrer(dir);
  return { existe: true, archivos, bytes };
}
