// Ajustes que la TUI recuerda por proyecto, por la ruta de su carpeta (como Claude Code o Codex): idioma,
// modelo (el base y el fuerte), razonamiento, router, topes, User-Agent, escáneres y señuelos. Ventanas, pestañas y tema son generales. Viven en la configuración del usuario
// (clave «proyectos») y al abrir el proyecto se reaplican con las mismas operaciones del daemon que usan
// los comandos. El idioma se aplica fijando LC_ALL en este proceso, que es lo que t() lee.
// shortcut: lo que cambia el agente hablando (session_settings) no se recuerda, porque eso pasa en el
// daemon; para recordarlo, el daemon tendría que avisar los cambios.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { t } from "../idioma.ts";
import { configPath } from "../providers.ts";
import { validarPestanas, type Pestana } from "./pestanas.ts";
import { validarArreglo, type Arreglo } from "./ventanas.ts";
import { buscarTema, type TemaId } from "./temas.ts";

export type Idioma = "es" | "en";
/** Operaciones del daemon cuyo valor se recuerda por proyecto cuando se cambian desde la TUI. */
export const RECORDADOS = ["model", "strong", "reasoning", "budget", "requests", "rate", "agent", "scanners", "decoys", "router", "router_medio", "investigation_auto"] as const;
export type Recordado = (typeof RECORDADOS)[number];
export type Ajustes = Partial<Record<Recordado, string>> & { idioma?: Idioma | "sistema"; pestanas?: unknown; ventanas?: unknown; mouse?: boolean };

const LOCALE: Record<Idioma, string> = { es: "es_AR.UTF-8", en: "en_US.UTF-8" };
const LC_ALL_SISTEMA = process.env.LC_ALL;
/** Ruta del proyecto abierto; vacía fuera de la TUI (los ajustes van a la parte general). */
let proyecto = "";

/** Si no se pudo escribir, la sesión sigue con esto (los cambios se aplican igual, sin persistir). */
let enMemoria: Record<string, unknown> | undefined;

function readConfig(): Record<string, unknown> {
  const path = configPath();
  let archivo: Record<string, unknown> | undefined;
  if (existsSync(path)) {
    try {
      const parsed: unknown = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) archivo = parsed as Record<string, unknown>;
    } catch { /* ilegible: writeConfig no lo pisa */ }
  } else archivo = {};
  if (!enMemoria) return archivo ?? {};
  if (!archivo || !existsSync(path)) return structuredClone(enMemoria);
  // Siempre manda el archivo (otros escritores lo cambian); de la memoria sólo lo que es de la TUI.
  // shortcut: un idioma general borrado en memoria no se aplica al archivo; es raro y se reelige.
  const propio: Record<string, unknown> = { ...archivo, proyectos: { ...proyectos(archivo), ...proyectos(enMemoria) } };
  for (const clave of ["idioma", "tema", "descifrado", "novedades", "pestanas", "ventanas"]) if (enMemoria[clave] !== undefined) propio[clave] = enMemoria[clave];
  return structuredClone(propio);
}

/** Devuelve el aviso (ruta y motivo) si no pudo escribir; nunca tira. */
function writeConfig(config: Record<string, unknown>): string | undefined {
  const path = configPath();
  try {
    // Un archivo que no se puede leer nunca se pisa: se perderían los proveedores del usuario.
    if (existsSync(path)) JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
  } catch (error) {
    enMemoria = config;
    return t(`No guardé en ${path}: no es un JSON válido (${(error as Error).message}). Arreglalo a mano; el cambio vale hasta que cierres.`, `Not saved to ${path}: it is not valid JSON (${(error as Error).message}). Fix it by hand; the change lasts until you quit.`);
  }
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`);
    enMemoria = undefined;
    return undefined;
  } catch (error) {
    enMemoria = config;
    return t(`No pude guardar en ${path}: ${(error as Error).message}. El cambio vale hasta que cierres.`, `Could not save to ${path}: ${(error as Error).message}. The change lasts until you quit.`);
  }
}

const proyectos = (config: Record<string, unknown>) =>
  (config.proyectos && typeof config.proyectos === "object" && !Array.isArray(config.proyectos) ? config.proyectos : {}) as Record<string, Ajustes>;

/** Lo recordado para el proyecto abierto. */
export function ajustes(): Ajustes {
  return proyecto ? { ...proyectos(readConfig())[proyecto] } : {};
}

/** Guarda (o borra, con undefined) un ajuste del proyecto abierto, sin tocar el resto de la configuración. */
export function guardarAjuste<K extends keyof Ajustes>(key: K, value: Ajustes[K] | undefined): string | undefined {
  if (!proyecto) return;
  const config = readConfig();
  const todos = proyectos(config);
  const propio = { ...todos[proyecto] };
  if (value === undefined) delete propio[key];
  else propio[key] = value;
  config.proyectos = { ...todos, [proyecto]: propio };
  return writeConfig(config);
}

/** Ventanas y pestañas valen para todos los proyectos (es cómo se ve la pantalla, no el proyecto); lo que quedó guardado en un proyecto se usa mientras no haya uno general. */
const pantallaGuardada = (clave: "pestanas" | "ventanas"): unknown => readConfig()[clave] ?? ajustes()[clave];
export const pestanasGuardadas = (): Pestana[] => validarPestanas(pantallaGuardada("pestanas"));
export const guardarPestanas = (lista: Pestana[]) => guardarGeneral("pestanas", lista);
/** El arreglo de ventanas; si falta, las pestañas guardadas son la única ventana. */
export const arregloGuardado = (): Arreglo => validarArreglo(pantallaGuardada("ventanas"), pestanasGuardadas());
/** Guarda el arreglo y, por compatibilidad, la ventana 0 como «pestanas». */
export const guardarArreglo = (a: Arreglo): string | undefined => guardarGeneral("ventanas", a) ?? guardarGeneral("pestanas", a.pestanas[0]);
export const mouseGuardado = (env: NodeJS.ProcessEnv = process.env): boolean =>
  ajustes().mouse ?? !(env.CYBER_CONSOLE === "conhost" || env.TERM_PROGRAM === "Apple_Terminal");
export const guardarMouse = (valor: boolean) => guardarAjuste("mouse", valor);

/** El idioma elegido: el del proyecto, si no el general (clave «idioma»); nada si sigue al sistema. */
export function idiomaGuardado(): Idioma | undefined {
  const propio = ajustes().idioma;
  if (propio) return propio === "sistema" ? undefined : propio;
  const general = readConfig().idioma;
  return general === "es" || general === "en" ? general : undefined;
}

export function aplicarIdioma(lang: Idioma | undefined): void {
  if (lang) process.env.LC_ALL = LOCALE[lang];
  else if (LC_ALL_SISTEMA === undefined) delete process.env.LC_ALL;
  else process.env.LC_ALL = LC_ALL_SISTEMA;
}

/** Elige el idioma (undefined: el del sistema) para el proyecto abierto, o en general si no hay proyecto, y lo aplica ya. */
export function elegirIdioma(lang: Idioma | undefined): string | undefined {
  // En un proyecto, «sistema» se guarda tal cual: si no, ganaría el idioma general.
  let aviso: string | undefined;
  if (proyecto) aviso = guardarAjuste("idioma", lang ?? "sistema");
  else {
    const config = readConfig();
    if (lang) config.idioma = lang;
    else delete config.idioma;
    aviso = writeConfig(config);
  }
  aplicarIdioma(idiomaGuardado());
  return aviso;
}

/** Tema y efecto descifrado: claves de nivel superior, valen para todos los proyectos. */
export const temaGuardado = (): TemaId => buscarTema(String(readConfig().tema ?? ""))?.id ?? "orobas";
/** En memoria: se consulta en cada cuadro dibujado; se relee al abrir el proyecto. */
let descifrado: boolean | undefined;
export const descifradoGuardado = (): boolean => (descifrado ??= readConfig().descifrado !== false);

function guardarGeneral(clave: string, valor: unknown): string | undefined {
  const config = readConfig();
  config[clave] = valor;
  return writeConfig(config);
}
export const guardarTema = (id: TemaId) => guardarGeneral("tema", id);
export const guardarDescifrado = (valor: boolean) => { descifrado = valor; return guardarGeneral("descifrado", valor); };

/** Novedades vistas (por máquina). */
export const novedadesVistas = (): string[] => {
  const v = readConfig().novedades;
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
};
export const marcarNovedades = (ids: string[]) => guardarGeneral("novedades", [...new Set([...novedadesVistas(), ...ids])]);
/** Primera vez en la máquina: sin clave «novedades» y sin ningún proyecto guardado. */
export const sinHistoria = (): boolean => { const c = readConfig(); return c.novedades === undefined && !Object.keys(proyectos(c)).length; };

/** Lo que /ultra recuerda (general, no por proyecto); sin «harnesses» se usan todos los instalados. */
export interface UltraGuardado { harnesses?: string[]; partes: number | "auto"; modo: "repo" | "objetivo" }
export const ULTRA_POR_DEFECTO: UltraGuardado = { partes: "auto", modo: "repo" };
export function ultraGuardado(): UltraGuardado {
  const crudo = readConfig().ultra;
  if (!crudo || typeof crudo !== "object" || Array.isArray(crudo)) return { ...ULTRA_POR_DEFECTO };
  const { harnesses, partes, modo } = crudo as Record<string, unknown>;
  const ids = Array.isArray(harnesses) ? harnesses.filter((h): h is string => typeof h === "string" && /^[a-z]+$/.test(h)) : [];
  return {
    ...(ids.length ? { harnesses: ids } : {}),
    partes: typeof partes === "number" && Number.isInteger(partes) && partes >= 2 && partes <= 6 ? partes : "auto",
    modo: modo === "objetivo" ? "objetivo" : "repo",
  };
}
export const guardarUltra = (valor: UltraGuardado) => guardarGeneral("ultra", valor);

/** Abre el proyecto (su ruta real, también dentro de Docker) y aplica su idioma. */
export function abrirProyecto(path: string): void {
  proyecto = path;
  descifrado = undefined;
  aplicarIdioma(idiomaGuardado());
}
