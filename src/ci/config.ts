// Configuración de la corrida de CI (.orobas/ci.yml): esquema, valores por defecto, variables de entorno y banderas
// que la pisan, el alcance expandido y su huella (lo que se autoriza), y las identidades de prueba resueltas desde
// el entorno. Todo error de configuración sale junto, con archivo, línea y columna, y nunca con el valor de un secreto.
//
// Referencia completa: docs/ci.md («Referencia de la configuración»).
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { isIP } from "node:net";
import { isAbsolute, join, relative } from "node:path";
import { SEVERITIES } from "../findings.ts";
import { MODOS_TRAZAS, type ModoTrazas } from "../privacidad-trazas.ts";
import { hostPort, parseRule, type ScopeRule } from "../scope.ts";
import { ErrorYaml, leerYaml, type Posicion } from "./yaml.ts";

export const ARCHIVO_POR_DEFECTO = ".orobas/ci.yml";
export const SUPRESIONES_POR_DEFECTO = ".orobas/supresiones.yml";

export type Severidad = (typeof SEVERITIES)[number];
export const PERFILES = ["general", "api", "web", "superficie", "completo"] as const;
export type Perfil = (typeof PERFILES)[number];

export interface RefSecreto {
  env: string;
  /** Cómo va el valor en la cabecera: «Bearer {}». Sin esto, el valor tal cual. */
  formato?: string;
}

export interface ReglaCi {
  tipo: "url" | "host" | "cidr";
  /** El texto del archivo antes de expandir variables: identifica el destino entre corridas y entre entornos. */
  literal: string;
  puertos?: number[];
  nombre?: string;
  /** Patrones que tiene que cumplir el valor expandido de una regla con variables. */
  permitido?: string[];
  ruta: string;
}

export interface LoginCi {
  url: string;
  cuerpo: Record<string, unknown>;
  /** Ruta con puntos al token en la respuesta JSON («data.token»). */
  token?: string;
  /** Guardar las cookies que pone la respuesta en vez de un token. */
  cookie: boolean;
  cabecera: string;
  formato: string;
}

export interface IdentidadCi {
  nombre: string;
  cabeceras?: Record<string, RefSecreto>;
  login?: LoginCi;
  ruta: string;
}

export interface ConfigCi {
  version: 1;
  /** Ruta del archivo tal como se pidió, relativa al repositorio si se puede. */
  archivo: string;
  /** Texto del archivo, para la huella de la configuración. */
  fuente: string;
  /** Commit del que se leyó, si fue de git (--config-ref). */
  ref?: string;
  nombre: string;
  alcance: ReglaCi[];
  excluir: ReglaCi[];
  comprobarObjetivo: boolean;
  identidades: IdentidadCi[];
  evaluacion: {
    perfil: Perfil;
    consigna: string;
    capacidades: "bounty" | "pentest";
    soloLectura: boolean;
    escaneres: boolean;
    soloCambios: { activo: "auto" | "si" | "no"; base?: string; acotarAlcance: boolean; rutasSiempre: string[] };
  };
  presupuesto: { usd: number; minutos: number; verificacionUsd: number; porCandidatoUsd: number; peticiones?: number; ritmo?: number };
  modelo: { nombre?: string; tarifas?: { input: number; output: number; cacheRead: number; cacheWrite: number }; router?: "auto" | "fijo" };
  trazas?: ModoTrazas;
  politica: { fallarDesde: Severidad | "nunca"; soloNuevos: boolean };
  lineaBase: { supresiones: string; retestAusentes: boolean };
  salidas: { carpeta: string; junit: boolean; sarifCandidatos: boolean };
  posiciones: Map<string, Posicion>;
}

/** Lo que se puede pisar desde la línea de comandos (gana sobre el entorno, que gana sobre el archivo). */
export interface Banderas {
  presupuestoUsd?: string;
  minutos?: string;
  modelo?: string;
  fallarDesde?: string;
  salida?: string;
  soloCambios?: string;
  soloLectura?: boolean;
  junit?: boolean;
  trazas?: string;
}

export interface Problema {
  ruta: string;
  mensaje: string;
  linea?: number;
  columna?: number;
}

export class ErrorConfig extends Error {
  readonly problemas: Problema[];
  readonly archivo: string;
  constructor(archivo: string, problemas: Problema[]) {
    super(problemas.map((p) => `${archivo}${p.linea ? `:${p.linea}:${p.columna ?? 1}` : ""}: ${p.mensaje}`).join("\n"));
    this.archivo = archivo;
    this.problemas = problemas;
  }
}

/** Distancia de edición, para sugerir la clave que se quiso escribir. */
function distancia(a: string, b: string): number {
  const fila = Array.from({ length: b.length + 1 }, (_, k) => k);
  for (let i = 1; i <= a.length; i++) {
    let previo = fila[0]!;
    fila[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const guardado = fila[j]!;
      fila[j] = Math.min(fila[j]! + 1, fila[j - 1]! + 1, previo + (a[i - 1] === b[j - 1] ? 0 : 1));
      previo = guardado;
    }
  }
  return fila[b.length]!;
}

const sugerencia = (clave: string, validas: string[]) => {
  const cerca = validas.map((v) => [v, distancia(clave.toLowerCase(), v)] as const).sort((a, b) => a[1] - b[1])[0];
  return cerca && cerca[1] <= Math.max(2, Math.floor(clave.length / 3)) ? ` (¿quisiste decir «${cerca[0]}»?)` : "";
};

const tipoDe = (valor: unknown) => (valor === null ? "vacío" : Array.isArray(valor) ? "una lista" : typeof valor === "object" ? "un mapa" : typeof valor === "string" ? `«${valor.length > 40 ? `${valor.slice(0, 40)}…` : valor}»` : String(valor));

/** Lector con los problemas acumulados: cada «pedir» devuelve el valor o undefined y anota qué estuvo mal. */
class Lector {
  readonly problemas: Problema[] = [];
  readonly posiciones: Map<string, Posicion>;
  constructor(posiciones: Map<string, Posicion>) {
    this.posiciones = posiciones;
  }

  error(ruta: string, mensaje: string): undefined {
    const pos = this.posiciones.get(ruta) ?? this.posiciones.get(ruta.replace(/(\.[^.[]+|\[\d+\])$/, ""));
    this.problemas.push({ ruta, mensaje: `«${ruta || "(raíz)"}» ${mensaje}`, linea: pos?.linea, columna: pos?.columna });
    return undefined;
  }

  mapa(valor: unknown, ruta: string, claves: string[]): Record<string, unknown> | undefined {
    if (valor === undefined || valor === null) return undefined;
    if (typeof valor !== "object" || Array.isArray(valor)) return this.error(ruta, `tiene que ser un mapa (clave: valor) y es ${tipoDe(valor)}`);
    for (const clave of Object.keys(valor)) if (!claves.includes(clave)) this.error(ruta ? `${ruta}.${clave}` : clave, `no es una clave conocida${sugerencia(clave, claves)}. Válidas: ${claves.join(", ")}`);
    return valor as Record<string, unknown>;
  }

  lista(valor: unknown, ruta: string): unknown[] | undefined {
    if (valor === undefined || valor === null) return undefined;
    if (!Array.isArray(valor)) return this.error(ruta, `tiene que ser una lista y es ${tipoDe(valor)}`);
    return valor;
  }

  texto(valor: unknown, ruta: string, opciones: { vacio?: boolean } = {}): string | undefined {
    if (valor === undefined || valor === null) return undefined;
    if (typeof valor === "number") valor = String(valor);
    if (typeof valor !== "string") return this.error(ruta, `tiene que ser un texto y es ${tipoDe(valor)}`);
    if (!opciones.vacio && !valor.trim()) return this.error(ruta, "está vacío");
    return valor;
  }

  numero(valor: unknown, ruta: string, minimo: number, maximo: number, entero = false): number | undefined {
    if (valor === undefined || valor === null) return undefined;
    const n = typeof valor === "string" && /^\s*\d+([.,]\d+)?\s*$/.test(valor) ? Number(valor.replace(",", ".")) : valor;
    if (typeof n !== "number" || !Number.isFinite(n)) return this.error(ruta, `tiene que ser un número y es ${tipoDe(valor)}`);
    if (entero && !Number.isInteger(n)) return this.error(ruta, `tiene que ser un entero y es ${n}`);
    if (n < minimo || n > maximo) return this.error(ruta, `tiene que estar entre ${minimo} y ${maximo} (vino ${n})`);
    return n;
  }

  booleano(valor: unknown, ruta: string): boolean | undefined {
    if (valor === undefined || valor === null) return undefined;
    if (typeof valor === "boolean") return valor;
    if (typeof valor === "string" && /^(si|sí|true|on|1)$/i.test(valor.trim())) return true;
    if (typeof valor === "string" && /^(no|false|off|0)$/i.test(valor.trim())) return false;
    return this.error(ruta, `tiene que ser true o false y es ${tipoDe(valor)}`);
  }

  opcion<T extends string>(valor: unknown, ruta: string, opciones: readonly T[], normalizar = (v: string) => v): T | undefined {
    const texto = this.texto(valor, ruta);
    if (texto === undefined) return undefined;
    const limpio = normalizar(texto.trim().toLowerCase());
    if (!(opciones as readonly string[]).includes(limpio)) return this.error(ruta, `tiene que ser ${opciones.map((o) => `«${o}»`).join(", ")} y es «${texto}»${sugerencia(limpio, [...opciones])}`);
    return limpio as T;
  }
}

const sinAcentos = (texto: string) => texto.normalize("NFD").replace(/[̀-ͯ]/g, "");
const VARIABLE = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
const NOMBRE_ENV = /^[A-Za-z_][A-Za-z0-9_]*$/;
const NOMBRE = /^[a-z0-9][a-z0-9_-]{0,39}$/;

function refSecreto(l: Lector, valor: unknown, ruta: string, permitirLiteral: boolean): RefSecreto | unknown {
  if (valor && typeof valor === "object" && !Array.isArray(valor)) {
    const m = l.mapa(valor, ruta, ["env", "formato"]);
    const env = l.texto(m?.env, `${ruta}.env`);
    if (env === undefined) return l.error(ruta, "necesita «env»: el nombre de la variable de entorno (o secreto del CI) con el valor");
    if (!NOMBRE_ENV.test(env)) return l.error(`${ruta}.env`, `«${env}» no es un nombre de variable de entorno válido`);
    const formato = l.texto(m?.formato, `${ruta}.formato`);
    if (formato !== undefined && !formato.includes("{}")) return l.error(`${ruta}.formato`, "tiene que llevar «{}» donde va el valor (por ejemplo «Bearer {}»)");
    return { env, ...(formato ? { formato } : {}) };
  }
  if (!permitirLiteral) return l.error(ruta, "no puede ir escrito en el archivo: las credenciales van por referencia a una variable de entorno o secreto del CI, con «{ env: NOMBRE }»");
  return valor;
}

/** Claves de un cuerpo de login que no pueden ir literales. */
const CLAVE_SENSIBLE = /pass|clave|contrase|secret|token|key|pin|otp|codigo|code/i;

function leerRegla(l: Lector, valor: unknown, ruta: string): ReglaCi | undefined {
  const m = l.mapa(valor, ruta, ["url", "host", "cidr", "puertos", "nombre", "permitido"]);
  if (!m) return valor === null || valor === undefined ? l.error(ruta, "está vacía") : undefined;
  const tipos = (["url", "host", "cidr"] as const).filter((tipo) => m[tipo] !== undefined && m[tipo] !== null);
  if (tipos.length !== 1) return l.error(ruta, tipos.length ? `lleva ${tipos.join(" y ")}: cada regla es una sola cosa (url, host o cidr)` : "necesita «url», «host» o «cidr»");
  const tipo = tipos[0]!;
  const literal = l.texto(m[tipo], `${ruta}.${tipo}`)?.trim();
  if (literal === undefined) return undefined;
  const puertos = l.lista(m.puertos, `${ruta}.puertos`)?.map((p, k) => l.numero(p, `${ruta}.puertos[${k}]`, 1, 65535, true));
  if (puertos?.some((p) => p === undefined)) return undefined;
  if (puertos && !puertos.length) return l.error(`${ruta}.puertos`, "está vacía: sacala para todos los puertos, o nombrá cuáles");
  if (puertos && tipo === "url") return l.error(`${ruta}.puertos`, "no va con «url»: el puerto va en la URL (https://host:8443)");
  const nombre = l.texto(m.nombre, `${ruta}.nombre`);
  if (nombre !== undefined && !NOMBRE.test(nombre)) return l.error(`${ruta}.nombre`, "sólo minúsculas, dígitos, «-» y «_» (hasta 40)");
  const permitido = l.lista(m.permitido, `${ruta}.permitido`)?.map((p, k) => l.texto(p, `${ruta}.permitido[${k}]`)?.trim().toLowerCase());
  if (permitido?.some((p) => p === undefined)) return undefined;
  const conVariables = [...literal.matchAll(VARIABLE)].length > 0;
  if (/\$(?!\{[A-Za-z_][A-Za-z0-9_]*\})/.test(literal)) return l.error(`${ruta}.${tipo}`, "tiene un «$» que no es una variable «${NOMBRE}»");
  if (conVariables && !permitido?.length) return l.error(`${ruta}.permitido`, "falta: una regla con variables necesita la lista de valores permitidos (por ejemplo «https://pr-*.preview.ejemplo.com»), así la variable no puede apuntar a cualquier lado");
  if (!conVariables && permitido) return l.error(`${ruta}.permitido`, "sólo va en reglas con variables «${…}»");
  for (const [k, patron] of (permitido ?? []).entries()) {
    const problema = problemaDePatron(patron!);
    if (problema) l.error(`${ruta}.permitido[${k}]`, problema);
  }
  if (!conVariables) {
    const problema = problemaDeRegla(tipo, literal, puertos as number[] | undefined);
    if (problema) return l.error(`${ruta}.${tipo}`, problema);
  }
  return { tipo, literal, ...(puertos ? { puertos: [...new Set(puertos as number[])].sort((a, b) => a - b) } : {}), ...(nombre ? { nombre } : {}), ...(permitido ? { permitido: permitido as string[] } : {}), ruta };
}

/** Dominios donde cualquiera publica (un «*.vercel.app» autorizaría las apps de todo el mundo). */
const ALOJAMIENTO_COMPARTIDO = /(^|\.)(github\.io|vercel\.app|netlify\.app|herokuapp\.com|amazonaws\.com|cloudfront\.net|azurewebsites\.net|azurestaticapps\.net|appspot\.com|firebaseapp\.com|web\.app|pages\.dev|workers\.dev|onrender\.com|fly\.dev|ngrok\.io|ngrok-free\.app|run\.app|railway\.app|up\.railway\.app|trycloudflare\.com)$/;

/** Por qué un patrón de «permitido» no sirve; undefined si sirve. */
export function problemaDePatron(patron: string): string | undefined {
  const m = /^(https?:\/\/)?([a-z0-9*.-]+)(:(?:\d{1,5}|\*))?$/.exec(patron);
  if (!m) return `«${patron}» no es un patrón de origen válido: [esquema://]host[:puerto], con «*» en lugar de una parte de una etiqueta (o del puerto)`;
  const etiquetas = m[2]!.split(".");
  if (etiquetas.some((e) => !e)) return `«${patron}» tiene una etiqueta vacía`;
  const ultimaConComodin = etiquetas.findLastIndex((e) => e.includes("*"));
  const fijas = etiquetas.slice(ultimaConComodin + 1);
  if (ultimaConComodin >= 0 && fijas.length < 2) return `«${patron}» es demasiado amplio: después del «*» tiene que quedar el dominio entero (por ejemplo «https://pr-*.preview.ejemplo.com»)`;
  if (ultimaConComodin >= 0 && ALOJAMIENTO_COMPARTIDO.test(fijas.join(".")) && etiquetas.slice(0, ultimaConComodin + 1).some((e) => e === "*")) return `«${patron}» autorizaría lo de cualquiera en ${fijas.join(".")} (alojamiento compartido): fijá una parte propia en la etiqueta, por ejemplo «miapp-*-miequipo.${fijas.join(".")}»`;
  return undefined;
}

/** Por qué un valor (ya expandido) no sirve como regla de alcance de CI; undefined si sirve. */
export function problemaDeRegla(tipo: ReglaCi["tipo"], valor: string, puertos?: number[]): string | undefined {
  const v = valor.trim().toLowerCase();
  if (tipo === "url") {
    if (!/^https?:\/\/[^/]/.test(v)) return `«${valor}» no es una URL http(s)://host[:puerto][/ruta]`;
    let url: URL;
    try { url = new URL(v); } catch { return `«${valor}» no es una URL válida`; }
    if (url.username || url.password) return "la URL lleva usuario o contraseña: las credenciales van en «identidades»";
    if (url.search || url.hash) return "la URL de alcance no lleva consulta (?…) ni fragmento (#…)";
    if (url.hostname.includes("*")) return "en CI el alcance es explícito: sin comodines";
    return undefined;
  }
  if (tipo === "host") {
    if (v.includes("*")) return "en CI el alcance es explícito: nombrá cada host (sin comodines «*.dominio»); para entornos efímeros usá una variable con «permitido»";
    if (/[/:]/.test(v) && !isIP(v)) return `«${valor}» no es un host: sin esquema, ruta ni puerto (el puerto va en «puertos»)`;
    try {
      const regla = parseRule(v);
      if (regla.kind !== "host") return `«${valor}» no es un host`;
    } catch (error) {
      return (error as Error).message;
    }
    return undefined;
  }
  const m = /^([0-9a-f:.]+)\/(\d{1,3})$/.exec(v);
  if (!m || !isIP(m[1]!)) return `«${valor}» no es una red CIDR (por ejemplo 10.20.0.0/28)`;
  const bits = Number(m[2]);
  const v6 = isIP(m[1]!) === 6;
  if (bits > (v6 ? 128 : 32)) return `/${bits} no es un prefijo válido`;
  if (bits < (v6 ? 64 : 16)) return `la red /${bits} es demasiado amplia para CI (mínimo /${v6 ? 64 : 16}): partila en redes más chicas`;
  if (puertos) {
    if (v6) return "una red IPv6 con «puertos» no se puede expandir: usá hosts con puertos";
    const cantidad = 2 ** (32 - bits) * puertos.length;
    if (cantidad > 4096) return `la red /${bits} con ${puertos.length} puerto(s) son ${cantidad} destinos: con «puertos» hasta 4096 (usá una red más chica o sacá «puertos»)`;
  }
  return undefined;
}

function leerIdentidad(l: Lector, valor: unknown, ruta: string): IdentidadCi | undefined {
  const m = l.mapa(valor, ruta, ["nombre", "cabeceras", "login"]);
  if (!m) return valor === null || valor === undefined ? l.error(ruta, "está vacía") : undefined;
  const nombre = l.texto(m.nombre, `${ruta}.nombre`);
  if (nombre === undefined) return l.error(ruta, "necesita «nombre»");
  if (!NOMBRE.test(nombre)) return l.error(`${ruta}.nombre`, "sólo minúsculas, dígitos, «-» y «_» (hasta 40)");
  const tiene = ["cabeceras", "login"].filter((k) => m[k] !== undefined && m[k] !== null);
  if (tiene.length !== 1) return l.error(ruta, tiene.length ? "lleva «cabeceras» y «login»: elegí una" : "necesita «cabeceras» (valores desde variables de entorno) o «login»");
  if (m.cabeceras !== undefined) {
    const c = m.cabeceras;
    if (!c || typeof c !== "object" || Array.isArray(c) || !Object.keys(c).length) return l.error(`${ruta}.cabeceras`, "tiene que ser un mapa no vacío: nombre de cabecera → { env: VARIABLE }");
    const cabeceras: Record<string, RefSecreto> = {};
    for (const [clave, v] of Object.entries(c)) {
      if (!/^[A-Za-z0-9-]+$/.test(clave)) {
        l.error(`${ruta}.cabeceras.${clave}`, "no es un nombre de cabecera HTTP válido");
        continue;
      }
      const ref = refSecreto(l, v, `${ruta}.cabeceras.${clave}`, false) as RefSecreto | undefined;
      if (ref) cabeceras[clave.toLowerCase()] = ref;
    }
    return { nombre, cabeceras, ruta };
  }
  const lg = l.mapa(m.login, `${ruta}.login`, ["url", "cuerpo", "token", "cookie", "cabecera", "formato"]);
  if (!lg) return undefined;
  const url = l.texto(lg.url, `${ruta}.login.url`)?.trim();
  if (url === undefined) return l.error(`${ruta}.login`, "necesita «url»");
  const cuerpoMapa = lg.cuerpo;
  if (!cuerpoMapa || typeof cuerpoMapa !== "object" || Array.isArray(cuerpoMapa)) return l.error(`${ruta}.login.cuerpo`, "tiene que ser un mapa con los campos del inicio de sesión (los secretos con { env: VARIABLE })");
  const cuerpo: Record<string, unknown> = {};
  for (const [clave, v] of Object.entries(cuerpoMapa)) {
    const aqui = `${ruta}.login.cuerpo.${clave}`;
    if (v && typeof v === "object" && !Array.isArray(v)) cuerpo[clave] = refSecreto(l, v, aqui, false);
    else if (CLAVE_SENSIBLE.test(clave) && typeof v === "string") l.error(aqui, "parece un secreto y no puede ir escrito en el archivo: usá { env: VARIABLE }");
    else cuerpo[clave] = v;
  }
  const token = l.texto(lg.token, `${ruta}.login.token`);
  const cookie = l.booleano(lg.cookie, `${ruta}.login.cookie`) ?? false;
  if (!token && !cookie) return l.error(`${ruta}.login`, "necesita «token» (la ruta al token en la respuesta JSON, por ejemplo «data.token») o «cookie: true»");
  if (token && cookie) return l.error(`${ruta}.login`, "lleva «token» y «cookie»: elegí una");
  if (token && !/^[A-Za-z0-9_$-]+(\.[A-Za-z0-9_$-]+)*$/.test(token)) return l.error(`${ruta}.login.token`, "tiene que ser una ruta con puntos («data.token»)");
  const cabecera = (l.texto(lg.cabecera, `${ruta}.login.cabecera`) ?? (cookie ? "cookie" : "authorization")).toLowerCase();
  const formato = l.texto(lg.formato, `${ruta}.login.formato`) ?? (cookie ? "{}" : "Bearer {}");
  if (!formato.includes("{}")) return l.error(`${ruta}.login.formato`, "tiene que llevar «{}» donde va el token");
  return { nombre, login: { url, cuerpo, ...(token ? { token } : {}), cookie, cabecera, formato }, ruta };
}

/** «si», «no», «auto»: el modo «sólo lo que cambió». */
const normalizarSiNo = (v: string) => (/^(si|sí|true|on)$/.test(v) ? "si" : /^(no|false|off)$/.test(v) ? "no" : v);

/** Lee el archivo, del disco o de un commit (para los PRs de forks: la configuración de la rama base). */
export function leerFuente(cwd: string, archivo: string, ref?: string): string | undefined {
  if (ref) {
    const ruta = isAbsolute(archivo) ? relative(cwd, archivo) : archivo;
    try {
      return execFileSync("git", ["-C", cwd, "show", `${ref}:./${ruta.replace(/^\.\//, "")}`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 4 << 20 });
    } catch (error) {
      const salida = String((error as { stderr?: string }).stderr ?? "");
      if (/does not exist|exists on disk, but not in|no existe|bad revision|unknown revision|invalid object name/i.test(salida)) return undefined;
      throw new ErrorConfig(archivo, [{ ruta: "", mensaje: `No pude leer ${archivo} de ${ref} con git: ${salida.split("\n")[0] || (error as Error).message}` }]);
    }
  }
  const absoluta = isAbsolute(archivo) ? archivo : join(cwd, archivo);
  return existsSync(absoluta) ? readFileSync(absoluta, "utf8") : undefined;
}

export function parsearDocumento(archivo: string, fuente: string): { valor: unknown; posiciones: Map<string, Posicion> } {
  if (/\.json$/i.test(archivo)) {
    try {
      return { valor: JSON.parse(fuente), posiciones: new Map() };
    } catch (error) {
      throw new ErrorConfig(archivo, [{ ruta: "", mensaje: `JSON inválido: ${(error as Error).message}` }]);
    }
  }
  try {
    return leerYaml(fuente);
  } catch (error) {
    if (error instanceof ErrorYaml) throw new ErrorConfig(archivo, [{ ruta: "", mensaje: error.message.replace(/^\d+:\d+: /, ""), linea: error.linea, columna: error.columna }]);
    throw error;
  }
}

export interface Carga {
  cwd: string;
  archivo: string;
  ref?: string;
  env: NodeJS.ProcessEnv;
  banderas?: Banderas;
}

/** Carga y valida la configuración. Lanza ErrorConfig con todos los problemas juntos. */
export function cargarConfig({ cwd, archivo, ref, env, banderas = {} }: Carga): ConfigCi {
  const fuente = leerFuente(cwd, archivo, ref);
  if (fuente === undefined) {
    throw new ErrorConfig(archivo, [{ ruta: "", mensaje: `No existe ${archivo}${ref ? ` en ${ref}` : ""}. Sin un alcance explícito y versionado, la corrida no arranca: creá el archivo (cyber ci ejemplo muestra uno) o indicá otro con --config.` }]);
  }
  const { valor, posiciones } = parsearDocumento(archivo, fuente);
  const l = new Lector(posiciones);
  const raiz = l.mapa(valor, "", ["version", "nombre", "objetivo", "identidades", "evaluacion", "presupuesto", "modelo", "trazas", "politica", "linea_base", "salidas"]);
  if (!raiz) throw new ErrorConfig(archivo, l.problemas.length ? l.problemas : [{ ruta: "", mensaje: "El archivo está vacío: hace falta al menos version, objetivo.alcance y presupuesto." }]);

  const version = l.numero(raiz.version, "version", 1, 1, true);
  if (raiz.version === undefined) l.error("version", "falta: poné «version: 1»");

  const nombre = l.texto(raiz.nombre, "nombre") ?? "orobas-ci";
  if (!NOMBRE.test(nombre)) l.error("nombre", "sólo minúsculas, dígitos, «-» y «_» (hasta 40): nombra esta configuración en el comentario del PR y en el SARIF");

  const objetivo = l.mapa(raiz.objetivo, "objetivo", ["alcance", "excluir", "comprobar"]);
  if (!objetivo) l.error("objetivo", "falta: sin «objetivo.alcance» no hay nada autorizado y la corrida no arranca");
  const alcanceLista = l.lista(objetivo?.alcance, "objetivo.alcance");
  if (objetivo && (!alcanceLista || !alcanceLista.length)) l.error("objetivo.alcance", "falta o está vacío: sin alcance explícito la corrida no arranca");
  const alcance = (alcanceLista ?? []).map((r, k) => leerRegla(l, r, `objetivo.alcance[${k}]`)).filter((r): r is ReglaCi => !!r);
  const excluir = (l.lista(objetivo?.excluir, "objetivo.excluir") ?? []).map((r, k) => leerRegla(l, r, `objetivo.excluir[${k}]`)).filter((r): r is ReglaCi => !!r);
  const comprobarObjetivo = l.booleano(objetivo?.comprobar, "objetivo.comprobar") ?? true;
  const nombresReglas = alcance.map((r) => r.nombre).filter(Boolean);
  for (const repetido of nombresReglas.filter((n, k) => nombresReglas.indexOf(n) !== k)) l.error("objetivo.alcance", `el nombre «${repetido}» está repetido`);

  const identidades = (l.lista(raiz.identidades, "identidades") ?? []).map((v, k) => leerIdentidad(l, v, `identidades[${k}]`)).filter((v): v is IdentidadCi => !!v);
  const nombresId = identidades.map((i) => i.nombre);
  for (const repetido of nombresId.filter((n, k) => nombresId.indexOf(n) !== k)) l.error("identidades", `la identidad «${repetido}» está repetida`);

  const ev = l.mapa(raiz.evaluacion, "evaluacion", ["perfil", "consigna", "capacidades", "solo_lectura", "escaneres", "solo_cambios"]);
  const perfil = l.opcion(ev?.perfil, "evaluacion.perfil", PERFILES) ?? "general";
  const consigna = l.texto(ev?.consigna, "evaluacion.consigna", { vacio: true })?.trim() ?? "";
  if (consigna.length > 8000) l.error("evaluacion.consigna", `es muy larga (${consigna.length} caracteres; hasta 8000)`);
  const capacidades = l.opcion(ev?.capacidades, "evaluacion.capacidades", ["bounty", "pentest"] as const) ?? "bounty";
  const sc = l.mapa(ev?.solo_cambios, "evaluacion.solo_cambios", ["activo", "base", "acotar_alcance", "rutas_siempre"]);
  const activo = l.opcion(sc?.activo === true ? "si" : sc?.activo === false ? "no" : sc?.activo, "evaluacion.solo_cambios.activo", ["auto", "si", "no"] as const, normalizarSiNo) ?? "auto";
  const rutasSiempre = (l.lista(sc?.rutas_siempre, "evaluacion.solo_cambios.rutas_siempre") ?? []).map((r, k) => {
    const t = l.texto(r, `evaluacion.solo_cambios.rutas_siempre[${k}]`);
    if (t !== undefined && !t.startsWith("/")) return l.error(`evaluacion.solo_cambios.rutas_siempre[${k}]`, "tiene que empezar con «/»");
    return t;
  }).filter((r): r is string => !!r);

  const pr = l.mapa(raiz.presupuesto, "presupuesto", ["usd", "minutos", "verificacion_usd", "por_candidato_usd", "peticiones", "ritmo"]);
  if (!pr) l.error("presupuesto", "falta: los topes de gasto y de tiempo son obligatorios en CI (presupuesto.usd y presupuesto.minutos)");
  let usd = l.numero(pr?.usd, "presupuesto.usd", 0.01, 1000);
  if (pr && pr.usd === undefined) l.error("presupuesto.usd", "falta: el tope de gasto en USD de la corrida entera (agente y verificador)");
  let minutos = l.numero(pr?.minutos, "presupuesto.minutos", 1, 360);
  if (pr && pr.minutos === undefined) l.error("presupuesto.minutos", "falta: el tope de tiempo de la corrida, en minutos");
  const verificacionUsd = l.numero(pr?.verificacion_usd, "presupuesto.verificacion_usd", 0, 1000);
  const porCandidatoUsd = l.numero(pr?.por_candidato_usd, "presupuesto.por_candidato_usd", 0.01, 100) ?? 0.5;
  const peticiones = l.numero(pr?.peticiones, "presupuesto.peticiones", 1, 1_000_000, true);
  const ritmo = l.numero(pr?.ritmo, "presupuesto.ritmo", 0.1, 1000);

  const mo = l.mapa(raiz.modelo, "modelo", ["nombre", "tarifas", "router"]);
  let modeloNombre = l.texto(mo?.nombre, "modelo.nombre")?.trim();
  const ta = l.mapa(mo?.tarifas, "modelo.tarifas", ["entrada", "salida", "cache_lectura", "cache_escritura"]);
  let tarifas: ConfigCi["modelo"]["tarifas"];
  if (ta) {
    const entrada = l.numero(ta.entrada, "modelo.tarifas.entrada", 0, 10_000);
    const salida = l.numero(ta.salida, "modelo.tarifas.salida", 0, 10_000);
    if (entrada === undefined || salida === undefined) l.error("modelo.tarifas", "necesita «entrada» y «salida» (USD por millón de tokens)");
    else tarifas = { input: entrada, output: salida, cacheRead: l.numero(ta.cache_lectura, "modelo.tarifas.cache_lectura", 0, 10_000) ?? entrada, cacheWrite: l.numero(ta.cache_escritura, "modelo.tarifas.cache_escritura", 0, 10_000) ?? 0 };
  }
  const router = l.opcion(mo?.router, "modelo.router", ["auto", "fijo"] as const);

  let trazas = l.opcion(raiz.trazas, "trazas", MODOS_TRAZAS);

  const po = l.mapa(raiz.politica, "politica", ["fallar_desde", "solo_nuevos"]);
  const umbrales = [...SEVERITIES, "nunca"] as const;
  let fallarDesde = l.opcion(po?.fallar_desde, "politica.fallar_desde", umbrales, sinAcentos) ?? "alta";
  const soloNuevos = l.booleano(po?.solo_nuevos, "politica.solo_nuevos") ?? false;

  const lb = l.mapa(raiz.linea_base, "linea_base", ["supresiones", "retest_ausentes"]);
  const supresiones = l.texto(lb?.supresiones, "linea_base.supresiones") ?? SUPRESIONES_POR_DEFECTO;
  const retestAusentes = l.booleano(lb?.retest_ausentes, "linea_base.retest_ausentes") ?? true;

  const sa = l.mapa(raiz.salidas, "salidas", ["carpeta", "junit", "sarif_candidatos"]);
  let carpeta = l.texto(sa?.carpeta, "salidas.carpeta") ?? "orobas-ci";
  let junit = l.booleano(sa?.junit, "salidas.junit") ?? false;
  const sarifCandidatos = l.booleano(sa?.sarif_candidatos, "salidas.sarif_candidatos") ?? false;
  let soloLectura = l.booleano(ev?.solo_lectura, "evaluacion.solo_lectura") ?? false;
  const escaneres = l.booleano(ev?.escaneres, "evaluacion.escaneres") ?? false;
  let soloCambios: "auto" | "si" | "no" = activo;

  // Entorno y banderas: ganan sobre el archivo (las banderas sobre el entorno). Nunca tocan el alcance.
  const otro = new Lector(new Map());
  const de = (bandera: string | undefined, variable: string) => (bandera !== undefined ? { v: bandera, donde: `--${variable.toLowerCase().replace(/^orobas_ci_/, "").replace(/_/g, "-")}` } : env[variable] !== undefined && env[variable] !== "" ? { v: env[variable]!, donde: variable } : undefined);
  const pisar = <T>(fuenteValor: { v: string; donde: string } | undefined, leer: (v: string, donde: string) => T | undefined, actual: T): T => (fuenteValor ? leer(fuenteValor.v, fuenteValor.donde) ?? actual : actual);
  usd = pisar(de(banderas.presupuestoUsd, "OROBAS_CI_PRESUPUESTO_USD"), (v, d) => otro.numero(v, d, 0.01, 1000), usd);
  minutos = pisar(de(banderas.minutos, "OROBAS_CI_MINUTOS"), (v, d) => otro.numero(v, d, 1, 360), minutos);
  modeloNombre = pisar(de(banderas.modelo, "OROBAS_CI_MODELO"), (v, d) => otro.texto(v, d)?.trim(), modeloNombre);
  fallarDesde = pisar(de(banderas.fallarDesde, "OROBAS_CI_FALLAR_DESDE"), (v, d) => otro.opcion(v, d, umbrales, sinAcentos), fallarDesde);
  carpeta = pisar(de(banderas.salida, "OROBAS_CI_SALIDA"), (v, d) => otro.texto(v, d), carpeta);
  soloCambios = pisar(de(banderas.soloCambios, "OROBAS_CI_SOLO_CAMBIOS"), (v, d) => otro.opcion(v, d, ["auto", "si", "no"] as const, normalizarSiNo), soloCambios);
  trazas = pisar(de(banderas.trazas, "OROBAS_CI_TRAZAS"), (v, d) => otro.opcion(v, d, MODOS_TRAZAS), trazas);
  soloLectura = banderas.soloLectura ?? pisar(de(undefined, "OROBAS_CI_SOLO_LECTURA"), (v, d) => otro.booleano(v, d), soloLectura);
  junit = banderas.junit ?? junit;
  for (const p of otro.problemas) l.problemas.push({ ruta: p.ruta, mensaje: p.mensaje.replace(/^«([^»]+)»/, "$1") });

  if (usd !== undefined && verificacionUsd !== undefined && verificacionUsd >= usd) l.error("presupuesto.verificacion_usd", `(${verificacionUsd}) tiene que ser menor que presupuesto.usd (${usd}): el resto es para explorar`);
  if (l.problemas.length || version === undefined || usd === undefined || minutos === undefined) throw new ErrorConfig(archivo, l.problemas.length ? l.problemas : [{ ruta: "", mensaje: "configuración incompleta" }]);

  return {
    version: 1,
    archivo,
    fuente,
    ...(ref ? { ref } : {}),
    nombre,
    alcance,
    excluir,
    comprobarObjetivo,
    identidades,
    evaluacion: { perfil, consigna, capacidades, soloLectura, escaneres, soloCambios: { activo: soloCambios, ...(sc?.base ? { base: String(sc.base) } : {}), acotarAlcance: l.booleano(sc?.acotar_alcance, "evaluacion.solo_cambios.acotar_alcance") ?? false, rutasSiempre } },
    presupuesto: { usd, minutos, verificacionUsd: verificacionUsd ?? Math.round(usd * 0.4 * 100) / 100, porCandidatoUsd, ...(peticiones ? { peticiones } : {}), ...(ritmo ? { ritmo } : {}) },
    modelo: { ...(modeloNombre ? { nombre: modeloNombre } : {}), ...(tarifas ? { tarifas } : {}), ...(router ? { router } : {}) },
    // Sin modo explícito (archivo, OROBAS_CI_TRAZAS o --trazas), una corrida de CI no arma material de entrenamiento:
    // corre sin operador mirando y con datos del equipo, así que compartir tiene que ser una decisión, no un default.
    trazas: trazas ?? "no",
    politica: { fallarDesde, soloNuevos },
    lineaBase: { supresiones, retestAusentes },
    salidas: { carpeta, junit, sarifCandidatos },
    posiciones,
  };
}

/** Forma canónica de una regla para la huella: lo que define a quién se le pega, no los nombres. */
const canonica = (r: ReglaCi) => ({ tipo: r.tipo, valor: r.literal.trim().toLowerCase().replace(/\/+$/, ""), puertos: r.puertos ?? null, permitido: r.permitido ? [...r.permitido].sort() : null });

/**
 * Huella del alcance: lo que autoriza quien confirma la corrida. Cubre las reglas tal como están escritas (con las
 * variables sin expandir y sus patrones permitidos) y las exclusiones; no cubre nombres, presupuesto ni consigna.
 * Si alguien cambia a quién se le pega, la huella cambia y la confirmación vieja deja de valer.
 */
export function huellaAlcance(config: Pick<ConfigCi, "alcance" | "excluir">): string {
  const orden = (a: { tipo: string; valor: string }, b: { tipo: string; valor: string }) => `${a.tipo}:${a.valor}`.localeCompare(`${b.tipo}:${b.valor}`);
  const forma = { v: 1, alcance: config.alcance.map(canonica).sort(orden), excluir: config.excluir.map(canonica).sort(orden) };
  return `sha256:${createHash("sha256").update(JSON.stringify(forma)).digest("hex").slice(0, 32)}`;
}

/** Huella del archivo entero (para el registro de la autorización). */
export const huellaArchivo = (fuente: string) => `sha256:${createHash("sha256").update(fuente).digest("hex").slice(0, 32)}`;

/** ¿El valor expandido cumple el patrón? «*» es una o más letras, dígitos o guiones dentro de una etiqueta. */
export function cumplePatron(valor: string, patron: string): boolean {
  const regex = new RegExp(`^${patron.replace(/[.+?^${}()|[\]\\/]/g, "\\$&").replace(/\*/g, "[a-z0-9-]+")}$`);
  return regex.test(valor);
}

export interface ReglaExpandida {
  regla: ReglaCi;
  valor: string;
  reglas: ScopeRule[];
  /** Origen para pedir la raíz (comprobación de llegada): una URL, o host:puerto. */
  origenes: string[];
}

/** Las reglas con las variables reemplazadas, validadas y convertidas al alcance del harness. */
export function expandirAlcance(config: Pick<ConfigCi, "alcance" | "excluir" | "archivo" | "posiciones">, env: NodeJS.ProcessEnv): { incluidas: ReglaExpandida[]; excluidas: ReglaExpandida[] } {
  const l = new Lector(config.posiciones);
  const expandir = (regla: ReglaCi): ReglaExpandida | undefined => {
    const faltan: string[] = [];
    const valor = regla.literal.replace(VARIABLE, (_todo, nombre: string) => {
      const v = env[nombre];
      if (v === undefined || v.trim() === "") faltan.push(nombre);
      return (v ?? "").trim();
    }).trim();
    const donde = `${regla.ruta}.${regla.tipo}`;
    if (faltan.length) return l.error(donde, `usa ${faltan.map((f) => `$\{${f}}`).join(", ")} y la variable no está definida o está vacía`);
    if (regla.permitido) {
      const problema = problemaDeRegla(regla.tipo, valor, regla.puertos);
      if (problema) return l.error(donde, `expandida: ${problema}`);
      const origen = regla.tipo === "url" ? (() => { const u = new URL(valor.toLowerCase()); return `${u.protocol}//${u.host}`; })() : valor.toLowerCase();
      const sinEsquema = origen.replace(/^https?:\/\//, "");
      const cumple = regla.permitido.some((p) => (/^https?:\/\//.test(p) ? cumplePatron(origen, p) : cumplePatron(sinEsquema, p)));
      if (!cumple) return l.error(donde, `expandida da «${origen}», que no cumple ninguno de los patrones permitidos (${regla.permitido.join(", ")}): no se toca`);
    }
    const reglas = reglasDe(regla.tipo, valor.toLowerCase(), regla.puertos);
    const origenes = regla.tipo === "url" ? [valor.replace(/\/+$/, "")] : regla.tipo === "host" ? (regla.puertos ?? [443, 80]).map((p) => hostPort(valor.toLowerCase(), String(p))) : [];
    return { regla, valor, reglas, origenes };
  };
  const incluidas = config.alcance.map(expandir).filter((r): r is ReglaExpandida => !!r);
  const excluidas = config.excluir.map(expandir).filter((r): r is ReglaExpandida => !!r);
  if (l.problemas.length) throw new ErrorConfig(config.archivo, l.problemas);
  return { incluidas, excluidas };
}

function reglasDe(tipo: ReglaCi["tipo"], valor: string, puertos?: number[]): ScopeRule[] {
  const nota = "CI: autorizado en el archivo versionado";
  if (tipo === "url") return [parseRule(valor, nota)];
  if (tipo === "host") return puertos ? puertos.map((p) => parseRule(hostPort(valor, String(p)), nota)) : [parseRule(valor, nota)];
  if (!puertos) return [parseRule(valor, nota)];
  const [base, bits] = valor.split("/") as [string, string];
  const inicio = base.split(".").reduce((n, parte) => (n << 8) + Number(parte), 0) >>> 0;
  const mascara = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  const red = (inicio & mascara) >>> 0;
  const reglas: ScopeRule[] = [];
  for (let k = 0; k < 2 ** (32 - Number(bits)); k++) {
    const ip = [(red + k) >>> 24, ((red + k) >>> 16) & 255, ((red + k) >>> 8) & 255, (red + k) & 255].join(".");
    for (const p of puertos) reglas.push(parseRule(`${ip}:${p}`, nota));
  }
  return reglas;
}

export interface IdentidadResuelta {
  nombre: string;
  /** Cabeceras ya armadas (con identidades de cabeceras) o undefined si sale de un login. */
  cabeceras?: Record<string, string>;
  login?: { url: string; cuerpo: Record<string, unknown>; token?: string; cookie: boolean; cabecera: string; formato: string };
  /** Los valores secretos que salieron del entorno: se tapan en todas las salidas. */
  secretos: string[];
}

/** Lee del entorno los valores de cada identidad. Lanza ErrorConfig con todas las variables que faltan (nunca con valores). */
export function resolverIdentidades(config: Pick<ConfigCi, "identidades" | "archivo" | "posiciones">, env: NodeJS.ProcessEnv): IdentidadResuelta[] {
  const l = new Lector(config.posiciones);
  const salida: IdentidadResuelta[] = [];
  for (const id of config.identidades) {
    const secretos: string[] = [];
    const leer = (ref: RefSecreto, donde: string): string | undefined => {
      const v = env[ref.env];
      if (v === undefined || v === "") return l.error(donde, `necesita la variable de entorno ${ref.env} (o el secreto del CI con ese nombre), que no está definida o está vacía`);
      secretos.push(v);
      return ref.formato ? ref.formato.replace("{}", v) : v;
    };
    if (id.cabeceras) {
      const cabeceras: Record<string, string> = {};
      for (const [nombre, ref] of Object.entries(id.cabeceras)) {
        const v = leer(ref, `${id.ruta}.cabeceras.${nombre}`);
        if (v !== undefined) cabeceras[nombre] = v;
      }
      salida.push({ nombre: id.nombre, cabeceras, secretos });
      continue;
    }
    const login = id.login!;
    const faltan: string[] = [];
    const url = login.url.replace(VARIABLE, (_t, nombre: string) => {
      const v = env[nombre];
      if (!v) faltan.push(nombre);
      return (v ?? "").trim();
    });
    if (faltan.length) l.error(`${id.ruta}.login.url`, `usa ${faltan.map((f) => `$\{${f}}`).join(", ")} y la variable no está definida o está vacía`);
    const cuerpo: Record<string, unknown> = {};
    for (const [clave, v] of Object.entries(login.cuerpo)) cuerpo[clave] = v && typeof v === "object" && "env" in (v as object) ? leer(v as RefSecreto, `${id.ruta}.login.cuerpo.${clave}`) : v;
    salida.push({ nombre: id.nombre, login: { ...login, url, cuerpo }, secretos });
  }
  if (l.problemas.length) throw new ErrorConfig(config.archivo, l.problemas);
  return salida;
}

/** Ejemplo comentado de .orobas/ci.yml (cyber ci ejemplo, y lo que copia docs/ci.md). */
export const EJEMPLO = `# Orobas en CI: qué se evalúa, con qué identidades, cuánto puede gastar y cuándo falla el job.
# Referencia completa: docs/ci.md. Validalo con «cyber ci validar» y mirá la huella del alcance con «cyber ci huella».
version: 1
nombre: staging

objetivo:
  # El alcance lo autoriza quien versiona este archivo, y la corrida además pide la huella del alcance en
  # OROBAS_CI_AUTORIZACION (una variable del CI que define quien administra el repositorio). Nada fuera de acá se toca.
  alcance:
    - url: https://staging.ejemplo.com
      nombre: web
    - host: api.staging.ejemplo.com
      puertos: [443]
      nombre: api
  excluir:
    - url: https://staging.ejemplo.com/admin

# Identidades de prueba: los valores salen de variables de entorno o secretos del CI, nunca de este archivo.
identidades:
  - nombre: alicia
    cabeceras:
      authorization: { env: STAGING_TOKEN_ALICIA, formato: "Bearer {}" }
  - nombre: bruno
    login:
      url: https://api.staging.ejemplo.com/login
      cuerpo:
        email: { env: STAGING_BRUNO_EMAIL }
        password: { env: STAGING_BRUNO_CLAVE }
      token: token

evaluacion:
  perfil: api            # general, api, web, superficie o completo
  consigna: |
    Prestá atención a los pedidos y a la facturación: cada cliente sólo ve lo suyo.
  solo_cambios:
    activo: auto         # en PRs, concentrarse en las rutas que cambió el PR
    rutas_siempre: [/login]

presupuesto:
  usd: 3                 # tope duro de la corrida (agente y verificador)
  minutos: 30            # tope duro de tiempo
  verificacion_usd: 1    # reservado para el verificador independiente

modelo:
  nombre: orobas/glm-5.3-flash

trazas: no

politica:
  fallar_desde: alta     # severidad verificada desde la que falla el job (o «nunca»)

linea_base:
  supresiones: .orobas/supresiones.yml
`;
