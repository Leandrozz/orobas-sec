// Máquina de estados del modo investigar, en datos (método de Niels Provos, «Finding zero-days with any
// model»): un objeto declarativo por estado con su entrada, su salida, las herramientas que puede usar, el
// criterio de avance, los topes y a dónde puede ir después. El orquestador (src/investigar/investigacion.ts)
// no tiene un if por estado: lee estas definiciones y el diario.
//
// Cada estado corre como un tramo con contexto limpio: no ve la conversación ni los tramos anteriores,
// sólo lo que el diario y los artefactos citados le dan (ENTRADA). Las hipótesis estáticas no valen hasta
// que un harness ejecutable las dispara, y una hipótesis sube de nivel (función → componentes → punta a
// punta) sólo con la evidencia ejecutable del nivel anterior.
import type { Nivel, Rol } from "../router.ts";

export const ESTADOS_ID = ["analista", "hipotesis", "harness-1", "harness-2", "harness-3", "reporte"] as const;
export type EstadoId = (typeof ESTADOS_ID)[number];

/** Lo que un estado le pone en el contexto a su tramo, sacado del diario y de los artefactos. */
export type Entrada = "objetivo" | "mapa" | "hipotesis" | "hipotesis-elegida" | "evidencia-previa" | "evidencias" | "intentos";
/** Lo que un estado tiene que devolver con investigation_output. */
export type Salida = "mapa" | "hipotesis" | "evidencia" | "reporte";
/** «misma»: la hipótesis del tramo que terminó; «otra»: cualquiera elegible, por prioridad; sin nada, ninguna. */
export interface Movida { estado: EstadoId; hipotesis?: "misma" | "otra" }

export interface DefinicionEstado {
  id: EstadoId;
  nombre: { es: string; en: string };
  /** Rol y nivel para el router (src/router.ts): blue lee, planifica y redacta; red comprueba y explota. */
  rol: Rol;
  nivel: Nivel;
  /** Corre sobre una hipótesis elegida (los harnesses) o sobre la investigación entera. */
  porHipotesis: boolean;
  /** Nivel de harness: 1 función, 2 componentes, 3 punta a punta. `requiere`: el nivel que la hipótesis ya tiene que tener. */
  harness?: { nivel: 1 | 2 | 3; requiere: 0 | 1 | 2 };
  entrada: Entrada[];
  salida: Salida;
  /** Herramientas que puede usar el tramo (las que existan en esta instalación), además de investigation_output. */
  herramientas: string[];
  /** Qué tiene que hacer, para el tramo. */
  tarea: string;
  /**
   * Cuándo el estado cuenta como cumplido: la salida esperada con al menos `minimo` elementos y, si
   * `ejecucion`, reproducida en limpio (poc_run) de forma determinista. Lo evalúa `cumple`.
   */
  avance: { salida: Salida; minimo?: number; ejecucion?: boolean };
  /** Topes del tramo y veces que el orquestador puede repetir el estado (por hipótesis, si corresponde). */
  tope: { pasos: number; usd: string; intentos: number };
  /** Movidas posibles según cómo terminó; el orquestador elige entre las que pasen las guardas. */
  siguiente: { cumplido: Movida[]; fallido: Movida[] };
}

const LEER_CODIGO = ["code_list", "code_search", "code_read", "code_semgrep", "artifact_read"];
/** Las de la caja: armar un harness, fuzzear y correr un PoC en limpio (las provee la caja de Orobas). */
export const HERRAMIENTAS_CAJA = ["harness_build", "fuzz_run", "poc_run"];

export const ESTADOS: Record<EstadoId, DefinicionEstado> = {
  analista: {
    id: "analista",
    nombre: { es: "analista", en: "analyst" },
    rol: "medio",
    nivel: "blue",
    porHipotesis: false,
    entrada: ["objetivo", "intentos"],
    salida: "mapa",
    herramientas: LEER_CODIGO,
    tarea: "Armá el mapa del objetivo: puntos de entrada (lo que llega de afuera), flujo de datos desde ahí, cadenas de llamadas hasta las funciones que tocan memoria o estado, parsers y aritmética de tamaños (longitudes, offsets, multiplicaciones, conversiones de signo). Citá archivo:línea en cada punto. No propongas fallas todavía.",
    avance: { salida: "mapa", minimo: 1 },
    tope: { pasos: 24, usd: "0.8", intentos: 2 },
    siguiente: { cumplido: [{ estado: "hipotesis" }], fallido: [{ estado: "analista" }] },
  },
  hipotesis: {
    id: "hipotesis",
    nombre: { es: "hipótesis", en: "hypotheses" },
    rol: "fuerte",
    nivel: "blue",
    porHipotesis: false,
    entrada: ["objetivo", "mapa", "hipotesis", "intentos"],
    salida: "hipotesis",
    herramientas: ["code_search", "code_read", "artifact_read", "cwe_detail"],
    tarea: "Con el mapa, armá una lista priorizada de hipótesis de falla (de 3 a 8): para cada una, la clase, la función o componente (activo), por qué podría fallar y la evidencia estática (archivo:línea, la condición que falta). Primero las más probables y con más impacto. Son hipótesis: no valen hasta que un harness las dispare.",
    avance: { salida: "hipotesis", minimo: 1 },
    tope: { pasos: 16, usd: "0.8", intentos: 2 },
    siguiente: { cumplido: [{ estado: "harness-1", hipotesis: "otra" }, { estado: "reporte" }], fallido: [{ estado: "hipotesis" }, { estado: "reporte" }] },
  },
  "harness-1": {
    id: "harness-1",
    nombre: { es: "harness-1 (función)", en: "harness-1 (function)" },
    rol: "fuerte",
    nivel: "red",
    porHipotesis: true,
    harness: { nivel: 1, requiere: 0 },
    entrada: ["objetivo", "hipotesis-elegida", "intentos"],
    salida: "evidencia",
    herramientas: [...LEER_CODIGO, ...HERRAMIENTAS_CAJA],
    tarea: "Nivel 1, función: escribí un harness mínimo que llame a la función de la hipótesis con entradas controladas, compilalo con sanitizadores (harness_build) y fuzzealo o correlo con el caso exacto (fuzz_run, poc_run). Si dispara, devolvé el comando de reproducción y la señal que lo prueba (p. ej. la línea del sanitizador).",
    avance: { salida: "evidencia", ejecucion: true },
    tope: { pasos: 30, usd: "1.2", intentos: 2 },
    siguiente: {
      cumplido: [{ estado: "harness-2", hipotesis: "misma" }, { estado: "harness-1", hipotesis: "otra" }, { estado: "reporte" }],
      fallido: [{ estado: "harness-1", hipotesis: "misma" }, { estado: "harness-1", hipotesis: "otra" }, { estado: "hipotesis" }, { estado: "reporte" }],
    },
  },
  "harness-2": {
    id: "harness-2",
    nombre: { es: "harness-2 (componentes)", en: "harness-2 (components)" },
    rol: "fuerte",
    nivel: "red",
    porHipotesis: true,
    harness: { nivel: 2, requiere: 1 },
    entrada: ["objetivo", "hipotesis-elegida", "evidencia-previa", "intentos"],
    salida: "evidencia",
    herramientas: [...LEER_CODIGO, ...HERRAMIENTAS_CAJA],
    tarea: "Nivel 2, componentes: la falla ya dispara en la función (evidencia abajo). Llevala al componente que la usa: armá un harness que entre por la API pública del componente (o la cadena de llamadas real), sin tocar el estado interno, y mostrá que la misma condición se alcanza. Devolvé el comando de reproducción y la señal.",
    avance: { salida: "evidencia", ejecucion: true },
    tope: { pasos: 30, usd: "1.5", intentos: 2 },
    siguiente: {
      cumplido: [{ estado: "harness-3", hipotesis: "misma" }, { estado: "harness-1", hipotesis: "otra" }, { estado: "reporte" }],
      fallido: [{ estado: "harness-2", hipotesis: "misma" }, { estado: "harness-1", hipotesis: "otra" }, { estado: "reporte" }],
    },
  },
  "harness-3": {
    id: "harness-3",
    nombre: { es: "harness-3 (punta a punta)", en: "harness-3 (end to end)" },
    rol: "fuerte",
    nivel: "red",
    porHipotesis: true,
    harness: { nivel: 3, requiere: 2 },
    entrada: ["objetivo", "hipotesis-elegida", "evidencia-previa", "intentos"],
    salida: "evidencia",
    herramientas: [...LEER_CODIGO, ...HERRAMIENTAS_CAJA, "scope_check", "http_request"],
    tarea: "Nivel 3, punta a punta: la falla ya se alcanza desde el componente (evidencia abajo). Reproducila en el laboratorio como la usaría un atacante: el binario o servicio real con una entrada externa (archivo, petición, mensaje), sin harness interno. Sólo contra destinos del alcance o locales. Devolvé el comando de reproducción y la señal.",
    avance: { salida: "evidencia", ejecucion: true },
    tope: { pasos: 30, usd: "1.5", intentos: 2 },
    siguiente: {
      cumplido: [{ estado: "harness-1", hipotesis: "otra" }, { estado: "reporte" }],
      fallido: [{ estado: "harness-3", hipotesis: "misma" }, { estado: "harness-1", hipotesis: "otra" }, { estado: "reporte" }],
    },
  },
  reporte: {
    id: "reporte",
    nombre: { es: "reporte", en: "report" },
    rol: "fuerte",
    nivel: "blue",
    porHipotesis: false,
    entrada: ["objetivo", "evidencias", "intentos"],
    salida: "reporte",
    herramientas: ["artifact_read", "code_read", "finding_list", "finding_update"],
    tarea: "Redactá el informe de la investigación sólo con la evidencia ejecutable (abajo): por hipótesis que disparó, el nivel alcanzado, el comando de reproducción, la señal, el impacto que demuestra ese nivel y lo que falta demostrar. Lo que no disparó va en una sección aparte, sin inflarlo. Si corresponde, ajustá título y severidad de los hallazgos con finding_update.",
    avance: { salida: "reporte", minimo: 1 },
    tope: { pasos: 12, usd: "0.6", intentos: 2 },
    siguiente: { cumplido: [], fallido: [{ estado: "reporte" }] },
  },
};

export const ESTADO_INICIAL: EstadoId = "analista";

/** ¿La salida que devolvió el tramo cumple el criterio de avance del estado? `reproduce`: la corrida en limpio. */
export function cumple(def: DefinicionEstado, salida: { tipo: Salida; elementos: number } | undefined, reproduce?: boolean): boolean {
  if (!salida || salida.tipo !== def.avance.salida) return false;
  if (salida.elementos < (def.avance.minimo ?? 1)) return false;
  return def.avance.ejecucion ? reproduce === true : true;
}
