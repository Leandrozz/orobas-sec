// El resultado de una corrida de CI en su formato propio (orobas-ci/1): lo que escribe resultado.json y de lo que
// salen el SARIF, el resumen en Markdown y el JUnit. Es un formato estable: un campo nuevo puede aparecer; uno que
// está no cambia de nombre ni de sentido sin pasar a orobas-ci/2. Esquema: distro/ci/orobas-ci-resultado.schema.json.
// Todo lo que entra acá ya pasó por el tapado de secretos.
import type { Severidad } from "./config.ts";
import type { Clase } from "./huella.ts";

export const FORMATO = "orobas-ci/1";

/** Códigos de salida: estables y documentados (docs/ci.md, «Códigos de salida»). */
export const CODIGOS = {
  ok: 0,
  hallazgos: 1,
  configuracion: 2,
  infraestructura: 3,
  incompleto: 4,
} as const;
export type EstadoCorrida = keyof typeof CODIGOS;

export const DESCRIPCION_CODIGO: Record<EstadoCorrida, string> = {
  ok: "sin hallazgos verificados que bloqueen, con la corrida completa",
  hallazgos: "hay hallazgos verificados que bloquean según la política",
  configuracion: "error de configuración, de autorización, de identidades o de cuenta: no se evaluó nada",
  infraestructura: "falló el proveedor de modelos, el objetivo no respondió o hubo un error interno: la corrida no es concluyente",
  incompleto: "se agotó el presupuesto o el tiempo antes de terminar: lo que no se llegó a probar o a verificar no es «todo bien»",
};

export interface Paso {
  metodo: string;
  url: string;
  cabeceras: Record<string, string>;
  cuerpo?: string;
  /** La identidad de prueba que firmó la petición (sus valores nunca van). */
  identidad?: string;
  curl: string;
  respuesta?: { estado: number; cabeceras: Record<string, string>; extracto: string; recortado: boolean };
  error?: string;
  /** Hash del artefacto con el intercambio completo (en la base de la corrida, no en las salidas). */
  artefacto: string;
}

export interface HallazgoCi {
  huella: string;
  id: string;
  estado: "verificado" | "candidato" | "descartado" | "pista";
  severidad: Severidad;
  clase: Clase;
  /** La clase con las palabras del agente. */
  clase_declarada: string;
  titulo: string;
  activo: string;
  /** Destino de la huella: el nombre de la regla del alcance o la regla tal como está escrita. */
  destino: string;
  metodo: string;
  ruta: string;
  consulta: string[];
  resumen: string;
  limites: string;
  /** Motivo del veredicto (verificador) o del descarte. */
  motivo: string;
  decidido_por: string;
  comparacion: "nuevo" | "persiste" | "sin-anterior";
  supresion?: { motivo: string; autor: string; vence: string };
  bloqueante: boolean;
  /** Las peticiones de la evidencia, con curl para reproducirlas. */
  reproduccion: Paso[];
  /** Prueba y control del verificador (sólo verificados por el verificador independiente). */
  verificacion?: { prueba?: Paso; control?: Paso; costo_usd?: string };
  evidencia: string[];
}

export interface RetestCi {
  huella: string;
  titulo: string;
  severidad: Severidad;
  clase: Clase;
  resultado: "arreglado" | "persiste" | "sin-confirmar";
  motivo: string;
  /** La petición original repetida ahora. */
  repeticion?: Paso;
  /** Prueba y control del verificador en el retest: en un arreglado, la prueba ya da como el control. */
  prueba?: Paso;
  control?: Paso;
  bloqueante: boolean;
  supresion?: { motivo: string; autor: string; vence: string };
}

export interface ResultadoCi {
  formato: typeof FORMATO;
  herramienta: { nombre: "orobas-sec"; version: string };
  nombre: string;
  modo: "evaluacion" | "retest";
  resultado: { codigo: number; estado: EstadoCorrida; descripcion: string; motivo: string; bloqueantes: number };
  corrida: {
    inicio: string;
    fin: string;
    duracion_s: number;
    sesion: string;
    repositorio?: string;
    commit?: string;
    ref?: string;
    evento?: string;
    pr?: number;
    url?: string;
    /** Cómo terminó la exploración: «cierre» (el agente terminó), «presupuesto», «tiempo», «pasos», «sin-avance», «proveedor», «sin-saldo», «no-corrio». */
    fin_exploracion: string;
  };
  autorizacion: { huella: string; fuente: string; archivo: string; huella_archivo: string; ref?: string } | null;
  alcance: { incluido: string[]; excluido: string[]; reglas: Array<{ destino: string; tipo: string; valor: string }>; acotado_a_cambios: boolean };
  modelo: { nombre: string; modelos_usados: string[]; router: string };
  gasto: { usd: string; tope_usd: string; verificacion_usd: string; solicitudes: number; solicitudes_sin_costo: number; tokens: { entrada: number; cache_lectura: number; cache_escritura: number; salida: number } };
  tiempo: { tope_min: number; duracion_s: number };
  trafico: { peticiones: number; bloqueadas_por_alcance: number; intentos_fuera_de_alcance: string[]; solo_lectura: boolean; hosts: string[] };
  cobertura: {
    probadas: string[];
    sin_probar: string[];
    solo_cambios: { activo: boolean; motivo: string; base?: string; rutas: Array<{ ruta: string; archivo: string; linea?: number }>; archivos_sin_ruta: string[] };
  };
  politica: { fallar_desde: string; solo_nuevos: boolean };
  hallazgos: HallazgoCi[];
  comparacion: { anterior: { sesion: string; fin: string; commit?: string } | null; nuevos: string[]; persisten: string[]; resueltos: string[]; sin_confirmar: string[] };
  supresiones: { archivo: string; aplicadas: string[]; vencidas: Array<{ huella: string; motivo: string; autor: string; vence: string }>; sin_uso: string[] };
  retest: RetestCi[];
  avisos: string[];
}
