// Grafo de hechos de la evaluación: una representación única y consultable de lo que el harness ya sabe del
// objetivo (hosts, servicios, rutas con método, parámetros, identidades, objetos, tecnologías, credenciales por
// referencia, artefactos de fuente, hallazgos, hipótesis y CVEs) y de cómo se relacionan. Lo alimenta el harness
// solo, de forma determinista (src/grafo-alimentar.ts): cada respuesta HTTP, cosecha, sonda, lectura de fuente,
// recon y hallazgo. El modelo lo consulta (src/grafo-herramientas.ts) y puede anotar hipótesis o relaciones, que
// quedan «inferidas» hasta que el harness las observe.
//
// Reglas que no se negocian:
// - Nada entra sin evidencia identificable: cada nodo y arista guarda de dónde salió (herramienta, el hash del
//   intercambio o artefacto que lo prueba, quién lo escribió y cuándo) y un estado (observado, inferido,
//   verificado, refutado).
// - El grafo no autoriza nada. El alcance se evalúa al leer, con el alcance vigente: un nodo fuera de él se marca
//   y nunca se propone como destino. Los señuelos marcados tampoco.
// - Es por programa, con la misma regla que la memoria (sameScope): lo de otro programa de la misma carpeta no se
//   ve. Cada escritura va a la partición del alcance de quien escribe; al leer se juntan las particiones visibles.
// - Los valores del operador no entran nunca: credenciales por nombre o marcador, y todo texto pasa por `tapar`.
// - Crece con tope: nodos y aristas por partición, atributos y etiquetas acotados.
import { AsyncLocalStorage } from "node:async_hooks";
import type { DatabaseSync, StatementSync } from "node:sqlite";
import type { Tool } from "./agent.ts";
import { decide, sameScope, type Scope, type ScopeTag } from "./scope.ts";

export const TIPOS_NODO = ["host", "servicio", "ruta", "parametro", "identidad", "objeto", "tecnologia", "credencial", "artefacto", "hallazgo", "hipotesis", "cve"] as const;
export type TipoNodo = (typeof TIPOS_NODO)[number];
export const TIPOS_ARISTA = ["expone", "acepta", "pertenece_a", "accesible_por", "observado_en", "deriva_de", "habilita", "refuta"] as const;
export type TipoArista = (typeof TIPOS_ARISTA)[number];
export const ESTADOS = ["inferido", "observado", "verificado", "refutado"] as const;
export type Estado = (typeof ESTADOS)[number];

/** Cómo se lee cada arista: «origen expone destino». */
export const LECTURA_ARISTA: Record<TipoArista, string> = { expone: "expone", acepta: "acepta", pertenece_a: "pertenece a", accesible_por: "accesible por", observado_en: "observado en", deriva_de: "deriva de", habilita: "habilita", refuta: "refuta" };

/** Un estado más fuerte reemplaza a uno más débil; para bajar hace falta `forzar` (el operador cambió un hallazgo). */
const RANGO: Record<Estado, number> = { inferido: 0, observado: 1, refutado: 2, verificado: 3 };

export type Valor = string | number | boolean;
export type Atributos = Record<string, Valor | Valor[]>;

/** Un nodo como lo escribe el alimentador: el identificador canónico va sin el tipo. */
export interface NodoSpec {
  tipo: TipoNodo;
  id: string;
  etiqueta?: string;
  estado: Estado;
  atributos?: Atributos;
  /** Destino del nodo para el alcance (URL, origen o host); sin esto, el nodo no es un destino. */
  destino?: string;
  /** Reemplaza el estado aunque sea más débil (un hallazgo que el operador volvió a candidato). */
  forzar?: boolean;
}

export interface Procedencia {
  herramienta: string;
  /** Hash del intercambio o artefacto que lo prueba, o la referencia que lo identifica (hallazgo:…, memoria:…). */
  evidencia: string;
  /** principal, sub:N, verificador:…, harness. */
  worker: string;
  sesion: string;
  momento: string;
}

/** Quién está escribiendo ahora: lo pone el envoltorio de cada herramienta y el de cada subagente. */
export interface ContextoEscritura {
  herramienta?: string;
  worker?: string;
}

export const contextoGrafo = new AsyncLocalStorage<ContextoEscritura>();

/** Corre `fn` con el contexto dado sumado al vigente (el worker de afuera se conserva si no se pisa). */
export function conContexto<T>(contexto: ContextoEscritura, fn: () => T): T {
  return contextoGrafo.run({ ...contextoGrafo.getStore(), ...contexto }, fn);
}

/** Las herramientas de un subagente o del verificador escriben en el grafo con su procedencia. */
export function conWorker(worker: string, tools: Tool[]): Tool[] {
  return tools.map((tool) => ({ ...tool, execute: (args, signal) => conContexto({ worker }, () => tool.execute(args, signal)) }));
}

/** Topes por partición. Lo de menor valor (objetos, rutas inferidas, parámetros) deja de entrar primero. */
export const TOPES = { nodos: 60_000, aristas: 250_000, etiqueta: 160, texto: 200, lista: 20, atributos: 2_000 } as const;
/** Tipos que siguen entrando aunque la partición esté llena: son pocos y son lo que importa. */
const SIEMPRE: ReadonlySet<TipoNodo> = new Set(["host", "servicio", "identidad", "hallazgo", "hipotesis", "cve", "tecnologia"]);

const INVISIBLES = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿\u{e0000}-\u{e007f}]/gu;

/** Un texto para una etiqueta o un atributo: sin controles ni invisibles, en una línea y acotado. */
export function limpio(texto: string, max: number = TOPES.texto): string {
  const plano = String(texto).replace(INVISIBLES, " ").replace(/\s+/g, " ").trim();
  return plano.length > max ? `${plano.slice(0, max - 1)}…` : plano;
}

/** Atributos acotados: listas de hasta TOPES.lista (sin repetir, en orden estable), textos cortos y JSON chico. */
export function acotar(atributos: Atributos): Atributos {
  const out: Atributos = {};
  for (const [clave, valor] of Object.entries(atributos)) {
    if (valor === undefined || valor === null) continue;
    const nombre = limpio(clave, 40);
    if (Array.isArray(valor)) {
      const lista = [...new Set(valor.filter((item) => item !== undefined && item !== null).map((item) => (typeof item === "string" ? limpio(item) : item)))];
      out[nombre] = ordenar(lista).slice(0, TOPES.lista);
    } else out[nombre] = typeof valor === "string" ? limpio(valor) : valor;
  }
  // Un JSON que no entra pierde primero lo largo: las listas se acortan y, si no alcanza, se van claves.
  let json = JSON.stringify(out);
  for (const clave of Object.keys(out).sort((a, b) => JSON.stringify(out[b]).length - JSON.stringify(out[a]).length)) {
    if (json.length <= TOPES.atributos) break;
    const valor = out[clave]!;
    if (Array.isArray(valor) && valor.length > 3) out[clave] = valor.slice(0, 3);
    else delete out[clave];
    json = JSON.stringify(out);
  }
  return out;
}

const ordenar = (lista: Valor[]): Valor[] => [...lista].sort((a, b) => (typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b))));

/** Une dos juegos de atributos: las listas se suman, lo demás lo pisa lo nuevo. */
export function mezclar(viejo: Atributos, nuevo: Atributos): Atributos {
  const out: Atributos = { ...viejo };
  for (const [clave, valor] of Object.entries(nuevo)) {
    const previo = out[clave];
    out[clave] = Array.isArray(valor) && Array.isArray(previo) ? [...previo, ...valor] : valor;
  }
  return acotar(out);
}

/** El estado que queda: el más fuerte, salvo que el nuevo venga forzado. */
export function combinar(viejo: Estado, nuevo: Estado, forzar = false): Estado {
  if (forzar) return nuevo;
  return RANGO[nuevo] >= RANGO[viejo] ? nuevo : viejo;
}

/**
 * Estado de una arista «accesible por»: observada si la identidad obtuvo una respuesta exitosa (o la prueba
 * cruzada leyó o modificó el objeto), refutada si sólo recibió rechazos, inferida si nada concluye.
 */
export function estadoDeAcceso(atributos: Atributos, previo: Estado): Estado {
  if (previo === "verificado") return previo;
  const veredicto = String(atributos.veredicto ?? "");
  if (/^(leido|modificado|publico)$/.test(veredicto)) return "observado";
  const estados = (Array.isArray(atributos.estados) ? atributos.estados : []).map(Number).filter((n) => Number.isFinite(n));
  if (estados.some((n) => n < 400)) return "observado";
  if (/^(negado|redirigido)$/.test(veredicto) || estados.some((n) => n >= 400 && n < 500)) return "refutado";
  return previo;
}

export interface ParticionFila {
  clave: string;
  programa: string;
  dominios: string[];
  sesion: string;
}

/** Partición de quien escribe: el programa, el alcance manual por sus dominios, o la sesión si no hay alcance. */
export function particionDe(tag: ScopeTag | undefined, sesion: string): ParticionFila {
  if (!tag?.program) return { clave: `sesion:${sesion}`, programa: "", dominios: [], sesion };
  if (tag.program === "manual") {
    const dominios = [...new Set(tag.domains)].sort();
    return { clave: `manual:${dominios.join(",")}`, programa: "manual", dominios, sesion: "" };
  }
  return { clave: `programa:${tag.program}`, programa: tag.program, dominios: [...new Set(tag.domains)].sort(), sesion: "" };
}

/** ¿Se ve la partición desde esta sesión? La misma regla que la memoria por programa. */
export function particionVisible(fila: ParticionFila, tag: ScopeTag | undefined, sesion: string): boolean {
  if (fila.clave.startsWith("sesion:")) return fila.sesion === sesion;
  return !!tag && sameScope({ program: fila.programa, domains: fila.dominios }, tag);
}

export interface NodoVista {
  clave: string;
  tipo: TipoNodo;
  id: string;
  etiqueta: string;
  estado: Estado;
  atributos: Atributos;
  destino?: string;
  origen: Procedencia;
  ultima: Procedencia;
  vistas: number;
  particiones: string[];
}

export interface AristaVista {
  clave: string;
  origen: string;
  tipo: TipoArista;
  destino: string;
  estado: Estado;
  atributos: Atributos;
  procedencia: Procedencia;
  ultima: Procedencia;
  vistas: number;
}

interface FilaNodo {
  id: number; particion: string; clave: string; tipo: string; etiqueta: string; estado: string; destino: string | null; atributos: string;
  herramienta: string; evidencia: string; worker: string; sesion: string; creado: string;
  ult_herramienta: string; ult_evidencia: string; ult_worker: string; ult_sesion: string; visto: string; vistas: number;
}
interface FilaArista {
  id: number; particion: string; oc: string; tipo: string; dc: string; estado: string; atributos: string;
  herramienta: string; evidencia: string; worker: string; sesion: string; creado: string;
  ult_herramienta: string; ult_evidencia: string; ult_worker: string; ult_sesion: string; visto: string; vistas: number;
}

const json = (texto: string): Atributos => {
  try { return JSON.parse(texto) as Atributos; } catch { return {}; }
};

/**
 * Lo que se ve del grafo desde una sesión: las particiones visibles juntas en memoria. Un mismo nodo puede estar
 * en dos particiones visibles (un alcance manual y un programa que comparten dominio): se muestra uno, con el
 * estado más fuerte y los atributos sumados.
 */
export class Vista {
  readonly nodos = new Map<string, NodoVista>();
  readonly aristas = new Map<string, AristaVista>();
  readonly salientes = new Map<string, AristaVista[]>();
  readonly entrantes = new Map<string, AristaVista[]>();
  private readonly filasNodo = new Map<string, Map<string, FilaNodo>>();
  private readonly filasArista = new Map<string, Map<string, FilaArista>>();
  private readonly alcances = new Map<string, "dentro" | "fuera" | "señuelo">();
  private alcanceDe?: Scope;
  readonly particiones: string[];
  readonly alcance: () => Scope | undefined;
  readonly senuelo?: (destino: string) => boolean;

  constructor(particiones: string[], alcance: () => Scope | undefined, senuelo?: (destino: string) => boolean) {
    this.particiones = particiones;
    this.alcance = alcance;
    this.senuelo = senuelo;
  }

  aplicarNodo(fila: FilaNodo): void {
    const filas = this.filasNodo.get(fila.clave) ?? new Map<string, FilaNodo>();
    filas.set(fila.particion, fila);
    this.filasNodo.set(fila.clave, filas);
    const todas = [...filas.values()];
    const reciente = todas.reduce((a, b) => (b.visto > a.visto ? b : a));
    const primera = todas.reduce((a, b) => (b.creado < a.creado ? b : a));
    const estado: Estado = todas.some((item) => item.estado === "verificado") ? "verificado" : (reciente.estado as Estado);
    const atributos = todas.length === 1 ? json(fila.atributos) : todas.map((item) => json(item.atributos)).reduce((a, b) => mezclar(a, b), {});
    const tipo = fila.tipo as TipoNodo;
    this.nodos.set(fila.clave, {
      clave: fila.clave, tipo, id: fila.clave.slice(tipo.length + 1), etiqueta: reciente.etiqueta, estado, atributos,
      ...(reciente.destino ? { destino: reciente.destino } : {}),
      origen: { herramienta: primera.herramienta, evidencia: primera.evidencia, worker: primera.worker, sesion: primera.sesion, momento: primera.creado },
      ultima: { herramienta: reciente.ult_herramienta, evidencia: reciente.ult_evidencia, worker: reciente.ult_worker, sesion: reciente.ult_sesion, momento: reciente.visto },
      vistas: todas.reduce((suma, item) => suma + item.vistas, 0),
      particiones: [...filas.keys()].sort(),
    });
  }

  aplicarArista(fila: FilaArista): void {
    const clave = `${fila.oc}\n${fila.tipo}\n${fila.dc}`;
    const filas = this.filasArista.get(clave) ?? new Map<string, FilaArista>();
    filas.set(fila.particion, fila);
    this.filasArista.set(clave, filas);
    const todas = [...filas.values()];
    const reciente = todas.reduce((a, b) => (b.visto > a.visto ? b : a));
    const primera = todas.reduce((a, b) => (b.creado < a.creado ? b : a));
    const estado = todas.some((item) => item.estado === "verificado") ? "verificado" : reciente.estado as Estado;
    const arista: AristaVista = {
      clave, origen: fila.oc, tipo: fila.tipo as TipoArista, destino: fila.dc, estado,
      atributos: todas.length === 1 ? json(fila.atributos) : todas.map((item) => json(item.atributos)).reduce((a, b) => mezclar(a, b), {}),
      procedencia: { herramienta: primera.herramienta, evidencia: primera.evidencia, worker: primera.worker, sesion: primera.sesion, momento: primera.creado },
      ultima: { herramienta: reciente.ult_herramienta, evidencia: reciente.ult_evidencia, worker: reciente.ult_worker, sesion: reciente.ult_sesion, momento: reciente.visto },
      vistas: todas.reduce((suma, item) => suma + item.vistas, 0),
    };
    const nueva = !this.aristas.has(clave);
    this.aristas.set(clave, arista);
    for (const [indice, extremo] of [[this.salientes, fila.oc], [this.entrantes, fila.dc]] as const) {
      const lista = indice.get(extremo) ?? [];
      const donde = nueva ? -1 : lista.findIndex((item) => item.clave === clave);
      if (donde < 0) lista.push(arista);
      else lista[donde] = arista;
      indice.set(extremo, lista);
    }
  }

  /** Nodos de un tipo, en orden estable (por clave). */
  deTipo(tipo: TipoNodo): NodoVista[] {
    return [...this.nodos.values()].filter((nodo) => nodo.tipo === tipo).sort((a, b) => a.clave.localeCompare(b.clave));
  }

  vecinas(clave: string): AristaVista[] {
    return [...(this.salientes.get(clave) ?? []), ...(this.entrantes.get(clave) ?? [])];
  }

  /**
   * Dónde queda un nodo respecto del alcance vigente, evaluado ahora (el alcance cambia durante la sesión): un
   * nodo sin destino (identidad, hallazgo, hipótesis, CVE, artefacto) no es un destino y queda «dentro».
   */
  ubicacion(nodo: NodoVista): "dentro" | "fuera" | "señuelo" {
    if (!nodo.destino) return "dentro";
    const alcance = this.alcance();
    if (alcance !== this.alcanceDe) {
      this.alcances.clear();
      this.alcanceDe = alcance;
    }
    const previa = this.alcances.get(nodo.destino);
    if (previa) return previa;
    let ubicacion: "dentro" | "fuera" | "señuelo";
    try {
      ubicacion = this.senuelo?.(nodo.destino) ? "señuelo" : decide(alcance, nodo.destino).allowed ? "dentro" : "fuera";
    } catch {
      ubicacion = "fuera";
    }
    this.alcances.set(nodo.destino, ubicacion);
    return ubicacion;
  }

  /** ¿Se puede proponer como destino? Dentro del alcance vigente y sin marca de señuelo. */
  destinable(nodo: NodoVista): boolean {
    return this.ubicacion(nodo) === "dentro";
  }
}

export interface OpcionesGrafo {
  sesion: string;
  /** Programa de la sesión ahora (cambia si cambia el alcance). */
  etiqueta: () => ScopeTag | undefined;
  /** Alcance vigente, para marcar lo que queda fuera. */
  alcance?: () => Scope | undefined;
  /** Señuelos marcados por el operador. */
  senuelo?: (destino: string) => boolean;
  /** Tapa lo del operador en todo texto que entra (credenciales, identidades): nunca entra un valor suyo. */
  tapar?: (texto: string) => string;
  evento?: (tipo: string, payload: unknown) => void;
  limites?: { nodos?: number; aristas?: number };
  /** Vista del operador sin sesión (la CLI): lee, nunca escribe. */
  soloLectura?: boolean;
}

interface OpNodo {
  particion: string;
  clave: string;
  tipo: TipoNodo;
  etiqueta: string;
  estado: Estado;
  forzar: boolean;
  atributos: Atributos;
  destino?: string;
  /** Sólo hace falta que exista (extremo de una arista): no suma una observación. */
  referencia: boolean;
  primera: Procedencia;
  ultima: Procedencia;
  veces: number;
}

interface OpArista {
  particion: string;
  origen: OpNodo;
  tipo: TipoArista;
  destino: OpNodo;
  estado: Estado;
  forzar: boolean;
  atributos: Atributos;
  primera: Procedencia;
  ultima: Procedencia;
  veces: number;
}

const ESQUEMA = `
create table if not exists meta(key text primary key, value text not null);
create table if not exists grafo_particiones(clave text primary key, programa text not null, dominios text not null default '[]', sesion text not null default '', creada text not null, usada text not null);
create table if not exists grafo_nodos(
  id integer primary key, particion text not null, clave text not null, tipo text not null, etiqueta text not null,
  estado text not null, destino text, atributos text not null default '{}',
  herramienta text not null, evidencia text not null, worker text not null, sesion text not null, creado text not null,
  ult_herramienta text not null, ult_evidencia text not null, ult_worker text not null, ult_sesion text not null, visto text not null,
  vistas integer not null default 1, unique(particion, clave));
create index if not exists grafo_nodos_tipo on grafo_nodos(particion, tipo);
create table if not exists grafo_aristas(
  id integer primary key, particion text not null, origen integer not null, tipo text not null, destino integer not null,
  estado text not null, atributos text not null default '{}',
  herramienta text not null, evidencia text not null, worker text not null, sesion text not null, creado text not null,
  ult_herramienta text not null, ult_evidencia text not null, ult_worker text not null, ult_sesion text not null, visto text not null,
  vistas integer not null default 1, unique(particion, origen, tipo, destino));
create index if not exists grafo_aristas_origen on grafo_aristas(origen);
create index if not exists grafo_aristas_destino on grafo_aristas(destino);
create index if not exists grafo_aristas_particion on grafo_aristas(particion, tipo);
`;

/** Versión del esquema: una migración futura la sube; ésta sólo crea tablas nuevas (los proyectos viejos no se tocan). */
export const VERSION_ESQUEMA = "1";

/** Cambios hechos por cualquier Grafo de esta misma conexión (data_version sólo ve los de otras conexiones). */
const versionesLocales = new WeakMap<DatabaseSync, number>();

/** Escrituras pendientes antes de vaciar sin esperar a que termine la herramienta. */
const LOTE = 400;

export class Grafo {
  readonly db: DatabaseSync;
  readonly opciones: OpcionesGrafo;
  private readonly pendNodos = new Map<string, OpNodo>();
  private readonly pendAristas = new Map<string, OpArista>();
  private readonly filas = new Map<string, { id: number; estado: Estado; atributos: Atributos }>();
  private readonly filasArista = new Map<string, { id: number; estado: Estado; atributos: Atributos }>();
  private readonly cuentas = new Map<string, { nodos: number; aristas: number }>();
  private readonly avisados = new Set<string>();
  private readonly particionesConocidas = new Map<string, ParticionFila>();
  private vista?: { particiones: string; version: string; vista: Vista };
  private temporizador?: ReturnType<typeof setTimeout>;
  private sentencias?: Record<string, StatementSync>;
  /** Escrituras que no entraron por el tope, por tipo. */
  readonly descartadas = new Map<string, number>();

  constructor(db: DatabaseSync, opciones: OpcionesGrafo) {
    this.db = db;
    this.opciones = opciones;
    if (!opciones.soloLectura) {
      db.exec(ESQUEMA);
      db.prepare("insert into meta(key,value) values('grafo.esquema',?) on conflict(key) do nothing").run(VERSION_ESQUEMA);
    }
  }

  /** ¿Existen las tablas? Una base de antes del grafo abierta en sólo lectura no las tiene. */
  existe(): boolean {
    return !!this.db.prepare("select 1 from sqlite_master where type='table' and name='grafo_nodos'").get();
  }

  private sql(): Record<string, StatementSync> {
    return (this.sentencias ??= {
      filaNodo: this.db.prepare("select id, estado, atributos from grafo_nodos where particion=? and clave=?"),
      insertarNodo: this.db.prepare("insert into grafo_nodos(particion,clave,tipo,etiqueta,estado,destino,atributos,herramienta,evidencia,worker,sesion,creado,ult_herramienta,ult_evidencia,ult_worker,ult_sesion,visto,vistas) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) returning id"),
      actualizarNodo: this.db.prepare("update grafo_nodos set etiqueta=?, estado=?, destino=coalesce(?, destino), atributos=?, ult_herramienta=?, ult_evidencia=?, ult_worker=?, ult_sesion=?, visto=?, vistas=vistas+? where id=?"),
      filaArista: this.db.prepare("select id, estado, atributos from grafo_aristas where particion=? and origen=? and tipo=? and destino=?"),
      insertarArista: this.db.prepare("insert into grafo_aristas(particion,origen,tipo,destino,estado,atributos,herramienta,evidencia,worker,sesion,creado,ult_herramienta,ult_evidencia,ult_worker,ult_sesion,visto,vistas) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) returning id"),
      actualizarArista: this.db.prepare("update grafo_aristas set estado=?, atributos=?, ult_herramienta=?, ult_evidencia=?, ult_worker=?, ult_sesion=?, visto=?, vistas=vistas+? where id=?"),
      contarNodos: this.db.prepare("select count(*) n from grafo_nodos where particion=?"),
      contarAristas: this.db.prepare("select count(*) n from grafo_aristas where particion=?"),
      particion: this.db.prepare("select clave, programa, dominios, sesion from grafo_particiones where clave=?"),
      guardarParticion: this.db.prepare("insert into grafo_particiones(clave,programa,dominios,sesion,creada,usada) values(?,?,?,?,?,?) on conflict(clave) do update set dominios=excluded.dominios, usada=excluded.usada"),
    });
  }

  private etiquetaGuardada?: { valor: ScopeTag | undefined };

  /** El programa de la sesión, leído una vez hasta que cambie el alcance (invalidarAlcance). */
  private etiquetaActual(): ScopeTag | undefined {
    return (this.etiquetaGuardada ??= { valor: this.opciones.etiqueta() }).valor;
  }

  /** El alcance de la sesión cambió: la próxima escritura y la próxima lectura vuelven a mirar el programa. */
  invalidarAlcance(): void {
    this.etiquetaGuardada = undefined;
  }

  private forzada?: { fila: ParticionFila; sesion: string };

  /**
   * Escribe lo que haga `fn` en la partición de otra sesión, con esa sesión como procedencia: la migración de lo que
   * ya había en la base (src/grafo-migrar.ts) lo pone en el programa donde nació, no en el de quien abre el proyecto.
   */
  escribirEn(tag: ScopeTag | undefined, sesion: string, fn: () => void): void {
    const previa = this.forzada;
    this.forzada = { fila: particionDe(tag, sesion), sesion };
    try {
      this.registrarParticion(this.forzada.fila);
      fn();
    } finally {
      this.forzada = previa;
    }
  }

  /** Después de deshacer una transacción de afuera, los ids en memoria pueden no existir: se vuelven a leer. */
  olvidarCache(): void {
    this.filas.clear();
    this.filasArista.clear();
    this.cuentas.clear();
    this.particionesConocidas.clear();
    this.vista = undefined;
  }

  /** La partición donde escribe esta sesión ahora; queda registrada con sus dominios (los de un programa se suman). */
  particionActual(): ParticionFila {
    if (this.forzada) return this.forzada.fila;
    return this.registrarParticion(particionDe(this.etiquetaActual(), this.opciones.sesion));
  }

  private registrarParticion(fila: ParticionFila): ParticionFila {
    const conocida = this.particionesConocidas.get(fila.clave);
    if (conocida && fila.dominios.every((dominio) => conocida.dominios.includes(dominio))) return conocida;
    if (this.opciones.soloLectura) return fila;
    const guardada = this.sql().particion!.get(fila.clave) as { dominios: string } | undefined;
    const dominios = [...new Set([...(guardada ? (JSON.parse(guardada.dominios) as string[]) : []), ...fila.dominios])].sort();
    const ahora = new Date().toISOString();
    this.sql().guardarParticion!.run(fila.clave, fila.programa, JSON.stringify(dominios), fila.sesion, ahora, ahora);
    const final = { ...fila, dominios };
    this.particionesConocidas.set(fila.clave, final);
    return final;
  }

  /** Particiones que se ven desde esta sesión. */
  visibles(): string[] {
    if (!this.existe()) return [];
    const tag = this.etiquetaActual();
    const filas = this.db.prepare("select clave, programa, dominios, sesion from grafo_particiones").all() as Array<{ clave: string; programa: string; dominios: string; sesion: string }>;
    return filas
      .map((fila) => ({ clave: fila.clave, programa: fila.programa, dominios: JSON.parse(fila.dominios) as string[], sesion: fila.sesion }))
      .filter((fila) => particionVisible(fila, tag, this.opciones.sesion))
      .map((fila) => fila.clave)
      .sort();
  }

  /** La procedencia de una escritura: la herramienta y el worker del contexto, la evidencia que se pasa. */
  private procedencia(evidencia: string, herramienta?: string): Procedencia {
    const contexto = contextoGrafo.getStore();
    return {
      herramienta: limpio(herramienta ?? contexto?.herramienta ?? "harness", 60),
      evidencia: limpio(evidencia, 120),
      worker: limpio(contexto?.worker ?? (contexto?.herramienta ? "principal" : "harness"), 60),
      sesion: this.forzada?.sesion ?? this.opciones.sesion,
      momento: new Date().toISOString(),
    };
  }

  private tapar(texto: string): string {
    return this.opciones.tapar ? this.opciones.tapar(texto) : texto;
  }

  private opNodo(spec: NodoSpec, procedencia: Procedencia, referencia: boolean, particion: string): OpNodo {
    const id = limpio(this.tapar(spec.id), 400);
    if (!id) throw new Error("Nodo sin identificador");
    const clave = `${spec.tipo}:${id}`;
    const atributos: Atributos = {};
    for (const [nombre, valor] of Object.entries(spec.atributos ?? {})) {
      atributos[nombre] = Array.isArray(valor) ? valor.map((item) => (typeof item === "string" ? this.tapar(item) : item)) : typeof valor === "string" ? this.tapar(valor) : valor;
    }
    return {
      particion, clave, tipo: spec.tipo,
      etiqueta: limpio(this.tapar(spec.etiqueta ?? spec.id), TOPES.etiqueta),
      estado: spec.estado, forzar: !!spec.forzar, atributos: acotar(atributos),
      ...(spec.destino ? { destino: limpio(this.tapar(spec.destino), 400) } : {}),
      referencia, primera: procedencia, ultima: procedencia, veces: referencia ? 0 : 1,
    };
  }

  private juntarNodo(op: OpNodo): OpNodo {
    const llave = `${op.particion}\n${op.clave}`;
    const previa = this.pendNodos.get(llave);
    if (!previa) {
      this.pendNodos.set(llave, op);
      return op;
    }
    if (op.referencia) return previa;
    const junta: OpNodo = previa.referencia
      ? op
      : { ...previa, etiqueta: op.etiqueta, estado: combinar(previa.estado, op.estado, op.forzar), forzar: previa.forzar || op.forzar, atributos: mezclar(previa.atributos, op.atributos), destino: op.destino ?? previa.destino, ultima: op.ultima, veces: previa.veces + 1 };
    this.pendNodos.set(llave, junta);
    return junta;
  }

  /** Clave del nodo (`tipo:id`) tal como queda guardada. */
  clave(spec: Pick<NodoSpec, "tipo" | "id">): string {
    return `${spec.tipo}:${limpio(this.tapar(spec.id), 400)}`;
  }

  /** Registra un nodo con su evidencia. Devuelve su clave. */
  nodo(spec: NodoSpec, evidencia: string, herramienta?: string): string {
    if (this.opciones.soloLectura) throw new Error("El grafo está abierto en sólo lectura.");
    if (!evidencia?.trim()) throw new Error(`Sin evidencia no entra nada al grafo (${spec.tipo} ${spec.id}).`);
    const op = this.juntarNodo(this.opNodo(spec, this.procedencia(evidencia, herramienta), false, this.particionActual().clave));
    this.programar();
    return op.clave;
  }

  /** Registra una arista entre dos nodos (que se crean si hace falta) con su evidencia. */
  arista(origen: NodoSpec, tipo: TipoArista, destino: NodoSpec, estado: Estado, evidencia: string, atributos: Atributos = {}, opciones: { herramienta?: string; forzar?: boolean } = {}): void {
    if (this.opciones.soloLectura) throw new Error("El grafo está abierto en sólo lectura.");
    if (!evidencia?.trim()) throw new Error(`Sin evidencia no entra nada al grafo (${origen.id} ${tipo} ${destino.id}).`);
    if (!(TIPOS_ARISTA as readonly string[]).includes(tipo)) throw new Error(`Tipo de arista desconocido: ${tipo}`);
    const procedencia = this.procedencia(evidencia, opciones.herramienta);
    const particion = this.particionActual().clave;
    const desde = this.juntarNodo(this.opNodo(origen, procedencia, true, particion));
    const hacia = this.juntarNodo(this.opNodo(destino, procedencia, true, particion));
    const llave = `${particion}\n${desde.clave}\n${tipo}\n${hacia.clave}`;
    const previa = this.pendAristas.get(llave);
    const limpios: Atributos = {};
    for (const [nombre, valor] of Object.entries(atributos)) limpios[nombre] = typeof valor === "string" ? this.tapar(valor) : Array.isArray(valor) ? valor.map((item) => (typeof item === "string" ? this.tapar(item) : item)) : valor;
    const op: OpArista = previa
      ? { ...previa, estado: combinar(previa.estado, estado, opciones.forzar), forzar: previa.forzar || !!opciones.forzar, atributos: mezclar(previa.atributos, acotar(limpios)), ultima: procedencia, veces: previa.veces + 1 }
      : { particion, origen: desde, tipo, destino: hacia, estado, forzar: !!opciones.forzar, atributos: acotar(limpios), primera: procedencia, ultima: procedencia, veces: 1 };
    this.pendAristas.set(llave, op);
    this.programar();
  }

  /** Vacía sin esperar si el lote creció; si no, al rato (o al terminar la herramienta, o antes de leer). */
  private programar(): void {
    if (this.pendNodos.size + this.pendAristas.size >= LOTE) return this.vaciar();
    if (this.temporizador) return;
    this.temporizador = setTimeout(() => {
      this.temporizador = undefined;
      try { this.vaciar(); } catch { /* el grafo nunca rompe un turno */ }
    }, 1000);
    this.temporizador.unref?.();
  }

  pendientes(): number {
    return this.pendNodos.size + this.pendAristas.size;
  }

  private cuenta(particion: string): { nodos: number; aristas: number } {
    let cuenta = this.cuentas.get(particion);
    if (!cuenta) {
      cuenta = { nodos: Number((this.sql().contarNodos!.get(particion) as { n: number }).n), aristas: Number((this.sql().contarAristas!.get(particion) as { n: number }).n) };
      this.cuentas.set(particion, cuenta);
    }
    return cuenta;
  }

  private descartar(tipo: string, particion: string): void {
    this.descartadas.set(tipo, (this.descartadas.get(tipo) ?? 0) + 1);
    if (this.avisados.has(`${particion}|${tipo}`)) return;
    this.avisados.add(`${particion}|${tipo}`);
    this.opciones.evento?.("grafo.tope", { particion, tipo, nodos: this.cuenta(particion).nodos, aristas: this.cuenta(particion).aristas });
  }

  private escribirNodo(op: OpNodo, tocados: Set<number>): number | undefined {
    const llave = `${op.particion}\n${op.clave}`;
    let fila = this.filas.get(llave);
    if (!fila) {
      const guardada = this.sql().filaNodo!.get(op.particion, op.clave) as { id: number; estado: string; atributos: string } | undefined;
      if (guardada) {
        fila = { id: Number(guardada.id), estado: guardada.estado as Estado, atributos: json(guardada.atributos) };
        this.filas.set(llave, fila);
      }
    }
    if (!fila) {
      const cuenta = this.cuenta(op.particion);
      if (cuenta.nodos >= (this.opciones.limites?.nodos ?? TOPES.nodos) && !SIEMPRE.has(op.tipo)) {
        this.descartar(op.tipo, op.particion);
        return undefined;
      }
      const p = op.primera;
      const u = op.ultima;
      const { id } = this.sql().insertarNodo!.get(op.particion, op.clave, op.tipo, op.etiqueta, op.estado, op.destino ?? null, JSON.stringify(op.atributos), p.herramienta, p.evidencia, p.worker, p.sesion, p.momento, u.herramienta, u.evidencia, u.worker, u.sesion, u.momento, Math.max(1, op.veces)) as { id: number };
      fila = { id: Number(id), estado: op.estado, atributos: op.atributos };
      this.filas.set(llave, fila);
      cuenta.nodos++;
      tocados.add(fila.id);
      return fila.id;
    }
    if (op.referencia) return fila.id;
    const estado = combinar(fila.estado, op.estado, op.forzar);
    const atributos = mezclar(fila.atributos, op.atributos);
    const u = op.ultima;
    this.sql().actualizarNodo!.run(op.etiqueta, estado, op.destino ?? null, JSON.stringify(atributos), u.herramienta, u.evidencia, u.worker, u.sesion, u.momento, op.veces, fila.id);
    fila.estado = estado;
    fila.atributos = atributos;
    tocados.add(fila.id);
    return fila.id;
  }

  private escribirArista(op: OpArista, nodos: Set<number>, aristas: Set<number>): void {
    const origen = this.filas.get(`${op.particion}\n${op.origen.clave}`)?.id ?? this.escribirNodo(op.origen, nodos);
    const destino = this.filas.get(`${op.particion}\n${op.destino.clave}`)?.id ?? this.escribirNodo(op.destino, nodos);
    if (origen === undefined || destino === undefined) return;
    const llave = `${op.particion}\n${origen}\n${op.tipo}\n${destino}`;
    let fila = this.filasArista.get(llave);
    if (!fila) {
      const guardada = this.sql().filaArista!.get(op.particion, origen, op.tipo, destino) as { id: number; estado: string; atributos: string } | undefined;
      if (guardada) {
        fila = { id: Number(guardada.id), estado: guardada.estado as Estado, atributos: json(guardada.atributos) };
        this.filasArista.set(llave, fila);
      }
    }
    if (!fila) {
      const cuenta = this.cuenta(op.particion);
      if (cuenta.aristas >= (this.opciones.limites?.aristas ?? TOPES.aristas)) {
        this.descartar(`arista:${op.tipo}`, op.particion);
        return;
      }
      const estado = op.tipo === "accesible_por" ? estadoDeAcceso(op.atributos, op.estado) : op.estado;
      const p = op.primera;
      const u = op.ultima;
      const { id } = this.sql().insertarArista!.get(op.particion, origen, op.tipo, destino, estado, JSON.stringify(op.atributos), p.herramienta, p.evidencia, p.worker, p.sesion, p.momento, u.herramienta, u.evidencia, u.worker, u.sesion, u.momento, op.veces) as { id: number };
      this.filasArista.set(llave, { id: Number(id), estado, atributos: op.atributos });
      cuenta.aristas++;
      aristas.add(Number(id));
      return;
    }
    const atributos = mezclar(fila.atributos, op.atributos);
    const combinado = combinar(fila.estado, op.estado, op.forzar);
    const estado = op.tipo === "accesible_por" && !op.forzar ? estadoDeAcceso(atributos, combinado === "refutado" ? "inferido" : combinado) : combinado;
    const u = op.ultima;
    this.sql().actualizarArista!.run(estado, JSON.stringify(atributos), u.herramienta, u.evidencia, u.worker, u.sesion, u.momento, op.veces, fila.id);
    fila.estado = estado;
    fila.atributos = atributos;
    aristas.add(fila.id);
  }

  /**
   * Escribe lo pendiente en una sola transacción (un punto de guardado, por si quien llama ya tiene una abierta).
   * Nunca tira: un error queda en un evento y lo pendiente se descarta.
   */
  vaciar(): void {
    if (this.temporizador) {
      clearTimeout(this.temporizador);
      this.temporizador = undefined;
    }
    if (!this.pendNodos.size && !this.pendAristas.size) return;
    const nodos = [...this.pendNodos.values()];
    const aristas = [...this.pendAristas.values()];
    this.pendNodos.clear();
    this.pendAristas.clear();
    const tocadosNodos = new Set<number>();
    const tocadasAristas = new Set<number>();
    this.db.exec("savepoint grafo");
    try {
      // Primero los nodos con observación propia, después los que sólo hacen falta como extremo.
      for (const op of nodos) if (!op.referencia) this.escribirNodo(op, tocadosNodos);
      for (const op of nodos) if (op.referencia) this.escribirNodo(op, tocadosNodos);
      for (const op of aristas) this.escribirArista(op, tocadosNodos, tocadasAristas);
      this.db.exec("release grafo");
    } catch (error) {
      try { this.db.exec("rollback to grafo"); this.db.exec("release grafo"); } catch { /* ya no había punto de guardado */ }
      // Los ids en memoria pueden no existir después del rollback: se vuelven a leer de la base.
      this.filas.clear();
      this.filasArista.clear();
      this.cuentas.clear();
      this.opciones.evento?.("grafo.error", { error: (error as Error).message.slice(0, 200), nodos: nodos.length, aristas: aristas.length });
      this.vista = undefined;
      return;
    }
    versionesLocales.set(this.db, (versionesLocales.get(this.db) ?? 0) + 1);
    if (this.vista) {
      this.aplicar(this.vista.vista, [...tocadosNodos], [...tocadasAristas]);
      this.vista.version = this.versionDb();
    }
  }

  private versionDb(): string {
    const remota = (this.db.prepare("pragma data_version").get() as { data_version: number }).data_version;
    return `${remota}:${versionesLocales.get(this.db) ?? 0}`;
  }

  private aplicar(vista: Vista, nodos: number[], aristas: number[]): void {
    const visibles = new Set(vista.particiones);
    for (let i = 0; i < nodos.length; i += 400) {
      const tramo = nodos.slice(i, i + 400);
      const filas = this.db.prepare(`select * from grafo_nodos where id in (${tramo.map(() => "?").join(",")})`).all(...tramo) as unknown as FilaNodo[];
      for (const fila of filas) if (visibles.has(fila.particion)) vista.aplicarNodo(fila);
    }
    for (let i = 0; i < aristas.length; i += 400) {
      const tramo = aristas.slice(i, i + 400);
      const filas = this.db.prepare(`select a.*, o.clave oc, d.clave dc from grafo_aristas a join grafo_nodos o on o.id=a.origen join grafo_nodos d on d.id=a.destino where a.id in (${tramo.map(() => "?").join(",")})`).all(...tramo) as unknown as FilaArista[];
      for (const fila of filas) if (visibles.has(fila.particion)) vista.aplicarArista(fila);
    }
  }

  /**
   * Lo que se ve desde esta sesión, en memoria. Se arma una vez y después se actualiza con cada escritura propia;
   * se rearma si cambian las particiones visibles (otro alcance) o si otra conexión escribió en la base.
   */
  ver(): Vista {
    if (!this.opciones.soloLectura) this.vaciar();
    const particiones = this.visibles();
    const llave = particiones.join("\n");
    const version = this.existe() ? this.versionDb() : "vacia";
    if (this.vista && this.vista.particiones === llave && this.vista.version === version) return this.vista.vista;
    const vista = new Vista(particiones, this.opciones.alcance ?? (() => undefined), this.opciones.senuelo);
    if (particiones.length) {
      const marcas = particiones.map(() => "?").join(",");
      for (const fila of this.db.prepare(`select * from grafo_nodos where particion in (${marcas}) order by id`).all(...particiones) as unknown as FilaNodo[]) vista.aplicarNodo(fila);
      for (const fila of this.db.prepare(`select a.*, o.clave oc, d.clave dc from grafo_aristas a join grafo_nodos o on o.id=a.origen join grafo_nodos d on d.id=a.destino where a.particion in (${marcas}) order by a.id`).all(...particiones) as unknown as FilaArista[]) vista.aplicarArista(fila);
    }
    this.vista = { particiones: llave, version, vista };
    return vista;
  }

  /** Para pruebas y el operador: cuántas filas hay en las particiones visibles. */
  tamano(): { nodos: number; aristas: number } {
    const vista = this.ver();
    return { nodos: vista.nodos.size, aristas: vista.aristas.size };
  }

  cerrar(): void {
    try { this.vaciar(); } catch { /* al cerrar no se rompe nada */ }
  }
}
