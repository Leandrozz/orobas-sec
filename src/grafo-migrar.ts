// Migración al grafo de hechos de lo que ya hay en la base de un proyecto de antes del grafo: hallazgos y sus
// vínculos, ids cosechados y pruebas cruzadas, hipótesis de la memoria, y la superficie que dejaron los
// intercambios HTTP guardados como artefactos. Cada cosa entra en la partición del programa donde nació (el
// alcance de su sesión, o el del dominio en la memoria), con «migracion» como herramienta y la evidencia que la
// identifica (el hash del intercambio cuando se puede reconstruir; si no, la fila de origen).
//
// La tabla `coverage` sólo guarda las marcas por categoría, no la superficie: no son hechos del objetivo y no
// entran como nodos (la superficie sale de los intercambios guardados).
//
// Idempotente: cada fase se hace una vez y queda anotada en `meta` dentro de la misma transacción que sus
// escrituras; los intercambios avanzan con un cursor, por tandas, para no trabar el arranque de una base grande.
import type { DatabaseSync } from "node:sqlite";
import type { Artifacts } from "./artifacts.ts";
import type { CrossRow, CrossVerdict, HarvestRow, IdKind } from "./cosecha.ts";
import type { Findings } from "./findings.ts";
import { conContexto, type Grafo } from "./grafo.ts";
import type { Alimentador, EntradaLog } from "./grafo-alimentar.ts";
import { fieldMarks, type HttpExchange } from "./http.ts";
import { decide, projectScopeTags, type Scope, type ScopeTag } from "./scope.ts";
import type { Vault } from "./vault.ts";

export interface MigracionContexto {
  db: DatabaseSync;
  grafo: Grafo;
  alimentador: Alimentador;
  artifacts: Artifacts;
  vault?: Vault;
  findings?: Findings;
  /** Intercambios guardados por tanda (por defecto 2000): lo que falta sigue la próxima vez que se abre. */
  tanda?: number;
}

export interface MigracionResultado {
  hallazgos: number;
  cosechados: number;
  cruces: number;
  hipotesis: number;
  intercambios: number;
  /** Intercambios que no se pudieron atribuir a un solo programa (o a ninguno): no entran. */
  sinPrograma: number;
  pendientes: boolean;
}

const CLAVE = "grafo.migracion";
const MAX_ARTEFACTO = 3 * 1024 * 1024;

interface Estado {
  version: 1;
  fases: Record<string, boolean>;
  /** Último artefacto http procesado (por rowid de artifacts). */
  cursor: number;
  terminado: boolean;
}

const tabla = (db: DatabaseSync, nombre: string) => !!db.prepare("select 1 from sqlite_master where type='table' and name=?").get(nombre);

function leerEstado(db: DatabaseSync): Estado {
  const fila = db.prepare("select value from meta where key=?").get(CLAVE) as { value: string } | undefined;
  try { if (fila) return JSON.parse(fila.value) as Estado; } catch { /* estado roto: se rehace, las escrituras son idempotentes en nodos */ }
  return { version: 1, fases: {}, cursor: 0, terminado: false };
}

/** El programa de cada sesión: su última revisión de alcance. Sin alcance propio, undefined (partición de la sesión). */
function programas(db: DatabaseSync): { tag: (sesion: string) => ScopeTag | undefined; alcances: Map<string, Scope[]> } {
  const tags = new Map<string, ScopeTag>();
  for (const { session, tag } of projectScopeTags(db)) if (session) tags.set(session, tag);
  const alcances = new Map<string, Scope[]>();
  if (tabla(db, "scope")) {
    const columnas = db.prepare("pragma table_info(scope)").all() as Array<{ name: string }>;
    if (columnas.some((columna) => columna.name === "session_id")) {
      for (const fila of db.prepare("select json, session_id from scope where session_id is not null order by rev").all() as Array<{ json: string; session_id: string }>) {
        try { alcances.set(fila.session_id, [...(alcances.get(fila.session_id) ?? []), JSON.parse(fila.json) as Scope]); } catch { /* fila ilegible */ }
      }
    }
  }
  return { tag: (sesion) => tags.get(sesion), alcances };
}

/**
 * Ids de intercambio (h12) de una sesión con el hash de su artefacto, sacados de lo que el agente leyó (el resumen
 * de http_request y la tabla de los checkpoints). Un id que en la sesión apuntó a dos artefactos (los ids vuelven a
 * empezar al retomar) queda sin resolver.
 */
function hashesDeSesion(db: DatabaseSync, artifacts: Artifacts, sesion: string): Map<string, string> {
  const vistos = new Map<string, Set<string>>();
  for (const { json } of db.prepare("select json from messages where session_id=? and (json like '%sha256:%')").all(sesion) as Array<{ json: string }>) {
    for (const match of json.matchAll(/\b(h\d+)\b[^\n"\\]{0,200}?(sha256:[0-9a-f]{12,64})/g)) {
      const completo = artifacts.find(match[2]!);
      if (completo) vistos.set(match[1]!, (vistos.get(match[1]!) ?? new Set()).add(completo));
    }
  }
  return new Map([...vistos].filter(([, hashes]) => hashes.size === 1).map(([id, hashes]) => [id, [...hashes][0]!]));
}

function fase(contexto: MigracionContexto, estado: Estado, nombre: string, fn: () => number): number {
  if (estado.fases[nombre]) return 0;
  const { db, grafo } = contexto;
  db.exec("savepoint grafo_migracion");
  try {
    const n = fn();
    grafo.vaciar();
    estado.fases[nombre] = true;
    db.prepare("insert into meta(key,value) values(?,?) on conflict(key) do update set value=excluded.value").run(CLAVE, JSON.stringify(estado));
    db.exec("release grafo_migracion");
    return n;
  } catch (error) {
    db.exec("rollback to grafo_migracion");
    db.exec("release grafo_migracion");
    grafo.olvidarCache();
    throw error;
  }
}

/** Corre lo que falte de la migración. Una base nueva (o ya migrada) no hace nada. */
export function migrarGrafo(contexto: MigracionContexto): MigracionResultado {
  const { db, grafo, alimentador, artifacts } = contexto;
  const resultado: MigracionResultado = { hallazgos: 0, cosechados: 0, cruces: 0, hipotesis: 0, intercambios: 0, sinPrograma: 0, pendientes: false };
  const estado = leerEstado(db);
  if (estado.terminado) return resultado;
  const { tag, alcances } = programas(db);
  const hashes = new Map<string, Map<string, string>>();
  const resolver = (sesion: string, id: string) => {
    if (!hashes.has(sesion)) hashes.set(sesion, hashesDeSesion(db, artifacts, sesion));
    return hashes.get(sesion)!.get(id);
  };

  resultado.hallazgos = fase(contexto, estado, "hallazgos", () => {
    if (!contexto.findings || !tabla(db, "findings")) return 0;
    const todos = contexto.findings.list();
    for (const finding of todos) grafo.escribirEn(tag(finding.sessionId), finding.sessionId, () => conHerramienta(() => alimentador.hallazgo(finding, contexto.findings!)));
    return todos.length;
  });

  resultado.cosechados = fase(contexto, estado, "cosecha", () => {
    if (!tabla(db, "ids_cosechados")) return 0;
    const filas = db.prepare("select session_id, identidad, valor, tipo, metodo, origen, campo, enlace, descubierto, intercambio, at from ids_cosechados order by session_id, at").all() as Array<Record<string, string | number>>;
    for (const fila of filas) {
      const sesion = String(fila.session_id);
      const evidencia = resolver(sesion, String(fila.intercambio)) ?? `ids_cosechados:${sesion}:${String(fila.intercambio)}`;
      const row: HarvestRow = { identity: String(fila.identidad), value: String(fila.valor), kind: String(fila.tipo) as IdKind, method: String(fila.metodo), origin: String(fila.origen), field: String(fila.campo), link: String(fila.enlace ?? ""), discovered: !!fila.descubierto, exchange: String(fila.intercambio), at: String(fila.at) };
      grafo.escribirEn(tag(sesion), sesion, () => conHerramienta(() => alimentador.cosecha([row], { artifact: evidencia } as HttpExchange)));
    }
    return filas.length;
  });

  resultado.cruces = fase(contexto, estado, "cruces", () => {
    if (!tabla(db, "ids_cruces")) return 0;
    const filas = db.prepare("select session_id, valor, duenio, identidad, metodo, url, estado_duenio, estado, veredicto, intercambios, at from ids_cruces order by session_id, at").all() as Array<Record<string, string | number | null>>;
    for (const fila of filas) {
      const sesion = String(fila.session_id);
      const ids = String(fila.intercambios ?? "").split(",").map((id) => id.trim()).filter(Boolean);
      const resueltos = ids.map((id) => resolver(sesion, id)).filter((hash): hash is string => !!hash);
      const row: CrossRow = { value: String(fila.valor), owner: String(fila.duenio), identity: String(fila.identidad), method: String(fila.metodo), url: String(fila.url), ownerStatus: fila.estado_duenio === null ? undefined : Number(fila.estado_duenio), status: fila.estado === null ? undefined : Number(fila.estado), verdict: String(fila.veredicto) as CrossVerdict, exchanges: String(fila.intercambios ?? ""), at: String(fila.at) };
      grafo.escribirEn(tag(sesion), sesion, () => conHerramienta(() => alimentador.cruce(row, resueltos.length ? resueltos : [`ids_cruces:${sesion}:${ids.join("+") || "?"}`])));
    }
    return filas.length;
  });

  resultado.hipotesis = fase(contexto, estado, "memoria", () => {
    if (!contexto.vault || !tabla(db, "memory")) return 0;
    let n = 0;
    for (const { id } of db.prepare("select id from memory where type='hipotesis'").all() as Array<{ id: string }>) {
      const leido = contexto.vault.read(id);
      const programa = leido?.record.scope;
      // Como la memoria: una nota de programa desconocido («?») o sin alcance no se atribuye a nadie.
      if (!leido || !programa?.program || programa.program === "?") continue;
      grafo.escribirEn({ program: programa.program, domains: programa.domains }, `memoria:${id}`, () => conHerramienta(() => alimentador.hipotesisDeMemoria(leido.record.id, leido.record.rev, leido.record.title, leido.record.state, leido.record.summary)));
      n++;
    }
    return n;
  });

  // Intercambios guardados: la superficie (rutas, métodos, identidades, parámetros, tecnologías). Un artefacto entra
  // en el programa de la única sesión cuyo alcance lo cubría; si lo cubrían varios programas, o ninguno, no entra.
  if (!estado.fases.intercambios) {
    const tanda = contexto.tanda ?? 2000;
    const filas = tabla(db, "artifacts")
      ? db.prepare("select rowid, hash, bytes from artifacts where producer='http' and rowid > ? order by rowid limit ?").all(estado.cursor, tanda) as Array<{ rowid: number; hash: string; bytes: number }>
      : [];
    db.exec("savepoint grafo_migracion");
    try {
      for (const fila of filas) {
        estado.cursor = Number(fila.rowid);
        if (fila.bytes > MAX_ARTEFACTO) continue;
        let exchange: HttpExchange;
        try { exchange = JSON.parse(artifacts.read(fila.hash).toString("utf8")) as HttpExchange; } catch { continue; }
        if (!exchange?.request?.url || !exchange.response) continue;
        const sesiones = [...alcances].filter(([, revisiones]) => revisiones.some((alcance) => { try { return decide(alcance, exchange.request.url).allowed; } catch { return false; } })).map(([sesion]) => sesion);
        const particiones = new Map<string, string>();
        for (const sesion of sesiones) {
          const programa = tag(sesion);
          particiones.set(programa ? `${programa.program}|${programa.program === "manual" ? programa.domains.join(",") : ""}` : `sesion:${sesion}`, sesion);
        }
        if (particiones.size !== 1) { resultado.sinPrograma++; continue; }
        const sesion = [...particiones.values()][0]!;
        exchange.artifact = fila.hash;
        grafo.escribirEn(tag(sesion), sesion, () => conHerramienta(() => alimentador.intercambio(exchange, entradaDe(exchange))));
        resultado.intercambios++;
      }
      grafo.vaciar();
      if (filas.length < tanda) {
        estado.fases.intercambios = true;
        estado.terminado = Object.values(estado.fases).length >= 5;
      }
      db.prepare("insert into meta(key,value) values(?,?) on conflict(key) do update set value=excluded.value").run(CLAVE, JSON.stringify(estado));
      db.exec("release grafo_migracion");
    } catch (error) {
      db.exec("rollback to grafo_migracion");
      db.exec("release grafo_migracion");
      grafo.olvidarCache();
      throw error;
    }
    resultado.pendientes = !estado.fases.intercambios;
  }
  return resultado;
}

/** La migración escribe con «migracion» como herramienta y el harness como worker. */
const conHerramienta = (fn: () => void): void => conContexto({ herramienta: "migracion", worker: "harness" }, fn);

/**
 * La entrada del registro HTTP que habría tenido un intercambio guardado: la identidad sale del marcador que el
 * cliente dejó en sus cabeceras («<identidad ana>»), las claves del cuerpo y las marcas de sonda, de lo enviado.
 */
export function entradaDe(exchange: HttpExchange): EntradaLog {
  const cabeceras = exchange.request.headers ?? {};
  const identidad = Object.values(cabeceras).map((valor) => /^<identidad ([^>]+)>$/.exec(String(valor))?.[1]).find(Boolean);
  const sentAuth = Object.keys(cabeceras).some((clave) => /^(authorization|cookie|x-auth|x-api-key)$/i.test(clave));
  const query: Record<string, string> = {};
  const marks: Array<{ key: string; mark: "inyeccion" | "traversal" | "externo" }> = [];
  try {
    for (const [clave, valor] of new URL(exchange.request.url).searchParams) {
      query[clave] = valor.slice(0, 200);
      for (const mark of fieldMarks(valor)) marks.push({ key: clave, mark });
    }
  } catch { /* URL rota */ }
  let bodyKeys: string[] = [];
  const body = exchange.request.body;
  if (body) {
    try {
      const parsed = JSON.parse(body) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        bodyKeys = Object.keys(parsed);
        for (const [clave, valor] of Object.entries(parsed)) if (typeof valor === "string") for (const mark of fieldMarks(valor)) marks.push({ key: clave, mark });
      }
    } catch {
      for (const match of body.matchAll(/(?:^|&)([^=&]+)=([^&]*)/g)) {
        let clave = match[1]!;
        let valor = match[2]!;
        try { clave = decodeURIComponent(clave.replace(/\+/g, " ")); valor = decodeURIComponent(valor.replace(/\+/g, " ")); } catch { /* queda como vino */ }
        bodyKeys.push(clave);
        for (const mark of fieldMarks(valor)) marks.push({ key: clave, mark });
      }
    }
  }
  return {
    id: exchange.id, method: exchange.request.method, url: exchange.request.url, status: exchange.response?.status, hash: exchange.artifact,
    query, bodyKeys, bodyIds: [], sentAuth, ...(identidad ? { identity: identidad } : {}), ...(marks.length ? { marks } : {}),
  };
}
