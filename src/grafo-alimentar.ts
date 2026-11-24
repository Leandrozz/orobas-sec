// Alimentación del grafo de hechos (src/grafo.ts) desde lo que el harness ya hace, sin pedirle nada al modelo:
// cada respuesta HTTP (host, servicio, ruta con método, parámetros, identidad que la pidió y qué obtuvo,
// tecnologías, cookies por nombre, redirecciones, enlaces y formularios), cada operación importada o leída del
// código, cada id cosechado y cada prueba cruzada, cada hallazgo y sus vínculos, los CVE cruzados, la lectura de
// fuente (web_source_pull, code_crypto) y el recon (nmap, httpx, subfinder, katana, crt.sh, Wayback). Todo es
// determinista y lleva su evidencia: el hash del intercambio o del artefacto que lo prueba.
//
// Lo que viene del objetivo entra como dato acotado: rutas canónicas, nombres de parámetro y de cookie, nunca
// valores de cuerpos ni de cabeceras de credencial. Lo que pueda ser del operador lo tapa el grafo (`tapar`).
import { idKind, familyOfUrl, urlIds, type CrossRow, type HarvestRow, ANON, UNNAMED, type IdKind } from "./cosecha.ts";
import { OAUTH_PARAMS, OAUTH_PATH, parseSetCookie } from "./cadenas.ts";
import { techsFromExchange, tecnologia } from "./cvefeed.ts";
import type { Artifacts } from "./artifacts.ts";
import type { Finding, Findings } from "./findings.ts";
import { contextoGrafo, type ContextoEscritura, type Estado, type Grafo, type NodoSpec } from "./grafo.ts";
import { isStaticAsset, type HttpClient, type HttpExchange, type ObservedOperation } from "./http.ts";
import { decide, type Scope } from "./scope.ts";
import { jsonLines, parseNmapXml } from "./toolbox.ts";
import type { Vault } from "./vault.ts";

export type EntradaLog = HttpClient["log"][number];

const MAX_ENLACES = 60;
const MAX_PARAMS = 40;
const MAX_RECON = 300;
const ESCRITURAS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Origen y ruta de una URL; undefined si no es http(s). */
function partes(url: string): { origen: string; ruta: string; host: string; url: URL } | undefined {
  try {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) return undefined;
    return { origen: parsed.origin, ruta: parsed.pathname, host: parsed.hostname.replace(/^\[|\]$/g, ""), url: parsed };
  } catch {
    return undefined;
  }
}

/** Constructores de nodos: el identificador canónico de cada tipo vive acá y en ningún otro lado. */
export const nodos = {
  host(host: string, estado: Estado = "observado"): NodoSpec {
    const limpio = host.toLowerCase().replace(/^\[|\]$/g, "");
    return { tipo: "host", id: limpio, etiqueta: limpio, estado, destino: limpio };
  },
  servicio(origen: string, estado: Estado = "observado", atributos: NodoSpec["atributos"] = {}): NodoSpec {
    return { tipo: "servicio", id: origen.toLowerCase(), etiqueta: origen.toLowerCase(), estado, destino: `${origen}/`, atributos };
  },
  /** Ruta canónica con método: la familia (ids como {n}) del origen. `url` es una de verdad, para el alcance. */
  ruta(metodo: string, url: string, estado: Estado, atributos: NodoSpec["atributos"] = {}): NodoSpec | undefined {
    const p = partes(url);
    if (!p) return undefined;
    const verbo = metodo.toUpperCase();
    const familia = familyOfUrl(p.url.href);
    const oauth = OAUTH_PATH.test(p.ruta) || [...p.url.searchParams.keys()].some((nombre) => OAUTH_PARAMS.test(nombre));
    return {
      tipo: "ruta", id: `${verbo} ${p.origen}${familia}`, etiqueta: `${verbo} ${familia}`, estado, destino: `${p.origen}${p.ruta}`,
      atributos: { metodo: verbo, familia, origen: p.origen, ...(familia.includes("{n}") ? { con_id: true } : {}), ...(oauth ? { oauth: true } : {}), ...atributos },
    };
  },
  parametro(url: string, ubicacion: "consulta" | "cuerpo", nombre: string, estado: Estado, atributos: NodoSpec["atributos"] = {}): NodoSpec | undefined {
    const p = partes(url);
    if (!p || !nombre.trim()) return undefined;
    const familia = familyOfUrl(p.url.href);
    const corto = nombre.trim().slice(0, 64);
    return { tipo: "parametro", id: `${p.origen}${familia}|${ubicacion}|${corto}`, etiqueta: `${ubicacion === "consulta" ? "?" : ""}${corto} en ${familia}`, estado, destino: `${p.origen}${p.ruta}`, atributos: { nombre: corto, ubicacion, familia, ...(OAUTH_PARAMS.test(corto) ? { oauth: true } : {}), ...atributos } };
  },
  identidad(nombre: string): NodoSpec {
    return { tipo: "identidad", id: nombre, etiqueta: nombre, estado: "observado", atributos: { anonima: nombre === ANON } };
  },
  /** Objeto por id: UUID y ObjectId son únicos; un número se distingue por el recurso donde vive. */
  objeto(valor: string, clase: IdKind, recurso: string, atributos: NodoSpec["atributos"] = {}, destino?: string): NodoSpec {
    const id = clase === "numero" ? `numero:${recurso || "?"}/${valor}` : `${clase}:${valor.toLowerCase()}`;
    return { tipo: "objeto", id, etiqueta: clase === "numero" ? `${recurso || "?"}#${valor}` : valor, estado: "observado", atributos: { valor, clase, recurso: recurso || "?", ...atributos }, ...(destino ? { destino } : {}) };
  },
  tecnologia(clave: string, producto: string, version: string | undefined, atributos: NodoSpec["atributos"] = {}): NodoSpec {
    return { tipo: "tecnologia", id: `${clave}@${version ?? "*"}`, etiqueta: `${producto}${version ? ` ${version}` : ""}`, estado: "observado", atributos: { producto, ...(version ? { version } : {}), ...atributos } };
  },
  cookie(origen: string, nombre: string, atributos: NodoSpec["atributos"] = {}): NodoSpec {
    return { tipo: "credencial", id: `cookie ${origen} ${nombre}`, etiqueta: `cookie ${nombre}`, estado: "observado", destino: `${origen}/`, atributos: { clase: "cookie", nombre, ...atributos } };
  },
  archivo(ruta: string, atributos: NodoSpec["atributos"] = {}): NodoSpec {
    return { tipo: "artefacto", id: `archivo:${ruta}`, etiqueta: ruta, estado: "observado", atributos: { clase: "archivo", ...atributos } };
  },
  funcion(archivo: string, nombre: string): NodoSpec {
    return { tipo: "artefacto", id: `funcion:${archivo}#${nombre}`, etiqueta: `${nombre}() en ${archivo}`, estado: "observado", atributos: { clase: "funcion", archivo, nombre } };
  },
  evidencia(hash: string, productor: string): NodoSpec {
    return { tipo: "artefacto", id: `evidencia:${hash}`, etiqueta: `${productor} ${hash.slice(0, 19)}`, estado: "observado", atributos: { clase: "evidencia", productor } };
  },
  hallazgo(finding: Pick<Finding, "id" | "title" | "state" | "severity" | "kind" | "asset" | "sessionId">): NodoSpec {
    const estado: Estado = finding.state === "verificado" ? "verificado" : finding.state === "descartado" ? "refutado" : finding.state === "candidato" ? "observado" : "inferido";
    const destino = /^[a-z][a-z0-9+.-]*:\/\//i.test(finding.asset.trim()) ? finding.asset.trim().split(/\s/)[0] : undefined;
    return { tipo: "hallazgo", id: finding.id, etiqueta: finding.title, estado, forzar: true, atributos: { corto: finding.id.slice(0, 8), estado_hallazgo: finding.state, severidad: finding.severity, clase: finding.kind, activo: finding.asset, sesion: finding.sessionId }, ...(destino ? { destino } : {}) };
  },
  hipotesis(id: string, texto: string, estado: Estado = "inferido", atributos: NodoSpec["atributos"] = {}): NodoSpec {
    return { tipo: "hipotesis", id, etiqueta: texto, estado, atributos };
  },
  cve(id: string, atributos: NodoSpec["atributos"] = {}): NodoSpec {
    return { tipo: "cve", id: id.toUpperCase(), etiqueta: id.toUpperCase(), estado: "inferido", atributos };
  },
};

/** Quién pidió una entrada del registro HTTP: la identidad con nombre, sin credenciales o cabeceras propias. */
export function solicitante(entrada: Pick<EntradaLog, "identity" | "sentAuth"> | undefined): string {
  return entrada?.identity ?? (entrada?.sentAuth ? UNNAMED : ANON);
}

/**
 * Recurso de un id cosechado, para distinguir ids numéricos: el segmento anterior al id en el enlace, el nombre
 * del campo sin su sufijo de id (owner_id → owner) o el padre de un «id» suelto (customer.id → customer), y si
 * no, el último segmento que no es id de la ruta donde apareció.
 */
export function recursoDe(fila: Pick<HarvestRow, "value" | "field" | "link" | "origin">): string {
  const segmentos = (url: string) => { try { return new URL(url).pathname.split("/").filter(Boolean).map((segmento) => segmento.toLowerCase()); } catch { return []; } };
  if (fila.link) {
    const lista = segmentos(fila.link);
    const at = lista.indexOf(fila.value.toLowerCase());
    if (at > 0) return lista[at - 1]!;
  }
  const partes = fila.field.replace(/\[\]/g, "").split(".").filter(Boolean);
  const hoja = partes.at(-1) ?? "";
  const palabras = hoja.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (palabras.length > 1 && /^(id|uuid|guid|oid|uid|pk|ids)$/.test(palabras.at(-1)!)) return palabras.slice(0, -1).join("_");
  const padre = partes.at(-2);
  if (padre && !/^(data|result|results|item|items|records|rows|list|payload|response|content|value|values|entries|objects|docs|hits|nodes|node|edges|script)$/i.test(padre)) return padre.toLowerCase();
  const ruta = segmentos(fila.origin).filter((segmento) => !idKind(segmento, true));
  return ruta.at(-1) ?? "";
}

export interface OpcionesAlimentador {
  grafo: Grafo;
  artifacts: Artifacts;
  http?: HttpClient;
  alcance?: () => Scope | undefined;
  sesion: string;
  /** Tapa lo del operador en una URL antes de canonizarla (pasarla a minúsculas lo volvería irreconocible). */
  tapar?: (texto: string) => string;
}

/**
 * Traduce lo que hace el harness a nodos y aristas. Cada método tolera datos rotos (no tira): el grafo nunca
 * rompe una petición ni una herramienta.
 */
export class Alimentador {
  readonly grafo: Grafo;
  readonly artifacts: Artifacts;
  readonly http?: HttpClient;
  readonly alcance?: () => Scope | undefined;
  readonly sesion: string;
  private readonly tapar: (texto: string) => string;
  /** Ids de objetos conocidos por valor: un pedido que lleva uno es un acceso a ese objeto. */
  private readonly objetos = new Map<string, NodoSpec[]>();
  /** Operaciones importadas durante cada herramienta: se escriben al terminar, con su artefacto como evidencia. */
  private readonly operaciones = new WeakMap<ContextoEscritura, ObservedOperation[]>();
  /** Errores del alimentador (para pruebas y el operador): nunca se propagan. */
  readonly errores: string[] = [];

  constructor(opciones: OpcionesAlimentador) {
    this.grafo = opciones.grafo;
    this.artifacts = opciones.artifacts;
    this.http = opciones.http;
    this.alcance = opciones.alcance;
    this.sesion = opciones.sesion;
    this.tapar = opciones.tapar ?? ((texto) => texto);
  }

  private seguro(nombre: string, fn: () => void): void {
    try {
      fn();
    } catch (error) {
      if (this.errores.length < 50) this.errores.push(`${nombre}: ${(error as Error).message}`);
    }
  }

  /** Recuerda los objetos que ya están en el grafo (al retomar una sesión) para reconocer accesos. */
  cargarObjetos(): void {
    this.seguro("objetos", () => {
      for (const nodo of this.grafo.ver().deTipo("objeto")) this.recordar({ tipo: "objeto", id: nodo.id, etiqueta: nodo.etiqueta, estado: nodo.estado, atributos: nodo.atributos });
    });
  }

  private recordar(spec: NodoSpec): void {
    const valor = String(spec.atributos?.valor ?? "").toLowerCase();
    if (!valor) return;
    const lista = this.objetos.get(valor) ?? [];
    if (!lista.some((item) => item.id === spec.id)) lista.push(spec);
    this.objetos.set(valor, lista);
  }

  /** Una respuesta HTTP (no sintética) con su entrada del registro. */
  intercambio(exchange: HttpExchange, entrada?: EntradaLog): void {
    this.seguro("intercambio", () => this.alimentarIntercambio(exchange, entrada));
  }

  private alimentarIntercambio(exchange: HttpExchange, entrada?: EntradaLog): void {
    const response = exchange.response;
    const url = this.tapar(exchange.request.url);
    const p = partes(url);
    if (!response || !p || !exchange.artifact) return;
    const g = this.grafo;
    const evidencia = exchange.artifact;
    const metodo = exchange.request.method.toUpperCase();
    const host = nodos.host(p.host);
    const servicio = nodos.servicio(p.origen, "observado", { esquema: p.url.protocol.replace(":", ""), puerto: Number(p.url.port || (p.url.protocol === "https:" ? 443 : 80)) });
    g.arista(host, "expone", servicio, "observado", evidencia);
    const tipo = (response.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
    const estatico = isStaticAsset(p.ruta);
    const ruta = estatico ? undefined : nodos.ruta(metodo, url, "observado", { estados: [response.status], ...(tipo ? { tipos: [tipo] } : {}), ...(entrada?.challenge ? { desafio: entrada.challenge } : {}) });
    if (ruta) {
      g.nodo(ruta, evidencia);
      g.arista(servicio, "expone", ruta, "observado", evidencia);
      const quien = nodos.identidad(solicitante(entrada));
      g.arista(ruta, "accesible_por", quien, "inferido", evidencia, { estados: [response.status] });
      this.parametros(url, entrada, ruta, evidencia);
      this.redireccion(exchange, url, ruta, evidencia);
      // Un pedido que lleva el id de un objeto conocido es un acceso a ese objeto con esa identidad.
      for (const valor of urlIds(url)) {
        for (const objeto of this.objetos.get(valor.toLowerCase()) ?? []) g.arista(objeto, "accesible_por", quien, "inferido", evidencia, { estados: [response.status], metodos: [metodo] });
      }
      for (const cookie of this.cookies(response.headers["set-cookie"], p.origen)) g.arista(ruta, "expone", cookie, "observado", evidencia);
    }
    for (const tech of techsFromExchange(exchange)) {
      const nodo = nodos.tecnologia(tech.clave, tech.producto, tech.version, { fuente: tech.fuente, ...(tech.complemento ? { complemento: true } : {}) });
      g.arista(servicio, "expone", nodo, "observado", evidencia);
      if (ruta) g.arista(nodo, "observado_en", ruta, "observado", evidencia);
    }
    if (ruta && /html/i.test(tipo) && response.bodyEncoding !== "base64") this.enlaces(response.body, url, ruta, evidencia);
  }

  private parametros(url: string, entrada: EntradaLog | undefined, ruta: NodoSpec, evidencia: string): void {
    const marcas = new Map<string, Set<string>>();
    for (const marca of entrada?.marks ?? []) marcas.set(marca.key, (marcas.get(marca.key) ?? new Set()).add(marca.mark));
    const nombres: Array<{ nombre: string; ubicacion: "consulta" | "cuerpo" }> = [];
    try { for (const nombre of new URL(url).searchParams.keys()) nombres.push({ nombre, ubicacion: "consulta" }); } catch { /* sin consulta */ }
    for (const nombre of new Set([...(entrada?.bodyKeys ?? []), ...(entrada?.fields ?? [])])) nombres.push({ nombre, ubicacion: "cuerpo" });
    const vistos = new Set<string>();
    for (const { nombre, ubicacion } of nombres) {
      if (vistos.size >= MAX_PARAMS || vistos.has(`${ubicacion}|${nombre}`)) continue;
      vistos.add(`${ubicacion}|${nombre}`);
      const probado = [...(marcas.get(nombre) ?? [])];
      const param = nodos.parametro(url, ubicacion, nombre, "observado", probado.length ? { marcas: probado } : {});
      if (param) this.grafo.arista(ruta, "acepta", param, "observado", evidencia);
      if (param && probado.length) this.grafo.nodo(param, evidencia);
    }
  }

  /** Una redirección: a qué host va y si lo decide un parámetro de la consulta (la base de un open redirect). */
  private redireccion(exchange: HttpExchange, url: string, ruta: NodoSpec, evidencia: string): void {
    const response = exchange.response!;
    const location = response.headers.location;
    if (!location || response.status < 300 || response.status >= 400) return;
    let destino: URL;
    let origen: URL;
    try { origen = new URL(url); destino = new URL(this.tapar(location), origen); } catch { return; }
    const externo = destino.host !== origen.host;
    const controlado = [...origen.searchParams].find(([, valor]) => {
      if (!valor) return false;
      try { return new URL(valor, origen).href === destino.href || (valor.includes(destino.host) && externo); } catch { return false; }
    })?.[0];
    this.grafo.nodo({ ...ruta, atributos: { ...ruta.atributos, redirige: true, ...(externo ? { redirige_a: [destino.hostname] } : {}), ...(controlado ? { redireccion_por: controlado } : {}) } }, evidencia);
    if (externo && /^https?:$/.test(destino.protocol)) this.grafo.arista(ruta, "expone", nodos.host(destino.hostname), "observado", evidencia, { via: "redireccion", ...(controlado ? { parametro: controlado } : {}) });
    if (controlado) {
      const param = nodos.parametro(url, "consulta", controlado, "observado", { redirige: true });
      if (param) this.grafo.nodo(param, evidencia);
    }
  }

  /** Cookies que fijó la respuesta: por nombre y banderas, nunca el valor. */
  private cookies(cabecera: string | undefined, origen: string): NodoSpec[] {
    if (!cabecera) return [];
    const lineas = cabecera.split(/\n|,(?=\s*[^;,=\s]+=)/).map((linea) => linea.trim()).filter(Boolean);
    return parseSetCookie(cabecera).map((cookie, i) => {
      const linea = lineas[i] ?? "";
      const samesite = /;\s*samesite\s*=\s*(\w+)/i.exec(linea)?.[1]?.toLowerCase();
      return nodos.cookie(origen, cookie.name, { httponly: cookie.httpOnly, secure: /;\s*secure\s*(;|$)/i.test(linea), ...(samesite ? { samesite } : {}) });
    }).slice(0, 20);
  }

  /** Enlaces y formularios del mismo origen en una página: rutas vistas (inferidas) hasta que se pidan. */
  private enlaces(html: string, base: string, pagina: NodoSpec, evidencia: string): void {
    const cuerpo = html.slice(0, 500_000);
    const origen = partes(base)?.origen;
    if (!origen) return;
    let cuenta = 0;
    const agregar = (destino: string, metodo: string, campos: string[] = []) => {
      if (cuenta >= MAX_ENLACES) return;
      let url: URL;
      try { url = new URL(destino.replace(/&amp;/g, "&"), base); } catch { return; }
      if (url.origin !== origen || isStaticAsset(url.pathname)) return;
      const ruta = nodos.ruta(metodo, url.href, "inferido", { via: metodo === "GET" ? "enlace" : "formulario" });
      if (!ruta) return;
      cuenta++;
      this.grafo.arista(pagina, "expone", ruta, "observado", evidencia);
      for (const nombre of [...url.searchParams.keys()].slice(0, 10)) {
        const param = nodos.parametro(url.href, "consulta", nombre, "inferido");
        if (param) this.grafo.arista(ruta, "acepta", param, "inferido", evidencia);
      }
      for (const nombre of campos.slice(0, 20)) {
        const param = nodos.parametro(url.href, metodo === "GET" ? "consulta" : "cuerpo", nombre, "inferido");
        if (param) this.grafo.arista(ruta, "acepta", param, "inferido", evidencia);
      }
    };
    for (const match of cuerpo.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
      const atributos = match[1]!;
      const accion = /\baction\s*=\s*["']([^"']*)["']/i.exec(atributos)?.[1] ?? base;
      const metodo = (/\bmethod\s*=\s*["']?(\w+)/i.exec(atributos)?.[1] ?? "GET").toUpperCase();
      const campos = [...match[2]!.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']{1,64})["']/gi)].map((campo) => campo[1]!);
      agregar(accion, ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(metodo) ? metodo : "GET", campos);
    }
    for (const match of cuerpo.matchAll(/\b(?:href|src)\s*=\s*["']([^"'#]+)["']/gi)) agregar(match[1]!, "GET");
  }

  /**
   * Una operación importada o leída (OpenAPI, HAR, Postman, js_endpoints, el código bajado): es una posibilidad,
   * no una prueba. Se junta durante la herramienta y se escribe al terminar con el artefacto de la herramienta.
   */
  operacion(operacion: ObservedOperation): void {
    this.seguro("operacion", () => {
      const contexto = contextoGrafo.getStore();
      if (contexto) {
        const lista = this.operaciones.get(contexto) ?? [];
        if (lista.length < 2000) lista.push(operacion);
        this.operaciones.set(contexto, lista);
        return;
      }
      // Fuera de una herramienta no hay salida que la respalde: la operación misma queda como artefacto.
      const hash = this.artifacts.put(JSON.stringify(operacion), "application/json", "grafo:operacion").hash;
      this.escribirOperaciones([operacion], hash);
    });
  }

  private escribirOperaciones(operaciones: ObservedOperation[], evidencia: string): void {
    for (const original of operaciones) {
      const operacion = { ...original, url: this.tapar(original.url) };
      const ruta = nodos.ruta(operacion.method, operacion.url, "inferido", { via: "contrato" });
      if (!ruta) continue;
      this.grafo.nodo(ruta, evidencia);
      const p = partes(operacion.url);
      if (p) this.grafo.arista(nodos.servicio(p.origen, "inferido"), "expone", ruta, "inferido", evidencia);
      for (const nombre of (operacion.params ?? []).slice(0, MAX_PARAMS)) {
        const param = nodos.parametro(operacion.url, "consulta", nombre, "inferido");
        if (param) this.grafo.arista(ruta, "acepta", param, "inferido", evidencia);
      }
      for (const nombre of (operacion.bodyKeys ?? []).slice(0, MAX_PARAMS)) {
        const param = nodos.parametro(operacion.url, "cuerpo", nombre, "inferido");
        if (param) this.grafo.arista(ruta, "acepta", param, "inferido", evidencia);
      }
    }
  }

  /** Ids cosechados de una respuesta: el objeto, dónde apareció y de quién es (si le llegó sin pedirlo). */
  cosecha(filas: HarvestRow[], exchange: HttpExchange): void {
    this.seguro("cosecha", () => {
      if (!exchange.artifact) return;
      for (const fila of filas) {
        const recurso = recursoDe(fila);
        const objeto = nodos.objeto(fila.value, fila.kind, recurso, { campo: fila.field.slice(0, 80) }, fila.link ? this.tapar(fila.link) : undefined);
        this.recordar(objeto);
        const ruta = nodos.ruta(fila.method, this.tapar(fila.origin), "observado");
        if (ruta) this.grafo.arista(objeto, "observado_en", ruta, "observado", exchange.artifact, { campo: fila.field.slice(0, 80) });
        else this.grafo.nodo(objeto, exchange.artifact);
        // La propiedad es una inferencia del harness: le llegó sin pedirlo (ver src/cosecha.ts).
        if (fila.discovered) this.grafo.arista(objeto, "pertenece_a", nodos.identidad(fila.identity), "inferido", exchange.artifact, { criterio: "le llegó sin pedirlo" });
      }
    });
  }

  /** Una prueba cruzada de ids_harvest: la otra identidad leyó, modificó o fue negada sobre el objeto del dueño. */
  cruce(fila: CrossRow, conocidos?: string[]): void {
    this.seguro("cruce", () => {
      if (fila.verdict === "omitida") return;
      const hashes = conocidos ?? fila.exchanges.split(",").map((id) => this.http?.hashOf(id.trim())).filter((hash): hash is string => !!hash);
      const evidencia = hashes.at(-1);
      if (!evidencia) return;
      const conocido = this.objetos.get(fila.value.toLowerCase())?.[0];
      const clase = idKind(fila.value, true) ?? "numero";
      const objeto = conocido ?? nodos.objeto(fila.value, clase, familyOfUrl(this.tapar(fila.url)).split("/").filter((segmento) => segmento && segmento !== "{n}").at(-1) ?? "");
      this.grafo.arista(objeto, "accesible_por", nodos.identidad(fila.identity), "inferido", evidencia, { veredicto: fila.verdict, metodos: [fila.method], ...(fila.status !== undefined ? { estados: [fila.status] } : {}), duenio: fila.owner, intercambios: hashes.map((hash) => hash.slice(0, 19)) });
    });
  }

  /**
   * Un hallazgo nuevo o cambiado: su nodo (el estado sigue al del hallazgo), dónde se observó según su evidencia,
   * sus vínculos como aristas «habilita» y el estado de las hipótesis que se le enlazaron.
   */
  hallazgo(finding: Finding, findings: Findings): void {
    this.seguro("hallazgo", () => {
      const g = this.grafo;
      const nodo = nodos.hallazgo(finding);
      const propia = `hallazgo:${finding.id}@${finding.rev}`;
      g.nodo(nodo, finding.evidence[0] ?? propia);
      for (const hash of finding.evidence.slice(0, 10)) {
        const intercambio = this.leerIntercambio(hash);
        const ruta = intercambio ? nodos.ruta(intercambio.method, this.tapar(intercambio.url), "observado") : undefined;
        if (ruta) g.arista(nodo, "observado_en", ruta, "observado", hash);
        else g.arista(nodo, "deriva_de", nodos.evidencia(hash, this.artifacts.producer(hash) ?? "artefacto"), "observado", hash);
      }
      const todos = findings.list();
      for (const { finding: otro, role } of findings.linksOf(finding.id, todos)) {
        if (role === "relacionado") continue;
        const [habilitador, escalada] = role === "habilita" ? [finding, otro] : [otro, finding];
        const estado: Estado = habilitador.state === "descartado" || escalada.state === "descartado" ? "refutado" : escalada.state === "verificado" ? "verificado" : "inferido";
        g.arista(nodos.hallazgo(habilitador), "habilita", nodos.hallazgo(escalada), estado, `hallazgo:${finding.id}@${finding.rev}`, { evidencias: [...habilitador.evidence.slice(0, 3), ...escalada.evidence.slice(0, 3)].map((hash) => hash.slice(0, 19)) }, { forzar: true });
      }
      // Hipótesis que el agente ató a este hallazgo: se confirman o se caen con él.
      if (finding.state === "verificado" || finding.state === "descartado") {
        const vista = g.ver();
        const clave = g.clave(nodo);
        for (const arista of vista.salientes.get(clave) ?? []) {
          const destino = vista.nodos.get(arista.destino);
          if (arista.tipo !== "deriva_de" || destino?.tipo !== "hipotesis") continue;
          g.nodo({ tipo: "hipotesis", id: destino.id, etiqueta: destino.etiqueta, estado: finding.state === "verificado" ? "verificado" : "refutado", forzar: true }, propia);
        }
      }
    });
  }

  /** El método y la URL de un intercambio guardado; undefined si el artefacto no es uno. */
  private leerIntercambio(hash: string): { method: string; url: string } | undefined {
    try {
      const data = JSON.parse(this.artifacts.read(hash).toString("utf8")) as { request?: { method?: string; url?: string } };
      return data.request?.url ? { method: data.request.method ?? "GET", url: data.request.url } : undefined;
    } catch {
      return undefined;
    }
  }

  /** Un CVE que el feed cruzó con una tecnología vista: una pista (inferida), nunca un hallazgo. */
  cve(evento: { cve?: unknown; tecnologia?: unknown; version?: unknown; activo?: unknown; fuente?: unknown; severidad?: unknown; cvss?: unknown; veredicto?: unknown; confirmacion?: unknown }): void {
    this.seguro("cve", () => {
      const id = String(evento.cve ?? "");
      if (!/^CVE-\d{4}-\d{3,}$/i.test(id)) return;
      const producto = String(evento.tecnologia ?? "");
      const version = evento.version ? String(evento.version) : undefined;
      const tech = tecnologia(producto, version, String(evento.activo ?? ""), String(evento.fuente ?? ""));
      const nodoCve = nodos.cve(id, { ...(evento.severidad ? { severidad: String(evento.severidad) } : {}), ...(evento.cvss !== undefined && evento.cvss !== null ? { cvss: Number(evento.cvss) } : {}), ...(evento.veredicto ? { veredicto: String(evento.veredicto) } : {}), ...(evento.confirmacion ? { confirmacion: String(evento.confirmacion) } : {}) });
      const evidencia = `cve_cruces:${this.sesion}:${id.toUpperCase()}`;
      if (tech) this.grafo.arista(nodos.tecnologia(tech.clave, tech.producto, tech.version), "expone", nodoCve, "inferido", evidencia, { cruce: String(evento.confirmacion ?? "texto") });
      else this.grafo.nodo(nodoCve, evidencia);
    });
  }

  /**
   * Al terminar una herramienta: lo importado durante ella y lo que su artefacto dice (fuente, recon, memoria).
   * `resultado` es lo que devolvió, sin recortar.
   */
  trasHerramienta(nombre: string, resultado: { text: string; details?: Record<string, unknown>; isError?: boolean }, vault?: Vault): void {
    this.seguro(`herramienta ${nombre}`, () => {
      const contexto = contextoGrafo.getStore();
      const artefacto = typeof resultado.details?.artefacto === "string" ? resultado.details.artefacto : undefined;
      const importadas = contexto ? this.operaciones.get(contexto) : undefined;
      if (contexto && importadas?.length) {
        this.operaciones.delete(contexto);
        const evidencia = artefacto ?? this.artifacts.put(resultado.text, "text/plain", `grafo:${nombre}`).hash;
        this.escribirOperaciones(importadas, evidencia);
      }
      if (resultado.isError) return;
      if (nombre === "memory_write") return this.memoria(resultado.text, vault);
      if (!artefacto) return;
      const datos = this.leerJson(artefacto);
      if (!datos) return;
      if (nombre === "code_crypto") this.cripto((datos.puntos as CryptoPunto[]) ?? [], artefacto);
      else if (nombre === "web_source_pull") this.fuenteWeb(datos, artefacto);
      else if (nombre === "nmap_scan") this.nmap(String(datos.stdout ?? ""), artefacto);
      else if (nombre === "httpx_probe") this.httpx(String(datos.stdout ?? ""), artefacto);
      else if (nombre === "subfinder_enum") this.hosts(String(datos.stdout ?? "").split("\n"), artefacto, "subfinder");
      else if (nombre === "crt_sh") this.hosts(Array.isArray(datos.subdominios) ? (datos.subdominios as string[]) : [], artefacto, "crt.sh");
      else if (nombre === "katana_crawl") this.urls(jsonLines(String(datos.stdout ?? "")).map((fila) => fila?.request?.endpoint ?? fila?.endpoint).filter((url): url is string => typeof url === "string"), artefacto, "katana");
      else if (nombre === "wayback_cdx") this.urls((Array.isArray(datos.urls) ? datos.urls as Array<{ host?: string; path?: string }> : []).map((fila) => `https://${fila.host}${fila.path ?? "/"}`), artefacto, "wayback");
    });
  }

  private leerJson(hash: string): Record<string, unknown> | undefined {
    try {
      const datos = JSON.parse(this.artifacts.read(hash).toString("utf8")) as unknown;
      return datos && typeof datos === "object" && !Array.isArray(datos) ? (datos as Record<string, unknown>) : undefined;
    } catch {
      return undefined;
    }
  }

  private dentro(destino: string): boolean {
    try { return decide(this.alcance?.(), destino).allowed; } catch { return false; }
  }

  /** Funciones y secretos del código (code_crypto): archivo, función y, para un secreto fijo, sólo dónde está. */
  private cripto(puntos: CryptoPunto[], evidencia: string): void {
    for (const punto of puntos.slice(0, 200)) {
      if (!punto?.file) continue;
      const archivo = nodos.archivo(punto.file);
      const dueno = punto.fn ? nodos.funcion(punto.file, punto.fn) : archivo;
      if (punto.fn) this.grafo.arista(dueno, "pertenece_a", archivo, "observado", evidencia);
      this.grafo.nodo({ ...dueno, atributos: { ...dueno.atributos, cripto: [`${punto.kind}:${punto.risk}`] } }, evidencia);
      if (punto.kind === "secreto fijo" || punto.kind === "token en el cliente") {
        const credencial: NodoSpec = { tipo: "credencial", id: `fuente ${punto.file}:${punto.line}`, etiqueta: `${punto.kind} en ${punto.file}:${punto.line}`, estado: "observado", atributos: { clase: punto.kind, archivo: punto.file, linea: punto.line, riesgo: punto.risk, ...(punto.fn ? { funcion: punto.fn } : {}) } };
        this.grafo.arista(dueno, "expone", credencial, "observado", evidencia);
      }
    }
  }

  /** web_source_pull: la carpeta bajada, sus archivos, la API que usa el cliente y la cripto de ese código. */
  private fuenteWeb(datos: Record<string, unknown>, evidencia: string): void {
    const carpeta = String(datos.carpeta ?? "fuente-web");
    const raiz: NodoSpec = { tipo: "artefacto", id: `carpeta:${carpeta}`, etiqueta: `${carpeta}/`, estado: "observado", atributos: { clase: "carpeta", pagina: String(datos.pagina ?? "") } };
    this.grafo.nodo(raiz, evidencia);
    for (const archivo of (Array.isArray(datos.archivos) ? datos.archivos as Array<{ file?: string; url?: string; kind?: string }> : []).slice(0, 200)) {
      if (!archivo?.file) continue;
      this.grafo.arista(nodos.archivo(archivo.file, { tipo: String(archivo.kind ?? "") }), "pertenece_a", raiz, "observado", evidencia);
    }
    const pagina = partes(this.tapar(String(datos.pagina ?? "")));
    if (pagina) {
      for (const op of (Array.isArray(datos.api) ? datos.api as Array<{ path?: string; methods?: string[]; keys?: string[] }> : []).slice(0, 300)) {
        if (!op?.path) continue;
        const url = `${pagina.origen}${String(op.path).replace(/\{[^}]*\}/g, "1")}`;
        for (const metodo of op.methods?.length ? op.methods : ["GET"]) {
          const ruta = nodos.ruta(metodo, url, "inferido", { via: "codigo" });
          if (!ruta) continue;
          this.grafo.arista(ruta, "deriva_de", raiz, "observado", evidencia);
          if (ESCRITURAS.has(metodo.toUpperCase())) for (const clave of (op.keys ?? []).slice(0, 20)) {
            const param = nodos.parametro(url, "cuerpo", clave, "inferido");
            if (param) this.grafo.arista(ruta, "acepta", param, "inferido", evidencia);
          }
        }
      }
    }
    this.cripto((datos.cripto as CryptoPunto[]) ?? [], evidencia);
  }

  private nmap(xml: string, evidencia: string): void {
    for (const host of parseNmapXml(xml).slice(0, 100)) {
      const nodoHost = nodos.host(host.nombre ?? host.host);
      for (const puerto of host.puertos.slice(0, 100)) {
        const esquema = /^https?$/.test(puerto.servicio) ? puerto.servicio : puerto.servicio === "ssl/http" ? "https" : puerto.proto;
        const servicio = nodos.servicio(`${esquema}://${(host.nombre ?? host.host).toLowerCase()}:${puerto.puerto}`, "observado", { servicio: puerto.servicio, puerto: Number(puerto.puerto), proto: puerto.proto });
        this.grafo.arista(nodoHost, "expone", servicio, "observado", evidencia);
        const tech = puerto.producto ? tecnologia(puerto.producto, puerto.version || undefined, host.host, "nmap") : undefined;
        if (tech) this.grafo.arista(servicio, "expone", nodos.tecnologia(tech.clave, tech.producto, tech.version, { fuente: "nmap" }), "observado", evidencia);
      }
    }
  }

  private httpx(salida: string, evidencia: string): void {
    for (const fila of jsonLines(salida).slice(0, MAX_RECON)) {
      const p = typeof fila?.url === "string" ? partes(fila.url) : undefined;
      if (!p) continue;
      const servicio = nodos.servicio(p.origen, "observado", { ...(fila.status_code ? { estado_http: Number(fila.status_code) } : {}), ...(fila.title ? { titulo: String(fila.title).slice(0, 80) } : {}) });
      this.grafo.arista(nodos.host(p.host), "expone", servicio, "observado", evidencia);
      for (const nombre of (Array.isArray(fila.tech) ? fila.tech as string[] : []).slice(0, 20)) {
        const [producto, version] = String(nombre).split(":");
        const tech = tecnologia(producto ?? "", version, p.host, "httpx");
        if (tech) this.grafo.arista(servicio, "expone", nodos.tecnologia(tech.clave, tech.producto, tech.version, { fuente: "httpx" }), "observado", evidencia);
      }
    }
  }

  /** Hosts de fuentes pasivas: entran como inferidos y sólo los del alcance (lo de afuera no hace falta guardarlo). */
  private hosts(lista: string[], evidencia: string, fuente: string): void {
    let cuenta = 0;
    for (const host of lista) {
      const limpio = host.trim().toLowerCase();
      if (!limpio || cuenta >= MAX_RECON || !/^[a-z0-9.-]+$/.test(limpio) || !this.dentro(limpio)) continue;
      cuenta++;
      this.grafo.nodo({ ...nodos.host(limpio, "inferido"), atributos: { fuente } }, evidencia);
    }
  }

  /** URLs de rastreo o de historia: rutas inferidas del alcance. */
  private urls(lista: string[], evidencia: string, fuente: string): void {
    let cuenta = 0;
    for (const cruda of lista) {
      if (cuenta >= MAX_RECON || !this.dentro(cruda)) continue;
      const url = this.tapar(cruda);
      const p = partes(url);
      if (!p || isStaticAsset(p.ruta)) continue;
      const ruta = nodos.ruta("GET", url, "inferido", { via: fuente });
      if (!ruta) continue;
      cuenta++;
      this.grafo.arista(nodos.servicio(p.origen, "inferido"), "expone", ruta, "inferido", evidencia);
    }
  }

  /** Una hipótesis guardada en la memoria: entra como hipótesis inferida (o refutada, si la memoria la refutó). */
  private memoria(texto: string, vault?: Vault): void {
    const match = /^Guardado ([a-z0-9][a-z0-9-]*) rev (\d+)/.exec(texto);
    if (!match || !vault) return;
    const leido = vault.read(match[1]!);
    if (!leido || leido.record.type !== "hipotesis") return;
    this.hipotesisDeMemoria(leido.record.id, leido.record.rev, leido.record.title, leido.record.state, leido.record.summary);
  }

  hipotesisDeMemoria(id: string, rev: number, titulo: string, estado: string, resumen: string): void {
    this.seguro("memoria", () => {
      this.grafo.nodo(nodos.hipotesis(`memoria:${id}`, titulo, estado === "refutado" ? "refutado" : "inferido", { memoria: id, resumen: resumen.slice(0, 200), origen: "memoria" }), `memoria:${id}@${rev}`);
    });
  }
}

/** Un punto de code_crypto tal como queda en su artefacto (src/fuente.ts, CryptoHit), sin el extracto. */
interface CryptoPunto {
  file: string;
  line: number;
  kind: string;
  risk: string;
  fn?: string;
}
