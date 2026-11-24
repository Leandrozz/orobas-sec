// Cobertura de una evaluación, mantenida por el harness: lista de verificación por categoría,
// rutas habituales que conviene consultar y mapa de superficie (qué rutas y métodos ya se probaron).
// El modelo no decide solo cuándo terminó: antes de cerrar se le muestra lo que falta.
import type { DatabaseSync } from "node:sqlite";
import { isScriptAsset, isStaticAsset, type HttpClient } from "./http.ts";

export const CATEGORIES: Record<string, string> = {
  reconocimiento: "mapa de rutas: enlaces, robots.txt, documentación de API, rutas habituales no enlazadas (respaldos, depuración, métricas, administración)",
  autenticacion: "login con credenciales de prueba, contraseñas comunes en cuentas administrativas, mensajes de error distintos (enumeración), tokens inválidos o ausentes",
  "control de acceso": "recursos de otro usuario (ids ajenos), funciones de administración con cuenta común, métodos de escritura (PUT/POST/PATCH/DELETE) sobre recursos propios y ajenos, campos de rol o permiso en los cuerpos; graphql_probe para operaciones y tipos; csrf_check para escrituras por cookie",
  inyeccion: "parámetros reflejados en HTML, filtros y búsquedas con comillas y operadores, rutas con ../ en parámetros de archivo; si la aplicación acepta expresiones del usuario (XPath, JSONPath, plantillas, fórmulas, consultas), probá las funciones de ese lenguaje que leen archivos o traen URLs",
  "logica de negocio": "precios, cantidades, descuentos o estados enviados por el cliente; secuencias de pasos salteados; escrituras que un estado declarado debería impedir (archivado, bloqueado, cerrado, congelado, cancelado, pagado); race_probe para comparar escrituras concurrentes con un control secuencial",
  configuracion: "redirecciones con destino controlado, listados de directorio, archivos de respaldo o configuración, cabeceras de seguridad, CORS; outbound_probe en parámetros que reciben URLs",
  deteccion: "modo purple (perfil defensa/laboratorio): señales esperadas por acción ofensiva contra infra propia y si el canal de detección las registró; cada señal esperada sin detectar es un gap de detección (hallazgo detection-gap)",
};

/** Sub-recursos de administración que una API suele colgar de un recurso que ya responde. */
export const ADMIN_SUBPATHS = ["settings", "config", "wiki", "issue-tracker", "issues", "collaborators", "hooks", "mirror", "mirror-sync", "transfer", "archive", "members", "permissions", "roles", "tokens", "export", "convert", "duplicate", "move", "copy", "status"];

/** Rutas que un servicio web suele exponer sin enlazarlas. Se sugieren; el alcance decide si se consultan. */
export const COMMON_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/api", "/api/docs", "/swagger.json", "/openapi.json", "/api-docs", "/admin", "/api/admin", "/debug", "/api/debug", "/api/debug/config", "/api/config", "/config", "/metrics", "/backup", "/backups", "/.env", "/.git/config", "/config.json", "/health", "/status"];

/** Nombres de parámetro que suelen recibir rutas de archivo o destinos: hay que probarlos con ../ y con hosts externos. */
const FILE_PARAMS = /^\??(archivo|file|path|ruta|page|pagina|doc|template|include|name|nombre)$/i;
const REDIRECT_PARAMS = /^\??(url|volver|redirect|redirect_uri|next|return|returnto|return_to|to|dest|destino|continue|callback|goto)$/i;
const LOGIN_PATHS = /\/(login|signin|sign-in|auth|authenticate|sesion|session|token|oauth)/i;
/** Un segmento que es un identificador de objeto: número, UUID u ObjectId. */
export const ID_SEGMENT = /^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})$/i;
/** Rutas de compra como segmento («/api/orders», «/carrito»), no como pedazo de otra palabra («/border»). */
const COMMERCE = /(^|\/)(carritos?|carts?|shopcart|basket|pedidos?|orders?|compras?|checkout|pagos?|payments?|cupon(es)?|coupons?|descuentos?|discounts?|vouchers?)(\/|$|[-_.{])/i;
const PRICED = /precio|price|monto|amount|total|cantidad|qty|quantity|descuento|discount|cupon|coupon/i;
/** Rutas de respaldo, configuración, depuración y métricas: lo que la categoría «configuracion» pide mirar. */
const CONFIG_PATHS = /backup|\.env|\.git|config|debug|metrics|actuator|phpinfo|server-(status|info)|\.htaccess|web\.config|\.ds_store|\.svn|dump|\.bak|\.old|\.sql|swagger|openapi|api-docs|heapdump/i;

/** Lo que falta en una categoría: una sola acción concreta, con una clave para no repetirla. */
interface Gap {
  key: string;
  category: string;
  text: string;
  /** Orden en la objeción: primero lo que profundiza una grieta ya vista, después lo que amplía. */
  rank: number;
}

/** «limitada»: se probó hasta donde se pudo y la nota dice qué faltó y por qué. Cierra la categoría sin fingir que está completa. */
export type CoverageState = "pendiente" | "cubierta" | "no aplica" | "limitada";

export interface CoverageMark {
  category: string;
  state: CoverageState;
  note: string;
  at: string;
}

/**
 * Forma canónica de una ruta: sin barras finales ni repetidas, sin parámetros de segmento (;x) y en
 * minúsculas. Dos textos con la misma canónica son el mismo recurso escrito distinto.
 */
/** Prefijos de API que no son un recurso: no tienen operaciones «sobre todo su contenido». */
const API_PREFIX = /^\/(api|rest|graphql|services?|v\d+|api\/v\d+)$/i;

export function canonicalPath(path: string): string {
  const joined = path
    .split("/")
    .map((segment) => segment.split(";")[0]!)
    .filter(Boolean)
    .join("/")
    .toLowerCase();
  return joined ? `/${joined}` : "/";
}

export class Coverage {
  readonly db: DatabaseSync;
  readonly http: HttpClient;
  /** Modo purple: ledger de señales esperadas (perfil defensa/laboratorio). Opcional. */
  detection?: import("./deteccion.ts").DetectionLedger;
  /** Ids de objetos cosechados de las respuestas por identidad (src/cosecha.ts). Opcional. */
  harvest?: import("./cosecha.ts").IdHarvest;

  constructor(db: DatabaseSync, http: HttpClient) {
    this.db = db;
    this.http = http;
    db.exec("create table if not exists coverage(session_id text not null, category text not null, state text not null, note text not null, at text not null, primary key(session_id, category))");
  }

  private readonly rejections = new Map<string, number>();
  /** Objeciones ya hechas por sesión (clave de la acción): la misma no se repite. */
  private readonly raised = new Map<string, Set<string>>();

  /**
   * «limitada» con una nota corta se acepta siempre: es la salida honesta cuando lo que falta no se
   * puede conseguir. «cubierta» exige la evidencia mínima del tráfico.
   */
  mark(sessionId: string, category: string, state: CoverageState, note: string): CoverageMark {
    const key = normalize(category).replace(/[_-]+/g, " ");
    if (!(key in CATEGORIES)) throw new Error(`Categoría desconocida «${category}». Válidas: ${Object.keys(CATEGORIES).join(", ")}`);
    if (state !== "cubierta" && state !== "no aplica" && state !== "pendiente" && state !== "limitada") throw new Error("Estado inválido: cubierta, limitada, no aplica o pendiente");
    if (state !== "pendiente" && !note.trim()) throw new Error("Decí qué probaste (o por qué no aplica)");
    if (state === "cubierta") {
      const missing = this.minimumEvidence(key);
      if (missing) {
        // El mismo rechazo una y otra vez es un bucle: si lo que falta no se puede conseguir, se cierra como limitada.
        const rejected = (this.rejections.get(`${sessionId}:${key}`) ?? 0) + 1;
        this.rejections.set(`${sessionId}:${key}`, rejected);
        throw new Error(`No se marca «${key}» como cubierta: ${missing}${rejected >= 2 ? `\nYa van ${rejected} rechazos. Si eso no se puede conseguir (no hay otra cuenta, el recurso no existe, el servidor frena), no insistas: marcala «limitada» diciendo en la nota qué probaste y qué quedó sin probar y por qué.` : ""}`);
      }
    }
    const mark: CoverageMark = { category: key, state, note: note.trim(), at: new Date().toISOString() };
    this.db.prepare("insert or replace into coverage(session_id,category,state,note,at) values(?,?,?,?,?)").run(sessionId, key, state, note.trim(), mark.at);
    return mark;
  }

  /**
   * Evidencia mínima que el tráfico tiene que mostrar para aceptar «cubierta». Devuelve qué falta (una
   * sola acción), o undefined. No prueba que la categoría esté bien cubierta; evita marcarla sin haber
   * hecho lo básico.
   */
  minimumEvidence(category: string): string | undefined {
    return this.gap(category)?.text;
  }

  /** Lo que falta en la categoría, como una sola acción con su clave; undefined si está lo mínimo. */
  private gap(category: string): Gap | undefined {
    const found = this.gapOf(category);
    if (!found) return undefined;
    const order = Object.keys(CATEGORIES).indexOf(category);
    return { key: `${category}:${found.key}`, category, text: found.text, rank: found.rank ?? 10 + order };
  }

  private gapOf(category: string): { key: string; text: string; rank?: number } | undefined {
    const log = this.http.log;
    const surface = this.http.surface();
    const writes = log.filter((entry) => !["GET", "HEAD", "OPTIONS"].includes(entry.method));
    const marked = (kind: "inyeccion" | "traversal" | "externo", key?: RegExp) => log.some((entry) => (entry.marks ?? []).some((mark) => mark.mark === kind && (!key || key.test(mark.key))));
    switch (category) {
      case "reconocimiento": {
        const tested = surface.filter((row) => row.methods.length && !isStaticAsset(row.path));
        if (tested.length < 5) {
          const common = this.unvisitedCommon().filter((path) => this.reachable(path)).slice(0, 10);
          return { key: "pocas", text: `se probaron menos de cinco rutas (${tested.length}): una sola llamada a http_probe con ${common.length ? `las habituales que faltan (${common.join(", ")})` : "las rutas que enlaza la página"}` };
        }
        if (this.reachable("/robots.txt") && !surface.some((row) => row.methods.length && row.path === "/robots.txt")) return { key: "robots", text: "no se consultó /robots.txt: pedilo con http_request (dice qué rutas el sitio prefiere no indexar)" };
        // Imágenes, estilos, fuentes, medios y bundles no cuentan (isStaticAsset).
        const links = this.http.unvisitedLinks();
        if (links.length) return { key: `enlaces:${links.slice(0, 8).join(",")}`, text: `hay ${links.length} ruta${links.length > 1 ? "s" : ""} enlazada${links.length > 1 ? "s" : ""} sin visitar: ${links.slice(0, 8).join(", ")}${links.length > 8 ? ", …" : ""}; una sola llamada a http_probe con ${links.length > 1 ? "esas rutas" : "esa ruta"}` };
        // Los bundles no se visitan uno por uno: alcanza con que js_endpoints (o una lectura) haya bajado alguno.
        const scripts = [...this.http.linked].filter((link) => isScriptAsset(link));
        if (scripts.length && !log.some((entry) => isScriptAsset(this.key(entry.url)))) return { key: "scripts", text: `la página carga ${scripts.length} script${scripts.length > 1 ? "s" : ""} y no se leyó ninguno: js_endpoints sobre la página que los carga (los baja y te da el contrato de la API)` };
        return undefined;
      }
      case "autenticacion": {
        // Un desafío del servidor (401 con WWW-Authenticate) es una puerta declarada: no se cierra
        // la categoría sin haber mandado al menos una credencial contra ella.
        const untried = this.unansweredChallenges();
        if (untried.length) return { key: `desafio:${untried[0]!.path}`, rank: 3, text: `hay un desafío de autenticación sin intentar (${untried.slice(0, 4).map((row) => `${row.challenge} en ${row.path}`).join(", ")}): el mecanismo se prueba aunque no tengas credenciales, con credenciales inventadas y sus casos límite (usuario inexistente, secreto vacío, otro algoritmo), para ver si el rechazo es consistente. http_request admite digest, y acepta pasar el HA1 directo porque un archivo htdigest guarda HA1 y no la contraseña` };
        const logins = writes.filter((entry) => LOGIN_PATHS.test(entry.url));
        if (!logins.length) return { key: "login", text: "no hubo ningún POST a una ruta de login: una llamada a http_probe con methods [POST] sobre /login, /api/login, /auth, /api/auth y /sesion; si no existe ninguna, marcala «no aplica» diciéndolo" };
        if (logins.length < 4) return { key: "login-pocos", text: `sólo ${logins.length} intento(s) de login: auth_probe con commonPasswords sobre la cuenta administrativa si conocés su email (compara además usuario inexistente y contraseña incorrecta)` };
        return undefined;
      }
      case "control de acceso": {
        // Primero lo que profundiza una grieta ya vista; después lo que falta para poder verla.
        // Leer un recurso ajeno y recibir 403 demuestra que existe, no que esté protegido en todas
        // sus operaciones: hay que intentar al menos una escritura que lleve ese id.
        const foreign = this.foreignIds();
        if (foreign.length && !this.wroteWithForeignId()) {
          return { key: `ajenos:${foreign[0]!.path}`, rank: 0, text: `viste ids que no son de tu cuenta (${foreign.slice(0, 6).map((row) => `${row.id} en ${row.path} → ${row.status}`).join(", ")}) pero ninguna escritura llevó uno: probá una operación de esa familia (crear, convertir, mover, asignar, duplicar, cambiar estado) con el id ajeno en la ruta o en un campo de id del cuerpo` };
        }
        // Ids que le llegaron a una identidad y otra nunca vio, sin ninguna prueba cruzada: es el IDOR
        // con ids reales (UUID, ObjectId), que no se adivinan. Una sola vez por sesión (clave fija).
        const cross = this.harvest?.pendingCross();
        if (cross) return { key: "cosecha", rank: 1, text: cross };
        // Un hijo denegado dentro de un padre permitido: las operaciones que actúan sobre todo el
        // contenido del padre pueden arrastrarlo sin comprobar sus reglas.
        const nested = this.deniedInsideAllowed();
        if (nested.length) {
          const row = nested[0]!;
          return { key: `anidado:${row.denied}`, rank: 1, text: `hay un recurso denegado (${row.denied} → ${row.status}) dentro de uno permitido (${row.allowed}) y no probaste ninguna operación sobre el padre: probá sobre ${row.allowed} una de las que actúan sobre todo su contenido (copiar, exportar, comprimir, mover), empezando por las que no destruyen nada` };
        }
        // Una escritura rechazada puede estar rechazada por la forma del texto, no por el permiso.
        const unvaried = this.rejectedWritesWithoutVariants();
        if (unvaried.length) return { key: `formas:${unvaried[0]}`, rank: 2, text: `hay escrituras rechazadas sin probar otras formas de la misma ruta (${unvaried.slice(0, 4).join(", ")}): path_probe sobre ${unvaried[0]} antes de darla por protegida; la barra final, un punto y coma o una barra doble cambian qué capa decide` };
        if (!log.some((entry) => entry.status !== undefined && !isStaticAsset(this.key(entry.url)) && this.family(entry.url))) return { key: "sin-id", text: "no se pidió ningún recurso por id: pedí uno tuyo con http_request (access_matrix compara identidades; graphql_probe compara operaciones de GraphQL y csrf_check escrituras por cookie)" };
        // Antes de poder hablar de ids ajenos hay que haber mirado más de un id en alguna familia:
        // con un solo id no se sabe qué existe ni qué te niegan. Alcanza con una familia explorada.
        const thin = this.familiesWithOneId();
        if (thin.length && !this.exploredFamilies().length) return { key: `un-id:${thin[0]}`, rank: 4, text: `sólo probaste un id en cada familia de rutas (${thin.slice(0, 5).join(", ")}): pedí un segundo id de ${thin[0]} (un vecino del tuyo o uno bajo) para ver cuáles existen, cuáles te niegan y cuáles no están; sin eso no sabés cuál es ajeno` };
        if (!writes.some((entry) => /PUT|PATCH|DELETE/.test(entry.method))) return { key: "sin-escritura", text: "no se probó PUT, PATCH ni DELETE sobre ningún recurso: http_probe con methods [PUT, PATCH, DELETE] sobre un recurso tuyo; para GraphQL usá graphql_probe y para escrituras por cookie csrf_check" };
        return undefined;
      }
      case "inyeccion": {
        // Comillas, < > o ../ en la consulta, en el cuerpo o en la ruta: los datos de muchas APIs van en el cuerpo.
        // Un canario sembrado que reapareció en otra ruta o identidad (src/canario.ts) también es inyección probada.
        if (!marked("inyeccion") && !marked("traversal") && !this.http.canarios?.hits().length) {
          const param = surface.flatMap((row) => row.params.map((name) => `${row.path} (${name.replace(/^\?/, "")})`))[0];
          return { key: "sin-payload", text: param ? `ningún parámetro recibió comillas, < > ni ../ (ni en la consulta ni en el cuerpo): param_probe sobre ${param}` : "ningún parámetro recibió comillas, < > ni ../ y no se vio ninguno donde probar: js_endpoints o site_map para encontrar entradas; si la aplicación no tiene ninguna, marcala «no aplica» diciéndolo" };
        }
        const fileParams = surface.flatMap((row) => row.params.filter((param) => FILE_PARAMS.test(param)).map((param) => `${row.path} (${param.replace(/^\?/, "")})`));
        if (fileParams.length && !marked("traversal", FILE_PARAMS)) return { key: `traversal:${fileParams[0]}`, text: `hay parámetros de archivo sin probar con ../ (${fileParams.slice(0, 4).join(", ")}): param_probe, familia traversal, sobre ${fileParams[0]}` };
        return undefined;
      }
      case "logica de negocio": {
        if (!writes.some((entry) => entry.bodyKeys.length || entry.fields?.length)) return { key: "sin-cuerpo", text: "no se envió ningún cuerpo (POST/PUT con campos) para ver qué acepta el servidor: conseguí una escritura que funcione (js_endpoints da sus campos) y pasale body_probe; race_probe compara concurrencia contra un control secuencial" };
        // Sólo rutas de compra con una escritura (vista o probada): un historial de pedidos de sólo lectura no tiene precio que alterar.
        const commerce = surface.filter((row) => !isStaticAsset(row.path) && COMMERCE.test(row.path) && row.seenMethods.some((method) => ["POST", "PUT", "PATCH"].includes(method)));
        const priced = writes.some((entry) => COMMERCE.test(this.key(entry.url)) && [...entry.bodyKeys, ...(entry.fields ?? [])].some((key) => PRICED.test(key)));
        if (commerce.length && !priced) return { key: `compra:${commerce[0]!.path}`, text: `hay rutas de compra con escritura (${commerce.slice(0, 4).map((row) => row.path).join(", ")}) y ninguna escritura mandó precio, monto o cantidad propios: conseguí una escritura que funcione sobre ${commerce[0]!.path} y pasale body_probe alterando esos campos (race_probe después, para concurrencia)` };
        return undefined;
      }
      case "configuracion": {
        const redirectParams = surface.flatMap((row) => row.params.filter((param) => REDIRECT_PARAMS.test(param)).map((param) => `${row.path} (${param.replace(/^\?/, "")})`));
        if (redirectParams.length && !marked("externo", REDIRECT_PARAMS)) return { key: `redireccion:${redirectParams[0]}`, text: `hay parámetros de redirección sin probar con un destino externo (${redirectParams.slice(0, 4).join(", ")}): outbound_probe sobre ${redirectParams[0]} (comprueba visitas del servidor con un canal declarado)` };
        // Sólo se exige si alguna de esas rutas está dentro del alcance (un alcance por URL puede dejarlas afuera).
        const wanted = COMMON_PATHS.filter((path) => /backup|\.env|\.git|config|debug|metrics/.test(path) && this.reachable(path));
        if (wanted.length && !surface.some((row) => row.methods.length && CONFIG_PATHS.test(row.path))) return { key: "respaldos", text: `no se consultó ninguna ruta de respaldo, configuración, depuración ni métricas: una sola llamada a http_probe con ${wanted.join(", ")}` };
        return undefined;
      }
      case "deteccion": {
        // El modo purple sólo se abre con perfil defensa/laboratorio; sin señales esperadas no hay
        // nada que cerrar. La evidencia es el propio marcado de señales, no el tráfico.
        const signals = this.detection?.summary();
        if (!signals || !signals.esperadas) return { key: "sin-senales", text: "sin señales esperadas registradas (detection_expect por cada acción ofensiva con la regla que debería dispararla): no se puede cerrar «detección» sin ninguna" };
        if (signals.esperadas < 3) return { key: "pocas-senales", text: `sólo ${signals.esperadas} señal(es) esperadas: registrá una por acción ofensiva representativa (acceso aceptido, sonda de inyección, escritura concurrente) para que el análisis valga` };
        return undefined;
      }
    }
    return undefined;
  }

  /** ¿Esta ruta está dentro del alcance en algún origen ya visto? Sin tráfico todavía, se asume que sí. */
  private reachable(path: string): boolean {
    const origins = new Set<string>();
    for (const entry of this.http.log) {
      try { origins.add(new URL(entry.url).origin); } catch { /* URL rota: no aporta origen */ }
    }
    return !origins.size || [...origins].some((origin) => this.http.inScope(`${origin}${path}`));
  }

  /** Desafíos de autenticación que el servidor declaró y a los que nunca se respondió con credenciales. */
  unansweredChallenges(): Array<{ path: string; challenge: string }> {
    const challenged = new Map<string, string>();
    for (const entry of this.http.log) {
      if (entry.challenge && !challenged.has(this.key(entry.url))) challenged.set(this.key(entry.url), entry.challenge);
    }
    const answered = new Set(this.http.log.filter((entry) => entry.sentAuth).map((entry) => this.key(entry.url)));
    return [...challenged].filter(([path]) => !answered.has(path)).map(([path, challenge]) => ({ path, challenge }));
  }

  /**
   * Familia de una URL: la ruta canónica con los números reemplazados por {n}. Las formas que
   * genera path_probe (punto y coma, barra doble, mayúsculas) son el mismo recurso escrito distinto:
   * si contaran como familias aparte, cada una tendría un solo id y la objeción no se podría cumplir.
   */
  private family(url: string): string | undefined {
    const segments = canonicalPath(this.key(url)).split("/").filter(Boolean);
    if (!segments.some((segment) => ID_SEGMENT.test(segment))) return undefined;
    return `/${segments.map((segment) => (ID_SEGMENT.test(segment) ? "{n}" : segment)).join("/")}`;
  }

  /**
   * Los ids de una URL: los segmentos numéricos, en orden, unidos con «/». Son los que la familia
   * muestra como {n}; tomar el último segmento fallaba cuando el id está en el medio
   * (/recurso/{n}/config), porque todas las peticiones compartían el mismo «id».
   */
  private idsOf(url: string): string {
    return canonicalPath(this.key(url)).split("/").filter((segment) => ID_SEGMENT.test(segment)).join("/");
  }

  /** Ids pedidos por ruta que la cuenta no puede ver (403/404) donde otro id de la misma familia sí respondió. */
  foreignIds(): Array<{ path: string; id: string; status: number }> {
    const families = new Map<string, { ok: Set<string>; denied: Map<string, number> }>();
    for (const entry of this.http.log) {
      if (entry.status === undefined || isStaticAsset(this.key(entry.url))) continue;
      const normalized = this.family(entry.url);
      if (!normalized) continue;
      const id = this.idsOf(entry.url);
      const family = families.get(normalized) ?? { ok: new Set<string>(), denied: new Map<string, number>() };
      if (entry.status < 300) family.ok.add(id);
      else if (entry.status === 401 || entry.status === 403 || entry.status === 404) family.denied.set(id, entry.status);
      families.set(normalized, family);
    }
    const foreign: Array<{ path: string; id: string; status: number }> = [];
    for (const [normalized, family] of families) {
      if (!family.ok.size) continue; // sin un id propio que funcione no se sabe si la ruta existe
      for (const [id, status] of family.denied) if (!family.ok.has(id)) foreign.push({ path: normalized, id, status });
    }
    return foreign;
  }

  /**
   * ¿Hubo alguna escritura que llevara uno de esos ids ajenos, en la ruta o en el cuerpo?
   * Se compara el valor, no el nombre del campo: mandar «project_id» del proyecto propio no
   * prueba nada sobre el ajeno.
   */
  /**
   * Ids pedidos por familia, sólo de las familias que existen (algún 2xx) o están protegidas (401/403).
   * Una familia que sólo dio 404 no dice que haya un recurso, y los estáticos no son recursos.
   */
  private familyIds(): Map<string, Set<string>> {
    const ids = new Map<string, Set<string>>();
    const alive = new Set<string>();
    for (const entry of this.http.log) {
      if (entry.status === undefined || isStaticAsset(this.key(entry.url))) continue;
      const normalized = this.family(entry.url);
      if (!normalized) continue;
      const group = ids.get(normalized) ?? new Set<string>();
      group.add(this.idsOf(entry.url));
      ids.set(normalized, group);
      if ((entry.status >= 200 && entry.status < 300) || entry.status === 401 || entry.status === 403) alive.add(normalized);
    }
    return new Map([...ids].filter(([path]) => alive.has(path)));
  }

  /** Familias de rutas con id donde sólo se probó un id: no alcanza para saber qué es ajeno. */
  familiesWithOneId(): string[] {
    return [...this.familyIds()].filter(([, group]) => group.size < 2).map(([path]) => path);
  }

  /** Familias donde ya se miró más de un id. */
  exploredFamilies(): string[] {
    return [...this.familyIds()].filter(([, group]) => group.size >= 2).map(([path]) => path);
  }

  wroteWithForeignId(): boolean {
    // Un id compuesto (/{n}/x/{n}) se compara por cada número que lo forma.
    const ids = new Set(this.foreignIds().flatMap((row) => row.id.split("/")));
    if (!ids.size) return false;
    return this.http.log.some((entry) => {
      if (["GET", "HEAD", "OPTIONS"].includes(entry.method)) return false;
      const segments = this.key(entry.url).split("/").filter(Boolean).map((segment) => segment.split(";")[0]!.toLowerCase());
      if (segments.some((segment) => ids.has(segment))) return true;
      return (entry.bodyIds ?? []).some((value) => ids.has(value.toLowerCase()));
    });
  }

  /**
   * Recursos denegados que viven dentro de uno permitido, mientras no se haya probado ninguna
   * operación sobre el padre. Es la forma de ruta del mismo problema que `foreignIds` ve por id.
   */
  deniedInsideAllowed(): Array<{ allowed: string; denied: string; status: number }> {
    // Un padre «permitido» tiene que ser un recurso: una página HTML (la aplicación de una sola
    // página que responde 200 a cualquier ruta) o un prefijo de API pelado no contienen al hijo.
    const ok = new Set<string>();
    const pages = new Set<string>();
    const denied = new Map<string, number>();
    for (const entry of this.http.log) {
      if (entry.status === undefined) continue;
      const path = this.key(entry.url).replace(/\/+$/, "") || "/";
      if (entry.status < 300) {
        ok.add(path);
        if (entry.html) pages.add(path);
      } else if (entry.status === 401 || entry.status === 403) denied.set(path, entry.status);
    }
    const operated = new Set(
      this.http.log.filter((entry) => !["GET", "HEAD", "OPTIONS"].includes(entry.method)).map((entry) => this.key(entry.url).replace(/\/+$/, "") || "/"),
    );
    const pairs: Array<{ allowed: string; denied: string; status: number }> = [];
    for (const [path, status] of denied) {
      if (ok.has(path)) continue; // el mismo recurso respondió bien en otra petición: no está denegado
      const segments = path.split("/").filter(Boolean);
      for (let i = segments.length - 1; i >= 1; i--) {
        const parent = "/" + segments.slice(0, i).join("/");
        if (!ok.has(parent) || pages.has(parent) || API_PREFIX.test(parent)) continue;
        if (!operated.has(parent)) pairs.push({ allowed: parent, denied: path, status });
        break;
      }
    }
    return pairs;
  }

  /**
   * Rutas donde una escritura fue rechazada y nunca se probó otra forma del mismo texto.
   * Dos capas que normalizan distinto deciden la autorización sobre textos distintos.
   */
  rejectedWritesWithoutVariants(): string[] {
    const canonical = canonicalPath;
    const seen = new Map<string, Set<string>>();
    for (const entry of this.http.log) {
      const path = this.key(entry.url);
      const group = seen.get(canonical(path)) ?? new Set<string>();
      group.add(path);
      seen.set(canonical(path), group);
    }
    const pending: string[] = [];
    for (const entry of this.http.log) {
      if (["GET", "HEAD", "OPTIONS"].includes(entry.method)) continue;
      if (entry.status !== 401 && entry.status !== 403) continue;
      const path = this.key(entry.url);
      // Sólo se reclama si de ese recurso se probó una única forma del texto.
      if ((seen.get(canonical(path))?.size ?? 1) === 1 && !pending.includes(path)) pending.push(path);
    }
    return pending;
  }

  private key(url: string): string {
    try {
      return new URL(url).pathname;
    } catch {
      return url;
    }
  }

  marks(sessionId: string): Map<string, CoverageMark> {
    const rows = this.db.prepare("select category,state,note,at from coverage where session_id=?").all(sessionId) as unknown as CoverageMark[];
    return new Map(rows.map((row) => [row.category, row]));
  }

  /** Categorías sin marcar. «deteccion» sólo cuenta en modo purple (perfil defensa/laboratorio). */
  pending(sessionId: string): string[] {
    const marks = this.marks(sessionId);
    return Object.keys(CATEGORIES).filter((category) => (category !== "deteccion" || this.detection) && (marks.get(category)?.state ?? "pendiente") === "pendiente");
  }

  /** Rutas habituales que todavía no se consultaron en ningún host visto. */
  unvisitedCommon(): string[] {
    const seen = new Set(this.http.surface().filter((row) => row.methods.length).map((row) => row.path.toLowerCase()));
    return COMMON_PATHS.filter((path) => !seen.has(path));
  }

  /** Rutas que parecen recursos de API y sólo se probaron con GET. */
  readOnlyPaths(): string[] {
    return this.http
      .surface()
      .filter((row) => row.methods.every((method) => method === "GET" || method === "HEAD" || method === "OPTIONS") && /\/api\/|\{n\}/.test(row.path) && row.statuses.some((status) => status < 400))
      .map((row) => row.path);
  }

  /** Vista completa para el modelo o el operador. */
  view(sessionId: string): string[] {
    const marks = this.marks(sessionId);
    const lines = ["COBERTURA"];
    for (const [category, description] of Object.entries(CATEGORIES)) {
      const mark = marks.get(category);
      lines.push(`  ${mark ? (mark.state === "cubierta" ? "✓" : mark.state === "limitada" ? "~" : mark.state === "no aplica" ? "–" : "○") : "○"} ${category}: ${mark?.note || description}`);
    }
    const remaining = this.http.remaining();
    lines.push(`Peticiones HTTP: ${this.http.count}${remaining !== undefined ? ` · quedan ${remaining}` : ""}`);
    const surface = this.http.surface();
    if (surface.length) {
      lines.push(`Superficie vista (${surface.length} rutas)`);
      for (const row of surface.slice(0, 60)) {
        const pending = row.seenMethods.filter((method) => !row.methods.includes(method));
        lines.push(`  ${row.host} ${row.path}  ${row.methods.join(",") || "sin probar"}  → ${row.statuses.join(",") || "sin respuesta"}${pending.length ? `  vistos sin probar: ${pending.join(",")}` : ""}${row.params.length ? `  params: ${row.params.join(" ")}` : ""}`);
      }
      if (surface.length > 60) lines.push(`  … ${surface.length - 60} más`);
    }
    return lines;
  }

  /**
   * Qué falta antes de cerrar la evaluación, o undefined si no hay nada que objetar. Una sola acción por
   * objeción, la más profunda primero (una grieta ya vista antes que ampliar el mapa), y nunca la misma
   * dos veces en la sesión: si el agente ya la intentó y sigue faltando, o no se puede, queda para el
   * operador. Sólo objeta categorías sin marcar: «limitada» con su nota es una salida honesta y cierra.
   * Sólo tiene sentido si en este turno hubo tráfico HTTP y queda presupuesto.
   */
  objection(sessionId: string, requestsThisTurn: number): string | undefined {
    if (requestsThisTurn === 0) return undefined;
    const remaining = this.http.remaining();
    if (remaining !== undefined && remaining < 3) return undefined;
    const pending = this.pending(sessionId);
    if (!pending.length) return undefined;
    const raised = this.raised.get(sessionId) ?? new Set<string>();
    this.raised.set(sessionId, raised);
    const gaps: Gap[] = [];
    const ready: string[] = [];
    for (const category of pending) {
      const gap = this.gap(category);
      if (gap) gaps.push(gap);
      else ready.push(category);
    }
    if (ready.length) gaps.push({ key: `marcar:${ready.join(",")}`, category: ready.join(", "), rank: 30, text: `${ready.length > 1 ? "esas categorías ya tienen" : "ya tiene"} lo mínimo y ${ready.length > 1 ? "falta marcarlas" : "falta marcarla"}: coverage_mark (cubierta, limitada o no aplica, con una nota corta)` });
    const next = gaps.sort((a, b) => a.rank - b.rank).find((gap) => !raised.has(gap.key));
    if (!next) return undefined;
    raised.add(next.key);
    const others = pending.filter((category) => !next.category.split(", ").includes(category));
    const marking = next.key.startsWith("marcar:");
    return [
      `[sistema] Antes de cerrar falta una cosa en la cobertura («${next.category}»): ${next.text}.`,
      `${marking ? "" : `Si no se puede (no hay otra cuenta, el recurso no existe, el servidor frena), marcá «${next.category}» como «limitada» con una nota corta de qué faltó y por qué: se acepta siempre. `}${others.length ? `Siguen sin marcar: ${others.join(", ")}.` : ""}`.trim(),
      `Peticiones HTTP usadas: ${this.http.count}${remaining !== undefined ? `; quedan ${remaining}` : ""}.`,
    ].filter(Boolean).join("\n");
  }
}

function normalize(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/\s+/g, " ");
}
