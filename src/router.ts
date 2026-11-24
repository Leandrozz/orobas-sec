// Router de modelos por rol, estilo planificador/ejecutor. El bucle principal corre SIEMPRE con el
// ejecutor (el modelo de la sesión, /modelo): su caché de prompts no se rompe nunca. Ante una señal de
// decisión, el router le pide al ejecutor un traspaso compacto y le encarga el trabajo al fuerte (o al medio, para leer código) sobre ese traspaso,
// con un contexto propio y chico: una consulta sin herramientas, o un tramo de pocos pasos con
// herramientas y su propio historial. El resultado se AGREGA al final del bucle: el prefijo cacheado del
// ejecutor queda intacto.
//
// El traspaso compacto evita releer el historial entero con otro modelo.
// Cada modelo conserva el esfuerzo de razonamiento configurado.
//
// Las tareas se clasifican «blue» (leer y entender, planificar, redactar: un modelo estándar con barandas
// lo hace bien y suele ser más barato) o «red» (comprobar un candidato, explotar, evadir: se usa el
// modelo configurado para ese nivel). Si un estándar se niega, el mismo encargo se repite con el del nivel red y la
// negativa queda en la tasa por modelo (src/rechazos.ts).
import { t } from "./idioma.ts";
import type { Rates } from "./llm.ts";
import { ratePico, usd } from "./money.ts";
import type { Nivel } from "./rechazos.ts";

export type { Nivel };
export type RouterMode = "auto" | "fijo";
export type Perfil = "web" | "codigo" | "movil";
export type Senal = "operador" | "candidato" | "canario" | "objecion" | "sin-avance" | "hallazgo" | "errores" | "anomalia" | "analisis";
export type Rol = "fuerte" | "medio";
export type Forma = "consulta" | "tramo";
export type Motivo = Senal | "codigo";

/** Un trabajo que el router le saca al bucle: quién, de qué forma, a qué nivel y por qué. */
export interface Encargo {
  rol: Rol;
  forma: Forma;
  nivel: Nivel;
  motivo: Motivo;
  /** Lo que disparó el encargo, textual y corto (un extracto del resultado, el pedido del operador). */
  detalle: string;
}

/** Lo que el router ve de un paso del bucle: llamadas, resultados y el texto del modelo. */
export interface PasoVisto {
  llamadas: Array<{ nombre: string; args: string }>;
  resultados: Array<{ nombre: string; texto: string; error: boolean }>;
  texto: string;
}

/* ---------- Familias de herramientas (las mismas de las trazas) ---------- */

export const MECANICO = new Set(["tools_load", "tool_search", "coverage_mark", "coverage_view", "memory_write", "memory_read", "memory_search", "scope_check", "artifact_read", "finding_list", "site_map", "skill_load", "help_search", "session_settings", "http_identities"]);
export const SONDEO = new Set(["http_request", "http_probe", "http_replay", "path_probe", "param_probe", "js_endpoints", "tech_fingerprint", "nmap_scan", "nuclei_scan", "katana_crawl", "subfinder_enum", "httpx_probe", "wayback_cdx", "crt_sh", "code_list", "code_read", "code_search", "shell"]);
export const DECISION = new Set(["finding_record", "finding_update", "access_matrix", "auth_probe", "body_probe", "race_probe", "graphql_probe", "csrf_check", "scope_edit", "report_generate"]);
/** El agente ya consultó al fuerte por su cuenta: cuenta como encargo para el enfriamiento. */
const CONSULTA_PROPIA = new Set(["deep_reason", "delegate"]);
const CODIGO = /^(code_|apk_)/;
const MOVIL = /^apk_/;
const HTTP = /^(http_|access_matrix|ids_harvest|param_probe|body_probe|auth_probe|graphql_probe|path_probe|site_map|js_endpoints|race_probe|csrf_check|upload_probe|reset_probe|ffuf_|nuclei_|katana_|chrome_|openapi_import)/;

/* ---------- Señales en los resultados ---------- */

/** Un resultado que suele preceder una decisión: la herramienta ve algo que hay que comprobar. */
const CANDIDATO = /registr[áa] (un |el )?candidato|candidato (posible|probable)|xss almacenado|sin escapar|combinaci[oó]n(es)?\)? entraron|acept[óo] (el|los|la|las) (campo|valor|cambio)|confirmad[oa] por relectura|acceso cruzado|\bids? ajenos?\b|de otro usuario|bypass|posible (idor|bola|inyecci[óo]n|sqli|ssrf|xxe|rce|lfi|escalada)|escalada (de privilegios|posible)|token (filtrado|expuesto)|credenciales? (expuestas?|filtradas?)/i;
/** Una respuesta rara del objetivo: error del servidor con detalle, traza, error de SQL o de plantilla. */
const ANOMALIA = /\b5\d\d\b[^\n]{0,80}(error|exception|excepci[óo]n)|traceback|stack ?trace|sql syntax|sqlstate|ora-\d{4,5}|syntaxerror|nullpointer|unhandled exception|uncaught|internal server error|warning: [^\n]{0,80} on line|template ?error|deserializ/i;
/** El modelo anuncia que va a pensar: hipótesis, analizar, decidir. */
const ANALISIS = /\b(analic|analiz|hip[óo]tesis|razon(o|emos|ando)|pens(emos|ando)|evalu(o|emos)|decid(o|amos)|sospech|podr[íi]a (ser|tratarse)|parece (vulnerable|que)|veamos si|tengo que entender|no (est[áa]|queda) claro)/i;

const PESO: Record<Senal, number> = { operador: 3, candidato: 3, canario: 3, objecion: 3, "sin-avance": 3, hallazgo: 2, errores: 2, anomalia: 1, analisis: 1 };
const PRIORIDAD: Senal[] = ["operador", "candidato", "canario", "objecion", "sin-avance", "hallazgo", "errores", "anomalia", "analisis"];
/** Nivel de cada encargo: planificar, revisar, redactar y leer código son blue; comprobar y explotar, red. */
export const NIVEL: Record<Motivo, Nivel> = { operador: "blue", hallazgo: "blue", errores: "blue", analisis: "blue", codigo: "blue", candidato: "red", canario: "red", objecion: "red", "sin-avance": "red", anomalia: "red" };

/**
 * Umbrales por perfil. La presión sube con cada señal (su peso) y baja uno por paso de rutina; el fuerte
 * entra cuando llega al umbral y pasaron `enfriar` pasos desde el último encargo (histéresis: nunca uno
 * por paso). En código y móvil se sube antes: leer código lleva a decisiones más seguido que barrer rutas.
 */
export const PERFILES: Record<Perfil, { umbral: number; enfriar: number; enfriarMedio: number }> = {
  web: { umbral: 3, enfriar: 6, enfriarMedio: 8 },
  codigo: { umbral: 2, enfriar: 4, enfriarMedio: 6 },
  movil: { umbral: 2, enfriar: 4, enfriarMedio: 6 },
};
/** Encargos por turno, como máximo: acota el gasto de un turno largo con muchas señales. */
export const TOPE_TURNO = 4;
/** Pasos de un tramo (fuerte o medio con herramientas) como máximo. */
export const PASOS_TRAMO = 8;

/** «seguí», «dale», «ok»: no es un pedido nuevo, no hace falta planificar. */
export function trivial(texto: string): boolean {
  const limpio = texto.replace(/\n\n(<[a-z_]+>|\[sistema\])[\s\S]*$/, "").trim().toLowerCase();
  return limpio.length < 12 || /^(seg(u|ú)[ií]|dale|ok|okey|s[ií]|listo|gracias|continu[aá]|bien|perfecto)\b[^.?\n]{0,24}$/.test(limpio);
}

export interface ContextoDecision {
  /** Fracción del presupuesto que queda (0 a 1); sin tope, undefined. */
  fraccion?: number;
  /** Si el presupuesto absoluto alcanza para un encargo de ese rol y forma. */
  alcanza: (rol: Rol, forma: Forma) => boolean;
  /** Roles disponibles (se preguntan sólo si hace falta): el fuerte, si es otro modelo con tarifa; el medio, si se configuró. */
  hay: { fuerte: () => boolean; medio: () => boolean };
}

export class Router {
  modo: RouterMode;
  readonly conteo = { http: 0, codigo: 0, movil: 0 };
  private pendientes = new Map<Senal, string>();
  /** La señal más importante desde el último encargo: si el enfriamiento la frenó, sigue siendo el motivo. */
  private acumulada?: [Senal, string];
  private presion = 0;
  private desdeEncargo = Infinity;
  private desdeMedio = Infinity;
  private encargosTurno = 0;
  private errores = 0;
  private codigoReciente: boolean[] = [];
  /** Candidatos ya encargados: el mismo extracto no se manda dos veces. */
  private vistos = new Set<string>();

  constructor(modo: RouterMode = "auto") {
    this.modo = modo;
  }

  /** Perfil del programa, por la actividad de la sesión: revisión de código, app móvil o caja negra web. */
  perfil(): Perfil {
    const { http, codigo, movil } = this.conteo;
    if (movil >= 1 && movil >= codigo / 3) return "movil";
    if (codigo >= 3 && codigo * 3 >= http) return "codigo";
    return "web";
  }

  /** Estado para /router estado. */
  ahora(fraccion?: number): { presion: number; umbral: number; enfriando: number; encargosTurno: number } {
    const p = PERFILES[this.perfil()];
    return { presion: this.presion, umbral: p.umbral + ((fraccion ?? 1) < 0.5 ? 1 : 0), enfriando: Number.isFinite(this.desdeEncargo) ? Math.max(0, p.enfriar + 1 - this.desdeEncargo) : 0, encargosTurno: this.encargosTurno };
  }

  senal(senal: Senal, detalle: string): void {
    if (!this.pendientes.has(senal)) this.pendientes.set(senal, detalle.replace(/\s+/g, " ").trim().slice(0, 300));
  }

  inicioTurno(texto: string): void {
    this.encargosTurno = 0;
    if (!trivial(texto)) this.senal("operador", texto.replace(/\n\n(<[a-z_]+>|\[sistema\])[\s\S]*$/, ""));
  }

  finTurno(): void {
    this.pendientes.clear();
    this.acumulada = undefined;
    this.presion = 0;
    this.errores = 0;
  }

  /** El agente consultó al fuerte por su cuenta (deep_reason, delegate): no hace falta otro encargo ya. */
  consulto(): void {
    this.desdeEncargo = 0;
    this.presion = 0;
    this.acumulada = undefined;
  }

  /** Lo que pasó en el paso anterior: cuenta para el perfil y deja señales. */
  observar(paso: PasoVisto): void {
    for (const call of paso.llamadas) {
      if (MOVIL.test(call.nombre)) this.conteo.movil++;
      else if (CODIGO.test(call.nombre)) this.conteo.codigo++;
      else if (HTTP.test(call.nombre)) this.conteo.http++;
    }
    if (!paso.llamadas.length && !paso.resultados.length) return;
    this.codigoReciente = [...this.codigoReciente.slice(-2), paso.llamadas.some((call) => CODIGO.test(call.nombre))];
    if (paso.resultados.length && paso.resultados.every((result) => result.error)) {
      if (++this.errores >= 3) this.senal("errores", `${this.errores} pasos seguidos con todas las llamadas en error; la última: ${paso.resultados.at(-1)!.nombre}: ${paso.resultados.at(-1)!.texto.slice(0, 200)}`);
    } else if (paso.resultados.length) this.errores = 0;
    if (paso.llamadas.some((call) => CONSULTA_PROPIA.has(call.nombre))) this.consulto();
    const buenos = paso.resultados.filter((result) => !result.error && !CONSULTA_PROPIA.has(result.nombre));
    const candidato = extracto(buenos, CANDIDATO);
    if (candidato && !this.vistos.has(clave(candidato))) this.senal("candidato", candidato);
    else {
      const anomalia = extracto(buenos, ANOMALIA);
      if (anomalia) this.senal("anomalia", anomalia);
    }
    const registro = buenos.find((result) => result.nombre === "finding_record" || result.nombre === "finding_update");
    if (registro) this.senal("hallazgo", `${registro.nombre}: ${registro.texto.slice(0, 240)}`);
    if (ANALISIS.test(paso.texto)) this.senal("analisis", paso.texto.slice(0, 240));
    else if (paso.llamadas.some((call) => DECISION.has(call.nombre) && !call.nombre.startsWith("finding_"))) this.senal("analisis", paso.llamadas.map((call) => call.nombre).join(", "));
  }

  /**
   * Qué hacer antes del próximo paso del bucle: nada (sigue el ejecutor) o un encargo. Se llama una vez
   * por paso; consume las señales pendientes.
   */
  decidir(ctx: ContextoDecision): Encargo | undefined {
    const pendientes = [...this.pendientes].sort((a, b) => PRIORIDAD.indexOf(a[0]) - PRIORIDAD.indexOf(b[0]));
    this.pendientes.clear();
    this.desdeEncargo++;
    this.desdeMedio++;
    if (this.modo === "fijo") return undefined;
    const perfil = this.perfil();
    const p = PERFILES[perfil];
    const fuertes = pendientes.filter(([senal]) => PESO[senal] >= 2).length;
    if (pendientes.length) this.presion += Math.max(...pendientes.map(([senal]) => PESO[senal])) + (fuertes >= 2 ? 1 : 0);
    else this.presion = Math.max(0, this.presion - 1);
    const primera = pendientes[0];
    if (primera && (!this.acumulada || PRIORIDAD.indexOf(primera[0]) < PRIORIDAD.indexOf(this.acumulada[0]))) this.acumulada = primera;
    if (this.presion === 0) this.acumulada = undefined;
    const fraccion = ctx.fraccion ?? 1;
    // A medida que se gasta el presupuesto, más conservador: con menos de la mitad hace falta más presión
    // y no hay tramos con herramientas (sólo consultas); con menos de un quinto, nada de fuerte.
    const umbral = p.umbral + (fraccion < 0.5 ? 1 : 0);
    const operador = primera?.[0] === "operador";
    if (this.acumulada && fraccion >= 0.2 && this.presion >= umbral && (operador || this.desdeEncargo > p.enfriar) && this.encargosTurno < TOPE_TURNO && ctx.hay.fuerte()) {
      // El motivo es la señal fuerte de este paso; si sólo hubo débiles, la que se venía acumulando.
      const [motivo, detalle] = primera && PESO[primera[0]] >= 2 ? primera : this.acumulada;
      const quiere: Forma = (motivo === "candidato" || motivo === "canario") && fraccion >= 0.5 ? "tramo" : "consulta";
      const forma = ctx.alcanza("fuerte", quiere) ? quiere : quiere === "tramo" && ctx.alcanza("fuerte", "consulta") ? "consulta" : undefined;
      if (forma) {
        this.presion = 0;
        this.acumulada = undefined;
        // El plan de un pedido nuevo no enfría: un candidato que aparece dos pasos después es otra decisión.
        if (motivo !== "operador") this.desdeEncargo = 0;
        this.encargosTurno++;
        if (motivo === "candidato") this.vistos.add(clave(detalle));
        return { rol: "fuerte", forma, nivel: NIVEL[motivo], motivo, detalle };
      }
    }
    // Leer código: el medio (si hay) trabaja un tramo sobre un traspaso cuando el ejecutor viene leyendo código.
    if (perfil !== "web" && this.codigoReciente.filter(Boolean).length >= 2 && this.desdeMedio > p.enfriarMedio && this.encargosTurno < TOPE_TURNO && fraccion >= 0.2 && ctx.hay.medio() && ctx.alcanza("medio", "tramo")) {
      this.desdeMedio = 0;
      this.encargosTurno++;
      return { rol: "medio", forma: "tramo", nivel: "blue", motivo: "codigo", detalle: "el ejecutor viene leyendo código" };
    }
    return undefined;
  }
}

const clave = (texto: string) => texto.toLowerCase().replace(/\s+/g, " ").slice(0, 160);

/** Extracto alrededor de la primera coincidencia, con el nombre de la herramienta. */
function extracto(resultados: PasoVisto["resultados"], patron: RegExp): string | undefined {
  for (const result of resultados) {
    const texto = result.texto.slice(0, 8000);
    const match = patron.exec(texto);
    if (!match) continue;
    const desde = Math.max(0, match.index - 160);
    return `${result.nombre}: ${desde ? "…" : ""}${texto.slice(desde, match.index + match[0].length + 200).replace(/\s+/g, " ").trim()}`;
  }
  return undefined;
}

/* ---------- Textos del encargo ---------- */

/** Qué tiene que hacer el fuerte (o el medio) con el traspaso. */
export function instruccion(encargo: Encargo): string {
  const consulta = encargo.forma === "consulta";
  const formato = consulta ? " Respondé en 200 palabras como máximo: DECISIÓN, PLAN (pasos numerados, con la herramienta y qué mirar) y, si corresponde, HALLAZGO (título, severidad, impacto demostrado, evidencia por id)." : "";
  const tarea: Record<Motivo, string> = {
    operador: "Armá el plan para el pedido del operador: hasta 6 pasos concretos y en orden.",
    candidato: consulta
      ? "Decidí si el candidato se sostiene y cómo comprobarlo: la petición exacta y qué mirar en la respuesta. Si ya alcanza, redactá el hallazgo."
      : "Comprobá el candidato con la petición propia mínima que muestre el efecto, dentro del alcance. Si se sostiene, registralo con finding_record (candidato, con la evidencia por id), con título, severidad e impacto demostrado; si no, decí por qué no.",
    canario: consulta
      ? "Un canario sembrado reapareció: decidí si es XSS almacenado u otra inyección y cómo comprobarlo sin dañar nada. Si ya alcanza, redactá el hallazgo."
      : "Un canario sembrado reapareció: comprobá con una carga inofensiva si el contexto lo interpreta. Si se sostiene, registralo con finding_record con la siembra y la respuesta como evidencia.",
    objecion: "El harness objetó el cierre del turno (abajo): decidí cómo resolverlo con una o dos acciones concretas.",
    "sin-avance": "El agente no avanza (motivo abajo): proponé otro enfoque concreto, qué probar distinto y por qué.",
    hallazgo: "Revisá el hallazgo recién registrado: si se sostiene con la evidencia, si la severidad es la correcta y qué falta comprobar. Redactá título e impacto mejores si hace falta.",
    errores: "Las herramientas vienen fallando seguido (abajo): decí qué está mal en las llamadas y cómo seguir.",
    anomalia: "Una respuesta del objetivo es anómala (abajo): decidí si es una grieta y cómo explorarla.",
    analisis: "El agente está analizando (abajo): elegí la hipótesis más prometedora y el próximo paso.",
    codigo: "Leé el código relevante para el objetivo actual y explicá qué hace y dónde puede fallar (rutas, controles de permisos, entradas sin validar), con archivos y líneas concretas.",
  };
  return `${tarea[encargo.motivo]}${encargo.detalle ? `\nLo que lo disparó: ${encargo.detalle}` : ""}${formato}`;
}

/** Pedido al ejecutor: que escriba el traspaso desde su propio contexto (caché caliente), sin herramientas. */
export function pedidoTraspaso(encargo: Encargo): string {
  const quien = encargo.rol === "fuerte" ? "un modelo más capaz" : "otro modelo";
  return [
    `[sistema] Pausa para un traspaso: no uses herramientas. ${quien[0]!.toUpperCase()}${quien.slice(1)} va a ${encargo.forma === "tramo" ? "trabajar" : "decidir"} sin leer esta conversación. Escribile el traspaso, en castellano y sin saludo, con estas secciones y nada más:`,
    "OBJETIVO Y ALCANCE: qué pidió el operador y qué destinos están autorizados.",
    "PLAN: en qué punto está el trabajo y qué falta.",
    "HIPÓTESIS: abiertas, con lo que las apoya; descartadas, con por qué.",
    "CANDIDATOS: cada uno con sus ids de evidencia (h12, sha256:…, id de hallazgo), literales; se releen con artifact_read.",
    "ÚLTIMO: lo que pasó en los últimos pasos, con resultados concretos.",
    `PREGUNTA: ${instruccion({ ...encargo, forma: "tramo" }).split("\n")[0]}`,
    "Conservá literalmente rutas, ids, hashes y números; no inventes nada. Máximo 350 palabras.",
  ].join("\n");
}

/** Traspaso armado por el harness, sin modelo: al empezar la sesión (no hay nada que resumir) o si el ejecutor no pudo escribirlo. */
export function traspasoMecanico(datos: { pedido?: string; alcance: string; hallazgos: string[]; pasos: PasoVisto[]; encargo: Encargo }): string {
  const pasos = datos.pasos.slice(-4).map((paso) => {
    const llamadas = paso.llamadas.map((call) => `${call.nombre}(${call.args.slice(0, 160)})`).join(" ");
    const resultados = paso.resultados.map((result) => `${result.nombre}${result.error ? " · error" : ""}: ${result.texto.replace(/\s+/g, " ").slice(0, 400)}`).join("\n  ");
    return `- ${llamadas || paso.texto.slice(0, 200)}${resultados ? `\n  ${resultados}` : ""}`;
  });
  return [
    `OBJETIVO Y ALCANCE: ${datos.pedido ? datos.pedido.replace(/\s+/g, " ").slice(0, 1200) : "(sin pedido del operador todavía)"}\nAlcance: ${datos.alcance}`,
    `CANDIDATOS: ${datos.hallazgos.length ? datos.hallazgos.slice(0, 10).join("; ") : "ninguno registrado"}`,
    `ÚLTIMO:\n${pasos.join("\n") || "- nada todavía"}`,
    `PREGUNTA: ${instruccion({ ...datos.encargo, forma: "tramo" }).split("\n")[0]}`,
  ].join("\n");
}

const ROL_NOMBRE: Record<Rol | "ejecutor", () => string> = { fuerte: () => t("fuerte", "strong"), medio: () => t("medio", "mid"), ejecutor: () => t("ejecutor", "executor") };
const FORMA_NOMBRE: Record<Forma, () => string> = { consulta: () => t("consulta", "ask"), tramo: () => t("tramo", "run") };
const MOTIVO_NOMBRE: Record<Motivo, () => string> = {
  operador: () => t("plan", "plan"), candidato: () => t("candidato", "candidate"), canario: () => t("canario", "canary"), objecion: () => t("objeción", "objection"),
  "sin-avance": () => t("sin avance", "stalled"), hallazgo: () => t("hallazgo", "finding"), errores: () => t("errores", "errors"), anomalia: () => t("anomalía", "anomaly"),
  analisis: () => t("análisis", "analysis"), codigo: () => t("código", "code"),
};

/** «fuerte·tramo·red»: rol, forma y nivel de un encargo. */
export const etiqueta = (encargo: Pick<Encargo, "rol" | "forma" | "nivel">) => `${ROL_NOMBRE[encargo.rol]()}·${FORMA_NOMBRE[encargo.forma]()}·${encargo.nivel}`;
export const motivoNombre = (motivo: Motivo) => MOTIVO_NOMBRE[motivo]();

/** Lo que vuelve al bucle, al final: corto, con quién lo hizo y sobre qué. */
export function resultadoParaBucle(encargo: Encargo, modelo: string, texto: string, tokensTraspaso: number): string {
  const recortado = texto.length > 3500 ? `${texto.slice(0, 3500)}…` : texto;
  const quien = `${encargo.rol === "fuerte" ? "el modelo fuerte" : "el modelo medio"} (${modelo})`;
  const siguiente = encargo.forma === "tramo" ? "Seguí desde acá sin repetir lo que ya hizo." : "Seguilo salvo que la evidencia diga otra cosa; no hace falta deep_reason para esto.";
  return `[sistema] Router: ${MOTIVO_NOMBRE[encargo.motivo]()} → ${quien} trabajó sobre un traspaso de ~${tokensTraspaso} tokens, sin leer esta conversación. ${siguiente}\n${recortado}`;
}

/* ---------- Pie y estado ---------- */

/** Indicador del pie: «router: ejecutor» en reposo, «router: fuerte·tramo (candidato)» mientras trabaja otro rol. */
export function pie(modo: RouterMode, activo?: Encargo): string {
  if (modo === "fijo") return t("router: fijo", "router: fixed");
  if (!activo) return `router: ${ROL_NOMBRE.ejecutor()}`;
  return `router: ${ROL_NOMBRE[activo.rol]()}·${FORMA_NOMBRE[activo.forma]()} (${MOTIVO_NOMBRE[activo.motivo]()})`;
}

/** Versión corta del pie, para terminales angostas: «router: fuerte·tramo», sin el motivo. */
export function pieCorto(modo: RouterMode, activo?: Encargo): string {
  if (modo === "fijo" || !activo) return pie(modo);
  return `router: ${ROL_NOMBRE[activo.rol]()}·${FORMA_NOMBRE[activo.forma]()}`;
}

/** Una fila de requests, en orden, para estimar lo que habría costado otro modelo. */
export interface FilaUso { input: number; cacheRead: number; cacheWrite: number; output: number }

/**
 * Lo que habría costado el mismo bucle con otro modelo y la caché caliente: cada paso relee del caché lo
 * que ya mandó el anterior y paga entero sólo lo nuevo (si el contexto se achicó, por la dieta o la
 * compactación, lo paga entero). La salida se toma tal cual.
 */
export function costoReferencia(pasos: FilaUso[], tarifa: Rates): bigint {
  let anterior = 0;
  let total = 0n;
  for (const paso of pasos) {
    const prompt = paso.input + paso.cacheRead + paso.cacheWrite;
    const cacheado = prompt >= anterior ? anterior : 0;
    total += BigInt(prompt - cacheado) * ratePico(tarifa.input) + BigInt(cacheado) * ratePico(tarifa.cacheRead) + BigInt(paso.output) * ratePico(tarifa.output);
    anterior = prompt;
  }
  return total;
}

export interface FilaRol { rol: "ejecutor" | "traspaso" | Rol; modelo: string; nivel?: Nivel; pasos: number; rechazos?: number; tasa?: number; pico: bigint }

export interface EstadoRouter {
  modo: RouterMode;
  perfil: Perfil;
  conteo: { http: number; codigo: number; movil: number };
  ahora: { presion: number; umbral: number; enfriando: number; encargosTurno: number; activo?: Encargo };
  filas: FilaRol[];
  traspasos: { n: number; tokens: number; mecanicos: number };
  gasto: { bucle: bigint; router: bigint; referencia?: { modelo: string; pico: bigint } };
  decisiones: Array<{ at: string; etiqueta: string; motivo: string; detalle: string }>;
  ejecutor: string;
  /** El ejecutor cuesta como un fuerte: el router ahorra poco hasta que haya uno barato. */
  ejecutorCaro?: boolean;
}

const corto = (spec: string) => spec.slice(spec.indexOf("/") + 1);
const ajustar = (texto: string, ancho: number) => (texto.length > ancho ? `${texto.slice(0, ancho - 1)}…` : texto.padEnd(ancho));
const pct = (x: number) => `${Math.round(x * 100)} %`;

/** Ancho del panel de /router estado: entra sin cortes en el recuadro de una terminal de 80 columnas. */
export const ANCHO_ESTADO = 72;

/** Panel de /router estado: etiquetas a la izquierda y tabla alineada, sin pasar de ANCHO_ESTADO columnas. */
export function estadoLineas(e: EstadoRouter): string[] {
  const col = (label: string) => label.padEnd(12);
  const sangria = " ".repeat(12);
  const perfiles: Record<Perfil, () => string> = { web: () => t("web (caja negra)", "web (black box)"), codigo: () => t("revisión de código", "code review"), movil: () => t("app móvil", "mobile app") };
  const lineas = [
    "ROUTER",
    `${col(t("Modo", "Mode"))}${e.modo === "auto" ? t("auto · bucle con el ejecutor; el fuerte, sobre traspasos", "auto · loop on the executor; the strong, on handoffs") : t("fijo · todo con el modelo de la sesión, sin encargos", "fixed · everything on the session model, no handoffs")}`,
    `${col(t("Perfil", "Profile"))}${perfiles[e.perfil]()} · ${e.conteo.http} http, ${e.conteo.codigo} ${t("código", "code")}, ${e.conteo.movil} ${t("móvil", "mobile")}`,
  ];
  if (e.modo === "auto") {
    const trabajando = e.ahora.activo ? `${etiqueta(e.ahora.activo)} (${MOTIVO_NOMBRE[e.ahora.activo.motivo]()})` : ROL_NOMBRE.ejecutor();
    lineas.push(`${col(t("Ahora", "Now"))}${trabajando}`);
    lineas.push(`${sangria}${t("presión", "pressure")} ${e.ahora.presion}/${e.ahora.umbral}${e.ahora.enfriando ? t(` · enfría ${e.ahora.enfriando} pasos`, ` · cools ${e.ahora.enfriando} steps`) : ""} · ${t("encargos", "handoffs")} ${e.ahora.encargosTurno}/${TOPE_TURNO} ${t("en el turno", "this turn")}`);
  }
  const fila = (rol: string, modelo: string, pasos: string, rechazos: string, tasa: string, plata: string) => `${ajustar(rol, 12)}${ajustar(modelo, 22)}${pasos.padStart(5)} ${rechazos.padStart(5)} ${tasa.padStart(5)} ${plata.padStart(7)}`;
  lineas.push(`${col(t("Modelos", "Models"))}${fila(t("rol", "role"), t("modelo", "model"), t("pasos", "steps"), t("rech.", "ref."), t("tasa", "rate"), "USD")}`);
  const nombres: Record<FilaRol["rol"], () => string> = { ejecutor: ROL_NOMBRE.ejecutor, fuerte: ROL_NOMBRE.fuerte, medio: ROL_NOMBRE.medio, traspaso: () => t("traspaso", "handoff") };
  for (const item of e.filas) {
    const rol = `${nombres[item.rol]()}${item.nivel ? `·${item.nivel}` : ""}`;
    lineas.push(`${sangria}${fila(rol, corto(item.modelo), String(item.pasos), item.rechazos === undefined ? "—" : String(item.rechazos), item.tasa === undefined ? "—" : pct(item.tasa), usd(item.pico, 3))}`);
  }
  if (!e.filas.length) lineas.push(`${sangria}${t("todavía no hubo pasos", "no steps yet")}`);
  if (e.traspasos.n) lineas.push(`${col(t("Traspasos", "Handoffs"))}${e.traspasos.n}${e.traspasos.mecanicos ? t(` (${e.traspasos.mecanicos} armados por el harness)`, ` (${e.traspasos.mecanicos} built by the harness)`) : ""} · ≈ ${(e.traspasos.tokens / 1000).toFixed(1).replace(".", t(",", "."))}k tokens ${t("promedio", "average")}`);
  const total = e.gasto.bucle + e.gasto.router;
  lineas.push(`${col(t("Gasto", "Spend"))}${t("bucle", "loop")} USD ${usd(e.gasto.bucle, 2)} + router USD ${usd(e.gasto.router, 2)} = USD ${usd(total, 2)}`);
  if (e.gasto.referencia) {
    const { modelo, pico } = e.gasto.referencia;
    lineas.push(`${col(t("Sin router", "No router"))}${t(`todo el bucle con ${ajustar(corto(modelo), 24).trimEnd()}`, `the whole loop on ${ajustar(corto(modelo), 24).trimEnd()}`)} ≈ USD ${usd(pico, 2)}`);
    const ahorro = pico - total;
    lineas.push(`${col(t("Ahorro", "Savings"))}${ahorro >= 0n ? "≈" : t("≈ gasto extra", "≈ extra spend")} USD ${usd(ahorro >= 0n ? ahorro : -ahorro, 2)}${pico > 0n ? ` (${pct(Number(ahorro) / Number(pico))})` : ""}`);
  }
  if (e.ejecutorCaro) lineas.push(`${sangria}${t(`Ejecutor caro (${ajustar(corto(e.ejecutor), 20).trimEnd()}): con /modelo glm ahorra más.`, `Expensive executor (${ajustar(corto(e.ejecutor), 20).trimEnd()}): /modelo glm saves more.`)}`);
  e.decisiones.slice(-6).forEach((decision, index) => {
    const detalle = decision.detalle.replace(/\s+/g, " ").trim();
    lineas.push(`${index ? sangria : col(t("Decisiones", "Decisions"))}${decision.at} ${ajustar(decision.etiqueta, 21)}${ajustar(decision.motivo, 11)}${detalle ? `«${detalle.length > 16 ? `${detalle.slice(0, 15).trimEnd()}…` : detalle}»` : ""}`);
  });
  lineas.push(t("Uso: /router auto | fijo | estado · /router medio <modelo> | no", "Usage: /router auto | fijo | estado · /router medio <model> | no"));
  return lineas;
}
