// Una corrida de CI de punta a punta: autorización del alcance, proveedor y tarifas, motor sin operador con el
// alcance sellado, identidades, comprobación de llegada, exploración con topes duros de gasto y de tiempo,
// verificación independiente, retest, línea de base, salidas y código de salida. Todo lo que sale va tapado.
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { accountGate } from "../cuenta.ts";
import { Engine } from "../engine.ts";
import { SEVERITIES, type Finding } from "../findings.ts";
import type { Rates } from "../llm.ts";
import { usd, usdToPico } from "../money.ts";
import { apiKey, defaultStrongModel, missingKeyMessage, type Provider, resolveProvider } from "../providers.ts";
import type { ScopeRule } from "../scope.ts";
import { logEvent } from "../store.ts";
import { fetchCatalog } from "../tarifas.ts";
import { exhaustedError, type Verdict, type VerifyResult } from "../verifier.ts";
import { type Cambios, inferirCambios } from "./cambios.ts";
import { type ConfigCi, ErrorConfig, expandirAlcance, huellaAlcance, huellaArchivo, type IdentidadResuelta, type ReglaExpandida, resolverIdentidades } from "./config.ts";
import { armarConsigna } from "./consigna.ts";
import type { DestinoHuella } from "./huella.ts";
import { comparar, type Supresiones } from "./linea-base.ts";
import { hallazgoCi, intercambio } from "./recolectar.ts";
import { CODIGOS, DESCRIPCION_CODIGO, type EstadoCorrida, FORMATO, type HallazgoCi, type ResultadoCi, type RetestCi } from "./resultado.ts";
import { type DestinoActual, retestear } from "./retest.ts";
import { Tapador } from "./tapado.ts";

/** Herramientas que no se ofrecen en CI: salen del alcance (terceros), piden un operador o escriben fuera de la corrida. */
export const HERRAMIENTAS_FUERA_DE_CI = [
  // Shell y orquestación de otros agentes: ejecutan comandos en el runner.
  "shell", "harness_run", "harness_wait", "harness_status", "harness_result", "harness_stop", "harness_cleanup",
  // Plataformas y programas: cuentas del operador, otros alcances.
  "platform_status", "platform_link", "platform_cli", "h1_programs", "h1_scope_load", "h1_report_submit", "bb_programs", "bb_scope_load",
  "cyber_bounty_programs", "cyber_bounty_scope", "cyber_bounty_submit", "cyber_bounty_status",
  // Ajustes que sólo da el operador (el alcance, además, está sellado).
  "scope_edit", "profile_set", "session_settings", "decoy_mark", "report_generate",
  // Lectura y reconocimiento en servicios de terceros: no se toca nada fuera del alcance.
  "reference_read", "crt_sh", "wayback_cdx", "github_search", "takeover_check", "js_wayback_diff", "cve_recent",
  // Correo de prueba, el navegador del operador, post-explotación de laboratorio y el modo investigar.
  "mail_address", "mail_wait", "reset_probe", "chrome_tabs", "chrome_open", "chrome_read", "chrome_act", "chrome_session", "chrome_traffic", "chrome_capture",
  "postex_persist", "postex_exfil", "postex_cleanup", "investigation_start",
];
/** Además, en sólo lectura: las sondas que escriben (el cliente HTTP igual las frenaría petición por petición). */
export const HERRAMIENTAS_DE_ESCRITURA = ["upload_probe", "race_probe", "csrf_check", "body_probe", "auth_probe"];

export interface ContextoCi {
  repositorio?: string;
  commit?: string;
  ref?: string;
  evento?: string;
  actor?: string;
  pr?: number;
  url?: string;
  /** El PR viene de un fork (GitHub). */
  fork?: boolean;
}

/** Lo que dice el CI (GitHub Actions o GitLab CI) de esta corrida; fuera de un CI, lo que dice git. */
export function contextoCi(env: NodeJS.ProcessEnv, cwd: string): ContextoCi {
  let evento: { pull_request?: { number?: number; head?: { repo?: { fork?: boolean; full_name?: string } }; base?: { repo?: { full_name?: string } } } } = {};
  try {
    if (env.GITHUB_EVENT_PATH && existsSync(env.GITHUB_EVENT_PATH)) evento = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8"));
  } catch { /* evento ilegible: sin PR */ }
  const pr = evento.pull_request?.number ?? (env.CI_MERGE_REQUEST_IID ? Number(env.CI_MERGE_REQUEST_IID) : undefined);
  const fork = evento.pull_request ? !!evento.pull_request.head?.repo?.fork || (evento.pull_request.head?.repo?.full_name !== undefined && evento.pull_request.head.repo.full_name !== evento.pull_request.base?.repo?.full_name) : undefined;
  let commit = env.GITHUB_SHA ?? env.CI_COMMIT_SHA;
  if (!commit) {
    try { commit = execFileSync("git", ["-C", cwd, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { /* sin git */ }
  }
  const url = env.GITHUB_RUN_ID && env.GITHUB_REPOSITORY ? `${env.GITHUB_SERVER_URL ?? "https://github.com"}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : env.CI_JOB_URL;
  return {
    ...(env.GITHUB_REPOSITORY ?? env.CI_PROJECT_PATH ? { repositorio: env.GITHUB_REPOSITORY ?? env.CI_PROJECT_PATH } : {}),
    ...(commit ? { commit } : {}),
    ...(env.GITHUB_REF ?? env.CI_COMMIT_REF_NAME ? { ref: env.GITHUB_REF ?? env.CI_COMMIT_REF_NAME } : {}),
    ...(env.GITHUB_EVENT_NAME ?? env.CI_PIPELINE_SOURCE ? { evento: env.GITHUB_EVENT_NAME ?? env.CI_PIPELINE_SOURCE } : {}),
    ...(env.GITHUB_ACTOR ?? env.GITLAB_USER_LOGIN ? { actor: env.GITHUB_ACTOR ?? env.GITLAB_USER_LOGIN } : {}),
    ...(pr ? { pr } : {}),
    ...(url ? { url } : {}),
    ...(fork !== undefined ? { fork } : {}),
  };
}

export interface OpcionesCorrida {
  cwd: string;
  config: ConfigCi;
  env: NodeJS.ProcessEnv;
  modo: "evaluacion" | "retest";
  version: string;
  supresiones: Supresiones;
  anterior?: ResultadoCi;
  avisos?: string[];
  /** Confirmación por bandera (--autorizo-alcance); si no, OROBAS_CI_AUTORIZACION. */
  autorizacion?: string;
  /** Carpeta de datos de la corrida; por defecto una temporal que se borra al terminar. */
  datos?: string;
  conservarDatos?: boolean;
  /** Proveedor ya resuelto (pruebas: el simulado con guion). */
  proveedor?: Provider;
  /** Proveedor del verificador (pruebas); por defecto el mismo. */
  log?: (linea: string) => void;
  /** Para las pruebas: reloj y reservas de tiempo. */
  reservaVerificacionMs?: number;
}

export interface Corrida {
  resultado: ResultadoCi;
  codigo: number;
  registro: Array<Record<string, unknown>>;
  /** Carpeta de trazas locales para copiar a las salidas (modo «local»). */
  trazas?: string;
  /** El tapado de la corrida, para la última pasada sobre cada archivo de salida. */
  tapador: Tapador;
}

const ahoraIso = () => new Date().toISOString();

/** Esqueleto del resultado cuando la corrida no llegó a evaluar (configuración o infraestructura antes de empezar). */
export function resultadoSinCorrer(opciones: { nombre: string; modo: "evaluacion" | "retest"; version: string; estado: EstadoCorrida; motivo: string; inicio: number; contexto?: ContextoCi; config?: ConfigCi; huella?: string; avisos?: string[] }): ResultadoCi {
  const fin = Date.now();
  const c = opciones.config;
  return {
    formato: FORMATO,
    herramienta: { nombre: "orobas-sec", version: opciones.version },
    nombre: opciones.nombre,
    modo: opciones.modo,
    resultado: { codigo: CODIGOS[opciones.estado], estado: opciones.estado, descripcion: DESCRIPCION_CODIGO[opciones.estado], motivo: opciones.motivo, bloqueantes: 0 },
    corrida: { inicio: new Date(opciones.inicio).toISOString(), fin: new Date(fin).toISOString(), duracion_s: Math.round((fin - opciones.inicio) / 1000), sesion: "", ...(opciones.contexto ?? {}), fin_exploracion: "no-corrio" },
    autorizacion: c && opciones.huella ? { huella: opciones.huella, fuente: "sin confirmar", archivo: c.archivo, huella_archivo: huellaArchivo(c.fuente), ...(c.ref ? { ref: c.ref } : {}) } : null,
    alcance: { incluido: [], excluido: [], reglas: [], acotado_a_cambios: false },
    modelo: { nombre: c?.modelo.nombre ?? "", modelos_usados: [], router: "" },
    gasto: { usd: "0.000000", tope_usd: c ? c.presupuesto.usd.toFixed(2) : "0.00", verificacion_usd: "0.000000", solicitudes: 0, solicitudes_sin_costo: 0, tokens: { entrada: 0, cache_lectura: 0, cache_escritura: 0, salida: 0 } },
    tiempo: { tope_min: c?.presupuesto.minutos ?? 0, duracion_s: Math.round((fin - opciones.inicio) / 1000) },
    trafico: { peticiones: 0, bloqueadas_por_alcance: 0, intentos_fuera_de_alcance: [], solo_lectura: c?.evaluacion.soloLectura ?? false, hosts: [] },
    cobertura: { probadas: [], sin_probar: [], solo_cambios: { activo: false, motivo: "la corrida no llegó a evaluar", rutas: [], archivos_sin_ruta: [] } },
    politica: { fallar_desde: c?.politica.fallarDesde ?? "alta", solo_nuevos: c?.politica.soloNuevos ?? false },
    hallazgos: [],
    comparacion: { anterior: null, nuevos: [], persisten: [], resueltos: [], sin_confirmar: [] },
    supresiones: { archivo: c?.lineaBase.supresiones ?? "", aplicadas: [], vencidas: [], sin_uso: [] },
    retest: [],
    avisos: opciones.avisos ?? [],
  };
}

class Detener extends Error {
  readonly estado: EstadoCorrida;
  constructor(estado: EstadoCorrida, mensaje: string) {
    super(mensaje);
    this.estado = estado;
  }
}

/** Tarifas del modelo: las publicadas, las de la configuración o cero para un modelo local; si no hay, no se corre. */
async function prepararProveedor(config: ConfigCi, env: NodeJS.ProcessEnv, inyectado: Provider | undefined, avisos: string[]): Promise<{ provider: Provider; strong?: Provider }> {
  let provider: Provider;
  if (inyectado) provider = inyectado;
  else {
    try {
      provider = resolveProvider(config.modelo.nombre);
    } catch (error) {
      throw new Detener("configuracion", `Modelo: ${(error as Error).message}`);
    }
  }
  const modelo = provider.model;
  if (modelo.apiKeyEnv && !apiKey(modelo.apiKeyEnv)) throw new Detener("configuracion", `${missingKeyMessage(modelo.apiKeyEnv)}. En CI la clave va por un secreto del CI como variable de entorno ${modelo.apiKeyEnv}.`);
  if (modelo.provider === "orobas") {
    const negado = await accountGate(modelo);
    if (negado) throw new Detener("configuracion", negado);
    if (!modelo.cost && !config.modelo.tarifas) {
      try {
        await fetchCatalog(modelo.baseUrl, apiKey("OROBAS_API_KEY"));
      } catch (error) {
        throw new Detener("infraestructura", `No pude leer las tarifas del servicio (${(error as Error).message}): sin tarifa no hay tope de gasto duro, y no corro sin él.`);
      }
      const otra = resolveProvider(`${modelo.provider}/${modelo.id}`);
      if (otra.model.cost) modelo.cost = otra.model.cost;
    }
  }
  if (!modelo.cost) {
    if (config.modelo.tarifas) modelo.cost = config.modelo.tarifas as Rates;
    else if (!modelo.apiKeyEnv || modelo.provider === "faux") {
      modelo.cost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
      avisos.push(`El modelo ${modelo.provider}/${modelo.id} es local o simulado: su costo es cero y el tope en dinero no lo limita; rige el de tiempo.`);
    } else throw new Detener("configuracion", `No conozco la tarifa de ${modelo.provider}/${modelo.id}: sin tarifa no hay tope de gasto duro. Declarala en modelo.tarifas (USD por millón de tokens de entrada y de salida) o en la configuración del harness.`);
  }
  // El modelo fuerte (deep_reason, delegar con fuerte): si su tarifa no se conoce, hace de fuerte el mismo modelo.
  if (inyectado) return { provider, strong: provider };
  const fuerte = defaultStrongModel(modelo);
  if (fuerte === `${modelo.provider}/${modelo.id}`) return { provider };
  try {
    const strong = resolveProvider(fuerte);
    if (strong.model.cost && (!strong.model.apiKeyEnv || apiKey(strong.model.apiKeyEnv))) return { provider };
  } catch { /* no se puede usar: el mismo */ }
  avisos.push(`El modelo fuerte (${fuerte}) no tiene tarifa conocida o clave: en esta corrida hace de fuerte ${modelo.provider}/${modelo.id}.`);
  return { provider, strong: provider };
}

/** El alcance acotado a las rutas del PR: cada URL del alcance pasa a cubrir sólo esas rutas (y las de siempre). */
export function acotar(incluidas: ReglaExpandida[], cambios: Cambios, siempre: string[] = []): { reglas: ScopeRule[]; acotado: boolean } {
  const prefijos = [...new Set([...cambios.rutas.map((r) => r.ruta), ...siempre].map((r) => r.replace(/\/\{[^}]*\}.*$/, "")).map((r) => r || "/"))];
  if (!cambios.activo || !prefijos.length || prefijos.includes("/")) return { reglas: incluidas.flatMap((r) => r.reglas), acotado: false };
  const reglas: ScopeRule[] = [];
  let acotado = false;
  for (const r of incluidas) {
    if (r.regla.tipo !== "url") {
      reglas.push(...r.reglas);
      continue;
    }
    const base = r.reglas[0]!.value.replace(/\/+$/, "");
    for (const prefijo of prefijos) reglas.push({ kind: "url", value: `${base}${prefijo}`.toLowerCase(), note: "CI: acotado a las rutas del PR" });
    acotado = true;
  }
  return { reglas, acotado };
}

const rango = (s: string) => (SEVERITIES as readonly string[]).indexOf(s);

export async function correr(op: OpcionesCorrida): Promise<Corrida> {
  const inicio = Date.now();
  const { config, env } = op;
  const avisos = [...(op.avisos ?? [])];
  const log = op.log ?? (() => {});
  const contexto = contextoCi(env, op.cwd);
  const huella = huellaAlcance(config);
  const sinCorrer = (estado: EstadoCorrida, motivo: string): Corrida => {
    log(`✗ ${motivo}`);
    const resultado = resultadoSinCorrer({ nombre: config.nombre, modo: op.modo, version: op.version, estado, motivo, inicio, contexto, config, huella, avisos });
    return { resultado, codigo: CODIGOS[estado], registro: [{ t: ahoraIso(), tipo: "ci.fin", estado, motivo }], tapador: new Tapador() };
  };

  // 1. Autorización: el archivo versionado + la confirmación explícita con la huella del alcance.
  const dada = (op.autorizacion ?? env.OROBAS_CI_AUTORIZACION ?? "").trim();
  const fuenteAutorizacion = op.autorizacion !== undefined ? "--autorizo-alcance" : "OROBAS_CI_AUTORIZACION";
  if (!dada) return sinCorrer("configuracion", `Falta la autorización del alcance. Quien administra el repositorio la da con la huella del alcance de ${config.archivo} en la variable del CI OROBAS_CI_AUTORIZACION (no en el archivo) o con --autorizo-alcance. Huella de este alcance: ${huella}. Si cambia el alcance, cambia la huella y hay que volver a autorizarlo.`);
  if (dada.replace(/^sha256:/, "") !== huella.replace(/^sha256:/, "")) return sinCorrer("configuracion", `La autorización (${fuenteAutorizacion}) es para otro alcance: autoriza ${dada.startsWith("sha256:") ? dada : `sha256:${dada}`} y el alcance de ${config.archivo}${config.ref ? ` en ${config.ref}` : ""} tiene la huella ${huella}. Si el cambio de alcance es legítimo, quien administra el repositorio actualiza la variable; si no, alguien cambió a quién se le pega.`);

  // 2. Alcance expandido, identidades y cambios del PR.
  let incluidas: ReglaExpandida[];
  let excluidas: ReglaExpandida[];
  let identidades: IdentidadResuelta[];
  try {
    ({ incluidas, excluidas } = expandirAlcance(config, env));
    identidades = resolverIdentidades(config, env);
  } catch (error) {
    if (error instanceof ErrorConfig) return sinCorrer("configuracion", error.message);
    throw error;
  }
  const cambios = op.modo === "retest" ? { activo: false, motivo: "retest: se prueban los hallazgos conocidos", archivos: [], rutas: [], sinRuta: [] } : inferirCambios(op.cwd, config.evaluacion.soloCambios.activo, config.evaluacion.soloCambios.base, env, config.evaluacion.soloCambios.rutasSiempre);
  if (cambios.error && config.evaluacion.soloCambios.activo === "si") avisos.push(`Modo «sólo lo que cambió»: ${cambios.motivo}.`);
  // Acotado a las rutas del PR, el inicio de sesión de las identidades sigue adentro (si no, no habría con qué probar).
  const rutasDeLogin = identidades.flatMap((i) => { try { return i.login ? [new URL(i.login.url).pathname] : []; } catch { return []; } });
  const { reglas: incluidasHarness, acotado } = config.evaluacion.soloCambios.acotarAlcance ? acotar(incluidas, cambios, rutasDeLogin) : { reglas: incluidas.flatMap((r) => r.reglas), acotado: false };
  const destinos: DestinoHuella[] = incluidas.map((r) => ({ clave: r.regla.nombre ?? r.regla.literal, reglas: r.reglas }));
  const destinosActuales: DestinoActual[] = incluidas.map((r) => ({ clave: r.regla.nombre ?? r.regla.literal, ...(r.regla.tipo === "url" ? { origen: new URL(r.valor).origin } : {}) }));

  // 3. Proveedor, clave, cuenta y tarifas: los mensajes de cuenta e identidad son los del harness.
  let provider: Provider;
  let strong: Provider | undefined;
  try {
    ({ provider, strong } = await prepararProveedor(config, env, op.proveedor, avisos));
  } catch (error) {
    if (error instanceof Detener) return sinCorrer(error.estado, error.message);
    throw error;
  }

  // 4. Motor sin operador, en una carpeta de datos propia (temporal: no va al caché ni a los artefactos del job).
  const anteriores = { datos: process.env.CYBER_DATA_DIR, trazas: process.env.CYBER_TRAZAS };
  const datos = op.datos ?? mkdtempSync(join(tmpdir(), "orobas-ci-datos-"));
  process.env.CYBER_DATA_DIR = datos;
  if (config.trazas) process.env.CYBER_TRAZAS = config.trazas;
  const { usd: totalUsd, verificacionUsd, minutos } = config.presupuesto;
  const exploracionUsd = op.modo === "retest" ? 0.01 : Math.max(0.01, totalUsd - verificacionUsd);
  const totalMs = minutos * 60_000;
  const reservaMs = op.reservaVerificacionMs ?? Math.min(Math.max(120_000, totalMs * 0.25), totalMs * 0.5);
  const limite = inicio + totalMs;
  const secretosEntorno = [...identidades.flatMap((i) => i.secretos), ...(provider.model.apiKeyEnv ? [apiKey(provider.model.apiKeyEnv) ?? ""] : [])].filter(Boolean);
  let engine: Engine;
  try {
    engine = new Engine({
      cwd: op.cwd,
      provider,
      ...(strong ? { strong } : {}),
      budgetPico: usdToPico(exploracionUsd.toFixed(2)),
      disabled: [...HERRAMIENTAS_FUERA_DE_CI, ...(config.evaluacion.soloLectura ? HERRAMIENTAS_DE_ESCRITURA : [])],
      autoVerify: false,
      cveFeed: false,
      mcp: {},
      investigacion: false,
      router: config.modelo.router ?? "fijo",
      ...(config.presupuesto.peticiones ? { httpLimit: config.presupuesto.peticiones } : {}),
      ...(config.presupuesto.ritmo ? { httpRate: config.presupuesto.ritmo } : {}),
      verifier: { budgetUsd: config.presupuesto.porCandidatoUsd },
      retries: 4,
    });
  } catch (error) {
    process.env.CYBER_DATA_DIR = anteriores.datos;
    if (anteriores.trazas === undefined) delete process.env.CYBER_TRAZAS;
    else process.env.CYBER_TRAZAS = anteriores.trazas;
    if (!op.datos && !op.conservarDatos) rmSync(datos, { recursive: true, force: true });
    return sinCorrer("infraestructura", `No pude abrir el motor: ${(error as Error).message}`);
  }
  const tapador = new Tapador(engine, secretosEntorno);
  const avisosMotor: string[] = [];
  engine.onNotice = (texto) => {
    avisosMotor.push(texto);
    log(`· ${tapador.texto(texto).slice(0, 300)}`);
  };
  const ev = (tipo: string, datosEvento: Record<string, unknown>) => logEvent(engine.db, engine.sessionId, tipo, datosEvento);

  let finExploracion = "no-corrio";
  let detenido: { estado: EstadoCorrida; motivo: string } | undefined;
  const verdicts = new Map<string, Verdict>();
  const fallasVerificacion: Array<{ id: string; error: string; proveedor: boolean; corte: boolean }> = [];
  const retestHechos: Awaited<ReturnType<typeof retestear>> = [];
  const idsRetest = new Set<string>();
  const control = new AbortController();
  const temporizadores: NodeJS.Timeout[] = [];
  let porTiempo = false;

  try {
    engine.ledger.setProjectBudget(usdToPico(totalUsd.toFixed(2)));
    engine.setProfile(config.evaluacion.capacidades);
    engine.http.scanners = config.evaluacion.escaneres;
    for (const s of secretosEntorno) engine.secretos.registrar(s, "entorno");

    // 5. El alcance autorizado, sellado. Queda como fuente del alcance y como evento: es el consentimiento de CI.
    const corto = contexto.commit ? contexto.commit.slice(0, 12) : "sin-commit";
    engine.scope.save({
      source: `ci:${config.archivo}@${corto}`,
      include: incluidasHarness,
      exclude: excluidas.flatMap((r) => r.reglas),
      notes: `Corrida de CI «${config.nombre}». Alcance autorizado en ${config.archivo} (huella ${huella}), confirmado con ${fuenteAutorizacion}${contexto.repositorio ? ` en ${contexto.repositorio}` : ""}${contexto.commit ? ` @ ${contexto.commit}` : ""}. Sellado: no se amplía.${acotado ? " Acotado a las rutas del PR." : ""}`,
    });
    engine.scope.sellar(`lo autorizó ${config.archivo} (huella ${huella}) para esta corrida de CI y no hay operador que pueda ampliarlo`);
    ev("ci.autorizacion", { huella, fuente: fuenteAutorizacion, archivo: config.archivo, huella_archivo: huellaArchivo(config.fuente), ref: config.ref ?? null, ...contexto, reglas: incluidas.map((r) => r.regla.literal), excluidas: excluidas.map((r) => r.regla.literal) });
    ev("ci.inicio", { nombre: config.nombre, modo: op.modo, presupuesto_usd: totalUsd, verificacion_usd: verificacionUsd, minutos, solo_lectura: config.evaluacion.soloLectura, perfil: config.evaluacion.perfil, capacidades: config.evaluacion.capacidades, modelo: `${provider.model.provider}/${provider.model.id}` });
    log(`Alcance autorizado (${huella}): ${incluidas.map((r) => r.valor).join(", ")}${acotado ? " (acotado a las rutas del PR)" : ""}`);

    // 6. Identidades: por cabeceras, o con el login configurado (lo hace el harness, dentro del alcance).
    for (const id of identidades) {
      if (id.cabeceras) {
        engine.http.setIdentity({ name: id.nombre, headers: id.cabeceras });
        continue;
      }
      const lg = id.login!;
      let ex;
      try {
        ex = await engine.http.send({ method: "POST", url: lg.url, headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(lg.cuerpo), timeoutMs: 30_000 });
      } catch (error) {
        throw new Detener("configuracion", `El login de la identidad «${id.nombre}» no se pudo mandar: ${tapador.texto((error as Error).message)}`);
      }
      if (!ex.response) throw new Detener("infraestructura", `El login de «${id.nombre}» no respondió (${tapador.texto(ex.error ?? "sin respuesta")}): el objetivo no está disponible.`);
      if (ex.response.status >= 500) throw new Detener("infraestructura", `El login de «${id.nombre}» respondió ${ex.response.status}: el objetivo no está sano.`);
      if (ex.response.status >= 400) throw new Detener("configuracion", `El login de «${id.nombre}» respondió ${ex.response.status}: revisá las credenciales (las variables de entorno de identidades[].login.cuerpo) y la URL.`);
      let valor: string | undefined;
      if (lg.token) {
        try {
          let v: unknown = JSON.parse(ex.response.body);
          for (const parte of lg.token.split(".")) v = v && typeof v === "object" ? (v as Record<string, unknown>)[parte] : undefined;
          if (typeof v === "string" && v) valor = v;
        } catch { /* no es JSON */ }
        if (!valor) throw new Detener("configuracion", `El login de «${id.nombre}» respondió ${ex.response.status} pero no trae un token en «${lg.token}».`);
      } else {
        const cookies = Object.entries(ex.response.headers).filter(([k]) => k.toLowerCase() === "set-cookie").flatMap(([, v]) => v.split(/,(?=\s*[^;=\s]+=)/)).map((c) => c.split(";")[0]!.trim()).filter((c) => c.includes("="));
        if (!cookies.length) throw new Detener("configuracion", `El login de «${id.nombre}» respondió ${ex.response.status} sin cookies.`);
        valor = cookies.join("; ");
      }
      tapador.sumar([valor]);
      engine.secretos.registrar(valor, "entorno");
      engine.http.setIdentity({ name: id.nombre, headers: { [lg.cabecera]: lg.formato.replace("{}", valor) } });
    }
    if (identidades.length) ev("ci.identidades", { nombres: identidades.map((i) => i.nombre) });

    // 7. ¿Llega? Si ninguna raíz del alcance responde, la corrida no puede decir nada: infraestructura.
    if (config.comprobarObjetivo) {
      // Con el alcance acotado, se pide lo que quedó adentro (la raíz puede haber quedado afuera).
      const origenes = (acotado ? incluidasHarness.filter((r) => r.kind === "url").map((r) => r.value) : [...new Set(incluidas.flatMap((r) => r.origenes.map((o) => (/^https?:\/\//.test(o) ? o : `https://${o}`))))]).slice(0, 6);
      let alguna = origenes.length === 0;
      const fallas: string[] = [];
      for (const origen of origenes) {
        try {
          const ex = await engine.http.send({ method: "GET", url: origen, timeoutMs: 20_000 });
          if (ex.response) alguna = true;
          else fallas.push(`${origen}: ${ex.error ?? "sin respuesta"}`);
        } catch (error) {
          fallas.push(`${origen}: ${(error as Error).message.split(". ")[0]}`);
        }
        if (alguna) break;
      }
      if (!alguna) throw new Detener("infraestructura", `El objetivo no respondió: ${tapador.texto(fallas.join("; ")).slice(0, 600)}. Sin objetivo no se evalúa nada (y no es «todo bien»).`);
    }
    if (config.evaluacion.soloLectura) engine.http.soloLectura = "modo sólo lectura de esta corrida de CI (evaluacion.solo_lectura): sólo salen GET, HEAD y OPTIONS";

    // 8. Exploración, con su tope de tiempo (la reserva queda para verificar y escribir).
    temporizadores.push(setTimeout(() => { porTiempo = true; control.abort(); engine.abort(); }, Math.max(1000, limite - Date.now())));
    if (op.modo === "evaluacion") {
      const consigna = armarConsigna({ config, huella, identidades: engine.http.identityNames(), exploracionUsd, exploracionMin: (totalMs - reservaMs) / 60_000, cambios });
      let porTiempoExploracion = false;
      const corteExploracion = setTimeout(() => { porTiempoExploracion = true; engine.abort(); }, Math.max(1000, totalMs - reservaMs - (Date.now() - inicio)));
      temporizadores.push(corteExploracion);
      log(`Explorando: hasta USD ${exploracionUsd.toFixed(2)} y ${Math.round((totalMs - reservaMs) / 60_000)} min.`);
      const desde = engine.agent.messages.length;
      await engine.send(consigna);
      clearTimeout(corteExploracion);
      finExploracion = clasificarFin(engine.agent.messages.slice(desde), porTiempoExploracion || porTiempo);
      ev("ci.exploracion", { fin: finExploracion });
      log(`Exploración terminada: ${finExploracion}.`);
    } else finExploracion = "retest";

    // 9. Verificación independiente de los candidatos, de mayor a menor severidad, con topes de gasto y tiempo.
    const parar = (): string | undefined => {
      if (porTiempo || Date.now() > limite - 20_000) return "se agotó el tiempo de la corrida";
      if (engine.ledger.overProjectBudget(usdToPico("0.01"))) return "se agotó el presupuesto de la corrida";
      return undefined;
    };
    const proveedorCaido = finExploracion === "proveedor" || finExploracion === "sin-saldo";
    const candidatos = engine.findings.list({ sessionId: engine.sessionId }).filter((f) => f.state === "candidato").sort((a, b) => rango(b.severity) - rango(a.severity));
    if (candidatos.length && !proveedorCaido) {
      log(`Verificando ${candidatos.length} candidato(s).`);
      const resultados: VerifyResult[] = await engine.verifier.verifyAll({ findings: candidatos, signal: control.signal, stop: parar, retries: 1 });
      for (const r of resultados) {
        if ("error" in r) fallasVerificacion.push({ id: r.finding.id, error: r.error, proveedor: !!r.exhausted || exhaustedError(r.error) || /proveedor|HTTP 5\d\d|no respondió|Red:/.test(r.error), corte: !!r.skipped || porTiempo });
        else verdicts.set(r.finding.id, r);
      }
      ev("ci.verificacion", { veredictos: verdicts.size, sin_terminar: fallasVerificacion.length });
    } else if (candidatos.length) for (const f of candidatos) fallasVerificacion.push({ id: f.id, error: "el proveedor de modelos falló antes de verificar", proveedor: true, corte: false });

    // 10. Retest: los verificados conocidos (todos en modo retest; en una evaluación, los que no reaparecieron).
    const actuales = engine.findings.list({ sessionId: engine.sessionId });
    const recolectados = actuales.filter((f) => f.state === "verificado" || f.state === "candidato").map((f) => hallazgoCi(engine, tapador, f, destinos, verdicts.get(f.id)).huella);
    const conocidos = (op.anterior?.hallazgos ?? []).filter((h) => h.estado === "verificado" && (op.modo === "retest" || (config.lineaBase.retestAusentes && !recolectados.includes(h.huella))));
    if (conocidos.length && !proveedorCaido) {
      log(`Retest de ${conocidos.length} hallazgo(s) conocido(s).`);
      retestHechos.push(...(await retestear({ engine, tapador, conocidos, destinos: destinosActuales, signal: control.signal, parar })));
      for (const r of retestHechos) if (r.id) idsRetest.add(r.id);
      ev("ci.retest", { resultados: retestHechos.map((r) => ({ huella: r.retest.huella, resultado: r.retest.resultado })) });
    } else if (conocidos.length) for (const h of conocidos) retestHechos.push({ retest: { huella: h.huella, titulo: h.titulo, severidad: h.severidad, clase: h.clase, resultado: "sin-confirmar", motivo: "el proveedor de modelos falló antes del retest", bloqueante: false }, proveedor: true });
  } catch (error) {
    if (error instanceof Detener) detenido = { estado: error.estado, motivo: error.message };
    else if (error instanceof ErrorConfig) detenido = { estado: "configuracion", motivo: error.message };
    else detenido = { estado: "infraestructura", motivo: `Error interno de la corrida: ${tapador.texto((error as Error).message)}` };
    log(`✗ ${detenido.motivo}`);
  } finally {
    for (const t of temporizadores) clearTimeout(t);
  }

  // 11. Resultado: hallazgos con huella, supresiones, comparación, política y código de salida.
  const fin = Date.now();
  const hallazgos: HallazgoCi[] = engine.findings.list({ sessionId: engine.sessionId }).filter((f) => !idsRetest.has(f.id)).sort((a: Finding, b: Finding) => rango(b.severity) - rango(a.severity) || a.createdAt.localeCompare(b.createdAt)).map((f) => hallazgoCi(engine, tapador, f, destinos, verdicts.get(f.id)));
  const retestMapa = new Map(retestHechos.map((r) => [r.retest.huella, r.retest.resultado] as const));
  const comparacion = comparar(hallazgos, op.anterior, retestMapa);
  const verificadosAntes = new Set((op.anterior?.hallazgos ?? []).filter((h) => h.estado === "verificado").map((h) => h.huella));
  const umbral = config.politica.fallarDesde;
  const aplicadas = new Set<string>();
  const supera = (sev: string) => umbral !== "nunca" && rango(sev) >= rango(umbral);
  for (const h of hallazgos) {
    if (h.estado !== "verificado") continue;
    h.comparacion = op.anterior ? (verificadosAntes.has(h.huella) ? "persiste" : "nuevo") : "sin-anterior";
    const s = op.supresiones.vigentes.get(h.huella);
    if (s) {
      h.supresion = { motivo: tapador.texto(s.motivo), autor: tapador.texto(s.autor), vence: s.vence };
      aplicadas.add(h.huella);
    }
    h.bloqueante = supera(h.severidad) && !s && (!config.politica.soloNuevos || h.comparacion !== "persiste");
  }
  const retest: RetestCi[] = retestHechos.map((r) => {
    const s = op.supresiones.vigentes.get(r.retest.huella);
    if (s && r.retest.resultado === "persiste") aplicadas.add(r.retest.huella);
    return { ...r.retest, ...(s ? { supresion: { motivo: tapador.texto(s.motivo), autor: tapador.texto(s.autor), vence: s.vence } } : {}), bloqueante: r.retest.resultado === "persiste" && supera(r.retest.severidad) && !s && (!config.politica.soloNuevos || op.modo === "retest") };
  });
  const bloqueantes = hallazgos.filter((h) => h.bloqueante).length + retest.filter((r) => r.bloqueante).length;

  // ¿Infraestructura o incompleto? Lo que no se pudo probar o verificar nunca se lee como «todo bien».
  const proveedorFallo = finExploracion === "proveedor" || finExploracion === "sin-saldo" || fallasVerificacion.some((f) => f.proveedor) || retestHechos.some((r) => r.proveedor);
  const incompleto = ["presupuesto", "tiempo", "pasos"].includes(finExploracion) || fallasVerificacion.some((f) => !f.proveedor) || retestHechos.some((r) => r.corte || (r.retest.resultado === "sin-confirmar" && op.modo === "retest"));
  let estado: EstadoCorrida;
  let motivo: string;
  if (bloqueantes) {
    estado = "hallazgos";
    motivo = `${bloqueantes} hallazgo(s) verificado(s) desde severidad ${umbral}${config.politica.soloNuevos ? " (sólo nuevos)" : ""} sin supresión vigente.`;
  } else if (detenido && detenido.estado !== "hallazgos") {
    estado = detenido.estado;
    motivo = detenido.motivo;
  } else if (proveedorFallo) {
    estado = "infraestructura";
    motivo = finExploracion === "sin-saldo" ? "El proveedor dice que la cuenta no tiene saldo o el plan está inactivo: la corrida no es concluyente." : "El proveedor de modelos falló: la corrida no es concluyente.";
  } else if (incompleto) {
    estado = "incompleto";
    const partes = [
      finExploracion === "presupuesto" ? "la exploración agotó su presupuesto" : finExploracion === "tiempo" ? "la exploración agotó su tiempo" : finExploracion === "pasos" ? "la exploración llegó al tope de pasos" : "",
      fallasVerificacion.length ? `${fallasVerificacion.length} candidato(s) sin verificar` : "",
      retestHechos.some((r) => r.retest.resultado === "sin-confirmar") ? `${retestHechos.filter((r) => r.retest.resultado === "sin-confirmar").length} retest sin confirmar` : "",
    ].filter(Boolean);
    motivo = `Corrida incompleta: ${partes.join("; ")}.`;
  } else {
    estado = "ok";
    motivo = umbral === "nunca" ? "La política no hace fallar el job por hallazgos (fallar_desde: nunca)." : `Sin hallazgos verificados desde severidad ${umbral} sin supresión vigente.`;
  }
  if (bloqueantes && (detenido || proveedorFallo || incompleto)) avisos.push(`Además, la corrida no terminó entera (${detenido?.motivo ?? (proveedorFallo ? "falló el proveedor" : "presupuesto o tiempo")}): puede haber más.`);
  if (finExploracion === "sin-avance") avisos.push("El agente cortó la exploración por falta de avance (repetía lo mismo): lo que no llegó a probar está en «sin probar».");
  for (const f of fallasVerificacion) avisos.push(`Candidato ${f.id.slice(0, 8)} sin verificar: ${tapador.texto(f.error).slice(0, 200)}`);
  for (const s of op.supresiones.vencidas) avisos.push(`La supresión de ${s.huella} venció el ${s.vence}: ya no vale.`);
  avisos.push(...op.supresiones.avisos);

  const totales = engine.ledger.totals(engine.sessionId);
  const verificadorPico = BigInt((engine.db.prepare("select coalesce(sum(cast(cost_input as integer)+cast(cost_cache_read as integer)+cast(cost_cache_write as integer)+cast(cost_output as integer)),0) n from requests where session_id=? and worker like 'verificador:%' and cost_input is not null").get(engine.sessionId) as { n: number | bigint }).n);
  const modelos = (engine.db.prepare("select distinct provider || '/' || model m from requests where session_id=? and input is not null").all(engine.sessionId) as Array<{ m: string }>).map((r) => r.m);
  const fuera = intentosFuera(engine, tapador);
  const superficie = engine.http.surface();
  const probadas = superficie.filter((r) => r.state === "probado").map((r) => `${r.methods.join(",")} ${tapador.url(`http://${r.host}${r.path}`).replace(/^http:\/\//, "")}`).slice(0, 300);
  const sinProbar = [...superficie.filter((r) => r.state === "visto").map((r) => tapador.url(`http://${r.host}${r.path}`).replace(/^http:\/\//, "")), ...engine.http.unvisitedLinks().map((l) => tapador.texto(l))].slice(0, 300);
  if (cambios.activo) {
    const tocadas = new Set(superficie.filter((r) => r.state === "probado").map((r) => r.path));
    for (const r of cambios.rutas) {
      const patron = new RegExp(`^${r.ruta.replace(/[.+?^$()|[\]\\]/g, "\\$&").replace(/\{[^}]*\*\}/g, ".*").replace(/\{[^}]*\}/g, "[^/]+")}$`);
      if (![...tocadas].some((p) => patron.test(p))) sinProbar.push(`${r.ruta} (cambiada en el PR)`);
    }
  }
  const hosts = [...new Set(engine.http.log.map((l) => { try { return new URL(l.url).host; } catch { return ""; } }).filter(Boolean))].sort();

  const resultado: ResultadoCi = {
    formato: FORMATO,
    herramienta: { nombre: "orobas-sec", version: op.version },
    nombre: config.nombre,
    modo: op.modo,
    resultado: { codigo: CODIGOS[estado], estado, descripcion: DESCRIPCION_CODIGO[estado], motivo: tapador.texto(motivo), bloqueantes },
    corrida: { inicio: new Date(inicio).toISOString(), fin: new Date(fin).toISOString(), duracion_s: Math.round((fin - inicio) / 1000), sesion: engine.sessionId, ...omitirFork(contexto), fin_exploracion: finExploracion },
    autorizacion: { huella, fuente: fuenteAutorizacion, archivo: config.archivo, huella_archivo: huellaArchivo(config.fuente), ...(config.ref ? { ref: config.ref } : {}) },
    alcance: {
      incluido: incluidasHarness.map((r) => tapador.texto(r.value)),
      excluido: excluidas.flatMap((r) => r.reglas).map((r) => tapador.texto(r.value)),
      reglas: incluidas.map((r) => ({ destino: r.regla.nombre ?? r.regla.literal, tipo: r.regla.tipo, valor: tapador.texto(r.valor) })),
      acotado_a_cambios: acotado,
    },
    modelo: { nombre: `${provider.model.provider}/${provider.model.id}`, modelos_usados: modelos, router: engine.router.modo },
    gasto: { usd: usd(totales.knownPico, 6), tope_usd: totalUsd.toFixed(2), verificacion_usd: usd(verificadorPico, 6), solicitudes: totales.requests, solicitudes_sin_costo: totales.unknownRequests, tokens: { entrada: totales.tokens.input, cache_lectura: totales.tokens.cacheRead, cache_escritura: totales.tokens.cacheWrite, salida: totales.tokens.output } },
    tiempo: { tope_min: minutos, duracion_s: Math.round((fin - inicio) / 1000) },
    trafico: { peticiones: engine.http.count, bloqueadas_por_alcance: engine.http.blocked, intentos_fuera_de_alcance: fuera, solo_lectura: config.evaluacion.soloLectura, hosts },
    cobertura: { probadas, sin_probar: [...new Set(sinProbar)], solo_cambios: { activo: cambios.activo, motivo: cambios.motivo, ...(cambios.base ? { base: cambios.base } : {}), rutas: cambios.rutas.map((r) => ({ ruta: r.ruta, archivo: r.archivo, ...(r.linea ? { linea: r.linea } : {}) })), archivos_sin_ruta: cambios.sinRuta } },
    politica: { fallar_desde: umbral, solo_nuevos: config.politica.soloNuevos },
    hallazgos,
    comparacion: { anterior: comparacion.anterior, nuevos: comparacion.nuevos, persisten: comparacion.persisten, resueltos: comparacion.resueltos, sin_confirmar: comparacion.sinConfirmar },
    supresiones: { archivo: op.supresiones.archivo, aplicadas: [...aplicadas], vencidas: op.supresiones.vencidas.map(({ huella: h, motivo: m, autor, vence }) => ({ huella: h, motivo: tapador.texto(m), autor: tapador.texto(autor), vence })), sin_uso: [...op.supresiones.vigentes.keys()].filter((h) => !aplicadas.has(h)) },
    retest,
    avisos: avisos.map((a) => tapador.texto(a)),
  };
  if (totales.unknownRequests) resultado.avisos.push(`${totales.unknownRequests} solicitud(es) con costo desconocido: el tope de gasto no las cuenta.`);
  const registro = armarRegistro(engine, tapador, resultado, avisosMotor);
  log(`${estado === "ok" ? "✓" : "✗"} ${resultado.resultado.motivo} (código ${CODIGOS[estado]}) · USD ${resultado.gasto.usd} · ${resultado.tiempo.duracion_s} s`);

  // 12. Cierre: el motor, el entorno y la carpeta de datos (salvo que se pida conservarla).
  const trazas = engine.trazasDir;
  const cerrado = await Promise.race([engine.close().then(() => true), new Promise<boolean>((fin) => setTimeout(() => fin(false), 15_000).unref())]);
  if (!cerrado) resultado.avisos.push("El motor no terminó de cerrar en 15 s; la corrida siguió igual.");
  process.env.CYBER_DATA_DIR = anteriores.datos;
  if (anteriores.trazas === undefined) delete process.env.CYBER_TRAZAS;
  else process.env.CYBER_TRAZAS = anteriores.trazas;
  let trazasCopia: string | undefined;
  if (config.trazas === "local" && existsSync(trazas)) {
    trazasCopia = mkdtempSync(join(tmpdir(), "orobas-ci-trazas-"));
    cpSync(trazas, trazasCopia, { recursive: true });
  }
  if (!op.datos && !op.conservarDatos) rmSync(datos, { recursive: true, force: true });
  return { resultado, codigo: CODIGOS[estado], registro, tapador, ...(trazasCopia ? { trazas: trazasCopia } : {}) };
}

const omitirFork = ({ fork: _fork, actor: _actor, ...resto }: ContextoCi) => resto;

/** Cómo terminó el turno de exploración, según los mensajes del turno. */
export function clasificarFin(mensajes: Engine["agent"]["messages"], porTiempo: boolean): string {
  if (porTiempo) return "tiempo";
  const errores = mensajes.filter((m) => m.role === "assistant" && (m.stopReason === "error" || m.stopReason === "aborted"));
  for (const m of errores) {
    if (m.role !== "assistant") continue;
    const texto = m.errorMessage ?? "";
    if (m.exhausted || exhaustedError(texto)) return "sin-saldo";
    if (/Presupuesto de sesión|Tope del proyecto/.test(texto)) return "presupuesto";
    if (/Límite de pasos/.test(texto)) return "pasos";
    if (/falta de avance/.test(texto)) return "sin-avance";
    if (m.stopReason === "aborted") return "tiempo";
    if (!m.requestId.startsWith("local:")) return "proveedor";
  }
  if (mensajes.some((m) => m.role === "user" && typeof m.content === "string" && m.content.startsWith("[sistema] Llegaste al tope"))) {
    const ultimo = mensajes.findLast((m) => m.role === "assistant");
    if (ultimo?.role === "assistant" && ultimo.provider === "harness") return "pasos";
  }
  return "cierre";
}

/** Destinos que el agente intentó y el alcance frenó (de los resultados de sus herramientas), tapados. */
function intentosFuera(engine: Engine, tapador: Tapador): string[] {
  const salida = new Set<string>();
  for (const m of engine.agent.messages) {
    if (m.role !== "tool") continue;
    const texto = String(m.content);
    if (!/Fuera del alcance|Excluido por la regla/.test(texto)) continue;
    const destino = /Fuera del alcance: (?:No hay alcance definido[^.]*\.|(\S+?) no coincide con ninguna regla)/.exec(texto)?.[1] ?? /Excluido por la regla (\S+)/.exec(texto)?.[1];
    if (destino) salida.add(tapador.texto(destino));
    else if (/Fuera del alcance/.test(texto)) salida.add(tapador.texto(texto.slice(0, 160)));
  }
  return [...salida].slice(0, 50);
}

/** El registro de lo que hizo la corrida (artefacto del job): eventos, peticiones y herramientas, todo tapado. */
function armarRegistro(engine: Engine, tapador: Tapador, resultado: ResultadoCi, avisos: string[]): Array<Record<string, unknown>> {
  const lineas: Array<{ t: string; [k: string]: unknown }> = [];
  const eventos = engine.db.prepare("select type, at, payload from events where session_id=? order by seq").all(engine.sessionId) as Array<{ type: string; at: string; payload: string }>;
  for (const e of eventos) {
    if (/^(contexto\.|ajuste\.presupuesto|ledger\.)/.test(e.type)) continue;
    let datos: unknown;
    try { datos = JSON.parse(e.payload); } catch { datos = e.payload; }
    lineas.push({ t: e.at, tipo: e.type, datos: tapador.objeto(datos) });
  }
  const artefactos = new Map((engine.db.prepare("select hash, created_at from artifacts where producer='http'").all() as Array<{ hash: string; created_at: string }>).map((a) => [a.hash, a.created_at]));
  for (const l of engine.http.log) {
    const ex = intercambio(engine, l.hash);
    lineas.push({ t: artefactos.get(l.hash) ?? resultado.corrida.inicio, tipo: "http", id: l.id, metodo: l.method, url: tapador.url(l.url), estado: l.status ?? null, identidad: l.identity ?? null, ms: ex?.durationMs ?? null, artefacto: l.hash });
  }
  for (const m of engine.agent.messages) {
    if (m.role === "assistant") for (const c of m.toolCalls) lineas.push({ t: new Date(m.at).toISOString(), tipo: "herramienta", nombre: c.name, argumentos: tapador.texto(c.arguments).slice(0, 600) });
    // Lo que se rechazó (fuera del alcance, sólo lectura, guardas): queda constancia de qué se intentó y por qué no salió.
    if (m.role === "tool" && m.isError) lineas.push({ t: new Date(m.at).toISOString(), tipo: "herramienta.rechazo", nombre: m.name, texto: tapador.texto(String(m.content)).slice(0, 600) });
  }
  for (const a of avisos) lineas.push({ t: resultado.corrida.fin, tipo: "aviso", texto: tapador.texto(a).slice(0, 600) });
  lineas.push({ t: resultado.corrida.fin, tipo: "ci.fin", estado: resultado.resultado.estado, codigo: resultado.resultado.codigo, motivo: resultado.resultado.motivo, gasto_usd: resultado.gasto.usd, peticiones: resultado.trafico.peticiones, bloqueadas_por_alcance: resultado.trafico.bloqueadas_por_alcance });
  return lineas.sort((a, b) => String(a.t).localeCompare(String(b.t)));
}
