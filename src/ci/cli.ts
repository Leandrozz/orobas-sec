// «cyber ci»: la corrida no interactiva para integración continua y sus ayudantes (validar, huella, ejemplo,
// comentar). Tiene sus propias opciones: src/cli.ts la despacha antes de leer las del resto de la CLI.
// Códigos de salida (estables): 0 sin hallazgos que bloqueen · 1 hallazgos verificados que bloquean · 2 configuración ·
// 3 proveedor o infraestructura · 4 presupuesto o tiempo agotado sin terminar. Ver docs/ci.md.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { Provider } from "../providers.ts";
import { comentarGithub, comentarGitlab } from "./comentario.ts";
import { ARCHIVO_POR_DEFECTO, cargarConfig, type ConfigCi, EJEMPLO, ErrorConfig, expandirAlcance, huellaAlcance, SUPRESIONES_POR_DEFECTO } from "./config.ts";
import { contextoCi, correr, resultadoSinCorrer } from "./corrida.ts";
import { leerAnterior, leerSupresiones, type Supresiones } from "./linea-base.ts";
import { marcador } from "./markdown.ts";
import { CODIGOS, DESCRIPCION_CODIGO } from "./resultado.ts";
import { ARCHIVOS, escribirSalidas } from "./salidas.ts";

export const AYUDA = `cyber ci: evaluación de seguridad no interactiva para integración continua

Uso:
  cyber ci [opciones]                corre la evaluación con .orobas/ci.yml
  cyber ci --retest [opciones]       vuelve a probar los hallazgos verificados de --anterior
  cyber ci validar [--config A]      valida la configuración y muestra la huella del alcance
  cyber ci huella [--config A]       imprime sólo la huella del alcance (lo que se autoriza)
  cyber ci ejemplo                   imprime un .orobas/ci.yml comentado
  cyber ci comentar [--resumen R]    crea o edita el comentario del PR (GitHub) o del MR (GitLab)

Opciones:
  --config ARCHIVO           configuración (por defecto .orobas/ci.yml; también OROBAS_CI_CONFIG)
  --config-ref COMMIT        leer la configuración y las supresiones de ese commit (PRs de forks: la base)
  --autorizo-alcance HUELLA  confirma el alcance (si no, OROBAS_CI_AUTORIZACION)
  --anterior ARCHIVO         resultado.json de la corrida anterior (comparación y retest; también OROBAS_CI_ANTERIOR)
  --salida CARPETA           dónde escribir las salidas (por defecto orobas-ci)
  --presupuesto USD          tope de gasto de la corrida      --minutos N   tope de tiempo
  --modelo PROVEEDOR/MODELO  modelo                           --fallar-desde SEVERIDAD|nunca
  --solo-cambios si|no|auto  concentrarse en lo que cambió el PR
  --solo-lectura             sólo GET, HEAD y OPTIONS         --junit       también junit.xml
  --trazas compartir|local|no
  --conservar-datos          no borrar la carpeta de datos de la corrida (para depurar)
  -C, --dir CARPETA          raíz del repositorio (por defecto la actual)

Códigos de salida: 0 sin hallazgos que bloqueen · 1 hallazgos verificados que bloquean · 2 configuración ·
3 proveedor o infraestructura · 4 presupuesto o tiempo agotado sin terminar.`;

/** La versión instalada (archivo VERSION del release) o la del paquete. */
export function versionInstalada(): string {
  const raiz = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  try {
    return readFileSync(join(raiz, "VERSION"), "utf8").trim();
  } catch {
    try {
      return `${(JSON.parse(readFileSync(join(raiz, "package.json"), "utf8")) as { version: string }).version} (desarrollo)`;
    } catch {
      return "desconocida";
    }
  }
}

export interface Inyectado {
  /** Proveedor ya resuelto (pruebas). */
  proveedor?: Provider;
  fetch?: typeof fetch;
  salida?: (texto: string) => void;
  error?: (texto: string) => void;
  reservaVerificacionMs?: number;
  datos?: string;
}

const OPCIONES = {
  config: { type: "string" },
  "config-ref": { type: "string" },
  "autorizo-alcance": { type: "string" },
  anterior: { type: "string" },
  retest: { type: "boolean" },
  salida: { type: "string" },
  presupuesto: { type: "string" },
  minutos: { type: "string" },
  modelo: { type: "string" },
  "fallar-desde": { type: "string" },
  "solo-cambios": { type: "string" },
  "solo-lectura": { type: "boolean" },
  junit: { type: "boolean" },
  trazas: { type: "string" },
  "conservar-datos": { type: "boolean" },
  resumen: { type: "string" },
  nombre: { type: "string" },
  pr: { type: "string" },
  dir: { type: "string", short: "C" },
  help: { type: "boolean", short: "h" },
} as const;

/** Corre «cyber ci» con estos argumentos y devuelve el código de salida. */
export async function correrCi(argv: string[], env: NodeJS.ProcessEnv = process.env, inyectado: Inyectado = {}): Promise<number> {
  const salida = inyectado.salida ?? ((t: string) => process.stdout.write(`${t}\n`));
  const error = inyectado.error ?? ((t: string) => process.stderr.write(`${t}\n`));
  let args: ReturnType<typeof parseArgs<{ options: typeof OPCIONES; allowPositionals: true }>>;
  try {
    args = parseArgs({ args: argv, options: OPCIONES, allowPositionals: true });
  } catch (e) {
    error(`${(e as Error).message}\n\n${AYUDA}`);
    return CODIGOS.configuracion;
  }
  const v = args.values;
  const sub = args.positionals[0];
  if (v.help || sub === "ayuda" || sub === "help") {
    salida(AYUDA);
    return 0;
  }
  if (sub === "ejemplo") {
    salida(EJEMPLO);
    return 0;
  }
  if (sub && !["validar", "huella", "comentar"].includes(sub)) {
    error(`Subcomando desconocido: ${sub}\n\n${AYUDA}`);
    return CODIGOS.configuracion;
  }
  const cwd = resolve(v.dir ?? process.cwd());
  if (!existsSync(cwd)) {
    error(`No existe la carpeta ${cwd}`);
    return CODIGOS.configuracion;
  }
  if (sub === "comentar") return comentar(cwd, v, env, inyectado, salida, error);

  const archivo = v.config ?? env.OROBAS_CI_CONFIG ?? ARCHIVO_POR_DEFECTO;
  const ref = v["config-ref"] ?? (env.OROBAS_CI_CONFIG_REF || undefined);
  const banderas = { presupuestoUsd: v.presupuesto, minutos: v.minutos, modelo: v.modelo, fallarDesde: v["fallar-desde"], salida: v.salida, soloCambios: v["solo-cambios"], soloLectura: v["solo-lectura"], junit: v.junit, trazas: v.trazas };
  const inicio = Date.now();
  const version = versionInstalada();
  const modo = v.retest ? "retest" as const : "evaluacion" as const;
  let config: ConfigCi | undefined;
  let supresiones: Supresiones | undefined;
  const avisos: string[] = [];
  try {
    config = cargarConfig({ cwd, archivo, ref, env, banderas });
    if (sub === "huella") {
      salida(huellaAlcance(config));
      return 0;
    }
    supresiones = leerSupresiones(cwd, config.lineaBase.supresiones, ref);
    if (!supresiones.existe && config.lineaBase.supresiones !== SUPRESIONES_POR_DEFECTO) avisos.push(`No existe ${config.lineaBase.supresiones}: ninguna supresión.`);
    if (sub === "validar") {
      const huella = huellaAlcance(config);
      salida(`${archivo}${ref ? ` (de ${ref})` : ""}: configuración válida «${config.nombre}».`);
      salida(`Huella del alcance: ${huella}`);
      salida(`Para autorizarlo, quien administra el repositorio define OROBAS_CI_AUTORIZACION=${huella} en el CI (variable o secreto, no en el archivo).`);
      try {
        const { incluidas, excluidas } = expandirAlcance(config, env);
        salida(`Alcance con este entorno: ${incluidas.map((r) => r.valor).join(", ")}${excluidas.length ? `; excluido: ${excluidas.map((r) => r.valor).join(", ")}` : ""}.`);
      } catch (e) {
        if (!(e instanceof ErrorConfig)) throw e;
        salida(`Con este entorno el alcance todavía no se puede expandir (se resuelve al correr):\n${e.message}`);
      }
      salida(`Supresiones: ${supresiones.existe ? `${supresiones.vigentes.size} vigente(s), ${supresiones.vencidas.length} vencida(s)` : "ninguna"}.`);
      return 0;
    }
  } catch (e) {
    if (!(e instanceof ErrorConfig)) throw e;
    error(`Configuración inválida:\n${e.message}`);
    if (sub) return CODIGOS.configuracion;
    // La corrida igual deja sus salidas: el comentario del PR dice por qué no corrió.
    const nombre = config?.nombre ?? "orobas-ci";
    const resultado = resultadoSinCorrer({ nombre, modo, version, estado: "configuracion", motivo: `Configuración inválida: ${e.message}`, inicio, contexto: contextoCi(env, cwd), avisos });
    const carpeta = banderas.salida ?? env.OROBAS_CI_SALIDA ?? "orobas-ci";
    const escritas = escribirSalidas({ carpeta, cwd, resultado, registro: [{ t: new Date().toISOString(), tipo: "ci.fin", estado: "configuracion" }], junit: !!banderas.junit, sarifCandidatos: false });
    publicarEnElCi(env, escritas.markdown, resultado.resultado.codigo, resultado.resultado.estado, escritas, 0);
    return CODIGOS.configuracion;
  }

  const anteriorRuta = v.anterior ?? (env.OROBAS_CI_ANTERIOR || undefined);
  let anterior;
  if (anteriorRuta) {
    const ruta = resolve(cwd, anteriorRuta);
    const leido = leerAnterior(existsSync(ruta) ? readFileSync(ruta, "utf8") : undefined);
    anterior = leido.anterior;
    if (leido.aviso) avisos.push(leido.aviso);
    if (!existsSync(ruta)) avisos.push(`No hay corrida anterior en ${anteriorRuta}: no hay contra qué comparar${modo === "retest" ? " ni qué retestear" : ""}.`);
  }
  if (modo === "retest" && !anterior?.hallazgos.some((h) => h.estado === "verificado")) avisos.push("Retest sin hallazgos verificados conocidos: no hay nada que volver a probar.");

  const corrida = await correr({ cwd, config, env, modo, version, supresiones: supresiones!, anterior, avisos, autorizacion: v["autorizo-alcance"], conservarDatos: v["conservar-datos"], proveedor: inyectado.proveedor, log: error, reservaVerificacionMs: inyectado.reservaVerificacionMs, datos: inyectado.datos });
  const escritas = escribirSalidas({ carpeta: config.salidas.carpeta, cwd, resultado: corrida.resultado, registro: corrida.registro, config, junit: config.salidas.junit, sarifCandidatos: config.salidas.sarifCandidatos, tapador: corrida.tapador, trazas: corrida.trazas });
  publicarEnElCi(env, escritas.markdown, corrida.codigo, corrida.resultado.resultado.estado, escritas, corrida.resultado.resultado.bloqueantes);
  salida(`${DESCRIPCION_CODIGO[corrida.resultado.resultado.estado]} (código ${corrida.codigo}).`);
  salida(`Salidas en ${relative(cwd, escritas.carpeta) || "."}: ${[ARCHIVOS.json, ARCHIVOS.sarif, ARCHIVOS.markdown, ARCHIVOS.registro, ...(escritas.junit ? [ARCHIVOS.junit] : [])].join(", ")}.`);
  return corrida.codigo;
}

/** En GitHub Actions: el resumen del job y las salidas del paso. */
function publicarEnElCi(env: NodeJS.ProcessEnv, markdown: string, codigo: number, estado: string, escritas: ReturnType<typeof escribirSalidas>, bloqueantes: number): void {
  try {
    if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${readFileSync(markdown, "utf8")}\n`);
    if (env.GITHUB_OUTPUT) {
      appendFileSync(env.GITHUB_OUTPUT, [`codigo=${codigo}`, `estado=${estado}`, `bloqueantes=${bloqueantes}`, `json=${escritas.json}`, `sarif=${escritas.sarif}`, `resumen=${escritas.markdown}`, `carpeta=${escritas.carpeta}`, ""].join("\n"));
    }
  } catch { /* el resumen del job es un extra: no cambia el resultado */ }
}

async function comentar(cwd: string, v: { resumen?: string; nombre?: string; pr?: string; salida?: string }, env: NodeJS.ProcessEnv, inyectado: Inyectado, salida: (t: string) => void, error: (t: string) => void): Promise<number> {
  const ruta = resolve(cwd, v.resumen ?? join(v.salida ?? env.OROBAS_CI_SALIDA ?? "orobas-ci", ARCHIVOS.markdown));
  if (!existsSync(ruta)) {
    error(`No existe ${ruta}: corré «cyber ci» primero.`);
    return CODIGOS.configuracion;
  }
  const cuerpo = readFileSync(ruta, "utf8");
  const nombre = v.nombre ?? /^<!-- orobas-sec:ci:([^ ]+) -->/.exec(cuerpo)?.[1] ?? "orobas-ci";
  const pr = v.pr ? Number(v.pr) : undefined;
  const gitlab = !!env.GITLAB_CI;
  try {
    const hecho = await (gitlab ? comentarGitlab : comentarGithub)({ cuerpo, marcador: marcador(nombre), env, fetch: inyectado.fetch, ...(pr ? { pr } : {}) });
    salida(`Comentario ${hecho.accion}${hecho.url ? `: ${hecho.url}` : ` (${hecho.id})`}.`);
    return 0;
  } catch (e) {
    error(`No pude comentar: ${(e as Error).message}`);
    return /^Falta|^No es un/.test((e as Error).message) ? CODIGOS.configuracion : CODIGOS.infraestructura;
  }
}
