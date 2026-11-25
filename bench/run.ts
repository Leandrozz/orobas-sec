// Benchmark contra OWASP Juice Shop. El oráculo son los desafíos que Juice Shop marca como
// resueltos en su propia base: no depende de lo que el agente diga haber encontrado.
//
//   node bench/run.ts --task bench/tasks/exploracion.md --runs 2 --label harness
//   node bench/run.ts --task bench/tasks/exploracion.md --external "cyberstrike ..." --label cyberstrike
//   node bench/run.ts --target fenix --task bench/tasks/fenix.md --runs 3 --label harness-fenix
//   node bench/run.ts --target cve --caso todos --version afectada --runs 1 --label banco   (guía: docs/benchmark.md)
//   node bench/run.ts --target cve --caso CVE-2026-55066 --version afectada --runs 5 --label harness-cve
//   node bench/run.ts --target cve --caso todos --version corregida --runs 2 --label harness-cve-fp
//
// --grafo no apaga el grafo de hechos (src/grafo.ts) para medir con y sin, en las mismas condiciones. --verificar no
// apaga la verificación automática (su modelo y su tope son otros: confunden la comparación y el gasto). --fuerte fija
// el modelo de deep_reason y de los subagentes fuertes (por defecto el de la configuración).
//
// --pasos sube el tope de pasos por turno (60 por defecto): los casos que exigen encadenar
// operaciones se quedan sin pasos mucho antes de gastar el presupuesto.
//
// Objetivo cve: cada caso de bench/cve/ corre con Docker Compose local o, si se pide, por SSH;
// el oráculo es el estado de la aplicación (bench/cve/README.md) y la consigna sale de tarea.md
// del caso. La versión corregida mide qué afirma el agente cuando la falla no existe.
//
// Cada corrida reinicia Juice Shop (base limpia), crea un proyecto nuevo con el alcance del
// laboratorio y mide: desafíos resueltos por categoría y dificultad, candidatos registrados,
// solicitudes, tokens, costo, duración, pasos sin avance y errores.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { Engine } from "../src/engine.ts";
import { usd } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";
import { composeProblems, cveCommand, isRemoteDockerEndpoint, isWildcard, urlHost } from "./cve/command.ts";

const JUICE = { dir: join(homedir(), "lab", "juice-shop", "app"), url: "http://127.0.0.1:3000", pidFile: join(homedir(), "lab", "juice-shop", "juice.pid") };
const FENIX = { url: "http://127.0.0.1:3001", script: join(import.meta.dirname, "lab", "fenix.ts") };

const { values } = parseArgs({
  options: {
    task: { type: "string" },
    target: { type: "string", default: "juice" },
    runs: { type: "string", default: "1" },
    label: { type: "string", default: "harness" },
    model: { type: "string" },
    presupuesto: { type: "string", default: "0.50" },
    peticiones: { type: "string", default: "sin" },
    pasos: { type: "string" },
    objeciones: { type: "string" },
    // Regla de cierre honesta: «sin» la apaga para medirla por contraste.
    cierre: { type: "string" },
    // Banco de CVE/CWE: en --target cve va apagado (medición ciega); «si» lo habilita para medir la diferencia.
    banco: { type: "string" },
    grafo: { type: "string", default: "si" },
    verificar: { type: "string", default: "si" },
    fuerte: { type: "string" },
    external: { type: "string" },
    out: { type: "string", default: join(import.meta.dirname, "results") },
    // Sólo para --target cve.
    caso: { type: "string", default: "todos" },
    version: { type: "string", default: "afectada" },
    bind: { type: "string" },
    puerto: { type: "string", default: "18080" },
  },
});
if (!values.task && values.target !== "cve") throw new Error("Falta --task <archivo con la consigna>");
// Con cve la consigna sale de tarea.md de cada caso, con la URL publicada; se fija al reiniciar el objetivo.
let task = values.task ? readFileSync(values.task, "utf8").trim() : "";

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function challenges(): Promise<Array<{ key: string; name: string; category: string; difficulty: number; solved: boolean }>> {
  const response = await fetch(`${JUICE.url}/api/Challenges/`);
  return ((await response.json()) as any).data;
}

async function restartJuice(): Promise<void> {
  if (existsSync(JUICE.pidFile)) {
    const pid = Number(readFileSync(JUICE.pidFile, "utf8"));
    const alive = () => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };
    // Esperar a que suelte el puerto: si arrancamos el nuevo antes, no puede escuchar y el viejo sigue.
    for (let i = 0; alive() && i < 30; i++) {
      try {
        process.kill(pid, i < 20 ? "SIGTERM" : "SIGKILL");
      } catch {}
      await wait(500);
    }
  }
  const child = spawn(process.execPath, ["build/app.js"], { cwd: JUICE.dir, detached: true, stdio: "ignore", env: { ...process.env, PORT: "3000" } });
  child.unref();
  writeFileSync(JUICE.pidFile, `${child.pid}\n`);
  for (let i = 0; i < 180; i++) {
    await wait(2000);
    try {
      const list = await challenges();
      if (list.length && !list.some((item) => item.solved)) return;
    } catch {}
  }
  throw new Error("Juice Shop no arrancó limpio en 6 minutos");
}

interface Solved {
  key: string;
  category: string;
  difficulty: number;
}

/** Objetivo del benchmark: cómo reiniciarlo limpio y qué dice su oráculo. */
interface Target {
  url: string;
  total: number;
  restart(): Promise<void>;
  solved(): Promise<Solved[]>;
  /** Peticiones HTTP que recibió el objetivo en la corrida, si las cuenta. */
  httpRequests?(): Promise<number>;
  /** Clasifica el activo de un hallazgo: verdadero (clave de la falla), señuelo, o fuera de la lista. */
  classify?(asset: string): { kind: "verdadero"; key: string } | { kind: "no_demostrado"; key: string } | { kind: "derivado"; key: string } | { kind: "señuelo"; why: string } | { kind: "sin_clasificar" };
  stop?(): void;
  /** Objetivos con varios casos (cve): cuál está activo y cuáles correr. */
  casos?: string[];
  use?(caso: string): void;
  /** Consigna propia del caso activo (cve), ya con la URL publicada. */
  task?(): string;
  /** Último código del oráculo (cve): 0 efecto, 1 sin efecto, 2 laboratorio inválido. */
  oracleExit?(): number | undefined;
}

const juiceTarget: Target = {
  url: JUICE.url,
  total: 0,
  restart: restartJuice,
  solved: async () => (await challenges()).filter((item) => item.solved).map((item) => ({ key: item.key, category: item.category, difficulty: item.difficulty })),
};

function fenixTarget(): Target {
  let child: ReturnType<typeof spawn> | undefined;
  let oracle: any;
  let defs: { VULNS: Record<string, { paths: RegExp }>; DECOYS: Array<{ path: RegExp; why: string }> };
  const stop = () => {
    if (child?.pid) {
      try {
        process.kill(child.pid, "SIGTERM");
      } catch {}
    }
    child = undefined;
  };
  const target: Target = {
    url: FENIX.url,
    total: 0,
    stop,
    async restart() {
      stop();
      // El laboratorio de Fénix queda fuera de la exportación pública; CVE no lo necesita.
      defs = await import(join(import.meta.dirname, "lab", "fenix-defs.ts"));
      await wait(300);
      child = spawn(process.execPath, ["--disable-warning=ExperimentalWarning", FENIX.script, "3001"], { stdio: "ignore" });
      child.unref(); // que no mantenga vivo al runner al terminar; lo mata el manejador de exit.
      for (let i = 0; i < 50; i++) {
        await wait(200);
        try {
          oracle = await (await fetch(`${FENIX.url}/__oracle`)).json();
          target.total = Object.keys(oracle.vulns).length;
          return;
        } catch {}
      }
      throw new Error("Tienda Fénix no arrancó");
    },
    async httpRequests() {
      return ((await (await fetch(`${FENIX.url}/__oracle`)).json()) as any).requests as number;
    },
    async solved() {
      oracle = await (await fetch(`${FENIX.url}/__oracle`)).json();
      return Object.entries(oracle.vulns as Record<string, any>)
        .filter(([, v]) => v.triggered)
        .map(([key, v]) => ({ key, category: v.kind, difficulty: v.difficulty }));
    },
    classify(asset) {
      // Marcadores de posición ({id}, :id) cuentan como un número; sólo se mira la primera URL del activo.
      let path = asset.trim().split(/\s/)[0]!.replace(/\{[^}]*\}|:[a-z]+(?=\/|$)/gi, "1");
      try {
        path = /^https?:\/\//i.test(path) ? new URL(path).pathname + new URL(path).search : path;
      } catch {}
      // Verdadero sólo si además el oráculo vio la explotación: un candidato sobre la ruta correcta con una afirmación falsa no cuenta.
      // Varias fallas pueden compartir ruta (login: credenciales débiles y enumeración): vale cualquiera que el oráculo haya visto.
      const matching = Object.entries(defs.VULNS).filter(([, v]) => v.paths.test(path)).map(([key]) => key);
      if (matching.length) {
        const shown = matching.find((key) => oracle?.vulns?.[key]?.triggered);
        return shown ? { kind: "verdadero", key: shown } : { kind: "no_demostrado", key: matching[0]! };
      }
      // Con el rol escalado por asignación masiva, leer pedidos ajenos es consecuencia de esa falla, no un falso positivo.
      for (const d of defs.DECOYS) if (d.path.test(path)) return /\/api\/pedidos/.test(path) && oracle?.vulns?.asignacion_masiva?.triggered ? { kind: "derivado", key: "asignacion_masiva" } : { kind: "señuelo", why: d.why };
      // El listado completo de pedidos con el rol escalado también deriva de la asignación masiva; /__demo es el andamiaje del laboratorio.
      if (/\/api\/pedidos/.test(path) && oracle?.vulns?.asignacion_masiva?.triggered) return { kind: "derivado", key: "asignacion_masiva" };
      if (/\/__demo/.test(path)) return { kind: "derivado", key: "laboratorio" };
      return { kind: "sin_clasificar" };
    },
  };
  return target;
}

interface CaseInfo {
  producto: string;
  clase: string;
  corregida: string;
  seed: boolean;
}

/** Corre una orden sin perder la salida cuando Docker o SSH devuelven error. */
function runCommand(command: ReturnType<typeof cveCommand>): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    let out = "";
    const child = spawn(command.file, command.args, { cwd: command.cwd, env: command.env, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (out += chunk));
    child.on("error", (error) => (out += `\n${error.message}`));
    child.on("close", (code) => resolve({ code, out }));
  });
}

function cveTarget(): Target {
  const root = join(import.meta.dirname, "..");
  const casos = (JSON.parse(readFileSync(join(root, "bench", "cve", "casos.json"), "utf8")) as { casos: Record<string, CaseInfo> }).casos;
  const chosen = values.caso === "todos" ? Object.keys(casos) : values.caso!.split(",").map((c) => c.trim());
  for (const c of chosen) if (!casos[c]) throw new Error(`Caso desconocido: ${c} (ver bench/cve/casos.json)`);
  if (values.version !== "afectada" && values.version !== "corregida") throw new Error(`--version debe ser afectada o corregida`);
  const sshHost = process.env.CYBER_CVE_SSH?.trim() || undefined;
  const port = Number(values.puerto);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("--puerto debe ser un entero entre 1 y 65535");
  if (port === 80 || port === 443) throw new Error("Usá un puerto distinto de 80/443: el alcance del harness no distingue puertos predeterminados");
  if (sshHost?.startsWith("-")) throw new Error("CYBER_CVE_SSH no puede empezar con «-»");
  const remoteDir = process.env.CYBER_CVE_REMOTE_DIR || "/tmp/elevate-cve-runner";
  // Local: 127.0.0.1. SSH sin bind explícito: la primera IP del host remoto (`hostname -I`), como antes,
  // para que el agente que corre en esta máquina llegue al laboratorio. La URL sigue al bind salvo que se pida otra.
  let bind = values.bind || process.env.CYBER_CVE_BIND?.trim() || (sshHost ? "" : "127.0.0.1");
  const explicitPublic = process.env.CYBER_CVE_PUBLIC_HOST?.trim() || undefined;
  const publicFor = (b: string) => explicitPublic ?? (isWildcard(b) ? (sshHost?.split("@").pop() ?? "127.0.0.1") : b);
  let publicHost = bind ? publicFor(bind) : "";
  let caso = chosen[0]!;
  let lastOracle: number | undefined;
  let synced = false;

  // El nombre de proyecto propio evita pisar contenedores o volúmenes de una prueba manual.
  const invocation = (command: string, which = caso) => cveCommand({
    root, caso: which, port, bind, publicHost, sshHost, remoteDir,
    correctedImage: values.version === "corregida" ? casos[which]!.corregida : undefined,
  }, command);
  const compose = (command: string) => runCommand(invocation(command));
  const oracle = async () => {
    const r = await compose("./oracle.sh");
    lastOracle = r.code ?? 2;
    if (lastOracle === 2) process.stdout.write(`  oráculo inválido:\n${r.out.trim().split("\n").slice(-5).map((l) => "    " + l).join("\n")}\n`);
    return lastOracle;
  };
  const down = (which = caso) => runCommand(invocation("docker compose down -v --remove-orphans", which));
  // Todos los casos publican el mismo puerto: al cambiar de caso hay que bajar el anterior, no sólo el propio.
  let previous: string | undefined;

  const target: Target = {
    url: "",
    total: 1,
    casos: chosen,
    use(c) {
      caso = c;
      lastOracle = undefined;
    },
    task: () => readFileSync(join(root, "bench", "cve", caso, "tarea.md"), "utf8").trim().replaceAll("{{BASE_URL}}", target.url),
    oracleExit: () => lastOracle,
    async restart() {
      if (!synced) {
        if (sshHost) {
          if (!bind) {
            const r = await runCommand({ file: "ssh", args: ["-o", "BatchMode=yes", sshHost, "hostname -I"] });
            bind = r.out.trim().split(/\s+/)[0] ?? "";
            if (r.code !== 0 || !bind) throw new Error(`No pude obtener la IP de ${sshHost} (definí CYBER_CVE_BIND): ${r.out.trim()}`);
            publicHost = publicFor(bind);
          }
          // Las semillas importan src/; no se copian notas de explotación, resultados ni credenciales.
          // --delete-excluded borra también lo que una copia vieja haya dejado de esos archivos.
          await runCommand({ file: "ssh", args: ["-o", "BatchMode=yes", sshHost, `mkdir -p '${remoteDir.replaceAll("'", "'\\''")}'`] });
          execFileSync("rsync", ["-aR", "--delete", "--delete-excluded", "--exclude=OPERADOR.md", "--exclude=positivo/", "--exclude=verificacion/", "--exclude=fichas-revisadas.json", "src/", "bench/cve/", `${sshHost}:${remoteDir}/`], { cwd: root, stdio: "inherit" });
        } else {
          // Los Compose montan archivos del caso: con un Docker de otra máquina se resolverían en su disco.
          const endpoint = process.env.DOCKER_HOST || (await runCommand({ file: "docker", args: ["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"] })).out.trim();
          if (isRemoteDockerEndpoint(endpoint)) throw new Error(`Docker apunta a otra máquina (${endpoint}). Para un Docker remoto usá CYBER_CVE_SSH=<host>, o elegí un contexto local con DOCKER_CONTEXT=default.`);
        }
        synced = true;
      }
      target.url = `http://${urlHost(publicHost)}:${port}`;
      if (previous && previous !== caso) await down(previous);
      previous = caso;
      await down();
      const t0 = Date.now();
      const up = await compose("docker compose up -d --wait --wait-timeout 300");
      if (up.code !== 0) {
        // Compose 2.26 devuelve 1 con --wait cuando un contenedor de una sola pasada (la semilla) ya terminó, aunque haya salido con 0.
        // Se mira el estado real: ningún contenedor salido con código distinto de 0 y los que siguen corriendo, sanos.
        const ps = await compose("docker compose ps -a --format json");
        const bad = ps.code === 0 ? composeProblems(ps.out) : [ps.out.trim()];
        if (bad.length) throw new Error(`${caso}: compose up falló (${up.code}):\n${up.out.trim().split("\n").slice(-12).join("\n")}\n${bad.join("\n")}`);
      }
      if (casos[caso]!.seed) {
        // Compose 2.26 puede saltear un contenedor ya terminado con `compose wait`; se espera por ID, como documenta el caso.
        const seed = await compose(`seed=$(docker compose ps -a -q seed); test -n "$seed" && test "$(docker wait "$seed")" = 0 || { docker compose logs seed | tail -20; exit 1; }`);
        if (seed.code !== 0) throw new Error(`${caso}: la semilla falló:\n${seed.out.trim().split("\n").slice(-20).join("\n")}`);
      }
      const o = await oracle();
      if (o !== 1) throw new Error(`${caso}: el oráculo inicial devolvió ${o} y debía ser 1; no se evalúa al agente sobre un laboratorio inválido`);
      // El oráculo corre del lado de Docker; el agente, acá. Si desde acá no se llega, la corrida no mide nada.
      try {
        await fetch(target.url, { signal: AbortSignal.timeout(10_000), redirect: "manual" });
      } catch (error) {
        throw new Error(`${caso}: el laboratorio está arriba pero ${target.url} no responde desde esta máquina (${(error as Error).message}). Revisá CYBER_CVE_BIND y CYBER_CVE_PUBLIC_HOST.`);
      }
      process.stdout.write(`  ${caso} (${casos[caso]!.producto}, ${values.version}) arriba en ${Math.round((Date.now() - t0) / 1000)} s · ${target.url}\n`);
    },
    async solved() {
      const o = await oracle();
      return o === 0 ? [{ key: caso, category: casos[caso]!.clase, difficulty: 0 }] : [];
    },
    stop() {
      // Al salir: bajar sólo los volúmenes del proyecto del runner. Bloqueante porque el proceso termina.
      if (!synced) return;
      try {
        const command = invocation("docker compose down -v --remove-orphans");
        execFileSync(command.file, command.args, { cwd: command.cwd, env: command.env, stdio: "ignore", timeout: 90_000 });
      } catch {}
    },
  };
  return target;
}

const target: Target = values.target === "fenix" ? fenixTarget() : values.target === "juice" ? juiceTarget : values.target === "cve" ? cveTarget() : (() => {
  throw new Error(`Objetivo desconocido: ${values.target} (juice | fenix | cve)`);
})();
process.on("exit", () => target.stop?.());

let currentCase: string | undefined;
function runExternal(command: string, cwd: string): Promise<{ exitCode: number | null; log: string }> {
  return new Promise((resolve) => {
    let log = "";
    const child = spawn("sh", ["-c", command], { cwd, env: { ...process.env, TASK: task, TARGET: target.url, CASO: currentCase ?? "", ROOT: join(import.meta.dirname, "..") }, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => {
      try {
        process.kill(-child.pid!, "SIGTERM");
      } catch {}
    }, 25 * 60_000);
    child.on("close", () => clearTimeout(timer));
    child.stdout.on("data", (chunk) => (log += chunk));
    child.stderr.on("data", (chunk) => (log += chunk));
    child.on("close", (exitCode) => resolve({ exitCode, log }));
  });
}

interface RunResult {
  label: string;
  run: number;
  startedAt: string;
  durationSec: number;
  target: string;
  /** Fallas reales (o desafíos) que el oráculo marca como explotadas; `total` sólo cuando el objetivo lo conoce. */
  solved: Solved[];
  total?: number;
  solvedByDifficulty: Record<string, number>;
  findings?: { candidatos: number; pistas: number; verificados: number; descartados: number; titulos: string[] };
  /** Sólo con verdad conocida: candidatos sobre fallas explotadas de verdad; falsos (señuelos o afirmaciones que el oráculo no vio); y sobre activos fuera de la lista. */
  precision?: {
    verdaderos: number;
    falsos: number;
    sinClasificar: number;
    /** Qué hizo el verificador independiente frente al oráculo. */
    verificador?: { verificadosCiertos: number; verificadosErrados: number; descartesAcertados: number; descartesErrados: number };
    detalle: Array<{ titulo: string; activo: string; estado?: string; clase: string }>;
  };
  requests?: number;
  tokens?: number;
  costUsd?: string;
  unknownRequests?: number;
  stalls?: number;
  errors?: string[];
  project?: string;
  external?: { exitCode: number | null; logChars: number };
  /** Peticiones HTTP reales contra el objetivo, medidas por el objetivo: para cotejar el tope de la consigna. */
  httpRequests?: number;
  timedOut?: boolean;
  /** Corrida que no mide al agente: el proveedor no respondió (ningún token) o el laboratorio quedó inválido. */
  invalid?: "proveedor" | "laboratorio";
  /** Con o sin grafo de hechos. */
  grafo?: boolean;
  /** Contexto que leyó el bucle principal en cada pedido (entrada + caché leída + caché escrita), en tokens. */
  contexto?: { pedidos: number; promedio: number; maximo: number; ultimo: number };
  /** Llamadas del agente a las herramientas del grafo. */
  usoGrafo?: Record<string, number>;
  /** Sólo cve: caso, versión desplegada y último código del oráculo (0 efecto, 1 sin efecto, 2 inválido). */
  caso?: string;
  version?: string;
  oracleExit?: number;
}

mkdirSync(values.out!, { recursive: true });
const results: RunResult[] = [];
const file = join(values.out!, `${values.label}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
for (const caso of target.casos ?? [undefined]) for (let run = 1; run <= Number(values.runs); run++) {
  if (caso) target.use!(caso);
  currentCase = caso;
  console.log(`\n=== ${values.label}${caso ? ` · ${caso} · ${values.version}` : ""} · corrida ${run}/${values.runs} ===`);
  try {
    await target.restart();
  } catch (error) {
    // Un laboratorio que no arranca no es un cero del agente: se anota y se sigue con el próximo caso.
    console.log(`  ✗ ${(error as Error).message}`);
    results.push({ label: values.label!, run, target: values.target!, caso, version: caso ? values.version : undefined, startedAt: new Date().toISOString(), durationSec: 0, solved: [], solvedByDifficulty: {}, oracleExit: target.oracleExit?.(), errors: [(error as Error).message] });
    writeFileSync(file, JSON.stringify({ task: values.task, target: values.target, model: values.model ?? "(config)", budget: values.presupuesto, results }, null, 1));
    break;
  }
  if (target.task) task = target.task();
  const started = Date.now();
  const result: RunResult = { label: values.label!, run, target: values.target!, caso, version: caso ? values.version : undefined, startedAt: new Date(started).toISOString(), durationSec: 0, solved: [], solvedByDifficulty: {} };
  const cwd = mkdtempSync(join(tmpdir(), `bench-${values.label}-`));
  result.project = cwd;
  if (values.external) {
    const external = await runExternal(values.external, cwd);
    writeFileSync(join(cwd, "external.log"), external.log);
    result.external = { exitCode: external.exitCode, logChars: external.log.length };
    // CyberStrike con --format json: cada step_finish trae tokens; el costo se calcula con la tarifa de nuestra configuración.
    const steps = external.log.split("\n").filter((line) => line.includes('"step_finish"')).flatMap((line) => {
      try {
        return [JSON.parse(line).part];
      } catch {
        return [];
      }
    });
    if (steps.length) {
      const tokens = steps.reduce((sum, step) => ({ input: sum.input + (step.tokens?.input ?? 0), output: sum.output + (step.tokens?.output ?? 0), cacheRead: sum.cacheRead + (step.tokens?.cache?.read ?? 0) }), { input: 0, output: 0, cacheRead: 0 });
      const cost = values.model ? resolveProvider(values.model).model.cost : undefined;
      result.requests = steps.length;
      result.tokens = tokens.input + tokens.output + tokens.cacheRead;
      result.costUsd = cost ? usd(BigInt(Math.max(0, tokens.input - tokens.cacheRead)) * BigInt(Math.round(cost.input * 1e6)) + BigInt(tokens.cacheRead) * BigInt(Math.round(cost.cacheRead * 1e6)) + BigInt(tokens.output) * BigInt(Math.round(cost.output * 1e6))) : undefined;
      const toolErrors = external.log.split("\n").filter((line) => line.includes('"tool"') && line.includes('"status":"error"')).length;
      result.errors = toolErrors ? [`${toolErrors} herramientas con error`] : [];
    }
  } else {
    const provider = resolveProvider(values.model);
    // Tope de peticiones aplicado por el harness (--peticiones N). Por defecto sin tope, como CyberStrike, y se mide lo que cada uno usa.
    // Un proveedor saturado (429) no debe convertir una corrida en un cero: se espera hasta 2+6+18+54+162+486 s antes de rendirse.
    const engine = new Engine({ cwd, provider, grafo: values.grafo !== "no", autoVerify: values.verificar !== "no", ...(values.fuerte ? { strong: resolveProvider(values.fuerte) } : {}), budgetPico: BigInt(Math.round(Number(values.presupuesto) * 1e12)), httpLimit: values.peticiones === "sin" ? undefined : Number(values.peticiones), retries: 6, retryBaseMs: 2000, maxSteps: values.pasos ? Number(values.pasos) : undefined, coverageObjections: values.objeciones ? Number(values.objeciones) : undefined, closingGate: values.cierre === "sin" ? false : undefined, disabled: values.target === "cve" && values.banco !== "si" ? ["cve_search", "cve_detail", "cwe_detail", "cve_recent", "cve-stack"] : undefined });
    engine.scope.edit({ include: [target.url] });
    // Como haría el operador: la cuenta de prueba queda configurada como identidad (sin que el modelo vea el token).
    if (values.target === "fenix") {
      const demo = (await (await fetch(`${target.url}/__demo`)).json()) as { token: string; user: string };
      engine.http.setIdentity({ name: "alicia", headers: { authorization: `Bearer ${demo.token}` } });
    }
    let stalls = 0;
    const errors: string[] = [];
    const usoGrafo: Record<string, number> = {};
    engine.agent.on((event) => {
      if (event.type === "stall") stalls++;
      if (event.type === "tool_end" && /^grafo/.test(event.name)) usoGrafo[event.name] = (usoGrafo[event.name] ?? 0) + 1;
      if (event.type === "message" && event.message.role === "assistant" && event.message.stopReason === "error") errors.push(event.message.errorMessage ?? "error");
      if (event.type === "tool_end") process.stdout.write(`  [${event.isError ? "✗" : "✓"}] ${event.name}\n`);
    });
    await engine.send(task);
    const totals = engine.ledger.totals(engine.sessionId);
    const findings = engine.findings.list();
    const count = (state: string) => findings.filter((f) => f.state === state).length;
    result.findings = { candidatos: count("candidato"), pistas: count("pista"), verificados: count("verificado"), descartados: count("descartado"), titulos: findings.map((f) => f.title) };
    if (target.classify) {
      await target.solved(); // refresca el oráculo antes de clasificar
      // Se clasifica lo que el agente afirmó (candidatos y verificados); lo que el verificador descartó se mide aparte.
      const detalle = findings.filter((f) => f.state !== "pista").map((f) => {
        const clase = target.classify!(f.asset);
        return { titulo: f.title, activo: f.asset, estado: f.state, clase: clase.kind === "verdadero" ? `verdadero:${clase.key}` : clase.kind === "no_demostrado" ? `no_demostrado:${clase.key}` : clase.kind === "derivado" ? `derivado:${clase.key}` : clase.kind === "señuelo" ? `señuelo:${clase.why}` : "sin_clasificar" };
      });
      const claimed = detalle.filter((d) => d.estado !== "descartado");
      const wrong = (d: { clase: string }) => d.clase.startsWith("señuelo") || d.clase.startsWith("no_demostrado") || d.clase === "sin_clasificar";
      result.precision = {
        verdaderos: claimed.filter((d) => d.clase.startsWith("verdadero")).length,
        falsos: claimed.filter((d) => d.clase.startsWith("señuelo") || d.clase.startsWith("no_demostrado")).length,
        sinClasificar: claimed.filter((d) => d.clase === "sin_clasificar").length,
        verificador: {
          verificadosCiertos: detalle.filter((d) => d.estado === "verificado" && d.clase.startsWith("verdadero")).length,
          verificadosErrados: detalle.filter((d) => d.estado === "verificado" && wrong(d)).length,
          descartesAcertados: detalle.filter((d) => d.estado === "descartado" && wrong(d)).length,
          descartesErrados: detalle.filter((d) => d.estado === "descartado" && d.clase.startsWith("verdadero")).length,
        },
        detalle,
      };
    }
    result.requests = totals.requests;
    result.tokens = totals.tokens.input + totals.tokens.cacheRead + totals.tokens.cacheWrite + totals.tokens.output;
    // Sin un solo token facturado y con errores del proveedor, el agente no llegó a trabajar: la corrida es inválida, no un cero.
    if (result.tokens === 0 && errors.length) result.invalid = "proveedor";
    result.costUsd = usd(totals.knownPico);
    result.unknownRequests = totals.unknownRequests;
    result.stalls = stalls;
    result.errors = errors;
    result.grafo = !!engine.grafo;
    result.usoGrafo = usoGrafo;
    const pedidos = engine.db.prepare("select coalesce(input,0)+coalesce(cache_read,0)+coalesce(cache_write,0) n from requests where session_id=? and worker='principal' and input is not null order by rowid").all(engine.sessionId) as Array<{ n: number }>;
    if (pedidos.length) result.contexto = { pedidos: pedidos.length, promedio: Math.round(pedidos.reduce((a, b) => a + Number(b.n), 0) / pedidos.length), maximo: Math.max(...pedidos.map((p) => Number(p.n))), ultimo: Number(pedidos.at(-1)!.n) };
    await engine.close();
  }
  result.durationSec = Math.round((Date.now() - started) / 1000);
  const solved = await target.solved();
  result.solved = solved;
  if (target.total) result.total = target.total;
  if (target.oracleExit) {
    result.oracleExit = target.oracleExit();
    if (result.oracleExit === 2) result.invalid = "laboratorio";
  }
  if (target.httpRequests) result.httpRequests = await target.httpRequests();
  for (const item of solved) result.solvedByDifficulty[item.difficulty] = (result.solvedByDifficulty[item.difficulty] ?? 0) + 1;
  results.push(result);
  // Se guarda tras cada corrida: si la siguiente falla, no se pierden las anteriores.
  writeFileSync(file, JSON.stringify({ task: values.task, target: values.target, model: values.model ?? "(config)", budget: values.presupuesto, results }, null, 1));
  const v = result.precision?.verificador;
  const precision = result.precision ? ` · verdaderos ${result.precision.verdaderos} · falsos ${result.precision.falsos} · sin clasificar ${result.precision.sinClasificar}${v ? ` · verificador ✓${v.verificadosCiertos} ✗${v.verificadosErrados} · descartes ✓${v.descartesAcertados} ✗${v.descartesErrados}` : ""}` : "";
  if (result.contexto) console.log(`  contexto por paso: promedio ${result.contexto.promedio} · máximo ${result.contexto.maximo} · último ${result.contexto.ultimo} tokens (${result.contexto.pedidos} pedidos)${result.usoGrafo && Object.keys(result.usoGrafo).length ? ` · grafo ${JSON.stringify(result.usoGrafo)}` : ""}`);
  console.log(`  ${result.invalid ? `INVÁLIDA (${result.invalid}) · ` : ""}resueltos ${solved.length}${target.total ? `/${target.total}` : ""}${result.oracleExit !== undefined ? ` · oráculo ${result.oracleExit}` : ""}${result.httpRequests !== undefined ? ` · HTTP ${result.httpRequests}` : ""}${precision} · candidatos ${result.findings?.candidatos ?? "?"} · verificados ${result.findings?.verificados ?? "?"} · solicitudes ${result.requests ?? "?"} · USD ${result.costUsd ?? "?"} · ${result.durationSec} s · sin avance ${result.stalls ?? "?"}`);
}
console.log(`\nResultados en ${file}`);
