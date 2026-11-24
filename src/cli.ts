#!/usr/bin/env node
// Elevate AI Cyber — punto de entrada. Todo pasa por el daemon del proyecto.
import { accessSync, constants, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { connectDaemon, inContainer } from "./client.ts";
import { compartido, despedirVentana } from "./compartido.ts";
import { Daemon } from "./daemon.ts";
import { hostPath, ProjectLocked, runtimeDir } from "./datos.ts";
import { t } from "./idioma.ts";
import { accent, bold, link, linkify } from "./tui/text.ts";
import { prendido } from "./tui/streamer.ts";
import { cliHelp, PLATFORM_NAMES } from "./manual.ts";
import { accountMenu, askHiddenInTerminal, mailMenu, pickInTerminal, platformMenu, prompt } from "./menu.ts";

const HELP = cliHelp();
// Los lanzadores se instalan desde un release firmado (README: «Instalar»), nunca desde main.
const LANZADOR_URL = "https://github.com/Leandrozz/orobas-sec/releases/latest";

/** La versión instalada: el archivo VERSION que pone el release (scripts/release/armar.sh); sin él, la del paquete. */
function version(): string {
  const raiz = join(dirname(fileURLToPath(import.meta.url)), "..");
  try {
    return readFileSync(join(raiz, "VERSION"), "utf8").trim();
  } catch {
    const { version: v } = JSON.parse(readFileSync(join(raiz, "package.json"), "utf8")) as { version: string };
    return `${v} (${t("desarrollo", "development")})`;
  }
}

/**
 * Las opciones del lanzador (--actualizar, --instalar, --cerrar-docker) nunca llegan acá con el
 * lanzador de verdad: si llegan, el «cyber» del usuario llama a la imagen directo (una función o
 * alias con el «docker run» de la guía vieja). Se explica eso en vez de un error de parseArgs.
 * Va en los dos idiomas: sin el lanzador no llega LANG al contenedor.
 */
function opcionDelLanzador(argv: string[]): string | null {
  const opcion = argv.find((a) => a === "--actualizar" || a === "--instalar" || a === "--cerrar-docker");
  if (!opcion) return null;
  return [
    `«cyber ${opcion}» es del lanzador, pero llegó directo al agente: el «cyber» que corriste llama a la imagen sin pasar por el lanzador`,
    "(seguramente una función o un alias con «docker run» de la guía vieja). Fijate qué es con «Get-Command cyber -All» (PowerShell)",
    "o «type cyber» (Linux y macOS), sacalo de tu perfil e instalá el lanzador:",
    "",
    `"cyber ${opcion}" belongs to the launcher, but it reached the agent directly: your "cyber" runs the image without the launcher`,
    '(probably a function or alias with "docker run" from the old guide). Check it with "Get-Command cyber -All" (PowerShell)',
    'or "type cyber" (Linux and macOS), remove it from your profile and install the launcher:',
    "",
    `  ${LANZADOR_URL}`,
  ].join("\n");
}

/** parseArgs con los errores de uso como una línea clara (con el código, que el lanzador reconoce) en vez de un stack. */
function leerArgs() {
  const delLanzador = opcionDelLanzador(process.argv.slice(2));
  if (delLanzador) {
    console.error(delLanzador);
    process.exit(2);
  }
  try {
    return parseArgs({
      allowPositionals: true,
      options: OPCIONES,
    });
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "";
    if (!code.startsWith("ERR_PARSE_ARGS")) throw e;
    const desconocida = /^Unknown option '([^']+)'/.exec((e as Error).message)?.[1];
    const yo = inContainer() ? "cyber" : "orobas-sec";
    console.error(`${desconocida ? t(`Opción desconocida: ${desconocida}`, `Unknown option: ${desconocida}`) : (e as Error).message} [${code}]`);
    console.error(t(`Mirá «${yo} --help».`, `See "${yo} --help".`));
    process.exit(2);
  }
}

const OPCIONES = {
  continue: { type: "boolean", short: "c" },
  session: { type: "string", short: "s" },
  print: { type: "string", short: "p" },
  streamer: { type: "boolean" },
  "no-streamer": { type: "boolean" },
  obs: { type: "string" },
  detach: { type: "boolean" },
  continuar: { type: "boolean" },
  model: { type: "string", short: "m" },
  presupuesto: { type: "string", short: "b" },
  peticiones: { type: "string", short: "r" },
  ritmo: { type: "string" },
  agente: { type: "string" },
  cabecera: { type: "string", multiple: true },
  dir: { type: "string", short: "C" },
  resumen: { type: "boolean" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean" },
  chequeo: { type: "boolean" },
} as const;
// «cyber ci»: la corrida para integración continua tiene sus propias opciones y no pasa por el daemon (src/ci/).
if (process.argv[2] === "ci") {
  const { correrCi } = await import("./ci/cli.ts");
  process.exit(await correrCi(process.argv.slice(3)).catch((error: Error) => {
    console.error(`Error interno de cyber ci: ${error.message}`);
    return 3;
  }));
}
const { values, positionals } = leerArgs();

let pantallaProtegida = values.obs !== undefined || (!values["no-streamer"] && (!!values.streamer || prendido(process.env.CYBER_STREAMER)));

const VIEWS: Record<string, string> = { costos: "costos", uso: "uso", memoria: "memoria", evidencia: "evidencia", jobs: "jobs", sesiones: "sesiones", scope: "scope", findings: "findings", cobertura: "cobertura", grafo: "grafo", informe: "informe", trayectorias: "trayectorias", cves: "cves" };


/** Opción oculta del lanzador: las tres carpetas montadas existen como montaje y se pueden escribir. */
function chequeoMontajes(): void {
  const montajes = readFileSync("/proc/self/mountinfo", "utf8").split("\n").map((l) => l.split(" ")[4]);
  const falta = ["/proyecto", process.env.CYBER_DATA_DIR ?? "/home/node/.local/share/elevate-cyber", "/home/node/.config/elevate-cyber"].filter((d) => {
    try {
      accessSync(d, constants.W_OK);
      return !montajes.includes(d);
    } catch {
      return true;
    }
  });
  console.log("compartido"); // marca de protocolo: el lanzador nuevo la exige para saber que la imagen entiende el modo compartido
  if (falta.length) console.error(`Falta montar o no se puede escribir: ${falta.join(", ")}`);
  process.exitCode = falta.length ? 1 : 0;
}

/**
 * Dentro del contenedor, los datos (sesiones, hallazgos, evidencia) viven en carpetas que el
 * lanzador monta desde la máquina del usuario. Arrancado a la vieja usanza («docker run -v
 * "$PWD:/proyecto" …», sin esos montajes), los datos quedarían adentro del contenedor y se
 * perderían al salir; peor, la mudanza se llevaría ahí la .cyber del proyecto. No se arranca.
 */
function sinMontajes(command?: string): void {
  if (!existsSync("/.dockerenv") || process.env.CYBER_SIN_MONTAJES === "1" || command === "toolbox") return;
  let montajes: string[];
  try { montajes = readFileSync("/proc/self/mountinfo", "utf8").split("\n").map((l) => l.split(" ")[4] ?? ""); } catch { return; }
  const datos = process.env.CYBER_DATA_DIR ?? "/home/node/.local/share/elevate-cyber";
  const falta = [datos, "/home/node/.config/elevate-cyber"].filter((d) => !montajes.includes(d));
  if (!falta.length) return;
  if (pantallaProtegida) { console.error("La TUI necesita los montajes de datos y credenciales del lanzador."); process.exit(2); }
  console.error([
    "Esta versión guarda las sesiones fuera de la carpeta del proyecto, y este contenedor arrancó sin esas carpetas montadas:",
    ...falta.map((d) => `  falta ${d}`),
    "Así los datos se perderían al cerrar. No arranco.",
    "",
    "Usá el lanzador nuevo (un solo comando, «cyber»): está en distro/lanzador/ del repositorio y en la guía.",
    "O agregá al docker run:",
    '  -v "$HOME/.local/share/elevate-cyber:/home/node/.local/share/elevate-cyber" -v "$HOME/.config/elevate-cyber:/home/node/.config/elevate-cyber"',
    "Tus sesiones anteriores (la carpeta .cyber del proyecto) siguen intactas: se mudan solas la primera vez que arranque bien.",
  ].join("\n"));
  process.exit(2);
}

async function main(): Promise<void> {
  // En una terminal, los títulos de sección en el color de acento; redirigida, texto plano.
  if (values.help) return console.log(process.stdout.isTTY && !process.env.NO_COLOR ? HELP.replace(/^[A-ZÁÉÍÓÚÑ ]{4,}$/gm, (title) => bold(accent(title))) : HELP);
  if (values.version) return console.log(`orobas-sec ${version()}`);
  if (values.chequeo) return chequeoMontajes();
  if (positionals[0] === "despedir-ventana") {
    await despedirVentana(positionals[1] ?? "");
    return;
  }
  if (pantallaProtegida && (positionals.length || values.print !== undefined || values.continuar || values.resumen)) {
    if (values.streamer || values.obs !== undefined || values.resumen) {
      console.error("El modo streamer requiere la TUI interactiva. Abrí cyber --streamer o retomá con -c.");
      process.exitCode = 1;
      return;
    }
    pantallaProtegida = false; // La variable configura la TUI; el daemon también hereda el entorno.
  }
  sinMontajes(positionals[0]);
  const cwd = resolve(values.dir ?? process.cwd());
  if (!existsSync(cwd)) throw new Error(`No existe la carpeta ${cwd}`);
  let [command, ...rest] = positionals;
  // Sin ningún socket abierto el daemon (pid 1) se apagaría a los 30 s y se llevaría al exec (--resumen, login…): una conexión que no retiene al proceso lo mantiene.
  if (compartido() && command !== "daemon") (await connectDaemon(cwd)).sinRetener();
  let session = values.session;
  if (values.resumen) {
    session = await (await import("./resumen.ts")).chooseSession(cwd);
    if (!session) return;
  }

  if (command === "daemon") {
    if (rest[0] === "stop") {
      const client = await connectDaemon(cwd, { spawn: false });
      console.log((await client.ask("shutdown", { force: true })).join("\n"));
      return client.leave();
    }
    let daemon: Daemon;
    try {
      daemon = new Daemon({ cwd, idleMs: compartido() ? 30_000 : 10 * 60_000, onClose: () => process.exit(0) });
    } catch (error) {
      // El cliente lo muestra en vez de «Ver daemon.log». Con el candado tomado fuera de Docker hay otro daemon arrancando y el cliente se conecta a ese;
      // en Docker el cliente ya probó conectarse, así que solo queda un candado ajeno o uno vivo de un contenedor que se cerró hace poco.
      const locked = error instanceof ProjectLocked;
      if (!locked || inContainer()) {
        try {
          const message = locked ? t("Este proyecto está abierto en otra terminal, o se cerró hace menos de 30 s: esperá unos segundos y volvé a intentar.", "This project is open in another terminal, or was closed less than 30 s ago: wait a few seconds and try again.") : (error as Error).message;
          writeFileSync(join(runtimeDir(cwd), "arranque.err"), message, { mode: 0o600 });
        } catch {}
      }
      // En modo compartido el contenedor muere con este proceso: se espera a que la ventana que aguarda lea arranque.err.
      if (compartido()) await new Promise((fin) => setTimeout(fin, Number(process.env.CYBER_ARRANQUE_ESPERA_MS ?? 10_000)));
      throw error;
    }
    await daemon.listen();
    console.log(`[${new Date().toISOString()}] daemon de Cyber en ${daemon.path} (pid ${process.pid})`);
    for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => daemon.close());
    return;
  }
  if (command === "login" || command === "logout") {
    if (rest[0] === "cyber-bounty") {
      const bounty = await import("./cyber-bounty.ts");
      if (command === "logout") {
        bounty.clearBountyKey();
        return console.log("Clave de Cyber Bounty borrada. Si viene del entorno, quitá CYBER_BOUNTY_KEY también.");
      }
      console.log("Creá una clave de agente bb_ en https://cyber.elevateai.ar/bounty/agentes. No uses la clave oro_. Queda en tu almacén de credenciales, fuera del proyecto.");
      const key = await prompt("Clave de agente (no se muestra): ", true);
      const programs = await new bounty.CyberBounty(key).programs();
      const saved = bounty.saveBountyKey(key);
      return console.log(`Clave validada y guardada${saved.encrypted ? " cifrada" : " sin cifrar (no hay llave; archivo sólo legible por tu usuario)"}. ${programs.length} programas accesibles.`);
    }
    if (rest[0] !== "hackerone") {
      const { platforms, terminalLogin } = await import("./plataformas.ts");
      const names = ["hackerone", ...platforms().map((item) => item.name)];
      if (!rest[0] || !names.includes(rest[0])) throw new Error(`Uso: orobas-sec ${command} <${names.join("|")}>`);
      if (command === "logout") return console.log(`La sesión de ${rest[0]} es la de su propia CLI: cerrala con ella (por ejemplo gh auth logout, vercel logout, supabase logout, az logout).`);
      process.exitCode = terminalLogin(rest[0]);
      return;
    }
    const h1 = await import("./hackerone.ts");
    if (command === "logout") {
      h1.clearCredentials();
      return console.log(t("Credenciales de HackerOne borradas.", "HackerOne credentials deleted."));
    }
    console.log(t(`HackerOne no ofrece OAuth para su API: usa un token personal.\nGeneralo en ${link("https://hackerone.com/settings/api_token/edit")} y pegalo acá. Queda cifrado en tu carpeta de credenciales, no en el proyecto.`, `HackerOne has no OAuth for its API: it uses a personal token.\nCreate it at ${link("https://hackerone.com/settings/api_token/edit")} and paste it here. It is stored encrypted in your credentials folder, not in the project.`));
    const username = await prompt("Usuario de HackerOne: ");
    const token = await prompt("Token de API (no se muestra): ", true);
    if (!username || !token) throw new Error("Faltan usuario o token.");
    const programs = await new h1.HackerOne({ username, token }).programs();
    const where = h1.saveCredentials({ username, token });
    return console.log(`Listo: credenciales válidas, guardadas en ${where}. ${programs.length} programas accesibles. Verlos: cyber h1`);
  }
  if (command === "extension" || command === "extensión") {
    const { extensionGuide } = await import("./chrome.ts");
    const { fileURLToPath } = await import("node:url");
    return console.log(extensionGuide(fileURLToPath(new URL("../extension", import.meta.url))).join("\n"));
  }
  if (command === "toolbox") {
    const { toolboxStatus } = await import("./toolbox.ts");
    const { vulndbStatus } = await import("./vulndb.ts");
    const { harnessStatus } = await import("./orquesta.ts");
    const { browserStatus } = await import("./browser.ts");
    const { modelLine } = await import("./providers.ts");
    const model = modelLine(values.model);
    const { platformStatusLines } = await import("./plataformas.ts");
    return console.log(["CAJA DE HERRAMIENTAS", ...toolboxStatus(), "", "BANCO DE CVE/CWE (habilidad cve-stack)", vulndbStatus(), "", "OTROS HARNESSES (orquestación: /ultra)", ...harnessStatus(), "", "NAVEGADOR", ...browserStatus(), "", "PLATAFORMAS (vincular: cyber <plataforma>, o pedíselo al agente)", ...(await platformStatusLines()), "", "MODELO", model, `node ${process.version}`].join("\n"));
  }
  if (command === "tope") {
    const client = await connectDaemon(cwd);
    console.log((await client.ask("tope", { value: rest[0] })).join("\n"));
    return client.leave();
  }
  if (command === "datos" || command === "trazas") {
    // cyber datos [compartir | local | no | subir | revocar]: el modo de trazas y las sesiones anteriores.
    const client = await connectDaemon(cwd);
    const word = (rest[0] ?? "").toLowerCase();
    const payload = /^(compartir|local|no)$/.test(word) ? { action: "modo", value: word } : word === "subir" ? { action: "share" } : word === "revocar" ? { action: "revoke" } : { action: "status" };
    console.log((await client.ask("datos", payload)).join("\n"));
    return client.leave();
  }
  if (command === "perfil" || command === "deteccion" || command === "consent" || command === "navegador") {
    const client = await connectDaemon(cwd);
    const op = command === "perfil" ? "perfil" : command === "deteccion" ? "deteccion" : command === "navegador" ? "navegador" : "consent";
    const payload = command === "perfil" || command === "navegador" ? { value: rest[0] } : command === "consent" ? { value: rest.join(" ") } : {};
    console.log((await client.ask(op, payload)).join("\n"));
    return client.leave();
  }
  // Salida de los menús de cuentas: un bloque con sangría, como el resto de la pantalla.
  const block = (lines: string[]) => lines.length && console.log(lines.map((line) => `  ${linkify(line)}`).join("\n"));
  if (command === "orobas" || command === "hackerone") {
    const client = await connectDaemon(cwd);
    const status = async () => (await client.ask("account", { service: command, action: "status" }))[0] ?? "";
    const before = await status();
    block(await accountMenu(command, { ask: (op, payload) => client.ask(op, payload), pick: pickInTerminal, askHidden: askHiddenInTerminal, notice: block }));
    const after = await status();
    // Recién vinculado orobas en una terminal interactiva: se entra directo a la TUI en vez de volver al shell.
    const enter = command === "orobas" && process.stdin.isTTY && after !== before && !/sin vincular|not linked|cifrada|encrypted/.test(after);
    await client.leave();
    if (!enter) return;
    command = undefined;
    rest = [];
  }
  if (command === "correo" || command === "mail") {
    const client = await connectDaemon(cwd);
    block(await mailMenu({ ask: (op, payload) => client.ask(op, payload), pick: pickInTerminal, askHidden: askHiddenInTerminal }));
    return client.leave();
  }
  if (command && PLATFORM_NAMES.includes(command)) {
    const client = await connectDaemon(cwd);
    client.on((event) => event.type === "notice" && block([event.text]));
    block(await platformMenu(command, command, { ask: (op, payload) => client.ask(op, payload), pick: pickInTerminal }));
    return client.leave();
  }
  if (command === "h1") {
    const client = await connectDaemon(cwd);
    console.log((await client.ask("h1", { action: rest[0] ?? "programas", handle: rest[1], ...(session && { session }) })).join("\n"));
    return client.leave();
  }
  if (command && !VIEWS[command]) throw new Error(`Comando desconocido: ${command}\n\n${HELP}`);

  if (values.detach && inContainer()) throw new Error(t("--detach no sirve con Docker: el turno terminaría al cerrarse el contenedor. Usá -p sin --detach.", "--detach does not work with Docker: the turn would end when the container closes. Use -p without --detach."));
  const client = await connectDaemon(cwd);
  if (command) {
    console.log((await client.view(VIEWS[command]!, rest.join(" "), session)).join("\n"));
    return client.leave();
  }

  const snapshot = await client.attach({
    session: session ?? (values.continue || values.continuar ? "last" : "new"),
    model: values.model,
    budget: values.presupuesto,
    requests: values.peticiones,
    rate: values.ritmo,
    agent: values.agente,
    cabeceras: values.cabecera,
  });

  if (values.continuar && !snapshot.status.interrupted) {
    await client.leave();
    throw new Error("Esa sesión no tiene un turno interrumpido.");
  }
  if (values.print !== undefined || values.continuar) {
    for (const aviso of snapshot.avisos ?? []) process.stderr.write(`[aviso] ${aviso}\n`);
    if (values.continuar) client.resume();
    else client.send(values.print!);
    if (values.detach) {
      // Dar tiempo a que el mensaje salga antes de cortar la conexión.
      await client.view("jobs");
      console.log(`Trabajando en segundo plano. Sesión ${snapshot.sessionId.slice(0, 8)} · verla: cyber -s ${snapshot.sessionId.slice(0, 8)} · estado: cyber jobs`);
      return client.leave();
    }
    client.on((event) => {
      if (event.type === "text") { if (!event.worker) process.stdout.write(event.delta); }
      else if (event.type === "tool_end") process.stderr.write(`[${event.worker ? `${event.worker} ` : ""}${event.isError ? "falló" : "listo"}] ${event.name} ${JSON.stringify(event.isError ? event.text : event.details)}\n`);
      else if (event.type === "retry") process.stderr.write(`[reintento ${event.attempt}] ${event.reason}\n`);
      else if (event.type === "notice") process.stderr.write(`[aviso] ${linkify(event.text)}\n`);
      else if (event.type === "answer") process.stdout.write(`${event.text}\n`);
      else if (event.type === "message" && event.message.role === "assistant" && event.message.stopReason === "error") {
        process.stderr.write(`[error] ${event.message.errorMessage?.replace("/orobas", "cyber orobas")}\n`); // sin TUI no hay barra: se usa el comando
        process.exitCode = 1;
      }
    });
    await client.idle();
    process.stdout.write("\n");
    process.stderr.write(`${client.status.usage}\n${client.status.cost}\n`);
    return client.leave();
  }

  if (!process.stdin.isTTY) {
    await client.leave();
    throw new Error('La TUI necesita una terminal interactiva. Usá -p "texto" para un turno sin TUI.');
  }
  const { startFoco } = await import("./tui/foco.ts");
  const { restaurarSiDentro, restaurarTerminal } = await import("./tui/pantalla.ts");
  // Pase lo que pase (Ctrl+C, un error), la terminal no se queda en pantalla alternativa ni sin cursor.
  process.on("exit", () => restaurarSiDentro(process.stdout));
  process.on("uncaughtException", (error) => { restaurarTerminal(process.stdout); if (pantallaProtegida) { console.error("Se cerró la TUI en modo streamer."); process.exit(1); } throw error; });
  const explicit = ([["model", values.model], ["budget", values.presupuesto], ["requests", values.peticiones], ["rate", values.ritmo], ["agent", values.agente]] as const).flatMap(([op, flag]) => (flag === undefined ? [] : [op]));
  startFoco(client, snapshot, {
    cwd,
    project: hostPath(cwd),
    explicit,
    streamer: pantallaProtegida, obs: values.obs, alCambiarStreamer: (activo) => { pantallaProtegida = activo; },
    onExit: async (protegida) => {
      // En Docker sin modo compartido el daemon se apaga con el contenedor: el turno en curso se detiene, no sigue.
      const background = client.status.running ? (inContainer() && !compartido() ? `\n${t("Se detuvo el turno en curso.", "The running turn was stopped.")}` : "\nEl turno sigue en segundo plano.") : "";
      console.log(`\n${protegida ? "" : client.status.cost}${background}\nPara retomar esta sesión: cyber -c`);
      await client.leave();
      process.exit(0);
    },
  });
}

main().catch((error: Error) => {
  console.error(pantallaProtegida ? "No se pudo abrir la TUI en modo streamer. Revisá las opciones y la terminal." : error.message);
  process.exit(1);
});
