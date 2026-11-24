// Instalación de las herramientas de la caja. Cada entrada es un plan fijo, escrito acá, no un
// comando que arme el modelo ni texto del objetivo: el usuario ve cada plan en el inicio y decide
// cuál descargar. Los instaladores corren sólo por /toolbox_install, con el entorno mínimo.
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { zipExtract } from "./apk.ts";
import { exec, which, type ExecResult } from "./exec.ts";

export interface InstallPlan {
  binary: string;
  display: string;
  argv: string[];
  env?: Record<string, string>;
  /** Cómo verificarlo una vez terminado; si no existe, vale que esté en el PATH. */
  verify?: string[];
  /** Antes de argv: baja un archivo fijo y lo compara con su tamaño y su sha256; si no coinciden, no se guarda ni se abre nada. */
  download?: Download & { file: string };
  /** En vez de argv: abre un zip ya verificado en una carpeta, sin herramientas externas. */
  unzip?: { file: string; into: string };
  /** En vez de argv: escribe un envoltorio ejecutable (sh) que corre la herramienta con el Java de la caja. */
  wrapper?: { path: string; command: string[] };
}

/** Un archivo publicado por su autor, con versión, tamaño y sha256 fijos. */
export interface Download {
  url: string;
  sha256: string;
  bytes: number;
}

/**
 * Herramientas para apps móviles (apk_analyze), sólo para la caja. Versión fija y sha256 publicado por
 * el autor (el «digest» del release de GitHub; el del JRE coincide además con la API de Adoptium): para
 * subir de versión se cambia acá, con el sha256 publicado, nunca con uno calculado sobre lo que se bajó.
 * Las mismas versiones van en distro/Dockerfile.
 */
export const MOVIL = {
  jadx: { version: "1.5.6", url: "https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip", sha256: "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974", bytes: 72_646_741 },
  apktool: { version: "3.0.3", url: "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar", sha256: "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423", bytes: 15_478_013 },
  /** Java para correrlas si la caja no trae (las imágenes viejas no traen): Temurin JRE 21, carpeta jdk-21.0.13+9-jre. */
  jre: {
    version: "21.0.13+9",
    carpeta: "jdk-21.0.13+9-jre",
    x64: { url: "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz", sha256: "a535a1df9c6284d9618872984e026ae0352d1f7e9e0605425c0e6114f47351dd", bytes: 52_181_297 },
    arm64: { url: "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jre_aarch64_linux_hotspot_21.0.13_9.tar.gz", sha256: "b1734db7ade49c3f6acc6ae06233b8c2dd90e3e2f00f67000ae1c972aaa64d8c", bytes: 51_266_660 },
  },
} as const;

/** Las que nunca se instalan en el host: sólo dentro de la caja (el contenedor del proyecto). */
export const SOLO_CAJA = new Set(["jadx", "apktool"]);

/** ¿Corre dentro de la caja? La marca de Docker y la carpeta del proyecto que pasa el lanzador, las dos (igual que chrome.ts). */
export const enCaja = (dockerenv = "/.dockerenv") => !!process.env.CYBER_PROYECTO_HOST && existsSync(dockerenv);

/** Opciones de instalación; las pruebas cambian la casa, la descarga y lo fijado. */
export interface InstallOptions {
  enCaja?: boolean;
  home?: string;
  fetcher?: (url: string) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;
  /** Descargas fijas a usar en vez de MOVIL (sólo pruebas: el sha256 real no se puede imitar). */
  fijas?: { jadx?: Download; apktool?: Download; jre?: Download };
  arch?: string;
}

const short = (sha: string) => `${sha.slice(0, 12)}…`;
const quote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;

/** Pasos fijos para jadx o apktool: Java si falta, la herramienta y su envoltorio en ~/.local/bin. */
export function planesMovil(name: "jadx" | "apktool", options: InstallOptions = {}): InstallPlan[] {
  const home = options.home ?? process.env.HOME ?? homedir();
  const base = join(home, ".local", "share", "cyber-movil");
  const arch = options.arch ?? process.arch;
  const plans: InstallPlan[] = [];
  let java = which("java");
  if (!java || options.fijas?.jre) {
    const jre = options.fijas?.jre ?? (arch === "x64" ? MOVIL.jre.x64 : arch === "arm64" ? MOVIL.jre.arm64 : undefined);
    if (!jre) throw new Error(`No hay Java fijado para la arquitectura ${arch}: reconstruí la caja (distro/Dockerfile trae Java).`);
    const file = join(base, "jre.tar.gz");
    plans.push({ display: `Java ${MOVIL.jre.version} (Temurin JRE, sha256 ${short(jre.sha256)}) en ~/.local/share/cyber-movil`, download: { ...jre, file }, binary: "tar", argv: ["-xzf", file, "-C", base, "--no-same-owner"] });
    java = join(base, MOVIL.jre.carpeta, "bin", "java");
  }
  const bin = join(home, ".local", "bin", name);
  if (name === "jadx") {
    const tool = options.fijas?.jadx ?? MOVIL.jadx;
    const file = join(base, `jadx-${MOVIL.jadx.version}.zip`);
    const into = join(base, `jadx-${MOVIL.jadx.version}`);
    plans.push({ display: `jadx ${MOVIL.jadx.version} (sha256 ${short(tool.sha256)}) en ~/.local/share/cyber-movil`, download: { ...tool, file }, unzip: { file, into }, binary: "", argv: [] });
    // Los argumentos de la JVM son los del script oficial de jadx (applicationDefaultJvmArgs de jadx-cli).
    plans.push({ display: "envoltorio ~/.local/bin/jadx", binary: "", argv: [], wrapper: { path: bin, command: [java, "-XX:+IgnoreUnrecognizedVMOptions", "-Xms256M", "-XX:MaxRAMPercentage=70.0", "-XX:ParallelGCThreads=3", "-Djdk.util.zip.disableZip64ExtraFieldValidation=true", "-cp", join(into, "lib", "*"), "jadx.cli.JadxCLI"] }, verify: ["--version"] });
  } else {
    const tool = options.fijas?.apktool ?? MOVIL.apktool;
    const file = join(base, `apktool_${MOVIL.apktool.version}.jar`);
    plans.push({ display: `apktool ${MOVIL.apktool.version} (sha256 ${short(tool.sha256)}) en ~/.local/share/cyber-movil`, download: { ...tool, file }, binary: "", argv: [] });
    plans.push({ display: "envoltorio ~/.local/bin/apktool", binary: "", argv: [], wrapper: { path: bin, command: [java, "-jar", file] }, verify: ["--version"] });
  }
  return plans;
}

/** Baja, compara tamaño y sha256 con lo fijado y recién entonces guarda. */
async function bajar(download: Download & { file: string }, fetcher: NonNullable<InstallOptions["fetcher"]>): Promise<void> {
  const response = await fetcher(download.url);
  if (!response.ok) throw new Error(`${download.url} respondió ${response.status}`);
  const data = Buffer.from(await response.arrayBuffer());
  const sum = createHash("sha256").update(data).digest("hex");
  if (data.length !== download.bytes || sum !== download.sha256) {
    throw new Error(`${download.url}: no coincide con lo fijado (${data.length} bytes, sha256 ${short(sum)}; se esperaba ${download.bytes} bytes y ${short(download.sha256)}). No se guardó ni se abrió nada.`);
  }
  mkdirSync(dirname(download.file), { recursive: true });
  writeFileSync(download.file, data);
}

const defaultFetcher: NonNullable<InstallOptions["fetcher"]> = (url) => fetch(url, { redirect: "follow", signal: AbortSignal.timeout(900_000) });

/** jadx o apktool dentro de la caja: cada paso es fijo y se corta en el primero que falla. */
async function instalarMovil(name: "jadx" | "apktool", runner: Runner, options: InstallOptions): Promise<string> {
  const plans = planesMovil(name, options);
  const fetcher = options.fetcher ?? defaultFetcher;
  const outputs: string[] = [];
  let wrapper: string | undefined;
  for (const plan of plans) {
    try {
      if (plan.download) await bajar(plan.download, fetcher);
      if (plan.unzip) {
        rmSync(plan.unzip.into, { recursive: true, force: true });
        zipExtract(readFileSync(plan.unzip.file), plan.unzip.into);
      }
      if (plan.wrapper) {
        mkdirSync(dirname(plan.wrapper.path), { recursive: true });
        const [program, ...args] = plan.wrapper.command;
        // Las rutas van entre comillas simples; «lib/*» queda literal para que lo expanda Java, no el shell.
        writeFileSync(plan.wrapper.path, `#!/bin/sh\n# Instalado por Orobas (/toolbox_install ${name}) dentro de la caja: versión fija con sha256 verificado.\nexec ${[program!, ...args].map(quote).join(" ")} "$@"\n`);
        chmodSync(plan.wrapper.path, 0o755);
        wrapper = plan.wrapper.path;
      }
      if (plan.binary) {
        const result = await runner([plan.binary, ...plan.argv], { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin", LANG: "C.UTF-8", TERM: "dumb" });
        if (result.exitCode !== 0) throw new Error(`salió con ${result.exitCode ?? "?"}: ${(result.stderr ?? "").trim().slice(-500)}`);
      }
      // El archivo bajado se borra si era un paquete que ya se abrió (zip o tar); el .jar de apktool se queda.
      if (plan.download && (plan.unzip || plan.binary)) rmSync(plan.download.file, { force: true });
      outputs.push(`${plan.display}: listo`);
      if (plan.wrapper && plan.verify) {
        const check = await runner([plan.wrapper.path, ...plan.verify], { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin", LANG: "C.UTF-8", TERM: "dumb" }).catch((error: Error) => ({ exitCode: null, stdout: "", stderr: error.message, durationMs: 0 }));
        if (check.exitCode !== 0) throw new Error(`no arranca: ${(check.stderr || check.stdout).trim().slice(-300)}`);
        outputs.push(`${name} ${check.stdout.trim().split("\n")[0]?.slice(0, 60) ?? ""}`.trim());
      }
    } catch (error) {
      outputs.push(`${plan.display}: falló (${(error as Error).message}). No se ejecutó nada más.`);
      return outputs.join("\n");
    }
  }
  outputs.push(`${name}: instalado en ${wrapper}. Vive en esta caja hasta que se recree el contenedor; para que quede fija, reconstruí la imagen (distro/Dockerfile ya la trae).`);
  return outputs.join("\n");
}

/** Paquete del sistema: brew en macOS, pacman en el resto. */
const pkg = (name: string): InstallPlan =>
  process.platform === "darwin"
    ? { display: `brew install ${name}`, binary: "brew", argv: ["install", name] }
    : { display: `sudo pacman -S ${name}`, binary: "pacman", argv: ["-S", "--noconfirm", name] };

/** Sólo los comandos necesarios. Los paquetes con `sudo` piden el permiso del operador aparte. */
export const INSTALLERS: Record<string, InstallPlan[]> = {
  get nmap() {
    return [pkg("nmap")];
  },
  get sqlmap() {
    return [pkg("sqlmap")];
  },
  get gitleaks() {
    return [pkg("gitleaks")];
  },
  ffuf: [
    { display: "go install github.com/ffuf/ffuf/v2@latest", binary: "go", argv: ["install", "github.com/ffuf/ffuf/v2@latest"] },
  ],
  httpx: [
    { display: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", binary: "go", argv: ["install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"] },
  ],
  nuclei: [
    { display: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", binary: "go", argv: ["install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"] },
  ],
  subfinder: [
    { display: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", binary: "go", argv: ["install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"] },
  ],
  katana: [
    { display: "go install github.com/projectdiscovery/katana/cmd/katana@latest", binary: "go", argv: ["install", "github.com/projectdiscovery/katana/cmd/katana@latest"] },
  ],
  dnsx: [
    { display: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", binary: "go", argv: ["install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"] },
  ],
  semgrep: [
    { display: "pipx install semgrep", binary: "pipx", argv: ["install", "semgrep"] },
    { display: "semgrep --version", binary: "semgrep", argv: ["--version"] },
  ],
  playwright: [
    { display: "npm install playwright en ~/.local/share/cyber-browser", binary: "npm", argv: ["install", "--no-save", "--no-audit", "--no-fund", `playwright@${process.env.CYBER_PLAYWRIGHT_VERSION ?? "1.64.0"}`], env: { PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1" } },
  ],
  // Sólo dentro de la caja (installTool lo exige): Java si falta, la herramienta fijada por sha256 y su envoltorio.
  get jadx() {
    return planesMovil("jadx");
  },
  get apktool() {
    return planesMovil("apktool");
  },
};

export type Runner = (argv: string[], env: Record<string, string>) => Promise<Pick<ExecResult, "exitCode" | "stdout" | "stderr" | "durationMs">>;

async function defaultRunner(argv: string[], env: Record<string, string>): Promise<ExecResult> {
  const bin = which(argv[0]!);
  if (!bin) throw new Error(`No encuentro «${argv[0]}» en el PATH. Instalalo antes de seguir con el resto de herramientas.`);
  return exec({ argv: [bin, ...argv.slice(1)], env, timeoutMs: 900_000, maxOutputBytes: 2_000_000 });
}

/**
 * Instala una herramienta de la lista permitida. Su código corre por un plan fijo (no por shell),
 * deja todo el registro como resultado textual y verifica que el binario efectivamente quede instalado.
 */
export async function installTool(
  name: string,
  cwd: string,
  runner: Runner = defaultRunner,
  options: InstallOptions = {},
): Promise<string> {
  if (!Object.hasOwn(INSTALLERS, name)) throw new Error(`«${name}» no es una herramienta de la lista de downloads opcionales del instalador.`);
  if (SOLO_CAJA.has(name)) {
    // Regla dura: las herramientas ofensivas no se instalan en la máquina del operador, sólo en la caja.
    if (!(options.enCaja ?? enCaja())) throw new Error(`${name} se instala sólo dentro de la caja de Orobas (el contenedor del proyecto que abre el lanzador «cyber»), nunca en esta máquina. Acá apk_analyze trabaja sin decompilar.`);
    if (which(name)) return `${name}: ya estaba instalado en ${which(name)}`;
    return instalarMovil(name as "jadx" | "apktool", runner, options);
  }
  const plans = INSTALLERS[name]!;
  const home = process.env.HOME ?? homedir();
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
    HOME: home,
    LANG: "C.UTF-8",
    TERM: "dumb",
    GOPATH: join(home, "go"),
  };
  // Si ya está, no vuelve a descargar ni compilar nada.
  if (which(name)) return `${name}: ya estaba instalado en ${which(name)}`;
  const destination = name === "playwright" ? join(env.HOME ?? homedir(), ".local", "share", "cyber-browser") : cwd;
  if (name === "playwright") mkdirSync(destination, { recursive: true });

  const outputs: string[] = [];
  for (const plan of plans) {
    const envForPlan = { ...env, ...plan.env, HOME: destination };
    const command = [plan.binary, ...plan.argv];
    let result: Pick<ExecResult, "exitCode" | "stdout" | "stderr" | "durationMs">;
    try {
      result = await runner(command, envForPlan);
    } catch (error) {
      outputs.push(`${plan.display}: no se pudo arrancar (${(error as Error).message})`);
      break;
    }
    const err = (result.stderr ?? "").trim().slice(-2_000);
    outputs.push(`${plan.display} (${result.exitCode ?? "?"} en ${Math.round(result.durationMs / 1000)} s)${err ? `\n${err}` : ""}`);
    if (result.exitCode !== 0) break;
    // La verificación no reinstala: comprobamos que la herramienta arranque antes de ofrecer la install.
    if (plan.verify) {
      const check = await runner([plan.binary, ...plan.verify], { ...env, HOME: destination }).catch(() => null);
      if (!check) break;
    }
  }
  const present = name === "playwright"
    ? existsSync(join(destination, "node_modules", "playwright", "index.mjs"))
    : which(name);
  if (present) outputs.push(`${name}: instalado${name !== "playwright" ? ` en ${which(name)}` : ""}`);
  else outputs.push(`${name}: todavía no está instalado. Revisá los errores de arriba; no se ejecutó nada más.`);
  return outputs.join("\n");
}

/** Herramientas con instalación propia disponible en el wizard (las de la caja, sólo dentro de la caja). */
export const INSTALLABLE: string[] = Object.keys(INSTALLERS).filter((name) => !SOLO_CAJA.has(name) || enCaja());

/** Estado de las herramientas de apps móviles para /toolbox: en el host no cuentan como faltantes. */
export function movilStatus(): string[] {
  const inside = enCaja();
  return (["jadx", "apktool"] as const).map((name) => {
    const path = which(name);
    if (path) return `${name.padEnd(10)} ✓ ${path}`;
    return inside
      ? `${name.padEnd(10)} ✗ no instalado · /toolbox_install ${name} (versión fija con sha256); sin ella apk_analyze no decompila`
      : `${name.padEnd(10)} · sólo en la caja (contenedor de Orobas); acá apk_analyze trabaja sin decompilar`;
  });
}
