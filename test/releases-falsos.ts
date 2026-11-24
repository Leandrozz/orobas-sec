// Ayudas para probar el instalador, el actualizador de los lanzadores y el armado de releases sin salir de la
// máquina: un repositorio mínimo con los instaladores y lanzadores reales (con una clave de PRUEBA generada en el
// momento, nunca guardada), releases armados con scripts/release/armar.sh y firmados con esa clave, y un servidor
// de releases falso en otro proceso. Todo vive en .pruebas/ dentro del worktree (ignorada por git) y se borra.
import { spawn, spawnSync, type SpawnSyncOptions } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export const RAIZ = resolve(".");
export const hay = (programa: string) => spawnSync("sh", ["-c", `command -v ${programa}`]).status === 0;

export function carpetaPrueba(prefijo: string): string {
  const base = join(RAIZ, ".pruebas");
  mkdirSync(base, { recursive: true });
  return mkdtempSync(join(base, `${prefijo}-`));
}

export function correr(programa: string, args: string[], opciones: SpawnSyncOptions = {}): string {
  const r = spawnSync(programa, args, { encoding: "utf8", ...opciones });
  if (r.status !== 0) throw new Error(`${programa} ${args.join(" ")} salió con ${r.status}: ${r.stderr}${r.stdout}`);
  return String(r.stdout);
}

export interface Clave { privada: string; publica: string; texto: string }
export function nuevaClave(dir: string, nombre: string): Clave {
  const privada = join(dir, nombre);
  correr("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "clave-de-prueba", "-f", privada]);
  const texto = readFileSync(`${privada}.pub`, "utf8").split(" ").slice(0, 2).join(" ");
  return { privada, publica: `${privada}.pub`, texto };
}

export function firmar(clave: Clave, archivo: string): void {
  rmSync(`${archivo}.sig`, { force: true });
  correr("ssh-keygen", ["-q", "-Y", "sign", "-n", "orobas-sec-release", "-f", clave.privada, archivo]);
}

// El agente falso: responde --version con el VERSION que pone el release y, si no, repite sus argumentos.
const CLI_FALSO = `import { readFileSync } from "node:fs";
const v = readFileSync(new URL("../VERSION", import.meta.url), "utf8").trim();
console.log(process.argv.includes("--version") ? "orobas-sec " + v : "agente falso " + v + ": " + process.argv.slice(2).join(" "));
`;
const GIT = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.test", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"];
const SIN_RED = { ...process.env, npm_config_offline: "true", npm_config_update_notifier: "false", npm_config_audit: "false", npm_config_fund: "false" };

/** Un repositorio con lo que armar.sh necesita: instaladores, lanzadores y scripts reales; la clave de prueba puesta con fijar-clave.sh. */
export function repoFalso(base: string, clave: Clave, imagen?: string): string {
  const repo = join(base, "repo");
  for (const f of ["install.sh", "install.ps1", "distro/lanzador/cyber", "distro/lanzador/cyber.ps1", "scripts/release/armar.sh", "scripts/release/fijar-clave.sh"]) {
    mkdirSync(dirname(join(repo, f)), { recursive: true });
    copyFileSync(join(RAIZ, f), join(repo, f));
  }
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "agente-falso", version: "0.0.0", private: true, type: "module" }, null, 2));
  writeFileSync(join(repo, "package-lock.json"), JSON.stringify({ name: "agente-falso", version: "0.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "agente-falso", version: "0.0.0" } } }, null, 2));
  mkdirSync(join(repo, "src"));
  writeFileSync(join(repo, "src/cli.ts"), CLI_FALSO);
  mkdirSync(join(repo, "bin"));
  writeFileSync(join(repo, "bin/cyber"), '#!/bin/sh\nexec node "$(dirname "$0")/../src/cli.ts" "$@"\n');
  writeFileSync(join(repo, "README.md"), "agente falso\n");
  writeFileSync(join(repo, "distro/imagen-release.txt"), imagen ? `# fijada\n${imagen}\n` : "# sin imagen fijada\n");
  correr("git", [...GIT, "init", "-q", repo]);
  correr("git", [...GIT, "-C", repo, "add", "-A"]);
  correr("git", [...GIT, "-C", repo, "commit", "-q", "-m", "fuente"]);
  correr("sh", [join(repo, "scripts/release/fijar-clave.sh"), clave.publica], { cwd: repo });
  correr("git", [...GIT, "-C", repo, "commit", "-q", "-a", "-m", "clave de prueba"]);
  return repo;
}

/** Arma el release `version` del repo en servidor/<version> y firma su SHA256SUMS. */
export function publicar(repo: string, servidor: string, version: string, clave: Clave): string {
  const salida = join(servidor, version);
  correr("sh", [join(repo, "scripts/release/armar.sh"), version, salida], { cwd: repo, env: SIN_RED });
  firmar(clave, join(salida, "SHA256SUMS"));
  return salida;
}

export function marcarUltimo(servidor: string, version: string): void {
  writeFileSync(join(servidor, "latest"), `${version}\n`);
}

export interface Servidor { url: string; pedidos: () => string[]; cerrar: () => void }
export async function levantarServidor(dir: string): Promise<Servidor> {
  const p = spawn(process.execPath, ["--disable-warning=ExperimentalWarning", join(RAIZ, "test/servidor-releases.ts"), dir], { stdio: ["ignore", "pipe", "inherit"] });
  const puerto = await new Promise<string>((listo, falla) => {
    p.stdout!.once("data", (d) => listo(String(d).trim()));
    p.once("exit", (c) => falla(new Error(`el servidor de releases salió con ${c}`)));
  });
  return {
    url: `http://127.0.0.1:${puerto}/releases`,
    pedidos: () => (existsSync(join(dir, "pedidos.log")) ? readFileSync(join(dir, "pedidos.log"), "utf8").trim().split("\n") : []),
    cerrar: () => void p.kill(),
  };
}

/** Un PATH con sólo estas herramientas del sistema (para probar qué pasa cuando falta alguna). */
export function pathCon(dir: string, herramientas: string[]): string {
  mkdirSync(dir, { recursive: true });
  for (const h of herramientas) {
    const r = spawnSync("sh", ["-c", `command -v ${h}`], { encoding: "utf8" });
    if (r.status === 0 && !existsSync(join(dir, h))) symlinkSync(r.stdout.trim(), join(dir, h));
  }
  return dir;
}
export const BASICAS = ["sh", "uname", "mktemp", "sed", "grep", "awk", "tar", "gzip", "curl", "ssh-keygen", "sha256sum", "cut", "head", "wc", "tr", "cat", "cp", "mv", "rm", "mkdir", "ln", "chmod", "rmdir", "basename", "dirname", "find", "cmp", "env", "sleep", "od"];

export function ejecutable(ruta: string, cuerpo: string): void {
  mkdirSync(dirname(ruta), { recursive: true });
  writeFileSync(ruta, cuerpo);
  chmodSync(ruta, 0o755);
}

/** Sin terminal: con setsid, /dev/tty no se puede abrir aunque las pruebas corran desde una terminal. */
const SETSID = ((ruta) => (ruta && spawnSync(ruta, ["-w", "true"]).status === 0 ? ruta : ""))(spawnSync("sh", ["-c", "command -v setsid"], { encoding: "utf8" }).stdout.trim());
/** Sin setsid (macOS), un instalador corrido desde una terminal podría preguntar en ella: esas pruebas se saltean. */
export const aislado = !!SETSID;
export function sinTerminal(programa: string, args: string[]): [string, string[]] {
  return SETSID ? [SETSID, ["-w", programa, ...args]] : [programa, args];
}

export const vacia = (dir: string) => !existsSync(dir) || readdirSync(dir).length === 0;
export const borrar = (dir: string) => rmSync(dir, { recursive: true, force: true });
