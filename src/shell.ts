// Shell del agente: una línea de shell completa, con permiso emergente del operador por comando.
// El comando lo escribe el modelo (nunca se interpola contenido del objetivo), así que la defensa
// contra una inyección de la página es que nada corre sin que la persona vea la línea exacta.
// Clasifica por riesgo, aprende prefijos aprobados («siempre») por proyecto, y siempre vuelve a
// preguntar lo riesgoso aunque el prefijo esté permitido.
import { mkdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { exec, SEARCH_PATH } from "./exec.ts";
import { MARCADOR_SIN_REPONER } from "./secretos-sesion.ts";

export type ShellKind = "lectura" | "escritura" | "red" | "destructivo";

export interface ShellVerdict {
  kind: ShellKind;
  /** Pide confirmación aunque el prefijo esté permitido: lo que no se deshace, o lo que trae código de afuera. */
  risky: boolean;
  reasons: string[];
  /** Prefijo que se guarda con «siempre». */
  prefix: string;
  /** Catastrófico o con contraseña de sistema: pregunta aunque el operador haya autoaprobado todo. */
  critical?: boolean;
}

/**
 * Lo que pregunta incluso con «autoaprobar todo»: no se recupera (formatear, borrar la raíz o el
 * home, escribir un disco), apaga la máquina, o pide la contraseña del sistema y colgaría el turno.
 */
function criticalReasons(command: string): string[] {
  const found: string[] = [];
  const whole = command.replace(/\\\n/g, " ");
  if (/(^|[;&|(]\s*)(sudo|su|doas|pkexec)\b/.test(whole)) found.push("pide privilegios de sistema");
  if (/(^|[;&|(]\s*)(mkfs(\.\w+)?|wipefs|fdisk|parted|sfdisk)\b/.test(whole)) found.push("formatea o particiona un disco");
  if (/(^|[;&|(]\s*)(shutdown|reboot|poweroff|halt)\b|systemctl\s+(poweroff|reboot|halt|suspend)/.test(whole)) found.push("apaga o reinicia la máquina");
  if (/\bdd\b[^;&|]*\bof=\/dev\/(?!null\b)/.test(whole) || />\s*\/dev\/(sd|nvme|hd|vd|mmcblk)/.test(whole)) found.push("escribe directo a un disco");
  if (/:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:/.test(whole)) found.push("fork bomb");
  const root = String.raw`(\/|\/\*|~\/?|~\/\*|\$HOME\/?|\$\{HOME\}\/?|\/(home|etc|usr|var|boot|bin|lib|lib64|opt|srv|root)\/?)`;
  if (new RegExp(String.raw`\brm\s+(-[A-Za-z-]+\s+)*` + root + String.raw`(\s|$|;|&|\|)`).test(whole) && /\brm\s+[^;&|]*-[A-Za-z]*[rR]/.test(whole)) found.push("borra la raíz, el home o una carpeta del sistema");
  if (new RegExp(String.raw`\b(chmod|chown)\s+(-[A-Za-z]+\s+)*-R\b[^;&|]*\s` + root + String.raw`(\s|$)`).test(whole)) found.push("cambia permisos de todo el sistema");
  return found;
}

/**
 * Archivo global (todas las carpetas de proyecto): `{"autoaprobar": true}` saca el aviso de cada comando.
 * Vive junto a la configuración del usuario (CYBER_CONFIG), así los tests y las imágenes lo aíslan igual.
 */
export function shellConfigFile(): string {
  const config = process.env.CYBER_CONFIG || join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "elevate-cyber", "config.json");
  return join(dirname(config), "shell.json");
}

function readAutoApprove(): boolean {
  const env = process.env.CYBER_SHELL_AUTOAPROBAR;
  if (env !== undefined && env !== "") return /^(1|si|sí|true|yes)$/i.test(env);
  try {
    return (JSON.parse(readFileSync(shellConfigFile(), "utf8")) as { autoaprobar?: unknown }).autoaprobar === true;
  } catch {
    return false;
  }
}

/** Lo que no se deshace con un `git checkout`: se borra o se pisa sin respaldo. */
const DESTRUCTIVE = new Set(["rm", "rmdir", "shred", "truncate", "dd", "mkfs", "kill", "pkill", "killall", "chmod", "chown", "chgrp", "ln", "mv"]);
/**
 * Lo que toca el sistema fuera del proyecto o baja código de un tercero: el alcance del harness no
 * cubre al shell, así que acá el operador es el único control.
 */
const SYSTEMIC = new Set(["sudo", "su", "apt", "apt-get", "pacman", "yum", "dnf", "brew", "systemctl", "service", "docker", "podman", "mount", "umount", "useradd", "crontab"]);
const NETWORK = new Set(["curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ping", "dig", "host", "nslookup", "whois"]);
const WRITE = new Set(["mkdir", "touch", "cp", "tee", "tar", "zip", "unzip", "gzip", "gunzip", "xargs", "install", "patch", "node", "python3", "python", "make", "pip", "pip3", "npm", "npx", "cargo", "go", "deno", "bun"]);
const READ = new Set(["ls", "cat", "head", "tail", "wc", "grep", "rg", "ag", "find", "tree", "file", "stat", "du", "df", "pwd", "echo", "printf", "jq", "yq", "sed", "awk", "cut", "sort", "uniq", "tr", "diff", "md5sum", "sha256sum", "readlink", "realpath", "basename", "dirname", "which", "command", "type", "env", "date", "uname", "id", "sleep", "test", "true", "false", "column", "less", "more", "nl", "od", "xxd", "strings"]);

/** Tramos de la línea, separados por lo que encadena (`;`, `&&`, `||`, `|`, salto de línea). */
function segments(command: string): string[] {
  return command
    .replace(/\\\n/g, " ")
    .split(/\|\||&&|[;|]|\n/)
    .map((piece) => piece.trim())
    .filter(Boolean);
}

/** Palabras del tramo, sin asignaciones de entorno adelante (`FOO=1 comando`). */
function words(segment: string): string[] {
  const raw = segment.split(/\s+/).filter(Boolean);
  let at = 0;
  while (at < raw.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(raw[at]!)) at++;
  return raw.slice(at);
}

/**
 * Clasifica la línea: el tramo más peligroso manda. Devuelve el prefijo que se guardaría y las
 * razones que se le muestran al operador antes de decidir.
 */
export function classifyCommand(command: string, cwd: string): ShellVerdict {
  const reasons: string[] = [];
  const tramos = segments(command);
  let kind: ShellKind = "lectura";
  const rank: Record<ShellKind, number> = { lectura: 0, escritura: 1, red: 2, destructivo: 3 };
  const raise = (next: ShellKind) => { if (rank[next] > rank[kind]) kind = next; };
  let risky = false;
  let first: string[] = [];

  for (const [index, tramo] of tramos.entries()) {
    const list = words(tramo);
    const binary = list[0] ?? "";
    if (!first.length) first = list;
    if (index && binary) reasons.push(`encadena ${tramos.length} tramos`);
    if (!/[A-Za-z0-9/_.-]/.test(binary)) { risky = true; reasons.push(`tramo sin binario claro («${tramo.slice(0, 30)}»)`); continue; }
    if (SYSTEMIC.has(binary)) { raise("destructivo"); risky = true; reasons.push(`${binary} toca el sistema`); continue; }
    if (DESTRUCTIVE.has(binary)) { raise("destructivo"); risky = true; reasons.push(`${binary} puede borrar o pisar`); continue; }
    if (NETWORK.has(binary)) { raise("red"); risky = true; reasons.push(`${binary} sale a la red`); continue; }
    if (WRITE.has(binary)) { raise("escritura"); continue; }
    if (READ.has(binary)) {
      // `sed -i`, `git fetch`, `npm i`: el mismo binario a veces escribe.
      if (binary === "sed" && /\s-i/.test(tramo)) raise("escritura");
      continue;
    }
    if (/^git$/i.test(binary)) {
      const sub = list[1] ?? "";
      if (/^(status|diff|log|show|branch|remote|rev-parse|ls-files|describe|blame|shortlog|tag|config --get)$/.test(sub)) { continue; }
      if (/^(reset|clean|checkout|restore|stash)$/.test(sub) && /--hard|--force|-f\b|--\s/.test(tramo)) { raise("destructivo"); risky = true; reasons.push(`git ${sub} descarta cambios`); continue; }
      if (/^(fetch|pull|push|clone|submodule)$/.test(sub)) { raise("red"); risky = true; reasons.push(`git ${sub} sale a la red`); continue; }
      raise("escritura");
      continue;
    }
    if (/^(bash|sh|zsh|dash)$/.test(binary)) { raise("escritura"); risky = true; reasons.push(`${binary} interpreta otro texto`); continue; }
    if (/^(\.\/)?[^\s]+\.(sh|bash|py|js|ts|mjs)$/.test(binary)) { raise("escritura"); continue; }
    // Sin clasificar: se trata como escritura y se pide permiso, por las dudas.
    if (binary) { raise("escritura"); risky = true; reasons.push(`«${binary}» no está clasificado`); }
  }

  const whole = command.trim();
  if (/\|\s*(sudo\s+)?(ba)?sh\b/.test(whole)) { risky = true; reasons.push("el resultado se ejecuta con otro shell"); }
  if (/[`]|\$\(/.test(whole)) { risky = true; reasons.push("interpola otro comando"); }
  if (/^\s*eval\b/.test(whole)) { risky = true; reasons.push("eval"); }
  if (/(^|\s)-{1,2}(force|yes|-dangerously)\b/.test(whole)) { risky = true; reasons.push("bandera forzada"); }
  if (/[^\s]\s*>\s*\S/.test(whole)) { raise("escritura"); reasons.push("redirige a un archivo"); }
  // Comillas sin cerrar: típico de texto pegado a medias desde una página.
  const quotes = (whole.match(/(["'])/g) ?? []).length;
  if (quotes % 2) { risky = true; reasons.push("comillas sin cerrar"); }
  if (tramos.length > 3) { risky = true; reasons.push(`${tramos.length} tramos en una línea`); }
  // Rutas absolutas que salen del proyecto: el radio de daño deja de ser la carpeta de trabajo.
  for (const path of whole.match(/(?:^|\s)(\/[^\s"';|&)]+)/g) ?? []) {
    const target = path.trim();
    if (!isAbsolute(target)) continue;
    const inside = resolve(cwd) === resolve(target) || !relative(resolve(cwd), resolve(target)).startsWith("..");
    if (!inside) { risky = true; reasons.push(`toca ${target.split("/").slice(0, 2).join("/")} fuera del proyecto`); }
  }
  const prefix = [first[0] ?? "", first[1] ?? ""].filter((word) => word && !word.startsWith("-")).slice(0, 2).join(" ");
  const critical = criticalReasons(whole);
  if (critical.length) { raise("destructivo"); risky = true; reasons.push(...critical); }
  return { kind, risky, reasons: [...new Set(reasons)], prefix: prefix || (first[0] ?? ""), critical: critical.length > 0 };
}

/** Prefijos aprobados con «siempre», por proyecto. La tabla vive en la base del proyecto. */
export class ShellPermissions {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    db.exec("create table if not exists shell_permisos(prefijo text primary key, at text not null)");
  }

  allows(prefix: string): boolean {
    return !!prefix && !!this.db.prepare("select prefijo from shell_permisos where prefijo=?").get(prefix);
  }

  /** «Autoaprobar todo»: global para todos los proyectos; lo crítico igual pregunta. */
  auto(): boolean {
    return readAutoApprove();
  }

  setAuto(on: boolean): void {
    const file = shellConfigFile();
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    let current: Record<string, unknown> = {};
    try { current = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>; } catch { /* nuevo */ }
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ ...current, autoaprobar: on }, null, 1) + "\n", { mode: 0o600 });
    renameSync(tmp, file);
  }

  allow(prefix: string): void {
    if (!prefix) return;
    this.db.prepare("insert or ignore into shell_permisos(prefijo,at) values(?,?)").run(prefix, new Date().toISOString());
  }

  revoke(prefix: string): boolean {
    return this.db.prepare("delete from shell_permisos where prefijo=?").run(prefix).changes > 0;
  }

  clear(): void {
    this.db.exec("delete from shell_permisos");
  }

  view(): string[] {
    const rows = this.db.prepare("select prefijo, at from shell_permisos order by at").all() as Array<{ prefijo: string; at: string }>;
    const mode = this.auto()
      ? ["Modo: autoaprobar todo (en todos los proyectos). Sólo preguntan sudo, formatear o escribir discos, apagar la máquina y borrar la raíz, el home o carpetas del sistema. /permisos normal lo apaga."]
      : [];
    if (!rows.length) return [...mode, mode.length ? "Sin prefijos guardados." : "Sin permisos de shell guardados. Cada comando pregunta; «siempre» en el aviso guarda el prefijo para este proyecto. /permisos todo autoaprueba todo."];
    return [...mode, ...rows.map((row) => `permitido siempre: «${row.prefijo}» (desde ${new Date(row.at).toLocaleString("es-AR")})`)];
  }
}

export interface ShellConfirmInfo {
  command: string;
  cwd: string;
  kind: ShellKind;
  risky: boolean;
  reasons: string[];
  prefix: string;
}

export interface ShellContext {
  cwd: string;
  artifacts: Artifacts;
  permissions: ShellPermissions;
  /** Pregunta al operador. Sin confirmador (modo sin interfaz) sólo pasan las lecturas. */
  confirm?: (info: ShellConfirmInfo) => Promise<"si" | "siempre" | "no">;
  /** Aviso opcional para la interfaz cuando un comando quedó esperando permiso. */
  onAsk?: (info: ShellConfirmInfo) => void;
}

/** El cwd del comando no puede salirse del proyecto. */
function insideProject(root: string, path?: string): string {
  const base = realpathSync(resolve(root));
  const target = path ? resolve(base, path) : base;
  const real = resolve(target);
  if (real !== base && !real.startsWith(base + sep)) throw new Error(`«${path}» queda fuera de la carpeta del proyecto (${base})`);
  statSync(real);
  return real;
}

export function createShellTool(context: ShellContext): Tool {
  return {
    name: "shell",
    label: "Shell",
    description:
      "Corre una línea de shell completa en la carpeta del proyecto, con permiso del operador cuando hace falta. " +
      "Sirve para lo que las herramientas propias no cubren: git, compilar, correr un script, mover archivos, revisar el entorno. " +
      "El comando lo escribís vos entero (nada se interpola del objetivo), y la persona ve la línea exacta antes de aceptar: es lo que impide que una página inyecte algo. " +
      "Pide permiso para escribir, salir a la red, tocar el sistema o borrar; las lecturas simples y los prefijos aprobados con «siempre» corren directo, salvo lo riesgoso, que siempre pregunta.",
    parameters: {
      type: "object",
      properties: {
        command: { type: "string", description: "Línea completa, p. ej. «git status --short» o «npm ci && npm test»", maxLength: 4000 },
        cwd: { type: "string", description: "Subcarpeta del proyecto donde correrlo; por defecto la raíz" },
        timeoutSec: { type: "integer", minimum: 1, maximum: 600, description: "Por defecto 120; corta el grupo de procesos entero" },
        stdin: { type: "string", description: "Texto que se manda por la entrada estándar", maxLength: 20000 },
      },
      required: ["command"],
    },
    execute: async (params, signal): Promise<ToolResult> => {
      const command = String(params.command ?? "").replace(/\r/g, "").trim();
      if (!command) throw new Error("Pasá un comando");
      // Desde el motor, reponer ya cortó (src/secretos-sesion.ts); esto cubre a quien llama a la herramienta directo.
      if (MARCADOR_SIN_REPONER.test(command) || MARCADOR_SIN_REPONER.test(String(params.stdin ?? ""))) throw new Error("No ejecuté la shell: quedó un marcador de secreto sin reponer en el comando o la entrada. El archivo del laboratorio debe recibir el valor real; revisá la procedencia de la clave.");
      if (command.length > 4000) throw new Error("El comando pasa los 4000 caracteres: partilo en dos llamadas");
      const cwd = insideProject(context.cwd, params.cwd ? String(params.cwd) : undefined);
      const verdict = classifyCommand(command, cwd);
      const allowed = !verdict.risky && (verdict.kind === "lectura" || context.permissions.allows(verdict.prefix));
      const auto = !allowed && !verdict.critical && context.permissions.auto();

      let decision: "si" | "siempre" | "no" = "no";
      if (allowed || auto) decision = "si";
      else if (context.confirm) {
        context.onAsk?.({ command, cwd, kind: verdict.kind, risky: verdict.risky, reasons: verdict.reasons, prefix: verdict.prefix });
        try {
          decision = await context.confirm({ command, cwd, kind: verdict.kind, risky: verdict.risky, reasons: verdict.reasons, prefix: verdict.prefix });
        } catch (error) {
          decision = "no";
          verdict.reasons.push(`el permiso no llegó a la interfaz (${(error as Error).message})`);
        }
      } else {
        verdict.reasons.push("sin interfaz para pedir permiso");
      }
      if (decision === "siempre") context.permissions.allow(verdict.prefix);
      if (decision === "no") {
        return {
          text: [
            `Rechazado: ${command}`,
            `tipo: ${verdict.kind}${verdict.risky ? " (riesgoso)" : ""}${verdict.reasons.length ? ` · ${verdict.reasons.join("; ")}` : ""}`,
            "Nada se ejecutó. Si hace falta, el operador lo habilita con «siempre» en el aviso o con /permisos permitir.",
          ].join("\n"),
          details: { ejecutado: false, tipo: verdict.kind, prefijo: verdict.prefix },
          isError: false,
        };
      }

      const timeoutMs = Math.min(600, Math.max(1, Number(params.timeoutSec) || 120)) * 1000;
      // Entorno mínimo: el hijo no hereda las claves del harness, así que lo que lea del disco no
      // se puede descifrar con lo que tenga a mano.
      const result = await exec({
        argv: ["/bin/sh", "-c", command],
        cwd,
        timeoutMs,
        maxOutputBytes: 1_000_000,
        stdin: params.stdin === undefined ? undefined : String(params.stdin),
        signal,
        env: { PATH: `${SEARCH_PATH}:${process.env.PATH ?? ""}`, HOME: process.env.HOME ?? "", LANG: process.env.LANG ?? "C.UTF-8", TERM: "dumb", TZ: process.env.TZ ?? "" },
      });
      const artifact = context.artifacts.put(
        JSON.stringify({ command, cwd, kind: verdict.kind, risky: verdict.risky, decision, exitCode: result.exitCode, signal: result.signal, timedOut: result.timedOut, durationMs: result.durationMs, stdout: result.stdout, stderr: result.stderr }, null, 1),
        "application/json",
        "shell",
      );
      const body = [result.stdout.trim(), result.stderr.trim()].filter(Boolean).join("\n[stderr]\n");
      const cut = body.length > 6000 ? `${body.slice(0, 6000)}\n… (${body.length} caracteres; completo en el artefacto)` : body;
      const state = result.cancelled ? "cancelado" : result.timedOut ? `cortado a los ${timeoutMs / 1000} s` : `salida ${result.exitCode ?? result.signal}`;
      const head = `$ ${command}\n(${verdict.kind} · ${decision === "siempre" ? "permitido siempre: " : auto ? "autoaprobado: " : ""}${state} · ${(result.durationMs / 1000).toFixed(1)} s · artefacto ${artifact.hash.slice(0, 19)})`;
      return {
        text: `${head}\n${cut || "(sin salida)"}`,
        details: { salida: result.exitCode ?? result.signal, tipo: verdict.kind, artefacto: artifact.hash },
        isError: result.exitCode !== 0,
      };
    },
  };
}
