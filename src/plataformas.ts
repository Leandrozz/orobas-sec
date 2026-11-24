// Plataformas: las CLIs oficiales (GitHub, Vercel, Supabase, AWS, Google Cloud, Azure, Cloudflare,
// Kubernetes y las que el operador agregue en la configuración) como herramientas del agente.
// Corren sin shell, con la sesión que el operador ya tiene en cada CLI, y el código decide qué
// se puede: leer corre directo, cambiar algo exige citar el pedido del operador, y borrar,
// imprimir credenciales o abrir algo interactivo no corre nunca. Los secretos no llegan al modelo.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, isAbsolute, join, relative, resolve } from "node:path";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { exec, SEARCH_PATH, which } from "./exec.ts";
import { operatorQuote } from "./operador.ts";
import { configPath } from "./providers.ts";
import { credentialsDir } from "./secretos.ts";
import { t } from "./idioma.ts";

export interface PlatformSpec {
  name: string;
  label: string;
  binary: string;
  install: string;
  /** Variables del entorno del operador que se pasan si existen (credenciales y contexto de la CLI). */
  env: string[];
  /** Variables fijas: sin preguntas interactivas, sin paginador, sin colores. */
  fixed?: Record<string, string>;
  /** Comando que confirma la vinculación y muestra la cuenta. */
  status?: string[];
  /** Vinculación sin terminal: imprime una URL y un código que el operador aprueba en su navegador. */
  device?: string[];
  /** Vinculación interactiva en la terminal: orobas-sec login <plataforma>. */
  terminal?: () => string[];
  /** Cierre de sesión de la CLI, sin preguntas. */
  logout?: string[];
  /** Carpetas de sesión de la CLI, relativas a su HOME aislado. */
  session?: string[];
  /** Palabras de comando que sólo leen, además de las generales (list, view, describe, get…). */
  read?: string[];
  /** Secuencias bloqueadas por imprimir credenciales; con flags, sólo si aparece alguna. */
  secret?: Array<{ seq: string[]; flags?: string[] }>;
  /** Palabras de comando bloqueadas: interactivas, de larga duración o que ejecutan código local. */
  blocked?: string[];
  /** Palabras que borran o interrumpen, además de las generales. */
  destructive?: string[];
  /** Subcomando de API cruda (gh api): lee con GET y escribe con cualquier otro método o con campos. */
  api?: string;
}

const graphical = () => !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);

export const BUILTIN: PlatformSpec[] = [
  {
    name: "github",
    label: "GitHub",
    binary: "gh",
    install: "https://cli.github.com (pacman -S github-cli · brew install gh · winget install GitHub.cli)",
    env: ["GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_ENTERPRISE_TOKEN", "GH_REPO"],
    fixed: { GH_PROMPT_DISABLED: "1", GH_NO_UPDATE_NOTIFIER: "1", GIT_TERMINAL_PROMPT: "0", GH_PAGER: "cat" },
    status: ["auth", "status"],
    device: ["auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--web"],
    terminal: () => ["auth", "login"],
    logout: ["auth", "logout", "--hostname", "github.com"],
    session: [".config/gh"],
    read: ["clone", "download", "checks", "diff", "status"],
    secret: [{ seq: ["auth", "token"] }, { seq: ["auth", "status"], flags: ["-t", "--show-token"] }],
    blocked: ["extension", "extensions", "alias", "codespace", "auth", "config", "browse"],
    api: "api",
  },
  {
    name: "vercel",
    label: "Vercel",
    binary: "vercel",
    install: "npm i -g vercel",
    env: ["VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID"],
    fixed: { VERCEL_TELEMETRY_DISABLED: "1" },
    status: ["whoami"],
    device: ["login"],
    terminal: () => ["login"],
    logout: ["logout"],
    session: [".local/share/com.vercel.cli", ".config/com.vercel.cli"],
    read: ["whoami", "inspect", "logs", "ls", "list", "certs"],
    // pull y env pull escriben las variables con sus valores en archivos del proyecto.
    secret: [{ seq: ["pull"] }],
    blocked: ["dev", "build", "telemetry"],
    api: "api",
  },
  {
    name: "supabase",
    label: "Supabase",
    binary: "supabase",
    install: "https://supabase.com/docs/guides/cli (brew install supabase/tap/supabase · npm i -g supabase · scoop install supabase)",
    env: ["SUPABASE_ACCESS_TOKEN", "SUPABASE_PROJECT_ID", "SUPABASE_DB_PASSWORD"],
    fixed: { DO_NOT_TRACK: "1" },
    status: ["projects", "list"],
    terminal: () => ["login"],
    logout: ["logout", "--yes"],
    session: [".supabase"],
    read: ["inspect", "lint", "dump", "gen"],
    blocked: ["start", "stop", "serve", "bootstrap", "init"],
  },
  {
    name: "aws",
    label: "AWS",
    binary: "aws",
    install: "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
    env: ["AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"],
    fixed: { AWS_PAGER: "", AWS_CLI_AUTO_PROMPT: "off" },
    status: ["sts", "get-caller-identity"],
    terminal: () => (graphical() ? ["login"] : ["login", "--remote"]),
    session: [".aws"],
    secret: [
      "get-secret-value", "get-session-token", "get-federation-token", "assume-role", "assume-role-with-saml", "assume-role-with-web-identity",
      "get-login-password", "get-authorization-token", "generate-db-auth-token", "create-access-key", "export-credentials", "get-role-credentials",
      "get-token", "get-password-data", "get-credentials-for-identity", "get-open-id-token", "initiate-auth", "admin-initiate-auth", "create-login-profile",
    ].map((word) => ({ seq: [word] })),
    blocked: ["configure", "sso", "start-session", "send-command", "execute-command", "mv"],
  },
  {
    name: "gcloud",
    label: "Google Cloud",
    binary: "gcloud",
    install: "https://cloud.google.com/sdk/docs/install",
    env: ["CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT", "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"],
    fixed: { CLOUDSDK_CORE_DISABLE_PROMPTS: "1", CLOUDSDK_CORE_DISABLE_USAGE_REPORTING: "true" },
    status: ["auth", "list", "--filter=status:ACTIVE", "--format=value(account)"],
    terminal: () => (graphical() ? ["auth", "login"] : ["auth", "login", "--no-launch-browser"]),
    logout: ["auth", "revoke", "--all"],
    session: [".config/gcloud"],
    read: ["read", "info"],
    secret: [
      { seq: ["print-access-token"] }, { seq: ["print-identity-token"] }, { seq: ["print-refresh-token"] }, { seq: ["config-helper"] },
      { seq: ["versions", "access"] }, { seq: ["keys", "create"] }, { seq: ["get-server-ca-certs"] },
    ],
    blocked: ["ssh", "scp", "init", "auth", "tail", "interactive"],
  },
  {
    name: "azure",
    label: "Azure",
    binary: "az",
    install: "https://learn.microsoft.com/cli/azure/install-azure-cli",
    env: ["AZURE_CONFIG_DIR", "AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
    fixed: { AZURE_CORE_NO_COLOR: "1", AZURE_CORE_ONLY_SHOW_ERRORS: "1", AZURE_CORE_COLLECT_TELEMETRY: "0" },
    status: ["account", "show", "--query", "user.name", "-o", "tsv"],
    device: ["login", "--use-device-code"],
    terminal: () => ["login", "--use-device-code"],
    logout: ["logout"],
    session: [".azure"],
    secret: [
      { seq: ["get-access-token"] }, { seq: ["keys", "list"] }, { seq: ["secret", "show"] }, { seq: ["secret", "download"] },
      { seq: ["show-connection-string"] }, { seq: ["list-publishing-credentials"] }, { seq: ["list-publishing-profiles"] }, { seq: ["list-keys"] }, { seq: ["list-connection-strings"] },
    ],
    blocked: ["ssh", "login", "interactive", "serial-console", "configure"],
  },
  {
    name: "cloudflare",
    label: "Cloudflare",
    binary: "wrangler",
    install: "npm i -g wrangler",
    env: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
    fixed: { WRANGLER_SEND_METRICS: "false" },
    status: ["whoami"],
    terminal: () => ["login"],
    read: ["whoami", "tail"],
    logout: ["logout"],
    session: [".config/.wrangler", ".wrangler"],
    blocked: ["dev", "tail", "init", "generate"],
  },
  {
    name: "kubernetes",
    label: "Kubernetes",
    binary: "kubectl",
    install: "https://kubernetes.io/docs/tasks/tools/",
    env: ["KUBECONFIG"],
    status: ["config", "current-context"],
    session: [".kube"],
    read: ["top", "explain", "api-resources", "api-versions", "cluster-info", "can-i", "current-context", "version"],
    secret: [{ seq: ["get", "secret"], flags: ["-o", "--output"] }, { seq: ["get", "secrets"], flags: ["-o", "--output"] }, { seq: ["config", "view"], flags: ["--raw"] }, { seq: ["create", "token"] }],
    blocked: ["exec", "attach", "port-forward", "proxy", "edit", "debug"],
    destructive: ["drain", "cordon", "taint"],
  },
];

/** Plataformas incorporadas más las que declara la configuración («plataformas»: { nombre: {binary, …} }). */
export function platforms(): PlatformSpec[] {
  const all = [...BUILTIN];
  try {
    const path = configPath();
    const extra = existsSync(path) ? JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, "")).plataformas : undefined;
    for (const [name, raw] of Object.entries(extra ?? {}) as Array<[string, any]>) {
      if (!/^[a-z0-9-]+$/.test(name) || typeof raw?.binary !== "string" || all.some((item) => item.name === name)) continue;
      const words = (value: unknown) => (Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : undefined);
      all.push({
        name,
        label: typeof raw.label === "string" ? raw.label : name,
        binary: raw.binary,
        install: typeof raw.install === "string" ? raw.install : `instalar ${raw.binary}`,
        env: words(raw.env) ?? [],
        status: words(raw.status),
        device: words(raw.device),
        terminal: words(raw.terminal) ? () => words(raw.terminal)! : undefined,
        read: words(raw.read),
        blocked: words(raw.blocked),
        destructive: words(raw.destructive),
        secret: (words(raw.secret) ?? []).map((word) => ({ seq: word.split(/\s+/) })),
        api: typeof raw.api === "string" ? raw.api : undefined,
      });
    }
  } catch {}
  return all;
}

export function platform(name: string): PlatformSpec {
  const found = platforms().find((item) => item.name === name || item.binary === name);
  if (!found) throw new Error(`Plataforma desconocida: ${name}. Disponibles: ${platforms().map((item) => item.name).join(", ")}`);
  return found;
}

// ── Clasificación ────────────────────────────────────────────────────────────────────────────

const READ = new Set(["list", "ls", "view", "show", "get", "describe", "status", "whoami", "inspect", "logs", "log", "search", "read", "info", "version", "help", "diff", "lint", "explain", "query", "scan", "clone", "download", "dump", "can-i", "current-context", "cat"]);
const READ_PREFIX = ["describe-", "list-", "get-", "head-", "lookup-", "batch-get-", "search-", "query-", "scan-", "check-", "validate-", "simulate-", "estimate-", "preview-", "test-"];
const DESTRUCTIVE = new Set(["delete", "remove", "rm", "rmdir", "rb", "destroy", "purge", "terminate", "deregister", "reset", "prune", "drop", "wipe", "erase", "revoke", "uninstall", "archive", "transfer", "cancel", "detach", "disassociate", "disable", "stop", "unset", "logout", "unlink", "truncate", "empty"]);
const SECRET_FLAGS = ["--show-token", "--show-secrets", "--with-decryption", "--reveal", "--token", "--password", "--decrypt"];
const DESTRUCTIVE_FLAGS = ["--delete", "--purge", "--force-delete", "--delete-all"];

export interface Classified {
  kind: "lectura" | "escritura";
  words: string[];
}

/** Palabras de comando: los posicionales iniciales, saltando flags iniciales con su valor. */
export function commandWords(args: string[]): string[] {
  const words: string[] = [];
  let index = 0;
  while (index < args.length && args[index]!.startsWith("-")) {
    const flag = args[index]!;
    index += !flag.includes("=") && index + 1 < args.length && !args[index + 1]!.startsWith("-") ? 2 : 1;
  }
  for (; index < args.length && !args[index]!.startsWith("-"); index++) words.push(args[index]!.toLowerCase());
  return words;
}

const hasFlag = (args: string[], flags: string[]) =>
  args.some((arg) => {
    const lower = arg.toLowerCase();
    return flags.some((flag) => lower === flag || lower.startsWith(`${flag}=`) || (/^-[a-z]$/.test(flag) && lower.startsWith(flag) && !lower.startsWith("--")));
  });

function contains(words: string[], seq: string[]): boolean {
  for (let start = 0; start + seq.length <= words.length; start++) if (seq.every((word, offset) => words[start + offset] === word)) return true;
  return false;
}

/** Valor de un flag (--method POST, --method=POST, -XPOST). */
function flagValue(args: string[], names: string[]): string | undefined {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    for (const name of names) {
      if (arg === name) return args[index + 1];
      if (arg.startsWith(`${name}=`)) return arg.slice(name.length + 1);
      if (/^-[A-Za-z]$/.test(name) && arg.startsWith(name) && arg.length > 2 && !arg.startsWith("--")) return arg.slice(2);
    }
  }
  return undefined;
}

/** Un argumento que apunta a un archivo tiene que quedar dentro del proyecto y fuera de .cyber. */
function checkPaths(args: string[], cwd: string, apiEndpoint?: number): void {
  const root = resolve(cwd);
  args.forEach((arg, index) => {
    if (index === apiEndpoint) return;
    for (const raw of [arg, arg.replace(/^[^=]*=/, "")]) {
      const candidate = raw.replace(/^(?:fileb?:\/\/|@)/, "");
      if (/(^|[\\/])\.cyber([\\/]|$)/.test(candidate)) throw new Error(`Bloqueado: «${arg}» apunta a .cyber, donde el harness guarda credenciales y evidencia.`);
      const pathy = isAbsolute(candidate) || candidate.startsWith("~") || /(^|[\\/])\.\.([\\/]|$)/.test(candidate);
      if (!pathy || /^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) continue;
      const target = resolve(root, candidate.replace(/^~(?=$|[\\/])/, homedir()));
      const inside = relative(root, target);
      if (inside.startsWith("..") || isAbsolute(inside)) throw new Error(`Bloqueado: «${arg}» sale de la carpeta del proyecto. Trabajá con rutas dentro de ella.`);
    }
  });
}

/** Decide si un comando lee, escribe o no corre. Lanza un error con el motivo cuando no corre. */
export function classify(spec: PlatformSpec, args: string[], cwd: string): Classified {
  if (!Array.isArray(args) || args.length > 80 || args.some((arg) => typeof arg !== "string" || arg.length > 4000 || arg.includes("\0"))) throw new Error("args tiene que ser una lista de hasta 80 textos");
  const words = commandWords(args);
  const label = `${spec.binary} ${words.join(" ")}`.trim();
  for (const rule of spec.secret ?? []) {
    if (contains(words, rule.seq) && (!rule.flags || hasFlag(args, rule.flags))) throw new Error(`Bloqueado: «${label}» imprime o exporta credenciales. Las credenciales nunca pasan por el modelo.`);
  }
  if (hasFlag(args, SECRET_FLAGS)) throw new Error("Bloqueado: ese flag muestra o recibe credenciales. Las pone el harness desde la sesión del operador, nunca el modelo.");
  if (words.some((word) => ["login"].includes(word))) throw new Error("Para vincular una cuenta usá platform_link: muestra al operador una URL y un código para aprobar en su navegador.");
  const blocked = words.find((word) => (spec.blocked ?? []).includes(word));
  // gh auth status es la única lectura de auth permitida.
  if (blocked && !(spec.name === "github" && blocked === "auth" && words[1] === "status")) throw new Error(`Bloqueado: «${label}» es interactivo, queda corriendo, cambia la configuración de la CLI o ejecuta código local. Si hace falta, lo corre el operador.`);
  const destructive = [...DESTRUCTIVE, ...(spec.destructive ?? [])];
  const killer = words.find((word) => destructive.includes(word) || destructive.some((verb) => word.startsWith(`${verb}-`)));
  const method = spec.api && words[0] === spec.api ? (flagValue(args, ["-X", "--method", "--request"]) ?? "").toUpperCase() : "";
  if (killer || method === "DELETE" || hasFlag(args, DESTRUCTIVE_FLAGS)) throw new Error(`Bloqueado: «${label}» borra, vacía o interrumpe algo. Eso lo hace el operador, a mano.`);
  const apiAt = spec.api ? args.findIndex((arg) => arg === spec.api) : -1;
  checkPaths(args, cwd, apiAt >= 0 ? apiAt + 1 : undefined);
  if (spec.api && words[0] === spec.api) {
    const fields = hasFlag(args, ["-f", "-F", "--field", "--raw-field", "--input", "-d", "--data"]);
    return { kind: (!method || method === "GET" || method === "HEAD") && !fields ? "lectura" : "escritura", words };
  }
  const reads = new Set([...READ, ...(spec.read ?? [])]);
  const reading = words.length > 0 && words.some((word) => reads.has(word) || READ_PREFIX.some((prefix) => word.startsWith(prefix)));
  return { kind: reading ? "lectura" : "escritura", words };
}

// ── Secretos en la salida ────────────────────────────────────────────────────────────────────

const OUTPUT_SECRETS: Array<{ name: string; pattern: RegExp }> = [
  { name: "clave privada", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { name: "token de GitHub", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g },
  { name: "token de Supabase", pattern: /\b(?:sbp_[a-f0-9]{30,}|sb_secret_[A-Za-z0-9_-]{16,})\b/g },
  { name: "JWT", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: "token de Google", pattern: /\bya29\.[A-Za-z0-9_-]{20,}/g },
  { name: "clave de Google", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "clave de Stripe", pattern: /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g },
  { name: "token de Slack", pattern: /\bxox[abpr]-[A-Za-z0-9-]{10,}\b/g },
  { name: "URL con credenciales", pattern: /\b([a-z][a-z0-9+.-]*:\/\/[^\s/:@"']+:)[^\s/@"']+(@)/gi },
  { name: "credencial", pattern: /("?(?:SecretAccessKey|SessionToken|secret_access_key|session_token|aws_secret_access_key|aws_session_token|accessToken|access_token|refreshToken|refresh_token|id_token|client_secret|clientSecret|password|passwd|private_key|privateKey|secret|token|api_key|apiKey|connectionString|primaryKey|secondaryKey)"?\s*[:=]\s*"?)([^"\s,}]{8,})/gi },
];

/** Oculta credenciales conocidas y patrones de secretos, dejando una marca con el tipo. */
export function redactSecrets(text: string, known: string[] = []): string {
  let out = text;
  for (const value of known) if (value && value.length >= 8) out = out.split(value).join("[credencial omitida]");
  for (const { name, pattern } of OUTPUT_SECRETS) {
    out = out.replace(pattern, (match, ...groups) => {
      if (name === "URL con credenciales") return `${groups[0]}[credencial omitida]${groups[1]}`;
      if (name === "credencial") {
        const value = String(groups[1]);
        // Una referencia en código (process.env.X, config.secret, un identificador) no es el secreto.
        const reference = /omitid/.test(value) || !/\d/.test(value) || /^(?:process\.env|os\.environ|getenv|env\(|ENV\[|System\.getenv|config\.|settings\.|\$\{|\$[A-Z_])/.test(value);
        return reference ? match : `${groups[0]}[secreto omitido]`;
      }
      return `[secreto omitido: ${name}]`;
    });
  }
  return out;
}

// ── Ejecución ────────────────────────────────────────────────────────────────────────────────

/** HOME aislado de las CLIs: en el contenedor, dentro de la carpeta de credenciales; en la instalación nativa, ninguno (se usa el HOME real). */
export function platformsHome(): string | undefined {
  return process.env.CYBER_PLATAFORMAS_HOME || (process.env.CYBER_PROYECTO_HOST ? join(credentialsDir(), "plataformas") : undefined);
}

/** Entorno mínimo para la CLI: su sesión, sin las claves de API del harness. */
export function platformEnv(spec: PlatformSpec): { env: Record<string, string>; known: string[] } {
  // En el contenedor, CYBER_PLATAFORMAS_HOME apunta a la carpeta montada: los logins sobreviven al contenedor.
  const isolated = platformsHome();
  const home = isolated ?? homedir();
  if (isolated) mkdirSync(home, { recursive: true, mode: 0o700 });
  const env: Record<string, string> = {
    PATH: [process.env.PATH ?? "", SEARCH_PATH].filter(Boolean).join(":"),
    HOME: home,
    LANG: process.env.LANG ?? "C.UTF-8",
    TERM: "dumb",
    NO_COLOR: "1",
    ...(spec.fixed ?? {}),
  };
  for (const name of ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "SSL_CERT_FILE", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"]) {
    if (process.env[name]) env[name] = process.env[name]!;
  }
  const known: string[] = [];
  for (const name of spec.env) {
    const value = process.env[name];
    if (!value) continue;
    env[name] = value;
    if (/TOKEN|SECRET|KEY|PASSWORD/.test(name)) known.push(value);
  }
  return { env, known };
}

export interface PlatformContext {
  artifacts: Artifacts;
  cwd: string;
  /** Mensajes textuales del operador en esta sesión: lo único que habilita una escritura. */
  operatorTexts: () => string[];
}

const pending = new Map<string, ChildProcess>();

/** Ruta del binario: las rutas fijas del harness y, después, el PATH del operador (Homebrew, npm global, gcloud). */
export function findBinary(name: string): string | undefined {
  const fixed = which(name);
  if (fixed || name.includes("/")) return fixed;
  for (const dir of [...(process.env.PATH ?? "").split(delimiter), "/opt/homebrew/bin", join(homedir(), "google-cloud-sdk", "bin")].filter(Boolean)) {
    try {
      accessSync(join(dir, name), constants.X_OK);
      return join(dir, name);
    } catch {}
  }
  return undefined;
}

/** Estado de una plataforma: instalada y vinculada. Nunca muestra la credencial. */
export async function platformState(spec: PlatformSpec, signal?: AbortSignal): Promise<{ installed: boolean; linked?: boolean; account?: string; detail?: string }> {
  const binary = findBinary(spec.binary);
  if (!binary) return { installed: false };
  if (!spec.status) return { installed: true };
  const { env, known } = platformEnv(spec);
  const result = await exec({ argv: [binary, ...spec.status], env, timeoutMs: 25_000, maxOutputBytes: 20_000, signal });
  const text = redactSecrets(`${result.stdout}\n${result.stderr}`, known).replace(/\u001b\[[0-9;]*m/g, "");
  const lines = text.split("\n").map((line) => line.trim()).filter((line) => line && !/^(Vercel CLI|>|A new version|We recommend)/.test(line));
  const account = /account\s+(\S+)/i.exec(text)?.[1] ?? /"Arn":\s*"([^"]+)"/.exec(text)?.[1] ?? lines.find((line) => /^[^\s@]+@[^\s@]+$/.test(line)) ?? (lines.length === 1 && /^[\w.@-]+$/.test(lines[0]!) ? lines[0] : undefined);
  const linked = result.exitCode === 0 && !/no credentialed accounts|not logged in|no existing credentials/i.test(text);
  return { installed: true, linked, account: account?.slice(0, 160), detail: linked ? undefined : text.trim().split("\n").slice(-2).join(" ").slice(0, 200) };
}

/** Lanza el login por dispositivo de la CLI y espera la URL y el código; el proceso sigue esperando la aprobación. */
export async function startDevice(spec: PlatformSpec, signal?: AbortSignal): Promise<{ child: ChildProcess; found: { url?: string; code?: string }; output: () => string }> {
  pending.get(spec.name)?.kill("SIGTERM");
  const { env } = platformEnv(spec);
  const child = spawn(findBinary(spec.binary)!, spec.device, { env, stdio: ["pipe", "pipe", "pipe"] });
  pending.set(spec.name, child);
  // Un fallo del proceso o de su entrada no puede tirar el daemon.
  child.on("error", () => {});
  child.stdin!.on("error", () => {});
  const timer = setTimeout(() => child.kill("SIGTERM"), 15 * 60_000);
  timer.unref();
  child.on("exit", () => {
    clearTimeout(timer);
    if (pending.get(spec.name) === child) pending.delete(spec.name);
  });
  let output = "";
  const found = await new Promise<{ url?: string; code?: string }>((done) => {
    const check = () => {
      const url = /https:\/\/[^\s"')]+/.exec(output)?.[0];
      const code = /\b(?:code|código)[^A-Z0-9]{0,40}([A-Z0-9]{4}-[A-Z0-9]{4}|[A-Z0-9]{8,9})\b/i.exec(output)?.[1] ?? /\b([A-Z0-9]{4}-[A-Z0-9]{4})\b/.exec(output)?.[1] ?? /user_code=([A-Za-z0-9-]+)/.exec(output)?.[1];
      if (url && (code || /user_code=/.test(url) || /device/.test(url))) done({ url, code });
    };
    const onData = (chunk: Buffer) => {
      output += chunk.toString("utf8");
      check();
    };
    child.stdout!.on("data", onData);
    child.stderr!.on("data", onData);
    child.on("exit", () => done({}));
    setTimeout(() => done({}), 30_000).unref();
    signal?.addEventListener("abort", () => done({}), { once: true });
  });
  // Algunas CLIs piden Enter antes de abrir el navegador: se lo damos y siguen esperando la aprobación.
  if (child.exitCode === null && !child.stdin!.destroyed) child.stdin!.write("\n");
  return { child, found, output: () => output };
}

export function createPlatformTools(context: PlatformContext): Tool[] {
  const names = () => platforms().map((item) => item.name);

  const status: Tool = {
    name: "platform_status",
    label: "Plataformas vinculadas",
    description: "Lista las plataformas (GitHub, Vercel, Supabase, AWS, Google Cloud, Azure, Cloudflare, Kubernetes y las que agregue el operador): si su CLI está instalada y si hay una cuenta vinculada, con la cuenta. Nunca muestra credenciales.",
    parameters: { type: "object", properties: { plataforma: { type: "string" } }, required: [] },
    parallel: true,
    replay: "safe",
    execute: async (params, signal): Promise<ToolResult> => {
      const chosen = params.plataforma ? [platform(params.plataforma)] : platforms();
      const states = await Promise.all(chosen.map(async (spec) => ({ spec, state: await platformState(spec, signal) })));
      const lines = states.map(({ spec, state }) =>
        `${spec.name.padEnd(11)} ${!state.installed ? `✗ ${spec.binary} no instalado · ${spec.install}` : state.linked === undefined ? `✓ ${spec.binary} instalado` : state.linked ? `✓ vinculada${state.account ? ` · ${state.account}` : ""}` : `· sin vincular${state.detail ? ` (${state.detail})` : ""} → platform_link`}`);
      return { text: lines.join("\n"), details: { vinculadas: states.filter((item) => item.state.linked).map((item) => item.spec.name) } };
    },
  };

  const link: Tool = {
    name: "platform_link",
    label: "Vincular plataforma",
    description: "Vincula la cuenta del operador en una plataforma sin que ninguna credencial pase por el chat: inicia el login por dispositivo de la CLI y devuelve una URL y un código para que el operador lo apruebe en su navegador (GitHub, Vercel, Azure). Donde no hay login por dispositivo, devuelve el comando de terminal o la variable de entorno que tiene que cargar el operador.",
    parameters: { type: "object", properties: { plataforma: { type: "string", enum: names() } }, required: ["plataforma"] },
    execute: async (params, signal): Promise<ToolResult> => {
      const spec = platform(params.plataforma);
      const state = await platformState(spec, signal);
      if (!state.installed) return { text: `${spec.label}: falta instalar ${spec.binary}. ${spec.install}`, details: { estado: "sin instalar" } };
      if (state.linked) return { text: `${spec.label} ya está vinculada${state.account ? ` (${state.account})` : ""}.`, details: { estado: "vinculada" } };
      const manual = `El operador la vincula en su terminal con: /${spec.name} en la TUI (o cyber ${spec.name})${spec.env.length ? `, o definiendo ${spec.env.filter((name) => /TOKEN|KEY|PROFILE|CONFIG/.test(name)).slice(0, 3).join(" / ") || spec.env[0]} antes de abrir cyber` : ""}. Las credenciales nunca se pegan en el chat.`;
      if (!spec.device) return { text: `${spec.label} no tiene login por dispositivo. ${manual}`, details: { estado: "manual" } };
      const { child, found, output } = await startDevice(spec, signal);
      if (!found.url) {
        child.kill("SIGTERM");
        return { text: `No pude iniciar el login por dispositivo de ${spec.label}: ${redactSecrets(output()).trim().slice(-300) || "sin salida"}. ${manual}`, details: { estado: "falló" } };
      }
      return {
        text: `Para vincular ${spec.label}: abrí ${found.url}${found.code ? ` e ingresá el código ${found.code}` : ""}, y aprobá el acceso. Queda esperando hasta 15 minutos; después confirmá con platform_status.`,
        details: { estado: "esperando aprobación", url: found.url },
      };
    },
  };

  const run: Tool = {
    name: "platform_cli",
    label: "CLI de plataforma",
    description:
      "Corre la CLI oficial de una plataforma vinculada (GitHub gh, Vercel, Supabase, AWS, Google Cloud gcloud, Azure az, Cloudflare wrangler, Kubernetes kubectl) con argumentos en lista, sin shell, en la carpeta del proyecto y con la sesión del operador. " +
      "Leer (list, view, describe, get, logs, clone, download, gh api con GET) corre directo. Crear o cambiar algo (deploy, create, push, api POST/PATCH) necesita «pedido»: la frase textual del operador que lo pidió en esta sesión. " +
      "Borrar, imprimir o exportar credenciales, y lo interactivo o que queda corriendo, no corren nunca. La salida llega con los secretos ocultos y completa como artefacto.",
    parameters: {
      type: "object",
      properties: {
        plataforma: { type: "string", enum: names() },
        args: { type: "array", items: { type: "string" }, description: "Argumentos sin el nombre del binario, p. ej. [\"repo\",\"clone\",\"dueño/repo\",\"repos/repo\"]" },
        pedido: { type: "string", description: "Para una escritura: cita textual del mensaje del operador que la pide" },
        timeoutSec: { type: "integer", minimum: 5, maximum: 900, description: "Por defecto 120" },
      },
      required: ["plataforma", "args"],
    },
    execute: async (params, signal): Promise<ToolResult> => {
      const spec = platform(params.plataforma);
      const args = (params.args ?? []) as string[];
      const verdict = classify(spec, args, context.cwd);
      let quote: string | undefined;
      if (verdict.kind === "escritura") quote = operatorQuote(context.operatorTexts(), params.pedido, `${spec.binary} ${verdict.words.join(" ")}`);
      const { env, known } = platformEnv(spec);
      const timeoutMs = Math.min(900, Math.max(5, Number(params.timeoutSec) || 120)) * 1000;
      const binary = findBinary(spec.binary);
      if (!binary) throw new Error(`${spec.binary} no está instalado. Instalarlo: ${spec.install}`);
      const result = await exec({ argv: [binary, ...args], cwd: context.cwd, env, timeoutMs, maxOutputBytes: 2_000_000, signal });
      const clean = (text: string) => redactSecrets(text.replace(/\u001b\[[0-9;]*[A-Za-z]/g, ""), known);
      const stdout = clean(result.stdout);
      const stderr = clean(result.stderr);
      const artifact = context.artifacts.put(JSON.stringify({ plataforma: spec.name, argv: [spec.binary, ...args].map((arg) => clean(arg)), tipo: verdict.kind, pedido: quote, exitCode: result.exitCode, timedOut: result.timedOut, stdout, stderr }, null, 1), "application/json", `plataforma:${spec.name}`);
      const state = result.cancelled ? "cancelado" : result.timedOut ? `cortado a los ${timeoutMs / 1000} s` : `salida ${result.exitCode}`;
      const head = `$ ${spec.binary} ${args.map((arg) => (/\s/.test(arg) ? JSON.stringify(arg) : arg)).join(" ")}  (${verdict.kind} · ${state} · ${(result.durationMs / 1000).toFixed(1)} s · artefacto ${artifact.hash.slice(0, 19)})`;
      // Algunas CLIs (Vercel, Supabase) escriben el resultado en stderr: si stdout viene vacío, ése es el cuerpo.
      const main = stdout.trim() ? stdout : stderr;
      const body = main.length > 6000 ? `${main.slice(0, 6000)}\n… (${main.length} caracteres; completo en el artefacto)` : main;
      const errors = stdout.trim() && stderr.trim() ? `\n[stderr]\n${stderr.trim().slice(-1500)}` : "";
      return { text: `${head}\n${body.trim()}${errors}`, details: { plataforma: spec.name, tipo: verdict.kind, salida: result.exitCode, artefacto: artifact.hash } };
    },
  };

  return [status, link, run];
}

/** orobas-sec login <plataforma>: el login interactivo de la propia CLI, con la terminal del operador. */
export function terminalLogin(name: string): number {
  const spec = platform(name);
  if (!spec.terminal) throw new Error(`${spec.label} no tiene login interactivo: se vincula con ${spec.env.join(" / ") || "su configuración"}.`);
  const { env } = platformEnv(spec);
  const binary = findBinary(spec.binary);
  if (!binary) throw new Error(`${spec.binary} no está instalado. Instalarlo: ${spec.install}`);
  const result = spawnSync(binary, spec.terminal(), { stdio: "inherit", env });
  if (result.error) throw new Error(`No se pudo correr ${spec.binary}: ${result.error.message}. Instalarlo: ${spec.install}`);
  return result.status ?? 1;
}

export async function platformStatusLines(): Promise<string[]> {
  const states = await Promise.all(platforms().map(async (spec) => ({ spec, state: await platformState(spec) })));
  return states.map(({ spec, state }) =>
    `${spec.name.padEnd(11)} ${!state.installed ? `✗ ${spec.binary} no instalado · ${spec.install}` : state.linked ? `✓ vinculada${state.account ? ` · ${state.account}` : ""}` : state.linked === false ? `· sin vincular · ${spec.terminal ? `cyber ${spec.name}` : `definí ${spec.env[0] ?? "su configuración"}`}` : `✓ ${spec.binary}`}`);
}

/** Cierra la sesión de la CLI y borra su carpeta de sesión del HOME aislado; devuelve lo que hizo. */
export async function revokePlatform(name: string): Promise<string[]> {
  const spec = platform(name);
  const lines: string[] = [];
  const binary = findBinary(spec.binary);
  if (binary && spec.logout) {
    const { env } = platformEnv(spec);
    const result = await exec({ argv: [binary, ...spec.logout], env, timeoutMs: 30_000, maxOutputBytes: 20_000 });
    lines.push(result.exitCode === 0 ? t(`${spec.label}: sesión cerrada.`, `${spec.label}: signed out.`) : t(`${spec.label}: el cierre de sesión de la CLI falló (salida ${result.exitCode}).`, `${spec.label}: the CLI sign-out failed (exit ${result.exitCode}).`));
  }
  // Sólo en el HOME aislado: en la instalación nativa esas carpetas son del usuario (p. ej. ~/.kube) y no se tocan.
  const home = platformsHome();
  if (home) {
    for (const dir of spec.session ?? []) rmSync(join(home, dir), { recursive: true, force: true });
    lines.push(t(`${spec.label}: sesión borrada de esta máquina.`, `${spec.label}: session deleted from this machine.`));
  } else if (!lines.length) lines.push(t(`${spec.label}: su sesión es la de su propia CLI; cerrala con ella.`, `${spec.label}: its session belongs to its own CLI; sign out with it.`));
  return lines;
}
