import { join } from "node:path";

export interface CveCommandOptions {
  root: string;
  caso: string;
  port: number;
  bind: string;
  publicHost: string;
  correctedImage?: string;
  sshHost?: string;
  remoteDir?: string;
}

export interface CveCommand {
  file: string;
  args: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

/** Host listo para una URL: una IPv6 va entre corchetes. */
export function urlHost(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

/** Interfaces que escuchan en todas partes: no sirven como host de la URL. */
export function isWildcard(host: string): boolean {
  return host === "0.0.0.0" || host === "::" || host === "[::]";
}

/**
 * Endpoint de Docker que no está en esta máquina (ssh://, tcp:// o http(s):// a otro host).
 * Los Compose montan archivos del caso: con un daemon remoto se resolverían en el disco remoto.
 */
export function isRemoteDockerEndpoint(endpoint: string | undefined): boolean {
  const value = endpoint?.trim();
  if (!value) return false;
  if (/^(unix|npipe):\/\//i.test(value)) return false;
  if (/^ssh:\/\//i.test(value)) return true;
  const match = /^(?:tcp|https?):\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^:/]+)/i.exec(value);
  if (!match) return false;
  const host = match[1]!.replace(/^\[|\]$/g, "").toLowerCase();
  return !(host === "localhost" || host === "::1" || host.startsWith("127."));
}

/**
 * Contenedores con problemas según `docker compose ps -a --format json` (un arreglo o una línea JSON por contenedor):
 * salidos con código distinto de 0 o corriendo sin estar sanos.
 */
export function composeProblems(raw: string): string[] {
  const text = raw.trim();
  if (!text) return [];
  let rows: Array<Record<string, unknown>>;
  try {
    rows = text.startsWith("[") ? JSON.parse(text) : text.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
  } catch {
    return [`salida de compose ps ilegible: ${text.slice(0, 200)}`];
  }
  return rows
    .filter((r) => (r.State === "exited" && Number(r.ExitCode ?? 0) !== 0) || (r.State === "running" && ![undefined, null, "", "healthy"].includes(r.Health as string)))
    .map((r) => `${r.Name}:${r.State}:${r.ExitCode ?? ""}:${r.Health ?? ""}`);
}

/** Variables del entorno local que cambiarían qué Compose o qué imagen corre sin que el runner lo sepa. */
function cleanEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(env)) {
    if (name.startsWith("COMPOSE_") || name.startsWith("CVE_")) continue;
    out[name] = value;
  }
  return out;
}

/** Arma la misma orden para Docker local o, si se pidió, para un host SSH. */
export function cveCommand(options: CveCommandOptions, command: string): CveCommand {
  const variables: Record<string, string> = {
    COMPOSE_PROJECT_NAME: `elevate-runner-${options.caso.toLowerCase()}`,
    CVE_PORT: String(options.port),
    CVE_BIND: options.bind,
    CVE_HOST: options.publicHost,
    CVE_PUBLIC_URL: `http://${urlHost(options.publicHost)}:${options.port}/`,
  };
  if (options.correctedImage) variables.CVE_IMAGE = options.correctedImage;

  if (!options.sshHost) {
    return {
      file: "sh", args: ["-c", command],
      cwd: join(options.root, "bench", "cve", options.caso),
      env: { ...cleanEnv(process.env), ...variables },
    };
  }
  if (options.sshHost.startsWith("-")) throw new Error("CYBER_CVE_SSH no puede empezar con «-»");
  if (!options.remoteDir) throw new Error("Falta la carpeta remota para el modo SSH");
  const remoteCase = join(options.remoteDir, "bench", "cve", options.caso);
  const exports = Object.entries(variables).map(([name, value]) => `${name}=${quote(value)}`).join(" ");
  return {
    file: "ssh",
    args: ["-o", "BatchMode=yes", options.sshHost, `cd ${quote(remoteCase)} && export ${exports} && ${command}`],
  };
}
