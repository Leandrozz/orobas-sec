// Secretos en la carpeta de credenciales del usuario, cifrados con AES-256-GCM cuando hay llave.
import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { t } from "./idioma.ts";

const KEYRING = ["service", "elevate-cyber", "account", "llave"];

export function credentialsDir(): string {
  const dir = process.env.CYBER_CREDENTIALS_DIR || join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "elevate-cyber");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700); // también si ya existía con otros permisos
  } catch {}
  return dir;
}

const file = (name: string) => join(credentialsDir(), `${name}.secreto`);
const asKey = (b64: string): Buffer | undefined => {
  const key = Buffer.from(b64.trim(), "base64");
  // Node ignora caracteres inválidos al decodificar: se exige que re-codifique idéntico.
  return key.length === 32 && key.toString("base64") === b64.trim() ? key : undefined;
};

let cached: Buffer | undefined;
/** Para las pruebas: olvida la llave del llavero que quedó en memoria. */
export const forgetKey = () => {
  cached = undefined;
};
const lockedError = () => new Error(t("tu clave está cifrada y no tengo la llave del llavero; desbloquealo o borrá la cuenta con Revocar", "your key is encrypted and I do not have the keyring key; unlock it or delete the account with Revoke"));

/** Llavero de macOS: mismo servicio y cuenta que el lanzador. `security find` sale con 44 si no hay entrada. */
function darwinKey(create: boolean): Buffer | undefined {
  const found = spawnSync("security", ["find-generic-password", "-s", "elevate-cyber", "-a", "llave", "-w"], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] });
  if ((found.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") return undefined;
  if (found.error || (found.status !== 0 && found.status !== 44)) throw new Error(t("el llavero no respondió; desbloquealo y reintentá", "the keyring did not answer; unlock it and retry"));
  if (found.status === 0 && found.stdout.trim()) return (cached = asKey(found.stdout));
  if (!create) return undefined;
  const fresh = randomBytes(32).toString("base64");
  // Por stdin (security -i) para que la llave no quede en argv; el base64 no tiene comillas ni espacios.
  const stored = spawnSync("security", ["-i"], { input: `add-generic-password -U -s elevate-cyber -a llave -w ${fresh}\n`, timeout: 3000, stdio: ["pipe", "ignore", "ignore"] });
  // «security -i» puede salir con 0 aunque el comando falle: se relee y se compara, como el lanzador sh.
  const back = stored.status === 0 ? spawnSync("security", ["find-generic-password", "-s", "elevate-cyber", "-a", "llave", "-w"], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] }) : undefined;
  return back?.status === 0 && back.stdout.trim() === fresh ? (cached = asKey(fresh)) : undefined;
}

/** CYBER_SECRETS_KEY (base64 de 32 bytes) o el llavero nativo. Solo con `create` se genera una llave nueva: leer nunca la inventa. Lanza si el llavero falla por otra razón que «no hay entrada». */
export function secretsKey(create = false): Buffer | undefined {
  if (process.env.CYBER_SECRETS_KEY) {
    // La llave la puso el lanzador a propósito: si está mal, no se degrada a texto plano.
    const key = asKey(process.env.CYBER_SECRETS_KEY);
    if (!key) throw new Error(t("CYBER_SECRETS_KEY no es una llave válida (base64 de 32 bytes)", "CYBER_SECRETS_KEY is not a valid key (base64 of 32 bytes)"));
    return key;
  }
  if (cached) return cached;
  if (process.platform === "darwin") return darwinKey(create);
  const found = spawnSync("secret-tool", ["lookup", ...KEYRING], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] });
  if ((found.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") return undefined; // sin secret-tool no hay llavero
  // Sin entrada, secret-tool sale con 1 y sin salida; cualquier otra cosa (tiempo agotado, llavero bloqueado) no autoriza a inventar otra llave.
  if (found.error || (found.status !== 0 && found.status !== 1)) throw new Error(t("el llavero no respondió; desbloquealo y reintentá", "the keyring did not answer; unlock it and retry"));
  if (found.status === 0 && found.stdout.trim()) return (cached = asKey(found.stdout));
  if (!create) return undefined;
  const fresh = randomBytes(32).toString("base64");
  const stored = spawnSync("secret-tool", ["store", "--label", "Elevate AI Cyber · llave", ...KEYRING], { input: fresh, timeout: 3000, stdio: ["pipe", "ignore", "ignore"] });
  return stored.status === 0 ? (cached = asKey(fresh)) : undefined;
}

const read = (name: string): { plano?: string; iv?: string; tag?: string; data?: string } | undefined => {
  try {
    return JSON.parse(readFileSync(file(name), "utf8"));
  } catch {
    return undefined;
  }
};

export function writeSecret(name: string, value: string, options: { requireEncryption?: boolean } = {}): { encrypted: boolean; path: string } {
  const before = read(name);
  const wasEncrypted = typeof before?.iv === "string";
  const key = secretsKey(!wasEncrypted); // sobre un cifrado no se inventa una llave nueva
  if (options.requireEncryption && !key) throw new Error(t("Necesito el llavero o CYBER_SECRETS_KEY para guardar esta sesión cifrada.", "A keyring or CYBER_SECRETS_KEY is required to store this session encrypted."));
  // Un archivo cifrado sin llave no se pisa con texto plano: se perdería sin remedio.
  if (wasEncrypted && !key) throw lockedError();
  let body: object = { v: 1, plano: value };
  if (key) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    body = { v: 1, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
  }
  const path = file(name);
  const tmp = `${path}.${process.pid}.tmp`;
  // Un temporal viejo (pid reciclado) conservaría sus permisos: se borra y se crea exclusivo 0600.
  try {
    unlinkSync(tmp);
  } catch {}
  try {
    writeFileSync(tmp, JSON.stringify(body), { mode: 0o600, flag: "wx" });
    renameSync(tmp, path);
  } finally {
    try {
      unlinkSync(tmp);
    } catch {}
  }
  return { encrypted: !!key, path };
}

function decrypt(body: { iv?: string; tag?: string; data?: string }): string | undefined {
  try {
    const key = secretsKey();
    if (!key) return undefined;
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(body.iv!, "base64"));
    decipher.setAuthTag(Buffer.from(body.tag!, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(body.data!, "base64")), decipher.final()]).toString("utf8");
  } catch {
    return undefined;
  }
}

/** «none»: no existe; «ok»: se puede leer; «locked»: existe cifrado y no se puede descifrar (sin llave, llavero bloqueado o llave distinta). */
export function secretState(name: string): "none" | "ok" | "locked" {
  const body = read(name);
  if (!body) return "none";
  if (typeof body.plano === "string") return "ok";
  return decrypt(body) === undefined ? "locked" : "ok";
}

export function readSecret(name: string): string | undefined {
  const body = read(name);
  if (!body) return undefined;
  return typeof body.plano === "string" ? body.plano : decrypt(body);
}

export function deleteSecret(name: string): void {
  try {
    unlinkSync(file(name));
  } catch {}
}
