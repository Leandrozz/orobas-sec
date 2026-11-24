import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { t } from "../src/idioma.ts";
import { deleteSecret, forgetKey, readSecret, secretsKey, writeSecret } from "../src/secretos.ts";

const saved = { ...process.env };
const key = () => randomBytes(32).toString("base64");

beforeEach(() => {
  process.env.CYBER_CREDENTIALS_DIR = mkdtempSync(join(tmpdir(), "cred-"));
  // PATH vacío: el secret-tool real de la máquina nunca se toca.
  process.env.PATH = mkdtempSync(join(tmpdir(), "path-"));
  process.env.CYBER_SECRETS_KEY = key();
});
afterEach(() => {
  process.env = { ...saved };
});

test("t(): español con LANG=es, inglés si no", () => {
  delete process.env.LC_ALL;
  delete process.env.LC_MESSAGES;
  process.env.LANG = "es_AR.UTF-8";
  assert.equal(t("hola", "hello"), "hola");
  process.env.LANG = "en_US.UTF-8";
  assert.equal(t("hola", "hello"), "hello");
});

test("con llave: cifrado, 0600 y se lee de vuelta", () => {
  const r = writeSecret("orobas", "oro_abc");
  assert.equal(r.encrypted, true);
  assert.ok(!readFileSync(r.path, "utf8").includes("oro_abc"));
  assert.equal(statSync(r.path).mode & 0o777, 0o600);
  assert.equal(readSecret("orobas"), "oro_abc");
});

test("otra llave: readSecret devuelve undefined sin lanzar", () => {
  writeSecret("orobas", "oro_abc");
  process.env.CYBER_SECRETS_KEY = key();
  assert.equal(readSecret("orobas"), undefined);
});

test("sin llave ni secret-tool: texto plano 0600", () => {
  process.env.CYBER_SECRETS_KEY = "";
  const r = writeSecret("orobas", "oro_abc");
  assert.equal(r.encrypted, false);
  assert.equal(statSync(r.path).mode & 0o777, 0o600);
  assert.equal(readSecret("orobas"), "oro_abc");
});

test("deleteSecret borra el archivo", () => {
  const r = writeSecret("orobas", "oro_abc");
  deleteSecret("orobas");
  assert.ok(!existsSync(r.path));
  assert.equal(readSecret("orobas"), undefined);
});

test("llave mal formada: writeSecret lanza y no escribe nada", () => {
  for (const bad of [randomBytes(16).toString("base64"), "!!!no-es-base64!!!", `${key()}x`]) {
    process.env.CYBER_SECRETS_KEY = bad;
    assert.throws(() => writeSecret("orobas", "oro_abc"), (e: Error) => !e.message.includes(bad));
    assert.deepEqual(readdirSync(process.env.CYBER_CREDENTIALS_DIR!), []);
  }
});

test("temporal viejo 0644: el final queda 0600 y no sobra ningún .tmp", () => {
  const tmp = join(process.env.CYBER_CREDENTIALS_DIR!, `orobas.secreto.${process.pid}.tmp`);
  writeFileSync(tmp, "viejo", { mode: 0o644 });
  const r = writeSecret("orobas", "oro_abc");
  assert.equal(statSync(r.path).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(process.env.CYBER_CREDENTIALS_DIR!), ["orobas.secreto"]);
  assert.equal(readSecret("orobas"), "oro_abc");
});

test("apiKey: el almacén sirve de respaldo y el entorno gana", async () => {
  const { apiKey } = await import("../src/providers.ts");
  delete process.env.OROBAS_API_KEY;
  writeSecret("orobas", "oro_x");
  assert.equal(apiKey("OROBAS_API_KEY"), "oro_x");
  process.env.OROBAS_API_KEY = "oro_env";
  assert.equal(apiKey("OROBAS_API_KEY"), "oro_env");
});

test("resolveProvider sin clave no lanza y un turno falla sin requests", async () => {
  const { resolveProvider } = await import("../src/providers.ts");
  const { openAICompletions } = await import("../src/llm.ts");
  delete process.env.OROBAS_API_KEY;
  process.env.LANG = "es_AR.UTF-8";
  delete process.env.LC_ALL;
  delete process.env.LC_MESSAGES;
  const { model } = resolveProvider("orobas/deepseek-v4.1-flash-estandar");
  const realFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => (calls++, new Response("{}"))) as typeof fetch;
  try {
    const r = await openAICompletions({ system: "s", messages: [{ role: "user", content: "hola", at: 0 }], tools: [], model });
    assert.equal(r.stopReason, "error");
    assert.equal(r.errorMessage, "Falta la clave de orobas: usá /orobas");
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("HackerOne: saveCredentials y loadCredentials pasan por el almacén", async () => {
  const h1 = await import("../src/hackerone.ts");
  delete process.env.H1_USERNAME;
  delete process.env.H1_API_TOKEN;
  process.env.LANG = "es_AR.UTF-8";
  delete process.env.LC_ALL;
  delete process.env.LC_MESSAGES;
  assert.match(h1.saveCredentials({ username: "u", token: "tok" }), /cifrado en tu carpeta/);
  assert.deepEqual(h1.loadCredentials(), { username: "u", token: "tok" });
  h1.clearCredentials();
  assert.equal(readSecret("hackerone"), undefined);
});

test("modelLine: sin clave, solo en el almacén y en el entorno", async () => {
  const { modelLine } = await import("../src/providers.ts");
  process.env.LANG = "es_AR.UTF-8";
  delete process.env.LC_ALL;
  delete process.env.LC_MESSAGES;
  delete process.env.OROBAS_API_KEY;
  assert.equal(modelLine("orobas/deepseek-v4.1-flash-estandar"), "✗ orobas/deepseek-v4.1-flash-estandar · Falta la clave de orobas: usá /orobas");
  writeSecret("orobas", "oro_x");
  assert.equal(modelLine("orobas/deepseek-v4.1-flash-estandar"), "✓ orobas/deepseek-v4.1-flash-estandar · clave guardada");
  process.env.OROBAS_API_KEY = "oro_env";
  assert.equal(modelLine("orobas/deepseek-v4.1-flash-estandar"), "✓ orobas/deepseek-v4.1-flash-estandar · clave en $OROBAS_API_KEY presente");
});

test("macOS: la llave va al Llavero con security (por stdin, sin argv) y se lee de vuelta", () => {
  const bin = process.env.PATH!;
  const almacen = join(bin, "almacen");
  const log = join(bin, "argv.log");
  // security simulado: find-generic-password lee el almacén (44 si no hay); -i guarda la llave que recibe por stdin.
  writeFileSync(join(bin, "security"), `#!/bin/sh\necho "$@" >> ${log}\nif [ "$1" = -i ]; then read -r l; echo "\${l##* }" > ${almacen}; exit 0; fi\n[ -f ${almacen} ] && { read -r k < ${almacen}; echo "$k"; exit 0; }; exit 44\n`);
  chmodSync(join(bin, "security"), 0o755);
  Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
  try {
    process.env.CYBER_SECRETS_KEY = "";
    forgetKey();
    assert.equal(writeSecret("orobas", "oro_abc").encrypted, true);
    forgetKey();
    assert.equal(readSecret("orobas"), "oro_abc");
    assert.match(readFileSync(log, "utf8"), /find-generic-password -s elevate-cyber -a llave -w/);
    assert.doesNotMatch(readFileSync(log, "utf8"), new RegExp(readFileSync(almacen, "utf8").trim().replace(/[+/=]/g, ".")));
  } finally {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    forgetKey();
  }
});

test("macOS: si security -i sale con 0 pero no guardó nada, la llave no se da por guardada", () => {
  const bin = process.env.PATH!;
  // «security» que dice haber guardado y no guarda: -i sale con 0 y find sigue sin entrada (44).
  writeFileSync(join(bin, "security"), `#!/bin/sh\nif [ "$1" = -i ]; then cat >/dev/null; exit 0; fi\nexit 44\n`);
  chmodSync(join(bin, "security"), 0o755);
  Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
  try {
    process.env.CYBER_SECRETS_KEY = "";
    forgetKey();
    assert.equal(secretsKey(true), undefined);
  } finally {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    forgetKey();
  }
});
