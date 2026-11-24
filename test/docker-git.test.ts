import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveProvider } from "../src/providers.ts";

function withEnv(vars: Record<string, string | undefined>, fn: () => void) {
  const prev = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  try { fn(); } finally {
    for (const [k, v] of Object.entries(prev)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
}
const sinConfig = join(mkdtempSync(join(tmpdir(), "cyber-ollama-")), "no-existe.json");

test("ollama: en el contenedor apunta al host; afuera, a 127.0.0.1", () => {
  withEnv({ CYBER_CONFIG: sinConfig, CYBER_CONFIG_BASE: undefined, CYBER_PROYECTO_HOST: "C:\\proyectos\\x" }, () =>
    assert.equal(resolveProvider("ollama/llama3").model.baseUrl, "http://host.docker.internal:11434/v1"));
  withEnv({ CYBER_CONFIG: sinConfig, CYBER_CONFIG_BASE: undefined, CYBER_PROYECTO_HOST: undefined }, () =>
    assert.equal(resolveProvider("ollama/llama3").model.baseUrl, "http://127.0.0.1:11434/v1"));
});

test("ollama: la baseUrl del usuario gana también en el contenedor", () => {
  const path = join(mkdtempSync(join(tmpdir(), "cyber-ollama-")), "config.json");
  writeFileSync(path, JSON.stringify({ providers: { ollama: { baseUrl: "http://10.0.0.5:11434/v1" } } }));
  withEnv({ CYBER_CONFIG: path, CYBER_CONFIG_BASE: undefined, CYBER_PROYECTO_HOST: "/home/x" }, () =>
    assert.equal(resolveProvider("ollama/llama3").model.baseUrl, "http://10.0.0.5:11434/v1"));
});

test("Dockerfile: safe.directory de todo (nested repos) y Chromium sin /dev/shm; .gitattributes con los fines de línea", () => {
  const docker = readFileSync("distro/Dockerfile", "utf8");
  assert.match(docker, /git config --system --add safe\.directory '\*'/);
  assert.match(docker, /CYBER_CHROMIUM_ARGS="--no-sandbox --disable-dev-shm-usage"/);
  const attrs = readFileSync(".gitattributes", "utf8");
  for (const l of ["bin/cyber text eol=lf", "distro/lanzador/cyber text eol=lf", "*.sh text eol=lf", "*.ps1 -text", "*.cmd -text"]) assert.ok(attrs.includes(l), l);
});
