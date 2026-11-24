import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";

test("cada herramienta propia tiene una sección en el manual", async (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "catalogo-documentado-"));
  const engine = new Engine({
    cwd, provider: resolveProvider("faux"), mcp: {}, cveFeed: false, autoVerify: false, grafo: true,
    // Sólo construimos el catálogo. El constructor comprueba que el ejecutable exista.
    fuzzing: { enCaja: true, binarios: { clang: process.execPath } },
  });
  t.after(async () => { await engine.close(); rmSync(cwd, { recursive: true, force: true }); });
  const registradas = new Set([...engine.agent.tools.map((tool) => tool.name), ...engine.catalog.available.keys()]);
  // Los trabajadores tienen herramientas privadas que se construyen al entrar en cada estado.
  for (const entrada of readdirSync("src", { withFileTypes: true, recursive: true })) {
    if (!entrada.isFile() || !entrada.name.endsWith(".ts")) continue;
    const codigo = readFileSync(join(entrada.parentPath, entrada.name), "utf8");
    for (const declaracion of codigo.matchAll(/:\s*Tool\s*=\s*\{\s*name:\s*"([a-z0-9_]+)"/g)) registradas.add(declaracion[1]!);
  }
  for (const nombre of ["grafo", "fuzz_run", "verdict", "investigation_output"]) assert.ok(registradas.has(nombre), nombre);
  const manual = readFileSync("docs/herramientas.md", "utf8");
  const documentadas = new Set([...manual.matchAll(/^### ([a-z][a-z0-9_]+)\s*$/gm)].map((m) => m[1]));
  assert.deepEqual([...registradas].filter((n) => !documentadas.has(n)).sort(), []);
});
