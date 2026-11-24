// Prueba de punta a punta: el daemon manda el aviso de permiso, la interfaz responde y el comando corre.
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";

test("e2e: el aviso sale al cliente, la respuesta habilita y el comando corre", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-shell-e2e-"));
  const engine = new Engine({ cwd: dir, provider: resolveProvider("faux"), budgetPico: 50_000_000_000n });
  t.after(() => { engine.close?.(); rmSync(dir, { recursive: true, force: true }); });
  const avisos: Array<{ id: number; prefix: string; command: string }> = [];
  engine.onShellAsk = (info) => {
    avisos.push({ id: info.id, prefix: info.prefix, command: info.command });
    // Respondemos como la interfaz, en el siguiente tick.
    setImmediate(() => engine.resolveShell(info.id, "si"));
  };
  const tool = engine.agent.tools.find((item) => item.name === "shell")!;
  // `mkdir` es escritura: pregunta. La lectura simple ya no pregunta.
  const result = await tool.execute({ command: "mkdir salida" }, new AbortController().signal);
  assert.equal(avisos.length, 1, "pidió permiso");
  assert.match(avisos[0]!.command, /mkdir salida/);
  assert.ok(statSync(join(dir, "salida")).isDirectory());
  const lectura = await tool.execute({ command: "ls" }, new AbortController().signal);
  assert.equal(avisos.length, 1, "la lectura no volvió a preguntar");
  assert.match(String(lectura.text), /salida/);
});
