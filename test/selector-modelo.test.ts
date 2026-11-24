import "./datos-tmp.ts";
// /modelo: lista lo que la cuenta puede usar, cambia el modelo de la sesión en caliente (también
// pedido hablando) y lo conserva al retomar. Los nombres no dicen qué proveedor hay detrás.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine, pickModel } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { configureAliases, resolveProvider } from "../src/providers.ts";

// Nombres anteriores de ejemplo (la tabla real se prueba en alias-orobas-privado.test.ts, que no se publica).
configureAliases({ "viejo-flash-libre": "deepseek-v4.1-flash", "viejo-flash": "deepseek-v4.1-flash-estandar" });

const NEW = ["auto", "deepseek-v4.1-flash", "deepseek-v4.1-flash-estandar", "glm-5.3-flash", "qwen3.8-27b"].map((id) => `orobas/${id}`);

test("nombre corto o completo; uno que la cuenta no tiene se rechaza", () => {
  assert.equal(pickModel("glm", NEW, "orobas/auto"), "orobas/glm-5.3-flash");
  assert.equal(pickModel("qwen", NEW, "orobas/auto"), "orobas/qwen3.8-27b");
  assert.equal(pickModel("deepseek", NEW, "orobas/auto"), "orobas/deepseek-v4.1-flash", "el más corto");
  assert.equal(pickModel("estandar", NEW, "orobas/auto"), "orobas/deepseek-v4.1-flash-estandar");
  assert.equal(pickModel("orobas/auto", NEW, "orobas/glm-5.3-flash"), "orobas/auto");
  assert.throws(() => pickModel("glm", ["orobas/deepseek-v4.1-flash"], "orobas/deepseek-v4.1-flash"), /No hay un modelo «glm»\. Disponibles: deepseek-v4\.1-flash/);
  assert.throws(() => pickModel("orobas/glm-5.3-flash", ["orobas/deepseek-v4.1-flash"], "orobas/deepseek-v4.1-flash"), /No hay un modelo «orobas\/glm-5\.3-flash»\. Disponibles: deepseek-v4\.1-flash/);
});

test("un nombre viejo de la configuración se traduce al nombre propio", () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-alias-"));
  const prev = { c: process.env.CYBER_CONFIG, k: process.env.OROBAS_API_KEY };
  writeFileSync(join(dir, "config.json"), JSON.stringify({ defaultModel: "orobas/viejo-flash" }));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  process.env.OROBAS_API_KEY = "oro_prueba";
  try {
    assert.equal(resolveProvider().model.id, "deepseek-v4.1-flash-estandar");
    assert.equal(resolveProvider("orobas/viejo-flash-libre").model.id, "deepseek-v4.1-flash");
    assert.equal(resolveProvider("orobas/deepseek-v4.1-flash-estandar").model.cost, undefined);
  } finally {
    if (prev.c === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev.c;
    if (prev.k === undefined) delete process.env.OROBAS_API_KEY; else process.env.OROBAS_API_KEY = prev.k;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("/modelo y «pasate a GLM»: lista de la cuenta, cambio en caliente, razonamiento conservado y retomado", async () => {
  // Servicio falso: con la clave del equipo, sólo los abiertos; con la completa, todos.
  const server = createServer((req, res) => {
    const all = req.headers.authorization === "Bearer oro_completa";
    const ids = all ? ["auto", "deepseek-v4.1-flash", "glm-5.3-flash", "qwen3.8-27b", "deepseek-v4.1-flash-estandar"] : ["deepseek-v4.1-flash", "deepseek-v4.1-flash-estandar"];
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ object: "list", data: ids.map((id) => ({ id })) }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-selector-"));
  const cwd = join(dir, "proyecto");
  const prev = { c: process.env.CYBER_CONFIG, k: process.env.OROBAS_API_KEY };
  writeFileSync(join(dir, "config.json"), JSON.stringify({ providers: { orobas: { baseUrl: base, apiKeyEnv: "OROBAS_API_KEY" } } }));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  let engine: Engine | undefined;
  try {
    process.env.OROBAS_API_KEY = "oro_equipo";
    engine = new Engine({ cwd, provider: resolveProvider("orobas/deepseek-v4.1-flash-estandar"), budgetPico: usdToPico("1") });
    const team = await engine.availableModels();
    assert.deepEqual(team.models, ["orobas/deepseek-v4.1-flash", "orobas/deepseek-v4.1-flash-estandar"]);
    await assert.rejects(() => engine!.setModel("glm"), /No hay un modelo «glm»/);
    engine.close();

    process.env.OROBAS_API_KEY = "oro_completa";
    engine = new Engine({ cwd, provider: resolveProvider("orobas/auto"), budgetPico: usdToPico("1") });
    const shared = engine.agent.model;
    engine.setReasoning(true);
    assert.equal(await engine.setModel("glm"), "orobas/glm-5.3-flash");
    assert.equal(engine.agent.model, shared, "el mismo objeto: subagentes y verificador ven el cambio");
    assert.equal(engine.agent.model.id, "glm-5.3-flash");
    assert.equal(engine.agent.model.reasoning, true);
    assert.equal(engine.agent.model.cost, undefined);
    assert.equal(engine.provider.model.id, "glm-5.3-flash");

    // Retomar la sesión recupera el modelo elegido.
    const session = engine.sessionId;
    engine.close();
    engine = new Engine({ cwd, provider: resolveProvider("orobas/auto"), budgetPico: usdToPico("1"), resume: session });
    assert.equal(engine.agent.model.id, "glm-5.3-flash");
  } finally {
    engine?.close();
    server.close();
    if (prev.c === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev.c;
    if (prev.k === undefined) delete process.env.OROBAS_API_KEY; else process.env.OROBAS_API_KEY = prev.k;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hablando: cambiar de modelo exige que el operador lo haya nombrado", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-selector-ln-"));
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("1") });
  const asked: string[] = [];
  // El cambio real lo prueba el test anterior; acá sólo la autorización del pedido.
  (engine as unknown as { setModel: (w: string) => Promise<string> }).setModel = async (wanted) => { asked.push(wanted); return `orobas/${wanted}`; };
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  try {
    provider.faux!.queue = [
      call("tools_load", { names: ["session_settings"] }),
      call("session_settings", { modelo: "qwen", pedido: "pasate a GLM que es más barato" }),
      call("session_settings", { modelo: "glm", pedido: "pasate a GLM que es más barato" }),
      { text: "listo" },
    ];
    await engine.send("Pasate a GLM que es más barato");
    const results = engine.agent.messages.filter((m) => m.role === "tool").map((m) => m.content as string);
    assert.match(results[1]!, /Cambiar de modelo exige que el operador lo haya nombrado \(«qwen»\)/);
    assert.match(results[2]!, /Cambiado: modelo/);
    assert.deepEqual(asked, ["glm"]);
  } finally {
    engine.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
