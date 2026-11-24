import "./datos-tmp.ts";
// La tarifa que muestra la TUI es la que cobra el servicio: se lee de /v1/models, se guarda junto a la
// configuración y la adopta el modelo en uso, también uno que el harness no conocía.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { providerModels, resolveProvider } from "../src/providers.ts";
import { catalogPath, parseCatalog, saveCatalog } from "../src/tarifas.ts";

const withConfig = async (config: object, fn: (dir: string) => Promise<void> | void) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-tarifas-"));
  writeFileSync(join(dir, "config.json"), JSON.stringify(config));
  const prev = { c: process.env.CYBER_CONFIG, m: process.env.CYBER_MODEL, k: process.env.OROBAS_API_KEY };
  process.env.CYBER_CONFIG = join(dir, "config.json");
  delete process.env.CYBER_MODEL;
  process.env.OROBAS_API_KEY = "oro_" + "a".repeat(48);
  try { await fn(dir); } finally {
    for (const [name, value] of [["CYBER_CONFIG", prev.c], ["CYBER_MODEL", prev.m], ["OROBAS_API_KEY", prev.k]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    rmSync(dir, { recursive: true, force: true });
  }
};

test("la lista del servicio se traduce a tarifas del harness; sin precio, costo pendiente", () => {
  const models = parseCatalog([
    { id: "nuevo", name: "Nuevo", kind: "general", context_length: 1_000_000, status: "ok", pricing: { input: 2.7, cached_input: 0.41, output: 5.4 } },
    { id: "sin-precio", context_length: 262_000 },
    { id: "", pricing: { input: 1, output: 1 } },
  ]);
  assert.deepEqual(models.nuevo, { cost: { input: 2.7, output: 5.4, cacheRead: 0.41, cacheWrite: 0 }, contextWindow: 1_000_000, name: "Nuevo", kind: "general", status: "ok" });
  assert.deepEqual(models["sin-precio"], { contextWindow: 262_000 });
  assert.equal(Object.keys(models).length, 2);
});

test("con la copia guardada, un modelo desconocido para el código tiene tarifa y contexto del servicio, y el modelo sin precio queda pendiente", () => withConfig({}, () => {
  saveCatalog("https://cyber.elevateai.ar/api/v1", parseCatalog([
    { id: "nuevo", context_length: 1_000_000, pricing: { input: 2.7, cached_input: 0.41, output: 5.4 } },
    { id: "glm-5.3-flash", context_length: 1_000_000, pricing: { input: 0.7, cached_input: 0.07, output: 2.8 } },
  ]));
  assert.ok(existsSync(catalogPath()) && catalogPath().startsWith(process.env.CYBER_CONFIG!.replace(/config\.json$/, "")), "vive junto a la configuración");
  const nuevo = resolveProvider("orobas/nuevo").model;
  assert.equal(nuevo.cost?.output, 5.4);
  assert.equal(nuevo.contextWindow, 1_000_000);
  assert.equal(nuevo.costSource, "servicio");
  assert.equal(resolveProvider("orobas/glm-5.3-flash").model.cost?.input, 0.7, "el servicio manda sobre el código");
  assert.equal(resolveProvider("orobas/auto").model.cost, undefined, "el servicio no publicó un precio para este modelo");
  assert.equal(resolveProvider("orobas/auto").model.costSource, undefined);
  assert.ok(providerModels("orobas").includes("nuevo"), "y se puede elegir por nombre sin servicio");
}));

test("al arrancar y al listar modelos, el harness pide la lista al servicio, la guarda y el modelo en uso adopta su tarifa", async () => {
  let hits = 0;
  const server = createServer((req, res) => {
    hits++;
    assert.match(req.headers.authorization ?? "", /^Bearer oro_a/);
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ object: "list", data: [
      { id: "auto", name: "auto", kind: "auto", context_length: 524_000, pricing: { input: 1, cached_input: 0.1, output: 4 } },
      { id: "caro", name: "Caro", kind: "general", context_length: 1_000_000, pricing: { input: 4.56, cached_input: 1.12, output: 8.25 } },
    ] }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  await withConfig({ providers: { orobas: { baseUrl: base, apiKeyEnv: "OROBAS_API_KEY" } } }, async (dir) => {
    let engine = new Engine({ cwd: join(dir, "p"), provider: resolveProvider("orobas/auto"), budgetPico: usdToPico("1") });
    try {
      for (const start = Date.now(); !existsSync(catalogPath()) && Date.now() - start < 4000; ) await new Promise((r) => setTimeout(r, 10));
      assert.ok(existsSync(catalogPath()), "al arrancar sin copia, la pide en segundo plano");
      assert.equal(hits, 1);
      const saved = JSON.parse(readFileSync(catalogPath(), "utf8"));
      assert.equal(saved.models.caro.cost.cacheRead, 1.12);

      // Cambiar al modelo caro: la tarifa viene de la copia, y el costo de la sesión se calcula con ella.
      assert.equal(await engine.setModel("caro"), "orobas/caro");
      assert.equal(engine.agent.model.cost?.input, 4.56);
      assert.equal(engine.agent.model.costSource, "servicio");
      assert.equal(engine.agent.model.contextWindow, 1_000_000);
      const { details } = await engine.availableModels();
      assert.equal(details["orobas/caro"]!.price, "4.56 / 1.12 / 8.25");
      engine.close();

      // Con la copia fresca, otro arranque no vuelve a preguntar; el modelo igual adopta la tarifa guardada.
      const before = hits;
      engine = new Engine({ cwd: join(dir, "p2"), provider: resolveProvider("orobas/caro"), budgetPico: usdToPico("1") });
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(hits, before);
      assert.equal(engine.agent.model.cost?.output, 8.25);
    } finally { engine.close(); server.close(); }
  });
});
