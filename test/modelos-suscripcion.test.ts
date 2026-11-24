import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { configureAliases, resolveProvider } from "../src/providers.ts";

// La tabla real de nombres anteriores se prueba en alias-orobas-privado.test.ts (no se publica):
// acá, una tabla propia con nombres de ejemplo, para que la prueba no dependa de ella.
configureAliases({ "viejo-flash-libre": "deepseek-v4.1-flash", "viejo-flash": "deepseek-v4.1-flash-estandar" });

// Configuración vieja de orobas: elige por defecto un modelo con el nombre anterior.
function withConfig(config: object, fn: () => void) {
  const dir = mkdtempSync(join(tmpdir(), "cyber-modelos-"));
  const path = join(dir, "config.json");
  writeFileSync(path, JSON.stringify(config));
  const prev = { c: process.env.CYBER_CONFIG, m: process.env.CYBER_MODEL, k: process.env.OROBAS_API_KEY };
  process.env.CYBER_CONFIG = path;
  delete process.env.CYBER_MODEL;
  process.env.OROBAS_API_KEY = "oro_prueba";
  try { fn(); } finally {
    for (const [name, value] of [["CYBER_CONFIG", prev.c], ["CYBER_MODEL", prev.m], ["OROBAS_API_KEY", prev.k]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
}
const vieja = {
  defaultModel: "orobas/viejo-flash",
  providers: { orobas: { baseUrl: "https://cyber.elevateai.ar/api/v1", apiKeyEnv: "OROBAS_API_KEY", models: { "viejo-flash": { contextWindow: 1048576 } } } },
};

test("una configuración vieja sigue en su modelo, con el nombre propio, y sin catálogo deja el costo pendiente", () => withConfig(vieja, () => {
  const p = resolveProvider();
  assert.equal(p.model.id, "deepseek-v4.1-flash-estandar", "el nombre viejo se traduce: el proveedor no aparece");
  assert.equal(p.model.cost, undefined);
  const auto = resolveProvider("orobas/auto");
  assert.equal(auto.model.cost, undefined);
  assert.equal(auto.model.contextWindow, 524288);
  for (const id of ["deepseek-v4.1-flash", "glm-5.3-flash", "qwen3.8-27b"]) assert.equal(resolveProvider(`orobas/${id}`).model.cost, undefined);
}));

test("la tarifa que el usuario configuró bajo el alias se conserva con el nombre actual", () => {
  const cost = { input: 1, output: 4, cacheRead: 0.1, cacheWrite: 0 };
  const orobas = vieja.providers.orobas;
  const models = { "viejo-flash": { cost } };
  withConfig({ ...vieja, providers: { orobas: { ...orobas, models } } }, () => {
    const model = resolveProvider("orobas/deepseek-v4.1-flash-estandar").model;
    assert.deepEqual(model.cost, cost);
    assert.equal(model.costSource, "configuración");
  });
});

test("pedido con -m, el nombre viejo también se traduce", () => withConfig(vieja, () => {
  assert.equal(resolveProvider("orobas/viejo-flash").model.id, "deepseek-v4.1-flash-estandar");
  assert.equal(resolveProvider("orobas/viejo-flash-libre").model.id, "deepseek-v4.1-flash");
}));

test("un defaultModel elegido a mano no se toca", () => withConfig({ ...vieja, defaultModel: "orobas/qwen3.8-27b" }, () => {
  assert.equal(resolveProvider().model.id, "qwen3.8-27b");
}));

function conBase(base: object | undefined, user: object | undefined, fn: () => void) {
  const dir = mkdtempSync(join(tmpdir(), "cyber-base-"));
  const prev = { c: process.env.CYBER_CONFIG, b: process.env.CYBER_CONFIG_BASE, m: process.env.CYBER_MODEL };
  process.env.CYBER_CONFIG = join(dir, "user.json");
  delete process.env.CYBER_MODEL;
  if (base) writeFileSync(join(dir, "base.json"), JSON.stringify(base));
  if (user) writeFileSync(process.env.CYBER_CONFIG, JSON.stringify(user));
  if (base) process.env.CYBER_CONFIG_BASE = join(dir, "base.json"); else delete process.env.CYBER_CONFIG_BASE;
  try { fn(); } finally {
    for (const [name, value] of [["CYBER_CONFIG", prev.c], ["CYBER_CONFIG_BASE", prev.b], ["CYBER_MODEL", prev.m]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
}
const base = { defaultModel: "x/a", providers: { x: { baseUrl: "http://base", models: { a: { contextWindow: 1000 }, b: { contextWindow: 2000 } } } } };

test("CYBER_CONFIG_BASE: la base sola sirve", () => conBase(base, undefined, () => {
  const p = resolveProvider();
  assert.equal(p.model.id, "a");
  assert.equal(p.model.baseUrl, "http://base");
}));

test("CYBER_CONFIG_BASE: el usuario gana por proveedor y por modelo, y la base completa lo que falta", () => conBase(base, { defaultModel: "x/b", providers: { x: { baseUrl: "http://user", models: { a: { contextWindow: 5 } } } } }, () => {
  const p = resolveProvider();
  assert.equal(p.model.id, "b");
  assert.equal(p.model.baseUrl, "http://user");
  assert.equal(p.model.contextWindow, 2000, "el modelo que solo está en la base sigue");
  assert.equal(resolveProvider("x/a").model.contextWindow, 5);
}));

test("sin CYBER_CONFIG_BASE, solo la del usuario; una base ilegible da el error claro", () => {
  conBase(undefined, base, () => assert.equal(resolveProvider().model.baseUrl, "http://base"));
  conBase(base, undefined, () => {
    writeFileSync(process.env.CYBER_CONFIG_BASE!, "{no");
    assert.throws(() => resolveProvider(), /Configuración inválida en .*base\.json/);
  });
});

test("una configuración con BOM (Notepad) se lee", () => conBase(undefined, undefined, () => {
  writeFileSync(process.env.CYBER_CONFIG!, "\uFEFF" + JSON.stringify(base));
  assert.equal(resolveProvider().model.baseUrl, "http://base");
}));

test("una base de sólo lectura (la de la imagen) aporta proveedores y modelo; lo del operador va encima y lo que se guarda va a su archivo", async () => {
  const { chmodSync, existsSync, readFileSync } = await import("node:fs");
  const { inicioDone, markInicio, resetInicio } = await import("../src/inicio.ts");
  const dir = mkdtempSync(join(tmpdir(), "cyber-base-"));
  const base = join(dir, "base.json");
  writeFileSync(base, JSON.stringify({ defaultModel: "orobas/deepseek-v4.1-flash-estandar", providers: { orobas: { baseUrl: "https://cyber.elevateai.ar/api/v1", apiKeyEnv: "OROBAS_API_KEY" } } }));
  chmodSync(base, 0o444);
  const own = join(dir, "usuario", "config.json");
  const prev = { b: process.env.CYBER_CONFIG_BASE, c: process.env.CYBER_CONFIG, m: process.env.CYBER_MODEL, k: process.env.OROBAS_API_KEY };
  process.env.CYBER_CONFIG_BASE = base;
  process.env.CYBER_CONFIG = own;
  delete process.env.CYBER_MODEL;
  process.env.OROBAS_API_KEY = "oro_prueba";
  try {
    assert.equal(resolveProvider().model.id, "deepseek-v4.1-flash-estandar", "sin archivo propio, manda la base");
    markInicio();
    assert.ok(existsSync(own), "el inicio se marca en el archivo del operador");
    assert.ok(inicioDone());
    assert.equal(JSON.parse(readFileSync(base, "utf8")).inicio, undefined, "la base no se toca");
    writeFileSync(own, JSON.stringify({ ...JSON.parse(readFileSync(own, "utf8")), defaultModel: "orobas/auto" }));
    assert.equal(resolveProvider().model.id, "auto", "lo propio pisa la base");
    assert.equal(resolveProvider().model.baseUrl, "https://cyber.elevateai.ar/api/v1", "y conserva el proveedor de la base");
    resetInicio();
    // Si el archivo del operador no se puede escribir, el error dice dónde, sin pila.
    process.env.CYBER_CONFIG = base;
    assert.throws(() => markInicio(), /No puedo guardar la configuración en .*base\.json/);
  } finally {
    for (const [name, value] of [["CYBER_CONFIG_BASE", prev.b], ["CYBER_CONFIG", prev.c], ["CYBER_MODEL", prev.m], ["OROBAS_API_KEY", prev.k]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});
