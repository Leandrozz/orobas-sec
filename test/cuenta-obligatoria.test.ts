import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { accountGate, configureAccount, fetchAccount, requiredLevel } from "../src/cuenta.ts";
import { orobasBaseUrl } from "../src/providers.ts";
import { modoTrazas } from "../src/privacidad-trazas.ts";
import { deleteSecret } from "../src/secretos.ts";

// Regla vigente (22/11/2026): sin verificar se usa todo lo que no es nuestro (modelos locales y cualquier API
// con clave propia, sin cuenta siquiera); la identidad verificada se pide sólo para los modelos de la
// suscripción (proveedor orobas).

const KEY = "oro_" + "a".repeat(48);
const model = (provider: string, baseUrl: string) => ({ provider, baseUrl });
const OROBAS = model("orobas", "https://cyber.elevateai.ar/api/v1");

/** Lo que no es nuestro: locales y APIs compatibles con clave propia, en direcciones oficiales o no. */
const AJENOS = [
  model("ollama", "http://127.0.0.1:11434/v1"),
  model("openai", "http://127.0.0.1:8080/v1"),
  model("openai", "https://api.openai.com/v1"),
  model("anthropic", "https://api.anthropic.com/v1"),
  model("openrouter", "https://openrouter.ai/api/v1"),
  model("deepseek", "https://api.deepseek.com/v1"),
  model("mi-proveedor", "https://llm.ejemplo.net/v1"),
  model("deepseek", "no es una url"),
];

/** Servicio simulado: responde la cuenta con el nivel que diga `state.level` en cada consulta, y las cuenta. */
function service(level: string, status = 200) {
  const state = { level, calls: [] as string[] };
  configureAccount({
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      state.calls.push(`${String(url)} ${new Headers(init?.headers).get("authorization")}`);
      return new Response(JSON.stringify(status === 200 ? { object: "account", name: "Prueba", verification: state.level, plan: "profesional", tier_usd: 20 } : { error: { message: "Clave inválida" } }), { status });
    }) as typeof fetch,
  });
  return state;
}

test.afterEach(() => { configureAccount(); delete process.env.OROBAS_API_KEY; deleteSecret("orobas"); });

test("qué pide cada modelo: sólo la suscripción pide nivel, y es la identidad", () => {
  assert.equal(requiredLevel(model("faux", "")), null);
  assert.equal(requiredLevel(OROBAS), "basica");
  for (const ajeno of AJENOS) assert.equal(requiredLevel(ajeno), null, `${ajeno.provider} ${ajeno.baseUrl}`);
});

test("sin cuenta, los modelos locales y las claves propias de cualquier proveedor pasan sin consultar nada", async () => {
  const state = service("ninguna");
  for (const ajeno of AJENOS) assert.equal(await accountGate(ajeno), undefined, `${ajeno.provider} ${ajeno.baseUrl}`);
  assert.equal(await accountGate(model("faux", "")), undefined);
  assert.equal(state.calls.length, 0);
});

test("con cuenta sin verificar, los locales y las claves propias también pasan", async () => {
  process.env.OROBAS_API_KEY = KEY;
  const state = service("ninguna");
  for (const ajeno of AJENOS) assert.equal(await accountGate(ajeno), undefined, `${ajeno.provider} ${ajeno.baseUrl}`);
  assert.equal(state.calls.length, 0);
});

test("orobas/<modelo> sin cuenta no pasa: dice cómo vincularla y que lo local no la pide", async () => {
  service("completa");
  const denied = await accountGate(OROBAS);
  assert.ok(denied);
  assert.match(denied, /\/orobas/);
  assert.match(denied, /cyber\.elevateai\.ar\/cuenta/);
  assert.match(denied, /locales|local models/i);
});

test("orobas/<modelo> con cuenta sin identidad no pasa y el mensaje dice cómo verificar", async () => {
  process.env.OROBAS_API_KEY = KEY;
  service("ninguna");
  const denied = await accountGate(OROBAS);
  assert.ok(denied);
  assert.match(denied, /identidad verificada|verified identity/);
  assert.match(denied, /Verificala en cyber\.elevateai\.ar\/cuenta|Verify it at cyber\.elevateai\.ar\/cuenta/);
  assert.match(denied, /modelo local|local model/);
});

test("orobas/<modelo> con identidad (básica o completa) pasa; se consulta al servicio con la clave y se recuerda", async () => {
  process.env.OROBAS_API_KEY = KEY;
  const state = service("basica");
  for (let i = 0; i < 3; i++) assert.equal(await accountGate(OROBAS), undefined);
  assert.equal(state.calls.length, 1);
  assert.equal(state.calls[0], `${orobasBaseUrl().replace(/\/$/, "")}/cuenta Bearer ${KEY}`);
  service("completa");
  assert.equal(await accountGate(OROBAS), undefined);
});

test("después de un rechazo no se recuerda el nivel: apenas verifica, el próximo pedido pasa", async () => {
  process.env.OROBAS_API_KEY = KEY;
  const state = service("ninguna");
  assert.ok(await accountGate(OROBAS));
  state.level = "basica";
  assert.equal(await accountGate(OROBAS), undefined);
  assert.equal(state.calls.length, 2);
});

test("si el servicio no confirma la cuenta, el pedido a orobas sigue y decide el servicio", async () => {
  process.env.OROBAS_API_KEY = KEY;
  service("", 401);
  assert.equal(await accountGate(OROBAS), undefined);
  configureAccount({ fetch: (async () => { throw new TypeError("fetch failed"); }) as typeof fetch });
  assert.deepEqual(await fetchAccount(KEY), { error: "no se pudo conectar" });
  assert.equal(await accountGate(OROBAS), undefined);
});

test("un rechazo por identidad olvida el nivel, no el modo de trazas que informó la cuenta (#40 + #39)", async () => {
  process.env.OROBAS_API_KEY = KEY;
  // La cuenta pidió que no se guarden trazas (en la web) y todavía no verificó la identidad.
  configureAccount({
    fetch: (async () => new Response(JSON.stringify({ object: "account", name: "Prueba", verification: "ninguna", plan: null, tier_usd: 0, trazas: "no" }), { status: 200 })) as typeof fetch,
  });
  const antes = process.env.CYBER_TRAZAS;
  delete process.env.CYBER_TRAZAS;
  try {
    assert.ok(await accountGate(OROBAS), "sin identidad no pasa");
    // Entre el rechazo y la próxima consulta (el cierre del turno manda el registro a /traces), rige la cuenta.
    assert.equal(modoTrazas(), "no");
  } finally {
    if (antes === undefined) delete process.env.CYBER_TRAZAS;
    else process.env.CYBER_TRAZAS = antes;
  }
});
