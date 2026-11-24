import "./datos-tmp.ts";
// Registro de cada turno para el servicio de la suscripción: lo que habló el operador, lo que le
// contestaron, qué herramientas se usaron y qué falló. Sin credenciales ni datos del objetivo.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";

const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });

async function service() {
  const received: Array<{ auth?: string; body: any }> = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      if (req.url === "/v1/traces") received.push({ auth: req.headers.authorization, body: JSON.parse(raw) });
      res.writeHead(204).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { received, baseUrl: `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`, close: () => server.close() };
}

async function waitFor(check: () => boolean) {
  for (let i = 0; i < 100 && !check(); i++) await new Promise((resolve) => setTimeout(resolve, 20));
}

test("cada turno se registra en el servicio, con la credencial tachada y sin lo que devolvieron las herramientas", async () => {
  const svc = await service();
  const cwd = mkdtempSync(join(tmpdir(), "cyber-trazas-"));
  process.env.CYBER_TEST_ORO = "oro_prueba";
  const provider = resolveProvider("faux");
  provider.model = { ...provider.model, provider: "orobas", baseUrl: svc.baseUrl, apiKeyEnv: "CYBER_TEST_ORO" };
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("2"), coverageObjections: 0 });
  try {
    engine.scope.edit({ include: ["api.tienda.test"] });
    provider.faux!.queue = [call("memory_read", { id: "no-existe" }), call("memory_search", { query: "login" }), { text: "Cargué la identidad tienda-1 y no hay nada en memoria sobre el login." }];
    await engine.send("Bearer abcdefghijklmnopqrstuvwxyz123456 es mi token; ¿qué sabemos del login?");
    await waitFor(() => svc.received.length > 0);
    assert.equal(svc.received.length, 1);
    const { auth, body } = svc.received[0]!;
    assert.equal(auth, "Bearer oro_prueba");
    assert.equal(body.session, engine.sessionId);
    const sent = JSON.stringify(body);
    assert.ok(!sent.includes("abcdefghijklmnopqrstuvwxyz123456"), "la credencial no viaja");
    assert.match(body.turn.operator[0].text, /credencial cargada como identidad tienda-1/);
    assert.equal(body.turn.agent.at(-1).text, "Cargué la identidad tienda-1 y no hay nada en memoria sobre el login.");
    assert.deepEqual(body.turn.tools, { memory_read: 1, memory_search: 1 });
    assert.equal(body.turn.errors[0].tool, "memory_read");
    assert.equal(body.turn.end, "respuesta");
    assert.deepEqual(body.turn.identities, ["tienda-1"]);
    assert.equal(body.turn.steps, 3);

    // Apagado a pedido.
    process.env.CYBER_TRAZAS = "no";
    provider.faux!.queue = [{ text: "ok" }];
    await engine.send("hola");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(svc.received.length, 1);
  } finally {
    delete process.env.CYBER_TRAZAS;
    delete process.env.CYBER_TEST_ORO;
    engine.close();
    svc.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("con otro proveedor no se manda nada", async () => {
  const svc = await service();
  const cwd = mkdtempSync(join(tmpdir(), "cyber-trazas-"));
  const provider = resolveProvider("faux");
  provider.model = { ...provider.model, baseUrl: svc.baseUrl };
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("2") });
  try {
    provider.faux!.queue = [{ text: "ok" }];
    await engine.send("hola");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(svc.received.length, 0);
  } finally {
    engine.close();
    svc.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
