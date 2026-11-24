import "./datos-tmp.ts";
// El operador prende o apaga el razonamiento previo del modelo hablando, con /razonamiento o
// desde la configuración; sin elegir nada, cada modelo hace lo suyo.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { openAICompletions } from "../src/llm.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";
import { configureAccount } from "../src/cuenta.ts";

// Estas pruebas miran el transporte, no la cuenta: una cuenta verificada de mentira deja pasar cualquier proveedor.
process.env.OROBAS_API_KEY = "oro_" + "a".repeat(48);
configureAccount({ fetch: (async () => new Response(JSON.stringify({ object: "account", name: "prueba", verification: "completa", plan: "profesional", tier_usd: 0 }))) as typeof fetch });

const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });

test("el pedido lleva reasoning sólo si se eligió", async () => {
  const bodies: Array<Record<string, unknown>> = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      bodies.push(JSON.parse(raw));
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end('data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  const request = { system: "s", messages: [{ role: "user" as const, content: "hola", at: 0 }], tools: [] };
  try {
    for (const reasoning of [undefined, false, true]) {
      const result = await openAICompletions({ ...request, model: { provider: "local", id: "m", baseUrl, reasoning } });
      assert.equal(result.content, "ok");
    }
    assert.equal("reasoning" in bodies[0]!, false, "sin elegir: no se manda nada");
    assert.deepEqual(bodies[1]!.reasoning, { enabled: false });
    assert.deepEqual(bodies[2]!.reasoning, { enabled: true });
  } finally {
    server.close();
  }
});

test("«apagá el razonamiento» lo apaga citando el pedido, y una sesión retomada lo conserva", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-razon-"));
  const provider = resolveProvider("faux");
  let engine = new Engine({ cwd, provider, budgetPico: usdToPico("2") });
  try {
    assert.equal(engine.agent.model.reasoning, undefined);
    provider.faux!.queue = [
      call("tools_load", { names: ["session_settings"] }),
      call("session_settings", { razonamiento: "apagado", pedido: "subí el presupuesto a 3" }),
      call("session_settings", { razonamiento: "apagado", pedido: "apagá el razonamiento" }),
      { text: "listo" },
    ];
    await engine.send("Subí el presupuesto a 3 y apagá el razonamiento, que sale caro");
    const results = engine.agent.messages.filter((m) => m.role === "tool").map((m) => m.content as string);
    assert.match(results[1]!, /Cambiar el razonamiento exige que el operador lo haya pedido/);
    assert.match(results[2]!, /razonamiento del modelo: apagado/);
    assert.equal(engine.agent.model.reasoning, false);

    // Lo mismo por la TUI (el daemon llama a setReasoning) y vuelta al de cada modelo.
    engine.setReasoning(true);
    assert.equal(engine.agent.model.reasoning, true);

    // Retomar la sesión: un motor nuevo sobre el mismo proyecto recupera la última elección.
    const session = engine.sessionId;
    engine.close();
    const again = resolveProvider("faux");
    engine = new Engine({ cwd, provider: again, budgetPico: usdToPico("2"), resume: session });
    assert.equal(engine.sessionId, session);
    assert.equal(engine.agent.model.reasoning, true);
  } finally {
    engine.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("GLM no se puede apagar: se avisa", async () => {
  const { reasoningLine } = await import("../src/operador.ts");
  assert.match(reasoningLine(false, "glm-5.3-flash"), /GLM no permite apagarlo/);
  assert.equal(reasoningLine(undefined, "auto"), "razonamiento del modelo: el de cada modelo");
});

test("el razonamiento que llega por el stream se cuenta, no se muestra", async () => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end([
      'data: {"choices":[{"delta":{"reasoning_content":"pienso en voz baja"}}]}',
      'data: {"choices":[{"delta":{"reasoning":"y sigo"}}]}',
      'data: {"choices":[{"delta":{"content":"listo"},"finish_reason":"stop"}]}',
      "data: [DONE]", "",
    ].join("\n\n"));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  try {
    const counts: number[] = [];
    let shown = "";
    const result = await openAICompletions({ system: "s", messages: [{ role: "user", content: "hola", at: 0 }], tools: [], model: { provider: "local", id: "m", baseUrl }, onReasoning: (n) => counts.push(n), onText: (d) => (shown += d) });
    assert.deepEqual(counts, ["pienso en voz baja".length, "y sigo".length]);
    assert.equal(shown, "listo");
    assert.equal(result.content, "listo", "el razonamiento no entra en la respuesta");
  } finally { server.close(); }
});

test("un nivel viaja como reasoning: { enabled, effort }", async () => {
  const bodies: Array<Record<string, unknown>> = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      bodies.push(JSON.parse(raw));
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end('data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  try {
    await openAICompletions({ system: "s", messages: [{ role: "user", content: "hola", at: 0 }], tools: [], model: { provider: "local", id: "m", baseUrl, reasoning: "high" } });
    assert.deepEqual(bodies[0]!.reasoning, { enabled: true, effort: "high" });
  } finally {
    server.close();
  }
});

test("los niveles de cada modelo salen de lo que publica el servicio", async () => {
  const { parseCatalog } = await import("../src/tarifas.ts");
  const models = parseCatalog([
    { id: "kimi", reasoning: { efforts: ["low", "high", "max", "inventado"], off: false } },
    { id: "gpt", reasoning: { efforts: [], off: true } },
    { id: "viejo" },
  ]);
  assert.deepEqual(models.kimi!.reasoningEfforts, ["low", "high", "max"], "un nivel que el harness no conoce no se ofrece");
  assert.equal(models.kimi!.reasoningOff, false);
  assert.deepEqual(models.gpt!.reasoningEfforts, []);
  assert.equal(models.gpt!.reasoningOff, true);
  assert.equal(models.viejo!.reasoningEfforts, undefined, "sin dato del servicio: sólo prendido o apagado");
});

test("/razonamiento: niveles, lo que se muestra y lo que se avisa", async () => {
  const { parseReasoning, reasoningLine, reasoningStatus, capsOf } = await import("../src/operador.ts");
  assert.deepEqual(parseReasoning("alto"), { value: "high" });
  assert.deepEqual(parseReasoning(" MAX "), { value: "max" });
  assert.deepEqual(parseReasoning("medium"), { value: "medium" });
  assert.deepEqual(parseReasoning("no"), { value: false });
  assert.deepEqual(parseReasoning("defecto"), { value: undefined });
  assert.equal(parseReasoning("muchísimo"), null);

  const kimi = capsOf({ reasoningEfforts: ["low", "high", "max"], reasoningOff: false })!;
  assert.equal(capsOf({}), undefined);
  assert.equal(reasoningLine("high", "kimi", kimi), "razonamiento del modelo: nivel alto");
  assert.match(reasoningLine("medium", "kimi", kimi), /nivel medio \(este modelo no tiene ese nivel: va el más cercano\)/);
  assert.match(reasoningLine(false, "kimi", kimi), /apagado \(este modelo no permite apagarlo: va al mínimo\)/);
  assert.equal(reasoningLine(false, "deepseek", { efforts: ["low"], off: true }), "razonamiento del modelo: apagado");
  // Con lo que publica el servicio no hace falta adivinar por el nombre.
  assert.equal(reasoningLine(false, "glm-5.3-cyber", { efforts: ["low"], off: true }), "razonamiento del modelo: apagado");

  const status = reasoningStatus("max", "kimi", kimi);
  assert.match(status, /Niveles de este modelo: bajo, alto, max; no se puede apagar\./);
  assert.match(status, /Uso: \/razonamiento no \| bajo \| alto \| max \| defecto$/);
  assert.match(reasoningStatus(undefined, "m"), /Uso: \/razonamiento si \| no \| defecto$/);
  assert.doesNotMatch(reasoningStatus(undefined, "m"), /Niveles/);
});

test("«poné el razonamiento en alto» elige el nivel, y una sesión retomada lo conserva", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-razon-nivel-"));
  const provider = resolveProvider("faux");
  let engine = new Engine({ cwd, provider, budgetPico: usdToPico("2") });
  try {
    provider.faux!.queue = [
      call("tools_load", { names: ["session_settings"] }),
      call("session_settings", { razonamiento: "alto", pedido: "poné el razonamiento en alto" }),
      { text: "listo" },
    ];
    await engine.send("Poné el razonamiento en alto");
    const results = engine.agent.messages.filter((m) => m.role === "tool").map((m) => m.content as string);
    assert.match(results[1]!, /razonamiento del modelo: nivel alto/);
    assert.equal(engine.agent.model.reasoning, "high");

    const session = engine.sessionId;
    engine.close();
    engine = new Engine({ cwd, provider: resolveProvider("faux"), budgetPico: usdToPico("2"), resume: session });
    assert.equal(engine.agent.model.reasoning, "high");
    engine.setReasoning(undefined);
    assert.equal(engine.agent.model.reasoning, undefined);
  } finally {
    engine.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("daemon: /razonamiento acepta los niveles y contesta con los del modelo de la sesión", async () => {
  const { Daemon } = await import("../src/daemon.ts");
  const { connectDaemon } = await import("../src/client.ts");
  const cwd = mkdtempSync(join(tmpdir(), "cyber-razon-daemon-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new", budget: "sin" });
    // Sin dato del servicio: lo de siempre.
    assert.match((await client.ask("reasoning", {})).join("\n"), /el de cada modelo\. Razonar más .* Uso: \/razonamiento si \| no \| defecto$/);
    // Un modelo que publica niveles y no se apaga.
    const model = [...daemon.hosts.values()][0]!.engine.agent.model;
    model.reasoningEfforts = ["low", "high", "max"];
    model.reasoningOff = false;
    assert.match((await client.ask("reasoning", { value: "alto" })).join("\n"), /nivel alto\. Niveles de este modelo: bajo, alto, max; no se puede apagar\./);
    assert.equal(model.reasoning, "high");
    assert.match((await client.ask("reasoning", { value: "medio" })).join("\n"), /nivel medio \(este modelo no tiene ese nivel: va el más cercano\)/);
    assert.match((await client.ask("reasoning", { value: "no" })).join("\n"), /apagado \(este modelo no permite apagarlo: va al mínimo\)/);
    assert.equal(model.reasoning, false);
    await assert.rejects(client.ask("reasoning", { value: "muchísimo" }), /Uso: \/razonamiento no \| bajo \| alto \| max \| defecto/);
    await client.ask("reasoning", { value: "defecto" });
    assert.equal(model.reasoning, undefined);
    client.close();
  } finally {
    daemon.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
