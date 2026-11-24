import "./datos-tmp.ts";
// Resiliencia del proveedor. En noviembre cada caída costaba ~130 s con cyber-zero/cyber-ultra (vigía de
// 120 s) y ~320 s con kimi: ~75 minutos perdidos. Ahora: vigía de 45 s que cuenta como actividad todo lo
// que llega (también los latidos), un reintento rápido y, a la segunda falla seguida, otro modelo con
// aviso y evento. Sin saldo (usage_limit) no se reintenta ni se cambia: el turno se corta con un mensaje claro.
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Agent } from "../src/agent.ts";
import { Engine, fallbackModel } from "../src/engine.ts";
import { fauxTransport, forgetSilences, IDLE_DEFAULT_MS, IDLE_MAX_MS, idleTimeoutFor, type Model, noteSilence, openAICompletions } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-caido-"));

/** Servicio de orobas de mentira: /models lista, /chat/completions lo decide `chat` según el modelo pedido. */
async function fakeService(chat: (model: string, res: ServerResponse, req: IncomingMessage) => void): Promise<{ server: Server; base: string; hits: string[] }> {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    if (req.url?.endsWith("/models")) return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ object: "list", data: ["glm-5.3-flash", "auto", "cyber-ultra-1.0"].map((id) => ({ id, pricing: { input: id === "cyber-ultra-1.0" ? 5 : 1, cached_input: 0.1, output: 4 } })) }));
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const model = String(JSON.parse(body || "{}").model ?? "");
      hits.push(model);
      chat(model, res, req);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, base: `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`, hits };
}

/** Respuesta SSE completa con un texto. */
function answer(res: ServerResponse, text: string): void {
  if (!res.headersSent) res.writeHead(200, { "content-type": "text/event-stream" });
  res.write(`data: ${JSON.stringify({ id: "r", choices: [{ delta: { content: text } }] })}\n\n`);
  res.write(`data: ${JSON.stringify({ choices: [{ delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 100, completion_tokens: 5 } })}\n\n`);
  res.end("data: [DONE]\n\n");
}

async function withService(config: (base: string) => object, fn: (base: string) => Promise<void>, service: Awaited<ReturnType<typeof fakeService>>): Promise<void> {
  const dir = tmp();
  const prev = { c: process.env.CYBER_CONFIG, k: process.env.OROBAS_API_KEY, t: process.env.CYBER_TRAZAS };
  writeFileSync(join(dir, "config.json"), JSON.stringify(config(service.base)));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  process.env.OROBAS_API_KEY = "oro_prueba";
  process.env.CYBER_TRAZAS = "no";
  try { await fn(service.base); } finally {
    service.server.closeAllConnections();
    service.server.close();
    for (const [name, value] of [["CYBER_CONFIG", prev.c], ["OROBAS_API_KEY", prev.k], ["CYBER_TRAZAS", prev.t]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

test("vigía de silencio: 45 s por defecto (menos de un minuto por caída), sube con el silencio medido hasta 120 s, y lo configurado manda", () => {
  forgetSilences();
  const model: Model = { provider: "orobas", id: "glm-5.3-flash", baseUrl: "" };
  assert.equal(IDLE_DEFAULT_MS, 45_000);
  assert.ok(idleTimeoutFor(model) <= 60_000);
  noteSilence(model, 20_000);
  assert.equal(idleTimeoutFor(model), 45_000, "un silencio corto no cambia nada");
  noteSilence(model, 50_000);
  assert.equal(idleTimeoutFor(model), 75_000, "un modelo que piensa callado 50 s y responde bien tiene margen");
  noteSilence(model, 30_000);
  assert.equal(idleTimeoutFor(model), 75_000, "se queda con el más largo");
  noteSilence(model, 400_000);
  assert.equal(idleTimeoutFor(model), IDLE_MAX_MS);
  assert.equal(idleTimeoutFor({ ...model, id: "otro" }), 45_000, "por modelo");
  assert.equal(idleTimeoutFor({ ...model, idleTimeoutMs: 5000 }), 5000);
  forgetSilences();
});

test("stream: los latidos y el razonamiento cuentan como actividad; un proveedor callado se corta en el plazo y es reintentable", async () => {
  forgetSilences();
  const service = await fakeService((model, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    if (model === "callado") return; // cabecera y después nada, con la conexión abierta
    // 600 ms en total, con un latido o razonamiento cada 80 ms: más que el plazo de 250 ms, pero nunca callado.
    let n = 0;
    const timer = setInterval(() => {
      if (++n < 8) return void res.write(n % 2 ? ": keep-alive\n\n" : `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "pienso" } }] })}\n\n`);
      clearInterval(timer);
      answer(res, "Listo.");
    }, 80);
  });
  await withService(() => ({}), async (base) => {
    const model = (id: string): Model => ({ provider: "orobas", id, baseUrl: base, apiKeyEnv: "OROBAS_API_KEY", idleTimeoutMs: 250 });
    const slow = await openAICompletions({ model: model("latidos"), system: "s", messages: [{ role: "user", content: "hola", at: 0 }], tools: [] });
    assert.equal(slow.stopReason, "stop");
    assert.equal(slow.content, "Listo.");
    assert.ok(slow.silenceMs! < 250, `el hueco más largo fue ${slow.silenceMs} ms`);
    const started = Date.now();
    const silent = await openAICompletions({ model: model("callado"), system: "s", messages: [{ role: "user", content: "hola", at: 0 }], tools: [] });
    assert.equal(silent.stopReason, "error");
    assert.equal(silent.retryable, true);
    assert.match(silent.errorMessage!, /no respondió en/);
    assert.ok(Date.now() - started < 2000, "se corta en el plazo, no en minutos");
  }, service);
});

test("agente: a la segunda falla seguida pasa al plan B y reintenta ya; sin plan B sigue como antes; sin saldo no reintenta", async () => {
  const faux = fauxTransport();
  const model: Model = { provider: "faux", id: "a", baseUrl: "" };
  const used: string[] = [];
  const asked: string[] = [];
  const agent = new Agent({
    system: "s",
    model,
    tools: [],
    retryBaseMs: 1,
    transport: (request) => { used.push(request.model.id); return faux.transport(request); },
    fallback: async (reply) => { asked.push(reply.errorMessage ?? ""); model.id = "b"; return "faux/b"; },
  });
  const retries: Array<{ attempt: number; waitMs: number; reason: string }> = [];
  agent.on((event) => { if (event.type === "retry") retries.push(event); });
  faux.queue.push({ fail: { message: "El modelo está saturado", retryable: true } }, { fail: { message: "El proveedor no respondió en 45 s", retryable: true } }, { text: "Hola." });
  await agent.prompt("hola");
  assert.deepEqual(used, ["a", "a", "b"], "una vez rápido con el mismo; a la segunda falla, el otro");
  assert.deepEqual(asked, ["El proveedor no respondió en 45 s"]);
  assert.deepEqual(retries.map((r) => [r.attempt, r.waitMs]), [[1, 1], [2, 0]]);
  assert.match(retries[1]!.reason, /^paso a faux\/b · El proveedor no respondió/);
  assert.equal((agent.messages.at(-1) as { content: string }).content, "Hola.");

  // Sin saldo: ni reintento ni plan B.
  used.length = 0;
  asked.length = 0;
  faux.queue.push({ fail: { message: "Sin saldo [usage_limit]", rejected: true, exhausted: true } }, { text: "no llega" });
  await agent.prompt("otra");
  assert.deepEqual(used, ["b"]);
  assert.deepEqual(asked, []);

  // Sin plan B, como siempre: hasta tres reintentos con el mismo modelo.
  const lone = fauxTransport();
  const plain = new Agent({ system: "s", model: { provider: "faux", id: "a", baseUrl: "" }, tools: [], retryBaseMs: 1, transport: lone.transport });
  lone.queue.push({ fail: { message: "503", retryable: true } }, { fail: { message: "503", retryable: true } }, { fail: { message: "503", retryable: true } }, { text: "Ok." });
  await plain.prompt("hola");
  assert.equal(lone.calls, 4);
  assert.equal((plain.messages.at(-1) as { content: string }).content, "Ok.");
});

test("motor: el base saturado dos veces seguidas pasa a «auto», avisa, deja evento y la sesión retomada sigue con él", async () => {
  const service = await fakeService((model, res) => {
    if (model === "auto") return answer(res, "Sigo con auto.");
    res.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ error: { message: "El modelo está saturado", code: "upstream_busy" } }));
  });
  await withService((base) => ({ providers: { orobas: { baseUrl: base, apiKeyEnv: "OROBAS_API_KEY" } } }), async () => {
    const cwd = tmp();
    const engine = new Engine({ cwd, provider: resolveProvider("orobas/glm-5.3-flash"), retryBaseMs: 1 });
    const notices: string[] = [];
    engine.onNotice = (text) => notices.push(text);
    const started = Date.now();
    await engine.send("hola");
    assert.ok(Date.now() - started < 10_000);
    assert.deepEqual(service.hits, ["glm-5.3-flash", "glm-5.3-flash", "auto"]);
    assert.equal((engine.agent.messages.at(-1) as { content: string }).content, "Sigo con auto.");
    assert.equal(engine.agent.model.id, "auto");
    const fallback = engine.db.prepare("select payload from events where session_id=? and type='modelo.fallback'").get(engine.sessionId) as { payload: string };
    assert.deepEqual(JSON.parse(fallback.payload), { de: "orobas/glm-5.3-flash", a: "orobas/auto", motivo: "proveedor sin respuesta", error: "El modelo está saturado [upstream_busy]" });
    assert.ok(notices.some((text) => /falló dos veces seguidas \(El modelo está saturado.*sigo con orobas\/auto/.test(text)), notices.join(" | "));
    const session = engine.sessionId;
    engine.close();
    const reopened = new Engine({ cwd, provider: resolveProvider("orobas/glm-5.3-flash"), resume: session });
    assert.equal(reopened.agent.model.id, "auto", "el cambio queda como un ajuste del modelo");
    reopened.close();
  }, service);
});

test("motor: sin saldo corta el turno con un mensaje claro, sin reintentar ni cambiar de modelo, y nada sale hasta que el operador escriba", async () => {
  const service = await fakeService((_model, res) => {
    res.writeHead(429, { "content-type": "application/json" }).end(JSON.stringify({ error: { message: "Se terminó el saldo del mes", code: "usage_limit" } }));
  });
  await withService((base) => ({ providers: { orobas: { baseUrl: base, apiKeyEnv: "OROBAS_API_KEY" } } }), async () => {
    const engine = new Engine({ cwd: tmp(), provider: resolveProvider("orobas/glm-5.3-flash"), retryBaseMs: 1 });
    const notices: string[] = [];
    engine.onNotice = (text) => notices.push(text);
    await engine.send("hola");
    assert.equal(service.hits.length, 1, "una sola solicitud: ni reintento, ni cierre pedido al modelo");
    assert.equal(engine.agent.model.id, "glm-5.3-flash", "no se cambia de modelo: ninguno tendría saldo");
    const closing = (engine.agent.messages.at(-1) as { content: string }).content;
    assert.match(closing, /^Corté el turno sin reintentar: el servicio dice que tu cuenta no tiene saldo/);
    assert.match(closing, /Se terminó el saldo del mes/);
    assert.match(closing, /cyber\.elevateai\.ar\/cuenta/);
    assert.equal(notices.filter((text) => /no tiene saldo/.test(text)).length, 1);
    assert.ok(engine.db.prepare("select 1 from events where session_id=? and type='modelo.sin_saldo'").get(engine.sessionId));
    // Verificador, subagentes o compactador tampoco salen a la red mientras tanto.
    const blocked = await engine.tagged("verificador:1")({ model: engine.agent.model, system: "s", messages: [], tools: [] });
    assert.equal(blocked.exhausted, true);
    assert.equal(service.hits.length, 1);
    // El operador vuelve a escribir: se intenta una vez más.
    await engine.send("ya cargué");
    assert.equal(service.hits.length, 2);
    engine.close();
  }, service);
});

test("plan B: «auto» primero; si no hay, el más barato; si no hay precios, el primero", () => {
  const price = (spec: string) => ({ "orobas/caro": 5, "orobas/barato": 1, "orobas/medio": 2 } as Record<string, number>)[spec];
  assert.equal(fallbackModel("orobas/medio", ["orobas/caro", "orobas/medio", "orobas/auto", "orobas/barato"], price), "orobas/auto");
  assert.equal(fallbackModel("orobas/medio", ["orobas/caro", "orobas/medio", "orobas/barato"], price), "orobas/barato");
  assert.equal(fallbackModel("orobas/medio", ["orobas/caro", "orobas/medio"]), "orobas/caro");
});
