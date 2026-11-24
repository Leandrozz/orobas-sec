import "./datos-tmp.ts";
// Un proveedor que corta la conexión a mitad de la respuesta no puede pasar por una respuesta terminada.
// Detrás de un intermediario el corte llega como un cierre limpio (sin error de red): lo único que lo delata
// es que falta el final del stream (finish_reason y [DONE]). Visto el 19/11/2026: ocho cortes en tres minutos
// dejaron tres finales de turno falsos y una llamada a «delegate» con los argumentos truncados.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { configureAccount } from "../src/cuenta.ts";
import { anthropicMessages, openAICompletions } from "../src/llm.ts";

process.env.OROBAS_API_KEY = "oro_" + "a".repeat(48);
configureAccount({ fetch: (async () => new Response(JSON.stringify({ object: "account", name: "prueba", verification: "completa", plan: "profesional", tier_usd: 0 }))) as typeof fetch });

async function serve(events: string[], run: (baseUrl: string) => Promise<void>) {
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.end(events.map((event) => `data: ${event}\n\n`).join(""));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try { await run(`http://127.0.0.1:${(server.address() as { port: number }).port}/v1`); } finally { server.close(); }
}
const request = { system: "s", messages: [{ role: "user" as const, content: "hola", at: 0 }], tools: [] };

test("llamada a herramienta cortada a mitad de los argumentos: error reintentable, no una llamada rota", async () => {
  await serve([
    '{"choices":[{"delta":{"content":"Lanzo los subagentes."}}]}',
    '{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"delegate","arguments":"{\\"budgetUsd\\": 0.4, \\"context\\": \\"Hosts: https://sinequ"}}]}}]}',
  ], async (baseUrl) => {
    const result = await openAICompletions({ ...request, model: { provider: "local", id: "m", baseUrl } });
    assert.equal(result.stopReason, "error");
    assert.equal(result.retryable, true, "se reintenta: el corte es del proveedor, no del pedido");
    assert.deepEqual(result.toolCalls, [], "la llamada truncada no se ejecuta ni entra al historial");
    assert.match(result.errorMessage ?? "", /cortó la respuesta/);
  });
});

test("texto cortado sin final de stream: no es el final del turno", async () => {
  await serve(['{"choices":[{"delta":{"content":"Encontré tres rutas y ahora voy a"}}]}'], async (baseUrl) => {
    const result = await openAICompletions({ ...request, model: { provider: "local", id: "m", baseUrl } });
    assert.equal(result.stopReason, "error");
    assert.equal(result.retryable, true);
  });
});

test("un stream completo sigue valiendo, con finish_reason o con [DONE] solo", async () => {
  await serve(['{"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}'], async (baseUrl) => {
    const result = await openAICompletions({ ...request, model: { provider: "local", id: "m", baseUrl } });
    assert.equal(result.stopReason, "stop");
    assert.equal(result.content, "ok");
  });
  await serve(['{"choices":[{"delta":{"content":"ok"}}]}', "[DONE]"], async (baseUrl) => {
    const result = await openAICompletions({ ...request, model: { provider: "local", id: "m", baseUrl } });
    assert.equal(result.stopReason, "stop");
  });
});

test("Anthropic Messages: sin stop_reason ni message_stop, también es un corte", async () => {
  const start = '{"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":5,"output_tokens":0}}}';
  const text = ['{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}', '{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"voy a"}}'];
  await serve([start, ...text], async (baseUrl) => {
    const result = await anthropicMessages({ ...request, model: { provider: "local", id: "m", baseUrl } });
    assert.equal(result.stopReason, "error");
    assert.equal(result.retryable, true);
  });
  await serve([start, ...text, '{"type":"content_block_stop","index":0}', '{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}', '{"type":"message_stop"}'], async (baseUrl) => {
    const result = await anthropicMessages({ ...request, model: { provider: "local", id: "m", baseUrl } });
    assert.equal(result.stopReason, "stop");
    assert.equal(result.content, "voy a");
  });
});
