import "./datos-tmp.ts";
// Un modelo que corta una llamada a mitad de los argumentos (JSON sin cerrar) no puede envenenar la sesión:
// el historial se reenvía en cada turno y el servicio rechaza el pedido entero si un `arguments` no es JSON.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { configureAccount } from "../src/cuenta.ts";
import { openAICompletions } from "../src/llm.ts";

process.env.OROBAS_API_KEY = "oro_" + "a".repeat(48);
configureAccount({ fetch: (async () => new Response(JSON.stringify({ object: "account", name: "prueba", verification: "completa", plan: "profesional", tier_usd: 0 }))) as typeof fetch });

test("argumentos de herramienta rotos en el historial salen como JSON válido", async () => {
  const bodies: any[] = [];
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
  const roto = '{"url":"https://objetivo.test/api","body":"{\\"id\\": 1, \\"nombre\\": \\"sin cerr';
  const sano = '{"url":"https://objetivo.test/"}';
  try {
    await openAICompletions({
      system: "s",
      tools: [],
      model: { provider: "local", id: "m", baseUrl },
      messages: [
        { role: "user", content: "probá", at: 0 },
        { role: "assistant", content: "", toolCalls: [{ id: "a", name: "http_request", arguments: roto }, { id: "b", name: "http_request", arguments: sano }], stopReason: "toolUse", provider: "local", model: "m", requestId: "r", at: 0 },
        { role: "tool", toolCallId: "a", name: "http_request", content: "Unterminated string in JSON", isError: true, at: 0 },
        { role: "tool", toolCallId: "b", name: "http_request", content: "200", isError: false, at: 0 },
        { role: "user", content: "k pasó", at: 0 },
      ] as any,
    });
    const calls = bodies[0].messages[2].tool_calls;
    for (const call of calls) assert.doesNotThrow(() => JSON.parse(call.function.arguments), `arguments inválido: ${call.function.arguments}`);
    assert.equal(calls[1].function.arguments, sano, "los argumentos sanos no se tocan");
  } finally {
    server.close();
  }
});
