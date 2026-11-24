import assert from "node:assert/strict";
import { test } from "node:test";
import { Agent, type Tool } from "../src/agent.ts";
import type { ToolCall, ToolMessage } from "../src/llm.ts";

test("agente: distingue nombres desconocidos de llamadas malformadas sin ejecutar", async () => {
  let executed = 0;
  const tool: Tool = { name: "segura", label: "segura", description: "", parameters: {}, execute: () => { executed++; return { text: "ok" }; } };
  const agent = new Agent({ system: "", model: { provider: "local", id: "m", baseUrl: "http://localhost" }, tools: [tool], transport: async () => { throw new Error("no se usa"); } });
  const run = (name: string, args: string) => (agent as unknown as { run: (call: ToolCall, signal: AbortSignal) => Promise<ToolMessage> }).run({ id: "c", name, arguments: args }, new AbortController().signal);
  for (const name of ["http_request  $MISSING</arg_value>", "js_endpoints  $MISSING</arg_value> 有利于url=...", "no existe", "no\texiste", "no\nexiste", "$tool", "no\u0000existe", "no\u007fexiste", "no\u200bexiste", "herramientá", ""]) {
    const result = await run(name, "{}");
    if (!name) assert.equal(result.content, "Herramienta desconocida: ");
    else {
      assert.match(result.content, /salió malformada/);
      assert.ok(result.content.includes(JSON.stringify(name)));
    }
    assert.equal(result.isError, true);
  }
  for (const args of ["{", "undefined"]) {
    let parseError = "";
    try { JSON.parse(args); } catch (error) { parseError = (error as Error).message; }
    const result = await run("no_existe", args);
    assert.match(result.content, /salió malformada/);
    assert.ok(result.content.includes(parseError));
    assert.ok(result.content.includes('"no_existe"'));
    assert.equal(result.isError, true);
  }
  assert.equal((await run("no_existe", "{}")).content, "Herramienta desconocida: no_existe");
  assert.equal((await run("no_existe", "")).content, "Herramienta desconocida: no_existe");
  assert.equal(executed, 0);
  assert.equal((await run("segura", "{}")).content, "ok");
  assert.equal(executed, 1);
});
