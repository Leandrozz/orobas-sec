import assert from "node:assert/strict";
import test from "node:test";
import { personalReasoning, personalFields, supported } from "../src/tui/effort-personal.ts";
import { openPersonalChat, type Connection } from "../src/tui/modelos-personales.ts";

const base = "https://example.invalid/v1";
for (const provider of ["Z.ai", "OpenCode Go", "OpenCode Zen"] as const) {
  test(provider + " · GLM 5.3 sólo publica low, high y max", () => {
    const c: Connection = { provider, base, model: "glm-5.3" };
    assert.deepEqual(supported(c), ["low", "high", "max"]);
    assert.throws(() => personalReasoning(c, "medio"));
    personalReasoning(c, "alto");
    assert.deepEqual(personalFields(c), { reasoning_effort: "high" });
    personalReasoning(c, "defecto");
    assert.deepEqual(personalFields(c), {});
  });
}
test("Kimi distingue esfuerzo continuo y modelos con interruptor", () => {
  const c: Connection = { provider: "Kimi (Moonshot AI)", base, model: "kimi-k2.6" };
  personalReasoning(c, "no");
  assert.deepEqual(personalFields(c), { thinking: { type: "disabled" } });
  c.model = "kimi-k3.1-pro";
  assert.throws(() => personalReasoning(c, "no"));
  personalReasoning(c, "max");
  assert.deepEqual(personalFields(c), { reasoning_effort: "max" });
});
test("las capacidades de la cuenta prevalecen y un modelo desconocido usa su valor por defecto", () => {
  const c: Connection = { provider: "Claude", model: "claude-opus-4-5", base, availableEfforts: [] };
  assert.deepEqual(supported(c), []);
  assert.throws(() => personalReasoning(c, "high"));
  assert.deepEqual(supported({ provider: "Self-hosted", base, model: "desconocido" }), []);
});
test("Claude envía el nivel mediante Messages y conserva los tokens", async t => {
  const c: Connection = { provider: "Claude", model: "claude-opus-4-5", key: "mock", base };
  personalReasoning(c, "medio");
  t.mock.method(globalThis, "fetch", async (url: string, opts: RequestInit) => {
    assert.equal(url, "https://api.anthropic.com/v1/messages");
    assert.deepEqual(JSON.parse(String(opts.body)).output_config, { effort: "medium" });
    return Response.json({ content: [{ type: "text", text: "ok" }], usage: { input_tokens: 4, output_tokens: 2 } });
  });
  const r = await openPersonalChat(c).reply("hola");
  assert.equal(r.usage?.total_tokens, 6);
});
test("Ollama consulta capacidades y convierte un interruptor en think booleano", async t => {
  const { loadPersonalReasoning } = await import("../src/tui/effort-personal.ts");
  const c: Connection = { provider: "Ollama", model: "modelo-local", base };
  t.mock.method(globalThis, "fetch", async (url: string, options: RequestInit) => {
    if (url.endsWith("/api/show")) return Response.json({ thinking: { values: [true, false] } });
    assert.ok(url.endsWith("/api/chat"));
    assert.equal(JSON.parse(String(options.body)).think, false);
    return Response.json({ message: { content: "ok" }, prompt_eval_count: 4, eval_count: 1 });
  });
  await loadPersonalReasoning(c, "no");
  assert.deepEqual(supported(c), ["on", "off"]);
  assert.equal((await openPersonalChat(c).reply("hola")).usage?.total_tokens, 5);
});
test("Antigravity agrupa variantes por conexión y conserva los IDs del transporte", async () => {
  const { catalogEntries, personalRow } = await import("../src/tui/modelos-personales.ts");
  const entries = catalogEntries({ provider: "Gemini", subscription: "agy", base: "", model: "" }, [
    "gemini-4-hydrogen-high", "gemini-4-hydrogen-medium", "claude-sonnet-4-6", "gpt-oss-120b-medium",
  ]);
  assert.deepEqual(entries.map(c => personalRow(c).label), ["Gemini Hydrogen 4", "Claude Sonnet 4.6", "GPT OSS 120B"]);
  assert.deepEqual(supported(entries[0]!), ["medium", "high"]);
  assert.equal(entries[0]!.variants!.medium, "gemini-4-hydrogen-medium");
  assert.equal(personalRow(entries[1]!).hint, "Gemini · Antigravity");
  assert.equal(personalRow({ provider: "Claude", model: "claude-sonnet-4-6", base: "", nativeClaude: true }).hint, "Claude · Claude Code");
});

for (const provider of ["Z.ai", "OpenCode Zen", "OpenCode Go", "Ollama", "Self-hosted"]) {
  test(provider + " presenta el catálogo de la conexión en el buscador", async context => {
    const { connectPersonal } = await import("../src/tui/modelos-personales.ts");
    const custom = provider === "Self-hosted" || provider === "Ollama";
    const openCode = provider.startsWith("OpenCode");
    const endpoint = ({
      "Z.ai": "https://api.z.ai/api/paas/v4",
      "OpenCode Zen": "https://opencode.ai/inference/openai/v1",
      "OpenCode Go": "https://opencode.ai/inference/go/openai/v1",
      Ollama: "http://localhost:11434/v1",
      "Self-hosted": base,
    })[provider];
    context.mock.method(globalThis, "fetch", async (url: string, options: RequestInit) => {
      assert.equal(url, endpoint + "/models");
      assert.equal(new Headers(options.headers).get("Authorization"), custom ? null : "Bearer prueba");
      const data = [{ id: "glm-5.3", type: "chat" }];
      if (openCode) data.unshift({ id: "embedding", type: "embedding" });
      return Response.json({ data });
    });
    const inputs = custom ? [provider === "Ollama" ? "" : base, ""] : ["prueba"];
    const connection = await connectPersonal({
      async input() { return inputs.shift(); },
      async pick(title, rows, options) {
        if (options?.search) {
          assert.deepEqual(rows, [{ label: "GLM 5.3", hint: provider }]);
          return 0;
        }
        if (title === "OpenCode") return provider === "OpenCode Go" ? 1 : 0;
        if (title === provider) return 0;
        return rows.findIndex(row => (typeof row === "string" ? row : row.label) === (openCode ? "OpenCode" : provider));
      },
    });
    assert.equal(connection?.model, "glm-5.3");
  });
}
