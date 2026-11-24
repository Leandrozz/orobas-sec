import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildDataset, buildExamples } from "../src/dataset.ts";

const turn = (operator: string, extra: Partial<{ end: string; errors: number; follow_up: string }> = {}, steps = 1) => ({
  operator,
  messages: [
    ...Array.from({ length: steps }, (_, i) => [
      { role: "assistant", by: "modelo", content: i ? "" : "Miro.", tool_calls: [{ id: `c${i}`, name: "http_request", arguments: { url: "https://host-1/api" } }] },
      { role: "tool", tool_call_id: `c${i}`, name: "http_request", content: "HTTP 200", is_error: false },
    ]).flat(),
    { role: "assistant", by: "modelo", content: "Encontré un IDOR en /api/pedidos.", tool_calls: [] },
  ],
  labels: { steps, errors: 0, end: "respuesta", follow_up: "nuevo", ...extra },
});
const record = (turns: unknown[], verificados = 1) => ({
  harness: "0.1.0", project: "demo", sesion: { id: "s1", model: "orobas/x" }, system: "Sos Orobas.",
  labels: { findings: { verificados } }, turns,
});

test("un ejemplo por turno, en formato chat con herramientas y con el contexto de los turnos previos", () => {
  const out = buildExamples(record([turn("Revisá pedidos"), turn("Ahora el login", {}, 2)]) as any);
  assert.deepEqual(out.map((item) => item.reason), ["ok", "ok"]);
  const first = out[0]!.example!;
  assert.deepEqual(first.messages.map((m) => m.role), ["system", "user", "assistant", "tool", "assistant"]);
  assert.equal(first.messages[2]!.tool_calls![0]!.function.name, "http_request");
  assert.equal(first.messages[2]!.tool_calls![0]!.function.arguments, '{"url":"https://host-1/api"}');
  assert.equal(first.messages[3]!.tool_call_id, "c0");
  assert.deepEqual(first.meta.tools, ["http_request"]);
  const second = out[1]!.example!;
  // El turno anterior viaja resumido: pedido del operador y respuesta final, sin sus pasos.
  assert.deepEqual(second.messages.slice(0, 4).map((m) => [m.role, m.content]), [["system", "Sos Orobas."], ["user", "Revisá pedidos"], ["assistant", "Encontré un IDOR en /api/pedidos."], ["user", "Ahora el login"]]);
  assert.equal(second.messages.filter((m) => m.role === "tool").length, 2);
});

test("los filtros dejan afuera lo que no conviene imitar", () => {
  const turns = [
    turn("a", { end: "cierre-harness" }),
    turn("b", { errors: 2 }),
    turn("c", { follow_up: "corrección" }),
    turn("d"),
  ];
  const strict = buildDataset([JSON.stringify(record(turns))]);
  assert.equal(strict.examples.length, 1);
  assert.deepEqual(strict.dropped, { ok: 1, "sin verificados": 0, "con errores": 1, corregido: 1, cortado: 1, "sin pasos": 0 });
  const loose = buildDataset([JSON.stringify(record(turns))], { dropErrors: false, dropCorrected: false, dropCut: false });
  assert.equal(loose.examples.length, 4);
  const none = buildDataset([JSON.stringify(record(turns, 0))], { onlyVerified: true });
  assert.equal(none.examples.length, 0);
  assert.equal(none.dropped["sin verificados"], 4);
  // El cierre escrito por el harness no entra como si fuera del modelo.
  const cut = { ...turn("e"), messages: [{ role: "assistant", by: "harness", content: "Corté el turno." }] };
  assert.equal(buildExamples(record([cut]) as any)[0]!.reason, "sin pasos");
});
