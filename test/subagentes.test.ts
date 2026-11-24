import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import type { AssistantMessage } from "../src/llm.ts";
import { Subagentes } from "../src/tui/subagentes.ts";

const asistente = (extra: Partial<AssistantMessage> = {}): AssistantMessage =>
  ({ role: "assistant", content: "", toolCalls: [], stopReason: "stop", provider: "p", model: "m", requestId: "r", at: 0, ...extra });
const delegar = (id: string, objective: string) => ({ id, name: "delegate", arguments: JSON.stringify({ objective }) });
const texto = (worker: string, delta: string) => ({ type: "text" as const, delta, worker });
const fin = (id: string, worker: string, estado = "listo") =>
  ({ type: "tool_end" as const, id, name: "delegate", isError: false, text: "", details: { worker, estado, solicitudes: 3, usd: "0.0123", transcripcion: "sha256:abc" } });
const textoDe = (s: { registro: { entradas(): readonly { tipo: string }[] } }) =>
  s.registro.entradas().filter((e) => e.tipo === "texto").map((e) => (e as unknown as { markdown: string }).markdown).join("|");

test("subagentes: un worker nuevo toma el objetivo de la llamada delegate en curso", () => {
  const s = new Subagentes();
  assert.equal(s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "mapear puertos")] }) }), undefined);
  const sub = s.evento(texto("sub:1", "hola"));
  assert.equal(sub?.worker, "sub:1");
  assert.equal(sub?.objetivo, "mapear puertos");
  assert.equal(sub?.estado, "trabajando");
  assert.equal(s.de("sub:1"), sub);
});

test("subagentes: dos delegate en paralelo no mezclan objetivo ni texto", () => {
  const s = new Subagentes();
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "uno"), delegar("c2", "dos")] }) });
  s.evento(texto("sub:5", "a1"));
  s.evento(texto("sub:6", "b1"));
  s.evento(texto("sub:5", "a2"));
  assert.equal(s.de("sub:5")?.objetivo, "uno");
  assert.equal(s.de("sub:6")?.objetivo, "dos");
  assert.equal(textoDe(s.de("sub:5")!), "a1a2");
  assert.equal(textoDe(s.de("sub:6")!), "b1");
});

test("subagentes: el tool_end de delegate corrige el worker y cierra con terminó / no terminó", () => {
  const s = new Subagentes();
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "uno"), delegar("c2", "dos")] }) });
  s.evento(texto("sub:1", "x")); // se asocia a c1
  s.evento(texto("sub:2", "y")); // se asocia a c2
  const a = s.evento(fin("c2", "sub:1", "incompleto"));
  assert.equal(a?.worker, "sub:1");
  assert.equal(a?.objetivo, "dos");
  assert.equal(a?.estado, "no terminó");
  assert.equal(a?.solicitudes, 3);
  assert.equal(a?.usd, "0.0123");
  assert.equal(typeof a?.fin, "number");
  const b = s.evento(fin("c1", "sub:2"));
  assert.equal(b?.estado, "terminó");
  assert.equal(b?.objetivo, "uno");
  assert.equal(textoDe(b!), "y");
  assert.equal(b?.registro.entradas().find((e) => e.tipo === "texto" && !e.completo), undefined);
});

test("subagentes: las acciones del worker quedan en su registro con el id sin prefijo", () => {
  const s = new Subagentes();
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "x")] }) });
  const sub = s.evento({ type: "tool_start", id: "sub:5/c9", name: "shell", label: "Ejecutar", worker: "sub:5" });
  assert.equal(sub?.worker, "sub:5");
  s.evento({ type: "tool_end", id: "sub:5/c9", name: "shell", isError: false, text: "", details: {}, worker: "sub:5" });
  const acc = sub!.registro.entradas().find((e) => e.tipo === "acciones") as unknown as { llamada: string; estado: string; worker?: string };
  assert.equal(acc.llamada, "c9");
  assert.equal(acc.estado, "ok");
  assert.equal(acc.worker, undefined);
});

test("subagentes: lista() del más nuevo al más viejo", () => {
  const s = new Subagentes();
  s.evento(texto("sub:1", "a"));
  s.evento(texto("sub:2", "b"));
  s.evento(texto("sub:3", "c"));
  assert.deepEqual(s.lista().map((x) => x.worker), ["sub:3", "sub:2", "sub:1"]);
  assert.equal(s.evento({ type: "tool_start", id: "z", name: "shell", label: "x" }), undefined);
});

test("subagentes: un worker que cierra sin haber emitido no roba la llamada de otro", () => {
  const s = new Subagentes();
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "uno"), delegar("c2", "dos")] }) });
  const a = s.evento(fin("c1", "sub:5"));
  assert.equal(a?.objetivo, "uno");
  assert.equal(s.evento(texto("sub:6", "x"))?.objetivo, "dos");
});

test("subagentes: delegate con error y sin details.worker no cierra a ningún worker", () => {
  const s = new Subagentes();
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "uno"), delegar("c2", "dos")] }) });
  s.evento(texto("sub:5", "x")); // el FIFO lo asocia a c1
  assert.equal(s.evento({ type: "tool_end", id: "c1", name: "delegate", isError: true, text: "fallo", details: {} }), undefined);
  assert.equal(s.de("sub:5")?.estado, "trabajando");
  assert.equal(s.de("sub:5")?.objetivo, "dos"); // tomó la otra llamada libre
  assert.equal(s.evento(fin("c2", "sub:5"))?.estado, "terminó");
});

test("subagentes: el texto de cada paso queda entre sus acciones, no todo arriba", () => {
  const s = new Subagentes();
  s.evento(texto("sub:1", "a"));
  s.evento({ type: "tool_start", id: "sub:1/c9", name: "shell", label: "x", worker: "sub:1" });
  s.evento({ type: "tool_end", id: "sub:1/c9", name: "shell", isError: false, text: "", details: {}, worker: "sub:1" });
  s.evento(texto("sub:1", "b"));
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "x")] }) });
  const sub = s.evento(fin("c1", "sub:1"))!;
  assert.deepEqual(sub.registro.entradas().map((e) => (e.tipo === "texto" ? (e as unknown as { markdown: string }).markdown : e.tipo)), ["a", "acciones", "resultados", "b"]);
  assert.equal(sub.informe, "b");
});

test("subagentes: un worker del verificador no es un subagente", () => {
  const s = new Subagentes();
  assert.equal(s.evento({ type: "tool_start", id: "verificador:1/c1", name: "shell", label: "x", worker: "verificador:1" }), undefined);
  assert.deepEqual(s.lista(), []);
});

test("subagentes: sub:6 emite antes que sub:5: mientras corren, cada uno queda con el objetivo de su llamada", () => {
  const s = new Subagentes();
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "uno"), delegar("c2", "dos")] }) });
  s.evento(texto("sub:6", "b"));
  s.evento(texto("sub:5", "a"));
  assert.equal(s.de("sub:5")?.objetivo, "uno");
  assert.equal(s.de("sub:6")?.objetivo, "dos");
});

test("subagentes: al quedar la sesión en reposo, un sub que seguía trabajando pasa a «no terminó»", () => {
  const s = new Subagentes();
  s.evento({ type: "message", message: asistente({ toolCalls: [delegar("c1", "x"), delegar("c2", "y")] }) });
  s.evento(texto("sub:1", "parcial"));
  s.evento(texto("sub:2", "otro"));
  s.evento(fin("c2", "sub:2"));
  s.evento({ type: "idle" } as never);
  assert.equal(s.de("sub:1")?.estado, "no terminó");
  assert.equal(s.de("sub:1")?.informe, "parcial");
  assert.equal(typeof s.de("sub:1")?.fin, "number");
  assert.equal(s.de("sub:2")?.estado, "terminó");
});
