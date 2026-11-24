import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import type { AssistantMessage, Message } from "../src/llm.ts";
import { type Entrada, Registro } from "../src/tui/entradas.ts";

const asistente = (extra: Partial<AssistantMessage> = {}): AssistantMessage =>
  ({ role: "assistant", content: "", toolCalls: [], stopReason: "stop", provider: "p", model: "m", requestId: "r", at: 0, ...extra });
const HASH = "sha256:0123456789abcdef0123";

test("entradas: una acción une tool_start, tool_end y los argumentos de la llamada", () => {
  const r = new Registro();
  r.evento({ type: "message", message: asistente({ toolCalls: [{ id: "c1", name: "shell", arguments: '{"command":"git log"}' }], stopReason: "toolUse" }) });
  r.evento({ type: "tool_start", id: "c1", name: "shell", label: "Ejecutar shell" });
  r.evento({ type: "tool_end", id: "c1", name: "shell", isError: false, text: "", details: { artefacto: HASH, lineas: 5 } });
  const [accion, resultado] = r.entradas();
  assert.equal(r.entradas().length, 2);
  assert.equal(typeof (accion as { inicio?: number }).inicio, "number");
  assert.equal(typeof (accion as { fin?: number }).fin, "number");
  assert.deepEqual({ ...accion }, { id: accion!.id, tipo: "acciones", llamada: "c1", nombre: "shell", etiqueta: "Ejecutar shell", argumentos: { command: "git log" }, inicio: (accion as { inicio?: number }).inicio, fin: (accion as { fin?: number }).fin, estado: "ok", resumen: "artefacto 0123456789ab · lineas 5", worker: undefined });
  assert.deepEqual({ ...resultado }, { id: resultado!.id, tipo: "resultados", llamada: "c1", hash: HASH });
});

test("entradas: los argumentos se unen aunque el mensaje llegue después", () => {
  const r = new Registro();
  r.evento({ type: "tool_start", id: "c1", name: "shell", label: "x" });
  r.evento({ type: "message", message: asistente({ toolCalls: [{ id: "c1", name: "shell", arguments: '{"a":1}' }] }) });
  assert.deepEqual((r.entradas()[0] as { argumentos: unknown }).argumentos, { a: 1 });
});

test("entradas: el texto de la IA llega por partes y se cierra con el mensaje", () => {
  const r = new Registro();
  r.evento({ type: "text", delta: "Hola " });
  const [parcial] = r.evento({ type: "text", delta: "mundo" });
  assert.equal(parcial!.tipo === "texto" && parcial!.completo, false);
  r.evento({ type: "message", message: asistente({ content: "Hola mundo" }) });
  assert.equal(r.entradas().length, 1);
  const x = r.entradas()[0] as Extract<Entrada, { tipo: "texto" }>;
  assert.deepEqual({ ...r.entradas()[0]! }, { id: r.entradas()[0]!.id, tipo: "texto", markdown: "Hola mundo", completo: true, en: x.en, llegadas: x.llegadas });
  assert.equal(typeof x.en, "number");
  assert.deepEqual(x.llegadas!.map(([d]) => d), [0, 5]);
});

test("entradas: desde el snapshot se reconstruyen acciones y resultados completos", () => {
  const messages: Message[] = [
    { role: "user", content: "hacé algo\n\n<memoria>\nsecreto</memoria>", at: 0 } as Message,
    asistente({ content: "Voy", toolCalls: [{ id: "c1", name: "shell", arguments: '{"command":"ls"}' }], stopReason: "toolUse" }),
    { role: "tool", toolCallId: "c1", name: "shell", content: "salida entera", isError: true, at: 0 },
  ];
  const e = Registro.desdeSnapshot(messages).entradas();
  assert.deepEqual(e.map((x) => x.tipo), ["mensajes", "texto", "acciones", "resultados"]);
  assert.equal((e[0] as { texto: string }).texto, "hacé algo");
  assert.equal((e[2] as { estado: string }).estado, "error");
  assert.deepEqual((e[2] as { argumentos: unknown }).argumentos, { command: "ls" });
  assert.equal((e[3] as { texto?: string }).texto, "salida entera");
});

test("entradas: avisos de reintento, aviso del daemon y turno detenido", () => {
  const r = new Registro();
  r.evento({ type: "retry", attempt: 2, waitMs: 3000, reason: "429" });
  r.evento({ type: "notice", text: "ojo" });
  r.evento({ type: "recall", ids: ["a", "b"] });
  r.evento({ type: "answer", text: "listo" });
  r.evento({ type: "message", message: asistente({ stopReason: "aborted" }) });
  r.evento({ type: "message", message: asistente({ stopReason: "error", errorMessage: "boom" }) });
  const a = r.entradas().map((x) => (x.tipo === "avisos" ? [x.texto, x.tono] : x.tipo));
  assert.deepEqual(a, [
    ["El proveedor falló (429). Reintento 2 en 3 s.", "dim"], ["ojo", "warn"], ["memoria: a, b", "dim"],
    ["listo", "normal"], ["Turno detenido.", "dim"], ["boom", "warn"],
  ]);
});

test("entradas: un reintento descarta el texto parcial", () => {
  const r = new Registro();
  r.evento({ type: "text", delta: "Hol" });
  r.evento({ type: "retry", attempt: 1, waitMs: 1000, reason: "503" });
  r.evento({ type: "text", delta: "Hola completo" });
  r.evento({ type: "message", message: asistente({ content: "Hola completo" }) });
  const e = r.entradas();
  assert.deepEqual(e.map((x) => x.tipo), ["avisos", "texto"]);
  assert.equal((e[1] as { markdown: string }).markdown, "Hola completo");
});

test("registro: horas de llegada", () => {
  let n = 0;
  const r = new Registro(() => ++n * 1000);
  const m = r.mensaje("hola") as Extract<Entrada, { tipo: "mensajes" }>;
  assert.equal(m.en, 1000);
  r.evento({ type: "text", delta: "ab" });
  r.evento({ type: "text", delta: "cd" });
  const x = r.entradas()[1] as Extract<Entrada, { tipo: "texto" }>;
  assert.equal(x.en, 2000);
  assert.deepEqual(x.llegadas, [[0, 2000], [2, 3000]]);
  r.evento({ type: "tool_start", id: "c1", name: "shell", label: "x" });
  r.evento({ type: "tool_end", id: "c1", name: "shell", isError: false, text: "", details: {} });
  const a = r.entradas()[2] as Extract<Entrada, { tipo: "acciones" }>;
  assert.equal(a.inicio, 4000);
  assert.equal(a.fin, 5000);
});

test("registro: un retry descarta el texto parcial con sus llegadas, y el snapshot trae `at`", () => {
  const r = new Registro(() => 1);
  r.evento({ type: "text", delta: "ab" });
  r.evento({ type: "retry", reason: "x", attempt: 1, waitMs: 1000 });
  r.evento({ type: "text", delta: "cd" });
  const x = r.entradas().filter((e) => e.tipo === "texto") as Extract<Entrada, { tipo: "texto" }>[];
  assert.equal(x.length, 1);
  assert.deepEqual(x[0]!.llegadas, [[0, 1]]);
  const s = Registro.desdeSnapshot([{ role: "user", content: "hi", at: 777 }, asistente({ content: "yo", at: 888 })]);
  assert.deepEqual(s.entradas().map((e) => (e as { en?: number }).en), [777, 888]);
});

test("registro: el historial sin `at` no inventa una hora", () => {
  const r = Registro.desdeSnapshot([{ role: "user", content: "hi" } as unknown as Message, { role: "user", content: "yo", at: 5 }]);
  assert.deepEqual(r.entradas().map((e) => (e as { en?: number }).en), [undefined, 5]);
});

test("entradas: el texto de un subagente no entra al chat", () => {
  const r = new Registro();
  assert.deepEqual(r.evento({ type: "text", delta: "hola", worker: "sub:1" }), []);
  assert.equal(r.entradas().length, 0);
  assert.equal(r.evento({ type: "text", delta: "hola" }).length, 1);
  assert.equal(r.entradas().length, 1);
});
