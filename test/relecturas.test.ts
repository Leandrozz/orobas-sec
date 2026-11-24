import "./datos-tmp.ts";
// Relecturas idénticas (src/relecturas.ts): una salida igual a otra de la misma herramienta que sigue a la vista
// entra como referencia, salvo dentro de la ventana del detector de falta de avance. Sólo en la conversación
// principal: un subagente que comparte las herramientas no recibe referencias a un historial que no ve.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import type { Message } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";
import { referenciaRelectura, relecturaIgual, VENTANA_SIN_AVANCE } from "../src/relecturas.ts";

const salida = "línea del archivo\n".repeat(60);
const paso = (i: number): Message[] => [
  { role: "assistant", content: "", toolCalls: [{ id: `c${i}`, name: "http_request", arguments: "{}" }], stopReason: "toolUse", provider: "faux", model: "m", requestId: `r${i}`, at: 1 },
  { role: "tool", toolCallId: `c${i}`, name: "http_request", content: `h${i} GET 200`, isError: false, at: 1 },
];
const lectura = (i: number): Message[] => [
  { role: "assistant", content: "", toolCalls: [{ id: `l${i}`, name: "code_read", arguments: '{"path":"a.ts"}' }], stopReason: "toolUse", provider: "faux", model: "m", requestId: `l${i}`, at: 1 },
  { role: "tool", toolCallId: `l${i}`, name: "code_read", content: salida, isError: false, at: 1 },
];
const actual: Message = { role: "assistant", content: "", toolCalls: [{ id: "x", name: "code_read", arguments: '{"path":"a.ts"}' }], stopReason: "toolUse", provider: "faux", model: "m", requestId: "x", at: 1 };
const guardar = () => "sha256:" + "e".repeat(64);

test("una salida idéntica que sigue a la vista entra como referencia con su artefacto", () => {
  const mensajes = [...lectura(0), ...Array.from({ length: VENTANA_SIN_AVANCE }, (_, i) => paso(i)).flat(), actual];
  assert.equal(relecturaIgual(mensajes, "code_read", salida, guardar), referenciaRelectura("code_read", VENTANA_SIN_AVANCE + 1, guardar()));
  assert.match(referenciaRelectura("code_read", 5, "sha256:abc"), /^\[Sin cambios: code_read devolvió exactamente lo mismo que hace 5 pasos.*Completa en sha256:abc\.\]$/);
});

test("dentro de la ventana del detector de falta de avance, otra herramienta o un texto corto, entra entera", () => {
  const cerca = [...lectura(0), ...paso(1), actual];
  assert.equal(relecturaIgual(cerca, "code_read", salida, guardar), undefined);
  const lejos = [...lectura(0), ...Array.from({ length: 6 }, (_, i) => paso(i)).flat(), actual];
  assert.equal(relecturaIgual(lejos, "artifact_read", salida, guardar), undefined);
  assert.equal(relecturaIgual(lejos, "code_read", "corto", guardar), undefined);
  assert.equal(relecturaIgual(lejos, "code_read", `${salida}distinto`, guardar), undefined);
});

test("el motor la aplica sólo a la conversación principal, sobre lo que se envía", () => {
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-relectura-")), provider: resolveProvider("faux") });
  engine.agent.messages.push(...lectura(0), ...Array.from({ length: 6 }, (_, i) => paso(i)).flat(), actual);
  const alEntrar = (engine.agent as unknown as { options: { alEntrar: (n: string, r: { text: string }) => { text: string; details?: Record<string, unknown> } } }).options.alEntrar;
  const resultado = alEntrar("code_read", { text: salida });
  assert.match(resultado.text, /^\[Sin cambios: code_read/);
  assert.equal(resultado.details?.relectura, true);
  const puntero = /Completa en (sha256:[0-9a-f]{64})/.exec(resultado.text)![1]!;
  assert.equal(engine.artifacts.read(puntero).toString("utf8"), salida);
  // Otra herramienta con el mismo texto no cuenta como relectura.
  assert.equal(alEntrar("shell", { text: salida }).text, salida);
});
