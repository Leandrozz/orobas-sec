import "./datos-tmp.ts";
// El agente «informaba» un gasto inventado cuando se le preguntaba (dijo 5,25 y el real de la sesión era
// 0,46). El harness sabe el gasto real: cuando el operador pregunta, viaja como dato de sólo lectura en
// su mensaje (después del último punto de caché: ni el prompt de sistema ni lo anterior cambian), con la
// sesión separada de la carpeta entera. session_settings también los separa: antes mostraba el gasto de
// todas las sesiones de la carpeta junto al tope del proyecto, sin decir que no era el de la sesión.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import type { LlmRequest } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";
import { Registro } from "../src/tui/entradas.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-gasto-"));
const engine = (cwd: string) => new Engine({ cwd, provider: resolveProvider("faux"), autoVerify: false, cveFeed: false });
/** Anota en el libro un gasto de `usd` (USD 1 por millón de tokens, mitad entrada y mitad salida). */
function spend(target: Engine, usd: number, id: string): void {
  const tokens = Math.round((usd / 2) * 1_000_000);
  target.ledger.record(
    { role: "assistant", content: "", toolCalls: [], stopReason: "stop", provider: "faux", model: "faux", requestId: id, at: Date.now(), usage: { input: tokens, cacheRead: 0, cacheWrite: 0, output: tokens } },
    { sessionId: target.sessionId, account: "faux", worker: "principal", model: { ...target.agent.model, cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 } } },
  );
}

test("si el operador pregunta cuánto se gastó, el dato real de la sesión viaja en su mensaje, separado del de la carpeta", async () => {
  const cwd = tmp();
  const before = engine(cwd);
  spend(before, 4.79, "vieja");
  await before.close();
  const session = engine(cwd);
  const sent: Array<Pick<LlmRequest, "system" | "messages">> = [];
  const transport = session.provider.transport;
  session.provider.transport = (request) => { sent.push(JSON.parse(JSON.stringify({ system: request.system, messages: request.messages }))); return transport(request); };
  try {
    spend(session, 0.46, "esta");
    session.provider.faux!.queue = [{ text: "ok" }];
    await session.send("seguí con el login");
    assert.doesNotMatch(String(sent.at(-1)!.messages.at(-1)!.content), /<gasto>/, "sin pregunta, sin bloque");
    session.provider.faux!.queue = [{ text: "USD 0.46" }];
    await session.send("¿cuánto gastaste hasta ahora?");
    const asked = sent.at(-1)!;
    const last = String(asked.messages.at(-1)!.content);
    assert.match(last, /<gasto>[\s\S]*esta sesión[^\n]*USD 0\.46[\s\S]*<\/gasto>/);
    assert.match(last, /todas las sesiones de esta carpeta[^\n]*USD 5\.25/);
    assert.match(last, /no lo estimes/);
    // Nada del dato antes del último mensaje: el prompt de sistema y la historia (el prefijo cacheado) no cambian.
    assert.doesNotMatch(asked.system, /0\.46|5\.25/);
    assert.equal(asked.system, sent[0]!.system, "el prompt de sistema es el mismo");
    assert.deepEqual(asked.messages[0], sent[0]!.messages[0], "lo anterior viaja igual");
    for (const message of asked.messages.slice(0, -1)) assert.doesNotMatch(String(message.content), /<gasto>/);
    // En la pantalla del operador el bloque no se ve: es para el modelo.
    const shown = Registro.desdeSnapshot(session.agent.messages).entradas().filter((item) => item.tipo === "mensajes").map((item) => (item as { texto: string }).texto);
    assert.ok(shown.includes("¿cuánto gastaste hasta ahora?"), shown.join(" | "));
  } finally {
    await session.close();
  }
});

test("session_settings separa el gasto de esta sesión (el de la barra) del de todas las sesiones de la carpeta", async () => {
  const cwd = tmp();
  const before = engine(cwd);
  spend(before, 4.79, "vieja");
  await before.close();
  const session = engine(cwd);
  try {
    spend(session, 0.46, "esta");
    session.catalog.load("session_settings");
    session.provider.faux!.queue = [{ toolCalls: [{ name: "session_settings", arguments: {} }] }, { text: "ok" }];
    await session.send("mostrame los ajustes");
    const text = String(session.agent.messages.findLast((m) => m.role === "tool" && m.name === "session_settings")!.content);
    assert.match(text, /gasto de esta sesión[^\n]*USD 0\.46/);
    assert.match(text, /todas las sesiones de esta carpeta[^\n]*USD 5\.25/);
    assert.doesNotMatch(text, /tope del proyecto: [^\n]*gastado/, "el gasto de la carpeta ya no va pegado al tope como si fuera el de la sesión");
  } finally {
    await session.close();
  }
});
