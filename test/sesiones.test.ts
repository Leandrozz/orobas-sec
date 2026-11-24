import "./datos-tmp.ts";
// Sesiones en la TUI: /sesiones lista con estado y actividad, retoma otra sesión en la misma pantalla
// (la conversación vuelve), abre una nueva, ramifica y renombra. Y el módulo detrás: filas, detalle, fork.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";
import { decodeRows, encodeRows, relative } from "../src/sesiones.ts";
import { startFoco } from "../src/tui/foco.ts";
import { stripAnsi } from "../src/tui/text.ts";

const tick = (ms = 30) => new Promise((resolve) => setTimeout(resolve, ms));
let screen = () => "";
const until = async (done: () => boolean, ms = 6000) => { for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5); assert.ok(done(), `se agotó la espera · pantalla:\n${screen().slice(-1500)}`); };

test("relative: ahora, minutos, horas, ayer, días, fecha", () => {
  const now = Date.parse("2026-11-16T20:00:00Z");
  assert.equal(relative("2026-11-16T19:59:40Z", now), "ahora");
  assert.equal(relative("2026-11-16T19:48:00Z", now), "hace 12 min");
  assert.equal(relative("2026-11-16T15:00:00Z", now), "hace 5 h");
  assert.equal(relative("2026-11-15T19:00:00Z", now), "ayer");
  assert.equal(relative("2026-11-10T19:00:00Z", now), "hace 6 d");
  assert.equal(relative("2026-09-01T19:00:00Z", now), "2026-09-01");
});

test("/sesiones: nueva sesión en la misma pantalla, retomar la anterior con su conversación, ramificar y renombrar", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-sesiones-"));
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux") });
  await daemon.listen();
  const state = { written: "", input: (_: string) => {} };
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    const first = await client.attach({ session: "new" });
    startFoco(client, first, { io: { output: { write: (data) => void (state.written += data), columns: 100, rows: 40 }, listen: (onData) => ((state.input = onData), () => {}) }, animate: false });
    const plain = () => stripAnsi(state.written);
    screen = plain;
    const reset = () => (state.written = "");
    state.input("hola orobas, primera sesión\r");
    await until(() => plain().includes("Respuesta simulada"));
    await until(() => !client.status.running);

    // El menú: la actual marcada, con actividad, mensajes y gasto; «nueva sesión» arriba.
    reset();
    state.input("/sesiones\r");
    await until(() => plain().includes("nueva sesión"));
    assert.match(plain(), /▶ ahora\s+hola orobas, primera sesión/);
    assert.match(plain(), new RegExp(`${first.sessionId.slice(0, 8)} · 2 msj · USD`));
    assert.match(plain(), /otros proyectos/);
    state.input("\x1b[A\r"); // ↑ a «nueva sesión» y Enter
    await until(() => plain().includes("Sesión nueva"));
    await until(() => client.status.session !== undefined && client.status.session !== first.sessionId);
    const second = client.status.session!;
    reset();
    state.input("/sesiones\r");
    await until(() => plain().includes("nueva sesión"));
    assert.doesNotMatch(plain().split("otros proyectos")[0]!, /hola orobas, primera sesión[\s\S]*▶/, "la nueva está marcada, no la vieja");

    // Retomar la primera: la conversación vuelve a la pantalla y el pie cambia de sesión.
    state.input("\x1b[B\r"); // ↓ a la sesión vieja (la actual está primera) y Enter
    await until(() => /retomar acá/i.test(plain()));
    assert.match(plain(), /ramificar|renombrar|detalle/i);
    state.input("\r");
    await until(() => plain().includes("retomada: 2 mensajes"));
    assert.equal(client.status.session, first.sessionId);
    assert.match(plain(), /hola orobas, primera sesión/);

    // Ramificar y renombrar por el daemon (lo que hace el menú).
    const [fork] = await client.ask("sesiones", { action: "fork", session: first.sessionId });
    assert.match(fork!, /^[0-9a-f-]{36}$/);
    const rows = decodeRows(await client.ask("sesiones", { action: "list" }));
    const forked = rows.find((r) => r.id === fork)!;
    assert.equal(forked.messages, 2, "la rama arranca con la conversación copiada");
    assert.match(forked.title, /^↳ hola orobas/);
    assert.ok(rows.find((r) => r.id === second)!.messages === 0);
    assert.deepEqual(decodeRows(encodeRows(rows)), rows, "las filas viajan en tabuladores y vuelven iguales");
    assert.deepEqual(await client.ask("sesiones", { action: "rename", session: first.sessionId.slice(0, 8), title: "Objetivo de prueba" }), [`Sesión ${first.sessionId.slice(0, 8)} renombrada.`]);
    await until(() => client.status.title === "Objetivo de prueba");
    const detail = await client.ask("sesiones", { action: "detalle", session: first.sessionId });
    assert.match(detail[0]!, /^SESIÓN .* · (abierta|guardada)/);
    assert.equal(detail[1], "Objetivo de prueba");
    assert.match(detail.join("\n"), /2 mensajes[\s\S]*Vos: hola orobas, primera sesión[\s\S]*Orobas: Respuesta simulada/);
    assert.match((await client.view("sesiones")).join("\n"), /SESIONES[\s\S]*▶ .*Objetivo de prueba/);
    await assert.rejects(client.ask("sesiones", { action: "detalle", session: "nope" }), /No existe la sesión/);
    client.close();
  } finally {
    daemon.close();
  }
});
