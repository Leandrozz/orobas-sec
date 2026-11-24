import "./datos-tmp.ts";
// Turnos que no dejan al operador empujando: sacado de las trazas reales, donde 44 de 266 mensajes del
// operador eran «retoma», «y?», «dale»… El turno sigue solo si avanzó, se reanuda con el tope que tenía,
// lo que se escribe durante un turno se ve en cola (sin repetidos) y se puede mandar ya cortando el turno.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Agent, type Tool } from "../src/agent.ts";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { Engine } from "../src/engine.ts";
import { storedBudget } from "../src/ledger.ts";
import type { Message } from "../src/llm.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";
import { abrirProyecto } from "../src/tui/ajustes.ts";
import { startFoco } from "../src/tui/foco.ts";
import { findCommand } from "../src/tui/comandos.ts";
import { KeyParser } from "../src/tui/keys.ts";
import { fakeIO } from "./fake-io.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

// Los avisos nuevos son bilingües: la prueba los mira en castellano.
process.env.LC_ALL = "es_AR.UTF-8";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};
const tmp = () => mkdtempSync(join(tmpdir(), "cyber-turnos-"));
const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const events = (engine: Engine, type: string) =>
  (engine.db.prepare("select payload from events where session_id=? and type=? order by seq").all(engine.sessionId, type) as Array<{ payload: string }>).map((row) => JSON.parse(row.payload) as Record<string, unknown>);
const users = (messages: Message[]) => messages.flatMap((m) => (m.role === "user" ? [String(m.content)] : []));

/** Toda llamada del asistente tiene su resultado, y ningún resultado queda sin su llamada. */
function consistent(messages: Message[]): void {
  const calls = messages.flatMap((m) => (m.role === "assistant" ? m.toolCalls.map((c) => c.id) : []));
  const results = messages.flatMap((m) => (m.role === "tool" ? [m.toolCallId] : []));
  assert.deepEqual([...results].sort(), [...calls].sort(), "cada llamada con su resultado");
}

function engineWith(options: { maxSteps?: number; budget?: string } = {}) {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico(options.budget ?? "5"), maxSteps: options.maxSteps, coverageObjections: 0, closingGate: false, autoVerify: false });
  const notices: string[] = [];
  engine.onNotice = (text) => void notices.push(text);
  return { engine, provider, notices, done: () => { engine.close(); rmSync(cwd, { recursive: true, force: true }); } };
}

const CATEGORIAS = ["reconocimiento", "autenticacion", "control de acceso", "inyeccion", "logica de negocio"];

test("tope de pasos con avance: el turno sigue solo, avisa y para a las 3 continuaciones seguidas", async () => {
  const { engine, provider, notices, done } = engineWith({ maxSteps: 2 });
  try {
    // Cada paso marca cobertura (avance): 4 tramos de 2 pasos = 3 continuaciones y el corte por tope.
    provider.faux!.queue = [
      ...Array.from({ length: 8 }, (_, i) => call("coverage_mark", { category: CATEGORIAS[i % CATEGORIAS.length], state: "limitada", note: `paso ${i}` })),
      { text: "Marqué la cobertura. Nada nuevo. Sigue: autenticación." },
    ];
    await engine.send("Recorré la cobertura");
    const continued = events(engine, "turn.continuado");
    assert.deepEqual(continued.map((e) => e.n), [1, 2, 3]);
    assert.ok(continued.every((e) => Number(e.cobertura) === 2 && e.de === 3));
    const systemTurns = users(engine.agent.messages).filter((text) => text.startsWith("[sistema] Llegaste al tope de 2 pasos de este tramo y hubo avance"));
    assert.equal(systemTurns.length, 3);
    assert.match(notices.find((n) => n.startsWith("Sigo solo (1 de 3)"))!, /llegué al tope de 2 pasos, pero el turno avanzó \(2 marcas de cobertura\)\. Esc lo detiene\./);
    // Al cuarto tope ya no sigue: se corta como siempre y se dice por qué.
    assert.deepEqual(events(engine, "turn.tope").map((e) => e.motivo), ["tope de continuaciones"]);
    assert.ok(notices.some((n) => /^Paré: ya seguí solo 3 veces seguidas en este turno \(8 pasos\)/.test(n)));
    assert.ok(engine.agent.messages.some((m) => m.role === "assistant" && /Límite de pasos/.test(m.errorMessage ?? "")));
    assert.equal(engine.agent.messages.at(-1)!.content, "Marqué la cobertura. Nada nuevo. Sigue: autenticación.");
    consistent(engine.agent.messages);
    // Un turno nuevo del operador vuelve a tener sus 3 continuaciones.
    provider.faux!.queue = [call("coverage_mark", { category: "inyeccion", state: "limitada", note: "otra" }), call("coverage_mark", { category: "reconocimiento", state: "cubierta", note: "otra" }), { text: "Listo." }];
    await engine.send("seguí");
    assert.equal(events(engine, "turn.continuado").at(-1)!.n, 1);
  } finally { done(); }
});

test("tope de pasos sin avance: corta como siempre, sin continuar, y el aviso dice por qué paró", async () => {
  const { engine, provider, notices, done } = engineWith({ maxSteps: 2 });
  try {
    provider.faux!.queue = [call("memory_search", { query: "a" }), call("memory_search", { query: "b" }), { text: "Busqué dos veces y no hay nada." }];
    await engine.send("Buscá");
    assert.equal(events(engine, "turn.continuado").length, 0);
    assert.deepEqual(events(engine, "turn.tope").map((e) => e.motivo), ["sin avance"]);
    assert.match(notices.join("\n"), /Paré: llegué al tope de 2 pasos y el último tramo no avanzó \(ni hallazgos, ni cobertura, ni respuestas HTTP nuevas\)/);
    assert.ok(users(engine.agent.messages).some((text) => text.startsWith("[sistema] El turno terminó (Límite de pasos")));
    assert.equal(engine.agent.messages.at(-1)!.content, "Busqué dos veces y no hay nada.");
  } finally { done(); }
});

test("tope de pasos con avance y mensajes en cola: no sigue solo, atiende lo que escribió el operador", async () => {
  const { engine, provider, notices, done } = engineWith({ maxSteps: 2 });
  try {
    provider.faux!.queue = [
      call("coverage_mark", { category: "reconocimiento", state: "limitada", note: "a" }),
      call("coverage_mark", { category: "inyeccion", state: "limitada", note: "b" }),
      { text: "Marqué dos categorías." },
      { text: "Voy con el login." },
    ];
    engine.agent.on((event) => { if (event.type === "tool_end" && event.name === "coverage_mark") engine.send("probá el login"); });
    await engine.send("Marcá");
    assert.equal(events(engine, "turn.continuado").length, 0);
    assert.deepEqual(events(engine, "turn.tope").map((e) => e.motivo), ["cola"]);
    assert.match(notices.join("\n"), /en vez de seguir solo, atiendo lo que dejaste en cola/);
    assert.equal(users(engine.agent.messages).filter((text) => text.startsWith("probá el login")).length, 1, "encolado una sola vez");
    assert.equal(engine.agent.messages.at(-1)!.content, "Voy con el login.");
  } finally { done(); }
});

test("tope de pasos con avance pero sin presupuesto: no sigue solo", async () => {
  const { engine, provider, notices, done } = engineWith({ maxSteps: 2, budget: "5" });
  try {
    provider.faux!.queue = [call("coverage_mark", { category: "reconocimiento", state: "limitada", note: "a" }), call("coverage_mark", { category: "inyeccion", state: "limitada", note: "b" })];
    // El tope baja a cero con la última marca del tramo (el modelo simulado no cobra): al llegar al tope
    // de pasos no alcanza para otro tramo.
    let marks = 0;
    engine.agent.on((event) => { if (event.type === "tool_end" && event.name === "coverage_mark" && ++marks === 2) engine.ledger.budgetPico = 0n; });
    await engine.send("Marcá");
    assert.equal(events(engine, "turn.continuado").length, 0);
    assert.deepEqual(events(engine, "turn.tope").map((e) => e.motivo), ["presupuesto"]);
    assert.match(notices.join("\n"), /no sigo solo: Presupuesto de sesión/);
  } finally { done(); }
});

test("reanudación automática: el daemon reabre la sesión con el tope que tenía, no con USD 2.00", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  // Una sesión con tope de USD 7 que el proceso dejó a medio turno.
  const crashed = new Engine({ cwd, provider, budgetPico: usdToPico("7") });
  assert.equal(storedBudget(crashed.db, crashed.sessionId), usdToPico("7"));
  provider.faux!.queue = [call("fixture_run", { name: "atlas-permisos" })];
  const crash = new Error("caída simulada");
  crashed.agent.on((event) => { if (event.type === "tool_start") throw crash; });
  await assert.rejects(crashed.send("Trabajá"), crash);
  crashed.db.prepare("delete from events where type='turn.ended'").run();
  const id = crashed.sessionId;
  crashed.close();
  provider.faux!.queue = [{ text: "Retomado con mi tope." }];
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const host = daemon.hosts.get(id)!;
    assert.ok(host, "retomó la sesión interrumpida");
    assert.equal(host.engine.ledger.budgetPico, usdToPico("7"));
    await until(() => !host.engine.agent.running && host.engine.agent.messages.at(-1)?.content === "Retomado con mi tope.");
    // Un cambio de tope (comando o ajuste del agente) también queda guardado para la próxima vez.
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: id });
    assert.match((await client.ask("budget", { value: "9.5" }))[0]!, /USD 9\.50/);
    client.close();
  } finally { await daemon.close(); }
  const again = new Daemon({ cwd, resolve: () => provider, autoResume: false });
  await again.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    const snapshot = await client.attach({ session: id });
    assert.equal(snapshot.sessionId, id);
    assert.equal(again.hosts.get(id)!.engine.ledger.budgetPico, usdToPico("9.5"));
    // Pedido explícito gana; «sin» se guarda como sin tope.
    assert.match((await client.ask("budget", { value: "sin" }))[0]!, /Sesión sin tope/);
    assert.equal(storedBudget(again.hosts.get(id)!.engine.db, id), "sin");
    client.close();
  } finally { await again.close(); rmSync(cwd, { recursive: true, force: true }); }
});

async function armarTui() {
  const cwd = tmp();
  process.env.CYBER_CONFIG = join(cwd, "config.json");
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  abrirProyecto(cwd);
  const state = { written: "", input: (_: string) => {}, exited: false };
  const output = { write: (data: string) => void (state.written += data), columns: 90, rows: 30 };
  const client = await connectDaemon(cwd, { spawn: false });
  const snapshot = await client.attach({ session: "new" });
  startFoco(client, snapshot, {
    project: cwd,
    io: { output, listen: (onData) => ((state.input = onData), () => {}) },
    onExit: () => ((state.exited = true), client.close()),
  });
  const visible = () => pantallaVisible(state.written, output.columns, output.rows).join("\r\n");
  const host = () => [...daemon.hosts.values()][0]!;
  return { cwd, state, provider, daemon, client, visible, host, done: async () => { await daemon.close(); rmSync(cwd, { recursive: true, force: true }); } };
}

test("cola visible: lo que se escribe durante un turno queda a la vista, no se encola dos veces y avisa al entrar", async () => {
  const t = await armarTui();
  let release!: () => void;
  try {
    const gate = new Promise<void>((resolve) => (release = resolve));
    t.host().engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
    t.provider.faux!.queue = [{ text: "Empiezo.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Terminé." }, { text: "Ahora el informe." }];
    t.state.input("trabajá\r");
    await until(() => t.host().engine.agent.running && /Esperar/.test(t.visible()));
    t.state.input("armá el reporte para hackenproof\r");
    await until(() => /en cola \(1\)/.test(t.visible()));
    assert.match(t.visible(), /\r\n  en cola \(1\) «armá el reporte para hackenproof» +Ctrl\+Y manda ya · \/cola/);
    assert.match(t.visible(), /en cola · sale cuando termine el turno · Ctrl\+Y lo manda ya/);
    // El operador no ve que entró y lo reenvía (con otras mayúsculas y espacios): no se encola dos veces.
    t.state.input("Armá  el reporte para HackenProof\r");
    await until(() => /ya está en cola: no lo mando de nuevo/.test(t.visible()));
    assert.equal(t.host().engine.queue.length, 1);
    // Por el daemon, sin la TUI de por medio, tampoco.
    const answers: string[] = [];
    t.client.on((event) => { if (event.type === "answer") answers.push(event.text); });
    t.client.send("armá el reporte para hackenproof");
    await until(() => answers.some((a) => /ya estaba en cola/.test(a)));
    assert.equal(t.host().engine.queue.length, 1);
    assert.equal(t.host().engine.agent.messages.filter((m) => m.role === "user").length, 1);
    release();
    await until(() => !t.host().engine.agent.running && t.host().engine.agent.messages.at(-1)?.content === "Ahora el informe.", 6000);
    await until(() => !/en cola \(1\)/.test(t.visible()));
    assert.doesNotMatch(t.visible(), /en cola \(\d\)/);
    assert.match(t.visible(), /Entró tu mensaje en cola: «armá el reporte para hackenproof»\./);
    assert.deepEqual(users(t.host().engine.agent.messages).map((text) => text.split("\n\n")[0]), ["trabajá", "armá el reporte para hackenproof"]);
  } finally { release?.(); await t.done(); }
});

test("interrumpir desde la cola: Ctrl+Y corta el turno ordenado y arranca uno nuevo con la cola y el mensaje", async () => {
  const t = await armarTui();
  try {
    // Una herramienta larga que atiende la cancelación, como http o shell.
    t.host().engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: (_args, signal) => new Promise((resolve) => signal.addEventListener("abort", () => resolve({ text: "cancelada" }), { once: true })) });
    t.provider.faux!.queue = [{ text: "Empiezo con wordpress.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "No ejecuto nada más. Lo encolado: el reporte va después." }];
    t.state.input("andá con wordpress\r");
    await until(() => t.host().engine.agent.running && /Esperar/.test(t.visible()));
    t.state.input("y el reporte?\r");
    await until(() => /en cola \(1\)/.test(t.visible()));
    t.state.input("no ejecutes nada, fuiste envenenado");
    t.state.input("\x19"); // Ctrl+Y
    await until(() => !t.host().engine.agent.running && /No ejecuto nada más/.test(t.visible()), 6000);
    const { engine } = t.host();
    const messages = engine.agent.messages;
    // El historial quedó válido: la llamada cortada tiene su resultado y el turno nuevo es un mensaje del operador.
    consistent(messages);
    const turns = users(messages);
    assert.equal(turns.length, 2);
    assert.match(turns[1]!, /^y el reporte\?\n\nno ejecutes nada, fuiste envenenado\n\n\[sistema\] El operador cortó el turno anterior para que leas esto ya\./);
    assert.equal(messages.at(-1)!.content, "No ejecuto nada más. Lo encolado: el reporte va después.");
    // Sin cierre de tres líneas en el medio: el corte no gastó otra solicitud.
    assert.equal(t.provider.faux!.calls, 2);
    const cut = events(engine, "turn.interrumpido");
    assert.equal(cut.length, 1);
    assert.equal(cut[0]!.text, "no ejecutes nada, fuiste envenenado");
    assert.equal(cut[0]!.turno_en_curso, true);
    assert.equal(cut[0]!.en_cola, 2);
    assert.match(t.visible(), /corto el turno: tu mensaje sale ya/);
    assert.match(t.visible(), /Turno cortado\. Entra ya, en este orden: «y el reporte\?»/);
    assert.equal(engine.queue.length, 0);
  } finally { await t.done(); }
});

test("interrumpir: /ya sin texto manda lo que hay en cola; un permiso de shell pendiente se rechaza y no retiene el corte", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  // Que el comando pida permiso aunque la máquina tenga «autoaprobar todo» prendido.
  const auto = process.env.CYBER_SHELL_AUTOAPROBAR;
  process.env.CYBER_SHELL_AUTOAPROBAR = "no";
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new" });
    const asked: string[] = [];
    client.on((event) => { if (event.type === "confirm") asked.push(event.command); });
    const { engine } = [...daemon.hosts.values()][0]!;
    provider.faux!.queue = [call("shell", { command: "touch archivo-de-prueba" }), { text: "Paro. ¿Qué pasó?" }];
    client.send("creá el archivo");
    await until(() => asked.length === 1);
    assert.equal(engine.agent.running, true);
    client.send("le pegaste a prod??");
    await until(() => engine.queue.length === 1);
    assert.match((await client.ask("queue", { action: "ya" }))[0]!, /Corto el turno y mando ya el mensaje en cola/);
    await until(() => !engine.agent.running && engine.agent.messages.at(-1)?.content === "Paro. ¿Qué pasó?", 6000);
    consistent(engine.agent.messages);
    const shell = engine.agent.messages.find((m) => m.role === "tool" && m.name === "shell");
    assert.match(String(shell?.content), /^Rechazado: touch archivo-de-prueba/);
    assert.match(users(engine.agent.messages)[1]!, /^le pegaste a prod\?\?\n\n\[sistema\] El operador cortó el turno anterior/);
    // Sin nada en cola ni texto, no hay qué mandar.
    assert.match((await client.ask("queue", { action: "ya" }))[0]!, /Nada en cola para mandar/);
    client.close();
  } finally {
    if (auto === undefined) delete process.env.CYBER_SHELL_AUTOAPROBAR; else process.env.CYBER_SHELL_AUTOAPROBAR = auto;
    await daemon.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("interrumpir sin turno en curso: el mensaje sale como uno común, sin aviso de corte", async () => {
  const { engine, provider, done } = engineWith();
  try {
    provider.faux!.queue = [{ text: "Hola." }];
    await engine.interrupt("hola");
    assert.deepEqual(users(engine.agent.messages).map((text) => text.split("\n\n")[0]), ["hola"]);
    assert.ok(!users(engine.agent.messages)[0]!.includes("cortó el turno"));
    assert.equal(events(engine, "turn.interrumpido")[0]!.turno_en_curso, false);
    await assert.rejects(engine.interrupt(""), /No hay nada para mandar ya/);
  } finally { done(); }
});

test("interrumpir: una herramienta que no atiende la cancelación no deja la llamada colgada", async () => {
  const provider = resolveProvider("faux");
  const stuck: Tool = { name: "colgada", label: "Colgada", description: "", parameters: { type: "object" }, execute: () => new Promise(() => {}) };
  const agent = new Agent({ system: "", model: provider.model, tools: [stuck], transport: provider.transport, abortGraceMs: 30 });
  provider.faux!.queue = [call("colgada", {})];
  let started = false;
  agent.on((event) => { if (event.type === "tool_start") started = true; });
  const turn = agent.prompt("hacé algo");
  await until(() => started);
  agent.abort();
  await turn;
  assert.equal(agent.running, false);
  consistent(agent.messages);
  const result = agent.messages.find((m) => m.role === "tool");
  assert.equal(result?.role === "tool" && result.isError, true);
  assert.match(String(result?.content), /^Llamada cortada: el operador detuvo el turno/);
});

test("/ya y /cola: mandan ya con la TUI; sin TUI, /ya manda lo que hay en cola", async () => {
  const sent: string[] = [];
  const { io, calls } = fakeIO({ queue: ["Corto el turno y mando ya el mensaje en cola."] });
  assert.equal(await findCommand("ya")!.run({ ...io, interrupt: (text) => void sent.push(text) }, "no ejecutes nada"), null);
  assert.deepEqual(sent, ["no ejecutes nada"]);
  const panel = await findCommand("ya")!.run(io, "");
  assert.deepEqual(calls.at(-1), { op: "queue", payload: { action: "ya" } });
  assert.match(panel!.lines.join("\n"), /Corto el turno/);
  assert.ok(findCommand("ya")!.hidden, "/ya no ocupa lugar en la lista de /");
  // En el menú de /cola, «mandar ya» pide lo mismo.
  const menu = fakeIO({ "queue:{\"action\":\"list\"}": ["1 mensaje en cola, salen juntos cuando termine el turno:", "1. y el reporte?"] }, [1]);
  await findCommand("cola")!.run(menu.io, "");
  assert.deepEqual(menu.picked[0]!.labels, ["ver", "mandar ya", "vaciar"]);
  assert.deepEqual(menu.calls.at(-1), { op: "queue", payload: { action: "ya" } });
});

test("teclas: Ctrl+Y llega como byte 0x19 y Ctrl+Enter sólo con un protocolo que lo distinga", () => {
  const parser = new KeyParser();
  assert.deepEqual(parser.parse("\x19"), [{ name: "ctrl+y" }]);
  assert.deepEqual(parser.parse("\x1b[121;5u"), [{ name: "ctrl+y" }]); // kitty con desambiguación
  assert.deepEqual(parser.parse("\x1b[13;5u"), [{ name: "ctrl+enter" }]);
  assert.deepEqual(parser.parse("\x1b[27;5;13~"), [{ name: "ctrl+enter" }]); // xterm con modifyOtherKeys
  // En el modo clásico (el de la TUI) kitty manda Ctrl+Enter como Enter y Alt+Enter como salto de línea.
  assert.deepEqual(parser.parse("\r"), [{ name: "enter" }]);
  assert.deepEqual(parser.parse("\x1b\r"), [{ name: "newline" }]);
});
