import "./datos-tmp.ts";
import { projectPaths } from "../src/store.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { decode } from "@toon-format/toon";
import { validate } from "../src/agent.ts";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { Engine } from "../src/engine.ts";
import { anthropicMessages, type AssistantMessage, normalizeUsage, openAICompletions } from "../src/llm.ts";
import { ratePico, usd, usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";
import { configureAccount } from "../src/cuenta.ts";
import { parseRule, scopeTag } from "../src/scope.ts";

// Estas pruebas miran el transporte, no la cuenta: una cuenta verificada de mentira deja pasar cualquier proveedor.
process.env.OROBAS_API_KEY = "oro_" + "a".repeat(48);
configureAccount({ fetch: (async () => new Response(JSON.stringify({ object: "account", name: "prueba", verification: "completa", plan: "profesional", tier_usd: 0 }))) as typeof fetch });

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-"));
const lastAssistant = (engine: Engine) => engine.agent.messages.at(-1) as AssistantMessage;
/** La memoria es del programa: las sesiones que la usan trabajan el mismo alcance (el laboratorio Atlas). */
const atlas = (engine: Engine) => engine.scope.save({ source: "manual", include: [parseRule("atlas.test")], exclude: [], notes: "" });
/** El último error del turno: después viene el cierre para el operador (un turno nunca termina en silencio). */
const lastError = (engine: Engine) => engine.agent.messages.findLast((m) => m.role === "assistant" && m.stopReason === "error") as AssistantMessage;

test("dinero: picoUSD exacto y redondeo de presentación", () => {
  assert.equal(ratePico(0.006), 6000n);
  assert.equal(ratePico("15.625"), 15_625_000n);
  assert.equal(usdToPico("2.00"), 2_000_000_000_000n);
  assert.equal(usd(21_600_000_000n), "0.0216");
  assert.throws(() => ratePico("-1"));
});

test("recorrido: herramienta → artefacto → memoria → contabilidad → reanudación", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  provider.faux!.queue = [
    { toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }], requestId: "r1" },
    { toolCalls: [{ name: "memory_write", arguments: { type: "observacion", title: "Reembolsos accesibles al comprador", summary: "En el fixture Atlas, /api/operador/reembolsos responde 200 al comprador.", tags: ["permisos"] } }], requestId: "r2" },
    { text: "Dos candidatos sintéticos guardados.", requestId: "r3" },
  ];
  const engine = new Engine({ cwd, provider });
  atlas(engine);
  await engine.send("Revisá permisos entre comprador y operador.");
  assert.equal(lastAssistant(engine).content, "Dos candidatos sintéticos guardados.");

  // El resultado completo quedó como artefacto; el modelo recibió sólo los candidatos.
  const toolResult = engine.agent.messages.find((m) => m.role === "tool" && m.name === "fixture_run")!;
  const view = decode(toolResult.content as string) as any;
  assert.equal(view.candidatos.length, 2);
  assert.equal(view.rutas, 18);
  assert.equal(JSON.parse(engine.artifacts.read(view.artefacto).toString()).matrix.length, 18);

  // Memoria: archivo TOON canónico + índice.
  assert.equal(readdirSync(projectPaths(cwd).records).length, 1);
  assert.equal(engine.vault.search("reembolsos comprador")[0]?.type, "observacion");

  // Contabilidad: tres solicitudes únicas; el modelo simulado no tiene tarifa → costo pendiente.
  const session = engine.ledger.totals(engine.sessionId);
  assert.equal(session.requests, 3);
  assert.equal(session.unknownRequests, 3);
  assert.ok(session.tokens.input > 0);
  assert.ok(engine.contextTokens() > 0);
  const sessionId = engine.sessionId;
  const count = engine.agent.messages.length;
  engine.close();

  // Mismo proyecto, misma sesión: retoma mensajes y no duplica gasto.
  provider.faux!.queue = [{ text: "Sigo desde donde quedamos.", requestId: "r4" }];
  const resumed = new Engine({ cwd, provider, resume: true });
  assert.equal(resumed.sessionId, sessionId);
  assert.equal(resumed.agent.messages.length, count);
  await resumed.send("¿Qué pasaba con reembolsos?");
  assert.equal(resumed.ledger.totals().requests, 4);
  resumed.close();

  // Sesión nueva: recupera el recuerdo relevante en el mensaje, sin cargar todo el vault.
  provider.faux!.queue = [{ text: "Lo tengo.", requestId: "r5" }];
  const fresh = new Engine({ cwd, provider });
  atlas(fresh);
  assert.notEqual(fresh.sessionId, sessionId);
  await fresh.send("¿Qué sabemos de reembolsos?");
  assert.equal(fresh.lastRecall.length, 1);
  assert.match(fresh.agent.messages[0]!.content as string, /<memoria>/);
  assert.equal(fresh.ledger.totals(fresh.sessionId).requests, 1);
  assert.equal(fresh.ledger.totals().requests, 5);
  fresh.close();
});

test("agente: argumentos inválidos, herramienta desconocida, intervención y corte", async () => {
  assert.equal(validate({ type: "object", required: ["a"], properties: { a: { type: "string" } } }, { a: 1 }), "argumentos.a: se esperaba texto");
  assert.match(validate({ type: "object", required: ["a"] }, {})!, /falta «a»/);
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider });
  provider.faux!.queue = [
    { toolCalls: [{ name: "memory_read", arguments: {} }, { name: "no_existe", arguments: {} }] },
    { text: "Corregido." },
    { text: "Respondo a la intervención." },
  ];
  // El operador interviene mientras corre el turno: entra antes de terminar.
  engine.agent.on((event) => {
    if (event.type === "tool_start" && event.name === "no_existe") engine.agent.steer("Cambiá de foco.");
  });
  await engine.send("Probá");
  const roles = engine.agent.messages.map((m) => m.role);
  assert.deepEqual(roles, ["user", "assistant", "tool", "tool", "user", "assistant"]);
  assert.ok(engine.agent.messages.filter((m) => m.role === "tool").every((m) => m.isError));
  assert.equal(engine.agent.messages[4]!.content, "Cambiá de foco.");

  // Corte durante una herramienta: el transcript queda válido y el turno termina.
  provider.faux!.queue = [{ toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }, { name: "fixture_run", arguments: { name: "atlas-permisos" } }] }, { text: "no debería llegar" }];
  engine.agent.on((event) => event.type === "tool_start" && engine.abort());
  await engine.send("Cortá");
  assert.equal(engine.agent.running, false);
  assert.equal(provider.faux!.queue.length, 1);
  assert.equal(engine.agent.messages.at(-1)!.role, "tool");
  engine.close();
});

test("bucle: reintentos, paralelo, llamadas repetidas y salidas grandes", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider, retryBaseMs: 1 });
  const events: string[] = [];
  engine.agent.on((event) => events.push(event.type === "retry" ? `retry${event.attempt}` : event.type === "tool_start" || event.type === "tool_end" ? `${event.type}:${event.name}` : event.type));

  // Dos fallas transitorias y después responde: un solo mensaje en el transcript, tres solicitudes contadas.
  provider.faux!.queue = [{ fail: { message: "HTTP 503", retryable: true } }, { fail: { message: "HTTP 429", retryable: true } }, { text: "Listo." }];
  await engine.send("hola");
  assert.deepEqual(engine.agent.messages.map((m) => m.role), ["user", "assistant"]);
  assert.deepEqual(events.filter((e) => e.startsWith("retry")), ["retry1", "retry2"]);
  assert.equal(engine.ledger.totals(engine.sessionId).requests, 3);
  // Un error no transitorio no se reintenta.
  provider.faux!.queue = [{ fail: { message: "HTTP 401", rejected: true } }, { text: "no llega" }];
  await engine.send("otra");
  assert.equal(lastError(engine).stopReason, "error");
  // El proveedor rechazó: el cierre lo arma el harness, sin otra solicitud.
  assert.match(lastAssistant(engine).content, /^Corté el turno: HTTP 401/);
  assert.equal(provider.faux!.queue.length, 1);

  // Lecturas juntas: ambas empiezan antes de que termine la primera. La repetida no se vuelve a ejecutar.
  events.length = 0;
  const call = { name: "fixture_run", arguments: { name: "atlas-permisos" } };
  provider.faux!.queue = [{ toolCalls: [call, { name: "memory_search", arguments: { query: "permisos" } }] }, { toolCalls: [call] }, { text: "fin" }];
  await engine.send("corré");
  const order = events.filter((e) => e.startsWith("tool_"));
  assert.deepEqual(order.slice(0, 2), ["tool_start:fixture_run", "tool_start:memory_search"]);
  const results = engine.agent.messages.filter((m) => m.role === "tool" && m.name === "fixture_run");
  assert.match(results[1]!.content as string, /Llamada idéntica/);

  // Salida enorme: al modelo va una ventana; el total queda como artefacto.
  engine.agent.tools.push((engine as any).bounded({ name: "volcar", label: "Volcar", description: "", parameters: { type: "object" }, execute: () => ({ text: "línea\n".repeat(5000) }) }));
  provider.faux!.queue = [{ toolCalls: [{ name: "volcar", arguments: {} }] }, { text: "fin" }];
  await engine.send("volcá");
  const dump = engine.agent.messages.findLast((m) => m.role === "tool")!.content as string;
  assert.ok(dump.length < 7000);
  const hash = /sha256:[0-9a-f]{64}/.exec(dump)![0];
  assert.equal(engine.artifacts.read(hash).length, "línea\n".length * 5000 + 5000);
  engine.close();
});

test("compactación: checkpoint reemplaza lo viejo, se persiste y la sesión sigue", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider });
  atlas(engine);
  const note = engine.vault.write({ type: "decision", title: "Usar identidad comprador-2", summary: "Las pruebas usan comprador-2.", scope: scopeTag(engine.scope.current()) });
  provider.faux!.queue = [{ text: "uno" }];
  await engine.send("Primer pedido sobre comprador");
  provider.faux!.queue = [{ toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }] }, { text: "dos" }];
  await engine.send("Segundo pedido");
  provider.faux!.queue = [{ toolCalls: [{ name: "memory_search", arguments: { query: "x" } }] }, { text: "tres" }];
  await engine.send("Tercer pedido");
  assert.equal(engine.compactions, 0);
  // El contexto supera el umbral: antes de la próxima solicitud se resume la parte vieja.
  engine.compactAt = 1;
  provider.faux!.queue = [{ text: "OBJETIVO: revisar permisos.\nPENDIENTE: nada." }, { text: "cuatro" }];
  await engine.send("Cuarto pedido sobre comprador");
  assert.equal(engine.compactions, 1);
  const roles = engine.agent.messages.map((m) => m.role);
  assert.equal(roles[0], "checkpoint");
  assert.notEqual(roles[1], "tool"); // la cola conservada no empieza con un resultado huérfano
  assert.ok(roles.length <= 8);
  assert.equal(lastAssistant(engine).content, "cuatro");
  assert.equal(engine.lastRecall.length, 0);
  const workers = engine.db.prepare("select worker, count(*) n from requests group by worker order by worker").all().map((r: any) => `${r.worker}:${r.n}`);
  assert.deepEqual(workers, ["compactador:1", "principal:6"]);
  // Tras compactar, un recuerdo que salió del contexto puede volver a inyectarse.
  engine.compactAt = 1e9;
  provider.faux!.queue = [{ text: "cinco" }];
  await engine.send("¿Qué identidad comprador usamos?");
  assert.deepEqual(engine.lastRecall.map((hit) => hit.id), [note.id]);
  const kept = engine.agent.messages.map((m) => JSON.stringify(m));
  const all = (engine.db.prepare("select count(*) n from messages").get() as any).n;
  engine.close();

  // Al reabrir: mismo contexto compactado; la historia completa sigue en la base.
  const reopened = new Engine({ cwd, provider, resume: true });
  assert.deepEqual(reopened.agent.messages.map((m) => JSON.stringify(m)), kept);
  assert.ok(all > kept.length);
  reopened.close();
});

test("reanudación tras una caída: lo seguro se repite, lo demás queda desconocido", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider });
  // El proceso «muere» mientras corren dos herramientas: una segura y una que modifica estado.
  provider.faux!.queue = [{ toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }, { name: "memory_write", arguments: { type: "decision", title: "t", summary: "s" } }] }];
  const crash = new Error("caída simulada");
  engine.agent.on((event) => {
    if (event.type === "tool_start") throw crash;
  });
  await assert.rejects(engine.send("Trabajá"), crash);
  // Un proceso muerto no llega a registrar el fin del turno.
  engine.db.prepare("delete from events where type='turn.ended'").run();
  engine.close();

  const after = new Engine({ cwd, provider, resume: true });
  assert.equal(after.interrupted, true);
  assert.equal(after.agent.messages.at(-1)!.role, "assistant");
  provider.faux!.queue = [{ text: "Retomé." }];
  await after.resumeTurn();
  const tools = after.agent.messages.filter((m) => m.role === "tool");
  assert.equal(tools.length, 2);
  assert.equal(tools.find((m) => m.name === "fixture_run")!.isError, false);
  assert.match(tools.find((m) => m.name === "memory_write")!.content as string, /Resultado desconocido/);
  assert.equal(after.vault.count(), 0); // la escritura no se repitió sola
  assert.equal(lastAssistant(after).content, "Retomé.");
  assert.equal(after.interrupted, false);
  after.close();

  // Un daemon nuevo retoma solo lo que quedó interrumpido.
  const cwd2 = tmp();
  const crashed = new Engine({ cwd: cwd2, provider });
  provider.faux!.queue = [{ toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }] }];
  crashed.agent.on((event) => {
    if (event.type === "tool_start") throw crash;
  });
  await assert.rejects(crashed.send("Trabajá"), crash);
  crashed.db.prepare("delete from events where type='turn.ended'").run();
  crashed.close();
  provider.faux!.queue = [{ text: "Retomado por el daemon." }];
  const daemon = new Daemon({ cwd: cwd2, resolve: () => provider });
  await daemon.listen();
  try {
    assert.equal(daemon.hosts.size, 1);
    const host = [...daemon.hosts.values()][0]!;
    await new Promise<void>((resolve) => host.engine.agent.on((event) => event.type === "idle" && resolve()));
    assert.equal(lastAssistant(host.engine).content, "Retomado por el daemon.");
    assert.equal(daemon.interruptedSessions().length, 0);
  } finally {
    daemon.close();
  }
});

test("daemon: adjuntar, vistas, segundo plano y una sola instancia por proyecto", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    assert.throws(() => new Daemon({ cwd }), /ya está abierto|already open/); // el candado se toma en el constructor
    const a = await connectDaemon(cwd, { spawn: false });
    const first = await a.attach({ session: "new", budget: "sin" });
    assert.equal(first.messages.length, 0);
    provider.faux!.queue = [{ text: "Hola desde el daemon." }];
    a.send("hola");
    await a.idle();
    assert.equal(a.status.running, false);
    assert.match(a.status.cost, /sin tope/);
    assert.deepEqual(await a.ask("budget", { value: "5" }), ["Tope de sesión: USD 5.00. Uso: /presupuesto <USD> o /presupuesto sin"]);
    assert.match((await a.view("jobs")).join("\n"), new RegExp(`${first.sessionId.slice(0, 8)}  abierta .* hola`));
    assert.match((await a.view("costos")).join("\n"), /1 solicitudes únicas/);
    await assert.rejects(a.view("nada"), /Vista desconocida/);
    await assert.rejects(a.attach({ session: "zzzz" }), /No existe la sesión/);
    a.close();

    // Otra interfaz se adjunta a la misma sesión viva por prefijo de ID.
    const b = await connectDaemon(cwd, { spawn: false });
    const again = await b.attach({ session: first.sessionId.slice(0, 8) });
    assert.equal(again.sessionId, first.sessionId);
    assert.equal(again.messages.length, 2);
    assert.equal(daemon.hosts.size, 1);
    assert.deepEqual(await b.ask("shutdown"), ["Daemon detenido."]);
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(daemon.closed, true);
    await assert.rejects(connectDaemon(cwd, { spawn: false }), /No hay un daemon/);
  } finally {
    daemon.close();
  }
});

test("contabilidad: tarifa aplicada, deduplicación y desconocidos", () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider });
  const model = { ...provider.model, cost: { input: 2, output: 8, cacheRead: 0.5, cacheWrite: 2.5 } };
  const message = (requestId: string, usage?: object, extra: object = {}): AssistantMessage => ({
    role: "assistant", content: "x", toolCalls: [], stopReason: "stop", provider: "demo", model: "m", requestId, at: Date.now(),
    ...(usage && { usage: { input: 0, cacheRead: 0, cacheWrite: 0, output: 0, ...usage } }), ...extra,
  });
  const ctx = { sessionId: engine.sessionId, account: "a", worker: "w1", model };
  assert.equal(engine.ledger.record(message("a1", { input: 2000, cacheRead: 1000, output: 600 }), ctx), true);
  assert.equal(engine.ledger.record(message("a2", { input: 1200, cacheRead: 800, output: 500 }), { ...ctx, worker: "w2" }), true);
  assert.equal(engine.ledger.record(message("a3", { input: 600, cacheRead: 600, output: 500 }), ctx), true);
  // Mismo recibo otra vez (replay o rama): no suma.
  assert.equal(engine.ledger.record(message("a3", { input: 600, cacheRead: 600, output: 500 }), ctx), false);
  // Turno cortado sin uso y modelo sin tarifa: pendientes, no en cero. Rechazo previo: cero conocido.
  engine.ledger.record(message("a4", undefined, { stopReason: "aborted" }), ctx);
  engine.ledger.record(message("a5", { input: 10, output: 10 }), { ...ctx, model: provider.model });
  engine.ledger.record(message("a6", undefined, { stopReason: "error", rejected: true }), ctx);
  const totals = engine.ledger.totals(engine.sessionId);
  assert.equal(usd(totals.knownPico), "0.0216"); // mismo resultado que la maqueta de costos
  assert.equal(totals.requests, 6);
  assert.equal(totals.unknownRequests, 2);
  engine.close();
});

test("presupuesto: reserva antes de enviar y nunca se pasa del tope", async () => {
  const provider = resolveProvider("faux");
  provider.model.cost = { input: 2, output: 8, cacheRead: 0, cacheWrite: 0 };
  provider.model.maxTokens = 100;
  const engine = new Engine({ cwd: tmp(), provider });
  engine.ledger.budgetPico = engine.estimate() + usdToPico("0.0002"); // entra una solicitud, no dos
  provider.faux!.queue = [{ text: "uno" }, { text: "dos" }];
  await engine.send("hola");
  assert.equal(lastAssistant(engine).content, "uno");
  // Lo gastado más la estimación de la siguiente superan el tope: se bloquea sin enviar.
  await engine.send("otra");
  assert.match(lastError(engine).errorMessage!, /no alcanza: gastado USD \d+\.\d+ \+ estimado de esta solicitud USD/);
  assert.match(lastAssistant(engine).content, /^Corté el turno: Presupuesto de sesión/, "sin presupuesto, el cierre no gasta otra solicitud");
  assert.equal(provider.faux!.calls, 1);
  assert.ok(engine.ledger.totals(engine.sessionId).knownPico < engine.ledger.budgetPico!);
  // Una reserva en vuelo de otro worker también cuenta.
  engine.ledger.budgetPico = engine.ledger.totals(engine.sessionId).knownPico + engine.estimate() + usdToPico("0.0001");
  engine.ledger.reserve("otra-intencion", engine.sessionId, usdToPico("0.0030"));
  assert.match(engine.ledger.overBudget(engine.sessionId, engine.estimate())!, /en vuelo USD 0\.0030/);
  engine.ledger.settle("otra-intencion");
  assert.equal(engine.ledger.overBudget(engine.sessionId, engine.estimate()), undefined);
  engine.close();
});

test("falta de avance: aviso al primer paso repetido y corte al tercero", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider });
  const stalls: number[] = [];
  engine.agent.on((event) => event.type === "stall" && stalls.push(event.strikes));
  // Herramienta no pura que devuelve siempre lo mismo (p. ej. un escaneo que no cambia).
  engine.agent.tools.push({ name: "mirar", label: "Mirar", description: "", parameters: { type: "object" }, execute: () => ({ text: "nada nuevo" }) });
  const look = { toolCalls: [{ name: "mirar", arguments: {} }] };
  provider.faux!.queue = [look, look, look, look, look, { text: "no llega" }];
  await engine.send("Mirá hasta que aparezca algo");
  assert.deepEqual(stalls, [1, 2, 3]);
  const last = lastError(engine);
  assert.match(last.errorMessage!, /falta de avance: las mismas llamadas devolvieron exactamente lo mismo/);
  // Cortado por el harness: se le pide el cierre al modelo; acá devolvió otra llamada, así que lo arma el harness.
  assert.match(lastAssistant(engine).content, /^Corté el turno: Turno cortado por falta de avance/);
  assert.ok(engine.agent.messages.some((m) => m.role === "user" && String(m.content).startsWith("[sistema] El turno terminó (Turno cortado por falta de avance")));
  // Al primer strike se le avisó al modelo con un mensaje de sistema.
  assert.ok(engine.agent.messages.some((m) => m.role === "user" && (m.content as string).startsWith("[sistema] Sin avance")));
  assert.equal(provider.faux!.calls, 5); // paso 1 nuevo, pasos 2-4 repetidos → corte; la quinta es el cierre
  assert.equal(provider.faux!.queue.length, 1);

  // Errores repetidos también cuentan; un paso con algo nuevo reinicia la cuenta.
  const bad = { toolCalls: [{ name: "memory_read", arguments: { id: "no-existe" } }] };
  stalls.length = 0;
  provider.faux!.queue = [bad, bad, { toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }] }, bad, { text: "fin" }];
  await engine.send("Otra cosa");
  assert.deepEqual(stalls, [1, 1]); // el segundo aviso: la misma llamada fallida volvió más tarde; entre medio hubo avance
  assert.equal(lastAssistant(engine).content, "fin");
  engine.close();
});

test("memoria: revisiones, sustitución y reindexado desde archivos", () => {
  const cwd = tmp();
  const engine = new Engine({ cwd, provider: resolveProvider("faux") });
  const first = engine.vault.write({ type: "decision", title: "Usar identidad comprador-1", summary: "Las pruebas de permisos usan comprador-1." });
  const second = engine.vault.write({ type: "decision", title: "Usar identidad comprador-2", summary: "comprador-1 fue dado de baja; usar comprador-2.", supersedes: first.id });
  assert.equal(engine.vault.read(first.id)!.record.state, "sustituido");
  assert.deepEqual(engine.vault.decisions().map((hit) => hit.id), [second.id]);
  assert.equal(engine.vault.search("comprador")[0]!.id, second.id);
  assert.throws(() => engine.vault.write({ id: second.id, type: "decision", title: "x", summary: "y", expectedRev: 7 }));
  // Edición externa del archivo canónico: el reindexado la incorpora.
  const path = join(projectPaths(cwd).records, `${second.id}.toon`);
  writeFileSync(path, readFileSync(path, "utf8").replace("dado de baja", "revocado por auditoría"));
  assert.equal(engine.vault.search("auditoría").length, 0);
  assert.deepEqual(engine.vault.reindex(), { indexed: 2, invalid: [], migrated: 0 });
  assert.equal(engine.vault.search("auditoría")[0]!.id, second.id);
  engine.close();
});

test("transporte: streaming SSE, llamadas a herramientas, uso con caché y rechazo 401", async () => {
  assert.deepEqual(normalizeUsage({ prompt_tokens: 100, completion_tokens: 7, prompt_cache_hit_tokens: 60 }), { input: 40, cacheRead: 60, cacheWrite: 0, output: 7 });
  assert.equal(normalizeUsage({}), undefined);
  let body: any;
  const server = createServer((req, res) => {
    if (req.headers.authorization !== "Bearer clave-de-prueba") {
      res.writeHead(401).end('{"error":"clave inválida"}');
      return;
    }
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      body = JSON.parse(raw);
      res.writeHead(200, { "content-type": "text/event-stream" });
      const send = (data: object) => res.write(`data: ${JSON.stringify(data)}\n\n`);
      send({ id: "chatcmpl-1", choices: [{ delta: { role: "assistant", content: "Ho" } }] });
      // Un evento partido en dos escrituras TCP.
      res.write('data: {"id":"chatcmpl-1","choices":[{"delta":{"con');
      res.write('tent":"la"}}]}\n\n');
      send({ id: "chatcmpl-1", choices: [{ delta: { tool_calls: [{ index: 0, id: "call_a", function: { name: "memory_search", arguments: '{"que' } }] } }] });
      send({ id: "chatcmpl-1", choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'ry":"x"}' } }] }, finish_reason: "tool_calls" }] });
      send({ id: "chatcmpl-1", choices: [], usage: { prompt_tokens: 120, completion_tokens: 9, prompt_tokens_details: { cached_tokens: 100 } } });
      res.end("data: [DONE]\n\n");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as any).port}/v1`;
  const request = { system: "sistema", messages: [{ role: "user" as const, content: "hola", at: 0 }], tools: [{ name: "memory_search", description: "d", parameters: { type: "object" } }] };
  try {
    process.env.CYBER_TEST_KEY = "clave-de-prueba";
    let streamed = "";
    const ok = await openAICompletions({ ...request, model: { provider: "local", id: "m1", baseUrl, apiKeyEnv: "CYBER_TEST_KEY" }, onText: (delta) => (streamed += delta) });
    assert.equal(streamed, "Hola");
    assert.equal(ok.stopReason, "toolUse");
    assert.deepEqual(ok.toolCalls, [{ id: "call_a", name: "memory_search", arguments: '{"query":"x"}' }]);
    assert.deepEqual(ok.usage, { input: 20, cacheRead: 100, cacheWrite: 0, output: 9 });
    assert.equal(ok.requestId, "chatcmpl-1");
    assert.equal(body.messages[0].role, "system");
    assert.equal(body.stream_options.include_usage, true);

    process.env.CYBER_TEST_KEY = "otra";
    const denied = await openAICompletions({ ...request, model: { provider: "local", id: "m1", baseUrl, apiKeyEnv: "CYBER_TEST_KEY" } });
    assert.equal(denied.stopReason, "error");
    assert.equal(denied.rejected, true);
    assert.match(denied.errorMessage!, /HTTP 401/);
  } finally {
    delete process.env.CYBER_TEST_KEY;
    server.close();
  }
});

test("transporte Anthropic: bloques tool_use, uso con caché y conversión de mensajes", async () => {
  let body: any;
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      body = JSON.parse(raw);
      if (req.headers["x-api-key"] !== "clave-anthropic") return void res.writeHead(401).end('{"error":{"message":"invalid x-api-key"}}');
      res.writeHead(200, { "content-type": "text/event-stream" });
      const send = (data: object) => res.write(`event: ${(data as any).type}\ndata: ${JSON.stringify(data)}\n\n`);
      send({ type: "message_start", message: { id: "msg_01", usage: { input_tokens: 30, cache_read_input_tokens: 200, cache_creation_input_tokens: 10, output_tokens: 1 } } });
      send({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
      send({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Voy a " } });
      send({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "buscar." } });
      send({ type: "content_block_stop", index: 0 });
      send({ type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "toolu_1", name: "memory_search", input: {} } });
      send({ type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"query":' } });
      send({ type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '"permisos"}' } });
      send({ type: "content_block_stop", index: 1 });
      send({ type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 23 } });
      send({ type: "message_stop" });
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as any).port}/v1`;
  const model = { provider: "anthropic", id: "claude-x", baseUrl, apiKeyEnv: "CYBER_TEST_ANTHROPIC", maxTokens: 777 };
  const messages = [
    { role: "user" as const, content: "hola", at: 0 },
    { role: "assistant" as const, content: "", toolCalls: [{ id: "toolu_0", name: "fixture_run", arguments: '{"name":"a"}' }], stopReason: "toolUse" as const, provider: "anthropic", model: "claude-x", requestId: "r", at: 0 },
    { role: "tool" as const, toolCallId: "toolu_0", name: "fixture_run", content: "resultado", isError: false, at: 0 },
    { role: "checkpoint" as const, content: "resumen", keepFrom: 0, at: 0 },
  ];
  try {
    process.env.CYBER_TEST_ANTHROPIC = "clave-anthropic";
    let streamed = "";
    const reply = await anthropicMessages({ model, system: "sistema", messages, tools: [{ name: "memory_search", description: "d", parameters: { type: "object" } }], onText: (delta) => (streamed += delta) });
    assert.equal(streamed, "Voy a buscar.");
    assert.equal(reply.stopReason, "toolUse");
    assert.deepEqual(reply.toolCalls, [{ id: "toolu_1", name: "memory_search", arguments: '{"query":"permisos"}' }]);
    assert.deepEqual(reply.usage, { input: 30, cacheRead: 200, cacheWrite: 10, output: 23 });
    assert.equal(reply.requestId, "msg_01");
    assert.equal(body.max_tokens, 777);
    assert.deepEqual(body.system, [{ type: "text", text: "sistema", cache_control: { type: "ephemeral" } }]);
    assert.deepEqual(body.messages.at(-1).content.at(-1).cache_control, { type: "ephemeral" });
    assert.equal(body.messages[0].content[0].cache_control, undefined);
    assert.equal(body.tools[0].input_schema.type, "object");
    assert.deepEqual(body.messages.map((m: any) => [m.role, m.content.map((b: any) => b.type)]), [
      ["user", ["text"]],
      ["assistant", ["tool_use"]],
      ["user", ["tool_result", "text"]],
    ]);
    assert.deepEqual(body.messages[1].content[0].input, { name: "a" });

    process.env.CYBER_TEST_ANTHROPIC = "mala";
    const denied = await anthropicMessages({ model, system: "s", messages: messages.slice(0, 1), tools: [] });
    assert.equal(denied.rejected, true);
    assert.match(denied.errorMessage!, /HTTP 401/);
  } finally {
    delete process.env.CYBER_TEST_ANTHROPIC;
    server.close();
  }
});

test("subagentes: contexto propio, paralelo, gasto imputado al worker y cancelación", async () => {
  const provider = resolveProvider("faux");
  provider.model.cost = { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 };
  const engine = new Engine({ cwd: tmp(), provider });
  const events: string[] = [];
  engine.agent.on((event) => (event.type === "tool_start" || event.type === "tool_end") && events.push(`${event.type}:${event.worker ?? "principal"}:${event.name}`));
  // El faux consume en orden de inicio: padre, luego los dos hijos (que arrancan juntos), luego sus cierres, luego el padre.
  provider.faux!.queue = [
    { toolCalls: [{ name: "delegate", arguments: { objective: "Contá las rutas del fixture", context: "fixture atlas-permisos" } }, { name: "delegate", arguments: { objective: "Buscá en memoria sobre permisos" } }] },
    { toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }] }, // sub:1 paso 1
    { toolCalls: [{ name: "memory_search", arguments: { query: "permisos" } }] }, // sub:2 paso 1
    { text: "RESULTADO: 18 rutas.\nLÍMITES: ninguno.\nSIGUIENTE: nada." }, // sub:1 cierre
    { text: "RESULTADO: sin notas." }, // sub:2 cierre
    { text: "Listo: 18 rutas y sin notas previas." },
  ];
  await engine.send("Delegá dos cosas");
  assert.equal(lastAssistant(engine).content, "Listo: 18 rutas y sin notas previas.");
  const results = engine.agent.messages.filter((m) => m.role === "tool" && m.name === "delegate");
  assert.equal(results.length, 2);
  assert.match(results[0]!.content as string, /RESULTADO: 18 rutas[\s\S]*\[sub:1: 2 solicitudes, USD 0\.\d+, transcripción sha256:/);
  assert.match(results[1]!.content as string, /sin notas[\s\S]*\[sub:2:/);
  // Los hijos arrancaron en paralelo y sus herramientas se vieron con su worker.
  assert.ok(events.includes("tool_start:sub:1:fixture_run") && events.includes("tool_start:sub:2:memory_search"));
  assert.ok(events.indexOf("tool_start:sub:2:memory_search") < events.indexOf("tool_end:principal:delegate"));
  // Gasto por worker en el ledger y transcripción guardada como artefacto.
  const workers = engine.db.prepare("select worker,count(*) n from requests group by worker order by worker").all().map((r: any) => `${r.worker}:${r.n}`);
  assert.deepEqual(workers, ["principal:2", "sub:1:2", "sub:2:2"]);
  const hash = /sha256:[0-9a-f]{64}/.exec(results[0]!.content as string)![0];
  assert.equal(JSON.parse(engine.artifacts.read(hash).toString()).length, 4);
  // El subagente no puede delegar ni superar su tope.
  provider.faux!.queue = [
    { toolCalls: [{ name: "delegate", arguments: { objective: "x", budgetUsd: 0.01 } }] },
    { toolCalls: [{ name: "delegate", arguments: { objective: "anidado" } }] },
    { text: "cierre hijo" },
    { text: "fin" },
  ];
  await engine.send("Otra");
  const nested = JSON.parse(engine.artifacts.read(/sha256:[0-9a-f]{64}/.exec(engine.agent.messages.findLast((m) => m.role === "tool")!.content as string)![0]).toString());
  assert.match(nested.find((m: any) => m.role === "tool").content, /Herramienta desconocida: delegate/);
  // Cancelar el turno cancela al hijo.
  let release!: () => void;
  engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await new Promise<void>((r) => (release = r)), { text: "ok" }) });
  provider.faux!.queue = [{ toolCalls: [{ name: "delegate", arguments: { objective: "esperá" } }] }, { toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "no llega" }];
  const turn = engine.send("Cancelame");
  await new Promise((r) => setTimeout(r, 30));
  engine.abort();
  release();
  await turn;
  assert.match(engine.agent.messages.findLast((m) => m.role === "tool")!.content as string, /no terminó/);
  engine.close();
});
