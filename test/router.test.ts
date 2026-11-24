import "./datos-tmp.ts";
// Router de modelos por rol (src/router.ts): el ejecutor hace el bucle con su caché siempre caliente; ante
// una señal de decisión, el ejecutor escribe un traspaso compacto y el fuerte (o el medio) trabaja sobre él
// con contexto propio; el resultado se agrega al final del bucle. Lo blue va primero a un estándar; si se
// niega, a uno sin barandas, y la negativa queda en la tasa por modelo.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine, type EngineOptions } from "../src/engine.ts";
import { ratePico, usd, usdToPico } from "../src/money.ts";
import type { Provider } from "../src/providers.ts";
import { rechazosPath } from "../src/rechazos.ts";
import { type ContextoDecision, costoReferencia, estadoLineas, PERFILES, type PasoVisto, Router, TOPE_TURNO, trivial } from "../src/router.ts";
import { readRefusal } from "../src/coherencia.ts";
import { llama, MundoFalso, simular, sondeo, TARIFAS } from "./router-falso.ts";

process.env.LC_ALL = "es_AR.UTF-8";
const tmp = () => mkdtempSync(join(tmpdir(), "cyber-router-"));

/** Motor con ejecutor glm, fuerte ultra y kimi como estándar para lo blue; cada prueba con su archivo de tasas. */
function armar(extra: Partial<EngineOptions> = {}, mundo = new MundoFalso()) {
  process.env.CYBER_CONFIG = join(tmp(), "config.json");
  const providers: Record<string, Provider> = {
    "faux/glm": mundo.proveedor("glm", TARIFAS.glm),
    "faux/glm-estandar": mundo.proveedor("glm-estandar", TARIFAS.glm),
    "faux/ultra": mundo.proveedor("ultra", TARIFAS.ultra),
    "faux/kimi": mundo.proveedor("kimi", TARIFAS.kimi),
    "faux/hy4": mundo.proveedor("hy4", TARIFAS.hy4),
  };
  const resolve = (spec: string) => { const found = providers[spec]; if (!found) throw new Error(`sin ${spec}`); return { ...found, model: { ...found.model } }; };
  const engine = new Engine({ cwd: tmp(), provider: providers["faux/glm"]!, strong: providers["faux/ultra"]!, resolve, routerModels: { blue: { fuerte: "faux/kimi" } }, autoVerify: false, ...extra });
  simular(engine, "http_request");
  simular(engine, "finding_record", () => "Registrado 1a2b3c4d como candidato.");
  const etiquetas: string[] = [];
  engine.onRouterChange = () => etiquetas.push(engine.routerPie());
  return { mundo, engine, etiquetas };
}

const eventos = (engine: Engine, type: string) => (engine.db.prepare("select payload from events where session_id=? and type=? order by seq").all(engine.sessionId, type) as Array<{ payload: string }>).map((row) => JSON.parse(row.payload));
const filas = (engine: Engine) => (engine.db.prepare("select worker, model from requests where session_id=? order by rowid").all(engine.sessionId) as Array<{ worker: string; model: string }>).map((row) => `${row.worker}:${row.model}`);
const CANDIDATO = "HTTP 200: GET /api/pedidos/7 devolvió el pedido de otro usuario con mi sesión";

/* ---------- La lógica, sin motor ---------- */

const paso = (nombre: string, texto: string, error = false): PasoVisto => ({ llamadas: [{ nombre, args: "{}" }], resultados: [{ nombre, texto, error }], texto: "" });
const ctx = (extra: Partial<ContextoDecision> = {}): ContextoDecision => ({ alcanza: () => true, hay: { fuerte: () => true, medio: () => false }, ...extra });

test("router: presión con histéresis, enfriamiento, tope por turno y lo trivial no planifica", () => {
  const router = new Router();
  assert.ok(trivial("seguí") && trivial("dale, seguí nomás") && !trivial("Probá el login de app.test con contraseñas comunes"));
  router.inicioTurno("seguí");
  assert.equal(router.decidir(ctx()), undefined, "un «seguí» no es un pedido nuevo");
  router.inicioTurno("Probá el control de acceso de app.test");
  assert.deepEqual(router.decidir(ctx()), { rol: "fuerte", forma: "consulta", nivel: "blue", motivo: "operador", detalle: "Probá el control de acceso de app.test" });
  // Un candidato es red y se comprueba con herramientas (tramo).
  router.observar(paso("http_request", CANDIDATO));
  const encargo = router.decidir(ctx())!;
  assert.deepEqual([encargo.forma, encargo.nivel, encargo.motivo], ["tramo", "red", "candidato"]);
  // Otro candidato enseguida: el enfriamiento lo frena; una señal débil sola, tampoco; la rutina baja la presión.
  router.observar(paso("http_request", "HTTP 200 con id ajeno 9 en /api/facturas"));
  assert.equal(router.decidir(ctx()), undefined, "enfriando");
  for (let i = 0; i < PERFILES.web.enfriar; i++) {
    router.observar(paso("http_request", "HTTP 200 normal"));
    assert.equal(router.decidir(ctx()), undefined);
  }
  assert.equal(router.ahora().presion, 0, "la rutina descargó la presión");
  router.observar(paso("http_request", "HTTP 500 Internal Server Error: Traceback (most recent call last)"));
  assert.equal(router.decidir(ctx()), undefined, "una anomalía sola no alcanza en web");
  router.observar(paso("http_request", "HTTP 500 SQLSTATE[42000] syntax error"));
  assert.equal(router.decidir(ctx()), undefined, "dos débiles: presión 2 de 3");
  router.observar({ llamadas: [{ nombre: "http_request", args: "{}" }], resultados: [{ nombre: "http_request", texto: "HTTP 500 ORA-00933", error: false }], texto: "Analicemos: podría ser una inyección" });
  const acumulado = router.decidir(ctx())!;
  assert.deepEqual([acumulado.motivo, acumulado.nivel, acumulado.forma], ["anomalia", "red", "consulta"], "tres débiles acumuladas sí");
  // Tope por turno.
  let extra = 0;
  for (let i = 0; i < 40; i++) {
    router.observar(paso("http_request", `HTTP 200: pedido ${i} de otro usuario`));
    if (router.decidir(ctx())) extra++;
  }
  assert.equal(extra, TOPE_TURNO - 3, "no más de TOPE_TURNO encargos por turno");
  router.finTurno();
  router.inicioTurno("Ahora probá /api/admin");
  assert.equal(router.decidir(ctx())?.motivo, "operador", "un turno nuevo vuelve a tener encargos");
});

test("router: el perfil de código sube antes; el presupuesto lo vuelve conservador; fijo no rutea", () => {
  const web = new Router();
  web.observar(paso("finding_record", "Registrado ab12 como pista."));
  assert.equal(web.decidir(ctx()), undefined, "en web, registrar un hallazgo solo no alcanza");
  const code = new Router();
  for (const file of ["a.ts", "b.ts", "c.ts"]) code.observar(paso("code_read", `// ${file}\nexport const x = 1;`));
  assert.equal(code.perfil(), "codigo");
  code.decidir(ctx());
  code.observar(paso("finding_record", "Registrado ab12 como pista."));
  assert.equal(code.decidir(ctx())?.motivo, "hallazgo", "en código, sí (umbral 2)");
  assert.equal(code.decidir(ctx()), undefined);
  // El medio lee código: dos de los últimos tres pasos con código, y después enfría.
  const mid = new Router();
  for (const file of ["a.ts", "b.ts", "c.ts"]) mid.observar(paso("code_read", file));
  assert.deepEqual(mid.decidir(ctx({ hay: { fuerte: () => false, medio: () => true } }))?.rol, "medio");
  mid.observar(paso("code_read", "d.ts"));
  assert.equal(mid.decidir(ctx({ hay: { fuerte: () => false, medio: () => true } })), undefined, "enfriando el medio");
  assert.equal(new Router().perfil(), "web");
  const movil = new Router();
  movil.observar(paso("apk_analyze", "AndroidManifest.xml"));
  assert.equal(movil.perfil(), "movil");

  // Presupuesto: con menos de la mitad, más presión hace falta y no hay tramos; con menos de un quinto, nada.
  const half = new Router();
  half.inicioTurno("Probá app.test a fondo");
  assert.equal(half.decidir(ctx({ fraccion: 0.4 })), undefined, "con 40 % de presupuesto, un pedido solo no planifica");
  half.observar({ llamadas: [{ nombre: "http_request", args: "{}" }, { nombre: "finding_record", args: "{}" }], resultados: [{ nombre: "http_request", texto: CANDIDATO, error: false }, { nombre: "finding_record", texto: "Registrado", error: false }], texto: "" });
  const conservador = half.decidir(ctx({ fraccion: 0.4 }))!;
  assert.deepEqual([conservador.motivo, conservador.forma], ["candidato", "consulta"], "dos señales fuertes sí, pero consulta y no tramo");
  const poor = new Router();
  poor.inicioTurno("Probá app.test a fondo");
  poor.observar(paso("http_request", CANDIDATO));
  assert.equal(poor.decidir(ctx({ fraccion: 0.15 })), undefined);
  // Si el tramo no entra en el presupuesto, consulta; si nada entra, nada.
  const tight = new Router();
  tight.observar(paso("http_request", CANDIDATO));
  assert.equal(tight.decidir(ctx({ alcanza: (_rol, forma) => forma === "consulta" }))?.forma, "consulta");
  const none = new Router();
  none.observar(paso("http_request", CANDIDATO));
  assert.equal(none.decidir(ctx({ alcanza: () => false })), undefined);
  const fixed = new Router("fijo");
  fixed.inicioTurno("Probá app.test");
  fixed.observar(paso("http_request", CANDIDATO));
  assert.equal(fixed.decidir(ctx()), undefined);
});

test("negativas: frase al empezar, vacía o un texto que sólo explica por qué no; una llamada o un corte por largo no lo son", () => {
  const reply = (content: string, stopReason = "stop", toolCalls: Array<{ name: string; arguments: string }> = []) => ({ content, stopReason, toolCalls });
  assert.equal(readRefusal(reply("Lo siento, no puedo ayudar con eso.")), "negativa al empezar");
  assert.equal(readRefusal(reply("I'm sorry, but I can't help with exploiting systems.")), "negativa al empezar");
  assert.equal(readRefusal(reply("")), "respuesta vacía");
  assert.equal(readRefusal(reply("Entiendo el pedido, pero no puedo proporcionar cargas para explotar sistemas.")), "explica por qué no lo hace en vez de hacerlo");
  assert.equal(readRefusal(reply("", "length")), undefined);
  assert.equal(readRefusal(reply("", "toolUse", [{ name: "http_request", arguments: "{}" }])), undefined);
  assert.equal(readRefusal(reply("DECISIÓN: se sostiene. PLAN: 1. GET /api/pedidos/7")), undefined);
});

/* ---------- En el motor, con caché por modelo ---------- */

test("planificar → sondear → candidato → sondear: el ejecutor no cambia nunca, el fuerte trabaja sobre traspasos y la caché del bucle queda intacta", async () => {
  const { mundo, engine, etiquetas } = armar();
  mundo.bucle = [sondeo("/api/pedidos"), sondeo("/api/pedidos/7", CANDIDATO), sondeo("/api/facturas"), { text: "Listo: el IDOR en pedidos se sostiene (1a2b3c4d)." }];
  mundo.tramos = [{ text: "RESULTADO: se sostiene: GET /api/pedidos/7 con la identidad B devuelve el pedido de A (h9). Registré 1a2b3c4d. LÍMITES: no probé escritura. SIGUIENTE: PUT." }];
  await engine.send("Probá el control de acceso de app.test: buscá IDOR en /api");

  assert.deepEqual(mundo.llamadas.map((call) => `${call.worker}:${call.modelo}`), [
    "router:blue:fuerte:kimi", // el plan: blue, a un estándar
    "principal:glm",
    "principal:glm",
    "traspaso:glm", // el ejecutor escribe el traspaso desde su caché
    "sub:1:fuerte:ultra", // el candidato: red, tramo con herramientas y contexto propio
    "principal:glm",
    "principal:glm",
  ]);
  assert.deepEqual(filas(engine).filter((row) => !row.startsWith("principal")), ["router:blue:fuerte:kimi", "traspaso:glm", "sub:1:fuerte:ultra"]);
  // La caché del bucle: cada paso relee del caché todo el prompt del anterior; el traspaso también.
  const principal = mundo.llamadas.filter((call) => call.worker === "principal");
  for (let i = 1; i < principal.length; i++) assert.ok(principal[i]!.cacheado >= principal[i - 1]!.prompt, `paso ${i}: el prefijo cacheado del ejecutor sigue entero`);
  const handoff = mundo.llamadas.find((call) => call.worker === "traspaso")!;
  assert.ok(handoff.cacheado >= principal[1]!.prompt && handoff.prompt - handoff.cacheado < 500, "el traspaso sale de la caché caliente del ejecutor");
  const tramo = mundo.llamadas.find((call) => call.worker.startsWith("sub:"))!;
  assert.ok(tramo.prompt < principal[2]!.prompt / 2, `el fuerte lee un contexto propio y chico (${tramo.prompt} contra ${principal[2]!.prompt} tokens)`);

  const decisions = eventos(engine, "router.decision");
  assert.deepEqual(decisions.map((item) => [item.rol, item.forma, item.nivel, item.motivo, item.modelo, item.estado, item.traspaso.mecanico]), [
    ["fuerte", "consulta", "blue", "operador", "faux/kimi", "listo", true],
    ["fuerte", "tramo", "red", "candidato", "faux/ultra", "listo", false],
  ]);
  assert.match(decisions[1].detalle, /otro usuario/);
  // Lo que vuelve al bucle va al final, con quién lo hizo.
  const notes = engine.agent.messages.filter((message) => message.role === "user" && message.content.startsWith("[sistema] Router:")).map((message) => message.content as string);
  assert.equal(notes.length, 2);
  assert.match(notes[1]!, /^\[sistema\] Router: candidato → el modelo fuerte \(ultra\) trabajó sobre un traspaso de ~\d+ tokens, sin leer esta conversación\./);
  assert.match(notes[1]!, /RESULTADO: se sostiene/);
  // El pie: sólo cambia mientras trabaja otro rol.
  assert.deepEqual(etiquetas, ["router: fuerte·consulta (plan)", "router: ejecutor", "router: fuerte·tramo (candidato)", "router: ejecutor"]);
  // El estado, por rol.
  const estado = engine.routerEstado();
  assert.deepEqual(estado.filas.map((fila) => [fila.rol, fila.nivel ?? "", fila.modelo, fila.pasos]), [
    ["ejecutor", "", "faux/glm", 4],
    ["fuerte", "blue", "faux/kimi", 1],
    ["fuerte", "red", "faux/ultra", 1],
    ["traspaso", "", "faux/glm", 1],
  ]);
  assert.deepEqual(estado.traspasos, { n: 2, tokens: estado.traspasos.tokens, mecanicos: 1 });
  engine.close();
});

test("histéresis: con un candidato en cada paso, los encargos van espaciados, no pasan del tope y el bucle nunca cambia de modelo", async () => {
  const { mundo, engine } = armar();
  mundo.bucle = [...Array.from({ length: 24 }, (_, i) => sondeo(`/api/r${i}`, `HTTP 200: el recurso ${i} de otro usuario con mi sesión`)), { text: "Listo." }];
  await engine.send("Barré /api buscando IDOR en app.test");
  const workers = mundo.llamadas.map((call) => call.worker);
  assert.ok(mundo.llamadas.filter((call) => call.worker === "principal").every((call) => call.modelo === "glm"), "el bucle siempre con el ejecutor");
  const encargos = workers.flatMap((worker, index) => (worker.startsWith("router:") || worker.startsWith("sub:") ? [index] : []));
  assert.ok(encargos.length >= 2 && encargos.length <= TOPE_TURNO, `encargos: ${encargos.length}`);
  // Entre dos encargos por candidato hay al menos `enfriar` pasos del ejecutor.
  const steps = (from: number, to: number) => workers.slice(from, to).filter((worker) => worker === "principal").length;
  for (let i = 2; i < encargos.length; i++) assert.ok(steps(encargos[i - 1]!, encargos[i]!) >= PERFILES.web.enfriar, `entre el encargo ${i - 1} y el ${i}: ${steps(encargos[i - 1]!, encargos[i]!)} pasos`);
  engine.close();
});

test("presupuesto: si no alcanza para el encargo no hay fuerte, y el bucle sigue igual", async () => {
  const { mundo, engine } = armar({ budgetPico: usdToPico("0.05") });
  mundo.bucle = [sondeo("/api/pedidos/7", CANDIDATO), { text: "Listo." }];
  await engine.send("Probá el control de acceso de app.test");
  assert.deepEqual(mundo.llamadas.map((call) => call.worker), ["principal", "principal"]);
  assert.deepEqual(eventos(engine, "router.decision"), []);
  engine.close();
});

test("modo: auto por defecto en sesiones nuevas, fijo no rutea, se cambia y se conserva al retomar; una sesión de antes del router queda fija", async () => {
  const cwd = tmp();
  let { mundo, engine } = armar({ cwd, router: "fijo" });
  mundo.bucle = [{ text: "Listo." }];
  await engine.send("Probá el control de acceso de app.test");
  assert.deepEqual(mundo.llamadas.map((call) => call.worker), ["principal"], "fijo: ni plan");
  assert.equal(engine.routerPie(), "router: fijo");
  engine.setRouter("auto");
  mundo.bucle = [{ text: "Listo." }];
  await engine.send("Ahora probá /api/admin con la cuenta B");
  // Con conversación previa, el traspaso para el plan lo escribe el ejecutor.
  assert.deepEqual(mundo.llamadas.map((call) => call.worker).slice(1), ["traspaso", "router:blue:fuerte", "principal"]);
  const session = engine.sessionId;
  engine.close();
  ({ engine } = armar({ cwd, resume: session, router: "fijo" }));
  assert.equal(engine.router.modo, "auto", "la sesión retomada conserva el suyo");
  engine.db.prepare("delete from events where session_id=? and type='ajuste.router'").run(session);
  engine.close();
  ({ engine } = armar({ cwd, resume: session }));
  assert.equal(engine.router.modo, "fijo", "una sesión de antes del router no cambia sola");
  engine.close();
  ({ engine } = armar({ cwd }));
  assert.equal(engine.router.modo, "auto", "nueva: auto");
  engine.close();
  process.env.CYBER_ROUTER = "fijo";
  try {
    ({ engine } = armar({ cwd }));
    assert.equal(engine.router.modo, "fijo", "$CYBER_ROUTER cambia el de las nuevas");
    engine.close();
  } finally { delete process.env.CYBER_ROUTER; }
});

test("ahorro: el gasto real y el estimado con todo el bucle en el fuerte salen de las mismas cuentas que hace el proveedor", async () => {
  const { mundo, engine } = armar();
  const grande = "x".repeat(40_000);
  mundo.bucle = [sondeo("/api/a", `HTTP 200 ${grande}`), sondeo("/api/b", `HTTP 200 ${grande}`), sondeo("/api/pedidos/7", `${CANDIDATO} ${grande}`), sondeo("/api/c", `HTTP 200 ${grande}`), sondeo("/api/d", `HTTP 200 ${grande}`), sondeo("/api/e", `HTTP 200 ${grande}`), { text: "Listo." }];
  await engine.send("Probá el control de acceso de app.test");
  const estado = engine.routerEstado();
  const sum = (calls: typeof mundo.llamadas) => calls.reduce((total, call) => total + call.pico, 0n);
  const principal = mundo.llamadas.filter((call) => call.worker === "principal");
  assert.equal(estado.gasto.bucle, sum(principal));
  // El router: traspasos, consultas y tramos (la compactación es del bucle de siempre, no del router).
  assert.equal(estado.gasto.router, sum(mundo.llamadas.filter((call) => /^(traspaso|router:|sub:)/.test(call.worker))));
  assert.ok(principal.some((call, i) => i > 0 && call.prompt < principal[i - 1]!.prompt), "se compactó: la referencia también relee en frío lo que quedó");
  // Todo el bucle con ultra y la caché caliente: cada paso relee lo del anterior y paga entero sólo lo nuevo.
  const manual = principal.reduce((acc, call) => {
    const cached = call.prompt >= acc.prev ? acc.prev : 0;
    const pico = BigInt(call.prompt - cached) * ratePico(TARIFAS.ultra.input) + BigInt(cached) * ratePico(TARIFAS.ultra.cacheRead) + BigInt(call.salida) * ratePico(TARIFAS.ultra.output);
    return { prev: call.prompt, pico: acc.pico + pico };
  }, { prev: 0, pico: 0n });
  assert.equal(estado.gasto.referencia?.modelo, "faux/ultra");
  assert.equal(estado.gasto.referencia?.pico, manual.pico, "costoReferencia hace la cuenta a mano");
  assert.equal(costoReferencia(principal.map((call) => ({ input: call.prompt - call.cacheado, cacheRead: call.cacheado, cacheWrite: 0, output: call.salida })), TARIFAS.ultra), manual.pico);
  // El fuerte del tramo trabajó con un contexto propio: mucho menos que el del bucle cuando lo llamaron.
  const tramo = mundo.llamadas.findIndex((call) => call.worker.startsWith("sub:"));
  const before = mundo.llamadas.slice(0, tramo).filter((call) => call.worker === "principal").at(-1)!;
  assert.ok(mundo.llamadas[tramo]!.prompt < before.prompt / 2, `${mundo.llamadas[tramo]!.prompt} contra ${before.prompt} tokens`);
  const real = estado.gasto.bucle + estado.gasto.router;
  const lines = estadoLineas(estado);
  const ahorro = manual.pico - real;
  assert.ok(ahorro > 0n, "el router sale más barato que todo el bucle en el fuerte");
  assert.ok(lines.includes(`Ahorro      ≈ USD ${usd(ahorro, 2)} (${Math.round((Number(ahorro) / Number(manual.pico)) * 100)} %)`), lines.join("\n"));
  assert.ok(lines.includes(`Gasto       bucle USD ${usd(estado.gasto.bucle, 2)} + router USD ${usd(estado.gasto.router, 2)} = USD ${usd(real, 2)}`));
  engine.close();
});

test("negativas: el estándar que se niega se reintenta con el sin barandas, se cuenta, y pasado el umbral deja de recibir ese nivel", async () => {
  const { mundo, engine } = armar();
  mundo.niega = (modelo) => modelo === "kimi";
  for (let turno = 0; turno < 3; turno++) {
    mundo.bucle = [{ text: "Listo." }];
    await engine.send(`Armá el plan para probar el módulo ${turno} de app.test`);
  }
  const consultas = mundo.llamadas.filter((call) => call.worker.startsWith("router:")).map((call) => `${call.modelo}${call.rechazo ? " (se negó)" : ""}`);
  // Dos negativas: (2 + 5·0,03) / (2 + 5) = 0,307 > 0,3: el tercer plan va directo a ultra.
  assert.deepEqual(consultas, ["kimi (se negó)", "ultra", "kimi (se negó)", "ultra", "ultra"]);
  assert.deepEqual(eventos(engine, "router.rechazo").map((item) => [item.modelo, item.nivel, item.clase, item.reintento]), [["faux/kimi", "blue", "operador", "faux/ultra"], ["faux/kimi", "blue", "operador", "faux/ultra"]]);
  const notes = engine.agent.messages.filter((message) => message.role === "user" && /^\[sistema\] Router:/.test(message.content as string));
  assert.ok(notes.every((message) => /\(ultra\)/.test(message.content as string)), "al bucle llega la respuesta que sirvió");
  // Las cuentas quedan en el archivo del usuario, fuera del proyecto, para aprender entre proyectos.
  assert.ok(existsSync(rechazosPath()));
  const saved = JSON.parse(readFileSync(rechazosPath(), "utf8"));
  assert.deepEqual(saved.modelos["faux/kimi"], { blue: { pasos: 2, rechazos: 2 } });
  assert.deepEqual(saved.modelos["faux/ultra"], { blue: { pasos: 3, rechazos: 0 } });
  assert.deepEqual(saved.clases["faux/kimi"], { "blue:operador": { pasos: 2, rechazos: 2 } });
  // /router estado: por modelo, pasos, rechazos y tasa.
  const panel = engine.routerStatus().join("\n");
  assert.match(panel, /fuerte·blue kimi +2 +2 +31 %/);
  assert.match(panel, /fuerte·blue ultra +3 +0 +1 %/);
  engine.close();
});

test("negativas en el bucle: un ejecutor estándar que se niega repite ese paso con su versión sin barandas; los dos quedan en la cuenta", async () => {
  const mundo = new MundoFalso();
  mundo.niega = (modelo, worker) => modelo === "glm-estandar" && worker === "principal";
  const { engine } = armar({ provider: mundo.proveedor("glm-estandar", TARIFAS.glm), routerModels: { estandar: ["faux/glm-estandar"] }, router: "auto" }, mundo);
  mundo.bucle = [sondeo("/api/a"), { text: "Listo." }];
  await engine.send("seguí");
  // Una negativa red de un estándar ya pasa el umbral ((1 + 5·0,2) / (1 + 5) = 0,33): el paso siguiente va directo.
  assert.deepEqual(mundo.llamadas.map((call) => `${call.worker}:${call.modelo}${call.rechazo ? "!" : ""}`), ["principal:glm-estandar!", "principal:glm", "principal:glm"]);
  assert.deepEqual(filas(engine), ["principal:glm-estandar", "principal:glm", "principal:glm"]);
  assert.ok(engine.rechazos.tasa("faux/glm-estandar", "red", true) > 0.3);
  assert.equal(eventos(engine, "router.rechazo")[0].reintento, "faux/glm");
  assert.ok(engine.agent.messages.every((message) => message.role !== "assistant" || !/Lo siento/.test(message.content)), "la negativa no entra al historial");
  engine.close();
});

test("revisión de código: el medio lee código sobre un traspaso, por tramos y con enfriamiento", async () => {
  const { mundo, engine } = armar();
  assert.equal(await engine.setMediumModel("faux/hy4"), "faux/hy4");
  engine.catalog.load("code_read");
  simular(engine, "code_read", (args) => `// ${String(args.path)}\nrouter.get("/admin", (req, res) => res.json(db.users())); // sin control de rol`);
  mundo.bucle = [...["a.ts", "b.ts", "c.ts", "d.ts", "e.ts", "f.ts"].map((path) => llama("code_read", { path })), { text: "Listo." }];
  await engine.send("seguí");
  assert.equal(engine.router.perfil(), "codigo");
  const workers = mundo.llamadas.map((call) => `${call.worker}:${call.modelo}`);
  assert.equal(workers.filter((worker) => worker.endsWith(":medio:hy4")).length, 1, workers.join(" "));
  assert.deepEqual(eventos(engine, "router.decision").map((item) => [item.rol, item.forma, item.nivel, item.motivo]), [["medio", "tramo", "blue", "codigo"]]);
  assert.ok(mundo.llamadas.filter((call) => call.worker === "principal").every((call) => call.modelo === "glm"));
  engine.close();
});
