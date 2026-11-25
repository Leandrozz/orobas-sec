import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { DatabaseSync } from "node:sqlite";
import { DetectorBucles, lecturaShell, notaBucle, TOPE_CLAVES_BUCLE } from "../src/automejora-bucles.ts";
import { diagnosticarMejoras, redactarConModelo } from "../src/mejoras.ts";
import { Engine } from "../src/engine.ts";
import { conWorker } from "../src/grafo.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider, type Provider } from "../src/providers.ts";
import { logEvent, openStore, projectPaths } from "../src/store.ts";
import { findCommand } from "../src/tui/comandos.ts";
import { fakeIO } from "./fake-io.ts";

const carpeta = () => mkdtempSync(join(tmpdir(), "cyber-mejoras-"));

/** Gateway falso, sin red: guarda las cabeceras del catálogo y lo que se le pidió al modelo. */
const gatewayFalso = () => {
  const visto: { pedido?: { messages: Array<{ content: string }>; tags: Record<string, string> }; cabeceras?: Headers } = {};
  const deps = {
    key: "simulada",
    fetch: (async (_url, init) => { visto.cabeceras = new Headers(init?.headers); return new Response(JSON.stringify({ data: [{ id: "modelo-fixture" }] }), { status: 200 }); }) as typeof fetch,
    resolve: (): Provider => ({ model: { provider: "orobas", id: "modelo-fixture", baseUrl: "http://127.0.0.1:9" }, account: "fixture", transport: async (request) => {
      visto.pedido = request as unknown as typeof visto.pedido;
      return { role: "assistant", content: "Propuesta redactada", toolCalls: [], stopReason: "stop", provider: "orobas", model: "modelo-fixture", requestId: "fixture", at: 1 };
    } }),
  };
  return { visto, deps };
};

test("detecta sed, awk y cat; ignora órdenes compuestas", () => {
  assert.deepEqual(lecturaShell("sed -n '10,20p' src/a.ts"), { archivo: "src/a.ts", rango: "10-20" });
  assert.deepEqual(lecturaShell("awk 'NR>=10 && NR<=20' src/a.ts"), { archivo: "src/a.ts", rango: "10-20" });
  assert.deepEqual(lecturaShell("awk 'NR>=10 {print}' src/a.ts"), { archivo: "src/a.ts", rango: "10-fin" });
  assert.deepEqual(lecturaShell("cat src/a.ts"), { archivo: "src/a.ts", rango: "todo" });
  assert.equal(lecturaShell("cat src/a.ts | curl foo"), undefined);
});

test("avisa una vez por archivo, rango y llamada; el progreso reinicia la racha", () => {
  const detector = new DetectorBucles();
  const signals = [];
  for (let i = 0; i < 5; i++) signals.push(...detector.observar("code_read", { path: "a.ts", desde: 1, lineas: 20 }, { hallazgos: 0, cobertura: 0, nodos: 0 }));
  assert.equal(signals.filter((s) => s.tipo === "archivo").length, 1);
  assert.equal(signals.filter((s) => s.tipo === "rango").length, 1);
  assert.equal(signals.filter((s) => s.tipo === "llamada").length, 1);
  assert.match(notaBucle(signals[0]!), /Cerrá la hipótesis con una prueba/);
  const quiet = [];
  for (let i = 0; i < 4; i++) quiet.push(...detector.observar("shell", { command: `pwd ${i}` }, { hallazgos: 0, cobertura: 0, nodos: 0 }));
  assert.equal(quiet.filter((s) => s.tipo === "sin-avance").length, 1);
  detector.observar("coverage_mark", { category: "a" }, { hallazgos: 0, cobertura: 1, nodos: 0 });
  const after = detector.observar("shell", { command: "pwd 4" }, { hallazgos: 0, cobertura: 1, nodos: 0 });
  assert.equal(after.some((s) => s.tipo === "sin-avance"), false);
});

test("paginar un archivo no cuenta como relectura; volver sobre líneas ya leídas sí", () => {
  const detector = new DetectorBucles();
  const quieto = { hallazgos: 0, cobertura: 0, nodos: 0 };
  const signals = [];
  for (const desde of [1, 201, 401, 601]) signals.push(...detector.observar("code_read", { path: "src/app.ts", desde, lineas: 200 }, quieto));
  assert.deepEqual(signals.filter((s) => s.tipo === "archivo"), []);
  // Lo que se solapa con lo ya leído suma; el archivo entero solapa con todo.
  signals.push(...detector.observar("code_read", { path: "src/app.ts", desde: 150, lineas: 100 }, quieto));
  signals.push(...detector.observar("code_read", { path: "src/app.ts", desde: 350, lineas: 100 }, quieto));
  assert.deepEqual(signals.filter((s) => s.tipo === "archivo"), []);
  signals.push(...detector.observar("shell", { command: "cat src/app.ts" }, quieto));
  const archivo = signals.filter((s) => s.tipo === "archivo");
  assert.equal(archivo.length, 1);
  assert.equal(archivo[0]!.detalle, "src/app.ts");
  // Un artefacto paginado por caracteres tampoco es relectura.
  const otro = new DetectorBucles();
  const pages = [0, 2000, 4000, 6000].flatMap((at) => otro.observar("artifact_read", { hash: "sha256:x", at, chars: 2000 }, quieto));
  assert.deepEqual(pages.filter((s) => s.tipo === "archivo"), []);
});

test("repetir una orden con otro resultado o un sondeo no es un bucle; la misma salida sí", () => {
  const quieto = { hallazgos: 0, cobertura: 0, nodos: 0 };
  const detector = new DetectorBucles();
  const signals = [];
  // npm test tras cada edición: la orden es la misma, el resultado cambia.
  for (const salida of ["2 fallan", "1 falla", "todo pasa"]) signals.push(...detector.observar("shell", { command: "npm test" }, quieto, false, { resultado: salida }));
  // Esperas y sondeos se repiten por diseño.
  for (let i = 0; i < 4; i++) signals.push(...detector.observar("harness_wait", { id: "h1", segundos: 30 }, quieto, false, { resultado: "sigue corriendo" }));
  for (let i = 0; i < 4; i++) signals.push(...detector.observar("mail_wait", { segundos: 60 }, quieto, false, { resultado: "sin correo nuevo" }));
  assert.deepEqual(signals.filter((s) => s.tipo === "llamada"), []);
  const igual = new DetectorBucles();
  const repetidas = [0, 1, 2].flatMap(() => igual.observar("shell", { command: "npm test" }, quieto, false, { resultado: "2 fallan" }));
  assert.equal(repetidas.filter((s) => s.tipo === "llamada").length, 1);
  // Una herramienta pura repite con los mismos argumentos aunque el texto cambie.
  const pura = new DetectorBucles();
  const puras = ["a", "b", "c"].flatMap((texto) => pura.observar("jwt_inspect", { token: "x" }, quieto, false, { resultado: texto, pura: true }));
  assert.equal(puras.filter((s) => s.tipo === "llamada").length, 1);
});

test("el motor no avisa por una orden de shell repetida cuyo resultado cambia", async () => {
  const engine = new Engine({ cwd: carpeta(), provider: resolveProvider("faux"), grafo: false });
  let corrida = 0;
  const tool = engine.bounded({ name: "shell", label: "shell", description: "", parameters: {}, execute: () => ({ text: `corrida ${++corrida}: ${4 - corrida} fallan` }) });
  const textos = [];
  for (let i = 0; i < 3; i++) textos.push((await tool.execute({ command: "npm test" }, new AbortController().signal)).text);
  assert.ok(textos.every((text) => !text.includes("[automejora]")), textos.join("\n"));
  engine.db.close();
});

test("el detector guarda huellas con tope, no argumentos completos, y olvida lo usado hace más tiempo", () => {
  const quieto = { hallazgos: 0, cobertura: 0, nodos: 0 };
  const detector = new DetectorBucles();
  const grande = "x".repeat(10_000);
  for (let i = 0; i < 700; i++) for (let vez = 0; vez < 3; vez++) detector.observar("http_request", { url: `https://a.test/${i}`, body: grande }, quieto, false, { resultado: grande });
  for (let i = 0; i < 700; i++) detector.observar("code_read", { path: `src/${i}-${grande.slice(0, 500)}.ts` }, quieto);
  const internos = detector as unknown as Record<string, { size: number; keys(): Iterable<string> }>;
  for (const nombre of ["archivos", "rangos", "llamadas", "avisadas"]) {
    const mapa = internos[nombre]!;
    assert.ok(mapa.size <= TOPE_CLAVES_BUCLE, `${nombre}: ${mapa.size} claves`);
    for (const key of mapa.keys()) assert.ok(key.length <= 64, `${nombre}: clave de ${key.length} caracteres`);
  }
  // LRU: una llamada usada hace poco sobrevive aunque entren más claves que el tope.
  const lru = new DetectorBucles();
  const otras = (desde: number) => { for (let i = desde; i < desde + Math.ceil(TOPE_CLAVES_BUCLE * 0.8); i++) lru.observar("shell", { command: `echo ${i}` }, quieto, false, { resultado: String(i) }); };
  lru.observar("shell", { command: "id" }, quieto, false, { resultado: "uid=0" });
  otras(0);
  lru.observar("shell", { command: "id" }, quieto, false, { resultado: "uid=0" });
  otras(10_000);
  const tercera = lru.observar("shell", { command: "id" }, quieto, false, { resultado: "uid=0" });
  assert.equal(tercera.filter((s) => s.tipo === "llamada").length, 1);
});

test("la nota pide cerrar la hipótesis o descartarla con motivo, sin mandar a abandonar una grieta abierta", () => {
  for (const tipo of ["archivo", "rango", "llamada", "sin-avance"] as const) {
    const nota = notaBucle({ tipo, detalle: "src/app.ts", paso: 9, desde: 1, veces: 8 });
    assert.match(nota, /Cerrá la hipótesis con una prueba/);
    assert.match(nota, /descartala en la memoria con el motivo/);
    assert.match(nota, /grieta concreta, no la abandones/);
    assert.doesNotMatch(nota, /pasá a otra|cambiá de tema/);
  }
});

test("el motor agrega la nota al resultado y registra la señal local", async () => {
  const cwd = carpeta();
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), grafo: false });
  const tool = engine.bounded({ name: "code_read", label: "leer", description: "", parameters: {}, execute: () => ({ text: "archivo sintético" }) });
  let result;
  for (let i = 0; i < 4; i++) result = await tool.execute({ path: "a.ts", desde: 1, lineas: 20 }, new AbortController().signal);
  assert.match(result!.text, /Cerrá la hipótesis con una prueba/);
  const events = engine.db.prepare("select type from events where session_id=? and type='automejora.loop'").all(engine.sessionId);
  assert.equal(events.length, 3);
  const again = await tool.execute({ path: "a.ts", desde: 1, lineas: 20 }, new AbortController().signal);
  assert.doesNotMatch(again.text, /Cerrá la hipótesis/);
  engine.db.close();
});

test("cada bucle (principal, subagente, verificador) lleva su propio detector", async () => {
  const engine = new Engine({ cwd: carpeta(), provider: resolveProvider("faux"), grafo: false });
  const tool = engine.bounded({ name: "code_read", label: "leer", description: "", parameters: {}, execute: () => ({ text: "archivo sintético" }) });
  const [sub] = conWorker("sub:1", [tool]);
  const [verificador] = conWorker("verificador:f1", [tool]);
  const args = { path: "a.ts", desde: 1, lineas: 20 };
  const textos = [];
  for (const each of [tool, tool, sub!, sub!, verificador!, verificador!]) textos.push((await each.execute(args, new AbortController().signal)).text);
  assert.ok(textos.every((text) => !text.includes("[automejora]")), textos.join("\n"));
  // Dentro de un mismo bucle sí: la tercera llamada idéntica del subagente avisa.
  assert.match((await sub!.execute(args, new AbortController().signal)).text, /\[sistema\]\[automejora\]/);
  engine.db.close();
});

test("el progreso de cada llamada no recorre events ni grafo_nodos enteros y sigue viendo lo nuevo", async (t) => {
  const engine = new Engine({ cwd: carpeta(), provider: resolveProvider("faux"), grafo: true });
  t.after(() => engine.db.close());
  assert.ok(engine.grafo);
  const nodo = (sesion: string, clave: string) => engine.db.prepare("insert into grafo_nodos(particion,clave,tipo,etiqueta,estado,herramienta,evidencia,worker,sesion,creado,ult_herramienta,ult_evidencia,ult_worker,ult_sesion,visto) values('p',?,'ruta',?,'pedido','x','x','principal',?,'t','x','x','principal',?,'t')").run(clave, clave, sesion, sesion);
  for (let i = 0; i < 200; i++) { logEvent(engine.db, "otra-sesion", "finding.changed", { id: `f${i}` }); nodo("otra-sesion", `/vieja/${i}`); }
  let corrida = 0;
  const tool = engine.bounded({ name: "shell", label: "shell", description: "", parameters: {}, execute: () => ({ text: `salida ${++corrida}` }) });
  const original = engine.db.prepare.bind(engine.db);
  const consultas = new Set<string>();
  engine.db.prepare = ((sql: string) => { consultas.add(sql); return original(sql); }) as typeof engine.db.prepare;
  const textos: string[] = [];
  const correr = async (n: number) => { for (let i = 0; i < n; i++) textos.push((await tool.execute({ command: `echo ${corrida}` }, new AbortController().signal)).text); };
  try {
    await correr(7);
    logEvent(engine.db, engine.sessionId, "finding.changed", { id: "nuevo" });
    await correr(7);
    nodo(engine.sessionId, "/nueva");
    await correr(7);
  } finally { engine.db.prepare = original; }
  // Un hallazgo y un nodo nuevos cortan la racha: nunca llegan a ocho herramientas seguidas sin progreso.
  assert.ok(textos.every((text) => !/sin progreso/.test(text)), textos.join("\n"));
  const recorridos = [...consultas].filter((sql) => /^\s*select/i.test(sql) && /\b(events|grafo_nodos)\b/.test(sql)).flatMap((sql) =>
    (original(`explain query plan ${sql}`).all() as Array<{ detail: string }>).filter((row) => /^SCAN (events|grafo_nodos)\b/.test(row.detail)).map((row) => `${row.detail} ← ${sql}`));
  assert.deepEqual(recorridos, []);
});

test("modo no corta antes de consultar la base", () => {
  const trap = { prepare: () => { throw new Error("leyó cyber.db"); } } as unknown as DatabaseSync;
  const report = diagnosticarMejoras(trap, carpeta(), 10, "no");
  assert.equal(report.sesiones, 0);
  assert.match(report.lineas.join("\n"), /no leí trazas ni cyber.db/);
});

test("la redacción optativa no usa proveedores fuera del gateway", async () => {
  await assert.rejects(redactarConModelo({ modo: "local", sesiones: 1, trazas: 1, patrones: [], lineas: [] }, carpeta(), "faux"), /gateway de Elevate/);
});

test("--modelo consulta el catálogo y envía sólo evidencia estructurada", async () => {
  const cwd = carpeta();
  const { visto, deps } = gatewayFalso();
  const report = { modo: "local", sesiones: 1, trazas: 1, lineas: [], patrones: [{ tipo: "archivo", sesion: "fixture-123456", pasos: [2, 5] as [number, number], evidencia: "src/ejemplo.ts", datos: { herramienta: "code_read", conteo: 4 }, cambio: "ajustar guarda", hipotesis: "menos relecturas", cve: false }] };
  const text = await redactarConModelo(report, cwd, "orobas/modelo-fixture", deps);
  assert.equal(text, "Propuesta redactada");
  assert.equal(visto.cabeceras?.get("x-cyber-session"), "mejoras-local");
  assert.equal(visto.cabeceras?.get("x-cyber-project"), cwd.split("/").at(-1));
  assert.equal(visto.cabeceras?.get("x-cyber-trazas"), "no");
  const enviado = JSON.parse(visto.pedido!.messages[0]!.content)[0];
  assert.deepEqual({ tipo: enviado.tipo, sesion: enviado.sesion, pasos: enviado.pasos, herramienta: enviado.herramienta, conteo: enviado.conteo }, { tipo: "archivo", sesion: "fixture-1234", pasos: [2, 5], herramienta: "code_read", conteo: 4 });
  assert.doesNotMatch(visto.pedido!.messages[0]!.content, /src\/ejemplo\.ts/);
  assert.deepEqual(visto.pedido!.tags, { session: "mejoras-local", project: cwd.split("/").at(-1), trazas: "no" });
});

test("--modelo no sube textos de la sesión: errores, motivos y rutas quedan en el informe local", async (t) => {
  const cwd = carpeta(), paths = projectPaths(cwd), db = openStore(paths);
  t.after(() => db.close());
  const id = "sesion-con-secretos";
  db.prepare("insert into sessions(id,started_at,model) values(?,?,?)").run(id, "2026-01-01T00:00:00Z", "faux/faux");
  let seq = 0;
  const message = (body: object) => db.prepare("insert into messages(session_id,seq,json) values(?,?,?)").run(id, ++seq, JSON.stringify(body));
  // Armado en dos partes para que el verificador de la exportación pública no lo tome por una credencial real.
  const token = ["ghp", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("_");
  for (let i = 0; i < 2; i++) {
    const call = { id: `e${i}`, name: "shell", arguments: JSON.stringify({ command: `cat /home/operador/privado/nota-${i}.txt` }) };
    message({ role: "assistant", content: "", toolCalls: [call], stopReason: "toolUse", provider: "faux", model: "faux", at: 1 });
    message({ role: "tool", toolCallId: call.id, name: call.name, content: `La llamada salió malformada: argumentos JSON en /home/operador/privado/nota-${i}.txt con ${token}`, isError: true, at: 1 });
  }
  db.exec("create table findings(id text primary key, json text not null)");
  db.prepare("insert into findings(id,json) values(?,?)").run("f1", JSON.stringify({ id: "f1", sessionId: id, state: "descartado", decidedBy: "verificador:x", reason: `vale ${token} en /home/operador/privado` }));
  const report = diagnosticarMejoras(db, cwd, 10, "local");
  assert.ok(report.patrones.some((p) => p.tipo === "malformada"));
  assert.match(report.lineas.join("\n"), /\/home\/operador\/privado/, "el informe local conserva la evidencia");
  const { visto, deps } = gatewayFalso();
  await redactarConModelo(report, cwd, "orobas/modelo-fixture", deps);
  const content = visto.pedido!.messages[0]!.content;
  assert.doesNotMatch(content, /ghp_|\/home\/operador|privado|malformada:|vale /);
  const enviados = JSON.parse(content) as Array<Record<string, unknown>>;
  for (const item of enviados) for (const key of Object.keys(item)) assert.ok(["id", "tipo", "sesion", "pasos", "herramienta", "conteo", "propuesta", "hipotesis"].includes(key), key);
  assert.ok(enviados.some((item) => item.tipo === "malformada" && item.herramienta === "shell" && item.conteo === 1));
  assert.ok(enviados.some((item) => item.tipo === "descartado" && item.conteo === 1));
});

test("--modelo tapa con los secretos conocidos el nombre de herramienta que manda", async (t) => {
  const previo = process.env.FIXTURE_MEJORAS_TOKEN;
  process.env.FIXTURE_MEJORAS_TOKEN = "valorSecreto12345678";
  t.after(() => { if (previo === undefined) delete process.env.FIXTURE_MEJORAS_TOKEN; else process.env.FIXTURE_MEJORAS_TOKEN = previo; });
  const { visto, deps } = gatewayFalso();
  const report = { modo: "local", sesiones: 1, trazas: 0, lineas: [], patrones: [{ tipo: "llamada", sesion: "fixture-123456", pasos: [1, 3] as [number, number], evidencia: "mcp__valorSecreto12345678", datos: { herramienta: "mcp__valorSecreto12345678", conteo: 3 }, cambio: "x", hipotesis: "y", cve: false }] };
  await redactarConModelo(report, carpeta(), "orobas/modelo-fixture", deps);
  const content = visto.pedido!.messages[0]!.content;
  assert.doesNotMatch(content, /valorSecreto12345678/);
  assert.match(JSON.parse(content)[0].herramienta, /^mcp__\[credencial omitida\]$/);
});

test("/mejoras abre la vista del daemon con los argumentos pedidos", async () => {
  const control = fakeIO({ "view:mejoras": ["MEJORAS", "2 patrones"] });
  const panel = await findCommand("mejoras")!.run(control.io, "5");
  assert.deepEqual(control.calls, [{ op: "view:mejoras", payload: { arg: "5" } }]);
  assert.equal(panel?.title, "MEJORAS");
});

test("la vista del daemon respeta el modo no sin pedir un modelo", async (t) => {
  const cwd = carpeta(), previo = process.env.CYBER_TRAZAS;
  process.env.CYBER_TRAZAS = "no";
  t.after(() => { if (previo === undefined) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = previo; });
  const daemon = new Daemon({ cwd, autoResume: false, resolve: () => resolveProvider("faux") });
  t.after(() => daemon.close());
  const interno = daemon as unknown as { handle: (request: object, host: undefined, send: () => void) => Promise<string[]> };
  const lines = await interno.handle({ op: "view", name: "mejoras", arg: "5 modelo" }, undefined, () => {});
  assert.match(lines.join("\n"), /no leí trazas ni cyber.db/);
});

test("informe con fixture local cita sesión, pasos, propuestas y comandos válidos", () => {
  const cwd = carpeta(), paths = projectPaths(cwd), db = openStore(paths);
  const id = "sesion-fixture";
  db.prepare("insert into sessions(id,started_at,model) values(?,?,?)").run(id, "2026-01-01T00:00:00Z", "faux/faux");
  let seq = 0;
  const message = (body: object) => db.prepare("insert into messages(session_id,seq,json) values(?,?,?)").run(id, ++seq, JSON.stringify(body));
  for (let i = 0; i < 4; i++) {
    const call = { id: `c${i}`, name: "code_read", arguments: JSON.stringify({ path: "src/ejemplo.ts", desde: 1, lineas: 20 }) };
    message({ role: "assistant", content: "", toolCalls: [call], stopReason: "toolUse", provider: "faux", model: "faux", at: 1 });
    message({ role: "tool", toolCallId: call.id, name: call.name, content: "contenido sintético".repeat(100), isError: false, at: 1 });
  }
  for (let i = 0; i < 2; i++) {
    const call = { id: `e${i}`, name: "shell", arguments: JSON.stringify({ command: `cat archivo-${i}` }) };
    message({ role: "assistant", content: "", toolCalls: [call], stopReason: "toolUse", provider: "faux", model: "faux", at: 1 });
    message({ role: "tool", toolCallId: call.id, name: call.name, content: "La llamada salió malformada: argumentos JSON", isError: true, at: 1 });
  }
  logEvent(db, id, "automejora.loop", { tipo: "sin-avance", desde: 1, paso: 8, veces: 8 });
  db.exec("create table findings(id text primary key, json text not null)");
  db.prepare("insert into findings(id,json) values(?,?)").run("f1", JSON.stringify({ id: "f1", sessionId: id, state: "descartado", decidedBy: "verificador:x", reason: "sin efecto" }));
  mkdirSync(paths.trazas, { recursive: true });
  for (const file of ["turnos.jsonl", "llamadas.jsonl"]) {
    const fixture = readFileSync(join(import.meta.dirname, "fixtures", "mejoras", file), "utf8");
    writeFileSync(join(paths.trazas, file), fixture.replaceAll("SESION", id));
  }
  const report = diagnosticarMejoras(db, cwd, 10, "local");
  assert.equal(report.sesiones, 1);
  assert.equal(report.trazas, 2);
  for (const type of ["archivo", "rango", "llamada", "sin-avance", "errores", "malformada", "rechazo", "descartado", "contexto"]) assert.ok(report.patrones.some((p) => p.tipo === type), type);
  const text = report.lineas.join("\n");
  assert.match(text, /sesión sesion-fixtu · pasos/);
  assert.match(text, /node bench\/run.ts --target fenix --task bench\/tasks\/fenix.md --runs 3 --presupuesto 0.50 --label mejora-base/);
  assert.match(text, /--target cve --caso todos --version afectada --runs 2/);
  assert.match(text, /Las propuestas son hipótesis/);
  db.close();
});
