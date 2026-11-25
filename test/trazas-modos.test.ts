import "./datos-tmp.ts";
// Trazas en tres modos (compartir, local, no): qué sale por la red hacia el servicio y qué queda en disco.
// El servicio es un servidor local de mentira que anota cada pedido con su cabecera x-cyber-trazas; el
// modelo es el simulado con forma de proveedor orobas. Nada sale de 127.0.0.1.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { configureAccount, refrescarModoCuenta } from "../src/cuenta.ts";
import { Daemon } from "../src/daemon.ts";
import { dataDir } from "../src/datos.ts";
import { Engine } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { anotarModoCuenta, cabecerasDePrivacidad, guardarModoTrazas, leerModo, masRestrictivo, modoLocal, modoTrazas } from "../src/privacidad-trazas.ts";
import { resolveProvider } from "../src/providers.ts";
import { projectPaths } from "../src/store.ts";
import { LEEME } from "../src/trazas-locales.ts";

const SECRETO = "abcdefghijklmnopqrstuvwxyz123456";
const PRIVADO = "revisá el carrito de la tienda";
const RESPUESTA = "el carrito no valida el precio";

type Pedido = { path: string; trazas: string | undefined; auth: string | undefined; body: string };
async function servicio(cuenta?: string) {
  const pedidos: Pedido[] = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      pedidos.push({ path: req.url ?? "", trazas: req.headers["x-cyber-trazas"] as string | undefined, auth: req.headers.authorization, body: raw });
      if (req.url === "/v1/cuenta") return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ object: "account", name: "Ana", verification: "completa", plan: "profesional", tier_usd: 100, ...(cuenta ? { trazas: cuenta } : {}) }));
      res.writeHead(204).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  return { pedidos, base, cerrar: () => { server.closeAllConnections(); server.close(); } };
}

/** Una sesión de dos turnos con el modelo simulado; devuelve qué llegó al servicio y la carpeta de trazas. */
async function sesion(opciones: { variable?: string; cuenta?: string }) {
  const svc = await servicio(opciones.cuenta);
  const cwd = mkdtempSync(join(tmpdir(), "cyber-modos-"));
  const prev = { trazas: process.env.CYBER_TRAZAS, key: process.env.OROBAS_API_KEY, base: process.env.OROBAS_BASE_URL, oro: process.env.CYBER_TEST_ORO };
  if (opciones.variable === undefined) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = opciones.variable;
  process.env.CYBER_TEST_ORO = "oro_prueba";
  process.env.OROBAS_API_KEY = "oro_prueba";
  process.env.OROBAS_BASE_URL = svc.base;
  configureAccount();
  // El modo de la cuenta llega por GET /cuenta: se lee antes de la sesión, como hace el motor al arrancar.
  await refrescarModoCuenta();
  const provider = resolveProvider("faux");
  provider.model = { ...provider.model, provider: "orobas", baseUrl: svc.base, apiKeyEnv: "CYBER_TEST_ORO" };
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("2"), coverageObjections: 0, cveFeed: false });
  try {
    engine.scope.edit({ include: ["api.tienda.test"] });
    provider.faux!.queue = [{ text: `Primera: ${RESPUESTA}` }];
    await engine.send(`Bearer ${SECRETO} es mi token. ${PRIVADO}`);
    provider.faux!.queue = [{ text: "Segunda." }];
    await engine.send("¿Seguimos?");
    await new Promise((resolve) => setTimeout(resolve, 150));
  } finally {
    await engine.close();
  }
  await new Promise((resolve) => setTimeout(resolve, 50));
  const dir = projectPaths(cwd).trazas;
  const restaurar = () => {
    for (const [name, value] of [["CYBER_TRAZAS", prev.trazas], ["OROBAS_API_KEY", prev.key], ["OROBAS_BASE_URL", prev.base], ["CYBER_TEST_ORO", prev.oro]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    configureAccount();
    svc.cerrar();
    rmSync(cwd, { recursive: true, force: true });
  };
  return { pedidos: svc.pedidos, dir, sessionId: engine.sessionId, restaurar };
}

const leer = (ruta: string) => readFileSync(ruta, "utf8");
const lineas = (ruta: string) => leer(ruta).split("\n").filter(Boolean).map((linea) => JSON.parse(linea) as Record<string, any>);
const conContenido = (pedidos: Pedido[]) => pedidos.filter((p) => /\/(traces|trayectorias|consent)$/.test(p.path));
/** Todos llevan la cabecera; la primera lectura de la cuenta sale antes de saber su modo, con el local. */
const cabeceras = (pedidos: Pedido[], rige: string) => {
  assert.ok(pedidos.every((p) => typeof p.trazas === "string"), "todo pedido al servicio lleva el modo");
  const resto = pedidos.filter((p) => p.path !== "/v1/cuenta");
  assert.ok(resto.every((p) => p.trazas === rige), JSON.stringify(pedidos.map((p) => [p.path, p.trazas])));
};

test("modos: nombres, sinónimos de antes, lo desconocido restringe y gana el más restrictivo", () => {
  assert.equal(leerModo("compartir"), "compartir");
  assert.equal(leerModo(" Local "), "local");
  for (const v of ["no", "0", "false", "off", "cantidades", "cualquiera"]) assert.equal(leerModo(v), "no", v);
  for (const v of ["si", "sí", "1", "on", "completa"]) assert.equal(leerModo(v), "compartir", v);
  assert.equal(leerModo(""), undefined);
  assert.equal(leerModo(undefined), undefined);
  assert.equal(masRestrictivo("compartir", "local"), "local");
  assert.equal(masRestrictivo("local", "compartir"), "local");
  assert.equal(masRestrictivo("local", "no"), "no");
  assert.equal(masRestrictivo("no", undefined), "no");
});

test("el modo local sale de la variable, si no de la configuración, si no «no»; la cuenta sólo restringe", () => {
  const prev = process.env.CYBER_TRAZAS;
  const config = process.env.CYBER_CONFIG!;
  try {
    delete process.env.CYBER_TRAZAS;
    rmSync(config, { force: true });
    anotarModoCuenta(undefined);
    assert.deepEqual(modoLocal(), { modo: "no", origen: "defecto" });
    assert.deepEqual(cabecerasDePrivacidad(), { "x-cyber-trazas": "no" }, "la cabecera va siempre, con el modo");
    writeFileSync(config, JSON.stringify({ providers: {}, idioma: "es" }));
    assert.equal(guardarModoTrazas("local"), undefined);
    assert.deepEqual(JSON.parse(leer(config)), { providers: {}, idioma: "es", trazas: "local" }, "no pisa el resto de la configuración");
    assert.deepEqual(modoLocal(), { modo: "local", origen: "configuración" });
    process.env.CYBER_TRAZAS = "no";
    assert.deepEqual(modoLocal(), { modo: "no", origen: "variable" });
    assert.match(guardarModoTrazas("compartir") ?? "", /CYBER_TRAZAS=no manda/);
    delete process.env.CYBER_TRAZAS;
    anotarModoCuenta("no");
    assert.equal(modoTrazas(), "no", "la cuenta más restrictiva gana");
    anotarModoCuenta("compartir");
    guardarModoTrazas("local");
    assert.equal(modoTrazas(), "local", "la cuenta nunca amplía");
    writeFileSync(config, "{ esto no es json");
    anotarModoCuenta(undefined);
    assert.equal(modoTrazas(), "no", "una configuración que no se entiende restringe");
  } finally {
    rmSync(config, { force: true });
    anotarModoCuenta(undefined);
    if (prev === undefined) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = prev;
  }
});

test("compartir (elegido): salen el turno y la trayectoria (tapados) con la cabecera, y no queda nada en la carpeta local", async () => {
  const s = await sesion({ variable: "compartir" });
  try {
    assert.ok(s.pedidos.length > 0);
    assert.ok(s.pedidos.every((p) => p.trazas === "compartir"), JSON.stringify(s.pedidos.map((p) => [p.path, p.trazas])));
    const turnos = s.pedidos.filter((p) => p.path === "/v1/traces");
    assert.equal(turnos.length, 2, "un registro por turno");
    assert.match(turnos[0]!.body, new RegExp(PRIVADO));
    const trayectorias = s.pedidos.filter((p) => p.path === "/v1/trayectorias");
    assert.ok(trayectorias.length >= 1, "la trayectoria de la sesión se sube");
    const subida = JSON.parse(trayectorias.at(-1)!.body);
    assert.equal(subida.session, s.sessionId);
    assert.equal(subida.record.turns.length, 2, "la última subida tiene la sesión entera");
    assert.deepEqual(subida.record.scope.include, ["host-1"], "anonimizada");
    for (const p of s.pedidos) assert.ok(!p.body.includes(SECRETO), `${p.path} no lleva la credencial`);
    assert.equal(existsSync(s.dir), false, "en compartir no se escribe la carpeta de trazas locales");
  } finally { s.restaurar(); }
});

for (const [variable, cuenta, rige] of [["local", undefined, "local"], ["compartir", "local", "local"]] as const) {
  test(`local (variable ${variable}${cuenta ? `, cuenta ${cuenta}` : ""}): nada de contenido sale y el material completo queda en disco, tapado`, async () => {
    const s = await sesion({ variable, cuenta });
    try {
      assert.deepEqual(conContenido(s.pedidos), [], "ni turnos, ni trayectorias, ni citas");
      cabeceras(s.pedidos, rige);
      assert.equal(leer(join(s.dir, "LEEME.md")), LEEME);
      const llamadas = lineas(join(s.dir, "llamadas.jsonl"));
      assert.ok(llamadas.length >= 2, "al menos un pedido al modelo por turno");
      assert.equal(llamadas[0]!.v, 1);
      assert.equal(llamadas[0]!.sesion, s.sessionId);
      assert.match(llamadas[0]!.pedido.system, /^sha256:[0-9a-f]{64}$/);
      assert.ok(existsSync(join(s.dir, "piezas", `${llamadas[0]!.pedido.system.slice(7)}.json`)), "el prompt está una vez, como pieza");
      assert.ok(JSON.stringify(llamadas[0]!.pedido.messages).includes(PRIVADO), "el pedido entero, como salió");
      assert.ok(llamadas.some((l) => String(l.respuesta.content).includes(RESPUESTA)), "y la respuesta");
      const turnos = lineas(join(s.dir, "turnos.jsonl"));
      assert.equal(turnos.length, 2);
      assert.ok(turnos[0]!.turn.operator[0].text.includes(PRIVADO));
      const trayectoria = lineas(join(s.dir, "trayectorias", `${s.sessionId}.jsonl`));
      assert.equal(trayectoria.length, 1);
      assert.equal(trayectoria[0]!.turns.length, 2);
      assert.deepEqual(trayectoria[0]!.scope.include, ["api.tienda.test"], "en la PC los hosts quedan como están");
      const todo = readdirSync(s.dir, { recursive: true }).map(String).filter((f) => f.endsWith(".json") || f.endsWith(".jsonl")).map((f) => leer(join(s.dir, f))).join("\n");
      assert.ok(!todo.includes(SECRETO), "la credencial pegada no queda en disco");
    } finally { s.restaurar(); }
  });
}

for (const [variable, cuenta] of [["no", undefined], ["cantidades", undefined], ["compartir", "no"], ["local", "no"]] as const) {
  test(`no (variable ${variable}${cuenta ? `, cuenta ${cuenta}` : ""}): nada de contenido sale y no se arma material en disco`, async () => {
    const s = await sesion({ variable, cuenta });
    try {
      assert.deepEqual(conContenido(s.pedidos), []);
      cabeceras(s.pedidos, "no");
      assert.equal(existsSync(s.dir), false, "sin carpeta de trazas");
    } finally { s.restaurar(); }
  });
}

test("daemon: el aviso de la primera vez sale una sola vez, y en local cada sesión dice dónde quedan; la cita local queda tapada", async () => {
  const prev = { trazas: process.env.CYBER_TRAZAS, base: process.env.OROBAS_BASE_URL, key: process.env.OROBAS_API_KEY };
  delete process.env.CYBER_TRAZAS;
  process.env.OROBAS_BASE_URL = "http://127.0.0.1:9";
  delete process.env.OROBAS_API_KEY;
  rmSync(join(dataDir(), "aviso-trazas.json"), { force: true });
  const cwd = mkdtempSync(join(tmpdir(), "cyber-aviso-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const primero = await connectDaemon(cwd, { spawn: false });
    const snap = await primero.attach({ session: "new" });
    const aviso = (snap.avisos ?? []).join("\n");
    assert.match(aviso, /Sin telemetría: no se guardan ni se comparten trazas/);
    assert.match(aviso, /\/datos local/);
    assert.match(aviso, /\/datos compartir/);
    primero.close();
    const segundo = await connectDaemon(cwd, { spawn: false });
    assert.doesNotMatch(((await segundo.attach({ session: "new" })).avisos ?? []).join("\n"), /Sin telemetría/, "una sola vez");
    await segundo.ask("datos", { action: "modo", value: "local" });
    segundo.close();
    const tercero = await connectDaemon(cwd, { spawn: false });
    assert.match(((await tercero.attach({ session: "new" })).avisos ?? []).join("\n"), /Trazas en modo local: .*trazas/);
    const otorgado = await tercero.ask("consent", { value: `borrar-ajeno si «Autorizo borrar lo mío. token=DatoFicticio7382 ${PRIVADO}»` });
    assert.match(otorgado[0]!, /registrado/);
    assert.match(otorgado[0]!, /sin cuenta de orobas no se envía/, "sin cuenta no sale ningún pedido");
    const dir = projectPaths(cwd).trazas;
    const [cita] = lineas(join(dir, "consentimientos.jsonl"));
    assert.equal(cita!.kind, "borrar-ajeno");
    assert.match(cita!.cita, new RegExp(PRIVADO));
    assert.ok(!cita!.cita.includes("DatoFicticio7382"), "la cita local también va tapada");
    tercero.close();
  } finally {
    daemon.close();
    for (const [name, value] of [["CYBER_TRAZAS", prev.trazas], ["OROBAS_BASE_URL", prev.base], ["OROBAS_API_KEY", prev.key]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    rmSync(process.env.CYBER_CONFIG!, { force: true });
  }
});
