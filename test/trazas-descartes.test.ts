import "./datos-tmp.ts";
// Material de entrenamiento con credenciales de prueba en «compartir» (punto 4 del 22/11). Del lado del harness:
// - cada pedido al modelo que lleva a la vista material del objetivo sale con «x-cyber-trazas: no» (el gateway no
//   guarda su cuerpo);
// - el pedido en el que el agente INVENTA la contraseña salió en «compartir» sin ella, pero la respuesta la trae:
//   el motor pide descartar la traza de ese pedido (POST /traces/descartar, sólo ids);
// - el turno y la trayectoria salen igual, en «compartir» y con todo tapado: ése es el material que queda.
// El servicio es de mentira (secretos-falsos.ts) y aplica la regla del gateway de orobas-sec-web #68 para decir qué
// queda guardado. El servicio real se prueba en orobas-sec-web (test/trazas-material-objetivo.test.ts).
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ConsentStore } from "../src/consent.ts";
import { configureAccount, refrescarModoCuenta } from "../src/cuenta.ts";
import { Engine } from "../src/engine.ts";
import { anthropicMessages, openAICompletions } from "../src/llm.ts";
import { usdToPico } from "../src/money.ts";
import { anotarModoCuenta, modoLocal, modoTrazas } from "../src/privacidad-trazas.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { type Cerebro, escuchar, esperar, type Formato, guardadoPorElGateway, noModelo, proveedor, resultados, sinCanarios } from "./secretos-falsos.ts";

const PASS = "Pr0bandoCuenta-Agente-7h2Q";
const TOKEN = "TokenDeLaCuentaDePrueba9Wq3Ze";

/** El objetivo: /registro guarda la cuenta (formulario), /login devuelve un token si la contraseña es la registrada. */
async function objetivo() {
  const cuentas = new Map<string, string>();
  const server = createServer((req, res) => {
    let cuerpo = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (cuerpo += chunk));
    req.on("end", () => {
      const form = new URLSearchParams(cuerpo);
      if (req.url === "/registro") { cuentas.set(form.get("email") ?? "", form.get("password") ?? ""); return res.writeHead(201, { "content-type": "application/json" }).end(JSON.stringify({ id: "usr_1" })); }
      if (req.url === "/login") {
        if (cuentas.get(form.get("email") ?? "") !== form.get("password")) return res.writeHead(401).end("credenciales");
        return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: TOKEN }));
      }
      res.writeHead(200, { "content-type": "text/plain" }).end("hola");
    });
  });
  return { base: await escuchar(server), cerrar: () => { server.closeAllConnections(); server.close(); } };
}

/** El agente crea una cuenta de prueba con una contraseña que inventa, entra y cuenta lo que hizo. */
const cuentaDePrueba = (base: string): Cerebro => (body, formato) => {
  const vistos = resultados(body, formato);
  const form = `email=qa%40pruebas.test&password=${PASS}`;
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  if (vistos.length === 0) return { llamada: { name: "http_request", args: { url: `${base}/registro`, method: "POST", headers, body: form } } };
  if (vistos.length === 1) return { llamada: { name: "http_request", args: { url: `${base}/login`, method: "POST", headers, body: form } } };
  return { texto: `Cuenta de prueba creada con la contraseña ${PASS}; el login devolvió ${/"access_token":"([^"\\]+)/.exec(vistos[1]!)?.[1] ?? "nada"}.` };
};
/** El agente mira la portada y contesta: ninguna credencial en toda la sesión. */
const sinCredenciales = (base: string): Cerebro => (body, formato) =>
  resultados(body, formato).length === 0 ? { llamada: { name: "http_request", args: { url: `${base}/` } } } : { texto: "La portada dice hola." };

// Estas pruebas son del modo «compartir», que desde el 25/11/2026 se elige a mano: sin variable, la sesión lo elige.
// `variable: null` deja la máquina sin elegir (el modo por defecto, «no»).
async function sesion(formato: Formato, cerebro: (base: string) => Cerebro, opciones: { variable?: string | null; descartar?: () => number; cwd?: string } = {}) {
  const target = await objetivo();
  const svc = proveedor(formato, () => target.base, cerebro(target.base), { ids: true, descartar: opciones.descartar });
  const svcBase = `${await escuchar(svc.server)}/v1`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-descartes-"));
  const prev = { config: process.env.CYBER_CONFIG, key: process.env.OROBAS_API_KEY, trazas: process.env.CYBER_TRAZAS };
  writeFileSync(join(dir, "config.json"), JSON.stringify({ providers: { orobas: { baseUrl: svcBase, apiKeyEnv: "OROBAS_API_KEY" } } }));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  process.env.OROBAS_API_KEY = "oro_prueba_descartes_1";
  if (opciones.variable === null) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = opciones.variable ?? "compartir";
  const cwd = opciones.cwd ?? join(dir, "proyecto");
  mkdirSync(cwd, { recursive: true });
  const provider = { model: { provider: "orobas", id: "descartes", baseUrl: svcBase, apiKeyEnv: "OROBAS_API_KEY" }, transport: formato === "openai" ? openAICompletions : anthropicMessages, account: "OROBAS_API_KEY" };
  const abrir = () => {
    const engine = new Engine({ cwd, provider, budgetPico: usdToPico("5"), coverageObjections: 0, closingGate: false, autoVerify: false, router: "fijo", cveFeed: false, retryBaseMs: 1 });
    engine.scope.edit({ include: ["127.0.0.1"] });
    return engine;
  };
  const cerrar = () => {
    target.cerrar();
    svc.server.closeAllConnections();
    svc.server.close();
    for (const [name, value] of [["CYBER_CONFIG", prev.config], ["OROBAS_API_KEY", prev.key], ["CYBER_TRAZAS", prev.trazas]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    if (!opciones.cwd) rmSync(dir, { recursive: true, force: true });
  };
  return { abrir, svc, cerrar, cwd };
}

/** Un turno entero y el cierre: el registro del turno, los descartes pendientes y la trayectoria. */
async function turnoYCierre(engine: Engine, svc: ReturnType<typeof proveedor>, texto: string) {
  await engine.send(texto);
  await esperar(() => svc.cuerpos.some((item) => item.url.endsWith("/traces")));
  await engine.close();
  await esperar(() => svc.cuerpos.some((item) => item.url.endsWith("/trayectorias")));
}

const descartes = (svc: ReturnType<typeof proveedor>) => svc.cuerpos.filter((item) => item.url.endsWith("/traces/descartar"));

// El gateway de orobas habla Chat Completions (el proveedor «orobas» usa ese transporte): x-request-id trae el id.
for (const formato of ["openai"] as const) {
  test(`compartir con una cuenta de prueba (${formato}): el gateway no se queda con la contraseña, y el turno y la trayectoria tapados sí se guardan`, async () => {
    const s = await sesion(formato, cuentaDePrueba);
    try {
      anotarModoCuenta(undefined);
      assert.equal(modoTrazas(), "compartir", "elegido a mano");
      const engine = s.abrir();
      await turnoYCierre(engine, s.svc, "Creá una cuenta de prueba y entrá con ella.");
      const modelo = s.svc.modelo();
      assert.equal(modelo.length, 3, "registro, login y el cierre");
      // El pedido en el que inventa la contraseña no la lleva: sale en «compartir». Los siguientes la llevan: «no».
      assert.ok(!modelo[0]!.body.includes(PASS));
      assert.match(modelo[0]!.respuesta!, new RegExp(PASS), "la trae la respuesta");
      assert.deepEqual(modelo.map((pedido) => pedido.trazas), ["compartir", "no", "no"]);
      for (const pedido of modelo.slice(1)) assert.ok(pedido.body.includes(PASS), "el modelo ve la contraseña que inventó");
      // Se pidió descartar exactamente la traza de ese pedido: sólo el id, en «compartir», sin contenido.
      const pedidos = descartes(s.svc);
      assert.equal(pedidos.length, 1);
      assert.deepEqual(JSON.parse(pedidos[0]!.body), { traces: [modelo[0]!.id] });
      assert.equal(pedidos[0]!.trazas, "compartir");
      // Turno y trayectoria en «compartir», con la contraseña y el token tapados.
      const contenido = noModelo(s.svc.cuerpos).filter((item) => /\/(traces|trayectorias)$/.test(item.url));
      // La trayectoria sale al terminar el turno y otra vez al cerrar (el servicio reemplaza la misma sesión).
      assert.deepEqual([...new Set(contenido.map((item) => `${item.url.replace(/^.*\/v1/, "")} ${item.trazas}`))].sort(), ["/traces compartir", "/trayectorias compartir"]);
      sinCanarios(contenido, { contraseña: PASS, token: TOKEN });
      assert.match(contenido.find((item) => item.url.endsWith("/traces"))!.body, /contraseña ‹SECRETO_\d+›; el login devolvió ‹SECRETO_\d+›/);
      // Lo que queda guardado en el servicio: el turno y la trayectoria, y ningún rastro de la contraseña ni del token.
      const guardado = guardadoPorElGateway(s.svc.cuerpos);
      assert.deepEqual([...new Set(guardado.map((item) => item.url.replace(/^.*\/v1/, "")))].sort(), ["/traces", "/trayectorias"], "ni un pedido al modelo: el primero se descartó y los otros salieron con «no»");
      sinCanarios(guardado, { contraseña: PASS, token: TOKEN });
      // Sin descartar, el gateway se habría quedado con la contraseña en claro (control).
      assert.throws(() => sinCanarios(guardadoPorElGateway(s.svc.cuerpos.filter((item) => !item.url.endsWith("/traces/descartar"))), { contraseña: PASS }));
    } finally { s.cerrar(); }
  });
}

test("compartir sin credenciales: no se descarta nada y los pedidos al modelo quedan como material", async () => {
  const s = await sesion("openai", sinCredenciales);
  try {
    const engine = s.abrir();
    await turnoYCierre(engine, s.svc, "Mirá la portada.");
    assert.deepEqual(s.svc.modelo().map((pedido) => pedido.trazas), ["compartir", "compartir"]);
    assert.deepEqual(descartes(s.svc), []);
    assert.equal(guardadoPorElGateway(s.svc.cuerpos).filter((item) => /chat\/completions$/.test(item.url)).length, 2);
  } finally { s.cerrar(); }
});

for (const variable of ["no", "local", null] as const) {
  test(`en «${variable ?? "no"}»${variable === null ? " (sin elegir nada: el modo por defecto)" : ""} el gateway no guarda contenido: no hace falta descartar nada`, async () => {
    const s = await sesion("openai", cuentaDePrueba, { variable });
    try {
      const engine = s.abrir();
      await engine.send("Creá una cuenta de prueba y entrá con ella.");
      await engine.close();
      assert.ok(s.svc.modelo().every((pedido) => pedido.trazas === (variable ?? "no")));
      assert.deepEqual(descartes(s.svc), []);
      assert.deepEqual(guardadoPorElGateway(s.svc.cuerpos), []);
    } finally { s.cerrar(); }
  });
}

test("si el servicio no contesta el descarte, queda anotado y sale después (al cerrar o al volver a abrir el proyecto)", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-descartes-proyecto-"));
  try {
    // Primera sesión: el servicio contesta 503 siempre. El descarte queda pendiente en la base del proyecto.
    const caido = await sesion("openai", cuentaDePrueba, { descartar: () => 503, cwd });
    let pendiente = "";
    try {
      const engine = caido.abrir();
      await engine.send("Creá una cuenta de prueba y entrá con ella.");
      await esperar(() => descartes(caido.svc).length >= 1);
      pendiente = caido.svc.modelo()[0]!.id!;
      assert.deepEqual(engine.descartes.pendientes(), [pendiente]);
      await engine.close();
      assert.ok(descartes(caido.svc).length >= 2, "al cerrar se volvió a intentar");
    } finally { caido.cerrar(); }
    const db = openStore(projectPaths(cwd));
    assert.deepEqual((db.prepare("select pedido, clave from trazas_a_descartar").all() as Array<Record<string, string>>).map((fila) => ({ ...fila })), [{ pedido: pendiente, clave: "OROBAS_API_KEY" }], "en la base, con el nombre de la variable, nunca la clave");
    db.close();
    // Segunda vez, con el servicio de vuelta: sale apenas se abre el proyecto. (La base guardó el servicio de la
    // primera sesión, ya cerrado: para la prueba se apunta al nuevo.)
    const vuelta = await sesion("openai", sinCredenciales, { cwd });
    try {
      const base = `${vuelta.svc.server.address() && `http://127.0.0.1:${(vuelta.svc.server.address() as { port: number }).port}`}/v1`;
      const db2 = openStore(projectPaths(cwd));
      db2.prepare("update trazas_a_descartar set base = ?").run(base);
      db2.close();
      const engine = vuelta.abrir();
      await esperar(() => descartes(vuelta.svc).length >= 1);
      assert.deepEqual(JSON.parse(descartes(vuelta.svc)[0]!.body), { traces: [pendiente] });
      await esperar(() => engine.descartes.pendientes().length === 0);
      assert.deepEqual(engine.descartes.pendientes(), []);
      await engine.close();
    } finally { vuelta.cerrar(); }
  } finally { rmSync(cwd, { recursive: true, force: true }); }
});

/* ---------- El modo por defecto de una instalación que ya existía ---------- */

async function servicioDeCuenta(trazas?: string) {
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ object: "account", name: "Ana", verification: "completa", plan: "profesional", tier_usd: 100, ...(trazas ? { trazas } : {}) })));
  });
  return { base: `${await escuchar(server)}/v1`, cerrar: () => { server.closeAllConnections(); server.close(); } };
}

test("una instalación que ya existía, sin ajuste guardado, arranca en «no»; la cuenta nunca lo amplía", async () => {
  const prev = { trazas: process.env.CYBER_TRAZAS, key: process.env.OROBAS_API_KEY, base: process.env.OROBAS_BASE_URL };
  const config = process.env.CYBER_CONFIG!;
  try {
    delete process.env.CYBER_TRAZAS;
    // La configuración de antes: proveedores e idioma, sin «trazas».
    writeFileSync(config, JSON.stringify({ providers: {}, idioma: "es" }));
    process.env.OROBAS_API_KEY = "oro_prueba";
    for (const [cuenta, rige] of [[undefined, "no"], ["compartir", "no"], ["local", "no"], ["no", "no"]] as const) {
      const svc = await servicioDeCuenta(cuenta);
      try {
        process.env.OROBAS_BASE_URL = svc.base;
        configureAccount();
        await refrescarModoCuenta();
        assert.deepEqual(modoLocal(), { modo: "no", origen: "defecto" });
        assert.equal(modoTrazas(), rige, `cuenta ${cuenta ?? "sin el campo (servicio de hoy)"}`);
      } finally { svc.cerrar(); }
    }
  } finally {
    rmSync(config, { force: true });
    configureAccount();
    for (const [name, value] of [["CYBER_TRAZAS", prev.trazas], ["OROBAS_API_KEY", prev.key], ["OROBAS_BASE_URL", prev.base]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});

test("sin modo elegido rige «no», haya o no consentimientos de versiones anteriores; un modo elegido manda, y no hay aviso de migración", async () => {
  const prevTrazas = process.env.CYBER_TRAZAS;
  const config = process.env.CYBER_CONFIG!;
  const casos: Array<{ nombre: string; registros: Array<[string, string]>; config?: object; rige: string }> = [
    { nombre: "revocó", registros: [["trayectorias-no", "2026-11-10T10:00:00Z"]], rige: "no" },
    { nombre: "revocó y después volvió a compartir (sin elegirlo en la versión nueva)", registros: [["trayectorias-no", "2026-11-01T10:00:00Z"], ["trayectorias", "2026-11-10T10:00:00Z"]], rige: "no" },
    { nombre: "nunca tocó /datos", registros: [], rige: "no" },
    { nombre: "eligió «local»", registros: [["trayectorias-no", "2026-11-10T10:00:00Z"]], config: { trazas: "local" }, rige: "local" },
    { nombre: "eligió «compartir»", registros: [], config: { trazas: "compartir" }, rige: "compartir" },
  ];
  try {
    delete process.env.CYBER_TRAZAS;
    anotarModoCuenta(undefined);
    for (const caso of casos) {
      const cwd = mkdtempSync(join(tmpdir(), "cyber-revoco-"));
      rmSync(config, { force: true });
      if (caso.config) writeFileSync(config, JSON.stringify(caso.config));
      try {
        const db = openStore(projectPaths(cwd));
        new ConsentStore(db); // crea la tabla, como la versión anterior
        for (const [kind, at] of caso.registros) db.prepare("insert or replace into consents(kind,at,hash,pedido) values(?,?,?,?)").run(kind, at, `sha256:${kind}`, "cita");
        db.close();
        const engine = new Engine({ cwd, provider: { model: { provider: "faux", id: "faux", baseUrl: "http://127.0.0.1:9", apiKeyEnv: "" }, transport: async () => { throw new Error("sin modelo"); } } as never, budgetPico: usdToPico("1"), cveFeed: false });
        try {
          assert.equal(modoTrazas(), caso.rige, caso.nombre);
          assert.ok(!engine.notices.some((aviso) => /Habías revocado/.test(aviso)), caso.nombre);
          if (!caso.config) assert.equal(existsSync(config), false, `${caso.nombre}: no escribe la configuración`);
        } finally { await engine.close(); }
      } finally { rmSync(cwd, { recursive: true, force: true }); }
    }
  } finally {
    rmSync(config, { force: true });
    if (prevTrazas === undefined) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = prevTrazas;
  }
});
