import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { BrowserSession, browserPaths } from "../src/browser.ts";
import { CabecerasPrograma, leerCabecera, lineasCabeceras } from "../src/cabeceras-programa.ts";
import { Daemon } from "../src/daemon.ts";
import { HttpClient } from "../src/http.ts";
import { Ledger } from "../src/ledger.ts";
import { anthropicMessages, openAICompletions } from "../src/llm.ts";
import { createOperatorTools } from "../src/operador.ts";
import { avisoDeCabeceras } from "../src/politica-cabeceras.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule, ScopeStore, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { BINARIES, createNetTools } from "../src/toolbox.ts";
import { escanerFalso } from "./secretos-falsos.ts";

test("rechaza credenciales y valores de cabecera peligrosos", () => {
  for (const nombre of ["Authorization", "Cookie", "Proxy-Authorization", "Set-Cookie", "X-Api-Key", "X-Auth", "X-Auth-Token", "Host", "Content-Length", "Content-Type"]) {
    assert.throws(() => leerCabecera(`${nombre}: prueba`), /reservada|credencial/);
  }
  for (const valor of ["Bearer abcdef", "Cookie: sid=prueba", "sessionid=prueba", "sk-proj-" + "a".repeat(25), "abc123456.abc123456.abc123456", "a\r\nX-Otra: mal"]) {
    assert.throws(() => leerCabecera(`X-HackerOne: ${valor}`), /credencial|inválida/);
  }
  assert.deepEqual(leerCabecera("X-HackerOne: lean1ng"), ["X-HackerOne", "lean1ng"]);
});

test("la política importada sólo propone la cabecera", () => {
  assert.match(avisoDeCabeceras("X-HackerOne: <usuario>"), /Propuestas sin aplicar: confirmá con el operador/);
});

test("el CLI acepta --cabecera repetible", () => {
  const corrida = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning", "src/cli.ts", "--cabecera", "X-HackerOne: uno", "--cabecera", "User-Agent: HackerOne/uno", "--help"], {
    encoding: "utf8", timeout: 30_000, env: { ...process.env, OROBAS_BASE_URL: "http://127.0.0.1:9/v1", OROBAS_API_KEY: "" },
  });
  assert.equal(corrida.status, 0, corrida.stderr);
  assert.match(corrida.stdout, /--cabecera/);
});

test("session_settings exige una cita o confirmación concreta y guarda la decisión", async (t) => {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cabeceras-cita-")));
  const db = openStore(paths);
  t.after(() => db.close());
  const cabeceras = new CabecerasPrograma(db);
  const http = new HttpClient(new Artifacts(db, paths.artifacts), () => undefined);
  const textos = ["Configurá X-HackerOne: lean1ng para este programa."];
  const mensajes: Array<{ text: string; asked?: string }> = [];
  const tools = createOperatorTools({ scope: new ScopeStore(db, "s"), ledger: new Ledger(db), http, cabeceras,
    operatorTexts: () => textos, operatorMessages: () => mensajes, h1: () => ({}), report: async () => [] });
  const settings = tools.find((tool) => tool.name === "session_settings")!;
  await assert.rejects(() => settings.execute({ cabeceras: ["X-HackerOne: ajena"], pedido: textos[0] }, new AbortController().signal) as Promise<unknown>, /necesita una cita/);
  assert.deepEqual(cabeceras.listar(), {});
  textos.splice(0, 1, "Configurá X-HackerOne: uno y X-Otra: dos.");
  await assert.rejects(() => settings.execute({ cabeceras: ["X-HackerOne: dos"], pedido: textos[0] }, new AbortController().signal) as Promise<unknown>, /necesita una cita/);
  textos.splice(0, 1, "Configurá X-HackerOne: lean1ng para este programa.");
  const resultado = await settings.execute({ cabeceras: ["X-HackerOne: lean1ng"], pedido: textos[0] }, new AbortController().signal);
  assert.match(resultado.text, /X-HackerOne: lean1ng/);
  assert.deepEqual(cabeceras.listar(), { "X-HackerOne": "lean1ng" });
  textos.splice(0, 1, "sí");
  mensajes.push({ text: "sí", asked: "¿Confirmás X-HackerOne: otro como cabecera fija del programa?" });
  await settings.execute({ cabeceras: ["X-HackerOne: otro"], pedido: "sí" }, new AbortController().signal);
  assert.deepEqual(cabeceras.listar(), { "X-HackerOne": "otro" });
  mensajes.splice(0, 1, { text: "sí", asked: "¿Sigo con la evaluación?" });
  await assert.rejects(() => settings.execute({ cabeceras: ["X-HackerOne: no-autorizado"], pedido: "sí" }, new AbortController().signal) as Promise<unknown>, /no respondía|necesita una cita/);
  assert.deepEqual(cabeceras.listar(), { "X-HackerOne": "otro" });
});

test("una cabecera fija del proyecto no viaja a proveedores de modelos", async (t) => {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cabeceras-modelos-")));
  const db = openStore(paths);
  t.after(() => db.close());
  new CabecerasPrograma(db).poner("X-HackerOne: lean1ng");
  const vistos: Headers[] = [];
  t.mock.method(globalThis, "fetch", async (_url: unknown, init: RequestInit) => {
    vistos.push(new Headers(init.headers));
    return new Response("prueba local", { status: 400 });
  });
  for (const transporte of [openAICompletions, anthropicMessages]) {
    await transporte({ model: { provider: "local", id: "prueba", baseUrl: "http://127.0.0.1:9/v1" },
      system: "Prueba", messages: [{ role: "user", at: 1, content: "hola" }], tools: [] });
  }
  assert.equal(vistos.length, 2);
  for (const cabeceras of vistos) assert.equal(cabeceras.has("X-HackerOne"), false);
});

test("el daemon guarda las cabeceras repetidas y /alcance muestra, agrega y quita", async (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "cabeceras-daemon-"));
  const daemon = new Daemon({ cwd, autoResume: false, resolve: () => resolveProvider("faux"), engine: { cveFeed: false, autoVerify: false } });
  t.after(() => daemon.close());
  const privado = daemon as unknown as {
    open: (pedido: { session: string; cabeceras: string[] }) => unknown;
    handle: (pedido: object, host: unknown, enviar: () => void) => Promise<string[]>;
  };
  assert.throws(() => privado.open({ session: "new", cabeceras: ["X-HackerOne: pasajera", "Authorization: clave"] }), /reservada|credencial/);
  const host = privado.open({ session: "new", cabeceras: ["X-HackerOne: lean1ng", "User-Agent: HackerOne/lean1ng"] });
  const enviar = () => {};
  const vistaInicial = (await privado.handle({ op: "view", name: "scope", arg: "" }, host, enviar)).join("\n");
  assert.match(vistaInicial, /X-HackerOne: lean1ng/);
  assert.doesNotMatch(vistaInicial, /pasajera/);
  await privado.handle({ op: "view", name: "scope", arg: "cabecera X-HackerOne: nuevo" }, host, enviar);
  assert.match((await privado.handle({ op: "view", name: "scope", arg: "" }, host, enviar)).join("\n"), /X-HackerOne: nuevo/);
  await privado.handle({ op: "view", name: "scope", arg: "cabecera quitar X-HackerOne" }, host, enviar);
  assert.doesNotMatch((await privado.handle({ op: "view", name: "scope", arg: "" }, host, enviar)).join("\n"), /X-HackerOne:/);
});

test("persiste por proyecto, identifica HTTP y navegador, y no sale del alcance", async (t) => {
  const vistos: Array<Record<string, string | string[] | undefined>> = [];
  const ajenos: string[] = [];
  const externo = createServer((req, res) => { ajenos.push(String(req.headers["x-hackerone"] ?? "")); res.end("fuera"); });
  await new Promise<void>((resolve) => externo.listen(0, "127.0.0.1", resolve));
  t.after(() => { externo.closeAllConnections(); externo.close(); });
  const origenExterno = `http://127.0.0.1:${(externo.address() as { port: number }).port}`;
  const servidor = createServer((req, res) => {
    vistos.push(req.headers);
    if (req.url === "/redir") { res.writeHead(302, { location: origenExterno }); res.end(); }
    else res.end("bien");
  });
  await new Promise<void>((resolve) => servidor.listen(0, "127.0.0.1", resolve));
  t.after(() => { servidor.closeAllConnections(); servidor.close(); });
  const base = `http://127.0.0.1:${(servidor.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cabeceras-proyecto-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  t.after(() => db.close());
  const fijas = new CabecerasPrograma(db);
  fijas.poner("X-HackerOne: lean1ng");
  fijas.poner("User-Agent: HackerOne/lean1ng");
  const reabierta = openStore(paths);
  assert.deepEqual(new CabecerasPrograma(reabierta).listar(), fijas.listar());
  reabierta.close();
  const otroProyecto = openStore(projectPaths(mkdtempSync(join(tmpdir(), "cabeceras-otro-proyecto-"))));
  assert.deepEqual(new CabecerasPrograma(otroProyecto).listar(), {});
  otroProyecto.close();
  const scope: Scope = { rev: 1, at: "", source: "hackerone:prueba", notes: "", include: [parseRule(base)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, paths.artifacts), () => scope);
  http.cabecerasPrograma = () => fijas.listar();
  http.userAgent = "agente-anterior";
  http.setIdentity({ name: "investigadora", headers: { Cookie: "sid=prueba", "X-HackerOne": "lean1ng" } });
  assert.equal(http.conduct().userAgent, "HackerOne/lean1ng");
  const primera = await http.send({ url: `${base}/normal`, headers: { "X-HackerOne": "otro" } }, "investigadora");
  assert.equal(primera.request.headers["x-hackerone"], "lean1ng");
  assert.equal(primera.request.headers.cookie, "<identidad investigadora>");
  const navegador = await http.forward({ url: `${base}/navegador`, headers: { "user-agent": "Chromium" } });
  assert.equal(navegador.exchange.request.headers["x-hackerone"], "lean1ng");
  assert.equal(vistos.length, 2);
  for (const cabeceras of vistos) {
    assert.equal(cabeceras["x-hackerone"], "lean1ng");
    assert.equal(cabeceras["user-agent"], "HackerOne/lean1ng");
  }
  assert.equal(vistos[0]!.cookie, "sid=prueba");
  assert.equal(vistos[1]!.cookie, undefined);
  const sonda = createNetTools({ artifacts: http.artifacts, http, scope: () => scope }).find((tool) => tool.name === "http_probe")!;
  await sonda.execute({ urls: [`${base}/sonda`] }, new AbortController().signal);
  assert.equal(vistos[2]!["x-hackerone"], "lean1ng");
  await http.send({ url: `${base}/sin-identidad`, omitHeaders: ["Cookie", "X-HackerOne", "User-Agent"] }, "investigadora");
  assert.equal(vistos[3]!["x-hackerone"], "lean1ng");
  assert.equal(vistos[3]!["user-agent"], "HackerOne/lean1ng");
  assert.equal(vistos[3]!.cookie, undefined);
  const fuera = await http.send({ url: "http://127.0.0.1:9/fuera" });
  assert.match(fuera.error ?? "", /Fuera del alcance/);
  const redir = await http.send({ url: `${base}/redir`, followRedirects: true });
  assert.equal(redir.notFollowed, `${origenExterno}/`);
  assert.deepEqual(ajenos, []);
  assert.match(lineasCabeceras(fijas.listar()).join("\n"), /X-HackerOne: lean1ng/);
});

const navegadorDisponible = Object.values(browserPaths()).every((ruta) => existsSync(ruta));
test("el navegador propio manda cabeceras fijas en una navegación real", { skip: !navegadorDisponible }, async (t) => {
  const vistos: string[] = [];
  const servidor = createServer((req, res) => {
    vistos.push(String(req.headers["x-hackerone"] ?? ""));
    res.setHeader("content-type", "text/html");
    res.end("<html><title>Prueba</title><body>Bien</body></html>");
  });
  await new Promise<void>((resolve) => servidor.listen(0, "127.0.0.1", resolve));
  t.after(() => { servidor.closeAllConnections(); servidor.close(); });
  const base = `http://127.0.0.1:${(servidor.address() as { port: number }).port}`;
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cabeceras-navegador-")));
  const db = openStore(paths);
  t.after(() => db.close());
  const fijas = new CabecerasPrograma(db);
  fijas.poner("X-HackerOne: lean1ng");
  const scope: Scope = { rev: 1, at: "", source: "manual", notes: "", include: [parseRule(base)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, paths.artifacts), () => scope);
  http.cabecerasPrograma = () => fijas.listar();
  const browser = new BrowserSession(http);
  try {
    await browser.open(`${base}/pagina`);
    assert.ok(vistos.length > 0);
    assert.ok(vistos.every((valor) => valor === "lean1ng"), JSON.stringify(vistos));
  } finally { await browser.close(); }
});

test("ffuf, sqlmap, httpx, nuclei y katana llevan la cabecera fija al objetivo; nmap avisa su límite", async (t) => {
  const vistos: string[] = [];
  const servidor = createServer((req, res) => { vistos.push(String(req.headers["x-hackerone"] ?? "")); res.end("bien"); });
  await new Promise<void>((resolve) => servidor.listen(0, "127.0.0.1", resolve));
  t.after(() => { servidor.closeAllConnections(); servidor.close(); });
  const base = `http://127.0.0.1:${(servidor.address() as { port: number }).port}`;
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cabeceras-scan-")));
  const db = openStore(paths);
  t.after(() => db.close());
  const fijas = new CabecerasPrograma(db);
  fijas.poner("X-HackerOne: lean1ng");
  const scope: Scope = { rev: 1, at: "", source: "manual", notes: "", include: [parseRule(base)], exclude: [] };
  const artifacts = new Artifacts(db, paths.artifacts);
  const http = new HttpClient(artifacts, () => scope);
  http.cabecerasPrograma = () => fijas.listar();
  const registro = join(paths.root, "escaneres.jsonl");
  writeFileSync(registro, "");
  const nombres = ["ffuf", "sqlmap", "httpx", "nuclei", "katana"] as const;
  const anteriores = Object.fromEntries(nombres.map((nombre) => [nombre, BINARIES[nombre]!.binary]));
  for (const nombre of nombres) BINARIES[nombre]!.binary = escanerFalso(nombre, registro);
  t.after(() => { for (const nombre of nombres) BINARIES[nombre]!.binary = anteriores[nombre]!; });
  const herramientas = Object.fromEntries(createNetTools({ artifacts, http, scope: () => scope }).map((item) => [item.name, item]));
  const señal = new AbortController().signal;
  for (const [nombre, args] of [
    ["ffuf_fuzz", { url: `${base}/FUZZ`, words: ["ruta"], headers: ["X-HackerOne: equivocado"] }],
    ["sqlmap_scan", { url: `${base}/buscar?q=1` }],
    ["httpx_probe", { targets: [base] }],
    ["nuclei_scan", { targets: [base] }],
    ["katana_crawl", { url: `${base}/` }],
  ] as const) await herramientas[nombre]!.execute(args, señal);
  const corridas = readFileSync(registro, "utf8").trim().split("\n").map((linea) => JSON.parse(linea) as { escaner: string; argv: string[] });
  assert.equal(corridas.length, 5);
  for (const corrida of corridas) assert.ok(corrida.argv.includes("X-HackerOne: lean1ng"), corrida.escaner);
  assert.ok(!corridas[0]!.argv.includes("X-HackerOne: equivocado"));
  assert.ok(corridas.find((corrida) => corrida.escaner === "sqlmap")!.argv.includes("--ignore-redirects"));
  assert.ok(corridas.find((corrida) => corrida.escaner === "nuclei")!.argv.includes("-disable-redirects"));
  assert.ok(!corridas.find((corrida) => corrida.escaner === "nuclei")!.argv.includes("-no-interactsh"));
  const katana = corridas.find((corrida) => corrida.escaner === "katana")!.argv;
  assert.ok(katana.includes("-disable-redirects"));
  assert.match(katana[katana.indexOf("-crawl-scope") + 1]!, /127\\\.0\\\.0\\\.1/);
  assert.deepEqual(vistos, Array(5).fill("lean1ng"));
  await assert.rejects(() => herramientas.nmap_scan!.execute({ targets: [base] }, señal) as Promise<unknown>, /no puede garantizar cabeceras fijas/);
  // Sin cabeceras fijas, los escáneres siguen como en main: redirecciones, rastreo del host e interactsh.
  fijas.quitar("X-HackerOne");
  writeFileSync(registro, "");
  for (const [nombre, args] of [["sqlmap_scan", { url: `${base}/buscar?q=1` }], ["nuclei_scan", { targets: [base] }], ["katana_crawl", { url: `${base}/` }]] as const) await herramientas[nombre]!.execute(args, señal);
  const libres = readFileSync(registro, "utf8").trim().split("\n").map((linea) => JSON.parse(linea) as { escaner: string; argv: string[] });
  for (const corrida of libres) for (const flag of ["--ignore-redirects", "-disable-redirects", "-crawl-scope", "-no-interactsh"]) assert.ok(!corrida.argv.includes(flag), `${corrida.escaner} ${flag}`);
});
