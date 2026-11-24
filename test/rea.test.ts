import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { createHarTools } from "../src/importers/har.ts";
import { McpManager } from "../src/mcp.ts";
import { resolveProvider } from "../src/providers.ts";
import { EXTRACTO, ProxyAlcance, REA, reaBloqueo, reaRevisar, reaStatus } from "../src/rea.ts";
import { toolboxView } from "../src/daemon.ts";
import { fromLines, findCommand } from "../src/tui/comandos.ts";
import { Registro } from "../src/tui/entradas.ts";
import { dibujar, dibujarPanel, PESTANA_CHAT, type Pestana } from "../src/tui/pestanas.ts";
import { stripAnsi, truncate, visibleWidth } from "../src/tui/text.ts";
import { fakeIO } from "./fake-io.ts";

// Un REA falso: mismos nombres de herramientas que rea-agents 6.8.0 (algunas fuera de la política) y un
// registro de todo lo que le llega, para comprobar que lo rechazado nunca sale del harness.
const FALSO = String.raw`
import { appendFileSync } from "node:fs";
import { connect } from "node:net";
import { createInterface } from "node:readline";
// Como el Chromium de REA: lo de terceros que carga la página sale por el proxy de alcance.
const viaProxy = (target) => new Promise((done) => {
  const proxy = new URL(process.env.CYBER_REA_PROXY);
  const socket = connect(Number(proxy.port), proxy.hostname, () => socket.write("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"));
  let data = "";
  socket.on("data", (chunk) => { data += chunk; socket.end(); });
  socket.on("close", () => done(data.split("\r\n")[0]));
  socket.on("error", () => done("error"));
});
const audit = process.env.REA_FALSO_AUDIT;
const send = (message) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
const tool = (name) => ({ name, description: "Herramienta de REA " + name + ". ".repeat(400), inputSchema: { type: "object", properties: { path: { type: "string" } } } });
const NOMBRES = ["analyze_javascript_application", "export_environment_bundle", "capture_browser_scenario", "inspect_web_network_capture", "open_binary", "inspect_artifact", "inspect_analysis_view", "binary_session", "inspect_apk_signature", "execute_rizin_command", "start_frida_session"];
for await (const line of createInterface({ input: process.stdin })) {
  const m = JSON.parse(line);
  if (audit) appendFileSync(audit, JSON.stringify({ ...m, cwd: process.cwd(), entorno: Object.keys(process.env) }) + "\n");
  if (m.method === "initialize") send({ id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "rea", version: "6.8.0" } } });
  else if (m.method === "tools/list") send({ id: m.id, result: { tools: NOMBRES.map(tool) } });
  else if (m.method === "tools/call") {
    const { name, arguments: args } = m.params;
    if (args.falla) { send({ id: m.id, result: { isError: true, content: [{ type: "text", text: JSON.stringify({ error: { code: "provider_unavailable", message: "Falta el motor", remediation: { action: "Instalar Ghidra" } } }) }] } }); continue; }
    if (name === "capture_browser_scenario") args.proxy = await viaProxy("tracker.terceros.test:443");
    const grande = name === "analyze_javascript_application";
    const evidence = { evidence_id: "ev-hijo-1", normalized_result: { parent_evidence_id: "ev-padre-7" }, recibido: args, cwd: process.cwd(), ...(grande || args.conClave ? { clave: "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" } : {}), ...(grande ? { relleno: "módulo ".repeat(9000) } : {}) };
    send({ id: m.id, result: { content: [{ type: "text", text: JSON.stringify(evidence) }] } });
  }
}
`;

function laboratorio() {
  const root = mkdtempSync(join(tmpdir(), "cyber-rea-"));
  const cwd = join(root, "proyecto");
  mkdirSync(join(cwd, "app", ".output", "server"), { recursive: true });
  writeFileSync(join(cwd, "app", ".output", "server", "index.mjs"), "export default 1;\n");
  writeFileSync(join(cwd, "captura.har"), JSON.stringify({ log: { version: "1.2", entries: [{ request: { url: "https://app.tienda.test/api/me", method: "GET", headers: [] } }] } }));
  mkdirSync(join(root, "afuera"));
  writeFileSync(join(root, "afuera", "secreto.txt"), "no");
  symlinkSync(join(root, "afuera"), join(cwd, "atajo"));
  mkdirSync(join(cwd, ".cyber"), { recursive: true });
  const server = join(root, "rea-falso.mjs");
  const audit = join(root, "audit.jsonl");
  writeFileSync(server, FALSO);
  writeFileSync(audit, "");
  const records = () => readFileSync(audit, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
  return { root, cwd, server: { command: process.execPath, args: [server], env: { REA_FALSO_AUDIT: audit } }, records, calls: () => records().filter((item) => item.method === "tools/call"), clean: () => rmSync(root, { recursive: true, force: true }) };
}

const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const signal = new AbortController().signal;

test("REA: versión fija con integridad, el lock propio y la imagen que lo instala con npm ci", () => {
  const lock = JSON.parse(readFileSync(join(import.meta.dirname, "..", "distro", "rea", "package-lock.json"), "utf8"));
  const rea = lock.packages["node_modules/rea-agents"];
  assert.equal(rea.version, REA.version);
  assert.equal(rea.integrity, REA.integridad);
  assert.equal(lock.packages[""].dependencies["rea-agents"], REA.version, "versión exacta, sin rango");
  for (const [name, entry] of Object.entries(lock.packages as Record<string, { integrity?: string; resolved?: string }>)) {
    if (!name) continue;
    assert.match(entry.integrity ?? "", /^sha512-/, name);
    assert.ok(entry.resolved?.startsWith("https://registry.npmjs.org/"), name);
  }
  const docker = readFileSync(join(import.meta.dirname, "..", "distro", "Dockerfile"), "utf8");
  assert.ok(docker.includes("COPY distro/rea/package.json distro/rea/package-lock.json /opt/rea/"));
  assert.match(docker, /npm ci --omit=dev --ignore-scripts/);
  assert.ok(docker.includes(REA.integridad), "la imagen comprueba el sha512 publicado");
  assert.ok(docker.includes(`p.version!=="${REA.version}"`));
  assert.ok(docker.includes(REA.chromium) && docker.includes("--no-sandbox"));
  // El envoltorio de Chromium sale por el proxy de alcance y sin él no arranca (se prueba con echo en vez de Chromium).
  const wrapper = /printf '(#!\/bin\/sh\\n# Chromium de REA[^']*)' > \/usr\/local\/bin\/chromium-rea/.exec(docker)![1]!;
  const dir = mkdtempSync(join(tmpdir(), "cyber-rea-wrapper-"));
  try {
    const script = join(dir, "chromium-rea");
    execFileSync("sh", ["-c", `printf '${wrapper.replace("/usr/bin/chromium", "/bin/echo")}' > "$1"; chmod +x "$1"`, "sh", script]);
    assert.throws(() => execFileSync(script, ["--headless"], { env: { PATH: "/usr/bin:/bin" }, stdio: "pipe" }), /falta CYBER_REA_PROXY/);
    const argv = execFileSync(script, ["--headless"], { env: { PATH: "/usr/bin:/bin", CYBER_REA_PROXY: "http://127.0.0.1:9" } }).toString().trim();
    assert.equal(argv, "--no-sandbox --disable-dev-shm-usage --proxy-server=http://127.0.0.1:9 --proxy-bypass-list=<-loopback> --headless");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  assert.match(docker, /fonts-liberation procps/, "REA necesita ps");
  assert.ok(REA.entrada.startsWith(`${REA.raiz}/node_modules/rea-agents/`));
});

test("REA: fuera de la caja no se ofrece, ni el incorporado ni uno registrado a mano", async () => {
  const lab = laboratorio();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: lab.cwd, provider, autoVerify: false, rea: { enCaja: false, server: lab.server }, mcp: { rea: lab.server, propio: { command: "npx", args: ["-y", "rea-agents@6.8.0", "mcp"] } } });
  try {
    assert.deepEqual(engine.mcp.names(), []);
    assert.ok(![...engine.catalog.available.keys()].some((name) => name.startsWith("rea.")));
    assert.doesNotMatch(engine.catalog.summary(), /ingeniería inversa|MCP local/);
    const status = engine.mcp.status();
    assert.ok(status.every((row) => row.state === "bloqueado" && /sólo dentro de la caja|only runs inside the Orobas box/.test(row.error ?? "")), JSON.stringify(status));
    await assert.rejects(engine.mcp.tools("rea", signal), /caja|box/);
    assert.throws(() => engine.mcp.add("otro", { command: "/usr/bin/rea", args: ["mcp"] }), /caja|box/);
    assert.deepEqual(Object.keys(engine.mcp.all()).sort(), ["propio", "rea"], "la configuración del operador no se pierde al guardar");
    // La habilidad se ve igual: dice cómo seguir sin REA.
    assert.match(engine.agent.system, /ingenieria-inversa — Salir de la caja negra/);
    provider.faux!.queue = [call("skill_load", { name: "ingenieria-inversa" }), call("tools_load", { names: ["rea.open_binary"] }), { text: "Listo." }];
    await engine.send("Mirá el build");
    const replies = engine.agent.messages.filter((message) => message.role === "tool");
    const skill = String(replies.find((message) => message.name === "skill_load")!.content);
    assert.match(skill, /Herramientas cargadas: web_source_pull, code_crypto, hash_crack, code_search, code_read, reference_read, apk_analyze, har_import/);
    assert.match(skill, /REA \(rea\.\*\) corre sólo dentro de la caja/);
    assert.match(String(replies.find((message) => message.name === "tools_load")!.content), /No existen: rea\.open_binary\. REA \(rea\.\*\) corre sólo dentro de la caja/);
    assert.equal(lab.records().length, 0, "nunca se arrancó nada");
    assert.match(reaStatus({ enCaja: false }).join("\n"), /^rea {8}· (sólo en la caja|box only)/);
    assert.equal(reaBloqueo("vulndb", { command: "vulndb", args: ["mcp"] }, false), undefined, "otros servidores siguen como antes");
  } finally {
    await engine.close();
    lab.clean();
  }
});

test("REA: en la caja se registra incorporado, en su grupo, y arranca recién al primer uso", async () => {
  const lab = laboratorio();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: lab.cwd, provider, autoVerify: false, rea: { enCaja: true, server: lab.server }, mcp: { rea: { command: "npx", args: ["rea-agents"] } } });
  try {
    assert.deepEqual(engine.mcp.names(), ["rea"]);
    assert.ok(engine.catalog.available.has("rea.analyze_javascript_application"));
    assert.ok(!engine.catalog.loaded().some((name) => name.startsWith("rea.")), "por demanda, no en el núcleo");
    assert.match(engine.catalog.summary(), /^ingeniería inversa: rea\.analyze_javascript_application \(REA · (app JavaScript|JavaScript app)\)/m);
    assert.match(engine.catalog.summary(), /^rea: \d+ herramientas más \(tool_search rea\)\.$/m);
    assert.match(engine.agent.system, /habilidad ingenieria-inversa: en la caja corrés REA/);
    assert.ok(engine.mcp.status().some((row) => row.name === "rea" && row.state === "tapado por el incorporado"), "la entrada del operador con el mismo nombre queda tapada");
    assert.equal(lab.records().length, 0, "crear la sesión no arranca REA");
    provider.faux!.queue = [call("tool_search", { query: "javascript empaquetada" }), { text: "Ya vi." }];
    await engine.send("¿Qué hay para JS compilado?");
    const search = String(engine.agent.messages.filter((message) => message.role === "tool").at(-1)!.content);
    assert.match(search, /^rea\.analyze_javascript_application — Reconstruye/m);
    assert.equal(lab.records().length, 0, "buscar tampoco lo arranca");
    provider.faux!.queue = [call("tools_load", { names: ["rea.analyze_javascript_application", "rea.execute_rizin_command"] }), call("rea.analyze_javascript_application", { input_path: "app/.output" }), { text: "Listo." }];
    await engine.send("Analizá el build de Nuxt");
    const replies = engine.agent.messages.filter((message) => message.role === "tool");
    const loaded = String(replies.find((message) => message.name === "tools_load")!.content);
    assert.match(loaded, /Cargadas: rea\.analyze_javascript_application\./);
    assert.match(loaded, /No existen: rea\.execute_rizin_command/, "lo que la política no ofrece no se carga");
    assert.match(loaded, /Del servidor: Herramienta de REA/);
    assert.deepEqual(lab.records().slice(0, 3).map((item) => item.method), ["initialize", "notifications/initialized", "tools/list"]);
    const first = lab.records()[0]!;
    assert.equal(first.cwd, realpathSync(lab.cwd), "corre en la carpeta del proyecto");
    for (const name of ["CYBER_SECRETS_KEY", "OROBAS_API_KEY", "CYBER_DATA_DIR", "CYBER_CONFIG"]) assert.ok(!first.entorno.includes(name), `no hereda ${name}`);
    assert.ok(first.entorno.includes("PATH") && first.entorno.includes("REA_FALSO_AUDIT"));
    assert.ok(first.entorno.includes("CYBER_REA_PROXY"), "el Chromium de REA sale por el proxy de alcance");
    assert.equal(lab.calls()[0]!.params.arguments.input_path, join(realpathSync(lab.cwd), "app", ".output"), "la ruta relativa llega absoluta y real");
    assert.match(engine.mcp.status().find((row) => row.name === "rea" && row.command.startsWith("REA"))!.command, /REA 6\.8\.0 · (incorporado en la caja|built into the box) .*· (2 herramientas suyas fuera de la política|2 of its tools outside the policy)/);
    assert.ok(![...engine.catalog.available.keys()].includes("rea.start_frida_session"));
  } finally {
    await engine.close();
    lab.clean();
  }
});

test("REA: rutas fuera del proyecto y URLs fuera del alcance se rechazan sin llegar al servidor", async () => {
  const lab = laboratorio();
  const engine = new Engine({ cwd: lab.cwd, provider: resolveProvider("faux"), autoVerify: false, rea: { enCaja: true, server: lab.server } });
  try {
    engine.scope.edit({ include: ["*.tienda.test"] });
    const tools = new Map((await engine.mcp.tools("rea", signal)).map((tool) => [tool.name.slice(4), tool]));
    const run = async (name: string, args: object) => tools.get(name)!.execute(args, signal);
    for (const bad of ["/etc", "../afuera", "atajo", "atajo/secreto.txt", ".cyber", "~/x", `file://${join(lab.root, "afuera")}`]) {
      await assert.rejects(run("analyze_javascript_application", { input_path: bad }), /fuera de la carpeta del proyecto|\.cyber/, bad);
    }
    await assert.rejects(run("export_environment_bundle", { source: { kind: "retained-evidence", evidence_id: "ev-1" }, output_directory: join(lab.root, "afuera", "env") }), /fuera de la carpeta del proyecto/);
    await assert.rejects(run("export_environment_bundle", { source: { kind: "evidence-file", path: "/etc/passwd" }, output_directory: "env" }), /source\.path|fuera de la carpeta/);
    await assert.rejects(run("export_environment_bundle", { source: { kind: "retained-evidence", evidence_id: "ev-1" }, output_directory: "no-existe/env" }), /No existe/);
    const web = (extra: object) => run("capture_browser_scenario", { start_url: { url: "https://app.tienda.test/" }, actions: [], ...extra });
    await assert.rejects(run("capture_browser_scenario", { start_url: { url: "https://otro.test/" }, actions: [] }), /Fuera del alcance de esta sesión: https:\/\/otro\.test\//);
    await assert.rejects(web({ actions: [{ action: "goto", destination: { url: "https://evil.test/x" } }] }), /Fuera del alcance/);
    await assert.rejects(web({ actions: [{ action: "request", method: "POST", path: "/api/x" }] }), /sólo GET o HEAD/);
    await assert.rejects(web({ secrets: [{ secret_id: "pw", environment_variable: "AWS_SECRET_ACCESS_KEY" }] }), /sin las variables de entorno/);
    await assert.rejects(web({ browser: { mode: "connect", cdp_endpoint: "http://127.0.0.1:9222", target_id: "x" } }), /no se conecta a otro navegador/);
    await assert.rejects(web({ start_url: { url: "javascript:alert(1)" } }), /http\(s\)/);
    assert.equal(lab.calls().length, 0, "nada rechazado llegó a REA");
    assert.throws(() => reaRevisar({ cwd: lab.cwd, scope: () => undefined, artifacts: engine.artifacts }, "execute_rizin_command", { path: "x" }), /no está habilitada en Orobas/);
    // Lo que sí pasa llega reescrito: rutas absolutas y reales, el Chromium de la caja, HAR con su formato.
    await run("export_environment_bundle", { source: { kind: "retained-evidence", evidence_id: "ev-1" }, output_directory: "env-tienda" });
    const recorded = await run("capture_browser_scenario", { start_url: { url: "https://app.tienda.test/" }, actions: [{ action: "request", method: "GET", path: "/api/me" }], browser: { mode: "launch", executable_path: "/bin/sh" } });
    assert.match(recorded.text, /El proxy de alcance cortó conexiones del navegador de REA a hosts fuera del alcance: tracker\.terceros\.test \(1\)\./);
    await run("inspect_web_network_capture", { capture_path: "captura.har" });
    const [env, scenario, har] = lab.calls().map((item) => item.params.arguments);
    assert.equal(env.output_directory, join(realpathSync(lab.cwd), "env-tienda"));
    assert.deepEqual(scenario.browser, { mode: "launch", executable_path: REA.chromium, headless: true });
    assert.equal(scenario.secrets, undefined);
    assert.deepEqual(har, { capture_path: join(realpathSync(lab.cwd), "captura.har"), format: "har" });
  } finally {
    await engine.close();
    lab.clean();
  }
});

// Decisión de Lean del 22/11: lo que REA saca de un artefacto del objetivo (una app, un binario) en una carpeta por
// programa es material del objetivo y llega entero (una clave filtrada es un hallazgo). La captura HAR (la
// navegación del operador) y todo lo que se lee si el proyecto es su carpeta personal siguen tapados por formato.
test("REA: la salida queda entera en un artefacto y al modelo le llega un extracto con la evidencia; lo del objetivo, con sus claves", async () => {
  const lab = laboratorio();
  const engine = new Engine({ cwd: lab.cwd, provider: resolveProvider("faux"), autoVerify: false, rea: { enCaja: true, server: lab.server } });
  const casa = process.env.CYBER_HOME_HOST;
  try {
    const tools = new Map((await engine.mcp.tools("rea", signal)).map((tool) => [tool.name.slice(4), tool]));
    const result = await tools.get("analyze_javascript_application")!.execute({ input_path: "app/.output" }, signal);
    assert.ok(result.text.length < EXTRACTO + 900, `extracto acotado: ${result.text.length}`);
    assert.match(result.text, /^REA analyze_javascript_application: listo · evidencia ev-hijo-1, ev-padre-7 · completo en sha256:[a-f0-9]{64} \(\d+ caracteres\)\./);
    assert.match(result.text, /Extracto \(3000 de \d+ caracteres/);
    assert.match(result.text, /deep_reason con artifacts/);
    assert.match(result.text, /ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8/, "la clave filtrada en la app llega al modelo");
    assert.equal(result.procedencia, "objetivo");
    const full = engine.artifacts.read(String(result.details!.artefacto)).toString();
    assert.ok(full.length > 60_000 && full.includes("módulo módulo") && full.includes("ghp_A1b2"));
    assert.deepEqual(Object.keys(result.details!), ["evidencia", "artefacto"], "sin copia aparte: no había nada del operador");
    // La captura HAR es la navegación del operador: tapada por formato, con el crudo aparte para él.
    const har = await tools.get("inspect_web_network_capture")!.execute({ capture_path: "captura.har", conClave: true }, signal);
    assert.doesNotMatch(har.text, /ghp_A1b2/);
    assert.equal(har.procedencia, "local");
    assert.ok(engine.artifacts.read(String(har.details!.secretos)).toString().includes("ghp_A1b2"), "el crudo queda aparte para el operador");
    // Si la carpeta del proyecto es la carpeta personal del operador, lo que lee REA es suyo.
    process.env.CYBER_HOME_HOST = lab.cwd;
    const enCasa = await tools.get("open_binary")!.execute({ path: "captura.har", conClave: true }, signal);
    assert.doesNotMatch(enCasa.text, /ghp_A1b2/);
    assert.equal(enCasa.procedencia, "local");
    if (casa === undefined) delete process.env.CYBER_HOME_HOST; else process.env.CYBER_HOME_HOST = casa;
    const failed = await tools.get("open_binary")!.execute({ path: "captura.har", falla: true }, signal);
    assert.equal(failed.isError, true);
    assert.match(failed.text, /^Falló: provider_unavailable: Falta el motor · Remedio: Instalar Ghidra\nREA open_binary: error · /);
    const events = engine.db.prepare("select payload from events where type='rea.llamada'").all() as Array<{ payload: string }>;
    assert.equal(events.length, 4);
  } finally {
    if (casa === undefined) delete process.env.CYBER_HOME_HOST; else process.env.CYBER_HOME_HOST = casa;
    await engine.close();
    lab.clean();
  }
});

test("REA: la habilidad carga REA en la caja; retomar no lo arranca hasta que se usa", async () => {
  const lab = laboratorio();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: lab.cwd, provider, autoVerify: false, rea: { enCaja: true, server: lab.server } });
  let resumed: Engine | undefined;
  try {
    provider.faux!.queue = [call("skill_load", { name: "ingenieria-inversa" }), { text: "Leída." }];
    await engine.send("Hay un APK y un build de Nuxt");
    const skill = String(engine.agent.messages.filter((message) => message.role === "tool").at(-1)!.content);
    assert.match(skill, /^# Habilidad ingenieria-inversa/);
    assert.match(skill, /Herramientas cargadas: web_source_pull, code_crypto, hash_crack, code_search, code_read, reference_read, rea\.analyze_javascript_application, rea\.inspect_analysis_view, rea\.open_binary/);
    assert.match(skill, /deep_reason/);
    assert.ok(engine.agent.tools.some((tool) => tool.name === "rea.inspect_web_network_capture"));
    const session = engine.sessionId;
    await engine.close();
    const before = lab.records().length;
    const next = resolveProvider("faux");
    resumed = new Engine({ cwd: lab.cwd, provider: next, autoVerify: false, rea: { enCaja: true, server: lab.server }, resume: session });
    next.faux!.queue = [{ text: "Sigo." }];
    await resumed.send("¿Seguimos?");
    assert.equal(lab.records().length, before, "retomar con REA cargado no lo arranca");
    assert.ok(resumed.agent.tools.some((tool) => tool.name === "rea.open_binary"));
    next.faux!.queue = [call("rea.open_binary", { path: "captura.har" }), { text: "Abierto." }];
    await resumed.send("Abrilo");
    const opened = String(resumed.agent.messages.filter((message) => message.role === "tool").at(-1)!.content);
    assert.match(opened, /^REA open_binary: listo/);
    assert.equal(lab.calls().at(-1)!.params.arguments.path, join(realpathSync(lab.cwd), "captura.har"));
  } finally {
    await resumed?.close();
    await engine.close();
    lab.clean();
  }
});

test("REA: har_import sugiere seguir con REA sólo si está", async () => {
  const lab = laboratorio();
  const engine = new Engine({ cwd: lab.cwd, provider: resolveProvider("faux"), autoVerify: false, rea: false });
  try {
    const har = (rea: boolean) => createHarTools({ artifacts: engine.artifacts, http: engine.http, cwd: lab.cwd, rea: () => rea })[0]!.execute({ path: "captura.har" }, signal) as { text: string };
    assert.match(har(true).text, /rea\.inspect_web_network_capture con capture_path «captura\.har»/);
    assert.doesNotMatch(har(false).text, /con REA/);
  } finally {
    await engine.close();
    lab.clean();
  }
});

test("REA: un servidor del operador no se registra con el nombre del incorporado", () => {
  const manager = new McpManager({}, { incorporados: { rea: { config: { command: "x" }, resumen: "REA", oferta: [], revisar: (_tool, args) => args, salida: () => ({ text: "" }) } } });
  assert.throws(() => manager.add("rea", { command: "otro" }), /viene incorporado/);
  return assert.rejects(manager.remove("rea"), /no se quita/);
});

test("pantalla: REA en /herramientas a 80 columnas, con versión en la caja y «sólo en la caja» afuera", async () => {
  for (const [lines, expected] of [[reaStatus({ enCaja: false }), /rea {8}· (sólo en la caja|box only)/], [reaStatus({ enCaja: true, instalado: true }), /rea {8}✓ rea-agents 6\.8\.0 · (arranca al primer uso|starts on first use)/], [reaStatus({ enCaja: true, instalado: false }), /rea {8}✗ (falta en esta imagen|missing from this image) · cyber --actualizar/]] as Array<[string[], RegExp]>) {
    const view = toolboxView(lines, ["nmap       ✓ /usr/bin/nmap"]);
    // /herramientas abre su menú: la primera opción es «Qué hay instalado».
    const { io } = fakeIO({ toolbox: view }, [0]);
    const panel = (await findCommand("herramientas")!.run(io, ""))!;
    const rows = dibujarPanel(panel, 80).map(stripAnsi);
    const screen = rows.join("\n");
    assert.match(screen, expected);
    assert.match(screen, /INGENIERÍA INVERSA \(habilidad ingenieria-inversa\)|REVERSE ENGINEERING \(ingenieria-inversa skill\)/);
    for (const row of rows) assert.ok(visibleWidth(row) <= 80, `más de 80 columnas: «${row}»`);
    // Las líneas de REA entran sin cortarse en el panel de 80.
    for (const line of lines) assert.ok(visibleWidth(line) <= 80 - 8, line);
  }
  assert.equal(fromLines("x", reaStatus({ enCaja: false })).lines.length, 1);
});

test("pantalla: una llamada larga a REA se ve como las demás acciones, sin volcar la salida", async () => {
  const lab = laboratorio();
  const engine = new Engine({ cwd: lab.cwd, provider: resolveProvider("faux"), autoVerify: false, rea: { enCaja: true, server: lab.server } });
  try {
    const tools = await engine.mcp.tools("rea", signal);
    const registro = new Registro(() => 0);
    const texts = new Map<string, string>();
    const runs: Array<[string, object]> = [["rea.analyze_javascript_application", { input_path: "app/.output" }], ["rea.inspect_artifact", {}], ["rea.open_binary", { path: "captura.har" }], ["rea.open_binary", { path: "captura.har", falla: true }]];
    for (const [index, [name, args]] of runs.entries()) {
      const tool = tools.find((item) => item.name === name)!;
      const result = await tool.execute(args, signal);
      texts.set(`c${index}`, result.text);
      registro.evento({ type: "tool_start", id: `c${index}`, name: tool.name, label: tool.label } as never);
      registro.evento({ type: "tool_end", id: `c${index}`, name: tool.name, isError: result.isError === true, text: result.text, details: result.details ?? {} } as never);
    }
    // Lo que ve la pantalla: cada fila recortada al ancho, como hace pantalla.ts.
    const chat = PESTANA_CHAT as Pestana & { tipo: "conversacion" };
    const rows = dibujar(chat, registro.entradas(), { ancho: 80, expandidas: new Set<number>(), resultados: (e: { llamada?: string }) => texts.get(e.llamada ?? "") }).lineas.map((row) => stripAnsi(truncate(row, 80)));
    const screen = rows.join("\n");
    assert.match(screen, /REA · (app JavaScript|JavaScript app) · evidencia 2 · artefacto [a-f0-9]{12}/, "con secretos aparte, lo importante entra igual");
    assert.match(screen, /REA · (abrir objetivo|open target) · evidencia 2 · artefacto [a-f0-9]{12}$/m);
    assert.match(screen, /REA · (abrir objetivo|open target) · Falló: provider_unavailable: Falta el motor/);
    assert.doesNotMatch(screen, /módulo módulo/, "la salida cruda no se vuelca en la conversación");
    const plain = dibujar(chat, registro.entradas().slice(4, 6), { ancho: 80, expandidas: new Set<number>(), resultados: () => undefined }).lineas.map(stripAnsi);
    for (const row of plain) assert.ok(visibleWidth(row) <= 80, `más de 80 columnas: «${row}»`);
  } finally {
    await engine.close();
    lab.clean();
  }
});

test("REA: el proxy de alcance deja salir al navegador sólo hacia el alcance", async () => {
  const site = createServer((req, res) => res.end(`ok ${req.method} ${req.url}`));
  await new Promise<void>((done) => site.listen(0, "127.0.0.1", done));
  const port = (site.address() as { port: number }).port;
  const allowed = new Set([`127.0.0.1:${port}`]);
  const proxy = new ProxyAlcance((url) => (allowed.has(new URL(url).host) ? undefined : "fuera del alcance"));
  try {
    const base = new URL(await proxy.url());
    assert.equal(base.hostname, "127.0.0.1");
    assert.equal(await proxy.url(), base.href.replace(/\/$/, ""), "arranca una sola vez");
    // CONNECT (HTTPS, WebSocket): un túnel hacia el alcance; afuera, 403 sin conectar.
    const tunnel = (target: string, payload = "") => new Promise<string>((done, fail) => {
      const socket = connect(Number(base.port), base.hostname, () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n${payload}`));
      let data = "";
      socket.on("data", (chunk) => { data += chunk; if (/\r\n\r\n[^]*ok /.test(data) || data.startsWith("HTTP/1.1 403")) socket.end(); });
      socket.on("close", () => done(data));
      socket.on("error", fail);
    });
    assert.match(await tunnel("evil.test:443"), /^HTTP\/1\.1 403 Forbidden/);
    const inside = await tunnel(`127.0.0.1:${port}`, `GET /dentro HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`);
    assert.match(inside, /^HTTP\/1\.1 200 Connection Established[^]*ok GET \/dentro/);
    // HTTP plano: el navegador manda la URL absoluta.
    const viaProxy = (url: string) => new Promise<string>((done, fail) => {
      const socket = connect(Number(base.port), base.hostname, () => socket.write(`GET ${url} HTTP/1.1\r\nHost: ${new URL(url).host}\r\nConnection: close\r\n\r\n`));
      let data = "";
      socket.on("data", (chunk) => { data += chunk; });
      socket.on("close", () => done(data));
      socket.on("error", fail);
    });
    assert.match(await viaProxy(`http://127.0.0.1:${port}/plano`), /^HTTP\/1\.1 200[^]*ok GET \/plano/);
    assert.match(await viaProxy("http://tracker.terceros.test/pixel"), /^HTTP\/1\.1 403/);
    assert.deepEqual(proxy.vaciar(), [["evil.test", 1], ["tracker.terceros.test", 1]]);
    assert.deepEqual(proxy.vaciar(), [], "se vacía al preguntar");
  } finally {
    await proxy.close();
    site.close();
  }
});
