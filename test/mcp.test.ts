import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { McpClient, McpManager, readMcpConfig, writeMcpConfig } from "../src/mcp.ts";

// Dos herramientas alcanzan para observar protocolo, paginación y errores sin instalar un servidor.
const serverSource = String.raw`
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";
const audit = process.env.MCP_AUDIT;
let initialized = false;
let revision = 0;
const send = (message) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
for await (const line of createInterface({ input: process.stdin })) {
  const m = JSON.parse(line);
  if (audit) appendFileSync(audit, JSON.stringify(m) + "\n");
  if (m.method === "initialize") {
    if (process.env.MCP_MODE === "init_hang") continue;
    send({ id: m.id, result: { protocolVersion: "2025-03-26", capabilities: { tools: { listChanged: true } }, serverInfo: { name: "laboratorio", version: "1" } } });
  } else if (m.method === "notifications/initialized") initialized = true;
  else if (m.method === "notifications/cancelled") continue;
  else if (!initialized) send({ id: m.id, error: { code: -32000, message: "Falta initialized" } });
  else if (m.method === "tools/list") {
    send({ id: m.id, result: m.params.cursor ? { tools: [{ name: "largo", description: "Genera evidencia grande. " + "detalle ".repeat(80) + "\nSegunda línea.\nDetalle completo.", inputSchema: { type: "object", properties: {} } }] } : { tools: [{ name: "eco", description: "Lee datos locales, revisión " + revision, inputSchema: { type: "object", properties: { text: { type: "string" } } } }], nextCursor: "segunda" } });
  } else if (m.method === "tools/call") {
    const args = m.params.arguments;
    if (args.mode === "hang") continue;
    if (args.mode === "crash") process.exit(2);
    if (args.mode === "invalid") { process.stdout.write("no-json\n"); continue; }
    if (args.mode === "oversized") { process.stdout.write("x".repeat(4096)); continue; }
    if (args.mode === "rpc_error") { send({ id: m.id, error: { code: -32602, message: "Argumentos inválidos" } }); continue; }
    if (args.mode === "changed") { revision++; send({ method: "notifications/tools/list_changed" }); }
    const result = { content: [{ type: "text", text: args.mode === "env" ? Object.keys(process.env).join(",") : m.params.name === "largo" ? "x".repeat(10000) : args.text ?? process.env.MCP_MARKER ?? "ok" }], isError: args.mode === "tool_error" };
    send({ id: m.id, result });
  }
}
`;

function fixture() {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-mcp-"));
  const server = join(cwd, "server.mjs");
  const audit = join(cwd, "audit.jsonl");
  writeFileSync(server, serverSource);
  writeFileSync(audit, "");
  const config = { command: process.execPath, args: [server], env: { MCP_AUDIT: audit, MCP_MARKER: "del-entorno" } };
  return { cwd, config, records: () => readFileSync(audit, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)), clean: () => rmSync(cwd, { recursive: true, force: true }) };
}
const signal = new AbortController().signal;

test("MCP: arranque por demanda, initialize, catálogo paginado, llamadas y notificaciones", async () => {
  const lab = fixture();
  const manager = new McpManager({ laboratorio: lab.config });
  try {
    assert.deepEqual(manager.names(), ["laboratorio"]);
    assert.equal(lab.records().length, 0);
    const tools = await manager.tools();
    assert.deepEqual(tools.map((tool) => tool.name), ["laboratorio.eco", "laboratorio.largo"]);
    assert.ok(tools.every((tool) => tool.replay === "never" && !tool.parallel));
    assert.match(tools[0]!.description, /Análisis local.*El alcance.*no cubre.*no la uses contra destinos de red/);
    assert.match(tools[1]!.description, /Detalle completo/);
    const result = JSON.parse((await tools[0]!.execute({}, signal)).text);
    assert.equal(result.content[0].text, "del-entorno");
    const large = await tools[1]!.execute({}, signal);
    assert.equal(JSON.parse(large.text).content[0].text.length, 10000);
    const error = await tools[0]!.execute({ mode: "tool_error" }, signal);
    assert.equal(JSON.parse(error.text).isError, true);
    assert.equal(error.details?.isError, true);
    assert.deepEqual(lab.records().slice(0, 4).map((item) => item.method), ["initialize", "notifications/initialized", "tools/list", "tools/list"]);
    await manager.tools();
    assert.equal(lab.records().filter((item) => item.method === "tools/list").length, 2);
    await tools[0]!.execute({ mode: "changed" }, signal);
    assert.match((await manager.tools())[0]!.description, /revisión 1/);
    assert.equal(lab.records().filter((item) => item.method === "tools/list").length, 4);
    await assert.rejects(async () => tools[0]!.execute({ mode: "rpc_error" }, signal), /MCP -32602/);
    await assert.rejects(manager.tools("ausente"), /No existe el servidor/);
  } finally {
    await manager.close();
    await manager.close();
    lab.clean();
  }
  await assert.rejects(manager.tools(), /cerrada/);
});

test("MCP: cancelación, timeout y cierre rechazan pendientes sin repetir acciones", async () => {
  const lab = fixture();
  const client = new McpClient(lab.config, { timeoutMs: 100 });
  try {
    await client.initialize();
    const controller = new AbortController();
    const aborted = client.callTool("eco", { mode: "hang" }, controller.signal);
    setTimeout(() => controller.abort(), 20);
    await assert.rejects(aborted, /cancelada/);
    await assert.rejects(client.callTool("eco", { mode: "hang" }), /Tiempo de espera MCP/);
    const healthy = await client.callTool("eco", { text: "sigue" });
    assert.equal(healthy.content[0].text, "sigue");
    assert.equal(lab.records().filter((item) => item.method === "notifications/cancelled").length, 2);
    const pending = client.callTool("eco", { mode: "hang" });
    const checked = assert.rejects(pending, /cerrado/);
    await client.close();
    await checked;
  } finally {
    await client.close();
    lab.clean();
  }
});

test("MCP: errores de proceso y protocolo y límite de frame cierran la conexión", async () => {
  for (const mode of ["crash", "invalid", "oversized"]) {
    const lab = fixture();
    const client = new McpClient(lab.config, { timeoutMs: 500, maxFrameBytes: 2048 });
    try {
      await client.initialize();
      await assert.rejects(client.callTool("eco", { mode }), /terminó|stdout|Protocolo|tope/);
      await client.close();
      await assert.rejects(client.callTool("eco", {}), /cerrado|terminó|stdout|Protocolo|tope/);
    } finally {
      await client.close();
      lab.clean();
    }
  }
  const missing = new McpClient({ command: "/inexistente/cyber-mcp" });
  await assert.rejects(missing.initialize(), /No se pudo iniciar|cerró/);
  await missing.close();
});

test("MCP: cancelar durante initialize no espera el timeout del servidor", async () => {
  const lab = fixture();
  const client = new McpClient({ ...lab.config, env: { ...lab.config.env, MCP_MODE: "init_hang" } }, { timeoutMs: 5000 });
  const controller = new AbortController();
  try {
    const call = client.callTool("eco", {}, controller.signal);
    setTimeout(() => controller.abort(), 20);
    await assert.rejects(call, /cancelada/);
  } finally {
    await client.close();
    lab.clean();
  }
});

test("MCP: el servidor no hereda las claves del entorno de Cyber", async () => {
  const lab = fixture();
  Object.assign(process.env, { CYBER_SECRETS_KEY: "k", OROBAS_API_KEY: "o", H1_API_TOKEN: "h", NO_SECRETA: "1" });
  const manager = new McpManager({ laboratorio: lab.config });
  try {
    const [eco] = await manager.tools();
    const names = JSON.parse((await eco!.execute({ mode: "env" }, signal)).text).content[0].text.split(",");
    assert.ok(names.includes("NO_SECRETA"));
    for (const name of ["CYBER_SECRETS_KEY", "OROBAS_API_KEY", "H1_API_TOKEN"]) assert.ok(!names.includes(name), name);
  } finally {
    for (const name of ["CYBER_SECRETS_KEY", "OROBAS_API_KEY", "H1_API_TOKEN", "NO_SECRETA"]) delete process.env[name];
    await manager.close();
    lab.clean();
  }
});

test("MCP: configuración propia respeta CYBER_CONFIG y valida command, args y env", () => {
  const lab = fixture();
  const previous = process.env.CYBER_CONFIG;
  const config = join(lab.cwd, "config.json");
  process.env.CYBER_CONFIG = config;
  try {
    assert.deepEqual(readMcpConfig(), {});
    writeFileSync(config, JSON.stringify({ mcp: { rea: lab.config } }));
    assert.deepEqual(readMcpConfig().rea, lab.config);
    writeFileSync(config, JSON.stringify({ mcp: { rea: { command: "node", args: "archivo" } } }));
    assert.throws(readMcpConfig, /args de rea/);
    writeFileSync(config, JSON.stringify({ mcp: { rea: { command: "node", env: { KEY: 123 } } } }));
    assert.throws(readMcpConfig, /env de rea/);
  } finally {
    if (previous === undefined) delete process.env.CYBER_CONFIG;
    else process.env.CYBER_CONFIG = previous;
    lab.clean();
  }
});


test("MCP en el motor: catálogo por demanda, descripción completa, artefacto grande, error y restauración", async () => {
  const lab = fixture();
  const other = fixture();
  const provider = resolveProvider("faux");
  const mcp = { laboratorio: lab.config, otro: other.config };
  const engine = new Engine({ cwd: lab.cwd, provider, mcp });
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  let resumed: Engine | undefined;
  try {
    assert.deepEqual(engine.mcp.names(), ["laboratorio", "otro"]);
    assert.equal(lab.records().length, 0);
    assert.ok(!engine.agent.tools.some((tool) => tool.name.startsWith("laboratorio.")));
    provider.faux!.queue = [
      call("tool_search", { query: "laboratorio.largo" }),
      call("tools_load", { names: ["laboratorio.largo", "laboratorio.eco"] }),
      call("laboratorio.largo", {}),
      call("laboratorio.eco", { mode: "tool_error" }),
      { text: "Listo." },
    ];
    await engine.send("Buscá y usá las herramientas locales del laboratorio");
    const replies = engine.agent.messages.filter((message) => message.role === "tool");
    const search = String(replies.find((message) => message.name === "tool_search")!.content);
    const lines = search.split("\n");
    assert.equal(lines.length, 2);
    assert.ok(lines[1]!.length <= 320);
    assert.doesNotMatch(search, /Segunda línea|Detalle completo/);
    const loaded = String(replies.find((message) => message.name === "tools_load")!.content);
    assert.match(loaded, /Segunda línea\.\nDetalle completo/);
    assert.match(engine.agent.tools.find((tool) => tool.name === "laboratorio.largo")!.description, /Detalle completo/);
    const large = String(replies.find((message) => message.name === "laboratorio.largo")!.content);
    assert.match(large, /salida truncada/);
    assert.ok(large.length < 8000);
    const hash = large.match(/sha256:[a-f0-9]{64}/)![0];
    assert.equal(JSON.parse(engine.artifacts.read(hash).toString()).content[0].text.length, 10000);
    assert.equal(replies.find((message) => message.name === "laboratorio.eco")!.isError, true);
    assert.equal(engine.http.count, 0);
    assert.equal(other.records().length, 0, "buscar por servidor no arranca otros procesos");
    const session = engine.sessionId;
    await engine.close();
    const previous = lab.records().length;
    const nextProvider = resolveProvider("faux");
    resumed = new Engine({ cwd: lab.cwd, provider: nextProvider, mcp, resume: session });
    assert.equal(lab.records().length, previous, "retomar no arranca el proceso hasta el siguiente turno");
    nextProvider.faux!.queue = [call("laboratorio.eco", { text: "retomado" }), { text: "Listo." }];
    await resumed.send("Retomá la herramienta local cargada");
    assert.ok(resumed.agent.tools.some((tool) => tool.name === "laboratorio.eco"));
    assert.equal(lab.records().filter((item) => item.method === "initialize").length, 2);
    assert.equal(other.records().length, 0, "restaurar sólo arranca servidores con herramientas cargadas");
    const last = resumed.agent.messages.filter((message) => message.role === "tool" && message.name === "laboratorio.eco").at(-1)!;
    assert.match(String(last.content), /retomado/);
  } finally {
    await resumed?.close();
    await engine.close();
    lab.clean();
    other.clean();
  }
});

test("MCP en el motor: tools_load descubre sólo el prefijo solicitado", async () => {
  const lab = fixture();
  const other = fixture();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: lab.cwd, provider, mcp: { laboratorio: lab.config, otro: other.config } });
  try {
    provider.faux!.queue = [
      { toolCalls: [{ name: "tools_load", arguments: { names: ["laboratorio.eco"] } }] },
      { text: "Cargada." },
    ];
    await engine.send("Cargá laboratorio.eco");
    assert.ok(engine.agent.tools.some((tool) => tool.name === "laboratorio.eco"));
    assert.equal(lab.records().filter((item) => item.method === "initialize").length, 1);
    assert.equal(other.records().length, 0);
  } finally {
    await engine.close();
    lab.clean();
    other.clean();
  }
});

test("MCP: lee con BOM y writeMcpConfig no pisa un archivo ilegible", () => {
  const lab = fixture();
  const previous = process.env.CYBER_CONFIG;
  const config = join(lab.cwd, "config.json");
  process.env.CYBER_CONFIG = config;
  try {
    writeFileSync(config, `\uFEFF${JSON.stringify({ mcp: { rea: lab.config } })}`);
    assert.deepEqual(readMcpConfig().rea, lab.config);
    writeFileSync(config, "{ roto");
    assert.throws(() => writeMcpConfig({ rea: lab.config }), /No toqué/);
    assert.equal(readFileSync(config, "utf8"), "{ roto");
  } finally {
    if (previous === undefined) delete process.env.CYBER_CONFIG;
    else process.env.CYBER_CONFIG = previous;
    lab.clean();
  }
});
