import "./datos-tmp.ts";
// Modelo base y modelo fuerte (src/fuerte.ts): el bucle corre con uno barato y consulta al caro sólo para
// razonar (deep_reason) o para un subagente entero (delegate con strong). Lo que va al fuerte queda en
// requests con su worker. El operador elige los dos; un caro elegido para el bucle se respeta y se le
// muestra cuánto cuesta cada paso.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import type { LlmRequest, Scripted, Transport } from "../src/llm.ts";
import { DEFAULT_BASE_MODEL, DEFAULT_STRONG_MODEL, defaultStrongModel, type Provider, resolveProvider } from "../src/providers.ts";
import { parseCatalog, saveCatalog } from "../src/tarifas.ts";
import { stepCostLine } from "../src/fuerte.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-fuerte-"));

/** Un proveedor simulado que se hace pasar por el fuerte («faux/ultra»): anota lo que recibe y contesta lo que haya en `queue`. */
function fakeStrong(): { provider: Provider; seen: LlmRequest[]; queue: Scripted[] } {
  const faux = resolveProvider("faux");
  faux.faux!.queue = [];
  const seen: LlmRequest[] = [];
  const transport: Transport = (request) => { seen.push(request); return faux.transport(request); };
  return { provider: { ...faux, model: { provider: "faux", id: "ultra", baseUrl: "" }, transport }, seen, queue: faux.faux!.queue };
}

/** Configuración propia de la prueba (CYBER_CONFIG y la clave de orobas), restaurada al terminar. */
async function withConfig(config: object, fn: (dir: string) => Promise<void> | void): Promise<void> {
  const dir = tmp();
  const prev = { c: process.env.CYBER_CONFIG, k: process.env.OROBAS_API_KEY, m: process.env.CYBER_MODEL, s: process.env.CYBER_STRONG_MODEL, t: process.env.CYBER_TRAZAS };
  writeFileSync(join(dir, "config.json"), JSON.stringify(config));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  process.env.OROBAS_API_KEY = "oro_prueba";
  process.env.CYBER_TRAZAS = "no";
  delete process.env.CYBER_MODEL;
  delete process.env.CYBER_STRONG_MODEL;
  try { await fn(dir); } finally {
    for (const [name, value] of [["CYBER_CONFIG", prev.c], ["OROBAS_API_KEY", prev.k], ["CYBER_MODEL", prev.m], ["CYBER_STRONG_MODEL", prev.s], ["CYBER_TRAZAS", prev.t]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

test("deep_reason: una llamada al fuerte, sin herramientas, con la pregunta, los datos y los adjuntos; queda en requests como «fuerte»", async () => {
  const strong = fakeStrong();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider, strong: strong.provider });
  assert.ok(engine.agent.tools.some((tool) => tool.name === "deep_reason"), "el base lo tiene siempre a mano");
  const evidence = engine.artifacts.put("HTTP/1.1 200\n{\"token\":\"abc\",\"rol\":\"admin\"}", "text/plain", "prueba");
  provider.faux!.queue = [
    { toolCalls: [{ name: "deep_reason", arguments: { question: "¿Este token de otro usuario me deja escalar a admin?", data: "PUT /api/usuarios/7 → 200 con mi sesión", artifacts: [evidence.hash] } }] },
    { text: "Listo: el fuerte dice que sí; lo pruebo." },
  ];
  strong.queue.push({ text: "Conclusión: sí. Mandá PUT /api/usuarios/7 con rol=admin y mirá si el GET posterior lo refleja." });
  await engine.send("¿Se puede escalar?");

  const result = engine.agent.messages.find((m) => m.role === "tool" && m.name === "deep_reason")!;
  assert.match(result.content as string, /^Conclusión: sí\. Mandá PUT/);
  assert.match(result.content as string, /\[modelo fuerte faux\/ultra: /);
  assert.equal(strong.seen.length, 1, "una sola llamada");
  const asked = strong.seen[0]!;
  assert.deepEqual(asked.tools, [], "sin herramientas");
  assert.match(asked.system, /analista/);
  const prompt = asked.messages[0]!.content as string;
  assert.match(prompt, /escalar a admin/);
  assert.match(prompt, /DATOS:\nPUT \/api\/usuarios\/7/);
  assert.match(prompt, /"token":"abc"/, "el adjunto viaja con su contenido");
  assert.equal(asked.tags?.worker, "fuerte");
  const rows = engine.db.prepare("select worker, model from requests where session_id=? order by rowid").all(engine.sessionId).map((r: any) => `${r.worker}:${r.model}`);
  assert.deepEqual(rows, ["principal:faux", "fuerte:ultra", "principal:faux"]);
  const event = engine.db.prepare("select payload from events where session_id=? and type='modelo_fuerte.consulta'").get(engine.sessionId) as { payload: string };
  assert.equal(JSON.parse(event.payload).herramienta, "deep_reason");
  engine.close();
});

test("delegate con strong: el subagente trabaja con el fuerte, su worker lo dice y no se consulta a sí mismo", async () => {
  const strong = fakeStrong();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider, strong: strong.provider });
  strong.queue.push({ text: "RESULTADO: la cadena funciona con el id 7." });
  provider.faux!.queue = [
    { toolCalls: [{ name: "delegate", arguments: { objective: "Encadená la escalada con el id 7", strong: true } }] },
    { toolCalls: [{ name: "delegate", arguments: { objective: "Listá las rutas de /api" } }] },
    { text: "RESULTADO: rutas listadas." },
    { text: "Hecho." },
  ];
  await engine.send("Explotalo.");
  const results = engine.agent.messages.filter((m) => m.role === "tool" && m.name === "delegate").map((m) => m.content as string);
  assert.match(results[0]!, /^RESULTADO: la cadena funciona/);
  assert.match(results[0]!, /\[sub:1:fuerte: 1 solicitudes/);
  assert.match(results[1]!, /\[sub:2: 1 solicitudes/, "sin strong, el base");
  assert.equal(strong.seen.length, 1);
  assert.ok(!strong.seen[0]!.tools.some((tool) => tool.name === "deep_reason" || tool.name === "delegate"));
  const rows = engine.db.prepare("select worker, model from requests where session_id=? and worker like 'sub:%' order by rowid").all(engine.sessionId).map((r: any) => `${r.worker}:${r.model}`);
  assert.deepEqual(rows, ["sub:1:fuerte:ultra", "sub:2:faux"]);
  const event = engine.db.prepare("select payload from events where session_id=? and type='modelo_fuerte.consulta'").get(engine.sessionId) as { payload: string };
  assert.deepEqual([JSON.parse(event.payload).herramienta, JSON.parse(event.payload).worker], ["delegate", "sub:1:fuerte"]);
  engine.close();
});

test("modelos por defecto: base barato y fuerte de fábrica; la configuración y el entorno los cambian", () => withConfig({}, () => {
  assert.equal(DEFAULT_BASE_MODEL, "orobas/glm-5.3-flash");
  assert.equal(DEFAULT_STRONG_MODEL, "orobas/cyber-ultra-1.0");
  const base = resolveProvider();
  assert.equal(`${base.model.provider}/${base.model.id}`, "orobas/glm-5.3-flash", "sin elección, el base barato");
  assert.equal(defaultStrongModel(base.model), "orobas/cyber-ultra-1.0");
  assert.equal(defaultStrongModel({ provider: "anthropic", id: "claude-x" }), "anthropic/claude-x", "con otro proveedor, el mismo modelo");
  writeFileSync(process.env.CYBER_CONFIG!, JSON.stringify({ defaultModel: "orobas/cyber-zero-1.5", strongModel: "orobas/kimi-k3" }));
  assert.equal(resolveProvider().model.id, "cyber-zero-1.5", "un caro elegido a mano no se pisa");
  assert.equal(defaultStrongModel(base.model), "orobas/kimi-k3");
  process.env.CYBER_STRONG_MODEL = "orobas/otro";
  assert.equal(defaultStrongModel(base.model), "orobas/otro");
}));

test("/modelo fuerte: el operador lo elige de la lista de su cuenta, vale para deep_reason y se conserva al retomar", async () => {
  const server = createServer((req, res) => {
    if (req.url?.endsWith("/models")) return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ object: "list", data: ["glm-5.3-flash", "cyber-ultra-1.0", "cyber-zero-1.5", "auto"].map((id) => ({ id })) }));
    res.writeHead(500).end("no se llama a ningún modelo en esta prueba");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`;
  try {
    await withConfig({ providers: { orobas: { baseUrl: base, apiKeyEnv: "OROBAS_API_KEY" } } }, async () => {
      const cwd = tmp();
      let engine = new Engine({ cwd, provider: resolveProvider() });
      assert.equal(engine.agent.model.id, "glm-5.3-flash");
      assert.equal(engine.strongSpec(), "orobas/cyber-ultra-1.0");
      assert.equal(await engine.setStrongModel("zero"), "orobas/cyber-zero-1.5");
      const strong = engine.strong();
      assert.equal(strong.model.id, "cyber-zero-1.5");
      assert.equal(strong.model.idleTimeoutMs, 90_000, "el fuerte razona largo: más margen de silencio");
      assert.notEqual(strong.model, engine.agent.model, "el bucle sigue con el base");
      assert.equal(engine.agent.model.id, "glm-5.3-flash");
      await assert.rejects(() => engine.setStrongModel("inexistente"), /No hay un modelo «inexistente»/);
      const session = engine.sessionId;
      engine.close();
      engine = new Engine({ cwd, provider: resolveProvider(), resume: session });
      assert.equal(engine.strongSpec(), "orobas/cyber-zero-1.5", "retomada, conserva el fuerte elegido");
      assert.equal(await engine.setStrongModel("defecto"), "orobas/cyber-ultra-1.0");
      engine.close();
    });
  } finally {
    server.close();
  }
});

test("un modelo caro elegido para el bucle se respeta, y el operador ve cuánto cuesta cada paso", () => withConfig({}, () => {
  saveCatalog("https://cyber.elevateai.ar/api/v1", parseCatalog([
    { id: "glm-5.3-flash", pricing: { input: 1, cached_input: 0.1, output: 4 }, context_length: 1048576 },
    { id: "cyber-ultra-1.0", pricing: { input: 5, cached_input: 1.25, output: 20 }, context_length: 1048576 },
  ]));
  const notices: string[] = [];
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("orobas/cyber-ultra-1.0") });
  engine.onNotice = (text) => notices.push(text);
  assert.equal(engine.agent.model.id, "cyber-ultra-1.0", "no se pisa");
  const cost = engine.stepCost()!;
  assert.equal(cost.expensive, true);
  assert.match(cost.text, /^≈ USD 0\.\d{3} por paso \(estimado con 30k tokens de contexto, \d+ veces glm-5\.3-flash\)$/);
  (engine as any).tellCost();
  assert.equal(notices.length, 1);
  assert.match(notices[0]!, /Lo respeto porque lo elegiste/);
  assert.match(notices[0]!, /\/modelo fuerte cyber-ultra-1\.0/);
  const event = engine.db.prepare("select payload from events where session_id=? and type='modelo.caro'").get(engine.sessionId) as { payload: string };
  assert.equal(JSON.parse(event.payload).modelo, "orobas/cyber-ultra-1.0");
  engine.close();

  // El base no avisa nada.
  const cheap = new Engine({ cwd: tmp(), provider: resolveProvider("orobas/glm-5.3-flash") });
  cheap.onNotice = (text) => notices.push(text);
  (cheap as any).tellCost();
  assert.equal(notices.length, 1);
  assert.equal(cheap.stepCost()!.expensive, false);
  cheap.close();
  // Medido en la sesión manda sobre lo estimado.
  const measured = stepCostLine({ provider: "orobas", id: "x", baseUrl: "", cost: { input: 1, output: 1, cacheRead: 1, cacheWrite: 0 } }, 30_000, 155_000_000_000n, undefined)!;
  assert.match(measured.text, /≈ USD 0\.155 por paso \(medido en esta sesión\)/);
  assert.equal(measured.expensive, true);
}));

test("TUI: /modelo fuerte cambia el fuerte por nombre o desde el menú, con el vigente marcado; se recuerda por proyecto", async () => {
  const { findCommand, strongOf } = await import("../src/tui/comandos.ts");
  const { RECORDADOS } = await import("../src/tui/ajustes.ts");
  const { fakeIO } = await import("./fake-io.ts");
  assert.ok((RECORDADOS as readonly string[]).includes("strong"), "el ajuste «strong» se guarda y se reaplica como el modelo");
  assert.equal(strongOf(["Modelo fuerte: orobas/cyber-ultra-1.0 · base (bucle): orobas/glm-5.3-flash"]), "orobas/cyber-ultra-1.0");
  const direct = fakeIO({});
  await findCommand("modelo")!.run(direct.io, "fuerte zero");
  assert.deepEqual(direct.calls, [{ op: "strong", payload: { value: "zero" } }]);
  const answers = { strong: ["Modelo fuerte: orobas/cyber-ultra-1.0 · base (bucle): orobas/glm-5.3-flash"], models: ["current\torobas/glm-5.3-flash", "model\torobas/glm-5.3-flash\tGLM", "model\torobas/cyber-ultra-1.0\tUltra", "model\torobas/cyber-zero-1.5\tZero"] };
  const menu = fakeIO(answers, [2]);
  const panel = await findCommand("model")!.run(menu.io, "strong");
  assert.equal(menu.picked[0]!.at, 1, "marca el fuerte vigente, no el base");
  assert.deepEqual(menu.calls.at(-1), { op: "strong", payload: { value: "orobas/cyber-zero-1.5" } });
  assert.equal(panel?.tone, "ok");
  const same = fakeIO(answers, [1]);
  assert.equal(await findCommand("modelo")!.run(same.io, "fuerte"), null, "elegir el vigente no cambia nada");
  assert.ok(!same.calls.some((call) => call.op === "strong" && "value" in call.payload));
});

test("hablando: «usá ultra como fuerte» cambia el fuerte sólo si el operador lo nombró", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider });
  const asked: string[] = [];
  (engine as unknown as { setStrongModel: (w: string) => Promise<string> }).setStrongModel = async (wanted) => { asked.push(wanted); return `orobas/${wanted}`; };
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  provider.faux!.queue = [
    call("tools_load", { names: ["session_settings"] }),
    call("session_settings", { modelo_fuerte: "orobas/cyber-zero-1.5", pedido: "usá ultra como modelo fuerte" }),
    call("session_settings", { modelo_fuerte: "orobas/cyber-ultra-1.0", pedido: "usá ultra como modelo fuerte" }),
    { text: "listo" },
  ];
  await engine.send("Usá ultra como modelo fuerte");
  const results = engine.agent.messages.filter((m) => m.role === "tool").map((m) => m.content as string);
  assert.match(results[1]!, /Cambiar el modelo fuerte exige que el operador lo haya nombrado/);
  assert.match(results[2]!, /Cambiado: modelo_fuerte/);
  assert.match(results[2]!, /modelo fuerte: faux\/faux/, "muestra el vigente");
  assert.deepEqual(asked, ["orobas/cyber-ultra-1.0"]);
  engine.close();
});
