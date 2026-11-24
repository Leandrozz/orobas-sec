import "./datos-tmp.ts";
// Dieta de contexto (src/contexto.ts): las salidas viejas y largas de herramientas viajan resumidas, por
// tandas, y lo que se envía queda idéntico entre pasos hasta el próximo checkpoint, así el prefijo que el
// proveedor ya cacheó sigue sirviendo. También el umbral de compactación nuevo.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ContextDiet, DIET_KEEP, DIET_MIN_SAVING } from "../src/contexto.ts";
import { compactThreshold, Engine } from "../src/engine.ts";
import type { Message, Transport } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-dieta-"));
const MARK = "[resumido para ahorrar contexto]";

/** Conversación de prueba: n pasos, cada uno con una llamada HTTP y su salida larga. Seqs salteados, como los de la base. */
function conversation(n: number, size = 4000) {
  const messages: Message[] = [{ role: "user", content: "Probá todo el sitio.", at: 1 }];
  const add = (i: number, name = "http_request", content?: string) => {
    messages.push({ role: "assistant", content: `paso ${i}`, toolCalls: [{ id: `c${i}`, name, arguments: JSON.stringify({ url: `https://a.test/${i}` }) }], stopReason: "toolUse", provider: "faux", model: "m", requestId: `r${i}`, at: 1 });
    messages.push({ role: "tool", toolCallId: `c${i}`, name, content: content ?? `h${i + 1}  GET https://a.test/${i}  200  ${size} B\n${`cuerpo ${i} `.repeat(Math.ceil(size / 10))}`, isError: false, at: 1 });
  };
  for (let i = 0; i < n; i++) add(i);
  const seqs = () => messages.map((_, index) => index * 3 + 7);
  return { messages, add, seqs };
}

function saver() {
  const saved = new Map<string, string>();
  const save = (text: string) => {
    const hash = `sha256:${createHash("sha256").update(text).digest("hex")}`;
    saved.set(hash, text);
    return hash;
  };
  return { saved, save };
}

test("dieta: resume de una vez lo viejo y largo; lo reciente, lo corto, el operador, el asistente y el estado van literales", () => {
  const { messages, add, seqs } = conversation(20);
  add(20, "finding_list", "hallazgos:\n" + "x".repeat(3000));
  add(21, "http_request", "h99  GET https://a.test/corto  200  12 B");
  const { saved, save } = saver();
  const diet = new ContextDiet(save);
  assert.equal(diet.view(messages, seqs()), messages, "sin checkpoint, lo mismo");
  const plan = diet.plan(messages, seqs())!;
  assert.ok(plan, "veinte salidas de 4k alcanzan para un checkpoint");
  // La frontera deja literales las últimas ocho salidas; se resumen las 14 anteriores largas que no son estado.
  const tools = messages.flatMap((m, i) => (m.role === "tool" ? [i] : []));
  assert.equal(plan.boundary, seqs()[tools[tools.length - DIET_KEEP]!]);
  assert.equal(plan.count, 14);
  assert.ok(plan.saved >= DIET_MIN_SAVING);
  diet.advance(plan.boundary);
  const view = diet.view(messages, seqs());
  const masked = view.filter((m) => m.role === "tool" && m.content.startsWith(MARK));
  assert.equal(masked.length, 14);
  view.forEach((m, i) => {
    if (m.role !== "tool" || !m.content.startsWith(MARK)) assert.equal(m, messages[i], "lo que no se resume es el mismo objeto");
  });
  const first = masked[0]!.content as string;
  assert.match(first, /^\[resumido para ahorrar contexto\] http_request \{"url":"https:\/\/a\.test\/0"\} → \d+ caracteres\./, "qué fue, con la llamada");
  assert.match(first, /\nInicio: h1 GET https:\/\/a\.test\/0 200/, "cómo empezaba");
  assert.match(first, /Evidencia que nombraba: h1\n/, "conserva el id del intercambio para citarlo como evidencia");
  const hash = /Completa en (sha256:[0-9a-f]{64})/.exec(first)![1]!;
  assert.equal(saved.get(hash), messages[2]!.content, "el original entero queda en el artefacto");
  assert.ok(first.length < 1000);
  assert.ok(JSON.stringify(view).length < JSON.stringify(messages).length * 0.5, "lo enviado baja a menos de la mitad");
  // El estado (hallazgos) y las salidas cortas no se tocan aunque sean viejas.
  assert.ok(!view.some((m) => m.role === "tool" && m.name === "finding_list" && m.content.startsWith(MARK)));
  assert.equal(diet.plan(messages, seqs()), undefined, "recién hecho, no hay otro checkpoint");
});

test("dieta: entre checkpoints lo enviado sólo crece al final (prefijo estable para la caché) y al retomar sale igual", () => {
  const { messages, add, seqs } = conversation(24);
  const { save } = saver();
  const diet = new ContextDiet(save);
  diet.advance(diet.plan(messages, seqs())!.boundary);
  const before = JSON.parse(JSON.stringify(diet.view(messages, seqs()))) as Message[];
  // Tres pasos más: tres salidas salen de las ocho recientes, pero no alcanzan para un checkpoint.
  for (let i = 24; i < 27; i++) add(i);
  assert.equal(diet.plan(messages, seqs()), undefined, "ahorraría poco: la frontera no se mueve");
  const after = JSON.parse(JSON.stringify(diet.view(messages, seqs()))) as Message[];
  assert.deepEqual(after.slice(0, before.length), before, "lo ya enviado no cambió ni un byte");
  // Con bastante acumulado, otro checkpoint: lo resumido antes sigue idéntico y la frontera avanza.
  for (let i = 27; i < 44; i++) add(i);
  const second = diet.plan(messages, seqs())!;
  assert.ok(second.boundary > diet.boundary);
  diet.advance(second.boundary);
  const third = JSON.parse(JSON.stringify(diet.view(messages, seqs()))) as Message[];
  const firstNew = third.findIndex((m, i) => JSON.stringify(m) !== JSON.stringify(after[i]));
  assert.ok(firstNew > 0);
  assert.ok((third[firstNew] as { content: string }).content.startsWith(MARK), "el primer cambio es una salida recién resumida, no algo anterior");
  // Retomar la sesión: otra instancia con la misma frontera arma exactamente lo mismo.
  const resumed = new ContextDiet(save);
  resumed.advance(diet.boundary);
  assert.equal(JSON.stringify(resumed.view(messages, seqs())), JSON.stringify(third));
  // Una frontera vieja no retrocede.
  resumed.advance(0);
  assert.equal(resumed.boundary, diet.boundary);
});

test("dieta: una salida que la herramienta ya truncó remite al artefacto completo, sin guardar otro", () => {
  const full = `sha256:${"a".repeat(64)}`;
  const { messages, seqs } = conversation(24, 4000);
  for (const message of messages) if (message.role === "tool") message.content += `\n… salida truncada: 99999 caracteres en total. Completa en ${full}; ampliá con artifact_read usando filter u offset.`;
  let calls = 0;
  const diet = new ContextDiet(() => (calls++, "sha256:nunca"));
  diet.advance(diet.plan(messages, seqs())!.boundary);
  const view = diet.view(messages, seqs());
  const masked = view.filter((m) => m.role === "tool" && m.content.startsWith(MARK));
  assert.ok(masked.length > 0);
  for (const message of masked) assert.match(message.content as string, new RegExp(`Completa en ${full}:`));
  assert.equal(calls, 0);
});

test("motor: la dieta se dispara al pasar el umbral, achica lo enviado, no rompe la caché entre checkpoints y se retoma igual", async () => {
  const cwd = tmp();
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, maskAt: 1 });
  // Lo que recibe el proveedor en cada solicitud del agente principal.
  const sent: Message[][] = [];
  const original = provider.transport;
  const spy: Transport = async (request) => {
    if (request.tags?.worker === "principal") sent.push(JSON.parse(JSON.stringify(request.messages)));
    return original(request);
  };
  engine.provider = { ...engine.provider, transport: spy };
  let n = 0;
  engine.agent.tools.push((engine as any).bounded({ name: "leer", label: "Leer", description: "", parameters: { type: "object" }, execute: () => ({ text: `h${++n}  GET https://a.test/${n}  200\n${`dato ${n} `.repeat(700)}` }) }));
  const steps = 34;
  provider.faux!.queue = [...Array.from({ length: steps }, () => ({ toolCalls: [{ name: "leer", arguments: {} }] })), { text: "Listo." }];
  await engine.send("Leé todo.");
  assert.equal(sent.length, steps + 1);

  const checkpoints = engine.db.prepare("select payload from events where session_id=? and type='contexto.dieta' order by seq").all(engine.sessionId).map((row: any) => JSON.parse(row.payload));
  assert.ok(checkpoints.length >= 2, `hubo ${checkpoints.length} checkpoints`);
  assert.ok(checkpoints.length <= 3, "por tandas, no en cada paso");
  // Entre pasos, lo enviado antes es prefijo de lo siguiente; sólo un checkpoint lo cambia, y achica.
  let breaks = 0;
  for (let i = 1; i < sent.length; i++) {
    const prev = sent[i - 1]!;
    const next = sent[i]!;
    if (JSON.stringify(next.slice(0, prev.length)) === JSON.stringify(prev)) continue;
    breaks++;
    assert.ok(JSON.stringify(next).length < JSON.stringify(prev).length, "el paso del checkpoint envía menos que el anterior");
  }
  assert.equal(breaks, checkpoints.length, "la caché se rompe una vez por checkpoint y nada más");
  const last = sent.at(-1)!;
  const masked = last.filter((m) => m.role === "tool" && m.content.startsWith(MARK));
  assert.ok(masked.length >= 18);
  assert.equal(last.filter((m) => m.role === "tool" && !m.content.startsWith(MARK)).length >= DIET_KEEP, true, "las últimas ocho van literales");
  // El historial guardado sigue entero y el artefacto del resumen tiene el original.
  assert.ok(!engine.agent.messages.some((m) => m.role === "tool" && m.content.startsWith(MARK)));
  const stored = engine.db.prepare("select json from messages where session_id=?").all(engine.sessionId).map((row: any) => row.json as string);
  assert.ok(!stored.some((json) => json.includes(MARK)));
  const hash = /Completa en (sha256:[0-9a-f]{64})/.exec(masked[0]!.content as string)![1]!;
  assert.equal(engine.artifacts.read(hash).toString("utf8"), (engine.agent.messages.find((m) => m.role === "tool") as { content: string }).content);
  // El contexto medido baja después del checkpoint.
  const contexts = engine.db.prepare("select input from requests where session_id=? and worker='principal' order by rowid").all(engine.sessionId).map((row: any) => row.input as number);
  assert.ok(Math.min(...contexts.slice(20)) < Math.max(...contexts.slice(0, 20)));
  const view = JSON.stringify(engine.sentMessages());
  engine.close();

  // Retomar: misma frontera, misma vista byte a byte (la caché del proveedor sigue sirviendo).
  const reopened = new Engine({ cwd, provider, resume: true, maskAt: 1 });
  assert.equal(JSON.stringify(reopened.sentMessages()), view);
  reopened.close();
});

test("umbral de compactación: 60k o la mitad de la ventana; la dieta, la mitad de eso; lo fijado por quien abre se respeta", () => {
  assert.equal(compactThreshold({ contextWindow: 1_048_576 }), 60_000, "los modelos de 1M ya no esperan a 120k");
  assert.equal(compactThreshold({ contextWindow: 64_000 }), 32_000);
  assert.equal(compactThreshold({}), 60_000);
  const engine = new Engine({ cwd: tmp(), provider: resolveProvider("faux") });
  assert.equal(engine.compactAt, 60_000);
  assert.equal(engine.maskAt, 30_000);
  engine.close();
  const fixed = new Engine({ cwd: tmp(), provider: resolveProvider("faux"), compactAt: 5000 });
  assert.equal(fixed.compactAt, 5000);
  assert.equal(fixed.maskAt, 2500);
  fixed.close();

  // Al cambiar de modelo se recalcula con su ventana, salvo lo fijado.
  const dir = tmp();
  const prev = process.env.CYBER_CONFIG;
  writeFileSync(join(dir, "config.json"), JSON.stringify({ providers: { local: { baseUrl: "http://127.0.0.1:9", models: { chico: { contextWindow: 32_000 }, grande: { contextWindow: 1_000_000 } } } } }));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  try {
    const engine = new Engine({ cwd: tmp(), provider: resolveProvider("local/grande") });
    assert.equal(engine.compactAt, 60_000);
    (engine as any).applyModel("local/chico");
    assert.equal(engine.compactAt, 16_000);
    assert.equal(engine.maskAt, 8_000);
    engine.close();
    const pinned = new Engine({ cwd: tmp(), provider: resolveProvider("local/grande"), compactAt: 50_000, maskAt: 20_000 });
    (pinned as any).applyModel("local/chico");
    assert.equal(pinned.compactAt, 50_000);
    assert.equal(pinned.maskAt, 20_000);
    pinned.close();
  } finally {
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("compactación: el resumen se pide sobre lo mismo que ya leyó el modelo (prefijo en caché); si llama una herramienta, se arma la transcripción como antes", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider });
  const seen: Array<{ worker?: string; system: string; tools: number; messages: string }> = [];
  const original = provider.transport;
  engine.provider = { ...engine.provider, transport: async (request) => { seen.push({ worker: request.tags?.worker, system: request.system, tools: request.tools.length, messages: JSON.stringify(request.messages) }); return original(request); } };
  provider.faux!.queue = [{ text: "uno" }, { text: "dos" }, { text: "tres" }, { text: "cuatro" }];
  for (const text of ["a", "b", "c", "d"]) await engine.send(text);
  const last = seen.at(-1)!;
  provider.faux!.queue = [{ text: "OBJETIVO: probar.\nPENDIENTE: nada." }];
  assert.equal(await engine.compact(), true);
  const cached = seen.at(-1)!;
  assert.equal(cached.worker, "compactacion");
  assert.equal(cached.system, last.system, "mismo sistema");
  assert.equal(cached.tools, last.tools, "mismas herramientas");
  assert.ok(cached.messages.startsWith(last.messages.slice(0, -1)), "la conversación enviada antes es prefijo de la del resumen");
  assert.match(cached.messages, /Pausa para liberar contexto: no uses herramientas/);

  // Un modelo que, en vez de resumir, llama una herramienta: se descarta y va la transcripción aparte, sin herramientas.
  provider.faux!.queue = [{ text: "cinco" }, { text: "seis" }, { text: "siete" }, { text: "ocho" }];
  for (const text of ["e", "f", "g", "h"]) await engine.send(text);
  const before = seen.length;
  provider.faux!.queue = [{ toolCalls: [{ name: "memory_search", arguments: { query: "x" } }] }, { text: "OBJETIVO: seguir." }];
  assert.equal(await engine.compact(), true);
  assert.equal(seen.length - before, 2);
  assert.equal(seen.at(-1)!.tools, 0);
  assert.match(seen.at(-1)!.system, /^Vas a escribir un checkpoint/);
  assert.match(engine.agent.messages[0]!.content as string, /^OBJETIVO: seguir\./);
  assert.ok(engine.db.prepare("select 1 from events where session_id=? and type='compaction.sin_cache'").get(engine.sessionId));
  engine.close();
});
