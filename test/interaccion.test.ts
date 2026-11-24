import "./datos-tmp.ts";
// Arreglos de la interacción con el operador, sacados de una sesión real: el agente se quedaba
// callado, «¿cómo vamos?» no tenía respuesta, y cargar una cuenta terminó con un token en el chat.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { absorbCredentials, identityBase } from "../src/credenciales.ts";
import { Engine, isStatusPing } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";

const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const TOKEN = "dp.pt.inventadoParaLaPrueba0000000000000000000000";

function withEngine(fn: (engine: Engine, provider: ReturnType<typeof resolveProvider>) => Promise<void>, maxSteps?: number) {
  return async () => {
    const cwd = mkdtempSync(join(tmpdir(), "cyber-inter-"));
    const provider = resolveProvider("faux");
    const engine = new Engine({ cwd, provider, budgetPico: usdToPico("2"), maxSteps, coverageObjections: 0 });
    try { await fn(engine, provider); } finally { engine.close(); rmSync(cwd, { recursive: true, force: true }); }
  };
}

test("«¿cómo vamos?» y sus variantes son pedidos de estado; un pedido de trabajo no", () => {
  for (const text of ["como vamos?", "q tañ", "q tal vamos", "que tal vas?", "?", "como vamo?", "y", "que tal?", "¿Cómo va eso?", "novedades"]) assert.ok(isStatusPing(text), text);
  for (const text of ["probá la API", "y ahora probá el login con admin", "¿qué encontraste en /v3/configs y por qué importa?"]) assert.ok(!isStatusPing(text), text);
});

test("durante un turno, «q tal» lo contesta el harness al instante; otro mensaje le pide al modelo que conteste antes de seguir", withEngine(async (engine, provider) => {
  provider.faux!.queue = [call("memory_search", { query: "a" }), { text: "listo" }];
  const reply = engine.steer("q tal");
  assert.match(reply!, /^Sigo trabajando: \d+ min en este turno, \d+ pasos, \d+ peticiones\. Sin hallazgos registrados todavía\. Ahora: .+ Gasto de la sesión: USD \d+\.\d{2} de 2\.00\./);
  assert.equal(engine.steer("pará con el login y probá la API"), undefined);
  await engine.send("seguí");
  const steered = engine.agent.messages.find((m) => m.role === "user" && String(m.content).startsWith("pará con el login"));
  assert.match(String(steered?.content), /\[sistema\] El operador te escribió mientras trabajabas: contestale en una o dos líneas antes de seguir\./);
}));

test("un turno cortado por el tope de pasos cierra con tres líneas del modelo", withEngine(async (engine, provider) => {
  provider.faux!.queue = [call("memory_search", { query: "a" }), call("memory_search", { query: "b" }), { text: "Busqué en la memoria dos veces. No encontré nada. Sigue: cargar el alcance." }];
  await engine.send("Buscá");
  assert.ok(engine.agent.messages.some((m) => m.role === "user" && String(m.content).startsWith("[sistema] El turno terminó (Límite de pasos")));
  const last = engine.agent.messages.at(-1)!;
  assert.equal(last.role, "assistant");
  assert.equal(last.content, "Busqué en la memoria dos veces. No encontré nada. Sigue: cargar el alcance.");
}, 2));

test("credenciales pegadas en el chat: quedan como identidad y no llegan al modelo", withEngine(async (engine, provider) => {
  engine.scope.edit({ include: ["dashboard.doppler.com", "api.doppler.com"] });
  provider.faux!.queue = [{ text: "Uso la identidad doppler-1." }];
  await engine.send(`te creé un personal token en doppler! ${TOKEN}`);
  assert.deepEqual(engine.http.identityNames(), ["doppler-1"]);
  const sent = JSON.stringify(engine.agent.messages);
  assert.ok(!sent.includes(TOKEN), "el modelo no ve el token");
  assert.ok(!engine.operatorTexts().join(" ").includes(TOKEN), "tampoco queda en los mensajes del operador");
  assert.match(sent, /credencial cargada como identidad doppler-1/);
  assert.match(sent, /Usalas con identity: \\"doppler-1\\"/);
  assert.equal(engine.http.authentication("doppler-1").bearer, true);
  assert.equal(engine.http.redactIdentities(`x ${TOKEN} y`).includes(TOKEN), false, "el valor queda entre los que se tachan");
}));

test("cabeceras, Bearer, JWT y un HAR pegados; un texto común queda igual", withEngine(async (engine) => {
  const http = engine.http;
  const header = absorbCredentials("usá esta:\nCookie: session=abc123def456ghi789", http, "tienda");
  assert.deepEqual(header.loaded, ["tienda-1"]);
  assert.doesNotMatch(header.text, /abc123def456/);
  const bearer = absorbCredentials("probá con Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXByb2JhZGE", http, "tienda");
  assert.equal(bearer.loaded.length, 1);
  assert.doesNotMatch(bearer.text, /eyJ/);
  const har = JSON.stringify({ log: { version: "1.2", entries: [{ request: { method: "GET", url: "https://api.doppler.com/v3/me", headers: [{ name: "Authorization", value: "Bearer secreto-del-har-123456" }], cookies: [] }, response: { status: 200 } }] } });
  const pasted = absorbCredentials(har, http, "doppler");
  assert.equal(pasted.loaded.length, 1);
  assert.match(pasted.text, /^\[El operador pegó un HAR en el chat\. Importación:\]/);
  assert.match(pasted.text, /aprobadas: las pegó el operador/);
  assert.doesNotMatch(pasted.text, /secreto-del-har/);
  assert.ok(http.identityNames().includes(pasted.loaded[0]!));
  const plain = absorbCredentials("probá el login de admin con contraseñas comunes", http, "tienda");
  assert.deepEqual(plain, { text: "probá el login de admin con contraseñas comunes", loaded: [] });
  assert.equal(identityBase("*.doppler.com"), "doppler");
  assert.equal(identityBase(undefined), "operador");
}));

test("al compactar se avisa al operador antes de pedir el resumen", withEngine(async (engine, provider) => {
  const notices: string[] = [];
  engine.onNotice = (text) => notices.push(text);
  provider.faux!.queue = [{ text: "uno" }, { text: "dos" }, { text: "tres" }, { text: "cuatro" }];
  for (const text of ["a", "b", "c", "d"]) await engine.send(text);
  provider.faux!.queue = [{ text: "OBJETIVO: probar." }];
  assert.equal(await engine.compact(), true);
  assert.match(notices[0]!, /^Resumiendo la conversación/);
}));

test("«¿cómo vamos?» dice cuánto lleva la herramienta en curso", withEngine(async (engine, provider) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  engine.agent.tools.push({ name: "escaneo", label: "Escaneo lento", description: "", parameters: { type: "object" }, execute: async () => { await gate; return { text: "fin" }; } });
  provider.faux!.queue = [call("escaneo", {}), { text: "listo" }];
  const turn = engine.send("Escaneá");
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.match(engine.steer("q tal")!, /Ahora: Escaneo lento \(lleva \d+ s\)\./);
  release();
  await turn;
  assert.doesNotMatch(engine.statusReply(), /Escaneo lento/);
}));
