import "./datos-tmp.ts";
// Amnesia tras compactar (reporte de Nico, 22/11): la compactación resumía los mensajes del operador junto con el
// resto, y si caía a mitad de un turno largo el pedido en curso quedaba sólo en el resumen del modelo. En las
// trazas locales, 62 de 79 compactaciones resumieron el pedido en curso y las 79 el encargo inicial; de 1.285
// mensajes del operador compactados, 111 sobrevivían textuales. Ahora el checkpoint los lleva textuales.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { instruccionesDelOperador, TOPE_MENSAJE, TOPE_TOTAL, textoDelOperador } from "../src/instrucciones.ts";
import type { Message } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";

const ENCARGO = "Evaluá app.test, pero sólo /api/v2: no toques /admin ni mandes más de 2 peticiones por segundo.";
const CORRECCION = "Corrijo: la identidad para las escrituras es comprador-2, no comprador-1.";

test("una compactación a mitad de turno conserva textuales el encargo y la corrección en curso", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-amnesia-")), provider });
  const sent: Message[][] = [];
  const original = provider.transport;
  engine.provider = { ...engine.provider, transport: async (request) => (request.tags?.worker === "principal" && sent.push(request.messages), original(request)) };
  provider.faux!.queue = [{ text: "Arranco por /api/v2." }];
  await engine.send(ENCARGO);
  // La corrección inicia un turno largo; al cuarto paso el contexto «pasa» el umbral y se compacta a mitad de turno,
  // con la corrección fuera de los 6 mensajes recientes que se conservan.
  let n = 0;
  engine.agent.tools.push(engine.bounded({ name: "paso", label: "Paso", description: "", parameters: { type: "object" }, execute: () => {
    n++;
    engine.compactAt = n === 4 ? 1 : 1e9;
    return { text: `paso ${n}` };
  } }));
  const paso = { toolCalls: [{ name: "paso", arguments: {} }] };
  provider.faux!.queue = [paso, paso, paso, paso, { text: "OBJETIVO: revisar la API.\nPENDIENTE: seguir." }, paso, paso, { text: "Listo." }];
  await engine.send(CORRECCION);
  assert.equal(engine.compactions, 1, "hubo una compactación a mitad de turno");
  const checkpoint = engine.agent.messages[0]!;
  assert.equal(checkpoint.role, "checkpoint");
  const despues = JSON.stringify(sent.at(-1));
  for (const texto of [ENCARGO, CORRECCION]) {
    assert.ok(checkpoint.content.includes(texto), `el checkpoint lleva textual: ${texto}`);
    assert.ok(despues.includes(JSON.stringify(texto).slice(1, -1)), "y viaja en el pedido siguiente");
  }
  assert.ok(checkpoint.content.indexOf(ENCARGO) < checkpoint.content.indexOf(CORRECCION), "en orden");
  engine.close();
});

test("del mensaje guardado queda lo que escribió el operador, sin los bloques que agrega el harness", () => {
  assert.equal(textoDelOperador(`${ENCARGO}\n\n<alcance>\nincluye app.test\n</alcance>\n\n<memoria>\nx\n</memoria>`), ENCARGO);
  assert.equal(textoDelOperador(`${CORRECCION}\n\n[sistema] El operador te escribió mientras trabajabas: contestale.`), CORRECCION);
  assert.equal(textoDelOperador("[sistema] Van 40 peticiones sin registrar ningún hallazgo."), undefined);
  assert.equal(textoDelOperador("mirá esto\n\n<terminal>\n$ id\nuid=0\n</terminal>"), "mirá esto\n\n<terminal>\n$ id\nuid=0\n</terminal>", "lo que pegó de su terminal es suyo");
});

test("un pegado largo queda con su comienzo y un puntero; si no entra todo, el encargo y lo último, y el resto con puntero", () => {
  const guardados: string[] = [];
  const guardar = (texto: string) => (guardados.push(texto), `sha256:${String(guardados.length).repeat(64).slice(0, 64)}`);
  const pegado = `Leé esta política:\n${"regla ".repeat(2000)}`;
  const uno = instruccionesDelOperador([ENCARGO, pegado], guardar);
  assert.ok(uno.includes(ENCARGO));
  assert.ok(uno.includes("Leé esta política:"));
  assert.ok(uno.length < TOPE_MENSAJE + ENCARGO.length + 400);
  assert.equal(guardados[0], pegado);
  const muchos = Array.from({ length: 200 }, (_, i) => `corrección número ${i}: ${"detalle ".repeat(10)}`);
  const todo = instruccionesDelOperador([ENCARGO, ...muchos], guardar);
  assert.ok(todo.length <= TOPE_TOTAL + 600);
  assert.ok(todo.includes(ENCARGO), "el encargo inicial siempre");
  assert.ok(todo.includes("corrección número 199:"), "lo último siempre");
  assert.match(todo, /mensajes intermedios del operador, completos en sha256:/);
  assert.ok(guardados.at(-1)!.includes("corrección número 0:"), "lo del medio queda guardado entero");
  assert.equal(instruccionesDelOperador([], guardar), "");
});

test("los bloques que agregan el verificador (<verificacion>) y la pregunta por el gasto (<gasto>, #41) tampoco son del operador", () => {
  assert.equal(textoDelOperador(`¿Cuánto llevamos gastado?\n\n<gasto>\nSesión: USD 0,46\n</gasto>`), "¿Cuánto llevamos gastado?");
  assert.equal(textoDelOperador(`${CORRECCION}\n\n<verificacion>\nh-12: verificado\n</verificacion>\n\n<memoria>\nx\n</memoria>`), CORRECCION);
});
