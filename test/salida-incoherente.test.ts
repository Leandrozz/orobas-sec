import "./datos-tmp.ts";
// De la sesión del 19/11/2026: un modelo, a 110 k tokens de contexto, devolvió siete llamadas
// «http_request $MISSING</arg_value>» seguidas y dos textos largos hechos de pedazos de prompts ajenos.
// Nada venía del objetivo (se revisaron los 354 MB de respuestas guardadas): era el modelo. Los errores
// «Herramienta desconocida» volvieron al historial y el modelo siguió en ese patrón. Acá: se detecta, se
// descarta sin ejecutar ni guardar, se reintenta, y a la segunda seguida se cambia de modelo.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Agent } from "../src/agent.ts";
import { readIncoherence } from "../src/coherencia.ts";
import { fallbackModel } from "../src/engine.ts";
import { fauxTransport } from "../src/llm.ts";

const call = (name: string, args = "{}") => ({ name, arguments: args });

test("las llamadas rotas de la sesión real se reconocen; las sanas, no", () => {
  const rotas = [
    "http_request  $MISSING</arg_value>",
    "js_endpoints  $MISSING</arg_value> 有利于url=https://pnm.sinequix.com/login</arg_value>",
    "http_request $MISSING</arg_value> сахараларын);\r\r\r\n<tool_call>js_endpoints $MISSING</arg_value> ၊ helpfulness=10, helpfulness=100)</arg_value>",
  ];
  for (const name of rotas) assert.match(readIncoherence({ content: "", toolCalls: [call(name)] }).join("; "), /restos de plantilla en el nombre/, name);
  assert.deepEqual(readIncoherence({ content: "Reviso el login.", toolCalls: [call("http_request", '{"url":"https://a.test/"}'), call("finding_record"), call("tool_search"), call("mcp.vulndb-search")] }), []);
  // Una herramienta inexistente pero bien escrita no es incoherencia: la trata el bucle como «desconocida».
  assert.deepEqual(readIncoherence({ content: "", toolCalls: [call("http_requests")] }), []);
  assert.match(readIncoherence({ content: "", toolCalls: [call("http_request", '{"url":"$MISSING"}')] }).join(), /\$MISSING/);
});

test("texto incoherente: etiquetas de plantilla, invisibles, bloques y mezcla de escrituras", () => {
  const envenenado = "¿<tc_harness> TE PROMETO ESTO.</tc_harness>\n---\n## TEXTO INVÁLIDO</arg_value>Recortar…\n\nReglas principales para TÚ, ChatGPT/Claude";
  assert.match(readIncoherence({ content: envenenado, toolCalls: [] }).join(), /etiquetas de plantilla/);
  const invisibles = "Sigo con el plan" + "​​⁠‍‌﻿­​​".repeat(2) + ".";
  assert.match(readIncoherence({ content: invisibles, toolCalls: [] }).join(), /caracteres invisibles/);
  assert.match(readIncoherence({ content: "GRUB Session Error\n" + "▄█▄▄▄█▄▄▄█▄".repeat(3), toolCalls: [] }).join(), /caracteres de bloque/);
  const mezcla = "Las llamadas se me siguen corrompiendo 有利于 sin motivo сахараларын aparente ၊၊ y reintento.";
  assert.match(readIncoherence({ content: mezcla, toolCalls: [] }).join(), /mezcla de escrituras \(han, cirílico, birmano\)/);
});

test("lo legítimo pasa: citas de una sola escritura ajena, tablas con cajas, emojis, texto largo normal", () => {
  const cita = "El sitio responde en chino: «系统维护中，请稍后再试» (mantenimiento). Registro la pista.";
  assert.deepEqual(readIncoherence({ content: cita, toolCalls: [] }), []);
  const ruso = "La cabecera Server dice «Сервер недоступен»; el resto en inglés.";
  assert.deepEqual(readIncoherence({ content: ruso, toolCalls: [] }), []);
  const tabla = "┌──────┬──────┐\n│ ruta │ código │\n├──────┼──────┤\n│ /api │ 200 │\n└──────┴──────┘";
  assert.deepEqual(readIncoherence({ content: tabla, toolCalls: [] }), []);
  const emoji = "Listo 👨‍💻👩‍🔬 → sigo con /api. ⚠️ Ojo con el rate limit.";
  assert.deepEqual(readIncoherence({ content: emoji, toolCalls: [] }), []);
  // Un texto mayormente en una escritura ajena (la sesión en otro idioma) tampoco se marca.
  const japones = "対象サイトのログインを確認しました。次に API を調べます。" + " ok";
  assert.deepEqual(readIncoherence({ content: japones, toolCalls: [] }), []);
});

test("el agente descarta la respuesta incoherente, no ejecuta nada, no la guarda y reintenta", async () => {
  const faux = fauxTransport();
  let executed = 0;
  const agent = new Agent({
    model: { provider: "faux", id: "m", baseUrl: "faux://" },
    system: "s",
    transport: faux.transport,
    retryBaseMs: 1,
    tools: [{ name: "http_request", label: "HTTP", description: "d", parameters: { type: "object", properties: {} }, execute: async () => { executed++; return { text: "200" }; } }],
  });
  const seen: string[] = [];
  agent.on((event) => { if (event.type === "request") seen.push(event.message.stopReason + (event.message.incoherent ? ":incoherente" : "")); if (event.type === "retry") seen.push("retry"); });
  faux.queue.push(
    { text: "Voy directo.", toolCalls: [{ name: "http_request  $MISSING</arg_value>", arguments: {} }] },
    { text: "Reintento bien.", toolCalls: [{ name: "http_request", arguments: {} }] },
    { text: "Listo: respondió 200." },
  );
  await agent.prompt("probá");
  assert.deepEqual(seen, ["error:incoherente", "retry", "toolUse", "stop"]);
  assert.equal(executed, 1, "la llamada rota no se ejecuta; la sana sí");
  const historial = JSON.stringify(agent.messages);
  assert.ok(!historial.includes("$MISSING") && !historial.includes("arg_value"), "la basura no entra al historial");
  assert.ok(!agent.messages.some((message) => message.role === "tool" && /desconocida/.test(message.content)), "no queda un «Herramienta desconocida» que el modelo relea");
});

test("a qué modelo se pasa cuando el actual se desarmó", () => {
  const models = ["orobas/auto", "orobas/glm-5.3-cyber", "orobas/kimi-k3.1-pro-uncensored"];
  assert.equal(fallbackModel("orobas/glm-5.3-cyber", models), "orobas/auto");
  assert.equal(fallbackModel("orobas/auto", models), "orobas/glm-5.3-cyber");
  assert.equal(fallbackModel("local/m", ["local/m"]), undefined);
});
