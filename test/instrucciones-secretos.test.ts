import "./datos-tmp.ts";
// La compactación conserva textuales los mensajes del operador (#38, src/instrucciones.ts) y los secretos del
// operador viajan tapados (#39, src/secretos-sesion.ts). El checkpoint se aprende como texto de un modelo («sin
// clase»), así que lo que lo mantiene tapado es la clase que ya tenía el secreto: tiene que valer en el pedido
// siguiente a la compactación y también al retomar la sesión en otro proceso.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import type { LlmRequest, Message } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";

const CLAVE = "Sup3rClaveDelOperador-91xQ";
const ENCARGO = `Evaluá app.test con mi cuenta: usuario ana, password=${CLAVE}. Sólo /api/v2.`;
const CORRECCION = "Corrijo: no toques /admin.";

function espiar(engine: Engine, provider: ReturnType<typeof resolveProvider>): LlmRequest[] {
  const enviados: LlmRequest[] = [];
  const original = provider.transport;
  engine.provider = { ...engine.provider, transport: async (request) => (enviados.push(request), original(request)) };
  return enviados;
}

test("las instrucciones conservadas en el checkpoint llevan tapado el secreto del operador, también al retomar", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-instrucciones-secretos-"));
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider });
  const enviados = espiar(engine, provider);
  provider.faux!.queue = [{ text: "Arranco por /api/v2." }];
  await engine.send(ENCARGO);
  let n = 0;
  engine.agent.tools.push(engine.bounded({ name: "paso", label: "Paso", description: "", parameters: { type: "object" }, execute: () => {
    n++;
    engine.compactAt = n === 4 ? 1 : 1e9;
    return { text: `paso ${n}` };
  } }));
  const paso = { toolCalls: [{ name: "paso", arguments: {} }] };
  provider.faux!.queue = [paso, paso, paso, paso, { text: "OBJETIVO: revisar la API.\nPENDIENTE: seguir." }, paso, paso, { text: "Listo." }];
  await engine.send(CORRECCION);
  assert.equal(engine.compactions, 1, "hubo una compactación");
  const checkpoint = engine.agent.messages[0]!;
  assert.equal(checkpoint.role, "checkpoint");
  assert.ok(checkpoint.content.includes(ENCARGO), "el checkpoint guarda el encargo textual (la sesión guarda lo que pasó)");

  const despues = enviados.filter((request) => request.messages[0]?.role === "checkpoint");
  assert.ok(despues.length >= 1, "hubo pedidos con el checkpoint");
  for (const request of enviados) assert.ok(!JSON.stringify(request).includes(CLAVE), "ningún pedido lleva la clave del operador");
  const enCheckpoint = (request: LlmRequest) => (request.messages[0] as Message & { content: string }).content;
  assert.match(enCheckpoint(despues.at(-1)!), /usuario ana, password=‹SECRETO_\d+›\.? Sólo \/api\/v2\./, "el encargo viaja textual, con la clave tapada");
  assert.ok(enCheckpoint(despues.at(-1)!).includes(CORRECCION));
  engine.close();

  // Otro proceso retoma la sesión: el mensaje original ya no está en la conversación, sólo el checkpoint.
  const provider2 = resolveProvider("faux");
  const retomado = new Engine({ cwd, provider: provider2, resume: engine.sessionId });
  const enviados2 = espiar(retomado, provider2);
  assert.equal(retomado.agent.messages[0]?.role, "checkpoint");
  provider2.faux!.queue = [{ text: "Sigo." }];
  await retomado.send("Seguí.");
  assert.ok(enviados2.length >= 1);
  for (const request of enviados2) assert.ok(!JSON.stringify(request).includes(CLAVE), "al retomar, tampoco");
  assert.match(enCheckpoint(enviados2[0]!), /password=‹SECRETO_\d+›/, "el mismo encargo, con la clave tapada");
  retomado.close();
});
