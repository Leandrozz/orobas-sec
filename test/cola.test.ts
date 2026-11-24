import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};

test("lo que el operador escribe durante un turno se encola y sale junto como el turno siguiente; «!» interrumpe", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-cola-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new" });
    const answers: string[] = [];
    client.on((event) => { if (event.type === "answer") answers.push(event.text); });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const host = [...daemon.hosts.values()][0]!;
    host.engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
    provider.faux!.queue = [
      { text: "Arranco.\n", toolCalls: [{ name: "esperar", arguments: {} }] },
      { text: "Terminé el primero." },
      { text: "Atiendo lo encolado." },
    ];
    client.send("Trabajá en esto");
    await until(() => host.engine.agent.running);
    client.send("segundo pedido");
    client.send("tercer pedido");
    await until(() => client.status.queued === 2);
    assert.equal(host.engine.queue.length, 2);
    // «¿cómo vamos?» se contesta en el acto y no entra en la cola.
    client.send("¿cómo vamos?");
    await until(() => answers.length === 1);
    assert.match(answers[0]!, /Sigo trabajando/);
    assert.equal(host.engine.queue.length, 2);
    const listed = await client.ask("queue", { action: "list" });
    assert.match(listed[0]!, /2 mensajes en cola/);
    assert.match(listed[2]!, /tercer pedido/);
    release();
    await until(() => !host.engine.agent.running && host.engine.queue.length === 0 && client.status.queued === 0, 6000);
    const users = host.engine.agent.messages.filter((message) => message.role === "user").map((message) => (message as { content: string }).content);
    assert.equal(users.length, 2, "dos turnos: el original y el de la cola");
    assert.match(users[1]!, /^segundo pedido\n\ntercer pedido/);
    // Vaciar la cola.
    assert.match((await client.ask("queue", { action: "clear" }))[0]!, /ya estaba vacía/);
    client.close();
  } finally {
    daemon.close();
  }
});
