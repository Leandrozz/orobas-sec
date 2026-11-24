import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import type { AgentEvent } from "../src/agent.ts";
import { resolveProvider } from "../src/providers.ts";

const tick = (ms = 20) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};

test("subagente: su texto llega en vivo con worker y no entra en partial", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-subtxt-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new" });
    const events: AgentEvent[] = [];
    client.on((e) => e.type === "text" && events.push(e));
    provider.faux!.queue = [
      { toolCalls: [{ name: "delegate", arguments: { objective: "x" } }] },
      { text: "texto del sub" },
      { text: "texto principal" },
    ];
    const host = [...daemon.hosts.values()][0]!;
    assert.ok(host, "hay un host");
    let vistos = 0;
    const filtrado: string[] = []; // un assert dentro del oyente se lo tragaría el agente: se acumula y se afirma abajo
    // Corre síncrono después del oyente del Host: partial y snapshot ya reflejan este texto.
    host.engine.agent.on((e) => {
      if (e.type !== "text" || !e.worker) return;
      vistos++;
      if (host.partial.includes("texto del sub")) filtrado.push("partial");
      if (host.snapshot().partial.includes("texto del sub")) filtrado.push("snapshot");
    });
    client.send("hola");
    await until(() => events.some((e) => e.type === "text" && !e.worker && e.delta.includes("principal")));
    const sub = events.filter((e) => e.type === "text" && e.worker);
    assert.ok(sub.length > 0 && sub.every((e) => e.type === "text" && e.worker!.startsWith("sub:")));
    assert.match(sub.map((e) => (e as any).delta).join(""), /texto del sub/);
    assert.deepEqual(filtrado, [], "partial y snapshot sin texto del subagente");
    assert.ok(vistos > 0, "el oyente vio texto de subagente");
    const main = events.filter((e) => e.type === "text" && !e.worker).map((e) => (e as any).delta).join("");
    assert.equal(main, "texto principal");
    client.close();
  } finally { daemon.close(); }
});
