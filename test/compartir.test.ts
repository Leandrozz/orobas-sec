import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
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

test("datos: el modo se elige, «subir» manda las sesiones anteriores anónimas sólo en compartir, y revocar es «no»", async () => {
  const received: Array<{ path: string; auth: string | undefined; trazas: string | undefined; body: any }> = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      received.push({ path: req.url ?? "", auth: req.headers.authorization, trazas: req.headers["x-cyber-trazas"] as string | undefined, body: raw ? JSON.parse(raw) : null });
      res.writeHead(req.url === "/cuenta" ? 404 : 204).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const saved = { base: process.env.OROBAS_BASE_URL, key: process.env.OROBAS_API_KEY, trazas: process.env.CYBER_TRAZAS };
  process.env.OROBAS_BASE_URL = `http://127.0.0.1:${port}`;
  process.env.OROBAS_API_KEY = `oro_${"a".repeat(48)}`;
  delete process.env.CYBER_TRAZAS;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-compartir-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new" });
    const host = [...daemon.hosts.values()][0]!;
    host.engine.scope.edit({ include: ["api.cliente.test"] });
    provider.faux!.queue = [{ text: "Nada que reportar en api.cliente.test." }];
    client.send("Mirá api.cliente.test");
    await until(() => !host.engine.agent.running && host.engine.agent.messages.length >= 2);

    const status = await client.ask("datos", { action: "status" });
    assert.match(status[0]!, /elegido: no \(por defecto\)\. Rige: no/);
    assert.ok(!received.some((r) => r.path === "/trayectorias" || r.path === "/consent"), "sin elegir nada, no sale ni trayectoria ni consentimiento");

    // En «local» no se sube nada, ni a pedido.
    assert.match((await client.ask("datos", { action: "modo", value: "local" }))[0]!, /Trazas: «local»/);
    const antes = received.length;
    await assert.rejects(client.ask("datos", { action: "share" }), /están en «local»/);
    assert.ok(!received.slice(antes).some((r) => r.path === "/trayectorias"), "en local no sale ninguna trayectoria");

    // Elegir «compartir» a mano queda registrado en el servicio y deja subir lo anterior, anónimo.
    await client.ask("datos", { action: "modo", value: "compartir" });
    const consent = received.find((r) => r.path === "/consent")!;
    assert.equal(consent.body.kind, "trayectorias");
    assert.match(consent.auth!, /^Bearer oro_a/);
    const shared = await client.ask("datos", { action: "share" });
    assert.match(shared[0]!, /^Subidas 1 de 1 sesiones/);
    const upload = received.find((r) => r.path === "/trayectorias")!;
    assert.equal(upload.trazas, "compartir");
    assert.equal(upload.body.consent, consent.body.hash);
    assert.equal(upload.body.session, host.engine.sessionId);
    assert.deepEqual(upload.body.record.scope.include, ["host-1"]);
    assert.doesNotMatch(JSON.stringify(upload.body.record), /api\.cliente\.test/);

    // «revocar» (el nombre de antes) deja el modo en «no».
    assert.match((await client.ask("datos", { action: "revoke" }))[0]!, /Trazas: «no»/);
    assert.match((await client.ask("datos", { action: "status" }))[0]!, /elegido: no \(en la configuración\)/);
    await assert.rejects(client.ask("datos", { action: "modo", value: "talvez" }), /compartir, local o no/);
    assert.ok(received.every((r) => typeof r.trazas === "string"), "todo pedido al servicio lleva el modo");
    client.close();
  } finally {
    daemon.close();
    server.close();
    if (saved.base === undefined) delete process.env.OROBAS_BASE_URL; else process.env.OROBAS_BASE_URL = saved.base;
    if (saved.key === undefined) delete process.env.OROBAS_API_KEY; else process.env.OROBAS_API_KEY = saved.key;
    if (saved.trazas === undefined) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = saved.trazas;
  }
});
