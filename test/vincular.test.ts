import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { accountMenu } from "../src/menu.ts";
import { resolveProvider } from "../src/providers.ts";
import { readSecret } from "../src/secretos.ts";
import { waitDeviceKey } from "../src/vincular.ts";

const KEY = `oro_${"b".repeat(48)}`;

test("vincular por el sitio: el código se muestra, la clave llega al aprobar y queda guardada", async () => {
  let polls = 0;
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      if (req.url === "/dispositivo") {
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ device_code: "d".repeat(48), user_code: "BCDF-GHJK", verification_uri: "http://sitio.test/vincular", verification_uri_complete: "http://sitio.test/vincular?codigo=BCDF-GHJK", expires_in: 60, interval: 0 }));
      } else if (req.url === "/dispositivo/clave") {
        polls++;
        assert.equal(JSON.parse(raw).device_code, "d".repeat(48));
        if (polls < 3) res.writeHead(428, { "content-type": "application/json" }).end('{"error":{"code":"authorization_pending"}}');
        else res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ api_key: KEY, name: "Ana", verification: "basica" }));
      } else res.writeHead(404).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const savedBase = process.env.OROBAS_BASE_URL;
  const savedKey = process.env.OROBAS_API_KEY;
  process.env.OROBAS_BASE_URL = `http://127.0.0.1:${port}`;
  delete process.env.OROBAS_API_KEY;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-vincular-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new" });
    const shown: string[][] = [];
    // Menú de orobas sin vincular: primera opción, entrar por el sitio.
    const lines = await accountMenu("orobas", {
      ask: (op, payload) => client.ask(op, payload),
      pick: async (_title, options) => { assert.match(options[0]!, /Entrar por el sitio/); return 0; },
      askHidden: async () => undefined,
      notice: (text) => shown.push(text),
    });
    assert.equal(shown.length, 1);
    assert.match(shown[0]![0]!, /http:\/\/sitio\.test\/vincular\?codigo=BCDF-GHJK/);
    assert.match(shown[0]![1]!, /Código: BCDF-GHJK/);
    assert.match(lines[0]!, /^Vinculado como Ana: clave nueva guardada.*…bbbb/);
    assert.equal(readSecret("orobas"), KEY);
    assert.equal(polls, 3, "esperó hasta la aprobación");
    const status = await client.ask("account", { service: "orobas", action: "status" });
    assert.match(status[0]!, /termina en …bbbb/);
    client.close();
  } finally {
    daemon.close();
    server.close();
    if (savedBase === undefined) delete process.env.OROBAS_BASE_URL; else process.env.OROBAS_BASE_URL = savedBase;
    if (savedKey !== undefined) process.env.OROBAS_API_KEY = savedKey;
  }
});

test("la espera entiende rechazo, vencimiento y falta de cupo, y se cancela", async () => {
  const start = { device_code: "x".repeat(48), user_code: "AAAA-BBBB", verification_uri: "u", verification_uri_complete: "u", expires_in: 60, interval: 0 };
  const answer = (status: number) => (async () => new Response("{}", { status })) as unknown as typeof fetch;
  const noSleep = async () => {};
  assert.equal((await waitDeviceKey(start, { fetchImpl: answer(403), sleep: noSleep })).state, "denegado");
  assert.equal((await waitDeviceKey(start, { fetchImpl: answer(410), sleep: noSleep })).state, "vencido");
  assert.equal((await waitDeviceKey(start, { fetchImpl: answer(409), sleep: noSleep })).state, "sin_cupo");
  const controller = new AbortController();
  controller.abort();
  assert.equal((await waitDeviceKey(start, { fetchImpl: answer(428), sleep: noSleep, signal: controller.signal })).state, "cancelado");
  assert.equal((await waitDeviceKey({ ...start, expires_in: 0 }, { fetchImpl: answer(428), sleep: noSleep })).state, "vencido");
});
