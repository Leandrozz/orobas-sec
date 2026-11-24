import "./datos-tmp.ts";
// De una sesión real: 82 faltas de respuesta de 30 s (41 minutos esperando), en rachas de hasta 22
// seguidas después de ráfagas de peticiones. Un host que deja de responder se pausa y después se
// lo trata más despacio; no se sigue mandando ni esperando.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { HOST_TRIP } from "../src/http.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";

test("un host que deja de responder se pausa: no se sigue mandando ni esperando", async () => {
  let hang = false;
  const hits: string[] = [];
  const open = new Set<import("node:net").Socket>();
  const server = createServer((req, res) => {
    hits.push(req.url!);
    if (hang) return; // el backend frena: no contesta
    res.writeHead(200, { "content-type": "application/json" }).end('{"ok":true}');
  });
  server.on("connection", (socket) => { open.add(socket); socket.on("close", () => open.delete(socket)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-frenado-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), budgetPico: usdToPico("1") });
  const tool = (name: string) => engine.agent.tools.find((item) => item.name === name)!;
  try {
    engine.scope.edit({ include: [`${base}/`] });
    assert.equal((await engine.http.send({ url: `${base}/a` })).response?.status, 200);
    hang = true;
    const first = await engine.http.send({ url: `${base}/b`, timeoutMs: 80 });
    assert.match(first.error!, /Tiempo de espera agotado \(0 s\): sin respuesta en ese tiempo\. Puede ser un backend lento: reintentá una vez con timeoutSec más alto/);
    for (let i = 1; i < HOST_TRIP; i++) await engine.http.send({ url: `${base}/c${i}`, timeoutMs: 80 });
    const sent = hits.length;
    // Ya en pausa: un sondeo de veinte rutas no manda ninguna y vuelve enseguida.
    const started = Date.now();
    const probe = await tool("http_probe").execute({ urls: Array.from({ length: 20 }, (_, i) => `${base}/r${i}`), timeoutSec: 30 }, new AbortController().signal);
    assert.ok(Date.now() - started < 1500, "no espera");
    assert.equal(hits.length, sent, "no envía");
    assert.match(probe.text, /dejó de responder \(3 sin respuesta seguidas\) y está en pausa \d+ s más: no se envía\. Casi seguro nos está frenando/);
    assert.deepEqual(engine.http.cooling().map((item) => item.host), [new URL(base).host]);
    assert.match(engine.statusReply(), /en pausa \d+ s \(dejó de responder\)/);
  } finally {
    engine.close();
    for (const socket of open) socket.destroy();
    server.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("cobertura: tras dos rechazos iguales se ofrece «limitada», que cierra la categoría diciendo qué faltó", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-limitada-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), budgetPico: usdToPico("1") });
  try {
    const mark = (state: "cubierta" | "limitada") => engine.coverage.mark(engine.sessionId, "reconocimiento", state, "mapeé lo que respondía");
    assert.throws(() => mark("cubierta"), (error: Error) => /No se marca «reconocimiento»/.test(error.message) && !/limitada/.test(error.message));
    assert.throws(() => mark("cubierta"), /Ya van 2 rechazos\. Si eso no se puede conseguir.*marcala «limitada»/s);
    assert.equal(mark("limitada").state, "limitada");
    assert.ok(!engine.coverage.pending(engine.sessionId).includes("reconocimiento"));
  } finally {
    engine.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
