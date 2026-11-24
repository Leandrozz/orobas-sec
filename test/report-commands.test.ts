import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";

test("comandos: HAR pendiente, aprobación por identity e informe del daemon y CLI sin proveedor", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-comandos-"));
  const received: Array<string | undefined> = [];
  const server = createServer((request, response) => {
    received.push(request.headers.authorization);
    response.writeHead(200, { "content-type": "application/json" }).end('{"owner":2}');
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), autoResume: false });
  await daemon.listen();
  const client = await connectDaemon(cwd, { spawn: false });
  try {
    const snapshot = await client.attach({ model: "faux" });
    const engine = daemon.hosts.get(snapshot.sessionId)!.engine;
    await client.view("scope", `add ${base}`);
    for (const name of ["har_import", "postman_import", "openapi_import"]) assert.ok(engine.catalog.available.has(name));
    const source = engine.artifacts.put(JSON.stringify({ log: { version: "1.2", entries: [{ request: { method: "GET", url: `${base}/items/2`, headers: [{ name: "Authorization", value: "Bearer comando-secreto" }] } }] } }), "application/json", "fixture");
    const result = await engine.catalog.available.get("har_import")!.execute({ artifact: source.hash }, new AbortController().signal);
    assert.equal(received.length, 0);
    assert.equal(engine.http.count, 0);
    assert.deepEqual(engine.http.identityNames(), []);
    assert.doesNotMatch(result.text, /comando-secreto/);
    const pending = engine.http.proposedIdentities()[0]!;
    const listed = (await client.ask("identity")).join("\n");
    assert.ok(listed.includes(pending.name));
    assert.doesNotMatch(listed, /comando-secreto/);
    await assert.rejects(client.ask("identity", { value: "aprobar inexistente" }), /No existe/);
    await client.ask("identity", { value: `aprobar ${pending.name}` });
    assert.deepEqual(engine.http.identityNames(), [pending.name]);
    assert.deepEqual(engine.http.proposedIdentities(), []);
    const exchange = await engine.http.send({ url: `${base}/items/2` }, pending.name);
    assert.deepEqual(received, ["Bearer comando-secreto"]);
    engine.findings.record({ title: "Lectura entre cuentas", kind: "control de acceso", asset: `${base}/items/2`, summary: "El recurso pertenece a la otra cuenta de prueba.", evidence: [exchange.artifact], severity: "alta" }, engine.sessionId);
    const output = await client.view("informe");
    const path = output[0]!.replace("Informe guardado en ", "");
    const markdown = readFileSync(path, "utf8");
    assert.match(markdown, /Lectura entre cuentas/);
    assert.ok(markdown.includes(`<identidad ${pending.name}>`));
    assert.doesNotMatch(markdown, /comando-secreto/);
    // Versión en inglés por la vista del daemon (lo que usan /informe en y cyber informe en) y por la herramienta del agente.
    const english = await client.view("informe", "en");
    assert.match(english[0]!, /^Informe en inglés guardado en .*-en\.md$/);
    const englishMarkdown = readFileSync(english[0]!.replace("Informe en inglés guardado en ", ""), "utf8");
    assert.match(englishMarkdown, /^# Security assessment report/);
    assert.match(englishMarkdown, /Lectura entre cuentas/);
    assert.ok(englishMarkdown.includes(`<identity ${pending.name}>`));
    assert.doesNotMatch(englishMarkdown, /comando-secreto|<identidad /);
    await assert.rejects(client.view("informe", "fr"), /Uso: \/informe \[en\]/);
    const tool = await engine.catalog.available.get("report_generate")!.execute({ idioma: "en" }, new AbortController().signal);
    assert.match(tool.text, /^Informe en inglés guardado en .*-en(?:-\d+)?\.md\nArtefacto: sha256:/);
    assert.deepEqual(tool.details, { idioma: "en" });
    const cli = await promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", new URL("../src/cli.ts", import.meta.url).pathname, "-C", cwd, "informe"]);
    assert.match(cli.stdout, /Informe guardado en .*cyber-informes\/.*\.md\nArtefacto: sha256:/);
    assert.equal(received.length, 1, "ningún informe vuelve a consultar el objetivo");
    assert.equal(engine.ledger.totals().requests, 0, "el comando no llama al proveedor");
  } finally {
    client.close();
    daemon.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(cwd, { recursive: true, force: true });
  }
});
