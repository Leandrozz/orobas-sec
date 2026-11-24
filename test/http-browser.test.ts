import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { HttpClient } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

// Decisión de Lean del 22/11: el navegador tapa lo que cargó el operador (su identidad) y deja a la vista lo que
// fijó el objetivo (sus cookies): es material del objetivo, el modelo lo ve y las trazas lo tapan aparte.
test("HTTP para navegador: conserva bytes, tapa lo del operador, deja a la vista las cookies del objetivo y aplica límites antes de enviar", async () => {
  let received = 0;
  const binary = Buffer.from([0, 255, 128, 1, 2, 3]);
  const server = createServer((req, res) => {
    received++;
    if (req.url === "/binary") {
      res.setHeader("content-type", "image/png");
      res.end(binary);
    } else if (req.url === "/slow") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("inicio");
    } else if (req.url === "/redirect") {
      res.writeHead(302, { location: "/blocked" });
      res.end();
    } else if (req.url === "/large") {
      res.end("x".repeat(1024));
    } else {
      res.setHeader("content-type", "application/json");
      res.setHeader("set-cookie", ["sesion=nueva-secreta; HttpOnly", "otra=segunda-secreta; Path=/"]);
      res.end(JSON.stringify({ authorization: req.headers.authorization, cookie: req.headers.cookie }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-http-browser-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(base)], exclude: [parseRule(`${base}/blocked`)] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "ana", headers: { Authorization: "Bearer token-secreto", Cookie: "sesion=cookie-secreta" } });
  try {
    const headers = http.identityHeaders("ana");
    headers.Authorization = "alterada";
    assert.equal(http.identityHeaders("ana").Authorization, "Bearer token-secreto");
    assert.throws(() => http.identityHeaders("inexistente"), /No existe la identidad/);
    const echoed = await http.forward({ url: base }, "ana");
    assert.match(echoed.body.toString(), /token-secreto/);
    assert.match(echoed.rawHeaders["set-cookie"]!, /nueva-secreta.*\n.*segunda-secreta/);
    assert.doesNotMatch(JSON.stringify(echoed.exchange), /token-secreto|cookie-secreta/, "lo del operador, tapado");
    assert.doesNotMatch(artifacts.read(echoed.exchange.artifact).toString(), /token-secreto|cookie-secreta/);
    assert.match(JSON.stringify(echoed.exchange.response?.headers), /nueva-secreta[\s\S]*segunda-secreta/, "lo que fijó el objetivo, a la vista");
    assert.match(artifacts.read(echoed.exchange.artifact).toString(), /nueva-secreta/);
    assert.equal(http.redact("token-secreto nueva-secreta segunda-secreta"), "<credencial> nueva-secreta segunda-secreta");
    // Para el registro de la sesión: lo de la identidad es del operador; lo que fijó el objetivo, del objetivo.
    const clases = (valor: string) => [...new Set(http.sensitiveValues().filter(({ value }) => value === valor).map(({ kind }) => kind))].sort();
    assert.deepEqual(clases("token-secreto"), ["cookie", "identidad"], "nunca del objetivo");
    assert.deepEqual(clases("cookie-secreta"), ["cookie"]);
    assert.deepEqual(clases("nueva-secreta"), ["objetivo"]);
    assert.deepEqual(clases("segunda-secreta"), ["objetivo"]);
    const bytes = await http.forward({ url: `${base}/binary` });
    assert.deepEqual(bytes.body, binary);
    assert.equal(bytes.exchange.response?.bodyEncoding, "base64");
    assert.deepEqual(Buffer.from(bytes.exchange.response!.body, "base64"), binary);
    const large = await http.forward({ url: `${base}/large`, maxBodyBytes: 32 });
    assert.match(large.exchange.error!, /supera el tope/);
    assert.equal(large.exchange.response?.truncated, true);
    assert.equal(large.body.length, 0);
    const slow = await http.forward({ url: `${base}/slow`, timeoutMs: 30 });
    assert.match(slow.exchange.error!, /Tiempo de espera agotado/);
    assert.equal(slow.body.length, 0);
    const redirect = await http.forward({ url: `${base}/redirect`, followRedirects: true });
    assert.equal(redirect.exchange.response?.status, 302);
    assert.deepEqual(redirect.exchange.redirects, []);
    const before = received;
    const blocked = await http.forward({ url: `${base}/blocked` });
    assert.match(blocked.exchange.error!, /Fuera del alcance/);
    assert.equal(received, before);
    http.limit = http.count + 1;
    const concurrent = await Promise.all([http.forward({ url: base }), http.forward({ url: base })]);
    assert.equal(concurrent.filter((item) => item.exchange.error?.includes("Tope de peticiones")).length, 1);
    assert.equal(received, before + 1);
    assert.equal(http.count, http.limit);
    assert.ok(http.surface().some((row) => row.path === "/binary" && row.statuses.includes(200)));
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
