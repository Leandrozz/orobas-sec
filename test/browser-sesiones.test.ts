import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { BrowserSession, browserPaths, createBrowserTools } from "../src/browser.ts";
import { HttpClient } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { labServer } from "./lab-web.ts";

const { playwright, chromium } = browserPaths();
const skip = !existsSync(playwright) || !existsSync(chromium);

test("navegador: dos sesiones con cuentas propias trabajan en paralelo e incognito no hereda cookies", { skip }, async () => {
  const server = labServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-sesiones-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana", cookie: "session=browser-1" } });
  http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto", cookie: "session=browser-2" } });
  const browser = new BrowserSession(http);
  try {
    // Cada acción en paralelo recuerda su propia cuenta. Los adaptadores arranquen cada uno en su contexto.
    const aperturas = await Promise.all([
      browser.open(`${base}/browser`, "ana", { session: "cliente-a" }),
      browser.open(`${base}/browser`, "beto", { session: "cliente-b" }),
    ]);
    assert.equal(aperturas[0]!.session, "cliente-a");
    assert.equal(aperturas[1]!.session, "cliente-b");
    const [a, b] = await Promise.all([
      browser.act([{ type: "click", text: "Recordar" }, { type: "wait", ms: 80 }], "cliente-a"),
      browser.act([{ type: "click", text: "Recordar" }, { type: "wait", ms: 80 }], "cliente-b"),
    ]);
    assert.match(a.text, /Usuario: 1; cookie: true; recordada: true/);
    assert.match(b.text, /Usuario: 2; cookie: true; recordada: true/);
    const otraA = await browser.open(`${base}/browser`, "ana", { session: "cliente-a" });
    assert.match(otraA.text, /Usuario: 1; cookie: true; recordada: true/);
    const otraB = await browser.open(`${base}/browser`, "beto", { session: "cliente-b" });
    assert.match(otraB.text, /Usuario: 2; cookie: true; recordada: true/);

    // Una ventana privada con la misma identidad no usa el estado de la sesión normal.
    const privada = await browser.open(`${base}/browser`, "ana", { session: "privada", incognito: true });
    assert.equal(privada.incognito, true);
    assert.match(privada.text, /Usuario: 1; cookie: true; recordada: false/);

    const listado = (await createBrowserTools(browser).find((t) => t.name === "browser_tabs")!.execute({}, new AbortController().signal)).text;
    assert.match(listado, /cliente-a/);
    assert.match(listado, /cliente-b/);
    assert.match(listado, /incognito:privada/);

    await browser.closeTab("privada");
    const sigue = await browser.read("cliente-a");
    assert.match(sigue.text, /recordada: true/);
    await browser.closeTab("cliente-b");
    await assert.rejects(browser.read("cliente-b"), /cerrado|no existe/i);
  } finally {
    await browser.close();
    await new Promise<void>((r) => server.close(() => r()));
    db.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
