import "./datos-tmp.ts";
// La guarda de borrado vive en el cliente HTTP y el permiso sólo vale sobre recursos creados en la sesión.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { HttpClient } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { createNetTools } from "../src/toolbox.ts";

test("borrado: sólo con allowDestructive y sobre un recurso creado en esta sesión, por cualquier vía", async () => {
  const server = createServer((req, res) => {
    if (req.method === "POST" && req.url === "/api/items") return void res.writeHead(201, { "content-type": "application/json", location: "/api/items/7" }).end('{"id":7,"owner":{"user_id":3}}');
    if (req.method === "DELETE" && req.url?.startsWith("/api/items/")) return void res.writeHead(204).end();
    if (req.url?.startsWith("/clear_history")) return void res.writeHead(200).end("ok");
    res.writeHead(200, { "content-type": "application/json" }).end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-borrado-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "prueba", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  const probe = createNetTools({ http, artifacts: new Artifacts(db, join(cwd, "artifacts")), scope: () => scope }).find((tool) => tool.name === "http_probe")!;
  const signal = new AbortController().signal;
  try {
    // Sin permiso no sale nada, ni por método ni por ruta; con permiso pero sobre un id ajeno, tampoco.
    await assert.rejects(http.send({ url: `${base}/api/items/8`, method: "DELETE" }), /borra o vacía datos/);
    await assert.rejects(http.send({ url: `${base}/clear_history?uuid=8` }), /borra o vacía datos/);
    await assert.rejects(http.send({ url: `${base}/api/items/8`, method: "DELETE", allowDestructive: true }), /creado en esta sesión/);
    assert.equal(http.count, 0);
    // Crear un recurso propio registra sus ids (Location y campos id/uuid del cuerpo).
    await http.send({ url: `${base}/api/items`, method: "POST", body: "{}" });
    assert.ok(http.owns(`${base}/api/items/7`));
    assert.ok(http.owns(`${base}/clear_history?uuid=7`));
    assert.ok(http.owns(`${base}/users/3/reset`));
    assert.ok(!http.owns(`${base}/api/items/8`));
    assert.ok(!http.owns(`${base}/api/items`));
    // Un restablecimiento de contraseña no es un borrado.
    assert.equal((await http.send({ url: `${base}/password/reset`, method: "POST", body: "{}" })).response?.status, 200);
    // Sobre el propio, con permiso, sale.
    assert.equal((await http.send({ url: `${base}/api/items/7`, method: "DELETE", allowDestructive: true })).response?.status, 204);
    assert.equal((await http.send({ url: `${base}/clear_history?uuid=7`, allowDestructive: true })).response?.status, 200);
    // El sondeo por lista omite lo destructivo ajeno y lo dice, en vez de frenar toda la lista.
    const result = await probe.execute({ urls: [`${base}/api/items/8`], methods: ["GET", "DELETE"], allowDestructive: true }, signal);
    assert.match(result.text, /omitidas 1 combinaciones/);
    assert.equal((result.details as any).peticiones, 1);
    await assert.rejects(() => Promise.resolve(probe.execute({ urls: [`${base}/api/items/8`], methods: ["DELETE"] }, signal)), /no creaste en esta sesión/);
  } finally {
    db.close();
    server.close();
  }
});
