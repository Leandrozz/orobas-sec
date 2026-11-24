import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { describesTooling, Findings } from "../src/findings.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { contrast } from "../src/verifier.ts";

test("verificador: el control tiene que distinguir la causa", () => {
  const ok = (a: Parameters<typeof contrast>[0], b: Parameters<typeof contrast>[1]) => contrast(a, b).ok;
  // Misma petición citada dos veces no es un control.
  assert.equal(ok({ id: "h1", status: 200, body: "x" }, { id: "h1", status: 200, body: "x" }), false);
  // Control igual a la prueba: la condición quitada no era la causa.
  const same = contrast({ id: "h1", status: 200, body: '{"ok":true}' }, { id: "h2", status: 200, body: '{ "ok": true }' });
  assert.equal(same.ok, false);
  assert.match((same as { reason: string }).reason, /dio lo mismo/);
  // Sin respuesta del servidor no hay prueba ni control.
  assert.equal(ok({ id: "h1", error: "Tiempo de espera agotado" }, { id: "h2", status: 403 }), false);
  assert.equal(ok({ id: "h1", status: 200, body: "a" }, { id: "h2", error: "ECONNRESET" }), false);
  // Distinto estado, o mismo estado con otro cuerpo (el dato ajeno frente al propio), sí distinguen.
  assert.equal(ok({ id: "h1", status: 200, body: "secreto" }, { id: "h2", status: 403, body: "" }), true);
  assert.equal(ok({ id: "h1", status: 200, body: '{"owner":2}' }, { id: "h2", status: 200, body: '{"owner":1}' }), true);
});

test("hallazgos: lo que describe a la herramienta no se registra como candidato", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-herramienta-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash), (hash) => artifacts.read(hash));
  const exchange = (response?: object, error?: string) => artifacts.put(JSON.stringify({ id: "h1", request: { method: "GET", url: "http://lab.test/a" }, response, error }), "application/json", "http").hash;
  const withResponse = exchange({ status: 200, headers: {}, body: "{}" });
  const failed = exchange(undefined, "Tiempo de espera agotado");
  const base = { kind: "control de acceso", asset: "http://lab.test/a", summary: "Observación." };
  try {
    assert.equal(describesTooling("Campo indefinido: el body de h332 no se pudo leer completo", ""), true);
    assert.equal(describesTooling("Página del repo", "extracción de estructura bloqueada por formato del artefacto"), true);
    assert.equal(describesTooling("Sin sesión redirige a /login", "la herramienta lee HTML como si fuera JSON"), true);
    assert.equal(describesTooling("Repo archivado acepta escrituras", "PATCH devuelve 200 y el cambio persiste"), false);
    assert.throws(() => findings.record({ ...base, title: "Campo indefinido: el body no se pudo leer", evidence: [withResponse] }, "s"), /herramienta/);
    assert.throws(() => findings.record({ ...base, title: "Lectura de dato ajeno", evidence: [failed] }, "s"), /sin respuesta del servidor/);
    // Como pista sí queda constancia; con una respuesta real sí es candidato.
    assert.equal(findings.record({ ...base, state: "pista", title: "Campo indefinido en la respuesta" }, "s").state, "pista");
    const real = findings.record({ ...base, asset: "http://lab.test/b", title: "Lectura de dato ajeno", evidence: [withResponse, failed] }, "s");
    assert.equal(real.state, "candidato");
    assert.throws(() => findings.update(real.id, { summary: "La herramienta no pudo leer el cuerpo" }, "s"), /herramienta/);
    // El verificador puede corregir el título al verificar con otra causa.
    const fixed = findings.verdict(real.id, "verificado", "Entra cualquier usuario inexistente", [withResponse], "verificador:1", { title: "Cuentas inexistentes reciben secreto vacío" });
    assert.equal(fixed.title, "Cuentas inexistentes reciben secreto vacío");
  } finally {
    db.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
