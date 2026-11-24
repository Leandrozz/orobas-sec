import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { Findings } from "../src/findings.ts";
import { openStore, projectPaths } from "../src/store.ts";

test("hallazgos: verificar condiciones sin explotación conserva severidad informativa", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-severidad-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  const evidence = [artifacts.put("observación sintética", "text/plain", "test").hash];
  try {
    const cases = [
      ["configuración", "Cabeceras de seguridad ausentes"],
      ["cors ausente", "Configuración de origen"],
      ["huella", "Versiones expuestas"],
      ["directorio", "Listado de archivos sin datos sensibles"],
      ["configuración", "Missing security headers"],
      ["versión expuesta", "Huella del servidor"],
      ["configuración", "Sin HSTS"],
    ];
    for (const [i, [kind, title]] of cases.entries()) {
      const finding = findings.record({ kind: kind!, title: title!, asset: `https://example.test/${i}`, summary: "Condición observada.", severity: "alta", evidence }, "s");
      assert.equal(finding.severity, "informativa");
      assert.equal(findings.update(finding.id, { severity: "critica" }, "s").severity, "informativa");
      const verified = findings.verdict(finding.id, "verificado", "reproducido", evidence, "verificador:1");
      assert.equal(verified.state, "verificado");
      assert.equal(verified.severity, "informativa");
      assert.equal(findings.decide(finding.id, "verificado", "revisión humana").severity, "informativa");
    }
    for (const [i, title] of ["CORS permisivo permite leer datos privados", "Listado de directorio expone datos sensibles", "Inyección SQL con extracción", "Control de acceso ausente", "Cabecera Authorization ausente permite leer datos privados"].entries()) {
      assert.equal(findings.record({ kind: "explotable", title, asset: `https://example.test/real/${i}`, summary: "Impacto demostrado", severity: "alta", evidence }, "s").severity, "alta");
    }
    const current = findings.list()[0]!;
    assert.throws(() => findings.update(current.id, { severity: "inventada" }, "s"), /Severidad inválida/);
    const decided = findings.decide(current.id, "verificado", "revisión");
    assert.equal(findings.update(current.id, { summary: "Texto corregido" }, "s").decidedAt, decided.decidedAt);
    const old = { ...findings.list().find((item) => item.severity === "informativa")!, severity: "critica" };
    db.prepare("update findings set json=? where id=?").run(JSON.stringify(old), old.id);
    assert.equal(findings.get(old.id)!.severity, "informativa", "la regla también alcanza registros anteriores");
  } finally { db.close(); rmSync(cwd, { recursive: true, force: true }); }
});
