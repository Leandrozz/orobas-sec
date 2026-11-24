import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { nodos } from "../src/grafo-alimentar.ts";
import { resolveProvider } from "../src/providers.ts";
import { projectPaths } from "../src/store.ts";
import { generateReport } from "../src/report.ts";

const vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N";
function abrir(cwd: string, resume?: string) {
  return new Engine({ cwd, resume, provider: resolveProvider("faux"), mcp: {}, cveFeed: false,
    coverageObjections: 0, autoVerify: false, grafo: true, budgetPico: 2n * 10n ** 12n });
}

test("las herramientas guardan el vector, rechazan cambios inválidos y el informe lo recupera al reabrir", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "informe-cvss-"));
  let motor = abrir(cwd);
  try {
    const sesion = motor.sessionId;
    const artefacto = motor.artifacts.put("Permisos registrados en el inventario.", "text/plain", "inventario");
    const registro = { title: "Permisos del registro", asset: "/registro", kind: "permisos", state: "candidato",
      summary: "La evidencia identifica los campos visibles.", severity: "alta", evidence: [artefacto.hash] };
    const signal = new AbortController().signal;
    const herramienta = (nombre: string) => motor.agent.tools.find((tool) => tool.name === nombre)!;
    const alta = await herramienta("finding_record").execute({ ...registro, cvss: vector }, signal);
    const id = String(alta.details?.id);
    assert.equal(motor.findings.get(id)?.severity, "media");
    const previo = motor.findings.get(id);
    await assert.rejects(async () => herramienta("finding_update").execute({ id, cvss: vector + "/PR:L" }, signal), /repetida/);
    assert.deepEqual(motor.findings.get(id), previo);
    await herramienta("finding_update").execute({ id, severity: "critica", summary: "Revisión de la evidencia." }, signal);
    assert.equal(motor.findings.get(id)?.severity, "media");
    // C:H/I:L: el puntaje de C:H solo coincide con una tarifa interna y frena el verificador de la exportación pública.
    const nuevo = vector.replace("/C:L", "/C:H").replace("/I:N", "/I:L");
    await herramienta("finding_update").execute({ id, cvss: nuevo }, signal);
    await motor.close();
    motor = abrir(cwd, sesion);
    assert.equal(motor.findings.get(id)?.cvss, nuevo);
    for (const lang of ["es", "en"] as const) {
      const informe = await generateReport({ paths: projectPaths(cwd), db: motor.db, artifacts: motor.artifacts, findings: motor.findings, scope: motor.scope, ledger: motor.ledger, sessionId: sesion, lang });
      assert.ok(informe.markdown.includes(`CVSS 3.1 (base) · 7.1 · \`${nuevo}\``));
    }
  } finally { await motor.close(); rmSync(cwd, { recursive: true, force: true }); }
});

test("cierre documental respeta presupuesto, sesión, estado, severidad y tope de objeciones", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cierre-cvss-"));
  const motor = abrir(cwd);
  try {
    const evidence = [motor.artifacts.put("Inventario de permisos", "text/plain", "inventario").hash];
    const base = { asset: "/uno", title: "Permisos", kind: "permisos", summary: "Inventario", evidence };
    motor.findings.record({ ...base, asset: "/otra" }, "otra-sesion");
    motor.findings.record({ ...base, asset: "/baja", severity: "baja" }, motor.sessionId);
    motor.findings.record({ ...base, asset: "/pista", state: "pista" }, motor.sessionId);
    const item = motor.findings.record(base, motor.sessionId);
    const gate = motor.gate!;
    assert.equal(gate.objection(0), undefined);
    const recordatorio = gate.objection(1)!;
    assert.deepEqual(recordatorio.cracks.map((c) => c.key), ["informe:cvss"]);
    assert.match(recordatorio.text, new RegExp(`El candidato ${item.id.slice(0, 8)} \\(media\\)`));
    assert.equal(gate.objection(1), undefined);
    motor.findings.update(item.id, { cvss: vector }, motor.sessionId);
    assert.deepEqual(gate.pendientesDeInforme(), []);
  } finally { await motor.close(); rmSync(cwd, { recursive: true, force: true }); }
});

test("la consulta de grafo cuenta aunque la sesión se reabra", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cierre-grafo-"));
  let motor = abrir(cwd);
  try {
    const sesion = motor.sessionId;
    motor.scope.edit({ include: ["catalogo.test"] });
    assert.deepEqual(motor.gate!.pendientesDeInforme(motor.grafo!.ver()), []);
    motor.grafo!.nodo(nodos.ruta("GET", "https://catalogo.test/catalogo", "inferido")!, "sha256:inventario");
    assert.equal(motor.gate!.objection(1)?.cracks[0]?.key, "informe:grafo");
    motor.provider.faux!.queue = [{ toolCalls: [{ name: "grafo", arguments: { modo: "resumen" } }] }, { text: "Cobertura parcial." }];
    await motor.send("Resumí el inventario guardado.");
    assert.deepEqual(motor.gate!.pendientesDeInforme(motor.grafo!.ver()), []);
    await motor.close();
    motor = abrir(cwd, sesion);
    assert.deepEqual(motor.gate!.pendientesDeInforme(motor.grafo!.ver()), []);
  } finally { await motor.close(); rmSync(cwd, { recursive: true, force: true }); }
});

test("un vector no saltea el piso informativo y un vector vacío equivale a no mandarlo", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "informe-cvss-piso-"));
  const motor = abrir(cwd);
  try {
    const signal = new AbortController().signal;
    const herramienta = (nombre: string) => motor.agent.tools.find((tool) => tool.name === nombre)!;
    const artefacto = motor.artifacts.put("Respuesta sin Strict-Transport-Security.", "text/plain", "cabeceras");
    const cabecera = await herramienta("finding_record").execute({ title: "Falta de HSTS en la página de inicio", asset: "/", kind: "cabeceras",
      state: "candidato", summary: "La respuesta no trae la cabecera.", severity: "media", evidence: [artefacto.hash],
      cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" }, signal);
    assert.equal(motor.findings.get(String(cabecera.details?.id))?.severity, "informativa");
    const vacio = await herramienta("finding_record").execute({ title: "Lectura de pedidos ajenos", asset: "/pedidos/2", kind: "idor",
      state: "candidato", summary: "Otra cuenta lee el pedido.", severity: "alta", evidence: [artefacto.hash], cvss: "  " }, signal);
    const registrado = motor.findings.get(String(vacio.details?.id))!;
    assert.equal(registrado.cvss, undefined);
    assert.equal(registrado.severity, "alta");
  } finally {
    await motor.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
