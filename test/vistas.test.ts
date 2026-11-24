import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { etiquetarHallazgo, filasDe } from "../src/tui/vistas.ts";
import { stripAnsi, visibleWidth } from "../src/tui/text.ts";

test("vistas: filas de hallazgos y artefactos desde la respuesta del daemon", () => {
  // Las líneas exactas de findingsView (src/findings.ts) y evidenceView (src/views.ts).
  const hallazgos = [
    "HALLAZGOS · 0 verificados · 1 candidatos · 0 pistas · 0 descartados",
    "? a1b2c3d4  candidato  alta        SQLi en /login",
    "Detalle: /findings <id>",
  ];
  assert.deepEqual(filasDe("hallazgos", hallazgos), [{ id: "a1b2c3d4", texto: hallazgos[1]! }]);
  const artefactos = ["EVIDENCIA · artefactos recientes", "0123456789ab     1024 B  shell"];
  assert.deepEqual(filasDe("artefactos", artefactos), [{ id: "0123456789ab", texto: artefactos[1]! }]);
  assert.deepEqual(filasDe("costos", ["COSTO", "x"]), []);
});

test("hallazgos: etiqueta por severidad", () => {
  // Formato real de findingsView: estado padEnd(10), severidad padEnd(11).
  const casos: [string, string][] = [["critica", "◆ CRÍTICA"], ["alta", "▲ ALTA"], ["media", "■ MEDIA"], ["baja", "● BAJA"], ["informativa", "○ INFO"]];
  const anchos = new Set<number>();
  for (const [sev, etiqueta] of casos) {
    const out = etiquetarHallazgo(`? 1a2b3c4d  ${"candidato".padEnd(10)} ${sev.padEnd(11)} SQLi en /api`);
    const plano = stripAnsi(out);
    assert.ok(plano.startsWith(` ${etiqueta}`), plano);
    assert.ok(plano.includes("1a2b3c4d") && plano.includes("SQLi en /api") && !plano.includes(sev) && plano.includes("candidato"), plano);
    anchos.add(visibleWidth(plano.slice(0, plano.indexOf("?"))));
  }
  assert.equal(anchos.size, 1);
  for (const marca of ["·", "✓", "✗"]) assert.ok(stripAnsi(etiquetarHallazgo(`${marca} 1a2b3c4d  ${"verificado".padEnd(10)} ${"alta".padEnd(11)} x`)).includes(`${marca} 1a2b3c4d`));
});

test("hallazgos: otras líneas no cambian", () => {
  for (const l of ["HALLAZGOS · 1 verificados · 0 candidatos · 0 pistas · 0 descartados", "Detalle: /findings <id>"]) assert.equal(etiquetarHallazgo(l), l);
});

test("hallazgos: los títulos arrancan en la misma columna sea cual sea el estado, sin perder sangría", () => {
  const col = (estado: string, titulo = "SQLi") => {
    const plano = stripAnsi(etiquetarHallazgo(`? 1a2b3c4d  ${estado.padEnd(10)} ${"alta".padEnd(11)} ${titulo}`));
    return plano.indexOf(titulo.trim());
  };
  const cols = ["pista", "candidato", "verificado", "descartado"].map((e) => col(e));
  assert.equal(new Set(cols).size, 1, cols.join());
  assert.equal(col("pista", "  con sangría") - col("pista", "x"), 2);
});
