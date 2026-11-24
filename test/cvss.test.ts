import assert from "node:assert/strict";
import { test } from "node:test";
import { calcularCvss } from "../src/cvss.ts";

// Puntajes publicados por FIRST en https://www.first.org/cvss/v3.1/examples
const ejemplos = [
  ["CVE-2013-0375", "AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "media"],
  ["CVE-2014-3566", "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "baja"],
  ["CVE-2009-0783", "AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2, "media"],
  ["CVE-2012-0384", "AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "alta"],
  ["CVE-2015-1098", "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "alta"],
] as const;
for (const [id, vector, puntaje, severidad] of ejemplos) {
  test(`CVSS 3.1 coincide con FIRST para ${id}`, () => {
    assert.deepEqual(calcularCvss(`CVSS:3.1/${vector}`), { puntaje, severidad, grupo: "base" });
  });
}

const critica = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
test("CVSS acepta otro orden y respeta los extremos de la escala", () => {
  assert.deepEqual(calcularCvss("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:X"), calcularCvss(critica));
  assert.deepEqual(calcularCvss(critica.replace("S:U", "S:C")), { puntaje: 10, severidad: "critica", grupo: "base" });
  for (const alcance of ["C", "U"]) {
    assert.equal(calcularCvss(`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:${alcance}/C:N/I:N/A:N`).puntaje, 0);
  }
});

test("CVSS aplica los grupos opcionales, las métricas heredadas y el doble redondeo", () => {
  assert.deepEqual(calcularCvss(critica + "/E:U/RL:O/RC:U"), { puntaje: 7.8, severidad: "alta", grupo: "temporal" });
  assert.deepEqual(calcularCvss(critica + "/MC:N/MI:N/MA:N"), { puntaje: 0, severidad: "informativa", grupo: "ambiental" });
  assert.equal(calcularCvss(critica + "/MS:C/E:U/RL:O/RC:U").puntaje, 8);
  assert.equal(calcularCvss(critica + "/CR:H/MAV:P/MPR:H/MS:C").puntaje, 7.2);
});

test("CVSS rechaza versiones, campos repetidos, ausentes, desconocidos y malformados", () => {
  for (const vector of ["", critica.replace("3.1", "3.0"), critica.replace("S:U/", ""), critica.replace("AV:N", "AV:X"),
    critica + "/A:H", critica + "/E:X/E:X", critica + "/E:HL", critica + "/E:H:U", critica + "/E:",
    critica + "/inventada:X", critica + "/constructor:X", critica + "/", critica + "\n"]) {
    assert.throws(() => calcularCvss(vector), /CVSS/);
  }
});
