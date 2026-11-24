import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { visibleWidth } from "../src/tui/text.ts";
import { descifrar } from "../src/tui/descifrado.ts";

test("descifrado: letras por letras y dígitos por dígitos, el resto igual", () => {
  const orig = "**Hola** 12, `x_y` ñ e\u0301 😀";
  const r = descifrar(orig, [[0, 1000]], 1000, "fuerte", "ΞΣ", () => 0);
  const a = Array.from(orig), b = Array.from(r.texto);
  assert.equal(b.length, a.length);
  a.forEach((c, i) => {
    if (/\p{L}/u.test(c)) assert.match(b[i]!, /^[ΞΣ]$/u);
    else if (/\p{N}/u.test(c)) assert.match(b[i]!, /^\d$/);
    else assert.equal(b[i], c);
  });
  assert.ok(r.texto.includes("́") && r.texto.includes("😀"));
  assert.equal(r.animando, true);
});

test("descifrado: nada pasa del plazo de su intensidad", () => {
  const orig = "hola 123";
  assert.deepEqual(descifrar(orig, [[0, 1000]], 1500, "fuerte", "ΞΣ"), { texto: orig, animando: false });
  assert.deepEqual(descifrar(orig, [[0, 1000]], 1150, "suave", "ΞΣ"), { texto: orig, animando: false });
  assert.equal(descifrar(orig, [[0, 1000]], 1130, "suave", "ΞΣ").animando, true);
});

test("descifrado: cada trozo con su propio reloj", () => {
  const ll = [[0, 1000], [4, 1400]] as const;
  assert.notEqual(descifrar("abcdefgh", ll, 1500, "fuerte", "ΞΣ", () => 0).texto, "abcdefgh");
  assert.deepEqual(descifrar("abcdefgh", ll, 1900, "fuerte", "ΞΣ"), { texto: "abcdefgh", animando: false });
  // el primer trozo ya terminó a 1500 y el segundo no: sólo cambia el segundo
  assert.equal(descifrar("abcdefgh", ll, 1500, "fuerte", "ΞΣ", () => 0).texto.slice(0, 4), "abcd");
});

test("descifrado: intensidad «no» devuelve el original", () => {
  assert.deepEqual(descifrar("hola", [[0, 1000]], 1000, "no", "ΞΣ"), { texto: "hola", animando: false });
});

test("descifrado: los dígitos se reemplazan de verdad y lo ancho no se toca", () => {
  assert.equal(descifrar("1", [[0, 1000]], 1000, "fuerte", "ΞΣ", () => 0.99).texto, "9");
  const r = descifrar("漢字 ab", [[0, 1000]], 1000, "fuerte", "ΞΣ", () => 0).texto;
  assert.equal(r.slice(0, 2), "漢字");
  assert.equal(visibleWidth(r), visibleWidth("漢字 ab"));
});
