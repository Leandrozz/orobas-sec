import assert from "node:assert/strict";
import { test } from "node:test";
import { lineaLogica, palabraEn, resaltar, textoSeleccionado } from "../src/tui/seleccion.ts";
import { renderMarkdown } from "../src/tui/markdown.ts";
import { CORTE_ESPACIO, CORTE_PEGADO, adornoTUI, stripAnsi } from "../src/tui/text.ts";

test("seleccion: continuaciones, paneles y separadores", () => {
  assert.equal(textoSeleccionado(["  uno dos", CORTE_ESPACIO + "  tres"], { fila: 0, col: 0 }, { fila: 1, col: 8 }), "uno dos tres");
  assert.equal(textoSeleccionado(["  abcd", CORTE_PEGADO + "  efgh"], { fila: 0, col: 0 }, { fila: 1, col: 8 }), "abcdefgh");
  const panel = ["", adornoTUI("╭─ T ─╮"), "  " + adornoTUI("│") + " hola" + "   " + adornoTUI("│"), adornoTUI("╰──╯")];
  assert.equal(textoSeleccionado(panel, { fila: 0, col: 0 }, { fila: 3, col: 10 }), "hola");
  const sep = ["  " + adornoTUI("── ") + "Vos" + adornoTUI(" ──── 23:41 ──"), "  hola"];
  assert.equal(textoSeleccionado(sep, { fila: 0, col: 0 }, { fila: 1, col: 30 }), "Vos\nhola");
});

test("seleccion: una fila, sangría, ancho doble y orden", () => {
  const f = ["  " + adornoTUI("│") + " abc"];
  assert.equal(textoSeleccionado(f, { fila: 0, col: 2 }, { fila: 0, col: 4 }), "│ a");
  const cod = ["  a", "      b"];
  assert.equal(textoSeleccionado(cod, { fila: 0, col: 0 }, { fila: 1, col: 9 }), "a\n    b");
  assert.equal(textoSeleccionado(["  漢字x"], { fila: 0, col: 3 }, { fila: 0, col: 3 }), "漢");
  const a = { fila: 0, col: 0 };
  const b = { fila: 1, col: 9 };
  assert.equal(textoSeleccionado(cod, b, a), textoSeleccionado(cod, a, b));
});

test("seleccion: palabra, línea lógica y resaltado", () => {
  assert.deepEqual(palabraEn(["  ver /api/x hoy"], 0, 8), [{ fila: 0, col: 6 }, { fila: 0, col: 11 }]);
  assert.equal(palabraEn(["  ver /api/x hoy"], 0, 5), undefined);
  assert.deepEqual(lineaLogica(["a", CORTE_ESPACIO + "b", CORTE_ESPACIO + "c", "d"], 1), [0, 2]);
  const r = resaltar("ab\x1b[0mcd", 1, 2);
  assert.equal(stripAnsi(r), "abcd");
  assert.equal(r, "a\x1b[7mb\x1b[0m\x1b[7mc\x1b[27md");
});

test("seleccion: arrastre que empieza a mitad de fila no cuela el margen", () => {
  const f = ["  uno dos tres", CORTE_ESPACIO + "  cuatro cinco"];
  const y = ["  uno dos tres", "  cuatro cinco"];
  assert.equal(textoSeleccionado(y, { fila: 0, col: 2 }, { fila: 1, col: 20 }), "uno dos tres\ncuatro cinco");
  assert.equal(textoSeleccionado(y, { fila: 0, col: 6 }, { fila: 1, col: 20 }), "dos tres\ncuatro cinco");
  assert.equal(textoSeleccionado(f, { fila: 0, col: 6 }, { fila: 1, col: 20 }), "dos tres cuatro cinco");
});

test("seleccion: bloque de código y fila entera", () => {
  const cod = ["  " + adornoTUI("│ ") + "curl x", "  " + adornoTUI("│ ") + "  -H 'X: 1'"];
  assert.equal(textoSeleccionado(cod, { fila: 0, col: 0 }, { fila: 1, col: 30 }), "curl x\n  -H 'X: 1'");
  assert.equal(textoSeleccionado(["  hola qué tal"], { fila: 0, col: 0 }, { fila: 0, col: 70 }, true), "hola qué tal");
  const panel = ["  " + adornoTUI("│") + " Modelo: x   " + adornoTUI("│")];
  assert.equal(textoSeleccionado(panel, { fila: 0, col: 0 }, { fila: 0, col: 70 }, true), "Modelo: x");
});

test("seleccion: fila en blanco de panel queda como línea vacía", () => {
  const panel = [adornoTUI("╭─ T ─╮"), "  " + adornoTUI("│") + " a   " + adornoTUI("│"), "  " + adornoTUI("│") + "     " + adornoTUI("│"), "  " + adornoTUI("│") + " b   " + adornoTUI("│"), adornoTUI("╰──╯")];
  assert.equal(textoSeleccionado(panel, { fila: 0, col: 0 }, { fila: 4, col: 20 }), "a\n\nb");
});

test("seleccion: la palabra partida con CORTE_PEGADO se extiende a las filas vecinas", () => {
  const f = ["  ver https://exa", CORTE_PEGADO + "  mple.com/x hoy"];
  assert.deepEqual(palabraEn(f, 0, 8), [{ fila: 0, col: 6 }, { fila: 1, col: 11 }]);
  assert.deepEqual(palabraEn(f, 1, 5), [{ fila: 0, col: 6 }, { fila: 1, col: 11 }]);
  assert.equal(textoSeleccionado(f, ...palabraEn(f, 0, 8)!), "https://example.com/x");
});

test("seleccion: un bloque de código renderizado se copia sin el canal", () => {
  const f = renderMarkdown("```\ncurl x\n  -H 'X: 1'\n```", 40);
  assert.equal(textoSeleccionado(f, { fila: 0, col: 0 }, { fila: f.length - 1, col: 40 }), "curl x\n  -H 'X: 1'");
});
