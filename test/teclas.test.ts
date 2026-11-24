import assert from "node:assert/strict";
import test from "node:test";
import { KeyParser, esPegadoConhost } from "../src/tui/keys.ts";

test("teclas: Alt+número, Alt+flechas, páginas, Ctrl+Inicio/Fin y rueda del mouse", () => {
  const names = (data: string) => new KeyParser().parse(data).map((key) => key.name);
  assert.deepEqual(names("\x1b1\x1b9"), ["alt+1", "alt+9"]);
  assert.deepEqual(names("\x1b[1;3D\x1b[1;3C\x1b[1;3A\x1b[1;3B"), ["alt+left", "alt+right", "alt+up", "alt+down"]);
  assert.deepEqual(names("\x1b[5~\x1b[6~\x1b[1;5H\x1b[1;5F"), ["pageUp", "pageDown", "ctrl+home", "ctrl+end"]);
  assert.deepEqual(names("\x1b[<64;10;5M\x1b[<65;10;5M"), ["wheelUp", "wheelDown"]);
  assert.deepEqual(names("\x1b"), ["escape"], "un ESC suelto sigue siendo Escape");
  assert.deepEqual(names("\x1b[1;5D\x1bb"), ["wordLeft", "wordLeft"], "Ctrl+← y Alt+b siguen moviendo por palabras");
  assert.deepEqual(new KeyParser().parse("\x1b[<0;10;5M\x1b[<32;12;6M\x1b[<0;12;6m"),
    [{ name: "mouseDown", col: 9, fila: 4 }, { name: "mouseDrag", col: 11, fila: 5 }, { name: "mouseUp", col: 11, fila: 5 }]);
  assert.deepEqual(names("\x1b[<2;1;1M\x1b[<4;1;1M"), [], "otros botones y modificadores se descartan");
});

test("teclas: Ctrl+PgUp/PgDn y Ctrl+N/P llegan con nombre propio y no pisan Ctrl+←/→ ni PgUp", () => {
  const names = (data: string) => new KeyParser().parse(data).map((key) => key.name);
  assert.deepEqual(names("\x1b[5;5~\x1b[6;5~\x0e\x10\x1b[5~"), ["ctrl+pageUp", "ctrl+pageDown", "ctrl+n", "ctrl+p", "pageUp"]);
  assert.deepEqual(names("\x1b[5;5u"), [], "CSI-u no inventa teclas");
});

test("teclas: heurística de pegado de conhost sólo con CYBER_CONSOLE=conhost y texto+salto+texto", () => {
  const antes = process.env.CYBER_CONSOLE;
  try {
    delete process.env.CYBER_CONSOLE;
    assert.equal(esPegadoConhost("uno\rdos"), false, "fuera de conhost nunca");
    process.env.CYBER_CONSOLE = "conhost";
    assert.equal(esPegadoConhost("uno\rdos"), true);
    assert.equal(esPegadoConhost("uno\r\ndos\r\ntres"), true);
    assert.equal(esPegadoConhost("\r"), false, "un Enter solo envía");
    assert.equal(esPegadoConhost("hola\r"), false, "texto y un Enter final envía");
    assert.equal(esPegadoConhost("hola"), false);
    assert.equal(esPegadoConhost("\x1b[1;3A"), false);
    assert.equal(esPegadoConhost("a\r\x1b[A"), false, "con secuencias de escape no es pegado");
  } finally {
    if (antes === undefined) delete process.env.CYBER_CONSOLE; else process.env.CYBER_CONSOLE = antes;
  }
});

test("teclas: F6, Shift+F6, F2, Ctrl+Shift+←→ y Ctrl+Alt+←→", () => {
  const names = (data: string) => new KeyParser().parse(data).map((key) => key.name);
  assert.deepEqual(names("\x1b[17~\x1b[17;2~\x1bOQ\x1b[12~"), ["f6", "shift+f6", "f2", "f2"]);
  assert.deepEqual(names("\x1b[1;6C\x1b[1;6D\x1b[1;7C\x1b[1;7D"), ["ctrl+shift+right", "ctrl+shift+left", "ctrl+alt+right", "ctrl+alt+left"]);
});
