import { test } from "node:test";
import assert from "node:assert/strict";
import { Pantalla, a256, conFondo, modoColor, restaurarSiDentro, restaurarTerminal } from "../src/tui/pantalla.ts";
import { ADORNO_ABRE, ADORNO_CIERRA, CORTE_ESPACIO, adornoTUI } from "../src/tui/text.ts";
import { buscarTema, usarTema } from "../src/tui/temas.ts";

const salida = (columns = 40, rows = 8) => {
  const writes: string[] = [];
  return { writes, out: { columns, rows, write: (d: string) => void writes.push(d) } };
};
const cuenta = (s: string[], x: string) => s.join("").split(x).length - 1;

test("pantalla: entra y sale de la pantalla alternativa, salir dos veces no escribe dos veces", () => {
  const { out, writes } = salida();
  const p = new Pantalla(out, { mouse: true });
  p.entrar();
  assert.ok(writes.join("").includes("\x1b[?1049h"));
  assert.ok(writes.join("").includes("\x1b[?1006h"));
  assert.ok(writes.join("").includes("\x1b[?1000h\x1b[?1002h"));
  p.salir();
  p.salir();
  assert.equal(cuenta(writes, "\x1b[?1049l"), 1);
  assert.ok(writes.join("").includes("\x1b[?1006l"));
  assert.ok(writes.join("").includes("\x1b[?25h"));
  const r = salida();
  restaurarTerminal(r.out);
  assert.ok(r.writes.join("").includes("\x1b[?1049l"));
  assert.ok(r.writes.join("").includes("\x1b[?1002l"));
  assert.ok(r.writes.join("").includes("\x1b[?1000l"));
});

test("pantalla: un cambio en una fila repinta sólo esa fila", () => {
  const { out, writes } = salida();
  const p = new Pantalla(out, { mouse: false });
  const base = Array.from({ length: 8 }, (_, i) => `fila ${i}`);
  p.dibujar({ lineas: base });
  p.dibujar({ lineas: base.map((l, i) => (i === 3 ? "cambió" : l)) });
  const segunda = writes.at(-1)!;
  assert.ok(segunda.includes("\x1b[4;1H"));
  assert.ok(segunda.includes("cambió"));
  assert.equal(cuenta([segunda], "\x1b[2K"), 1);
  p.dibujar({ lineas: base.map((l, i) => (i === 3 ? "cambió" : l)) });
  assert.equal(cuenta([writes.at(-1)!], "\x1b[2K"), 0);
});

test("pantalla: cambio de tamaño repinta todo", () => {
  const { out, writes } = salida();
  const p = new Pantalla(out, { mouse: false });
  p.dibujar({ lineas: Array.from({ length: 8 }, () => "x") });
  out.rows = 10;
  p.dibujar({ lineas: Array.from({ length: 10 }, () => "x") });
  assert.equal(cuenta([writes.at(-1)!], "\x1b[2K"), 10);
});

test("pantalla: restaurarSiDentro sólo actúa si la pantalla sigue adentro", () => {
  const { out, writes } = salida();
  const p = new Pantalla(out, { mouse: false });
  p.entrar();
  p.salir();
  const n = writes.length;
  restaurarSiDentro(out);
  assert.equal(writes.length, n);
  p.entrar();
  restaurarSiDentro(out);
  assert.ok(writes.slice(n).join("").includes("\x1b[?1049l"));
  p.salir();
});

test("pantalla: si salir falla a mitad, restaurarSiDentro todavía la cubre (M10)", () => {
  const { out } = salida();
  const p = new Pantalla(out, { mouse: false });
  p.entrar();
  const roto = { columns: 40, rows: 8, write: (_: string) => { throw new Error("cerrada"); } };
  (p as unknown as { out: unknown }).out = roto;
  assert.throws(() => p.salir());
  const r = salida();
  restaurarSiDentro(r.out);
  assert.ok(r.writes.join("").includes("\x1b[?1049l"));
  restaurarTerminal(out);
});

test("color: modo según la terminal", () => {
  assert.equal(modoColor({ COLORTERM: "truecolor", TERM_PROGRAM: "Apple_Terminal" }), "24bit");
  assert.equal(modoColor({ TERM_PROGRAM: "Apple_Terminal" }), "256");
  assert.equal(modoColor({}), "24bit");
  assert.equal(modoColor({ CYBER_COLOR: "256" }), "256");
  assert.equal(modoColor({ CYBER_COLOR: "24bit", TERM_PROGRAM: "Apple_Terminal" }), "24bit");
});

test("color: conversión a 256", () => {
  assert.equal(a256("\x1b[38;2;0;0;0mx"), "\x1b[38;5;16mx");
  assert.equal(a256("\x1b[48;2;255;255;255mx"), "\x1b[48;5;231mx");
  const m = a256("\x1b[1;38;2;20;24;30;48;2;116;172;223mx");
  assert.ok(!m.includes("38;2") && !m.includes("48;2") && m.startsWith("\x1b[1;"));
});

test("color: a256 sólo toca secuencias SGR, no texto visible", () => {
  assert.equal(a256("38;2;1;2;3"), "38;2;1;2;3");
  assert.equal(a256("a 48;2;255;0;0 \x1b[38;2;0;0;0mx"), "a 48;2;255;0;0 \x1b[38;5;16mx");
});

test("fondo: \x1b[m cuenta como reset", () => {
  const tema = buscarTema("hornero")!;
  const s = conFondo("a\x1b[mb", tema);
  assert.ok(s.includes("\x1b[m\x1b[38;2;239;227;207m\x1b[48;2;28;22;17mb"), JSON.stringify(s));
});

test("fondo: sobrevive a los resets en medio de la línea", () => {
  const tema = buscarTema("hornero")!;
  const bg = "\x1b[48;2;28;22;17m";
  const fg = "\x1b[38;2;239;227;207m";
  const s = conFondo("a\x1b[0mb\x1b[39mc\x1b[49md", tema);
  assert.ok(s.startsWith(`${fg}${bg}\x1b[2K`));
  assert.ok(s.includes(`\x1b[0m${fg}${bg}b`));
  assert.ok(s.includes(`\x1b[39m${fg}c`));
  assert.ok(s.includes(`\x1b[49m${bg}d`));
});

test("fondo: cambiar de tema repinta también las filas vacías", () => {
  const { out, writes } = salida();
  const p = new Pantalla(out, { mouse: false });
  usarTema("orobas");
  const cuadro = { lineas: ["una línea"] };
  p.dibujar(cuadro);
  try {
    usarTema("hacker");
    p.dibujar(cuadro);
    assert.equal(cuenta([writes.at(-1)!], "\x1b[48;2;0;0;0m"), 8);
  } finally {
    usarTema("orobas");
  }
});

test("fondo: volver a un tema sin fondo reinicia el estilo en cada fila", () => {
  const { out, writes } = salida();
  const p = new Pantalla(out, { mouse: false });
  const cuadro = { lineas: ["una línea"] };
  try {
    usarTema("hacker");
    p.dibujar(cuadro);
    usarTema("orobas");
    p.dibujar(cuadro);
    const filas = writes.at(-1)!.split(/\x1b\[\d+;1H/).slice(1);
    assert.equal(filas.length, 8);
    for (const f of filas) assert.ok(f.startsWith("\x1b[0m\x1b[2K"));
  } finally {
    usarTema("orobas");
  }
});

test("fondo: con NO_COLOR no se emite ningún reset por fila", () => {
  const previo = process.env.NO_COLOR;
  process.env.NO_COLOR = "1";
  try {
    assert.equal(conFondo("a", buscarTema("orobas")!), "\x1b[2Ka");
    assert.equal(conFondo("a", buscarTema("hornero")!), "\x1b[2Ka");
  } finally {
    if (previo === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = previo;
  }
});

test("dibujar: las marcas de corte y de adorno no llegan a la terminal", () => {
  const { out, writes } = salida();
  new Pantalla(out, { mouse: false }).dibujar({ lineas: [`  ${adornoTUI("│")}${CORTE_ESPACIO} hola`] });
  const f = writes.join("");
  assert.ok(f.includes("hola") && !f.includes("\x1b[28;") && !f.includes("\x1b[29;"));
  assert.ok(![ADORNO_ABRE, ADORNO_CIERRA].some((m) => f.includes(m)));
});
