import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { buscarTema, contraste, FONDO_REFERENCIA, simbolos, TEMAS, usarTema } from "../src/tui/temas.ts";
import { accent, avisoLinea, badge, badgeWarn, cellWidth, segment, warn } from "../src/tui/text.ts";

function conEnv(clave: string, valor: string | undefined, fn: () => void): void {
  const antes = process.env[clave];
  if (valor === undefined) delete process.env[clave];
  else process.env[clave] = valor;
  try {
    fn();
  } finally {
    if (antes === undefined) delete process.env[clave];
    else process.env[clave] = antes;
  }
}

test("temas: los seis, en orden, con nombre y descripción en los dos idiomas", () => {
  assert.deepEqual(TEMAS.map((t) => t.id), ["orobas", "elevate", "hacker", "filete", "hornero", "ambar"]);
  conEnv("LC_ALL", "en_US.UTF-8", () => {
    assert.equal(buscarTema("ambar")!.nombre(), "Argentine hacker (amber)");
    for (const t of TEMAS) assert.ok(t.nombre() && t.descripcion());
  });
  conEnv("LC_ALL", "es_AR.UTF-8", () => {
    assert.equal(buscarTema("ambar")!.nombre(), "Hacker argentino (ámbar)");
    for (const t of TEMAS) assert.ok(t.nombre() && t.descripcion());
  });
});

test("temas: contraste ≥ 4.5 de texto, acento, aviso y apagado contra el fondo", () => {
  for (const t of TEMAS)
    for (const c of [t.texto ?? "#dce2e8", t.acento, t.aviso, t.apagado])
      assert.ok(contraste(c, t.fondo ?? FONDO_REFERENCIA) >= 4.5, `${t.id} ${c}`);
});

test("temas: los glifos del descifrado son letras de ancho 1", () => {
  for (const t of TEMAS) {
    if (t.descifrado === "no") continue;
    for (const c of [...t.glifos]) {
      assert.match(c, /^\p{L}$/u, t.id);
      assert.equal(cellWidth(c), 1, `${t.id} ${c}`);
    }
  }
  assert.equal(buscarTema("elevate")!.descifrado, "no");
});

test("temas: buscar por id o nombre sin tildes", () => {
  assert.equal(buscarTema("Filete Porteño")?.id, "filete");
  assert.equal(buscarTema("  HORNERO ")?.id, "hornero");
  assert.equal(buscarTema("xyz"), undefined);
});

test("temas: en conhost los símbolos se simplifican", () => {
  try {
    conEnv("CYBER_CONSOLE", "conhost", () => {
      usarTema("filete");
      assert.equal(simbolos().adorno, "*");
      assert.equal(simbolos().cursor, ">");
      usarTema("orobas");
      assert.deepEqual(simbolos().bordes.slice(0, 4), ["┌", "┐", "└", "┘"]);
    });
    conEnv("CYBER_CONSOLE", undefined, () => {
      assert.deepEqual(simbolos().bordes.slice(0, 4), ["╭", "╮", "╰", "╯"]);
    });
  } finally {
    usarTema("orobas");
  }
});

test("temas: contraste conocido", () => {
  assert.equal(Math.round(contraste("#000000", "#ffffff") * 10) / 10, 21);
});

test("estilos: Orobas da exactamente los códigos de hoy", () => {
  usarTema("orobas");
  assert.equal(accent("x"), "\x1b[38;2;116;172;223mx\x1b[0m");
  assert.equal(badge("x"), "\x1b[1;38;2;20;24;30;48;2;116;172;223mx\x1b[0m");
  assert.equal(segment("x"), "\x1b[38;2;220;226;232;48;2;42;48;56mx\x1b[0m");
  assert.equal(warn("x"), "\x1b[38;2;246;180;14mx\x1b[0m");
  assert.equal(avisoLinea("x"), "\x1b[1;38;2;246;180;14mx\x1b[0m");
});

test("estilos: cambian en vivo con el tema", () => {
  try {
    usarTema("hacker");
    assert.ok(accent("x").includes("38;2;182;255;200"));
    assert.ok(avisoLinea("x").includes("38;2;0;0;0;48;2;255;176;0"));
    usarTema("elevate");
    assert.ok(accent("x").startsWith("\x1b[1;38;2;238;238;242m"));
  } finally {
    usarTema("orobas");
  }
});

test("estilos: badgeWarn usa el fondo del tema o el de referencia", () => {
  try {
    usarTema("orobas");
    assert.ok(badgeWarn("x").includes("38;2;20;24;30;48;2;246;180;14"));
    usarTema("hornero");
    assert.ok(badgeWarn("x").includes("38;2;28;22;17;48;2;247;215;116"));
  } finally {
    usarTema("orobas");
  }
});

test("temas: la escarapela de la insignia es sólo del ámbar y en conhost pasa a «o»", () => {
  const previo = process.env.CYBER_CONSOLE;
  try {
    usarTema("ambar");
    delete process.env.CYBER_CONSOLE;
    assert.equal(simbolos().escarapela, "◎");
    process.env.CYBER_CONSOLE = "conhost";
    assert.equal(simbolos().escarapela, "o");
    usarTema("orobas");
    assert.equal(simbolos().escarapela, undefined);
  } finally { usarTema("orobas"); if (previo === undefined) delete process.env.CYBER_CONSOLE; else process.env.CYBER_CONSOLE = previo; }
});
