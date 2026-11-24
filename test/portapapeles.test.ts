import assert from "node:assert/strict";
import { test } from "node:test";
import { copiar, osc52 } from "../src/tui/portapapeles.ts";

test("portapapeles: OSC 52 plano, envuelto en tmux y con UTF-8", () => {
  assert.equal(osc52("hola", {}), "\x1b]52;c;aG9sYQ==\x07");
  const tmux = "\x1bPtmux;\x1b\x1b]52;c;aG9sYQ==\x07\x1b\\";
  assert.equal(osc52("hola", { TMUX: "/tmp/x" }), tmux);
  assert.equal(osc52("hola", { TERM: "screen-256color" }), tmux);
  assert.equal(osc52("hola", { TERM: "tmux-256color" }), tmux);
  const b64 = /52;c;([^\x07]+)\x07/.exec(osc52("ñ✓", {}))![1]!;
  assert.equal(Buffer.from(b64, "base64").toString("utf8"), "ñ✓");
});

test("portapapeles: copiar cuenta grafemas y respeta el tope", () => {
  const escrito: string[] = [];
  const w = (s: string) => escrito.push(s);
  const grande = copiar("x".repeat(50_001), w, {});
  assert.equal(escrito.length, 0);
  assert.equal(grande.ok, false);
  assert.match(grande.aviso, /50[ ,]000/);
  assert.ok(grande.aviso.includes("50001"));
  const chico = copiar("漢字", w, {});
  assert.equal(chico.ok, true);
  assert.equal(escrito.length, 1);
  assert.ok(chico.aviso.startsWith("✓ 2 "));
  assert.equal(copiar("x".repeat(50_000), w, {}).ok, true, "justo en el tope se copia");
});
