import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { MAX_AGENTE, bloqueTerminal, comandoDolar, correrComando } from "../src/tui/dolar.ts";

test("comandoDolar: solo con «$ » y algo después", () => {
  assert.equal(comandoDolar("$ ls -la"), "ls -la");
  assert.equal(comandoDolar("$   echo hola  "), "echo hola");
  assert.equal(comandoDolar("$5 de tope"), undefined);
  assert.equal(comandoDolar("$ "), undefined);
  assert.equal(comandoDolar("hola $ ls"), undefined);
});
test("correrComando: junta la salida, da el código y la avisa en vivo", async () => {
  const vivo: string[] = [];
  const c = await correrComando("echo hola; echo error >&2; exit 3", { cwd: tmpdir(), onOutput: (s) => vivo.push(s) });
  assert.match(c.salida, /hola/); assert.match(c.salida, /error/);
  assert.equal(c.codigo, 3); assert.equal(c.cortado, false);
  assert.ok(vivo.join("").includes("hola"));
});
test("correrComando: un comando inexistente no tira, sale distinto de 0", async () => {
  const c = await correrComando("noexiste-cyber-xyz", { cwd: tmpdir() });
  assert.notEqual(c.codigo, 0);
});
test("correrComando: el AbortSignal lo corta", async () => {
  const ac = new AbortController();
  const p = correrComando("sleep 30", { cwd: tmpdir(), signal: ac.signal });
  setTimeout(() => ac.abort(), 100);
  const c = await p;
  assert.equal(c.cortado, true);
});
test("bloqueTerminal: vacío sin corridas; con corridas, comando, salida y código; recorta a los últimos 16 KB", () => {
  assert.equal(bloqueTerminal([]), "");
  const b = bloqueTerminal([{ comando: "echo hola", salida: "hola\n", codigo: 0, cortado: false }]);
  assert.match(b, /^\n\n<terminal>\n/); assert.match(b, /\$ echo hola/); assert.match(b, /hola/); assert.match(b, /<\/terminal>$/);
  const grande = bloqueTerminal([{ comando: "yes", salida: "a".repeat(100_000) + "FIN", codigo: 0, cortado: false }]);
  assert.ok(grande.length < MAX_AGENTE + 500);
  assert.match(grande, /FIN/); assert.match(grande, /recortad/i);
});
test("correrComando: el comando ve el PATH del usuario, no las claves de API", async () => {
  process.env.CYBER_FAKE_KEY = "secreta";
  try {
    const c = await correrComando('echo "$PATH|$CYBER_FAKE_KEY"', { cwd: tmpdir() });
    assert.ok(c.salida.startsWith(`${process.env.PATH}|`), c.salida);
    assert.doesNotMatch(c.salida, /secreta/);
  } finally { delete process.env.CYBER_FAKE_KEY; }
});
test("correrComando: una salida enorme queda acotada y bloqueTerminal avisa que recortó", async () => {
  const c = await correrComando("seq 1 300000", { cwd: tmpdir() });
  assert.ok(c.salida.length <= MAX_AGENTE + 1);
  assert.match(bloqueTerminal([c]), /recortada/);
});
