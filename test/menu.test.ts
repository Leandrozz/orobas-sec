import assert from "node:assert/strict";
import { test } from "node:test";
import { askHiddenInTerminal, pickInTerminal } from "../src/menu.ts";

function typed(text: string, run: () => Promise<unknown>) {
  const stdin = process.stdin;
  const result = run();
  setImmediate(() => stdin.emit("data", Buffer.from(text)));
  return result;
}

test("terminal: pickInTerminal devuelve el índice y undefined fuera de rango", async () => {
  const log = console.log;
  console.log = () => {};
  try {
    assert.equal(await typed("2\r", () => pickInTerminal("T", ["a", "b"])), 1);
    assert.equal(await typed("9\r", () => pickInTerminal("T", ["a", "b"])), undefined);
  } finally { console.log = log; }
});

test("terminal: askHiddenInTerminal no muestra lo escrito y vacío es undefined", async () => {
  const write = process.stdout.write;
  let out = "";
  // El ejecutor de tests escribe Buffers por el mismo stdout: esos pasan, solo se captura el texto.
  process.stdout.write = ((chunk: string | Uint8Array) => { if (typeof chunk === "string") out += chunk; else write.call(process.stdout, chunk); return true; }) as typeof write;
  try {
    assert.equal(await typed(" clave \r", () => askHiddenInTerminal("Clave")), "clave");
    assert.equal(await typed("\r", () => askHiddenInTerminal("Clave")), undefined);
  } finally { process.stdout.write = write; }
  // Con el eco apagado sale solo el texto de la pregunta y el salto de línea de cada Enter.
  assert.equal(out, "Clave: \nClave: \n");
});
