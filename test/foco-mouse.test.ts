import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";
import { abrirProyecto } from "../src/tui/ajustes.ts";
import { startFoco } from "../src/tui/foco.ts";
import { osc52 } from "../src/tui/portapapeles.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 3000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};

async function armar(rows = 30) {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-mouse-"));
  process.env.CYBER_CONFIG = join(cwd, "config.json"); // ventanas y pestañas son generales: cada prueba con su configuración
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  abrirProyecto(cwd);
  const state = { written: "", input: (_: string) => {}, resize: () => {}, exited: false };
  const output = { write: (data: string) => void (state.written += data), columns: 70, rows };
  const client = await connectDaemon(cwd, { spawn: false });
  const snapshot = await client.attach({ session: "new" });
  const foco = startFoco(client, snapshot, {
    project: cwd,
    io: { output, listen: (onData, onResize) => ((state.input = onData), (state.resize = onResize), () => {}) },
    onExit: () => ((state.exited = true), client.close()),
    onboarding: false,
  });
  const filas = () => pantallaVisible(state.written, output.columns, output.rows);
  const visible = () => filas().join("\r\n");
  /** Fila (1-based) y columna (1-based) del texto en pantalla. */
  const donde = (texto: string) => {
    const i = filas().findIndex((f) => f.includes(texto));
    return { fila: i + 1, col: filas()[i]!.indexOf(texto) + 1 };
  };
  const down = (c: number, f: number) => state.input(`\x1b[<0;${c};${f}M`);
  const drag = (c: number, f: number) => state.input(`\x1b[<32;${c};${f}M`);
  const up = (c: number, f: number) => state.input(`\x1b[<0;${c};${f}m`);
  return { foco, state, provider, daemon, output, filas, visible, donde, down, drag, up };
}

const hablar = async (t: Awaited<ReturnType<typeof armar>>, texto = "Buenas.") => {
  t.provider.faux!.queue = [{ text: texto }];
  t.state.input("hola\r");
  await until(() => t.visible().includes(texto.split("\n").pop()!));
};

test("mouse: arrastrar copia y avisa sin ⚠", async () => {
  const t = await armar();
  try {
    await hablar(t);
    const { fila, col } = t.donde("Buenas.");
    t.down(col, fila); t.drag(col + 6, fila); t.up(col + 6, fila);
    assert.ok(t.state.written.includes(osc52("Buenas.")));
    assert.match(t.visible(), /✓ 7 caracteres copiados al portapapeles/);
    assert.doesNotMatch(t.visible(), /⚠/);
    assert.ok(t.state.written.includes("\x1b[7m"));
  } finally { t.daemon.close(); }
});

test("mouse: un clic sin arrastre no copia", async () => {
  const t = await armar();
  try {
    await hablar(t);
    const { fila, col } = t.donde("Buenas.");
    t.down(col, fila); t.up(col, fila);
    assert.doesNotMatch(t.state.written, /\x1b\]52;/);
  } finally { t.daemon.close(); }
});

test("mouse: doble clic copia la palabra", async () => {
  const t = await armar();
  try {
    await hablar(t, "uno dos tres");
    const { fila, col } = t.donde("dos");
    for (let i = 0; i < 2; i++) { t.down(col + 1, fila); t.up(col + 1, fila); }
    assert.ok(t.state.written.includes(osc52("dos")));
  } finally { t.daemon.close(); }
});

test("mouse: lo nuevo no mueve la selección", async () => {
  const t = await armar();
  try {
    await hablar(t);
    const { fila, col } = t.donde("Buenas.");
    t.down(col, fila); t.drag(col + 6, fila);
    t.provider.faux!.queue = [{ text: "Otra cosa." }];
    t.foco.submit("más");
    await until(() => /Otra cosa\./.test(t.visible()));
    const j = t.donde("Buenas.");
    t.up(j.col + 6, j.fila);
    assert.ok(t.state.written.includes(osc52("Buenas.")));
  } finally { t.daemon.close(); }
});

test("mouse: un cambio de ancho borra la selección", async () => {
  const t = await armar();
  try {
    await hablar(t);
    const { fila, col } = t.donde("Buenas.");
    t.down(col, fila); t.drag(col + 6, fila); t.up(col + 6, fila);
    const antes = t.state.written.length;
    t.output.columns = 50;
    t.state.resize();
    assert.doesNotMatch(t.state.written.slice(antes), /\x1b\[7m/);
  } finally { t.daemon.close(); }
});

test("mouse: arrastrar por debajo del área autodesplaza", async () => {
  const t = await armar();
  try {
    const largo = Array.from({ length: 40 }, (_, i) => `línea ${i + 1}`).join("\n\n");
    await hablar(t, largo);
    t.state.input("\x1b[5~");
    assert.doesNotMatch(t.visible(), /línea 40/);
    const f = t.filas().findIndex((l) => /línea/.test(l)) + 1;
    t.down(3, f); t.drag(20, t.output.rows);
    await tick(1200);
    t.up(20, t.output.rows);
    const copiado = /\x1b\]52;c;([^\x07]*)\x07/.exec(t.state.written);
    assert.ok(copiado, "se copió algo");
    assert.match(Buffer.from(copiado![1]!, "base64").toString().replace(/\n/g, "|"), /línea 40/);
  } finally { t.daemon.close(); }
});

test("mouse: con /config abierto el mouse no hace nada", async () => {
  const t = await armar();
  try {
    await hablar(t);
    t.state.input("/config\r");
    await until(() => /Configuración/.test(t.visible()));
    const antes = t.visible();
    t.down(5, 3); t.drag(20, 3); t.up(20, 3);
    assert.doesNotMatch(t.state.written, /\x1b\]52;/);
    assert.equal(t.visible(), antes);
  } finally { t.daemon.close(); }
});

test("mouse: tras copiar, Ctrl+C muestra su aviso con el símbolo de aviso", async () => {
  const t = await armar();
  try {
    await hablar(t);
    const { fila, col } = t.donde("Buenas.");
    t.down(col, fila); t.drag(col + 6, fila); t.up(col + 6, fila);
    t.state.input("\x03");
    const linea = t.filas().find((l) => l.includes("Ctrl+C otra vez para salir"));
    assert.ok(linea, "aparece el aviso");
    assert.match(linea!, /⚠|\[!\]/);
  } finally { t.daemon.close(); }
});

test("mouse: triple clic copia la línea sin el margen", async () => {
  const t = await armar();
  try {
    await hablar(t, "hola qué tal");
    const { fila, col } = t.donde("hola qué tal");
    for (let i = 0; i < 3; i++) { t.down(col + 1, fila); t.up(col + 1, fila); }
    assert.ok(t.state.written.includes(osc52("hola qué tal")));
  } finally { t.daemon.close(); }
});

test("mouse: una sola pestaña autodesplaza hacia arriba al llegar a la fila 1", async () => {
  const t = await armar();
  try {
    const largo = Array.from({ length: 40 }, (_, i) => `línea ${i + 1}`).join("\n\n");
    await hablar(t, largo);
    const f = t.filas().findIndex((l) => /línea 40/.test(l)) + 1;
    t.down(3, f); t.drag(20, 1);
    await tick(1200);
    t.up(20, 1);
    const copiado = /\x1b\]52;c;([^\x07]*)\x07/.exec(t.state.written);
    assert.ok(copiado, "se copió algo");
    assert.match(Buffer.from(copiado![1]!, "base64").toString(), /línea 1\d\b/);
  } finally { t.daemon.close(); }
});

test("mouse: la ayuda de teclas menciona la copia y tmux", async () => {
  const t = await armar(130);
  try {
    t.state.input("/help\r");
    await until(() => /Teclas|Alt\+1/.test(t.visible()));
    assert.match(t.visible(), /allow-passthrough on/);
  } finally { t.daemon.close(); }
});
