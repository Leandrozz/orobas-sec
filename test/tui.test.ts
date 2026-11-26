import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";
import { Editor } from "../src/tui/editor.ts";
import { startFoco } from "../src/tui/foco.ts";
import { KeyParser } from "../src/tui/keys.ts";
import { renderMarkdown } from "../src/tui/markdown.ts";
import { pantallaVisible } from "./pantalla-visible.ts";
import { ADORNO_ABRE, ADORNO_CIERRA, CORTE_ESPACIO, CORTE_PEGADO, adornoTUI, stripAnsi, truncate, visibleWidth, wrapSpans } from "../src/tui/text.ts";

test("texto: ancho por celda, corte y envoltura", () => {
  assert.equal(visibleWidth("☀️ ELEVATE"), 10);
  assert.equal(visibleWidth("\x1b[1mñandú\x1b[0m"), 5);
  assert.equal(visibleWidth("日本"), 4);
  assert.equal(visibleWidth(truncate("\x1b[1muna línea larga\x1b[0m", 8)), 8);
  assert.deepEqual(wrapSpans([{ text: "uno dos tres cuatro" }], 9, "  ").map(stripAnsi), ["  uno dos", "  tres", "  cuatro"]);
  assert.deepEqual(wrapSpans([{ text: "abcdefghij" }], 6, "  ").map(stripAnsi), ["  abcd", "  efgh", "  ij"]);
  for (const line of wrapSpans([{ text: "palabra ".repeat(30) }], 23, "  ")) assert.ok(visibleWidth(line) <= 23);
});

test("teclas: secuencias, pegado delimitado partido y Escape suelto", () => {
  const parser = new KeyParser();
  const names = (data: string) => parser.parse(data).map((key) => key.name + (key.text ? `:${key.text}` : ""));
  assert.deepEqual(names("hola\r"), ["text:hola", "enter"]);
  assert.deepEqual(names("\x1b[A\x1b[1;5D\x1b\r\x1b"), ["up", "wordLeft", "newline", "escape"]);
  assert.deepEqual(names("\x1b[200~línea 1\r\nlín"), []);
  assert.deepEqual(names("ea 2\x1b[201~x"), ["paste:línea 1\nlínea 2", "text:x"]);
  assert.deepEqual(names("\x1b[99;5u\x03"), ["ctrl+c", "ctrl+c"]);
});

test("pegado: inicio y cierre pueden partirse en cualquier punto sin bloquear las siguientes teclas", () => {
  const input = "\x1b[200~línea 1\r\nlínea 2\x1b[201~\r";
  for (let split = 2; split < input.length; split++) {
    const parser = new KeyParser();
    const keys = [...parser.parse(input.slice(0, split)), ...parser.parse(input.slice(split))];
    assert.deepEqual(keys, [{ name: "paste", text: "línea 1\nlínea 2" }, { name: "enter" }], `corte en ${split}`);
    assert.deepEqual(parser.parse("\x04"), [{ name: "ctrl+d" }]);
  }
});

test("pegado incompleto: Ctrl+C y Ctrl+D siguen disponibles, incluso después de un terminador parcial", () => {
  for (const control of ["\x03", "\x04"]) {
    const parser = new KeyParser();
    parser.parse("\x1b[200~texto\x1b[20");
    assert.deepEqual(parser.parse(control), [{ name: control === "\x03" ? "ctrl+c" : "ctrl+d" }]);
    assert.deepEqual(parser.parse("hola\r"), [{ name: "text", text: "hola" }, { name: "enter" }]);
  }
});

test("CSI-u: salida, texto, Enter y key-up funcionan con un protocolo heredado del shell", () => {
  const parser = new KeyParser();
  assert.deepEqual(parser.parse("\x1b[99;5u\x1b[100;5u\x1b[13u\x1b[97u\x1b[97;2u\x1b[97;1:3u"), [
    { name: "ctrl+c" }, { name: "ctrl+d" }, { name: "enter" }, { name: "text", text: "a" }, { name: "text", text: "A" },
  ]);
  assert.deepEqual(parser.parse("\x1b[999999999999999999u"), []);
});

test("editor: edición, líneas, historial y cursor en celdas", () => {
  const editor = new Editor();
  const press = (...names: string[]) => names.forEach((name) => editor.handle({ name }));
  editor.handle({ name: "text", text: "año 日本" });
  assert.deepEqual(editor.view(40, 5), { lines: ["  › año 日本"], cursorRow: 0, cursorCol: 12 });
  press("backspace", "wordLeft", "left");
  editor.handle({ name: "text", text: "!" });
  assert.equal(editor.text, "año! 日");
  press("newline");
  editor.handle({ name: "text", text: "dos" });
  assert.equal(editor.view(40, 5).cursorRow, 1);
  press("up", "home", "killToEnd");
  assert.equal(editor.text, "\ndos 日");
  editor.remember("primero");
  editor.remember("segundo");
  editor.set("");
  press("up");
  assert.equal(editor.text, "segundo");
  press("up", "down", "down");
  assert.equal(editor.text, "");
  // Línea más ancha que la terminal: se parte y el cursor sigue visible.
  editor.set("x".repeat(50));
  const view = editor.view(24, 2);
  assert.equal(view.lines.length, 2);
  assert.ok(view.lines.every((line) => visibleWidth(line) <= 24));
});

test("markdown: bloques y énfasis dentro del ancho", () => {
  const rows = renderMarkdown("# Título\n- **uno** y `dos`\n```\ncódigo *crudo*\n```\n1. [enlace](http://x)", 40).map(stripAnsi);
  assert.deepEqual(rows, ["  Título", "  · uno y dos", "  │ código *crudo*", "  1. enlace (http://x)"]);
  // Negrita con un asterisco dentro de código, como en `/api/operador/*`.
  assert.deepEqual(renderMarkdown("**Pendiente: ver `/api/*` hoy.** Listo, 2*3 y 4*5.", 60).map(stripAnsi), ["  Pendiente: ver /api/* hoy. Listo, 2*3 y 4*5."]);
  const table = renderMarkdown("| ruta | comprador |\n|---|---|\n| GET `/a/reembolsos` | **200** |\n| GET /b | 403 |\nfin", 40).map(stripAnsi);
  assert.deepEqual(table, ["  ruta               comprador", "  ─────────────────  ─────────", "  GET /a/reembolsos  200", "  GET /b             403", "  fin"]);
  assert.ok(renderMarkdown("| una columna bastante larga | otra columna igual de larga |\n|---|---|\n| a | b |", 30).every((row) => visibleWidth(row) <= 30));
});

test("foco sobre el daemon: conversación, comandos, salida y vuelta a un turno en curso", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
  // Espera a que la salida cumpla la condición en vez de adivinar cuánto tarda un turno.
  const until = async (done: () => boolean, ms = 3000) => {
    for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
  };
  const open = async (session: string) => {
    const state = { written: "", input: (_: string) => {}, exited: false };
    const client = await connectDaemon(cwd, { spawn: false });
    const snapshot = await client.attach({ session });
    startFoco(client, snapshot, {
      io: { output: { write: (data) => void (state.written += data), columns: 70, rows: 30 }, listen: (onData) => ((state.input = onData), () => {}) },
      onExit: () => ((state.exited = true), client.close()),
    });
    return { state, plain: () => pantallaVisible(state.written, 70, 30).join("\r\n") };
  };
  try {
    provider.faux!.queue = [
      { toolCalls: [{ name: "fixture_run", arguments: { name: "atlas-permisos" } }] },
      { text: "Hay **2** candidatos.\n\n| ruta | status |\n|---|---|\n| /a | 200 |\nSon sintéticos." },
    ];
    const first = await open("new");
    assert.doesNotMatch(first.plain(), /☀️ ELEVATE AI \/ CYBER/);
    assert.match(first.plain(), /¿Qué querés investigar ahora\?/);
    // La lista de / tapa el pie y se recorre con ↑↓ (vuelve al final desde el primero).
    const mark = first.state.written.length;
    first.state.input("/");
    assert.match(stripAnsi(first.state.written.slice(mark)), /\/sesiones \(\/resume\) +Sesiones del proyecto/);
    assert.doesNotMatch(stripAnsi(first.state.written.slice(mark)), /Enter enviar/);
    first.state.input("\x1b[B\x1b[B\x1b[A\x1b[B\t");
    assert.match(first.plain(), /› \/informe \s/);
    first.state.input("\x03");
    // Un alias en el otro idioma también aparece en la lista, con su par entre paréntesis, y Tab completa lo tipeado.
    first.state.input("/lang");
    assert.match(first.plain(), /\/lang \(\/idioma\) +En \/config · Idioma de la interfaz/);
    first.state.input("\t");
    assert.match(first.plain(), /› \/lang \s/);
    first.state.input("\x03");
    first.state.input("/cos");
    assert.match(first.plain(), /\/costos \(\/cost\) +En \/limites · Detalle del gasto/);
    assert.match(first.plain(), /╭─ Comandos/);
    // En conhost la fuente no tiene esquinas redondeadas.
    process.env.CYBER_CONSOLE = "conhost";
    const before = first.state.written.length;
    first.state.input("\x1b[B");
    delete process.env.CYBER_CONSOLE;
    assert.match(stripAnsi(first.state.written.slice(before)), /┌─ Comandos[^╭]*└/);
    assert.doesNotMatch(first.state.written.slice(before), /[╭╮╰╯]/);
    first.state.input("\t\r");
    await tick();
    assert.match(first.plain(), /COSTO API ESTIMADO/);
    first.state.input("Revisá permisos\r");
    await until(() => /ruta  status\r\n  ────  ──────\r\n  \/a    200/.test(first.plain()));
    assert.match(first.plain(), /── Vos [^\r]*\r\n  Revisá permisos/);
    assert.match(first.plain(), /✓ Ejecutar fixture · artefacto [0-9a-f]{12} · candidatos 2/);
    assert.match(first.plain(), /── Orobas [^\r]*\r\n  Hay 2 candidatos\.\r\n/);
    assert.match(first.plain(), /ruta  status\r\n  ────  ──────\r\n  \/a    200/);
    assert.match(first.plain(), / OROBAS  USD [\d.]+ \+2 pend\. \/ 2\.00 /);
    first.state.input("/jobs\r");
    await tick();
    assert.match(first.plain(), /TRABAJOS · sesiones del proyecto/);

    // Turno largo: la interfaz se va y el agente sigue; otra interfaz lo retoma en curso.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const host = [...daemon.hosts.values()][0]!;
    host.engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
    provider.faux!.queue = [{ text: "Empiezo.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Terminé en segundo plano." }];
    first.state.input("Trabajá solo\r");
    await tick();
    first.state.input("\x04");
    assert.ok(first.state.exited);
    assert.ok(first.state.written.endsWith("\x1b[?25h\x1b[0m"));
    await tick();
    assert.equal(host.engine.agent.running, true);

    const second = await open("last");
    assert.doesNotMatch(second.plain(), /notas de memoria · sesión/);
    assert.match(second.plain(), /Empiezo\./);
    assert.match(second.plain(), /› Esperar +en curso/);
    assert.match(second.plain(), / EN CURSO .*Esc detener/);
    release();
    await until(() => /Terminé en segundo plano\./.test(second.plain()));
    assert.match(second.plain(), /Terminé en segundo plano\./);
    assert.equal(host.engine.agent.running, false);
    second.state.input("\x03");
    assert.match(second.plain(), /Ctrl\+C otra vez para salir/);
    second.state.input("\x03");
    assert.ok(second.state.exited);
  } finally {
    daemon.close();
  }
});

test("link: hiperenlace OSC 8, texto plano en conhost o TERM=dumb, y no rompe el ancho ni truncate", async () => {
  const { link } = await import("../src/tui/text.ts");
  const saved = { c: process.env.CYBER_CONSOLE, t: process.env.TERM };
  try {
    delete process.env.CYBER_CONSOLE;
    process.env.TERM = "xterm";
    const u = "https://cyber.elevateai.ar/cuenta";
    assert.equal(link(u), `\x1b]8;;${u}\x1b\\${u}\x1b]8;;\x1b\\`);
    assert.equal(link(u, "cuenta"), `\x1b]8;;${u}\x1b\\cuenta\x1b]8;;\x1b\\`);
    assert.equal(visibleWidth(link(u)), visibleWidth(u));
    for (let width = 1; width < u.length; width++) {
      const cut = truncate(link(u), width);
      assert.ok(visibleWidth(cut) <= width);
      // Nunca corta dentro de la secuencia y el enlace queda cerrado.
      assert.equal(cut.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[0m/g, "").includes("\x1b"), false);
      assert.ok(cut.endsWith("\x1b]8;;\x1b\\\x1b[0m"));
    }
    process.env.CYBER_CONSOLE = "conhost";
    assert.equal(link(u), u);
    delete process.env.CYBER_CONSOLE;
    process.env.TERM = "dumb";
    assert.equal(link(u), u);
  } finally {
    for (const [k, v] of [["CYBER_CONSOLE", saved.c], ["TERM", saved.t]] as const) v === undefined ? delete process.env[k] : (process.env[k] = v);
  }
});

test("wrapSpans: las continuaciones llevan la marca de corte", () => {
  assert.deepEqual(wrapSpans([{ text: "uno dos tres" }], 9, "  "), ["  uno dos", `${CORTE_ESPACIO}  tres`]);
  assert.deepEqual(wrapSpans([{ text: "abcdefghij" }], 6, "  "), ["  abcd", `${CORTE_PEGADO}  efgh`, `${CORTE_PEGADO}  ij`]);
  assert.equal(stripAnsi(CORTE_ESPACIO + ADORNO_ABRE + "x" + ADORNO_CIERRA), "x");
  assert.equal(visibleWidth(adornoTUI("│")), 1);
});

test("linkify/wrapText: la puntuación final queda fuera del enlace y el corte no parte el OSC 8", async () => {
  const { linkify, wrapText } = await import("../src/tui/text.ts");
  const saved = { c: process.env.CYBER_CONSOLE, t: process.env.TERM };
  try {
    delete process.env.CYBER_CONSOLE;
    process.env.TERM = "xterm";
    assert.equal(
      linkify("fallo en https://x.io/a, reintentá. ver https://x.io/b."),
      "fallo en \x1b]8;;https://x.io/a\x1b\\https://x.io/a\x1b]8;;\x1b\\, reintentá. ver \x1b]8;;https://x.io/b\x1b\\https://x.io/b\x1b]8;;\x1b\\.",
    );
    const text = "abrí https://github.com/login/device e ingresá";
    for (const width of [30, 20]) {
      const lines = wrapText(linkify(text), width);
      for (const line of lines) {
        assert.ok(visibleWidth(line) <= width);
        // Cada línea es autónoma: aperturas y cierres de enlace balanceados.
        assert.equal((line.match(/\x1b\]8;;[^\x1b]/g) ?? []).length, (line.match(/\x1b\]8;;\x1b\\/g) ?? []).length);
      }
      assert.equal(stripAnsi(lines.join("")).replaceAll(" ", ""), text.replaceAll(" ", ""));
    }
  } finally {
    for (const [k, v] of [["CYBER_CONSOLE", saved.c], ["TERM", saved.t]] as const) v === undefined ? delete process.env[k] : (process.env[k] = v);
  }
});
