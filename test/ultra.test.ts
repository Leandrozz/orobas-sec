import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { guardarUltra, ultraGuardado, ULTRA_POR_DEFECTO } from "../src/tui/ajustes.ts";
import { armarUltra, dentroDeDocker, leerCorridas, leerHarnesses, menuOrquesta, selectorUltra, type Harness } from "../src/tui/ultra.ts";
import { fakeIO } from "./fake-io.ts";

process.env.LC_ALL = "es_AR.UTF-8";

test("leerHarnesses: ignora líneas sin el formato", () => {
  assert.deepEqual(leerHarnesses(["claude   ✓ /usr/bin/claude · Claude Code", "pi       ✗ no instalado · pi", "basura"]), [
    { id: "claude", label: "Claude Code", instalado: true },
    { id: "pi", label: "pi", instalado: false },
  ]);
});

test("leerCorridas: sólo filas con «#»", () => {
  const fila = (id: string, est: string, rama: string, tarea: string) => `#${id}  claude   ${est.padEnd(10)} 11-17 21:40  ${rama.padEnd(34)} ${tarea}`;
  const r = leerCorridas([
    "ORQUESTA · corridas de harnesses",
    fila("a3f", "corriendo", "orobas/login-1", "arreglá el login"),
    "", "anteriores:",
    fila("b4", "terminado", "sin worktree", ""),
    "Para ver una: /orquesta ver <id>",
  ]);
  assert.deepEqual(r, [
    { id: "a3f", harness: "claude", estado: "corriendo", rama: "orobas/login-1", tarea: "arreglá el login", enCurso: true, anterior: false },
    { id: "b4", harness: "claude", estado: "terminado", rama: undefined, tarea: "", enCurso: false, anterior: true },
  ]);
  assert.deepEqual(leerCorridas(["Sin corridas de otros harnesses. …", "", "claude   ✓ x · Claude"]), []);
});

const hs = (...ids: string[]): Harness[] => ["claude", "codex", "pi"].map((id) => ({ id, label: id, instalado: ids.includes(id) }));
const G = { harnesses: ["claude", "codex"], partes: 3 as number | "auto", modo: "repo" as const };

test("armarUltra: lo guardado completa lo que no se escribió", () => {
  const r = armarUltra("arreglá el login", G, hs("claude", "codex"), 0);
  assert.equal(r.arg, "arreglá el login --con claude,codex --partes 3");
  for (const s of ["claude, codex", "3 partes", "repositorio", "/ultra para cambiar"]) assert.ok(r.linea.includes(s), s);
});

test("armarUltra: lo escrito gana", () => {
  const r = armarUltra("x --con pi", G, hs("claude", "codex", "pi"), 0);
  assert.equal(r.arg.split("--con pi").length, 2);
  assert.ok(r.arg.includes("--partes 3"));
  assert.ok(r.linea.includes("pi") && !r.linea.includes("codex"));
});

test("armarUltra: harness no instalado, auto, objetivo y aviso", () => {
  const a = armarUltra("x", { ...G, harnesses: ["codex"] }, hs("claude"), 0);
  assert.equal(a.arg, "x --partes 3");
  assert.ok(a.linea.includes("todos los instalados"));
  const b = armarUltra("x", { ...G, partes: "auto" }, hs("claude", "codex"), 0);
  assert.ok(!b.arg.includes("--partes") && b.linea.includes("partes auto"));
  const c = armarUltra("x", { ...G, modo: "objetivo" }, hs("claude", "codex"), 0);
  assert.ok(c.arg.includes("--objetivo") && !c.arg.includes("--con"));
  assert.ok(c.linea.startsWith("ultra · objetivo") && !c.linea.includes("claude"));
  assert.ok(armarUltra("x", G, hs("claude"), 5).linea.includes("hay 5 en curso"));
  assert.ok(!armarUltra("x", G, hs("claude"), 3).linea.includes("en curso"));
});

test("dentroDeDocker: existe el archivo o no", () => {
  const f = join(mkdtempSync(join(tmpdir(), "cyber-ultra-")), "d");
  writeFileSync(f, "");
  assert.equal(dentroDeDocker(f), true);
  assert.equal(dentroDeDocker(f + "x"), false);
});

const HARN = ["claude   ✓ /usr/bin/claude · Claude Code", "codex    ✓ /usr/bin/codex · Codex", "pi       ✗ no instalado · pi"];
const HARN_PI = ["claude   ✓ /usr/bin/claude · Claude Code", "codex    ✓ /usr/bin/codex · Codex", "pi       ✓ /usr/bin/pi · pi"];
const KEY = 'orquesta:{"action":"harnesses"}';
const falso = (codigo = 0, salida = "ok") => {
  const comandos: Array<{ comando: string; cwd: string }> = [];
  return { comandos, correr: async (comando: string, o: { cwd: string }) => { comandos.push({ comando, cwd: o.cwd }); return { comando, salida, codigo, cortado: false }; } };
};
const limpio = () => guardarUltra({ ...ULTRA_POR_DEFECTO });

test("selector: filas, orden y pistas", async () => {
  limpio();
  const { io, picked } = fakeIO({ [KEY]: HARN }, [undefined]);
  assert.equal(await selectorUltra(io, { docker: false }), null);
  assert.equal(picked[0]!.title, "ultra");
  assert.deepEqual(picked[0]!.labels, ["✓ Claude Code", "✓ Codex", "↓ pi", "partes: auto", "modo: repositorio", "listo"]);
  assert.equal(picked[0]!.hints[2], "no instalado · Enter para instalar");
  const d = fakeIO({ [KEY]: HARN }, [undefined]);
  await selectorUltra(d.io, { docker: true });
  assert.equal(d.picked[0]!.hints[2], "no disponible dentro de Docker");
  guardarUltra({ partes: "auto", modo: "objetivo" });
  const o = fakeIO({ [KEY]: HARN }, [undefined]);
  await selectorUltra(o.io, { docker: false });
  assert.equal(o.picked[0]!.hints[0], "no aplica en modo objetivo");
});

test("selector: desmarcar, partes, modo y listo guardan; Esc no guarda", async () => {
  limpio();
  const a = fakeIO({ [KEY]: HARN }, [0, 3, 3, 3, 3, 3, 3, 4, 5]);
  const panel = await selectorUltra(a.io, { docker: false });
  assert.equal(a.picked[1]!.labels[0], "· Claude Code");
  assert.equal(a.picked[1]!.at, 0);
  assert.equal(a.picked[2]!.at, 3);
  assert.deepEqual(a.picked.slice(1, 7).map((p) => p.labels[3]), ["partes: auto", "partes: 2", "partes: 3", "partes: 4", "partes: 5", "partes: 6"]);
  assert.equal(a.picked[7]!.labels[3], "partes: auto");
  assert.equal(a.picked[8]!.labels[4], "modo: objetivo");
  assert.deepEqual(ultraGuardado(), { harnesses: ["codex"], partes: "auto", modo: "objetivo" });
  assert.match(panel!.lines[0]!, /^ultra · objetivo/);
  limpio();
  const b = fakeIO({ [KEY]: HARN }, [0, 3, undefined]);
  assert.equal(await selectorUltra(b.io, { docker: false }), null);
  assert.deepEqual(ultraGuardado(), ULTRA_POR_DEFECTO);
});

test("selector: listo sin marcar en repo avisa y sigue", async () => {
  limpio();
  const { io, picked, notices } = fakeIO({ [KEY]: HARN }, [0, 1, 5, undefined]);
  assert.equal(await selectorUltra(io, { docker: false }), null);
  assert.equal(notices[0]!.tone, "warn");
  assert.match(notices[0]!.lines[0]!, /Marcá al menos uno/);
  assert.equal(picked.length, 4);
  assert.deepEqual(ultraGuardado(), ULTRA_POR_DEFECTO);
});

test("selector: instalar con confirmación", async () => {
  limpio();
  const f = falso();
  let n = 0;
  const { io, confirms, notices, picked } = fakeIO({}, [2, 0, undefined]);
  const ask = io.ask;
  io.ask = async (op, p) => (JSON.stringify(p).includes("harnesses") ? (n++ === 0 ? HARN : HARN_PI) : ask(op, p));
  await selectorUltra(io, { docker: false, correr: f.correr as never });
  assert.match(confirms[0]!, /npm i -g @mariozechner\/pi-coding-agent/);
  assert.deepEqual(f.comandos, [{ comando: "npm i -g @mariozechner/pi-coding-agent", cwd: homedir() }]);
  assert.match(notices[0]!.lines[0]!, /instalando/);
  assert.equal(picked[1]!.labels[2], "✓ pi");
  const no = falso();
  const r = fakeIO({ [KEY]: HARN }, [2, 1, undefined]);
  await selectorUltra(r.io, { docker: false, correr: no.correr as never });
  assert.equal(no.comandos.length, 0);
});

test("selector: instalado pero invisible, falla y Docker", async () => {
  limpio();
  const f = falso();
  const a = fakeIO({ [KEY]: HARN }, [2, 0, undefined]);
  await selectorUltra(a.io, { docker: false, correr: f.correr as never });
  assert.equal(a.picked[1]!.labels[2], "↓ pi");
  assert.equal(a.picked[1]!.hints[2], "instalado; reiniciá cyber para que lo vea");
  const mal = falso(1, "a\nb\nboom");
  const b = fakeIO({ [KEY]: HARN }, [2, 0, undefined]);
  await selectorUltra(b.io, { docker: false, correr: mal.correr as never });
  assert.equal(b.notices.at(-1)!.tone, "warn");
  assert.ok(b.notices.at(-1)!.lines.includes("boom"));
  assert.equal(b.picked[1]!.labels[2], "↓ pi");
  const dk = falso();
  const c = fakeIO({ [KEY]: HARN }, [2, undefined]);
  await selectorUltra(c.io, { docker: true, correr: dk.correr as never });
  assert.equal(c.confirms.length, 0);
  assert.equal(dk.comandos.length, 0);
});

test("selector: un id heredado como «constructor» no tiene comando de instalación", async () => {
  limpio();
  const f = falso();
  const { io, confirms } = fakeIO({ [KEY]: ["constructor ✗ no instalado · x"] }, [0, undefined]);
  await selectorUltra(io, { docker: false, correr: f.correr as never });
  assert.equal(confirms.length, 0);
  assert.equal(f.comandos.length, 0);
});

const filaC = (id: string, est: string, rama: string, tarea: string) => `#${id}  claude   ${est.padEnd(10)} 11-17 21:40  ${rama.padEnd(34)} ${tarea}`;
const H1 = ["claude   ✓ /usr/bin/claude · Claude Code"];
const CORRIDAS = ["ORQUESTA · corridas de harnesses", filaC("a3f", "corriendo", "orobas/login-1", "arreglá el login"), filaC("b4", "terminado", "orobas/x-2", "otra"), filaC("c5", "terminado", "sin worktree", "sin rama")];
const mk = (picks: Array<number | undefined>) => fakeIO({ "orquesta:{}": CORRIDAS, 'orquesta:{"action":"harnesses"}': H1 }, picks);

test("menuOrquesta: una fila por corrida y al final los harnesses", async () => {
  const { io, picked } = mk([undefined]);
  assert.equal(await menuOrquesta(io), null);
  assert.equal(picked[0]!.title, "orquesta");
  assert.deepEqual(picked[0]!.labels, ["#a3f  claude  corriendo", "#b4  claude  terminado", "#c5  claude  terminado", "harnesses instalados"]);
  assert.deepEqual(picked[0]!.hints.slice(0, 3), ["orobas/login-1 · arreglá el login", "orobas/x-2 · otra", "sin worktree · sin rama"]);
});

test("menuOrquesta: parar pide confirmación", async () => {
  const si = mk([0, 1, 0]);
  await menuOrquesta(si.io);
  assert.deepEqual(si.picked[1]!.labels, ["ver", "parar"]);
  assert.deepEqual(si.calls.at(-1), { op: "orquesta", payload: { action: "parar", run: "a3f" } });
  const no = mk([0, 1, 1]);
  assert.equal(await menuOrquesta(no.io), null);
  assert.ok(!no.calls.some((c) => (c.payload as { action?: string }).action === "parar"));
});

test("menuOrquesta: terminada con rama limpia worktree o todo; sin worktree sólo ver", async () => {
  const todo = mk([1, 2, 0]);
  await menuOrquesta(todo.io);
  assert.deepEqual(todo.picked[1]!.labels, ["ver", "limpiar", "limpiar todo"]);
  assert.deepEqual(todo.calls.at(-1)!.payload, { action: "limpiar", run: "b4", rama: true });
  const solo = mk([1, 1, 0]);
  await menuOrquesta(solo.io);
  assert.deepEqual(solo.calls.at(-1)!.payload, { action: "limpiar", run: "b4", rama: false });
  const sin = mk([2, undefined]);
  await menuOrquesta(sin.io);
  assert.deepEqual(sin.picked[1]!.labels, ["ver"]);
});

test("menuOrquesta: ver, esc y harnesses", async () => {
  const ver = mk([0, 0]);
  const p = await menuOrquesta(ver.io);
  assert.deepEqual(ver.calls.at(-1)!.payload, { action: "ver", run: "a3f" });
  assert.equal(p?.title, "orquesta #a3f");
  const esc = mk([0, undefined]);
  assert.equal(await menuOrquesta(esc.io), null);
  assert.ok(!esc.calls.some((c) => (c.payload as { action?: string }).action === "ver"));
  const h = mk([3, undefined]);
  await menuOrquesta(h.io);
  assert.equal(h.picked[1]!.title, "ultra");
});

test("menuOrquesta: sin corridas sólo ofrece harnesses, con la primera línea al pie", async () => {
  const { io, picked } = fakeIO({ "orquesta:{}": ["Sin corridas de otros harnesses.", "", ...H1] }, [undefined]);
  await menuOrquesta(io);
  assert.deepEqual(picked[0]!.labels, ["harnesses instalados"]);
  assert.equal(picked[0]!.footer, "Sin corridas de otros harnesses.");
});

// --- Hallazgos de la revisión final ---

test("leerCorridas: tarea con salto de línea (como la entrega view()) no hace desaparecer la fila", () => {
  const r = leerCorridas([filaC("n1", "terminado", "orobas/x-2", "arreglá\n  el   login"), filaC("n2", "terminado", "orobas/y", "corta")]);
  assert.deepEqual(r.map((c) => [c.id, c.tarea]), [["n1", "arreglá el login"], ["n2", "corta"]]);
});

test("menuOrquesta: las corridas anteriores son de sólo lectura y no abren acciones", async () => {
  const ant = ["ORQUESTA · corridas de harnesses", filaC("a3f", "corriendo", "orobas/login-1", "x"), "", "anteriores:", filaC("o1", "terminado", "orobas/z-9", "vieja")];
  const { io, picked } = fakeIO({ "orquesta:{}": ant }, [1, undefined]);
  assert.equal(await menuOrquesta(io), null);
  assert.equal(picked.length, 2);
  assert.equal(picked[0]!.title, "orquesta");
  assert.match(picked[0]!.hints[1]!, /de otra sesión: sólo lectura/);
  assert.ok(!picked[0]!.hints[0]!.includes("sólo lectura"));
  assert.equal(picked[1]!.title, "orquesta");
});

test("selector: instalar avisa que puede tardar y muestra la cola de la salida al terminar bien", async () => {
  limpio();
  const f = falso(0, "uno\n\n\ndos\n");
  const { io, notices } = fakeIO({ [KEY]: HARN }, [2, 0, undefined]);
  await selectorUltra(io, { docker: false, correr: f.correr as never });
  assert.match(notices[0]!.lines[0]!, /instalando pi… \(puede tardar unos minutos\)/);
  assert.deepEqual(notices[1]!.lines.slice(-2), ["uno", "dos"]);
});

test("selector: instalación sin código dice «no se pudo ejecutar» y sin líneas vacías", async () => {
  limpio();
  const f = falso(null as never, "\n\nboom\n");
  const { io, notices } = fakeIO({ [KEY]: HARN }, [2, 0, undefined]);
  await selectorUltra(io, { docker: false, correr: f.correr as never });
  const w = notices.at(-1)!;
  assert.equal(w.tone, "warn");
  assert.match(w.lines[0]!, /no se pudo ejecutar/i);
  assert.ok(!w.lines.join("|").includes("null"));
  assert.deepEqual(w.lines.slice(1), ["boom"]);
});

test("selector: listo conserva lo guardado aunque no esté instalado, sin duplicar", async () => {
  guardarUltra({ harnesses: ["claude", "pi"], partes: "auto", modo: "repo" });
  const { io } = fakeIO({ [KEY]: HARN }, [5]);
  await selectorUltra(io, { docker: false });
  assert.deepEqual(ultraGuardado().harnesses, ["claude", "pi"]);
  guardarUltra({ harnesses: ["claude", "pi"], partes: "auto", modo: "repo" });
  const b = fakeIO({ [KEY]: HARN_PI }, [5]);
  await selectorUltra(b.io, { docker: false });
  assert.deepEqual(ultraGuardado().harnesses, ["claude", "pi"]);
});

test("selector: si no se puede guardar avisa en warn", async () => {
  limpio();
  const path = process.env.CYBER_CONFIG!;
  const antes = readFileSync(path, "utf8");
  writeFileSync(path, "{no es json");
  try {
    const { io, notices } = fakeIO({ [KEY]: HARN }, [5]);
    await selectorUltra(io, { docker: false });
    assert.equal(notices.at(-1)!.tone, "warn");
    assert.match(notices.at(-1)!.lines[0]!, /JSON/);
  } finally { writeFileSync(path, antes); }
});

test("selector: en Windows nativo no ofrece instalar", async () => {
  limpio();
  const f = falso();
  const { io, picked, confirms } = fakeIO({ [KEY]: HARN }, [2, undefined]);
  await selectorUltra(io, { docker: false, windows: true, correr: f.correr as never });
  assert.equal(picked[0]!.hints[2], "instalalo a mano: npm i -g @mariozechner/pi-coding-agent");
  assert.equal(confirms.length, 0);
  assert.equal(f.comandos.length, 0);
});

test("selector: cyber no instalado dice «no instalado» sin prometer Enter", async () => {
  limpio();
  const { io, picked } = fakeIO({ [KEY]: ["cyber    ✗ no instalado · Orobas"] }, [undefined]);
  await selectorUltra(io, { docker: false });
  assert.equal(picked[0]!.hints[0], "no instalado");
});

test("menuOrquesta: limpiar vacío avisa en warn y el confirm nombra la corrida por #id", async () => {
  const m = fakeIO({ "orquesta:{}": CORRIDAS, 'orquesta:{"action":"limpiar","run":"b4","rama":true}': [] }, [1, 2, 0]);
  const p = await menuOrquesta(m.io);
  assert.equal(p!.tone, "warn");
  assert.match(p!.lines[0]!, /No quedaba worktree/);
  assert.match(m.confirms[0]!, /#b4/);
  assert.ok(!m.confirms[0]!.includes("orobas/x-2"));
});

test("armarUltra: la línea no promete lo que el daemon ignora", () => {
  const a = armarUltra("x --con foo,claude", G, hs("claude", "codex"), 0);
  assert.ok(a.linea.includes("claude") && !a.linea.includes("foo"));
  const b = armarUltra("x --con foo", G, hs("claude", "codex"), 0);
  assert.ok(b.linea.includes("todos los instalados") && !b.linea.includes("foo"));
  const c = armarUltra("x --partes 0", G, hs("claude"), 0);
  assert.ok(c.linea.includes("partes auto") && !c.linea.includes("0 partes"));
  assert.ok(armarUltra("x --partes 1", G, hs("claude"), 0).linea.includes("2 partes"));
  assert.ok(armarUltra("x --partes 9", G, hs("claude"), 0).linea.includes("6 partes"));
});

test("menuOrquesta: el hint no deja un separador colgando si falta la tarea", async () => {
  const m = fakeIO({ "orquesta:{}": ["ORQUESTA · corridas de harnesses", filaC("d6", "terminado", "orobas/y-3", ""), filaC("e7", "terminado", "sin worktree", "")] }, [undefined]);
  await menuOrquesta(m.io);
  assert.deepEqual(m.picked[0]!.hints.slice(0, 2), ["orobas/y-3", "sin worktree"]);
});

test("selector: un harness instalado dentro del selector y desmarcado no vuelve al guardar", async () => {
  guardarUltra({ harnesses: ["claude", "pi"], partes: "auto", modo: "repo" });
  const f = falso();
  const { io } = fakeIO({ [KEY]: HARN }, [2, 0, 2, 5]);
  // tras instalar, el daemon pasa a ✓ (segunda lectura)
  let lecturas = 0;
  const ask = io.ask;
  io.ask = async (op, payload) => (op === "orquesta" && (payload as { action?: string })?.action === "harnesses" && ++lecturas > 1 ? HARN_PI : ask(op, payload));
  await selectorUltra(io, { docker: false, correr: f.correr as never });
  assert.deepEqual(ultraGuardado().harnesses, ["claude"]);
});

test("/ultra sin io.send: devuelve el prompt del daemon como panel", async () => {
  limpio();
  const { io, calls } = fakeIO({ [KEY]: HARN, "orquesta:{}": ["ORQUESTA · corridas de harnesses"] });
  const ask = io.ask;
  io.ask = async (op, payload) => (payload as { action?: string })?.action === "ultra" ? ["PROMPT DEL DAEMON"] : ask(op, payload);
  const { findCommand } = await import("../src/tui/comandos.ts");
  const p = await findCommand("ultra")!.run(io, "x");
  assert.deepEqual(p!.lines, ["PROMPT DEL DAEMON"]);
  assert.ok(calls.length > 0);
});

test("selector: en modo objetivo «listo» guarda aunque no haya nada marcado", async () => {
  guardarUltra({ harnesses: [], partes: "auto", modo: "objetivo" });
  const { io, notices } = fakeIO({ [KEY]: HARN }, [5]);
  const p = await selectorUltra(io, { docker: false });
  assert.ok(p);
  assert.ok(!notices.some((n) => /al menos uno/.test(n.lines[0]!)));
  assert.equal(ultraGuardado().modo, "objetivo");
});

test("menuOrquesta: rechazar «limpiar todo» no llama a limpiar", async () => {
  const m = fakeIO({ "orquesta:{}": CORRIDAS }, [1, 2, 1]);
  assert.equal(await menuOrquesta(m.io), null);
  assert.equal(m.confirms.length, 1);
  assert.ok(!m.calls.some((c) => (c.payload as { action?: string }).action === "limpiar"));
});

test("textos en inglés: línea de armarUltra y hint del selector", async () => {
  const antes = process.env.LC_ALL;
  process.env.LC_ALL = "en_US.UTF-8";
  try {
    assert.match(armarUltra("x", G, hs("claude", "codex"), 0).linea, /3 parts · repository   \(\/ultra to change\)/);
    limpio();
    const { io, picked } = fakeIO({ [KEY]: HARN }, [undefined]);
    await selectorUltra(io, { docker: false });
    assert.equal(picked[0]!.hints[2], "not installed · Enter to install");
  } finally { process.env.LC_ALL = antes; }
});
