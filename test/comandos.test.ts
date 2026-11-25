import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fakeIO } from "./fake-io.ts";
import { guardarUltra, abrirProyecto, mouseGuardado, temaGuardado } from "../src/tui/ajustes.ts";
import { temaActivo, usarTema } from "../src/tui/temas.ts";
import { PESTANA_CHAT, type Pestana } from "../src/tui/pestanas.ts";
import { saltoPorLetra } from "../src/tui/foco.ts";
import { COMMANDS, TUI_COMMANDS, VISIBLES, findCommand, hijos, PLATFORM_NAMES, fromLines, coverageLines, helpPanel, sugerencias, modelName, modelRow, parseMcp, parseModels } from "../src/tui/comandos.ts";

test("registro: nombres y alias únicos; la lista del manual sale de acá", () => {
  const names = COMMANDS.flatMap((command) => [command.name, ...(command.aliases ?? [])]);
  assert.equal(new Set(names).size, names.length, "un nombre o alias repetido");
  assert.deepEqual(TUI_COMMANDS.map((item) => item.name), COMMANDS.map((item) => item.name));
  assert.equal(findCommand("clear")?.name, "limpiar");
  assert.equal(findCommand("mcp")?.parent, "herramientas");
  assert.equal(findCommand("nada"), undefined);
  for (const command of COMMANDS) assert.ok(command.description.length > 3, command.name);
});

test("panel: la línea en mayúsculas es el título y las de «Uso:» van al pie", () => {
  const panel = fromLines("costos", ["COSTO API ESTIMADO", "sesión USD 0.10", "", "Uso: /presupuesto <USD>"]);
  assert.equal(panel.title, "COSTO API ESTIMADO");
  assert.deepEqual(panel.lines, ["sesión USD 0.10"]);
  assert.equal(panel.footer, "Uso: /presupuesto <USD>");
  assert.deepEqual(fromLines("x", []).lines, ["(nada que mostrar)"]);
  assert.equal(fromLines("x", ["sólo una línea"]).title, "x", "una sola línea no es título");
});

test("modelos: las filas del daemon se vuelven un menú con pista y el actual marcado", () => {
  const parsed = parseModels(["current\torobas/b", "model\torobas/a\tModelo A\ttipo-a\t1000\t1 / 0.1 / 4\tok", "model\torobas/b\tModelo B\ttipo-b\t500\t\tdegradado", "other\topenai"]);
  assert.equal(parsed.current, "orobas/b");
  assert.deepEqual(parsed.others, ["openai"]);
  assert.equal(modelRow(parsed.models[0]!, parsed.current).label, "Modelo A", "el nombre del servicio manda");
  assert.equal(modelRow(parsed.models[0]!, parsed.current).hint, "tipo-a · 1000k · USD 1 / 0.1 / 4");
  assert.match(modelRow(parsed.models[1]!, parsed.current).hint!, /DEGRADADO · Actual$/);
  assert.equal(modelRow({ spec: "orobas/deepseek-v4.1-flash" }, "").label, "DeepSeek V4.1 Flash", "sin nombre, se arma desde el id");
  assert.equal(modelRow({ spec: "orobas/auto" }, "orobas/auto").hint, "Elige solo; cambia si un proveedor falla · Actual", "el uso va primero");
});

test("modelName: ids de proveedores a nombres legibles", () => {
  assert.equal(modelName("orobas/deepseek-v4.1-flash-estandar"), "DeepSeek V4.1 Flash Estándar");
  assert.equal(modelName("orobas/glm-5.3-flash"), "GLM 5.3 Flash");
  assert.equal(modelName("orobas/qwen3.8-27b"), "Qwen3.8 27B");
  assert.equal(modelName("orobas/auto"), "Auto");
  assert.equal(modelName("anthropic/claude-sonnet-5-5"), "Claude Sonnet 5.5");
  assert.equal(modelName("openai/gpt-4o-mini"), "GPT 4o Mini");
});

test("/modelo sin argumento abre el menú en el actual y sólo cambia si se elige otro", async () => {
  const answers = { models: ["current\torobas/b", "model\torobas/a\tA", "model\torobas/b\tB"] };
  const same = fakeIO(answers, [1]);
  assert.equal(await findCommand("modelo")!.run(same.io, ""), null, "elegir el actual no cambia nada");
  assert.equal(same.picked[0]!.at, 1);
  assert.deepEqual(same.calls.map((call) => call.op), ["models"]);
  const other = fakeIO(answers, [0]);
  const panel = await findCommand("modelo")!.run(other.io, "");
  assert.deepEqual(other.calls.at(-1), { op: "model", payload: { value: "orobas/a" } });
  assert.equal(panel?.tone, "ok");
  const direct = fakeIO(answers);
  await findCommand("modelo")!.run(direct.io, "glm");
  assert.deepEqual(direct.calls, [{ op: "model", payload: { value: "glm" } }]);
  // Sin lista del proveedor el menú igual se abre, con el actual y «otro…» para escribir proveedor/modelo.
  const bare = fakeIO({ models: ["current\tfaux/faux", "other\topenai"] }, [1, 1], ["openai/gpt-x"]);
  await findCommand("modelo")!.run(bare.io, "");
  assert.deepEqual(bare.picked[0]!.labels, ["Simulado", "Otros"]);
  assert.deepEqual(bare.calls.at(-1), { op: "model", payload: { value: "openai/gpt-x" } });
  // Un actual que el proveedor no lista va primero y marcado; elegir otro sí cambia.
  const unlisted = fakeIO({ models: ["current\torobas/auto", "model\torobas/a\tA\testandar"] }, [1]);
  await findCommand("modelo")!.run(unlisted.io, "");
  assert.deepEqual(unlisted.picked[0]!.labels, ["Auto", "A", "Otros"]);
  assert.equal(unlisted.picked[0]!.at, 0);
  assert.deepEqual(unlisted.calls.at(-1), { op: "model", payload: { value: "orobas/a" } });
  assert.equal(modelRow({ spec: "orobas/a", kind: "estandar" }, "").hint, "Estándar");
});

test("opciones fijas: el menú marca la vigente y Esc no toca nada", async () => {
  const cancelled = fakeIO({ reasoning: ["Razonamiento: apagado para x"] }, [undefined]);
  assert.equal(await findCommand("razonamiento")!.run(cancelled.io, ""), null);
  assert.equal(cancelled.picked[0]!.at, 1, "«no» es la opción vigente");
  assert.deepEqual(cancelled.calls.map((call) => call.op), ["reasoning"]);
  const chosen = fakeIO({ reasoning: ["Razonamiento: apagado"] }, [0]);
  await findCommand("razonamiento")!.run(chosen.io, "");
  assert.deepEqual(chosen.calls.at(-1), { op: "reasoning", payload: { value: "si" } });
});

test("/razonamiento: el menú son los niveles del modelo de la sesión", async () => {
  // Lo que contesta el daemon para un modelo que publica niveles y no se puede apagar.
  const kimi = "razonamiento del modelo: nivel alto. Niveles de este modelo: bajo, alto, max; no se puede apagar. Razonar más da más calidad y cobra más salida. Uso: /razonamiento no | bajo | alto | max | defecto";
  const menu = fakeIO({ reasoning: [kimi] }, [3]);
  await findCommand("razonamiento")!.run(menu.io, "");
  assert.deepEqual(menu.picked[0]!.labels, ["no", "bajo", "alto", "max", "por defecto"], "sin «medio»: este modelo no lo tiene");
  assert.equal(menu.picked[0]!.at, 2, "«alto» es el vigente");
  assert.deepEqual(menu.calls.at(-1), { op: "reasoning", payload: { value: "max" } });
  // Un modelo que no regula por nivel (con herramientas va siempre apagado): sólo no y por defecto.
  const gpt = fakeIO({ reasoning: ["razonamiento del modelo: el de cada modelo. Niveles de este modelo: ninguno; se puede apagar. Uso: /razonamiento no | defecto"] }, [undefined]);
  await findCommand("razonamiento")!.run(gpt.io, "");
  assert.deepEqual(gpt.picked[0]!.labels, ["no", "por defecto"]);
  assert.equal(gpt.picked[0]!.at, 1);
  // Con argumento va directo, sin menú.
  const direct = fakeIO({ reasoning: [kimi] }, []);
  await findCommand("razonamiento")!.run(direct.io, "bajo");
  assert.deepEqual(direct.calls, [{ op: "reasoning", payload: { value: "bajo" } }]);
});

test("montos: valores usuales, «sin» y «otro…» que pide escribirlo", async () => {
  const preset = fakeIO({ budget: ["Tope de sesión: USD 2.00"] }, [2]);
  await findCommand("presupuesto")!.run(preset.io, "");
  assert.deepEqual(preset.calls.at(-1), { op: "budget", payload: { value: "5" } });
  const none = fakeIO({}, [5]);
  await findCommand("presupuesto")!.run(none.io, "");
  assert.deepEqual(none.calls.at(-1), { op: "budget", payload: { value: "sin" } });
  const typed = fakeIO({}, [6], ["7.5"]);
  await findCommand("presupuesto")!.run(typed.io, "");
  assert.deepEqual(typed.calls.at(-1), { op: "budget", payload: { value: "7.5" } });
  const abandoned = fakeIO({}, [6], [undefined]);
  assert.equal(await findCommand("presupuesto")!.run(abandoned.io, ""), null);
});

test("alcance: limpiar pide confirmación; agregar pide las reglas", async () => {
  const cleared = fakeIO({}, [0, 4, 0]);
  const panel = await findCommand("alcance")!.run(cleared.io, "");
  assert.deepEqual(cleared.calls.at(-1), { op: "view:scope", payload: { arg: "limpiar" } });
  assert.equal(panel?.tone, "warn");
  const refused = fakeIO({}, [0, 4, 1]);
  assert.equal(await findCommand("alcance")!.run(refused.io, ""), null);
  assert.equal(refused.calls.filter((call) => call.op === "view:scope").length, 1, "sólo la lectura inicial");
  const added = fakeIO({}, [0, 1], ["a.test b.test"]);
  await findCommand("alcance")!.run(added.io, "");
  assert.deepEqual(added.calls.at(-1), { op: "view:scope", payload: { arg: "add a.test b.test" } });
});

test("mcp: estado como menú, agregar con tres entradas, quitar con confirmación", () => {
  assert.deepEqual(parseMcp(["uno\tnpx x\tconectado\t3\t", "dos\tbin\tfalló\t\tno arranca"]), [
    { name: "uno", command: "npx x", state: "conectado", tools: "3" },
    { name: "dos", command: "bin", state: "falló", error: "no arranca" },
  ]);
});

test("mcp: flujos del menú", async () => {
  const status = { 'mcp:{"action":"status"}': ["uno\tnpx x\tsin iniciar\t\t"] };
  const added = fakeIO(status, [1], ["nuevo", "npx", "-y servidor --flag"]);
  await findCommand("mcp")!.run(added.io, "");
  assert.deepEqual(added.calls.at(-1), { op: "mcp", payload: { action: "add", name: "nuevo", command: "npx", args: ["-y", "servidor", "--flag"] } });
  const probed = fakeIO(status, [0, 0]);
  await findCommand("mcp")!.run(probed.io, "");
  assert.deepEqual(probed.calls.at(-1), { op: "mcp", payload: { action: "probe", name: "uno" } });
  const removed = fakeIO(status, [0, 1, 0]);
  await findCommand("mcp")!.run(removed.io, "");
  assert.deepEqual(removed.calls.at(-1), { op: "mcp", payload: { action: "remove", name: "uno" } });
  const kept = fakeIO(status, [0, 1, 1]);
  assert.equal(await findCommand("mcp")!.run(kept.io, ""), null);
  const direct = fakeIO({});
  await findCommand("mcp")!.run(direct.io, "quitar uno");
  assert.deepEqual(direct.calls, [{ op: "mcp", payload: { action: "remove", name: "uno" } }]);
  assert.equal((await findCommand("mcp")!.run(fakeIO({}).io, "cualquiercosa"))?.tone, "warn");
});

test("ayuda: teclas primero y los 17 visibles, con los miembros de cada grupo debajo", () => {
  const panel = helpPanel(["Enter envía"]);
  assert.equal(panel.lines[0], "Enter envía");
  const at = panel.lines.findIndex((line) => /^ {2}\/conexiones +/.test(line));
  assert.ok(at > 0);
  assert.match(panel.lines[at + 1]!, /github/);
  assert.ok(!panel.lines.some((line) => /^ {2}\/github/.test(line)));
  for (const name of VISIBLES) assert.ok(panel.lines.some((line) => line.startsWith(`  /${name} `)), name);
  assert.ok(panel.footer);
});

test("sugerencias: / solo muestra los visibles en orden; con letras busca también ocultos y dice dónde viven", () => {
  assert.deepEqual(sugerencias("").map((s) => s.word), VISIBLES);
  const git = sugerencias("git")[0]!;
  assert.equal(git.word, "github");
  assert.ok(git.description.startsWith("en /conexiones"));
  assert.ok(sugerencias("pest").some((s) => s.word === "pestañas" && s.description.startsWith("en /diseño")));
  assert.ok(!sugerencias("cola")[0]!.description.startsWith("en /"));
});

test("grupos: un alias del miembro delega (sin importar mayúsculas) y el resto del argumento llega intacto", async () => {
  const a = fakeIO({});
  await findCommand("conexiones")!.run(a.io, "MAIL");
  const b = fakeIO({});
  await findCommand("correo")!.run(b.io, "");
  assert.deepEqual(a.calls, b.calls);
  assert.deepEqual(a.calls.map((x) => x.op), ["mail_account"]);
  const c = fakeIO({});
  await findCommand("limites")!.run(c.io, "Presupuesto 5");
  const d = fakeIO({});
  await findCommand("presupuesto")!.run(d.io, "5");
  assert.deepEqual(c.calls, d.calls);
  assert.ok(c.calls.length > 0);
});

test("/idioma y /lang: elegir guarda en la configuración y cambia la interfaz; «sistema» vuelve al del sistema", async () => {
  const { mkdtempSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const prev = { c: process.env.CYBER_CONFIG, l: process.env.LC_ALL };
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-idioma-")), "config.json");
  try {
    assert.equal(findCommand("lang")?.name, "idioma");
    const { io, picked } = fakeIO({}, [1]);
    await findCommand("idioma")!.run(io, "");
    assert.deepEqual(picked[0]!.labels.slice(0, 2), ["español", "English"]);
    assert.equal(picked[0]!.at, 2, "sin elección, el actual es el del sistema");
    assert.equal(JSON.parse(readFileSync(process.env.CYBER_CONFIG, "utf8")).idioma, "en");
    assert.match(process.env.LC_ALL ?? "", /^en/);
    await findCommand("lang")!.run(fakeIO({}).io, "es");
    assert.match(process.env.LC_ALL ?? "", /^es/);
    await findCommand("idioma")!.run(fakeIO({}).io, "sistema");
    assert.equal(JSON.parse(readFileSync(process.env.CYBER_CONFIG, "utf8")).idioma, undefined);
    assert.equal(process.env.LC_ALL, prev.l);
    const wrong = await findCommand("idioma")!.run(fakeIO({}).io, "fr");
    assert.equal(wrong?.tone, "warn");
  } finally {
    if (prev.c === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev.c;
    if (prev.l === undefined) delete process.env.LC_ALL; else process.env.LC_ALL = prev.l;
  }
});

test("/config: lista los ajustes con su valor y ←→ cambia una opción fija con la operación de siempre", async () => {
  const answers = { scanners: ["Escáneres externos (nmap, ffuf, sqlmap, nuclei, katana, httpx): habilitados"], budget: ["Tope de sesión: USD 2.00. Uso: /presupuesto <USD> o /presupuesto sin"] };
  const { io, calls, picked } = fakeIO(answers, [undefined]);
  assert.equal(findCommand("configuracion")?.name, "config");
  assert.equal(await findCommand("config")!.run(io, ""), null, "Esc cierra sin tocar nada");
  const menu = picked[0]!;
  const at = (label: string) => menu.labels.indexOf(label);
  assert.ok(at("Escáneres externos") >= 0 && at("Modelo") >= 0 && at("Cuenta de orobas") >= 0);
  assert.equal(menu.hints[at("Escáneres externos")], "‹ Sí ›");
  assert.equal(menu.hints[at("Presupuesto de la sesión")], "USD 2.00");
  const row = await menu.cycle!(at("Escáneres externos"), 1) as { label: string; hint?: string };
  assert.deepEqual(calls.filter((call) => call.op === "scanners" && "value" in call.payload).at(-1), { op: "scanners", payload: { value: "no" } });
  assert.equal(row?.label, "Escáneres externos");
  assert.equal(await menu.cycle!(at("Modelo"), 1), undefined, "el modelo se abre con Enter, no cambia con ←→");
});

test("cobertura: cada categoría en su línea con nombre legible y lo que abarca debajo, con sangría", () => {
  const plain = (lines: string[]) => lines.map((line) => line.replace(/\x1b\[[0-9;]*m/g, ""));
  assert.deepEqual(plain(coverageLines(["COBERTURA", "  ○ autenticacion: login con credenciales de prueba", "  ✓ logica de negocio: precios", "Peticiones HTTP: 0"])), [
    "COBERTURA",
    "○ Autenticación", "    Login con credenciales de prueba", "",
    "✓ Lógica de negocio", "    Precios", "",
    "Peticiones HTTP: 0",
  ]);
});

/** fakeIO con pestañas en vivo: `setPestanas` guarda lo último que recibió. */
function ioPestanas(lista: Pestana[], picks: Array<number | undefined>, inputs: Array<string | undefined> = []) {
  const base = fakeIO({}, picks, inputs);
  const aplicadas: Pestana[][] = [];
  const mouse: boolean[] = [];
  base.io.pestanas = () => lista;
  base.io.setPestanas = (nueva) => void aplicadas.push(nueva);
  base.io.setMouse = (valor) => void mouse.push(valor);
  return { ...base, aplicadas, mouse };
}

test("/config: crear «Perú» sólo con comandos", async () => {
  // Pestañas → + Nueva (fila 1) → Conversación (0) → input «Perú» → Comandos / (fila 5 del editor) → Esc, Esc, Esc
  const { io, aplicadas } = ioPestanas([PESTANA_CHAT], [1, 1, 0, 5, undefined, undefined, undefined], ["Perú"]);
  await findCommand("config")!.run(io, "");
  assert.deepEqual(aplicadas.at(-1), [PESTANA_CHAT, { nombre: "Perú", tipo: "conversacion", contenido: ["comandos"], detalle: "normal" }]);
});

test("/config: no se puede borrar la única pestaña", async () => {
  const { io, picked } = ioPestanas([PESTANA_CHAT], [1, 0, undefined, undefined, undefined]);
  await findCommand("config")!.run(io, "");
  const edicion = picked.find((menu) => menu.labels.includes("Detalle"))!;
  assert.ok(!edicion.labels.includes("Borrar pestaña"));
});

test("/config: el mouse cambia con ←→ y se aplica en vivo", async () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-mouse-")), "config.json");
  abrirProyecto("/p");
  try {
    const { io, picked, mouse } = ioPestanas([PESTANA_CHAT], [undefined]);
    await findCommand("config")!.run(io, "");
    const menu = picked[0]!;
    const row = await menu.cycle!(menu.labels.indexOf("Mouse (rueda y seleccionar)"), 1) as { hint?: string };
    assert.deepEqual(mouse, [false]);
    assert.equal(mouseGuardado(), false);
    assert.equal(row?.hint, "‹ No ›");
  } finally {
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("/config: → sobre la primera pestaña la mueve y devuelve las filas nuevas con el cursor en ella", async () => {
  const PERU: Pestana = { nombre: "Perú", tipo: "conversacion", contenido: ["comandos"], detalle: "normal" };
  const { io, picked, aplicadas } = ioPestanas([PESTANA_CHAT, PERU], [1, undefined, undefined]);
  await findCommand("config")!.run(io, "");
  const lista = picked.find((menu) => menu.title.startsWith("Pestañas"))!;
  const res = await lista.cycle!(0, 1) as { rows: Array<string | { label: string }>; at: number };
  assert.deepEqual(aplicadas.at(-1)!.map((p) => p.nombre), ["Perú", "Chat"]);
  assert.deepEqual(res.rows.map((r) => (typeof r === "string" ? r : r.label)), ["Perú", "Chat", "+ Nueva pestaña"]);
  assert.equal(res.at, 1);
});

test("/config: borrar con confirmación deja una lista válida; Esc en el nombre no crea nada", async () => {
  const PERU: Pestana = { nombre: "Perú", tipo: "conversacion", contenido: ["comandos"], detalle: "normal" };
  // Pestañas → Perú (1) → Borrar (fila 8) → confirmar (0) → Esc, Esc
  const a = ioPestanas([PESTANA_CHAT, PERU], [1, 1, 8, 0, undefined, undefined]);
  await findCommand("config")!.run(a.io, "");
  assert.deepEqual(a.aplicadas.at(-1), [PESTANA_CHAT]);
  // Pestañas → + Nueva (1) → Hallazgos (1) → Esc en el nombre
  const b = ioPestanas([PESTANA_CHAT], [1, 1, 1, undefined, undefined], [undefined]);
  await findCommand("config")!.run(b.io, "");
  assert.equal(b.aplicadas.length, 0);
});

test("/tema: con argumento lo aplica y lo guarda; desconocido es uso", async () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-tema-")), "config.json");
  try {
    abrirProyecto("/p");
    await findCommand("tema")!.run(fakeIO({}).io, "Filete Porteño");
    assert.equal(temaActivo().id, "filete");
    assert.equal(temaGuardado(), "filete");
    const mal = await findCommand("tema")!.run(fakeIO({}).io, "xyz");
    assert.equal(mal?.tone, "warn");
    assert.ok([...mal!.lines, mal!.footer ?? ""].join("\n").includes("/tema"));
  } finally {
    usarTema("orobas");
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("/tema: la lista prueba en vivo y Esc vuelve al anterior", async () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-tema-")), "config.json");
  try {
    abrirProyecto("/p");
    usarTema("orobas");
    const { io } = fakeIO({});
    let durante = "";
    io.pick = async (_t, _r, options) => { options?.move?.(3); durante = temaActivo().id; return undefined; };
    assert.equal(await findCommand("tema")!.run(io, ""), null);
    assert.equal(durante, "filete");
    assert.equal(temaActivo().id, "orobas");
    assert.equal(temaGuardado(), "orobas");
  } finally {
    usarTema("orobas");
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("/config: Enter en «Tema» abre la lista; ←→ cambia el tema y lo guarda", async () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-tema-")), "config.json");
  try {
    abrirProyecto("/p");
    usarTema("orobas");
    const { io, picked } = fakeIO({}, [undefined]);
    await findCommand("config")!.run(io, "");
    const menu = picked[0]!;
    const fila = menu.labels.indexOf("Tema");
    await menu.cycle!(fila, 1);
    assert.equal(temaGuardado(), "elevate");
    const abrir = fakeIO({}, [fila, undefined, undefined]);
    await findCommand("config")!.run(abrir.io, "");
    assert.equal(abrir.picked[1]!.title, "tema");
  } finally {
    usarTema("orobas");
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("/ultra con tarea: arma con lo guardado y avisa la línea", async () => {
  guardarUltra({ harnesses: ["claude"], partes: 3, modo: "repo" });
  try {
    const { io, calls, notices } = fakeIO({
      'orquesta:{"action":"harnesses"}': ["claude   ✓ /usr/bin/claude · Claude Code"],
      "orquesta:{}": ["ORQUESTA · corridas de harnesses"],
    });
    await findCommand("ultra")!.run(io, "arreglá x");
    const ultra = calls.find((c) => (c.payload as { action?: string }).action === "ultra")!;
    assert.equal((ultra.payload as { tarea: string }).tarea, "arreglá x --con claude --partes 3");
    assert.match(notices[0]!.lines[0]!, /^ultra · claude/);
  } finally {
    guardarUltra({ partes: "auto", modo: "repo" });
  }
});

test("/orquesta: verbo desconocido avisa; ver sigue igual", async () => {
  const mal = fakeIO({});
  const p = await findCommand("orquesta")!.run(mal.io, "pará 3");
  assert.equal(p?.tone, "warn");
  assert.match(p!.lines[0]!, /pará/);
  assert.match(p!.lines[0]!, /ver \(view\), parar \(stop\), limpiar \(clean\) <id> \[rama\|branch\], harnesses/);
  const ver = fakeIO({});
  await findCommand("orquesta")!.run(ver.io, "ver 3");
  assert.deepEqual(ver.calls[0]!.payload, { action: "ver", run: "3" });
});

test("/orquesta: verbo conocido sin id abre el menú", async () => {
  for (const verbo of ["ver", "parar", "limpiar"]) {
    const { io, picked } = fakeIO({ "orquesta:{}": ["Sin corridas de otros harnesses."] }, [undefined]);
    const p = await findCommand("orquesta")!.run(io, verbo);
    assert.equal(p, null, verbo);
    assert.equal(picked[0]!.title, "orquesta", verbo);
  }
});

test("/orquesta clean <id> branch: la palabra en inglés también borra la rama", async () => {
  const { io, calls } = fakeIO({});
  await findCommand("orquesta")!.run(io, "clean 3 branch");
  assert.deepEqual(calls.at(-1)!.payload, { action: "limpiar", run: "3", rama: true });
});

test("grupos: los visibles son exactamente VISIBLES y todo lo demás está oculto o en un grupo", () => {
  assert.deepEqual(COMMANDS.filter((c) => !c.parent && !c.hidden).map((c) => c.name), VISIBLES);
  for (const c of COMMANDS) if (c.parent) assert.ok(VISIBLES.includes(c.parent), `${c.name} → ${c.parent}`);
  for (const [name, parent] of [["github", "conexiones"], ["mcp", "herramientas"], ["costos", "limites"], ["tema", "diseño"], ["idioma", "config"], ["jobs", "sesiones"]] as Array<[string, string]>) assert.equal(findCommand(name)!.parent, parent, name);
  assert.ok(findCommand("orquesta")!.hidden && !findCommand("orquesta")!.parent);
  assert.equal(findCommand("effort")!.name, "razonamiento");
  assert.equal(findCommand("diseno")!.name, "diseño");
  assert.equal(findCommand("tabs")!.name, "pestañas");
  for (const [alias, name] of [["help", "ayuda"], ["quit", "salir"], ["findings", "hallazgos"], ["scope", "alcance"], ["toolbox", "herramientas"]] as Array<[string, string]>) assert.equal(findCommand(alias)!.name, name);
});

test("grupo: sin argumento abre menú; con hijo delega; Esc no toca nada", async () => {
  const esc = fakeIO({}, [undefined]);
  assert.equal(await findCommand("conexiones")!.run(esc.io, ""), null);
  assert.equal(esc.calls.length, 0);
  assert.ok(esc.picked[0]!.labels.includes("/github") && esc.picked[0]!.labels.includes("/correo"));
  const second = fakeIO({}, [1]);
  await findCommand("limites")!.run(second.io, "");
  assert.equal(second.picked.length, 2, "el 2.º hijo (/peticiones) abre su propio menú");
  const direct = fakeIO({});
  await findCommand("limites")!.run(direct.io, "presupuesto 5");
  assert.deepEqual(direct.calls, [{ op: "budget", payload: { value: "5" } }]);
});

test("grupo con casa: la casa va primero y los argumentos propios siguen yendo a la casa", async () => {
  const menu = fakeIO({}, [undefined]);
  await findCommand("hallazgos")!.run(menu.io, "");
  assert.ok(!menu.picked[0]!.labels[0]!.startsWith("/") && menu.picked[0]!.labels[1]!.startsWith("/"));
  const own = fakeIO({});
  await findCommand("hallazgos")!.run(own.io, "3 cerrado");
  assert.deepEqual(own.calls.at(-1), { op: "view:findings", payload: { arg: "3 cerrado" } });
  const scope = fakeIO({});
  await findCommand("alcance")!.run(scope.io, "quitar a.test");
  assert.deepEqual(scope.calls.at(-1), { op: "view:scope", payload: { arg: "quitar a.test" } });
});

test("grupo puro con argumento desconocido avisa el uso", async () => {
  const panel = await findCommand("conexiones")!.run(fakeIO({}).io, "foo");
  assert.equal(panel?.tone, "warn");
  assert.match(panel!.lines.join(" "), /github/);
});

test("/ultra con tarea que empieza con «orquesta» sigue siendo tarea", async () => {
  guardarUltra({ harnesses: ["claude"], partes: 3, modo: "repo" });
  try {
    const { io, calls } = fakeIO({ 'orquesta:{"action":"harnesses"}': ["claude   ✓ /usr/bin/claude · Claude Code"], "orquesta:{}": ["ORQUESTA · corridas de harnesses"] });
    await findCommand("ultra")!.run(io, "orquesta de pruebas");
    const ultra = calls.find((c) => (c.payload as { action?: string }).action === "ultra")!;
    assert.equal((ultra.payload as { tarea: string }).tarea, "orquesta de pruebas --con claude --partes 3");
  } finally {
    guardarUltra({ partes: "auto", modo: "repo" });
  }
});

test("/diseño: muestra sólo pestañas, ventanas, mouse, tema y descifrado", async () => {
  const { io, picked } = fakeIO({}, [undefined]);
  await findCommand("diseño")!.run(io, "");
  assert.deepEqual(picked[0]!.labels, ["Pestañas", "Ventanas", "Mouse (rueda y seleccionar)", "Tema", "Efecto descifrado"]);
});

test("menú de grupo: escribir una letra salta a la fila cuya etiqueta, sin la «/», empieza con ella", () => {
  const labels = ["/github", "/vercel", "/gcloud", "/orobas"];
  assert.equal(saltoPorLetra(labels, 0, "g"), 2);
  assert.equal(saltoPorLetra(labels, 2, "g"), 0);
  assert.equal(saltoPorLetra(labels, 0, "z"), undefined);
});

test("conexiones: hijos en el orden de la tabla (nubes primero)", () => {
  assert.deepEqual(hijos("conexiones").map((h) => h.name), [...PLATFORM_NAMES, "orobas", "hackerone", "h1", "correo", "navegador"]);
});
