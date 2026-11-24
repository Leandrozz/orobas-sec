import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mock, test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { Orquesta, type Run } from "../src/orquesta.ts";
import { resolveProvider } from "../src/providers.ts";
import { abrirProyecto, guardarPestanas } from "../src/tui/ajustes.ts";
import { startFoco } from "../src/tui/foco.ts";
import { Harnesses } from "../src/tui/harnesses.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};
const F2 = "\x1bOQ";
const run = (r: Partial<Run>): Run => ({ id: "a3f", harness: "claude", task: "arreglá el login", state: "corriendo", cwd: "/c", command: "x", log: "/l", startedAt: Date.now(), ...r } as Run);
// view() real de Orquesta, como en harnesses.test.ts.
const LISTA = (Object.assign(Object.create(Orquesta.prototype), { runs: new Map([["a3f", run({})]]), saved: () => [] }) as Orquesta).view();

async function armar(conHarness = false, pestanas?: Parameters<typeof guardarPestanas>[0], columns = 120) {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-ia-"));
  process.env.CYBER_CONFIG = join(cwd, "config.json"); // ventanas y pestañas son generales: cada prueba con su configuración
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  abrirProyecto(cwd);
  if (pestanas) guardarPestanas(pestanas);
  const state = { written: "", input: (_: string) => {} };
  const output = { write: (data: string) => void (state.written += data), columns, rows: 30 };
  const client = await connectDaemon(cwd, { spawn: false });
  const snapshot = await client.attach({ session: "new" });
  startFoco(client, snapshot, {
    project: cwd,
    io: { output, listen: (onData) => ((state.input = onData), () => {}) },
    onExit: () => client.close(),
    onboarding: false,
    ...(conHarness ? { harnesses: (ask) => new Harnesses(async (op, p) => (op === "orquesta" && !("action" in p) ? LISTA : ask(op, p))) } : {}),
  });
  const visible = () => pantallaVisible(state.written, output.columns, output.rows).join("\r\n");
  const conSub = async () => {
    provider.faux!.queue = [{ toolCalls: [{ name: "delegate", arguments: { objective: "revisar el login" } }] }, { text: "texto del sub" }, { text: "listo" }];
    state.input("hola\r");
    await until(() => /listo/.test(visible()));
  };
  const marca = () => (t_visible().match(/sub:1 · (?:terminó|finished)/g) ?? []).length;
  const t_visible = visible;
  /** Abre la lista y elige la fila `n` (bajando desde «+ nueva»). */
  const elegir = async (n: number, espera = /sub:1 · (?:terminó|finished)/) => { state.input(F2); await tick(); state.input("\x1b[H" + "\x1b[B".repeat(n) + "\r"); await until(() => espera.test(visible())); };
  return { state, daemon, provider, client, visible, conSub, marca, elegir, cwd };
}

test("ia: la lista muestra los subagentes de una sesión abierta con ✓ al terminar", async () => {
  const t = await armar();
  try {
    await t.conSub();
    t.state.input(F2);
    await until(() => /✓ sub:1 · revisar/.test(t.visible()));
    assert.match(t.visible(), /✓ sub:1 · revisar/);
  } finally { t.daemon.close(); }
});

test("ia: elegir un subagente en la lista pone la fuente en la ventana activa; elegir una pestaña la saca", async () => {
  const t = await armar();
  try {
    await t.conSub();
    t.state.input(F2);
    await until(() => /sub:1/.test(t.visible()));
    t.state.input("\x1b[B\x1b[B\x1b[B\r"); // nueva, sesión, Chat, sub:1
    await until(() => /sub:1 · (?:terminó|finished)/.test(t.visible()));
    assert.match(t.visible(), /sub:1 · (?:terminó|finished)/);
    t.state.input(F2);
    t.state.input("\x1b[A\r"); // vuelve a la fila de la pestaña Chat
    await until(() => !/sub:1 · (?:terminó|finished)/.test(t.visible()));
    assert.doesNotMatch(t.visible(), /sub:1 · (?:terminó|finished)/);
  } finally { t.daemon.close(); }
});

test("ia: la lista muestra los harnesses que devuelve orquesta", async () => {
  const t = await armar(true);
  try {
    t.state.input(F2);
    await until(() => /⋯ #a3f claude/.test(t.visible()));
    assert.match(t.visible(), /⋯ #a3f claude/);
    assert.doesNotMatch(t.visible(), /\/ultra · harnesses/); // vivo: va debajo de su sesión, no en el grupo de anteriores
  } finally { t.daemon.close(); }
});

test("ia: Alt+N con una fuente puesta vuelve a la pestaña", async () => {
  const t = await armar();
  try {
    await t.conSub();
    await t.elegir(3);
    t.state.input("\x1b1");
    await until(() => t.marca() === 0);
    assert.equal(t.marca(), 0);
  } finally { t.daemon.close(); }
});

test("ia: elegir una sesión en la lista sobre una ventana con fuente la borra", async () => {
  const t = await armar();
  try {
    await t.conSub();
    await t.elegir(3);
    t.state.input(F2);
    await tick();
    t.state.input("\x1b[A\x1b[A\r"); // sub:1 → Chat → sesión
    await until(() => t.marca() === 0);
    assert.equal(t.marca(), 0);
  } finally { t.daemon.close(); }
});

test("ia: /clear con una fuente puesta la borra", async () => {
  const t = await armar();
  try {
    await t.conSub();
    await t.elegir(3);
    t.state.input("/clear\r");
    await until(() => t.marca() === 0);
    assert.equal(t.marca(), 0);
  } finally { t.daemon.close(); }
});

test("ia: mover la pestaña borra la fuente del origen y la del destino", async () => {
  const t = await armar();
  try {
    await t.conSub();
    t.state.input("/ventanas\r"); await until(() => /Lado a lado/.test(t.visible())); t.state.input("2"); await tick();
    await t.elegir(4); // ventana 1 (filas: nueva, sesión, Chat, Chat, sub:1)
    t.state.input("\x1b[17~"); await tick(); // F6: ventana 2
    await t.elegir(4, /sub:1 · (?:terminó|finished).*sub:1 · (?:terminó|finished)/s);
    assert.equal(t.marca(), 2);
    t.state.input("\x1b[1;6C"); // Ctrl+Shift+→ desde la ventana 2: la mueve a la 1
    await until(() => t.marca() === 0);
    assert.equal(t.marca(), 0);
  } finally { t.daemon.close(); }
});

test("ia: la ventana de subagente muestra objetivo, texto y acciones, y al terminar informe y ✓", async () => {
  const t = await armar();
  try {
    await t.conSub();
    await t.elegir(3);
    assert.match(t.visible(), /(?:Objetivo|Goal): revisar el login/);
    assert.match(t.visible(), /texto del sub/);
    assert.match(t.visible(), /(?:Informe|Report):/);
    assert.match(t.visible(), /✓ sub:1 · (?:terminó|finished)/);
    assert.match(t.visible(), /solicitud/);
  } finally { t.daemon.close(); }
});

test("ia: al arrancar un subagente aparece el aviso; el borrador y la ventana activa no cambian", async () => {
  const t = await armar();
  try {
    t.provider.faux!.queue = [{ toolCalls: [{ name: "delegate", arguments: { objective: "revisar el login" } }] }, { text: "texto del sub" }, { text: "listo" }];
    t.state.input("hola\r");
    t.state.input("borrador-xyz");
    await until(() => /sub:1 (?:arrancó \(F2 para verlo|started \(F2 to see it)\)/.test(t.visible()));
    assert.match(t.visible(), /sub:1 (?:arrancó \(F2 para verlo|started \(F2 to see it)\)/);
    assert.match(t.visible(), /borrador-xyz/);
    assert.equal(t.marca(), 0);
  } finally { t.daemon.close(); }
});

test("ia: dos ventanas con el mismo subagente se actualizan las dos", async () => {
  const t = await armar();
  try {
    await t.conSub();
    t.state.input("/ventanas\r"); await until(() => /Lado a lado/.test(t.visible())); t.state.input("2"); await tick();
    await t.elegir(4);
    t.state.input("\x1b[17~"); await tick();
    await t.elegir(4, /sub:1 · (?:terminó|finished).*sub:1 · (?:terminó|finished)/s);
    assert.equal((t.visible().match(/(?:Objetivo|Goal): revisar/g) ?? []).length, 2);
    (t.client as unknown as { emit(e: object): void }).emit({ type: "text", worker: "sub:1", delta: "novedad en vivo" });
    await until(() => (t.visible().match(/novedad en vivo/g) ?? []).length === 2);
    assert.equal((t.visible().match(/novedad en vivo/g) ?? []).length, 2);
  } finally { t.daemon.close(); }
});

test("ia: con una fuente a la vista, Alt+↑ no opera sobre la pestaña oculta", async () => {
  const t = await armar(false, [{ nombre: "Res", tipo: "conversacion", contenido: ["acciones", "resultados"], detalle: "completo" }]);
  try {
    await t.conSub();
    await t.elegir(3);
    t.state.input("\x1b[1;3A"); await tick(100);
    assert.doesNotMatch(t.visible(), /elegir acci|pick action/);
  } finally { t.daemon.close(); }
});

test("ia: el título de un subagente trabajando no repite el ● de la ventana activa", async () => {
  const t = await armar();
  try {
    await t.conSub();
    (t.client as unknown as { emit(e: object): void }).emit({ type: "text", worker: "sub:2", delta: "x" });
    t.state.input(F2); await tick(); t.state.input("\x1b[H" + "\x1b[B".repeat(3) + "\r");
    await until(() => /sub:2 · (?:trabajando|working)/.test(t.visible()));
    assert.match(t.visible(), /● ⋯ sub:2 · (?:trabajando|working)/);
  } finally { t.daemon.close(); }
});

test("ia: sin delegate, con una ventana, nada cambia", async () => {
  const t = await armar();
  try {
    t.state.input("hola\r");
    await until(() => /faux|hola/.test(t.visible()));
    await tick(200);
    assert.doesNotMatch(t.visible(), /arrancó|started|Objetivo:|Goal:|Informe:|Report:/);
    assert.equal(t.marca(), 0);
  } finally { t.daemon.close(); }
});

test("ia: cambiar las pestañas desde /config con una fuente puesta la borra", async () => {
  const t = await armar();
  try {
    await t.conSub();
    await t.elegir(3);
    t.state.input("/config\r"); await until(() => /Configuración/.test(t.visible()));
    t.state.input("\x1b[B\r"); await until(() => /Nueva pestaña/.test(t.visible()));
    t.state.input("\r"); await until(() => /Detalle/.test(t.visible()));
    t.state.input("\x1b[B\r"); // alterna un tipo de contenido: aplica la lista
    await until(() => t.marca() === 0);
    assert.equal(t.marca(), 0);
  } finally { t.daemon.close(); }
});

// --- Ventana de harness y sondeo ---
const vista = (runs: Run[]) => (Object.assign(Object.create(Orquesta.prototype), { runs: new Map(runs.map((r) => [r.id, r])), saved: () => [] }) as Orquesta).view();
const LISTA_RAMA = vista([run({ branch: "orobas/login-1" })]);
const verDe = (r: Partial<Run>) => Orquesta.prototype.summary.call(null as never, run(r)).split("\n");
const FIN = { state: "terminado", exitCode: 0, startedAt: 1_000_000, endedAt: 1_005_000 } as Partial<Run>;
const VACIA = vista([]);

/** El mock de setInterval se habilita ANTES de startFoco: así el intervalo de la TUI es el falso y se avanza a mano. */
async function armarH(ver: () => string[], lista: (sesion: number) => string[] | Promise<string[]> = () => LISTA_RAMA) {
  mock.timers.enable({ apis: ["setInterval"] });
  const espiaSet = mock.method(globalThis, "setInterval");
  const llamadas: object[] = [];
  let sesiones = 0;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-ia-"));
  process.env.CYBER_CONFIG = join(cwd, "config.json"); // ventanas y pestañas son generales: cada prueba con su configuración
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  abrirProyecto(cwd);
  const state = { written: "", input: (_: string) => {} };
  const output = { write: (data: string) => void (state.written += data), columns: 120, rows: 30 };
  const client = await connectDaemon(cwd, { spawn: false });
  const snapshot = await client.attach({ session: "new" });
  startFoco(client, snapshot, {
    project: cwd,
    io: { output, listen: (onData) => ((state.input = onData), () => {}) },
    onExit: () => client.close(),
    onboarding: false,
    harnesses: () => { const n = ++sesiones; return new Harnesses(async (_op, p) => { llamadas.push({ ...p, n }); return "action" in p ? ver() : lista(n); }); },
  });
  const visible = () => pantallaVisible(state.written, output.columns, output.rows).join("\r\n");
  const vers = () => llamadas.filter((p) => "action" in p).length;
  const listas = () => llamadas.filter((p) => !("action" in p)).length;
  const avanzar = async () => { mock.timers.tick(3000); await tick(80); };
  const lista3 = async () => { state.input(F2); await until(() => listas() > 0); await tick(40); };
  const abrir = async () => { await lista3(); state.input("\x1b[H" + "\x1b[B".repeat(3) + "\r"); await until(() => vers() > 0); await tick(40); };
  const cerrar = () => { mock.timers.reset(); mock.restoreAll(); daemon.close(); };
  const sondeo = () => espiaSet.mock.calls.find((c) => c.arguments[1] === 3000)?.result;
  return { state, daemon, client, sondeo, visible, vers, listas, avanzar, lista3, abrir, cerrar, llamadas };
}

test("ia: la ventana de harness muestra cabecera y cola y se actualiza en el siguiente tick", async () => {
  let cola = "linea uno";
  const t = await armarH(() => verDe({ tail: cola, worktree: "/w", branch: "orobas/login-1" }));
  try {
    await t.abrir();
    await until(() => /linea uno/.test(t.visible()));
    const v = t.visible();
    assert.match(v, /claude · corriendo · \d+ s/);
    assert.match(v, /arreglá el login/);
    assert.match(v, /rama orobas\/login-1/);
    assert.match(v, /⋯ #a3f · corriendo/);
    cola = "linea dos";
    await t.avanzar();
    await until(() => /linea dos/.test(t.visible()));
    assert.match(t.visible(), /linea dos/);
  } finally { t.cerrar(); }
});

test("ia: con la lista visible el tick pide la lista, pero no pide ver sin ventana de harness", async () => {
  const t = await armarH(() => verDe({}));
  try {
    await t.lista3();
    const antes = t.listas();
    await t.avanzar();
    assert.ok(t.listas() > antes, "el tick sí ocurre");
    assert.equal(t.vers(), 0);
  } finally { t.cerrar(); }
});

test("ia: con la ventana de harness visible se pide ver en cada tick; al volver a la pestaña ya no", async () => {
  const t = await armarH(() => verDe({}));
  try {
    await t.abrir();
    const v0 = t.vers();
    assert.ok(v0 > 0);
    await t.avanzar();
    assert.ok(t.vers() > v0, "con la ventana a la vista el tick pide ver");
    t.state.input("\x1b1"); // vuelve a la pestaña: la fuente se borra
    await tick(80);
    const v1 = t.vers();
    const l1 = t.listas();
    await t.avanzar();
    assert.ok(t.listas() > l1, "la lista sigue sondeándose");
    assert.equal(t.vers(), v1);
  } finally { t.cerrar(); }
});

test("ia: un harness terminado se pide una última vez y después no", async () => {
  const t = await armarH(() => verDe(FIN), () => vista([run(FIN)]));
  try {
    await t.abrir();
    await tick(80);
    const v = t.vers();
    await t.avanzar();
    await t.avanzar();
    assert.equal(t.vers(), v);
    assert.match(t.visible(), /✓ #a3f · terminado/);
  } finally { t.cerrar(); }
});

test("ia: si ver falla se ve ⚠ y la TUI sigue", async () => {
  const t = await armarH(() => { throw new Error("daemon caído"); });
  try {
    await t.abrir();
    await until(() => /⚠ .*daemon caído/.test(t.visible()));
    assert.match(t.visible(), /⚠ .*daemon caído/);
    t.state.input("x");
    await tick(60);
    await t.avanzar();
    assert.ok(t.visible().length > 0);
  } finally { t.cerrar(); }
});

test("ia: al salir se limpia el intervalo y no se pide nada más", async () => {
  const t = await armarH(() => verDe({}));
  try {
    await t.abrir();
    const antes = t.vers();
    await t.avanzar();
    assert.ok(t.vers() > antes, "antes de salir el tick sí pide");
    const espia = mock.method(globalThis, "clearInterval");
    t.state.input("/salir\r");
    await until(() => espia.mock.calls.some((c) => c.arguments[0] === t.sondeo()));
    assert.ok(t.sondeo() && espia.mock.calls.some((c) => c.arguments[0] === t.sondeo()), "exit limpia el intervalo del sondeo");
    await tick(100);
    const n = t.vers();
    const l = t.listas();
    await t.avanzar();
    assert.equal(t.vers(), n);
    assert.equal(t.listas(), l);
  } finally { t.cerrar(); }
});

test("ia: si ask tarda más de un tick no se apilan pedidos", async () => {
  let freno: Promise<string[]> | undefined;
  let suelta = () => {};
  const t = await armarH(() => verDe({}), () => freno ?? LISTA_RAMA);
  try {
    await t.abrir();
    freno = new Promise((r) => { suelta = () => r(LISTA_RAMA); });
    const l = t.listas();
    mock.timers.tick(3000);
    mock.timers.tick(3000);
    await tick(80);
    assert.equal(t.listas(), l + 1);
    suelta();
    await tick(80);
    freno = undefined;
    await t.avanzar();
    assert.equal(t.listas(), l + 2);
  } finally { t.cerrar(); }
});

test("ia: sin harnesses conocidos no se sondea la lista", async () => {
  const t = await armarH(() => verDe({}), () => VACIA);
  try {
    await t.lista3();
    const l = t.listas();
    await t.avanzar();
    assert.equal(t.listas(), l);
  } finally { t.cerrar(); }
});

test("ia: un tool_end de harness_run avisa «#id harness arrancó» y refresca la lista", async () => {
  const t = await armarH(() => verDe({}), () => VACIA);
  try {
    await tick(60);
    const l = t.listas();
    (t.client as unknown as { emit(e: object): void }).emit({ type: "tool_end", id: "hr1", name: "harness_run", isError: false, text: "", details: { id: "a3f", harness: "claude" } });
    await until(() => /#a3f claude arrancó/.test(t.visible()));
    assert.match(t.visible(), /#a3f claude arrancó \(F2 para verlo\)/);
    await until(() => t.listas() > l);
    assert.ok(t.listas() > l);
  } finally { t.cerrar(); }
});

// --- Hallazgos de la revisión final ---
const emitir = (client: unknown, e: object) => (client as { emit(e: object): void }).emit(e);

test("ia: un subagente trabajando lleva ⋯ en la lista, no ●", async () => {
  const t = await armar();
  try {
    emitir(t.client, { type: "text", delta: "x", worker: "sub:1" });
    t.state.input(F2);
    await until(() => /sub:1/.test(t.visible()));
    assert.match(t.visible(), /⋯ sub:1/);
    assert.doesNotMatch(t.visible(), /● sub:1 ·/);
  } finally { t.daemon.close(); }
});

test("ia: sin recuadro (una ventana, sin lista) una fuente muestra su estado y nombre", async () => {
  const t = await armar();
  try {
    await t.conSub();
    await t.elegir(3);
    t.state.input(F2); // enfoca la lista
    await tick();
    t.state.input(F2); // la esconde
    await tick(80);
    assert.doesNotMatch(t.visible(), /Sesiones/);
    assert.match(t.visible(), /✓ sub:1 · (?:terminó|finished)/);
  } finally { t.daemon.close(); }
});

test("ia: si la lista no entra, el aviso de arranque manda a agrandar la terminal", async () => {
  const t = await armar(false, undefined, 60);
  try {
    emitir(t.client, { type: "text", delta: "x", worker: "sub:1" });
    await until(() => /sub:1 (?:arrancó|started)/.test(t.visible()));
    assert.match(t.visible(), /(?:agrandá la terminal y F2 para verlo|enlarge the terminal and F2 to see it)/);
    assert.doesNotMatch(t.visible(), /\/sesiones/);
  } finally { t.daemon.close(); }
});

test("ia: un harness vivo de otra sesión va debajo de ESA sesión y se sigue con su Harnesses", async () => {
  // La sesión 1 (la de arranque) no conoce la corrida; la 2 (la que abre «+ nueva») sí es su dueña.
  const t = await armarH(() => verDe({ tail: "desde B" }), (n) => (n === 1 ? VACIA : LISTA_RAMA));
  try {
    await t.lista3();
    t.state.input("\x1b[H\r"); // + nueva: abre la sesión 2 en la ventana
    await until(() => /⋯ #a3f claude/.test(t.visible()), 8000);
    const izq = () => t.visible().split("\r\n").map((l) => l.slice(0, 24));
    const donde = (re: RegExp) => izq().findIndex((l) => re.test(l));
    assert.doesNotMatch(t.visible(), /\/ultra · harnesses/);
    const sesiones = izq().map((l, i) => (/^│.[◆⚠] /.test(l) ? i : -1)).filter((i) => i >= 0);
    // La ventana muestra la sesión 2 (con su Chat debajo): el harness va entre ella y la sesión 1.
    assert.ok(sesiones.length === 2 && donde(/#a3f/) > sesiones[0]! && donde(/#a3f/) < sesiones[1]!, JSON.stringify({ sesiones, fila: donde(/#a3f/) }));
    // Vuelve a la sesión 1: el harness de la 2 sigue debajo de la 2 y, abierto desde acá, se sigue con el Harnesses de la 2.
    t.state.input(F2);
    await tick(80);
    t.state.input("\x1b[H" + "\x1b[B".repeat(sesiones[1]! - 1) + "\r");
    await until(() => donde(/Chat/) > sesiones[1]!, 8000);
    assert.ok(donde(/#a3f/) > 0, "sigue en la lista, debajo de la sesión 2");
    t.state.input(F2);
    await tick(80);
    t.state.input("\x1b[H" + "\x1b[B".repeat(donde(/#a3f/) - 1) + "\r");
    await until(() => t.llamadas.some((p) => "action" in p));
    assert.ok(t.llamadas.filter((p) => "action" in p).every((p) => (p as unknown as { n: number }).n === 2), "ver sólo con la sesión dueña");
    await until(() => /desde B/.test(t.visible()));
  } finally { t.cerrar(); }
});

test("ia: los harnesses anteriores van al final, una sola vez, aunque dos sesiones los vean", async () => {
  const vieja = (Object.assign(Object.create(Orquesta.prototype), { runs: new Map(), saved: () => [run({ id: "b4", state: "terminado", task: "vieja" })] }) as Orquesta).view();
  const t = await armarH(() => verDe({}), () => vieja);
  try {
    await t.lista3();
    t.state.input("\x1b[H\r");
    await until(() => (t.visible().match(/◆/g) ?? []).length >= 2, 8000);
    t.state.input(F2);
    await tick(150);
    assert.equal((t.visible().match(/\/ultra · harnesses/g) ?? []).length, 1);
    assert.equal((t.visible().match(/#b4/g) ?? []).length, 1);
  } finally { t.cerrar(); }
});

test("ia: la lista no se sondea si sólo hay harnesses anteriores", async () => {
  const vieja = (Object.assign(Object.create(Orquesta.prototype), { runs: new Map(), saved: () => [run({ id: "b4", state: "terminado", task: "vieja" })] }) as Orquesta).view();
  const t = await armarH(() => verDe({}), () => vieja);
  try {
    await t.lista3();
    const l = t.listas();
    await t.avanzar();
    assert.equal(t.listas(), l);
  } finally { t.cerrar(); }
});

test("ia: si el harness de la ventana desaparece de la lista, deja de sondearse", async () => {
  let hay = true;
  const t = await armarH(() => verDe({}), () => (hay ? LISTA_RAMA : VACIA));
  try {
    await t.abrir();
    hay = false;
    await t.avanzar(); // refresca: ya no está → final
    const l = t.listas();
    await t.avanzar();
    await t.avanzar();
    assert.equal(t.listas(), l);
  } finally { t.cerrar(); }
});

test("ia: el estado del harness sale traducido y la cola limpia en la ventana", async () => {
  const t = await armarH(() => verDe({ tail: "\x1b]52;c;QUJD\x07hola\x1b[31m rojo\x1b[0m\r50%\rlisto\x07" }));
  try {
    await t.abrir();
    assert.match(t.visible(), /(?:corriendo|running)/);
    if (!/corriendo/.test(t.visible())) assert.doesNotMatch(t.visible(), /corriendo/);
    assert.match(t.visible(), /listo/);
    assert.doesNotMatch(t.visible(), /50%|QUJD/);
  } finally { t.cerrar(); }
});
