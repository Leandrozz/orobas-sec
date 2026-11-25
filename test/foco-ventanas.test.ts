import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";
import { abrirProyecto, arregloGuardado, guardarAjuste, guardarArreglo } from "../src/tui/ajustes.ts";
import { PESTANA_CHAT, type Pestana, validarPestanas } from "../src/tui/pestanas.ts";
import { validarArreglo } from "../src/tui/ventanas.ts";
import { osc52 } from "../src/tui/portapapeles.ts";
import { startFoco } from "../src/tui/foco.ts";
import { Sesion } from "../src/tui/sesion.ts";
import { visibleWidth } from "../src/tui/text.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 3000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};

async function armar(columns = 120, rows = 30, previas?: Pestana[][]) {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-vent-"));
  process.env.CYBER_CONFIG = join(cwd, "config.json"); // ventanas y pestañas son generales: cada prueba con su configuración
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  abrirProyecto(cwd);
  if (previas) guardarArreglo({ forma: "lado", pestanas: previas, divisores: {}, lista: false });
  const state = { written: "", writes: 0, input: (_: string) => {}, resize: () => {}, exited: false };
  const output = { write: (data: string) => void ((state.written += data), state.writes++), columns, rows };
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
  const forma = async (numero: number) => { state.input("/ventanas\r"); await until(() => /Lado a lado/.test(visible())); state.input(String(numero)); await tick(); };
  return { state, provider, daemon, output, filas, visible, forma, client, cwd, foco };
}

test("ventanas: por defecto no hay bordes nuevos ni «para …» en el editor", async () => {
  const t = await armar();
  try {
    assert.doesNotMatch(t.visible(), /●/);
    assert.doesNotMatch(t.visible(), /para /);
  } finally { t.daemon.close(); }
});

test("ventanas: /ventanas → lado a lado dibuja dos recuadros y la activa lleva ●", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    const fila = t.filas().find((f) => (f.match(/ · Chat/g) ?? []).length === 2);
    assert.ok(fila, t.visible());
    assert.equal((fila.match(/●/g) ?? []).length, 1);
  } finally { t.daemon.close(); }
});

test("ventanas: F6 pasa el ● a la otra ventana y el editor dice para quién", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    const antes = t.filas().find((f) => f.includes("●"))!;
    t.state.input("\x1b[17~");
    const despues = t.filas().find((f) => f.includes("●"))!;
    assert.notEqual(antes.indexOf("●"), despues.indexOf("●"));
    assert.ok(despues.indexOf("●") > 40);
    assert.match(t.visible(), /para /);
  } finally { t.daemon.close(); }
});

test("ventanas: la forma y las pestañas por ventana se recuerdan", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    const a = arregloGuardado();
    assert.equal(a.forma, "lado");
    assert.equal(a.pestanas.length, 2);
  } finally { t.daemon.close(); }
});

test("ventanas: un turno en curso sigue dibujándose al cambiar de forma", async () => {
  const t = await armar();
  try {
    t.provider.faux!.queue = [{ text: "Respuesta larga del turno en curso." }];
    t.state.input("hola\r");
    await t.forma(2);
    await until(() => /Respuesta larga/.test(t.visible()));
    assert.match(t.visible(), /Respuesta larga/);
  } finally { t.daemon.close(); }
});

test("ventanas: 2×2 en 50 columnas muestra una y avisa; al agrandar vuelven", async () => {
  const t = await armar();
  try {
    await t.forma(5);
    assert.equal(t.filas().filter((f) => f.includes(" · Chat")).length >= 2, true);
    t.output.columns = 50;
    t.state.resize();
    assert.match(t.visible(), /ventanas ocultas/);
    t.output.columns = 120;
    t.state.resize();
    const titulos = t.filas().join("\n").match(/ · Chat/g) ?? [];
    assert.equal(titulos.length, 4);
    assert.doesNotMatch(t.visible(), /ventanas ocultas/);
  } finally { t.daemon.close(); }
});

test("ventanas: seleccionar con el mouse dentro de la ventana de la derecha copia lo que se ve", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.state.input("\x1b[17~");
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => /Buenas\./.test(t.visible()));
    const i = t.filas().findIndex((f) => f.includes("Buenas."));
    const col = t.filas()[i]!.lastIndexOf("Buenas.") + 1; // la ventana de la derecha
    t.state.input(`\x1b[<0;${col};${i + 1}M\x1b[<32;${col + 6};${i + 1}M\x1b[<0;${col + 6};${i + 1}m`);
    assert.match(t.visible(), /7 caracteres copiados/);
  } finally { t.daemon.close(); }
});

test("ventanas: «lado» a 120 columnas: todas las filas miden lo mismo y los bordes caen en las mismas columnas", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    const filas = t.filas();
    const caja = filas.filter((f) => f.startsWith("│"));
    assert.ok(caja.length > 10);
    for (const f of filas.slice(0, caja.length + 2).filter((f) => /^[│╭╰]/.test(f))) assert.equal(visibleWidth(f), 120, f);
    const cols = (f: string) => [...f].map((c, i) => (c === "│" ? i : -1)).filter((i) => i >= 0).join(",");
    assert.equal(new Set(caja.map(cols)).size, 1);
  } finally { t.daemon.close(); }
});

test("ventanas: el «para …» con título de ancho doble o de 60 caracteres cabe y el cursor queda tras lo escrito", async () => {
  for (const titulo of ["日本語日本語日本語日本語日本語日本語", "x".repeat(60)]) {
    const t = await armar();
    try {
      await t.forma(2);
      await t.client.ask("sesiones", { action: "rename", session: t.client.status.session, title: titulo });
      await until(() => t.client.status.title === titulo);
      await tick();
      t.state.input("hola mundo");
      const fila = t.filas().findIndex((f) => f.includes("hola mundo"));
      assert.ok(fila >= 0, t.visible());
      const linea = t.filas()[fila]!;
      assert.ok(visibleWidth(linea) <= 120);
      const nombre = /^ {2}para (.*): .* hola mundo$/.exec(linea)?.[1];
      assert.ok(nombre !== undefined && visibleWidth(nombre) <= 16, linea);
      const cursor = [...t.state.written.matchAll(/\x1b\[(\d+);(\d+)H(?![^]*\x1b\[\d+;\d+H)/g)].pop();
      assert.equal(Number(cursor![2]), visibleWidth(linea) + 1);
    } finally { t.daemon.close(); }
  }
});

const COSTOS: Pestana = { nombre: "Costos", tipo: "vista", vista: "costos" };
const borde = (filas: string[]) => filas[0]!.indexOf("╮");

test("ventanas: Ctrl+Shift+→ mueve la pestaña activa a la otra ventana y el origen queda con Chat", async () => {
  const t = await armar(120, 30, [[PESTANA_CHAT, COSTOS], [PESTANA_CHAT]]);
  try {
    t.state.input("\x1b2"); // Alt+2: la pestaña Costos
    t.state.input("\x1b[1;6C");
    await tick();
    const a = arregloGuardado();
    assert.deepEqual(a.pestanas.map((l) => l.map((p) => p.nombre)), [["Chat"], ["Chat", "Costos"]]);
    const fila = t.filas().find((f) => f.includes("●"))!;
    assert.ok(fila.indexOf("●") > 40 && /● .*· Costos/.test(fila.slice(fila.indexOf("●"))), fila);
  } finally { t.daemon.close(); }
});

test("ventanas: Ctrl+Alt+→ agranda la ventana izquierda dos columnas y se recuerda", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    const antes = borde(t.filas());
    t.state.input("\x1b[1;7C");
    assert.equal(borde(t.filas()), antes + 2);
    assert.ok(arregloGuardado().divisores.x! > 0.5);
  } finally { t.daemon.close(); }
});

test("ventanas: clic en la otra ventana la activa", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.state.input("\x1b[<0;90;5M\x1b[<0;90;5m");
    const fila = t.filas().find((f) => f.includes("●"))!;
    assert.ok(fila.indexOf("●") > 40, fila);
    assert.doesNotMatch(t.state.written, /caracteres copiados/);
  } finally { t.daemon.close(); }
});

test("ventanas: arrastrar el divisor lo corre", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    const c = borde(t.filas());
    t.state.input(`\x1b[<0;${c + 1};5M`);
    t.state.input(`\x1b[<32;${c + 7};5M`);
    assert.equal(borde(t.filas()), c + 6); // en vivo
    t.state.input(`\x1b[<0;${c + 7};5m`);
    assert.ok(Math.abs(arregloGuardado().divisores.x! - (60 + 6) / 120) < 0.01);
  } finally { t.daemon.close(); }
});

const MENSAJES: Pestana = { nombre: "Mensajes", tipo: "conversacion", contenido: ["mensajes"], detalle: "normal" };
const TEXTO: Pestana = { nombre: "Texto", tipo: "conversacion", contenido: ["texto"], detalle: "normal" };
const copiadoDe = (t: Awaited<ReturnType<typeof armar>>) => {
  const m = [...t.state.written.matchAll(/\x1b\]52;c;([^\x07\x1b]*)/g)].pop();
  return m ? Buffer.from(m[1]!, "base64").toString() : "";
};

test("ventanas: una selección que se arrastra a la otra ventana no la cruza (en ambos sentidos)", async () => {
  const t = await armar(120, 30, [[MENSAJES], [TEXTO]]);
  try {
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => /Buenas\./.test(t.visible()) && /hola/.test(t.visible()));
    const fh = t.filas().findIndex((f) => f.startsWith("│  hola"));
    const fb = t.filas().findIndex((f) => f.includes("Buenas."));
    assert.ok(fh >= 0 && fb >= 0, t.visible());
    // De la izquierda hacia adentro de la derecha: sólo «hola».
    const ch = t.filas()[fh]!.indexOf("hola") + 1;
    t.state.input(`\x1b[<0;${ch};${fh + 1}M\x1b[<32;115;${fh + 1}M\x1b[<0;115;${fh + 1}m`);
    assert.match(copiadoDe(t), /hola/);
    assert.doesNotMatch(copiadoDe(t), /Buenas/);
    // Un clic activa la derecha; desde ahí, el arrastre hacia adentro de la izquierda: sólo «Buenas.».
    const cb = t.filas()[fb]!.indexOf("Buenas.") + 1;
    t.state.input(`\x1b[<0;${cb};${fb + 1}M\x1b[<0;${cb};${fb + 1}m`);
    t.state.input(`\x1b[<0;${cb + 6};${fb + 1}M\x1b[<32;5;${fb + 1}M\x1b[<0;5;${fb + 1}m`);
    assert.match(copiadoDe(t), /Buenas/);
    assert.doesNotMatch(copiadoDe(t), /hola/);
  } finally { t.daemon.close(); }
});

test("ventanas: en «cuatro» y «tres» el divisor se agarra en toda su extensión", async () => {
  const t = await armar();
  try {
    await t.forma(5);
    const c = borde(t.filas());
    const f = t.filas().findIndex((l, i) => i > 0 && l.startsWith("╰")); // borde inferior de las de arriba
    const abajo = f + 5; // dentro de la mitad de abajo
    t.state.input(`\x1b[<0;${c + 1};${abajo + 1}M\x1b[<32;${c + 5};${abajo + 1}M\x1b[<0;${c + 5};${abajo + 1}m`);
    assert.equal(borde(t.filas()), c + 4);
    // El horizontal desde la mitad derecha.
    t.state.input(`\x1b[<0;100;${f + 1}M\x1b[<32;100;${f + 4}M\x1b[<0;100;${f + 4}m`);
    assert.ok(arregloGuardado().divisores.y! > 0.5 + 0.05, JSON.stringify(arregloGuardado().divisores));
    await t.forma(4);
    const c3 = borde(t.filas());
    t.state.input(`\x1b[<0;${c3 + 1};20M\x1b[<32;${c3 + 3};20M\x1b[<0;${c3 + 3};20m`);
    assert.equal(borde(t.filas()), c3 + 2);
  } finally { t.daemon.close(); }
});

const F2 = "\x1bOQ";
const F6 = "\x1b[17~";
const idsDe = (fila: string) => [...fila.matchAll(/([0-9a-f]{8}) · Chat/g)].map((m) => m[1]!);
/** Lado a lado, ventana derecha activa y una sesión nueva abierta en ella desde la lista (F2 + Enter sobre «+ nueva»). */
async function conOtraSesion(t: Awaited<ReturnType<typeof armar>>) {
  await t.forma(2);
  t.state.input(F6);
  t.state.input(F2);
  await until(() => /\+ nueva/.test(t.visible()));
  t.state.input("\r");
  await until(() => new Set(idsDe(t.filas().find((f) => f.includes("●")) ?? "")).size === 2);
}

test("ventanas: abrir una sesión nueva en la otra ventana; lo que escribís va a la activa", async () => {
  const t = await armar();
  try {
    await conOtraSesion(t);
    const fila = t.filas().find((f) => f.includes("●"))!;
    const [izq, der] = idsDe(fila);
    assert.notEqual(izq, der, fila);
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => /Buenas\./.test(t.visible()));
    const aparece = t.filas().filter((f) => f.includes("Buenas."));
    assert.equal(aparece.length, 1, t.visible());
    assert.ok(aparece[0]!.indexOf("Buenas.") > 70, aparece[0]!); // lista (24) + ventana izquierda (48)
  } finally { t.daemon.close(); }
});

test("ventanas: dos ventanas con la misma sesión comparten la conversación", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => t.filas().some((f) => (f.match(/Buenas\./g) ?? []).length === 2));
    assert.ok(t.filas().some((f) => (f.match(/Buenas\./g) ?? []).length === 2), t.visible());
  } finally { t.daemon.close(); }
});

test("ventanas: un permiso de la sesión no activa avisa y espera; el borrador no se pierde", async () => {
  const t = await armar();
  const otro = await connectDaemon(t.cwd, { spawn: false });
  try {
    await conOtraSesion(t);
    t.state.input(F6); // activa: la izquierda
    t.state.input("borrador");
    const idB = [...t.daemon.hosts.keys()].find((id) => id !== t.client.status.session)!;
    await otro.attach({ session: idB });
    t.provider.faux!.queue = [{ toolCalls: [{ name: "shell", arguments: { command: "git push origin main" } }] }, { text: "fin" }];
    otro.send("subí los cambios");
    await until(() => /espera tu respuesta/.test(t.visible()));
    assert.match(t.visible(), /⚠ .* espera tu respuesta \(F6 para ir\)/);
    assert.match(t.visible(), /╭─ ⚠ .* · espera respuesta/);
    assert.match(t.visible(), /borrador/);
    assert.doesNotMatch(t.visible(), /permiso de shell/i);
    t.state.input(F6);
    await until(() => /permiso de shell/i.test(t.visible()));
    assert.match(t.visible(), /permiso de shell/i);
    t.state.input("r");
    await until(() => !/permiso de shell/i.test(t.visible()));
    assert.doesNotMatch(t.visible(), /espera tu respuesta/);
    await until(() => /\bfin\b/.test(t.visible())); // el turno de esa sesión siguió (rechazado) y terminó
  } finally { otro.close(); t.daemon.close(); }
});

test("ventanas: achicar la forma deja la sesión sin ventana en la lista y conectada", async () => {
  const t = await armar();
  try {
    await conOtraSesion(t);
    await t.forma(1);
    assert.equal(t.filas().filter((f) => f.includes(" · Chat")).length >= 1, true);
    t.state.input(F2);
    await tick();
    const marcadas = t.filas().filter((f) => f.includes("◆"));
    assert.equal(marcadas.length, 2, t.visible());
    assert.ok([...t.daemon.hosts.values()].filter((h) => h.clients.size > 0).length >= 2);
  } finally { t.daemon.close(); }
});

test("ventanas: al salir se cierran todas las conexiones", async () => {
  const t = await armar();
  try {
    await conOtraSesion(t);
    assert.ok([...t.daemon.hosts.values()].some((h) => h.clients.size > 0));
    t.state.input("\x04");
    await until(() => t.state.exited && [...t.daemon.hosts.values()].every((h) => h.clients.size === 0));
    assert.equal(t.state.exited, true);
    assert.deepEqual([...t.daemon.hosts.values()].map((h) => h.clients.size), [0, 0]);
  } finally { t.daemon.close(); }
});

/** Deja un permiso de shell pendiente en la otra sesión (la de la derecha) pedido desde un segundo cliente, que también puede resolverlo. */
async function permisoAjeno(t: Awaited<ReturnType<typeof armar>>) {
  const otro = await connectDaemon(t.cwd, { spawn: false });
  let id = -1;
  otro.on((e) => { if (e.type === "confirm") id = e.id; });
  const idB = [...t.daemon.hosts.keys()].find((x) => x !== t.client.status.session)!;
  await otro.attach({ session: idB });
  t.provider.faux!.queue = [{ toolCalls: [{ name: "shell", arguments: { command: "git push origin main" } }] }, { text: "fin" }];
  otro.send("subí los cambios");
  await until(() => id >= 0 && /espera tu respuesta/.test(t.visible()));
  return { otro, resolver: () => otro.ask("confirm", { permiso: id, ok: false, decision: "no" }) };
}

test("ventanas: si otro cliente resuelve el permiso de la sesión no activa, no queda ⚠ ni caja muerta", async () => {
  const t = await armar();
  let otro: Awaited<ReturnType<typeof permisoAjeno>>["otro"] | undefined;
  try {
    await conOtraSesion(t);
    t.state.input(F6);
    const p = await permisoAjeno(t);
    otro = p.otro;
    assert.match(t.visible(), /╭─ ⚠ .* · espera respuesta/);
    await p.resolver();
    await until(() => !/espera tu respuesta/.test(t.visible()));
    assert.doesNotMatch(t.visible(), /espera tu respuesta/);
    assert.doesNotMatch(t.visible(), /⚠/);
    t.state.input(F6);
    await tick();
    assert.doesNotMatch(t.visible(), /permiso de shell/i);
    await until(() => /\bfin\b/.test(t.visible()));
  } finally { otro?.close(); t.daemon.close(); }
});

const falso = () => {
  let escucha: (e: never) => void = () => {};
  const client = { status: { running: true, session: "s1" }, on: (l: typeof escucha) => { escucha = l; } };
  const sesion = new Sesion(client as never, { messages: [], status: client.status, tools: {} } as never);
  sesion.on(() => {});
  const emit = (e: object) => escucha(e as never);
  const pide = () => emit({ type: "confirm", id: 1, command: "x", cwd: "/", kind: "red", risky: true, reasons: [], prefix: "x" });
  return { sesion, emit, pide, client };
};
const inicio = (id: string) => ({ type: "tool_start", id, name: "shell", label: id });
const fin = (id: string) => ({ type: "tool_end", id, name: "shell", isError: false, text: "", details: {} });

test("permiso ajeno: el tool_end de la herramienta que pidió lo resuelve; con otra en paralelo, sólo al terminar las dos", () => {
  const a = falso();
  a.emit(inicio("c1"));
  a.pide();
  assert.ok(a.sesion.permiso);
  a.emit(fin("c1"));
  assert.equal(a.sesion.permiso, undefined);
  const b = falso();
  b.emit(inicio("c1"));
  b.emit(inicio("c2"));
  b.pide();
  b.emit(fin("c2"));
  assert.ok(b.sesion.permiso, "c1 sigue esperando");
  b.emit(fin("c1"));
  assert.equal(b.sesion.permiso, undefined);
});

test("permiso ajeno: idle y el fin del turno también lo resuelven; un status con el turno en marcha no", () => {
  const a = falso();
  a.emit(inicio("c1"));
  a.pide();
  a.emit({ type: "status" });
  assert.ok(a.sesion.permiso);
  a.emit({ type: "idle" });
  assert.equal(a.sesion.permiso, undefined);
  const b = falso();
  b.emit(inicio("c1"));
  b.pide();
  b.client.status.running = false;
  b.emit({ type: "status" });
  assert.equal(b.sesion.permiso, undefined);
});

test("ventanas: si la sesión que espera no tiene ventana, el aviso manda a F2", async () => {
  const t = await armar();
  let otro: Awaited<ReturnType<typeof permisoAjeno>>["otro"] | undefined;
  try {
    await conOtraSesion(t);
    await t.forma(1);
    t.state.input(F6); // con una sola ventana no hace nada: sigue la izquierda... la activa mira otra sesión
    const p = await permisoAjeno(t);
    otro = p.otro;
    assert.match(t.visible(), /espera tu respuesta \(F2 para ir\)/);
    await p.resolver();
    await until(() => /\bfin\b/.test(t.visible()) || !/espera tu respuesta/.test(t.visible()));
  } finally { otro?.close(); t.daemon.close(); }
});

test("ventanas: F2, Esc y escribir: el editor vuelve a recibir las teclas", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.state.input(F2);
    t.state.input("x"); // con la lista enfocada no llega al editor
    assert.doesNotMatch(t.visible(), /› x/);
    t.state.input("\x1b");
    await tick(80);
    t.state.input("hola");
    assert.match(t.visible(), /hola/);
  } finally { t.daemon.close(); }
});

// ---- Ola de arreglos de la revisión final ----

const unaVez = (t: Awaited<ReturnType<typeof armar>>) => [...t.daemon.hosts.entries()].find(([id]) => id !== t.client.status.session)?.[1];

test("ola 1: una sesión nueva en otra ventana recibe los ajustes recordados del proyecto", async () => {
  const t = await armar();
  try {
    guardarAjuste("rate", "7"); // después del arranque: sólo una sesión abierta ahora puede recibirlo
    await conOtraSesion(t);
    await until(() => unaVez(t)?.engine.http.rate === 7);
    assert.equal(unaVez(t)?.engine.http.rate, 7);
  } finally { t.daemon.close(); }
});

/** Deja un permiso de shell pendiente en la sesión activa (la del arranque). */
async function permisoPropio(t: Awaited<ReturnType<typeof armar>>) {
  t.provider.faux!.queue = [{ toolCalls: [{ name: "shell", arguments: { command: "git push origin main" } }] }, { text: "fin" }];
  t.state.input("subí los cambios\r");
  await until(() => /permiso de shell/i.test(t.visible()));
}

test("ola 2: un menú que desplaza el permiso no lo rechaza; la caja vuelve al cerrarse", async () => {
  const t = await armar();
  try {
    await permisoPropio(t);
    void t.foco.pick("Menú de prueba", ["uno", "dos"]);
    await until(() => /Menú de prueba/.test(t.visible()));
    await tick(150);
    assert.doesNotMatch(t.visible(), /Rechazado/);
    assert.doesNotMatch(t.visible(), /\bfin\b/);
    t.state.input("\x1b");
    await until(() => /permiso de shell/i.test(t.visible()));
    assert.match(t.visible(), /permiso de shell/i);
    t.state.input("r");
    await until(() => /\bfin\b/.test(t.visible()));
  } finally { t.daemon.close(); }
});

test("ola 3: con 4 ventanas, los eventos de texto se juntan en pocos cuadros", async () => {
  const t = await armar();
  try {
    await t.forma(5);
    let eventos = 0;
    t.client.on((e) => { if (e.type === "text") eventos++; });
    const antes = t.state.writes;
    t.provider.faux!.queue = [{ text: Array.from({ length: 300 }, (_, i) => `p${i}`).join(" ") }];
    t.state.input("hola\r");
    await until(() => /p299/.test(t.visible()));
    await tick(100);
    const escrituras = t.state.writes - antes;
    assert.ok(eventos >= 100, `eventos ${eventos}`);
    assert.ok(escrituras * 4 < eventos, `escrituras ${escrituras} eventos ${eventos}`);
  } finally { t.daemon.close(); }
});

test("ola 4: si pasás a otra ventana mientras se abre la sesión, te quedás en ella", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.state.input(F6);
    t.state.input(F2);
    await until(() => /\+ nueva/.test(t.visible()));
    t.state.input("\r");
    t.state.input(F6); // conecta en segundo plano: la activa pasa a la izquierda
    await until(() => new Set(t.filas().join("\n").match(/[0-9a-f]{8} · Chat/g)).size === 2);
    await tick();
    const fila = t.filas().find((f) => f.includes("●"))!;
    assert.ok(fila.indexOf("●") < 72, fila);
  } finally { t.daemon.close(); }
});

test("ola 5: si la TUI se cierra mientras se abre una sesión, la conexión nueva no queda abierta", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.state.input(F2);
    await until(() => /\+ nueva/.test(t.visible()));
    t.state.input("\r");
    t.state.input("\x04");
    await until(() => t.state.exited && [...t.daemon.hosts.values()].every((h) => h.clients.size === 0));
    await tick(200);
    assert.deepEqual([...t.daemon.hosts.values()].map((h) => h.clients.size), t.daemon.hosts.size === 1 ? [0] : [0, 0]);
  } finally { t.daemon.close(); }
});

test("ola 6: un segundo pedido de permiso rechaza al primero con el client de esa sesión", () => {
  const preguntas: Array<[string, unknown]> = [];
  let escucha: (e: never) => void = () => {};
  const client = { status: { running: true, session: "s1" }, on: (l: typeof escucha) => { escucha = l; }, ask: async (op: string, p: unknown) => (preguntas.push([op, p]), []) };
  const sesion = new Sesion(client as never, { messages: [], status: client.status, tools: {} } as never);
  sesion.on(() => {});
  const pide = (id: number) => escucha({ type: "confirm", id, command: "x", cwd: "/", kind: "red", risky: true, reasons: [], prefix: "x" } as never);
  pide(1);
  assert.deepEqual(preguntas, []);
  pide(2);
  assert.deepEqual(preguntas, [["confirm", { permiso: 1, ok: false, decision: "no" }]]);
  assert.equal(sesion.permiso?.id, 2);
});

test("ola 7: con la lista enfocada, el ● y el borde en acento son de la lista y no de la ventana activa", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.state.input(F2);
    await until(() => /Sesiones/.test(t.visible()));
    assert.equal((t.visible().match(/●/g) ?? []).length, 1, t.visible());
    assert.match(t.filas().find((f) => f.includes("Sesiones"))!, /●/);
    t.state.input("\x1b");
    await tick(80);
    assert.equal((t.visible().match(/●/g) ?? []).length, 1);
    assert.doesNotMatch(t.filas().find((f) => f.includes("Sesiones"))!.slice(0, 24), /●/);
  } finally { t.daemon.close(); }
});

test("ola 8: si la lista no entra, F2 no enfoca nada y avisa", async () => {
  const t = await armar(50);
  try {
    t.state.input(F2);
    await tick(80);
    assert.match(t.visible(), /La lista no entra: agrandá la terminal/);
    assert.equal(arregloGuardado().lista, false);
  } finally { t.daemon.close(); }
});

test("ola 9: con una ventana la ayuda nombra F2 y, siempre visible, la sección de Ventanas", async () => {
  const t = await armar(120, 120); // alta: la ayuda entra entera
  try {
    t.state.input("/help\r");
    await until(() => /allow-passthrough/.test(t.visible()));
    assert.match(t.visible(), /F2 muestra la lista/);
    assert.match(t.visible(), /F6/);
  } finally { t.daemon.close(); }
});

test("ola 11: cada ventana tiene su propia «Chat»: moverla de una no borra la de otra", () => {
  const a = validarArreglo({ forma: "tres", pestanas: [] }, [PESTANA_CHAT]);
  assert.notEqual(a.pestanas[0]![0], a.pestanas[1]![0]);
  assert.notEqual((a.pestanas[0]![0] as { contenido: unknown[] }).contenido, (a.pestanas[1]![0] as { contenido: unknown[] }).contenido);
  assert.notEqual(validarPestanas(null)[0], PESTANA_CHAT);
  assert.deepEqual(validarPestanas(null)[0], PESTANA_CHAT);
});

test("ola 12: la rueda recorre la ventana que está bajo el puntero y no cambia la activa", async () => {
  const t = await armar();
  try {
    await t.forma(2);
    t.provider.faux!.queue = [{ text: `${Array.from({ length: 60 }, (_, i) => `linea ${i}`).join("\n\n")}\n\nFINAL` }];
    t.state.input("hola\r");
    await until(() => t.filas().some((f) => (f.match(/FINAL/g) ?? []).length === 2));
    t.state.input("\x1b[<64;100;10M\x1b[<64;100;10M");
    await tick(60);
    const quedan = t.filas().filter((f) => f.includes("FINAL"));
    assert.equal(quedan.length, 1, t.visible());
    assert.ok(quedan[0]!.indexOf("FINAL") < 60, quedan[0]!); // la izquierda (activa) no se movió
    assert.ok(t.filas().find((f) => f.includes("●"))!.indexOf("●") < 60);
  } finally { t.daemon.close(); }
});

test("ventanas: con dos ventanas el pie dice F6 ventana · F2 lista", async () => {
  const t = await armar();
  try {
    assert.doesNotMatch(t.visible(), /F6 ventana/);
    await t.forma(2);
    assert.match(t.visible(), /F6 ventana · F2 lista · \/diseño/);
  } finally { t.daemon.close(); }
});

test("ventanas: /ventanas explica las formas", async () => {
  const t = await armar(80);
  try {
    t.state.input("/ventanas\r");
    await until(() => /Lado a lado/.test(t.visible()));
    for (const x of [/como siempre/, /dos iguales/, /una ancha y una angosta/, /una y dos apiladas/, /cuatro iguales/, /Enter/, /Esc/]) assert.match(t.visible(), x);
  } finally { t.daemon.close(); }
});

test("ventanas: al salir se rechazan los permisos pendientes de todas las sesiones", async () => {
  const t = await armar();
  let p: Awaited<ReturnType<typeof permisoAjeno>> | undefined;
  try {
    await conOtraSesion(t);
    t.state.input(F6);
    p = await permisoAjeno(t);
    assert.ok(p.otro.status.running);
    t.foco.exit();
    await until(() => !p!.otro.status.running);
    assert.equal(p.otro.status.running, false); // el turno no quedó esperando el permiso
  } finally { p?.otro.close(); t.daemon.close(); }
});

test("chat personal: el editor despacha comandos de Orobas y sólo envía texto al proveedor", async () => {
  const { writeSecret } = await import("../src/secretos.ts");
  const { mock } = await import("node:test");
  const previous = process.env.CYBER_CREDENTIALS_DIR;
  process.env.CYBER_CREDENTIALS_DIR = mkdtempSync(join(tmpdir(), "personal-foco-"));
  const requests: string[] = [];
  const fetchMock = mock.method(globalThis, "fetch", async (_url: unknown, options: { body?: string }) => {
    if (!options.body) return Response.json({ data: [] });
    requests.push(JSON.parse(options.body).messages.at(-1).content);
    return Response.json({ choices: [{ message: { content: "respuesta personal de prueba" } }], usage: { total_tokens: 17, prompt_tokens: 12 } });
  });
  const t = await armar();
  try {
    writeSecret("chat-personal-" + "a".repeat(64), JSON.stringify({ provider: "Self-hosted", model: "modelo-prueba", base: "https://example.invalid/v1" }));
    t.foco.submit("/modelos");
    await until(() => t.visible().includes("Modelo Prueba"));
    t.state.input("self-hosted");
    assert.match(t.visible(), /Modelo Prueba/);
    assert.doesNotMatch(t.visible(), /Conectar modelo o escribir proveedor/i);
    t.state.input("\r");
    await until(() => t.visible().includes("chat personal"));
    t.foco.submit("/ayuda");
    await tick();
    t.foco.submit("hola desde el editor");
    await until(() => t.visible().includes("respuesta personal de prueba"));
    assert.deepEqual(requests, ["hola desde el editor"]);
    assert.match(t.visible(), /respuesta personal de prueba/);
    const { projectPaths, openStore } = await import("../src/store.ts");
    const db = openStore(projectPaths(t.cwd));
    try {
      const rows = db.prepare("select type,payload from events where session_id=? and type like 'personal.%' order by seq").all(t.client.status.session!);
      assert.deepEqual(rows.map(row => row.type), ["personal.start", "personal.finish"]);
      assert.equal(JSON.parse(String(rows[1]!.payload)).tokens, 17);
    } finally { db.close(); }
  } finally {
    fetchMock.mock.restore();
    if (previous === undefined) delete process.env.CYBER_CREDENTIALS_DIR;
    else process.env.CYBER_CREDENTIALS_DIR = previous;
    t.foco.exit();
    t.daemon.close();
  }
});
