import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";
import { abrirProyecto, elegirIdioma, guardarPestanas } from "../src/tui/ajustes.ts";
import { clampScroll, startFoco } from "../src/tui/foco.ts";
import { Registro } from "../src/tui/entradas.ts";
import type { Pestana } from "../src/tui/pestanas.ts";
import { Pantalla } from "../src/tui/pantalla.ts";
import { usarTema } from "../src/tui/temas.ts";
import { visibleWidth } from "../src/tui/text.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 3000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};
const PERU: Pestana = { nombre: "Perú", tipo: "conversacion", contenido: ["comandos"], detalle: "normal" };
const CHAT: Pestana = { nombre: "Chat", tipo: "conversacion", contenido: ["mensajes", "texto", "acciones", "resultados", "comandos", "avisos"], detalle: "normal" };

async function armar(pestanas?: Pestana[], terminal?: Record<string, unknown>, rows = 30, extra: { onboarding?: boolean } = {}) {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-pest-"));
  process.env.CYBER_CONFIG = join(cwd, "config.json"); // ventanas y pestañas son generales: cada prueba con su configuración
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  abrirProyecto(cwd);
  if (pestanas) guardarPestanas(pestanas);
  const state = { written: "", input: (_: string) => {}, resize: () => {}, exited: false };
  const output = { write: (data: string) => void (state.written += data), columns: 70, rows };
  const client = await connectDaemon(cwd, { spawn: false });
  const snapshot = await client.attach({ session: "new" });
  startFoco(client, snapshot, {
    project: cwd,
    io: { output, ...(terminal ? { terminal: terminal as never } : {}), listen: (onData, onResize) => ((state.input = onData), (state.resize = onResize), () => {}) },
    onExit: () => ((state.exited = true), client.close()),
    ...extra,
  });
  const filas = () => pantallaVisible(state.written, output.columns, output.rows);
  const visible = () => filas().join("\r\n");
  return { state, provider, daemon, output, filas, visible, client };
}

test("pestañas: con una sola no hay fila de pestañas y la conversación se ve como hoy", async () => {
  const t = await armar();
  try {
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => /Buenas\./.test(t.visible()));
    assert.match(t.visible(), /── Vos [^\r]*\r\n  hola/);
    assert.match(t.visible(), /── Orobas [^\r]*\r\n  Buenas\./);
    assert.doesNotMatch(t.visible(), /Chat/);
  } finally { t.daemon.close(); }
});

test("pestañas: «Chat» con todo y «Perú» sólo comandos: /costos aparece en las dos, el mensaje sólo en Chat, y Perú cuenta 1 novedad", async () => {
  const t = await armar([CHAT, PERU], undefined, 60);
  try {
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => /Buenas\./.test(t.visible()));
    t.state.input("/costos\r");
    await until(() => /COSTO API ESTIMADO/.test(t.visible()));
    assert.match(t.filas()[0]!, /Chat/);
    assert.equal(t.filas()[0], " Chat   Perú  1 ");
    assert.match(t.filas()[1]!, /^ ━━━━─+$/);
    t.state.input("\x1b2");
    assert.match(t.visible(), /COSTO API ESTIMADO/);
    assert.doesNotMatch(t.visible(), /hola/);
    assert.match(t.filas()[0]!, /Perú/);
    assert.doesNotMatch(t.filas()[0]!, /Perú  1/);
    t.state.input("\x1b1");
    assert.match(t.visible(), /── Vos [^\r]*\r\n  hola/);
    t.state.input("\x1b[1;3C");
    assert.doesNotMatch(t.visible(), /hola/);
  } finally { t.daemon.close(); }
});

const parrafos = Array.from({ length: 40 }, (_, i) => `línea ${i + 1}`).join("\n\n");

test("pestañas: PgUp deja de seguir el final y Ctrl+Fin vuelve", async () => {
  const t = await armar();
  try {
    t.provider.faux!.queue = [{ text: parrafos }];
    t.state.input("largo\r");
    await until(() => /línea 40/.test(t.visible()));
    assert.match(t.visible(), /línea 40/);
    t.state.input("\x1b[5~");
    assert.doesNotMatch(t.visible(), /línea 40/);
    t.state.input("\x1b[6~");
    assert.match(t.visible(), /línea 40/);
    t.state.input("\x1b[5~\x1b[5~");
    t.state.input("\x1b[1;5F");
    assert.match(t.visible(), /línea 40/);
    t.state.input("\x1b[<64;5;5M"); // rueda hacia arriba: 3 líneas
    assert.doesNotMatch(t.visible(), /línea 40/);
  } finally { t.daemon.close(); }
});

test("pestañas: un cambio de ancho con scroll arriba no se sale de rango", async () => {
  assert.equal(clampScroll(100, 50, 10), 40);
  assert.equal(clampScroll(-3, 50, 10), 0);
  assert.equal(clampScroll(5, 3, 10), 0);
  const t = await armar();
  try {
    t.provider.faux!.queue = [{ text: parrafos }];
    t.state.input("largo\r");
    await until(() => /línea 40/.test(t.visible()));
    t.state.input("\x1b[1;5H"); // Ctrl+Inicio
    t.output.columns = 24;
    t.state.resize();
    assert.match(t.visible(), /línea 1\b/);
    assert.doesNotMatch(t.visible(), /línea 40/);
    assert.match(t.visible(), /── Vos [^\r]*\r\n  largo/);
  } finally { t.daemon.close(); }
});

test("pestañas: con el scroll arriba, lo nuevo no mueve lo que se lee y avisa «▼ N nuevas»", async () => {
  const t = await armar();
  try {
    t.provider.faux!.queue = [{ text: parrafos }];
    t.state.input("largo\r");
    await until(() => /línea 40/.test(t.visible()));
    t.state.input("\x1b[1;5H");
    const antes = t.filas().slice(0, 15);
    assert.match(antes.join("\n"), /línea 1\b/);
    t.state.input("/costos\r");
    await until(() => /▼ 1 (nuevas|new)/.test(t.visible()));
    assert.match(t.visible(), /▼ 1 (nuevas|new) · Ctrl\+(Fin|End)/);
    assert.deepEqual(t.filas().slice(0, 15), antes);
    assert.doesNotMatch(t.visible(), /COSTO API/);
    t.state.input("\x1b[1;5F");
    assert.match(t.visible(), /COSTO API ESTIMADO/);
    assert.doesNotMatch(t.visible(), /▼/);
  } finally { t.daemon.close(); }
});

test("pestañas: al desconectarse el daemon se sale de la pantalla alternativa", async () => {
  const t = await armar();
  t.daemon.close();
  await until(() => t.state.exited);
  assert.ok(t.state.exited);
  assert.ok(t.state.written.lastIndexOf("\x1b[?1049l") > t.state.written.lastIndexOf("\x1b[?1049h"));
});

test("pestañas: el sello no se borra al escribir y se coloca una vez", async () => {
  const t = await armar(undefined, { graphics: true, protocol: "sixel", cellWidth: 10, cellHeight: 20, cellSizeKnown: true });
  try {
    assert.match(t.state.written, /\x1bP/);
    const titulo = t.filas().findIndex((f) => /OROBAS/.test(f));
    assert.ok(titulo > 0);
    const marca = t.state.written.length;
    t.state.input("x");
    const nuevo = t.state.written.slice(marca);
    assert.doesNotMatch(nuevo, /\x1b\[2J|\x1bP/);
    for (const m of nuevo.matchAll(/\x1b\[(\d+);1H\x1b\[2K/g)) assert.ok(Number(m[1]) - 1 > titulo, `fila ${m[1]} bajo el sello`);
  } finally { t.daemon.close(); }
});

const COMPLETO: Pestana = { nombre: "Chat", tipo: "conversacion", contenido: ["mensajes", "texto", "acciones", "resultados", "comandos", "avisos"], detalle: "completo" };
/** Simula una herramienta que terminó dejando un artefacto. */
const herramienta = (client: unknown, id: string, hash: string) => {
  const emit = (client as { emit(e: object): void }).emit.bind(client);
  emit({ type: "tool_start", id, name: "shell", label: "shell" });
  emit({ type: "tool_end", id, name: "shell", isError: false, text: "", details: { artefacto: hash } });
};

test("resultados: en completo se trae el artefacto de lo visible, de a dos, y un fallo se muestra sin trabar", async () => {
  const t = await armar([COMPLETO], undefined, 60);
  try {
    let vuelo = 0, maximo = 0;
    const pedidos: string[] = [];
    (t.client as { view: unknown }).view = async (_: string, hash: string) => {
      pedidos.push(hash);
      maximo = Math.max(maximo, ++vuelo);
      await tick(120);
      vuelo--;
      if (hash === "sha256:mal") throw new Error("boom");
      return [`EVIDENCIA · ${hash}`, `cuerpo de ${hash}`];
    };
    herramienta(t.client, "a", "sha256:uno");
    herramienta(t.client, "b", "sha256:mal");
    herramienta(t.client, "c", "sha256:tres");
    await until(() => /cargando…|loading…/.test(t.visible()));
    t.state.input("hola");
    assert.match(t.visible(), /› hola/);
    await until(() => /no se pudo traer|could not fetch/.test(t.visible()) && /cuerpo de sha256:tres/.test(t.visible()));
    assert.match(t.visible(), /cuerpo de sha256:uno/);
    assert.doesNotMatch(t.visible(), /EVIDENCIA/);
    assert.equal(maximo, 2);
    assert.deepEqual(pedidos.sort(), ["sha256:mal", "sha256:tres", "sha256:uno"]);
  } finally { t.daemon.close(); }
});

test("resultados: Alt+↑ selecciona la última acción, Enter expande y escribir suelta la selección", async () => {
  const t = await armar([COMPLETO], undefined, 60);
  try {
    const cuerpo = Array.from({ length: 30 }, (_, i) => `fila ${i + 1}`);
    (t.client as { view: unknown }).view = async () => ["EVIDENCIA · x", ...cuerpo];
    herramienta(t.client, "a", "sha256:uno");
    await until(() => /fila 12/.test(t.visible()));
    assert.match(t.visible(), /18 (líneas más|more lines)/);
    assert.doesNotMatch(t.visible(), /fila 30/);
    t.state.input("\x1b[1;3A");
    assert.match(t.visible(), /Alt\+↑↓/);
    t.state.input("\r");
    assert.match(t.visible(), /fila 30/);
    assert.doesNotMatch(t.visible(), /líneas más · Enter/);
    t.provider.faux!.queue = [{ text: "Listo." }];
    t.state.input("x");
    assert.doesNotMatch(t.visible(), /Alt\+↑↓/);
    assert.match(t.visible(), /› x/);
    t.state.input("\r");
    await until(() => /Listo\./.test(t.visible()));
    assert.match(t.visible(), /── Vos [^\r]*\r\n  x/);
  } finally { t.daemon.close(); }
});

test("pick: un cycle que devuelve { rows, at } reemplaza las filas y mueve el cursor", async () => {
  const t = await armar([CHAT, PERU], undefined, 60);
  try {
    t.state.input("/config\r");
    await until(() => /Configuración/.test(t.visible()));
    t.state.input("\x1b[B\r");
    await until(() => /\+ Nueva pestaña/.test(t.visible()));
    t.state.input("\x1b[C");
    await until(() => /Perú.*\r\n.*Chat/.test(t.visible()));
    assert.match(t.visible(), /Perú[^\r]*\r\n[^\r]*Chat/);
    t.state.input("\r");
    await until(() => /Nombre/.test(t.visible()));
    assert.match(t.visible(), /Chat/, "el cursor quedó en la pestaña movida (Chat), que se edita");
  } finally { t.daemon.close(); }
});

const HALLAZGOS: Pestana = { nombre: "Hallazgos", tipo: "vista", vista: "hallazgos" };
const LISTA = ["HALLAZGOS · 0 verificados · 2 candidatos · 0 pistas · 0 descartados", "? a1b2c3d4  candidato  alta        SQLi en login", "? e5f6a7b8  candidato  media       XSS en búsqueda", "Detalle: /findings <id>"];

test("vistas: Enter abre el hallazgo, Esc vuelve a la misma fila, y con texto en el editor Enter envía", async () => {
  const t = await armar([CHAT, HALLAZGOS], undefined, 60);
  try {
    const pedidos: string[] = [];
    (t.client as { view: unknown }).view = async (nombre: string, arg = "") => {
      pedidos.push(`${nombre}:${arg}`);
      return arg ? [`HALLAZGO ${arg}`, `Detalle de ${arg}`] : LISTA;
    };
    t.state.input("\x1b2");
    await until(() => /XSS en búsqueda/.test(t.visible()));
    assert.deepEqual(pedidos, ["findings:"]);
    t.state.input("\x1b[B");
    assert.match(t.visible(), /▌ .* \? e5f6a7b8/);
    t.state.input("\r");
    await until(() => /Detalle de e5f6a7b8/.test(t.visible()));
    assert.deepEqual(pedidos, ["findings:", "findings:e5f6a7b8"]);
    t.state.input("\x1b");
    assert.match(t.visible(), /▌ .* \? e5f6a7b8/);
    assert.doesNotMatch(t.visible(), /Detalle de/);
    t.provider.faux!.queue = [{ text: "Listo." }];
    t.state.input("hola");
    t.state.input("\r");
    t.state.input("\x1b1");
    await until(() => /Listo\./.test(t.visible()));
    assert.match(t.visible(), /── Vos [^\r]*\r\n  hola/);
  } finally { t.daemon.close(); }
});

test("vistas: un fallo del daemon se muestra como texto y no traba el teclado", async () => {
  const t = await armar([CHAT, HALLAZGOS], undefined, 60);
  try {
    (t.client as { view: unknown }).view = async () => { throw new Error("caído"); };
    t.state.input("\x1b2");
    await until(() => /no se pudo traer/.test(t.visible()));
    t.state.input("\x1b[B\r");
    t.state.input("\x1b1");
    assert.match(t.filas()[0]!, /Chat/);
  } finally { t.daemon.close(); }
});

test("vistas: una pestaña inactiva se marca con • cuando termina un turno, y se pide al abrirla", async () => {
  const t = await armar([CHAT, HALLAZGOS], undefined, 60);
  try {
    let pedidos = 0;
    (t.client as { view: unknown }).view = async () => (pedidos++, LISTA);
    (t.client as unknown as { emit(e: object): void }).emit({ type: "idle" });
    await until(() => /Hallazgos ●/.test(t.filas()[0]!)); // los eventos se juntan en un cuadro de 16 ms
    assert.match(t.filas()[0]!, /Hallazgos ●/);
    assert.equal(pedidos, 0);
    t.state.input("\x1b2");
    await until(() => pedidos === 1);
    assert.doesNotMatch(t.filas()[0]!, /●/);
  } finally { t.daemon.close(); }
});

test("selección: /clear y Ctrl+L sueltan la selección y Enter vuelve a enviar", async () => {
  for (const limpiar of ["/clear\r", "\x0c"]) {
    const t = await armar([COMPLETO], undefined, 60);
    try {
      (t.client as { view: unknown }).view = async () => ["EVIDENCIA · x", "fila 1"];
      herramienta(t.client, "a", "sha256:uno");
      await until(() => /fila 1/.test(t.visible()));
      t.state.input("\x1b[1;3A");
      assert.match(t.visible(), /Alt\+↑↓/);
      t.state.input(limpiar);
      await until(() => !/fila 1/.test(t.visible()));
      assert.doesNotMatch(t.visible(), /Alt\+↑↓/);
      t.provider.faux!.queue = [{ text: "Enviado." }];
      t.state.input("x");
      t.state.input("\r");
      await until(() => /Enviado\./.test(t.visible()));
      assert.match(t.visible(), /Enviado\./);
    } finally { t.daemon.close(); }
  }
});

test("vistas: con más filas que el alto, la lista abre en su principio y la fila elegida siempre se ve", async () => {
  const t = await armar([CHAT, HALLAZGOS], undefined, 24);
  try {
    const lista = ["HALLAZGOS · 40 candidatos", ...Array.from({ length: 40 }, (_, i) => `? ${String(i + 1).padStart(8, "0")}  candidato  alta        hallazgo ${i + 1}`), "Detalle: /findings <id>"];
    (t.client as { view: unknown }).view = async () => lista;
    t.state.input("\x1b2");
    await until(() => /hallazgo 1\b/.test(t.visible()));
    assert.match(t.visible(), /▌ .* \? 00000001/);
    for (let i = 0; i < 29; i++) t.state.input("\x1b[B");
    assert.match(t.visible(), /▌ .* \? 00000030/);
    for (let i = 0; i < 29; i++) t.state.input("\x1b[A");
    assert.match(t.visible(), /▌ .* \? 00000001/);
  } finally { t.daemon.close(); }
});

// ---------- Tanda final de arreglos ----------
const emit = (client: unknown, e: object) => (client as { emit(e: object): void }).emit(e);
const ACCIONES: Pestana = { nombre: "Acc", tipo: "conversacion", contenido: ["acciones"], detalle: "normal" };
const RESULT: Pestana = { nombre: "Res", tipo: "conversacion", contenido: ["resultados"], detalle: "completo" };
/** Cierra los menús de /config (el de pestañas, el de ajustes) con Esc: cada uno reabre el anterior en el siguiente turno. */
const cerrarConfig = async (t: Awaited<ReturnType<typeof armar>>) => { for (let i = 0; i < 3; i++) { t.state.input("\x1b"); await tick(40); } };
/** /config → Pestañas → editor de la primera pestaña (con `bajar` filas hacia abajo en la lista). */
const abrirEditor = async (t: Awaited<ReturnType<typeof armar>>, bajar = 0) => {
  t.state.input("/config\r");
  await until(() => /Configuración/.test(t.visible()));
  t.state.input("\x1b[B\r");
  await until(() => /Nueva pestaña/.test(t.visible()));
  for (let i = 0; i < bajar; i++) t.state.input("\x1b[B");
  t.state.input("\r");
  await until(() => /Detalle/.test(t.visible()));
};

test("I2: una acción en curso no se dibuja ni suma novedad hasta que termina, y entonces cuenta una sola vez", async () => {
  const t = await armar([CHAT, ACCIONES], undefined, 60);
  try {
    emit(t.client, { type: "tool_start", id: "a", name: "shell", label: "shell" });
    await until(() => /en curso|in progress/.test(t.visible())); // los eventos se juntan en un cuadro de 16 ms
    assert.doesNotMatch(t.visible(), /[✓·] shell/);
    assert.match(t.visible(), /en curso|in progress/);
    assert.doesNotMatch(t.filas()[0]!, /Acc  \d/);
    emit(t.client, { type: "tool_end", id: "a", name: "shell", isError: false, text: "", details: {} });
    await until(() => /✓ shell/.test(t.visible()));
    assert.match(t.visible(), /✓ shell/);
    assert.match(t.filas()[0]!, /Acc  1 /);
  } finally { t.daemon.close(); }
});

test("M8: un resultado sin hash ni texto no se dibuja ni suma novedad", async () => {
  const t = await armar([CHAT, RESULT], undefined, 60);
  try {
    emit(t.client, { type: "tool_start", id: "a", name: "shell", label: "shell" });
    emit(t.client, { type: "tool_end", id: "a", name: "shell", isError: false, text: "", details: {} });
    await tick(60); // los eventos se juntan en un cuadro de 16 ms
    assert.doesNotMatch(t.filas()[0]!, /Res  \d/);
    emit(t.client, { type: "tool_start", id: "b", name: "shell", label: "shell" });
    emit(t.client, { type: "tool_end", id: "b", name: "shell", isError: false, text: "", details: { artefacto: "sha256:uno" } });
    await until(() => /Res  1 /.test(t.filas()[0]!));
    assert.match(t.filas()[0]!, /Res  1 /);
  } finally { t.daemon.close(); }
});

test("I3: dos cycles seguidos de Detalle llegan a Mínimo, y marcar una casilla después conserva el Detalle nuevo", async () => {
  const t = await armar([CHAT], undefined, 60);
  try {
    await abrirEditor(t);
    t.state.input("\x1b[B".repeat(7)); // hasta «Detalle»
    t.state.input("\x1b[C");
    await until(() => /‹ Completo ›/.test(t.visible()));
    t.state.input("\x1b[C");
    await until(() => /‹ Mínimo ›/.test(t.visible()));
    t.state.input("\x1b[D"); // vuelve a Completo
    await until(() => /‹ Completo ›/.test(t.visible()));
    t.state.input("\x1b[A".repeat(6)); // «Mensajes»
    t.state.input("\r");
    await until(() => /Mensajes\s+\[ \]/.test(t.visible()));
    assert.match(t.visible(), /‹ Completo ›/);
    // M11: Espacio marca y desmarca como Enter.
    t.state.input(" ");
    await until(() => /Mensajes\s+\[x\]/.test(t.visible()));
    t.state.input(" ");
    await until(() => /Mensajes\s+\[ \]/.test(t.visible()));
    assert.match(t.visible(), /‹ Completo ›/);
  } finally { t.daemon.close(); }
});

test("I4: Alt+←/→ con una sola pestaña mueven el cursor por palabras", async () => {
  const t = await armar();
  try {
    t.state.input("uno dos tres");
    t.state.input("\x1b[1;3D");
    t.state.input("X");
    assert.match(t.visible(), /› uno dos Xtres/);
    t.state.input("\x1b[1;3C");
    t.state.input("Y");
    assert.match(t.visible(), /› uno dos XtresY/);
  } finally { t.daemon.close(); }
});

test("I5: «+ Nueva pestaña» con Enter vacío usa el nombre del tipo y Esc cancela", async () => {
  const t = await armar([CHAT], undefined, 60);
  try {
    t.state.input("/config\r");
    await until(() => /Configuración/.test(t.visible()));
    t.state.input("\x1b[B\r");
    await until(() => /Nueva pestaña/.test(t.visible()));
    t.state.input("\x1b[B\r");
    await until(() => /Tipo de pestaña/.test(t.visible()));
    t.state.input("\x1b[B\r"); // Hallazgos
    await until(() => /Nombre de la pestaña/.test(t.visible()));
    t.state.input("\x1b"); // Esc cancela
    await until(() => /Nueva pestaña/.test(t.visible()) && !/Nombre de la pestaña/.test(t.visible()));
    assert.doesNotMatch(t.filas()[0]!, /Hallazgos/);
    t.state.input("\r");
    await until(() => /Tipo de pestaña/.test(t.visible()));
    t.state.input("\x1b[B\r");
    await until(() => /Nombre de la pestaña/.test(t.visible()));
    t.state.input("\r"); // vacío: el del tipo
    await until(() => /Chat\s+Hallazgos/.test(t.filas()[0]!));
    assert.match(t.filas()[0]!, /Chat\s+Hallazgos/);
  } finally { t.daemon.close(); }
});

test("M1 y M2: reordenar sigue mostrando la misma pestaña y lo expandido queda expandido", async () => {
  const t = await armar([COMPLETO, PERU], undefined, 60);
  try {
    const cuerpo = Array.from({ length: 30 }, (_, i) => `fila ${i + 1}`);
    (t.client as { view: unknown }).view = async () => ["EVIDENCIA · x", ...cuerpo];
    herramienta(t.client, "a", "sha256:uno");
    await until(() => /fila 12/.test(t.visible()));
    t.state.input("\x1b[1;3A");
    t.state.input("\r");
    assert.match(t.visible(), /fila 30/);
    t.state.input("/config\r");
    await until(() => /Configuración/.test(t.visible()));
    t.state.input("\x1b[B\r");
    await until(() => /Nueva pestaña/.test(t.visible()));
    t.state.input("\x1b[C"); // «Chat» pasa al segundo lugar
    await until(() => /Perú[^\r]*\r\n[^\r]*Chat/.test(t.visible()));
    await cerrarConfig(t);
    assert.match(t.filas()[0]!, /Perú\s+Chat/);
    assert.match(t.visible(), /fila 30/);
  } finally { t.daemon.close(); }
});

test("M1: borrar la pestaña activa vuelve a la primera", async () => {
  const t = await armar([CHAT, PERU], undefined, 60);
  try {
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => /Buenas\./.test(t.visible()));
    t.state.input("\x1b2");
    assert.doesNotMatch(t.visible(), /hola/);
    await abrirEditor(t, 1);
    t.state.input("\x1b[F"); // última fila: «Borrar pestaña»
    t.state.input("\r");
    await until(() => /Borrar la pestaña/.test(t.visible()));
    t.state.input("1");
    await until(() => !/Borrar la pestaña/.test(t.visible()));
    await cerrarConfig(t);
    assert.match(t.visible(), /── Vos [^\r]*\r\n  hola/);
  } finally { t.daemon.close(); }
});

test("M3: al volver a una pestaña con el scroll arriba que recibió contenido, la vista queda anclada", async () => {
  const t = await armar([CHAT, PERU], undefined, 60);
  try {
    t.provider.faux!.queue = [{ text: parrafos }];
    t.state.input("largo\r");
    await until(() => /línea 40/.test(t.visible()));
    t.state.input("\x1b[1;5H");
    const antes = t.filas().slice(1, 20);
    assert.match(antes.join("\n"), /línea 1\b/);
    t.state.input("\x1b2");
    t.state.input("/costos\r");
    await until(() => /COSTO API ESTIMADO/.test(t.visible()));
    t.state.input("\x1b1");
    assert.deepEqual(t.filas().slice(1, 20), antes);
  } finally { t.daemon.close(); }
});

test("M4: Alt+↑ fuera de «completo con resultados» no selecciona, y con texto Enter envía", async () => {
  const t = await armar([CHAT], undefined, 60);
  try {
    herramienta(t.client, "a", "sha256:uno");
    t.state.input("\x1b[1;3A");
    assert.doesNotMatch(t.visible(), /Alt\+↑↓/);
  } finally { t.daemon.close(); }
  const c = await armar([COMPLETO], undefined, 60);
  try {
    (c.client as { view: unknown }).view = async () => ["EVIDENCIA · x", "fila 1"];
    herramienta(c.client, "a", "sha256:uno");
    await until(() => /fila 1/.test(c.visible()));
    c.state.input("hola");
    c.state.input("\x1b[1;3A");
    assert.match(c.visible(), /Alt\+↑↓/);
    c.provider.faux!.queue = [{ text: "Listo." }];
    c.state.input("\r");
    await until(() => /Listo\./.test(c.visible()));
    assert.match(c.visible(), /── Vos [^\r]*\r\n  hola/);
    assert.doesNotMatch(c.visible(), /Alt\+↑↓/);
  } finally { c.daemon.close(); }
});

test("M5: en una vista sin filas, ↑↓ con el editor vacío recorren de a una línea", async () => {
  const COSTOS: Pestana = { nombre: "Costos", tipo: "vista", vista: "costos" };
  const t = await armar([CHAT, COSTOS], undefined, 14);
  try {
    (t.client as { view: unknown }).view = async () => Array.from({ length: 40 }, (_, i) => `renglón ${i + 1}`);
    t.state.input("\x1b2");
    await until(() => /renglón 40/.test(t.visible()));
    t.state.input("\x1b[A\x1b[A"); // el borde de abajo y una línea más
    assert.doesNotMatch(t.visible(), /renglón 40\b/);
    assert.match(t.visible(), /renglón 39\b/);
    t.state.input("\x1b[B\x1b[B");
    assert.match(t.visible(), /renglón 40\b/);
  } finally { t.daemon.close(); }
});

test("M7: la línea de /help de las pestañas sale en el idioma elegido", async () => {
  const t = await armar([CHAT], undefined, 60);
  try {
    elegirIdioma("en");
    t.state.input("/help\r");
    await until(() => /Tab completes a command/.test(t.visible()));
    t.state.input("\x1b[1;5H");
    assert.match(t.visible(), /Ctrl\+N \/ Ctrl\+P switch tabs/);
  } finally { elegirIdioma("es"); t.daemon.close(); }
});

test("M9: con un solo PgUp y un resize mientras llega texto, la vista no salta al final", async () => {
  const t = await armar([CHAT], undefined, 24);
  try {
    t.provider.faux!.queue = [{ text: parrafos }];
    t.state.input("largo\r");
    await until(() => /línea 40/.test(t.visible()));
    t.state.input("\x1b[5~"); // un PgUp
    assert.doesNotMatch(t.visible(), /línea 40/);
    emit(t.client, { type: "text", delta: "\n\nNUEVO uno" });
    t.output.columns = 30;
    t.state.resize();
    emit(t.client, { type: "text", delta: " y más texto que llega" });
    emit(t.client, { type: "text", delta: " mientras se achica" });
    assert.doesNotMatch(t.visible(), /NUEVO/);
    assert.doesNotMatch(t.visible(), /línea 40/);
    assert.match(t.visible(), /línea \d+/);
    assert.match(t.visible(), /▼ \d+ (nuevas|new)/);
  } finally { t.daemon.close(); }
});

test("M12: con 60 columnas el pie del menú de pestañas no se corta", async () => {
  const t = await armar([CHAT, PERU], undefined, 30);
  try {
    t.output.columns = 60;
    t.state.resize();
    t.state.input("/config\r");
    await until(() => /Configuración/.test(t.visible()));
    t.state.input("\x1b[B\r");
    await until(() => /Nueva pestaña/.test(t.visible()));
    assert.match(t.visible(), /Esc cierra ─/);
    assert.doesNotMatch(t.visible(), /…/);
  } finally { t.daemon.close(); }
});

test("M13: una vista usa su título con mayúscula y, sin datos, un estado vacío; una pestaña filtrada vacía también", async () => {
  const H: Pestana = { nombre: "H", tipo: "vista", vista: "hallazgos" };
  const t = await armar([CHAT, H, PERU], undefined, 40);
  try {
    let datos: string[] = [];
    (t.client as { view: unknown }).view = async () => datos;
    t.state.input("\x1b2");
    await until(() => /Sin hallazgos todavía\./.test(t.visible()));
    assert.match(t.visible(), /─ Hallazgos ─/);
    datos = LISTA;
    emit(t.client, { type: "idle" });
    await until(() => /XSS en búsqueda/.test(t.visible()));
    assert.match(t.visible(), /─ Hallazgos ─/);
    emit(t.client, { type: "notice", text: "algo pasó" }); // ya hay contenido: no se ve el sello
    t.state.input("\x1b3");
    assert.match(t.visible(), /Nada para mostrar en esta pestaña todavía\./);
  } finally { t.daemon.close(); }
});

test("inicio: avanzar de paso no reescribe las filas del sello ni borra la pantalla", async () => {
  const t = await armar(undefined, undefined, 40, { onboarding: true });
  try {
    await until(() => /Paso 1 de 7/.test(t.visible()));
    await tick(200);
    const antes = t.state.written.length;
    t.state.input("\r");
    await until(() => /Paso 2 de 7/.test(t.visible()));
    t.state.input("\r");
    await until(() => /Paso 3 de 7/.test(t.visible()));
    await tick(300);
    const nuevo = t.state.written.slice(antes);
    assert.doesNotMatch(nuevo, /\x1b\[[23]J/);
    const sello = nuevo.split(/\x1b\[\d+;1H\x1b\[2K/).filter((fila) => /[⠀-⣿]/.test(fila)).length;
    assert.equal(sello, 0, "filas del sello reescritas");
  } finally { t.daemon.close(); }
});

test("sin Alt: Ctrl+PgUp/PgDn y Ctrl+N/P cambian de pestaña", async () => {
  const t = await armar([CHAT, PERU], undefined, 60);
  try {
    t.provider.faux!.queue = [{ text: "Buenas." }];
    t.state.input("hola\r");
    await until(() => /Buenas\./.test(t.visible()));
    for (const [tecla, hola] of [["\x1b[6;5~", false], ["\x1b[5;5~", true], ["\x0e", false], ["\x10", true], ["\x10", false]] as const) {
      t.state.input(tecla);
      assert.equal(/── Vos [^\r]*\r\n  hola/.test(t.visible()), hola, JSON.stringify(tecla));
    }
  } finally { t.daemon.close(); }
});

test("sin Alt: Shift+Tab y Tab eligen acción en «completo con resultados»", async () => {
  const t = await armar([COMPLETO], undefined, 60);
  try {
    herramienta(t.client, "a", "sha256:uno");
    herramienta(t.client, "b", "sha256:dos");
    await until(() => /shell/.test(t.visible()));
    t.state.input("\x1b[Z");
    assert.match(t.visible(), /Tab\/Shift\+Tab/);
    t.state.input("\x1b[Z\t");
    assert.match(t.visible(), /Tab\/Shift\+Tab/);
  } finally { t.daemon.close(); }
});

function espiar(t: { provider: { transport: (r: never) => Promise<never> } }) {
  const vistos: string[] = [];
  const orig = t.provider.transport;
  t.provider.transport = async (r: never) => { vistos.push(JSON.stringify((r as { messages: unknown }).messages)); return orig(r); };
  return vistos;
}

test("$ comando: muestra la salida, no habla con el agente y la pega al próximo mensaje", async () => {
  const t = await armar();
  try {
    const vistos = espiar(t as never);
    t.state.input("$ echo hola-$((1+1))\r");
    await until(() => /salió con 0/.test(t.visible()));
    assert.match(t.visible(), /hola-2/);
    assert.equal(vistos.length, 0);
    t.provider.faux!.queue = [{ text: "Visto." }];
    t.state.input("qué salió\r");
    await until(() => /Visto\./.test(t.visible()));
    assert.match(vistos.at(-1)!, /<terminal>/);
    assert.match(vistos.at(-1)!, /hola-2/);
    assert.doesNotMatch(t.visible(), /<terminal>/);
    // «$5 de tope» no es un comando: va al agente tal cual.
    t.provider.faux!.queue = [{ text: "Tope." }];
    t.state.input("$5 de tope\r");
    await until(() => /Tope\./.test(t.visible()));
    const ultimo = (JSON.parse(vistos.at(-1)!) as { content: string }[]).at(-1)!.content;
    assert.equal(ultimo, "$5 de tope");
  } finally { t.daemon.close(); }
});

test("$ comando: Ctrl+C lo corta sin salir de la TUI", async () => {
  const t = await armar();
  try {
    t.state.input("$ sleep 30\r");
    await tick(200);
    t.state.input("\x03");
    await until(() => /cortado/.test(t.visible()));
    assert.match(t.visible(), /cortado/);
    assert.equal(t.state.exited, false);
  } finally { t.daemon.close(); }
});

test("$ comando: durante un turno corre al instante y no se encola", async () => {
  const t = await armar();
  let release!: () => void;
  try {
    const gate = new Promise<void>((resolve) => (release = resolve));
    const host = [...t.daemon.hosts.values()][0]!;
    host.engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
    t.provider.faux!.queue = [{ text: "Empiezo.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Listo." }];
    t.state.input("trabajá\r");
    await until(() => host.engine.agent.running && /Esperar/.test(t.visible()));
    assert.equal(host.engine.agent.running, true);
    t.state.input("$ echo y$((1+1))a\r");
    await until(() => /salió con 0/.test(t.visible()));
    assert.equal(host.engine.agent.running, true);
    assert.match(t.visible(), /y2a/);
    assert.doesNotMatch(t.visible(), /en cola/);
  } finally { release?.(); await tick(50); t.daemon.close(); }
});

test("$ comando: al reabrir la sesión el mensaje se ve sin el bloque <terminal>", () => {
  const r = Registro.desdeSnapshot([{ role: "user", content: "qué salió\n\n<terminal>\n$ ls\nx\n[código 0]\n</terminal>" } as never]);
  assert.deepEqual(r.entradas().map((e) => e.tipo === "mensajes" && e.texto), ["qué salió"]);
});

test("$ comando: al salir de la TUI el comando en curso se corta", async () => {
  const t = await armar();
  // Sin pgrep en la imagen: se mira /proc. «sleep 31.7» como argumento del shell y como proceso propio.
  const vivo = () => readdirSync("/proc").some((p) => /^\d+$/.test(p) && p !== String(process.pid) && (() => { try { return readFileSync(`/proc/${p}/cmdline`, "utf8").includes("31.7"); } catch { return false; } })());
  try {
    t.state.input("$ sleep 31.7\r");
    await until(vivo);
    assert.equal(vivo(), true);
    t.state.input("\x04");
    assert.equal(t.state.exited, true);
    await until(() => !vivo());
    assert.equal(vivo(), false);
  } finally { t.daemon.close(); }
});

test("$ comando: una salida enorme no tira la TUI y al agente le llegan solo los últimos 16 KB", async () => {
  const t = await armar();
  try {
    const vistos = espiar(t as never);
    t.state.input("$ seq 1 300000\r");
    await until(() => /salió con 0/.test(t.visible()), 60_000);
    assert.match(t.visible(), /salió con 0/);
    assert.equal(t.state.exited, false);
    t.provider.faux!.queue = [{ text: "Visto." }];
    t.state.input("qué salió\r");
    await until(() => /Visto\./.test(t.visible()));
    const ultimo = (JSON.parse(vistos.at(-1)!) as { content: string }[]).at(-1)!.content;
    assert.ok(ultimo.length < 16 * 1024 + 600, String(ultimo.length));
    assert.match(ultimo, /300000/); assert.match(ultimo, /recortada/);
  } finally { t.daemon.close(); }
});

test("$ comando: la salida de una sesión no viaja a otra", async () => {
  const t = await armar();
  try {
    const vistos = espiar(t as never);
    t.state.input("$ echo secreto-de-$((1+1))\r");
    await until(() => /salió con 0/.test(t.visible()));
    t.state.input("/sesiones nueva\r");
    await tick(300);
    t.provider.faux!.queue = [{ text: "Hola B." }];
    t.state.input("hola B\r");
    await until(() => /Hola B\./.test(t.visible()));
    assert.ok(vistos.length > 0);
    assert.doesNotMatch(vistos.join(""), /secreto-de-2/);
  } finally { t.daemon.close(); }
});

test("$ comando: no se cambia de sesión con un comando corriendo", async () => {
  const t = await armar();
  try {
    t.state.input("$ sleep 31.9\r");
    await tick(200);
    t.state.input("/sesiones nueva\r");
    await until(() => /Esperá a que termine|Wait for the/.test(t.visible()));
    assert.match(t.visible(), /Esperá a que termine|Wait for the/);
    t.state.input("\x03");
    await until(() => /cortado/.test(t.visible()));
  } finally { t.daemon.close(); }
});

test("$ comando: «¿cómo vamos?» durante un turno sale sin el bloque, no queda en cola, y el bloque espera", async () => {
  const t = await armar();
  let release!: () => void;
  try {
    const gate = new Promise<void>((resolve) => (release = resolve));
    const host = [...t.daemon.hosts.values()][0]!;
    host.engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
    t.provider.faux!.queue = [{ text: "Empiezo.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Listo." }];
    t.state.input("trabajá\r");
    await until(() => host.engine.agent.running && /Esperar/.test(t.visible()));
    t.state.input("$ echo ya\r");
    await until(() => /salió con 0/.test(t.visible()));
    t.state.input("¿cómo vamos?\r");
    await tick(300);
    assert.equal(host.engine.queue.length, 0);
  } finally { release?.(); await tick(50); t.daemon.close(); }
});

test("temas: el editor usa el cursor del tema", async () => {
  const t = await armar(); // arrancar aplica el tema guardado: se elige después
  try {
    usarTema("ambar");
    t.state.resize();
    assert.ok(t.filas().some((l) => l.startsWith("  che@orobas:~$ ")), t.visible());
    t.output.columns = 40;
    t.state.resize();
    assert.ok(t.filas().some((l) => l.startsWith("  > ")), t.visible());
    usarTema("orobas"); // Orobas (cursor de una columna) no cae a «>» ni en 40 columnas
    t.state.resize();
    assert.ok(t.filas().some((l) => l.startsWith("  › ")), t.visible());
  } finally { usarTema("orobas"); t.daemon.close(); }
});

test("pestañas: en 40 columnas con ámbar nada se pasa del ancho", async () => {
  const t = await armar([CHAT, PERU, { ...PERU, nombre: "Hallazgos" }], undefined, 40);
  // Se mide el cuadro que foco le pasa a Pantalla, antes de que ella corte las líneas.
  const original = Pantalla.prototype.dibujar;
  const cuadros: string[][] = [];
  Pantalla.prototype.dibujar = function (cuadro) { cuadros.push(cuadro.lineas); return original.call(this, cuadro); };
  try {
    usarTema("ambar");
    t.output.columns = 40;
    t.state.input("/costos\r");
    await until(() => /COSTO API ESTIMADO/.test(t.visible()));
    assert.match(t.filas()[0]!, /Perú  \d /);
    assert.match(t.filas()[1]!, /━/);
    const ultimo = cuadros[cuadros.length - 1]!;
    assert.ok(ultimo.length > 2);
    for (const linea of ultimo) assert.ok(visibleWidth(linea) <= 40, `${visibleWidth(linea)}: ${linea}`);
  } finally { Pantalla.prototype.dibujar = original; usarTema("orobas"); t.daemon.close(); }
});

test("limpiar durante el descifrado apaga el temporizador de redibujo", async () => {
  const t = await armar();
  const vivos = new Set<unknown>();
  const { setInterval: si, clearInterval: ci } = globalThis;
  globalThis.setInterval = ((f: () => void, ms?: number, ...a: unknown[]) => { const h = si(f, ms, ...a); if (ms === 33) vivos.add(h); return h; }) as typeof setInterval;
  globalThis.clearInterval = ((h: never) => { vivos.delete(h); return ci(h); }) as typeof clearInterval;
  try {
    usarTema("hacker");
    t.provider.faux!.queue = [{ text: "Respuesta bastante larga para que el efecto dure un rato." }];
    t.state.input("hola\r");
    await until(() => vivos.size > 0);
    assert.equal(vivos.size, 1, "el efecto arrancó");
    t.state.input("/limpiar\r");
    await until(() => vivos.size === 0, 400);
    assert.equal(vivos.size, 0, "el temporizador sigue vivo tras limpiar");
  } finally { globalThis.setInterval = si; globalThis.clearInterval = ci; for (const h of vivos) ci(h as never); usarTema("orobas"); await tick(50); t.daemon.close(); }
});

test("conhost: el spinner del turno usa cuadros ASCII", async () => {
  const prev = process.env.CYBER_CONSOLE;
  process.env.CYBER_CONSOLE = "conhost";
  const t = await armar();
  try {
    const normal = t.provider.transport;
    let soltar = () => {};
    const puerta = new Promise<void>((r) => (soltar = r));
    t.provider.transport = async (req) => (await puerta, normal(req));
    t.provider.faux!.queue = [{ text: "Listo." }];
    t.state.input("hola\r");
    await until(() => /trabajando|· \d+ s/.test(t.visible()));
    assert.match(t.visible(), /[|\/\\-] (trabajando|working)/);
    assert.doesNotMatch(t.visible(), /[\u2800-\u28ff]/);
    soltar();
  } finally { if (prev === undefined) delete process.env.CYBER_CONSOLE; else process.env.CYBER_CONSOLE = prev; await tick(50); t.daemon.close(); }
});

test("trabajando: tiempo del turno y gasto", async () => {
  const t = await armar();
  try {
    const normal = t.provider.transport;
    let soltar = () => {};
    const puerta = new Promise<void>((r) => (soltar = r));
    t.provider.transport = async (req) => (await puerta, normal(req));
    t.provider.faux!.queue = [{ text: "Listo." }];
    t.state.input("hola\r");
    await until(() => /· \d+ s/.test(t.visible()));
    assert.match(t.visible(), /· \d+ s/);
    assert.doesNotMatch(t.visible(), /USD \d+\.\d+ este turno/);
    t.client.status.cost = "API est. USD 5.00 / sin tope";
    await until(() => /este turno/.test(t.visible()));
    assert.match(t.visible(), /· USD 5\.00 este turno/);
    soltar();
    await until(() => !/este turno/.test(t.visible()));
    assert.doesNotMatch(t.visible(), /este turno/);
  } finally { t.daemon.close(); }
});

test("trabajando: con una herramienta en curso su etiqueta no se repite en la línea del turno", async () => {
  const t = await armar();
  let release!: () => void;
  try {
    const gate = new Promise<void>((resolve) => (release = resolve));
    const host = [...t.daemon.hosts.values()][0]!;
    host.engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
    t.provider.faux!.queue = [{ text: "Empiezo.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Listo." }];
    t.state.input("trabajá\r");
    await until(() => /en curso/.test(t.visible()) && /trabajando · \d+ s/.test(t.visible()));
    assert.match(t.visible(), /trabajando · \d+ s/);
    assert.equal(t.filas().filter((l) => l.includes("Esperar")).length, 1, t.visible());
  } finally { release?.(); await tick(50); t.daemon.close(); }
});

test("modo compartido: Ctrl+D con un turno en curso avisa antes de salir; sin la variable sale directo", async () => {
  const antes = process.env.CYBER_COMPARTIDO;
  try {
    process.env.CYBER_COMPARTIDO = "1";
    const t = await armar();
    try {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const host = [...t.daemon.hosts.values()][0]!;
      host.engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
      t.provider.faux!.queue = [{ text: "Arranco.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Listo." }];
      t.client.send("Trabajá");
      await until(() => t.client.status.running);
      t.state.input("\x04");
      await until(() => /El agente sigue trabajando/.test(t.visible()));
      assert.match(t.visible(), /El agente sigue trabajando/);
      assert.equal(t.state.exited, false);
      t.state.input("\x1b[A"); await tick(40); t.state.input("\r"); // «sí» (arranca en «cancelar»)
      await until(() => t.state.exited);
      assert.ok(t.state.exited);
      release();
    } finally { t.daemon.close(); }
    delete process.env.CYBER_COMPARTIDO;
    const u = await armar();
    try {
      u.state.input("\x04");
      await until(() => u.state.exited);
      assert.ok(u.state.exited);
    } finally { u.daemon.close(); }
  } finally {
    if (antes === undefined) delete process.env.CYBER_COMPARTIDO; else process.env.CYBER_COMPARTIDO = antes;
  }
});
