import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { Client, ClientEvent } from "../src/client.ts";
import type { Snapshot } from "../src/daemon.ts";
import { startFoco } from "../src/tui/foco.ts";
import { ImageReplies, type ImageTerminal, KittyImages } from "../src/tui/kitty.ts";
import { Sigil } from "../src/tui/sigil.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

function session(options: { animate?: boolean; resumed?: boolean } = {}) {
  const status = { running: false, interrupted: false, usage: "uso 0 tokens", cost: "USD 0 / USD 2", notes: 0, needsKey: false };
  const snapshot: Snapshot = {
    sessionId: "test-sigil", project: "prueba local", model: "faux", resumed: !!options.resumed,
    projectRequests: 0, messages: [], partial: "", tools: {}, status,
  };
  if (options.resumed) snapshot.messages = [{ role: "user", content: "Mensaje guardado" } as Snapshot["messages"][number]];
  let events: (event: ClientEvent) => void = () => {};
  let input = (_: string) => {};
  let output = "";
  let all = "";
  let exited = false;
  const sent: string[] = [];
  const client = {
    status,
    on: (listener: typeof events) => { events = listener; },
    send: (text: string) => { sent.push(text); },
    view: async () => ["DETALLE DE PRUEBA"],
  } as unknown as Client;
  const terminal = { graphics: true, cellWidth: 10, cellHeight: 22 };
  const size = { columns: 100, rows: 32 };
  let resize = () => {};
  const app = startFoco(client, snapshot, {
    animate: options.animate,
    onExit: () => { exited = true; },
    io: {
      terminal,
      output: { write: (data) => { output += data; all += data; }, get columns() { return size.columns; }, get rows() { return size.rows; } },
      listen: (onData, onResize) => { input = onData; resize = onResize; return () => {}; },
    },
  });
  return {
    app, status, sent, size, terminal, resize,
    get exited() { return exited; },
    input: (data: string) => input(data),
    event: (event: ClientEvent) => events(event),
    visible: () => pantallaVisible(all, size.columns, size.rows),
    take: () => { const result = output; output = ""; return result; },
  };
}

test("sello: escribir lo conserva; enviar lo retira; limpiar lo recupera sin repetir el arranque", () => {
  const s = session();
  try {
    assert.match(s.take(), /\x1b_Ga=p,/);
    s.input("hola");
    assert.doesNotMatch(s.take(), /\x1b_Ga=[pd],/); // el sello sigue en su lugar: solo se repinta la fila del editor
    s.input("\r");
    const submitted = s.take();
    assert.deepEqual(s.sent, ["hola"]);
    assert.match(submitted, /\x1b_Ga=d,d=i,/);
    assert.doesNotMatch(submitted, /\x1b_Ga=p,/);
    s.input("/clear\r");
    const cleared = s.take();
    assert.match(cleared, /\x1b_Ga=p,/);
    assert.match(cleared, /OROBAS/);
    assert.deepEqual(s.sent, ["hola"], "limpiar sólo cambia la vista, no manda un prompt ni borra la sesión");
  } finally { s.app.exit(); }
});

test("sello: no se superpone al historial retomado, ni se limpia un turno en curso", () => {
  const s = session({ resumed: true });
  try {
    assert.match(s.take(), /Mensaje guardado/);
    s.input("x");
    assert.doesNotMatch(s.take(), /\x1b_Ga=p,/);
    s.status.running = true;
    s.input("\x0c");
    const busy = s.take();
    assert.doesNotMatch(busy, /\x1b\[2J/);
    assert.match(busy, /Detené el turno/);
    s.status.running = false;
    s.input("\x0c");
    assert.match(s.take(), /\x1b_Ga=p,/);
  } finally { s.app.exit(); }
});

test("arranque: respeta los 12 cuadros y al terminar habilita el chat con el sello final", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const s = session({ animate: true });
  try {
    const first = s.take();
    assert.match(first, /\x1b_Ga=p,/);
    assert.doesNotMatch(first, /¿Qué querés investigar/);
    const delays = [120, 120, 120, 120, 120, 120, 120, 120, 120, 220, 220, 1020];
    for (const delay of delays) t.mock.timers.tick(delay);
    const final = s.take();
    assert.match(final, /¿Qué querés investigar/);
    assert.match(final, /\x1b_Ga=p,/);
    s.input("\x0c");
    s.take();
    t.mock.timers.tick(5000);
    assert.equal(s.take(), "", "limpiar no vuelve a iniciar temporizadores del arranque");
  } finally { s.app.exit(); }
});

test("arranque: se puede salir o escribir de inmediato y no quedan temporizadores activos", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const s = session({ animate: true });
  s.take();
  s.input("primer mensaje\r");
  assert.deepEqual(s.sent, ["primer mensaje"]);
  const frame = s.take();
  assert.match(frame, /¿Qué querés investigar/);
  assert.doesNotMatch(frame, /\x1b_Ga=p,/);
  assert.match(frame, /\x1b_Ga=d,d=I,/, "al saltar el arranque libera las imágenes cargadas");
  s.app.exit();
  assert.match(s.take(), /\x1b\[\?25h\x1b\[0m$/);
  t.mock.timers.tick(5000);
  assert.equal(s.take(), "");
  const earlyExit = session({ animate: true });
  earlyExit.take();
  earlyExit.app.exit();
  assert.match(earlyExit.take(), /\x1b_Ga=d,d=I,/);
  t.mock.timers.tick(5000);
  assert.equal(earlyExit.take(), "");
});

test("imagen: el ajuste conserva la proporción en píxeles y entra en el área disponible", () => {
  const sigil = new Sigil(false);
  for (const [width, height] of [[128, 15], [80, 12], [40, 8], [20, 6]]) {
    const terminal = { graphics: true, cellWidth: 10, cellHeight: 22 };
    const view = sigil.view(width!, height!, terminal);
    const image = view.image!;
    assert.ok(image);
    assert.ok(view.lines.length <= height!);
    assert.ok(image.col >= 0 && image.col + image.columns <= width!);
    assert.ok(image.rows <= height! - 1);
    // A lo sumo una fila de redondeo, sin estirar el PNG para llenar el rectángulo.
    const naturalHeight = image.columns * 10 * 700 / 820;
    assert.ok(image.rows * 22 >= naturalHeight && image.rows * 22 - naturalHeight < 22);
  }
});

test("sello: resize y falta de soporte retiran el PNG sin enviar escapes al editor", () => {
  const s = session();
  try {
    s.take();
    s.size.columns = 40;
    s.size.rows = 18;
    s.resize();
    const smaller = s.take();
    assert.match(smaller, /\x1b_Ga=d,d=[iI],/);
    assert.match(smaller, /\x1b\[2J/, "el resize del chat vacío limpia también imágenes recortadas");
    assert.match(smaller, /\x1b_Ga=p,/);
    s.terminal.graphics = false;
    s.resize();
    const fallback = s.take();
    assert.doesNotMatch(fallback, /\x1b_Ga=p,/);
    assert.match(fallback, /OROBAS/);
  } finally { s.app.exit(); }
});

test("Kitty: cuadros PNG en trozos, sin retransmitir cada vez que se escribe, y limpieza por ID propio", () => {
  const transport = new KittyImages();
  const png = readFileSync(new URL("../src/tui/assets/orobas/frames-transparentes/011.png", import.meta.url));
  const image = { key: "final", png, row: 0, col: 0, columns: 30, rows: 12 };
  const commands = transport.place(image);
  const chunks = [...commands.matchAll(/\x1b_G([^;]*);([^\x1b]*)\x1b\\/g)];
  assert.ok(chunks.length > 1);
  assert.ok(chunks.every((match) => match[2]!.length <= 4096));
  assert.deepEqual(Buffer.from(chunks.map((match) => match[2]).join(""), "base64"), png);
  assert.doesNotMatch(commands, /,r=\d+/, "la terminal calcula la altura sin estirar el sello");
  assert.doesNotMatch(transport.place(image), /a=t,/);
  assert.match(transport.hide(), /a=d,d=i,i=\d+/);
  assert.match(transport.close(), /a=d,d=I,i=\d+/);
  assert.equal(transport.close(), "");
});

test("respuestas de terminal: fragmentos de geometría y de Kitty nunca se insertan en el prompt", () => {
  const replies = new ImageReplies();
  const terminal: ImageTerminal = { graphics: false, cellWidth: 10, cellHeight: 20 };
  assert.equal(replies.consume("hola\x1b[6;22;", terminal).input, "hola");
  const size = replies.consume("10tmundo", terminal);
  assert.equal(size.input, "mundo");
  assert.equal(size.changed, true);
  assert.equal(terminal.cellHeight, 22);
  assert.equal(replies.consume(`\x1b_Gi=${replies.queryId};O`, terminal).input, "");
  assert.equal(replies.consume("K\x1b\\!", terminal).input, "!");
  assert.equal(terminal.graphics, true);
  assert.equal(replies.consume("\x1b", terminal).input, "");
  assert.equal(replies.flush(), "\x1b", "Escape se entrega al vencer la breve espera de una secuencia partida");
});

test("chat vacío: limpia el shell al entrar, elimina el encabezado y aprovecha la altura para el sello", () => {
  const s = session();
  try {
    const output = s.take();
    assert.ok(output.indexOf("\x1b[2J") < output.indexOf("\x1b_Ga=t,"));
    assert.doesNotMatch(output, /ELEVATE AI \/ CYBER|prueba local|notas de memoria|sesión nueva|solicitudes en el proyecto/);
    const rows = s.visible();
    assert.equal(rows.length, s.size.rows);
    assert.equal(rows.findIndex((line) => line.includes("¿Qué querés investigar")), s.size.rows - 3);
    const columns = Number(/a=p,[^\x1b]*,c=(\d+)/.exec(output)?.[1]);
    assert.ok(columns >= 50, "al quitar el encabezado el PNG usa el espacio recuperado");
  } finally { s.app.exit(); }
});

test("editor al fondo: / abre sugerencias debajo y sube la entrada, cerrar recupera su posición", () => {
  const s = session();
  try {
    s.take();
    s.input("/");
    s.take();
    const menu = s.visible();
    const editor = menu.findIndex((line) => line.includes("› /"));
    const first = menu.findIndex((line) => line.includes("/sesiones"));
    assert.equal(menu.length, s.size.rows);
    assert.equal(editor, s.size.rows - 10);
    assert.ok(first > editor, "las opciones ocupan el espacio debajo del editor");
    assert.ok(!menu.some((line) => line.includes("Enter enviar")), "la lista tapa el pie");
    s.input("\x7f");
    s.take();
    assert.equal(s.visible().findIndex((line) => line.includes("¿Qué querés investigar")), s.size.rows - 3);
    s.input("hola\r");
    s.take();
    assert.equal(s.visible().findIndex((line) => line.includes("¿Qué querés investigar")), s.size.rows - 3);
  } finally { s.app.exit(); }
});

test("entrada: un cierre de pegado partido no bloquea enviar ni salir; un pegado incompleto se puede cancelar", () => {
  const s = session();
  try {
    s.input("\x1b[200~hola\x1b");
    s.input("[201~\r");
    assert.deepEqual(s.sent, ["hola"]);
    s.input("\x1b[200~pegado sin cerrar\x1b[20");
    s.input("\x03\x03");
    assert.equal(s.exited, true);
  } finally { s.app.exit(); }
});

test("askHidden: muestra • por grafema, no deja rastro en frames ni historial; Esc y vacío dan undefined", async () => {
  const s = session();
  try {
    s.take();
    const ask = s.app.askHidden("Clave");
    s.input("  oro_secreto ");
    const out = s.take();
    assert.ok(!out.includes("oro_secreto"));
    assert.ok(out.includes("•"));
    s.input("\r");
    assert.equal(await ask, "oro_secreto");
    s.take();
    s.input("\x1b[A");
    assert.ok(!s.take().includes("oro_secreto"), "↑ no recupera el valor");
    const esc = s.app.askHidden("Clave");
    s.input("oro\x1b");
    assert.equal(await esc, undefined);
    assert.ok(!s.take().includes("oro"));
    const empty = s.app.askHidden("Clave");
    s.input("\r");
    assert.equal(await empty, undefined);
    const accents = s.app.askHidden("Clave");
    s.input("a👍🏽é");
    assert.equal((s.take(), s.visible()).find((line) => line.includes("Clave ›"))?.trim(), "Clave › •••");
    s.input("\x1b");
    await accents;
  } finally { s.app.exit(); }
});

test("pick: ↓ y Enter eligen, Esc cancela", async () => {
  const s = session();
  try {
    const choice = s.app.pick("HackerOne", ["Actualizar", "Revocar"]);
    assert.ok((s.take(), s.visible()).some((line) => line.includes("HackerOne · 1/2")));
    s.input("\x1b[B\r");
    assert.equal(await choice, 1);
    const cancel = s.app.pick("HackerOne", ["Actualizar"]);
    s.input("\x1b");
    assert.equal(await cancel, undefined);
  } finally { s.app.exit(); }
});

test("askHidden: desconexión, Ctrl+C, pegado y un segundo pedido no dejan promesas colgadas ni el secreto", async () => {
  const SECRETO = "zeta_9471_llave";
  const s = session();
  try {
    s.take();
    const lost = s.app.askHidden("Clave");
    s.input(SECRETO);
    s.event({ type: "disconnected" } as ClientEvent);
    assert.equal(await lost, undefined);
    assert.ok(!s.take().includes(SECRETO));

    const second = s.app.askHidden("Clave");
    s.input(SECRETO);
    s.input("\x03");
    assert.equal(await second, undefined);
  } finally { s.app.exit(); }
  const t2 = session();
  try {
    t2.take();
    const pasted = t2.app.askHidden("Clave");
    t2.input(`\x1b[200~${SECRETO}\x1b[201~`);
    const out = t2.take();
    assert.ok(!out.includes(SECRETO) && out.includes("•"));
    assert.deepEqual(t2.sent, []);
    const replaced = t2.app.pick("Menú", ["a"]);
    assert.equal(await pasted, undefined);
    t2.input("\r");
    assert.equal(await replaced, 0);
    assert.ok(!t2.take().includes(SECRETO));
  } finally { t2.app.exit(); }
});
