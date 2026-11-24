import "./datos-tmp.ts";
// /investigar en la TUI y el daemon: comando oculto como /cola (se alcanza escribiéndolo), panel de estado,
// confirmación para cerrar y el indicador del pie mientras la investigación corre, también en 80 columnas.
import assert from "node:assert/strict";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { findCommand, sugerencias, VISIBLES } from "../src/tui/comandos.ts";
import { startFoco } from "../src/tui/foco.ts";
import { visibleWidth } from "../src/tui/text.ts";
import { fakeIO } from "./fake-io.ts";
import { herramientasCaja, MundoInv, repo, TARIFAS } from "./investigar-falso.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

process.env.LC_ALL = "es_AR.UTF-8";
const until = async (done: () => boolean, ms = 8000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.ok(done(), "no llegó a tiempo");
};

test("/investigar: oculto como /cola, aparece al escribirlo; estado, abrir y cerrar con confirmación", async () => {
  const auto = fakeIO({ investigation_auto: ["Investigación automática: apagada."] });
  await findCommand("investigacion-auto")!.run(auto.io, "si");
  assert.deepEqual(auto.calls, [{ op: "investigation_auto", payload: { value: "si" } }]);
  const command = findCommand("investigar")!;
  assert.ok(command.hidden && !command.parent);
  assert.equal(findCommand("investigacion")!.name, "investigar");
  assert.equal(VISIBLES.length, 18, "la lista de / no cambia"); // 18 con /streamer (#35)
  assert.ok(!VISIBLES.includes("investigar"));
  assert.ok(!sugerencias("").some((item) => item.word === "investigar"));
  assert.ok(sugerencias("inv").some((item) => item.word === "investigar"));

  const estado = fakeIO({ investigar: ["INVESTIGACIÓN", "Objetivo    libparse", "Uso: /investigar <objetivo> [usd] · estado · pausa · seguir [usd] · cerrar"] });
  const panel = await command.run(estado.io, "");
  assert.deepEqual(estado.calls, [{ op: "investigar", payload: {} }]);
  assert.equal(panel!.title, "INVESTIGACIÓN");
  assert.match(panel!.footer!, /Uso: \/investigar <objetivo> \[usd\]/);

  const abrir = fakeIO({});
  await command.run(abrir.io, "libparse: parser de cabeceras 5");
  assert.deepEqual(abrir.calls, [{ op: "investigar", payload: { value: "libparse: parser de cabeceras 5" } }]);

  const arrepentido = fakeIO({}, [1]);
  assert.equal(await command.run(arrepentido.io, "cerrar"), null);
  assert.deepEqual(arrepentido.calls, [], "sin confirmar no se cierra");
  assert.match(arrepentido.confirms[0]!, /¿Cerrar la investigación\?/);
  const cierra = fakeIO({}, [0]);
  await command.run(cierra.io, "cerrar");
  assert.deepEqual(cierra.calls, [{ op: "investigar", payload: { value: "cerrar" } }]);
});

test("daemon y pie: /investigar abre la investigación, el pie dice estado, hipótesis y gasto mientras corre (en 80 columnas) y desaparece al cerrarla", async () => {
  const cwd = repo();
  const mundo = new MundoInv();
  let soltar!: () => void;
  const suelta = new Promise<void>((resolve) => (soltar = resolve));
  mundo.frenar = (worker) => (/:harness-1:h1:/.test(worker) ? suelta : undefined);
  const glm = mundo.proveedor("glm", TARIFAS.glm);
  const daemon = new Daemon({ cwd, resolve: () => glm, engine: { strong: mundo.proveedor("ultra", TARIFAS.ultra), resolve: () => mundo.proveedor("kimi", TARIFAS.kimi), autoVerify: false, cveFeed: false } });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    const snapshot = await client.attach({ session: "new" });
    const engine = [...daemon.hosts.values()][0]!.engine;
    engine.catalog.register(herramientasCaja().tools);
    assert.match((await client.ask("investigation_auto", {}))[0]!, /apagada/);
    assert.match((await client.ask("investigation_auto", { value: "si" }))[0]!, /activa/);
    assert.equal(engine.investigationAuto, true);
    assert.match(engine.agent.system, /Investigación automática: activa/);
    await client.ask("investigation_auto", { value: "no" });
    assert.match((await client.ask("investigar", {})).join("\n"), /No hay investigaciones en este proyecto/);

    const screen = { written: "" };
    const foco = startFoco(client, snapshot, { io: { output: { write: (data) => void (screen.written += data), columns: 80, rows: 30 }, listen: () => () => {} }, onExit: () => client.close() });
    const rows = () => pantallaVisible(screen.written, 80, 30);
    const pie = () => rows().filter((row) => /OROBAS|EN CURSO/.test(row)).at(-1) ?? "";
    await until(() => /OROBAS/.test(pie()));
    assert.doesNotMatch(pie(), /inv:/);

    const abierta = await client.ask("investigar", { value: "libparse 5" });
    assert.match(abierta[0]!, /^Investigación [0-9a-f]{8} abierta: «libparse», tope USD 5,00\./);
    await until(() => /^inv: harness-1 · h1\/3 · USD \d+,\d\d$/.test(client.status.investigacion?.label ?? ""));
    assert.equal(client.status.investigacion!.activa, true);
    await until(() => /inv: harness-1 · h1\/3 · USD \d+,\d\d/.test(pie()));
    assert.ok(visibleWidth(pie()) <= 80);

    foco.submit("/investigar estado");
    await until(() => rows().some((row) => row.includes("Por estado")));
    const visible = rows().join("\n");
    assert.match(visible, /INVESTIGACIÓN/);
    assert.match(visible, /harness-1 \(función\) · h1 · corriendo/);
    assert.ok(rows().every((row) => visibleWidth(row) <= 80));

    await client.ask("investigar", { value: "pausa" });
    soltar();
    await until(() => /^inv: pausada · harness-1 · h1\/3/.test(client.status.investigacion?.label ?? "") && !client.status.investigacion?.activa);
    assert.match((await client.ask("investigar", { value: "cerrar" })).join("\n"), /Cerré la investigación/);
    await until(() => !client.status.investigacion);
    await until(() => !/inv:/.test(pie()));
    foco.exit();
  } finally {
    soltar();
    daemon.close();
  }
});
