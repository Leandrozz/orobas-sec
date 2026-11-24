import "./datos-tmp.ts";
// El router en la TUI y el daemon: /router como /razonamiento (menú, auto, fijo, estado, modelo medio), su
// fila en /config, el indicador del pie (sin avisos en el chat) y el panel de estado legible en 80 columnas.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import type { LlmRequest } from "../src/llm.ts";
import { estadoLineas, ANCHO_ESTADO } from "../src/router.ts";
import { RECORDADOS } from "../src/tui/ajustes.ts";
import { findCommand, hijos } from "../src/tui/comandos.ts";
import { startFoco } from "../src/tui/foco.ts";
import { visibleWidth } from "../src/tui/text.ts";
import { fakeIO } from "./fake-io.ts";
import { pantallaVisible } from "./pantalla-visible.ts";
import { MundoFalso, simular, sondeo, TARIFAS } from "./router-falso.ts";

process.env.LC_ALL = "es_AR.UTF-8";
const tmp = () => mkdtempSync(join(tmpdir(), "cyber-router-tui-"));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await new Promise((resolve) => setTimeout(resolve, 5));
  assert.ok(done(), "no llegó a tiempo");
};

const ESTADO = ["ROUTER", "Modo        auto · bucle con el ejecutor; el fuerte, sobre traspasos", "Uso: /router auto | fijo | estado · /router medio <modelo> | no"];

test("/router: sin argumento, un menú como /razonamiento con el vigente marcado; estado, modo y modelo medio; vive en /modelo y en /config", async () => {
  const menu = fakeIO({ router: ESTADO }, [1]);
  const chosen = findCommand("router")!;
  assert.equal(chosen.parent, "modelo");
  assert.ok(hijos("modelo").some((command) => command.name === "router"));
  assert.equal(findCommand("ruteo")!.name, "router");
  const panel = await chosen.run(menu.io, "");
  assert.deepEqual(menu.picked[0]!.labels, ["auto", "fijo", "estado", "modelo medio…"]);
  assert.equal(menu.picked[0]!.at, 0);
  assert.match(menu.picked[0]!.hints[0]!, /el ejecutor trabaja; el fuerte decide sobre un traspaso · Actual$/);
  assert.doesNotMatch(menu.picked[0]!.hints[1]!, /Actual/);
  assert.deepEqual(menu.calls.at(-1), { op: "router", payload: { value: "fijo" } });
  assert.equal(panel?.tone, "ok");
  // «estado» muestra el panel sin cambiar nada; Esc no toca nada.
  const status = fakeIO({ router: ESTADO }, [2]);
  const shown = await chosen.run(status.io, "");
  assert.deepEqual(status.calls, [{ op: "router", payload: {} }]);
  assert.equal(shown?.title, "ROUTER");
  assert.match(shown!.footer!, /Uso: \/router auto \| fijo \| estado/);
  const esc = fakeIO({ router: ESTADO }, [undefined]);
  assert.equal(await chosen.run(esc.io, ""), null);
  assert.deepEqual(esc.calls, [{ op: "router", payload: {} }]);
  // Con argumento va directo, también desde /modelo.
  const direct = fakeIO({});
  await chosen.run(direct.io, "estado");
  await chosen.run(direct.io, "auto");
  await chosen.run(direct.io, "medio orobas/cyber-hy4");
  await findCommand("modelo")!.run(direct.io, "router fijo");
  assert.deepEqual(direct.calls, [{ op: "router", payload: {} }, { op: "router", payload: { value: "auto" } }, { op: "router_medio", payload: { value: "orobas/cyber-hy4" } }, { op: "router", payload: { value: "fijo" } }]);
  // Se recuerda por proyecto como los otros ajustes.
  assert.ok(RECORDADOS.includes("router") && RECORDADOS.includes("router_medio"));
  // /config: su fila, con ←→ entre auto y fijo.
  const config = fakeIO({ router: ESTADO }, [undefined]);
  await findCommand("config")!.run(config.io, "");
  const rows = config.picked[0]!;
  const at = rows.labels.indexOf("Router de modelos");
  assert.ok(at > rows.labels.indexOf("Razonamiento"), "junto al razonamiento");
  assert.equal(rows.hints[at], "‹ Auto ›");
  await rows.cycle!(at, 1);
  assert.deepEqual(config.calls.filter((call) => "value" in call.payload).at(-1), { op: "router", payload: { value: "fijo" } });
});

test("panel de estado: tabla alineada que entra en el recuadro de 80 columnas, en castellano y en inglés", () => {
  const estado = {
    modo: "auto" as const,
    perfil: "codigo" as const,
    conteo: { http: 34, codigo: 120, movil: 0 },
    ahora: { presion: 2, umbral: 2, enfriando: 3, encargosTurno: 4, activo: { rol: "fuerte" as const, forma: "consulta" as const, nivel: "red" as const, motivo: "sin-avance" as const, detalle: "" } },
    filas: [
      { rol: "ejecutor" as const, modelo: "orobas/glm-5.3-flash", pasos: 1234, pico: 9_870_000_000_000n },
      { rol: "fuerte" as const, nivel: "blue" as const, modelo: "orobas/kimi-k3.1-pro", pasos: 12, rechazos: 1, tasa: 0.08, pico: 120_000_000_000n },
      { rol: "fuerte" as const, nivel: "red" as const, modelo: "orobas/deepseek-v4.1-flash-estandar-ultrafast", pasos: 40, rechazos: 0, tasa: 0.01, pico: 2_340_000_000_000n },
      { rol: "medio" as const, nivel: "blue" as const, modelo: "orobas/cyber-hy4", pasos: 9, rechazos: 0, tasa: 0.02, pico: 90_000_000_000n },
      { rol: "traspaso" as const, modelo: "orobas/glm-5.3-flash", pasos: 30, pico: 40_000_000_000n },
    ],
    traspasos: { n: 30, tokens: 2140, mecanicos: 4 },
    gasto: { bucle: 9_870_000_000_000n, router: 2_590_000_000_000n, referencia: { modelo: "orobas/cyber-ultra-1.0", pico: 215_300_000_000_000n } },
    decisiones: [{ at: "14:02", etiqueta: "fuerte·consulta·blue", motivo: "plan", detalle: "Probá el login de app.test con las dos cuentas" }, { at: "14:05", etiqueta: "fuerte·tramo·red", motivo: "candidato", detalle: "http_request: HTTP 200 con id ajeno" }],
    ejecutor: "orobas/cyber-zero-1.5",
    ejecutorCaro: true,
  };
  for (const lang of ["es_AR.UTF-8", "en_US.UTF-8"]) {
    process.env.LC_ALL = lang;
    const lines = estadoLineas(estado);
    for (const line of lines.slice(1, -1)) assert.ok(visibleWidth(line) <= ANCHO_ESTADO, `${lang}: «${line}» (${visibleWidth(line)})`);
    // Las columnas de la tabla caen en el mismo lugar en todas las filas.
    const table = lines.filter((line) => / (USD|[\d.]+)$/.test(line) && /^(Modelos|Models| {12}(ejecutor|executor|fuerte|strong|medio|mid|traspaso|handoff))/.test(line));
    assert.equal(table.length, 6, table.join("\n"));
    const ends = new Set(table.map((line) => visibleWidth(line)));
    assert.equal(ends.size, 1, table.join("\n"));
  }
  process.env.LC_ALL = "es_AR.UTF-8";
  const lines = estadoLineas(estado);
  assert.match(lines.join("\n"), /Ahora {7}fuerte·consulta·red \(sin avance\)\n {12}presión 2\/2 · enfría 3 pasos · encargos 4\/4 en el turno/);
  assert.ok(lines.includes("Ahorro      ≈ USD 202.84 (94 %)"), lines.join("\n"));
  assert.ok(lines.some((line) => /deepseek-v4\.1-flash-e…/.test(line)), "un nombre largo se corta con «…» y no mueve la tabla");
  assert.ok(lines.includes("            Ejecutor caro (cyber-zero-1.5): con /modelo glm ahorra más."));
  assert.ok(lines.includes("Decisiones  14:02 fuerte·consulta·blue plan       «Probá el login…»"), lines.join("\n"));
});

test("daemon y pie: /router cambia el modo, el pie dice quién trabaja mientras el fuerte decide (también en 80 columnas) y el panel entra sin cortes", async () => {
  const cwd = tmp();
  process.env.CYBER_CONFIG = join(tmp(), "config.json");
  const mundo = new MundoFalso();
  const glm = mundo.proveedor("glm-5.3-flash", TARIFAS.glm);
  const ultra = mundo.proveedor("cyber-ultra-1.0", TARIFAS.ultra);
  // La consulta del fuerte espera hasta que la prueba la suelte: así se ve el pie mientras trabaja.
  let soltar!: () => void;
  const espera = new Promise<void>((resolve) => (soltar = resolve));
  const lento = { ...ultra, transport: async (request: LlmRequest) => { if (request.tags?.worker?.startsWith("router:")) await espera; return ultra.transport(request); } };
  const hy4 = mundo.proveedor("cyber-hy4", TARIFAS.hy4);
  const daemon = new Daemon({ cwd, resolve: () => glm, engine: { strong: lento, resolve: () => hy4, autoVerify: false } });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    const snapshot = await client.attach({ session: "new" });
    assert.deepEqual(client.status.router, { label: "router: ejecutor", short: "router: ejecutor", active: false });
    const engine = [...daemon.hosts.values()][0]!.engine;
    simular(engine, "http_request");
    assert.match((await client.ask("router", {})).join("\n"), /^ROUTER\nModo {8}auto · bucle con el ejecutor; el fuerte, sobre traspasos/);
    assert.match((await client.ask("router", { value: "fijo" })).join("\n"), /Modo {8}fijo · todo con el modelo de la sesión/);
    await until(() => client.status.router?.label === "router: fijo");
    await assert.rejects(client.ask("router", { value: "quizás" }), /Uso: \/router auto \| fijo \| estado/);
    await client.ask("router", { value: "auto" });
    await until(() => client.status.router?.label === "router: ejecutor");
    assert.match((await client.ask("router_medio", { value: "faux/cyber-hy4" })).join("\n"), /Modelo medio del router: faux\/cyber-hy4\./);
    assert.match((await client.ask("router_medio", { value: "no" })).join("\n"), /Sin modelo medio/);

    const screen = { written: "" };
    const foco = startFoco(client, snapshot, { io: { output: { write: (data) => void (screen.written += data), columns: 80, rows: 30 }, listen: () => () => {} }, onExit: () => client.close() });
    const rows = () => pantallaVisible(screen.written, 80, 30);
    const pie = () => rows().filter((row) => /OROBAS|EN CURSO/.test(row)).at(-1) ?? "";
    await until(() => /OROBAS/.test(pie()));
    assert.doesNotMatch(pie(), /router/, "en reposo y a 80 columnas, el router no ocupa lugar");
    mundo.bucle = [sondeo("/api/a"), { text: "Listo." }];
    foco.submit("Probá el control de acceso de app.test");
    await until(() => /router: fuerte·consulta \(plan\)/.test(pie()));
    assert.ok(visibleWidth(pie()) <= 80);
    const avisos = rows().join("\n");
    assert.doesNotMatch(avisos, /Router:|traspaso/, "ni avisos ni el resultado en el chat: el detalle está en /router estado");
    soltar();
    await until(() => !engine.agent.running && !/router: fuerte/.test(pie()));
    // El panel, con datos de verdad, entra en el recuadro sin cortes.
    const lines = engine.routerStatus();
    foco.submit("/router estado");
    await until(() => rows().some((row) => row.includes("Gasto       bucle USD")));
    const visible = rows();
    for (const line of lines.slice(1, -1)) assert.ok(visible.some((row) => row.includes(line.trimEnd())), `falta entera: «${line}»\n${visible.join("\n")}`);
    assert.ok(visible.every((row) => visibleWidth(row) <= 80));
    foco.exit();
  } finally {
    soltar();
    daemon.close();
  }
});
