import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { inicioDone, inicioPending, markInicio, resetInicio } from "../src/inicio.ts";
import { resolveProvider } from "../src/providers.ts";
import { startFoco } from "../src/tui/foco.ts";
import { stripAnsi } from "../src/tui/text.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};

test("inicio guiado: siete pasos sobre el sello, deja alcance y marca hecho; /inicio lo repite y «no mostrar más» lo omite", async () => {
  resetInicio();
  assert.equal(inicioPending(), true);
  const cwd = mkdtempSync(join(tmpdir(), "cyber-inicio-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  const state = { written: "", input: (_: string) => {}, exited: false };
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    const snapshot = await client.attach({ session: "new" });
    startFoco(client, snapshot, {
      io: { output: { write: (data) => void (state.written += data), columns: 90, rows: 40 }, listen: (onData) => ((state.input = onData), () => {}) },
      onExit: () => ((state.exited = true), client.close()),
      onboarding: true,
    });
    const plain = () => stripAnsi(state.written);
    await until(() => plain().includes("Paso 1 de 7"));
    assert.match(plain(), /Bienvenida/);
    await until(() => plain().includes("━"));
    assert.match(plain(), /━/, "la barra de progreso se dibuja");
    state.input("\r"); // empezar
    await until(() => plain().includes("Paso 2 de 7"));
    assert.match(plain(), /Cuenta/);
    state.input("\r"); // seguir (faux no necesita clave)
    await until(() => plain().includes("Paso 3 de 7"));
    await until(() => /bounty/i.test(plain()));
    state.input("\r"); // perfil actual
    await until(() => plain().includes("Paso 4 de 7"), 60_000); // revisa cada binario de la caja: tarda
    assert.match(plain(), /Herramientas/);
    state.input("\r");
    await until(() => plain().includes("Paso 5 de 7"));
    assert.match(plain(), /chrome:\/\/extensions/);
    state.input("\r");
    await until(() => plain().includes("Paso 6 de 7"));
    state.input("\r"); // seguir sin sumar cuentas
    await until(() => plain().includes("Paso 7 de 7"));
    state.input("objetivo.test\r");
    await until(() => plain().includes("Quedó todo configurado"));
    assert.ok(inicioDone() && !inicioDone()!.skipped, "quedó marcado como hecho");
    assert.equal(inicioPending(), false);
    const scope = await client.view("scope");
    assert.match(scope.join("\n"), /objetivo\.test/);

    // Se repite a pedido, y «no mostrar más» lo omite para siempre.
    state.input("/inicio\r");
    await until(() => plain().split("Paso 1 de 7").length >= 3);
    state.input("\x1b"); // cancelar el menú del paso
    await until(() => plain().includes("Dejamos el inicio acá"));
    state.input("\x1b[B\x1b[B\r"); // no mostrar más
    await until(() => plain().includes("Inicio omitido"));
    assert.equal(inicioDone()!.skipped, true);
    assert.equal(inicioPending(), false);
    assert.equal(state.exited, false);
  } finally {
    daemon.close();
    resetInicio();
  }
});

test("con el inicio ya hecho, la TUI arranca directo", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-inicio2-"));
  const provider = resolveProvider("faux");
  const daemon = new Daemon({ cwd, resolve: () => provider });
  await daemon.listen();
  const state = { written: "", input: (_: string) => {} };
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.ask("inicio", { action: "done" });
    const snapshot = await client.attach({ session: "new" });
    startFoco(client, snapshot, { io: { output: { write: (data) => void (state.written += data), columns: 80, rows: 30 }, listen: (onData) => ((state.input = onData), () => {}) }, onboarding: true });
    await tick(150);
    assert.doesNotMatch(stripAnsi(state.written), /Paso 1 de 7/);
    assert.match(stripAnsi(state.written), /¿Qué querés investigar ahora\?/);
  } finally {
    daemon.close();
    resetInicio();
  }
});

test("inicio: lee con BOM y no pisa una configuración ilegible", () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-inicio3-"));
  const previous = process.env.CYBER_CONFIG;
  const config = join(dir, "config.json");
  process.env.CYBER_CONFIG = config;
  try {
    writeFileSync(config, `﻿${JSON.stringify({ defaultModel: "x" })}`);
    markInicio();
    assert.match(readFileSync(config, "utf8"), /defaultModel/);
    assert.ok(inicioDone());
    writeFileSync(config, "{ roto");
    assert.throws(() => markInicio(), /No toqué|untouched/);
    assert.throws(() => resetInicio(), /No toqué|untouched/);
    assert.equal(readFileSync(config, "utf8"), "{ roto");
  } finally {
    if (previous === undefined) delete process.env.CYBER_CONFIG;
    else process.env.CYBER_CONFIG = previous;
  }
});

test("inicio: si el daemon no puede armar la guía de la extensión (EACCES), el paso avisa y sigue", async () => {
  const { runWizard } = await import("../src/tui/inicio.ts");
  const shown: string[] = [];
  const io = {
    ask: async (op: string) => { if (op === "extension") throw new Error("EACCES: permission denied, open '/opt/x/extension.json'"); return []; },
    view: async () => [],
    pick: async () => 0,
    input: async () => "",
    notice: () => {},
  } as any;
  const outcome = await runWizard({ io, show: (s) => shown.push(s.body.join("\n")), hide: () => {}, needsKey: () => false, pasteKey: async () => false, busy: () => {} });
  assert.equal(outcome, "completo");
  assert.ok(shown.some((body) => /EACCES/.test(body) && /cyber extension/.test(body)), "el paso 5 muestra el error y cómo reintentar");
});

test("inicio: sin clave y con un modelo que no es de la suscripción, la cuenta es opcional y se puede seguir sin ella", async () => {
  const { runWizard } = await import("../src/tui/inicio.ts");
  const shown: string[] = [];
  const offered: string[][] = [];
  const io = {
    ask: async () => [],
    view: async () => [],
    pick: async (title: string, options: Array<{ label: string }>) => {
      if (/cuenta de orobas|orobas account/.test(title)) { offered.push(options.map((option) => option.label)); return 0; }
      return 0;
    },
    input: async () => "",
    notice: () => {},
  } as any;
  const outcome = await runWizard({ io, show: (s) => shown.push(s.body.join("\n")), hide: () => {}, needsKey: () => false, hasKey: () => false, pasteKey: async () => false, busy: () => {} });
  assert.equal(outcome, "completo");
  assert.equal(offered.length, 1, "seguir sin cuenta no vuelve a preguntar");
  assert.match(offered[0]!.at(0)!, /seguir sin cuenta|continue without an account/, "va primero: Enter sigue");
  assert.ok(shown.some((body) => /opcional|optional/.test(body)), "el paso dice que la cuenta es opcional");
});

test("inicio: con un modelo de la suscripción y sin clave, no se ofrece seguir sin cuenta", async () => {
  const { runWizard } = await import("../src/tui/inicio.ts");
  const offered: string[][] = [];
  let pasted = 0;
  const io = {
    ask: async () => [],
    view: async () => [],
    pick: async (title: string, options: Array<{ label: string }>) => {
      if (/cuenta de orobas|orobas account/.test(title)) { offered.push(options.map((option) => option.label)); return 1; }
      return 0;
    },
    input: async () => "",
    notice: () => {},
  } as any;
  await runWizard({ io, show: () => {}, hide: () => {}, needsKey: () => true, hasKey: () => false, pasteKey: async () => (++pasted, true), busy: () => {} });
  assert.equal(offered.length, 1);
  assert.equal(offered[0]!.length, 2);
  assert.ok(!offered[0]!.some((label) => /sin cuenta|without an account/.test(label)));
  assert.equal(pasted, 1);
});
