import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { despedirVentana, otrasVentanas } from "../src/compartido.ts";
import { Daemon } from "../src/daemon.ts";
import { runtimeDir } from "../src/datos.ts";
import { resolveProvider } from "../src/providers.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 4000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};
const proc = (dir: string, pid: number, cmd: string[], env: string[] = []) => {
  mkdirSync(join(dir, String(pid)));
  writeFileSync(join(dir, String(pid), "cmdline"), cmd.join("\0") + "\0");
  writeFileSync(join(dir, String(pid), "environ"), env.join("\0") + "\0");
};
const cli = "/opt/elevate-cyber/src/cli.ts";

function conEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const antes = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  const poner = (v: Record<string, string | undefined>) => { for (const [k, x] of Object.entries(v)) x === undefined ? delete process.env[k] : (process.env[k] = x); };
  poner(vars);
  return fn().finally(() => poner(antes));
}

test("otrasVentanas cuenta sólo otros TUI", () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-proc-"));
  proc(dir, 10, ["node", cli, "-C", "/proyecto"]);
  proc(dir, 11, ["node", cli, "-C", "/proyecto", "daemon"]);
  proc(dir, 12, ["node", cli, "despedir-ventana", "x"]);
  proc(dir, 13, ["sh", "-c", "algo"]);
  mkdirSync(join(dir, "15")); // sin cmdline
  assert.equal(otrasVentanas(dir, 10), 0);
  proc(dir, 14, ["node", cli, "-C", "/proyecto"]);
  assert.equal(otrasVentanas(dir, 10), 1);
});

test("despedirVentana manda SIGHUP sólo a la ventana pedida y SIGKILL al que sigue vivo", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-proc-"));
  proc(dir, 20, ["node"], ["A=1", "CYBER_VENTANA=abc"]);
  proc(dir, 21, ["node"], ["CYBER_VENTANA=abcd"]);
  proc(dir, 22, ["node"], ["CYBER_VENTANA=abc"]);
  const llamadas: unknown[][] = [];
  // el 20 muere con el SIGHUP; el 22 lo ignora
  assert.equal(await despedirVentana("abc", dir, (...a) => llamadas.push(a), (pid) => pid === 22, 10), 2);
  assert.deepEqual(llamadas, [[20, "SIGHUP"], [22, "SIGHUP"], [22, "SIGKILL"]]);
});

test("compartido: la conexión de mantenimiento (sinRetener) mantiene vivo al daemon más allá del idle", async () => {
  await conEnv({ CYBER_COMPARTIDO: "1", CYBER_PROYECTO_HOST: "/p" }, async () => {
    const cwd = mkdtempSync(join(tmpdir(), "cyber-comp-"));
    const daemon = new Daemon({ cwd, idleMs: 100, resolve: () => resolveProvider("faux") });
    await daemon.listen();
    try {
      // un comando que sólo espera (como --resumen) tiene esta conexión y nada más
      const mantenimiento = await connectDaemon(cwd, { spawn: false });
      mantenimiento.sinRetener();
      await tick(450); // más de cuatro idle
      const otro = await connectDaemon(cwd, { spawn: false }); // sigue vivo
      otro.close();
      mantenimiento.close();
      await tick(450);
      await assert.rejects(connectDaemon(cwd, { spawn: false })); // sin sockets el idle sí lo apaga
    } finally {
      daemon.close();
    }
  });
});

test("compartido: si el daemon no puede arrancar deja arranque.err y espera antes de salir, para que la ventana lo lea", async () => {
  const { spawn } = await import("node:child_process");
  const cwd = mkdtempSync(join(tmpdir(), "cyber-comp-"));
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux") }); // toma el candado
  await daemon.listen();
  const hijo = spawn(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "../src/cli.ts"), "daemon", "-C", cwd], {
    env: { ...process.env, CYBER_COMPARTIDO: "1", CYBER_PROYECTO_HOST: "/p", CYBER_SIN_MONTAJES: "1", CYBER_ARRANQUE_ESPERA_MS: "1500" },
    stdio: "ignore",
  });
  let salio = false;
  hijo.once("exit", () => (salio = true));
  try {
    await until(() => existsSync(join(runtimeDir(cwd), "arranque.err")));
    assert.ok(existsSync(join(runtimeDir(cwd), "arranque.err")));
    await tick(500);
    assert.equal(salio, false, "sigue vivo mientras la ventana lee el motivo");
    await until(() => salio);
    assert.equal(salio, true);
  } finally {
    hijo.kill();
    daemon.close();
  }
});

async function conDaemon(fn: (cwd: string, daemon: Daemon) => Promise<void>) {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-comp-"));
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux") });
  await daemon.listen();
  try { await fn(cwd, daemon); } finally { daemon.close(); }
}

test("compartido: la última ventana apaga el daemon; con otras ventanas no", async () => {
  await conEnv({ CYBER_COMPARTIDO: "1", CYBER_PROYECTO_HOST: "/p" }, () => conDaemon(async (cwd) => {
    const a = await connectDaemon(cwd, { spawn: false });
    await a.leave(() => 1);
    const b = await connectDaemon(cwd, { spawn: false });
    await b.leave(() => 0);
    await tick(100);
    await assert.rejects(connectDaemon(cwd, { spawn: false }));
  }));
});

test("fuera de modo compartido, dentro del contenedor, leave pide force", async () => {
  await conEnv({ CYBER_COMPARTIDO: undefined, CYBER_PROYECTO_HOST: "/p" }, () => conDaemon(async (cwd) => {
    const client = await connectDaemon(cwd, { spawn: false });
    const pedidos: unknown[][] = [];
    client.ask = (async (...a: unknown[]) => (pedidos.push(a), [])) as never;
    await client.leave();
    assert.deepEqual(pedidos, [["shutdown", { force: true }]]);
  }));
});

test("compartido: la última ventana con un turno en curso no fuerza el apagado", async () => {
  await conEnv({ CYBER_COMPARTIDO: "1", CYBER_PROYECTO_HOST: "/p" }, async () => {
    const cwd = mkdtempSync(join(tmpdir(), "cyber-comp-"));
    const provider = resolveProvider("faux");
    const daemon = new Daemon({ cwd, resolve: () => provider });
    await daemon.listen();
    try {
      const client = await connectDaemon(cwd, { spawn: false });
      await client.attach({ session: "new" });
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const host = [...daemon.hosts.values()][0]!;
      host.engine.agent.tools.push({ name: "esperar", label: "Esperar", description: "", parameters: { type: "object" }, execute: async () => (await gate, { text: "ok" }) });
      provider.faux!.queue = [{ text: "Arranco.\n", toolCalls: [{ name: "esperar", arguments: {} }] }, { text: "Listo." }];
      client.send("Trabajá");
      await until(() => host.engine.agent.running);
      await client.leave(() => 0);
      await tick(200);
      const otro = await connectDaemon(cwd, { spawn: false }); // el daemon sigue vivo
      otro.close();
      release();
    } finally {
      daemon.close();
    }
  });
});
