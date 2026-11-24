import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon, type ClientEvent } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { loadCredentials } from "../src/hackerone.ts";
import { accountMenu, askHiddenInTerminal, pickInTerminal } from "../src/menu.ts";
import { resolveProvider } from "../src/providers.ts";
import { deleteSecret, readSecret } from "../src/secretos.ts";
import { startFoco } from "../src/tui/foco.ts";
import { stripAnsi } from "../src/tui/text.ts";

process.env.LC_ALL = "es_AR.UTF-8";
delete process.env.OROBAS_API_KEY;
delete process.env.H1_USERNAME;
delete process.env.H1_API_TOKEN;
const SECRET = "oro_k";
const tick = (ms = 30) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 3000) => {
  for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5);
};
const programs = () => new Response(JSON.stringify({ data: [{ id: "1", attributes: { handle: "a", name: "A" } }, { id: "2", attributes: { handle: "b", name: "B" } }], links: {} }));

async function setup(needsKey = false) {
  deleteSecret("orobas");
  const cwd = mkdtempSync(join(tmpdir(), "cyber-"));
  const provider = resolveProvider("faux");
  if (needsKey) provider.model = { ...provider.model, apiKeyEnv: "OROBAS_API_KEY" };
  const daemon = new Daemon({ cwd, resolve: () => provider, fetch: (async () => programs()) as typeof fetch });
  await daemon.listen();
  const client = await connectDaemon(cwd, { spawn: false });
  const events: ClientEvent[] = [];
  client.on((event) => events.push(event));
  const snapshot = await client.attach({ session: "new" });
  const state = { written: "", input: (_: string) => {} };
  const app = startFoco(client, snapshot, {
    io: { output: { write: (data) => void (state.written += data), columns: 70, rows: 30 }, listen: (onData) => ((state.input = onData), () => {}) },
    onExit: () => client.close(),
  });
  const plain = () => stripAnsi(state.written);
  const close = async () => { app.exit(); await daemon.close(); };
  return { cwd, provider, daemon, client, events, state, plain, close };
}

test("/orobas guarda la clave sin que pase por eventos ni frames, y el siguiente mensaje se procesa", async () => {
  const s = await setup();
  try {
    s.state.input("/orobas\r");
    await until(() => s.plain().includes("Pegar una clave"));
    s.state.input("\x1b[B\r"); // segunda opción: pegar una clave (la primera entra por el sitio)
    await until(() => s.plain().includes("Pegá tu clave"));
    s.state.input(`${SECRET}\r`);
    await until(() => readSecret("orobas") === SECRET);
    assert.equal(readSecret("orobas"), SECRET);
    s.provider.faux!.queue = [{ text: "Hola de vuelta." }];
    s.state.input("hola\r");
    await until(() => s.plain().includes("Hola de vuelta."));
    assert.match(s.plain(), /Hola de vuelta\./);
    assert.ok(!s.plain().includes(SECRET), "ningún frame");
    assert.ok(!JSON.stringify(s.events).includes(SECRET), "ningún evento del daemon");
    assert.match((await s.client.ask("account", { service: "orobas", action: "status" })).join(), /termina en …ro_k/);
  } finally { await s.close(); }
});

test("/hackerone valida con la API, guarda {username, token} y /hackerone Revocar borra", async () => {
  const s = await setup();
  try {
    s.state.input("/hackerone\r");
    await until(() => s.plain().includes("Iniciar sesión"));
    s.state.input("\r");
    await until(() => s.plain().includes("Usuario de HackerOne"));
    s.state.input("ana\r");
    await until(() => s.plain().includes("Token de API"));
    s.state.input("tok123\r");
    await until(() => s.plain().includes("2 programas"));
    assert.match(s.plain(), /2 programas/);
    assert.deepEqual(loadCredentials(), { username: "ana", token: "tok123" });
    assert.ok(!s.plain().includes("tok123") && !JSON.stringify(s.events).includes("tok123"));
    s.state.input("/hackerone\r");
    await until(() => s.plain().includes("vinculado como ana"));
    s.state.input("\x1b[B\r");
    await until(() => s.plain().includes("Sí, revocar"));
    s.state.input("\r");
    await until(() => !loadCredentials());
    assert.equal(loadCredentials(), undefined);
  } finally { await s.close(); }
});

test("sin clave, la sesión nueva pide la clave de orobas y Esc deja la TUI abierta", async () => {
  const s = await setup(true);
  try {
    assert.equal(s.client.status.needsKey, true);
    // Primero el menú: entrar por el sitio o pegar una clave. Acá, pegar.
    await until(() => s.plain().includes("pegar una clave"));
    s.state.input("\x1b[B\r");
    await until(() => s.plain().includes("Pegá tu clave de https://cyber.elevateai.ar/cuenta"));
    assert.match(s.plain(), /Pegá tu clave de https:\/\/cyber\.elevateai\.ar\/cuenta/);
    assert.ok(s.state.written.includes("\x1b]8;;https://cyber.elevateai.ar/cuenta\x1b\\"), "la URL va como hiperenlace OSC 8");
    s.state.input("\x1b");
    s.state.input("hola\r");
    await tick(100);
    assert.ok(s.plain().split("Tu cuenta de orobas").length >= 3, "el envío vuelve a ofrecer la cuenta");
    s.state.input("\x1b[B\r");
    await until(() => s.plain().split("Pegá tu clave").length >= 3);
    s.state.input("k_nueva\r");
    await until(() => readSecret("orobas") === "k_nueva");
    assert.equal(readSecret("orobas"), "k_nueva");
    await until(() => !s.client.status.needsKey);
    assert.equal(s.client.status.needsKey, false);
  } finally { await s.close(); }
});

test("cyber hackerone en la terminal: stdin simulado, mismo resultado", async () => {
  const s = await setup();
  const log = console.log;
  const write = process.stdout.write;
  const logged: string[] = [];
  let echoed = "";
  console.log = (...args: unknown[]) => void logged.push(args.join(" "));
  process.stdout.write = ((chunk: string | Uint8Array) => { if (typeof chunk === "string") echoed += chunk; else write.call(process.stdout, chunk); return true; }) as typeof write;
  try {
    const feed = (async () => { for (const line of ["1\r", "bea\r", "tok456\r"]) { await tick(40); process.stdin.emit("data", Buffer.from(line)); } })();
    const out = await accountMenu("hackerone", { ask: (op, payload) => s.client.ask(op, payload), pick: pickInTerminal, askHidden: askHiddenInTerminal });
    await feed;
    assert.match(out.join("\n"), /2 programas|2 programs/);
    assert.deepEqual(loadCredentials(), { username: "bea", token: "tok456" });
    assert.ok(!echoed.includes("tok456") && !logged.join().includes("tok456"));
  } finally { console.log = log; process.stdout.write = write; await s.close(); }
});

// Los binarios se buscan en rutas fijas antes que en PATH: con un gh real instalado ahí, este test
// ejecutaría el gh de verdad (un inicio de sesión real contra GitHub). En ese caso no corre.
const ghReal = ["/usr/local/bin/gh", "/usr/bin/gh", "/bin/gh", join(process.env.HOME ?? "", ".local/bin/gh"), join(process.env.HOME ?? "", "go/bin/gh")].find((path) => existsSync(path));
test("/github: iniciar sesión muestra URL y código; Revocar corre el logout de la CLI y borra su carpeta de sesión", { skip: ghReal ? `hay un gh real en ${ghReal}: no se ejecuta la CLI verdadera desde un test` : false }, async () => {
  const bin = mkdtempSync(join(tmpdir(), "cyber-bin-"));
  const home = mkdtempSync(join(tmpdir(), "cyber-plat-"));
  writeFileSync(join(bin, "gh"), `#!/bin/sh
case "$*" in
  "auth status") [ -f "$HOME/.config/gh/ok" ] || { echo "You are not logged into any GitHub hosts" >&2; exit 1; }; echo "Logged in as ana" ;;
  "auth login"*) echo "! First copy your one-time code: ABCD-1234"; echo "Open https://github.com/login/device"; sleep 0.3; mkdir -p "$HOME/.config/gh"; touch "$HOME/.config/gh/ok" ;;
  "auth logout"*) echo "$*" > "$HOME/logout.witness" ;;
esac
`, { mode: 0o755 });
  chmodSync(join(bin, "gh"), 0o755);
  const saved = { PATH: process.env.PATH, HOME: process.env.CYBER_PLATAFORMAS_HOME };
  process.env.PATH = `${bin}:${process.env.PATH}`;
  process.env.CYBER_PLATAFORMAS_HOME = home;
  const s = await setup();
  try {
    s.state.input("/github\r");
    await until(() => s.plain().includes("Iniciar sesión"));
    s.state.input("\r");
    await until(() => s.plain().includes("ABCD-1234"));
    assert.match(s.plain(), /https:\/\/github\.com\/login\/device/);
    await until(() => existsSync(join(home, ".config/gh/ok")));
    s.state.input("/github\r");
    await until(() => s.plain().includes("vinculada · ana") || s.plain().includes("Logged in as ana"));
    s.state.input("\r");
    await until(() => s.plain().includes("Sí, revocar"));
    s.state.input("\r");
    await until(() => existsSync(join(home, "logout.witness")) && !existsSync(join(home, ".config/gh")));
    assert.match(readFileSync(join(home, "logout.witness"), "utf8"), /auth logout/);
    assert.equal(existsSync(join(home, ".config/gh")), false);
  } finally {
    process.env.PATH = saved.PATH;
    if (saved.HOME === undefined) delete process.env.CYBER_PLATAFORMAS_HOME; else process.env.CYBER_PLATAFORMAS_HOME = saved.HOME;
    await s.close();
  }
});

test("el prompt del agente ya no manda a orobas-sec login", () => {
  assert.ok(!readFileSync(join(import.meta.dirname, "../src/engine.ts"), "utf8").includes("orobas-sec login"));
});

test("con CYBER_CONSOLE=conhost la clave se pide con la URL plana, sin OSC 8", async () => {
  process.env.CYBER_CONSOLE = "conhost";
  const s = await setup(true);
  try {
    await until(() => s.plain().includes("pegar una clave"));
    s.state.input("\x1b[B\r");
    await until(() => s.plain().includes("Pegá tu clave de https://cyber.elevateai.ar/cuenta"));
    assert.ok(s.plain().includes("https://cyber.elevateai.ar/cuenta"));
    assert.ok(!s.state.written.includes("\x1b]8"));
  } finally { delete process.env.CYBER_CONSOLE; await s.close(); }
});
