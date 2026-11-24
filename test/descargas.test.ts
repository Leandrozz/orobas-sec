import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { INSTALLABLE, INSTALLERS, installTool, type Runner } from "../src/instalar-herramientas.ts";

const wd = mkdtempSync(join(tmpdir(), "cyber-descargas-"));
const calls: string[][] = [];
const runner: Runner = async (argv) => {
  calls.push(argv);
  return { exitCode: 0, stdout: "instalado", stderr: "", durationMs: 120 };
};

test("instalación: rechaza una herramienta fuera de los planes permitidos antes de ejecutar nada", async () => {
  await assert.rejects(installTool("algo-que-no-espera", wd, runner), /no es una herramienta/);
  assert.deepEqual(calls, []);
});

test("instalación: corre cada plan como argv (sin interpolar shell) y verifica disponibilidad", async () => {
  // Herramienta elegida por tener instalador explícito y defender contra la interpolación del comando.
  const tool = "semgrep";
  const resultado = await installTool(tool, wd, runner);
  const ejecutado = calls[0] ?? [];
  assert.ok(INSTALLABLE.includes(tool));
  assert.ok(INSTALLERS[tool]!.every((plan) => typeof plan.display === "string"));
  assert.ok( ["pipx", "semgrep"].includes(ejecutado[0]!), `ejecutable previsto: ${ejecutado.join(" ")}`);
  if (ejecutado.length > 1) assert.notEqual(ejecutado.join(" "), `pipx install semgrep; rm -rf /`);
  assert.doesNotMatch(resultado, /ejecutaScript|var foo|eval/);
  assert.match(resultado, /semgrep|instalado|todavía no está/);
});

test("instalación: playwright construye el directorio destino y SKIP_BROWSER_DOWNLOAD (sin binarios descargados)", async () => {
  const dir = join(wd, "target");
  mkdirSync(dir, { recursive: true });
  const previo = process.env.HOME;
  process.env.HOME = dir;
  try {
    const calls: string[][] = [];
    const fake: Runner = async (argv, env) => {
      calls.push([...argv]);
      assert.equal(env.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD, "1", "no debe descargar Chromium: controla el del sistema");
      assert.ok(env.HOME!.endsWith("cyber-browser"));
      return { exitCode: 0, stdout: "ok", stderr: "", durationMs: 10 };
    };
    const resultado = await installTool("playwright", wd, fake);
    assert.ok(calls.at(-1)!.some((arg) => arg.startsWith("playwright@")));
    assert.match(resultado, /instalado|todavía no está instalado/i);
  } finally {
    if (previo === undefined) delete process.env.HOME;
    else process.env.HOME = previo;
  }
});

test("wizard: elegir descarga la herramienta elegida y muestra el resultado antes de seguir", async () => {
  const { herramientasFaltantes } = await import("../src/tui/inicio.ts");
  const steps: string[] = [];
  const calls: string[][] = [];
  const w = {
    io: {
      ask: async (op: string, payload?: any) => {
        if (op === "toolbox_install") { calls.push(payload!.tools); return ["gitleaks: instalado"]; }
        throw new Error(op);
      },
      pick: async () => 0,
      input: async () => undefined,
      clear: () => {},
      exit: () => {},
      resume: () => {},
      confirm: async () => true,
      keys: () => [],
      view: async () => [],
      status: () => ({}),
      notice: () => {},
      menu: () => {},
    },
    show: (step: any) => { steps.push(step.title); },
    busy: () => {},
    hide: () => {},
    needsKey: () => false,
    pasteKey: async () => true,
  } as any;
  const selected = await herramientasFaltantes(w, ["gitleaks", "otra-desconocida"]);
  assert.equal(selected, "seguir");
  assert.deepEqual(calls, [["gitleaks"]]);
  assert.ok(steps.some((title) => title.includes("Descargar herramientas")));
  assert.ok(steps.some((title) => title.includes("Herramientas listas")));
});

test("instalación: en macOS nmap se instala con brew y en el resto con pacman", () => {
  const real = process.platform;
  try {
    Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
    assert.deepEqual(INSTALLERS.nmap![0]!.argv, ["install", "nmap"]);
    assert.equal(INSTALLERS.nmap![0]!.binary, "brew");
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    assert.equal(INSTALLERS.nmap![0]!.binary, "pacman");
  } finally {
    Object.defineProperty(process, "platform", { value: real, configurable: true });
  }
});

test("SEARCH_PATH incluye Homebrew de Apple Silicon", async () => {
  const { SEARCH_PATH } = await import("../src/exec.ts");
  assert.match(SEARCH_PATH, /\/opt\/homebrew\/bin/);
  assert.match(SEARCH_PATH, /\/opt\/homebrew\/sbin/);
});
