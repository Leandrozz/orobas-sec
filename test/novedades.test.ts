import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { resolveProvider } from "../src/providers.ts";
import { abrirProyecto, guardarAjuste, marcarNovedades, novedadesVistas } from "../src/tui/ajustes.ts";
import { startFoco } from "../src/tui/foco.ts";
import { NOVEDADES, pendientes } from "../src/tui/novedades.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

const tick = (ms = 40) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (done: () => boolean, ms = 3000) => { for (const start = Date.now(); !done() && Date.now() - start < ms; ) await tick(5); };

async function armar(previa: "nada" | "proyecto" | "vista-vieja" | "cuatro") {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-nov-"));
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-nov-cfg-")), "config.json"); // configuración limpia por test
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux") });
  await daemon.listen();
  abrirProyecto(cwd);
  if (previa === "cuatro") marcarNovedades(["x"]);
  if (previa !== "nada") guardarAjuste("mouse", false);
  if (previa === "vista-vieja") marcarNovedades([NOVEDADES.at(-1)!.id]);
  const state = { written: "", input: (_: string) => {} };
  const output = { write: (data: string) => void (state.written += data), columns: 120, rows: 30 };
  const client = await connectDaemon(cwd, { spawn: false });
  const snapshot = await client.attach({ session: "new" });
  startFoco(client, snapshot, { project: cwd, io: { output, listen: (onData) => ((state.input = onData), () => {}) }, onExit: () => client.close(), onboarding: false, novedades: true });
  const visible = () => pantallaVisible(state.written, 120, 30).join("\r\n");
  return { state, daemon, visible };
}

test("novedades: pendientes devuelve las no vistas, máximo 3, más nuevas primero", () => {
  assert.deepEqual(pendientes([]).map((n) => n.id), NOVEDADES.slice(0, 3).map((n) => n.id));
  assert.deepEqual(pendientes([NOVEDADES[0]!.id]).map((n) => n.id), NOVEDADES.slice(1, 4).map((n) => n.id));
  assert.equal(pendientes(NOVEDADES.map((n) => n.id)).length, 0);
});

test("novedades: primera vez marca todas y no muestra", async () => {
  const t = await armar("nada");
  try {
    await tick(200);
    assert.doesNotMatch(t.visible(), /Novedades/);
    assert.deepEqual(novedadesVistas().sort(), NOVEDADES.map((n) => n.id).sort());
  } finally { t.daemon.close(); }
});

test("novedades: con una vista vieja muestra las nuevas en un panel y las marca", async () => {
  const t = await armar("vista-vieja");
  try {
    await until(() => /Novedades/.test(t.visible()));
    // La más nueva arriba (el panel muestra hasta tres).
    assert.ok(t.visible().includes(`◆ ${NOVEDADES[0]!.titulo()}`), t.visible());
    assert.match(t.visible(), /\/novedades para verlas otra vez/);
    assert.equal(novedadesVistas().length, NOVEDADES.length);
  } finally { t.daemon.close(); }
});

test("novedades: sin la clave pero con proyectos guardados, se muestran", async () => {
  const t = await armar("proyecto");
  try { await until(() => /Novedades/.test(t.visible())); } finally { t.daemon.close(); }
});

test("novedades: /novedades muestra todas", async () => {
  const t = await armar("nada");
  try {
    await tick(200);
    t.state.input("/novedades\r");
    await until(() => /Modo ultra/.test(t.visible()));
    assert.match(t.visible(), /◆ Temas de colores/);
    assert.match(t.visible(), /◆ Copiar con el mouse/);
  } finally { t.daemon.close(); }
});

test("novedades: con más de 3 sin ver avisa cuántas quedan", async () => {
  const t = await armar("cuatro");
  try { await until(() => /y 1 más en \/novedades/.test(t.visible())); } finally { t.daemon.close(); }
});

test("novedades: la entrada de subagentes y harnesses existe en es y en", () => {
  const n = NOVEDADES.find((x) => x.id === "2026-11-ventanas-ia")!;
  assert.ok(n);
  const antes = process.env.LANG;
  const textos = ["es_AR.UTF-8", "en_US.UTF-8"].map((lang) => { process.env.LANG = lang; delete process.env.LC_ALL; return n.titulo() + n.lineas().join(); });
  process.env.LANG = antes;
  assert.notEqual(textos[0], textos[1]);
});
