import "./datos-tmp.ts";
// Procedencia de lo que leen las herramientas de código (decisión de Lean del 22/11): en una carpeta por programa lo
// que hay es del objetivo (su repositorio clonado, su APK decompilado) y el modelo lo ve tal cual, claves filtradas
// incluidas; las trazas lo tapan. Si la carpeta del proyecto es la máquina del operador (su carpeta personal, la
// raíz o una que contiene su home), lo que se lee es suyo: tapado para el modelo y, en el registro, del operador.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createCodeTools } from "../src/codigo.ts";
import { carpetaDelOperador } from "../src/datos.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { which } from "../src/exec.ts";

const abort = new AbortController().signal;
// Inventadas, armadas por partes para que ningún escáner las tome por claves reales.
const STRIPE = "sk_" + "live_51FiltradaEnElRepo0123456789";
const DB = "Pg-Clave-" + "2026x9";

function repositorio(): string {
  const cwd = mkdtempSync(join(tmpdir(), "procedencia-"));
  mkdirSync(join(cwd, "src"), { recursive: true });
  writeFileSync(join(cwd, "src", "config.js"), `export const STRIPE = "${STRIPE}";\n// conexión\nconst url = "postgres://app:${DB}@db.interna:5432/app";\nDB_PASSWORD=${DB}\n`);
  return cwd;
}

test("carpeta del operador: la raíz, su carpeta personal o una que la contiene; una carpeta por programa, no", () => {
  assert.equal(carpetaDelOperador("/home/ana", "/home/ana"), true);
  assert.equal(carpetaDelOperador("/home", "/home/ana"), true);
  assert.equal(carpetaDelOperador("/", "/home/ana"), true);
  assert.equal(carpetaDelOperador("/home/ana/bb/tienda", "/home/ana"), false);
  assert.equal(carpetaDelOperador("/home/anabel", "/home/ana"), false, "un prefijo que no es carpeta no cuenta");
});

for (const ripgrep of [true, false]) {
  test(`código del objetivo (${ripgrep ? "con" : "sin"} ripgrep): code_read y code_search muestran la clave filtrada; en la carpeta del operador, tapada`, { skip: ripgrep && !which("rg") && "ripgrep no está instalado" }, async () => {
    const cwd = repositorio();
    try {
      const tools = Object.fromEntries(createCodeTools({ cwd, ripgrep, delOperador: () => false }).map((tool) => [tool.name, tool]));
      const leido = await tools.code_read!.execute({ path: "src/config.js" }, abort);
      assert.equal(leido.procedencia, "objetivo");
      for (const valor of [STRIPE, DB]) assert.ok(leido.text.includes(valor), `code_read: ${valor}`);
      const buscado = await tools.code_search!.execute({ pattern: "STRIPE|DB_PASSWORD", regex: true }, abort);
      assert.equal(buscado.procedencia, "objetivo");
      for (const valor of [STRIPE, DB]) assert.ok(buscado.text.includes(valor), `code_search: ${valor}`);
      assert.equal((await tools.code_list!.execute({}, abort)).procedencia, "objetivo");

      const delOperador = Object.fromEntries(createCodeTools({ cwd, ripgrep, delOperador: () => true }).map((tool) => [tool.name, tool]));
      const suyo = await delOperador.code_read!.execute({ path: "src/config.js" }, abort);
      assert.equal(suyo.procedencia, "local");
      for (const valor of [STRIPE, DB]) assert.ok(!suyo.text.includes(valor), `code_read en su carpeta: ${valor}`);
      assert.match(suyo.text, /\[secreto omitido/);
      const buscadoSuyo = await delOperador.code_search!.execute({ pattern: "STRIPE|DB_PASSWORD", regex: true }, abort);
      assert.equal(buscadoSuyo.procedencia, "local");
      for (const valor of [STRIPE, DB]) assert.ok(!buscadoSuyo.text.includes(valor), `code_search en su carpeta: ${valor}`);
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
}

test("motor: lo que code_read lee de un repositorio del objetivo es del objetivo (el modelo lo ve, las trazas no); en el home del operador, suyo", async () => {
  const casa = process.env.CYBER_HOME_HOST;
  for (const enCasa of [false, true]) {
    const cwd = repositorio();
    if (enCasa) process.env.CYBER_HOME_HOST = cwd; else delete process.env.CYBER_HOME_HOST;
    const engine = new Engine({ cwd, provider: resolveProvider("faux"), cveFeed: false, autoVerify: false });
    try {
      const leer = engine.bounded(createCodeTools({ cwd }).find((tool) => tool.name === "code_read")!);
      const resultado = await leer.execute({ path: "src/config.js" }, abort);
      const vista = engine.secretos.vistaModelo(resultado.text, "objetivo");
      const trazas = engine.secretos.vistaTrazas(resultado.text, "objetivo");
      for (const valor of [STRIPE, DB]) {
        // En el home se tapa por formato antes de mostrarse: el registro ni lo llega a ver (o lo ve del operador).
        if (enCasa) assert.notEqual(engine.secretos.claseDelValor(valor), "objetivo", valor);
        else assert.equal(engine.secretos.claseDelValor(valor), "objetivo", valor);
        assert.equal(vista.includes(valor), !enCasa, `vista del modelo: ${valor}`);
        assert.ok(!trazas.includes(valor), `trazas: ${valor}`);
      }
    } finally {
      await engine.close();
      rmSync(cwd, { recursive: true, force: true });
      if (casa === undefined) delete process.env.CYBER_HOME_HOST; else process.env.CYBER_HOME_HOST = casa;
    }
  }
});
