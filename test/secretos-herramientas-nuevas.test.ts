import "./datos-tmp.ts";
// Las herramientas que trajo #41 (reference_read, web_source_pull, code_crypto, hash_crack) con la regla de #39:
// lo del objetivo lo ve el modelo (y las trazas lo tapan); lo del operador queda tapado, y su marcador se repone
// sólo en las herramientas que ejecutan contra el alcance. Una herramienta sin declarar sería del operador.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { EJECUTAN_EN_EL_ALCANCE, origenDeHerramienta, origenDeProductor, SALIDA_DEL_OBJETIVO, SecretosSesion } from "../src/secretos-sesion.ts";

// Inventadas, armadas por partes para que ningún escáner las tome por claves reales.
const FILTRADA = "ghp_" + "FiltradaEnRepoPublico0123456789abcd";
const DEL_OPERADOR = "Clave-Del-" + "Operador-77Zq";

test("las cuatro herramientas de #41 están declaradas: su salida es del objetivo", () => {
  for (const nombre of ["reference_read", "web_source_pull", "code_crypto", "hash_crack"]) {
    assert.ok(SALIDA_DEL_OBJETIVO.has(nombre), `${nombre} declarada`);
    assert.equal(origenDeHerramienta(nombre), "objetivo", nombre);
  }
  // Sus artefactos: «referencia» (reference_read) y los que llevan el nombre de la herramienta.
  for (const productor of ["referencia", "web_source_pull", "code_crypto", "hash_crack"]) assert.equal(origenDeProductor(productor), "objetivo", productor);
  // Sólo web_source_pull ejecuta contra el alcance (por el cliente HTTP); las otras no salen al objetivo.
  assert.ok(EJECUTAN_EN_EL_ALCANCE.has("web_source_pull"));
  for (const nombre of ["reference_read", "code_crypto", "hash_crack"]) assert.ok(!EJECUTAN_EN_EL_ALCANCE.has(nombre), nombre);
});

test("una clave filtrada en una fuente de referencia se ve; en trazas, tapada", () => {
  const s = new SecretosSesion({ sal: "nuevas" });
  const texto = `const token = "${FILTRADA}";`;
  assert.ok(s.vistaModelo(texto, origenDeHerramienta("reference_read")).includes(FILTRADA), "el modelo la ve: es un hallazgo");
  assert.ok(!s.vistaTrazas(texto, origenDeHerramienta("reference_read")).includes(FILTRADA), "las trazas la tapan");
});

test("un marcador del operador se repone en web_source_pull (va por el cliente HTTP) y no en las que no salen al objetivo", () => {
  const s = new SecretosSesion({ sal: "nuevas", enAlcance: () => true });
  const marca = s.registrar(DEL_OPERADOR, "operador")!;
  const repuesto = s.reponer("web_source_pull", { url: `https://app.objetivo.test/?invitacion=${marca}` });
  assert.deepEqual(repuesto.desconocidos, []);
  assert.equal(repuesto.args.url, `https://app.objetivo.test/?invitacion=${DEL_OPERADOR}`);
  for (const nombre of ["reference_read", "hash_crack"]) {
    assert.throws(() => s.reponer(nombre, { url: `https://github.com/x/y?t=${marca}`, clave: marca }), /no ejecuta contra el alcance/, nombre);
  }
});

test("code_crypto dice la procedencia de su carpeta: del objetivo en una carpeta por programa, del operador en su home", async () => {
  const programa = mkdtempSync(join(tmpdir(), "nuevas-programa-"));
  mkdirSync(join(programa, "src"), { recursive: true });
  writeFileSync(join(programa, "src", "token.js"), `const t = require("crypto").createHash("md5").update(email + Date.now()).digest("hex");\n`);
  for (const [cwd, esperado] of [[programa, "objetivo"], [homedir(), "local"]] as const) {
    const engine = new Engine({ cwd, provider: resolveProvider("faux") });
    try {
      const tool = engine.catalog.available.get("code_crypto") ?? engine.agent.tools.find((item) => item.name === "code_crypto");
      assert.ok(tool, "code_crypto existe");
      const resultado = await tool!.execute({ path: cwd === programa ? "src" : "." }, new AbortController().signal);
      assert.equal(resultado.procedencia, esperado, cwd);
    } finally {
      engine.close();
    }
  }
});
