import "./datos-tmp.ts";
// Recorte al entrar (#38) con secretos en dos clases (#39). El recorte corta líneas largas en trozos, se queda con
// cabeza, cola y tramos del medio de 240 caracteres. Dos condiciones:
//   · lo del operador se tapa ANTES de cortar: un corte no deja a la vista del modelo un pedazo de su secreto;
//   · lo del objetivo se ve entero, pero las trazas lo tapan todo: un secreto del objetivo partido por un corte
//     tiene que quedar reconocible (los cortes del harness llevan «…», src/secretos-sesion.ts) y salir tapado.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { recortarSalida } from "../src/recorte.ts";

const DEL_OPERADOR = "OpEr4dorClaveQ7mZx2Wv9KpL";
const DEL_OBJETIVO = "Obj3tivoTokenR8nYc5Hs1JdT";

/** Pedazos de `minimo` caracteres o más de `secreto` (sin el entero si `entero` es false) que aparecen en `texto`. */
function pedazos(texto: string, secreto: string, entero: boolean, minimo = 8): string[] {
  const vistos: string[] = [];
  for (let largo = secreto.length - (entero ? 0 : 1); largo >= minimo; largo--) {
    for (let desde = 0; desde + largo <= secreto.length; desde++) {
      const pedazo = secreto.slice(desde, desde + largo);
      if (texto.includes(pedazo) && !vistos.some((visto) => visto.includes(pedazo))) vistos.push(pedazo);
    }
  }
  return vistos;
}

function herramienta(name: string, text: string): Tool {
  return { name, label: name, description: "", parameters: { type: "object", properties: {} }, execute: () => ({ text }) };
}

/** Una salida de shell de una sola línea larga (JavaScript minificado) con los dos secretos repetidos a paso irregular. */
function salidaLarga(): string {
  // El primero cae justo sobre el fin de la cabeza (tres trozos de 400): sin tapar antes, quedarían 5 caracteres a la vista.
  const partes: string[] = [`k=${".".repeat(1193)}`, `${DEL_OPERADOR};`];
  for (let i = 0; i < 400; i++) {
    partes.push(`var a${i}=${".".repeat(7 + (i % 13))};`);
    if (i % 3 === 0) partes.push(`token=${DEL_OBJETIVO};`);
    if (i % 5 === 1) partes.push(`clave=${DEL_OPERADOR};`);
  }
  return partes.join("");
}

test("recorte con secretos: lo del operador no queda partido a la vista del modelo y lo del objetivo sale tapado en trazas", async () => {
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-recorte-secretos-")), provider: resolveProvider("faux") });
  engine.secretos.registrar(DEL_OPERADOR, "operador");
  engine.secretos.registrar(DEL_OBJETIVO, "objetivo");
  const texto = salidaLarga();
  assert.ok(texto.length > 3 * 3000 && !texto.includes("\n"), "una línea larga: se corta en trozos");
  const recortado = await engine.bounded(herramienta("shell", texto)).execute({ command: "cat app.min.js" }, new AbortController().signal);
  assert.ok(recortado.details?.recortado, "se recortó");

  // Vista del modelo (la que viaja): lo del operador, nunca en pedazos; lo del objetivo, a la vista.
  const modelo = engine.secretos.vistaModelo(recortado.text, "local");
  assert.deepEqual(pedazos(modelo, DEL_OPERADOR, true), [], "ningún pedazo del secreto del operador");
  // Ni siquiera los chicos, que las trazas dejan pasar (menos de 8): se tapó antes de cortar, no después.
  assert.deepEqual(pedazos(modelo, DEL_OPERADOR, true, 5), [], "ni pedazos chicos: la vista se aplica antes del corte");
  assert.match(modelo, /‹SECRETO_\d+›/, "el secreto del operador entra como marcador");
  assert.ok(modelo.includes(DEL_OBJETIVO), "el secreto del objetivo se ve entero");

  // Vista de trazas: nada de ningún secreto, tampoco pedazos que dejó un corte.
  const trazas = engine.secretos.vistaTrazas(recortado.text, "local");
  assert.deepEqual(pedazos(trazas, DEL_OBJETIVO, true), [], "ningún pedazo del secreto del objetivo en trazas");
  assert.deepEqual(pedazos(trazas, DEL_OPERADOR, true), [], "ningún pedazo del secreto del operador en trazas");

  // El artefacto guarda el original entero.
  assert.equal(engine.artifacts.read(String(recortado.details?.recortado)).toString("utf8"), texto);
});

test("sin vista, el recorte no cambia: es el mismo que replica el simulador", () => {
  const texto = salidaLarga();
  const sinMarcas = recortarSalida(texto, 3000, ["token"], "sha256:" + "e".repeat(64))!;
  const conMarcas = recortarSalida(texto, 3000, ["token"], "sha256:" + "e".repeat(64), { marcarCortes: true })!;
  assert.ok(!/…\n…/.test(sinMarcas), "el formato del simulador no lleva marcas de corte");
  assert.match(conMarcas, /…\n…/, "con marcas, cada trozo de una línea partida termina y empieza en «…»");
  assert.equal(conMarcas.replace(/…(?=\n|$)|(?<=\n|: )…/g, ""), sinMarcas, "las marcas son lo único distinto");
});
