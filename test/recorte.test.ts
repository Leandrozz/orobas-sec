import "./datos-tmp.ts";
// Recorte al entrar (src/recorte.ts): una salida que pasa el tope de su herramienta entra como cabeza, cola y
// tramos con coincidencias, con el original en un artefacto. El simulador (scripts/repeticion_contexto.py)
// replica el algoritmo: los casos de test/fixtures/recorte-casos.json los generó él y acá tienen que dar igual.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { recortarAlEntrar, recortarSalida, terminos, TOPES_POR_HERRAMIENTA } from "../src/recorte.ts";

const fixtures = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "recorte-casos.json"), "utf8")) as {
  puntero: string;
  casos: Array<{ nombre: string; texto: string; tope: number; argumentos: unknown; terminos: string[]; esperado: string | null }>;
};

test("el recorte da lo mismo que la réplica del simulador, caso por caso", () => {
  assert.ok(fixtures.casos.length >= 5);
  for (const caso of fixtures.casos) {
    assert.deepEqual(terminos(caso.argumentos), caso.terminos, caso.nombre);
    assert.equal(recortarSalida(caso.texto, caso.tope, caso.terminos, fixtures.puntero) ?? null, caso.esperado, caso.nombre);
  }
});

test("cabeza, cola, tramos del medio con su posición y el puntero al original", () => {
  const lineas = Array.from({ length: 400 }, (_, i) => (i === 200 ? "Set-Cookie: sid=1; HttpOnly → 403 Forbidden" : i === 250 ? "const clave = buscada" : `relleno ${i}`));
  const texto = lineas.join("\n");
  const salida = recortarSalida(texto, 1500, ["buscada"], "sha256:" + "c".repeat(64))!;
  assert.ok(salida.startsWith("relleno 0\nrelleno 1\n"));
  assert.match(salida, /relleno 399\n\[Recortado al entrar: \d+ caracteres en total\. Completa en sha256:c{64}/);
  const posicion = texto.indexOf("Set-Cookie");
  assert.ok(salida.includes(`@${posicion}: Set-Cookie: sid=1; HttpOnly → 403 Forbidden`), "una señal del medio queda, con su posición");
  assert.ok(salida.includes(`@${texto.indexOf("const clave")}: const clave = buscada`), "lo que se buscó también");
  assert.ok(!salida.includes("relleno 120\n"), "el relleno del medio no entra");
  assert.ok(salida.length < 2000);
  assert.equal(recortarSalida("corto", 1500, [], "x"), undefined);
});

test("los términos salen de los argumentos, sin palabras vacías ni repetidas", () => {
  assert.deepEqual(terminos({ command: "curl -sS https://a.test/api/users | grep password", cwd: "/srv/app" }), ["a.test/api/users", "password", "srv/app"]);
  assert.deepEqual(terminos({ hash: "sha256:abcd", filters: ["token", "token", "id"] }), ["sha256", "abcd", "token"]);
});

function herramienta(name: string, text: string): Tool {
  return { name, label: name, description: "", parameters: { type: "object", properties: {} }, execute: () => ({ text }) };
}

test("el motor recorta al entrar las herramientas con tope y guarda el original entero", async () => {
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-recorte-")), provider: resolveProvider("faux") });
  const largo = Array.from({ length: 300 }, (_, i) => `fila ${i} del resultado`).join("\n");
  const recortado = await engine.bounded(herramienta("shell", largo)).execute({ command: "cat filas.txt" }, new AbortController().signal);
  const puntero = /Completa en (sha256:[0-9a-f]{64})/.exec(recortado.text)?.[1];
  assert.ok(puntero, "nombra el artefacto");
  assert.equal(engine.artifacts.read(puntero!).toString("utf8"), largo);
  assert.ok(recortado.text.length < TOPES_POR_HERRAMIENTA.shell! + 400);
  assert.equal(recortado.details?.recortado, puntero);
  // Una herramienta sin tope entra como antes (hasta el corte general).
  const http = await engine.bounded(herramienta("http_request", largo)).execute({}, new AbortController().signal);
  assert.equal(http.text, largo);
  // Y con CYBER_RECORTE=no el recorte se apaga.
  process.env.CYBER_RECORTE = "no";
  try {
    const entero = await engine.bounded(herramienta("shell", largo)).execute({}, new AbortController().signal);
    assert.equal(entero.text, largo);
  } finally {
    delete process.env.CYBER_RECORTE;
  }
});

test("la vista se aplica antes de cortar y el artefacto guarda el original", () => {
  const texto = `${"x".repeat(2000)}\nSECRETO-ENTERO\n${"y".repeat(2000)}`;
  const guardados: string[] = [];
  const salida = recortarAlEntrar("http_probe", {}, { text: texto }, (t) => (guardados.push(t), "sha256:" + "d".repeat(64)), (t) => t.replace("SECRETO-ENTERO", "‹SECRETO_1›"))!;
  assert.equal(guardados[0], texto);
  assert.ok(!salida.text.includes("SECRETO-ENTERO"));
});
