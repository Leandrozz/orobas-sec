import "./datos-tmp.ts";
// Carga sintética del grafo: una sesión con miles de rutas, objetos y accesos. Mide alimentar (en lote), armar la
// vista desde la base y las consultas, y que nada de eso trabe un turno. Los números salen como diagnóstico.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import type { HarvestRow } from "../src/cosecha.ts";
import { conContexto, Grafo } from "../src/grafo.ts";
import { Alimentador, type EntradaLog } from "../src/grafo-alimentar.ts";
import { bloqueCheckpoint, calcularFaltantes, faltantes, resumen, vecinos } from "../src/grafo-consultas.ts";
import type { HttpExchange } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const BASE = "http://carga.test";
const alcance: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule("carga.test")], exclude: [] };
const uuid = (n: number) => `${n.toString(16).padStart(8, "0")}-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;

test("carga: 6000 intercambios sobre 2000 familias, 3 identidades y 6000 objetos, sin trabar", (t) => {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "grafo-carga-")));
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const tag = () => ({ program: "manual", domains: ["carga.test"] });
  const grafo = new Grafo(db, { sesion: "s1", etiqueta: tag, alcance: () => alcance });
  const alimentador = new Alimentador({ grafo, artifacts, sesion: "s1", alcance: () => alcance });
  const identidades = ["ana", "beto", "carla"];
  const log: EntradaLog[] = [];
  const inicio = performance.now();
  let maxLote = 0;
  for (let i = 0; i < 6000; i++) {
    const familia = i % 2000;
    const identidad = identidades[i % 3]!;
    const metodo = i % 7 === 0 ? "PUT" : "GET";
    const url = `${BASE}/api/recurso${familia}/${(i % 50) + 1}?q=${i}`;
    const status = identidad === "carla" ? 403 : 200;
    const exchange: HttpExchange = {
      id: `h${i}`, request: { method: metodo, url, headers: {} },
      response: { status, headers: { "content-type": "application/json", server: "nginx/1.24.0" }, body: "{}", bodyBytes: 2, truncated: false },
      resolved: [], redirects: [], durationMs: 1, artifact: `sha256:${i.toString(16).padStart(64, "0")}`,
    };
    const entrada: EntradaLog = { id: exchange.id, method: metodo, url, status, hash: exchange.artifact, query: { q: String(i) }, bodyKeys: metodo === "PUT" ? ["nombre", "rol"] : [], bodyIds: [], identity: identidad };
    log.push(entrada);
    const antes = performance.now();
    conContexto({ herramienta: "http_probe" }, () => {
      alimentador.intercambio(exchange, entrada);
      if (identidad !== "carla") {
        const fila: HarvestRow = { identity: identidad, value: uuid(i), kind: "uuid", method: metodo, origin: url.split("?")[0]!, field: "data[].id", link: "", discovered: true, exchange: exchange.id, at: "" };
        alimentador.cosecha([fila], exchange);
      }
    });
    // Como al terminar una herramienta: cada 20 intercambios (un http_probe grande) se vacía el lote.
    if (i % 20 === 19) grafo.vaciar();
    maxLote = Math.max(maxLote, performance.now() - antes);
  }
  grafo.vaciar();
  const alimentar = performance.now() - inicio;
  assert.deepEqual(alimentador.errores, []);
  const filas = db.prepare("select count(*) n from grafo_nodos").get() as { n: number };
  const aristas = db.prepare("select count(*) n from grafo_aristas").get() as { n: number };
  // Una sesión nueva sobre la misma base arma la vista desde cero.
  const otra = new Grafo(db, { sesion: "s2", etiqueta: tag, alcance: () => alcance });
  const armar0 = performance.now();
  const vista = otra.ver();
  const armar = performance.now() - armar0;
  const consultas0 = performance.now();
  const pendientes = calcularFaltantes(vista, { identidades });
  const textoFaltantes = faltantes(vista, { identidades });
  const textoResumen = resumen(vista, { identidades });
  const textoVecinos = vecinos(vista, "ana");
  const bloque = bloqueCheckpoint(vista, log, { identidades });
  const consultas = performance.now() - consultas0;
  t.diagnostic(`nodos ${filas.n} · aristas ${aristas.n} · alimentar ${Math.round(alimentar)} ms (${(alimentar / 6000).toFixed(3)} ms por intercambio, peor intercambio con vaciado ${Math.round(maxLote)} ms) · armar la vista ${Math.round(armar)} ms · faltantes+resumen+vecinos+checkpoint ${Math.round(consultas)} ms · ${pendientes.length} pendientes`);
  assert.ok(filas.n > 10_000, `nodos ${filas.n}`);
  assert.equal(vista.nodos.size, filas.n);
  assert.ok(alimentar / 6000 < 5, `alimentar ${alimentar} ms`);
  assert.ok(maxLote < 1000, `un vaciado no traba: ${maxLote} ms`);
  assert.ok(armar < 15_000, `armar la vista ${armar} ms`);
  assert.ok(consultas < 10_000, `consultas ${consultas} ms`);
  for (const texto of [textoFaltantes, textoResumen, textoVecinos]) assert.ok(texto.length <= 6000);
  assert.ok(bloque.length < 12_000, `bloque del checkpoint ${bloque.length}`);
});

test("carga: el tope de la partición frena el crecimiento sin perder lo que importa", () => {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "grafo-tope-")));
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const avisos: string[] = [];
  const grafo = new Grafo(db, { sesion: "s1", etiqueta: () => ({ program: "manual", domains: ["carga.test"] }), alcance: () => alcance, limites: { nodos: 500, aristas: 2000 }, evento: (tipo) => avisos.push(tipo) });
  const alimentador = new Alimentador({ grafo, artifacts, sesion: "s1", alcance: () => alcance });
  for (let i = 0; i < 2000; i++) {
    const url = `${BASE}/api/x${i}/1`;
    alimentador.intercambio({ id: `h${i}`, request: { method: "GET", url, headers: {} }, response: { status: 200, headers: {}, body: "", bodyBytes: 0, truncated: false }, resolved: [], redirects: [], durationMs: 1, artifact: `sha256:${i}` }, { id: `h${i}`, method: "GET", url, status: 200, hash: `sha256:${i}`, query: {}, bodyKeys: [], bodyIds: [] });
  }
  grafo.nodo({ tipo: "hallazgo", id: "f1", etiqueta: "IDOR", estado: "observado" }, "sha256:f");
  grafo.vaciar();
  const nodos = (db.prepare("select count(*) n from grafo_nodos").get() as { n: number }).n;
  assert.ok(nodos <= 510, `nodos ${nodos}`);
  assert.ok(grafo.ver().nodos.has("hallazgo:f1"), "el hallazgo entra igual");
  assert.ok((grafo.descartadas.get("ruta") ?? 0) > 0);
  assert.ok(avisos.includes("grafo.tope"), "el operador se entera por el evento");
  assert.ok(avisos.filter((tipo) => tipo === "grafo.tope").length <= 3, "una vez por tipo, no por escritura");
});
