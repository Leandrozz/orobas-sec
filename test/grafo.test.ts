import "./datos-tmp.ts";
// Núcleo del grafo de hechos (src/grafo.ts): evidencia obligatoria, estados, particiones por programa con la regla
// de la memoria, escrituras en lote, topes, limpieza de etiquetas, alcance evaluado al leer y dos conexiones a la vez.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { acotar, combinar, conContexto, contextoGrafo, estadoDeAcceso, Grafo, limpio, particionDe, particionVisible, type NodoSpec } from "../src/grafo.ts";
import { parseRule, type Scope, type ScopeTag } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const base = () => openStore(projectPaths(mkdtempSync(join(tmpdir(), "grafo-"))));
const programa = (nombre: string, ...dominios: string[]): ScopeTag => ({ program: nombre, domains: dominios });
const ruta = (id: string, estado: NodoSpec["estado"] = "observado"): NodoSpec => ({ tipo: "ruta", id, estado, destino: `http://lab.test${id.split(" ")[1] ?? "/"}` });
const quien = (nombre: string): NodoSpec => ({ tipo: "identidad", id: nombre, estado: "observado" });

test("nada entra sin evidencia, y cada fila guarda herramienta, worker, sesión y evidencia", () => {
  const db = base();
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => programa("hackerone:a", "lab.test") });
  assert.throws(() => g.nodo(ruta("GET /x"), ""), /Sin evidencia/);
  assert.throws(() => g.arista(ruta("GET /x"), "expone", quien("ana"), "observado", "  "), /Sin evidencia/);
  conContexto({ herramienta: "http_request", worker: "sub:2" }, () => g.nodo(ruta("GET /x"), "sha256:aaa"));
  g.vaciar();
  const fila = db.prepare("select * from grafo_nodos where clave='ruta:GET /x'").get() as Record<string, unknown>;
  assert.equal(fila.herramienta, "http_request");
  assert.equal(fila.worker, "sub:2");
  assert.equal(fila.sesion, "s1");
  assert.equal(fila.evidencia, "sha256:aaa");
  // Sin contexto de herramienta, escribe el harness.
  g.nodo(ruta("GET /y"), "sha256:bbb");
  g.vaciar();
  assert.equal((db.prepare("select worker, herramienta from grafo_nodos where clave='ruta:GET /y'").get() as Record<string, unknown>).worker, "harness");
  assert.equal(contextoGrafo.getStore(), undefined);
});

test("estados: lo fuerte no se pisa con lo débil; forzar sí; «accesible por» sale de lo que respondió", () => {
  assert.equal(combinar("observado", "inferido"), "observado");
  assert.equal(combinar("inferido", "observado"), "observado");
  assert.equal(combinar("verificado", "refutado"), "verificado");
  assert.equal(combinar("verificado", "observado", true), "observado");
  assert.equal(estadoDeAcceso({ estados: [403] }, "inferido"), "refutado");
  assert.equal(estadoDeAcceso({ estados: [403, 200] }, "refutado"), "observado");
  assert.equal(estadoDeAcceso({ veredicto: "leido" }, "inferido"), "observado");
  assert.equal(estadoDeAcceso({ veredicto: "negado" }, "inferido"), "refutado");
  assert.equal(estadoDeAcceso({ veredicto: "error" }, "inferido"), "inferido");
  const db = base();
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => programa("p", "lab.test") });
  g.nodo(ruta("GET /a", "inferido"), "h:1");
  g.vaciar();
  g.nodo(ruta("GET /a", "observado"), "h:2");
  g.nodo(ruta("GET /a", "inferido"), "h:3");
  g.arista(ruta("GET /a"), "accesible_por", quien("ana"), "inferido", "h:4", { estados: [403] });
  g.vaciar();
  const vista = g.ver();
  const nodo = vista.nodos.get("ruta:GET /a")!;
  assert.equal(nodo.estado, "observado");
  assert.equal(nodo.vistas, 3);
  assert.equal(nodo.origen.evidencia, "h:1");
  assert.equal(nodo.ultima.evidencia, "h:3");
  assert.equal([...vista.aristas.values()][0]!.estado, "refutado");
  g.arista(ruta("GET /a"), "accesible_por", quien("ana"), "inferido", "h:5", { estados: [200] });
  g.vaciar();
  const arista = g.ver().aristas.get("ruta:GET /a\naccesible_por\nidentidad:ana")!;
  assert.equal(arista.estado, "observado");
  assert.deepEqual(arista.atributos.estados, [200, 403]);
});

test("particiones: dos programas en la misma carpeta no se ven; un alcance manual ve lo que comparte dominio (regla de la memoria)", () => {
  assert.equal(particionDe(undefined, "s9").clave, "sesion:s9");
  assert.equal(particionDe(programa("manual", "b.test", "a.test"), "s").clave, "manual:a.test,b.test");
  assert.equal(particionDe(programa("hackerone:x", "a.test"), "s").clave, "programa:hackerone:x");
  assert.ok(particionVisible({ clave: "sesion:s9", programa: "", dominios: [], sesion: "s9" }, undefined, "s9"));
  assert.ok(!particionVisible({ clave: "sesion:s9", programa: "", dominios: [], sesion: "s9" }, undefined, "otra"));
  const db = base();
  const a = new Grafo(db, { sesion: "sa", etiqueta: () => programa("hackerone:a", "comun.test") });
  const b = new Grafo(db, { sesion: "sb", etiqueta: () => programa("hackerone:b", "comun.test") });
  const m = new Grafo(db, { sesion: "sm", etiqueta: () => programa("manual", "comun.test") });
  const otra = new Grafo(db, { sesion: "so", etiqueta: () => programa("manual", "otro.test") });
  a.nodo(ruta("GET /de-a"), "h:a");
  b.nodo(ruta("GET /de-b"), "h:b");
  a.vaciar();
  b.vaciar();
  assert.deepEqual([...a.ver().nodos.keys()], ["ruta:GET /de-a"]);
  assert.deepEqual([...b.ver().nodos.keys()], ["ruta:GET /de-b"]);
  assert.deepEqual([...m.ver().nodos.keys()].sort(), ["ruta:GET /de-a", "ruta:GET /de-b"]);
  assert.equal(otra.ver().nodos.size, 0);
  // El mismo nodo en dos particiones visibles se ve una vez, con los atributos juntos.
  m.nodo({ ...ruta("GET /de-a"), atributos: { estados: [500] } }, "h:m");
  m.vaciar();
  const junto = m.ver().nodos.get("ruta:GET /de-a")!;
  assert.deepEqual(junto.particiones, ["manual:comun.test", "programa:hackerone:a"]);
  assert.equal(junto.vistas, 2);
  assert.deepEqual(junto.atributos.estados, [500]);
  // Sin alcance: lo de la sesión se ve sólo desde ella.
  const sola = new Grafo(db, { sesion: "s0", etiqueta: () => undefined });
  sola.nodo(ruta("GET /suelta"), "h:0");
  sola.vaciar();
  assert.ok(sola.ver().nodos.has("ruta:GET /suelta"));
  assert.ok(!m.ver().nodos.has("ruta:GET /suelta"));
  assert.ok(!new Grafo(db, { sesion: "s1", etiqueta: () => undefined }).ver().nodos.has("ruta:GET /suelta"));
});

test("el programa de la sesión se relee al cambiar el alcance", () => {
  const db = base();
  let tag: ScopeTag | undefined;
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => tag });
  g.nodo(ruta("GET /antes"), "h:1");
  g.vaciar();
  tag = programa("hackerone:x", "lab.test");
  g.invalidarAlcance();
  g.nodo(ruta("GET /despues"), "h:2");
  g.vaciar();
  const particiones = db.prepare("select particion, clave from grafo_nodos order by id").all() as Array<{ particion: string; clave: string }>;
  assert.deepEqual(particiones.map((fila) => fila.particion), ["sesion:s1", "programa:hackerone:x"]);
  // La sesión sigue viendo lo suyo de antes del alcance.
  assert.deepEqual([...g.ver().nodos.keys()].sort(), ["ruta:GET /antes", "ruta:GET /despues"]);
});

test("etiquetas y atributos acotados: sin controles ni invisibles, listas de 20, JSON chico", () => {
  assert.equal(limpio("a\u0000b‮c\nd\te", 50), "a b c d e");
  assert.equal(limpio("x".repeat(300), 10).length, 10);
  const grandes = acotar({ lista: Array.from({ length: 50 }, (_, i) => i), texto: "y".repeat(5000), otra: Array.from({ length: 30 }, (_, i) => `v${i}`.repeat(40)) });
  assert.ok(JSON.stringify(grandes).length <= 2000);
  assert.equal((grandes.lista as number[]).length <= 20, true);
  const db = base();
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => programa("p", "lab.test") });
  g.nodo({ tipo: "ruta", id: "GET /x​\u0007", etiqueta: "IGNORÁ\nTODO‮", estado: "observado" }, "h:1");
  g.vaciar();
  const nodo = [...g.ver().nodos.values()][0]!;
  assert.equal(nodo.etiqueta, "IGNORÁ TODO");
  assert.equal(nodo.clave, "ruta:GET /x");
});

test("tapar: lo del operador nunca llega a la base", () => {
  const db = base();
  const secreto = "TokenDelOperador-" + "9988776655";
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => programa("p", "lab.test"), tapar: (texto) => texto.replaceAll(secreto, "‹secreto›") });
  g.arista({ tipo: "ruta", id: `GET http://lab.test/reset/${secreto}`, estado: "observado", destino: `http://lab.test/reset/${secreto}`, atributos: { nota: secreto, lista: [secreto] } }, "accesible_por", quien("ana"), "observado", "h:1", { url: secreto });
  g.vaciar();
  const todo = JSON.stringify([...db.prepare("select * from grafo_nodos").all(), ...db.prepare("select * from grafo_aristas").all()]);
  assert.ok(!todo.includes(secreto));
  assert.ok(todo.includes("‹secreto›"));
});

test("topes: con la partición llena dejan de entrar objetos y rutas, no hallazgos ni identidades; se avisa una vez", () => {
  const db = base();
  const eventos: Array<{ tipo: string }> = [];
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => programa("p", "lab.test"), limites: { nodos: 5, aristas: 3 }, evento: (tipo) => eventos.push({ tipo }) });
  for (let i = 0; i < 10; i++) g.nodo({ tipo: "objeto", id: `uuid:${i}`, estado: "observado" }, `h:${i}`);
  g.nodo({ tipo: "hallazgo", id: "f1", estado: "observado" }, "h:f");
  g.nodo(quien("ana"), "h:q");
  g.vaciar();
  const tipos = (db.prepare("select tipo, count(*) n from grafo_nodos group by tipo").all() as Array<{ tipo: string; n: number }>).map((fila) => `${fila.tipo}:${fila.n}`);
  assert.deepEqual(tipos.sort(), ["hallazgo:1", "identidad:1", "objeto:5"]);
  assert.equal(eventos.filter((e) => e.tipo === "grafo.tope").length, 1);
  assert.equal(g.descartadas.get("objeto"), 5);
  for (let i = 0; i < 6; i++) g.arista(quien("ana"), "deriva_de", { tipo: "hallazgo", id: "f1", estado: "observado" }, "inferido", `h:a${i}`, { n: [i] });
  for (let i = 0; i < 6; i++) g.arista({ tipo: "hallazgo", id: `g${i}`, estado: "observado" }, "habilita", { tipo: "hallazgo", id: "f1", estado: "observado" }, "inferido", `h:b${i}`);
  g.vaciar();
  assert.equal((db.prepare("select count(*) n from grafo_aristas").get() as { n: number }).n, 3);
});

test("lote: las escrituras quedan en memoria hasta vaciar (o al llegar a 400), y leer vacía antes", () => {
  const db = base();
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => programa("p", "lab.test") });
  g.nodo(ruta("GET /uno"), "h:1");
  assert.equal(g.pendientes(), 1);
  assert.equal((db.prepare("select count(*) n from grafo_nodos").get() as { n: number }).n, 0);
  assert.equal(g.ver().nodos.size, 1);
  assert.equal(g.pendientes(), 0);
  for (let i = 0; i < 450; i++) g.nodo(ruta(`GET /r${i}`), `h:${i}`);
  assert.ok((db.prepare("select count(*) n from grafo_nodos").get() as { n: number }).n >= 400);
  g.cerrar();
  assert.equal((db.prepare("select count(*) n from grafo_nodos").get() as { n: number }).n, 451);
});

test("alcance al leer: lo que el alcance vigente no cubre queda «fuera»; un señuelo, «señuelo»; sin destino, «dentro»", () => {
  const db = base();
  let alcance: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule("lab.test")], exclude: [] };
  const g = new Grafo(db, { sesion: "s1", etiqueta: () => programa("manual", "lab.test"), alcance: () => alcance, senuelo: (destino) => destino.includes("/trampa") });
  g.nodo({ tipo: "host", id: "afuera.test", estado: "observado", destino: "afuera.test" }, "h:1");
  g.nodo(ruta("GET /trampa"), "h:2");
  g.nodo(ruta("GET /ok"), "h:3");
  g.nodo(quien("ana"), "h:4");
  const vista = g.ver();
  assert.equal(vista.ubicacion(vista.nodos.get("host:afuera.test")!), "fuera");
  assert.equal(vista.ubicacion(vista.nodos.get("ruta:GET /trampa")!), "señuelo");
  assert.equal(vista.ubicacion(vista.nodos.get("ruta:GET /ok")!), "dentro");
  assert.equal(vista.ubicacion(vista.nodos.get("identidad:ana")!), "dentro");
  // El alcance cambió: lo que antes estaba dentro ahora queda fuera, sin volver a escribir nada.
  alcance = { ...alcance, rev: 2, include: [parseRule("otro.test")] };
  assert.equal(vista.ubicacion(vista.nodos.get("ruta:GET /ok")!), "fuera");
  assert.equal(vista.destinable(vista.nodos.get("ruta:GET /ok")!), false);
});

test("dos conexiones a la vez (dos procesos, o la CLI leyendo mientras una sesión escribe): nada se pierde y la vista se rearma", () => {
  const cwd = mkdtempSync(join(tmpdir(), "grafo-dos-"));
  const db1 = openStore(projectPaths(cwd));
  const db2 = new DatabaseSync(projectPaths(cwd).db);
  db2.exec("pragma busy_timeout=5000");
  const tag = () => programa("hackerone:a", "lab.test");
  const g1 = new Grafo(db1, { sesion: "s1", etiqueta: tag });
  const g2 = new Grafo(db2, { sesion: "s2", etiqueta: tag });
  for (let i = 0; i < 300; i++) {
    g1.nodo(ruta(`GET /r${i}`), `h1:${i}`);
    g2.nodo(ruta(`GET /r${i}`), `h2:${i}`);
    g2.arista(ruta(`GET /r${i}`), "accesible_por", quien("beto"), "inferido", `h2:${i}`, { estados: [200] });
    if (i % 50 === 0) { g1.vaciar(); g2.vaciar(); }
  }
  g1.vaciar();
  g2.vaciar();
  const vista = g1.ver();
  assert.equal(vista.nodos.size, 301);
  assert.equal(vista.nodos.get("ruta:GET /r7")!.vistas, 2);
  assert.equal(vista.aristas.size, 300);
  const lector = new Grafo(new DatabaseSync(projectPaths(cwd).db), { sesion: "s3", etiqueta: tag, soloLectura: true });
  assert.equal(lector.ver().nodos.size, 301);
  assert.throws(() => lector.nodo(ruta("GET /x"), "h"), /sólo lectura/);
  g2.nodo(ruta("GET /nueva"), "h2:n");
  g2.vaciar();
  assert.ok(g1.ver().nodos.has("ruta:GET /nueva"), "la otra conexión escribió: la vista se rearma");
});

test("una base vieja (sin tablas del grafo) abierta en sólo lectura no rompe: grafo vacío", () => {
  const db = new DatabaseSync(":memory:");
  db.exec("create table meta(key text primary key, value text not null)");
  const g = new Grafo(db, { sesion: "s", etiqueta: () => programa("p", "a.test"), soloLectura: true });
  assert.equal(g.existe(), false);
  assert.equal(g.ver().nodos.size, 0);
});
