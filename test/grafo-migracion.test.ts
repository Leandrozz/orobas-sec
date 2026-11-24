import "./datos-tmp.ts";
// Migración al grafo de una base de antes del grafo (src/grafo-migrar.ts): hallazgos, ids cosechados, cruces,
// hipótesis de la memoria e intercambios guardados entran una vez, cada uno en el programa donde nació; dos
// programas de la misma carpeta no se mezclan; abrir de nuevo no duplica nada; los intercambios van por tandas.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { Engine } from "../src/engine.ts";
import { Findings } from "../src/findings.ts";
import { Grafo } from "../src/grafo.ts";
import { Alimentador } from "../src/grafo-alimentar.ts";
import { migrarGrafo } from "../src/grafo-migrar.ts";
import { resolveProvider } from "../src/providers.ts";
import { ScopeStore, scopeTag } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { Vault } from "../src/vault.ts";

const PEDIDO = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

/** Una carpeta con dos sesiones de programas distintos (a y b) y un intercambio que ambos cubren, sin tablas del grafo. */
function proyectoViejo() {
  const cwd = mkdtempSync(join(tmpdir(), "grafo-migra-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const ahora = new Date().toISOString();
  for (const [sesion, programa, hosts] of [["sa", "hackerone:a", ["a.test", "comun.test"]], ["sb", "hackerone:b", ["b.test", "comun.test"]]] as const) {
    db.prepare("insert into sessions(id,started_at,model) values(?,?,?)").run(sesion, ahora, "faux/faux");
    new ScopeStore(db, sesion).save({ source: programa, include: hosts.map((host) => ({ kind: "host" as const, value: host })), exclude: [], notes: "" });
  }
  const intercambio = (host: string, ruta: string, identidad: string | undefined, status: number, body: object) => artifacts.put(JSON.stringify({
    id: "h3", request: { method: "GET", url: `http://${host}${ruta}`, headers: identidad ? { authorization: `<identidad ${identidad}>` } : {} },
    response: { status, headers: { "content-type": "application/json", server: "nginx/1.24.0" }, body: JSON.stringify(body), bodyBytes: 10, truncated: false }, resolved: [], redirects: [], durationMs: 1, artifact: "",
  }), "application/json", "http").hash;
  const deA = intercambio("a.test", "/api/pedidos/7", "ana", 200, { id: PEDIDO });
  const deB = intercambio("b.test", "/api/facturas/9", "bruno", 403, { error: "no" });
  intercambio("comun.test", "/compartida", undefined, 200, {});
  // Lo que el agente leyó en la sesión a: «h3 … artefacto sha256:…» (resuelve el id de la cosecha).
  db.prepare("insert into messages(session_id,seq,json) values(?,?,?)").run("sa", 0, JSON.stringify({ role: "tool", name: "http_request", content: `h3 GET http://a.test/api/pedidos/7 · 3 ms · artefacto ${deA}` }));
  const findings = new Findings(db, (hash) => artifacts.find(hash), (hash) => artifacts.read(hash));
  findings.record({ title: "IDOR en pedidos", kind: "control de acceso", severity: "media", asset: "http://a.test/api/pedidos/7", summary: "lee pedidos ajenos", evidence: [deA] }, "sa");
  findings.record({ title: "Factura negada", kind: "configuracion", severity: "baja", asset: "http://b.test/api/facturas/9", summary: "x", evidence: [deB] }, "sb");
  db.exec(`create table if not exists ids_cosechados(session_id text not null, identidad text not null, valor text not null, tipo text not null, metodo text not null, origen text not null, campo text not null, enlace text not null default '', descubierto integer not null default 0, intercambio text not null, at text not null, primary key(session_id, identidad, valor, origen, campo));
    create table if not exists ids_cruces(session_id text not null, valor text not null, duenio text not null, identidad text not null, metodo text not null, url text not null, estado_duenio integer, estado integer, veredicto text not null, intercambios text not null, at text not null, primary key(session_id, valor, identidad, metodo, url));`);
  db.prepare("insert into ids_cosechados values(?,?,?,?,?,?,?,?,?,?,?)").run("sa", "ana", PEDIDO, "uuid", "GET", "http://a.test/api/pedidos/7", "id", "", 1, "h3", ahora);
  db.prepare("insert into ids_cruces values(?,?,?,?,?,?,?,?,?,?,?)").run("sa", PEDIDO, "ana", "beto", "GET", `http://a.test/api/pedidos/${PEDIDO}`, 200, 200, "leido", "h3,h9", ahora);
  const vault = new Vault(db, paths.records, paths.notes);
  vault.write({ type: "hipotesis", title: "Los pedidos no comprueban dueño", summary: "lo sugiere el 200 de beto", scope: { program: "hackerone:a", domains: ["a.test"] } });
  vault.write({ type: "hipotesis", title: "Nota vieja sin programa", summary: "?", scope: { program: "?", domains: [] } });
  db.close();
  return { cwd, deA, deB };
}

/** Abre el proyecto con una sesión nueva del programa dado (el motor migra al construirse). */
function abrir(cwd: string, programa: string, hosts: string[]) {
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), cveFeed: false });
  engine.scope.save({ source: programa, include: hosts.map((host) => ({ kind: "host" as const, value: host })), exclude: [], notes: "" });
  return engine;
}

test("migración: cada cosa entra en el programa donde nació, con su evidencia, y dos programas no se mezclan", async () => {
  const { cwd, deA } = proyectoViejo();
  const a = abrir(cwd, "hackerone:a", ["a.test", "comun.test"]);
  try {
    const vista = a.grafo!.ver();
    const claves = [...vista.nodos.keys()];
    assert.ok(claves.includes("ruta:GET http://a.test/api/pedidos/{n}"), "la superficie de a, desde su intercambio guardado");
    assert.ok(!claves.some((clave) => clave.includes("b.test")), "nada de b");
    assert.ok(!claves.some((clave) => clave.includes("comun.test")), "lo que cubren los dos programas no se atribuye a ninguno");
    const ruta = vista.nodos.get("ruta:GET http://a.test/api/pedidos/{n}")!;
    assert.equal(ruta.origen.herramienta, "migracion");
    assert.equal(ruta.origen.evidencia, deA);
    assert.ok(vista.aristas.has("ruta:GET http://a.test/api/pedidos/{n}\naccesible_por\nidentidad:ana"), "la identidad sale del marcador del intercambio");
    const objeto = vista.aristas.get(`objeto:uuid:${PEDIDO}\npertenece_a\nidentidad:ana`)!;
    assert.equal(objeto.procedencia.evidencia, deA, "el h3 de la cosecha se resolvió por lo que leyó la sesión");
    assert.equal(objeto.procedencia.sesion, "sa");
    const cruce = vista.aristas.get(`objeto:uuid:${PEDIDO}\naccesible_por\nidentidad:beto`)!;
    assert.equal(cruce.atributos.veredicto, "leido");
    assert.match(cruce.procedencia.evidencia, /^sha256:|^ids_cruces:sa:/);
    assert.equal(vista.deTipo("hallazgo").length, 1);
    assert.equal(vista.deTipo("hallazgo")[0]!.etiqueta, "IDOR en pedidos");
    assert.deepEqual(vista.deTipo("hipotesis").map((nodo) => nodo.etiqueta), ["Los pedidos no comprueban dueño"], "la nota de programa desconocido no entra");
  } finally {
    await a.close();
  }
  const b = abrir(cwd, "hackerone:b", ["b.test", "comun.test"]);
  try {
    const claves = [...b.grafo!.ver().nodos.keys()];
    assert.ok(claves.includes("ruta:GET http://b.test/api/facturas/{n}"));
    assert.ok(!claves.some((clave) => clave.includes("a.test")));
    assert.equal(b.grafo!.ver().deTipo("hallazgo")[0]!.etiqueta, "Factura negada");
  } finally {
    await b.close();
  }
});

test("migración idempotente: abrir de nuevo no duplica ni suma vistas", async () => {
  const { cwd } = proyectoViejo();
  const contar = (engine: Engine) => engine.db.prepare("select count(*) n, sum(vistas) v from grafo_nodos").get() as { n: number; v: number };
  const primero = abrir(cwd, "hackerone:a", ["a.test"]);
  const antes = contar(primero);
  await primero.close();
  const segundo = abrir(cwd, "hackerone:a", ["a.test"]);
  try {
    assert.deepEqual(contar(segundo), antes);
    assert.equal(JSON.parse((segundo.db.prepare("select value from meta where key='grafo.migracion'").get() as { value: string }).value).terminado, true);
  } finally {
    await segundo.close();
  }
});

test("migración por tandas: los intercambios avanzan con un cursor y terminan", () => {
  const { cwd } = proyectoViejo();
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const grafo = new Grafo(db, { sesion: "nueva", etiqueta: () => ({ program: "hackerone:a", domains: ["a.test"] }) });
  const alimentador = new Alimentador({ grafo, artifacts, sesion: "nueva" });
  const uno = migrarGrafo({ db, grafo, alimentador, artifacts, tanda: 1 });
  assert.equal(uno.pendientes, true);
  const dos = migrarGrafo({ db, grafo, alimentador, artifacts, tanda: 1 });
  assert.equal(dos.hallazgos, 0, "las fases hechas no se repiten");
  let resto = migrarGrafo({ db, grafo, alimentador, artifacts, tanda: 1 });
  while (resto.pendientes) resto = migrarGrafo({ db, grafo, alimentador, artifacts, tanda: 1 });
  assert.equal(uno.intercambios + dos.intercambios + resto.intercambios >= 2, true);
  assert.equal(migrarGrafo({ db, grafo, alimentador, artifacts }).intercambios, 0, "terminada: nada más");
});

test("una base nueva migra en vacío y queda terminada", async () => {
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "grafo-nueva-")), provider: resolveProvider("faux"), cveFeed: false });
  try {
    const estado = JSON.parse((engine.db.prepare("select value from meta where key='grafo.migracion'").get() as { value: string }).value);
    assert.equal(estado.terminado, true);
    assert.equal(engine.grafo!.ver().nodos.size, 0);
    assert.equal(scopeTag(engine.scope.current()), undefined);
  } finally {
    await engine.close();
  }
});
