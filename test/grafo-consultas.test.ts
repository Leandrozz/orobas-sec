import "./datos-tmp.ts";
// Consultas del grafo (src/grafo-consultas.ts), alimentación desde artefactos de fuente, recon, CVE y memoria
// (src/grafo-alimentar.ts), escaladas con nodos reales (src/cadenas.ts), la cadena en el informe y /grafo en el
// daemon: salida estable, paginada y con tope; lo de fuera del alcance no se propone; grafo vacío.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { cadenaConEvidencia, propuestasDeEscalada } from "../src/cadenas.ts";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import type { Finding } from "../src/findings.ts";
import { Grafo } from "../src/grafo.ts";
import { Alimentador, nodos } from "../src/grafo-alimentar.ts";
import { calcularFaltantes, caminos, comandoGrafo, exportar, faltantes, MAX_SALIDA, resolver, resumen, subgrafoHallazgo, vecinos } from "../src/grafo-consultas.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { Vault } from "../src/vault.ts";

const BASE = "http://lab.test";
const alcance: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule("lab.test")], exclude: [] };

function armar() {
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "grafo-consultas-")));
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const grafo = new Grafo(db, { sesion: "s1", etiqueta: () => ({ program: "manual", domains: ["lab.test"] }), alcance: () => alcance });
  const alimentador = new Alimentador({ grafo, artifacts, sesion: "s1", alcance: () => alcance });
  return { db, paths, artifacts, grafo, alimentador };
}

/** Un mapa chico: usuarios con id (ana lee el suyo, beto no probó), una escritura vista en el contrato, un objeto de ana. */
function sembrar(grafo: Grafo) {
  const usuarios = nodos.ruta("GET", `${BASE}/api/usuarios/1`, "observado", { estados: [200] })!;
  const ana = nodos.identidad("ana");
  const beto = nodos.identidad("beto");
  grafo.arista(nodos.servicio(BASE), "expone", usuarios, "observado", "sha256:aaaaaaaaaaaa1");
  grafo.arista(usuarios, "accesible_por", ana, "inferido", "sha256:aaaaaaaaaaaa1", { estados: [200] });
  grafo.arista(nodos.ruta("GET", `${BASE}/api/usuarios/2`, "observado")!, "accesible_por", beto, "inferido", "sha256:aaaaaaaaaaaa2", { estados: [403] });
  grafo.nodo(nodos.ruta("PUT", `${BASE}/api/usuarios/1`, "inferido", { via: "contrato" })!, "sha256:contrato");
  const objeto = nodos.objeto("3fa85f64-5717-4562-b3fc-2c963f66afa6", "uuid", "pedidos");
  grafo.arista(objeto, "pertenece_a", ana, "inferido", "sha256:aaaaaaaaaaaa1");
  grafo.arista(objeto, "observado_en", usuarios, "observado", "sha256:aaaaaaaaaaaa1");
  grafo.arista(usuarios, "acepta", nodos.parametro(`${BASE}/api/usuarios/1?q=1`, "consulta", "q", "observado")!, "observado", "sha256:aaaaaaaaaaaa1");
  grafo.nodo(nodos.host("afuera.test"), "sha256:fuera");
  grafo.arista(nodos.ruta("GET", "http://afuera.test/api/x/1", "observado")!, "accesible_por", ana, "inferido", "sha256:fuera", { estados: [200] });
  grafo.vaciar();
}

test("grafo vacío: cada consulta lo dice sin romper", () => {
  const { grafo } = armar();
  const vista = grafo.ver();
  assert.match(resumen(vista), /El grafo está vacío/);
  assert.match(faltantes(vista), /No falta nada concreto/);
  assert.match(vecinos(vista, "/api/x"), /No hay ningún nodo/);
  assert.match(caminos(vista, "a", "b"), /No hay ningún nodo/);
  assert.match(subgrafoHallazgo(vista, "abcd1234"), /No hay un hallazgo/);
  assert.equal(exportar(vista, "json").nodos, 0);
});

test("resolver: rutas con ids o con {n}, con o sin método, identidades, objetos y prefijos de hallazgo", () => {
  const { grafo } = armar();
  sembrar(grafo);
  grafo.nodo(nodos.hallazgo({ id: "abcd1234-0000-4000-8000-000000000000", title: "IDOR", state: "candidato", severity: "media", kind: "control de acceso", asset: `${BASE}/api/usuarios/2`, sessionId: "s1" }), "sha256:h");
  const vista = grafo.ver();
  assert.deepEqual(resolver(vista, "/api/usuarios/7").map((n) => n.etiqueta), ["GET /api/usuarios/{n}", "PUT /api/usuarios/{n}"]);
  assert.deepEqual(resolver(vista, "PUT /api/usuarios/{n}").map((n) => n.etiqueta), ["PUT /api/usuarios/{n}"]);
  assert.deepEqual(resolver(vista, `${BASE}/api/usuarios/3fa85f64-5717-4562-b3fc-2c963f66afa6`).map((n) => n.etiqueta).sort(), ["GET /api/usuarios/{n}", "PUT /api/usuarios/{n}"]);
  assert.equal(resolver(vista, "ana")[0]!.tipo, "identidad");
  assert.equal(resolver(vista, "3FA85F64-5717-4562-B3FC-2C963F66AFA6")[0]!.tipo, "objeto");
  assert.equal(resolver(vista, "abcd12")[0]!.tipo, "hallazgo");
});

test("faltantes: lo profundo primero, sólo dentro del alcance, estable y con clave", () => {
  const { grafo } = armar();
  sembrar(grafo);
  const vista = grafo.ver();
  const todos = calcularFaltantes(vista, { identidades: ["ana", "beto"] });
  assert.deepEqual(todos.map((item) => item.tipo), ["objeto", "identidad", "escritura", "parametro"]);
  assert.match(todos[0]!.accion, /pedirlo con beto/);
  assert.match(todos[1]!.accion, /probar con \(sin credenciales\) \(lo pidieron ana, beto\)/);
  assert.match(todos[2]!.accion, /PUT vistos en el contrato/);
  assert.ok(!todos.some((item) => item.donde.includes("afuera")), "lo de fuera del alcance no se propone");
  const texto = faltantes(vista, { identidades: ["ana", "beto"] });
  assert.equal(texto, faltantes(grafo.ver(), { identidades: ["ana", "beto"] }), "la misma consulta da el mismo texto");
  assert.match(faltantes(vista, { identidades: ["ana", "beto"], tipo: "escritura" }), /faltan\[1\]/);
  // La vista del modelo cuenta lo de afuera y no lo nombra; la del operador lo muestra marcado.
  assert.match(resumen(vista), /fuera del alcance o señuelos \(no se proponen\)/);
  assert.doesNotMatch(vecinos(vista, "ana"), /afuera/);
  assert.match(vecinos(vista, "ana", { operador: true }), /afuera\.test.*fuera del alcance/);
  assert.match(vecinos(vista, "http://afuera.test/api/x/1"), /fuera del alcance vigente/);
});

test("paginado y tope: muchas filas salen por páginas y ninguna salida pasa el tope", () => {
  const { grafo } = armar();
  for (let i = 0; i < 300; i++) grafo.arista(nodos.ruta("GET", `${BASE}/api/r${i}/1`, "observado", { estados: [200] })!, "accesible_por", nodos.identidad("ana"), "inferido", `sha256:${i}`, { estados: [200] });
  grafo.vaciar();
  const vista = grafo.ver();
  const primera = faltantes(vista, { identidades: ["ana", "beto"] });
  assert.match(primera, /página 1 de \d+ · siguiente: pagina 2/);
  const segunda = faltantes(vista, { identidades: ["ana", "beto"], pagina: 2 });
  assert.notEqual(primera, segunda);
  assert.ok(primera.length <= MAX_SALIDA && segunda.length <= MAX_SALIDA);
  assert.ok(vecinos(vista, "ana").length <= MAX_SALIDA);
  assert.ok(resumen(vista).length <= MAX_SALIDA);
});

test("caminos: el más corto en los dos sentidos, con estado y evidencia; sin camino, lo dice", () => {
  const { grafo } = armar();
  sembrar(grafo);
  const vista = grafo.ver();
  const texto = caminos(vista, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "beto");
  assert.match(texto, /^\[grafo · caminos/);
  assert.match(texto, /1\. 3fa85f64-5717-4562-b3fc-2c963f66afa6 —/);
  assert.match(texto, /beto \[(inferido|refutado) sha256:/);
  assert.match(caminos(vista, "ana", "PUT /api/usuarios/{n}"), /No hay camino/);
});

test("exportar: JSON entero, DOT y Mermaid válidos con lo de afuera marcado; Mermaid se recorta", () => {
  const { grafo } = armar();
  sembrar(grafo);
  const vista = grafo.ver();
  const json = JSON.parse(exportar(vista, "json").texto) as { nodos: Array<{ clave: string; alcance: string }>; aristas: unknown[] };
  assert.equal(json.nodos.find((n) => n.clave === "host:afuera.test")!.alcance, "fuera");
  assert.equal(json.aristas.length, vista.aristas.size);
  const dot = exportar(vista, "dot").texto;
  assert.match(dot, /^digraph grafo \{/);
  assert.match(dot, /n\d+ -> n\d+ \[label="accesible por"/);
  const mermaid = exportar(vista, "mermaid", 3);
  assert.match(mermaid.texto, /^flowchart LR/);
  assert.equal(mermaid.recortado, true);
  assert.doesNotMatch(mermaid.texto, /\{n\}/, "las llaves de la familia no rompen la sintaxis");
});

test("alimentación desde artefactos: code_crypto, web_source_pull, nmap y httpx; CVE cruzado; hipótesis de la memoria", () => {
  const { grafo, alimentador, artifacts, db, paths } = armar();
  const cripto = artifacts.put(JSON.stringify({ path: ".", archivos: 1, puntos: [{ file: "src/token.js", line: 3, kind: "secreto fijo", detail: "x", risk: "alto", fn: "firmar", snippet: "const k = '‹secreto›'", attack: "y" }, { file: "src/token.js", line: 9, kind: "hash", detail: "md5", risk: "medio", fn: "derivar", snippet: "", attack: "" }] }), "application/json", "code_crypto").hash;
  alimentador.trasHerramienta("code_crypto", { text: "…", details: { artefacto: cripto } });
  const fuente = artifacts.put(JSON.stringify({ pagina: `${BASE}/app`, carpeta: "fuente-web/lab.test", archivos: [{ file: "fuente-web/lab.test/web/app.js", url: `${BASE}/app.js`, kind: "js" }], api: [{ path: "/api/cupones/{id}", methods: ["POST"], keys: ["codigo", "monto"], object: true }], cripto: [] }), "application/json", "web_source_pull").hash;
  alimentador.trasHerramienta("web_source_pull", { text: "…", details: { artefacto: fuente } });
  const nmap = artifacts.put(JSON.stringify({ argv: [], stdout: `<host ><address addr="10.0.0.5"/><hostnames><hostname name="lab.test"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port></ports></host>` }), "application/json", "nmap").hash;
  alimentador.trasHerramienta("nmap_scan", { text: "…", details: { artefacto: nmap } });
  const httpx = artifacts.put(JSON.stringify({ argv: [], stdout: `{"url":"https://lab.test","status_code":200,"title":"Tienda","tech":["Express","PHP:8.1.2"]}\n` }), "application/json", "httpx").hash;
  alimentador.trasHerramienta("httpx_probe", { text: "…", details: { artefacto: httpx } });
  alimentador.cve({ cve: "CVE-2026-1111", tecnologia: "nginx", version: "1.24.0", severidad: "HIGH", cvss: 8.1, veredicto: "afectada" });
  const vault = new Vault(db, paths.records, paths.notes);
  const hip = vault.write({ type: "hipotesis", title: "Los cupones se pueden reusar", summary: "el monto lo manda el cliente" });
  alimentador.trasHerramienta("memory_write", { text: `Guardado ${hip.id} rev 1` }, vault);
  const vista = grafo.ver();
  assert.deepEqual(alimentador.errores, []);
  const secreto = vista.nodos.get("credencial:fuente src/token.js:3")!;
  assert.equal(secreto.atributos.funcion, "firmar");
  assert.ok(vista.aristas.has("artefacto:funcion:src/token.js#firmar\nexpone\ncredencial:fuente src/token.js:3"));
  assert.ok(vista.aristas.has("artefacto:funcion:src/token.js#derivar\npertenece_a\nartefacto:archivo:src/token.js"));
  const cupones = vista.nodos.get(`ruta:POST ${BASE}/api/cupones/{n}`)!;
  assert.equal(cupones.estado, "inferido");
  assert.ok(vista.nodos.has(`parametro:${BASE}/api/cupones/{n}|cuerpo|monto`));
  assert.ok(vista.nodos.has("servicio:https://lab.test:443"));
  assert.ok([...vista.nodos.keys()].some((clave) => clave.startsWith("tecnologia:php@8.1.2")));
  const cve = vista.aristas.get("tecnologia:nginx@1.24.0\nexpone\ncve:CVE-2026-1111")!;
  assert.equal(cve.estado, "inferido");
  assert.equal(cve.procedencia.evidencia, "cve_cruces:s1:CVE-2026-1111");
  assert.equal(vista.nodos.get(`hipotesis:memoria:${hip.id}`)!.estado, "inferido");
  // Una operación importada fuera de una herramienta queda con su propio artefacto como evidencia.
  alimentador.operacion({ url: `${BASE}/api/export`, method: "GET" });
  const ruta = grafo.ver().nodos.get(`ruta:GET ${BASE}/api/export`)!;
  assert.match(ruta.origen.evidencia, /^sha256:/);
  assert.equal(artifacts.producer(ruta.origen.evidencia), "grafo:operacion");
});

test("escaladas con nodos reales: open redirect + flujo OAuth observado → robo de código, con rutas y evidencia", () => {
  const { grafo } = armar();
  const salir = nodos.ruta("GET", `${BASE}/r?url=https://x`, "observado", { redirige: true, redireccion_por: "url" })!;
  grafo.nodo(salir, "sha256:11111111111122");
  grafo.arista(nodos.ruta("GET", `${BASE}/auth/callback`, "observado")!, "acepta", nodos.parametro(`${BASE}/auth/callback?code=1`, "consulta", "redirect_uri", "observado")!, "observado", "sha256:22222222222233");
  const finding = { id: "f0000000-0000-4000-8000-000000000001", rev: 1, state: "candidato", title: "Open redirect en /r", kind: "open redirect", severity: "media", asset: `${BASE}/r`, summary: "", evidence: [], limits: "", decidedBy: "agente", reason: "", sessionId: "s1", createdAt: "", updatedAt: "" } as Finding;
  grafo.nodo(nodos.hallazgo(finding), "sha256:11111111111122");
  grafo.arista(nodos.hallazgo(finding), "observado_en", salir, "observado", "sha256:11111111111122");
  const vista = grafo.ver();
  const propuestas = propuestasDeEscalada(vista, finding, alcance);
  assert.equal(propuestas.length, 1);
  assert.match(propuestas[0]!, /open redirect \(GET \/r redirige según \?url, sha256:111111111111\)/);
  assert.match(propuestas[0]!, /flujo OAuth \(GET \/auth\/callback \(observada, sha256:222222222222\)\)/);
  assert.match(subgrafoHallazgo(vista, "f0000000", { propuestas: (nodo) => propuestasDeEscalada(vista, nodo.id === finding.id ? finding : undefined, alcance) }), /escaladas propuestas[\s\S]*robo|redirect_uri/);
});

test("cadena con evidencia: cada arista «habilita» con su estado, sus evidencias y dónde se observó cada eslabón", () => {
  const { grafo } = armar();
  const a = { id: "a0000000-0000-4000-8000-000000000001", title: "Open redirect", state: "candidato", severity: "media", kind: "open redirect", asset: `${BASE}/r`, sessionId: "s1" } as Finding;
  const b = { id: "b0000000-0000-4000-8000-000000000002", title: "Robo de código", state: "verificado", severity: "alta", kind: "oauth", asset: `${BASE}/auth`, sessionId: "s1" } as Finding;
  grafo.arista(nodos.hallazgo(a), "observado_en", nodos.ruta("GET", `${BASE}/r`, "observado")!, "observado", "sha256:aaaaaaaaaaaa9");
  grafo.arista(nodos.hallazgo(a), "habilita", nodos.hallazgo(b), "verificado", "hallazgo:b@2", { evidencias: ["sha256:aaaaaaaaaaaa", "sha256:bbbbbbbbbbbb"] });
  const lineas = cadenaConEvidencia(grafo.ver(), b.id);
  assert.equal(lineas.length, 1);
  assert.match(lineas[0]!, /a0000000 «Open redirect» \(candidato\) habilita b0000000 «Robo de código» \(verificado\) · arista verificada|arista verificado/);
  assert.match(lineas[0]!, /evidencia sha256:aaaaaaaaaaaa, sha256:bbbbbbbbbbbb · el primero se observó en GET \/r sha256:aaaaaaaaaaaa/);
});

test("/grafo y cyber grafo: resumen, faltantes, vecinos, caminos, hallazgo y exportar; sin sesión abierta, en sólo lectura", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "grafo-daemon-"));
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), autoResume: false });
  await daemon.listen();
  const client = await connectDaemon(cwd, { spawn: false });
  try {
    const snapshot = await client.attach({ model: "faux" });
    const engine = daemon.hosts.get(snapshot.sessionId)!.engine;
    await client.view("scope", "add lab.test");
    sembrar(engine.grafo!);
    const resumenTexto = (await client.view("grafo", "")).join("\n");
    assert.match(resumenTexto, /^nodos \d+/);
    assert.match((await client.view("grafo", "faltantes")).join("\n"), /faltan\[/);
    assert.match((await client.view("grafo", "vecinos ana")).join("\n"), /afuera\.test.*fuera del alcance/, "el operador ve lo de afuera, marcado");
    assert.match((await client.view("grafo", "caminos ana → beto")).join("\n"), /1\. ana/);
    const exportado = (await client.view("grafo", "exportar dot")).join("\n");
    const ruta = /: (\/\S+\.dot)/.exec(exportado)![1]!;
    assert.ok(existsSync(ruta) && ruta.startsWith(join(cwd, "cyber-informes")));
    assert.match(readFileSync(ruta, "utf8"), /^digraph/);
    assert.equal(comandoGrafo(engine.grafo!.ver(), "exportar xml")[0], "Formatos: json, dot, mermaid. Uso: /grafo [resumen | faltantes [tipo] | vecinos <nodo> | caminos <desde> → <hasta> | hallazgo <id> | exportar json|dot|mermaid] [página N]");
  } finally {
    await client.leave();
    await daemon.close();
  }
  // La CLI con el daemon sin la sesión abierta lee la base en sólo lectura.
  const otro = new Daemon({ cwd, resolve: () => resolveProvider("faux"), autoResume: false });
  await otro.listen();
  const cli = await connectDaemon(cwd, { spawn: false });
  try {
    assert.match((await cli.view("grafo", "")).join("\n"), /^nodos \d+/);
  } finally {
    await cli.leave();
    await otro.close();
  }
});

test("rutas canónicas: mayúsculas, barras de más, ;jsessionid y cualquier id (número, UUID, ObjectId) son la misma familia; repetir suma vistas", () => {
  const { grafo } = armar();
  const formas = [`${BASE}/API/Usuarios/7/`, `${BASE}//api/usuarios/8;jsessionid=abc`, `${BASE}/api/usuarios/3fa85f64-5717-4562-b3fc-2c963f66afa6`, `${BASE}/api/usuarios/65f1a2b3c4d5e6f7a8b90001?x=1`];
  for (const [i, url] of formas.entries()) grafo.nodo(nodos.ruta("get", url, "observado")!, `sha256:${i}`);
  grafo.nodo(nodos.ruta("GET", formas[0]!, "observado")!, "sha256:otra-vez");
  const rutas = grafo.ver().deTipo("ruta");
  assert.deepEqual(rutas.map((n) => n.clave), [`ruta:GET ${BASE}/api/usuarios/{n}`]);
  assert.equal(rutas[0]!.vistas, 5);
  assert.equal(rutas[0]!.atributos.con_id, true);
  // Otro método u otro origen es otro nodo.
  grafo.nodo(nodos.ruta("PUT", formas[0]!, "observado")!, "sha256:put");
  grafo.nodo(nodos.ruta("GET", "https://lab.test/api/usuarios/1", "observado")!, "sha256:https");
  assert.equal(grafo.ver().deTipo("ruta").length, 3);
});

test("faltantes por identidad: no propone HEAD ni OPTIONS con otra identidad", () => {
  const { grafo } = armar();
  for (const metodo of ["HEAD", "OPTIONS", "GET"]) grafo.arista(nodos.ruta(metodo, `${BASE}/api/pedidos/1`, "observado")!, "accesible_por", nodos.identidad("ana"), "inferido", `sha256:${metodo}`, { estados: [200] });
  const pendientes = calcularFaltantes(grafo.ver(), { identidades: ["ana", "beto"] }).filter((item) => item.tipo === "identidad");
  assert.deepEqual(pendientes.map((item) => item.donde), ["GET /api/pedidos/{n}"]);
});
