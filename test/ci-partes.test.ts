import "./datos-tmp.ts";
// Las partes de «cyber ci» por separado: huellas estables, inferencia de rutas de un PR, supresiones y comparación,
// el tapado de secretos, las salidas (SARIF contra el esquema oficial, JSON contra el propio, Markdown y JUnit) y el
// comentario del PR contra un doble de las API de GitHub y GitLab.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";
import { inferirCambios, normalizarDeclarada, rutaDeArchivo, rutasDelDiff } from "../src/ci/cambios.ts";
import { correrCi } from "../src/ci/cli.ts";
import { comentarGithub, comentarGitlab } from "../src/ci/comentario.ts";
import { resultadoSinCorrer } from "../src/ci/corrida.ts";
import { claseCanonica, destinoDe, huella, normalizarRuta } from "../src/ci/huella.ts";
import { armarJunit } from "../src/ci/junit.ts";
import { comparar, leerAnterior, leerSupresiones } from "../src/ci/linea-base.ts";
import { armarMarkdown, marcador, MAXIMO } from "../src/ci/markdown.ts";
import type { HallazgoCi, ResultadoCi } from "../src/ci/resultado.ts";
import { armarSarif } from "../src/ci/sarif.ts";
import { Tapador } from "../src/ci/tapado.ts";
import { parseRule } from "../src/scope.ts";
import { validar } from "./esquema-json.ts";
import { escribir, git, limpiar, repo } from "./ci-guion.ts";

after(limpiar);
const SARIF = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "sarif-schema-2.1.0.json"), "utf8"));
const ESQUEMA = JSON.parse(readFileSync(join(import.meta.dirname, "..", "distro", "ci", "orobas-ci-resultado.schema.json"), "utf8"));

test("huella: estable entre corridas y entornos, distinta para otra falla", () => {
  const destinos = [{ clave: "${PREVIEW_URL}", reglas: [parseRule("https://pr-12.preview.example.com")] }, { clave: "api", reglas: [parseRule("api.example.com:443")] }];
  assert.equal(destinoDe(destinos, "https://pr-12.preview.example.com/x"), "${PREVIEW_URL}");
  assert.equal(destinoDe(destinos, "https://api.example.com/x"), "api");
  assert.equal(destinoDe(destinos, "https://otro.example.com/x"), "?");
  assert.deepEqual(normalizarRuta("https://x/api/Usuarios/42/pedidos/3f2a9c1e-1d2b-4c3d-9e8f-0a1b2c3d4e5f?b=1&a=2"), { ruta: "/api/usuarios/{id}/pedidos/{id}", consulta: ["a", "b"] });
  assert.equal(normalizarRuta("/api/usuarios/{id}").ruta, normalizarRuta("/api/usuarios/7").ruta);
  assert.equal(normalizarRuta("/api/usuarios/:id").ruta, "/api/usuarios/{id}");
  assert.equal(normalizarRuta("/docs/informe-anual-de-la-empresa-2026").ruta, "/docs/informe-anual-de-la-empresa-2026");
  assert.equal(normalizarRuta("/t/a1b2c3d4e5f6g7h8i9j0k1").ruta, "/t/{id}");
  assert.equal(claseCanonica("IDOR", "lee pedidos ajenos").id, "control-de-acceso");
  assert.equal(claseCanonica("control de acceso", "x").cwe, 284);
  assert.equal(claseCanonica("inyección", "XSS reflejado en /buscar").id, "xss");
  assert.equal(claseCanonica("Asignación masiva", "rol admin").id, "asignacion-masiva");
  assert.equal(claseCanonica("algo raro", "sin palabras clave").id, "algo-raro");
  const a = huella({ destino: "web", clase: "xss", metodo: "get", ruta: "/buscar", consulta: ["q"] });
  assert.match(a, /^orobas:v1:[0-9a-f]{24}$/);
  assert.equal(a, huella({ destino: "web", clase: "xss", metodo: "GET", ruta: "/buscar", consulta: ["q"] }));
  for (const otra of [{ destino: "api" }, { clase: "inyeccion-sql" }, { metodo: "POST" }, { ruta: "/buscar2" }, { consulta: ["p"] }]) assert.notEqual(a, huella({ destino: "web", clase: "xss", metodo: "GET", ruta: "/buscar", consulta: ["q"], ...otra }));
});

test("cambios: rutas declaradas en el diff y enrutado por archivos", () => {
  const diff = [
    "+++ b/src/rutas.ts", "@@ -0,0 +1,3 @@", '+router.post("/api/pedidos/:id/pagar", pagar);', "+const x = 1;", "+app.get('/salud', ok)",
    "+++ b/app/views.py", "@@ -3,0 +4,2 @@", '+ @app.route("/admin/<int:id>")', '+    path("cuentas/<slug:nombre>/", vista)',
    "+++ b/src/Api.java", "@@ -9 +10 @@", '+  @GetMapping("/v1/facturas/{id}")',
    "+++ b/routes/web.php", "@@ -1 +1 @@", "+Route::delete('/perfil', [PerfilController::class, 'borrar']);",
    "+++ b/main.go", "@@ -1 +1 @@", '+\tr.Get("/items/{id}", h)',
    "+++ b/README.md", "@@ -1 +1 @@", '+app.get("/no-es-codigo")',
  ].join("\n");
  const rutas = rutasDelDiff(diff);
  assert.deepEqual(rutas.map((r) => [r.ruta, r.archivo, r.linea]), [
    ["/api/pedidos/{id}/pagar", "src/rutas.ts", 1], ["/salud", "src/rutas.ts", 3], ["/admin/{id}", "app/views.py", 4], ["/cuentas/{nombre}", "app/views.py", 5],
    ["/v1/facturas/{id}", "src/Api.java", 10], ["/perfil", "routes/web.php", 1], ["/items/{id}", "main.go", 1],
  ]);
  assert.equal(rutaDeArchivo("app/api/pedidos/[id]/route.ts"), "/api/pedidos/{id}");
  assert.equal(rutaDeArchivo("src/app/(tienda)/carrito/page.tsx"), "/carrito");
  assert.equal(rutaDeArchivo("pages/api/usuarios/[...slug].ts"), "/api/usuarios/{slug*}");
  assert.equal(rutaDeArchivo("pages/_app.tsx"), undefined);
  assert.equal(rutaDeArchivo("src/routes/blog/[slug]/+page.svelte"), "/blog/{slug}");
  assert.equal(rutaDeArchivo("server/api/carrito.post.ts"), "/api/carrito");
  assert.equal(rutaDeArchivo("src/lib/util.ts"), undefined);
  assert.equal(normalizarDeclarada("^cuentas/(?P<id>[0-9]+)/$"), "/cuentas/{id}");
});

test("cambios: con base y PR, sin PR, sin base, y lo que no se pudo inferir se dice", () => {
  const dir = repo({ "src/app.ts": "x\n", "src/util.ts": "y\n" });
  git(dir, "checkout", "-qb", "pr");
  escribir(dir, { "src/util.ts": "y\nz\n" });
  git(dir, "commit", "-qam", "sin rutas");
  const sinRutas = inferirCambios(dir, "si", "main", {});
  assert.equal(sinRutas.activo, false);
  assert.match(sinRutas.motivo, /no pude inferir rutas HTTP de los 1 archivo/);
  assert.deepEqual(sinRutas.sinRuta, ["src/util.ts"]);
  escribir(dir, { "src/app.ts": 'x\napp.put("/api/perfil", f)\n' });
  git(dir, "commit", "-qam", "ruta");
  const pr = inferirCambios(dir, "auto", undefined, { GITHUB_EVENT_NAME: "pull_request", GITHUB_BASE_REF: "main" });
  assert.equal(pr.activo, false, "origin/main no existe en este repo: lo dice");
  assert.match(pr.motivo, /no pude comparar con origin\/main/);
  const conBase = inferirCambios(dir, "auto", "main", { GITHUB_EVENT_NAME: "pull_request" }, ["/login"]);
  assert.equal(conBase.activo, true);
  assert.deepEqual(conBase.rutas.map((r) => r.ruta), ["/api/perfil", "/login"]);
  assert.equal(inferirCambios(dir, "auto", "main", {}).activo, false, "fuera de un PR, auto no se activa");
  assert.match(inferirCambios(dir, "si", undefined, {}).motivo, /no sé contra qué comparar/);
  assert.equal(inferirCambios(dir, "no", "main", { CI_MERGE_REQUEST_IID: "3" }).motivo, "apagado en la configuración");
});

test("supresiones: válidas, vencidas, a más de un año, y errores con línea", () => {
  const h = (n: number) => `orobas:v1:${String(n).repeat(24).slice(0, 24)}`;
  const dir = repo({ ".orobas/supresiones.yml": `version: 1\nsupresiones:\n  - huella: ${h(1)}\n    motivo: Riesgo aceptado por el equipo\n    autor: ana\n    vence: 2027-01-10\n  - huella: ${h(2)}\n    motivo: Riesgo aceptado por el equipo\n    autor: ana\n    vence: 2026-01-10\n  - huella: ${h(3)}\n    motivo: Riesgo aceptado por el equipo\n    autor: ana\n    vence: 2030-01-10\n` });
  const s = leerSupresiones(dir, ".orobas/supresiones.yml", undefined, new Date("2026-11-23T00:00:00Z"));
  assert.deepEqual([...s.vigentes.keys()], [h(1), h(3)]);
  assert.deepEqual(s.vencidas.map((x) => x.huella), [h(2)]);
  assert.equal(s.avisos.length, 1);
  assert.equal(leerSupresiones(dir, ".orobas/no.yml", undefined).existe, false);
  escribir(dir, { ".orobas/supresiones.yml": `version: 1\nsupresiones:\n  - huella: abc\n    motivo: corto\n    vence: 2026-02-30\n` });
  assert.throws(() => leerSupresiones(dir, ".orobas/supresiones.yml", undefined), (e: Error) => /supresiones\.yml:3:5: «supresiones\[0\]\.huella» tiene que ser la huella/.test(e.message) && /motivo» falta o es muy corto/.test(e.message) && /autor» falta/.test(e.message) && /vence» falta o no es una fecha/.test(e.message));
});

const hallazgo = (extra: Partial<HallazgoCi>): HallazgoCi => ({
  huella: "orobas:v1:aaaaaaaaaaaaaaaaaaaaaaaa", id: "f1", estado: "verificado", severidad: "alta", clase: { id: "control-de-acceso", nombre: "Control de acceso", cwe: 284 }, clase_declarada: "idor", titulo: "IDOR en pedidos", activo: "https://x.example.com/api/pedidos/2", destino: "web", metodo: "GET", ruta: "/api/pedidos/{id}", consulta: [], resumen: "Ana lee el pedido de beto.", limites: "", motivo: "reproducido", decidido_por: "verificador:1", comparacion: "nuevo", bloqueante: true,
  reproduccion: [{ metodo: "GET", url: "https://x.example.com/api/pedidos/2", cabeceras: { authorization: "<identidad ana>" }, identidad: "ana", curl: "curl -i 'https://x.example.com/api/pedidos/2' \\\n  -H \"authorization: ${IDENTIDAD_ANA}\"", respuesta: { estado: 200, cabeceras: { "content-type": "application/json" }, extracto: '{"id":2}', recortado: false }, artefacto: "sha256:1" }],
  evidencia: ["sha256:1"], ...extra,
});

function resultado(extra: Partial<ResultadoCi> = {}): ResultadoCi {
  const base = resultadoSinCorrer({ nombre: "web", modo: "evaluacion", version: "v1.2.3", estado: "hallazgos", motivo: "1 hallazgo verificado", inicio: Date.now() - 5000 });
  return { ...base, autorizacion: { huella: `sha256:${"b".repeat(32)}`, fuente: "OROBAS_CI_AUTORIZACION", archivo: ".orobas/ci.yml", huella_archivo: `sha256:${"c".repeat(32)}` }, resultado: { ...base.resultado, codigo: 1, estado: "hallazgos", bloqueantes: 1 }, hallazgos: [hallazgo({}), hallazgo({ huella: "orobas:v1:bbbbbbbbbbbbbbbbbbbbbbbb", id: "f2", estado: "candidato", severidad: "media", titulo: "Posible XSS", bloqueante: false, comparacion: "sin-anterior" })], ...extra };
}

test("comparación: nuevos, persisten, resueltos sólo con retest, y la anterior se valida", () => {
  const anterior = resultado({ hallazgos: [hallazgo({}), hallazgo({ huella: "orobas:v1:cccccccccccccccccccccccc", id: "f3" }), hallazgo({ huella: "orobas:v1:dddddddddddddddddddddddd", id: "f4" })] });
  const c = comparar([hallazgo({}), hallazgo({ huella: "orobas:v1:eeeeeeeeeeeeeeeeeeeeeeee", id: "f5" })], anterior, new Map([["orobas:v1:cccccccccccccccccccccccc", "arreglado"]]));
  assert.deepEqual(c.nuevos, ["orobas:v1:eeeeeeeeeeeeeeeeeeeeeeee"]);
  assert.deepEqual(c.persisten, ["orobas:v1:aaaaaaaaaaaaaaaaaaaaaaaa"]);
  assert.deepEqual(c.resueltos, ["orobas:v1:cccccccccccccccccccccccc"]);
  assert.deepEqual(c.sinConfirmar, ["orobas:v1:dddddddddddddddddddddddd"]);
  assert.equal(leerAnterior('{"formato":"otro"}').aviso?.includes("no es del formato"), true);
  assert.equal(leerAnterior("{roto").aviso?.includes("No pude leer"), true);
  assert.equal(leerAnterior(JSON.stringify(anterior)).anterior?.hallazgos.length, 3);
});

test("tapado: identidades, literales del entorno en sus formas y lo que el redactor reconoce", () => {
  const secreto = ["valor", "secreto", "del", "ci", "4f3e2d"].join("_");
  const t = new Tapador(undefined, [secreto]);
  for (const forma of [secreto, encodeURIComponent(`${secreto}/x`), JSON.stringify(`a"${secreto}`).slice(1, -1), Buffer.from(secreto).toString("base64")]) assert.ok(!t.texto(`antes ${forma} después`).includes(secreto.slice(0, 20)), forma);
  assert.match(t.texto("Authorization: Bearer abcdefghijklmnop"), /\[credencial omitida\]/);
  assert.match(t.texto('{"password":"hunter2hunter2"}'), /\[credencial omitida\]/);
  assert.ok(t.contiene(`x${secreto}`));
  assert.equal(t.final(`{"a":"${secreto}"}`), '{"a":"[credencial omitida]"}');
});

test("salidas: SARIF válido contra el esquema oficial, JSON contra el propio, Markdown con marcador y JUnit", () => {
  const r = resultado({ retest: [{ huella: "orobas:v1:ffffffffffffffffffffffff", titulo: "Viejo IDOR", severidad: "critica", clase: { id: "control-de-acceso", nombre: "Control de acceso", cwe: 284 }, resultado: "sin-confirmar", motivo: "no se pudo", bloqueante: false }] });
  assert.deepEqual(validar(ESQUEMA, r), []);
  const sarif = armarSarif(r, { archivoConfig: ".orobas/ci.yml", lineas: { web: 7 }, lineaAlcance: 5, candidatos: false });
  assert.deepEqual(validar(SARIF, sarif), []);
  const run = (sarif.runs as Array<Record<string, any>>)[0]!;
  assert.equal(run.results.length, 2, "el verificado y el conocido sin confirmar (el candidato no)");
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 7);
  assert.equal(run.results[0].webRequest.method, "GET");
  assert.equal(run.results[0].webResponse.statusCode, 200);
  assert.equal(run.results[1].properties.retest, "sin-confirmar");
  assert.equal(run.invocations[0].exitCode, 1);
  assert.equal(run.automationDetails.id, "orobas-ci/web/");
  const conCandidatos = armarSarif(r, { archivoConfig: ".orobas/ci.yml", lineas: {}, lineaAlcance: 5, candidatos: true });
  assert.deepEqual(validar(SARIF, conCandidatos), []);
  assert.equal((conCandidatos.runs as Array<Record<string, any>>)[0]!.results.filter((x: { kind: string }) => x.kind === "review").length, 1);
  // Una corrida que no evaluó también da un SARIF válido (sin resultados, con la notificación del error).
  const sinCorrer = resultadoSinCorrer({ nombre: "web", modo: "evaluacion", version: "0.1.0 (desarrollo)", estado: "configuracion", motivo: "Falta la autorización", inicio: Date.now() });
  assert.deepEqual(validar(ESQUEMA, sinCorrer), []);
  const vacio = armarSarif(sinCorrer, { archivoConfig: ".orobas/ci.yml", lineas: {}, lineaAlcance: 1, candidatos: false });
  assert.deepEqual(validar(SARIF, vacio), []);
  assert.equal((vacio.runs as Array<Record<string, any>>)[0]!.invocations[0].executionSuccessful, false);

  const md = armarMarkdown(r);
  assert.ok(md.startsWith(marcador("web")));
  assert.match(md, /✗ Falla: hallazgos verificados/);
  assert.match(md, /curl -i 'https:\/\/x\.example\.com\/api\/pedidos\/2'/);
  assert.match(md, /Candidatos sin verificar \(no bloquean\)/);
  assert.match(md, /Retest de hallazgos conocidos/);
  const largo = armarMarkdown(resultado({ hallazgos: Array.from({ length: 400 }, (_, k) => hallazgo({ id: `f${k}`, huella: `orobas:v1:${k.toString(16).padStart(24, "0")}`, resumen: "x".repeat(400) })) }));
  assert.ok(largo.length <= MAXIMO);
  assert.match(largo, /se cortó por su largo/);

  const junit = armarJunit(r);
  assert.match(junit, /^<\?xml version="1\.0" encoding="UTF-8"\?>\n<testsuites name="orobas-sec" tests="4" failures="1" errors="0" skipped="2"/);
  assert.equal((junit.match(/<testcase /g) ?? []).length, 4);
  assert.ok(!/<[^>]*&(?!amp;|lt;|gt;|quot;)/.test(junit), "XML escapado");
});

async function dobleApi(manejar: (metodo: string, url: string, cuerpo: string) => { estado: number; cuerpo: unknown }) {
  const pedidos: Array<{ metodo: string; url: string; cuerpo: string; auth?: string }> = [];
  const server = createServer((req, res) => {
    let cuerpo = "";
    req.on("data", (c) => (cuerpo += c));
    req.on("end", () => {
      pedidos.push({ metodo: req.method!, url: req.url!, cuerpo, auth: req.headers.authorization ?? (req.headers["private-token"] as string | undefined) });
      const r = manejar(req.method!, req.url!, cuerpo);
      res.writeHead(r.estado, { "content-type": "application/json" }).end(JSON.stringify(r.cuerpo));
    });
  });
  await new Promise<void>((fin) => server.listen(0, "127.0.0.1", fin));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, pedidos, cerrar: () => new Promise<void>((fin) => server.close(() => fin())) };
}

test("comentario en GitHub: crea uno, después edita el mismo (con paginado), y si no puede editar crea otro", async () => {
  const marca = marcador("web");
  const comentarios: Array<{ id: number; body: string; user: { type: string } }> = Array.from({ length: 100 }, (_, k) => ({ id: k + 1, body: `otro ${k}`, user: { type: "User" } }));
  let denegar = false;
  const api = await dobleApi((metodo, url, cuerpo) => {
    const pagina = Number(/[?&]page=(\d+)/.exec(url)?.[1] ?? 1);
    if (metodo === "GET") return { estado: 200, cuerpo: comentarios.slice((pagina - 1) * 100, pagina * 100) };
    if (metodo === "POST") {
      const nuevo = { id: comentarios.length + 1, body: JSON.parse(cuerpo).body, user: { type: "Bot" } };
      comentarios.push(nuevo);
      return { estado: 201, cuerpo: { id: nuevo.id, html_url: `https://github.example.test/c/${nuevo.id}` } };
    }
    if (denegar) return { estado: 403, cuerpo: { message: "Resource not accessible by integration" } };
    const id = Number(/comments\/(\d+)$/.exec(url)![1]);
    comentarios.find((c) => c.id === id)!.body = JSON.parse(cuerpo).body;
    return { estado: 200, cuerpo: { id, html_url: `https://github.example.test/c/${id}` } };
  });
  const token = ["prueba", "github", "token"].join("-");
  const env = { GITHUB_TOKEN: token, GITHUB_REPOSITORY: "duena/repo", GITHUB_API_URL: api.url };
  try {
    const creado = await comentarGithub({ cuerpo: `${marca}\nprimera`, marcador: marca, env, pr: 7 });
    assert.equal(creado.accion, "creado");
    const editado = await comentarGithub({ cuerpo: `${marca}\nsegunda`, marcador: marca, env, pr: 7 });
    assert.deepEqual([editado.accion, editado.id], ["editado", creado.id]);
    assert.equal(comentarios.filter((c) => c.body.startsWith(marca)).length, 1, "un solo comentario");
    assert.ok(api.pedidos.some((p) => p.url.includes("page=2")), "pagina hasta encontrarlo");
    assert.ok(api.pedidos.every((p) => p.auth === `Bearer ${token}`));
    denegar = true;
    assert.equal((await comentarGithub({ cuerpo: `${marca}\ntercera`, marcador: marca, env, pr: 7 })).accion, "creado");
    await assert.rejects(comentarGithub({ cuerpo: "x", marcador: marca, env: { GITHUB_REPOSITORY: "duena/repo" }, pr: 7 }), /Falta GITHUB_TOKEN/);
    await assert.rejects(comentarGithub({ cuerpo: "x", marcador: marca, env }), /No es un PR/);
    // Por la CLI: lee el resumen y el número del PR del evento.
    const dir = repo({ "orobas-ci/resumen.md": `${marca}\ndesde la cli`, "evento.json": JSON.stringify({ pull_request: { number: 7 } }) });
    denegar = false;
    const salida: string[] = [];
    assert.equal(await correrCi(["comentar", "-C", dir], { ...env, GITHUB_EVENT_PATH: join(dir, "evento.json") }, { salida: (t) => salida.push(t), error: (t) => salida.push(t) }), 0, salida.join("\n"));
    assert.match(salida.join("\n"), /Comentario editado: https:\/\/github\.example\.test\/c\//);
    assert.ok(!salida.join("\n").includes(token));
  } finally {
    await api.cerrar();
  }
});

test("comentario en GitLab: nota única por MR, editada con PUT", async () => {
  const notas: Array<{ id: number; body: string }> = [{ id: 1, body: "hola" }];
  const api = await dobleApi((metodo, url, cuerpo) => {
    if (metodo === "GET") return { estado: 200, cuerpo: notas };
    if (metodo === "POST") { notas.push({ id: 2, body: JSON.parse(cuerpo).body }); return { estado: 201, cuerpo: { id: 2 } }; }
    notas.find((n) => url.endsWith(`/${n.id}`))!.body = JSON.parse(cuerpo).body;
    return { estado: 200, cuerpo: { id: 2 } };
  });
  const env = { OROBAS_CI_GITLAB_TOKEN: "glt", CI_PROJECT_ID: "grupo/proyecto", CI_MERGE_REQUEST_IID: "4", CI_API_V4_URL: api.url };
  try {
    assert.equal((await comentarGitlab({ cuerpo: `${marcador("web")}\nuno`, marcador: marcador("web"), env })).accion, "creado");
    assert.equal((await comentarGitlab({ cuerpo: `${marcador("web")}\ndos`, marcador: marcador("web"), env })).accion, "editado");
    assert.equal(notas.length, 2);
    assert.ok(api.pedidos[0]!.url.startsWith("/projects/grupo%2Fproyecto/merge_requests/4/notes"));
    assert.equal(api.pedidos[0]!.auth, "glt");
  } finally {
    await api.cerrar();
  }
});

test("tope duro: sin presupuesto, la compactación del contexto no gasta (y con presupuesto sí resume)", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const { usdToPico } = await import("../src/money.ts");
  const carpetas: string[] = [];
  const armar = (budget: string) => {
    const provider = resolveProvider("faux");
    provider.model.cost = { input: 3, output: 9, cacheRead: 1, cacheWrite: 0 };
    const cwd = mkdtempSync(join(tmpdir(), "orobas-ci-compactar-"));
    carpetas.push(cwd);
    const engine = new Engine({ cwd, provider, budgetPico: usdToPico(budget), cveFeed: false });
    for (let k = 0; k < 12; k++) engine.agent.messages.push({ role: "user", content: `mensaje ${k} ${"x".repeat(400)}`, at: Date.now() });
    provider.faux!.queue.splice(0, provider.faux!.queue.length, { text: "Resumen de la conversación." });
    return { engine, provider };
  };
  const sin = armar("0.000001");
  assert.equal(await sin.engine.compact(), false);
  assert.equal(sin.provider.faux!.calls, 0, "no salió ninguna solicitud");
  await sin.engine.close();
  const con = armar("5");
  assert.equal(await con.engine.compact(), true);
  assert.equal(con.provider.faux!.calls, 1);
  await con.engine.close();
  for (const cwd of carpetas) rmSync(cwd, { recursive: true, force: true });
});
