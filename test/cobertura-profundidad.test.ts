import "./datos-tmp.ts";
// Reglas de cobertura que salieron de la primera ronda del benchmark CVE: un desafío de
// autenticación declarado por el servidor hay que intentarlo, y un id ajeno que ya se vio
// hay que probarlo en escritura antes de dar por cubierto el control de acceso.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { Coverage } from "../src/coverage.ts";
import { HttpClient } from "../src/http.ts";
import { digestHeader } from "../src/probes.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

test("cobertura: exige intentar el desafío de autenticación y escribir con el id ajeno", async () => {
  const server = createServer((req, res) => {
    if (req.url === "/privado") {
      if (req.headers.authorization) return void res.writeHead(200).end("contenido");
      return void res.writeHead(401, { "www-authenticate": 'Digest realm="oficina", nonce="abc", qop="auth"' }).end();
    }
    if (req.url === "/api/items/1") return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    if (req.url === "/api/items/2") return void res.writeHead(403).end();
    if (req.url === "/api/items/1/mover") return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    if (req.url === "/carpeta") return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    if (req.url === "/carpeta/privada") return void res.writeHead(403).end();
    // Una aplicación de una sola página responde 200 HTML a cualquier ruta, y /api es un prefijo, no un recurso.
    if (req.url === "/app") return void res.writeHead(200, { "content-type": "text/html" }).end("<html></html>");
    if (req.url === "/app/admin") return void res.writeHead(403).end();
    if (req.url === "/api") return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    if (req.url === "/api/users") return void res.writeHead(403).end();
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-cob-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "prueba", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  const coverage = new Coverage(db, http);
  try {
    await http.send({ url: `${base}/privado` });
    await http.send({ url: `${base}/api/items/1` });
    await http.send({ url: `${base}/api/items/2` });

    // El servidor declaró una puerta y nadie la tocó.
    const untried = coverage.unansweredChallenges();
    assert.deepEqual(untried, [{ path: "/privado", challenge: "digest" }]);
    assert.match(coverage.minimumEvidence("autenticacion")!, /desafío de autenticación sin intentar \(digest en \/privado\)/);

    // El id 2 existe y la cuenta no lo ve: eso no dice nada de las otras operaciones.
    assert.deepEqual(coverage.foreignIds(), [{ path: "/api/items/{n}", id: "2", status: 403 }]);
    assert.equal(coverage.wroteWithForeignId(), false);
    coverage.mark("s", "control de acceso", "pendiente", "");
    await http.send({ url: `${base}/api/items/1`, method: "PATCH" });
    assert.match(coverage.minimumEvidence("control de acceso")!, /ninguna escritura llevó uno/);
    // La objeción dice una sola acción, la más profunda: escribir con el id ajeno.
    assert.match(coverage.objection("s", 4)!, /^\[sistema\] Antes de cerrar falta una cosa en la cobertura \(«control de acceso»\): viste ids que no son de tu cuenta \(2 en \/api\/items\/\{n\} → 403\) pero ninguna escritura llevó uno/);

    // Una escritura que lleva el id ajeno en el cuerpo ya alcanza para dejar de objetar eso.
    await http.send({ url: `${base}/api/items/1/mover`, method: "POST", body: JSON.stringify({ item_id: 2 }) });
    assert.equal(coverage.wroteWithForeignId(), true);
    assert.ok(!/ids que no son de tu cuenta/.test(coverage.objection("s", 5) ?? ""));

    // Un hijo denegado dentro de un padre permitido pide probar las operaciones del padre.
    await http.send({ url: `${base}/carpeta` });
    await http.send({ url: `${base}/carpeta/privada` });
    assert.deepEqual(coverage.deniedInsideAllowed(), [{ allowed: "/carpeta", denied: "/carpeta/privada", status: 403 }]);
    assert.match(coverage.objection("s", 6)!, /recurso denegado \(\/carpeta\/privada → 403\) dentro de uno permitido \(\/carpeta\)/);
    await http.send({ url: `${base}/carpeta`, method: "POST" });
    assert.deepEqual(coverage.deniedInsideAllowed(), []);

    // Una página HTML o un prefijo de API pelado no son padres con «operaciones sobre su contenido».
    await http.send({ url: `${base}/app` });
    await http.send({ url: `${base}/app/admin` });
    await http.send({ url: `${base}/api` });
    await http.send({ url: `${base}/api/users` });
    assert.deepEqual(coverage.deniedInsideAllowed(), []);

    // Responder el desafío lo saca de la lista: la cobertura mira el tráfico, no lo que se diga.
    await http.send({ url: `${base}/privado`, headers: { authorization: digestHeader('Digest realm="oficina", nonce="abc", qop="auth"', "GET", `${base}/privado`, "desconocido", "", "") } });
    assert.deepEqual(coverage.unansweredChallenges(), []);
  } finally {
    db.close();
    server.close();
  }
});

test("digest: firma con la contraseña o con el HA1 guardado", () => {
  const challenge = 'Digest realm="oficina", nonce="abc", qop="auth", algorithm="MD5"';
  const conClave = digestHeader(challenge, "GET", "http://x/privado", "ana", "secreta");
  const conHa1Vacio = digestHeader(challenge, "GET", "http://x/privado", "ana", "", "");
  assert.match(conClave, /^Digest username="ana", realm="oficina", nonce="abc", uri="\/privado", response="[0-9a-f]{32}"/);
  assert.match(conClave, /qop=auth, nc=00000001, cnonce="[0-9a-f]{16}"/);
  // El secreto vacío de un htdigest no es el hash de una contraseña vacía: son firmas distintas.
  const respuesta = (header: string) => /response="([0-9a-f]+)"/.exec(header)![1];
  assert.notEqual(respuesta(conHa1Vacio), respuesta(digestHeader(challenge, "GET", "http://x/privado", "ana", "")));
});

test("path_probe: la forma de la ruta cambia quién autoriza", async () => {
  // El servidor rechaza la escritura canónica y la acepta con barra final: dos capas que
  // normalizan distinto. Es la clase de File Browser y de Traccar.
  const server = createServer((req, res) => {
    if (req.method === "PATCH" && req.url === "/carpeta/") return void res.writeHead(200).end("copiada");
    if (req.method === "PATCH") return void res.writeHead(403).end();
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-path-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "prueba", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  const coverage = new Coverage(db, http);
  const { createProbeTools } = await import("../src/probes.ts");
  const probe = createProbeTools({ http, artifacts: new Artifacts(db, join(cwd, "artifacts")) } as any).find((tool: { name: string }) => tool.name === "path_probe")!;
  try {
    // Antes de variar, la cobertura reclama justamente esto.
    await http.send({ url: `${base}/carpeta`, method: "PATCH" });
    assert.deepEqual(coverage.rejectedWritesWithoutVariants(), ["/carpeta"]);

    const result = await probe.execute({ url: `${base}/carpeta`, method: "PATCH" }, new AbortController().signal);
    const text = typeof result === "string" ? result : result.text;
    assert.match(text, /original {2}\/carpeta {2}403/);
    assert.match(text, /DISTINTA {2}\/carpeta\/ {2}200/);
    assert.match(text, /la autorización depende de la forma del texto/);
    // Ya probó otra forma del mismo recurso: deja de reclamarla.
    assert.deepEqual(coverage.rejectedWritesWithoutVariants(), []);
    // Una barra final en otra ruta cualquiera no cuenta como haber variado esta.
    await http.send({ url: `${base}/otra/`, method: "PATCH" });
    assert.deepEqual(coverage.rejectedWritesWithoutVariants(), ["/otra/"]);
  } finally {
    db.close();
    server.close();
  }
});

test("cobertura: con un solo id probado por familia no se cierra control de acceso", async () => {
  // El agente que pide sólo su propio recurso no sabe qué existe ni qué le niegan: la regla de
  // ids ajenos no tiene de qué agarrarse hasta que haya mirado vecinos.
  const server = createServer((req, res) => {
    if (req.url === "/api/pedidos/1") return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    if (req.url === "/api/pedidos/2") return void res.writeHead(403).end();
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-ids-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "prueba", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  const coverage = new Coverage(db, http);
  try {
    await http.send({ url: `${base}/api/pedidos/1` });
    await http.send({ url: `${base}/api/pedidos/1`, method: "PATCH" });
    assert.deepEqual(coverage.familiesWithOneId(), ["/api/pedidos/{n}"]);
    assert.match(coverage.minimumEvidence("control de acceso")!, /sólo probaste un id en cada familia/);
    assert.match(coverage.objection("s", 2)!, /falta una cosa en la cobertura \(«control de acceso»\): sólo probaste un id .*pedí un segundo id de \/api\/pedidos\/\{n\}/);

    // Las formas de ruta de path_probe no son familias nuevas: siguen siendo la misma, con un solo id.
    await http.send({ url: `${base}//api/pedidos/1` });
    await http.send({ url: `${base}/api;x/pedidos/1` });
    await http.send({ url: `${base}/API/pedidos/1/` });
    assert.deepEqual(coverage.familiesWithOneId(), ["/api/pedidos/{n}"]);

    // Una familia que sólo dio 404 no dice que exista un recurso: no se exige otro id ahí.
    await http.send({ url: `${base}/api/pedidos/1/items` });
    assert.deepEqual(coverage.familiesWithOneId(), ["/api/pedidos/{n}"]);
    await http.send({ url: `${base}/api/pedidos/2/items` });
    assert.deepEqual(coverage.familiesWithOneId(), ["/api/pedidos/{n}"]);

    // Con el vecino pedido, la queja pasa a ser la que corresponde: no lo probó en escritura.
    await http.send({ url: `${base}/api/pedidos/2` });
    assert.deepEqual(coverage.familiesWithOneId(), []);
    assert.match(coverage.minimumEvidence("control de acceso")!, /ninguna escritura llevó uno/);
  } finally {
    db.close();
    server.close();
  }
});

test("http_request: la guarda de borrado también cubre la petición suelta", async () => {
  // La guarda sólo estaba en el sondeo por lista y dos corridas del benchmark se perdieron
  // porque el agente llamó la ruta de borrado una por una.
  const cwd = mkdtempSync(join(tmpdir(), "cyber-guarda-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", at: new Date().toISOString(), notes: "prueba", include: [parseRule("http://127.0.0.1:9/")], exclude: [] };
  const artifacts = new Artifacts(db, join(cwd, "artifacts"));
  const http = new HttpClient(artifacts, () => scope);
  const { createNetTools } = await import("../src/toolbox.ts");
  const request = createNetTools({ http, artifacts, scope: () => scope }).find((tool) => tool.name === "http_request")!;
  const signal = new AbortController().signal;
  try {
    await assert.rejects(() => Promise.resolve(request.execute({ url: "http://127.0.0.1:9/clear_history/abc" }, signal)), /borra o vacía datos/);
    await assert.rejects(() => Promise.resolve(request.execute({ url: "http://127.0.0.1:9/api/items/1?action=delete" }, signal)), /borra o vacía datos/);
    // No se envió ninguna petición: la guarda corta antes del cliente HTTP.
    assert.equal(http.count, 0);
  } finally {
    db.close();
  }
});
