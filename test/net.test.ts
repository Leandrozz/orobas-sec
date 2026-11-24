import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { exec, which } from "../src/exec.ts";
import { HttpClient, summarize } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-"));

test("ejecutor: sin shell, entorno filtrado, timeout sobre el grupo, salida acotada y cancelación", async () => {
  process.env.CYBER_SECRETO_TEST = "no-debe-verse";
  const echo = await exec({ argv: ["sh", "-c", 'printf "%s|%s|%s" "$1" "$CYBER_SECRETO_TEST" "$PERMITIDA"', "x", "a b; echo inyectado"], env: { PERMITIDA: "si" } });
  assert.equal(echo.stdout, "a b; echo inyectado||si"); // el argumento llega literal; la variable no permitida no viaja
  assert.equal(echo.exitCode, 0);
  delete process.env.CYBER_SECRETO_TEST;
  await assert.rejects(exec({ argv: ["binario-inexistente-xyz"] }), /No encuentro el binario/);
  assert.equal(which("sh")?.endsWith("/sh"), true);

  // Timeout: mata también al nieto que dejó el shell.
  const slow = await exec({ argv: ["sh", "-c", "sleep 30 & echo empieza; wait"], timeoutMs: 300 });
  assert.equal(slow.timedOut, true);
  assert.match(slow.stdout, /empieza/);
  assert.ok(slow.durationMs < 5000);

  const big = await exec({ argv: ["sh", "-c", "yes | head -c 100000"], maxOutputBytes: 1000 });
  assert.equal(big.truncated, true);
  assert.equal(big.stdout.length, 1000);

  const controller = new AbortController();
  const pending = exec({ argv: ["sleep", "30"], signal: controller.signal });
  setTimeout(() => controller.abort(), 50);
  const cancelled = await pending;
  assert.equal(cancelled.cancelled, true);
  assert.equal(cancelled.exitCode, null);
});

test("http: alcance por nombre y por IP resuelta, redirecciones validadas, identidades ocultas y artefacto completo", async () => {
  const cwd = tmp();
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const server = createServer((req, res) => {
    if (req.url === "/redir") return void res.writeHead(302, { location: "http://127.0.0.1:1/privado" }).end();
    if (req.url === "/redir-ok") return void res.writeHead(302, { location: "/final" }).end();
    if (req.url === "/grande") return void res.end("x".repeat(5000));
    res.writeHead(200, { "content-type": "application/json", "set-cookie": "s=1" });
    res.end(JSON.stringify({ path: req.url, auth: req.headers.authorization ?? null, method: req.method }));
  });
  await new Promise<void>((resolve) => server.listen(0, resolve)); // todas las interfaces: localhost puede resolver a ::1
  const port = (server.address() as any).port;
  const base = `http://127.0.0.1:${port}`;
  let scope: Scope | undefined;
  const client = new HttpClient(artifacts, () => scope);
  try {
    // Sin alcance, nada sale.
    const blocked = await client.send({ url: `${base}/x` });
    assert.match(blocked.error!, /Fuera del alcance: No hay alcance/);
    assert.ok(artifacts.find(blocked.artifact)); // el intento también queda registrado

    scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
    client.setIdentity({ name: "comprador", headers: { authorization: "Bearer secreto-comprador" } });
    const ok = await client.send({ method: "POST", url: `${base}/api/pedidos`, body: "{}" }, "comprador");
    assert.equal(ok.response!.status, 200);
    assert.match(ok.response!.body, /"auth":"Bearer secreto-comprador"/); // el servidor sí recibió la credencial
    assert.equal(ok.request.headers.authorization, "<identidad comprador>"); // el resumen no la expone
    assert.deepEqual(ok.resolved, ["127.0.0.1"]);
    const stored = JSON.parse(artifacts.read(ok.artifact).toString());
    assert.equal(stored.request.headers.authorization, "<identidad comprador>");
    assert.match(summarize(ok), /h2 POST .*\/api\/pedidos[\s\S]*HTTP 200[\s\S]*set-cookie: s=1/);
    await assert.rejects(client.send({ url: `${base}/x` }, "nadie"), /No existe la identidad/);

    // Redirección hacia un destino fuera del alcance: no se sigue (ese salto nunca sale) y no es un error:
    // la respuesta es la 3xx y el resumen dice a dónde iba.
    const redir = await client.send({ url: `${base}/redir`, followRedirects: true });
    assert.deepEqual(redir.redirects, []);
    assert.equal(redir.error, undefined);
    assert.equal(redir.response!.status, 302);
    assert.equal(redir.notFollowed, "http://127.0.0.1:1/privado");
    assert.match(summarize(redir), /fuera del alcance a http:\/\/127\.0\.0\.1:1\/privado: no se siguió/);
    assert.ok(!client.log.some((entry) => entry.url.startsWith("http://127.0.0.1:1/")), "el salto fuera del alcance no se pidió");
    const redirOk = await client.send({ url: `${base}/redir-ok`, followRedirects: true });
    assert.equal(redirOk.response!.status, 200);
    assert.match(redirOk.response!.body, /"path":"\/final"/);
    // Sin seguir: la redirección se informa.
    const noFollow = await client.send({ url: `${base}/redir` });
    assert.equal(noFollow.response!.status, 302);

    // Cuerpo acotado para el modelo, completo en el artefacto.
    const big = await client.send({ url: `${base}/grande`, maxBodyBytes: 100 });
    assert.equal(big.response!.truncated, true);
    assert.equal(big.response!.bodyBytes, 5000);
    assert.match(summarize(big), /\(truncado\)/);

    // Un nombre público autorizado que resuelve a una IP privada no listada se frena (DNS simulado: los tests no salen).
    scope = { ...scope, include: [parseRule("app.example.com")] };
    client.lookupHost = async () => ["127.0.0.1"];
    const dns = await client.send({ url: `http://app.example.com:${port}/` });
    assert.match(dns.error!, /resuelve a la dirección privada 127\.0\.0\.1/);
    client.lookupHost = undefined;
    // localhost es esta máquina: con «localhost» en el alcance, su propia resolución a 127.0.0.1 o ::1 no lo frena
    // (antes daba «localhost resuelve a la dirección privada»; reporte de laboratorios locales del 22/11).
    scope = { ...scope, include: [parseRule("localhost")] };
    assert.equal((await client.send({ url: `http://localhost:${port}/` })).response!.status, 200);
  } finally {
    server.close();
    db.close();
  }
});

test("cobertura: sondeo por lista con contador y tope, evidencia por id corto, y el harness objeta un cierre con cobertura pendiente", async () => {
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const seen: string[] = [];
  const server = createServer((req, res) => {
    seen.push(req.url ?? "");
    if (req.url === "/api/items/1" && req.method !== "GET") return void res.writeHead(405, { allow: "GET" }).end();
    if (req.url === "/robots.txt") return void res.end("User-agent: *");
    if (req.url?.startsWith("/api/")) return void res.writeHead(200, { "content-type": "application/json" }).end("{}");
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider, httpLimit: 12 });
  engine.scope.edit({ include: [`${base}/`] });
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  try {
    provider.faux!.queue = [
      // Dos ids de la misma familia: con uno solo la cobertura no acepta cerrar control de acceso.
      call("http_probe", { urls: [`${base}/api/items/1`, `${base}/api/items/2`], methods: ["GET", "PUT"] }), // 4 peticiones
      // Quiere cerrar con categorías pendientes: el harness objeta.
      { text: "Terminé: la API es de sólo lectura." },
      call("finding_record", { state: "candidato", title: "Recurso expuesto", kind: "exposición", asset: `${base}/api/items`, summary: "200 sin credenciales", evidence: ["h2"] }),
      call("coverage_mark", { category: "control de acceso", state: "cubierta", note: "PUT rechazado con 405 en items/1" }),
      call("http_probe", { urls: Array.from({ length: 9 }, (_, i) => `${base}/api/p${i}`) }), // 9 > las 8 que quedan
      call("coverage_mark", { category: "autenticación", state: "cubierta", note: "no vi login" }), // sin un POST a login no se acepta
      // Rutas que borran datos: el sondeo las omite sin enviar nada y lo dice.
      call("http_probe", { urls: [`${base}/delete?uuid=1`, `${base}/clear_history/1`, `${base}/api/items`] }),
      // Con el tope agotado el harness ya no objeta: el turno termina acá.
      { text: "Cierro." },
    ];
    await engine.send("Evaluá la API");
    const tools = engine.agent.messages.filter((m) => m.role === "tool") as Array<{ content: string; isError?: boolean }>;
    // Tabla compacta con los cuatro intercambios, código y contador.
    assert.match(tools[0]!.content, /h1\s+GET\s+.*\/api\/items\/1\s+200/);
    assert.match(tools[0]!.content, /PUT\s+.*\/api\/items\/1\s+405.*allow: GET/);
    assert.match(tools[0]!.content, /peticiones HTTP: 4 · quedan 8/);
    // La objeción llegó como mensaje de sistema y nombró una sola acción, con las categorías que siguen sin marcar.
    const objections = engine.agent.messages.filter((m) => m.role === "user" && String(m.content).startsWith("[sistema] Antes de cerrar"));
    assert.equal(objections.length, 1);
    assert.match(String(objections[0]!.content), /falta una cosa en la cobertura \(«reconocimiento»\): se probaron menos de cinco rutas \(1\): una sola llamada a http_probe con las habituales que faltan \(\/robots\.txt/);
    assert.match(String(objections[0]!.content), /marcá «reconocimiento» como «limitada» con una nota corta/);
    assert.match(String(objections[0]!.content), /Siguen sin marcar: autenticacion, control de acceso/);
    assert.doesNotMatch(String(objections[0]!.content), /deteccion/, "sin modo purple, «deteccion» no queda pendiente");
    assert.match(String(objections[0]!.content), /quedan 8/);
    // La evidencia por id corto se resolvió al hash del artefacto.
    assert.match(tools[1]!.content, /Registrado .* como candidato/);
    const finding = engine.findings.list()[0]!;
    assert.equal(finding.evidence[0], engine.http.hashOf("h2"));
    assert.match(tools[2]!.content, /control de acceso: cubierta\. Pendientes: reconocimiento, autenticacion, inyeccion/);
    // El tope de peticiones corta dentro del sondeo: 8 salieron, la novena no.
    assert.equal(engine.http.count, 12);
    assert.match(tools[3]!.content, /Tope de peticiones alcanzado \(12\)/);
    assert.match(tools[3]!.content, /quedan 0/);
    assert.match(tools[4]!.content, /No se marca «autenticacion» como cubierta: no hubo ningún POST a una ruta de login/);
    // Las rutas que borran datos se omiten sin enviar nada y se avisa; el resto de la lista sigue.
    assert.ok(!tools[5]!.isError);
    assert.match(tools[5]!.content, /omitidas 2 combinaciones .*\/delete\?uuid=1, .*\/clear_history\/1/);
    assert.ok(!seen.some((url) => url.startsWith("/delete") || url.startsWith("/clear_history")));
    assert.equal(engine.agent.messages.at(-1)!.role, "assistant");
    assert.equal(provider.faux!.queue.length, 0);
    assert.match(engine.coverage.view(engine.sessionId).join("\n"), /✓ control de acceso: PUT rechazado/);
    assert.match(engine.coverage.view(engine.sessionId).join("\n"), /\/api\/items\/\{n\}\s+GET,PUT\s+→ 200,405/);
  } finally {
    engine.close();
    server.close();
  }
});
