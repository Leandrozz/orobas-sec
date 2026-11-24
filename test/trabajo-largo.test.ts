// Todas las sesiones de una carpeta comparten un daemon de un solo hilo: una búsqueda de código o un informe
// grandes no pueden dejar a las demás sin responder (incidentes: code_search sobre el home entero y un informe
// que leía y redactaba 395 MB de evidencia de forma sincrónica).
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { connectDaemon } from "../src/client.ts";
import { createCodeTools } from "../src/codigo.ts";
import { Daemon } from "../src/daemon.ts";
import { which } from "../src/exec.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { Ledger } from "../src/ledger.ts";
import { resolveProvider } from "../src/providers.ts";
import { ReportRedactor } from "../src/redact.ts";
import { generateReport } from "../src/report.ts";
import { ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const abort = new AbortController().signal;
const tmp = (name: string) => mkdtempSync(join(tmpdir(), `cyber-${name}-`));
const RG = !!which("rg");
/** Con ripgrep (si está instalado) y con el recorrido propio: los dos tienen que cumplir lo mismo. */
const MODES = [...(RG ? [{ name: "ripgrep", ripgrep: true }] : []), { name: "recorrido propio", ripgrep: false }];

function tools(cwd: string, ripgrep: boolean): Record<string, Tool> {
  return Object.fromEntries(createCodeTools({ cwd, ripgrep }).map((tool) => [tool.name, tool]));
}

/** Corre el trabajo con un timer cada 5 ms y devuelve la mayor demora entre disparos (lo que tardó el event loop en atender). */
async function lagDuring<T>(work: () => Promise<T>): Promise<{ result: T; lag: number; ms: number }> {
  const started = performance.now();
  let last = started;
  let lag = 0;
  const timer = setInterval(() => {
    const now = performance.now();
    lag = Math.max(lag, now - last);
    last = now;
  }, 5);
  try {
    const result = await work();
    lag = Math.max(lag, performance.now() - last);
    return { result, lag, ms: performance.now() - started };
  } finally {
    clearInterval(timer);
  }
}

function tree() {
  const cwd = tmp("busqueda");
  const files: Record<string, string> = {
    "src/app.ts": "const clave = 'aguja';\n",
    "src/sub/util.ts": "export const x = 'aguja';\n",
    "raiz.ts": "// aguja en la raíz\n",
    ".env": "AGUJA=1\n",
    ".cache/pesado.txt": "aguja en caché\n",
    ".github/workflows/ci.yml": "run: echo aguja\n",
    ".git/config": "aguja en git\n",
    ".cyber/secreto.txt": "aguja del harness\n",
    "node_modules/dep/index.js": "aguja en dependencia\n",
    "src/node_modules/otra/index.js": "aguja en dependencia anidada\n",
  };
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(join(cwd, path, ".."), { recursive: true });
    writeFileSync(join(cwd, path), content);
  }
  return cwd;
}

for (const mode of MODES) {
  test(`code_search (${mode.name}): saltea .cache, .git, .cyber, node_modules y carpetas ocultas; ocultos: true abre las ocultas menos esas`, async () => {
    const cwd = tree();
    try {
      const { code_search: search, code_list: list } = tools(cwd, mode.ripgrep);
      const plain = (await search!.execute({ pattern: "aguja" }, abort)).text;
      assert.match(plain, /^raiz\.ts:1: /m);
      assert.match(plain, /^src\/app\.ts:1: /m);
      assert.match(plain, /^src\/sub\/util\.ts:1: /m);
      assert.match(plain, /^\.env:1: AGUJA=1/m, "los archivos ocultos sueltos sí se buscan");
      assert.doesNotMatch(plain, /\.cache|\.github|\.git\/|\.cyber|node_modules/);
      const hidden = (await search!.execute({ pattern: "aguja", ocultos: true }, abort)).text;
      assert.match(hidden, /^\.github\/workflows\/ci\.yml:1: run: echo aguja/m);
      assert.doesNotMatch(hidden, /\.cache|\.git\/|\.cyber|node_modules/);
      // Glob con la misma semántica en los dos caminos: relativo a la raíz del proyecto, sin distinguir mayúsculas.
      const top = (await search!.execute({ pattern: "aguja", glob: "*.TS" }, abort)).text;
      assert.deepEqual(top.split("\n").map((line) => line.split(":")[0]), ["raiz.ts"]);
      const deep = (await search!.execute({ pattern: "aguja", glob: "src/**/*.ts" }, abort)).text;
      assert.deepEqual(deep.split("\n").map((line) => line.split(":")[0]), ["src/app.ts", "src/sub/util.ts"]);
      // Una carpeta pedida explícitamente se busca aunque sea oculta.
      assert.match((await search!.execute({ pattern: "aguja", path: ".github" }, abort)).text, /^\.github\/workflows\/ci\.yml:1:/m);
      const listing = (await list!.execute({ depth: 3 }, abort)).text;
      assert.match(listing, /src\/\n\s+sub\/\n\s+util\.ts/);
      assert.match(listing, /\.env {2}8 B/);
      assert.doesNotMatch(listing, /\.cache\/|\.git\/|\.cyber\/|node_modules\//);
      assert.match(listing, /carpetas ocultas sin listar: .*\.github.*ocultos: true/);
      assert.match((await list!.execute({ depth: 3, ocultos: true }, abort)).text, /\.github\/\n\s+workflows\//);
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });

  test(`code_search (${mode.name}): el tope corta la búsqueda y la señal del turno la cancela`, async () => {
    const cwd = tmp("tope");
    try {
      mkdirSync(join(cwd, "src"));
      for (let index = 0; index < 50; index++) writeFileSync(join(cwd, "src", `f${String(index).padStart(2, "0")}.txt`), "aguja\n".repeat(20));
      const { code_search: search } = tools(cwd, mode.ripgrep);
      const capped = await search!.execute({ pattern: "aguja", max: 30 }, abort);
      assert.equal(capped.details?.coincidencias, 30);
      assert.match(capped.text, /… \(tope de 30; afiná la búsqueda\)/);
      assert.match(capped.text, /^src\/f00\.txt:1: aguja/, "en orden de ruta, como antes");
      const cancelled = new AbortController();
      cancelled.abort(new Error("turno abortado"));
      await assert.rejects(async () => search!.execute({ pattern: "aguja" }, cancelled.signal), /abortado|cancelada/);
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });

  test(`code_search (${mode.name}): una búsqueda grande no frena el event loop`, async () => {
    const cwd = tmp("grande");
    try {
      const line = `${"const valor = calcular(a, b, c) + otra_cosa;".padEnd(60, " ")}\n`.repeat(2000);
      for (let dir = 0; dir < 15; dir++) {
        mkdirSync(join(cwd, `mod${dir}`));
        for (let file = 0; file < 20; file++) writeFileSync(join(cwd, `mod${dir}`, `f${file}.ts`), line);
      }
      const { code_search: search } = tools(cwd, mode.ripgrep);
      // Una expresión que trabaja en cada línea: la versión sincrónica dejaba el event loop ~0,4 s sin atender.
      const pattern = String.raw`\w+\s*=\s*\w+\(\w+,\s*\w+,\s*\w+\)\s*\+\s*nada`;
      const { result, lag, ms } = await lagDuring(async () => search!.execute({ pattern, regex: true }, abort));
      assert.match(result.text, /Sin coincidencias en 300 archivos/);
      assert.ok(lag < 200, `el event loop quedó ${lag.toFixed(0)} ms sin atender (búsqueda de ${ms.toFixed(0)} ms)`);
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
}

test("code_search y code_list sin ripgrep: una carpeta enorme no se recorre y se avisa; pedida como path sí", async () => {
  const cwd = tmp("enorme");
  try {
    mkdirSync(join(cwd, "datos"));
    for (let index = 0; index <= 5000; index++) writeFileSync(join(cwd, "datos", `${index}.txt`), index === 4999 ? "aguja" : "");
    writeFileSync(join(cwd, "app.ts"), "aguja\n");
    const { code_search: search, code_list: list } = tools(cwd, false);
    const result = (await search!.execute({ pattern: "aguja" }, abort)).text;
    assert.match(result, /^app\.ts:1: aguja/m);
    assert.doesNotMatch(result, /datos\/4999/);
    assert.match(result, /sin recorrer, más de 5000 entradas: datos/);
    assert.match((await search!.execute({ pattern: "aguja", path: "datos" }, abort)).text, /^datos\/4999\.txt:1: aguja/m);
    assert.match((await list!.execute({ depth: 2 }, abort)).text, /datos\/\n {2}… \(más de 5000 entradas: no se abre\)/);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("code_search con ripgrep: respeta .gitignore y una expresión que ripgrep no entiende pasa al recorrido propio", { skip: !RG && "ripgrep no está instalado" }, async () => {
  const cwd = tmp("gitignore");
  try {
    mkdirSync(join(cwd, ".git"));
    mkdirSync(join(cwd, "salida"));
    writeFileSync(join(cwd, ".gitignore"), "salida/\n");
    writeFileSync(join(cwd, "salida", "generado.js"), "aguja generada\n");
    writeFileSync(join(cwd, "app.ts"), "token = aguja\n");
    const { code_search: search } = tools(cwd, true);
    const result = (await search!.execute({ pattern: "aguja" }, abort)).text;
    assert.match(result, /^app\.ts:1:/m);
    assert.doesNotMatch(result, /salida/);
    // Lookbehind: sintaxis de JavaScript que el motor por defecto de ripgrep rechaza.
    assert.match((await search!.execute({ pattern: "(?<=token = )aguja", regex: true }, abort)).text, /^app\.ts:1: token = aguja/m);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

// ---------- informe ----------

function project() {
  const cwd = tmp("informe-grande");
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  return { cwd, paths, db, artifacts, findings, scope: new ScopeStore(db), ledger: new Ledger(db), close: () => { db.close(); rmSync(cwd, { recursive: true, force: true }); } };
}

/** Intercambio con la misma forma (y sangría) que guarda HttpClient. */
function exchange(index: number, method: string, url: string, status: number, headers: Record<string, string>, body: string, requestBody?: string): string {
  return JSON.stringify({ id: `h${index}`, request: { method, url, headers: { accept: "*/*" }, body: requestBody }, resolved: ["127.0.0.1"], redirects: [], durationMs: 3, artifact: "", response: { status, headers, body, bodyBytes: body.length, truncated: false } }, null, 1);
}

test("informe grande: el event loop sigue atendiendo, el cuerpo patológico no lo traba y los intercambios no citados se leen por el comienzo", async () => {
  const context = project();
  try {
    const page = `<html>${"<div class=\"fila\">contenido de relleno para que pese</div>\n".repeat(4000)}</html>`;
    for (let index = 0; index < 300; index++) context.artifacts.put(exchange(index, "GET", `https://app.example.test/pagina/${index}`, 200, { "content-type": "text/html", "set-cookie": `sid=COOKIE-${index}-SECRETA; Path=/` }, page), "application/json", "http");
    // Corridas largas de letras (JS minificado, base64url) y de líneas vacías: con los patrones viejos, cuadráticos
    // (100 kB así ya eran ~15 s de event loop trabado; 1 MB, horas).
    const minified = exchange(900, "GET", "https://app.example.test/app.js", 200, { "content-type": "application/javascript" }, `var a="${"Ab0_".repeat(25_000)}";${"\n".repeat(50_000)}token=JS-SECRETO`);
    const cited = Array.from({ length: 8 }, (_, index) => context.artifacts.put(exchange(1000 + index, "GET", `https://api.example.test/usuarios/${index}`, 200, { "content-type": "application/json" }, JSON.stringify({ items: Array.from({ length: 3000 }, (_, item) => ({ id: item, nombre: `persona ${item}`, access_token: `TOKEN-${index}-${item}` })) })), "application/json", "http").hash);
    const finding = context.findings.record({ title: "Lectura entre cuentas", kind: "control de acceso", asset: "https://api.example.test/usuarios", summary: "Reflejos: COOKIE-7-SECRETA, TOKEN-3-25, JS-SECRETO.", evidence: [...cited, context.artifacts.put(minified, "application/json", "http").hash], severity: "alta" }, "s1");
    context.findings.decide(finding.id, "verificado", "reproducido");
    const { result, lag, ms } = await lagDuring(() => generateReport(context));
    assert.ok(lag < 200, `el event loop quedó ${lag.toFixed(0)} ms sin atender (informe de ${ms.toFixed(0)} ms)`);
    assert.ok(ms < 10_000, `el informe tardó ${ms.toFixed(0)} ms`);
    assert.match(result.markdown, /Activos con respuestas HTTP guardadas en el proyecto: https:\/\/api\.example\.test, https:\/\/app\.example\.test\./);
    assert.doesNotMatch(result.markdown, /COOKIE-\d+-SECRETA|TOKEN-\d+-\d+|JS-SECRETO/, "las cookies de cabecera se aprenden aunque el cuerpo no se lea");
  } finally {
    context.close();
  }
});

test("informe: de los intercambios grandes no citados lee entero lo que aporta (escrituras, JSON, autenticación) y redacta lo reflejado", async () => {
  const context = project();
  const filler = "x".repeat(20_000);
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      if (request.url === "/api/items" && request.method === "POST") return response.writeHead(201, { "content-type": "application/json", location: "/api/items/9911" }).end(JSON.stringify({ id: 9911, relleno: filler }));
      if (request.url === "/api/login") return response.writeHead(200, { "content-type": "text/plain" }).end(`${filler}\nsession_token=LOGIN-SECRETO\n`);
      if (request.url === "/api/perfil") return response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ relleno: filler, api_key: "JSON-SECRETO" }));
      response.writeHead(200, { "content-type": "text/html" }).end(`<p>${filler}</p>`);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  context.scope.edit({ include: [base] });
  const http = new HttpClient(context.artifacts, () => context.scope.current());
  try {
    await http.send({ url: `${base}/api/items`, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ nombre: "prueba", relleno: filler }) });
    await http.send({ url: `${base}/api/login`, method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    await http.send({ url: `${base}/api/perfil` });
    await http.send({ url: `${base}/inicio` });
    const sizes = context.db.prepare("select bytes from artifacts where producer='http'").all() as Array<{ bytes: number }>;
    assert.ok(sizes.every((row) => row.bytes > 16 * 1024), "todos pasan el comienzo que se lee");
    const note = context.artifacts.put("nota", "text/plain", "test");
    context.findings.record({ title: "Nota", kind: "manual", asset: base, summary: "Reflejos: LOGIN-SECRETO JSON-SECRETO", evidence: [note.hash], severity: "alta" }, "s1");
    const { markdown } = await generateReport(context);
    assert.ok(markdown.includes(`Activos con respuestas HTTP guardadas en el proyecto: ${base}.`));
    assert.match(markdown.split("## Para limpiar")[1]!, new RegExp(`POST ${base.replace(/[.]/g, "\\.")}/api/items \\| 9911 \\| 201 \\|`));
    assert.doesNotMatch(markdown, /LOGIN-SECRETO|JSON-SECRETO/);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    context.close();
  }
});

test("informe: la señal del turno lo corta sin escribir nada", async () => {
  const context = project();
  try {
    const hash = context.artifacts.put(exchange(1, "GET", "https://example.test/", 200, {}, "hola"), "application/json", "http").hash;
    context.findings.record({ title: "Algo", kind: "manual", asset: "https://example.test/", summary: "x", evidence: [hash], severity: "alta" }, "s1");
    const cancelled = new AbortController();
    cancelled.abort(new Error("turno abortado"));
    await assert.rejects(generateReport({ ...context, signal: cancelled.signal }), /turno abortado/);
    assert.ok(!existsSync(context.paths.exports) || readdirSync(context.paths.exports).length === 0);
  } finally {
    context.close();
  }
});

test("daemon: mientras genera un informe grande, otra conexión (otra sesión) recibe respuesta antes de que termine", async () => {
  const cwd = tmp("daemon-ping");
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), autoResume: false });
  await daemon.listen();
  const client = await connectDaemon(cwd, { spawn: false });
  const other = await connectDaemon(cwd, { spawn: false });
  try {
    const snapshot = await client.attach({ model: "faux" });
    const engine = daemon.hosts.get(snapshot.sessionId)!.engine;
    const body = JSON.stringify({ items: Array.from({ length: 6000 }, (_, item) => ({ id: item, nombre: `persona ${item}`, token: `T${item}` })) });
    const cited = Array.from({ length: 12 }, (_, index) => engine.artifacts.put(exchange(index, "GET", `https://api.example.test/u/${index}`, 200, { "content-type": "application/json" }, body.replace("persona 0", `persona ${index}`)), "application/json", "http").hash);
    // Una página con muchas líneas vacías seguidas: la versión anterior se quedaba segundos en ella sin atender a nadie.
    cited.push(engine.artifacts.put(exchange(99, "GET", "https://api.example.test/vacia", 200, { "content-type": "text/html" }, `<p>${"\n".repeat(60_000)}</p>`), "application/json", "http").hash);
    engine.findings.record({ title: "Lectura entre cuentas", kind: "control de acceso", asset: "https://api.example.test/u", summary: "x", evidence: cited, severity: "alta" }, engine.sessionId);
    // Daemon y clientes comparten proceso en la prueba: los dos pedidos salen juntos y lo que cuenta es el orden de llegada.
    const started = performance.now();
    const order: string[] = [];
    let ping = 0;
    const report = client.view("informe").then((lines) => (order.push("informe"), lines));
    const pinged = other.view("scope").then(() => (order.push("ping"), (ping = performance.now() - started)));
    const [lines] = await Promise.all([report, pinged]);
    assert.match(lines[0]!, /^Informe guardado en /);
    assert.deepEqual(order, ["ping", "informe"], "la otra conexión no espera a que termine el informe");
    assert.ok(ping < 500, `el ping tardó ${ping.toFixed(0)} ms`);
  } finally {
    client.close();
    other.close();
    await daemon.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("redactor: clave=valor y la redacción final son lineales (corridas largas, miles de secretos)", () => {
  const redactor = new ReportRedactor();
  let started = performance.now();
  const text = redactor.text(`${"a".repeat(1_000_000)} ${"b-".repeat(500_000)} password=LINEAL-SECRETO`);
  assert.ok(performance.now() - started < 2000, `text() tardó ${(performance.now() - started).toFixed(0)} ms`);
  assert.doesNotMatch(text, /LINEAL-SECRETO/);
  for (let index = 0; index < 20_000; index++) redactor.headers({ "set-cookie": `sid=COOKIE${index}VALOR; Path=/` });
  started = performance.now();
  const report = redactor.finish(`${"palabra ".repeat(100_000)}COOKIE19999VALOR y COOKIE5VALORCOOKIE6VALOR fin`);
  assert.ok(performance.now() - started < 2000, `finish() tardó ${(performance.now() - started).toFixed(0)} ms`);
  assert.match(report, /\[credencial omitida\] y \[credencial omitida\] fin$/, "secretos pegados salen como un solo marcador");
});

// ---------- reinicios evitables ----------

test("connectDaemon: con otra versión del código no apaga un daemon que usan otras ventanas ni desde una conexión extra", async () => {
  const cwd = tmp("daemon-version");
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), autoResume: false });
  (daemon as unknown as { build: string }).build = "version-anterior"; // como si el código hubiera cambiado en disco después de arrancar
  await daemon.listen();
  const clients: Array<Awaited<ReturnType<typeof connectDaemon>>> = [];
  try {
    // Conexión extra de una TUI abierta (spawn: false): antes apagaba el daemon y fallaba con «No hay un daemon».
    clients.push(await connectDaemon(cwd, { spawn: false }));
    assert.equal(clients[0]!.hello.build, "version-anterior");
    assert.equal(clients[0]!.hello.clients, 0);
    // Otra ventana mientras la primera sigue conectada: antes, sin turno en curso, el daemon se apagaba para todas.
    clients.push(await connectDaemon(cwd));
    assert.equal(clients[1]!.hello.clients, 1);
    assert.equal(daemon.closed, false);
    assert.deepEqual(await clients[0]!.view("findings"), await clients[1]!.view("findings"), "las dos siguen hablando con el mismo daemon");
  } finally {
    for (const client of clients) client.close();
    await daemon.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
