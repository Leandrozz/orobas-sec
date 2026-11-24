// Salir de la caja negra (reporte de Nico, 22/11: «el REA hay que permitir que sea sobre webs y código
// fuente»): web_source_pull baja el código de una web del alcance a la carpeta del proyecto (scripts, chunks
// y el fuente de sus mapas), code_crypto mapea derivación de claves, firmas, hashes y validaciones del
// cliente, y hash_crack confirma offline una derivación. Todo con datos sintéticos y un servidor local.
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { createCodeTools } from "../src/codigo.ts";
import { chunkRefs, createSourceTools, safeRelative, scanText } from "../src/fuente.ts";
import { HttpClient } from "../src/http.ts";
import { ofertaRea, reaRevisar } from "../src/rea.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const signal = new AbortController().signal;

const AUTH_JS = `const crypto = require("crypto");
const API_SECRET = "s3cr3t-HMAC-key-2024";
function resetToken(email) {
  return crypto.createHash("sha256").update(email + ":" + Date.now()).digest("hex");
}
function signRequest(body) {
  return crypto.createHmac("sha256", "s3cr3t-HMAC-key-2024").update(body).digest("hex");
}
function legacyMac(data) {
  return crypto.createHash("md5").update(API_SECRET + data).digest("hex");
}
function checkSignature(given, expected) {
  return given.signature === expected;
}
function sessionId() {
  return Math.random().toString(36).slice(2) + "token";
}
function encrypt(text, key) {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  return cipher.update(text, "utf8", "hex") + cipher.final("hex");
}
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 32, "sha256");
}
const jwt = require("jsonwebtoken");
function issue(user) { return jwt.sign({ sub: user.id }, "dev-secret-123"); }
function read(token) { return jwt.decode(token); }
`;
const USERS_PY = `import hashlib, random
def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()
def otp_code():
    return str(random.randint(100000, 999999))  # otp
`;
const CLIENT_JS = `function canDelete(user) { return user.role === "admin"; }
const total = price * quantity - discount;
localStorage.setItem("authToken", token);
`;

function project(t: { after: (fn: () => void) => void }) {
  const cwd = realpathSync(mkdtempSync(join(tmpdir(), "cyber-fuente-")));
  const db = openStore(projectPaths(cwd));
  t.after(() => { db.close(); rmSync(cwd, { recursive: true, force: true }); });
  mkdirSync(join(cwd, "repo"), { recursive: true });
  writeFileSync(join(cwd, "repo", "auth.js"), AUTH_JS);
  writeFileSync(join(cwd, "repo", "users.py"), USERS_PY);
  writeFileSync(join(cwd, "repo", "client.js"), CLIENT_JS);
  return { cwd, db, artifacts: new Artifacts(db, projectPaths(cwd).artifacts) };
}

test("code_crypto: derivación predecible, HMAC y JWT con secreto fijo, MAC casero, ECB, PBKDF2 flojo, Math.random, == y lo que decide el cliente; sin mostrar secretos", async (t) => {
  const { cwd, artifacts } = project(t);
  let scope: Scope | undefined;
  const tools = Object.fromEntries(createSourceTools({ cwd, http: new HttpClient(artifacts, () => scope), artifacts }).map((tool) => [tool.name, tool]));
  const result = await tools.code_crypto!.execute({ path: "repo" }, signal);
  const text = result.text;
  for (const expected of [
    /\[alto\] repo\/auth\.js:4 resetToken\(\) · derivación: sha-256 de entrada predecible/,
    /\[alto\] repo\/auth\.js:7 signRequest\(\) · hmac: HMAC-sha-256 con clave fija en el código/,
    /\[alto\] repo\/auth\.js:10 legacyMac\(\) · mac casero: md5\(secreto ‖ datos\)/,
    /\[medio\] repo\/auth\.js:13 checkSignature\(\) · comparación/,
    /\[alto\] repo\/auth\.js:16 sessionId\(\) · aleatorio: Math\.random para un token/,
    /\[alto\] repo\/auth\.js:19 encrypt\(\) · cifrado: aes-128-ecb: modo ECB/,
    /\[alto\] repo\/auth\.js:23 hashPassword\(\) · kdf: PBKDF2 con 1000 iteraciones/,
    /\[alto\] repo\/auth\.js:26 issue\(\) · jwt: jwt\.sign con secreto fijo/,
    /\[medio\] repo\/auth\.js:27 read\(\) · jwt: jwt\.decode/,
    /\[alto\] repo\/auth\.js:2 · secreto fijo: API_SECRET fijo \(20 caracteres\)/,
    /\[alto\] repo\/users\.py:3 store_password\(\) · derivación: contraseña con md5/,
    /\[alto\] repo\/users\.py:5 otp_code\(\) · aleatorio: random\.randint para un token/,
    /\[medio\] repo\/client\.js:1 canDelete\(\) · validación en el cliente/,
    /\[medio\] repo\/client\.js:2 · monto en el cliente/,
    /repo\/client\.js:3 · token en el cliente: localStorage: authToken/,
    /Funciones propias para leer primero \(code_read\):[\s\S]*repo\/auth\.js:4 resetToken\(\)/,
    /extensión de longitud/,
    /hash_crack/,
  ]) assert.match(text, expected);
  assert.doesNotMatch(text, /s3cr3t-HMAC-key-2024|dev-secret-123/, "los secretos no viajan al chat");
  const stored = artifacts.read(result.details!.artefacto as string).toString();
  assert.doesNotMatch(stored, /s3cr3t-HMAC-key-2024|dev-secret-123/, "ni al artefacto");
  // Minificado: una sola línea enorme también se mira (por ventanas) y no rompe.
  const bundle = `${"var a=1;".repeat(5000)}e.token=Math.random().toString(36);${"var b=2;".repeat(5000)}`;
  assert.ok(scanText(bundle, "web/app.js").some((hit) => hit.kind === "aleatorio" && hit.risk === "alto"));
});

test("hash_crack: confirma sha256(email:hora), un token truncado, un HMAC con la clave del código sin mostrarla y {codigo}; topes y errores claros", async (t) => {
  const { cwd, artifacts } = project(t);
  writeFileSync(join(cwd, "palabras.txt"), "uno\ndos\nhunter2\n");
  const tool = createSourceTools({ cwd, http: new HttpClient(artifacts, () => undefined), artifacts }).find((item) => item.name === "hash_crack")!;
  const sha = (alg: string, text: string) => createHash(alg).update(text).digest("hex");

  const token = sha("sha256", "ana@lab.test:1732200321");
  const derived = await tool.execute({ objetivo: [token], algoritmo: "sha256", plantilla: "{email}:{n:1732200000-1732200500}", valores: { email: ["ana@lab.test"] } }, signal);
  assert.match(derived.text, /Confirmado 1 de 1 con sha256/);
  assert.match(derived.text, /«ana@lab\.test:1732200321»/);
  assert.match(derived.text, /n=1732200321/);

  const truncated = sha("sha1", "user-42").slice(0, 16);
  assert.match((await tool.execute({ objetivo: [truncated], algoritmo: "sha1", plantilla: "user-{n:0-100}" }, signal)).text, /valor truncado: se compara el prefijo[\s\S]*«user-42»/);
  assert.match((await tool.execute({ objetivo: [sha("sha256", "007")], algoritmo: "SHA-256", plantilla: "{n:000-999}" }, signal)).text, /«007»/, "ceros a la izquierda");

  const key = "s3cr3t-HMAC-key-2024";
  const signature = createHmac("sha256", key).update("pedido-77").digest("base64");
  const hmac = await tool.execute({ objetivo: [signature], algoritmo: "hmac-sha256", plantilla: "pedido-{n:0-99}", codigo: "repo/auth.js:2" }, signal);
  assert.match(hmac.text, /HMAC-sha256 con clave de repo\/auth\.js:2 \(20 caracteres, no se muestra\)/);
  assert.match(hmac.text, /«pedido-77»/);
  assert.doesNotMatch(hmac.text, new RegExp(key));
  assert.doesNotMatch(artifacts.read(hmac.details!.artefacto as string).toString(), new RegExp(key));

  const mac = sha("md5", `${key}x7`);
  const withCode = await tool.execute({ objetivo: [mac], algoritmo: "md5", plantilla: "{codigo}x{n:0-9}", codigo: "repo/auth.js:2" }, signal);
  assert.match(withCode.text, /«repo\/auth\.js:2»x7/);
  assert.doesNotMatch(withCode.text, new RegExp(key));

  assert.match((await tool.execute({ objetivo: [sha("md5", "hunter2")], algoritmo: "md5", plantilla: "{w}", diccionario: "palabras.txt" }, signal)).text, /«hunter2»/);
  assert.match((await tool.execute({ objetivo: [sha("md5", "nada")], algoritmo: "md5", plantilla: "{w}", palabras: ["a", "b"] }, signal)).text, /Sin coincidencia: 2 de 2 candidatos/);
  await assert.rejects(async () => tool.execute({ objetivo: [token], algoritmo: "sha256", plantilla: "{n:0-99999999}{m:0-9}" }, signal), /tope es 50\.000\.000/);
  await assert.rejects(async () => tool.execute({ objetivo: [token], algoritmo: "whirlpool", plantilla: "{n:0-9}" }, signal), /Algoritmo/);
  await assert.rejects(async () => tool.execute({ objetivo: [token], algoritmo: "hmac-sha256", plantilla: "{n:0-9}" }, signal), /necesita la clave/);
  await assert.rejects(async () => tool.execute({ objetivo: [token], algoritmo: "sha256", plantilla: "{w}" }, signal), /pasá palabras o diccionario/);
  await assert.rejects(async () => tool.execute({ objetivo: [sha("sha512", "x")], algoritmo: "sha256", plantilla: "{n:0-9}" }, signal), /no es ese algoritmo/);
  await assert.rejects(async () => tool.execute({ objetivo: [token], algoritmo: "sha256", plantilla: "{codigo}", codigo: "../afuera.js:1" }, signal), /fuera de la carpeta del proyecto|No existe/);
});

test("web_source_pull: página, scripts, chunks de webpack y Vite, mapas (también en línea) y fuente original a la carpeta del proyecto, sólo dentro del alcance", async (t) => {
  const { cwd, artifacts } = project(t);
  const seen: string[] = [];
  const mapa = JSON.stringify({ version: 3, sources: ["webpack:///src/auth.ts", "webpack:///./src/api/client.ts", "webpack:///node_modules/lib/index.js"], sourcesContent: [
    "export function resetToken(email: string) {\n  return createHash(\"sha256\").update(email + Date.now()).digest(\"hex\");\n}\n",
    "export const borrar = (id: string) => fetch(`/api/invoices/${id}`, { method: \"DELETE\" });\n",
    "module.exports = 1;\n",
  ] });
  const enLinea = Buffer.from(JSON.stringify({ version: 3, sources: ["webpack:///../../../etc/passwd"], sourcesContent: ["root:x:0:0:root:/root:/bin/sh"] })).toString("base64");
  const routes: Record<string, [string, string]> = {
    "/": ["text/html", `<html><head><script src="/static/js/main.abc.js"></script><script src="https://cdn.otro.com/lib.js"></script><link rel="modulepreload" href="/assets/vendor-1a2b3c4d.js"><script src="/dist/app.js"></script>
<script>window.__CONFIG__ = { apiUrl: "https://api.externa.com/v1", version: "3.2.1", features: [] };</script></head><body></body></html>`],
    "/static/js/main.abc.js": ["application/javascript", `fetch("/api/orders/" + id, {method:"POST", body: JSON.stringify({orderId: id, amount: 10})});
const routes = [{path:"/admin/users"}];
localStorage.setItem("authToken", t);
const h = {"Authorization": "Bearer " + t};
__webpack_require__.u = e => "static/js/" + e + "." + {12:"deadbeef",34:"cafebabe"}[e] + ".chunk.js";
import("./lazy-page.js");
//# sourceMappingURL=main.abc.js.map`],
    "/static/js/12.deadbeef.chunk.js": ["application/javascript", `fetch("/api/users/" + uid + "/role", {method: "PUT", body: JSON.stringify({role: r})});`],
    "/static/js/34.cafebabe.chunk.js": ["application/javascript", `if (user.isAdmin) showPanel();`],
    "/static/js/lazy-page.js": ["application/javascript", `const q = "query GetSecretThing { thing { id } }";`],
    "/assets/vendor-1a2b3c4d.js": ["application/javascript", `var v=1;\n//# sourceMappingURL=data:application/json;base64,${enLinea}`],
    "/dist/app.js": ["application/javascript", `const sig = crypto.createHmac("sha256", "clave-del-cliente-99").update(body).digest("hex");`],
    "/static/js/main.abc.js.map": ["application/json", mapa],
  };
  const server = createServer((req, res) => {
    seen.push(req.url ?? "");
    const route = routes[req.url ?? ""];
    if (!route) return void res.writeHead(404).end("no");
    res.writeHead(200, { "content-type": route[0] }).end(route[1]);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const port = (server.address() as AddressInfo).port;
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`127.0.0.1:${port}`)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  const tool = createSourceTools({ cwd, http, artifacts }).find((item) => item.name === "web_source_pull")!;
  const result = await tool.execute({ url: `http://127.0.0.1:${port}/` }, signal);
  const folder = `fuente-web/127.0.0.1_${port}`;
  const at = (rel: string) => join(cwd, folder, rel);
  for (const file of ["web/index.html", "web/static/js/main.abc.js", "web/static/js/12.deadbeef.chunk.js", "web/static/js/34.cafebabe.chunk.js", "web/static/js/lazy-page.js", "web/assets/vendor-1a2b3c4d.js", "web/_dist/app.js", "web/static/js/main.abc.js.map", "web/_en-linea/script-1.js", "fuentes/src/auth.ts", "fuentes/src/api/client.ts", "fuentes/etc/passwd", "manifiesto.json"]) {
    assert.ok(existsSync(at(file)), `${file} está`);
  }
  assert.ok(!existsSync(at("fuentes/node_modules")), "las dependencias de los mapas no se reconstruyen por defecto");
  assert.ok(!existsSync(join(cwd, "etc")), "una ruta con ../ en el mapa no sale de la carpeta");
  assert.ok(!seen.some((url) => /cdn\.otro|externa/.test(url)), "nada fuera del alcance");
  const manifest = JSON.parse(readFileSync(at("manifiesto.json"), "utf8"));
  assert.deepEqual(Object.keys(manifest.fueraDelAlcance), ["cdn.otro.com"]);
  assert.ok(manifest.archivos.every((item: { sha256: string; exchange: string }) => /^[0-9a-f]{64}$/.test(item.sha256) && /^h\d+$/.test(item.exchange)));
  const text = result.text;
  for (const expected of [
    new RegExp(`→ ${folder}/ · 6 scripts \\+ 1 en línea, 2 mapas, 3 fuentes originales recuperadas`),
    /Fuera del alcance, no bajado: cdn\.otro\.com \(1\)/,
    /POST +\/api\/orders\/\{id\}  campos: orderId, amount/,
    /PUT +\/api\/users\/\{uid\}\/role  campos: role/,
    /DELETE +\/api\/invoices\/\{id\}/,
    /Pantallas del cliente: \/admin\/users/,
    /Dónde guarda la sesión: localStorage\.setItem\("authToken"/,
    /Cómo arma la autorización: .*Authorization/,
    /Bases de API: https:\/\/api\.externa\.com\/v1/,
    /Bases de API fuera del alcance: https:\/\/api\.externa\.com\/v1/,
    /Operaciones GraphQL: query GetSecretThing/,
    /fuentes\/src\/auth\.ts:2 resetToken\(\) · derivación: sha-256 de entrada predecible/,
    /web\/_dist\/app\.js:1 · hmac: HMAC-sha-256 con clave fija/,
    /validación en el cliente/,
    new RegExp(`rea\\.analyze_javascript_application con input_path ${folder}/fuentes`),
  ]) assert.match(text, expected);
  assert.doesNotMatch(text, /clave-del-cliente-99/);
  assert.equal(http.count, seen.length, "cada archivo fue una petición del cliente HTTP");
  // Lo bajado se lee con las herramientas de código de siempre.
  const code = Object.fromEntries(createCodeTools({ cwd, ripgrep: false }).map((item) => [item.name, item]));
  assert.match((await code.code_search!.execute({ pattern: "resetToken", path: folder }, signal)).text, /fuentes\/src\/auth\.ts:1/);
  assert.match((await code.code_search!.execute({ pattern: "createHmac", path: folder }, signal)).text, /web\/_dist\/app\.js:1/, "«dist» se renombra para que el recorrido no la saltee");
  // Y REA (en la caja) recibe esa carpeta como app JavaScript.
  assert.equal(reaRevisar({ cwd, scope: () => scope, artifacts }, "analyze_javascript_application", { input_path: `${folder}/fuentes` }).input_path, join(cwd, folder, "fuentes"));
  assert.match(ofertaRea().find((entry) => entry.name === "analyze_javascript_application")!.description, /web_source_pull/);
  // Un host fuera del alcance no se baja.
  await assert.rejects(async () => tool.execute({ url: "https://cdn.otro.com/" }, signal), /Fuera del alcance/);
  await assert.rejects(async () => tool.execute({ url: `http://127.0.0.1:${port}/`, carpeta: "../afuera" }, signal), /dentro del proyecto/);
  await assert.rejects(async () => tool.execute({ url: `http://127.0.0.1:${port}/`, carpeta: ".cyber/x" }, signal), /dentro del proyecto/);
});

test("chunks y rutas: referencias de webpack, Vite y Next; rutas de mapas saneadas", () => {
  const refs = chunkRefs(`a="static/js/"+e+"."+{1:"aa11",2:"bb22"}[e]+".chunk.js";b=["assets/index-3f2a1b9c.js","./x.js","/_next/static/chunks/pages/admin-9f8e.js"];c="lodash.js";d="chunk-3f2a1b9c.js"`);
  for (const ref of ["static/js/1.aa11.chunk.js", "static/js/2.bb22.chunk.js", "assets/index-3f2a1b9c.js", "./x.js", "/_next/static/chunks/pages/admin-9f8e.js", "chunk-3f2a1b9c.js"]) assert.ok(refs.includes(ref), ref);
  assert.ok(!refs.includes("lodash.js"), "un nombre de paquete no es un chunk");
  assert.equal(safeRelative("webpack:///../../../etc/passwd"), "etc/passwd");
  assert.equal(safeRelative("webpack://app/./src/a b.ts"), "app/src/a_b.ts");
  assert.equal(safeRelative("/dist/../.git/config"), "_dist/_.git/config");
});

test("motor: las herramientas nuevas están en el catálogo, en su familia, y el prompt y la habilidad las nombran", async () => {
  const { Engine, SYSTEM_PROMPT } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const { GROUPS } = await import("../src/catalog.ts");
  const engine = new Engine({ cwd: realpathSync(mkdtempSync(join(tmpdir(), "cyber-fuente-motor-"))), provider: resolveProvider("faux"), autoVerify: false, cveFeed: false });
  try {
    for (const name of ["web_source_pull", "code_crypto", "hash_crack"]) assert.ok(engine.catalog.available.has(name), name);
    assert.ok(GROUPS["análisis web"]!.includes("web_source_pull") && GROUPS.código!.includes("code_crypto") && GROUPS.código!.includes("hash_crack"));
    assert.match(SYSTEM_PROMPT, /web_source_pull baja a la carpeta del proyecto su JavaScript/);
    assert.doesNotMatch(SYSTEM_PROMPT, /Con un repositorio de código fuente completo no uses REA/);
    const skill = readFileSync(new URL("../skills/ingenieria-inversa/SKILL.md", import.meta.url), "utf8");
    assert.match(skill, /^tools: web_source_pull, code_crypto, hash_crack/m);
  } finally {
    await engine.close();
  }
});
