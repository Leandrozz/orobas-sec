import "./datos-tmp.ts";
// De una sesión real: un endpoint «de administración» le regalaba a cualquiera un token, contraseñas
// y una cadena de rutas internas que colgaban. Es un señuelo: se marca, no se sigue en cadena y lo
// que entrega no se usa.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { summarize } from "../src/http.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";
import { readDecoy } from "../src/senuelos.ts";

const TOKEN = "tok_" + "a1b2c3d4".repeat(6);

test("qué es un señuelo y qué no", () => {
  const json = "application/json";
  const bait = JSON.stringify({ admins: [{ email: "a@x.test", password_hint: "abc123" }], rotating_token: TOKEN, next: ["/internal/v2/vault/1"] });
  const read = readDecoy({ authenticated: false, method: "GET", status: 200, contentType: json, body: bait });
  assert.deepEqual(read.reasons, ["entrega contraseñas a una petición sin autenticar"]);
  assert.deepEqual(read.paths, ["/internal/v2/vault/1"]);
  assert.ok(read.canaries.includes(TOKEN) && read.canaries.includes("abc123"));
  assert.match(readDecoy({ authenticated: true, method: "GET", status: 200, contentType: json, body: '{"flag":"flag{no_es}"}' }).reasons[0]!, /marca de carnada/);
  // Lo normal no se marca: un login que devuelve un token, un perfil propio, un token CSRF anónimo.
  assert.deepEqual(readDecoy({ authenticated: false, method: "POST", status: 200, contentType: json, body: JSON.stringify({ access_token: TOKEN }) }).reasons, []);
  assert.deepEqual(readDecoy({ authenticated: true, method: "GET", status: 200, contentType: json, body: '{"user":"ana","password":"hash"}' }).reasons, []);
  assert.deepEqual(readDecoy({ authenticated: false, method: "GET", status: 200, contentType: json, body: JSON.stringify({ csrfToken: TOKEN }) }).reasons, []);
  // Tampoco el código del sitio ni la palabra suelta: los bundles de React y Next traen «canary» en sus
  // versiones y los formularios de contacto llaman «honeypot» al campo anti-spam (42 falsos positivos reales).
  const chunk = 'self.__next_f.push([1,"19.2.0-canary-3fbfb9ba-20250409"]);var e={version:"15.3.0-canary.9"}';
  assert.deepEqual(readDecoy({ authenticated: false, method: "GET", status: 200, contentType: "application/javascript; charset=utf-8", body: chunk }).reasons, []);
  assert.deepEqual(readDecoy({ authenticated: false, method: "GET", status: 200, contentType: "text/html", body: '<form><input type="text" name="honeypot" style="display:none"><p>canary release</p></form>' }).reasons, []);
  assert.deepEqual(readDecoy({ authenticated: false, method: "GET", status: 200, contentType: "text/javascript", body: 'const t="flag{no_es_de_js}"' }).reasons, []);
  // Como nombre de campo o como token de canario sí es carnada.
  assert.match(readDecoy({ authenticated: true, method: "GET", status: 200, contentType: json, body: '{"canary_token":"' + TOKEN + '"}' }).reasons[0]!, /marca de carnada/);
  assert.match(readDecoy({ authenticated: true, method: "GET", status: 200, contentType: json, body: '{"honeypot":"/admin/backup"}' }).reasons[0]!, /marca de carnada/);
  assert.match(readDecoy({ authenticated: true, method: "GET", status: 200, contentType: "text/plain", body: 'http://canarytokens.com/abc' }).reasons[0]!, /marca de carnada/);
});

test("un señuelo se marca, sus rutas no se siguen en cadena y sus credenciales no se usan", async () => {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    const send = (body: object) => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
    if (req.url === "/api/admin") return void send({ status: "partial", rotating_token: TOKEN, next: ["/internal/v2/vault/1", "/internal/v2/bypass/2"], admins: [{ email: "admin1@x.test", password_hint: "abc123" }] });
    if (req.url === "/internal/v2/vault/1") return void send({ status: "partial", next: ["/internal/v2/vault/3"], admins: [{ email: "admin2@x.test", password_hint: "def456" }] });
    send({ ok: true });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-senuelo-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), budgetPico: usdToPico("1") });
  const notices: string[] = [];
  engine.onNotice = (text) => notices.push(text);
  try {
    engine.scope.edit({ include: [`${base}/`] });
    const first = await engine.http.send({ url: `${base}/api/admin` });
    assert.deepEqual(first.decoy, ["entrega contraseñas a una petición sin autenticar"]);
    assert.match(summarize(first), /⚠ SEÑUELO PROBABLE: entrega contraseñas.*No sigas las rutas que propone ni uses las credenciales/);
    assert.match(notices[0]!, /^Señuelo probable en http:\/\/127\.0\.0\.1:\d+\/api\/admin/);

    // Una ruta propuesta se puede pedir una vez, para confirmarlo.
    const second = await engine.http.send({ url: `${base}/internal/v2/vault/1` });
    assert.equal(second.response?.status, 200);
    assert.ok(second.decoy);
    const sent = hits.length;
    assert.match((await engine.http.send({ url: `${base}/internal/v2/vault/1` })).error!, /ya la pediste una vez: no se repite/);
    // La que propuso esa segunda respuesta ya es una cadena: no se sigue.
    assert.match((await engine.http.send({ url: `${base}/internal/v2/vault/3` })).error!, /cadena de señuelos.*no se sigue/);
    // Lo que regaló no se usa, ni como token ni como contraseña.
    assert.match((await engine.http.send({ url: `${base}/api/perfil`, headers: { authorization: `Bearer ${TOKEN}` } })).error!, /credencial que regaló una respuesta marcada como señuelo: no se envía/);
    assert.match((await engine.http.send({ url: `${base}/login`, method: "POST", body: JSON.stringify({ email: "admin1@x.test", password: "abc123" }) })).error!, /no se envía/);
    assert.equal(hits.length, sent, "nada de eso salió");
    // El resto del sitio sigue disponible.
    assert.equal((await engine.http.send({ url: `${base}/api/perfil` })).response?.status, 200);
    // Sólo el operador lo levanta.
    engine.http.decoysAllowed = true;
    assert.equal((await engine.http.send({ url: `${base}/internal/v2/vault/3` })).response?.status, 200);
    assert.equal(engine.http.decoysSeen, 2);
  } finally {
    engine.close();
    server.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
