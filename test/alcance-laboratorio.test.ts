// Laboratorios locales (reporte de Nico, 22/11): localhost, 127.0.0.1, ::1 y 0.0.0.0 son la misma máquina;
// una regla sin puerto cubre todos, una con puerto sólo ése; el agente suma su propio laboratorio en
// loopback sin cita del operador, pero la red del operador (192.168.x, 10.x, host.docker.internal) la
// suma sólo él; y el error de «fuera del alcance» dice qué regla agregar. reference_read sigue sin salir
// a loopback ni a la red local.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { HttpClient, privateResolutionAllowed } from "../src/http.ts";
import { createOperatorTools } from "../src/operador.ts";
import { referenceDecision } from "../src/referencia.ts";
import { decide, isLocalRule, parseRule, type Scope, ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const scopeOf = (...rules: string[]): Scope => ({ rev: 3, source: "manual", notes: "", at: "", include: rules.map((rule) => parseRule(rule)), exclude: [] });
const allowed = (scope: Scope, target: string) => decide(scope, target).allowed;

test("reglas: host:puerto, [::1]:puerto, *.localhost, *.test y host.docker.internal se entienden", () => {
  assert.deepEqual(parseRule("127.0.0.1:8899"), { kind: "host", value: "127.0.0.1:8899", note: undefined });
  assert.equal(parseRule("LOCALHOST:3000").value, "localhost:3000");
  assert.equal(parseRule("[::1]:8080").value, "[::1]:8080");
  assert.equal(parseRule("::1").value, "::1");
  assert.equal(parseRule("tienda.test:8443").value, "tienda.test:8443");
  assert.equal(parseRule("host.docker.internal").kind, "host");
  assert.equal(parseRule("*.localhost").kind, "wildcard");
  assert.equal(parseRule("*.test").kind, "wildcard");
  assert.equal(parseRule("192.168.0.0/16").kind, "cidr");
  assert.throws(() => parseRule("127.0.0.1:99999"), /No entiendo la regla/);
  assert.throws(() => parseRule("*.com"), /No entiendo la regla/, "un comodín sobre un dominio público de una etiqueta sigue sin valer");
});

test("equivalencias: localhost ≡ 127.0.0.1 ≡ ::1 ≡ 0.0.0.0 como destino; sin puerto cubre todos, con puerto sólo ése", () => {
  for (const rule of ["localhost", "127.0.0.1", "::1"]) {
    const scope = scopeOf(rule);
    for (const target of ["http://127.0.0.1:8899/x", "http://localhost:3000/", "http://[::1]:8080/a", "http://0.0.0.0:5000/", "127.0.0.1", "127.0.0.1:22", "localhost", "https://app.localhost:8443/"]) {
      assert.equal(allowed(scope, target), true, `${rule} cubre ${target}`);
    }
    for (const target of ["http://192.168.1.20:8080/", "10.0.0.1", "http://host.docker.internal:8080/", "http://tienda.test/", "https://example.com/"]) {
      assert.equal(allowed(scope, target), false, `${rule} no cubre ${target}: otra máquina`);
    }
  }
  const port = scopeOf("127.0.0.1:8899");
  assert.equal(allowed(port, "http://127.0.0.1:8899/app"), true);
  assert.equal(allowed(port, "http://localhost:8899/app"), true);
  assert.equal(allowed(port, "https://[::1]:8899/"), true);
  assert.equal(allowed(port, "127.0.0.1:8899"), true);
  assert.equal(allowed(port, "http://127.0.0.1:8900/"), false);
  assert.equal(allowed(port, "http://127.0.0.1/"), false, "el 80 no es el 8899");
  assert.equal(allowed(port, "127.0.0.1"), false, "un host pelado (nmap) no se escanea entero con una regla de un puerto");
  assert.match(decide(port, "127.0.0.1:22").reason, /la regla 127\.0\.0\.1:8899 cubre sólo ese puerto/);
  assert.equal(allowed(scopeOf("localhost:3000"), "http://[::1]:3000/"), true);
  assert.equal(allowed(scopeOf("localhost:3000"), "ws://127.0.0.1:3000/socket"), true, "un WebSocket del laboratorio, en ese puerto");
  assert.equal(allowed(scopeOf("127.0.0.1:443"), "wss://localhost/socket"), true, "wss sin puerto es el 443");
  // Una URL con puerto y ruta: el mismo laboratorio con otro nombre, pero sólo esa ruta y ese puerto.
  const url = scopeOf("http://127.0.0.1:8899/app");
  assert.equal(allowed(url, "http://localhost:8899/app/x"), true);
  assert.equal(allowed(url, "http://localhost:8899/otra"), false);
  assert.equal(allowed(url, "http://127.0.0.1:8900/app"), false);
  assert.equal(allowed(scopeOf("http://127.0.0.1:8899"), "127.0.0.1"), false, "nmap sobre todo el host no entra por una URL de un puerto");
  assert.equal(allowed(scopeOf("http://127.0.0.1:8899"), "127.0.0.1:8899"), true);
  // Un sitio virtual en loopback es ese nombre, no toda la máquina.
  const vhost = scopeOf("tienda.localhost");
  assert.equal(allowed(vhost, "http://tienda.localhost:3000/"), true);
  assert.equal(allowed(vhost, "http://127.0.0.1:3000/"), false);
  // Las exclusiones ganan también con otro nombre de la misma máquina.
  const excluded: Scope = { ...scopeOf("localhost"), exclude: [parseRule("127.0.0.1:5432")] };
  assert.equal(allowed(excluded, "http://localhost:5432/"), false);
  assert.equal(allowed(excluded, "http://localhost:8080/"), true);
});

test("rangos privados y nombres locales: los cubre la regla que los nombra, nada más", () => {
  assert.equal(allowed(scopeOf("192.168.0.0/16"), "http://192.168.1.20:8080/"), true);
  assert.equal(allowed(scopeOf("10.0.0.0/8"), "10.4.5.6:22"), true);
  assert.equal(allowed(scopeOf("172.16.0.0/12"), "http://172.31.255.1/"), true);
  assert.equal(allowed(scopeOf("172.16.0.0/12"), "http://172.32.0.1/"), false);
  assert.equal(allowed(scopeOf("fd00::/8"), "http://[fd12::5]:8080/"), true, "un CIDR IPv6 ya no es sólo coincidencia exacta");
  assert.equal(allowed(scopeOf("fd00::/8"), "http://[fe80::1]/"), false);
  assert.equal(allowed(scopeOf("192.168.1.20:8080"), "http://192.168.1.20:8080/"), true);
  assert.equal(allowed(scopeOf("192.168.1.20:8080"), "http://192.168.1.20:9090/"), false);
  assert.equal(allowed(scopeOf("host.docker.internal"), "http://host.docker.internal:8080/"), true);
  assert.equal(allowed(scopeOf("*.test"), "http://tienda.test/"), true);
  assert.equal(allowed(scopeOf("*.localhost"), "http://api.localhost:3000/"), true);
  // Un programa público no trae loopback ni la red local.
  assert.equal(allowed(scopeOf("*.example.com", "https://app.example.com"), "http://127.0.0.1/"), false);
});

test("el error de fuera del alcance dice qué regla agregar y quién puede hacerlo", () => {
  const program = scopeOf("*.example.com");
  const loop = decide(program, "http://127.0.0.1:8899/index.php").reason;
  assert.match(loop, /127\.0\.0\.1:8899 es loopback/);
  assert.match(loop, /scope_edit agregar \["127\.0\.0\.1:8899"\]/);
  assert.match(loop, /no necesita cita del operador/);
  assert.match(decide(program, "http://0.0.0.0:5000/").reason, /scope_edit agregar \["127\.0\.0\.1:5000"\]/, "0.0.0.0 se sugiere como 127.0.0.1");
  assert.match(decide(program, "localhost").reason, /scope_edit agregar \["localhost:<puerto>"\]/);
  assert.match(decide(program, "http://[::1]:8080/").reason, /scope_edit agregar \["\[::1\]:8080"\]/);
  const lan = decide(program, "http://192.168.1.20:8080/").reason;
  assert.match(lan, /red del operador/);
  assert.match(lan, /\/alcance add 192\.168\.1\.20:8080 \(sólo ese puerto\)/);
  assert.match(lan, /\/alcance add 192\.168\.1\.0\/24/);
  assert.match(lan, /No lo agregues vos/);
  assert.doesNotMatch(lan, /scope_edit agregar/);
  assert.match(decide(program, "http://host.docker.internal:8080/").reason, /máquina del operador vista desde el contenedor.*\/alcance add host\.docker\.internal:8080/);
  // Sin alcance también lo dice; y un destino público sigue con el motivo de siempre.
  assert.match(decide(undefined, "http://127.0.0.1:8899/").reason, /No hay alcance definido.*scope_edit agregar \["127\.0\.0\.1:8899"\]/);
  assert.doesNotMatch(decide(program, "https://otro.com/").reason, /alcance add|scope_edit/);
});

test("scope_edit: un laboratorio propio en loopback con puerto entra sin cita; loopback sin puerto o la red del operador, no", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-lab-"));
  const db = openStore(projectPaths(dir));
  t.after(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });
  const scope = new ScopeStore(db, "s1");
  scope.save({ source: "hackerone:tienda", include: [parseRule("*.tienda.com")], exclude: [], notes: "" });
  const texts = ["armá un laboratorio con la versión vulnerable y probalo"];
  const tool = createOperatorTools({ scope, ledger: {} as never, http: {} as never, operatorTexts: () => texts, h1: () => ({}), report: async () => [] }).find((item) => item.name === "scope_edit")!;
  const signal = new AbortController().signal;

  const result = await tool.execute({ agregar: ["127.0.0.1:8899", "localhost:3000"], pedido: "levanté el laboratorio en 8899 y 3000" }, signal);
  assert.match(result.text, /Laboratorio propio en loopback: 127\.0\.0\.1:8899, localhost:3000/);
  assert.equal(decide(scope.current(), "http://localhost:8899/").allowed, true);
  assert.equal(decide(scope.current(), "http://shop.tienda.com/").allowed, true, "el programa sigue");
  assert.equal(scope.current()!.include.find((rule) => rule.value === "127.0.0.1:8899")?.note, "laboratorio local (loopback)");
  assert.equal(scope.current()!.source, "hackerone:tienda");

  for (const [target, why] of [["localhost", /no coincide con ningún mensaje del operador.*localhost es loopback.*localhost:<puerto>/s], ["192.168.1.20:8080", /red del operador.*\/alcance add 192\.168\.1\.20:8080/s], ["host.docker.internal:8080", /máquina del operador vista desde el contenedor/], ["0.0.0.0/0", /no coincide con ningún mensaje del operador/]] as const) {
    await assert.rejects(async () => tool.execute({ agregar: [target], pedido: "levanté el laboratorio" }, signal), why, target);
  }
  // Mezclado con algo que no es loopback, el resto sigue pidiendo cita.
  await assert.rejects(async () => tool.execute({ agregar: ["127.0.0.1:9000", "api.otra.com"], pedido: "levanté el laboratorio" }, signal), /no coincide con ningún mensaje del operador/);
  assert.equal(decide(scope.current(), "http://127.0.0.1:9000/").allowed, false, "nada de esa llamada entró");
  // Si el operador nombra un host de su red, el agente lo suma citándolo (y el puerto achica, no amplía).
  texts.push("sumá 192.168.1.20 que es mi otra máquina");
  await tool.execute({ agregar: ["192.168.1.20:8080"], pedido: "sumá 192.168.1.20 que es mi otra máquina" }, signal);
  assert.equal(decide(scope.current(), "http://192.168.1.20:8080/").allowed, true);
  // Cargar otro programa conserva el laboratorio (y la red que dictó el operador).
  const { kept } = scope.saveProgram({ source: "hackerone:otro", include: [parseRule("*.otro.com")], exclude: [], notes: "" });
  assert.deepEqual(kept.map((rule) => rule.value).sort(), ["127.0.0.1:8899", "192.168.1.20:8080", "localhost:3000"]);
});

test("isLocalRule: loopback con puerto, comodines locales y nombres del operador se conservan; 0.0.0.0/0 no", () => {
  for (const rule of ["127.0.0.1:8899", "localhost:3000", "[::1]:8080", "*.localhost", "*.test", "tienda.test", "host.docker.internal", "10.0.0.0/8", "http://0.0.0.0:5000"]) assert.equal(isLocalRule(parseRule(rule)), true, rule);
  for (const rule of ["0.0.0.0/0", "example.com", "*.example.com", "https://app.example.com"]) assert.equal(isLocalRule(parseRule(rule)), false, rule);
});

test("cliente HTTP: localhost en el alcance ya no lo frena su propia resolución; un nombre público que resuelve adentro, sí", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-lab-http-"));
  const db = openStore(projectPaths(dir));
  const server = createServer((_req, res) => res.end("lab"));
  await new Promise<void>((resolve) => server.listen(0, resolve)); // todas las interfaces: localhost puede resolver a ::1
  t.after(() => { server.close(); db.close(); rmSync(dir, { recursive: true, force: true }); });
  const port = (server.address() as AddressInfo).port;
  let scope: Scope | undefined = scopeOf("localhost");
  const client = new HttpClient(new Artifacts(db, projectPaths(dir).artifacts), () => scope);
  assert.equal((await client.send({ url: `http://localhost:${port}/` })).response?.status, 200, "antes: «localhost resuelve a la dirección privada 127.0.0.1»");
  scope = scopeOf(`127.0.0.1:${port}`);
  assert.equal((await client.send({ url: `http://localhost:${port}/` })).response?.status, 200, "la regla de 127.0.0.1 con puerto cubre localhost en ese puerto");
  assert.equal((await client.send({ url: `http://127.0.0.1:${port}/` })).response?.status, 200);
  const other = await client.send({ url: `http://127.0.0.1:${port === 65535 ? port - 1 : port + 1}/` });
  assert.match(other.error ?? "", /Fuera del alcance: .*cubre sólo ese puerto.*scope_edit agregar/s);
  assert.doesNotMatch(other.error ?? "", /\.\./, "sin doble punto al unir el motivo");
  // Cabecera Host de un sitio virtual del laboratorio: con la regla del puerto, el Host de ese puerto vale.
  assert.equal((await client.send({ url: `http://127.0.0.1:${port}/`, headers: { host: `localhost:${port}` } })).response?.status, 200);

  // La guarda contra un nombre público que apunta a la red local sigue (sin DNS real: la resolución es simulada).
  scope = scopeOf("app.example.com");
  client.lookupHost = async () => ["10.0.0.5"];
  const inner = await client.send({ url: "https://app.example.com/" });
  assert.match(inner.error ?? "", /app\.example\.com resuelve a la dirección privada 10\.0\.0\.5.*agrega 10\.0\.0\.5:443/);
  assert.equal(privateResolutionAllowed(scopeOf("app.example.com"), "app.example.com", "127.0.0.1", "443"), false);
  assert.equal(privateResolutionAllowed(scopeOf("app.example.com", "10.0.0.5"), "app.example.com", "10.0.0.5", "443"), true);
  // Un nombre local que nombró el operador resuelve a su red por definición; *.localhost sólo a loopback.
  assert.equal(privateResolutionAllowed(scopeOf("tienda.test"), "tienda.test", "192.168.1.30", "80"), true);
  assert.equal(privateResolutionAllowed(scopeOf("host.docker.internal"), "host.docker.internal", "172.17.0.1", "8080"), true);
  assert.equal(privateResolutionAllowed(scopeOf("tienda.localhost"), "tienda.localhost", "127.0.0.1", "3000"), true);
  assert.equal(privateResolutionAllowed(scopeOf("tienda.localhost"), "tienda.localhost", "192.168.1.30", "3000"), false);
});

test("reference_read no sale a loopback ni a la red local aunque el alcance los tenga", () => {
  const scope: Scope = { ...scopeOf("localhost", "192.168.0.0/16", "tienda.test"), reference: [parseRule("localhost"), parseRule("https://docs.tienda.test")] };
  for (const target of ["https://localhost/repo", "https://app.localhost/x", "https://127.0.0.1/x", "https://[::1]/x", "https://0.0.0.0/x", "https://192.168.1.5/x", "https://10.1.2.3/x"]) {
    const verdict = referenceDecision(scope, target);
    assert.equal(verdict.allowed, false, target);
    assert.match(verdict.reason, /destino local/, target);
  }
  // Un nombre local que no está entre las fuentes no se lee; uno que sí está lo frena la resolución al leer (la de siempre).
  assert.equal(referenceDecision(scope, "https://host.docker.internal/x").allowed, false);
  assert.equal(referenceDecision(scope, "https://raw.githubusercontent.com/org/repo/main/README.md").allowed, true);
});
