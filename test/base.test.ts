import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { decide, parseRule, type Scope } from "../src/scope.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-"));
const scope = (include: string[], exclude: string[] = []): Scope => ({ rev: 1, source: "manual", notes: "", at: "", include: include.map((r) => parseRule(r)), exclude: exclude.map((r) => parseRule(r)) });

test("alcance: negar por defecto, comodines, redes, rutas y exclusiones", () => {
  assert.equal(decide(undefined, "ejemplo.com").allowed, false);
  const s = scope(["*.ejemplo.com", "api.otro.io", "10.0.0.0/24", "https://app.tercero.com/v2"], ["admin.ejemplo.com", "https://api.otro.io/interno"]);
  const ok = (target: string) => decide(s, target).allowed;
  assert.equal(ok("https://tienda.ejemplo.com/carrito?x=1"), true);
  assert.equal(ok("a.b.ejemplo.com"), true);
  assert.equal(ok("ejemplo.com"), false); // el comodín no incluye el dominio raíz
  assert.equal(ok("ejemplo.com.atacante.net"), false);
  assert.equal(ok("noejemplo.com"), false);
  assert.equal(ok("admin.ejemplo.com"), false); // la exclusión gana
  assert.equal(ok("https://api.otro.io/v1/usuarios"), true);
  assert.equal(ok("https://api.otro.io/interno/claves"), false);
  assert.equal(ok("10.0.0.77"), true);
  assert.equal(ok("10.0.1.77"), false);
  assert.equal(ok("https://app.tercero.com/v2/pedidos"), true);
  assert.equal(ok("https://app.tercero.com/v1/pedidos"), false);
  assert.equal(ok("https://app.tercero.com/v22"), false);
  assert.equal(ok("API.OTRO.IO:8443"), true);
  assert.equal(ok("http://[::1]/"), false);
  assert.throws(() => parseRule("no es una regla"));
  assert.match(decide(s, "admin.ejemplo.com").reason, /Excluido por la regla admin\.ejemplo\.com/);
});

test("hallazgos: el agente no puede verificar; candidato exige evidencia; el operador decide", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: tmp(), provider });
  engine.scope.edit({ include: ["*.atlas.test"], exclude: ["pagos.atlas.test"] });
  const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
  const base = { title: "Reembolsos visibles para comprador", kind: "Control de acceso", asset: "https://api.atlas.test/operador/reembolsos", summary: "comprador recibe 200" };
  provider.faux!.queue = [
    call("fixture_run", { name: "atlas-permisos" }),
    call("finding_record", { ...base, state: "candidato" }), // sin evidencia
    call("finding_record", { ...base, state: "candidato", evidence: ["sha256:" + "0".repeat(64)] }), // evidencia inexistente
    call("finding_record", { ...base, state: "verificado", evidence: ["6f9a7c2f"] }), // estado prohibido
    call("finding_record", { ...base, asset: "https://pagos.atlas.test/x", state: "pista" }), // fuera de alcance
    call("finding_record", { ...base, state: "candidato", evidence: ["6f9a7c2f"], severity: "alta" }),
    call("finding_record", { ...base, state: "pista" }), // duplicado
    call("scope_check", { target: "https://otra.com" }),
    { text: "listo" },
  ];
  await engine.send("Registrá lo que encuentres");
  const results = engine.agent.messages.filter((m) => m.role === "tool").map((m) => ({ error: m.isError, text: m.content as string }));
  assert.match(results[1]!.text, /necesita al menos un artefacto/);
  assert.match(results[2]!.text, /no es un artefacto guardado/);
  assert.match(results[3]!.text, /debe ser uno de pista, candidato/);
  assert.match(results[4]!.text, /No se registra: Excluido/);
  assert.equal(results[5]!.error, false);
  assert.match(results[6]!.text, /Ya existe/);
  assert.match(results[7]!.text, /^FUERA del alcance/);
  // El primer mensaje llevó el alcance vigente.
  assert.match(engine.agent.messages[0]!.content as string, /<alcance>\nrev 1 \(manual\)\. Dentro: \*\.atlas\.test\. Excluido: pagos\.atlas\.test\./);

  const [item] = engine.findings.list();
  assert.equal(item!.state, "candidato");
  assert.equal(item!.evidence[0]!.length, 71);
  assert.throws(() => engine.findings.update(item!.id, { state: "verificado" }, "s"), /no puede marcar/);
  assert.throws(() => engine.findings.update(item!.id, { state: "descartado" }, "s"), /motivo/);
  const verified = engine.findings.decide(item!.id.slice(0, 8), "verificado", "reproducido a mano");
  assert.equal(verified.decidedBy, "operador");
  assert.throws(() => engine.findings.update(item!.id, { state: "candidato" }, "s"), /sólo lo puede cambiar el operador/);
  engine.close();
});

test("daemon: /scope, /findings y alcance importado de HackerOne", async () => {
  const cwd = tmp();
  const seen: string[] = [];
  const page = (data: object[]) => new Response(JSON.stringify({ data, links: {} }), { status: 200 });
  const fakeFetch = (async (url: string, init: any) => {
    seen.push(`${init.headers.authorization} ${url}`);
    if (url.includes("/programs/acme/structured_scopes")) {
      return page([
        { attributes: { asset_type: "WILDCARD", asset_identifier: "*.acme.com", eligible_for_submission: true, max_severity: "critical" } },
        { attributes: { asset_type: "URL", asset_identifier: "https://api.acme.io, pagos.acme.io", eligible_for_submission: true } },
        { attributes: { asset_type: "URL", asset_identifier: "blog.acme.com", eligible_for_submission: false, instruction: "Tercero, no probar" } },
        { attributes: { asset_type: "GOOGLE_PLAY_APP_ID", asset_identifier: "com.acme.app", eligible_for_submission: true } },
      ]);
    }
    if (url.includes("/programs/vacio/")) return page([]);
    if (url.includes("/programs?")) return page([{ attributes: { handle: "acme", name: "Acme Corp", offers_bounties: true, submission_state: "open" } }]);
    return new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
  let credentials: { username: string; token: string } | undefined;
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), fetch: fakeFetch, h1Credentials: () => credentials });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    // El alcance es de cada sesión: sin ninguna, la CLI no tiene dónde cargarlo.
    await assert.rejects(client.view("scope", "add *.atlas.test"), /No hay sesiones en este proyecto|There are no sessions in this project/);
    await client.attach({ model: "faux" });
    assert.match((await client.view("scope")).join("\n"), /sin definir/);
    assert.match((await client.view("scope", "add *.atlas.test 10.1.0.0/16")).join("\n"), /Dentro \(2\)/);
    assert.match((await client.view("scope", "excluir pagos.atlas.test")).join("\n"), /Excluido \(1\)/);
    assert.match((await client.view("scope", "quitar 10.1.0.0/16")).join("\n"), /rev 3 · manual[\s\S]*Dentro \(1\)/);
    await assert.rejects(client.view("scope", "add ???"), /No entiendo la regla/);
    assert.deepEqual(await client.view("findings"), ["HALLAZGOS · esta sesión · ninguno registrado"]);

    await assert.rejects(client.ask("h1"), /Falta iniciar sesión en HackerOne/);
    credentials = { username: "lean", token: "secreto" };
    assert.match((await client.ask("h1")).join("\n"), /HACKERONE · 1 programas abiertos de 1 accesibles\nacme +paga +open +Acme Corp/);
    const imported = (await client.ask("h1", { action: "alcance", handle: "acme" })).join("\n");
    assert.match(imported, /3 dentro, 1 excluidos \(rev 4\)/);
    assert.match(imported, /No importados \(1; no son destinos de red\): GOOGLE_PLAY_APP_ID: com\.acme\.app/);
    assert.match(imported, /hackerone:acme[\s\S]*\*\.acme\.com  — severidad máx\. critical[\s\S]*blog\.acme\.com  — no elegible · Tercero, no probar/);
    await assert.rejects(client.ask("h1", { action: "alcance", handle: "vacio" }), /no tiene activos de red elegibles/);
    await assert.rejects(client.ask("h1", { action: "alcance", handle: "../x" }), /inválido/);
    assert.ok(seen.every((line) => line.startsWith(`Basic ${Buffer.from("lean:secreto").toString("base64")} https://api.hackerone.com/v1/hackers/`)));
    client.close();
  } finally {
    daemon.close();
  }
});
