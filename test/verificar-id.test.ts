import "./datos-tmp.ts";
// Reporte de Nico (22/11): le pidió al agente en el chat que dejara un hallazgo preparado y le pasara el id,
// corrió /verificar con ese id y el verificador «se puso a hacer lo que tenía ganas»: no fue por ese registro
// y la verificación falló. Causas en el código: Findings.get resolvía con «like 'x%' limit 1» sin orden (un
// prefijo ambiguo o con comodines devolvía cualquiera), un id inexistente no decía cuáles sí había, y la
// verificación automática del cierre del turno corría con el agente ya quieto, así que /verificar largaba otra
// en paralelo y en pantalla se mezclaban los dos verificadores (el automático trabaja todos los pendientes).
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule } from "../src/scope.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-verificar-id-"));
const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const engineAt = (cwd: string) => new Engine({ cwd, provider: resolveProvider("faux"), autoVerify: false, cveFeed: false, coverageObjections: 0, closingGate: false });
const toolText = (e: Engine, name: string) => String(e.agent.messages.findLast((m) => m.role === "tool" && m.name === name)?.content ?? "");

function lab(): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = createServer((_req, res) => res.writeHead(200, { "content-type": "application/json" }).end('{"pedido":2,"dueño":"otro"}'));
    server.listen(0, "127.0.0.1", () => resolve({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}

/** El chat registra un candidato con evidencia y devuelve el id corto que le muestra al operador. */
async function chatCandidate(engine: Engine, base: string): Promise<string> {
  engine.provider.faux!.queue = [
    call("http_request", { url: `${base}/pedidos/2` }),
    call("finding_record", { state: "candidato", title: "IDOR en pedidos", kind: "control de acceso", severity: "alta", asset: `${base}/pedidos/2`, summary: "Se lee el pedido 2 de otro usuario (h1).", evidence: ["h1"] }),
    { text: "Listo, quedó preparado." },
  ];
  await engine.send("dejá el hallazgo preparado y pasame el id");
  return /Registrado ([0-9a-f]{8}) como candidato/.exec(toolText(engine, "finding_record"))![1]!;
}

test("verificar <id> recién creado en el chat usa exactamente ese registro, y el verificador lo recibe sin ambigüedad", async () => {
  const cwd = tmp();
  const { server, base } = await lab();
  const engine = engineAt(cwd);
  const other = engineAt(cwd);
  try {
    engine.scope.save({ source: "manual", include: [parseRule(base)], exclude: [], notes: "" });
    // Hallazgos que ya estaban en el proyecto: de otra sesión y de ésta.
    const old = other.artifacts.put("evidencia vieja", "text/plain", "prueba").hash;
    const foreign = other.findings.record({ title: "IDOR viejo de otra sesión", kind: "control de acceso", asset: "https://otro.test/x", summary: "s", evidence: [old] }, other.sessionId);
    const id = await chatCandidate(engine, base);
    const created = engine.findings.get(id)!;
    assert.equal(created.title, "IDOR en pedidos");
    // /verificar <id>: el verificador (scriptado) dicta sobre ése y sólo ése.
    engine.provider.faux!.queue = [call("verdict", { state: "candidato", reason: "falta el control con el dueño" })];
    const verdict = await engine.verifier.verify(id);
    assert.equal(verdict.finding.id, created.id);
    const transcript = JSON.parse(engine.artifacts.read(verdict.transcript).toString("utf8")) as Array<{ role: string; content: string }>;
    const asked = transcript.find((message) => message.role === "user")!.content;
    assert.match(asked, new RegExp(`CANDIDATO ${id} \\(id completo ${created.id}\\)`));
    assert.match(asked, /Verificás este y ningún otro/);
    assert.match(asked, new RegExp(`Evidencia registrada \\(leela con artifact_read y estos hashes\\): ${created.evidence[0]!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.ok(!asked.includes(foreign.id.slice(0, 8)), "nada del otro hallazgo");
    assert.equal(engine.findings.get(foreign.id)!.decidedBy, "agente", "el otro no se tocó");
    assert.equal(engine.findings.get(id)!.decidedBy, "verificador:1");
    // Copiado del chat con comillas o un punto al final, es el mismo.
    assert.equal(engine.findings.resolve(`«${id}».`).id, created.id);
  } finally {
    await Promise.allSettled([engine.close(), other.close()]);
    server.close();
  }
});

test("un id que no existe, ambiguo o con comodines: error claro con los ids válidos, sin tomar otro ni llamar al modelo", async () => {
  const cwd = tmp();
  const { server, base } = await lab();
  const engine = engineAt(cwd);
  try {
    engine.scope.save({ source: "manual", include: [parseRule(base)], exclude: [], notes: "" });
    const id = await chatCandidate(engine, base);
    const calls = engine.provider.faux!.calls;
    // Inexistente: dice que no está y cuáles sí, empezando por los de esta sesión.
    await assert.rejects(engine.verifier.verify("ffffffff"), (error: Error) => {
      assert.match(error.message, /No hay un hallazgo «ffffffff» en este proyecto/);
      assert.match(error.message, new RegExp(`Ids de candidatos que sí existen: ${id} \\(candidato, «IDOR en pedidos»\\)`));
      return true;
    });
    // «%» y «_» eran comodines del LIKE: con «%» se verificaba el primero que hubiera.
    await assert.rejects(engine.verifier.verify("%"), /No hay un hallazgo «%»/);
    assert.equal(engine.findings.get("%"), undefined);
    assert.equal(engine.findings.get(""), undefined);
    // Dos con el mismo prefijo: no se elige ninguno al azar.
    const molde = JSON.parse((engine.db.prepare("select json from findings limit 1").get() as { json: string }).json);
    for (const twin of ["abcd0000-1111-4000-8000-000000000001", "abcd0000-2222-4000-8000-000000000002"]) engine.db.prepare("insert into findings(id,json) values(?,?)").run(twin, JSON.stringify({ ...molde, id: twin, title: `Gemelo ${twin.slice(9, 13)}` }));
    assert.equal(engine.findings.get("abcd0000"), undefined);
    await assert.rejects(engine.verifier.verify("abcd0000"), /«abcd0000» corresponde a 2 hallazgos: abcd0000 .*abcd0000 .*Pasá más caracteres/);
    assert.equal(engine.findings.get("abcd0000-2222")!.title, "Gemelo 2222");
    assert.equal(engine.provider.faux!.calls, calls, "no se llamó al modelo");
  } finally {
    await engine.close();
    server.close();
  }
});

test("/verificar <id> espera la verificación automática del cierre del turno en vez de correr otra en paralelo, y verifica ése", async () => {
  const cwd = tmp();
  const { server, base } = await lab();
  // Sin la tanda automática real: la simula la promesa de abajo, con el agente ya quieto.
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), autoResume: false, engine: { autoVerify: false } });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    const snapshot = await client.attach({ model: "faux" });
    const engine = daemon.hosts.get(snapshot.sessionId)!.engine;
    engine.scope.save({ source: "manual", include: [parseRule(base)], exclude: [], notes: "" });
    const id = await chatCandidate(engine, base);
    // Una tanda automática en curso (el agente ya está quieto): /verificar tiene que esperarla.
    const order: string[] = [];
    let finish!: () => void;
    engine.autoVerification = new Promise<void>((resolve) => { finish = resolve; }).then(() => { order.push("automática terminó"); engine.autoVerification = undefined; });
    engine.provider.faux!.queue = [call("verdict", { state: "candidato", reason: "falta el control" })];
    const asked = client.ask("verify", { value: id }).then((lines) => { order.push("manual terminó"); return lines; });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.deepEqual(order, [], "no arrancó en paralelo");
    assert.equal(engine.provider.faux!.queue.length, 1, "el verificador manual todavía no pidió nada");
    finish();
    const lines = (await asked).join("\n");
    assert.deepEqual(order, ["automática terminó", "manual terminó"]);
    assert.match(lines, new RegExp(`^${id}  candidato`, "m"));
    assert.match(lines, /Esperé a que terminara la verificación automática/);
    // Un id inexistente por el daemon: el error lista los válidos y no verifica otro.
    await assert.rejects(client.ask("verify", { value: "ffffffff" }), new RegExp(`No hay un hallazgo «ffffffff»[\\s\\S]*${id}`));
    client.close();
  } finally {
    await daemon.close();
    server.close();
  }
});
