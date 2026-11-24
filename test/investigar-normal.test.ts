import "./datos-tmp.ts";
// El modo investigar es un MODO: si el operador no lo abre, la sesión es la de siempre. Se corre la misma
// conversación (sondeo, un candidato web, la verificación automática y un turno de texto) con el modo
// disponible y con el modo apagado del todo, y se compara lo que sale al proveedor: el mismo prompt, las
// mismas herramientas, los mismos mensajes, los mismos eventos, el mismo verificador para lo web y el mismo pie.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import type { Engine } from "../src/engine.ts";
import { parseRule } from "../src/scope.ts";
import { projectPaths } from "../src/store.ts";
import { motor, MundoInv, repo, TARIFAS } from "./investigar-falso.ts";

process.env.LC_ALL = "es_AR.UTF-8";

/** Lo que cambia entre dos corridas iguales sin que cambie nada: ids al azar, horas y hashes de lo que los lleva. */
const normal = (texto: string) => texto
  .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, "UUID")
  .replace(/sha256:[0-9a-f]{64}/g, "HASH")
  .replace(/\b[0-9a-f]{8}\b/g, "ID8")
  .replace(/"at":\d+/g, '"at":0')
  .replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g, "FECHA");

async function sesion(modo: "disponible" | "apagado"): Promise<{ mundo: MundoInv; engine: Engine; eventos: string[] }> {
  const mundo = new MundoInv();
  const { engine } = motor(mundo, { autoVerify: true, ...(modo === "apagado" ? { investigacion: false } : {}) });
  engine.scope.save({ source: "prueba", include: [parseRule("app.test")], exclude: [], notes: "" });
  for (const tool of engine.agent.tools) if (tool.name === "http_request") tool.execute = async () => ({ text: "HTTP 200 OK: el pedido 7 es de otro usuario" });
  const evidencia = engine.artifacts.put("GET /api/pedidos/7 → 200 con la sesión de B", "text/plain", "prueba").hash;
  mundo.bucle = [
    { text: "Pruebo el pedido 7.", toolCalls: [{ name: "http_request", arguments: { url: "https://app.test/api/pedidos/7" } }] },
    { toolCalls: [{ name: "finding_record", arguments: { state: "candidato", title: "IDOR en pedidos", kind: "control de acceso", severity: "alta", asset: "https://app.test/api/pedidos", summary: "B lee el pedido 7 de A", evidence: [evidencia] } }] },
    { text: "Registré un candidato: IDOR en pedidos." },
    { text: "Sigo con el resto del alcance." },
  ];
  await engine.send("Probá el control de acceso de app.test, investigá a fondo los pedidos");
  await engine.send("seguí");
  const eventos = (engine.db.prepare("select type from events where session_id=? order by seq").all(engine.sessionId) as Array<{ type: string }>).map((row) => row.type);
  return { mundo, engine, eventos };
}

test("sesión normal sin cambios: con el modo disponible y sin abrirlo, el proveedor recibe lo mismo que con el modo apagado", async () => {
  const con = await sesion("disponible");
  const sin = await sesion("apagado");
  try {
    const vista = (mundo: MundoInv) => mundo.pedidos.map((pedido) => ({ worker: pedido.worker, modelo: pedido.modelo, system: normal(pedido.system), herramientas: pedido.herramientas, mensajes: normal(pedido.mensajes) }));
    assert.ok(con.mundo.pedidos.some((pedido) => pedido.worker.startsWith("verificador:")), "lo web pasó por el verificador del modelo");
    assert.deepEqual(vista(con.mundo), vista(sin.mundo), "mismo prompt, mismas herramientas, mismos mensajes, mismo verificador");
    assert.equal(con.engine.agent.system, sin.engine.agent.system, "el prompt del bucle, byte a byte");
    assert.deepEqual(con.engine.agent.tools.map((tool) => [tool.name, JSON.stringify(tool.parameters)]), sin.engine.agent.tools.map((tool) => [tool.name, JSON.stringify(tool.parameters)]));
    assert.deepEqual(con.eventos, sin.eventos, "los mismos eventos, en el mismo orden");
    assert.ok(!con.eventos.some((type) => type.startsWith("investigacion")));
    assert.doesNotMatch(con.mundo.pedidos.map((pedido) => pedido.mensajes).join("\n"), /investigation_start|modo investigar/, "ni una pista: el operador no nombró el modo");
    assert.ok(!con.mundo.pedidos.some((pedido) => pedido.worker.startsWith("inv:")), "ni orquestador ni tramos");
    assert.ok(!existsSync(con.engine.investigar!.base), "no crea la carpeta de investigaciones");
    assert.equal(con.engine.investigar!.pie(), undefined, "nada en el pie");
    assert.deepEqual(con.engine.notices, sin.engine.notices);
    const verificado = con.engine.findings.list({ sessionId: con.engine.sessionId })[0]!;
    assert.equal(verificado.state, "candidato");
    // El motivo lleva las comprobaciones del verificador (alcance del programa, coherencia, código abierto, duplicados).
    assert.match(verificado.reason, /^sin acceso para reproducir\nComprobaciones: alcance del programa: /, "el veredicto lo dictó el verificador de siempre");
  } finally {
    await con.engine.close();
    await sin.engine.close();
  }
});

test("daemon: sin investigación abierta, el estado que ve la TUI no trae nada del modo (el pie es el de siempre)", async () => {
  const cwd = repo();
  const mundo = new MundoInv();
  const glm = mundo.proveedor("glm", TARIFAS.glm);
  const daemon = new Daemon({ cwd, resolve: () => glm, engine: { strong: mundo.proveedor("ultra", TARIFAS.ultra), autoVerify: false, cveFeed: false } });
  await daemon.listen();
  try {
    const client = await connectDaemon(cwd, { spawn: false });
    await client.attach({ session: "new" });
    assert.ok(!("investigacion" in client.status));
    mundo.bucle = [{ text: "Listo." }];
    await client.ask("investigar", {});
    assert.ok(!("investigacion" in client.status), "mirar el panel no abre nada");
    assert.ok(!existsSync(join(projectPaths(cwd).root, "investigaciones")));
    client.close();
  } finally {
    daemon.close();
  }
});
