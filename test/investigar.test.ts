import "./datos-tmp.ts";
// Modo investigar (src/investigar/): máquina de estados en datos, diario append-only, orquestador que no lee
// el código, tramos con contexto limpio, subida de nivel sólo con evidencia ejecutable, verificación por
// ejecución, retomar desde el diario, topes de USD, panel y pie. Todo con proveedores falsos y dobles de las
// herramientas de la caja (harness_build, fuzz_run, poc_run).
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { Diario, diariosDe, plegar } from "../src/investigar/diario.ts";
import { guardarPoc } from "../src/investigar/ejecucion.ts";
import { ESTADOS, ESTADOS_ID } from "../src/investigar/estados.ts";
import { leerPedido, movidasPosibles } from "../src/investigar/investigacion.ts";
import { projectPaths } from "../src/store.ts";
import { CANARIO_REPO, guionFeliz, motor, MundoInv, repo } from "./investigar-falso.ts";

process.env.LC_ALL = "es_AR.UTF-8";

const inicios = (diario: Diario) => diario.leer().flatMap((a) => (a.tipo === "estado.inicio" ? [`${a.estado}${a.hipotesis ? ` ${a.hipotesis}` : ""}`] : []));
const opciones = (prompt: string) => [...prompt.matchAll(/^(\d+)\. (.+)$/gm)].map((m) => ({ n: m[1]!, texto: m[2]! }));

/** Orquestador de las pruebas: profundiza h1, prueba h2 una vez y después pide el reporte. */
function orquestadorPrueba(prompt: string): string {
  const lista = opciones(prompt);
  const h1 = lista.find((o) => / sobre h1 /.test(o.texto));
  if (h1) return `MOVIDA: ${h1.n}\nMOTIVO: h1 es la más prometedora.`;
  const h2 = lista.find((o) => /harness-1 \(función\) sobre h2/.test(o.texto));
  if (h2 && !/harness-1:h2/.test(prompt)) return `MOVIDA: ${h2.n}\nMOTIVO: probar h2 una vez.`;
  const reporte = lista.find((o) => /^reporte/.test(o.texto));
  if (reporte) return `MOVIDA: ${reporte.n}\nMOTIVO: ya alcanza para el reporte.`;
  return "MOVIDA: 1\nMOTIVO: la primera.";
}

test("estados en datos: cada uno declara entrada, salida, herramientas, criterio de avance, topes y movidas válidas", () => {
  for (const id of ESTADOS_ID) {
    const def = ESTADOS[id];
    assert.equal(def.id, id);
    assert.ok(def.entrada.length && def.herramientas.length && def.tarea.length > 40, id);
    assert.equal(def.avance.salida, def.salida, `${id}: el criterio mira la salida que pide`);
    assert.ok(def.tope.pasos > 0 && Number(def.tope.usd) > 0 && def.tope.intentos > 0, id);
    for (const movida of [...def.siguiente.cumplido, ...def.siguiente.fallido]) assert.ok(ESTADOS[movida.estado], `${id} → ${movida.estado}`);
    if (def.harness) assert.equal(def.harness.requiere, def.harness.nivel - 1, `${id}: un nivel exige el anterior`);
    if (def.porHipotesis) assert.ok(def.avance.ejecucion, `${id}: los harnesses avanzan sólo con ejecución`);
  }
  assert.deepEqual(leerPedido("libparse: parser de cabeceras 5"), { objetivo: "libparse: parser de cabeceras", presupuesto: "5" });
  assert.deepEqual(leerPedido("libparse usd 12,5"), { objetivo: "libparse", presupuesto: "12.5" });
  assert.deepEqual(leerPedido("libparse"), { objetivo: "libparse" });
});

test("avanza por los estados con contexto limpio, el orquestador decide sin ver el código, cada rol con su modelo y el bucle principal ni se entera", async () => {
  const mundo = new MundoInv();
  mundo.orquestador = orquestadorPrueba;
  const { engine, corridas, avisos } = motor(mundo);
  try {
    await engine.setMediumModel("faux/hy4");
    mundo.bucle = [{ text: "Hola, arrancamos." }];
    await engine.send("MENSAJE_DEL_CHAT_9b2: arrancamos");
    const antes = { mensajes: engine.agent.messages.length, herramientas: engine.agent.tools.map((tool) => tool.name), system: engine.agent.system };
    const lineas = await engine.investigar!.comando("libparse: parser de cabeceras 5");
    assert.match(lineas[0]!, /^Investigación [0-9a-f]{8} abierta: «libparse: parser de cabeceras», tope USD 5,00\.$/);
    await engine.investigar!.esperar();
    const { diario, p } = engine.investigar!.todas()[0]!;

    // Los estados en el orden que eligió el orquestador; termina con el reporte.
    assert.deepEqual(inicios(diario), ["analista", "hipotesis", "harness-1 h1", "harness-2 h1", "harness-3 h1", "harness-1 h2", "reporte"]);
    assert.equal(p.fase, "cerrada");
    assert.ok(p.reporte && p.mapa);
    assert.deepEqual(p.hipotesis.map((h) => [h.id, h.nivel]), [["h1", 3], ["h2", 0], ["h3", 0]]);
    assert.ok(avisos.some((aviso) => /La investigación [0-9a-f]{8} terminó\. 3 hipótesis, 1 con evidencia ejecutable \(nivel máximo 3\)/.test(aviso)), avisos.join("\n"));

    // h1 subió nivel por nivel con su PoC reproducido en limpio; su hallazgo quedó verificado por ejecución.
    const h1 = p.hipotesis[0]!;
    assert.ok(h1.pocs[1] && h1.pocs[2] && h1.pocs[3]);
    const hallazgo = engine.findings.get(h1.hallazgo!)!;
    assert.equal(hallazgo.state, "verificado");
    assert.match(hallazgo.decidedBy, /^verificador:/);
    assert.match(hallazgo.reason, /reproduce de forma determinista: la señal «AddressSanitizer: heap-buffer-overflow» en 2 de 2 corridas en limpio/);
    for (const nivel of [1, 2, 3] as const) assert.ok(hallazgo.evidence.includes(h1.pocs[nivel]!), `evidencia del nivel ${nivel}`);
    assert.deepEqual(corridas, ["./h1-n1 crash-h1", "./h1-n1 crash-h1", "./h1-n2 crash-h1", "./h1-n2 crash-h1", "./h1-n3 crash-h1", "./h1-n3 crash-h1"]);
    assert.equal(mundo.de(/^verificador:/).length, 0, "verificar por ejecución no le pregunta a un modelo");

    // El orquestador decide con el resumen del diario: ni el código, ni el mapa, ni la conversación.
    const orquestador = mundo.de(/^inv:[0-9a-f]{8}:orquestador$/);
    assert.ok(orquestador.length >= 4);
    for (const pedido of orquestador) {
      assert.doesNotMatch(pedido.mensajes, new RegExp(`${CANARIO_REPO}|memcpy|MENSAJE_DEL_CHAT|Leo el parser`));
      assert.match(pedido.mensajes, /MOVIDAS POSIBLES/);
      assert.equal(pedido.modelo, "glm", "el orquestador es el modelo barato del bucle");
      assert.deepEqual(pedido.herramientas, []);
    }
    assert.ok(diario.leer().some((a) => a.tipo === "orquestador" && a.por === "modelo" && /h1 es la más prometedora/.test(a.motivo)));

    // Cada tramo arranca limpio: un solo mensaje armado del diario y los artefactos citados, nunca el chat.
    const tramos = new Map<string, typeof mundo.pedidos>();
    for (const pedido of mundo.de(/^inv:[0-9a-f]{8}:(?!orquestador)/)) tramos.set(pedido.worker, [...(tramos.get(pedido.worker) ?? []), pedido]);
    assert.equal(tramos.size, 7);
    for (const [worker, pedidos] of tramos) {
      const primero = pedidos[0]!;
      assert.equal(JSON.parse(primero.mensajes).length, 1, `${worker}: contexto limpio`);
      assert.doesNotMatch(primero.mensajes, /MENSAJE_DEL_CHAT|Hola, arrancamos/, worker);
      assert.match(primero.system, /^Sos un tramo de una investigación de Orobas/);
      assert.ok(primero.herramientas.includes("investigation_output"));
      assert.ok(!primero.herramientas.includes("finding_record") && !primero.herramientas.includes("delegate"), worker);
    }
    const de = (patron: RegExp) => [...tramos.entries()].find(([worker]) => patron.test(worker))![1];
    assert.ok(de(/:analista:/).slice(1).some((pedido) => pedido.mensajes.includes(CANARIO_REPO)), "el analista sí lee el código");
    assert.match(de(/:hipotesis:/)[0]!.primero, new RegExp(`MAPA \\(sha256:[0-9a-f]{64}\\):[\\s\\S]*${CANARIO_REPO}`), "hipótesis recibe el mapa citado");
    assert.doesNotMatch(de(/:harness-1:h1:/)[0]!.mensajes, new RegExp(`${CANARIO_REPO}|Leo el parser|puntos_entrada`), "harness-1 no hereda lo que leyó el analista");
    assert.match(de(/:harness-2:h1:/)[0]!.primero, new RegExp(`EVIDENCIA DEL NIVEL 1[\\s\\S]*PoC: ${h1.pocs[1]}`));
    assert.match(de(/:reporte:/)[0]!.primero, /EVIDENCIA POR HIPÓTESIS[\s\S]*h1 \[alta\] nivel 3[\s\S]*harness-1 falló: el harness no disparó/);
    for (const name of ["harness_build", "fuzz_run", "poc_run", "code_read"]) assert.ok(de(/:harness-1:h1:/)[0]!.herramientas.includes(name), name);

    // El modelo de cada estado sale del router por rol y nivel: el medio lee, el estándar blue planifica y redacta, el red explota.
    const modelos = Object.fromEntries([...tramos.entries()].map(([worker, pedidos]) => [worker.split(":").slice(2, -1).join(":"), pedidos[0]!.modelo]));
    assert.deepEqual(modelos, { analista: "hy4", hipotesis: "kimi", "harness-1:h1": "ultra", "harness-2:h1": "ultra", "harness-3:h1": "ultra", "harness-1:h2": "ultra", reporte: "kimi" });

    // El bucle principal no cambió: ni mensajes, ni herramientas, ni prompt; una sola solicitud suya (la del chat).
    assert.equal(engine.agent.messages.length, antes.mensajes);
    assert.deepEqual(engine.agent.tools.map((tool) => tool.name), antes.herramientas);
    assert.equal(engine.agent.system, antes.system);
    assert.equal(mundo.de(/^principal$/).length, 1);

    // Costo por estado y total, desde el ledger, igual a lo que cobró el proveedor.
    const costos = engine.investigar!.costos(p.id);
    const cobrado = mundo.de(/^inv:/).reduce((sum, pedido) => sum + pedido.pico, 0n);
    assert.equal(costos.total.pico, cobrado);
    assert.equal(costos.total.tramos, 7);
    assert.deepEqual([...costos.porEstado.keys()].sort(), ["analista", "harness-1", "harness-2", "harness-3", "hipotesis", "orquestador", "reporte"]);
  } finally {
    await engine.close();
  }
});

test("subida de nivel: sólo con la evidencia ejecutable del nivel anterior, y un PoC que no reproduce no sube", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cyber-diario-"));
  const diario = new Diario(dir);
  diario.anotar({ tipo: "inicio", id: "0123456789abcdef", objetivo: "x", presupuesto: "5", sesion: "s", por: "operador" });
  diario.anotar({ tipo: "estado.inicio", tramo: 1, estado: "analista", intento: 1, modelo: "m", worker: "w" });
  diario.anotar({ tipo: "estado.fin", tramo: 1, estado: "analista", resultado: "cumplido", motivo: "ok", pasos: 2, usd: "0.01" });
  diario.anotar({ tipo: "estado.inicio", tramo: 2, estado: "hipotesis", intento: 1, modelo: "m", worker: "w" });
  for (const id of ["h1", "h2"]) diario.anotar({ tipo: "hipotesis", tramo: 2, id, titulo: id, clase: "c", activo: `a:${id}`, porque: "p", evidencia: "e", prioridad: "alta" });
  diario.anotar({ tipo: "estado.fin", tramo: 2, estado: "hipotesis", resultado: "cumplido", motivo: "ok", pasos: 1, usd: "0.01" });
  const etiqueta = (lista: Array<{ estado: string; hipotesis?: string }>) => lista.map((m) => `${m.estado}${m.hipotesis ? ` ${m.hipotesis}` : ""}`);
  assert.deepEqual(etiqueta(movidasPosibles(plegar(diario.leer())!)), ["harness-1 h1", "harness-1 h2", "reporte"], "sin nivel 1 no hay harness-2");

  // Un nivel salteado no cuenta; una corrida que no disparó tampoco.
  diario.anotar({ tipo: "ejecucion", tramo: 3, hipotesis: "h2", nivel: 2, dispara: true, poc: "sha256:aa", corridas: "2/2", motivo: "saltó el nivel 1" });
  diario.anotar({ tipo: "ejecucion", tramo: 3, hipotesis: "h1", nivel: 1, dispara: false, poc: "sha256:bb", corridas: "1/2", motivo: "no reproduce" });
  let p = plegar(diario.leer())!;
  assert.deepEqual(p.hipotesis.map((h) => h.nivel), [0, 0]);
  diario.anotar({ tipo: "estado.inicio", tramo: 3, estado: "harness-1", hipotesis: "h1", intento: 1, modelo: "m", worker: "w" });
  diario.anotar({ tipo: "ejecucion", tramo: 3, hipotesis: "h1", nivel: 1, dispara: true, poc: "sha256:cc", comando: "./h1", corridas: "2/2", motivo: "reproduce" });
  diario.anotar({ tipo: "estado.fin", tramo: 3, estado: "harness-1", hipotesis: "h1", resultado: "cumplido", motivo: "ok", pasos: 3, usd: "0.1" });
  p = plegar(diario.leer())!;
  assert.deepEqual(p.hipotesis.map((h) => h.nivel), [1, 0]);
  assert.equal(p.hipotesis[0]!.pocs[1], "sha256:cc");
  assert.deepEqual(etiqueta(movidasPosibles(p)), ["harness-2 h1", "harness-1 h2", "reporte"], "h1 sube a componentes; h2 no");

  // Un tramo que se cortó (pausa) o que quedó abierto (caída) se retoma antes que cualquier otra movida.
  diario.anotar({ tipo: "estado.inicio", tramo: 4, estado: "harness-2", hipotesis: "h1", intento: 1, modelo: "m", worker: "w" });
  assert.deepEqual(etiqueta(movidasPosibles(plegar(diario.leer())!)), ["harness-2 h1"]);
  diario.anotar({ tipo: "estado.fin", tramo: 4, estado: "harness-2", hipotesis: "h1", resultado: "cortado", motivo: "pausa", pasos: 1, usd: "0.01" });
  p = plegar(diario.leer())!;
  assert.deepEqual(etiqueta(movidasPosibles(p)), ["harness-2 h1"]);
  assert.equal(p.intentos["harness-2:h1"], undefined, "un corte no gasta un intento");
  assert.match(new Diario(dir).leer().at(-1)!.at, /^\d{4}-/);

  // Con el motor: el harness dice que disparó, pero el PoC no se reproduce en limpio (1 de 2): no sube y el hallazgo queda candidato con el motivo.
  const mundo = new MundoInv();
  mundo.orquestador = (prompt) => { const lista = opciones(prompt); const h1 = lista.find((o) => / sobre h1 /.test(o.texto)); const reporte = lista.find((o) => /^reporte/.test(o.texto)); return `MOVIDA: ${(h1 ?? reporte ?? lista[0])!.n}`; };
  mundo.tramo = (info) => (info.estado === "harness-1" && info.hipotesis === "h1" ? (info.paso === 0 ? { toolCalls: [{ name: "investigation_output", arguments: { dispara: true, comando: "./h1 flaky", senal: "AddressSanitizer", resumen: "dispara a veces" } }] } : { text: "Listo." }) : guionFeliz(info));
  const { engine, corridas } = motor(mundo);
  try {
    await engine.investigar!.comando("libparse 5");
    await engine.investigar!.esperar();
    const { diario: real, p: final } = engine.investigar!.todas()[0]!;
    assert.deepEqual(inicios(real), ["analista", "hipotesis", "harness-1 h1", "harness-1 h1", "reporte"]);
    assert.equal(final.hipotesis[0]!.nivel, 0);
    const ejecuciones = real.leer().filter((a) => a.tipo === "ejecucion");
    assert.ok(ejecuciones.length === 2 && ejecuciones.every((a) => a.tipo === "ejecucion" && !a.dispara && a.corridas === "1/2"));
    const hallazgo = engine.findings.get(final.hipotesis[0]!.hallazgo!)!;
    assert.equal(hallazgo.state, "candidato");
    assert.match(hallazgo.decidedBy, /^verificador:/);
    assert.match(hallazgo.reason, /no reproduce de forma determinista: la señal «AddressSanitizer» en 1 de 2 corridas/);
    assert.equal(corridas.length, 4);
  } finally {
    await engine.close();
  }
});

test("retomar: si el proceso se corta a mitad de un estado, la investigación sigue desde el diario sin rehacer lo hecho", async () => {
  const mundo = new MundoInv();
  mundo.orquestador = orquestadorPrueba;
  let llego!: () => void;
  const enHipotesis = new Promise<void>((resolve) => (llego = resolve));
  let frenado = true;
  mundo.frenar = (worker, signal) => (frenado && /:hipotesis:/.test(worker) ? new Promise<void>((resolve) => { llego(); signal?.addEventListener("abort", () => resolve(), { once: true }); }) : undefined);
  const cwd = repo();
  const { engine } = motor(mundo, { cwd });
  await engine.investigar!.comando("libparse 5");
  await enHipotesis;
  // El proceso se cierra en medio del estado «hipótesis».
  await engine.close();
  const [cortado] = diariosDe(join(projectPaths(cwd).root, "investigaciones"));
  const aMedias = plegar(cortado!.leer())!;
  assert.equal(aMedias.fase, "corriendo");
  assert.deepEqual(aMedias.pendiente, { estado: "hipotesis" });
  assert.deepEqual(inicios(cortado!), ["analista", "hipotesis"]);

  frenado = false;
  const { engine: otro, avisos } = motor(mundo, { cwd, resume: engine.sessionId });
  try {
    assert.ok(otro.notices.some((aviso) => /quedó a medio en hipótesis: \/investigar seguir la retoma desde el diario/.test(aviso)), otro.notices.join("\n"));
    const lineas = await otro.investigar!.comando("seguir");
    assert.match(lineas[0]!, /^Sigo la investigación [0-9a-f]{8} desde el diario: hipótesis\./);
    await otro.investigar!.esperar();
    const { diario, p } = otro.investigar!.todas()[0]!;
    assert.deepEqual(inicios(diario), ["analista", "hipotesis", "hipotesis", "harness-1 h1", "harness-2 h1", "harness-3 h1", "harness-1 h2", "reporte"], "el analista no se repite");
    const segunda = diario.leer().filter((a) => a.tipo === "estado.inicio" && a.estado === "hipotesis");
    assert.deepEqual(segunda.map((a) => a.tipo === "estado.inicio" && a.intento), [1, 1], "el intento cortado no cuenta");
    assert.equal(p.fase, "cerrada");
    assert.equal(new Set(mundo.de(/:analista:/).map((pedido) => pedido.worker)).size, 1, "un solo tramo de analista en las dos vidas del proceso");
    assert.ok(avisos.some((aviso) => /terminó/.test(aviso)));
  } finally {
    await otro.close();
  }
});

test("verificación por ejecución: con PoC se corre en limpio (reproduce → verificado, no → candidato con motivo); lo web sigue con el verificador de siempre", async () => {
  const mundo = new MundoInv();
  const { engine, corridas } = motor(mundo);
  const { engine: sinCaja } = motor(mundo, { caja: false });
  try {
    const registrar = (target: Engine, comando: string, asset: string) => {
      const poc = guardarPoc(target.artifacts, { comando, senal: "AddressSanitizer" });
      return { poc, finding: target.findings.record({ title: `Desborde ${asset}`, kind: "desborde de buffer", asset, summary: "memcpy sin límite", evidence: [poc] }, target.sessionId) };
    };
    const bueno = registrar(engine, "./poc crash", "src/parser.c:parse_header");
    const verdict = await engine.verifier.verify(bueno.finding.id);
    assert.equal(verdict.state, "verificado");
    assert.equal(verdict.requests, 0);
    assert.deepEqual(verdict.ejecucion, { disparos: 2, corridas: 2 });
    assert.ok(verdict.evidence.includes(bueno.poc) && verdict.evidence.length === 2, "el PoC y la salida de las corridas");
    assert.match(JSON.parse(engine.artifacts.read(verdict.transcript).toString()).corridas[0].salida, /heap-buffer-overflow/);
    assert.deepEqual(corridas, ["./poc crash", "./poc crash"]);

    const flojo = registrar(engine, "./poc flaky", "src/parser.c:parse_trailer");
    const otro = await engine.verifier.verify(flojo.finding.id);
    assert.equal(otro.state, "candidato");
    assert.match(otro.reason, /no reproduce de forma determinista/);
    assert.equal(engine.findings.get(flojo.finding.id)!.state, "candidato");
    assert.ok(!engine.verifier.pending().some((item) => item.id === flojo.finding.id), "no se reintenta solo en cada turno");

    const sinPoc = registrar(sinCaja, "./poc crash", "src/parser.c:parse_header");
    assert.match((await sinCaja.verifier.verify(sinPoc.finding.id)).reason, /no hay poc_run para correrlo en limpio/);

    // Con una investigación abierta: un candidato de código sin PoC no pasa a verificado (y no gasta un modelo);
    // uno web sigue con el verificador de siempre.
    mundo.frenar = (worker, signal) => (worker.startsWith("inv:") ? new Promise<void>((resolve) => signal?.addEventListener("abort", () => resolve(), { once: true })) : undefined);
    await engine.investigar!.comando("libparse 5");
    engine.investigar!.pausar();
    await engine.investigar!.esperar();
    mundo.frenar = () => undefined;
    const nota = engine.artifacts.put("lectura de src/server.c", "text/plain", "prueba").hash;
    const codigo = engine.findings.record({ title: "Signo en read_request", kind: "conversión de signo", asset: "src/server.c:read_request", summary: "int a size_t", evidence: [nota] }, engine.sessionId);
    const estatico = await engine.verifier.verify(codigo.id);
    assert.equal(estatico.state, "candidato");
    assert.match(estatico.reason, /no trae evidencia ejecutable/);
    assert.equal(mundo.de(/^verificador:/).length, 0);
    const web = engine.findings.record({ title: "IDOR en pedidos", kind: "control de acceso", asset: "https://app.test/api/pedidos", summary: "otro usuario lee el pedido", evidence: [nota] }, engine.sessionId);
    const veredicto = await engine.verifier.verify(web.id);
    assert.equal(veredicto.state, "candidato");
    // El motivo lleva las comprobaciones del verificador (alcance del programa, coherencia, código abierto, duplicados).
    assert.match(veredicto.reason, /^sin acceso para reproducir\nComprobaciones: alcance del programa: /);
    assert.ok(mundo.de(/^verificador:/).length >= 1, "lo web pasa por el verificador del modelo");
    engine.investigar!.cerrar();
  } finally {
    await engine.close();
    await sinCaja.close();
  }
});

test("tope de USD por investigación: se pausa al llegar, no sigue sin más presupuesto y sigue con uno mayor", async () => {
  const mundo = new MundoInv();
  // Un analista que lee y lee sin entregar: cada paso relee un contexto más grande.
  mundo.tramo = (info) => (info.estado === "analista" ? { toolCalls: [{ name: "code_read", arguments: { path: `src/m${info.paso}.c` } }], text: "x".repeat(4000) } : guionFeliz(info));
  const { engine, avisos } = motor(mundo);
  engine.catalog.register([{ name: "code_read", label: "Leer código", description: "doble", parameters: { type: "object", properties: {}, additionalProperties: true }, execute: (args: { path: string }) => ({ text: `${args.path}: ${"c".repeat(8000)}` }) }]);
  try {
    await engine.investigar!.comando("libparse 0.05");
    await engine.investigar!.esperar();
    let { p } = engine.investigar!.todas()[0]!;
    assert.equal(p.fase, "tope");
    const gastado = engine.investigar!.costos(p.id).total.pico;
    const maxPaso = mundo.de(/^inv:/).reduce((max, pedido) => (pedido.pico > max ? pedido.pico : max), 0n);
    assert.ok(gastado <= 50_000_000_000n + maxPaso, `gastó ${gastado} con un tope de 0,05 USD`);
    assert.ok(avisos.some((aviso) => /llegó a su tope \(USD 0,0\d de 0,05: lo que queda no alcanza para otro tramo\) y se pausó/.test(aviso)), avisos.join("\n"));
    assert.equal(engine.investigar!.pie()!.label.startsWith("inv: en su tope · "), true);
    assert.throws(() => engine.investigar!.seguir(), /ya se gastó/);
    const pedidos = mundo.pedidos.length;
    const lineas = engine.investigar!.seguir("0.12");
    assert.match(lineas[0]!, /Tope USD 0,12/);
    await engine.investigar!.esperar();
    ({ p } = engine.investigar!.todas()[0]!);
    assert.ok(mundo.pedidos.length > pedidos, "siguió con el tope nuevo");
    assert.equal(p.presupuesto, "0.12");
    assert.ok(engine.investigar!.costos(p.id).total.pico <= 120_000_000_000n + maxPaso);
  } finally {
    await engine.close();
  }
});

test("sin saldo en el proveedor: la investigación se pausa sin gastar intentos y avisa", async () => {
  const mundo = new MundoInv();
  mundo.tramo = (info) => (info.estado === "hipotesis" ? { fail: { message: "HTTP 402 insufficient_balance: sin saldo", exhausted: true } } : guionFeliz(info));
  const { engine, avisos } = motor(mundo);
  try {
    await engine.investigar!.comando("libparse 5");
    await engine.investigar!.esperar();
    const { diario, p } = engine.investigar!.todas()[0]!;
    assert.equal(p.fase, "pausada");
    assert.deepEqual(p.pendiente, { estado: "hipotesis" }, "se retoma ahí");
    assert.equal(p.intentos.hipotesis, undefined, "no gastó un intento");
    assert.ok(diario.leer().some((a) => a.tipo === "control" && a.accion === "pausa" && /no hay saldo/.test(a.motivo ?? "")));
    assert.ok(avisos.some((aviso) => /se pausó: el proveedor dice que no hay saldo/.test(aviso)), avisos.join("\n"));
  } finally {
    await engine.close();
  }
});

test("panel y pie: estado, hipótesis con su nivel, evidencia y costo por estado; el pie dice dónde va mientras corre", async () => {
  const mundo = new MundoInv();
  mundo.orquestador = orquestadorPrueba;
  let soltar!: () => void;
  const suelta = new Promise<void>((resolve) => (soltar = resolve));
  let llego!: () => void;
  const enHarness = new Promise<void>((resolve) => (llego = resolve));
  mundo.frenar = (worker) => (/:harness-2:h1:/.test(worker) ? (llego(), suelta) : undefined);
  const { engine } = motor(mundo);
  try {
    assert.equal(engine.investigar!.pie(), undefined, "sin investigación, nada en el pie");
    await engine.investigar!.comando("libparse 5");
    await enHarness;
    const corriendo = engine.investigar!.pie()!;
    assert.equal(corriendo.activa, true);
    assert.match(corriendo.label, /^inv: harness-2 · h1\/3 · USD \d+,\d\d$/);
    assert.match(corriendo.short, /^inv: harness-2 · USD \d+,\d\d$/);
    const panel = engine.investigar!.estadoLineas();
    assert.equal(panel[0], "INVESTIGACIÓN");
    assert.match(panel.join("\n"), /Estado {6}harness-2 \(componentes\) · h1 · corriendo · [0-9a-f]{8}/);
    assert.match(panel.join("\n"), /Hipótesis {3}id {3}nivel {4}prior\. {2}título\n {12}h1 {3}■□□ 1\/3 {2}alta {4}Desborde de buffer en parse_header/);
    assert.match(panel.join("\n"), /Evidencia {3}h1 n1 PoC [0-9a-f]{8} · hallazgo [0-9a-f]{8} verificado/);
    assert.match(panel.join("\n"), /Por estado {2}estado {18}tramos {2}pasos {4}tokens {5}USD\n {12}analista {21}1/);
    for (const linea of panel.filter((l) => !/^(Diario|Uso:)/.test(l))) assert.ok(linea.length <= 72, `más de 72 columnas: «${linea}»`);
    assert.equal(panel.at(-1), "Uso: /investigar <objetivo> [usd] · estado · pausa · seguir [usd] · cerrar");

    const pausa = engine.investigar!.pausar();
    assert.match(pausa[0]!, /Pausé la investigación/);
    soltar();
    await engine.investigar!.esperar();
    const pausada = engine.investigar!.pie()!;
    assert.equal(pausada.activa, false);
    assert.match(pausada.label, /^inv: pausada · harness-2 · h1\/3 · USD/);
    engine.investigar!.cerrar();
    assert.equal(engine.investigar!.pie(), undefined, "cerrada, el pie vuelve a ser el de siempre");
    assert.match(engine.investigar!.estadoLineas().join("\n"), /cerrada/);
  } finally {
    soltar();
    await engine.close();
  }
});

test("lenguaje natural: investigation_start abre el modo sólo con la cita del operador; la pista aparece sólo si nombra el modo", async () => {
  const mundo = new MundoInv();
  mundo.frenar = (worker, signal) => (worker.startsWith("inv:") ? new Promise<void>((resolve) => signal?.addEventListener("abort", () => resolve(), { once: true })) : undefined);
  const { engine } = motor(mundo);
  try {
    assert.ok(engine.catalog.available.has("investigation_start"));
    assert.match(engine.agent.system, /investigation_start/);
    assert.match(engine.agent.system, /Investigación automática: apagada/);
    assert.ok(engine.catalog.search("investigar").some((tool) => tool.name === "investigation_start"), "tool_search la encuentra");
    mundo.bucle = [
      { toolCalls: [{ name: "tools_load", arguments: { names: ["investigation_start"] } }] },
      { toolCalls: [{ name: "investigation_start", arguments: { objetivo: "libparse", pedido: "abrí el modo investigación sobre libparse con un tope de 3" } }] },
      { text: "No la abro: falta tu pedido." },
    ];
    await engine.send("¿qué hace el parser?");
    assert.equal(engine.investigar!.activa(), undefined, "sin cita del operador no se abre");
    assert.doesNotMatch(mundo.de(/^principal$/)[0]!.mensajes, /\[sistema\] El operador nombra el modo investigar/);
    mundo.bucle = [
      { toolCalls: [{ name: "investigation_start", arguments: { objetivo: "libparse", presupuesto_usd: 3, pedido: "abrí el modo investigación sobre libparse" } }] },
      { text: "Abierta." },
    ];
    await engine.send("abrí el modo investigación sobre libparse con un tope de 3");
    assert.match(mundo.de(/^principal$/).at(-2)!.mensajes, /\[sistema\] El operador nombra el modo investigar: se abre con investigation_start/);
    const abierta = engine.investigar!.activa()!;
    assert.equal(abierta.p.presupuesto, "3");
    const inicio = abierta.diario.leer()[0]!;
    assert.ok(inicio.tipo === "inicio" && inicio.por === "agente" && inicio.pedido === "abrí el modo investigación sobre libparse");
    engine.investigar!.cerrar();
  } finally {
    await engine.close();
  }
});

test("investigación automática apagada por defecto; al activarla usa la mitad del saldo y avisa", async () => {
  const mundo = new MundoInv();
  mundo.frenar = (worker, signal) => (worker.startsWith("inv:") ? new Promise<void>((resolve) => signal?.addEventListener("abort", () => resolve(), { once: true })) : undefined);
  const { engine, avisos } = motor(mundo, { budgetPico: 3_000_000_000_000n });
  try {
    const tool = engine.catalog.available.get("investigation_start")!;
    assert.ok(tool);
    await assert.rejects(async () => tool.execute({ objetivo: "src/parser.c" }, new AbortController().signal), /cita del operador|investigación automática/);
    engine.setInvestigationAuto(true);
    assert.match(engine.agent.system, /Investigación automática: activa/);
    await tool.execute({ objetivo: "src/parser.c", presupuesto_usd: 99 }, new AbortController().signal);
    assert.equal(Number(engine.investigar!.activa()!.p.presupuesto), 1.5, "ignora el monto del modelo y usa la mitad de USD 3");
    assert.ok(avisos.some((aviso) => /investigación automática/.test(aviso)));
    engine.investigar!.cerrar();
  } finally {
    await engine.close();
  }
});
