import "./datos-tmp.ts";
// Alcance, hallazgos y verificador por sesión. Trazas reales: varias sesiones de programas distintos
// en la misma carpeta (~) se pisaban el alcance («el alcance tuyo sigue siendo el tuyo, no wordpress»),
// los informes mezclaban programas y el verificador fallaba más de lo que dictaba.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { connectDaemon } from "../src/client.ts";
import { Daemon } from "../src/daemon.ts";
import { sharedFolderWarning } from "../src/datos.ts";
import { Engine } from "../src/engine.ts";
import { findingsView } from "../src/findings.ts";
import { resolveProvider } from "../src/providers.ts";
import { generateReport } from "../src/report.ts";
import { decide, parseRule, ScopeStore } from "../src/scope.ts";
import { forkSession } from "../src/sesiones.ts";
import { logEvent, openStore, projectPaths } from "../src/store.ts";
import { exhaustedError, VERIFIER_BUDGET_USD } from "../src/verifier.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-alcance-sesion-"));
const faux = () => resolveProvider("faux");
const load = (source: string, ...rules: string[]) => ({ source, include: rules.map((rule) => parseRule(rule)), exclude: [], notes: "" });

test("alcance por sesión: dos sesiones del mismo proyecto no se pisan, una nueva empieza vacía y la retomada recupera el suyo", async () => {
  const cwd = tmp();
  const cripto = new Engine({ cwd, provider: faux(), autoVerify: false });
  const wordpress = new Engine({ cwd, provider: faux(), autoVerify: false });
  try {
    cripto.scope.save(load("hackerone:shapeshift", "*.shapeshift.test"));
    wordpress.scope.save(load("hackerone:wordpress", "*.wordpress.test"));
    // Cargar el de WordPress no tocó el de cripto.
    assert.equal(cripto.scope.current()?.source, "hackerone:shapeshift");
    assert.equal(decide(cripto.scope.current(), "api.shapeshift.test").allowed, true);
    assert.equal(decide(cripto.scope.current(), "api.wordpress.test").allowed, false);
    assert.equal(decide(wordpress.scope.current(), "api.shapeshift.test").allowed, false);
    // Lo aplica el cliente HTTP de cada sesión, no sólo la vista.
    const blocked = await cripto.http.send({ url: "https://api.wordpress.test/" }).catch((error: Error) => ({ error: error.message }));
    assert.match(blocked.error ?? "", /Fuera del alcance/);
    // Y lo que ve el agente: su bloque <alcance> es el de su sesión.
    await cripto.send("seguimos con cripto");
    assert.match(String(cripto.agent.messages[0]!.content), /<alcance>\nrev \d+ \(hackerone:shapeshift\)\. Dentro: \*\.shapeshift\.test\./);
    assert.doesNotMatch(String(cripto.agent.messages[0]!.content), /wordpress/);

    // Una sesión nueva en la misma carpeta empieza vacía: no hereda el último cargado.
    const nueva = new Engine({ cwd, provider: faux(), autoVerify: false });
    assert.equal(nueva.scope.current(), undefined);
    assert.deepEqual(nueva.notices, []);
    await nueva.send("hola");
    assert.match(String(nueva.agent.messages[0]!.content), /<alcance>\nsin definir/);
    await nueva.close();

    // La vista del proyecto junta los de todas las sesiones (para el informe del proyecto y anonimizar).
    const project = cripto.scope.project()!;
    assert.deepEqual(project.include.map((rule) => rule.value).sort(), ["*.shapeshift.test", "*.wordpress.test"]);

    // Retomada, vuelve con el suyo.
    const id = cripto.sessionId;
    await cripto.close();
    const again = new Engine({ cwd, provider: faux(), autoVerify: false, resume: id });
    assert.equal(again.scope.current()?.source, "hackerone:shapeshift");
    assert.deepEqual(again.notices, []);
    // Una rama sigue el mismo trabajo: hereda el alcance de la sesión de la que sale.
    const fork = forkSession(again.db, id);
    assert.equal(again.scope.of(fork).current()?.source, "hackerone:shapeshift");
    await again.close();
  } finally {
    await Promise.allSettled([cripto.close(), wordpress.close()]);
  }
});

test("alcance: las filas viejas (sin sesión) no se heredan; una sesión vieja recupera sólo lo que cargó ella", async () => {
  const cwd = tmp();
  const db = openStore(projectPaths(cwd));
  // Una base de antes del cambio: la tabla sin sesión y dos sesiones que se pisaron el alcance.
  db.exec("create table scope(rev integer primary key autoincrement, json text not null, at text not null)");
  const before = "2026-11-10T10:00:00.000Z";
  const row = (source: string, host: string) => db.prepare("insert into scope(json,at) values(?,?)").run(JSON.stringify(load(source, host)), before);
  row("hackerone:shapeshift", "*.shapeshift.test"); // rev 1, la cargó la sesión cripto
  row("hackerone:wordpress", "*.wordpress.test"); // rev 2, la cargó la sesión wordpress y pisó la anterior
  const session = (id: string, messages: object[]) => {
    db.prepare("insert into sessions(id,started_at,model) values(?,?,?)").run(id, before, "faux/faux");
    messages.forEach((message, seq) => db.prepare("insert into messages(session_id,seq,json) values(?,?,?)").run(id, seq, JSON.stringify({ at: 1, ...message })));
  };
  const loaded = (handle: string, rev: number) => [
    { role: "user", content: `vamos con ${handle}` },
    { role: "assistant", content: "", toolCalls: [{ id: `c${rev}`, name: "h1_scope_load", arguments: "{}" }], stopReason: "toolUse", provider: "faux", model: "faux", requestId: `r${rev}` },
    { role: "tool", toolCallId: `c${rev}`, name: "h1_scope_load", content: `Alcance importado de HackerOne «${handle}»: 1 dentro, 0 excluidos (rev ${rev}).\n\nALCANCE · rev ${rev} · hackerone:${handle} · 2026-11-10 10:00`, isError: false },
    { role: "assistant", content: "Cargado.", toolCalls: [], stopReason: "stop", provider: "faux", model: "faux", requestId: `f${rev}` },
  ];
  // La sesión cripto cargó el suyo y después, por el error, vio el de WordPress en su bloque <alcance>.
  session("sesion-cripto", [...loaded("shapeshift", 1), { role: "user", content: "noooo el alcance tuyo sigue siendo el tuyo\n\n<alcance>\nrev 2 (hackerone:wordpress). Dentro: *.wordpress.test.\n</alcance>" }]);
  session("sesion-wordpress", loaded("wordpress", 2));
  // Ésta nunca cargó uno con el agente: sólo vio el último.
  session("sesion-mirona", [{ role: "user", content: "hola\n\n<alcance>\nrev 2 (hackerone:wordpress). Dentro: *.wordpress.test.\n</alcance>" }]);
  db.close();

  const open = (resume?: string) => new Engine({ cwd, provider: faux(), autoVerify: false, ...(resume && { resume }) });
  const cripto = open("sesion-cripto");
  try {
    // Recupera lo que cargó ella (rev 1), no lo que vio después (rev 2, de otra sesión).
    assert.equal(cripto.scope.current()?.source, "hackerone:shapeshift");
    assert.match(cripto.notices.join("\n"), /recuperé el que había cargado ella \(hackerone:shapeshift/);
    const event = cripto.db.prepare("select payload from events where session_id=? and type='alcance.recuperado'").get(cripto.sessionId) as { payload: string };
    assert.equal(JSON.parse(event.payload).fuente, "hackerone:shapeshift");
    // Una sola vez: retomarla de nuevo no copia otra revisión.
    await cripto.close();
    const otra = open("sesion-cripto");
    assert.equal(otra.scope.revisions().length, 1);
    assert.deepEqual(otra.notices, []);
    await otra.close();

    const wordpress = open("sesion-wordpress");
    assert.equal(wordpress.scope.current()?.source, "hackerone:wordpress");
    await wordpress.close();

    // Sin carga propia, no se le da el del proyecto: arranca vacía y el operador ve cuál vio y cómo tomarlo.
    const mirona = open("sesion-mirona");
    assert.equal(mirona.scope.current(), undefined);
    assert.match(mirona.notices.join("\n"), /arranca sin alcance\. El último que vio fue la rev 2 \(hackerone:wordpress: \*\.wordpress\.test\)\. Si era el suyo: \/alcance recuperar 2\./);
    mirona.scope.adopt(2);
    assert.equal(mirona.scope.current()?.source, "hackerone:wordpress");
    await mirona.close();

    // Una sesión nueva no pasa por la recuperación, aunque haya filas viejas.
    const nueva = open();
    assert.equal(nueva.scope.current(), undefined);
    assert.deepEqual(nueva.notices, []);
    // Las filas viejas siguen como «alcance viejo del proyecto».
    assert.equal(new ScopeStore(nueva.db).current()?.source, "hackerone:wordpress");
    await nueva.close();
  } finally {
    await cripto.close();
  }
});

test("daemon: el alcance de la TUI es el de su sesión; la CLI apunta a la última o a -s; /scope sesiones muestra cada uno", async () => {
  const cwd = tmp();
  const daemon = new Daemon({ cwd, resolve: () => faux(), autoResume: false });
  await daemon.listen();
  const one = await connectDaemon(cwd, { spawn: false });
  const two = await connectDaemon(cwd, { spawn: false });
  try {
    const first = await one.attach({ model: "faux" });
    const second = await two.attach({ model: "faux" });
    await one.view("scope", "add *.shapeshift.test");
    await two.view("scope", "add *.wordpress.test");
    assert.match((await one.view("scope")).join("\n"), /Dentro \(1\)\n  \*\.shapeshift\.test/);
    assert.doesNotMatch((await one.view("scope")).join("\n"), /wordpress/);
    assert.equal(daemon.hosts.get(first.sessionId)!.engine.scope.current()?.include[0]?.value, "*.shapeshift.test");
    assert.equal(daemon.hosts.get(second.sessionId)!.engine.scope.current()?.include[0]?.value, "*.wordpress.test");
    // Cada sesión con el suyo, para el operador.
    const each = (await one.view("scope", "sesiones")).join("\n");
    assert.match(each, new RegExp(`▸ ${first.sessionId.slice(0, 8)}  rev \\d+  manual +\\*\\.shapeshift\\.test`));
    assert.match(each, new RegExp(`  ${second.sessionId.slice(0, 8)}  rev \\d+  manual +\\*\\.wordpress\\.test`));
    // Sin interfaz adjunta (la CLI): la sesión que se nombra, o la última, y dice cuál.
    const cli = await connectDaemon(cwd, { spawn: false });
    const latest = (await cli.view("scope")).join("\n");
    assert.match(latest, new RegExp(`^\\S+ ${second.sessionId.slice(0, 8)}[\\s\\S]*\\*\\.wordpress\\.test`));
    const named = (await cli.view("scope", "", first.sessionId.slice(0, 8))).join("\n");
    assert.match(named, new RegExp(`${first.sessionId.slice(0, 8)}[\\s\\S]*shapeshift`));
    await assert.rejects(cli.view("scope", "", "no-existe"), /No existe la sesión no-existe/);
    cli.close();
  } finally {
    one.close();
    two.close();
    await daemon.close();
  }
});

test("hallazgos e informe por sesión, con la vista de todo el proyecto para el operador", async () => {
  const cwd = tmp();
  const cripto = new Engine({ cwd, provider: faux(), autoVerify: false });
  const wordpress = new Engine({ cwd, provider: faux(), autoVerify: false });
  try {
    cripto.scope.save(load("hackerone:shapeshift", "*.shapeshift.test"));
    wordpress.scope.save(load("hackerone:wordpress", "*.wordpress.test"));
    const evidence = cripto.artifacts.put("evidencia de prueba", "text/plain", "prueba").hash;
    cripto.findings.record({ title: "Firma de retiro sin verificar", kind: "integridad", asset: "https://api.shapeshift.test/retiro", summary: "s", evidence: [evidence], severity: "alta" }, cripto.sessionId);
    wordpress.findings.record({ title: "XSS en comentarios", kind: "xss", asset: "https://blog.wordpress.test/c", summary: "s", evidence: [evidence], severity: "media" }, wordpress.sessionId);

    // La lista de la sesión, con el aviso de lo que hay en las demás; «todos» muestra el proyecto.
    const mine = findingsView(cripto.findings, "", cripto.sessionId);
    assert.match(mine[0]!, /^HALLAZGOS · esta sesión · 0 verificados · 1 candidatos/);
    assert.ok(mine.some((line) => line.includes("Firma de retiro")) && !mine.some((line) => line.includes("XSS")));
    assert.equal(mine.at(-1), "En otras sesiones de este proyecto hay 1 más: /findings todos");
    const all = findingsView(cripto.findings, "todos", cripto.sessionId);
    assert.match(all[0]!, /^HALLAZGOS · todo el proyecto · 0 verificados · 2 candidatos/);
    // Lo que ve el agente: finding_list es de su sesión.
    const list = await cripto.agent.tools.find((tool) => tool.name === "finding_list")!.execute({}, new AbortController().signal);
    assert.match(list.text, /Firma de retiro/);
    assert.doesNotMatch(list.text, /XSS/);

    // El informe de la sesión no mezcla programas; el del proyecto tiene los dos.
    const report = (sessionId?: string) => generateReport({ paths: projectPaths(cwd), db: cripto.db, artifacts: cripto.artifacts, findings: cripto.findings, scope: cripto.scope, ledger: cripto.ledger, sessionId });
    const own = (await report(cripto.sessionId)).markdown;
    assert.match(own, /Firma de retiro/);
    assert.doesNotMatch(own, /XSS en comentarios|wordpress/);
    assert.match(own, /Fuente: hackerone:shapeshift\./);
    assert.match(own, /Costo de API conocido de la sesión/);
    const whole = (await report()).markdown;
    assert.ok(whole.includes("Firma de retiro") && whole.includes("XSS en comentarios"));
    assert.match(whole, /Fuente: hackerone:shapeshift, hackerone:wordpress\./);
    // report_generate del agente: el de su sesión, o el del proyecto si se pide.
    const tool = cripto.catalog.available.get("report_generate")!;
    const saved = async (args: object) => readFileSync(/guardado en (.+\.md)/.exec((await tool.execute(args, new AbortController().signal)).text)![1]!, "utf8");
    assert.doesNotMatch(await saved({}), /XSS en comentarios/);
    assert.match(await saved({ proyecto: true }), /XSS en comentarios/);
  } finally {
    await Promise.allSettled([cripto.close(), wordpress.close()]);
  }
});

test("verificador: sólo los candidatos de su sesión; sin saldo corta la tanda y avisa una sola vez", async () => {
  const cwd = tmp();
  const provider = faux();
  const engine = new Engine({ cwd, provider, coverageObjections: 0, closingGate: false });
  const other = new Engine({ cwd, provider: faux(), autoVerify: false });
  try {
    assert.equal(VERIFIER_BUDGET_USD, 0.5);
    assert.equal(exhaustedError("Sin saldo en tu cuenta [usage_limit] · pedido oro_req_1"), true);
    assert.equal(exhaustedError("HTTP 429: {\"error\":\"rate\"}"), true);
    assert.equal(exhaustedError("Presupuesto de sesión (USD 1.429) no alcanza"), false);
    const evidence = engine.artifacts.put("evidencia de prueba", "text/plain", "prueba").hash;
    const record = (target: Engine, title: string, path: string) => target.findings.record({ title, kind: `control de acceso ${path}`, asset: `https://api.cripto.test/${path}`, summary: "s", evidence: [evidence] }, target.sessionId);
    const first = record(engine, "IDOR en pedidos", "pedidos");
    const second = record(engine, "IDOR en facturas", "facturas");
    const foreign = record(other, "IDOR de otro programa", "ajeno");
    assert.deepEqual(engine.verifier.pending().map((item) => item.id).sort(), [first.id, second.id].sort());

    const notices: string[] = [];
    engine.onNotice = (text) => notices.push(text);
    // El turno termina bien; el verificador arranca y el proveedor dice que no hay saldo.
    provider.faux!.queue = [{ text: "Listo." }, { fail: { message: "Sin saldo en tu cuenta [usage_limit]", rejected: true } }, { text: "no debería pedirse" }];
    await engine.send("seguí");
    const events = () => (engine.db.prepare("select type from events where session_id=? and type like 'verification.%' order by seq").all(engine.sessionId) as Array<{ type: string }>).map((row) => row.type);
    assert.deepEqual(events(), ["verification.started", "verification.stopped"]);
    assert.equal(provider.faux!.queue.length, 1, "el segundo candidato no se intentó");
    assert.equal(notices.filter((text) => /no hay saldo/.test(text)).length, 1);
    // El de la otra sesión ni se miró.
    assert.equal(engine.findings.get(foreign.id)!.decidedBy, "agente");
    assert.equal(engine.verifier.failures(engine.findings.get(first.id)!), 0, "la falta de saldo no cuenta como falla del candidato");

    // El turno siguiente termina sin saldo: el verificador no arranca ni vuelve a avisar.
    provider.faux!.queue = [{ fail: { message: "Sin saldo en tu cuenta [usage_limit]", rejected: true } }];
    await engine.send("¿y?");
    assert.match(String(engine.agent.messages.filter((m) => m.role === "user").at(-1)!.content), /<verificacion>\n- el verificador se detuvo: el proveedor no tiene saldo; 2 candidatos sin verificar/);
    assert.deepEqual(events(), ["verification.started", "verification.stopped", "verification.skipped"]);
    assert.equal(notices.filter((text) => /no hay saldo/.test(text)).length, 1);

    // Un candidato que ya falló dos veces sin cambios queda para /verificar; con otra revisión vuelve.
    logEvent(engine.db, engine.sessionId, "verification.failed", { id: first.id, rev: first.rev, error: "x" });
    logEvent(engine.db, engine.sessionId, "verification.failed", { id: first.id, rev: first.rev, error: "x" });
    assert.deepEqual(engine.verifier.pending(2).map((item) => item.id), [second.id]);
    engine.findings.update(first.id, { limits: "falta el control" }, engine.sessionId);
    assert.equal(engine.verifier.pending(2).length, 2);
  } finally {
    await Promise.allSettled([engine.close(), other.close()]);
  }
});

test("verificador: su propio tope de pasos (le pide el veredicto antes) y no depende del presupuesto de la sesión", async () => {
  const cwd = tmp();
  const provider = faux();
  // Sesión con el presupuesto ya gastado: el agente principal no podría pedir nada, el verificador sí.
  const engine = new Engine({ cwd, provider, autoVerify: false, budgetPico: 1n, verifier: { maxSteps: 4 } });
  try {
    engine.ledger.record({ role: "assistant", content: "", toolCalls: [], stopReason: "stop", provider: "faux", model: "faux", requestId: "gastado", at: Date.now(), usage: { input: 1000, cacheRead: 0, cacheWrite: 0, output: 1000 } }, { sessionId: engine.sessionId, account: "faux", worker: "principal", model: { ...engine.agent.model, cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 } } });
    assert.ok(engine.ledger.overBudget(engine.sessionId), "la sesión está sin presupuesto");
    const evidence = engine.artifacts.put("evidencia de prueba", "text/plain", "prueba").hash;
    const finding = engine.findings.record({ title: "IDOR", kind: "control de acceso", asset: "https://api.cripto.test/x", summary: "s", evidence: [evidence] }, engine.sessionId);
    // Pasos distintos (que no los corte la falta de avance): consultas de alcance a hosts distintos.
    provider.faux!.queue = [1, 2, 3, 4, 5].map((n) => ({ toolCalls: [{ name: "scope_check", arguments: { target: `h${n}.cripto.test` } }] }));
    const failure = await engine.verifier.verify(finding.id).then(() => undefined, (error: Error) => error);
    assert.match(failure?.message ?? "", /Límite de pasos del verificador \(4\) alcanzado/);
    assert.doesNotMatch(failure?.message ?? "", /Presupuesto de sesión/);
    const transcript = JSON.parse(engine.artifacts.read(/Transcripción (sha256:[0-9a-f]+)/.exec(failure!.message)![1]!).toString("utf8")) as Array<{ role: string; content: string }>;
    assert.ok(transcript.some((message) => message.role === "user" && /Dictá el veredicto ahora/.test(message.content)));
    assert.ok(!transcript.some((message) => message.role === "user" && /finding_record/.test(message.content)), "sin el aviso del agente principal");
  } finally {
    await engine.close();
  }
});

test("aviso: abrir en el home o en la raíz avisa sin bloquear; una carpeta por programa no", async () => {
  const warning = /carpeta por programa|one folder per program/;
  assert.match(sharedFolderWarning(homedir()) ?? "", warning);
  assert.match(sharedFolderWarning("/") ?? "", warning);
  assert.equal(sharedFolderWarning(join(homedir(), "bb", "acme")), undefined);
  assert.equal(sharedFolderWarning(tmp()), undefined);
  // En Docker el home es el de la máquina anfitriona, que se deduce de la carpeta de datos montada.
  const saved = { proyecto: process.env.CYBER_PROYECTO_HOST, datos: process.env.CYBER_DATOS_HOST };
  try {
    process.env.CYBER_PROYECTO_HOST = "/home/ana";
    process.env.CYBER_DATOS_HOST = "/home/ana/.local/share/elevate-cyber";
    assert.match(sharedFolderWarning("/proyecto") ?? "", /\/home\/ana/);
    process.env.CYBER_PROYECTO_HOST = "/home/ana/bb/acme";
    assert.equal(sharedFolderWarning("/proyecto"), undefined);
  } finally {
    for (const [key, value] of [["CYBER_PROYECTO_HOST", saved.proyecto], ["CYBER_DATOS_HOST", saved.datos]] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  // Al abrir una sesión en esa carpeta, el aviso llega con la sesión; se puede trabajar igual.
  const cwd = tmp();
  process.env.CYBER_HOME_HOST = cwd;
  const daemon = new Daemon({ cwd, resolve: () => faux(), autoResume: false });
  try {
    await daemon.listen();
    const client = await connectDaemon(cwd, { spawn: false });
    const snapshot = await client.attach({ model: "faux" });
    assert.match(snapshot.avisos?.join("\n") ?? "", /comparten daemon, memoria, artefactos y hallazgos|shares the daemon, memory, artifacts and findings/);
    assert.ok(snapshot.sessionId);
    client.close();
  } finally {
    delete process.env.CYBER_HOME_HOST;
    await daemon.close();
  }
});
