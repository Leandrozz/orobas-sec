import "./datos-tmp.ts";
// Memoria atada al programa. Reporte real: trabajando Matomo, Tools for Humanity y Kubernetes en la
// misma carpeta apareció sola una memoria de otro programa (de Mercado Libre). La memoria era de la
// carpeta, no del programa: en la primera vuelta de cada sesión entraban todas las decisiones y
// pendientes vigentes del proyecto, y la búsqueda por texto no miraba de qué programa era cada nota.
// Los casos son sintéticos (dominios .test).
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { decode, encode } from "@toon-format/toon";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { parseRule, sameScope, ScopeStore, scopeTag } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { Vault } from "../src/vault.ts";
import { memoryView } from "../src/views.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-memoria-alcance-"));
const load = (source: string, ...rules: string[]) => ({ source, include: rules.map((rule) => parseRule(rule)), exclude: [], notes: "" });
const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const engine = (cwd: string) => new Engine({ cwd, provider: resolveProvider("faux"), autoVerify: false, cveFeed: false });
const toolText = (e: Engine, name: string) => String(e.agent.messages.findLast((m) => m.role === "tool" && m.name === name)?.content ?? "");

test("la etiqueta del alcance: programa de la plataforma o, si es manual, sus dominios", () => {
  assert.equal(scopeTag(undefined), undefined);
  assert.equal(scopeTag(load("manual")), undefined, "sin reglas no hay alcance");
  assert.deepEqual(scopeTag(load("hackerone:Matomo", "matomo.test", "*.cloud.matomo.test")), { program: "hackerone:matomo", domains: ["matomo.test"] });
  assert.deepEqual(scopeTag(load("manual", "http://127.0.0.1:8899", "api.tienda.com.ar", "10.0.0.0/24")), { program: "manual", domains: ["10.0.0.0/24", "127.0.0.1:8899", "tienda.com.ar"] });
  const matomo = { program: "hackerone:matomo", domains: ["matomo.test"] };
  const meli = { program: "hackerone:mercadolibre", domains: ["mercadolibre.test"] };
  assert.equal(sameScope(matomo, matomo), true);
  assert.equal(sameScope(matomo, { ...matomo, domains: ["otro.test"] }), true, "el mismo programa aunque cambie su lista");
  assert.equal(sameScope(matomo, meli), false);
  assert.equal(sameScope(matomo, { program: "hackerone:otro", domains: ["matomo.test"] }), false, "dos programas distintos nunca se cruzan, aunque compartan un dominio");
  assert.equal(sameScope({ program: "manual", domains: ["127.0.0.1:8899"] }, { program: "manual", domains: ["127.0.0.1:8899", "lab.test"] }), true, "un alcance manual que creció sigue siendo el mismo");
  assert.equal(sameScope({ program: "manual", domains: ["127.0.0.1:8899"] }, { program: "manual", domains: ["127.0.0.1:3000"] }), false);
  assert.equal(sameScope({ program: "manual", domains: ["matomo.test"] }, matomo), true, "un laboratorio manual del mismo dominio que el programa");
  for (const unknown of [{ program: "", domains: [] }, { program: "?", domains: ["matomo.test"] }]) {
    assert.equal(sameScope(unknown, matomo), false, `«${unknown.program}» no coincide con nada`);
    assert.equal(sameScope(unknown, unknown), false);
  }
  assert.equal(sameScope(matomo, undefined), false);
});

test("una memoria de otro programa no entra sola: ni en la primera vuelta ni por coincidir el texto; se le ofrece al operador", async () => {
  const cwd = tmp();
  // Sesión de Mercado Libre: guarda un pendiente y una decisión con el agente.
  const meli = engine(cwd);
  meli.scope.save(load("hackerone:mercadolibre", "*.mercadolibre.test"));
  meli.provider.faux!.queue = [
    call("memory_write", { type: "pendiente", title: "MeliGPT auth bloqueada", summary: "El login de meligpt.mercadolibre.test quedó bloqueado; retomar con otra cuenta." }),
    call("memory_write", { type: "decision", title: "Sin escáneres en Mercado Libre", summary: "El programa prohíbe escáneres automáticos." }),
    { text: "Guardado." },
  ];
  await meli.send("anotá lo de la auth bloqueada");
  const written = readdirSync(projectPaths(cwd).records);
  assert.equal(written.length, 2);
  for (const file of written) {
    const record = decode(readFileSync(join(projectPaths(cwd).records, file), "utf8")) as { scope?: { program: string } };
    assert.equal(record.scope?.program, "hackerone:mercadolibre", "cada memoria queda atada al programa donde nació");
  }
  await meli.close();

  // Sesión nueva en la misma carpeta, otro programa.
  const matomo = engine(cwd);
  const notices: string[] = [];
  matomo.onNotice = (text) => notices.push(text);
  // Primera vuelta sin alcance: antes entraban todas las decisiones y pendientes del proyecto.
  matomo.provider.faux!.queue = [{ text: "ok" }];
  await matomo.send("hola, arrancamos");
  assert.deepEqual(matomo.lastRecall, []);
  assert.doesNotMatch(String(matomo.agent.messages.find((m) => m.role === "user")!.content), /<memoria>/);
  matomo.scope.save(load("hackerone:matomo", "*.matomo.test"));
  // Con el alcance de Matomo y un mensaje que coincide con la nota de Mercado Libre.
  matomo.provider.faux!.queue = [{ text: "ok" }];
  await matomo.send("la auth quedó bloqueada en el login, retomar con otra cuenta");
  assert.deepEqual(matomo.lastRecall, [], "nada de Mercado Libre");
  const sent = matomo.agent.messages.filter((m) => m.role === "user").map((m) => String(m.content)).join("\n");
  assert.doesNotMatch(sent, /meligpt|mercadolibre|Mercado Libre/i, "ni una palabra de la nota ajena llega al modelo");
  assert.ok(notices.some((text) => /otro programa/.test(text) && /hackerone:mercadolibre/.test(text) && /\/memoria /.test(text)), `se le ofrece al operador, marcada: ${notices.join(" | ")}`);
  // Una sola vez por nota.
  const offers = () => notices.filter((text) => /otro programa/.test(text)).length;
  const offered = offers();
  matomo.provider.faux!.queue = [{ text: "ok" }];
  await matomo.send("de nuevo: la auth quedó bloqueada en el login");
  assert.equal(offers(), offered);

  // Las herramientas tampoco la dan: buscar la nombra sólo como cantidad; leerla o pisarla, no.
  const id = written.find((file) => file.startsWith("meligpt"))!.replace(/\.toon$/, "");
  matomo.provider.faux!.queue = [call("memory_search", { query: "auth bloqueada login" }), call("memory_read", { id }), call("memory_write", { id, type: "pendiente", title: "pisada", summary: "pisada desde otro programa" }), { text: "listo" }];
  await matomo.send("buscá en la memoria lo de la auth");
  assert.match(toolText(matomo, "memory_search"), /Sin resultados/);
  assert.match(toolText(matomo, "memory_search"), /1 recuerdo de otro programa/);
  assert.doesNotMatch(toolText(matomo, "memory_search"), /meligpt/i);
  assert.match(toolText(matomo, "memory_read"), /otro programa.*hackerone:mercadolibre|hackerone:mercadolibre.*otro programa/s);
  assert.doesNotMatch(toolText(matomo, "memory_read"), /retomar con otra cuenta/);
  assert.match(toolText(matomo, "memory_write"), /otro programa/);
  assert.equal(matomo.vault.read(id)!.record.title, "MeliGPT auth bloqueada", "la nota ajena quedó intacta");
  await matomo.close();

  // El operador sí la ve, marcada con su programa.
  const db = openStore(projectPaths(cwd));
  const view = memoryView({ db, vault: new Vault(db, projectPaths(cwd).records, projectPaths(cwd).notes) }, "", { program: "hackerone:matomo", domains: ["matomo.test"] });
  assert.ok(view.some((line) => /otro programa · hackerone:mercadolibre/.test(line)), view.join("\n"));
  const one = memoryView({ db, vault: new Vault(db, projectPaths(cwd).records, projectPaths(cwd).notes) }, id);
  assert.ok(one.some((line) => /retomar con otra cuenta/.test(line)), "con el id, el operador lee la nota completa");
  db.close();
});

test("las del mismo programa sí vuelven: decisiones y pendientes al tener alcance, y lo que coincide con el mensaje", async () => {
  const cwd = tmp();
  const first = engine(cwd);
  first.scope.save(load("hackerone:matomo", "*.matomo.test"));
  first.provider.faux!.queue = [call("memory_write", { type: "decision", title: "Usar la cuenta tester-2", summary: "Las pruebas de Matomo van con tester-2." }), { text: "ok" }];
  await first.send("guardá que usamos tester-2");
  await first.close();
  const second = engine(cwd);
  second.provider.faux!.queue = [{ text: "ok" }];
  await second.send("hola");
  assert.equal(second.lastRecall.length, 0, "sin alcance todavía, nada");
  second.scope.save(load("hackerone:matomo", "*.matomo.test", "http://127.0.0.1:8899"));
  second.provider.faux!.queue = [{ text: "ok" }];
  await second.send("seguimos");
  assert.deepEqual(second.lastRecall.map((hit) => hit.title), ["Usar la cuenta tester-2"], "al tener el alcance del programa, sus decisiones");
  assert.match(String(second.agent.messages.findLast((m) => m.role === "user")!.content), /<memoria>[\s\S]*tester-2/);
  await second.close();
});

test("una nota del programa aparece aunque haya muchas más relevantes de otros programas", () => {
  const cwd = tmp();
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  try {
    const vault = new Vault(db, paths.records, paths.notes);
    const otro = { program: "hackerone:otro", domains: ["otro.test"] };
    const propio = { program: "hackerone:matomo", domains: ["matomo.test"] };
    // 60 notas de otro programa con la palabra en el título (pesa más) y una sola del propio, en el resumen.
    for (let i = 0; i < 60; i++) vault.write({ type: "decision", title: `Cuenta tester ${i}`, summary: `Nota ${i} de otro programa.`, scope: otro });
    vault.write({ type: "decision", title: "Credenciales de Matomo", summary: "Usamos la cuenta tester de Matomo.", scope: propio });
    assert.deepEqual(vault.search("tester", 5, { scope: propio }).map((hit) => hit.title), ["Credenciales de Matomo"]);
    assert.deepEqual(vault.decisions(8, { scope: propio }).map((hit) => hit.title), ["Credenciales de Matomo"]);
  } finally {
    db.close();
  }
});

test("migración: una nota vieja sin programa se atribuye sólo si no hay duda; si no, queda desconocida y no entra sola", async () => {
  const cwd = tmp();
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const scopes = new ScopeStore(db, "s-meli");
  new ScopeStore(db, "s-matomo").save(load("hackerone:matomo", "*.matomo.test"));
  scopes.save(load("hackerone:mercadolibre", "*.mercadolibre.test"));
  for (const session of ["s-meli", "s-matomo"]) db.prepare("insert into sessions(id,started_at,model) values(?,?,?)").run(session, new Date().toISOString(), "faux/faux");
  // Notas escritas por una versión vieja: sin campo «scope».
  const old = (id: string, title: string, type = "pendiente") => writeFileSync(join(paths.records, `${id}.toon`), `${encode({ id, rev: 1, type, state: "vigente", title, summary: `${title}: detalle.`, body: "", tags: [], sources: [], links: [], observedAt: new Date().toISOString(), validity: "" })}\n`);
  old("meli-auth-01", "Auth de meli bloqueada");
  old("suelta-02", "Nota suelta sin autor");
  // La primera la escribió la sesión de Mercado Libre (su resultado quedó en la conversación).
  db.prepare("insert into messages(session_id,seq,json) values(?,?,?)").run("s-meli", 0, JSON.stringify({ role: "tool", toolCallId: "c1", name: "memory_write", content: "Guardado meli-auth-01 rev 1", isError: false, at: 0 }));
  const vault = new Vault(db, paths.records, paths.notes);
  const result = vault.reindex();
  assert.equal(result.indexed, 2);
  const tagOf = (id: string) => vault.read(id)!.record.scope;
  assert.deepEqual(tagOf("meli-auth-01"), { program: "hackerone:mercadolibre", domains: ["mercadolibre.test"], migrated: true, attributionVersion: 2 });
  assert.deepEqual(tagOf("suelta-02"), { program: "?", domains: [], migrated: true, attributionVersion: 2 }, "dos programas en el proyecto y sin autor: desconocida");
  const matomo = { program: "hackerone:matomo", domains: ["matomo.test"] };
  assert.deepEqual(vault.pending(5, { scope: matomo }), []);
  assert.deepEqual(vault.search("nota suelta", 5, { scope: matomo }), [], "la desconocida no entra sola en ningún alcance");
  assert.deepEqual(vault.search("auth meli", 5, { scope: { program: "hackerone:mercadolibre", domains: [] } }).map((hit) => hit.id), ["meli-auth-01"]);
  // Reindexar otra vez no cambia nada (la migración se hace una sola vez y queda en el archivo).
  vault.reindex();
  assert.deepEqual(tagOf("meli-auth-01"), { program: "hackerone:mercadolibre", domains: ["mercadolibre.test"], migrated: true, attributionVersion: 2 });
  db.close();

  // Un proyecto de un solo programa: lo viejo es de ese programa.
  const solo = tmp();
  const soloPaths = projectPaths(solo);
  const soloDb = openStore(soloPaths);
  new ScopeStore(soloDb, "s1").save(load("hackerone:matomo", "*.matomo.test"));
  new ScopeStore(soloDb, "s2").save(load("hackerone:matomo", "*.matomo.test", "api.matomo.test"));
  writeFileSync(join(soloPaths.records, "vieja-01.toon"), `${encode({ id: "vieja-01", rev: 1, type: "decision", state: "vigente", title: "Vieja", summary: "Una decisión vieja.", body: "", tags: [], sources: [], links: [], observedAt: new Date().toISOString(), validity: "" })}\n`);
  const soloVault = new Vault(soloDb, soloPaths.records, soloPaths.notes);
  soloVault.reindex();
  assert.equal(soloVault.read("vieja-01")!.record.scope?.program, "hackerone:matomo");
  assert.deepEqual(soloVault.decisions(8, { scope: matomo }).map((hit) => hit.id), ["vieja-01"]);
  soloDb.close();
});

test("una edición sin programa impide atribuir la nota vieja, aunque la primera migración ya la haya asignado", () => {
  const paths = projectPaths(tmp());
  const db = openStore(paths);
  try {
    const etiqueta = { program: "hackerone:editorial", domains: ["editorial.test"] };
    for (const id of ["redaccion", "imprenta"]) {
      new ScopeStore(db, id).save(load(etiqueta.program, "editorial.test"));
    }
    new ScopeStore(db, "archivo").save(load("hackerone:archivo", "archivo.test"));
    const vault = new Vault(db, paths.records, paths.notes);
    const recibo = db.prepare("insert into messages(session_id,seq,json) values(?,?,?)");
    const casos = [
      { id: "antigua", autores: ["redaccion", "desconocido"], visible: false },
      { id: "inferida", autores: ["desconocido", "redaccion"], visible: false, scope: { ...etiqueta, migrated: true } },
      { id: "acuerdo", autores: ["imprenta", "redaccion"], visible: true },
      { id: "explicita", autores: ["redaccion", "desconocido"], visible: true, scope: etiqueta },
      { id: "recibos-ausentes", autores: [], visible: true, scope: { ...etiqueta, migrated: true } },
      { id: "ya-reservada", autores: ["redaccion"], visible: false, scope: { program: "?", domains: [], migrated: true } },
    ];
    let seq = 0;
    for (const caso of casos) {
      const nota = { id: caso.id, rev: 2, type: "decision", title: "Cartón editorial", summary: "Usar cartón gris.",
        body: "Detalle conservado.", ...(caso.scope ? { scope: caso.scope } : {}) };
      writeFileSync(join(paths.records, caso.id + ".toon"), encode(nota));
      for (const [i, autor] of caso.autores.entries()) {
        recibo.run(autor, seq++, JSON.stringify({ role: "tool", name: "memory_write", content: `Guardado ${caso.id} rev ${i + 1}` }));
      }
    }
    assert.deepEqual(vault.reindex().invalid, []);
    const archivos = casos.map(c => readFileSync(join(paths.records, c.id + ".toon"), "utf8"));
    assert.deepEqual(vault.reindex().invalid, []);
    const visibles = vault.decisions(8, { scope: etiqueta }).map(h => h.id);
    for (const [i, caso] of casos.entries()) {
      const nota = vault.read(caso.id)!.record;
      assert.equal(visibles.includes(caso.id), caso.visible, caso.id);
      assert.equal(nota.scope?.program, caso.visible ? etiqueta.program : "?");
      assert.equal(nota.body, "Detalle conservado.");
      assert.equal(nota.rev, 2);
      assert.equal(readFileSync(join(paths.records, caso.id + ".toon"), "utf8"), archivos[i]);
    }
  } finally { db.close(); }
});
