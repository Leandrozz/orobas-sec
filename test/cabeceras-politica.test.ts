import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { bugcrowdScope, importBBScope, intigritiScope } from "../src/bugcrowd.ts";
import { bountyScope, type BountyProgram } from "../src/cyber-bounty.ts";
import { HackerOne, importScope } from "../src/hackerone.ts";
import { anthropicMessages, openAICompletions } from "../src/llm.ts";
import { avisoDeCabeceras, textoDePolitica } from "../src/politica-cabeceras.ts";
import { scopeView, ScopeStore } from "../src/scope.ts";
import { SecretosSesion } from "../src/secretos-sesion.ts";

const host = "api.ejemplo.test";
const cita = "X-HackerOne-Research: [H1 username]";
const valorDePrueba = "sk-proj-" + "prueba-local-".repeat(3);

test("la revisión cita una vez cada nombre explícito y conserva las plantillas en la nota", () => {
  const politica = "Usá `User-Agent: HackerOne/<researcher-handle>` y «X-HackerOne: <report-reference>».";
  const vista = avisoDeCabeceras(politica, "x-hackerone: otra referencia");
  assert.match(vista, /\(User-Agent, X-HackerOne\)/);
  assert.equal(textoDePolitica(politica), politica);
  assert.equal(avisoDeCabeceras("Identificate con tu cuenta de HackerOne.", "User-Agent:", null), "");
});

test("las cabeceras de credenciales quedan fuera del aviso, y sus valores fuera de la nota", () => {
  for (const nombre of ["aUthoriZation", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token"]) {
    const politica = `Primera condición.\n- \`${nombre}: muestra=privada con espacios; otro=dato\`\nSegunda condición.`;
    assert.equal(avisoDeCabeceras(politica), "");
    const nota = textoDePolitica(politica);
    assert.doesNotMatch(nota, /privada|otro=dato/);
    assert.match(nota, /Primera condición/);
    assert.match(nota, /Segunda condición/);
  }
});

test("un campo de autenticación partido entre líneas no deja el valor en la nota", () => {
  const nota = textoDePolitica("Cookie:\r\n  sid=reservado\r\n\totro=privado\r\nCondición del programa.");
  assert.doesNotMatch(nota, /sid=|otro=|privado/);
  assert.match(nota, /Condición del programa/);
});

test("ocultar una cabecera entre comillas conserva las restricciones que la siguen", () => {
  const nota = textoDePolitica("Usá `Cookie: sid=privado` sólo en la cuenta propia y «X-Api-Key: reservada» sólo los lunes.");
  assert.match(nota, /sólo en la cuenta propia/);
  assert.match(nota, /sólo los lunes/);
  assert.doesNotMatch(nota, /privado|reservada/);
});

for (const via of ["API", "CSV"]) {
  test(`HackerOne por ${via} conserva la mención al lado del activo al reabrir el alcance`, async (t) => {
    const db = new DatabaseSync(":memory:");
    t.after(() => db.close());
    const instrucciones = "Condiciones del activo. ".repeat(7) + "\n" + cita;
    const activos = [host, "otro.ejemplo.test"];
    const consultar: typeof fetch = async () => {
      if (via === "CSV") {
        const csv = ["identifier,asset_type,eligible_for_submission,instruction",
          ...activos.map((activo, i) => `${activo},DOMAIN,true,"${i ? "" : instrucciones}"`)].join("\n");
        return new Response(csv, { headers: { "content-type": "text/csv" } });
      }
      return Response.json({ data: activos.map((activo, i) => ({ attributes: {
        asset_identifier: activo, asset_type: "DOMAIN", eligible_for_submission: true, instruction: i ? "" : instrucciones,
      } })) });
    };
    const api = via === "API" ? new HackerOne({ username: "demo", token: "prueba" }, consultar) : undefined;
    await importScope(api, new ScopeStore(db, "s"), "demo", consultar);
    const guardado = new ScopeStore(db, "s").current()!;
    assert.match(guardado.include[0]!.note!, /X-HackerOne-Research/);
    assert.doesNotMatch(guardado.include[1]!.note ?? "", /X-HackerOne-Research/);
    assert.match(scopeView(guardado).join("\n"), /Revisá en la política/);
  });
}

for (const plataforma of ["bugcrowd", "intigriti"] as const) {
  test(`${plataforma} muestra la mención del programa y descarta los valores del texto de origen`, async (t) => {
    const db = new DatabaseSync(":memory:");
    t.after(() => db.close());
    const policy = `User-Agent: ${valorDePrueba}`;
    const datos = plataforma === "bugcrowd"
      ? { data: { policy, targets: [{ name: host, description: cita }] } }
      : { rulesOfEngagement: policy, endpoints: [{ uri: host, description: cita }] };
    const consultar = async () => Response.json(datos);
    const leer = plataforma === "bugcrowd" ? bugcrowdScope : intigritiScope;
    const store = new ScopeStore(db, "s");
    await importBBScope(plataforma, await leer("prueba", "demo", consultar), store, "demo");
    assert.match(store.current()!.notes, /User-Agent/);
    assert.match(store.current()!.include[0]!.note!, /X-HackerOne-Research/);
    assert.ok(!JSON.stringify(store.current()).includes(valorDePrueba));
    await importBBScope(plataforma, { include: [{ kind: "host", value: host }], exclude: [], saltados: [] }, store, "otro");
    assert.doesNotMatch(scopeView(store.current()).join("\n"), /X-HackerOne|User-Agent/);
  });
}

test("Cyber Bounty conserva el ritmo y las condiciones al destacar las cabeceras", () => {
  const programa: BountyProgram = {
    id: "demo", name: "Demo", scope_revision: 2, accepting_reports: true, status: "abierto",
    scope: { include: [{ kind: "host", value: host }], exclude: [] },
    policy: `Respetá la ventana de prueba.\n${cita}`,
    conduct: { max_requests_per_second: 3, destructive_actions: false, agent_header: `X-Cyber-Agent: ${valorDePrueba}`, test_window: "lunes" },
  };
  const { notes } = bountyScope(programa);
  assert.match(notes, /\(X-HackerOne-Research, X-Cyber-Agent\)/);
  assert.match(notes, /Respetá la ventana de prueba/);
  assert.match(notes, /^Conducta: máximo 3 peticiones\/s;/m);
  assert.ok(!notes.includes(valorDePrueba));
});

test("la traza mantiene el identificador público y tapa un token aunque use la misma cabecera", () => {
  const secretos = new SecretosSesion({ sal: "prueba" });
  const publica = "X-HackerOne: investigadora-demo";
  assert.equal(secretos.vistaTrazas(publica, "operador"), publica);
  const original = `X-HackerOne: ${valorDePrueba}`;
  assert.ok(!textoDePolitica(`User-Agent: https://ejemplo.test/${valorDePrueba}`).includes(valorDePrueba));
  for (const salida of [secretos.vistaTrazas(original, "operador"), textoDePolitica(original)]) {
    assert.match(salida, /X-HackerOne/);
    assert.ok(!salida.includes(valorDePrueba));
  }
});

test("los dos transportes de modelos mantienen fuera de sus cabeceras las menciones importadas", async (t) => {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const store = new ScopeStore(db, "s");
  const alcance = await bugcrowdScope("prueba", "demo", async () => Response.json({ policy: cita, targets: [host] }));
  const lineas = await importBBScope("bugcrowd", alcance, store, "demo");
  assert.match(lineas.join("\n"), /X-HackerOne-Research/);
  const llamadas: Headers[] = [];
  t.mock.method(globalThis, "fetch", async (_url: unknown, init: RequestInit) => {
    llamadas.push(new Headers(init.headers));
    return new Response("fin de la prueba", { status: 400 });
  });
  for (const transporte of [openAICompletions, anthropicMessages]) {
    await transporte({ model: { provider: "local", id: "prueba", baseUrl: "http://127.0.0.1:9/v1" },
      system: "Prueba local", messages: [{ role: "user", at: 1, content: lineas.join("\n") }], tools: [] });
  }
  assert.equal(llamadas.length, 2);
  for (const cabeceras of llamadas) assert.equal(cabeceras.has("X-HackerOne-Research"), false);
});
