import "./datos-tmp.ts";
// body_probe en modo «agregar» (asignación masiva) y «hpp» (claves duplicadas) contra laboratorios
// locales: uno vulnerable, uno que ignora los campos, uno que los refleja sin guardarlos y uno que
// valida la primera clave y aplica la última. Sólo cuenta APLICADO si la relectura lo confirma.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { IdHarvest } from "../src/cosecha.ts";
import { HttpClient } from "../src/http.ts";
import { createProbeTools } from "../src/probes.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { labAsignacion } from "./lab-idor.ts";

const abort = new AbortController().signal;
const json = { "content-type": "application/json" };
const form = { "content-type": "application/x-www-form-urlencoded" };

async function setup() {
  const lab = labAsignacion();
  await new Promise<void>((resolve) => lab.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(lab.server.address() as any).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-asig-"));
  const db = openStore(projectPaths(cwd));
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: [parseRule(`${base}/`)], exclude: [] };
  const http = new HttpClient(new Artifacts(db, join(cwd, "artifacts")), () => scope);
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer t-ana" } });
  http.setIdentity({ name: "beto", headers: { authorization: "Bearer t-beto" } });
  const harvest = new IdHarvest({ db, http, sessionId: "s1" });
  http.onExchange = (exchange) => harvest.observe(exchange);
  const events: Array<{ type: string; payload: any }> = [];
  const tools = Object.fromEntries(createProbeTools({ artifacts: http.artifacts, http, harvest, event: (type, payload) => events.push({ type, payload }) }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  return { lab, base, http, harvest, events, probe: tools.body_probe!, close: () => lab.server.close() };
}

test("agregar: el vulnerable aplica rol, admin y plan (confirmado por relectura), guarda campos que no existían y se restaura", async () => {
  const { lab, base, http, events, probe, close } = await setup();
  try {
    const control = await http.send({ url: `${base}/v/api/me`, method: "PATCH", headers: json, body: JSON.stringify({ name: "Ana" }) }, "ana");
    const result = await probe.execute({ id: control.id, mode: "agregar" }, abort);
    assert.match(result.text, /^estado antes h\d+: GET \/v\/api\/me → 200/m);
    assert.match(result.text, /role="admin" \(agregar\)\s+200 reflejado\s+relectura h\d+: APLICADO \(antes "user"\)/);
    assert.match(result.text, /is_admin=true \(agregar\)\s+200 reflejado\s+relectura h\d+: APLICADO \(antes false\)/);
    assert.match(result.text, /plan="enterprise" \(agregar\)\s+200 reflejado\s+relectura h\d+: APLICADO \(antes "free"\)/);
    // Un campo que el objeto no tenía y el servidor guarda igual: no es hallazgo sin efecto.
    assert.match(result.text, /tier="premium" \(agregar\)\s+200 reflejado\s+relectura h\d+: GUARDADO \(antes no existía\)/);
    assert.match(result.text, /APLICADO \(la relectura lo muestra con el valor enviado y antes tenía otro\): role, is_admin, plan\. Cada uno es candidato a asignación masiva/);
    assert.match(result.text, /GUARDADO pero el objeto no tenía ese campo: .*tier/);
    assert.equal(result.details!.aplicados, 3);
    assert.deepEqual(result.details!.restaurados, ["role", "is_admin", "plan"]);
    assert.ok((result.details!.peticiones as number) <= 41);
    // Restaurado de verdad en el servidor.
    assert.equal(lab.users.v![1]!.role, "user");
    assert.equal(lab.users.v![1]!.is_admin, false);
    assert.equal(lab.users.v![1]!.plan, "free");
    const event = events.find((item) => item.type === "asignacion.sondeo")!;
    assert.deepEqual(event.payload.aplicados, ["role", "is_admin", "plan"]);
    assert.equal(event.payload.identidad, "ana");
  } finally {
    close();
  }
});

test("agregar en formulario: role=admin y is_admin=true llegan como texto y la relectura los confirma", async () => {
  const { lab, base, http, probe, close } = await setup();
  try {
    const control = await http.send({ url: `${base}/v/api/me`, method: "PATCH", headers: form, body: "name=Ana" }, "ana");
    const result = await probe.execute({ id: control.id, mode: "agregar", fields: ["role", "is_admin"], restore: false }, abort);
    assert.match(result.text, /role="admin" \(agregar\).*APLICADO/);
    assert.match(result.text, /is_admin=true \(agregar\).*APLICADO/);
    assert.equal(lab.users.v![1]!.role, "admin");
    const sent = http.log.filter((entry) => entry.method === "PATCH").map((entry) => entry.bodyKeys.join("&"));
    assert.ok(sent.includes("name&role"), `se mandó como formulario: ${sent.join(" | ")}`);
  } finally {
    close();
  }
});

test("falsos positivos: el que ignora no aplica nada y el que refleja sin guardar no es hallazgo", async () => {
  const { base, http, probe, close } = await setup();
  try {
    const ignore = await http.send({ url: `${base}/i/api/me`, method: "PATCH", headers: json, body: JSON.stringify({ name: "Ana" }) }, "ana");
    const ignored = await probe.execute({ id: ignore.id, mode: "agregar", fields: ["role", "is_admin", "plan", "balance"] }, abort);
    assert.equal(ignored.details!.aplicados, 0);
    assert.equal(ignored.details!.guardados, 0);
    assert.match(ignored.text, /role="admin" \(agregar\)\s+200\s+relectura h\d+: sin efecto/);
    assert.match(ignored.text, /Ningún campo se aplicó: la relectura del objeto no cambió\./);
    assert.doesNotMatch(ignored.text, /APLICADO/);

    const reflect = await http.send({ url: `${base}/r/api/me`, method: "PATCH", headers: json, body: JSON.stringify({ name: "Ana" }) }, "ana");
    const reflected = await probe.execute({ id: reflect.id, mode: "agregar", fields: ["role", "is_admin", "plan"] }, abort);
    assert.equal(reflected.details!.aplicados, 0);
    assert.equal(reflected.details!.reflejados, 3);
    assert.match(reflected.text, /role="admin" \(agregar\)\s+200 reflejado\s+relectura h\d+: reflejado, no aplicado/);
    assert.match(reflected.text, /Reflejados en la respuesta pero no aplicados: role, is_admin, plan\. No es hallazgo/);
    assert.doesNotMatch(reflected.text, /APLICADO/);
  } finally {
    close();
  }
});

test("hpp: el validador mira la primera clave y el modelo usa la última; agregar a secas queda rechazado", async () => {
  const { lab, base, http, probe, close } = await setup();
  try {
    const control = await http.send({ url: `${base}/h/api/me`, method: "PATCH", headers: json, body: JSON.stringify({ name: "Ana" }) }, "ana");
    const plain = await probe.execute({ id: control.id, mode: "agregar", fields: ["role"] }, abort);
    assert.match(plain.text, /role="admin" \(agregar\)\s+403\s+rechazado/);
    assert.equal(plain.details!.aplicados, 0);

    const duplicated = await probe.execute({ id: control.id, mode: "hpp", fields: ["role"] }, abort);
    assert.match(duplicated.text, /role="admin" \(hpp: "user" y después "admin"\)\s+200 reflejado\s+relectura h\d+: APLICADO \(antes "user"\)/);
    // Restaurado enseguida, el otro orden arranca del estado original: el validador lo frena.
    assert.match(duplicated.text, /role="admin" \(hpp: "admin" y después "user"\)\s+403\s+rechazado/);
    assert.match(duplicated.text, /candidato a asignación masiva por clave duplicada/);
    assert.match(duplicated.text, /restauración h\d+: role="user" → relectura h\d+: restaurado/);
    const raw = http.log.filter((entry) => entry.method === "PATCH").map((entry) => entry.hash);
    const bodies = raw.map((hash) => JSON.parse(http.artifacts.read(hash).toString("utf8")).request.body as string);
    assert.ok(bodies.includes('{"name":"Ana","role":"user","role":"admin"}'), bodies.join(" | "));
    assert.equal(lab.users.h![1]!.role, "user");

    // En formulario: role=user&role=admin.
    const formControl = await http.send({ url: `${base}/h/api/me`, method: "PATCH", headers: form, body: "name=Ana" }, "ana");
    const formDup = await probe.execute({ id: formControl.id, mode: "hpp", fields: ["role"], restore: false }, abort);
    assert.match(formDup.text, /hpp: "user" y después "admin".*APLICADO/);
    assert.equal(lab.users.h![1]!.role, "admin");
  } finally {
    close();
  }
});

test("alta: cada intento crea un objeto y se compara contra el del control; el dueño ajeno es una identidad del operador", async () => {
  const { lab, base, http, probe, close } = await setup();
  try {
    // Beto ve su propio id en /me: es el id de otra identidad del operador para owner_id.
    await http.send({ url: `${base}/v/api/me` }, "beto");
    const control = await http.send({ url: `${base}/v/api/projects`, method: "POST", headers: json, body: JSON.stringify({ name: "p" }) }, "ana");
    const result = await probe.execute({ id: control.id, mode: "agregar", fields: ["plan", "owner_id"] }, abort);
    assert.match(result.text, /alta: el control creó \/v\/api\/projects\/\d+/);
    assert.match(result.text, /plan="enterprise" \(agregar\).*APLICADO \(antes "free"\)/);
    assert.match(result.text, /owner_id=2 \(agregar\).*APLICADO \(antes 1\)/);
    assert.match(result.text, /Cada intento creó un objeto/);
    assert.ok([...lab.projects.values()].some((project) => project.owner_id === 2 && project.name === "p"));
  } finally {
    close();
  }
});

test("propiedad: sobre un recurso de otra identidad se niega sin mandar nada; sin relectura no hay hallazgo", async () => {
  const { base, http, probe, close } = await setup();
  try {
    await http.send({ url: `${base}/v/api/users/2` }, "beto");
    await http.send({ url: `${base}/v/api/me` }, "beto");
    const count = http.count;
    await assert.rejects(Promise.resolve(probe.execute({ url: `${base}/v/api/users/2`, method: "PATCH", body: { name: "x" }, identity: "ana", mode: "agregar" }, abort)), /sólo corre sobre recursos propios: el id 2 nunca le llegó a «ana»/);
    await assert.rejects(Promise.resolve(probe.execute({ url: `${base}/v/api/users/2`, method: "PATCH", body: { name: "x" }, mode: "hpp" }, abort)), /no usa ninguna identidad del operador/);
    assert.equal(http.count, count, "no se mandó nada");
    // Una escritura sin lectura posible (POST que no es alta y sin GET): no se prueba a ciegas.
    const blind = await probe.execute({ url: `${base}/v/api/feedback`, method: "POST", body: { text: "q" }, identity: "ana", mode: "agregar" }, abort);
    assert.match(blind.text, /Sin una lectura JSON del objeto no se puede confirmar nada/);
    assert.equal(blind.details!.aplicados, 0);
    // mutar sigue igual (JSON obligatorio).
    const formControl = await http.send({ url: `${base}/v/api/me`, method: "PATCH", headers: form, body: "name=Ana" }, "ana");
    await assert.rejects(Promise.resolve(probe.execute({ id: formControl.id }, abort)), /no es JSON/);
  } finally {
    close();
  }
});
