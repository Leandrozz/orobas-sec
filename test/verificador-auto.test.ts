// Verificación automática al cierre del turno (reporte de Nico, 22/11: «el verificador funcionando solo sin que
// yo le diga nada y chupando usage», con «Consultar alcance · dentro false» varias veces): no repite candidatos
// que ya vio con la misma evidencia, no lanza el modelo para lo que está fuera del alcance, avisa antes qué va a
// verificar y después cuánto gastó, y el operador elige el modo (automática, a pedido o con tope). El valor de
// fábrica sigue siendo «automática».
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { configPath, resolveProvider } from "../src/providers.ts";
import { parseRule } from "../src/scope.ts";
import { DEFAULT_VERIFY, findingPrint, parseVerifySetting, readVerifySetting, saveVerifySetting, verifySettingLine } from "../src/verificacion.ts";

const verdict = (state: string, reason: string) => ({ toolCalls: [{ name: "verdict", arguments: { state, reason } }] });

test("verificación automática: huella de evidencia, alcance resuelto sin modelo, aviso antes y después, y modos a pedido y con tope", async (t) => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-verif-auto-")), provider, coverageObjections: 0, closingGate: false });
  const saved = existsSync(configPath()) ? readFileSync(configPath(), "utf8") : undefined;
  t.after(async () => {
    if (saved === undefined) writeFileSync(configPath(), "{}\n");
    else writeFileSync(configPath(), saved);
    await engine.close();
  });
  assert.deepEqual(readVerifySetting(), DEFAULT_VERIFY, "de fábrica: automática, como siempre");
  engine.scope.save({ source: "hackerone:tienda", include: [parseRule("*.tienda.test")], exclude: [], notes: "" });
  const notices: string[] = [];
  engine.onNotice = (text) => notices.push(text);
  const evidence = engine.artifacts.put("evidencia A", "text/plain", "prueba").hash;
  const record = (title: string, asset: string, proof = [evidence]) => engine.findings.record({ title, kind: "control de acceso", asset, summary: "s", evidence: proof }, engine.sessionId);
  const inside = record("IDOR en pedidos", "https://api.tienda.test/pedidos/2");
  const outside = record("IDOR en un host que ya no está", "https://otro.ejemplo.com/x");

  // Turno 1: el de afuera no llega al modelo; el de adentro sí, una vez.
  provider.faux!.queue = [{ text: "Listo." }, verdict("candidato", "no pude reproducir sin la cuenta de bob"), { text: "ok" }];
  await engine.send("seguí");
  assert.equal(provider.faux!.queue.length, 0, "el verificador corrió sólo para el candidato del alcance");
  assert.ok(notices.some((text) => /No verifico un candidato fuera del alcance de esta sesión/.test(text) && text.includes(outside.id.slice(0, 8)) && /no se gasta nada/.test(text)), notices.join(" | "));
  assert.ok(notices.some((text) => /^Verificación automática al cierre del turno: un candidato sin verificar con esta evidencia/.test(text) && text.includes(inside.id.slice(0, 8)) && /hasta USD 0\.5 cada uno/.test(text) && /\/verificacion para cambiarlo/.test(text)), notices.join(" | "));
  assert.ok(notices.some((text) => /^Verificación terminada: 1 sigue candidato · USD \d+\.\d{4} · \d+ solicitudes al modelo\.$/.test(text)), notices.join(" | "));
  const types = () => (engine.db.prepare("select type, payload from events where session_id=? and type like 'verification.%' order by seq").all(engine.sessionId) as Array<{ type: string; payload: string }>);
  const verdicts = types().filter((row) => row.type === "verification.verdict").map((row) => JSON.parse(row.payload));
  assert.equal(verdicts.length, 1);
  assert.equal(verdicts[0].huellaAntes, findingPrint(inside));
  assert.equal(verdicts[0].huella, findingPrint(engine.findings.get(inside.id)!));
  assert.equal(engine.findings.get(outside.id)!.state, "candidato", "el de afuera no cambia: sólo no se verifica");

  // Turno 2: nada cambió → el verificador no corre, ni se repite el aviso de fuera del alcance.
  notices.length = 0;
  provider.faux!.queue = [{ text: "Listo." }];
  await engine.send("¿y?");
  assert.equal(provider.faux!.queue.length, 0);
  assert.deepEqual(notices.filter((text) => /Verificación|No verifico/.test(text)), []);

  // Cambiar el título o el resumen no es evidencia nueva; un candidato duplicado con la misma evidencia tampoco.
  engine.findings.update(inside.id, { title: "IDOR en pedidos (otra redacción)" }, engine.sessionId);
  engine.findings.record({ title: "IDOR en pedidos, otra vez", kind: "idor", asset: "https://api.tienda.test/pedidos/2", summary: "s", evidence: engine.findings.get(inside.id)!.evidence }, engine.sessionId);
  const pendingInside = () => engine.verifier.pending().map((item) => item.id).filter((id) => id !== outside.id);
  assert.deepEqual(pendingInside(), [], "ya lo vio con esta evidencia");
  // Evidencia nueva: vuelve (antes, un candidato que el verificador había dejado como candidato no volvía nunca).
  const more = engine.artifacts.put("evidencia nueva", "text/plain", "prueba").hash;
  engine.findings.update(inside.id, { evidence: [more] }, engine.sessionId);
  assert.deepEqual(pendingInside(), [inside.id]);

  // A pedido: no corre solo; avisa una vez qué quedó sin verificar.
  saveVerifySetting(parseVerifySetting("a pedido")!);
  notices.length = 0;
  provider.faux!.queue = [{ text: "Listo." }];
  await engine.send("seguí");
  assert.equal(provider.faux!.queue.length, 0, "a pedido no lanza el verificador");
  assert.ok(notices.some((text) => /^Sin verificar \(la verificación es a pedido\): /.test(text) && text.includes(inside.id.slice(0, 8))), notices.join(" | "));

  // Con tope: lo gastado por el verificador en la sesión ya pasa el tope → no corre y lo dice.
  saveVerifySetting(parseVerifySetting("tope 0,001")!);
  engine.db.prepare("insert into requests(provider,account,request_id,session_id,worker,model,at,stop_reason,input,cache_read,cache_write,output,cost_input,cost_cache_read,cost_cache_write,cost_output) values('faux','test','rv1',?,'verificador:1','faux','2026-11-22T12:00:00.000Z','stop',10,0,0,10,'2000000000','0','0','0')").run(engine.sessionId);
  notices.length = 0;
  provider.faux!.queue = [{ text: "Listo." }];
  await engine.send("seguí");
  assert.equal(provider.faux!.queue.length, 0);
  assert.ok(notices.some((text) => /llegó a su tope de la sesión \(USD 0\.001\)/.test(text)), notices.join(" | "));
});

test("ajuste de verificación: se lee y se guarda en config.json sin tocar lo demás", (t) => {
  const path = configPath();
  const saved = existsSync(path) ? readFileSync(path, "utf8") : undefined;
  t.after(() => writeFileSync(path, saved ?? "{}\n"));
  writeFileSync(path, JSON.stringify({ defaultModel: "orobas/glm-5.3-flash", cveFeed: false }));
  assert.deepEqual(readVerifySetting(), DEFAULT_VERIFY);
  saveVerifySetting({ mode: "tope", topeUsd: 2.5 });
  const config = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(config.defaultModel, "orobas/glm-5.3-flash");
  assert.equal(config.cveFeed, false);
  assert.deepEqual(config.verificacion, { modo: "tope", topeUsd: 2.5 });
  assert.deepEqual(readVerifySetting(), { mode: "tope", topeUsd: 2.5 });
  assert.match(verifySettingLine(readVerifySetting()), /^Verificación automática con tope: hasta USD 2\.5 del verificador por sesión/);
  saveVerifySetting(parseVerifySetting("a-pedido")!);
  assert.equal(JSON.parse(readFileSync(path, "utf8")).verificacion, "a-pedido");
  assert.match(verifySettingLine(readVerifySetting()), /^Verificación a pedido: sólo con \/verificar/);
  assert.equal(parseVerifySetting("cualquier cosa"), undefined);
  assert.equal(parseVerifySetting("tope 0"), undefined);
  writeFileSync(path, "{ ilegible");
  assert.deepEqual(readVerifySetting(), DEFAULT_VERIFY, "una configuración rota no apaga ni cambia nada");
});
