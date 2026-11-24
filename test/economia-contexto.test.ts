import "./datos-tmp.ts";
// Dieta por economía (src/economia-contexto.ts): con las tarifas del modelo, resumir conviene cuando el ahorro por
// paso durante los pasos que quedan (a la baja, y no más allá de la próxima compactación) paga reescribir el prefijo.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { CACHE_TTL_MS, convieneDieta, crecimientoPorPaso, HistoriaDePedidos, lineasIntercambios, MIN_TOKENS, pasosRestantes } from "../src/economia-contexto.ts";
import { Engine } from "../src/engine.ts";
import type { AssistantMessage } from "../src/llm.ts";
import { resolveProvider } from "../src/providers.ts";

const tarifas = { input: 10, cacheRead: 1, cacheWrite: 0, output: 20 };
const base = { tarifas, hechos: 100, tamanos: [30_000, 30_600, 31_200, 31_800, 32_400, 33_000, 33_600, 34_200, 34_800], contexto: 35_000, compactarEn: 60_000, frio: false };

test("conviene si el ahorro durante los pasos restantes paga dos veces la reescritura", () => {
  // 30.000 caracteres = 10.000 tokens menos por paso; reescribir 6.000 caracteres (2.000 tokens) a 9 de diferencia.
  const si = convieneDieta({ ...base, ahorroChars: 30_000, despuesChars: 6_000 });
  assert.equal(si.conviene, true);
  assert.equal(si.pasos, 40);
  assert.ok(Math.abs(si.ahorroPaso - 0.01) < 1e-9 && Math.abs(si.reescribir - 0.018) < 1e-9);
  // Si lo que sigue al primer resumido es mucho, no paga.
  assert.equal(convieneDieta({ ...base, ahorroChars: 30_000, despuesChars: 600_000 }).conviene, false);
  // Por debajo del mínimo no se resume aunque reescribir sea gratis.
  assert.equal(convieneDieta({ ...base, ahorroChars: (MIN_TOKENS - 1) * 3, despuesChars: 0, frio: true }).conviene, false);
  // Con la caché fría de todos modos, reescribir no cuesta nada extra.
  const fria = convieneDieta({ ...base, ahorroChars: 30_000, despuesChars: 600_000, frio: true });
  assert.equal(fria.conviene, true);
  assert.equal(fria.reescribir, 0);
  // Un modelo sin descuento de caché tampoco paga por reescribir.
  assert.equal(convieneDieta({ ...base, tarifas: { ...tarifas, cacheRead: 10 }, ahorroChars: 30_000, despuesChars: 600_000 }).reescribir, 0);
});

test("pasos restantes a la baja y nunca más allá de la próxima compactación", () => {
  assert.equal(pasosRestantes(2, 600, 10_000, 60_000), 4);
  assert.equal(pasosRestantes(30, 600, 10_000, 60_000), 15);
  assert.equal(pasosRestantes(500, 600, 10_000, 60_000), 40);
  assert.equal(pasosRestantes(500, 1000, 55_000, 60_000), 5);
  assert.equal(pasosRestantes(500, 1000, 70_000, 60_000), 1);
  assert.equal(crecimientoPorPaso([]), 600);
  assert.equal(crecimientoPorPaso([10, 20, 15, 40, 41]), 10, "mediana de las subidas: 10, 25, 1");
});

const respuesta = (model: string, input: number): AssistantMessage => ({ role: "assistant", content: "", toolCalls: [], stopReason: "toolUse", provider: "p", model, requestId: "r", at: 0, usage: { input, cacheRead: 0, cacheWrite: 0, output: 1 } });

test("caché fría: herramientas distintas o un modelo sin uso reciente; sin historia, no se supone", () => {
  const historia = new HistoriaDePedidos();
  assert.equal(historia.fria("p/a", "x,y", 0), false);
  historia.anotar(respuesta("a", 100), "x,y", 1000);
  assert.equal(historia.fria("p/a", "x,y", 2000), false);
  assert.equal(historia.fria("p/a", "x,y,z", 2000), true, "cargó una herramienta");
  assert.equal(historia.fria("p/b", "x,y", 2000), true, "otro modelo");
  assert.equal(historia.fria("p/a", "x,y", 1000 + CACHE_TTL_MS + 1), true, "pausa larga");
  assert.deepEqual([historia.pasos, historia.tamanos], [1, [100]]);
  historia.anotar({ ...respuesta("a", 5), stopReason: "error" }, "x,y", 3000);
  assert.equal(historia.pasos, 1, "un error no cuenta");
});

test("motor: con tarifas la dieta decide por economía y deja la cuenta en el evento", async () => {
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-economia-")), provider, maskAt: 1 });
  engine.agent.model.cost = { ...tarifas };
  let n = 0;
  engine.agent.tools.push((engine as any).bounded({ name: "leer", label: "Leer", description: "", parameters: { type: "object" }, execute: () => ({ text: `h${++n}  GET https://a.test/${n}  200\n${`dato ${n} `.repeat(700)}` }) }));
  provider.faux!.queue = [...Array.from({ length: 34 }, () => ({ toolCalls: [{ name: "leer", arguments: {} }] })), { text: "Listo." }];
  await engine.send("Leé todo.");
  const dietas = engine.db.prepare("select payload from events where session_id=? and type='contexto.dieta' order by seq").all(engine.sessionId).map((row: any) => JSON.parse(row.payload));
  assert.ok(dietas.length >= 1, "resume al menos una vez");
  for (const dieta of dietas) {
    assert.equal(dieta.regla, "economica");
    assert.ok(dieta.ahorro_paso_usd * dieta.pasos > dieta.reescribir_usd * 2);
    assert.ok(dieta.caracteres / 3 >= MIN_TOKENS);
  }
  engine.close();
});

test("la tabla de intercambios del checkpoint nombra cada artefacto por un prefijo que sigue sirviendo", () => {
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-tabla-")), provider: resolveProvider("faux") });
  const { hash } = engine.artifacts.put("HTTP/1.1 200 OK\n\n{}", "text/plain", "prueba");
  const log = Array.from({ length: 90 }, (_, i) => ({ id: `h${i + 1}`, method: "GET", url: `https://a.test/api/${i}`, status: 200, hash }));
  const lineas = lineasIntercambios(log);
  assert.equal(lineas.length, 80, "los últimos 80, como antes");
  assert.equal(lineas[0], `h11 GET https://a.test/api/10 → 200 · ${hash.slice(0, 19)}`);
  assert.ok(lineas.every((linea) => linea.length < 100));
  // El prefijo se lee con artifact_read y vale como evidencia de un hallazgo.
  const prefijo = hash.slice(0, 19);
  assert.equal(engine.artifacts.read(prefijo).toString("utf8"), "HTTP/1.1 200 OK\n\n{}");
  const hallazgo = engine.findings.record({ state: "candidato", title: "IDOR en api", kind: "control de acceso", asset: "https://a.test/api", summary: "lee el recurso de otro usuario", evidence: [prefijo] } as any, engine.sessionId);
  assert.deepEqual(hallazgo.evidence, [hash]);
  engine.close();
});
